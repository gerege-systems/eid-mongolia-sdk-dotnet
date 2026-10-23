using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Qr;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>«Миний QR»: cross-SDK vector (testdata/qr_vectors.json — Go / TS SDK-д ижил файл) ба stub CA.</summary>
public class QrTests
{
    private static readonly JsonElement V =
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "qr_vectors.json"))).RootElement;

    private const string Tok = "q9Xk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiM";

    [Fact]
    public void VectorsCatalog()
    {
        Assert.Equal(V.GetProperty("attributes").EnumerateArray().Select(a => a.GetString()!), QrAttributes.All);
        Assert.Equal(TimeSpan.FromSeconds(V.GetProperty("maxAgeSeconds").GetInt32()), EidQr.DefaultMaxAge);
    }

    [Fact]
    public void VectorsParse()
    {
        foreach (var c in V.GetProperty("parse").EnumerateArray())
        {
            var input = c.GetProperty("in").GetString();
            if (c.TryGetProperty("error", out var err))
            {
                var ex = Assert.Throws<EidQrException>(() => EidQr.Parse(input));
                Assert.Equal(err.GetString(), ex.Code);
            }
            else
            {
                Assert.Equal(c.GetProperty("token").GetString(), EidQr.Parse(input));
            }
        }
    }

    [Fact]
    public void VectorsVerify()
    {
        var jwks = V.GetProperty("jwks").GetRawText();
        foreach (var c in V.GetProperty("verify").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString();
            var e = c.GetProperty("expect");
            var exp = new QrExpect
            {
                Issuer = e.GetProperty("issuer").GetString(),
                Audience = e.GetProperty("audience").GetString()!,
                SessionId = e.GetProperty("sessionID").GetString()!,
                Nonce = e.GetProperty("nonce").GetString()!,
                Attributes = e.GetProperty("attributes").EnumerateArray().Select(a => a.GetString()!).ToArray(),
                Now = DateTimeOffset.FromUnixTimeSeconds(e.GetProperty("now").GetInt64()),
            };
            var jws = c.GetProperty("jws").GetString()!;
            if (c.TryGetProperty("error", out var err))
            {
                var ex = Assert.Throws<EidQrException>(() => EidQr.VerifyPresentation(jws, jwks, exp));
                Assert.True(err.GetString() == ex.Code, name);
                continue;
            }
            var p = EidQr.VerifyPresentation(jws, jwks, exp);
            var want = c.GetProperty("result");
            Assert.Equal(want.GetProperty("sub").GetString(), p.Sub);
            Assert.Equal(want.GetProperty("unavailable").EnumerateArray().Select(a => a.GetString()!), p.Unavailable);
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(want.GetProperty("attrs").GetRawText()), AttrsJson(p.Attrs)), name);
            Assert.Equal(1792800000, p.IssuedAt.ToUnixTimeSeconds());
            Assert.Equal(jws, p.Jws);
        }
    }

    private static JsonObject AttrsJson(QrAttrs a)
    {
        var o = new JsonObject();
        if (a.AgeOver18 is { } b18) o["age_over_18"] = b18;
        if (a.AgeOver21 is { } b21) o["age_over_21"] = b21;
        if (a.FullName is { } fn) o["full_name"] = new JsonObject { ["surname"] = fn.Surname, ["givenName"] = fn.GivenName };
        if (a.Phone is { } ph) o["phone"] = ph;
        if (a.BirthDate is { } bd) o["birth_date"] = bd;
        if (a.CivilId is { } ci) o["civil_id"] = ci;
        return o;
    }

    /// <summary>Stub CA: JWKS, POST /authentication/qr, GET /session/sess-1.</summary>
    private sealed class Stub : HttpMessageHandler
    {
        public ECDsa Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Kid = "k1";
        public int JwksHits;
        public JsonObject? StartBody;
        public string State = "COMPLETE";
        public string End = "OK";
        public string Nonce = "";
        public Action<JsonObject>? Mutate;

        private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private string Sign(JsonObject p)
        {
            var input = B64(Encoding.UTF8.GetBytes(new JsonObject { ["alg"] = "ES256", ["kid"] = Kid }.ToJsonString())) + "." +
                B64(Encoding.UTF8.GetBytes(p.ToJsonString()));
            return input + "." + B64(Key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256));
        }

        private static HttpResponseMessage Json(HttpStatusCode s, JsonNode body) =>
            new(s) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            var path = r.RequestUri!.AbsolutePath;
            if (path == "/.well-known/eid-jwks.json")
            {
                Assert.Null(r.Headers.Authorization);
                JwksHits++;
                var q = Key.ExportParameters(false).Q;
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["keys"] = new JsonArray(new JsonObject
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256",
                        ["kid"] = Kid,
                        ["alg"] = "ES256",
                        ["use"] = "sig",
                        ["x"] = B64(q.X!),
                        ["y"] = B64(q.Y!),
                    }),
                });
            }
            if (path == "/missing")
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
            Assert.Equal("Bearer rp_sk_secret", r.Headers.Authorization!.ToString());
            if (path == "/authentication/qr")
            {
                StartBody = JsonNode.Parse(await r.Content!.ReadAsStringAsync(ct))!.AsObject();
                if (StartBody["qr"]!.GetValue<string>().EndsWith(new string('A', 43), StringComparison.Ordinal))
                {
                    return Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "x", ["code"] = "QR_TOKEN_INVALID" });
                }
                Nonce = StartBody["nonce"]?.GetValue<string>() ?? StartBody["signatureProtocolParameters"]!["rpChallenge"]!.GetValue<string>();
                return Json(HttpStatusCode.OK, new JsonObject { ["sessionID"] = "sess-1", ["vc"] = new JsonObject { ["type"] = "numeric4", ["value"] = "4821" } });
            }
            if (path == "/session/sess-1")
            {
                var body = new JsonObject { ["state"] = State, ["result"] = new JsonObject { ["endResult"] = End } };
                if (State == "COMPLETE" && End == "OK")
                {
                    var p = new JsonObject
                    {
                        ["iss"] = EidQr.DefaultIssuer,
                        ["aud"] = "rp-uuid",
                        ["sid"] = "sess-1",
                        ["sub"] = "pairwise-1",
                        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        ["nonce"] = Nonce,
                        ["attrs"] = new JsonObject { ["age_over_18"] = true },
                        ["unavailable"] = new JsonArray("phone"),
                    };
                    Mutate?.Invoke(p);
                    body["presentation"] = new JsonObject { ["jws"] = Sign(p) };
                }
                return Json(HttpStatusCode.OK, body);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private static (Stub, EidQrClient) Client(string jwksUrl = "https://ca.test/.well-known/eid-jwks.json")
    {
        var s = new Stub();
        var c = new EidQrClient(new EidQrOptions
        {
            BaseUrl = "https://rp.test",
            RpUuid = "rp-uuid",
            RpName = "Дэлгүүр",
            ApiSecret = "rp_sk_secret",
            HttpClient = new HttpClient(s),
            JwksUrl = jwksUrl,
        });
        return (s, c);
    }

    [Fact]
    public async Task StartResultCacheRotation()
    {
        var (s, c) = Client();
        var sess = await c.StartAsync(new QrStartRequest { Qr = "EIDMN-QR1:" + Tok, Attributes = new[] { "age_over_18", "phone" } });
        Assert.Equal("sess-1", sess.SessionId);
        Assert.Equal("4821", sess.Vc);
        var b = s.StartBody!;
        Assert.Equal("EIDMN-QR1:" + Tok, b["qr"]!.GetValue<string>());
        Assert.Equal("rp-uuid", b["relyingPartyUUID"]!.GetValue<string>());
        Assert.Equal("Дэлгүүр", b["relyingPartyName"]!.GetValue<string>());
        Assert.Equal("ACSP_V2", b["signatureProtocol"]!.GetValue<string>());
        Assert.Null(b["interactions"]);
        Assert.Null(b["nonce"]);
        var ch = b["signatureProtocolParameters"]!["rpChallenge"]!.GetValue<string>();
        Assert.Equal(32, Convert.FromBase64String(ch).Length);
        Assert.Equal(ch, sess.Nonce);

        var stored = JsonSerializer.Deserialize<QrSession>(JsonSerializer.Serialize(sess))!;
        var p = await c.ResultAsync(stored, TimeSpan.FromSeconds(5));
        Assert.Equal("pairwise-1", p.Sub);
        Assert.True(p.Attrs.AgeOver18);
        Assert.Null(p.Attrs.Phone);
        Assert.Equal(new[] { "phone" }, p.Unavailable);
        await c.ResultAsync(stored, TimeSpan.FromSeconds(5));
        Assert.Equal(1, s.JwksHits);

        s.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        s.Kid = "k2";
        typeof(EidQrClient).GetField("_lastAttempt", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .SetValue(c, DateTimeOffset.MinValue);
        await c.ResultAsync(stored, TimeSpan.FromSeconds(5));
        Assert.Equal(2, s.JwksHits);
    }

    [Fact]
    public async Task StartNonceAndErrors()
    {
        var (s, c) = Client();
        var sess = await c.StartAsync(new QrStartRequest { Qr = Tok, Attributes = new[] { "full_name" }, Nonce = "order-42" });
        Assert.Equal("order-42", sess.Nonce);
        Assert.Equal("order-42", s.StartBody!["nonce"]!.GetValue<string>());
        var ex = await Assert.ThrowsAsync<EidQrException>(() => c.StartAsync(new QrStartRequest { Qr = new string('A', 43), Attributes = new[] { "age_over_18" } }));
        Assert.Equal(EidQrErrorCodes.TokenInvalid, ex.Code);
        Assert.Equal(404, ex.HttpStatus);
        s.StartBody = null;
        foreach (var a in new[] { Array.Empty<string>(), new[] { "age_over_99" }, new[] { "phone", "phone" } })
        {
            ex = await Assert.ThrowsAsync<EidQrException>(() => c.StartAsync(new QrStartRequest { Qr = Tok, Attributes = a }));
            Assert.Equal(EidQrErrorCodes.AttributesInvalid, ex.Code);
        }
        ex = await Assert.ThrowsAsync<EidQrException>(() => c.StartAsync(new QrStartRequest { Qr = "hello", Attributes = new[] { "phone" } }));
        Assert.Equal(EidQrErrorCodes.FormatInvalid, ex.Code);
        Assert.Null(s.StartBody);
    }

    [Fact]
    public async Task ResultFailures()
    {
        var (s, c) = Client();
        var sess = await c.StartAsync(new QrStartRequest { Qr = Tok, Attributes = new[] { "age_over_18", "phone" } });
        var wait = TimeSpan.FromSeconds(2);
        s.End = "USER_REFUSED";
        var ex = await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(sess, wait));
        Assert.Equal((EidQrErrorCodes.SessionFailed, "USER_REFUSED"), (ex.Code, ex.EndResult));
        s.End = "OK";
        s.Mutate = p => p["aud"] = "other-rp";
        Assert.Equal(EidQrErrorCodes.PresentationInvalid, (await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(sess, wait))).Code);
        s.Mutate = p => p["attrs"] = new JsonObject { ["age_over_18"] = true, ["civil_id"] = "1" };
        Assert.Equal(EidQrErrorCodes.PresentationInvalid, (await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(sess, wait))).Code);
        s.Mutate = null;
        var replay = new QrSession { SessionId = sess.SessionId, Nonce = "replayed", Attributes = sess.Attributes };
        Assert.Equal(EidQrErrorCodes.PresentationInvalid, (await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(replay, wait))).Code);
        s.End = "TIMEOUT";
        ex = await Assert.ThrowsAsync<EidQrException>(() => c.CheckAsync(sess));
        Assert.Equal((EidQrErrorCodes.SessionFailed, "TIMEOUT"), (ex.Code, ex.EndResult));
        s.End = "OK";
        s.State = "RUNNING";
        Assert.Equal(EidQrErrorCodes.Pending, (await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(sess, TimeSpan.FromSeconds(1)))).Code);
        Assert.Equal(new QrCheck(false, null), await c.CheckAsync(sess));
        s.State = "COMPLETE";
        var done = await c.CheckAsync(sess);
        Assert.True(done.Complete);
        Assert.True(done.Presentation!.Attrs.AgeOver18);
    }

    [Theory]
    [InlineData("https://ca.test/missing")]
    [InlineData("http://example.com/jwks.json")]
    public async Task JwksUnavailable(string url)
    {
        var (_, c) = Client(url);
        var sess = new QrSession { SessionId = "s", Nonce = "n", Attributes = new[] { "age_over_18" } };
        var ex = await Assert.ThrowsAsync<EidQrException>(() => c.VerifyAsync("a.b.c", sess));
        Assert.Equal(EidQrErrorCodes.JwksUnavailable, ex.Code);
    }
}
