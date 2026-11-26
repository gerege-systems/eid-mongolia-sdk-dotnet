using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// Cross-SDK conformance корпус (rp-conformance/1): Go reference-ийн <c>testdata/conformance</c>-ийн байт-ижил хуулбар
/// (<c>build/sync-conformance.sh</c>, CI <c>conformance-sync</c>). Формат: <c>testdata/conformance/README.md</c>.
/// </summary>
internal static class Corpus
{
    public static string Dir => Path.Combine(AppContext.BaseDirectory, "testdata", "conformance");

    public static byte[] Bytes(string rel) => File.ReadAllBytes(Path.Combine(Dir, rel));

    public static string Text(string rel) => Encoding.UTF8.GetString(Bytes(rel));

    public static JsonElement Json(string rel)
    {
        using var d = JsonDocument.Parse(Bytes(rel));
        return d.RootElement.Clone();
    }

    public static X509Certificate2 Cert(string rel) => X509Loader.Load(ParsedCert.ParsePem(Text(rel))[0].Raw);

    public static IEnumerable<object[]> Names(string rel) =>
        Json(rel).GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("name").GetString()! });

    public static JsonElement Case(string rel, string name) =>
        Json(rel).GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);

    /// <summary>Объектын мөр талбар; алга / мөр биш бол "".</summary>
    public static string Str(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    /// <summary>Объектын мөр талбар; алга бол null ("" ба алга ялгагдана).</summary>
    public static string? Opt(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static DateTimeOffset Time(string s) => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    public static string Sha256Hex(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    /// <summary>rp-validate-ийн trust профайл → <see cref="TrustConfig"/> (README §rp-validate Trust).</summary>
    public static TrustConfig Trust(JsonElement tr)
    {
        List<string> Pems(string key) => tr.GetProperty(key).EnumerateArray().Select(p => Text(p.GetString()!)).ToList();
        return new TrustConfig
        {
            TrustAnchorsPem = Pems("anchors"),
            IntermediatesPem = Pems("intermediates"),
            AllowedIssuerSkis = tr.TryGetProperty("allowedIssuerSkis", out var s) ? s.EnumerateArray().Select(x => x.GetString()!).ToList() : null,
            RequiredLevel = Opt(tr, "requiredLevel"),
            ClockSkew = TimeSpan.FromSeconds(tr.TryGetProperty("clockSkewSeconds", out var cs) ? cs.GetInt32() : 0),
        };
    }
}

/// <summary>OCSP HTTP replay: түлхүүр «METHOD URL» (AIA-ийн URL яг хэвээр), жагсаалтад байхгүй → 404.</summary>
internal sealed class ReplayHandler : HttpMessageHandler
{
    private readonly JsonElement _http;
    private int _calls;

    public ReplayHandler(JsonElement http) => _http = http;

    public int Calls => Volatile.Read(ref _calls);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        var key = request.Method.Method + " " + request.RequestUri!.OriginalString;
        HttpResponseMessage res;
        if (_http.ValueKind == JsonValueKind.Object && _http.TryGetProperty(key, out var rep))
        {
            res = new HttpResponseMessage((HttpStatusCode)rep.GetProperty("status").GetInt32())
            {
                Content = new ByteArrayContent(Convert.FromBase64String(Corpus.Str(rep, "bodyB64"))),
            };
            if (Corpus.Str(rep, "contentType") is { Length: > 0 } t)
            {
                res.Content.Headers.TryAddWithoutValidation("Content-Type", t);
            }
        }
        else
        {
            res = new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new ByteArrayContent(Array.Empty<byte>()) };
        }
        return Task.FromResult(res);
    }
}

public class ConformanceTests
{
    private const string RpValidate = "rp-validate/cases.json";
    private const string WireFile = "wire/cases.json";
    private const string OcspFile = "ocsp/cases.json";

    [Fact]
    public void Manifest()
    {
        var m = Corpus.Json("manifest.json");
        Assert.Equal("rp-conformance/1", m.GetProperty("version").GetString());
        var files = m.GetProperty("files").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!, StringComparer.Ordinal);
        Assert.NotEmpty(files);
        foreach (var (rel, sum) in files)
        {
            Assert.True(Corpus.Sha256Hex(Corpus.Bytes(rel)) == sum, rel + ": sha256 manifest-тэй зөрөв");
        }
        // Хуулбар = manifest-ийн файлууд + manifest.json (илүү файлгүй, pki/keys-гүй).
        var onDisk = Directory.EnumerateFiles(Corpus.Dir, "*", SearchOption.AllDirectories)
            .Select(p => Path.GetRelativePath(Corpus.Dir, p).Replace('\\', '/'))
            .OrderBy(x => x, StringComparer.Ordinal).ToList();
        var want = files.Keys.Append("manifest.json").OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.Equal(want, onDisk);
        // CA-ийн frozen файлуудын pin (README: devicelink_golden.json / myqr_vectors.json-ийг copy-доо тулгана).
        foreach (var (pin, file) in new[] { ("devicelinkGolden", "devicelink_golden.json"), ("myqrVectors", "myqr_vectors.json") })
        {
            var b = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "testdata", file));
            Assert.Equal(m.GetProperty(pin).GetProperty("sha256").GetString(), Corpus.Sha256Hex(b));
        }
    }

    [Fact]
    public void CaseCounts()
    {
        // Корпус чимээгүй багасвал улаан (README: rp-validate 77, wire 26, OCSP 17).
        Assert.Equal(77, Corpus.Names(RpValidate).Count());
        Assert.Equal(26, Corpus.Names(WireFile).Count());
        Assert.Equal(17, Corpus.Names(OcspFile).Count());
    }

    // ── interactions / acsp ──

    [Fact]
    public void InteractionsGolden()
    {
        foreach (var c in Corpus.Json("interactions_golden.json").GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString();
            var list = c.GetProperty("interactions").Deserialize<Interaction[]>(EidHttp.Json)!;
            var json = c.GetProperty("json").GetString()!;
            var b64 = c.GetProperty("base64").GetString()!;
            Assert.True(JsJson.Interactions(list) == json, name + ": JSON зөрөв");
            Assert.True(EidCrypto.InteractionsToBase64(list) == b64, name + ": base64 зөрөв");
            Assert.Equal(json, Encoding.UTF8.GetString(Convert.FromBase64String(b64)));
        }
    }

    [Fact]
    public void AcspV2()
    {
        foreach (var c in Corpus.Json("acsp_v2.json").GetProperty("cases").EnumerateArray())
        {
            var p = c.GetProperty("params");
            var prm = new AcspV2Params
            {
                SchemeName = Corpus.Str(p, "schemeName"),
                ServerRandom = Corpus.Str(p, "serverRandom"),
                RpChallenge = Corpus.Str(p, "rpChallenge"),
                UserChallenge = Corpus.Str(p, "userChallenge"),
                RelyingPartyName = Corpus.Str(p, "relyingPartyName"),
                BrokeredRpName = Corpus.Str(p, "brokeredRpName"),
                Interactions = Corpus.Str(p, "interactions"),
                InteractionTypeUsed = Corpus.Str(p, "interactionTypeUsed"),
                InitialCallbackUrl = Corpus.Str(p, "initialCallbackUrl"),
                FlowType = Corpus.Str(p, "flowType"),
            };
            var name = c.GetProperty("name").GetString();
            Assert.True(Encoding.UTF8.GetString(Acsp.BuildV2Payload(prm)) == c.GetProperty("payload").GetString(), name + ": payload");
            Assert.True(Convert.ToBase64String(Acsp.V2Digest(prm, c.GetProperty("hashAlgorithm").GetString()!)) == c.GetProperty("digestB64").GetString(),
                name + ": digest");
        }
    }

    // ── rp-validate ──

    public static IEnumerable<object[]> RpValidateNames() => Corpus.Names(RpValidate);

    [Theory]
    [MemberData(nameof(RpValidateNames))]
    public void RpValidateCase(string name)
    {
        var f = Corpus.Json(RpValidate);
        var c = Corpus.Case(RpValidate, name);
        var v = new ResponseValidator(Corpus.Trust(f.GetProperty("trust").GetProperty(c.GetProperty("trust").GetString()!)),
            new ManualClock(Corpus.Time(c.GetProperty("now").GetString()!)));
        var r = SessionService.ParseSessionResult(c.GetProperty("session").GetRawText());
        var o = c.TryGetProperty("options", out var oo) ? oo : default;
        X509Certificate2? cert = null;
        CertSubject? subject = null;
        string doc = "", level = "", alg = "";
        Exception? err = null;
        try
        {
            switch (c.GetProperty("kind").GetString())
            {
                case "auth":
                    {
                        var acsp = c.GetProperty("acsp").Deserialize<AcspContext>(EidHttp.Json)!;
                        var id = v.ValidateAuth(r, acsp, new ValidateAuthOptions
                        {
                            ExpectedFlowType = Corpus.Opt(o, "expectedFlowType"),
                            UserChallengeVerifier = Corpus.Opt(o, "userChallengeVerifier"),
                        });
                        (cert, subject, doc, level) = (id.Certificate, id.Subject, id.DocumentNumber, id.CertificateLevel);
                        break;
                    }
                case "sign":
                    {
                        var ec = Corpus.Opt(o, "expectedCertificate");
                        var vs = v.ValidateSign(r, c.GetProperty("digest").GetString()!, Corpus.Opt(c, "hashAlgorithm"), new ValidateSignOptions
                        {
                            ExpectedFlowType = Corpus.Opt(o, "expectedFlowType"),
                            ExpectedAlgorithm = Corpus.Opt(o, "expectedAlgorithm"),
                            ExpectedCertificate = ec is null ? null : X509Loader.Load(Convert.FromBase64String(ec)),
                        });
                        (cert, subject, doc, level, alg) = (vs.Certificate, vs.Subject, vs.DocumentNumber, vs.CertificateLevel, vs.SignatureAlgorithm);
                        break;
                    }
                case "certificateChoice":
                    {
                        var sessionId = Corpus.Opt(c, "certChoiceSessionId");
                        var s = v.ValidateCertificateChoice(r, sessionId);
                        (cert, subject, doc, level) = (s.Certificate, s.Subject, s.DocumentNumber, s.CertificateLevel);
                        Assert.Equal(sessionId, s.CertChoiceSessionId);
                        Assert.Equal(Convert.ToBase64String(s.Certificate.RawData), s.CertificateDerB64);
                        SignerRef sr = s;
                        Assert.Equal(new SignerRef(s.DocumentNumber, sessionId), sr);
                        break;
                    }
                default:
                    throw new InvalidOperationException("kind " + c.GetProperty("kind").GetString());
            }
        }
        catch (EidException e)
        {
            err = e;
        }

        var exp = c.GetProperty("expect");
        if (exp.TryGetProperty("error", out var ee))
        {
            var want = Corpus.Str(ee, "class") == "SessionFailedError"
                ? "SessionFailedError endResult=" + Corpus.Str(ee, "endResult")
                : "ValidationError reason=" + Corpus.Str(ee, "reason");
            var got = err switch
            {
                null => "амжилттай",
                EidSessionFailedException sf => "SessionFailedError endResult=" + sf.EndResult,
                EidValidationException ve => "ValidationError reason=" + ve.Reason,
                _ => "? " + err.GetType().Name,
            };
            Assert.True(want == got, name + ": " + got + " ≠ хүлээсэн " + want + " (" + err?.Message + ")");
            return;
        }
        Assert.True(err is null, name + ": амжилт хүлээсэн — " + err?.Message);
        var ok = exp.GetProperty("ok");
        Assert.Equal(Corpus.Str(ok, "documentNumber"), doc);
        Assert.Equal(Corpus.Str(ok, "certificateLevel"), level);
        Assert.Equal(Corpus.Str(ok, "certificateSha256"), Corpus.Sha256Hex(cert!.RawData));
        Assert.Equal(Corpus.Str(ok, "signatureAlgorithm"), alg);
        var es = ok.GetProperty("subject");
        Assert.Equal(
            new[] { Corpus.Str(es, "serialNumber"), Corpus.Str(es, "givenName"), Corpus.Str(es, "surname"), Corpus.Str(es, "country"), Corpus.Str(es, "commonName") },
            new[] { subject!.SerialNumber, subject.GivenName, subject.Surname, subject.Country, subject.CommonName });
        Assert.Equal(subject, ResponseValidator.ParseSubject(cert));
    }

    // ── OCSP ──

    public static IEnumerable<object[]> OcspNames() => Corpus.Names(OcspFile);

    [Theory]
    [MemberData(nameof(OcspNames))]
    public async Task OcspCase(string name)
    {
        var c = Corpus.Case(OcspFile, name);
        var handler = new ReplayHandler(c.TryGetProperty("http", out var h) ? h : default);
        using var http = new HttpClient(handler);
        var checker = new OcspRevocationChecker(new OcspOptions
        {
            HttpClient = http,
            TimeProvider = new ManualClock(Corpus.Time(c.GetProperty("now").GetString()!)),
        });
        using var cert = Corpus.Cert(c.GetProperty("certificate").GetString()!);
        using var issuer = Corpus.Cert(c.GetProperty("issuer").GetString()!);
        string status, kind = "", detail = "";
        try
        {
            status = (await checker.CheckAsync(cert, issuer)).ToString().ToLowerInvariant();
        }
        catch (EidOcspException e)
        {
            (status, kind, detail) = ("unknown", e.Kind, e.Message);
        }
        var exp = c.GetProperty("expect");
        Assert.True(Corpus.Str(exp, "status") == status, name + ": status " + status + " ≠ " + Corpus.Str(exp, "status") + " (" + detail + ")");
        Assert.True(Corpus.Str(exp, "errorKind") == kind, name + ": errorKind " + kind + " ≠ " + Corpus.Str(exp, "errorKind") + " (" + detail + ")");
    }

    // ── wire ──

    public static IEnumerable<object[]> WireNames() => Corpus.Names(WireFile);

    [Theory]
    [MemberData(nameof(WireNames))]
    public async Task Wire(string name)
    {
        var cl = Corpus.Json(WireFile).GetProperty("client");
        var c = Corpus.Case(WireFile, name);
        var resp = c.GetProperty("response");
        var hdrs = resp.TryGetProperty("headers", out var rh) ? rh : default;
        var rec = new Recorder(_ => Rig.Json(resp.GetProperty("status").GetInt32(), resp.GetProperty("body").GetRawText(), Corpus.Opt(hdrs, "Retry-After")));
        using var client = new EidClient(new EidClientOptions
        {
            BaseUrl = Corpus.Str(cl, "baseUrl"),
            Credentials = new EidCredentials(Corpus.Str(cl, "rpUUID"), Corpus.Str(cl, "rpName"), Corpus.Str(cl, "apiSecret")),
            DefaultCertificateLevel = Corpus.Str(cl, "defaultCertificateLevel"),
        }, new HttpClient(rec));
        JsonNode got;
        try
        {
            var hasExp = resp.GetProperty("body").ValueKind == JsonValueKind.Object && resp.GetProperty("body").TryGetProperty("expiresAt", out _);
            got = WireResult(await Invoke(client, c.GetProperty("call")), hasExp);
        }
        catch (EidException e) when (e is EidApiException or EidAuthenticationException or EidForbiddenException)
        {
            got = new JsonObject { ["error"] = ErrJson(e) };
        }

        var req = c.GetProperty("request");
        var r = Assert.Single(rec.Requests);
        Assert.Equal(req.GetProperty("method").GetString(), r.Method);
        Assert.Equal(req.GetProperty("path").GetString(), r.PathAndQuery);
        foreach (var hp in req.GetProperty("headers").EnumerateObject())
        {
            var hv = hp.Name switch
            {
                "Content-Type" => r.Request.Content?.Headers.ContentType?.MediaType,
                "Authorization" => r.Request.Headers.Authorization?.ToString(),
                _ => r.Request.Headers.TryGetValues(hp.Name, out var vs) ? string.Join(",", vs) : null,
            };
            Assert.True(hp.Value.GetString() == hv, name + ": header " + hp.Name + " = " + hv);
        }
        var sent = r.Body is null ? null : JsonNode.Parse(r.Body);
        if (!req.TryGetProperty("body", out var wantBody))
        {
            Assert.Null(r.Body);
        }
        else
        {
            var body = sent?.DeepClone();
            if (req.TryGetProperty("volatile", out var vol))
            {
                foreach (var vp in vol.EnumerateObject())
                {
                    Assert.Equal("base64:64", vp.Value.GetString());
                    var val = Pointer(body, vp.Name)?.GetValue<string>() ?? "";
                    Assert.True(B64.TryDecodeStd(val, out var raw) && raw.Length == 64, name + ": volatile " + vp.Name + " = " + val);
                    SetPointer(body!, vp.Name, "$volatile");
                }
            }
            JsonAssert.Equivalent(wantBody.GetRawText(), Element(body), name + ": хүсэлтийн бие");
        }
        var want = JsonNode.Parse(c.GetProperty("expect").GetRawText())!;
        Resolve(want, sent);
        JsonAssert.Equivalent(want.ToJsonString(), Element(got), name + ": үр дүн");
    }

    private static JsonElement Element(JsonNode? n)
    {
        using var d = JsonDocument.Parse(n?.ToJsonString() ?? "null");
        return d.RootElement.Clone();
    }

    private static JsonNode? Pointer(JsonNode? root, string ptr)
    {
        var cur = root;
        foreach (var k in ptr.TrimStart('/').Split('/'))
        {
            cur = cur is JsonObject o && o.TryGetPropertyValue(k, out var next) ? next : null;
        }
        return cur;
    }

    private static void SetPointer(JsonNode root, string ptr, string value)
    {
        var parts = ptr.TrimStart('/').Split('/');
        var parent = parts.Length == 1 ? root.AsObject() : Pointer(root, "/" + string.Join("/", parts[..^1]))!.AsObject();
        parent[parts[^1]] = value;
    }

    /// <summary>expect доторх "$request:&lt;ptr&gt;" утгыг бодит хүсэлтийн биеэс орлуулна.</summary>
    private static void Resolve(JsonNode node, JsonNode? sent)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var k in o.Select(p => p.Key).ToList())
                {
                    if (o[k] is JsonValue v && v.TryGetValue<string>(out var s) && s.StartsWith("$request:", StringComparison.Ordinal))
                    {
                        o[k] = Pointer(sent, s["$request:".Length..])?.DeepClone();
                    }
                    else if (o[k] is { } child)
                    {
                        Resolve(child, sent);
                    }
                }
                break;
            case JsonArray a:
                foreach (var child in a)
                {
                    if (child is not null)
                    {
                        Resolve(child, sent);
                    }
                }
                break;
        }
    }

    private static async Task<object> Invoke(EidClient c, JsonElement call)
    {
        var a = call.GetProperty("args");
        string S(string k) => a.GetProperty(k).GetString()!;
        Interaction[]? Ix() => a.TryGetProperty("interactions", out var v) ? v.Deserialize<Interaction[]>(EidHttp.Json) : null;
        T? Opt<T>() where T : class => a.TryGetProperty("options", out var v) ? v.Deserialize<T>(EidHttp.Json) : null;
        SignerRef SignerArg() => a.GetProperty("signer").Deserialize<SignerRef>(EidHttp.Json)!;
        var m = call.GetProperty("method").GetString();
        return m switch
        {
            "auth.notificationByEtsi" => await c.Auth.NotificationByEtsiAsync(S("id"), Ix(), Opt<AuthOptions>()),
            "auth.notificationByDocument" => await c.Auth.NotificationByDocumentAsync(S("documentNumber"), Ix(), Opt<AuthOptions>()),
            "auth.deviceLinkAnonymous" => await c.Auth.DeviceLinkAnonymousAsync(Ix(), Opt<AuthOptions>()),
            "auth.deviceLinkByEtsi" => await c.Auth.DeviceLinkByEtsiAsync(S("id"), Ix(), Opt<AuthOptions>()),
            "sign.digestByEtsi" => await c.Sign.DigestByEtsiAsync(S("id"), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.digestByDocument" => await c.Sign.DigestByDocumentAsync(S("documentNumber"), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.textByEtsi" => await c.Sign.TextByEtsiAsync(S("id"), S("text"), Ix(), Opt<SignOptions>()),
            "sign.deviceLinkByEtsi" => await c.Sign.DeviceLinkByEtsiAsync(S("id"), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.deviceLinkByDocument" => await c.Sign.DeviceLinkByDocumentAsync(S("documentNumber"), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.digestForSigner" => await c.Sign.DigestForSignerAsync(SignerArg(), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.deviceLinkForSigner" => await c.Sign.DeviceLinkForSignerAsync(SignerArg(), S("digest"), Ix(), Opt<SignOptions>()),
            "sign.certificateChoiceByEtsi" => await c.Sign.CertificateChoiceByEtsiAsync(S("id"), Opt<CertChoiceOptions>()),
            "sign.certificateChoiceDeviceLink" => await c.Sign.CertificateChoiceDeviceLinkAsync(Opt<CertChoiceOptions>()),
            "session.poll" => await c.Session.PollAsync(S("sessionId"), TimeSpan.FromMilliseconds(a.GetProperty("serverPollMs").GetInt32())),
            _ => throw new InvalidOperationException("wire: үл мэдэх method " + m),
        };
    }

    private static JsonNode? Ns(string? v) => string.IsNullOrEmpty(v) ? null : JsonValue.Create(v);

    private static JsonNode? Ctx<T>(T? v) where T : class => v is null ? null : JsonSerializer.SerializeToNode(v, EidHttp.Json);

    private static JsonObject Start(string sessionId, string vc, string rpChallenge, AcspContext? acsp, SignContext? sign,
        DateTimeOffset? expiresAt, bool hasExp)
    {
        var o = new JsonObject
        {
            ["sessionId"] = sessionId,
            ["vc"] = vc,
            ["rpChallenge"] = rpChallenge,
            ["acsp"] = Ctx(acsp),
            ["sign"] = Ctx(sign),
        };
        if (hasExp)
        {
            o["expiresAt"] = expiresAt?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }
        return o;
    }

    private static JsonNode WireResult(object res, bool hasExp)
    {
        switch (res)
        {
            case SessionResult s:
                return new JsonObject { ["type"] = "session", ["session"] = SessionJson(s) };
            case NotificationSession n:
                {
                    var o = Start(n.SessionId, n.Vc, n.RpChallenge, n.Acsp, n.Sign, n.ExpiresAt, hasExp);
                    o["type"] = "notification";
                    return o;
                }
            case DeviceLinkSession d:
                {
                    var o = Start(d.SessionId, d.Vc, d.RpChallenge, d.Acsp, d.Sign, d.ExpiresAt, hasExp);
                    o["type"] = "deviceLink";
                    o["sessionToken"] = d.SessionToken;
                    o["sessionSecret"] = d.SessionSecret;
                    o["deviceLinkBase"] = d.DeviceLinkBase;
                    o["sessionType"] = d.SessionType;
                    if (d.SessionType == DeviceLinkSessionTypes.Cert)
                    {
                        o["relyingPartyName"] = d.RelyingPartyName;
                        o["callbackUrl"] = d.CallbackUrl ?? "";
                    }
                    return o;
                }
            default:
                throw new InvalidOperationException("wire: үл мэдэх үр дүн " + res.GetType().Name);
        }
    }

    /// <summary>README §wire «Parsed session».</summary>
    private static JsonObject SessionJson(SessionResult r)
    {
        JsonObject? prm = null;
        if (r.SignatureAlgorithmParameters is { HashAlgorithm.Length: > 0 } p)
        {
            prm = new JsonObject { ["hashAlgorithm"] = p.HashAlgorithm };
            if (p.SaltLength is { } salt)
            {
                prm["saltLength"] = salt;
            }
        }
        JsonObject? obo = null;
        if (r.OnBehalfOf is { OrgEtsi.Length: > 0 } ob)
        {
            obo = new JsonObject { ["orgEtsi"] = ob.OrgEtsi, ["orgName"] = Ns(ob.OrgName), ["role"] = Ns(ob.Role), ["rightType"] = Ns(ob.RightType) };
            if (!string.IsNullOrEmpty(ob.RoleLabel))
            {
                obo["roleLabel"] = ob.RoleLabel;
            }
            if (!string.IsNullOrEmpty(ob.RightTypeLabel))
            {
                obo["rightTypeLabel"] = ob.RightTypeLabel;
            }
        }
        JsonObject? person = null;
        if (r.Person is { } pp)
        {
            person = new JsonObject();
            foreach (var (k, v) in new[]
            {
                ("firstName", pp.FirstName), ("lastName", pp.LastName), ("familyName", pp.FamilyName), ("firstNameEn", pp.FirstNameEn),
                ("lastNameEn", pp.LastNameEn), ("civilId", pp.CivilId), ("regNo", pp.RegNo), ("birthDate", pp.BirthDate),
                ("gender", pp.Gender), ("nationality", pp.Nationality),
            })
            {
                if (!string.IsNullOrEmpty(v))
                {
                    person[k] = v;
                }
            }
            if (pp.GeId != 0)
            {
                person["geID"] = pp.GeId;
            }
            if (person.Count == 0)
            {
                person = null;
            }
        }
        JsonObject? tok = null;
        if (r.TokenCertificate is { Status.Length: > 0 } t)
        {
            tok = new JsonObject { ["status"] = t.Status };
            if (!string.IsNullOrEmpty(t.ErrorCode))
            {
                tok["errorCode"] = t.ErrorCode;
            }
            if (!string.IsNullOrEmpty(t.AuthSerialHex))
            {
                tok["authSerialHex"] = t.AuthSerialHex;
            }
            if (!string.IsNullOrEmpty(t.SignSerialHex))
            {
                tok["signSerialHex"] = t.SignSerialHex;
            }
        }
        return new JsonObject
        {
            ["state"] = r.State,
            ["endResult"] = Ns(r.EndResult),
            ["documentNumber"] = Ns(r.DocumentNumber),
            ["certificateDerB64"] = Ns(r.CertificateDerB64),
            ["certificateLevel"] = Ns(r.CertificateLevel),
            ["signatureValueB64"] = Ns(r.SignatureValueB64),
            ["signatureAlgorithm"] = Ns(r.SignatureAlgorithm),
            ["signatureProtocol"] = Ns(r.SignatureProtocol),
            ["serverRandom"] = Ns(r.ServerRandom),
            ["userChallenge"] = Ns(r.UserChallenge),
            ["flowType"] = Ns(r.FlowType),
            ["interactionTypeUsed"] = Ns(r.InteractionTypeUsed),
            ["initialCallbackUrl"] = r.InitialCallbackUrl,
            ["signatureAlgorithmParameters"] = prm,
            ["onBehalfOf"] = obo,
            ["person"] = person,
            ["tokenCertificate"] = tok,
        };
    }

    private static JsonObject ErrJson(EidException e)
    {
        var o = new JsonObject
        {
            ["class"] = e switch
            {
                EidForbiddenException => "ForbiddenError",
                EidAuthenticationException => "AuthenticationError",
                _ => "ApiError",
            },
            ["status"] = e.Status,
            ["code"] = e.Code ?? "",
        };
        if (e.RetryAfter is { } ra)
        {
            o["retryAfterSeconds"] = (int)Math.Round(ra.TotalSeconds);
        }
        return o;
    }
}
