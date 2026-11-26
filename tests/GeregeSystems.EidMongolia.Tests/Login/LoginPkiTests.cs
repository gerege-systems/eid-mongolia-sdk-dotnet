using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// OK зам БОДИТ гинж ба гарын үсгээр: conformance корпусын rp-validate векторууд (test PKI 01 → 02 → 04, leaf-auth,
/// RSA-PSS ACSP_V2) ба OCSP replay-ийг handler-ээр дамжуулна — validator, OCSP checker, OnSuccess, нэг удаагийн амжилт.
/// </summary>
public class LoginPkiTests
{
    private const string RpValidate = "rp-validate/cases.json";
    private const string Sid = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
    private const string CallbackUrl = "https://rp.conformance.test/auth/eid/callback";

    private sealed class Env
    {
        public required EidLoginHandler H { get; init; }

        public required CaseUpstream Upstream { get; init; }

        public required ReplayHandler Ocsp { get; init; }

        public required List<EidLoginIdentity> IdsSource { get; init; }

        public required List<EidLoginEvent> EventsSource { get; init; }

        public async Task<EidLoginResponse> Do(string method, string url, string? body = null, string? cookie = null)
        {
            var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (body is not null)
            {
                h["Content-Type"] = "application/json";
            }
            if (cookie is not null)
            {
                h["Cookie"] = cookie;
            }
            return await H.HandleAsync(new EidLoginRequest { Method = method, Url = url, Headers = h, Body = body });
        }
    }

    /// <summary>rp-validate кейсийн ACSP-ийг handler яг давтахаар client-ийг тохируулна (rpChallenge, нэр, interactions).</summary>
    private static Env Create(string caseName, string ocspCase, RevocationMode mode = RevocationMode.HardFail)
    {
        var f = Corpus.Json(RpValidate);
        var c = Corpus.Case(RpValidate, caseName);
        var acsp = c.GetProperty("acsp");
        var clock = new ManualClock(Corpus.Time(c.GetProperty("now").GetString()!));
        var upstream = new CaseUpstream(c.GetProperty("session").GetRawText());
        var client = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp-api.conformance.test",
            Credentials = new EidCredentials("00000000-0000-4000-8000-000000000001", Corpus.Str(acsp, "relyingPartyName"), "rp_sk_conformance_test"),
            Trust = Corpus.Trust(f.GetProperty("trust").GetProperty(c.GetProperty("trust").GetString()!)),
            TimeProvider = clock,
        }, new HttpClient(upstream));
        var rpChallenge = Corpus.Str(acsp, "rpChallenge");
        client.NewChallenge = () => rpChallenge;
        var interactions = JsonNode.Parse(Convert.FromBase64String(Corpus.Str(acsp, "interactions")))!.AsArray();
        var ocsp = new ReplayHandler(Corpus.Case("ocsp/cases.json", ocspCase).GetProperty("http"));
        var ids = new List<EidLoginIdentity>();
        var events = new List<EidLoginEvent>();
        var h = new EidLoginHandler(new EidLoginOptions
        {
            Client = client,
            CallbackUrl = CallbackUrl,
            CookieName = "eid_login",
            FailureRedirect = "/login",
            DisplayText = (string)interactions[0]!["displayText60"]!,
            TimeProvider = clock,
            DisablePushFloor = true,
            Revocation = new OcspRevocationChecker(new OcspOptions { HttpClient = new HttpClient(ocsp), TimeProvider = clock }).Checker,
            RevocationMode = mode,
            OnSuccess = (id, _, _) =>
            {
                ids.Add(id);
                return Task.FromResult<EidLoginSuccess?>(new EidLoginSuccess { Redirect = "/dashboard" });
            },
            OnEvent = (ev, _) =>
            {
                events.Add(ev);
                return Task.CompletedTask;
            },
        });
        // Handler-ийн interactions нь векторынхтой байт-ижил (ACSP_V2 payload-д ордог).
        Assert.Equal(Corpus.Str(acsp, "interactions"), EidCrypto.InteractionsToBase64(h.Interactions));
        return new Env { H = h, Upstream = upstream, Ocsp = ocsp, IdsSource = ids, EventsSource = events };
    }

    [Fact]
    public async Task QrOkWithRealChainSignatureAndOcspGood()
    {
        var e = Create("auth-pss-sha512-qr", "good");
        var start = await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}");
        Assert.Equal(200, start.Status);
        var cookie = Cookie(start);
        // Хүсэлтийн ACSP нь векторын acsp-тэй ижил.
        var acsp = Corpus.Case(RpValidate, "auth-pss-sha512-qr").GetProperty("acsp");
        var sent = e.Upstream.LastStart!;
        Assert.Equal(Corpus.Str(acsp, "rpChallenge"), (string?)sent["signatureProtocolParameters"]!["rpChallenge"]);
        Assert.Equal(Corpus.Str(acsp, "interactions"), (string?)sent["interactions"]);
        Assert.False(sent.ContainsKey("initialCallbackUrl"));

        var ok = await e.Do("GET", "/auth/eid/status", cookie: cookie);
        var body = JsonNode.Parse(ok.Body)!.AsObject();
        Assert.True((string?)body["state"] == "OK", ok.Body + " " + string.Join(",", e.EventsSource.Select(x => x.Kind + ":" + JsonSerializer.Serialize(x.Meta))));
        Assert.Equal("/dashboard", (string?)body["redirect"]);
        var id = Assert.Single(e.IdsSource);
        var expect = Corpus.Case(RpValidate, "auth-pss-sha512-qr").GetProperty("expect").GetProperty("ok");
        Assert.Equal("PNOMN-999999990001", id.Etsi);
        Assert.Equal("999999990001", id.CivilId);
        Assert.Equal("TEST", id.GivenName);
        Assert.Equal("TESTOV", id.Surname);
        Assert.Equal("MN", id.Country);
        Assert.Equal(Corpus.Str(expect, "documentNumber"), id.DocumentNumber);
        Assert.Equal(Corpus.Str(expect, "certificateLevel"), id.CertificateLevel);
        Assert.Equal(Corpus.Str(expect, "certificateSha256"), Corpus.Sha256Hex(id.Certificate.RawData));
        Assert.Equal(FlowTypes.Qr, id.FlowType);
        Assert.Equal(RevocationStatus.Good, id.Revocation);
        Assert.Equal(Sid, id.SessionId);
        Assert.Null(id.Person);
        Assert.Equal(1, e.Ocsp.Calls);
        var last = e.EventsSource[^1];
        Assert.Equal(EidLoginEventKinds.Success, last.Kind);
        Assert.Equal("good", last.Meta["revocation"]);
        Assert.Equal("QR", last.Meta["flow"]);

        // Replay: дууссан оролдлого дахин амжилт гаргахгүй.
        var again = await e.Do("GET", "/auth/eid/status", cookie: cookie);
        Assert.Equal("EXPIRED", (string?)JsonNode.Parse(again.Body)!["state"]);
        Assert.Single(e.IdsSource);
    }

    public static IEnumerable<object[]> RevocationFailures() => new[]
    {
        new object[] { "revoked", "revoked" },
        new object[] { "unknown-is-revoked", "revoked" },
        new object[] { "stale-49h", "revocation_unavailable" },
        new object[] { "wrong-serial", "revocation_unavailable" },
    };

    [Theory]
    [MemberData(nameof(RevocationFailures))]
    public async Task QrRevokedOrUnknownIsValidationFailure(string ocspCase, string reason)
    {
        var e = Create("auth-pss-sha512-qr", ocspCase);
        var cookie = Cookie(await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}"));
        var r = await e.Do("GET", "/auth/eid/status", cookie: cookie);
        var body = JsonNode.Parse(r.Body)!.AsObject();
        Assert.Equal("FAILED", (string?)body["state"]);
        Assert.Equal("VALIDATION", (string?)body["error"]);
        Assert.Empty(e.IdsSource);
        var last = e.EventsSource[^1];
        Assert.Equal(EidLoginEventKinds.Unverified, last.Kind);
        Assert.Equal(reason, last.Meta["reason"]);
    }

    [Fact]
    public async Task QrUnknownOcspSoftFailIsUnchecked()
    {
        var e = Create("auth-pss-sha512-qr", "stale-49h", RevocationMode.SoftFail);
        var cookie = Cookie(await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}"));
        var r = await e.Do("GET", "/auth/eid/status", cookie: cookie);
        Assert.Equal("OK", (string?)JsonNode.Parse(r.Body)!["state"]);
        Assert.Equal(RevocationStatus.Unchecked, Assert.Single(e.IdsSource).Revocation);
    }

    [Fact]
    public async Task Web2AppOkWithRealSignatureAndVerifier()
    {
        const string caseName = "auth-web2app-verifier";
        var c = Corpus.Case(RpValidate, caseName);
        var verifier = Corpus.Str(c.GetProperty("options"), "userChallengeVerifier");
        var e = Create(caseName, "good");
        var start = await e.Do("GET", "/auth/eid/start?mode=web2app");
        Assert.Equal(302, start.Status);
        Assert.StartsWith("https://eid.conformance.test/dl?deviceLinkType=Web2App&", start.Header("Location"));
        Assert.Equal(CallbackUrl, (string?)e.Upstream.LastStart!["initialCallbackUrl"]);
        var cookie = Cookie(start);

        var wait = await e.Do("GET", "/auth/eid/status", cookie: cookie);
        Assert.Equal("WAIT_CALLBACK", (string?)JsonNode.Parse(wait.Body)!["state"]);
        Assert.Empty(e.IdsSource);

        var cb = "/auth/eid/callback?sessionId=" + Sid + "&userChallengeVerifier=" + verifier;
        // Буруу verifier → VALIDATION, оролдлого устна.
        var wrong = Create(caseName, "good");
        var wc = Cookie(await wrong.Do("GET", "/auth/eid/start?mode=web2app"));
        var bad = await wrong.Do("GET", cb.Replace(verifier, verifier[..^1] + (verifier[^1] == 'A' ? "B" : "A")), cookie: wc);
        Assert.Equal("/login?eid_error=VALIDATION", bad.Header("Location"));
        Assert.Empty(wrong.IdsSource);

        var ok = await e.Do("GET", cb, cookie: cookie);
        Assert.Equal(303, ok.Status);
        Assert.Equal("/dashboard", ok.Header("Location"));
        Assert.Contains(ok.HeaderValues("Set-Cookie"), v => v.StartsWith("eid_login=;", StringComparison.Ordinal));
        var id = Assert.Single(e.IdsSource);
        Assert.Equal(FlowTypes.Web2App, id.FlowType);
        Assert.Equal(RevocationStatus.Good, id.Revocation);
        var replay = await e.Do("GET", cb, cookie: cookie);
        Assert.Equal("/login?eid_error=expired", replay.Header("Location"));
        Assert.Single(e.IdsSource);
    }

    private static string Cookie(EidLoginResponse r)
    {
        var c = r.HeaderValues("Set-Cookie").Single(x => x.StartsWith("eid_login=", StringComparison.Ordinal));
        Assert.Contains("; HttpOnly", c);
        Assert.Contains("; Secure", c);
        Assert.Contains("; SameSite=Lax", c);
        return c.Split(';')[0];
    }

    /// <summary>Fake RP-API: device-link start → тогтмол session; GET /session/{Sid} → кейсийн session JSON.</summary>
    private sealed class CaseUpstream : HttpMessageHandler
    {
        private readonly string _session;

        public CaseUpstream(string session) => _session = session;

        public JsonObject? LastStart { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/authentication/device-link/anonymous")
            {
                LastStart = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
                return Json(new JsonObject
                {
                    ["sessionID"] = Sid,
                    ["sessionToken"] = "tok_Conformance-0001",
                    ["sessionSecret"] = Convert.ToBase64String(new byte[32]),
                    ["deviceLinkBase"] = "https://eid.conformance.test/dl",
                    ["vc"] = "12345",
                }.ToJsonString());
            }
            if (path == "/session/" + Sid)
            {
                return Json(_session);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{\"error\":\"not found\"}", Encoding.UTF8, "application/json") };
        }

        private static HttpResponseMessage Json(string body) =>
            new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
}
