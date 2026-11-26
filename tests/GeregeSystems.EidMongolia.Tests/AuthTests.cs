using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class AuthTests
{
    /// <summary>base64(<c>[{"type":"displayTextAndPIN","displayText60":"Нэвтрэх"}]</c>) — devicelink_golden.json eid-* векторуудын interactions.</summary>
    internal const string LoginInteractionsB64 = "W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6ItCd0Y3QstGC0YDRjdGFIn1d";

    internal static readonly Interaction[] Login = { new() { Type = "displayTextAndPIN", DisplayText60 = "Нэвтрэх" } };

    // Go client_test.go TestAuth_RequestBodyAndParse (1-р хэсэг).
    [Fact]
    public async Task NotificationByEtsiBodyAndParse()
    {
        var (c, h, _) = Rig.Create(200, "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"90177\"}}");
        var s = await c.Auth.NotificationByEtsiAsync("PNOMN-12345678", Login,
            new AuthOptions { CallbackUrl = " https://rp.test/cb ", OnBehalfOf = " NTRMN-6235972 " });
        var r = h.Last;
        Assert.Equal("POST", r.Method);
        Assert.Equal("/authentication/notification/etsi/PNOMN-12345678", r.Path);
        Assert.Equal("Bearer rp_sk_secret123", r.Request.Headers.Authorization!.ToString());
        Assert.Equal("application/json", r.Request.Content!.Headers.ContentType!.MediaType);
        JsonAssert.Equivalent("""
            {"relyingPartyUUID":"rp-uuid","relyingPartyName":"Гэрээний систем","certificateLevel":"QUALIFIED",
             "signatureProtocol":"ACSP_V2",
             "signatureProtocolParameters":{"rpChallenge":"Zml4ZWQtcnAtY2hhbGxlbmdlLWZvci13aXJlLXRlc3Rz","signatureAlgorithm":"rsassa-pss",
               "signatureAlgorithmParameters":{"hashAlgorithm":"SHA-512"}},
             "interactions":"W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6ItCd0Y3QstGC0YDRjdGFIn1d",
             "initialCallbackUrl":"https://rp.test/cb","onBehalfOf":"NTRMN-6235972"}
            """, r.Json());
        Assert.Equal("s1", s.SessionId);
        Assert.Equal("90177", s.Vc);
        Assert.Equal(Rig.Challenge, s.RpChallenge);
        Assert.Null(s.Sign);
        Assert.False(s.ExpiresAt.HasValue);
        var a = s.Acsp!;
        Assert.Equal(Rig.Challenge, a.RpChallenge);
        Assert.Equal("Гэрээний систем", a.RelyingPartyName);
        Assert.Equal("", a.BrokeredRpName);
        Assert.Equal(LoginInteractionsB64, a.Interactions);
        Assert.Equal("https://rp.test/cb", a.InitialCallbackUrl);
        Assert.Equal(new[] { FlowTypes.Notification, FlowTypes.App2App, FlowTypes.Web2App }, a.FlowTypes);
        Assert.Equal(SignatureAlgorithms.RsassaPss, a.SignatureAlgorithm);
        Assert.Equal(HashAlgorithms.Sha512, a.HashAlgorithm);
    }

    // Go client_test.go TestAuth_RequestBodyAndParse (2-р хэсэг): device link, сонголтгүй.
    [Fact]
    public async Task DeviceLinkAnonymousBodyAndParse()
    {
        var (c, h, clock) = Rig.Create(200,
            "{\"sessionID\":\"s2\",\"sessionToken\":\"t\",\"sessionSecret\":\"c2VjcmV0\",\"deviceLinkBase\":\"https://ca.eidmongolia.mn/dl\",\"vc\":\"04821\"}");
        var d = await c.Auth.DeviceLinkAnonymousAsync(null);
        var r = h.Last;
        Assert.Equal("/authentication/device-link/anonymous", r.Path);
        Assert.Equal("certificateLevel,interactions,relyingPartyName,relyingPartyUUID,signatureProtocol,signatureProtocolParameters", r.Keys());
        Assert.Equal("W10=", r.Json().GetProperty("interactions").GetString());
        Assert.Equal("04821", d.Vc);
        Assert.Equal("t", d.SessionToken);
        Assert.Equal("c2VjcmV0", d.SessionSecret);
        Assert.Equal("https://ca.eidmongolia.mn/dl", d.DeviceLinkBase);
        Assert.Equal(clock.Now, d.ReceivedAt);
        Assert.Equal(DeviceLinkSessionTypes.Auth, d.SessionType);
        Assert.Equal(new[] { FlowTypes.Qr }, d.Acsp!.FlowTypes);
        Assert.Equal("", d.Acsp.InitialCallbackUrl);
        Assert.False(d.ExpiresAt.HasValue);
    }

    [Fact]
    public async Task OptionsAndPaths()
    {
        var (c, h, _) = Rig.Create(200, "{\"sessionID\":\"s3\",\"vc\":\"1\"}");
        var o = new AuthOptions
        {
            CertificateLevel = CertificateLevels.Qscd,
            SignatureAlgorithm = SignatureAlgorithms.EcdsaWithSha256,
            HashAlgorithm = HashAlgorithms.Sha256,
        };
        var n = await c.Auth.NotificationByDocumentAsync("PNOMN-12345678-MOCK-Q", Login, o);
        Assert.Equal("/authentication/notification/document/PNOMN-12345678-MOCK-Q", h.Last.Path);
        var spp = h.Last.Json().GetProperty("signatureProtocolParameters");
        Assert.Equal("QSCD", h.Last.Json().GetProperty("certificateLevel").GetString());
        Assert.Equal("ecdsa-with-SHA256", spp.GetProperty("signatureAlgorithm").GetString());
        Assert.Equal("SHA-256", spp.GetProperty("signatureAlgorithmParameters").GetProperty("hashAlgorithm").GetString());
        Assert.Equal(HashAlgorithms.Sha256, n.Acsp!.HashAlgorithm);
        Assert.Equal("1", n.Vc);

        // Замын параметр: Uri.EscapeDataString (TS encodeURIComponent-тэй ойр; Go url.PathEscape-ээс ялгаатай — conformance шийднэ).
        await c.Auth.DeviceLinkByEtsiAsync("PNOMN-TEST 01/x", Login);
        Assert.Equal("/authentication/device-link/etsi/PNOMN-TEST%2001%2Fx", h.Last.Path);
    }

    [Fact]
    public async Task EmptyInteractionTextsAreOmitted()
    {
        // Go omitempty (TS нь "" гэж илгээдэг — мэдэгдэж буй зөрүү, conformance шийднэ).
        var (c, h, _) = Rig.Create(200, "{\"sessionID\":\"s\"}");
        var s = await c.Auth.NotificationByEtsiAsync("PNOMN-1", new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "", DisplayText200 = null } });
        Assert.Equal(EidCrypto.InteractionsToBase64(new[] { new Interaction { Type = "displayTextAndPIN" } }), s.Acsp!.Interactions);
        Assert.Equal("W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIn1d", h.Last.Json().GetProperty("interactions").GetString());
    }

    // Go session_start_test.go TestSessionStartCAExpiresAt / TestSessionStartExpiresAtFallback (auth хэсэг).
    [Theory]
    [InlineData("2026-10-14T14:10:00Z", "2026-10-14T14:10:00+00:00")]
    [InlineData("2026-10-14T22:10:00.5+08:00", "2026-10-14T14:10:00.5+00:00")]
    [InlineData("маргааш", null)]
    [InlineData("2026-10-14", null)]
    public async Task AuthExpiresAtFromCa(string caValue, string? want)
    {
        var (c, _, _) = Rig.Create(r => Rig.Json(200, r.Path.Contains("device-link", StringComparison.Ordinal)
            ? "{\"sessionID\":\"s\",\"sessionToken\":\"t\",\"sessionSecret\":\"AA==\",\"deviceLinkBase\":\"https://ca.eidmongolia.mn/dl\",\"vc\":\"1\",\"expiresAt\":\"" + caValue + "\"}"
            : "{\"sessionID\":\"s\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"54321\"},\"expiresAt\":\"" + caValue + "\"}"));
        DateTimeOffset? expected = want is null ? null : DateTimeOffset.Parse(want, System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(expected, (await c.Auth.NotificationByEtsiAsync("PNOMN-1", Login)).ExpiresAt);
        Assert.Equal(expected, (await c.Auth.DeviceLinkAnonymousAsync(Login)).ExpiresAt);
    }

    // Go client_test.go TestHTTPErrors (onBehalfOf 403) — auth талд.
    [Fact]
    public async Task ForbiddenOnBehalfOf()
    {
        var (c, _, _) = Rig.Create(403, "{\"error\":\"төлөөлөх эрхгүй\",\"code\":\"REPRESENTATION_DENIED\"}");
        var e = await Assert.ThrowsAsync<EidForbiddenException>(() =>
            c.Auth.NotificationByEtsiAsync("PNOMN-1", Login, new AuthOptions { OnBehalfOf = "NTRMN-1" }));
        Assert.Equal(EidErrorCodes.RepresentationDenied, e.Code);
        Assert.Contains("REPRESENTATION_DENIED", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnparsableStartResponseIsEidException()
    {
        var (c, _, _) = Rig.Create(200, "{\"sessionID\":\"s\",\"vc\":42}");
        await Assert.ThrowsAsync<EidException>(() => c.Auth.NotificationByEtsiAsync("PNOMN-1", Login));
    }

    [Fact]
    public async Task DefaultChallengeIsRandom64Bytes()
    {
        var (c, _, _) = Rig.Create(_ => Rig.Json(200, "{\"sessionID\":\"s\"}"), challenge: null);
        var a = await c.Auth.NotificationByEtsiAsync("PNOMN-1", Login);
        var b = await c.Auth.NotificationByEtsiAsync("PNOMN-1", Login);
        Assert.Equal(64, Convert.FromBase64String(a.RpChallenge).Length);
        Assert.NotEqual(a.RpChallenge, b.RpChallenge);
    }

    [Fact]
    public async Task CallerCancellationPropagates()
    {
        var (c, _, _) = Rig.Create(200, "{}");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.Auth.NotificationByEtsiAsync("PNOMN-1", Login, null, cts.Token));
    }

    /// <summary>
    /// Auth device-link session → холбоос / QR ticker нь CA-ийн devicelink_golden.json (eid-qr-auth-e0, e7, eid-web2app-auth,
    /// eid-app2app-auth)-тэй БАЙТ-ИЖИЛ: start хүсэлтийн rpChallenge / rpName / interactions → AcspContext → authCode.
    /// </summary>
    [Fact]
    public async Task DeviceLinkSessionMatchesGoldenEndToEnd()
    {
        var g = Golden.Load();
        var v = Golden.Vector(g, "eid-qr-auth-e0");
        var i = v.GetProperty("input");
        var (c, _, clock) = Rig.Create(_ => Rig.Json(200, JsonSerializer.Serialize(new
        {
            sessionID = "s-golden",
            sessionToken = i.GetProperty("sessionToken").GetString(),
            sessionSecret = i.GetProperty("sessionSecret").GetString(),
            deviceLinkBase = i.GetProperty("deviceLinkBase").GetString(),
            vc = "12345",
        })), creds: new EidCredentials("rp-uuid", i.GetProperty("relyingPartyName").GetString()!, "rp_sk_x"),
            challenge: i.GetProperty("rpChallengeOrDigest").GetString());
        var s = await c.Auth.DeviceLinkAnonymousAsync(Login, new AuthOptions { CallbackUrl = i.GetProperty("initialCallbackUrl").GetString() });
        Assert.Equal(i.GetProperty("interactions").GetString(), s.Acsp!.Interactions);
        Assert.Equal(clock.Now, s.ReceivedAt);

        Assert.Equal(Golden.Link(g, "eid-qr-auth-e0"), s.BuildLink(DeviceLinkTypes.Qr, "mon", clock.Now + TimeSpan.FromMilliseconds(999)));
        Assert.Equal(Golden.Link(g, "eid-web2app-auth"), s.BuildLink(DeviceLinkTypes.Web2App, "mon"));
        Assert.Equal(Golden.Link(g, "eid-app2app-auth"), s.BuildLink(DeviceLinkTypes.App2App, "mon"));

        // Ticker: эхний холбоос шууд (elapsed 0), дараагийнх нь цаг 7.9 с урагшилсны дараа (elapsed 7).
        var received = clock.Now;
        var links = new List<string>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await foreach (var l in s.TickQrAsync("mon", TimeSpan.FromMilliseconds(5), clock, cts.Token))
        {
            links.Add(l);
            if (links.Count == 2)
            {
                break;
            }
            clock.Now = received + TimeSpan.FromMilliseconds(7900);
        }
        Assert.Equal(new[] { Golden.Link(g, "eid-qr-auth-e0"), Golden.Link(g, "eid-qr-auth-e7") }, links);

        // Хадгалсан session (JSON) → ижил холбоос.
        var stored = JsonSerializer.Deserialize<DeviceLinkSession>(JsonSerializer.Serialize(s))!;
        Assert.Equal(Golden.Link(g, "eid-web2app-auth"), stored.BuildLink(DeviceLinkTypes.Web2App, "mon"));
    }
}

/// <summary>testdata/devicelink_golden.json туслах.</summary>
internal static class Golden
{
    public static JsonElement Load()
    {
        using var d = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "testdata", "devicelink_golden.json")));
        return d.RootElement.Clone();
    }

    public static JsonElement Vector(JsonElement g, string name) =>
        g.GetProperty("vectors").EnumerateArray().Single(v => v.GetProperty("name").GetString() == name);

    public static string Link(JsonElement g, string name) => Vector(g, name).GetProperty("deviceLink").GetString()!;
}
