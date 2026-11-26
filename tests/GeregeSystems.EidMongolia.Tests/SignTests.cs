using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class SignTests
{
    /// <summary>Go sign_gaps_test.go <c>dlReply</c>.</summary>
    internal const string DlReply = "{\"sessionID\":\"0b8f3f0e-1111-4222-8333-444455556666\",\"sessionToken\":\"tok_abc-123\"," +
        "\"sessionSecret\":\"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTMyYg==\",\"deviceLinkBase\":\"https://ca.eidmongolia.mn/dl\",\"vc\":\"12345\"}";

    private const string PushReply = "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"90177\"}}";

    private static readonly Interaction[] Contract = { new() { Type = "displayTextAndPIN", DisplayText60 = "Гэрээнд гарын үсэг зурах" } };

    private static (EidClient, Recorder, ManualClock) Server() =>
        Rig.Create(r => Rig.Json(200, r.Path.Contains("device-link", StringComparison.Ordinal) ? DlReply : PushReply));

    // Go client_test.go TestSign_Body.
    [Fact]
    public async Task TextByEtsiBody()
    {
        var (c, h, clock) = Server();
        var s = await c.Sign.TextByEtsiAsync("PNOMN-1", "x", null, new SignOptions { OnBehalfOf = "NTRMN-6235972" });
        Assert.Equal("/signature/notification/etsi/PNOMN-1", h.Last.Path);
        JsonAssert.Equivalent("""
            {"relyingPartyUUID":"rp-uuid","relyingPartyName":"Гэрээний систем","certificateLevel":"QUALIFIED",
             "signatureProtocol":"RAW_DIGEST_SIGNATURE",
             "signatureProtocolParameters":{"digest":"LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=","signatureAlgorithm":"rsassa-pss",
               "signatureAlgorithmParameters":{"hashAlgorithm":"SHA-256"}},
             "interactions":"W10=","onBehalfOf":"NTRMN-6235972"}
            """, h.Last.Json());
        Assert.Equal(EidCrypto.Sha256Base64(Encoding.UTF8.GetBytes("x")), s.Sign!.Digest);
        Assert.Equal("90177", s.Vc);
        Assert.Null(s.Acsp);
        Assert.Equal("", s.RpChallenge);
        // Go TestSignExpiresAt: CA expiresAt-гүй бол sent + 600 с.
        Assert.Equal(clock.Now + SessionTimes.DefaultSignSessionTtl, s.ExpiresAt);
        Assert.Equal(SignatureAlgorithms.RsassaPss, s.Sign.SignatureAlgorithm);
    }

    // Go sign_gaps_test.go TestSignDeviceLink.
    [Fact]
    public async Task DeviceLinkByEtsiBodyAndLinks()
    {
        var (c, h, clock) = Server();
        var digest = EidCrypto.Sha256Base64(Encoding.UTF8.GetBytes("гэрээ"));
        var s = await c.Sign.DeviceLinkByEtsiAsync("PNOMN-12345678", digest, Contract, new SignOptions
        {
            CallbackUrl = " https://rp.example.mn/cb ",
            FileName = "Гэрээ.pdf",
            OnBehalfOf = "NTRMN-6235972",
            SignatureAlgorithm = SignatureAlgorithms.Sha256WithRsa,
        });
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/signature/device-link/etsi/PNOMN-12345678", h.Last.Path);
        JsonAssert.Equivalent("""
            {"relyingPartyUUID":"rp-uuid","relyingPartyName":"Гэрээний систем","certificateLevel":"QUALIFIED",
             "signatureProtocol":"RAW_DIGEST_SIGNATURE",
             "signatureProtocolParameters":{"digest":"@D@","signatureAlgorithm":"sha256WithRSAEncryption",
               "signatureAlgorithmParameters":{"hashAlgorithm":"SHA-256"}},
             "interactions":"W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6ItCT0Y3RgNGN0Y3QvdC0INCz0LDRgNGL0L0g0q/RgdGN0LMg0LfRg9GA0LDRhSJ9XQ==",
             "initialCallbackUrl":"https://rp.example.mn/cb","fileName":"Гэрээ.pdf","onBehalfOf":"NTRMN-6235972"}
            """.Replace("@D@", digest, StringComparison.Ordinal), h.Last.Json());
        Assert.Equal("0b8f3f0e-1111-4222-8333-444455556666", s.SessionId);
        Assert.Equal("tok_abc-123", s.SessionToken);
        Assert.Equal("12345", s.Vc);
        Assert.Equal(DeviceLinkSessionTypes.Sign, s.SessionType);
        Assert.Equal(digest, s.Sign!.Digest);
        Assert.Equal(Rig.Creds.RpName, s.Sign.RelyingPartyName);
        Assert.Equal("https://rp.example.mn/cb", s.Sign.InitialCallbackUrl);
        Assert.Equal(clock.Now + SessionTimes.DefaultSignSessionTtl, s.ExpiresAt);
        foreach (var t in new[] { DeviceLinkTypes.Qr, DeviceLinkTypes.Web2App, DeviceLinkTypes.App2App })
        {
            var l = s.BuildLink(t, "mon");
            Assert.Contains("sessionType=sign", l, StringComparison.Ordinal);
            Assert.Contains("deviceLinkType=" + t, l, StringComparison.Ordinal);
        }
        // LinkInput нь гараар угсарсантай байт-ижил (Web2App — callback authCode-д ордог).
        var manual = DeviceLink.Build(new DeviceLinkInput
        {
            DeviceLinkBase = s.DeviceLinkBase,
            DeviceLinkType = DeviceLinkTypes.Web2App,
            SessionToken = s.SessionToken,
            SessionSecret = s.SessionSecret,
            SessionType = DeviceLinkSessionTypes.Sign,
            Lang = "mon",
            Digest = digest,
            RelyingPartyName = Rig.Creds.RpName,
            Interactions = s.Sign.Interactions,
            InitialCallbackUrl = "https://rp.example.mn/cb",
        });
        Assert.Equal(manual, s.BuildLink(DeviceLinkTypes.Web2App, "mon"));

        await c.Sign.DeviceLinkByDocumentAsync("PNOMN-12345678-MOCK-Q", digest, Contract);
        Assert.Equal("/signature/device-link/document/PNOMN-12345678-MOCK-Q", h.Last.Path);
        Assert.False(h.Last.Json().TryGetProperty("initialCallbackUrl", out _));
        Assert.Equal("rsassa-pss", h.Last.Json().GetProperty("signatureProtocolParameters").GetProperty("signatureAlgorithm").GetString());
    }

    [Fact]
    public async Task DigestByDocumentPathAndOptions()
    {
        var (c, h, _) = Server();
        var d = EidCrypto.Sha256Base64(new byte[] { 1 });
        var s = await c.Sign.DigestByDocumentAsync("DOC-1", d, Contract,
            new SignOptions { CertificateLevel = CertificateLevels.Advanced, HashAlgorithm = HashAlgorithms.Sha512, FileName = "  " });
        Assert.Equal("/signature/notification/document/DOC-1", h.Last.Path);
        var b = h.Last.Json();
        Assert.Equal("ADVANCED", b.GetProperty("certificateLevel").GetString());
        Assert.False(b.TryGetProperty("fileName", out _));
        Assert.Equal("SHA-512", s.Sign!.HashAlgorithm);
    }

    // Go sign_gaps_test.go TestSignExpiresAt: Config.SignSessionTTL.
    [Fact]
    public async Task SignSessionTtlOption()
    {
        var (c, _, clock) = Rig.Create(_ => Rig.Json(200, PushReply), signTtl: TimeSpan.FromSeconds(90));
        Assert.Equal(TimeSpan.FromSeconds(90), c.SignSessionTtl);
        var s = await c.Sign.DigestByEtsiAsync("PNOMN-1", EidCrypto.Sha256Base64(ReadOnlySpan<byte>.Empty), null);
        Assert.Equal(clock.Now + TimeSpan.FromSeconds(90), s.ExpiresAt);
    }

    // Go session_start_test.go TestSessionStartCAExpiresAt (sign / cert хэсэг).
    [Fact]
    public async Task CaExpiresAtWins()
    {
        var exp = new DateTimeOffset(2026, 10, 14, 14, 10, 0, TimeSpan.Zero);
        var (c, _, _) = Rig.Create(r => Rig.Json(200, r.Path.Contains("device-link", StringComparison.Ordinal)
            ? DlReply.TrimEnd('}') + ",\"expiresAt\":\"2026-10-14T14:10:00Z\"}"
            : "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"54321\"},\"expiresAt\":\"2026-10-14T14:10:00Z\"}"));
        var d = EidCrypto.Sha256Base64(ReadOnlySpan<byte>.Empty);
        Assert.Equal(exp, (await c.Sign.DigestByEtsiAsync("PNOMN-1", d, Contract)).ExpiresAt);
        Assert.Equal(exp, (await c.Sign.DeviceLinkByEtsiAsync("PNOMN-1", d, Contract)).ExpiresAt);
        Assert.Equal(exp, (await c.Sign.CertificateChoiceByEtsiAsync("PNOMN-1")).ExpiresAt);
        Assert.Equal(exp, (await c.Sign.CertificateChoiceDeviceLinkAsync()).ExpiresAt);
    }

    // Go session_start_test.go TestSessionStartTypedErrors.
    [Theory]
    [InlineData(409, "NO_SIGNING_CERTIFICATE", typeof(EidNoSigningCertificateException))]
    [InlineData(409, "CERT_CHOICE_INVALID", typeof(EidCertChoiceInvalidException))]
    [InlineData(400, "REQUEST_INVALID", typeof(EidRequestInvalidException))]
    public async Task StartTypedErrors(int status, string code, Type type)
    {
        var (c, _, _) = Rig.Create(status, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
        var e = await Assert.ThrowsAnyAsync<EidApiException>(() => c.Sign.DigestByEtsiAsync("PNOMN-1", EidCrypto.Sha256Base64(ReadOnlySpan<byte>.Empty), null));
        Assert.IsType(type, e);
        Assert.Equal(status, e.Status);
        Assert.Equal(code, e.Code);
    }

    // Go contract_test.go TestContractCertChoiceDTO (сүлжээгүй): CA dto.CertificateChoiceRequest-ийн талбарууд.
    [Fact]
    public void CertChoiceDtoFields()
    {
        Assert.Equal(new[] { "certificateLevel", "initialCallbackUrl", "relyingPartyName", "relyingPartyUUID" },
            PdfTests.JsonNames(typeof(CertChoiceRequest)).OrderBy(x => x, StringComparer.Ordinal).ToArray());
    }

    // Go sign_gaps_test.go TestCertificateChoice.
    [Fact]
    public async Task CertificateChoice()
    {
        var (c, h, _) = Rig.Create(r => Rig.Json(200, r.Path.Contains("device-link", StringComparison.Ordinal)
            ? DlReply
            : "{\"sessionID\":\"cc-1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"11111\"}}"));
        var s = await c.Sign.CertificateChoiceByEtsiAsync("PNOMN-12345678", new CertChoiceOptions { CallbackUrl = "https://rp.example.mn/cb" });
        Assert.Equal("cc-1", s.SessionId);
        Assert.Equal("11111", s.Vc);
        Assert.True(s.ExpiresAt.HasValue);
        Assert.Null(s.Sign);
        Assert.Null(s.Acsp);
        Assert.Equal("/signature/certificate-choice/notification/etsi/PNOMN-12345678", h.Last.Path);
        // CA dto.CertificateChoiceRequest — үл мэдэгдэх талбар 400; notification-д callback ЯВАХГҮЙ (Go TestCertificateChoiceByEtsi_NoCallback).
        JsonAssert.Equivalent("{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"QUALIFIED\"}", h.Last.Json());

        var d = await c.Sign.CertificateChoiceDeviceLinkAsync(new CertChoiceOptions { CertificateLevel = CertificateLevels.Qscd });
        Assert.Equal("/signature/certificate-choice/device-link/anonymous", h.Last.Path);
        JsonAssert.Equivalent("{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"QSCD\"}", h.Last.Json());
        Assert.Equal(DeviceLinkSessionTypes.Cert, d.SessionType);
        Assert.Equal(Rig.Creds.RpName, d.RelyingPartyName);
        Assert.Null(d.CallbackUrl);
        Assert.Contains("sessionType=cert", d.BuildLink(DeviceLinkTypes.Qr, "eng"), StringComparison.Ordinal);
        // Callback-гүй тул Web2App боломжгүй.
        Assert.Throws<EidDeviceLinkException>(() => d.BuildLink(DeviceLinkTypes.Web2App, "eng"));
    }

    // Go certchoice_callback_test.go TestCertificateChoiceDeviceLink_Callback.
    [Fact]
    public async Task CertificateChoiceDeviceLinkCallback()
    {
        var (c, h, _) = Rig.Create(200, DlReply);
        var s = await c.Sign.CertificateChoiceDeviceLinkAsync(new CertChoiceOptions { CallbackUrl = " https://rp.example.mn/auth/eid/callback?value=abc " });
        Assert.Equal("certificateLevel,initialCallbackUrl,relyingPartyName,relyingPartyUUID", h.Last.Keys());
        Assert.Equal("https://rp.example.mn/auth/eid/callback?value=abc", h.Last.Json().GetProperty("initialCallbackUrl").GetString());
        Assert.Equal("https://rp.example.mn/auth/eid/callback?value=abc", s.CallbackUrl);
        Assert.Contains("deviceLinkType=Web2App", s.BuildLink(DeviceLinkTypes.Web2App, "eng"), StringComparison.Ordinal);
        await c.Sign.CertificateChoiceDeviceLinkAsync();
        Assert.False(h.Last.Json().TryGetProperty("initialCallbackUrl", out _));
    }

    // Go sign_gaps_test.go TestDigestForSigner.
    [Fact]
    public async Task DigestForSigner()
    {
        var (c, h, _) = Server();
        var d = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("signedAttrs")));
        var sg = new SignerRef("PNOMN-12345678-ABCD-Q", "cc-1");

        var s = await c.Sign.DigestForSignerAsync(sg, d, null, new SignOptions { FileName = "a.pdf" });
        Assert.Equal("/signature/notification/linked/PNOMN-12345678-ABCD-Q", h.Last.Path);
        var b = h.Last.Json();
        Assert.Equal("cc-1", b.GetProperty("linkedSessionID").GetString());
        Assert.Equal("a.pdf", b.GetProperty("fileName").GetString());
        var spp = b.GetProperty("signatureProtocolParameters");
        Assert.Equal("sha256WithRSAEncryption", spp.GetProperty("signatureAlgorithm").GetString());
        Assert.Equal(d, spp.GetProperty("digest").GetString());
        Assert.Equal(SignatureAlgorithms.Sha256WithRsa, s.Sign!.SignatureAlgorithm);
        Assert.Equal(HashAlgorithms.Sha256, s.Sign.HashAlgorithm);

        await c.Sign.DigestForSignerAsync(new SignerRef("DOC-1"), d, null);
        Assert.Equal("/signature/notification/document/DOC-1", h.Last.Path);
        Assert.False(h.Last.Json().TryGetProperty("linkedSessionID", out _));

        var dl = await c.Sign.DeviceLinkForSignerAsync(sg, d, null, new SignOptions { CallbackUrl = "https://rp.example.mn/cb" });
        Assert.Equal(DeviceLinkSessionTypes.Sign, dl.SessionType);
        Assert.Equal(SignatureAlgorithms.Sha256WithRsa, dl.Sign!.SignatureAlgorithm);
        Assert.Equal("/signature/device-link/document/PNOMN-12345678-ABCD-Q", h.Last.Path);
        Assert.False(h.Last.Json().TryGetProperty("linkedSessionID", out _));

        var n = h.Requests.Count;
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DigestForSignerAsync(null!, d, null); });
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DigestForSignerAsync(new SignerRef(" "), d, null); });
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DigestForSignerAsync(sg, Convert.ToBase64String(new byte[48]), null); });
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DigestForSignerAsync(sg, d, null, new SignOptions { HashAlgorithm = HashAlgorithms.Sha512 }); });
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DigestForSignerAsync(sg, "not base64!", null); });
        Assert.Throws<ArgumentException>(() => { _ = c.Sign.DeviceLinkForSignerAsync(sg, d, null, new SignOptions { HashAlgorithm = "MD5" }); });
        Assert.Equal(n, h.Requests.Count);
    }

    /// <summary>Sign / cert device-link session → холбоос нь devicelink_golden.json (eid-qr-sign-e12, eid-web2app-cert)-тэй байт-ижил.</summary>
    [Fact]
    public async Task DeviceLinkSessionsMatchGolden()
    {
        var g = Golden.Load();
        var i = Golden.Vector(g, "eid-qr-sign-e12").GetProperty("input");
        var reply = JsonSerializer.Serialize(new
        {
            sessionID = "s-golden",
            sessionToken = i.GetProperty("sessionToken").GetString(),
            sessionSecret = i.GetProperty("sessionSecret").GetString(),
            deviceLinkBase = i.GetProperty("deviceLinkBase").GetString(),
            vc = "12345",
        });
        var (c, _, clock) = Rig.Create(_ => Rig.Json(200, reply), creds: new EidCredentials("rp-uuid", i.GetProperty("relyingPartyName").GetString()!, "rp_sk_x"));
        var callback = i.GetProperty("initialCallbackUrl").GetString();
        var s = await c.Sign.DeviceLinkByEtsiAsync("PNOMN-1", i.GetProperty("rpChallengeOrDigest").GetString()!, AuthTests.Login,
            new SignOptions { CallbackUrl = callback });
        Assert.Equal(Golden.Link(g, "eid-qr-sign-e12"), s.BuildLink(DeviceLinkTypes.Qr, "mon", clock.Now + TimeSpan.FromSeconds(12.5)));

        var cc = await c.Sign.CertificateChoiceDeviceLinkAsync(new CertChoiceOptions { CallbackUrl = callback });
        Assert.Equal(Golden.Link(g, "eid-web2app-cert"), cc.BuildLink(DeviceLinkTypes.Web2App, "eng"));
    }
}
