using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Корпусаас гадуурх validator / OCSP-ийн шалгалт (шигтгэсэн гинж, цуцлалтын горим, кэш, client холболт).</summary>
public class ValidatorTests
{
    private const string RpValidate = "rp-validate/cases.json";

    private static ResponseValidator Default(DateTimeOffset now, RevocationChecker? revocation = null, RevocationMode mode = RevocationMode.HardFail) =>
        new(Corpus.Trust(Corpus.Json(RpValidate).GetProperty("trust").GetProperty("default")) with { Revocation = revocation, RevocationMode = mode },
            new ManualClock(now));

    private static OcspRevocationChecker Ocsp(string ocspCase, out ReplayHandler handler, ManualClock clock, TimeSpan cacheTtl = default)
    {
        var c = Corpus.Case("ocsp/cases.json", ocspCase);
        handler = new ReplayHandler(c.TryGetProperty("http", out var h) ? h : default);
        return new OcspRevocationChecker(new OcspOptions { HttpClient = new HttpClient(handler), TimeProvider = clock, CacheTtl = cacheTtl });
    }

    private static readonly DateTimeOffset Now = Corpus.Time("2026-10-14T04:00:00Z");

    [Fact]
    public void EmbeddedTrustMatchesPadesAndChains()
    {
        var pades = Directory.EnumerateFiles(Path.Combine(AppContext.BaseDirectory, "testdata", "pades-trust"), "0*.pem")
            .OrderBy(x => x, StringComparer.Ordinal).Select(File.ReadAllText).ToList();
        Assert.Equal(pades[0], EidTrust.NationalRootCaPem);
        Assert.Equal(pades.Skip(1).Take(3), EidTrust.CitizenIntermediatesPem);

        var root = ParsedCert.ParsePem(EidTrust.NationalRootCaPem).Single();
        Assert.Equal("cbe7f3fe1f048037c215da321e58caa4f363de9e54bbc442a3bfd62fad834482", Corpus.Sha256Hex(root.Raw));
        var inter = EidTrust.CitizenIntermediatesPem.Select(p => ParsedCert.ParsePem(p).Single()).ToList();
        Assert.Equal(EidTrust.CitizenIssuingCaSki, Convert.ToHexString(inter[2].SubjectKeyId!).ToLowerInvariant());

        // SDK-ийн замын угсралт бодит гинж дээр: 04 → 03 → 02 → 01 (гарын үсэг, нэр, AKI/SKI, keyCertSign).
        var v = new ResponseValidator(new TrustConfig { TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem } });
        Assert.Same(EidTrust.CitizenIntermediates[1], v.FindIssuer(inter[2]));
        Assert.Same(EidTrust.CitizenIntermediates[0], v.FindIssuer(inter[1]));
        Assert.Equal(root.Raw, v.FindIssuer(inter[0])!.Raw);
    }

    [Fact]
    public void TrustConfigErrors()
    {
        Assert.Throws<ArgumentException>(() => new ResponseValidator(new TrustConfig { TrustAnchorsPem = new[] { "not a pem" } }));
        Assert.Throws<ArgumentException>(() => new ResponseValidator(new TrustConfig
        {
            TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem },
            AllowedIssuerSkis = new[] { "zz" },
        }));
        // ":"-тэй, том үсэгтэй SKI зөвшөөрөгдөнө (Go/TS).
        _ = new ResponseValidator(new TrustConfig { AllowedIssuerSkis = new[] { "B8:A3:7F" } });
    }

    [Fact]
    public void NoAnchorIsFailClosedUnlessAllowUntrusted()
    {
        var c = Corpus.Case(RpValidate, "auth-pss-sha512-qr");
        var r = SessionService.ParseSessionResult(c.GetProperty("session").GetRawText());
        var acsp = System.Text.Json.JsonSerializer.Deserialize<AcspContext>(c.GetProperty("acsp").GetRawText(), EidHttp.Json)!;
        var e = Assert.Throws<EidValidationException>(() => new ResponseValidator(null, new ManualClock(Now)).ValidateAuth(r, acsp));
        Assert.Equal(ValidationReasons.TrustNoAnchor, e.Reason);
        var id = new ResponseValidator(new TrustConfig { AllowUntrusted = true }, new ManualClock(Now)).ValidateAuth(r, acsp);
        Assert.Equal("PNOMN-999999990001-MOCK-Q", id.DocumentNumber);
    }

    [Fact]
    public void ClientValidatorUsesClientTrustAndClock()
    {
        var f = Corpus.Json(RpValidate);
        var c = Corpus.Case(RpValidate, "auth-pss-sha512-qr");
        using var client = new EidClient(new EidClientOptions
        {
            Credentials = Rig.Creds,
            Trust = Corpus.Trust(f.GetProperty("trust").GetProperty("default")),
            TimeProvider = new ManualClock(Now),
        });
        var r = SessionService.ParseSessionResult(c.GetProperty("session").GetRawText());
        var acsp = System.Text.Json.JsonSerializer.Deserialize<AcspContext>(c.GetProperty("acsp").GetRawText(), EidHttp.Json)!;
        Assert.Equal(CertificateLevels.Qualified, client.Validator.ValidateAuth(r, acsp).CertificateLevel);

        // Clock-ийг leaf-ийн notAfter-аас хойш шилжүүлбэл ижил хариу cert.expired.
        using var late = new EidClient(new EidClientOptions
        {
            Credentials = Rig.Creds,
            Trust = Corpus.Trust(f.GetProperty("trust").GetProperty("default")),
            TimeProvider = new ManualClock(Now.AddYears(10)),
        });
        Assert.Equal(ValidationReasons.CertExpired, Assert.Throws<EidValidationException>(() => late.Validator.ValidateAuth(r, acsp)).Reason);
    }

    [Fact]
    public void EcdsaSignatureMustBeDerNotP1363()
    {
        var c = Corpus.Case(RpValidate, "sign-ec-legacy");
        var r = SessionService.ParseSessionResult(c.GetProperty("session").GetRawText());
        var v = Default(Now);
        var digest = c.GetProperty("digest").GetString()!;
        Assert.Equal(SignatureAlgorithms.EcdsaWithSha256, v.ValidateSign(r, digest, HashAlgorithms.Sha256).SignatureAlgorithm);

        // Ижил (r, s)-ийг IEEE P1363 (r‖s) хэлбэрээр → татгалзана.
        var seq = new AsnReader(Convert.FromBase64String(r.SignatureValueB64), AsnEncodingRules.DER).ReadSequence();
        var p1363 = Fixed(seq.ReadIntegerBytes().ToArray()).Concat(Fixed(seq.ReadIntegerBytes().ToArray())).ToArray();
        var bad = r with { SignatureValueB64 = Convert.ToBase64String(p1363) };
        Assert.Equal(ValidationReasons.SignSignature, Assert.Throws<EidValidationException>(() => v.ValidateSign(bad, digest, HashAlgorithms.Sha256)).Reason);

        static byte[] Fixed(byte[] i)
        {
            var t = i.SkipWhile(b => b == 0).ToArray();
            return new byte[32 - t.Length].Concat(t).ToArray();
        }
    }

    [Theory]
    [InlineData("good", RevocationMode.HardFail, "good")]
    [InlineData("unknown-is-revoked", RevocationMode.SoftFail, ValidationReasons.RevocationRevoked)]
    [InlineData("revoked", RevocationMode.HardFail, ValidationReasons.RevocationRevoked)]
    [InlineData("http-500", RevocationMode.HardFail, ValidationReasons.RevocationUnknown)]
    [InlineData("http-500", RevocationMode.SoftFail, "unchecked")]
    [InlineData("stale-49h", RevocationMode.SoftFail, "unchecked")]
    public async Task CheckRevocationModes(string ocspCase, RevocationMode mode, string want)
    {
        var clock = new ManualClock(Now);
        var checker = Ocsp(ocspCase, out _, clock);
        var v = Default(Now, checker.Checker, mode);
        using var leaf = Corpus.Cert("pki/leaf-auth.pem");
        try
        {
            var st = await v.CheckRevocationAsync(leaf);
            Assert.Equal(want, st.ToString().ToLowerInvariant());
        }
        catch (EidValidationException e)
        {
            Assert.Equal(want, e.Reason);
            if (e.Reason == ValidationReasons.RevocationUnknown)
            {
                Assert.Equal(OcspErrorKinds.HttpStatus, Assert.IsType<EidOcspException>(e.InnerException).Kind);
            }
        }
    }

    [Fact]
    public async Task CheckRevocationSkippedWithoutChecker()
    {
        using var leaf = Corpus.Cert("pki/leaf-auth.pem");
        Assert.Equal(RevocationStatus.Skipped, await Default(Now).CheckRevocationAsync(leaf));
    }

    [Fact]
    public async Task OcspCachesGoodForTtl()
    {
        var clock = new ManualClock(Now);
        var seen = new List<OcspObservation>();
        var c = Corpus.Case("ocsp/cases.json", "good");
        var handler = new ReplayHandler(c.GetProperty("http"));
        var checker = new OcspRevocationChecker(new OcspOptions { HttpClient = new HttpClient(handler), TimeProvider = clock, Observe = seen.Add });
        using var leaf = Corpus.Cert("pki/leaf-auth.pem");
        using var issuer = Corpus.Cert("pki/04-eid.pem");
        Assert.Equal(RevocationStatus.Good, await checker.CheckAsync(leaf, issuer));
        Assert.Equal(RevocationStatus.Good, await checker.CheckAsync(leaf, issuer));
        Assert.Equal(1, handler.Calls);
        Assert.Equal(new[] { false, true }, seen.Select(o => o.Cached));
        Assert.Equal("http://ocsp.conformance.test/ocsp", seen[0].Responder);

        clock.Now = Now + OcspRevocationChecker.DefaultCacheTtl + TimeSpan.FromSeconds(1);
        Assert.Equal(RevocationStatus.Good, await checker.CheckAsync(leaf, issuer));
        Assert.Equal(2, handler.Calls);

        // Сөрөг CacheTtl — кэшлэхгүй.
        var noCache = Ocsp("good", out var h2, new ManualClock(Now), TimeSpan.FromSeconds(-1));
        await noCache.CheckAsync(leaf, issuer);
        await noCache.CheckAsync(leaf, issuer);
        Assert.Equal(2, h2.Calls);
    }

    [Fact]
    public async Task OcspDoesNotCacheFailures()
    {
        var checker = Ocsp("revoked", out var handler, new ManualClock(Now));
        using var leaf = Corpus.Cert("pki/leaf-auth.pem");
        using var issuer = Corpus.Cert("pki/04-eid.pem");
        Assert.Equal(RevocationStatus.Revoked, await checker.CheckAsync(leaf, issuer));
        Assert.Equal(RevocationStatus.Revoked, await checker.CheckAsync(leaf, issuer));
        Assert.Equal(2, handler.Calls);
        var e = await Assert.ThrowsAsync<EidOcspException>(() => checker.CheckAsync(leaf, null));
        Assert.Equal(OcspErrorKinds.NoIssuer, e.Kind);
    }

    [Fact]
    public void OcspRequestIsSha1CertId()
    {
        var leaf = ParsedCert.ParsePem(Corpus.Text("pki/leaf-auth.pem")).Single();
        var issuer = ParsedCert.ParsePem(Corpus.Text("pki/04-eid.pem")).Single();
        var req = new AsnReader(OcspRevocationChecker.CreateRequest(leaf, issuer), AsnEncodingRules.DER).ReadSequence();
        var certId = req.ReadSequence().ReadSequence().ReadSequence().ReadSequence();
        Assert.Equal("1.3.14.3.2.26", certId.ReadSequence().ReadObjectIdentifier());
        Assert.Equal(SHA1.HashData(issuer.RawSubject), certId.ReadOctetString());
        Assert.Equal(SHA1.HashData(issuer.PublicKeyBits), certId.ReadOctetString());
        Assert.Equal(leaf.Serial, certId.ReadInteger());
    }
}
