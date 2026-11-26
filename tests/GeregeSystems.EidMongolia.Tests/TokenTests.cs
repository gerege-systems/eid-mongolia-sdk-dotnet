using System;
using System.Formats.Asn1;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Go portal_gaps_test.go TestTokenCertificate*, TestTokenAuth-ийн порт.</summary>
public class TokenTests
{
    private const string Rp = "2d87bd3a-1303-41bf-81bd-37d6b92fb7bc";
    private const string Ch32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    /// <summary>Тестийн PKI (Go testPKI): RSA root → RSA завсрын CA → EC P-256 навч.</summary>
    private sealed class Pki : IDisposable
    {
        private readonly RSA _rootKey = RSA.Create(2048);
        private readonly RSA _interKey = RSA.Create(2048);
        private readonly DateTimeOffset _nb = DateTimeOffset.UtcNow.AddDays(-1);
        private readonly DateTimeOffset _na = DateTimeOffset.UtcNow.AddDays(30);
        private byte _serial = 0x10;

        public Pki()
        {
            var rr = new CertificateRequest("CN=TEST ONLY token root, C=MN", _rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Ca(rr);
            Root = rr.CreateSelfSigned(_nb.AddDays(-1), _na.AddDays(1));
            var ir = new CertificateRequest("CN=TEST ONLY token issuing CA, C=MN", _interKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Ca(ir);
            ir.CertificateExtensions.Add(Aki(Root));
            using var tmp = ir.Create(Root.SubjectName, X509SignatureGenerator.CreateForRSA(_rootKey, RSASignaturePadding.Pkcs1), _nb, _na, new byte[] { 0x02 });
            Inter = X509Loader.Load(tmp.RawData);
        }

        public X509Certificate2 Root { get; }

        public X509Certificate2 Inter { get; }

        public static string Pem(X509Certificate2 c) => new(PemEncoding.Write("CERTIFICATE", c.RawData));

        private static void Ca(CertificateRequest r)
        {
            r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            r.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(r.PublicKey, false));
        }

        private static X509AuthorityKeyIdentifierExtension Aki(X509Certificate2 issuer) =>
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single());

        /// <summary>
        /// Go tokenKeys: EC P-256 CSR + тэр түлхүүрт олгосон навч (P-CITIZEN-AUTH-TOKEN: KU digitalSignature, EKU clientAuth +
        /// emailProtection), эсвэл <paramref name="sign"/> бол P-CITIZEN-SIGN-TOKEN (KU digitalSignature + contentCommitment, EKU-гүй).
        /// </summary>
        public (byte[] Csr, byte[] Cert, ECDsa Key) Leaf(string serial, bool sign = false, string? extraCn = null)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr = new CertificateRequest("CN=ignored", key, HashAlgorithmName.SHA256).CreateSigningRequest();
            var b = new X500DistinguishedNameBuilder();
            b.AddCountryOrRegion("MN");
            b.Add("2.5.4.5", serial, UniversalTagNumber.PrintableString);
            b.AddCommonName("TEST ONLY TOKEN");
            if (extraCn is not null)
            {
                b.AddCommonName(extraCn);
            }
            var lr = new CertificateRequest(b.Build(), key, HashAlgorithmName.SHA256);
            lr.CertificateExtensions.Add(new X509KeyUsageExtension(sign
                ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation
                : X509KeyUsageFlags.DigitalSignature, true));
            if (!sign)
            {
                lr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.4") }, false));
            }
            lr.CertificateExtensions.Add(Aki(Inter));
            using var c = lr.Create(Inter.SubjectName, X509SignatureGenerator.CreateForRSA(_interKey, RSASignaturePadding.Pkcs1), _nb, _na,
                new byte[] { 0x03, _serial++ });
            return (csr, c.RawData, key);
        }

        public void Dispose()
        {
            Root.Dispose();
            Inter.Dispose();
            _rootKey.Dispose();
            _interKey.Dispose();
        }
    }

    private static string Hex(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    private static (EidClient Client, Recorder Http) Client(Func<Recorded, HttpResponseMessage> respond, TrustConfig? trust)
    {
        var rec = new Recorder(respond);
        var c = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp.example.mn",
            Credentials = new EidCredentials(Rp, "x", "s"),
            Trust = trust,
        }, new HttpClient(rec));
        return (c, rec);
    }

    private static TrustConfig OkTrust(Pki p) => new()
    {
        TrustAnchorsPem = new[] { Pki.Pem(p.Root) },
        IntermediatesPem = new[] { Pki.Pem(p.Inter) },
        AllowAnyIssuer = true,
    };

    // Go TestTokenCertificate.
    [Fact]
    public async Task IssueCertificateAndResult()
    {
        using var p = new Pki();
        var (csrA, certA, ka) = p.Leaf("PNOMN-12345678");
        var (csrS, certS, ks) = p.Leaf("PNOMN-12345678");
        ka.Dispose();
        ks.Dispose();
        var (c, h, _) = Rig.Create(200, "{\"sessionID\":\"ts1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"04817\"}," +
            "\"csrAuthSha256\":\"" + Hex(csrA) + "\",\"csrSignSha256\":\"" + Hex(csrS) + "\",\"expiresAt\":\"2026-10-12T16:41:34+08:00\"}");
        var s = await c.Token.IssueCertificateAsync(new TokenCertInput { SignerEtsi = "PNOMN-12345678", CsrAuth = csrA, CsrSign = csrS, TokenSerial = "EP2003-0042A1" });
        Assert.Equal("ts1", s.SessionId);
        Assert.Equal("04817", s.Vc);
        Assert.Equal(Hex(csrA).ToLowerInvariant(), s.CsrAuthSha256);
        Assert.Null(s.Supersedes);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/token/certificate", h.Last.Path);
        JsonAssert.Equivalent("{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"signer\":{\"etsi\":\"PNOMN-12345678\"}," +
            "\"csrAuth\":\"" + Convert.ToBase64String(csrA) + "\",\"csrSign\":\"" + Convert.ToBase64String(csrS) + "\",\"tokenSerial\":\"EP2003-0042A1\"," +
            "\"onBehalfOf\":\"\",\"flow\":\"notification\"}", h.Last.Json());

        // CA өөр CSR-ийн hash буцаавал итгэхгүй.
        (c, _, _) = Rig.Create(200, "{\"sessionID\":\"ts1\",\"csrAuthSha256\":\"" + Hex(csrS) + "\",\"csrSignSha256\":\"" + Hex(csrS) + "\"}");
        var e = await Assert.ThrowsAsync<EidValidationException>(() => c.Token.IssueCertificateAsync(new TokenCertInput
        {
            SignerEtsi = "PNOMN-1",
            CsrAuth = csrA,
            CsrSign = csrS,
            TokenSerial = "x",
            TokenLabel = "L",
            OnBehalfOf = "NTRMN-1",
        }));
        Assert.Equal(ValidationReasons.TokenCsrMismatch, e.Reason);
        await Assert.ThrowsAsync<ArgumentException>(() => c.Token.IssueCertificateAsync(new TokenCertInput()));

        var result = "{\"status\":\"ISSUED\",\"auth\":{\"certificate\":\"" + Convert.ToBase64String(certA) + "\",\"serialHex\":\"A\"}," +
            "\"sign\":{\"certificate\":\"" + Convert.ToBase64String(certS) + "\",\"serialHex\":\"S\"},\"chain\":[\"x\"],\"organization\":null," +
            "\"keyMedium\":\"TOKEN\",\"certificateLevel\":\"ADVANCED\"}";
        (c, h, _) = Rig.Create(200, result);
        var r = await c.Token.CertificateResultAsync("ts1");
        Assert.Equal(TokenCertStatuses.Issued, r.Status);
        Assert.Null(r.Organization);
        Assert.Equal("TOKEN", r.KeyMedium);
        Assert.NotNull(r.Raw);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/token/certificate/ts1", h.Last.Path);
        TokenService.VerifyTokenCertificates(r, csrA, csrS);
        Assert.Equal(ValidationReasons.TokenCsrMismatch, Assert.Throws<EidValidationException>(() => TokenService.VerifyTokenCertificates(r, csrS, csrA)).Reason);
        Assert.Equal(ValidationReasons.ResponseMalformed,
            Assert.Throws<EidValidationException>(() => TokenService.VerifyTokenCertificates(new TokenCertResult(), csrA, csrS)).Reason);
        Assert.Throws<ArgumentException>(() => TokenService.VerifyTokenCertificates(r, new byte[] { 1, 2, 3 }, csrS));
    }

    // Go TestTokenCertificate (TokenLimitOf, TOKEN_SCOPE_CHANGE).
    [Fact]
    public async Task TokenLimitAndScopeChange()
    {
        using var p = new Pki();
        var (csrA, _, ka) = p.Leaf("PNOMN-1");
        var (csrS, _, ks) = p.Leaf("PNOMN-1");
        ka.Dispose();
        ks.Dispose();
        var input = new TokenCertInput { SignerEtsi = "PNOMN-1", CsrAuth = csrA, CsrSign = csrS, TokenSerial = "x" };
        var (c, _, _) = Rig.Create(409, "{\"error\":\"хязгаар\",\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"ORGANIZATION\",\"limit\":1,\"organization\":\"NTRMN-6235972\"}");
        var e = await Assert.ThrowsAsync<EidApiException>(() => c.Token.IssueCertificateAsync(input));
        Assert.Equal(new TokenLimit(TokenKinds.Organization, 1, "NTRMN-6235972"), TokenService.TokenLimitOf(e));

        foreach (var body in new[]
        {
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\"}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"ORGANIZATION\",\"limit\":1}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"X\",\"limit\":1}",
            "{\"code\":\"TOKEN_IN_USE\",\"kind\":\"PERSONAL\",\"limit\":1}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\",\"limit\":-1}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\",\"limit\":1.5}",
        })
        {
            var code = body.Contains("TOKEN_IN_USE", StringComparison.Ordinal) ? TokenErrorCodes.TokenInUse : TokenErrorCodes.TokenLimitReached;
            Assert.Null(TokenService.TokenLimitOf(new EidApiException(409, body, code, null, null, null)));
        }
        Assert.Equal(new TokenLimit(TokenKinds.Personal, 0, null),
            TokenService.TokenLimitOf(new EidApiException(409, "{\"kind\":\"PERSONAL\",\"limit\":0}", TokenErrorCodes.TokenLimitReached, null, null, null)));
        Assert.Null(TokenService.TokenLimitOf(new InvalidOperationException()));

        (c, _, _) = Rig.Create(409, "{\"error\":\"Токены төрлийг солихын тулд …\",\"code\":\"TOKEN_SCOPE_CHANGE\"}");
        var sc = await Assert.ThrowsAsync<EidApiException>(() => c.Token.IssueCertificateAsync(input with { OnBehalfOf = "NTRMN-1" }));
        Assert.Equal(409, sc.Status);
        Assert.Equal(TokenErrorCodes.TokenScopeChange, sc.Code);
        Assert.False(sc.Retryable);
        Assert.Null(TokenService.TokenLimitOf(sc));
    }

    // Go TestTokenCertificateInfo.
    [Fact]
    public async Task CertificateInfo()
    {
        var (c, h, _) = Rig.Create(200, "{\"version\":\"v3\",\"tokenCertificate\":{\"certificateLevel\":\"ADVANCED\",\"enabled\":true," +
            "\"issue\":\"https://rp.eidmongolia.mn/token/certificate\",\"keyAlgorithm\":\"EC P-256 (ecdsa-with-SHA256)\",\"onBehalfOf\":\"optional\"," +
            "\"permission\":\"TOKEN_ISSUE\",\"result\":\"https://rp.eidmongolia.mn/token/certificate/{sessionID}\",\"scopeLockedOnRenewal\":true," +
            "\"appTransaction\":\"optional\",\"personalAutoSupersede\":true,\"dryRun\":true}}");
        var i = await c.Token.CertificateInfoAsync();
        Assert.Equal("/.well-known/eid", h.Last.Path);
        Assert.True(i.Enabled && i.ScopeLockedOnRenewal && i.PersonalAutoSupersede && i.DryRun);
        Assert.Equal("TOKEN_ISSUE", i.Permission);
        Assert.Equal("optional", i.OnBehalfOf);
        Assert.Equal("optional", i.AppTransaction);
        Assert.NotNull(i.Raw);

        (c, _, _) = Rig.Create(200, "{\"version\":\"v3\"}");
        i = await c.Token.CertificateInfoAsync();
        Assert.False(i.Enabled || i.ScopeLockedOnRenewal);
        Assert.Equal("", i.AppTransaction);
    }

    // Go TestTokenCertificateAppTransaction.
    [Fact]
    public async Task AppTransaction()
    {
        using var p = new Pki();
        var (csrA, _, ka) = p.Leaf("PNOMN-12345678");
        var (csrS, _, ks) = p.Leaf("PNOMN-12345678");
        ka.Dispose();
        ks.Dispose();
        var hx = (Hex(csrA).ToLowerInvariant(), Hex(csrS).ToLowerInvariant());
        var input = new TokenCertInput
        {
            SignerEtsi = "PNOMN-12345678",
            CsrAuth = csrA,
            CsrSign = csrS,
            TokenSerial = "EP2003-0042A1",
            AppTransaction = "eyJhbGciOiJFUzI1NiJ9.e30.sig",
        };
        var (c, h, _) = Rig.Create(200, "{\"sessionID\":\"ts1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"04817\"},\"csrAuthSha256\":\"" + hx.Item1 +
            "\",\"csrSignSha256\":\"" + hx.Item2 + "\"}");
        Assert.Null((await c.Token.IssueCertificateAsync(input)).Supersedes);
        Assert.Equal(input.AppTransaction, h.Last.Json().GetProperty("appTransaction").GetString());

        var (c2, _, _) = Rig.Create(200, "{\"sessionID\":\"ts2\",\"csrAuthSha256\":\"" + hx.Item1 + "\",\"csrSignSha256\":\"" + hx.Item2 +
            "\",\"supersedes\":[{\"tokenSerial\":\"EP2003-0001\"}]}");
        Assert.Equal("EP2003-0001", Assert.Single((await c2.Token.IssueCertificateAsync(input)).Supersedes!).TokenSerial);

        await c.Token.IssueCertificateAsync(input with { AppTransaction = new string('a', TokenService.MaxAppTransactionBytes) });
        var n = h.Requests.Count;
        await Assert.ThrowsAsync<EidAppTransactionTooLargeException>(() =>
            c.Token.IssueCertificateAsync(input with { AppTransaction = new string('a', TokenService.MaxAppTransactionBytes + 1) }));
        Assert.Equal(n, h.Requests.Count);

        (c, _, _) = Rig.Create(400, "{\"error\":\"апп баталгаа хүчингүй\",\"code\":\"APP_ATTESTATION_INVALID\"}");
        var e = await Assert.ThrowsAsync<EidApiException>(() => c.Token.IssueCertificateAsync(input with { AppTransaction = "x.y.z" }));
        Assert.Equal(400, e.Status);
        Assert.Equal(TokenErrorCodes.AppAttestationInvalid, e.Code);
        Assert.False(e.Retryable);
    }

    // Go TestTokenCertificatePreview.
    [Fact]
    public async Task PreviewCertificate()
    {
        using var p = new Pki();
        var (csrA, _, ka) = p.Leaf("PNOMN-12345678");
        var (csrS, _, ks) = p.Leaf("PNOMN-12345678");
        ka.Dispose();
        ks.Dispose();
        var input = new TokenCertInput { SignerEtsi = "PNOMN-12345678", CsrAuth = csrA, CsrSign = csrS, TokenSerial = "EP2003-0042A2", AppTransaction = "a.b.c" };
        var (c, h, _) = Rig.Create(200, "{\"dryRun\":true,\"supersedes\":[{\"tokenSerial\":\"EP2003-0001\"}]}");
        var pr = await c.Token.PreviewCertificateAsync(input);
        Assert.Equal("EP2003-0001", Assert.Single(pr.Supersedes!).TokenSerial);
        var b = h.Last.Json();
        Assert.Equal("/token/certificate", h.Last.Path);
        Assert.True(b.GetProperty("dryRun").GetBoolean());
        Assert.Equal("EP2003-0042A2", b.GetProperty("tokenSerial").GetString());
        Assert.Equal("a.b.c", b.GetProperty("appTransaction").GetString());

        (c, _, _) = Rig.Create(200, "{\"dryRun\":true}");
        Assert.Null((await c.Token.PreviewCertificateAsync(input)).Supersedes);
        (c, _, _) = Rig.Create(409, "{\"error\":\"хязгаар\",\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"ORGANIZATION\",\"limit\":1,\"organization\":\"NTRMN-1\"}");
        Assert.Equal(TokenKinds.Organization, TokenService.TokenLimitOf(await Assert.ThrowsAsync<EidApiException>(() => c.Token.PreviewCertificateAsync(input)))!.Kind);
        (c, _, _) = Rig.Create(200, "{\"sessionID\":\"x\"}");
        Assert.Equal(ValidationReasons.ResponseMalformed, (await Assert.ThrowsAsync<EidValidationException>(() => c.Token.PreviewCertificateAsync(input))).Reason);
        await Assert.ThrowsAsync<ArgumentException>(() => c.Token.PreviewCertificateAsync(new TokenCertInput()));
    }

    // Go TestTokenAuth (docs/TOKEN_AUTH.md тест вектор).
    [Fact]
    public void TokenAuthDigestVector()
    {
        Assert.Equal("a88f9803b82f9e0701752360184f18f2035bc2447372283e3fa009fe2cfeeef5",
            Convert.ToHexString(TokenService.TokenAuthDigest(Rp, Ch32)).ToLowerInvariant());
        Assert.Throws<ArgumentException>(() => TokenService.TokenAuthDigest(Rp.ToUpperInvariant(), Ch32));
        Assert.Throws<ArgumentException>(() => TokenService.TokenAuthDigest(Rp + "\n", Ch32));
        Assert.Throws<ArgumentException>(() => TokenService.TokenAuthDigest(Rp, "AAEC"));
    }

    private const string OkVerify = "{\"result\":{\"endResult\":\"OK\"},\"identity\":{\"etsi\":\"PNOMN-55667788\",\"givenName\":\"Бат\",\"surname\":\"Болд\"}," +
        "\"cert\":{\"serialHex\":\"4f1c\",\"notAfter\":\"2027-10-12T08:40:00Z\"},\"organization\":{\"etsi\":\"NTRMN-1\",\"name\":\"X\"}}";

    private static byte[] SigOf(ECDsa key, TokenAuthChallenge ch) =>
        key.SignHash(TokenService.TokenAuthDigest(ch.RpUuid, ch.Challenge), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    // Go TestTokenAuth.
    [Fact]
    public async Task AuthChallengeAndVerify()
    {
        var (c0, h0, _) = Rig.Create(200, "{\"challengeId\":\"c1\",\"challenge\":\"q3J0\",\"rpUUID\":\"" + Rp + "\",\"expiresAt\":\"2026-10-12T08:42:10Z\"}");
        var ch0 = await c0.Token.AuthChallengeAsync();
        Assert.Equal("c1", ch0.ChallengeId);
        Assert.Equal(Rp, ch0.RpUuid);
        Assert.NotEqual(default, ch0.ExpiresAt);
        Assert.Equal("/token/auth/challenge", h0.Last.Path);
        JsonAssert.Equivalent("{\"relyingPartyName\":\"Гэрээний систем\",\"relyingPartyUUID\":\"rp-uuid\"}", h0.Last.Json());

        using var p = new Pki();
        var chal = new TokenAuthChallenge { ChallengeId = "c1", Challenge = Ch32, RpUuid = Rp };
        var (_, cert, key) = p.Leaf("PNOMN-55667788");
        using var disposeKey = key;
        var sig = SigOf(key, chal);
        var (c, h) = Client(_ => Rig.Json(200, OkVerify), OkTrust(p));
        var res = await c.Token.AuthVerifyAsync(chal, cert, sig);
        Assert.Equal("Болд", res.Identity.Surname);
        Assert.Equal("4f1c", res.SerialHex);
        Assert.Equal("NTRMN-1", res.Organization!.Etsi);
        Assert.Equal(2027, res.NotAfter.Year);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/token/auth/verify", h.Last.Path);
        JsonAssert.Equivalent("{\"challengeId\":\"c1\",\"certificate\":\"" + Convert.ToBase64String(cert) + "\",\"signature\":\"" +
            Convert.ToBase64String(sig) + "\"}", h.Last.Json());

        // CA-ийн хариу итгэхгүй: өөр иргэн, DENIED.
        foreach (var reply in new[] { OkVerify.Replace("PNOMN-55667788", "PNOMN-99999999", StringComparison.Ordinal), OkVerify.Replace("\"OK\"", "\"DENIED\"", StringComparison.Ordinal) })
        {
            (c, _) = Client(_ => Rig.Json(200, reply), OkTrust(p));
            var e = await Assert.ThrowsAsync<EidValidationException>(() => c.Token.AuthVerifyAsync(chal, cert, sig));
            Assert.Equal(ValidationReasons.TokenIdentity, e.Reason);
            Assert.DoesNotContain("PNOMN-", e.Message, StringComparison.Ordinal);
        }
        // Organization etsi хоосон → null.
        (c, _) = Client(_ => Rig.Json(200, OkVerify.Replace("\"etsi\":\"NTRMN-1\"", "\"etsi\":\"\"", StringComparison.Ordinal)), OkTrust(p));
        Assert.Null((await c.Token.AuthVerifyAsync(chal, cert, sig)).Organization);

        (c, _) = Client(_ => Rig.Json(410, "{\"error\":\"x\",\"code\":\"CHALLENGE_EXPIRED\"}"), OkTrust(p));
        Assert.Equal(TokenErrorCodes.ChallengeExpired, (await Assert.ThrowsAsync<EidApiException>(() => c.Token.AuthVerifyAsync(chal, cert, sig))).Code);

        (c, _) = Client(_ => Rig.Json(200, OkVerify), OkTrust(p));
        await Assert.ThrowsAsync<EidValidationException>(() => c.Token.AuthVerifyAsync(chal, Encoding.ASCII.GetBytes("junk"), sig));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Token.AuthVerifyAsync(null!, cert, sig));
    }

    // Go TestTokenAuth: SDK-ийн шалгалт унавал CA руу ЯВАХГҮЙ.
    [Fact]
    public async Task AuthVerifyLocalChecksBeforeCa()
    {
        using var p = new Pki();
        var chal = new TokenAuthChallenge { ChallengeId = "c1", Challenge = Ch32, RpUuid = Rp };
        var (_, cert, key) = p.Leaf("PNOMN-55667788");
        var (_, signCert, signKey) = p.Leaf("PNOMN-55667788", sign: true);
        var (_, dupCert, dupKey) = p.Leaf("PNOMN-55667788", extraCn: "TEST ONLY SECOND CN");
        using var k1 = key;
        using var k2 = signKey;
        using var k3 = dupKey;
        var sig = SigOf(key, chal);
        var other = chal with { Challenge = "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" };
        var otherRp = chal with { RpUuid = "00000000-0000-4000-8000-000000000000" };
        var cases = new (string Name, TokenAuthChallenge Ch, byte[] Cert, byte[] Sig, TrustConfig Trust, string Reason)[]
        {
            ("тэг гарын үсэг", chal, cert, new byte[64], OkTrust(p), ValidationReasons.TokenSignature),
            ("өөр challenge", other, cert, sig, OkTrust(p), ValidationReasons.TokenSignature),
            ("өөр RP", otherRp, cert, SigOf(key, otherRp), OkTrust(p), ValidationReasons.TokenChallenge),
            ("анхдагч issuer", chal, cert, sig, OkTrust(p) with { AllowAnyIssuer = false }, ValidationReasons.IssuerNotAllowed),
            ("anchor алга", chal, cert, sig, new TrustConfig(), ValidationReasons.TrustNoAnchor),
            ("гарын үсгийн гэрчилгээ", chal, signCert, SigOf(signKey, chal), OkTrust(p), ValidationReasons.PurposeAuthClientAuth),
            ("давхар CN", chal, dupCert, SigOf(dupKey, chal), OkTrust(p), ValidationReasons.SubjectDuplicateIdentity),
        };
        foreach (var tc in cases)
        {
            var (c, h) = Client(_ => Rig.Json(200, OkVerify), tc.Trust);
            var e = await Assert.ThrowsAsync<EidValidationException>(() => c.Token.AuthVerifyAsync(tc.Ch, tc.Cert, tc.Sig));
            Assert.True(tc.Reason == e.Reason, tc.Name + ": " + e.Reason);
            Assert.True(h.Requests.Count == 0, tc.Name + ": CA руу явсан");
        }
    }

    [Fact]
    public void TokenErrorCodesMatchGoOrder()
    {
        Assert.Equal(39, TokenErrorCodes.All.Count);
        Assert.Equal(TokenErrorCodes.All.Count, TokenErrorCodes.All.Distinct().Count());
        Assert.Equal("TOKEN_LIMIT_REACHED", TokenErrorCodes.All[0]);
        Assert.Equal("ISSUANCE_PENDING", TokenErrorCodes.All[^1]);
    }
}
