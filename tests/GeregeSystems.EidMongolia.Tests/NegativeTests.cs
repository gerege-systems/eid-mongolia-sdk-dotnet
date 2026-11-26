using System;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// Гарын үсгийн шалгалт бодитоор ажиллаж буйг батлах сөрөг тестүүд (security review S1): SignedBy / ParsedCert.Verifies,
/// ACSP_V2 ба RAW_DIGEST гарын үсэг, OCSP хариуны гарын үсэг ба delegated responder. Корпусын эерэг кейсийг байт солиж,
/// эсвэл тестийн өөрийн түлхүүрээр хуурамч гэрчилгээ / OCSP хариу үүсгэнэ (корпусын хувийн түлхүүрүүд vendor хийгдээгүй).
/// Эерэг хяналт: өөрчлөөгүй хувилбар бүр амжилттай.
/// </summary>
public class NegativeTests
{
    private const string RpValidate = "rp-validate/cases.json";
    private static readonly DateTimeOffset Now = Corpus.Time("2026-10-14T04:00:00Z");

    private static ResponseValidator Validator() =>
        new(Corpus.Trust(Corpus.Json(RpValidate).GetProperty("trust").GetProperty("default")), new ManualClock(Now));

    private static (SessionResult Session, AcspContext Acsp) Auth(string name)
    {
        var c = Corpus.Case(RpValidate, name);
        return (SessionService.ParseSessionResult(c.GetProperty("session").GetRawText()),
            JsonSerializer.Deserialize<AcspContext>(c.GetProperty("acsp").GetRawText(), EidHttp.Json)!);
    }

    private static byte[] Flip(byte[] b, int index)
    {
        var o = (byte[])b.Clone();
        o[index] ^= 0x01;
        return o;
    }

    private static string FlipB64(string b64, int? index = null)
    {
        var b = Convert.FromBase64String(b64);
        return Convert.ToBase64String(Flip(b, index ?? b.Length - 1));
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= hay.Length; i++)
        {
            if (hay.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                return i;
            }
        }
        return -1;
    }

    private static string Reason(Action a) => Assert.Throws<EidValidationException>(a).Reason;

    // ── (a) гинж: leaf-ийн TBS / гарын үсэг, завсрын CA-ийн гарын үсэг ──

    [Fact]
    public void TamperedLeafIsUntrusted()
    {
        var (r, acsp) = Auth("auth-pss-sha512-qr");
        var v = Validator();
        v.ValidateAuth(r, acsp);
        var der = Convert.FromBase64String(r.CertificateDerB64);
        var leaf = ParsedCert.Parse(der);
        var issuer = ParsedCert.ParsePem(Corpus.Text("pki/04-eid.pem")).Single();
        // Нөхцөл: issuer-ийн нэр ба AKI яг таарна — зөвхөн гарын үсэг л ялгана.
        Assert.Equal(issuer.RawSubject, leaf.RawIssuer);
        Assert.Equal(issuer.SubjectKeyId, leaf.AuthorityKeyId);

        // TBS доторх нэг байт (subject CN "TESTOV TEST" → "TXSTOV TEST"; DER хүчинтэй хэвээр).
        var at = IndexOf(der, Encoding.ASCII.GetBytes("TESTOV TEST"));
        Assert.True(at > 0 && at < leaf.Tbs.Length);
        var tbsFlip = der.ToArray();
        tbsFlip[at + 1] = (byte)'X';
        Assert.Equal(issuer.RawSubject, ParsedCert.Parse(tbsFlip).RawIssuer);
        Assert.Equal(ValidationReasons.ChainUntrusted,
            Reason(() => v.ValidateAuth(r with { CertificateDerB64 = Convert.ToBase64String(tbsFlip) }, acsp)));

        // Гарын үсгийн сүүлийн байт.
        Assert.Equal(ValidationReasons.ChainUntrusted,
            Reason(() => v.ValidateAuth(r with { CertificateDerB64 = Convert.ToBase64String(Flip(der, der.Length - 1)) }, acsp)));
    }

    [Fact]
    public void TamperedIntermediateSignatureIsUntrusted()
    {
        var (r, acsp) = Auth("auth-pss-sha512-qr");
        var tr = Corpus.Trust(Corpus.Json(RpValidate).GetProperty("trust").GetProperty("default"));
        var der04 = ParsedCert.ParsePem(Corpus.Text("pki/04-eid.pem")).Single().Raw;
        var bad04 = new string(PemEncoding.Write("CERTIFICATE", Flip(der04, der04.Length - 1)));
        var good04 = Corpus.Text("pki/04-eid.pem");
        var inter = tr.IntermediatesPem!.Select(p => p == good04 ? bad04 : p).ToList();
        Assert.Contains(bad04, inter);
        var v = new ResponseValidator(tr with { IntermediatesPem = inter }, new ManualClock(Now));
        Assert.Equal(ValidationReasons.ChainUntrusted, Reason(() => v.ValidateAuth(r, acsp)));
    }

    // ── (b) өөр түлхүүрээр зурсан, жинхэнэ issuer-ийн нэр + AKI-тай leaf ──

    [Fact]
    public void ForgedLeafWithIssuerNameAndAkiIsUntrusted()
    {
        var (r, acsp) = Auth("auth-pss-sha512-qr");
        var issuer = ParsedCert.ParsePem(Corpus.Text("pki/04-eid.pem")).Single();
        using var attacker = RSA.Create(2048);
        using var leafKey = RSA.Create(2048);
        var req = new CertificateRequest("C=MN, CN=TESTOV TEST", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.4") }, false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuer.SubjectKeyId!));
        using var forged = req.Create(new X500DistinguishedName(issuer.RawSubject), X509SignatureGenerator.CreateForRSA(attacker, RSASignaturePadding.Pkcs1),
            Now.AddDays(-1), Now.AddDays(30), new byte[] { 0x10, 0x99 });
        var f = ParsedCert.Parse(forged.RawData);
        Assert.Equal(issuer.RawSubject, f.RawIssuer);
        Assert.Equal(issuer.SubjectKeyId, f.AuthorityKeyId);
        Assert.Equal(ValidationReasons.ChainUntrusted,
            Reason(() => Validator().ValidateAuth(r with { CertificateDerB64 = Convert.ToBase64String(forged.RawData) }, acsp)));
    }

    // ── (c) ACSP_V2 ба RAW_DIGEST гарын үсэг ──

    [Theory]
    [InlineData("auth-pss-sha512-qr")]
    [InlineData("auth-sha256withrsa")]
    [InlineData("auth-token-ec-p256")]
    public void AuthSignatureAndPayloadFlipsFail(string name)
    {
        var (r, acsp) = Auth(name);
        var v = Validator();
        v.ValidateAuth(r, acsp);
        Assert.Equal(ValidationReasons.AuthSignature, Reason(() => v.ValidateAuth(r with { SignatureValueB64 = FlipB64(r.SignatureValueB64) }, acsp)));
        // Payload-ийн нэг байт: RP-ийн rpChallenge-ийн эхний тэмдэгт.
        var ch = acsp.RpChallenge;
        var other = acsp with { RpChallenge = (ch[0] == 'A' ? "B" : "A") + ch[1..] };
        Assert.Equal(ValidationReasons.AuthSignature, Reason(() => v.ValidateAuth(r, other)));
    }

    [Theory]
    [InlineData("sign-pss-sha256")]
    [InlineData("sign-pss-sha512")]
    [InlineData("sign-pkcs1-sha384")]
    [InlineData("sign-ec-legacy")]
    public void SignSignatureAndDigestFlipsFail(string name)
    {
        var c = Corpus.Case(RpValidate, name);
        var r = SessionService.ParseSessionResult(c.GetProperty("session").GetRawText());
        var digest = c.GetProperty("digest").GetString()!;
        var hash = c.GetProperty("hashAlgorithm").GetString();
        var v = Validator();
        v.ValidateSign(r, digest, hash);
        Assert.Equal(ValidationReasons.SignSignature, Reason(() => v.ValidateSign(r with { SignatureValueB64 = FlipB64(r.SignatureValueB64) }, digest, hash)));
        Assert.Equal(ValidationReasons.SignSignature, Reason(() => v.ValidateSign(r, FlipB64(digest, 0), hash)));
    }

    // ── (d) OCSP ──

    [Fact]
    public async Task OcspResponseSignatureFlipIsSignatureError()
    {
        var c = Corpus.Case("ocsp/cases.json", "good");
        var rep = c.GetProperty("http").GetProperty("POST http://ocsp.conformance.test/ocsp");
        var der = Convert.FromBase64String(rep.GetProperty("bodyB64").GetString()!);
        var (at, len) = OcspSignature(der);
        using var leaf = Corpus.Cert("pki/leaf-auth.pem");
        using var issuer = Corpus.Cert("pki/04-eid.pem");
        Assert.Equal(RevocationStatus.Good, await Checker(der).CheckAsync(leaf, issuer));
        var e = await Assert.ThrowsAsync<EidOcspException>(() => Checker(Flip(der, at + len / 2)).CheckAsync(leaf, issuer));
        Assert.Equal(OcspErrorKinds.Signature, e.Kind);
    }

    /// <summary>BasicOCSPResponse-ийн signature BIT STRING-ийн байтуудын байрлал (бүтэн DER дотор).</summary>
    private static (int Index, int Length) OcspSignature(byte[] der)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        outer.ReadEnumeratedBytes();
        var rb = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        rb.ReadObjectIdentifier();
        var basic = new AsnReader(rb.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
        basic.ReadEncodedValue();
        basic.ReadEncodedValue();
        var sig = basic.ReadBitString(out _);
        var at = IndexOf(der, sig);
        Assert.True(at > 0);
        return (at, sig.Length);
    }

    /// <summary>Тестийн өөрийн PKI: CA → leaf (AIA OCSP), CA → delegated responder (OCSPSigning).</summary>
    private sealed class TestPki : IDisposable
    {
        public const string Url = "http://ocsp.test.invalid/ocsp";
        public static readonly byte[] LeafSerial = { 0x01, 0x23 };

        public TestPki()
        {
            CaKey = RSA.Create(2048);
            var cr = new CertificateRequest("CN=TEST ONLY OCSP CA", CaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            cr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            cr.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            cr.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(cr.PublicKey, false));
            Ca = cr.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(1));
            using var leafKey = RSA.Create(2048);
            var lr = new CertificateRequest("CN=TEST ONLY OCSP leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            lr.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(new[] { Url }, null));
            Leaf = lr.Create(Ca, Now.AddDays(-30), Now.AddDays(30), LeafSerial);
        }

        public RSA CaKey { get; }

        public X509Certificate2 Ca { get; }

        public X509Certificate2 Leaf { get; }

        /// <summary>OCSPSigning EKU-тэй responder: <paramref name="issuer"/> null бол өөрөө зурсан (CA-тай холбоогүй).</summary>
        public static X509Certificate2 Responder(RSA key, X509Certificate2? issuer, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var r = new CertificateRequest("CN=TEST ONLY OCSP responder", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.9") }, false));
            return issuer is null ? r.CreateSelfSigned(notBefore, notAfter) : r.Create(issuer, notBefore, notAfter, new byte[] { 0x02, 0x34 });
        }

        public void Dispose()
        {
            Leaf.Dispose();
            Ca.Dispose();
            CaKey.Dispose();
        }
    }

    /// <summary>
    /// Delegated responder-ийн зурсан BasicOCSPResponse (good, thisUpdate = now − 1 ц, responder-ийг шигтгэсэн). CertID-ийн
    /// issuerNameHash / issuerKeyHash = SHA-1(<paramref name="certIdIssuer"/>-ийн subject / түлхүүр) — null бол тэг байт.
    /// </summary>
    private static byte[] OcspResponse(byte[] serial, RSA signer, X509Certificate2 responder, X509Certificate2? certIdIssuer)
    {
        var thisUpdate = Now.AddHours(-1);
        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                tbs.WriteEncodedValue(responder.SubjectName.RawData);
            }
            tbs.WriteGeneralizedTime(thisUpdate);
            using (tbs.PushSequence())
            using (tbs.PushSequence())
            {
                using (tbs.PushSequence())
                {
                    using (tbs.PushSequence())
                    {
                        tbs.WriteObjectIdentifier("1.3.14.3.2.26");
                        tbs.WriteNull();
                    }
                    tbs.WriteOctetString(certIdIssuer is null ? new byte[20] : SHA1.HashData(certIdIssuer.SubjectName.RawData));
                    tbs.WriteOctetString(certIdIssuer is null ? new byte[20] : SHA1.HashData(certIdIssuer.PublicKey.EncodedKeyValue.RawData));
                    tbs.WriteInteger(serial);
                }
                tbs.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0));
                tbs.WriteGeneralizedTime(thisUpdate);
            }
        }
        var tbsDer = tbs.Encode();
        var basic = new AsnWriter(AsnEncodingRules.DER);
        using (basic.PushSequence())
        {
            basic.WriteEncodedValue(tbsDer);
            using (basic.PushSequence())
            {
                basic.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                basic.WriteNull();
            }
            basic.WriteBitString(signer.SignData(tbsDer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (basic.PushSequence())
            {
                basic.WriteEncodedValue(responder.RawData);
            }
        }
        var resp = new AsnWriter(AsnEncodingRules.DER);
        using (resp.PushSequence())
        {
            resp.WriteEncodedValue(new byte[] { 0x0A, 0x01, 0x00 });
            using (resp.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (resp.PushSequence())
            {
                resp.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
                resp.WriteOctetString(basic.Encode());
            }
        }
        return resp.Encode();
    }

    private static OcspRevocationChecker Checker(byte[] response) => new(new OcspOptions
    {
        HttpClient = new HttpClient(new Recorder(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(response) })),
        TimeProvider = new ManualClock(Now),
    });

    [Fact]
    public async Task OcspDelegatedResponderMustBeIssuedByIssuerAndValid()
    {
        using var pki = new TestPki();
        using var key = RSA.Create(2048);

        // Эерэг хяналт: CA-ийн гаргасан, хүчинтэй responder → good.
        using (var ok = TestPki.Responder(key, pki.Ca, Now.AddDays(-10), Now.AddDays(10)))
        {
            Assert.Equal(RevocationStatus.Good, await Checker(OcspResponse(TestPki.LeafSerial, key, ok, pki.Ca)).CheckAsync(pki.Leaf, pki.Ca));
        }

        // CA-тай холбоогүй (өөрөө зурсан) responder.
        using (var rogue = TestPki.Responder(key, null, Now.AddDays(-10), Now.AddDays(10)))
        {
            var e = await Assert.ThrowsAsync<EidOcspException>(() => Checker(OcspResponse(TestPki.LeafSerial, key, rogue, pki.Ca)).CheckAsync(pki.Leaf, pki.Ca));
            Assert.Equal(OcspErrorKinds.Signature, e.Kind);
        }

        // CA-ийн гаргасан ч хугацаа нь дууссан responder.
        using (var expired = TestPki.Responder(key, pki.Ca, Now.AddDays(-10), Now.AddDays(-1)))
        {
            var e = await Assert.ThrowsAsync<EidOcspException>(() => Checker(OcspResponse(TestPki.LeafSerial, key, expired, pki.Ca)).CheckAsync(pki.Leaf, pki.Ca));
            Assert.Equal(OcspErrorKinds.Signature, e.Kind);
        }

        // Хүчинтэй responder-ийн хариуны гарын үсгийн байт солигдсон.
        using (var ok = TestPki.Responder(key, pki.Ca, Now.AddDays(-10), Now.AddDays(10)))
        {
            var der = OcspResponse(TestPki.LeafSerial, key, ok, pki.Ca);
            var (at, len) = OcspSignature(der);
            var e = await Assert.ThrowsAsync<EidOcspException>(() => Checker(Flip(der, at + len / 2)).CheckAsync(pki.Leaf, pki.Ca));
            Assert.Equal(OcspErrorKinds.Signature, e.Kind);
        }
    }

    // ── .NET-ийн нэмэлт OCSP хатуурал (cross-SDK review S5; Go/TS хараахан хийдэггүй) ──

    /// <summary>Хариуны CertID-ийн issuerNameHash / issuerKeyHash issuer-ийнхтэй таарахгүй бол (гарын үсэг зөв ч) invalid.</summary>
    [Fact]
    public async Task OcspCertIdMustMatchIssuer()
    {
        using var pki = new TestPki();
        using var other = new TestPki();
        using var key = RSA.Create(2048);
        using var ok = TestPki.Responder(key, pki.Ca, Now.AddDays(-10), Now.AddDays(10));
        foreach (var certIdIssuer in new[] { null, other.Ca })
        {
            var e = await Assert.ThrowsAsync<EidOcspException>(() =>
                Checker(OcspResponse(TestPki.LeafSerial, key, ok, certIdIssuer)).CheckAsync(pki.Leaf, pki.Ca));
            Assert.Equal(OcspErrorKinds.Invalid, e.Kind);
            Assert.Contains("CertID", e.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>Өгсөн issuer leaf-ийг гаргаагүй бол responder-оос асуухгүй (no_issuer, HTTP хүсэлтгүй).</summary>
    [Fact]
    public async Task OcspIssuerMustSignLeafBeforeNetwork()
    {
        using var pki = new TestPki();
        using var other = new TestPki();
        var rec = new Recorder(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var checker = new OcspRevocationChecker(new OcspOptions { HttpClient = new HttpClient(rec), TimeProvider = new ManualClock(Now) });
        var e = await Assert.ThrowsAsync<EidOcspException>(() => checker.CheckAsync(pki.Leaf, other.Ca));
        Assert.Equal(OcspErrorKinds.NoIssuer, e.Kind);
        Assert.Empty(rec.Requests);
        // Зөв issuer-тэй бол сүлжээ рүү гарна (энд 500 → http_status).
        Assert.Equal(OcspErrorKinds.HttpStatus, (await Assert.ThrowsAsync<EidOcspException>(() => checker.CheckAsync(pki.Leaf, pki.Ca))).Kind);
        Assert.Single(rec.Requests);
    }

    /// <summary>.NET-ийн нэмэлт: subject-д SERIALNUMBER эсвэл CN давхардсан гэрчилгээг validator татгалзана.</summary>
    [Fact]
    public void DuplicateSubjectIdentityIsDetected()
    {
        foreach (var (oid, ok) in new[] { ("2.5.4.5", false), ("2.5.4.3", false), ("2.5.4.42", true) })
        {
            var b = new X500DistinguishedNameBuilder();
            b.Add("2.5.4.5", "PNOMN-1", UniversalTagNumber.PrintableString);
            b.AddCommonName("TEST ONLY A");
            b.Add(oid, "TEST ONLY B", UniversalTagNumber.UTF8String);
            using var k = RSA.Create(2048);
            using var c = new CertificateRequest(b.Build(), k, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
            var p = ParsedCert.Parse(c.RawData);
            Assert.Equal(!ok, p.DuplicateSubjectIdentity);
            if (!ok)
            {
                Assert.Equal(ValidationReasons.SubjectDuplicateIdentity,
                    Assert.Throws<EidValidationException>(() => ResponseValidator.CheckSubjectIdentity(p)).Reason);
            }
        }
    }
}
