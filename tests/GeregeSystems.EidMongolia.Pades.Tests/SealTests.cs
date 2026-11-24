using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Байгууллагын тамга (<see cref="EidPades.SealAsync"/>): тест 04 олгосон e-Seal гэрчилгээ (ECDSA P-256, KeyUsage зөвхөн
/// nonRepudiation), fake TSA (tsa.pem-ээр зурсан RFC 3161 token), тамга ба TSA-ийн OCSP-г 04-ийн түлхүүрээр, бусдыг golden
/// HTTP fixture-ээс → PAdES-B-LT. Мөн CA <c>POST /seal/{orgEtsi}</c> хариуны дээж (testdata/seal_response.json).
/// </summary>
public class SealTests
{
    private static readonly JsonElement Manifest = LoadManifest();

    private static JsonElement LoadManifest()
    {
        using var d = JsonDocument.Parse(Fixtures.Read("manifest.json"));
        return d.RootElement.Clone();
    }

    private static readonly DateTimeOffset Now = DateTimeOffset.Parse(Manifest.GetProperty("now").GetString()!, CultureInfo.InvariantCulture);
    private static readonly DateTimeOffset SigningTime = DateTimeOffset.Parse(Manifest.GetProperty("signingTime").GetString()!, CultureInfo.InvariantCulture);
    private static readonly X509Certificate2 Ca04 = RevocationTests.Cert("04");
    private static readonly X509Certificate2 Tsa = RevocationTests.Cert("tsa");

    private static byte[] Input() => Fixtures.Read("input", "quartz-pdf13.pdf");

    private static byte[][] Chain() => new[] { Ca04.RawData, RevocationTests.Cert("03").RawData, RevocationTests.Cert("02").RawData };

    /// <summary>Тест 04-өөр олгосон ECDSA P-256 гэрчилгээ (байгууллагын тамганы профайл: <paramref name="usage"/>, EKU-гүй).</summary>
    private static (X509Certificate2 Cert, ECDsa Key) Issue(X509KeyUsageFlags usage, string serialHex)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var dn = new X500DistinguishedNameBuilder();
        dn.AddCountryOrRegion("MN");
        dn.AddOrganizationName("TEST ONLY Seal Org LLC");
        dn.Add("2.5.4.97", "NTRMN-1234567", UniversalTagNumber.UTF8String);
        dn.AddCommonName("TEST ONLY Seal Org LLC");
        var req = new CertificateRequest(dn.Build(), key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        req.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(new[] { "http://ocsp.pki.test/04" }, null));
        req.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(new[] { "http://crl.pki.test/04.crl" }));
        using var ca = RevocationTests.WithKey("04");
        using var caKey = ca.GetRSAPrivateKey()!;
        var cert = req.Create(Ca04.SubjectName, X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2028, 1, 1, 0, 0, 0, TimeSpan.Zero),
            Convert.FromHexString(serialHex));
        return (cert, key);
    }

    /// <summary>
    /// TSA: хүсэлтийн hash/nonce-оор tsa.pem-ийн түлхүүрээр зурсан token (genTime = Now − 20 с). OCSP 04: тамга ба TSA-ийн
    /// хүсэлтэд «good» (thisUpdate = Now − 10 с, genTime-аас хойш). Бусад нь golden replay.
    /// </summary>
    private sealed class Pki : HttpMessageHandler
    {
        private readonly X509Certificate2 _seal;

        public Pki(X509Certificate2 seal) => _seal = seal;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(ct);
            var url = request.RequestUri!.ToString();
            if (url == "http://tsa.pki.test/") return Reply(TimeStamp(body));
            if (url == "http://ocsp.pki.test/04")
            {
                foreach (var c in new[] { _seal, Tsa })
                {
                    if (body.AsSpan().SequenceEqual(Ocsp.CreateRequest(c, Ca04)))
                    {
                        using var signer = RevocationTests.WithKey("04");
                        return Reply(RevocationTests.OcspResponse(signer, Ca04, Cms.Serial(c), RevocationTests.St.Good, Now.AddSeconds(-10), Now.AddDays(1)));
                    }
                }
            }
            var key = request.Method.Method + " " + url + " " + Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant()[..16];
            return Reply(Manifest.GetProperty("http").TryGetProperty(key, out var f) ? Fixtures.Read(f.GetString()!.Split('/')) : null);
        }

        private static HttpResponseMessage Reply(byte[]? b) =>
            b is null ? new HttpResponseMessage(HttpStatusCode.NotFound) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(b) };

        /// <summary>TimeStampResp{ status granted, token = SignedData(TSTInfo), signingCertificateV2 }.</summary>
        private static byte[] TimeStamp(byte[] query)
        {
            Assert.True(Rfc3161TimestampRequest.TryDecode(query, out var req, out _));
            var info = new Rfc3161TimestampTokenInfo(new Oid("1.3.6.1.4.1.99999.1"), req!.HashAlgorithmId, req.GetMessageHash(), new byte[] { 0x5E, 0xA1 },
                Now.AddSeconds(-20), nonce: req.GetNonce());
            var cms = new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), info.Encode()));
            using var tsa = RevocationTests.WithKey("tsa");
            var essId = new AsnWriter(AsnEncodingRules.DER);
            using (essId.PushSequence())
            using (essId.PushSequence())
            using (essId.PushSequence())
                essId.WriteOctetString(SHA256.HashData(tsa.RawData));
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tsa)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
                IncludeOption = X509IncludeOption.EndCertOnly,
            };
            signer.SignedAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.16.2.47", essId.Encode()));
            cms.ComputeSignature(signer);
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                    w.WriteInteger(0);
                w.WriteEncodedValue(cms.Encode());
            }
            return w.Encode();
        }
    }

    private sealed class FixedTime : TimeProvider
    {
        private readonly DateTimeOffset _t;

        public FixedTime(DateTimeOffset t) => _t = t;

        public override DateTimeOffset GetUtcNow() => _t.ToUniversalTime();
    }

    private static CompleteOptions Complete(HttpClient http) => new()
    {
        TsaUrl = "http://tsa.pki.test/",
        Roots = new[] { RevocationTests.Cert("root").RawData },
        HttpClient = http,
        TimeProvider = new FixedTime(Now),
        Sleep = (_, _) => Task.CompletedTask,
    };

    [Fact]
    public async Task SealProducesBaselineLt()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA101");
        using var owned = key;
        using var http = new HttpClient(new Pki(seal));
        byte[]? seen = null;
        var done = await EidPades.SealAsync(Input(), new SealOptions { SealCert = seal.RawData, Chain = Chain(), Reason = "Байгууллагын тамга", SigningTime = SigningTime },
            (dtbs, ct) =>
            {
                seen = dtbs;
                return Task.FromResult(key.SignHash(dtbs, DSASignatureFormat.Rfc3279DerSequence)); // CA signature.value (ECDSA DER)
            }, Complete(http));

        Assert.Equal(32, seen!.Length);
        Assert.Equal(1, done.RevIndex);
        Assert.False(done.HasPage);
        Assert.Equal(seal.RawData, done.SignerCert);
        Assert.Equal(Fixtures.Sha(done.Pdf), done.OutSha256);
        // Анхдагч = харагдах тамганы дардас (APPEARANCE_SPEC.md §6.4): Letter хуудасны баруун доод буланд (612 − 256, 36).
        Assert.Equal(new Placement { Page = 1, X = 356, Y = 36, Width = 220, Height = 64, Status = PlacementStatus.Requested }, done.Placement);
        Assert.Contains("/AP << /N ", Encoding.Latin1.GetString(done.Pdf, Input().Length, done.Pdf.Length - Input().Length), StringComparison.Ordinal);
        // Verify хуудас / QR алга — тамгыг /verify/{docId}-д бүртгэдэггүй.
        Assert.DoesNotContain(EidPades.PageVerifyUrl, Encoding.Latin1.GetString(done.Pdf), StringComparison.Ordinal);
        var (sigs, _, hasDss) = Prechecks.Scan(done.Pdf);
        Assert.Single(sigs);
        Assert.True(hasDss);
        var (leaf, stamped) = Prechecks.CheckSignature(done.Pdf, sigs[0]);
        Assert.Equal(seal.RawData, leaf.RawData);
        Assert.True(stamped); // RFC 3161 timestamp (B-T) + /DSS (B-LT)
    }

    [Fact]
    public async Task NonSealCertIsSignerInvalid()
    {
        var (cert, key) = Issue(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, "5EA102");
        using var owned = key;
        var called = false;
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.SealAsync(Input(), new SealOptions { SealCert = cert.RawData, Chain = Chain() },
            (_, _) =>
            {
                called = true;
                return Task.FromResult(Array.Empty<byte>());
            }));
        Assert.Equal(EidPadesErrorCode.SignerInvalid, ex.Code);
        Assert.False(called);
        // Иргэний (golden) гэрчилгээ — digitalSignature бий.
        ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.SealAsync(Input(),
            new SealOptions { SealCert = RevocationTests.Cert("citizen").RawData, Chain = Chain() }, (_, _) => Task.FromResult(Array.Empty<byte>())));
        Assert.Equal(EidPadesErrorCode.SignerInvalid, ex.Code);
    }

    [Fact]
    public async Task SignatureByAnotherKeyIsSignatureInvalid()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA103");
        using var owned = key;
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var http = new HttpClient(new Pki(seal));
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.SealAsync(Input(), new SealOptions { SealCert = seal.RawData, Chain = Chain() },
            (dtbs, _) => Task.FromResult(other.SignHash(dtbs, DSASignatureFormat.Rfc3279DerSequence)), Complete(http)));
        Assert.Equal(EidPadesErrorCode.SignatureInvalid, ex.Code);
    }

    [Fact]
    public async Task DelegateExceptionPropagates()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA104");
        using var owned = key;
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => EidPades.SealAsync(Input(), new SealOptions { SealCert = seal.RawData, Chain = Chain() },
            (_, _) => throw new HttpRequestException("429 RATE_LIMITED", null, HttpStatusCode.TooManyRequests)));
        Assert.Equal(HttpStatusCode.TooManyRequests, ex.StatusCode);
    }

    /// <summary>CA <c>POST /seal/{orgEtsi}</c> хариу: <c>signature.value</c> (base64 ECDSA DER) = delegate-ийн буцаах байт.</summary>
    [Fact]
    public void CaSealResponseFeedsTheDelegate()
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "testdata", "seal_response.json")));
        var req = doc.RootElement.GetProperty("request");
        var resp = doc.RootElement.GetProperty("response");
        Assert.Equal("SHA256", req.GetProperty("hashType").GetString());
        var digest = Convert.FromBase64String(req.GetProperty("digest").GetString()!);
        var signature = Convert.FromBase64String(resp.GetProperty("signature").GetProperty("value").GetString()!);
        using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(resp.GetProperty("cert").GetProperty("value").GetString()!));

        Assert.True(EidPades.IsSealCertificate(cert));
        Assert.Equal("NTRMN-1234567", EidPades.LastAttr(cert.SubjectName, "2.5.4.97"));
        Assert.Equal(resp.GetProperty("orgEtsi").GetString(), EidPades.LastAttr(cert.SubjectName, "2.5.4.97"));
        using var pub = cert.GetECDsaPublicKey()!;
        Assert.True(pub.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence));
    }

    // ── Харагдах тамганы дардас (APPEARANCE_SPEC.md §6) ──

    /// <summary>
    /// §6.1: хувилбарыг зөвхөн гэрчилгээ сонгоно — CA биш, keyUsage bit 1 тавигдсан ба bit 0 тавигдаагүй (бусад бит, жишээ нь
    /// 32, үл тооно), EKU-ийн зорилгогүй (хоосон дараалал = зорилгогүй; танихгүй зорилго ч → биш).
    /// </summary>
    [Fact]
    public void SealCertificateRule()
    {
        var nonRep = new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, true);
        Assert.True(EidPades.IsSealCertificate(Variant(nonRep)));
        Assert.True(EidPades.IsSealCertificate(Variant(nonRep, new X509Extension("2.5.29.37", new byte[] { 0x30, 0x00 }, false))));
        Assert.True(EidPades.IsSealCertificate(Variant(nonRep, new X509BasicConstraintsExtension(false, false, 0, true))));
        // keyUsage BIT STRING 5 байт: bit 1 + bit 32 (07 40 00 00 00 80) → seal; bit 0 + 1 + 32 → биш.
        Assert.True(EidPades.IsSealCertificate(Variant(new X509Extension("2.5.29.15", new byte[] { 0x03, 0x06, 0x07, 0x40, 0, 0, 0, 0x80 }, true))));
        Assert.False(EidPades.IsSealCertificate(Variant(new X509Extension("2.5.29.15", new byte[] { 0x03, 0x06, 0x07, 0xC0, 0, 0, 0, 0x80 }, true))));

        Assert.False(EidPades.IsSealCertificate(Variant()));
        Assert.False(EidPades.IsSealCertificate(Variant(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DigitalSignature, true))));
        Assert.False(EidPades.IsSealCertificate(Variant(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true))));
        Assert.False(EidPades.IsSealCertificate(Variant(nonRep,
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.4.1.99999.7") }, false))));
        Assert.False(EidPades.IsSealCertificate(Variant(nonRep,
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, false))));
        Assert.False(EidPades.IsSealCertificate(Variant(nonRep, new X509BasicConstraintsExtension(true, false, 0, true))));

        Assert.True(EidPades.IsSealCertificate(RevocationTests.Cert("seal")));
        Assert.False(EidPades.IsSealCertificate(RevocationTests.Cert("citizen")));
        Assert.False(EidPades.IsSealCertificate(RevocationTests.Cert("04")));
    }

    /// <summary>
    /// Invisible = true: Sealer-т очих DTBS нь дардас нэмэгдэхээс өмнөх SealAsync-ийн (Appearance-гүй, verify хуудасгүй
    /// Prepare) DTBS-тэй ижил — prepared PDF ба signedAttrs байт-ижил; Appearance-ийг үл тооно, Placement null.
    /// </summary>
    [Fact]
    public async Task InvisibleMatchesThePreviousSeal()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA105");
        using var owned = key;
        using var http = new HttpClient(new Pki(seal));
        foreach (var input in new[] { Input(), Fixtures.Read("input", "libreoffice-contract.pdf") })
        {
            var (done, dtbs) = await Seal(input, seal, key, http, SealOpts(seal) with
            {
                Invisible = true,
                Appearance = new Appearance { X = 36, Y = 36, Width = 220, Height = 64 },
            });
            Assert.Equal(EidPades.Prepare(input, PreviousSeal(seal)).Dtbs, dtbs);
            Assert.Null(done.Placement);
            Assert.DoesNotContain("/AP << /N ", Encoding.Latin1.GetString(done.Pdf, input.Length, done.Pdf.Length - input.Length), StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// §6.4 жижиг хуудас: 58 мм-ийн баримт (164 pt) → 156 × 64 pt, x = 4; дардас багтахгүй хуудас (40 × 60) → үл харагдах
    /// тамга (Placement null, DTBS = өмнөх SealAsync), алдаагүй; дуудагчийн өгсөн Appearance багтахгүй бол REQUEST_INVALID.
    /// </summary>
    [Fact]
    public async Task SmallPagesFitOrFallBackToInvisible()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA106");
        using var owned = key;
        using var http = new HttpClient(new Pki(seal));

        var (receipt, _) = await Seal(PagePdf(164, 600), seal, key, http, SealOpts(seal));
        Assert.Equal(new Placement { Page = 1, X = 4, Y = 36, Width = 156, Height = 64, Status = PlacementStatus.Requested }, receipt.Placement);

        var tiny = PagePdf(40, 60);
        var (small, dtbs) = await Seal(tiny, seal, key, http, SealOpts(seal));
        Assert.Null(small.Placement);
        Assert.Equal(EidPades.Prepare(tiny, PreviousSeal(seal)).Dtbs, dtbs);

        var called = false;
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.SealAsync(tiny,
            SealOpts(seal) with { Appearance = new Appearance { X = 0, Y = 0, Width = 40, Height = 60 } }, (_, _) =>
            {
                called = true;
                return Task.FromResult(Array.Empty<byte>());
            }, Complete(http)));
        Assert.Equal(EidPadesErrorCode.RequestInvalid, ex.Code);
        Assert.False(called);
    }

    /// <summary>
    /// §6.4 хэмжээний хязгаар: үл харагдах тамга багтах ч автомат дардасны фонт (~82 KB) prepared PDF-ийг хязгаараас хэтрүүлэх
    /// оролт → анхдагч нь үл харагдах тамга (Placement null, DTBS = өмнөх SealAsync); дуудагчийн Appearance-тэй бол PDF_TOO_LARGE.
    /// </summary>
    [Fact]
    public async Task NearSizeLimitFallsBackToInvisible()
    {
        var (seal, key) = Issue(X509KeyUsageFlags.NonRepudiation, "5EA107");
        using var owned = key;
        using var http = new HttpClient(new Pki(seal));
        int Overhead(byte[] doc, Appearance? a) =>
            PrepState.Decode(EidPades.Prepare(doc, PreviousSeal(seal) with { Appearance = a }).State).Pdf.Length - doc.Length;
        var probe = PagePdf(612, 792, 1000);
        int inv = Overhead(probe, null), vis = Overhead(probe, EidPades.DefaultSealAppearance(probe));
        Assert.True(vis - inv >= 40_000, $"overheads: invisible {inv}, visible {vis}");
        // len(doc) + inv ≤ MaxInputBytes < len(doc) + vis (Prepare: len(prepared) + 256 KiB ≤ MaxOutputBytes).
        int target = EidPades.MaxOutputBytes - (256 << 10) - (inv + vis) / 2;
        var doc = PagePdf(612, 792, 1000 + target - probe.Length);
        Assert.InRange(doc.Length - target, -100, 100); // /Length and xref offset digits differ slightly
        Assert.True(doc.Length <= EidPades.MaxInputBytes);
        var direct = Assert.Throws<EidPadesException>(() =>
            EidPades.Prepare(doc, PreviousSeal(seal) with { Appearance = EidPades.DefaultSealAppearance(doc) }));
        Assert.Equal(EidPadesErrorCode.PdfTooLarge, direct.Code);

        var (done, dtbs) = await Seal(doc, seal, key, http, SealOpts(seal));
        Assert.Null(done.Placement);
        Assert.Equal(EidPades.Prepare(doc, PreviousSeal(seal)).Dtbs, dtbs);

        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.SealAsync(doc,
            SealOpts(seal) with { Appearance = new Appearance { X = 340, Y = 36, Width = 220, Height = 64 } },
            (_, _) => Task.FromResult(Array.Empty<byte>()), Complete(http)));
        Assert.Equal(EidPadesErrorCode.PdfTooLarge, ex.Code);
    }

    private static SealOptions SealOpts(X509Certificate2 seal) =>
        new() { SealCert = seal.RawData, Chain = Chain(), Reason = "Байгууллагын тамга", SigningTime = SigningTime };

    /// <summary>Дардас нэмэгдэхээс өмнөх SealAsync-ийн Prepare (verify хуудасгүй, Appearance-гүй, /Name = CN).</summary>
    private static PrepareOptions PreviousSeal(X509Certificate2 seal) => new()
    {
        SignerCert = seal.RawData,
        Chain = Chain(),
        SignerName = EidPades.LastAttr(seal.SubjectName, "2.5.4.3"),
        Reason = "Байгууллагын тамга",
        SigningTime = SigningTime,
        VerifyPage = false,
    };

    private static async Task<(Completed Done, byte[] Dtbs)> Seal(byte[] pdf, X509Certificate2 seal, ECDsa key, HttpClient http, SealOptions o)
    {
        byte[]? seen = null;
        var done = await EidPades.SealAsync(pdf, o, (dtbs, _) =>
        {
            seen = dtbs;
            return Task.FromResult(key.SignHash(dtbs, DSASignatureFormat.Rfc3279DerSequence));
        }, Complete(http));
        Assert.Equal(seal.RawData, done.SignerCert);
        return (done, seen!);
    }

    /// <summary>w × h pt нэг хуудастай PDF (дээд талд «RECEIPT»); pad &gt; 0 бол заагдаагүй pad байт stream объект нэмнэ.</summary>
    private static byte[] PagePdf(double w, double h, int pad = 0)
    {
        var objs = new List<object>
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            FormattableString.Invariant($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"),
            PlacementTests.Stream("", Encoding.ASCII.GetBytes(FormattableString.Invariant($"BT /F1 6 Tf 4 {h - 12} Td (RECEIPT) Tj ET"))),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        };
        if (pad > 0)
        {
            var zeros = new byte[pad];
            Array.Fill(zeros, (byte)'0');
            objs.Add(PlacementTests.Stream("", zeros));
        }
        return PlacementTests.Pdf(objs.ToArray());
    }

    /// <summary>
    /// Өөрөө зурсан ECDSA P-256 гэрчилгээ (хувийн түлхүүргүй), өгсөн өргөтгөлүүдтэй (§6.1-ийн дүрмийг шалгах). CreateSelfSigned
    /// биш: түлхүүр холбохдоо .NET keyUsage-ийг өөрийн декодероор уншдаг бөгөөд 9-өөс хойших бит (bit 32)-ийг задалж чадахгүй.
    /// </summary>
    private static X509Certificate2 Variant(params X509Extension[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var dn = new X500DistinguishedName("CN=TEST ONLY Variant");
        var req = new CertificateRequest(dn, key, HashAlgorithmName.SHA256);
        foreach (var e in extensions) req.CertificateExtensions.Add(e);
        return req.Create(dn, X509SignatureGenerator.CreateForECDsa(key), new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero), new byte[] { 0x5E, 0xA1, 0x60 });
    }
}
