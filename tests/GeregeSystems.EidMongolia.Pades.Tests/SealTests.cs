using System;
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
        using var cert = new X509Certificate2(Convert.FromBase64String(resp.GetProperty("cert").GetProperty("value").GetString()!));

        Assert.True(EidPades.IsSealCert(cert));
        Assert.Equal("NTRMN-1234567", EidPades.LastAttr(cert.SubjectName, "2.5.4.97"));
        Assert.Equal(resp.GetProperty("orgEtsi").GetString(), EidPades.LastAttr(cert.SubjectName, "2.5.4.97"));
        using var pub = cert.GetECDsaPublicKey()!;
        Assert.True(pub.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence));
    }
}
