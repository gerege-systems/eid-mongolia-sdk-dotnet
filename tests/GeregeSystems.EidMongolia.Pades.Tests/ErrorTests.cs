using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

public class ErrorTests
{
    private static byte[] Input() => Fixtures.Read("input", "quartz-pdf13.pdf");

    private static byte[] Pem(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name))).RawData;

    private static PrepareOptions Opts() => new()
    {
        SignerCert = Pem("citizen.pem"),
        Chain = new[] { Pem("04.pem"), Pem("03.pem"), Pem("02.pem") },
        SigningTime = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.FromHours(8)),
    };

    /// <summary>Бүх хүсэлтэд 503 — TSA хүрэхгүй.</summary>
    private sealed class Down : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }

    private static EidPadesException Throws(Action a) => Assert.Throws<EidPadesException>(a);

    [Fact]
    public void PrepareRejectsNonPdf()
    {
        var ex = Throws(() => EidPades.Prepare(Encoding.ASCII.GetBytes("not a pdf"), Opts()));
        Assert.Equal(EidPadesErrorCode.PdfInvalid, ex.Code);
        Assert.Equal("PDF_INVALID", ex.RawCode);
    }

    [Fact]
    public void PrepareRejectsDamagedPdf()
    {
        var ex = Throws(() => EidPades.Prepare(Encoding.ASCII.GetBytes("%PDF-1.7\n" + new string('x', 400)), Opts()));
        Assert.Equal(EidPadesErrorCode.PdfInvalid, ex.Code);
    }

    [Fact]
    public void PrepareRejectsTooLarge()
    {
        var ex = Throws(() => EidPades.Prepare(new byte[EidPades.MaxInputBytes + 1], Opts()));
        Assert.Equal(EidPadesErrorCode.PdfTooLarge, ex.Code);
    }

    [Fact]
    public void PrepareRejectsBadSignerCert()
    {
        var ex = Throws(() => EidPades.Prepare(Input(), Opts() with { SignerCert = new byte[] { 1, 2, 3 } }));
        Assert.Equal(EidPadesErrorCode.SignerInvalid, ex.Code);
    }

    [Theory]
    [InlineData("NOT-A-UUID", null)]
    [InlineData(null, "de")]
    public void PrepareRejectsBadOptions(string? docId, string? lang)
    {
        var ex = Throws(() => EidPades.Prepare(Input(), Opts() with { DocId = docId, Lang = lang }));
        Assert.Equal(EidPadesErrorCode.RequestInvalid, ex.Code);
    }

    private static readonly Appearance Visible = new() { X = 36, Y = 36, Width = 220, Height = 64 };

    public static TheoryData<string, PrepareOptions> BadAppearance() => new()
    {
        { "хуудас алга", Opts() with { Appearance = Visible with { Page = 2 } } },
        { "сөрөг page", Opts() with { Appearance = Visible with { Page = -1 } } },
        { "хуудаснаас гарна", Opts() with { Appearance = Visible with { X = 500 } } },
        { "дээш гарна", Opts() with { Appearance = Visible with { Y = 760 } } },
        { "нам (QR < 1 pt)", Opts() with { Appearance = Visible with { Height = 44 } } },
        { "нарийн (бичвэр)", Opts() with { Appearance = Visible with { Width = 90 } } },
        { "тэг өргөн", Opts() with { Appearance = Visible with { Width = 0 } } },
        { "NaN", Opts() with { Appearance = Visible with { X = double.NaN } } },
        { "14400-аас их", Opts() with { Appearance = Visible with { Height = 14401 } } },
        { "хэл", Opts() with { Appearance = Visible with { Lang = "de" } } },
        { "/Name бичигдэхгүй", Opts() with { Appearance = Visible, SignerName = "a stream b" } },
        { "role удирдах тэмдэгт", Opts() with { Appearance = Visible, ClaimedRole = "a\u200eb" } },
        { "role ганц surrogate", Opts() with { Appearance = Visible, ClaimedRole = "a\ud800b" } },
    };

    /// <summary>Go TestAppearanceRejects — APPEARANCE_SPEC.md §1, §3: байршил/хэмжээ буруу, багтахгүй бол REQUEST_INVALID.</summary>
    [Theory]
    [MemberData(nameof(BadAppearance))]
    public void AppearanceRejects(string name, PrepareOptions o)
    {
        var ex = Throws(() => EidPades.Prepare(Input(), o)); // 612 × 792, 1 хуудас
        Assert.True(ex.Code == EidPadesErrorCode.RequestInvalid, name + ": " + ex.RawCode + " " + ex.Message);
    }

    [Fact]
    public void AppearanceMinimumAndDocIdRequired()
    {
        // Хамгийн бага (45 pt өндөр) хүлээн авна; харагдах нь үл харагдахаас өөр DTBS.
        var p45 = EidPades.Prepare(Input(), Opts() with { DocId = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d", Appearance = Visible with { Height = 45 } });
        var inv = EidPades.Prepare(Input(), Opts() with { DocId = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d" });
        Assert.NotEqual(inv.Dtbs, p45.Dtbs);
        // Гарын үсэгтэй, хуудасгүй, docId-гүй баримтад → REQUEST_INVALID (verify URL-д docId заавал).
        var signed = Fixtures.Read("output", "quartz-pdf13-nopage.pdf");
        var ex = Throws(() => EidPades.Prepare(signed, Opts() with { Appearance = Visible }));
        Assert.Equal(EidPadesErrorCode.RequestInvalid, ex.Code);
        EidPades.Prepare(signed, Opts() with { DocId = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d", Appearance = Visible });
    }

    [Fact]
    public void VerifyPageNeedsFileName()
    {
        var ex = Throws(() => EidPades.Prepare(Input(), Opts() with { VerifyPage = true }));
        Assert.Equal(EidPadesErrorCode.RequestInvalid, ex.Code);
    }

    [Fact]
    public async Task CompleteRejectsGarbageState()
    {
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(new byte[] { 1, 2, 3 }, new byte[256]));
        Assert.Equal(EidPadesErrorCode.StateInvalid, ex.Code);
    }

    [Fact]
    public async Task CompleteRejectsTamperedState()
    {
        var p = EidPades.Prepare(Input(), Opts());
        var st = (byte[])p.State.Clone();
        st[^10] ^= 0xff;
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(st, new byte[256]));
        Assert.Equal(EidPadesErrorCode.StateInvalid, ex.Code);
    }

    [Fact]
    public async Task CompleteRejectsWrongSignature()
    {
        var p = EidPades.Prepare(Input(), Opts());
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(p.State, new byte[256]));
        Assert.Equal(EidPadesErrorCode.SignatureInvalid, ex.Code);
    }

    [Fact]
    public async Task CompleteReportsTsaUnavailable()
    {
        var p = EidPades.Prepare(Input(), Opts());
        using var key = RSA.Create();
        key.ImportFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", "citizen.key.pem")));
        var sig = key.SignHash(p.Dtbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var http = new HttpClient(new Down());
        var ex = await Assert.ThrowsAsync<EidPadesException>(() =>
            EidPades.CompleteAsync(p.State, sig, new CompleteOptions { HttpClient = http, TsaUrl = "http://tsa.pki.test/" }));
        Assert.Equal(EidPadesErrorCode.TsaUnavailable, ex.Code);
    }

    /// <summary>ECDSA P-256 иргэн: r‖s ба DER гарын үсэг хоёулаа DTBS-ийн шалгалтыг давж TSA алхамд хүрнэ.</summary>
    [Theory]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public async Task EcdsaSignatureFormatsAreAccepted(DSASignatureFormat format)
    {
        var now = DateTimeOffset.UtcNow; // нэг агшин — leaf.notAfter ≤ ca.notAfter (CertificateRequest.Create шалгана)
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=TEST ONLY EC CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var ca = caReq.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=TEST ONLY EC SIGNER", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(ca, now.AddDays(-1), now.AddDays(1), new byte[] { 7 });

        var p = EidPades.Prepare(Input(), new PrepareOptions { SignerCert = leaf.RawData, Chain = new[] { ca.RawData } });
        var sig = leafKey.SignHash(p.Dtbs, format);
        using var http = new HttpClient(new Down());
        var ex = await Assert.ThrowsAsync<EidPadesException>(() =>
            EidPades.CompleteAsync(p.State, sig, new CompleteOptions { HttpClient = http, TsaUrl = "http://tsa.pki.test/" }));
        Assert.Equal(EidPadesErrorCode.TsaUnavailable, ex.Code);
    }

    [Fact]
    public void UnknownCodeMapsToUnknown()
    {
        var ex = new EidPadesException("SOMETHING_NEW", "x");
        Assert.Equal(EidPadesErrorCode.Unknown, ex.Code);
        Assert.Equal("SOMETHING_NEW", ex.RawCode);
    }

    [Fact]
    public void FileNameIsCleaned()
    {
        Assert.Equal("Гэрээ.pdf", EidPades.CleanFileName("  Гэр​ээ.pdf\n "));
        Assert.Null(EidPades.CleanFileName(new string('a', 121)));
        Assert.Null(EidPades.CleanFileName(" \t "));
    }
}
