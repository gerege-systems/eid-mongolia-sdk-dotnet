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
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=TEST ONLY EC CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var ca = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=TEST ONLY EC SIGNER", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new byte[] { 7 });

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
