using System;
using System.Text;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

public class ErrorTests
{
    [Fact]
    public void VersionIsReported()
    {
        Assert.False(string.IsNullOrWhiteSpace(EidPades.Version()));
    }

    [Fact]
    public void PrepareRejectsNonPdf()
    {
        var ex = Assert.Throws<EidPadesException>(() =>
            EidPades.Prepare(Encoding.ASCII.GetBytes("not a pdf"), new PrepareOptions { SignerCert = Golden.SignerCert() }));
        Assert.Equal(EidPadesErrorCode.PdfInvalid, ex.Code);
        Assert.Equal("PDF_INVALID", ex.RawCode);
    }

    [Fact]
    public async Task CompleteRejectsGarbageState()
    {
        var ex = await Assert.ThrowsAsync<EidPadesException>(() =>
            EidPades.CompleteAsync(new byte[] { 1, 2, 3 }, new byte[64]));
        Assert.Equal(EidPadesErrorCode.StateInvalid, ex.Code);
    }

    [Fact]
    public void VerifyRejectsNonPdf()
    {
        var ex = Assert.Throws<EidPadesException>(() => EidPades.Verify(Encoding.ASCII.GetBytes("%PDF-garbage")));
        Assert.Equal(EidPadesErrorCode.PdfInvalid, ex.Code);
    }

    [Fact]
    public void PrepareRequiresSignerCert()
    {
        Assert.Throws<ArgumentException>(() => EidPades.Prepare(new byte[] { 1 }, new PrepareOptions()));
    }

    [Fact]
    public void UnknownCodeMapsToUnknown()
    {
        var ex = new EidPadesException("SOMETHING_NEW", "x");
        Assert.Equal(EidPadesErrorCode.Unknown, ex.Code);
        Assert.Equal("SOMETHING_NEW", ex.RawCode);
    }
}
