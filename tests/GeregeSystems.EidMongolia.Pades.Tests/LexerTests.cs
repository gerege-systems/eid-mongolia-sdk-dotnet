using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Pdf;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Lexer нь массив дотор `endobj`, мөн EOF-тэй буферийн төгсгөлд хаагдаагүй массив/мөрийг ахихгүй давталтгүйгээр
/// PdfFormatException (Prepare-д PDF_INVALID) болгоно. Регресс бол тест гацахын оронд хугацаа хэтэрч унана.
/// </summary>
public class LexerTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    private static byte[] L(string s) => Encoding.Latin1.GetBytes(s);

    [Theory]
    [InlineData("1 0 obj [1 endobj", false)]
    [InlineData("1 0 obj << /K [[ endobj", false)]
    [InlineData("[1 2", true)]
    [InlineData("<0a", true)]
    [InlineData("(abc", true)]
    public async Task MalformedObjectIsRejectedPromptly(string input, bool allowEof)
    {
        var data = L(input);
        var run = Task.Run(() => new Lexer(data, 0, data.Length) { AllowEof = allowEof }.ReadObject());
        var ex = await Record.ExceptionAsync(() => run.WaitAsync(Limit));
        Assert.IsType<PdfFormatException>(ex);
    }

    [Theory]
    [InlineData("1 0 obj [1 2 0 R (a) <0a> /N] endobj")]
    [InlineData("1 0 obj endobj")]
    public void WellFormedObjectStillParses(string input)
    {
        var data = L(input);
        Assert.IsType<ObjDef>(new Lexer(data, 0, data.Length).ReadObject());
    }

    private static byte[] Pem(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name))).RawData;

    [Fact]
    public async Task PrepareRejectsEndobjInsideArrayPromptly()
    {
        var ms = new MemoryStream();
        void W(string s) => ms.Write(L(s));
        W("%PDF-1.7\n");
        int off1 = (int)ms.Length;
        W("1 0 obj\n<< /Type /Catalog /Pages [ 1\nendobj\n");
        int xref = (int)ms.Length;
        W($"xref\n0 2\n0000000000 65535 f \n{off1:D10} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        var doc = ms.ToArray();
        var opts = new PrepareOptions { SignerCert = Pem("citizen.pem"), Chain = new[] { Pem("04.pem"), Pem("03.pem"), Pem("02.pem") } };
        var run = Task.Run(() => EidPades.Prepare(doc, opts));
        var ex = await Record.ExceptionAsync(() => run.WaitAsync(Limit));
        var e = Assert.IsType<EidPadesException>(ex);
        Assert.Equal("PDF_INVALID", e.RawCode);
    }
}
