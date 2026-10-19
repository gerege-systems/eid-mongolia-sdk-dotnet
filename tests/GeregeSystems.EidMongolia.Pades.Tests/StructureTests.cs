using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Pdf;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// PRECHECKS #2a/#2b/#4 (Go v0.8.0 CheckStructure, TS 0.21.0-ийн оролтууд): гүн давхарлалт, ObjStm мөчлөг, /Size, /Encrypt
/// шууд толь. Бүтцийн алдаа нь задлагчийн рекурсээс (StackOverflowException — процесс унана) ӨМНӨ PDF_INVALID болно.
/// </summary>
public class StructureTests
{
    private static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "testdata", "structure");

    private static byte[] Pem(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name))).RawData;

    private static PrepareOptions Opts() => new() { SignerCert = Pem("citizen.pem"), Chain = new[] { Pem("04.pem"), Pem("03.pem"), Pem("02.pem") } };

    private static byte[] L(string s) => Encoding.Latin1.GetBytes(s);

    /// <summary>Prepare-ийн код; бүтцийн шалгалтаар унасан бол "+structure".</summary>
    private static string PrepareCode(byte[] doc)
    {
        try
        {
            EidPades.Prepare(doc, Opts());
            return "ok";
        }
        catch (EidPadesException e)
        {
            return e.RawCode + (e.InnerException is PdfStructureException ? "+structure" : "");
        }
    }

    /// <summary>Go xrefStreamPDF: obj 1 Catalog (/X 3 0 R), obj 2 xref stream (/Size size, W [1 2 1]), obj 3 = ObjStm 4-ийн объект.</summary>
    private static byte[] XrefStreamPdf(string size, string length4, byte[]? row3 = null, byte[]? row4 = null)
    {
        var ms = new MemoryStream();
        void W(string s) => ms.Write(L(s));
        W("%PDF-1.5\n%" + new string('x', 300) + "\n");
        int off1 = (int)ms.Length;
        W("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n");
        int off4 = (int)ms.Length;
        W($"4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {length4} >>\nstream\n3 0 << >>\nendstream\nendobj\n");
        int off2 = (int)ms.Length;
        static byte[] Row(int t, int f2, int f3) => new[] { (byte)t, (byte)(f2 >> 8), (byte)f2, (byte)f3 };
        var rows = Row(0, 0, 0xff).Concat(Row(1, off1, 0)).Concat(Row(1, off2, 0)).Concat(row3 ?? Row(2, 4, 0)).Concat(row4 ?? Row(1, off4, 0)).ToArray();
        W($"2 0 obj\n<< /Type /XRef /Size {size} /W [1 2 1] /Index [0 5] /Root 1 0 R /Length {rows.Length} >>\nstream\n");
        ms.Write(rows);
        W($"\nendstream\nendobj\nstartxref\n{off2}\n%%EOF\n");
        return ms.ToArray();
    }

    private static byte[] InStm(int container) => new byte[] { 2, 0, (byte)container, 0 };

    public static IEnumerable<object[]> ObjStmCases() => new[]
    {
        new object[] { "legit ObjStm", XrefStreamPdf("5", "9"), false },
        new object[] { "/Size 2^21 (boundary)", XrefStreamPdf((1 << 21).ToString(), "9"), false },
        new object[] { "obj 3 is its own container", XrefStreamPdf("5", "9", InStm(3)), true },
        new object[] { "ObjStm 4 inside ObjStm 3 (mutual)", XrefStreamPdf("5", "9", null, InStm(3)), true },
        new object[] { "ObjStm /Length inside its own ObjStm", XrefStreamPdf("5", "3 0 R"), true },
        new object[] { "/Size 2^21+1", XrefStreamPdf(((1 << 21) + 1).ToString(), "9"), true },
        new object[] { "/Size 10^10", XrefStreamPdf("10000000000", "9"), true },
    };

    [Theory]
    [MemberData(nameof(ObjStmCases))]
    public void ObjStmGraphAndSize(string name, byte[] doc, bool bad)
    {
        if (bad)
        {
            Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
            Assert.Equal("PDF_INVALID+structure", PrepareCode(doc));
        }
        else
        {
            Structure.Check(doc); // name: xunit-д харагдана
            Assert.NotEqual("PDF_INVALID+structure", PrepareCode(doc));
        }
        Assert.NotNull(name);
    }

    [Theory]
    [InlineData("objstm-cycle-c8b2f6dc9d5d37bf.pdf")] // Go FuzzValidatePDF crash seed
    [InlineData("deep-nesting.pdf")] // Go validate v4: дээд түвшинд > 256
    [InlineData("deep-nesting-objstm.pdf")] // Go validate v4: ObjStm доторх объект > 256
    public void RejectedFixtures(string file)
    {
        var doc = File.ReadAllBytes(Path.Combine(Dir, file));
        Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        Assert.Equal("PDF_INVALID+structure", PrepareCode(doc));
    }

    [Theory]
    [InlineData(256, false)]
    [InlineData(257, true)]
    [InlineData(100_000, true)] // задлагчид шууд өгвөл stack overflow
    public void NestingLimit(int depth, bool bad)
    {
        var doc = L("%PDF-1.7\n1 0 obj\n" + new string('[', depth) + new string(']', depth) + "\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
        if (bad) Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        else Structure.Check(doc);
    }

    [Fact]
    public async Task CompleteRejectsDeepNestingInState()
    {
        var st = new PrepState
        {
            SignerCert = Pem("citizen.pem"),
            SignedAttrs = new byte[] { 0x31, 0x00 },
            RevIndex = 1,
            Pdf = File.ReadAllBytes(Path.Combine(Dir, "deep-nesting.pdf")),
        };
        st.PreparedSha256 = PrepState.Hex(System.Security.Cryptography.SHA256.HashData(st.Pdf));
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(st.Encode(), new byte[256]));
        Assert.Equal(EidPadesErrorCode.StateInvalid, ex.Code);
        Assert.IsType<PdfStructureException>(ex.InnerException);
    }

    private const string Aes256 = "/Filter /Standard /V 5 /R 6 /Length 256 /O <00> /U <00> /OE <00> /UE <00> /Perms <00> /P -4";
    private const string Rc4 = "/Filter/Standard/V 2/R 3/Length 128/O<00>/U<00>/P -4";

    /// <summary>Зөв xref-тэй жижиг PDF; trailer-д нэмэлт <paramref name="extra"/>.</summary>
    private static byte[] TinyPdf(string extra)
    {
        var s = new StringBuilder("%PDF-1.7\n%" + new string('x', 200) + "\n");
        var off = new int[3];
        void Obj(int n, string body)
        {
            off[n] = s.Length;
            s.Append($"{n} 0 obj\n{body}\nendobj\n");
        }
        Obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Obj(2, "<< /Type /Pages /Kids [] /Count 0 >>");
        int x = s.Length;
        s.Append($"xref\n0 3\n0000000000 65535 f \n{off[1]:D10} 00000 n \n{off[2]:D10} 00000 n \n");
        s.Append($"trailer\n<< /Size 3 /Root 1 0 R {extra} >>\nstartxref\n{x}\n%%EOF\n");
        return L(s.ToString());
    }

    /// <summary>Уншигч нээж чадахгүй (xref/startxref алга) — зөвхөн байтын regex.</summary>
    private static byte[] Broken(string extra) => L($"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< {extra} >>\n");

    [Theory]
    [InlineData("/Encrypt << " + Aes256 + " >>")]
    [InlineData("/Encrypt<<" + Rc4 + ">>")]
    public void EncryptReferenceOrDirectDictionary(string extra)
    {
        Assert.Equal("PDF_ENCRYPTED", PrepareCode(TinyPdf(extra)));
        Assert.Equal("PDF_ENCRYPTED", PrepareCode(Broken(extra)));
    }

    [Fact]
    public void EncryptMetadataIsNotEncryption()
    {
        Assert.NotEqual("PDF_ENCRYPTED", PrepareCode(TinyPdf("/EncryptMetadata false")));
        Assert.Equal("PDF_ENCRYPTED", PrepareCode(Broken("/Encrypt 9 0 R")));
        Assert.Equal("PDF_INVALID", PrepareCode(Broken("/EncryptMetadata false")));
    }
}
