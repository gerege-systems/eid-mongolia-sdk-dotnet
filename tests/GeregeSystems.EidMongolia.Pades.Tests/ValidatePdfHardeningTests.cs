using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Pdf;
using GeregeSystems.EidMongolia.Pades.Validation;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// PR #51 review-ийн DoS/хатууруулалтын regression: ObjStm-ийн шалгалтыг тойрох гурван зам (тайлбар дахь /Encrypt, давхар
/// FlateDecode, давхар /Filter түлхүүр) + Lexer-ийн гүний хязгаар, /N асар том ObjStm, CMS-ийн гэрчилгээний тоо, гэмтсэн нэр,
/// давхардсан issuer+serial — ValidatePdfAsync ба Prepare хоёуланд PDF_INVALID (StackOverflow / өлсгөлөн / crash биш).
/// </summary>
public class ValidatePdfHardeningTests
{
    private const int Deep = 200_000;

    private static byte[] L(string s) => Encoding.Latin1.GetBytes(s);

    private static byte[] Zlib(byte[] b)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(b);
        return ms.ToArray();
    }

    /// <summary>
    /// obj 1 Catalog (/X 3 0 R), obj 2 xref stream (W [1 4 1]), obj 3 = ObjStm 4-ийн объект. objStmDict — ObjStm-ийн толийн
    /// нэмэлт; data — stream-ийн байт; header — ObjStm-ийн толгой («3 0 »), first — /First.
    /// </summary>
    internal static byte[] XrefStreamPdf(string objStmDict, byte[] data, int first, string n = "1", string comment = "")
    {
        var ms = new MemoryStream();
        void W(string s) => ms.Write(L(s));
        W("%PDF-1.5\n%" + new string('x', 300) + "\n" + comment);
        int off1 = (int)ms.Length;
        W("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n");
        int off4 = (int)ms.Length;
        W($"4 0 obj\n<< /Type /ObjStm /N {n} /First {first} /Length {data.Length} {objStmDict} >>\nstream\n");
        ms.Write(data);
        W("\nendstream\nendobj\n");
        int off2 = (int)ms.Length;
        static byte[] Row(int t, int f2, int f3) => new[] { (byte)t, (byte)(f2 >> 24), (byte)(f2 >> 16), (byte)(f2 >> 8), (byte)f2, (byte)f3 };
        var rows = Row(0, 0, 0xff).Concat(Row(1, off1, 0)).Concat(Row(1, off2, 0)).Concat(Row(2, 4, 0)).Concat(Row(1, off4, 0)).ToArray();
        W($"2 0 obj\n<< /Type /XRef /Size 5 /W [1 4 1] /Index [0 5] /Root 1 0 R /Length {rows.Length} >>\nstream\n");
        ms.Write(rows);
        W($"\nendstream\nendobj\nstartxref\n{off2}\n%%EOF\n");
        return ms.ToArray();
    }

    private static byte[] DeepArray() => L("3 0 " + new string('[', Deep));

    private static PrepareOptions PrepOpts()
    {
        byte[] Pem(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name))).RawData;
        return new PrepareOptions { SignerCert = Pem("citizen.pem"), Chain = new[] { Pem("04.pem"), Pem("03.pem"), Pem("02.pem") } };
    }

    private static async Task<string> ValidateCode(byte[] doc)
    {
        try
        {
            await EidPades.ValidatePdfAsync(doc, new ValidatePdfOptions { Offline = true });
            return "ok";
        }
        catch (EidPadesException e)
        {
            return e.RawCode;
        }
    }

    private static string PrepareCode(byte[] doc)
    {
        try
        {
            EidPades.Prepare(doc, PrepOpts());
            return "ok";
        }
        catch (EidPadesException e)
        {
            return e.RawCode;
        }
    }

    public static IEnumerable<object[]> BypassCases()
    {
        // 1) /Encrypt-ийн бичвэр тайлбарт — өмнө нь бүх ObjStm шалгалтыг унтраадаг байсан (шахаагүй ObjStm).
        yield return new object[] { "comment /Encrypt", XrefStreamPdf("", DeepArray(), 4, comment: "% /Encrypt 1 0 R\n") };
        // 2) [/FlateDecode /FlateDecode] — уншигч гинжлэн тайлдаг, шалгагч тоолоогүй.
        yield return new object[] { "double FlateDecode", XrefStreamPdf("/Filter [/FlateDecode /FlateDecode]", Zlib(Zlib(DeepArray())), 4) };
        // 3) /Filter /FlateDecode … /Filter null — уншигч сүүлийнхийг (шүүлтүүргүй) авдаг, шалгагч эхнийхийг.
        yield return new object[] { "duplicate /Filter null", XrefStreamPdf("/Filter /FlateDecode /Filter null", DeepArray(), 4) };
    }

    [Theory]
    [MemberData(nameof(BypassCases))]
    public void ObjStmBypass_StructureRejects(string name, byte[] doc)
    {
        Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        Assert.Equal("PDF_INVALID", PrepareCode(doc));
        Assert.NotEmpty(name);
    }

    [Theory]
    [MemberData(nameof(BypassCases))]
    public async Task ObjStmBypass_ValidatePdfInvalid(string name, byte[] doc)
    {
        Assert.Equal("PDF_INVALID", await ValidateCode(doc));
        Assert.NotEmpty(name);
    }

    [Fact]
    public void Lexer_DepthLimit_TypedError()
    {
        // Structure.Check-ийг алгасаж уншигчаар шууд: гүн массив StackOverflow биш PdfFormatException болно.
        var doc = XrefStreamPdf("", DeepArray(), 4);
        var r = PdfDocument.Open(doc);
        var p = new ObjPtr(3, 0);
        Assert.Throws<PdfFormatException>(() => r.Resolve(p, p));
        var flat = new Lexer(L(new string('[', Lexer.MaxDepth + 10)), 0, Lexer.MaxDepth + 10);
        Assert.Throws<PdfFormatException>(() => flat.ReadObject());
    }

    [Fact(Timeout = 60_000)]
    public async Task HugeObjStmN_StopsAtEndOfData()
    {
        // ObjStm-ийн толгой obj 5-ийг л агуулна, xref obj 3-ыг тэнд гэж заана: /N 2147483647 — EOF дээр зогсоно.
        var doc = XrefStreamPdf("", L("5 0 << >>"), 4, n: "2147483647");
        var r = PdfDocument.Open(doc);
        var p = new ObjPtr(3, 0);
        Assert.Throws<PdfFormatException>(() => r.Resolve(p, p));
        Assert.Contains(await ValidateCode(doc), new[] { "PDF_INVALID", "PDF_NO_SIGNATURE" });
        Assert.NotNull(PrepareCode(doc)); // ямар ч тайлан/алдаа — 2^31 давталтгүй дуусна
    }

    // ── CMS ──

    private static byte[] RootDer() => ValidatePdfCorpusTests.PemDer("golden/pki/root.pem");

    private static byte[] SignedData(IEnumerable<byte[]> certs, byte[] issuer, byte[] serialInt)
    {
        var si = Asn1.Tlv(Asn1.Sequence,
            Asn1.Tlv(Asn1.Integer, new byte[] { 1 }),
            Asn1.Tlv(Asn1.Sequence, issuer, serialInt),
            Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("2.16.840.1.101.3.4.2.1")),
            Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("1.2.840.113549.1.1.1")),
            Asn1.Tlv(Asn1.OctetString, new byte[] { 0 }));
        var sd = Asn1.Tlv(Asn1.Sequence,
            Asn1.Tlv(Asn1.Integer, new byte[] { 1 }),
            Asn1.Tlv(Asn1.Set),
            Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("1.2.840.113549.1.7.1")),
            Asn1.Tlv(0xa0, certs.ToArray()),
            Asn1.Tlv(Asn1.Set, si));
        return Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("1.2.840.113549.1.7.2"), Asn1.Tlv(0xa0, sd));
    }

    private static (byte[] Issuer, byte[] SerialTlv) IssuerSerial(byte[] der)
    {
        var c = ValCert.Parse(der);
        return (c.RawIssuer, Asn1.Tlv(Asn1.Integer, c.Serial));
    }

    [Fact]
    public void ManyEmbeddedCertificates_Rejected()
    {
        var root = RootDer();
        var (iss, sn) = IssuerSerial(root);
        Assert.NotNull(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 32), iss, sn)));
        Assert.Null(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 33), iss, sn)));
        Assert.Null(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 5000), iss, sn)));
    }

    private static byte[] MakeCert(byte[] issuer, byte[] serialContent, byte[] subject, byte[] spki)
    {
        var validity = Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.UtcTime, L("260101000000Z")), Asn1.Tlv(Asn1.UtcTime, L("300101000000Z")));
        var alg = Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("1.2.840.113549.1.1.11"));
        var tbs = Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(0xa0, Asn1.Tlv(Asn1.Integer, new byte[] { 2 })), Asn1.Tlv(Asn1.Integer, serialContent), alg,
            issuer, validity, subject, spki);
        return Asn1.Tlv(Asn1.Sequence, tbs, alg, Asn1.Tlv(Asn1.BitString, new byte[] { 0, 1, 2, 3 }));
    }

    [Fact]
    public void DuplicateIssuerSerial_FirstCertificateWins()
    {
        var root = ValCert.Parse(RootDer());
        var other = ValCert.Parse(ValidatePdfCorpusTests.PemDer("validate/pki/05.pem"));
        // Ижил issuer+serial, өөр subject-тэй хоёр гэрчилгээ: TS onlySigner (find) — эхнийх; crash үгүй.
        var twin = MakeCert(root.RawIssuer, root.Serial, other.RawSubject, root.Spki);
        var sn = Asn1.Tlv(Asn1.Integer, root.Serial);
        var a = Extract.ParsePkcs7(SignedData(new[] { twin, root.Raw }, root.RawIssuer, sn))!;
        Assert.Equal(twin, Extract.OnlySigner(a)!.Raw);
        var b = Extract.ParsePkcs7(SignedData(new[] { root.Raw, twin }, root.RawIssuer, sn))!;
        Assert.Equal(root.Raw, Extract.OnlySigner(b)!.Raw);
    }

    [Fact]
    public void MalformedSubjectName_IsCertificateParseError()
    {
        var root = ValCert.Parse(RootDer());
        // Subject: SET { SEQUENCE { OID cn } } — утгагүй ATV.
        var badName = Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Set, Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv("2.5.4.3"))));
        var cert = MakeCert(root.RawSubject, new byte[] { 7 }, badName, root.Spki);
        Assert.Throws<ValCertException>(() => ValCert.Parse(cert));
        // CMS-ийн гэрчилгээ задрахгүй → тэр гарын үсэг malformed (баримт бүхэлдээ PDF_INVALID биш).
        Assert.Null(Extract.ParsePkcs7(SignedData(new[] { cert }, root.RawSubject, Asn1.Tlv(Asn1.Integer, new byte[] { 7 }))));
        // Хяналт: зөв нэртэй ижил бүтэц задарна.
        Assert.NotNull(ValCert.Parse(MakeCert(root.RawSubject, new byte[] { 7 }, root.RawSubject, root.Spki)));
    }
}
