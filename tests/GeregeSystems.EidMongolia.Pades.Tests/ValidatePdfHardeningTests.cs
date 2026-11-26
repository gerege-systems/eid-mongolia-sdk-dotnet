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
        // Go boundedCerts: > 32 гэрчилгээ → гарын үсэг malformed (задлал өөрөө амжилттай — цагийн тэмдгийн токенд TSTInfo тайланд орно).
        var root = RootDer();
        var (iss, sn) = IssuerSerial(root);
        Assert.True(Extract.BoundedCerts(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 32), iss, sn))!.Certs));
        Assert.False(Extract.BoundedCerts(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 33), iss, sn))!.Certs));
        Assert.False(Extract.BoundedCerts(Extract.ParsePkcs7(SignedData(Enumerable.Repeat(root, 5000), iss, sn))!.Certs));
    }

    private static byte[] RsaSpki(byte[] n, byte[] e) =>
        Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv(ValCert.OidRsaEncryption), Asn1.Tlv(0x05)),
            Asn1.Tlv(Asn1.BitString, new byte[] { 0 }.Concat(Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Integer, n), Asn1.Tlv(Asn1.Integer, e))).ToArray()));

    /// <summary>2^(bits−1)-ийн эерэг INTEGER агуулга (DER-ийн хамгийн богино хэлбэр).</summary>
    private static byte[] Pow2(int bits)
    {
        int k = bits - 1;
        var a = new byte[k / 8 + 1];
        a[0] = (byte)(1 << (k % 8));
        return k % 8 == 7 ? new byte[] { 0 }.Concat(a).ToArray() : a;
    }

    [Theory]
    [InlineData(160, 8192, 4, true)]
    [InlineData(161, 8192, 4, false)] // serial > 160 бит (RFC 5280 «≤ 20 octets», утгын хэмжээ)
    [InlineData(160, 8200, 4, false)] // RSA модуль > 8192 бит
    [InlineData(160, 2048, 5, false)] // илтгэгч 2^32 > 2^32−1
    public void BoundedCert_SerialAndRsaLimits(int serialBits, int modulusBits, int exponentBytes, bool ok)
    {
        var root = ValCert.Parse(RootDer());
        var e = new byte[exponentBytes];
        e[0] = 1;
        var c = ValCert.Parse(MakeCert(root.RawSubject, Pow2(serialBits), root.RawSubject, RsaSpki(Pow2(modulusBits), e)));
        Assert.Equal((long)serialBits, Extract.IntBitLength(c.Serial));
        Assert.Equal(ok, Extract.BoundedCert(c));
    }

    [Fact]
    public void WeakSignatureAlgorithms_GoList()
    {
        Assert.Equal(
            new[] { "1.2.840.10040.4.3", "1.2.840.10045.4.1", "1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.3.14.3.2.29" },
            Extract.WeakSignatureOids.OrderBy(x => x, StringComparer.Ordinal));
        Assert.DoesNotContain(ValCert.OidSha256WithRsa, Extract.WeakSignatureOids);
        Assert.DoesNotContain(ValCert.OidEcdsaSha256, Extract.WeakSignatureOids);
    }

    // ── Go CheckStructure v14: xref хэсэг, xref stream /W /Index, ObjStm-ийн ажил ──

    /// <summary>Зөвхөн нэг xref stream-ийн толь (бүтцийн шалгалтад; уншигч нээхгүй байж болно).</summary>
    private static byte[] XrefDict(string dict) => L("%PDF-1.5\n1 0 obj\n<< /Type /XRef " + dict + " /Length 0 >>\nstream\n\nendstream\nendobj\n%%EOF\n");

    [Theory]
    [InlineData("/Size 5 /W [1 2 1] /Index [0 5]", false)]
    [InlineData("/Size 5 /W [0 0 0] /Index [0 1000000000]", true)] // мөрийн урт 0
    [InlineData("/Size 5 /W [1 9 1]", true)] // /W-ийн элемент > 8
    [InlineData("/Size 5 /W [1 -1 1]", true)]
    [InlineData("/Size 5 /W [1 2 1] /Index [0 2097152]", false)] // 2^21 — хил
    [InlineData("/Size 5 /W [1 2 1] /Index [0 2097153]", true)]
    [InlineData("/Size 5 /W [1 2 1] /Index [2097150 3]", true)] // start + count > 2^21
    [InlineData("/Size 5 /W [1 2 1] /Index [-1 3]", true)]
    [InlineData("/Size 5 /W [1 2 1] /Index [0 1048576 1048576 1048577]", true)] // мөрийн нийлбэр > 2^21
    [InlineData("/Size 5 /W [1 2 1] /Filter [/FlateDecode /FlateDecode]", true)] // xref stream-д олон шүүлтүүр
    [InlineData("/Size 5 /W [0 0 0 2]", false)] // нийлбэр > 0
    [InlineData("/Size 5 /W [1 2 1.5]", false)] // бүхэл биш — уншигч өөрөө татгалзана
    public void XrefStream_WAndIndex(string dict, bool bad)
    {
        var doc = XrefDict(dict);
        if (bad) Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        else Structure.Check(doc);
    }

    [Theory]
    [InlineData(128, false)]
    [InlineData(129, true)]
    public void XrefSections_Max128(int n, bool bad)
    {
        var doc = L("%PDF-1.4\n" + string.Concat(Enumerable.Repeat("trailer\n<< /Size 1 >>\n", n)) + "%%EOF\n");
        if (bad) Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        else Structure.Check(doc);
    }

    [Theory]
    [InlineData(1000, false)]
    [InlineData(20000, true)] // 20000 хос × 80000 байт > 1 GiB
    public void ObjStmWork_Budget(int members, bool bad)
    {
        var header = string.Concat(Enumerable.Repeat("1 0 ", members));
        var doc = L($"%PDF-1.5\n4 0 obj\n<< /Type /ObjStm /N {members} /First 0 /Length {header.Length} >>\nstream\n{header}\nendstream\nendobj\n%%EOF\n");
        if (bad) Assert.Throws<PdfStructureException>(() => Structure.Check(doc));
        else Structure.Check(doc);
    }

    [Fact]
    public void ObjStmIndex_FirstMatchWins()
    {
        // Толгойг нэг удаа индексжүүлнэ — давхардсан дугаарт эхнийх (өмнөх давталттай ижил).
        var doc = XrefStreamPdf("", L("3 0 3 11 << /A 1 >> << /B 2 >>"), 9, n: "2");
        var r = PdfDocument.Open(doc);
        var p = new ObjPtr(3, 0);
        Assert.Equal(1L, r.Resolve(p, p).Key("A").Int64);
        Assert.True(r.Resolve(p, p).Key("B").IsNull);
    }

    [Fact]
    public void Reader_XrefStreamZeroRowWidth()
    {
        var doc = XrefStreamPdf("", L("3 0 << >>"), 4);
        var bad = Encoding.Latin1.GetString(doc).Replace("/W [1 4 1]", "/W [0 0 0]", StringComparison.Ordinal);
        Assert.Throws<PdfFormatException>(() => PdfDocument.Open(L(bad)));
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

    private static Task<PdfReport> ValidateCorpusInput(string name) =>
        EidPades.ValidatePdfAsync(ValidatePdfCorpusTests.Read("validate/input/" + name + ".pdf"), new ValidatePdfOptions
        {
            Roots = ValidatePdfCorpusTests.Ders("roots"),
            Issuers = ValidatePdfCorpusTests.Ders("issuers"),
            Time = ValidatePdfCorpusTests.ManifestTime,
            Offline = true,
        });

    /// <summary>
    /// Corpus v15 (Go TestValidatePDFLaterStampNameNotCompared): own-signer дардасны /Name-ийг гэрчилгээний нэртэй
    /// харьцуулахгүй — бүрэн бүтэн хожмын гарын үсгийн /Name (GOLDEN TESTOV) гэрчилгээнийхээс (QUALIFIED TESTOV) зөрсөн ч
    /// өмнөх гарын үсэг valid, extended_by_signatures_only, visible_later_signature; signer_name гэрчилгээнээс.
    /// </summary>
    [Fact]
    public async Task LaterStampName_NotComparedWithCertificate()
    {
        var rep = await ValidateCorpusInput("later-stamp-name-mismatch");
        Assert.Equal(2, rep.Signatures.Count);
        var first = rep.Signatures.Single(s => !s.CoversWholeDocument);
        var later = rep.Signatures.Single(s => s.CoversWholeDocument);
        Assert.Equal("valid", first.Indication);
        Assert.Empty(first.Problems);
        Assert.True(first.ExtendedBySignaturesOnly);
        Assert.True(first.VisibleLaterSignature);
        Assert.Equal(1, first.LaterSignatures);
        Assert.True(later.Visible);
        Assert.Equal("QUALIFIED TESTOV", later.SignerName);
        Assert.Equal("GOLDEN TESTOV", later.ClaimedName);
    }

    /// <summary>Дүрмийн нөгөө хагас хэвээр: integrity-д унасан хожмын гарын үсэг өргөтгөл биш → өмнөх нь modified_after_signing.</summary>
    [Fact]
    public async Task LaterSignatureFailingIntegrity_StillModifiesEarlier()
    {
        var rep = await ValidateCorpusInput("later-sig-integrity-failed");
        var first = rep.Signatures.First(s => !s.CoversWholeDocument);
        Assert.Contains("modified_after_signing", first.Problems);
        Assert.False(first.ExtendedBySignaturesOnly);
    }
}
