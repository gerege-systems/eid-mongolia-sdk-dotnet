using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// ValidatePdfAsync-ийн зорилтот сөрөг тест: гарын үсгийн мужид өөрчилсөн байт, messageDigest зөрсөн, гарын үсгийн дараа нэмсэн
/// гарын үсэггүй өгөгдөл, буруу оролт (тайрсан/санамсаргүй/хоосон/хэт том) — бүгд тайлан эсвэл <see cref="EidPadesException"/>
/// (өөр төрлийн exception, crash, хязгааргүй ажил үгүй).
/// </summary>
public class ValidatePdfNegativeTests
{
    private const string ValidInput = "golden/output/quartz-pdf13.pdf";

    private static ValidatePdfOptions Opts(HttpClient? client = null, bool offline = true) => new()
    {
        Roots = ValidatePdfCorpusTests.Ders("roots"),
        Issuers = ValidatePdfCorpusTests.Ders("issuers"),
        Time = ValidatePdfCorpusTests.ManifestTime,
        Offline = offline,
        HttpClient = client,
    };

    private static byte[] Valid() => ValidatePdfCorpusTests.Read(ValidInput);

    private static (long L0, long A1) Gap(byte[] doc)
    {
        var m = Regex.Matches(Encoding.Latin1.GetString(doc), @"/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)\s+(\d+)\s*\]").First();
        return (long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), long.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture));
    }

    private static async Task<SignatureReport> First(byte[] doc)
    {
        var rep = await EidPades.ValidatePdfAsync(doc, Opts());
        return rep.Signatures[0];
    }

    [Fact]
    public async Task Control_IsValid()
    {
        var rep = await EidPades.ValidatePdfAsync(Valid(), Opts());
        Assert.Equal("valid", rep.Indication);
        Assert.Empty(rep.Signatures[0].Problems);
    }

    [Fact]
    public async Task ModifiedByteInSignedRange_IntegrityFailed()
    {
        var doc = Valid();
        var (l0, _) = Gap(doc);
        // Гарын үсгийн мужийн (ByteRange-ийн эхний хэсэг) дундах нэг байт: /Contents-оос өмнөх объект доторх нэрийн үсэг.
        int at = Encoding.Latin1.GetString(doc, 0, (int)l0).LastIndexOf("/Type", StringComparison.Ordinal);
        Assert.True(at > 0 && at + 3 < l0);
        doc[at + 3] ^= 0x20; // /Type → /TyPe — задлалт хэвээр, хэш өөр
        var s = await First(doc);
        Assert.Equal("invalid", s.Indication);
        Assert.Contains("integrity_failed", s.Problems);
    }

    [Fact]
    public async Task WrongMessageDigest_IntegrityFailed()
    {
        var doc = Valid();
        var (l0, a1) = Gap(doc);
        var hex = Encoding.ASCII.GetString(doc, (int)l0 + 1, (int)(a1 - l0 - 2));
        // messageDigest атрибут: OID 1.2.840.113549.1.9.4, SET { OCTET STRING (32) }
        int i = hex.IndexOf("06092a864886f70d01090431220420", StringComparison.OrdinalIgnoreCase);
        Assert.True(i >= 0 && i % 2 == 0);
        int pos = (int)l0 + 1 + i + 30;
        doc[pos] = (byte)(doc[pos] == (byte)'0' ? '1' : '0');
        var s = await First(doc);
        Assert.Equal("invalid", s.Indication);
        Assert.Contains("integrity_failed", s.Problems);
    }

    [Fact]
    public async Task AppendedUnsignedData_ModifiedAfterSigning()
    {
        var doc = Valid().Concat(Encoding.ASCII.GetBytes("\n1 0 obj\n<< /Shadow true >>\nendobj\n")).ToArray();
        var rep = await EidPades.ValidatePdfAsync(doc, Opts());
        var s = rep.Signatures[0];
        Assert.False(s.ExtendedBySignaturesOnly);
        Assert.Contains("modified_after_signing", s.Problems);
        Assert.NotEqual("valid", rep.Indication);
    }

    [Fact]
    public async Task AppendedRevisionWithoutSignature_ModifiedAfterSigning()
    {
        // Shadow-style incremental update: шинэ xref хэсэг Catalog-ийг өөр (гарын үсэггүй) объектоор дахин тодорхойлно.
        var doc = Valid();
        var text = Encoding.Latin1.GetString(doc);
        int sx = text.LastIndexOf("startxref", StringComparison.Ordinal);
        var prev = Regex.Match(text[sx..], @"startxref\s+(\d+)").Groups[1].Value;
        var root = Regex.Matches(text, @"/Root\s+(\d+)\s+(\d+)\s+R").Last();
        var size = Regex.Matches(text, @"/Size\s+(\d+)").Last().Groups[1].Value;
        int rootNum = int.Parse(root.Groups[1].Value, CultureInfo.InvariantCulture);
        var obj = "\n" + rootNum + " 0 obj\n<< /Type /Catalog /Pages 999 0 R >>\nendobj\n";
        int objOff = doc.Length + 1;
        var xrefOff = doc.Length + obj.Length;
        var upd = obj + "xref\n" + rootNum + " 1\n" + objOff.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n\r\n" +
                  "trailer\n<< /Size " + size + " /Root " + rootNum + " 0 R /Prev " + prev + " >>\nstartxref\n" + xrefOff + "\n%%EOF\n";
        var attacked = doc.Concat(Encoding.Latin1.GetBytes(upd)).ToArray();
        SignatureReport s;
        try
        {
            s = (await EidPades.ValidatePdfAsync(attacked, Opts())).Signatures[0];
        }
        catch (EidPadesException e)
        {
            // Уншигч шинэ Catalog-ийг задалж чадахгүй бол тайлангүй алдаа — мөн «хүчинтэй» гэж үзэхгүй.
            Assert.Equal("PDF_INVALID", e.RawCode);
            return;
        }
        Assert.False(s.ExtendedBySignaturesOnly);
        Assert.Contains("modified_after_signing", s.Problems);
        Assert.NotEqual("valid", s.Indication);
    }

    [Fact]
    public async Task OtherRoot_UntrustedChain()
    {
        var o = Opts() with { Roots = new List<byte[]> { ValidatePdfCorpusTests.PemDer("validate/pki/05.pem") } };
        var s = (await EidPades.ValidatePdfAsync(Valid(), o)).Signatures[0];
        Assert.False(s.ChainTrusted);
        Assert.Contains("untrusted_chain", s.Problems);
        Assert.Equal("invalid", s.Indication);
    }

    [Fact]
    public async Task Offline_MakesNoRequests()
    {
        var replay = new ValidatePdfCorpusTests.Replay(new Dictionary<string, byte[]>());
        using var client = new HttpClient(replay);
        await EidPades.ValidatePdfAsync(Valid(), Opts(client, offline: true));
        Assert.Empty(replay.Requests);
    }

    [Fact]
    public async Task Online_UnavailableFallsBackToDss()
    {
        var replay = new ValidatePdfCorpusTests.Replay(new Dictionary<string, byte[]>());
        using var client = new HttpClient(replay);
        var rep = await EidPades.ValidatePdfAsync(Valid(), Opts(client, offline: false));
        Assert.NotEmpty(replay.Requests);
        Assert.Equal("valid", rep.Indication);
    }

    [Fact]
    public async Task Cancelled_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EidPades.ValidatePdfAsync(Valid(), Opts(), cts.Token));
    }

    [Fact]
    public async Task BadRootsOption_RequestInvalid()
    {
        var o = Opts() with { Roots = new List<byte[]> { new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 } } };
        var e = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.ValidatePdfAsync(Valid(), o));
        Assert.Equal("REQUEST_INVALID", e.RawCode);
    }

    [Fact]
    public async Task TooLarge_Rejected()
    {
        var e = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.ValidatePdfAsync(new byte[(10 << 20) + 1], Opts()));
        Assert.Equal("PDF_TOO_LARGE", e.RawCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("%PDF-1.7\n")]
    [InlineData("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")]
    [InlineData("not a pdf at all, just text")]
    public async Task Garbage_TypedError(string s)
    {
        var e = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.ValidatePdfAsync(Encoding.ASCII.GetBytes(s), Opts()));
        Assert.Contains(e.RawCode, new[] { "PDF_INVALID", "PDF_NO_SIGNATURE" });
    }

    private static async Task AssertTypedOutcome(byte[] doc)
    {
        try
        {
            var rep = await EidPades.ValidatePdfAsync(doc, Opts());
            Assert.Contains(rep.Indication, new[] { "valid", "invalid", "indeterminate" });
            Assert.NotNull(JsonNode.Parse(rep.ToJson()));
        }
        catch (EidPadesException e)
        {
            Assert.Contains(e.RawCode, new[] { "PDF_INVALID", "PDF_NO_SIGNATURE", "PDF_ENCRYPTED", "PDF_TOO_MANY_SIGNATURES" });
        }
    }

    [Fact]
    public async Task Truncated_TypedOutcome()
    {
        var doc = Valid();
        for (int k = 1; k <= 40; k++)
        {
            int n = (int)((long)doc.Length * k / 41);
            await AssertTypedOutcome(doc[..n]);
        }
        await AssertTypedOutcome(doc[..^1]);
        await AssertTypedOutcome(doc[..^7]);
    }

    [Fact]
    public async Task ByteFlips_TypedOutcome()
    {
        var doc = Valid();
        var rnd = new Random(20261126);
        for (int k = 0; k < 60; k++)
        {
            var d = (byte[])doc.Clone();
            int flips = 1 + rnd.Next(4);
            for (int j = 0; j < flips; j++) d[rnd.Next(d.Length)] ^= (byte)(1 << rnd.Next(8));
            await AssertTypedOutcome(d);
        }
    }

    [Fact]
    public async Task EveryCorpusInput_TruncatedTail_TypedOutcome()
    {
        foreach (var f in new[] { "golden/output/quartz-linearized.pdf", "golden/output/desktop-objstm-nopage.pdf", "validate/input/deep-nesting-objstm.pdf" })
        {
            var doc = ValidatePdfCorpusTests.Read(f);
            await AssertTypedOutcome(doc[..(doc.Length / 2)]);
            await AssertTypedOutcome(doc[..(doc.Length - 100)]);
        }
    }

    [Fact]
    public async Task Json_OmitsAbsentOptionalFields()
    {
        var rep = await EidPades.ValidatePdfAsync(Valid(), Opts());
        var j = JsonNode.Parse(rep.ToJson())!["signatures"]![0]!.AsObject();
        Assert.False(j.ContainsKey("reason"));
        Assert.False(j.ContainsKey("claimed_roles"));
        Assert.True(j.ContainsKey("problems"));
        Assert.Equal(0, j["later_signatures"]!.GetValue<int>());
    }
}
