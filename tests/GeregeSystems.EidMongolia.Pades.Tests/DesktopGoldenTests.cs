using System;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GeregeSystems.EidMongolia.Pades.Pdf;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Go reference-ийн core/desktop_golden_test.go-ийн C# хувилбар: eid-desktop-ийн (Swift) гаралтыг алхам бүрээр
/// (гарын үсэг → DSS → 2 дахь гарын үсэг → DSS) давтаж байт-түвшинд тулгана. CMS нь *.p7s, /M /Name /Reason нь хүлээгдэж
/// буй файлаас. Xref stream: хүлээгдэж буй файл zlib-тэй, манай бичигч шахалтгүй — хоёуланг нь задалсан хэлбэрээр тулгана.
/// </summary>
public class DesktopGoldenTests
{
    private static byte[] Desk(string rel) => Fixtures.Read("desktop", rel);

    [Theory]
    [InlineData("quartz")]
    [InlineData("objstm")]
    public void ReproducesDesktopOutputs(string kind)
    {
        var cur = Desk("input/base-" + kind + ".pdf");
        for (int n = 1; n <= 2; n++)
        {
            var want = Desk($"output/{kind}-{n}.pdf");
            var sig = LastSig(want, n);
            var prep = SignatureRevision.Prepare(cur, ParseM(sig.Key("M").Text), sig.Key("Name").Text, sig.Key("Reason").Text);
            var signed = SignatureRevision.EmbedCms(prep.Pdf, prep.ByteRange, Desk($"output/{kind}-{n}.p7s"));
            AssertSameDoc(want, signed, $"{kind}-{n}.pdf");

            signed = want;
            var wantDss = Desk($"output/{kind}-{n}-dss.pdf");
            var contents = SignatureRevision.SignatureContents(signed, prep.ByteRange);
            var d = VriItems(wantDss, Convert.ToHexString(SHA1.HashData(contents)));
            d.Contents = contents;
            var outDss = Dss.Append(signed, d);
            AssertSameDoc(wantDss, outDss, $"{kind}-{n}-dss.pdf");
            cur = wantDss;
        }
    }

    private static PdfValue LastSig(byte[] doc, int n)
    {
        var r = PdfDocument.Open(doc);
        var fields = r.Trailer.Key("Root").Key("AcroForm").Key("Fields");
        for (int i = 0; i < fields.Len; i++)
        {
            var f = fields.Index(i);
            if (f.Key("T").Text == "Signature " + n) return f.Key("V");
        }
        throw new Xunit.Sdk.XunitException("Signature " + n + " missing");
    }

    private static DateTimeOffset ParseM(string s)
    {
        s = s.StartsWith("D:", StringComparison.Ordinal) ? s[2..] : s;
        // YYYYMMDDHHmmSS+HH'mm'
        var dt = DateTime.ParseExact(s[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        int sign = s[14] == '-' ? -1 : 1;
        var off = new TimeSpan(int.Parse(s.Substring(15, 2), CultureInfo.InvariantCulture), int.Parse(s.Substring(18, 2), CultureInfo.InvariantCulture), 0);
        return new DateTimeOffset(dt, sign * off);
    }

    private static DssData VriItems(byte[] doc, string key)
    {
        var r = PdfDocument.Open(doc);
        var e = r.Trailer.Key("Root").Key("DSS").Key("VRI").Key(key);
        Assert.False(e.IsNull, "VRI " + key + " missing");
        var d = new DssData();
        void Read(string name, System.Collections.Generic.List<byte[]> into)
        {
            var a = e.Key(name);
            for (int i = 0; i < a.Len; i++) into.Add(a.Index(i).StreamBytes());
        }
        Read("Cert", d.Certs);
        Read("OCSP", d.Ocsps);
        Read("CRL", d.Crls);
        return d;
    }

    private static readonly Regex XrefHead = new(@"/Type /XRef /Length (\d+)( /Filter /FlateDecode)?", RegexOptions.CultureInvariant);
    private static readonly Regex ByteRangeTail = new(@"(/ByteRange \[0 \d+ \d+ )\d+\]", RegexOptions.CultureInvariant);

    /// <summary>Xref stream бүрийг задалж (zlib бол inflate), /Length ба /Filter-ийг арилгана; ByteRange-ийн сүүлийн тоог арилгана.</summary>
    internal static string Normalize(byte[] doc)
    {
        var s = Encoding.Latin1.GetString(doc);
        var sb = new StringBuilder();
        int pos = 0;
        while (true)
        {
            var m = XrefHead.Match(s, pos);
            if (!m.Success)
            {
                sb.Append(s, pos, s.Length - pos);
                break;
            }
            int len = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            bool z = m.Groups[2].Success;
            sb.Append(s, pos, m.Index - pos).Append("/Type /XRef /Length *");
            int i = s.IndexOf(">>\nstream\n", m.Index + m.Length, StringComparison.Ordinal);
            Assert.True(i >= 0);
            sb.Append(s, m.Index + m.Length, i + 10 - (m.Index + m.Length));
            var data = Encoding.Latin1.GetBytes(s.Substring(i + 10, len));
            if (z)
            {
                using var zs = new ZLibStream(new MemoryStream(data), CompressionMode.Decompress);
                using var ms = new MemoryStream();
                zs.CopyTo(ms);
                data = ms.ToArray();
            }
            sb.Append(Encoding.Latin1.GetString(data));
            pos = i + 10 + len;
        }
        return ByteRangeTail.Replace(sb.ToString(), "$1*]");
    }

    private static void AssertSameDoc(byte[] want, byte[] got, string what)
    {
        if (want.AsSpan().SequenceEqual(got)) return;
        var nw = Normalize(want);
        var ng = Normalize(got);
        if (nw == ng) return;
        int i = 0;
        while (i < nw.Length && i < ng.Length && nw[i] == ng[i]) i++;
        string Ctx(string x) => x.Substring(Math.Max(0, i - 80), Math.Min(200, Math.Max(0, x.Length - Math.Max(0, i - 80))));
        Assert.Fail($"{what} differs at {i} (want {nw.Length} got {ng.Length})\nwant: {Esc(Ctx(nw))}\ngot:  {Esc(Ctx(ng))}");
    }

    private static string Esc(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s) sb.Append(c is >= ' ' and < (char)0x7f ? c.ToString() : $"\\x{(int)c:X2}");
        return sb.ToString();
    }
}
