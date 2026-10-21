using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>Verify хуудасны тогтмол фонт (pades/assets/fonts) — FontFile2 stream-ийн байт ба metrics.json.</summary>
internal sealed class PageFont
{
    public string PsName { get; private init; } = "";
    public byte[] Stream { get; private init; } = Array.Empty<byte>();
    public int Length1 { get; private init; }
    public int Ascent { get; private init; }
    public int Descent { get; private init; }
    public int CapHeight { get; private init; }
    public int[] BBox { get; private init; } = Array.Empty<int>();
    public int[] Widths { get; private init; } = Array.Empty<int>();
    public Dictionary<int, ushort> Gid { get; } = new();

    public int Width1000(ushort gid) => Widths[Math.Min(gid, Widths.Length - 1)];

    public static readonly Lazy<PageFont> Regular = new(() => Load("NotoSans-Regular"));
    public static readonly Lazy<PageFont> Bold = new(() => Load("NotoSans-Bold"));

    private static PageFont Load(string name)
    {
        var asm = typeof(PageFont).Assembly;
        var stream = ReadResource(asm, "eid.assets." + name + ".ttf.zlib");
        using var doc = JsonDocument.Parse(ReadResource(asm, "eid.assets." + name + ".metrics.json"));
        var r = doc.RootElement;
        var f = new PageFont
        {
            PsName = r.GetProperty("psName").GetString()!,
            Stream = stream,
            Length1 = r.GetProperty("length1").GetInt32(),
            Ascent = r.GetProperty("ascent").GetInt32(),
            Descent = r.GetProperty("descent").GetInt32(),
            CapHeight = r.GetProperty("capHeight").GetInt32(),
            BBox = ToInts(r.GetProperty("bbox")),
            Widths = ToInts(r.GetProperty("widths")),
        };
        foreach (var pair in r.GetProperty("cmap").EnumerateArray())
            f.Gid[pair[0].GetInt32()] = (ushort)pair[1].GetInt32();
        return f;
    }

    private static int[] ToInts(JsonElement a)
    {
        var o = new int[a.GetArrayLength()];
        int i = 0;
        foreach (var e in a.EnumerateArray()) o[i++] = e.GetInt32();
        return o;
    }

    private static byte[] ReadResource(Assembly asm, string name)
    {
        using var s = asm.GetManifestResourceStream(name) ?? throw new InvalidOperationException("missing resource " + name);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}

internal sealed record PageData(string Brand, string FileName, string DocumentHash, long FileSize, string DocId, string VerifyUrl,
    string TrustUrl, string CaName, string TsaName, string Provider, string Lang);

/// <summary>PAGE_SPEC.md §3a — хуудасны тогтмол бичвэр (mn анхдагч, en).</summary>
internal sealed record PageText(string Title, string Subtitle, string Document, string FileName, string HashAlg, string Size,
    string DocHash, string DocId, string Verification, string Scan, string ScanHint, string Trust, string Provider)
{
    public static readonly PageText Mn = new(
        "-аар гарын үсэг зурсан баримт",
        "Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.",
        "БАРИМТ", "БАРИМТЫН НЭР", "HASH АЛГОРИТМ", "ХЭМЖЭЭ", "БАРИМТЫН HASH", "БАРИМТЫН ID", "ШАЛГАХ",
        "Гарын үсгийг шалгах",
        "QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.",
        "Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:",
        "Үйлчилгээ");

    public static readonly PageText En = new(
        " \u2014 Electronically signed document",
        "Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.",
        "DOCUMENT", "FILE NAME", "HASH ALGORITHM", "SIZE", "DOCUMENT HASH", "DOCUMENT ID", "VERIFICATION",
        "Scan to verify",
        "Scan this QR code with your phone camera to verify.",
        "Adobe Acrobat: trust the Mongolian National Root CA",
        "Provider");

    public static PageText For(string? lang) => lang switch
    {
        null or "" or "mn" => Mn,
        "en" => En,
        _ => throw new InvalidOperationException("pades: page language " + lang),
    };
}

/// <summary>Баталгаажуулалтын хуудас — PAGE_SPEC.md (pades-client/1), Go reference core/vpage.go-тэй байт-ижил.</summary>
internal static class VerifyPage
{
    private const string MediaBox = "[0 0 595.28 841.89]";
    private const int Left = 42, Width = 510, Col2 = 297, QrModule = 2, QrTextX = 136, FileNameMax = 3;
    internal const string ColText = "0.118 0.118 0.118", ColMuted = "0.431 0.431 0.431", ColOk = "0.086 0.541 0.31";
    private const string ColBanner = "0.863 0.961 0.902", ColLine = "0.863 0.863 0.863", ColLink = "0.118 0.431 0.863";

    private const string BannerPath = "48 800 m\n546 800 l\n549.31 800 552 797.31 552 794 c\n552 754 l\n552 750.69 549.31 748 546 748 c\n" +
                                      "48 748 l\n44.69 748 42 750.69 42 754 c\n42 794 l\n42 797.31 44.69 800 48 800 c\nh\nf";

    internal sealed record Link(int X1, int Y1, int X2, int Y2, string Url);

    internal sealed class Writer
    {
        public readonly StringBuilder Ops = new();
        public readonly PageFont Reg, Bld;
        public readonly List<Link> Links = new();

        public Writer(PageFont reg, PageFont bld)
        {
            Reg = reg;
            Bld = bld;
        }

        public void Op(string s) => Ops.Append(s).Append('\n');

        private PageFont Font(int id) => id == 2 ? Bld : Reg;

        public List<ushort> Gids(int id, string s)
        {
            var f = Font(id);
            var o = new List<ushort>();
            foreach (var r in s.EnumerateRunes())
                o.Add(f.Gid.TryGetValue(r.Value, out var g) ? g : f.Gid['?']);
            return o;
        }

        public int Width1000(int id, int size, string s)
        {
            if (id == 3)
            {
                int n = 0;
                foreach (var _ in s.EnumerateRunes()) n++;
                return 600 * n * size;
            }
            int sum = 0;
            foreach (var g in Gids(id, s)) sum += Font(id).Width1000(g);
            return sum * size;
        }

        public void Text(int id, int size, int x, int y, string color, string s)
        {
            string str;
            if (id == 3)
            {
                str = "(" + s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal)
                    .Replace(")", "\\)", StringComparison.Ordinal) + ")";
            }
            else
            {
                str = GlyphHex(id, s);
            }
            Op(color + " rg");
            Op(string.Create(CultureInfo.InvariantCulture, $"BT /F{id} {size} Tf {x} {y} Td {str} Tj ET"));
        }

        /// <summary>F1/F2 бичвэрийн <c>&lt;GGGG…&gt;</c> (PAGE_SPEC.md §2).</summary>
        public string GlyphHex(int id, string s)
        {
            var b = new StringBuilder("<");
            foreach (var g in Gids(id, s)) b.Append(g.ToString("X4", CultureInfo.InvariantCulture));
            return b.Append('>').ToString();
        }

        public void LinkAt(int id, int size, int x, int y, string s)
        {
            int wd = (Width1000(id, size, s) + 999) / 1000;
            Links.Add(new Link(x, y - 3, x + wd, y + size, s));
        }

        public void HLine(int y)
        {
            Op(ColLine + " RG");
            Op(string.Create(CultureInfo.InvariantCulture, $"0.75 w {Left} {y} m {Left + Width} {y} l S"));
        }

        public List<string> Wrap(int id, int size, string s, int maxW, int maxLines) => WrapLimit(id, size, s, maxW * 1000, maxLines);

        /// <summary>Wrap, өргөний хязгаар limit нь 1/1000 pt-ээр (харагдах гарын үсэгт: 1/100 pt × 10).</summary>
        public List<string> WrapLimit(int id, int size, string s, int limit, int maxLines)
        {
            bool Fits(string t) => Width1000(id, size, t) <= limit;
            var lines = new List<string>();
            string cur = "";
            foreach (var w0 in s.Split(' '))
            {
                var word = w0;
                if (word == "") continue;
                var cand = cur == "" ? word : cur + " " + word;
                if (Fits(cand))
                {
                    cur = cand;
                    continue;
                }
                if (cur != "")
                {
                    lines.Add(cur);
                    cur = "";
                }
                while (!Fits(word))
                {
                    var r = Runes(word);
                    int n = 1;
                    while (n < r.Count && Fits(Join(r, 0, n + 1))) n++;
                    lines.Add(Join(r, 0, n));
                    word = Join(r, n, r.Count);
                }
                cur = word;
            }
            if (cur != "") lines.Add(cur);
            if (lines.Count > maxLines)
            {
                var last = Runes(lines[maxLines - 1]);
                while (last.Count > 0 && !Fits(Join(last, 0, last.Count) + "…")) last.RemoveAt(last.Count - 1);
                lines.RemoveRange(maxLines - 1, lines.Count - (maxLines - 1));
                lines.Add(Join(last, 0, last.Count) + "…");
            }
            return lines;
        }

        private static List<Rune> Runes(string s)
        {
            var l = new List<Rune>();
            foreach (var r in s.EnumerateRunes()) l.Add(r);
            return l;
        }

        private static string Join(List<Rune> r, int from, int to)
        {
            var b = new StringBuilder();
            for (int i = from; i < to; i++) b.Append(r[i].ToString());
            return b.ToString();
        }
    }

    public static string HumanSize(long b)
    {
        if (b < 1L << 10) return b.ToString(CultureInfo.InvariantCulture) + " B";
        if (b < 1L << 20) return Tenths(b, 1L << 10) + " KB";
        if (b < 1L << 30) return Tenths(b, 1L << 20) + " MB";
        return Tenths(b, 1L << 30) + " GB";
    }

    private static string Tenths(long b, long unit)
    {
        long t = (b * 10 + unit / 2) / unit;
        return (t / 10).ToString(CultureInfo.InvariantCulture) + "." + (t % 10).ToString(CultureInfo.InvariantCulture);
    }

    private static string UrlHost(string u)
    {
        var s = u.StartsWith("https://", StringComparison.Ordinal) ? u[8..] : u;
        s = s.StartsWith("http://", StringComparison.Ordinal) ? s[7..] : s;
        int i = s.IndexOf('/', StringComparison.Ordinal);
        if (i > 0)
        {
            int next = s.IndexOf('/', i + 1);
            if (next > i + 1) return s[..next];
        }
        return s;
    }

    internal static bool AsciiUrl(string u)
    {
        foreach (var c in u)
            if (c < 0x21 || c > 0x7e || c is '(' or ')' or '\\') return false;
        return u != "";
    }

    private static (byte[] Content, List<Link> Links) Content(PageData p, PageFont reg, PageFont bld)
    {
        if (!AsciiUrl(p.VerifyUrl) || p.TrustUrl != "" && !AsciiUrl(p.TrustUrl)) throw new InvalidOperationException("pades: URL is not ASCII");
        var m = Qr.Encode(Encoding.ASCII.GetBytes(p.VerifyUrl));
        var tx = PageText.For(p.Lang);
        var w = new Writer(reg, bld);
        w.Op(ColBanner + " rg");
        w.Op(BannerPath);
        w.Text(2, 13, 56, 778, ColOk, p.Brand + tx.Title);
        w.Text(1, 9, 56, 760, ColOk, tx.Subtitle);
        int y = 724;
        w.HLine(y);
        w.Text(2, 11, Left, y - 17, ColText, tx.Document);
        y -= 34;
        w.Text(1, 8, Left, y, ColMuted, tx.FileName);
        y -= 14;
        var lines = w.Wrap(2, 10, p.FileName, Width, FileNameMax);
        for (int i = 0; i < lines.Count; i++)
        {
            if (i > 0) y -= 14;
            w.Text(2, 10, Left, y, ColText, lines[i]);
        }
        y -= 20;
        w.Text(1, 8, Left, y, ColMuted, tx.HashAlg);
        w.Text(1, 8, Col2, y, ColMuted, tx.Size);
        w.Text(2, 10, Left, y - 14, ColText, "SHA256");
        w.Text(2, 10, Col2, y - 14, ColText, HumanSize(p.FileSize));
        y -= 34;
        w.Text(1, 8, Left, y, ColMuted, tx.DocHash);
        w.Text(3, 9, Left, y - 13, ColText, p.DocumentHash);
        y -= 31;
        w.Text(1, 8, Left, y, ColMuted, tx.DocId);
        w.Text(3, 9, Left, y - 13, ColText, p.DocId);
        y -= 35;
        w.HLine(y);
        w.Text(2, 11, Left, y - 17, ColText, tx.Verification);
        y -= 35;
        w.Text(1, 9, Left, y, ColLink, p.VerifyUrl);
        w.LinkAt(1, 9, Left, y, p.VerifyUrl);
        y -= 14;
        w.Op("0 0 0 rg");
        int n = m.Length;
        for (int r = 0; r < n; r++)
        {
            for (int c = 0; c < n;)
            {
                if (!m[r][c])
                {
                    c++;
                    continue;
                }
                int s = c;
                while (c < n && m[r][c]) c++;
                w.Op(string.Create(CultureInfo.InvariantCulture, $"{Left + QrModule * s} {y - QrModule * (r + 1)} {QrModule * (c - s)} {QrModule} re"));
            }
        }
        w.Op("f");
        w.Text(2, 11, QrTextX, y - 14, ColText, tx.Scan);
        w.Text(1, 9, QrTextX, y - 29, ColMuted, tx.ScanHint);
        w.Text(2, 9, QrTextX, y - 43, ColLink, UrlHost(p.VerifyUrl));
        if (p.TrustUrl != "")
        {
            w.Text(1, 9, QrTextX, y - 60, ColMuted, tx.Trust);
            w.Text(2, 9, QrTextX, y - 74, ColLink, p.TrustUrl);
            w.LinkAt(2, 9, QrTextX, y - 74, p.TrustUrl);
        }
        w.HLine(71);
        w.Text(1, 8, Left, 58, ColMuted, "CA: " + p.CaName + "  |  TSA: " + p.TsaName + "  |  " + tx.Provider + ": " + p.Provider);
        return (Encoding.ASCII.GetBytes(w.Ops.ToString()), w.Links);
    }

    /// <summary>
    /// base-д хуудсыг incremental revision-оор нэмнэ: үндсэн /Pages-ийн /Kids-ийн төгсгөлд, <paramref name="first"/> бол
    /// эхэнд (PAGE_SPEC.md §8a); Catalog өөрчлөгдөхгүй.
    /// </summary>
    public static byte[] Append(byte[] baseBytes, PageData p, bool first = false)
    {
        var reg = PageFont.Regular.Value;
        var bld = PageFont.Bold.Value;
        var (content, links) = Content(p, reg, bld);
        var inc = Incremental.Open(baseBytes);
        var root = inc.Root;
        var pages = root.Key("Pages");
        var pp = pages.Ptr;
        if (pages.Kind != PdfKind.Dict || pages.Key("Type").Name != "Pages" || pp == root.Ptr || pp.Id == 0)
            throw new PdfFormatException("pades: /Pages root missing");
        long count = pages.Key("Count").Int64;
        if (count < 0 || pages.Key("Kids").Kind != PdfKind.Array) throw new PdfFormatException("pades: bad /Pages /Kids /Count");
        var rp = root.Ptr;
        if (rp.Gen != 0) throw new PdfFormatException("pades: Catalog generation is not 0");

        uint pageId = inc.Reserve(), contentId = inc.Reserve();
        var fontIds = new uint[2][];
        for (int i = 0; i < 2; i++)
        {
            fontIds[i] = new uint[5];
            for (int j = 0; j < 5; j++) fontIds[i][j] = inc.Reserve();
        }
        uint courierId = inc.Reserve();
        var linkIds = new uint[links.Count];
        for (int i = 0; i < linkIds.Length; i++) linkIds[i] = inc.Reserve();

        var pg = new StringBuilder();
        pg.Append(CultureInfo.InvariantCulture,
            $"<< /Type /Page /Parent {pp.Id} {pp.Gen} R /MediaBox {MediaBox} /CropBox {MediaBox} /Rotate 0 /Resources << /Font << /F1 {fontIds[0][0]} 0 R /F2 {fontIds[1][0]} 0 R /F3 {courierId} 0 R >> >> /Contents {contentId} 0 R");
        if (linkIds.Length > 0)
        {
            pg.Append(" /Annots [");
            for (int i = 0; i < linkIds.Length; i++)
            {
                if (i > 0) pg.Append(' ');
                pg.Append(CultureInfo.InvariantCulture, $"{linkIds[i]} 0 R");
            }
            pg.Append(']');
        }
        pg.Append(" >>");
        inc.WriteObject(pageId, Ascii(pg.ToString()));
        inc.WriteObject(contentId, StreamObj("", content));
        WriteFont(inc, fontIds[0], reg);
        WriteFont(inc, fontIds[1], bld);
        inc.WriteObject(courierId, Ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"));
        for (int i = 0; i < links.Count; i++)
        {
            var l = links[i];
            inc.WriteObject(linkIds[i], Ascii(string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Annot /Subtype /Link /Rect [{l.X1} {l.Y1} {l.X2} {l.Y2}] /Border [0 0 0] /A << /S /URI /URI ({l.Url}) >> >>")));
        }

        var pn = new MemoryStream();
        pn.Ascii("<<");
        foreach (var key in pages.Keys())
        {
            if (key is "Kids" or "Count") continue;
            pn.Ascii(" /" + Serializer.EscapeName(key) + " ");
            Serializer.Serialize(pn, pages.Key(key), pp.Id, 0);
        }
        var kids = pages.Key("Kids");
        var kp = kids.Ptr;
        pn.Ascii(" /Kids [");
        if (first)
        {
            pn.Ascii(string.Create(CultureInfo.InvariantCulture, $"{pageId} 0 R"));
            for (int i = 0; i < kids.Len; i++)
            {
                pn.Ascii(" ");
                Serializer.Serialize(pn, kids.Index(i), kp.Id, 0);
            }
            pn.Ascii(string.Create(CultureInfo.InvariantCulture, $"] /Count {count + 1} >>"));
        }
        else
        {
            for (int i = 0; i < kids.Len; i++)
            {
                Serializer.Serialize(pn, kids.Index(i), kp.Id, 0);
                pn.Ascii(" ");
            }
            pn.Ascii(string.Create(CultureInfo.InvariantCulture, $"{pageId} 0 R] /Count {count + 1} >>"));
        }
        inc.WriteObjectGen(pp.Id, pp.Gen, pn.ToArray());
        return inc.Finish(rp.Id);
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    internal static byte[] StreamObj(string extra, byte[] data)
    {
        var b = new MemoryStream();
        b.Ascii(string.Create(CultureInfo.InvariantCulture, $"<< /Length {data.Length}{extra} >>\nstream\n"));
        b.Write(data);
        b.Ascii("\nendstream");
        return b.ToArray();
    }

    private static void WriteFont(Incremental inc, uint[] ids, PageFont f)
    {
        var bodies = FontBodies(ids, f);
        for (int i = 0; i < bodies.Length; i++) inc.WriteObject(ids[i], bodies[i]);
    }

    /// <summary>WriteFont-ийн 5 объектын бие (ids-ийн дарааллаар); verify хуудас ба харагдах гарын үсэгт ижил.</summary>
    internal static byte[][] FontBodies(uint[] ids, PageFont f)
    {
        var wa = new StringBuilder();
        for (int g = 0; g < f.Widths.Length; g++)
        {
            if (g > 0) wa.Append(' ');
            wa.Append(f.Width1000((ushort)g).ToString(CultureInfo.InvariantCulture));
        }
        return new[]
        {
            Ascii(string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Font /Subtype /Type0 /BaseFont /{f.PsName} /Encoding /Identity-H /DescendantFonts [{ids[1]} 0 R] /ToUnicode {ids[4]} 0 R >>")),
            Ascii(string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{f.PsName} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor {ids[2]} 0 R /CIDToGIDMap /Identity /W [0 [{wa}]] >>")),
            Ascii(string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /FontDescriptor /FontName /{f.PsName} /Flags 32 /FontBBox [{f.BBox[0]} {f.BBox[1]} {f.BBox[2]} {f.BBox[3]}] /ItalicAngle 0 /Ascent {f.Ascent} /Descent {f.Descent} /CapHeight {f.CapHeight} /StemV 80 /FontFile2 {ids[3]} 0 R >>")),
            StreamObj(string.Create(CultureInfo.InvariantCulture, $" /Length1 {f.Length1} /Filter /FlateDecode"), f.Stream),
            StreamObj("", ToUnicode(f)),
        };
    }

    private static byte[] ToUnicode(PageFont f)
    {
        var uni = new Dictionary<ushort, int>();
        foreach (var (r, g) in f.Gid)
            if (!uni.TryGetValue(g, out var old) || r < old) uni[g] = r;
        var pairs = new List<(int G, int R)>();
        for (int g = 0; g < f.Widths.Length; g++)
            if (uni.TryGetValue((ushort)g, out var r)) pairs.Add((g, r));
        var b = new StringBuilder();
        b.Append("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n" +
                 "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n" +
                 "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");
        for (int i = 0; i < pairs.Count; i += 100)
        {
            int end = Math.Min(i + 100, pairs.Count);
            b.Append(CultureInfo.InvariantCulture, $"{end - i} beginbfchar\n");
            for (int k = i; k < end; k++) b.Append(CultureInfo.InvariantCulture, $"<{pairs[k].G:X4}> <{pairs[k].R:X4}>\n");
            b.Append("endbfchar\n");
        }
        b.Append("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend");
        return Encoding.ASCII.GetBytes(b.ToString());
    }
}
