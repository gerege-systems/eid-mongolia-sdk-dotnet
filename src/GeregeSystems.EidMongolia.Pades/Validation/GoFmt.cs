using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Validation;

// Go-ийн тайлангийн утгуудыг (CA /v3/validate/pdf JSON) байт-ижил гаргах туслахууд — TS SDK src/pades/validate/gofmt.ts-ийн
// порт: time.Time MarshalJSON (RFC3339Nano), pkix.Name.String(), big.Int.Text(16), digitorus pdf Value.Text(), JSON-ийн
// UTF-8 засвар.

/// <summary>Go time.Time (UTC): Unix секунд + наносекунд. <see cref="Sec"/> null = тэг утга (0001-01-01T00:00:00Z).</summary>
internal readonly record struct GoTime(long? Sec, int Nanos)
{
    private const long ZeroSec = -62135596800;

    public static readonly GoTime Zero = new(null, 0);

    public bool IsZero => Sec is null;

    public static GoTime FromPrecise(PreciseTime t) => new(FloorDiv(t.UnixMs, 1000), t.Nanos);

    /// <summary>JS Date-ийн мс-ээс (TS fromDate).</summary>
    public static GoTime FromUnixMs(long ms)
    {
        long sec = FloorDiv(ms, 1000);
        return new GoTime(sec, (int)((ms - sec * 1000) * 1_000_000));
    }

    public static GoTime FromDateTimeOffset(DateTimeOffset d) => FromUnixMs(d.ToUnixTimeMilliseconds());

    private static long FloorDiv(long a, long b)
    {
        long q = a / b;
        if (a % b != 0 && (a < 0) != (b < 0)) q--;
        return q;
    }

    private static int Cmp(GoTime a, GoTime b)
    {
        long x = a.Sec ?? ZeroSec;
        long y = b.Sec ?? ZeroSec;
        if (x != y) return x < y ? -1 : 1;
        return a.Nanos == b.Nanos ? 0 : a.Nanos < b.Nanos ? -1 : 1;
    }

    /// <summary>a &lt; b</summary>
    public static bool Before(GoTime a, GoTime b) => Cmp(a, b) < 0;

    /// <summary>a &gt; b</summary>
    public static bool After(GoTime a, GoTime b) => Cmp(a, b) > 0;

    /// <summary>t + ms (TS addMs).</summary>
    public GoTime AddMs(long ms)
    {
        long total = (Sec ?? ZeroSec) * 1000 + Nanos / 1_000_000 + ms;
        long sec = FloorDiv(total, 1000);
        return new GoTime(sec, (int)((total - sec * 1000) * 1_000_000 + Nanos % 1_000_000));
    }

    /// <summary>Go time.Time.MarshalJSON (UTC): "2006-01-02T15:04:05.999999999Z".</summary>
    public string Format()
    {
        if (Sec is not { } s) return "0001-01-01T00:00:00Z";
        var d = DateTimeOffset.FromUnixTimeSeconds(s).UtcDateTime;
        var o = d.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss", CultureInfo.InvariantCulture);
        if (Nanos > 0) o += "." + Nanos.ToString("D9", CultureInfo.InvariantCulture).TrimEnd('0');
        return o + "Z";
    }

    /// <summary>Сүлжээ/хүлцлийн тооцоонд (100 нс нарийвчлал).</summary>
    public DateTimeOffset ToDateTimeOffset() =>
        DateTimeOffset.FromUnixTimeSeconds(Sec ?? ZeroSec).AddTicks(Nanos / 100);
}

internal static class GoFmt
{
    /// <summary>big.Int.Text(16) томоор (CA hexSerial): INTEGER агуулга → "1A2B".</summary>
    public static string HexSerial(ReadOnlySpan<byte> intContent)
    {
        var v = new BigInteger(intContent, isUnsigned: false, isBigEndian: true);
        bool neg = v.Sign < 0;
        if (neg) v = BigInteger.Negate(v);
        var hex = v.IsZero ? "0" : Convert.ToHexString(v.ToByteArray(isUnsigned: true, isBigEndian: true)).TrimStart('0');
        if (hex.Length == 0) hex = "0";
        return (neg ? "-" : "") + hex;
    }

    private const int NoRune = -1;

    // digitorus/pdf text.go pdfDocEncoding (PDF 32000-1 Table D.2).
    private static readonly int[] PdfDoc = BuildPdfDoc();

    private static int[] BuildPdfDoc()
    {
        var t = new int[256];
        Array.Fill(t, NoRune);
        t[9] = 9;
        t[10] = 10;
        t[13] = 13;
        int[] a = { 0x02d8, 0x02c7, 0x02c6, 0x02d9, 0x02dd, 0x02db, 0x02da, 0x02dc };
        for (int i = 0; i < a.Length; i++) t[0x18 + i] = a[i];
        for (int i = 0x20; i < 0x7f; i++) t[i] = i;
        int[] b =
        {
            0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044, 0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c, 0x201d, 0x2018,
            0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x0141, 0x0152, 0x0160, 0x0178, 0x017d, 0x0131, 0x0142, 0x0153, 0x0161, 0x017e, NoRune,
        };
        for (int i = 0; i < b.Length; i++) t[0x80 + i] = b[i];
        t[0xa0] = 0x20ac;
        for (int i = 0xa1; i <= 0xff; i++) t[i] = i;
        t[0xad] = NoRune;
        return t;
    }

    /// <summary>digitorus pdf Value.Text(): PDFDocEncoding → UTF-16BE (BOM, тэгш урт) → түүхий байт (Go string).</summary>
    public static string PdfText(ReadOnlySpan<byte> b)
    {
        bool utf16 = b.Length >= 2 && b[0] == 0xfe && b[1] == 0xff && b.Length % 2 == 0;
        if (!utf16)
        {
            bool all = true;
            foreach (var x in b)
            {
                if (PdfDoc[x] == NoRune)
                {
                    all = false;
                    break;
                }
            }
            if (all)
            {
                var sb = new StringBuilder(b.Length);
                foreach (var x in b) sb.Append(char.ConvertFromUtf32(PdfDoc[x]));
                return sb.ToString();
            }
        }
        if (utf16)
        {
            var u = new char[(b.Length - 2) / 2];
            for (int i = 2, k = 0; i < b.Length; i += 2, k++) u[k] = (char)(b[i] << 8 | b[i + 1]);
            return FixSurrogates(new string(u));
        }
        return GoString(b);
    }

    /// <summary>Go utf16.Decode: хосгүй surrogate → U+FFFD.</summary>
    public static string FixSurrogates(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    sb.Append(c).Append(s[i + 1]);
                    i++;
                }
                else
                {
                    sb.Append('�');
                }
            }
            else if (char.IsLowSurrogate(c))
            {
                sb.Append('�');
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    /// <summary>Түүхий байт (Go string) → JSON-д Go-ийн бичих мөр: хүчингүй UTF-8 байт бүр U+FFFD (encoding/json).</summary>
    public static string GoString(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        for (int i = 0; i < b.Length;)
        {
            var (r, n) = DecodeRune(b, i);
            sb.Append(char.ConvertFromUtf32(r));
            i += n;
        }
        return sb.ToString();
    }

    /// <summary>Go utf8.DecodeRune: (rune, size); хүчингүй бол (U+FFFD, 1).</summary>
    private static (int, int) DecodeRune(ReadOnlySpan<byte> b, int i)
    {
        int c0 = b[i];
        if (c0 < 0x80) return (c0, 1);
        var bad = (0xfffd, 1);
        bool Cont(ReadOnlySpan<byte> s, int k, int lo = 0x80, int hi = 0xbf) => i + k < s.Length && s[i + k] >= lo && s[i + k] <= hi;
        if (c0 >= 0xc2 && c0 <= 0xdf) return Cont(b, 1) ? (((c0 & 0x1f) << 6) | (b[i + 1] & 0x3f), 2) : bad;
        if (c0 >= 0xe0 && c0 <= 0xef)
        {
            int lo = c0 == 0xe0 ? 0xa0 : 0x80;
            int hi = c0 == 0xed ? 0x9f : 0xbf;
            return Cont(b, 1, lo, hi) && Cont(b, 2) ? (((c0 & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f), 3) : bad;
        }
        if (c0 >= 0xf0 && c0 <= 0xf4)
        {
            int lo = c0 == 0xf0 ? 0x90 : 0x80;
            int hi = c0 == 0xf4 ? 0x8f : 0xbf;
            return Cont(b, 1, lo, hi) && Cont(b, 2) && Cont(b, 3)
                ? (((c0 & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) | ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f), 4)
                : bad;
        }
        return bad;
    }

    // ── pkix.Name ──

    private sealed record Atv(string Oid, string? Str, byte[] Raw);

    private static readonly Dictionary<string, string> AttrNames = new(StringComparer.Ordinal)
    {
        ["2.5.4.6"] = "C",
        ["2.5.4.10"] = "O",
        ["2.5.4.11"] = "OU",
        ["2.5.4.3"] = "CN",
        ["2.5.4.5"] = "SERIALNUMBER",
        ["2.5.4.7"] = "L",
        ["2.5.4.8"] = "ST",
        ["2.5.4.9"] = "STREET",
        ["2.5.4.17"] = "POSTALCODE",
    };

    /// <summary>Go encoding/asn1: interface{}-д задлах үед string болох tag-ууд.</summary>
    private static string? Asn1String(Asn1Node n)
    {
        var v = n.Value.Span;
        switch (n.Tag)
        {
            case Asn1.PrintableString:
            case Asn1.Ia5String:
            case 0x12: // NumericString
            case 0x14: // T61String — Go: байт бүр (шууд string)
            case Asn1.Utf8String:
                return GoString(v);
            case 0x1e:
                {
                    // BMPString — Go parseBMPString (UCS-2 → UTF-8); сондгой урт → алдаа
                    if (v.Length % 2 != 0) return null;
                    var u = new List<char>(v.Length / 2);
                    for (int i = 0; i < v.Length; i += 2) u.Add((char)(v[i] << 8 | v[i + 1]));
                    if (u.Count > 0 && u[u.Count - 1] == 0) u.RemoveAt(u.Count - 1);
                    return FixSurrogates(new string(u.ToArray()));
                }
        }
        return null;
    }

    private static List<List<Atv>> Rdns(ReadOnlyMemory<byte> rawName)
    {
        var o = new List<List<Atv>>();
        foreach (var rdn in Asn1.Children(Asn1.ReadNode(rawName, 0)))
        {
            var l = new List<Atv>();
            foreach (var atv in Asn1.Children(rdn))
            {
                var p = Asn1.Children(atv);
                var t = Asn1.At(p, 0) ?? throw new Asn1Exception("asn1: ATV");
                var v = Asn1.At(p, 1) ?? throw new Asn1Exception("asn1: ATV");
                l.Add(new Atv(Asn1.OidString(t), Asn1String(v), v.Raw.ToArray()));
            }
            o.Add(l);
        }
        return o;
    }

    /// <summary>Go asn1.Marshal(string): PrintableString (зөвшөөрөгдсөн тэмдэгт) эсвэл UTF8String.</summary>
    private static byte[] MarshalString(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        bool printable = true;
        foreach (var ch in s)
        {
            if (!(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || " '()+,-./:=?".IndexOf(ch) >= 0))
            {
                printable = false;
                break;
            }
        }
        int tag = printable ? Asn1.PrintableString : Asn1.Utf8String;
        int len = bytes.Length;
        byte[] hdr = len < 0x80 ? new[] { (byte)tag, (byte)len }
            : len < 0x100 ? new[] { (byte)tag, (byte)0x81, (byte)len }
            : new[] { (byte)tag, (byte)0x82, (byte)(len >> 8), (byte)(len & 0xff) };
        var o = new byte[hdr.Length + len];
        hdr.CopyTo(o, 0);
        bytes.CopyTo(o, hdr.Length);
        return o;
    }

    /// <summary>Go pkix.Name.String() (задалсан гэрчилгээний Subject/Issuer: ExtraNames nil).</summary>
    public static string NameString(ReadOnlyMemory<byte> rawName)
    {
        var seq = Rdns(rawName);
        var f = new Dictionary<string, List<string>>(StringComparer.Ordinal)
        {
            ["C"] = new(),
            ["ST"] = new(),
            ["L"] = new(),
            ["STREET"] = new(),
            ["POSTALCODE"] = new(),
            ["O"] = new(),
            ["OU"] = new(),
        };
        string cn = "", sn = "";
        var all = new List<Atv>();
        foreach (var rdn in seq)
        {
            foreach (var a in rdn)
            {
                all.Add(a);
                if (a.Str is null) continue;
                switch (a.Oid)
                {
                    case "2.5.4.3": cn = a.Str; break;
                    case "2.5.4.5": sn = a.Str; break;
                    case "2.5.4.6": f["C"].Add(a.Str); break;
                    case "2.5.4.7": f["L"].Add(a.Str); break;
                    case "2.5.4.8": f["ST"].Add(a.Str); break;
                    case "2.5.4.9": f["STREET"].Add(a.Str); break;
                    case "2.5.4.17": f["POSTALCODE"].Add(a.Str); break;
                    case "2.5.4.10": f["O"].Add(a.Str); break;
                    case "2.5.4.11": f["OU"].Add(a.Str); break;
                }
            }
        }
        var outRdns = new List<List<Atv>>();
        var skip = new HashSet<string>(StringComparer.Ordinal)
        {
            "2.5.4.3", "2.5.4.5", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.9", "2.5.4.10", "2.5.4.11", "2.5.4.17",
        };
        foreach (var a in all)
            if (!skip.Contains(a.Oid)) outRdns.Add(new List<Atv> { a });
        void Add(List<string> vals, string oid)
        {
            if (vals.Count == 0) return;
            var l = new List<Atv>();
            foreach (var v in vals) l.Add(new Atv(oid, v, Array.Empty<byte>()));
            outRdns.Add(l);
        }
        Add(f["C"], "2.5.4.6");
        Add(f["ST"], "2.5.4.8");
        Add(f["L"], "2.5.4.7");
        Add(f["STREET"], "2.5.4.9");
        Add(f["POSTALCODE"], "2.5.4.17");
        Add(f["O"], "2.5.4.10");
        Add(f["OU"], "2.5.4.11");
        if (cn != "") Add(new List<string> { cn }, "2.5.4.3");
        if (sn != "") Add(new List<string> { sn }, "2.5.4.5");
        var s = new StringBuilder();
        for (int i = 0; i < outRdns.Count; i++)
        {
            var rdn = outRdns[outRdns.Count - 1 - i];
            if (i > 0) s.Append(',');
            for (int j = 0; j < rdn.Count; j++)
            {
                var tv = rdn[j];
                if (j > 0) s.Append('+');
                if (!AttrNames.TryGetValue(tv.Oid, out var typeName))
                {
                    // Go: asn1.Marshal(tv.Value) — string бол дахин кодлоно, бусад — түүхий TLV.
                    var der = tv.Str is not null ? MarshalString(tv.Str) : tv.Raw;
                    s.Append(tv.Oid).Append("=#").Append(Asn1.Hex(der));
                    continue;
                }
                var v = tv.Str ?? "";
                int byteIdx = 0;
                int lastByte = Encoding.UTF8.GetByteCount(v) - 1;
                s.Append(typeName).Append('=');
                for (int k = 0; k < v.Length; k++)
                {
                    string c = char.IsHighSurrogate(v[k]) && k + 1 < v.Length && char.IsLowSurrogate(v[k + 1]) ? v.Substring(k, 2) : v.Substring(k, 1);
                    bool e = false;
                    if (c.Length == 1 && ",+\"\\<>;".IndexOf(c[0]) >= 0) e = true;
                    else if (c == " ") e = byteIdx == 0 || byteIdx == lastByte;
                    else if (c == "#") e = byteIdx == 0;
                    if (e) s.Append('\\');
                    s.Append(c);
                    byteIdx += Encoding.UTF8.GetByteCount(c);
                    k += c.Length - 1;
                }
            }
        }
        return s.ToString();
    }

    /// <summary>Go pkix.Name.CommonName (сүүлийн string CN).</summary>
    public static string CommonName(ReadOnlyMemory<byte> rawName) => Last(rawName, "2.5.4.3");

    /// <summary>Go pkix.Name.SerialNumber (сүүлийн string SERIALNUMBER).</summary>
    public static string SubjectSerialNumber(ReadOnlyMemory<byte> rawSubject) => Last(rawSubject, "2.5.4.5");

    private static string Last(ReadOnlyMemory<byte> rawName, string oid)
    {
        string v = "";
        foreach (var rdn in Rdns(rawName))
            foreach (var a in rdn)
                if (a.Oid == oid && a.Str is not null) v = a.Str;
        return v;
    }

    /// <summary>eidcrypto.SubjectNames: GIVENNAME (2.5.4.42) ба SURNAME (2.5.4.4) — сүүлийнх; string биш бол "".</summary>
    public static (string Given, string Surname) SubjectNames(ReadOnlyMemory<byte> rawSubject)
    {
        string given = "", surname = "";
        foreach (var rdn in Rdns(rawSubject))
        {
            foreach (var a in rdn)
            {
                if (a.Oid == "2.5.4.42") given = a.Str ?? "";
                if (a.Oid == "2.5.4.4") surname = a.Str ?? "";
            }
        }
        return (given, surname);
    }
}
