using System;
using System.Collections.Generic;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

internal enum PdfKind
{
    Null,
    Bool,
    Integer,
    Real,
    String,
    Name,
    Dict,
    Array,
    Stream,
}

/// <summary>Go pdf.Value: (уншигч, эзэн объектын заагч, өгөгдөл). Kind таарахгүй бол тэг утга буцаана.</summary>
internal readonly struct PdfValue
{
    private readonly PdfDocument? _r;
    private readonly object? _data;

    public PdfValue(PdfDocument r, ObjPtr ptr, object? data)
    {
        _r = r;
        Ptr = ptr;
        _data = data;
    }

    public ObjPtr Ptr { get; }

    public object? Data => _data;

    public bool IsNull => _data is null;

    public PdfKind Kind => _data switch
    {
        bool => PdfKind.Bool,
        long => PdfKind.Integer,
        double => PdfKind.Real,
        PdfString => PdfKind.String,
        PdfName => PdfKind.Name,
        PdfDict => PdfKind.Dict,
        PdfArray => PdfKind.Array,
        PdfStream => PdfKind.Stream,
        _ => PdfKind.Null,
    };

    public bool Bool => _data is bool b && b;

    public long Int64 => _data is long l ? l : 0;

    public double Float64 => _data switch
    {
        double d => d,
        long l => l,
        _ => 0,
    };

    /// <summary>Түүхий байт (Latin-1).</summary>
    public string RawString => _data is PdfString s ? s.Raw : "";

    public string Name => _data is PdfName n ? n.Value : "";

    /// <summary>PDF text string → .NET string (PDFDocEncoding эсвэл UTF-16BE BOM).</summary>
    public string Text => _data is PdfString s ? PdfText.Decode(s.Raw) : "";

    private PdfDict? Dict => _data switch
    {
        PdfDict d => d,
        PdfStream s => s.Header,
        _ => null,
    };

    public PdfValue Key(string key)
    {
        var d = Dict;
        if (d is null || _r is null) return default;
        return _r.Resolve(Ptr, d.GetValueOrDefault(key));
    }

    /// <summary>Түлхүүрүүд байтаар эрэмбэлсэн (Go sort.Strings). Толь/stream биш бол хоосон.</summary>
    public IReadOnlyList<string> Keys()
    {
        var d = Dict;
        if (d is null) return Array.Empty<string>();
        var keys = new List<string>(d.Keys);
        keys.Sort(StringComparer.Ordinal);
        return keys;
    }

    public int Len => _data is PdfArray a ? a.Count : 0;

    public PdfValue Index(int i)
    {
        if (_data is not PdfArray a || i < 0 || i >= a.Count || _r is null) return default;
        return _r.Resolve(Ptr, a[i]);
    }

    /// <summary>Stream-ийн тайлсан агуулга; stream биш бол алдаа.</summary>
    public byte[] StreamBytes()
    {
        if (_data is not PdfStream s || _r is null) throw new PdfFormatException("stream not present");
        return _r.StreamBytes(this, s);
    }

    /// <summary>Stream-ийн тайлаагүй (шүүлтүүрийн өмнөх) /Length байт; stream биш бол алдаа.</summary>
    public ReadOnlySpan<byte> RawStreamBytes()
    {
        if (_data is not PdfStream s || _r is null) throw new PdfFormatException("stream not present");
        return _r.RawStreamBytes(this, s);
    }
}

internal static class PdfText
{
    private const char NoRune = '�';

    public static string Decode(string x)
    {
        if (IsPdfDocEncoded(x)) return PdfDocDecode(x);
        if (IsUtf16(x)) return Utf16Decode(x, 2);
        return x;
    }

    private static bool IsUtf16(string s) => s.Length >= 2 && s[0] == 0xfe && s[1] == 0xff && s.Length % 2 == 0;

    private static bool IsPdfDocEncoded(string s)
    {
        if (IsUtf16(s)) return false;
        foreach (var c in s)
            if (PdfDocEncoding[c & 0xff] == NoRune) return false;
        return true;
    }

    private static string PdfDocDecode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(PdfDocEncoding[c & 0xff]);
        return sb.ToString();
    }

    private static string Utf16Decode(string s, int start)
    {
        var sb = new StringBuilder();
        for (int i = start; i + 1 < s.Length; i += 2) sb.Append((char)((s[i] & 0xff) << 8 | (s[i + 1] & 0xff)));
        // Go utf16.Decode: ганц surrogate → U+FFFD.
        var r = sb.ToString();
        var o = new StringBuilder(r.Length);
        for (int i = 0; i < r.Length; i++)
        {
            char c = r[i];
            if (char.IsHighSurrogate(c) && i + 1 < r.Length && char.IsLowSurrogate(r[i + 1]))
            {
                o.Append(c).Append(r[++i]);
            }
            else if (char.IsSurrogate(c))
            {
                o.Append(NoRune);
            }
            else
            {
                o.Append(c);
            }
        }
        return o.ToString();
    }

    // PDF 32000-1:2008, Table D.2 (Go text.go pdfDocEncoding).
    private static readonly char[] PdfDocEncoding = BuildTable();

    private static char[] BuildTable()
    {
        var t = new char[256];
        for (int i = 0; i < 256; i++) t[i] = (char)i;
        for (int i = 0; i < 0x18; i++) t[i] = NoRune;
        t[0x09] = '\t';
        t[0x0a] = '\n';
        t[0x0d] = '\r';
        ushort[] x18 = { 0x02d8, 0x02c7, 0x02c6, 0x02d9, 0x02dd, 0x02db, 0x02da, 0x02dc };
        for (int i = 0; i < 8; i++) t[0x18 + i] = (char)x18[i];
        t[0x7f] = NoRune;
        ushort[] x80 =
        {
            0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044,
            0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c, 0x201d, 0x2018,
            0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x0141, 0x0152, 0x0160,
            0x0178, 0x017d, 0x0131, 0x0142, 0x0153, 0x0161, 0x017e, 0xfffd,
            0x20ac,
        };
        for (int i = 0; i < x80.Length; i++) t[0x80 + i] = (char)x80[i];
        t[0xad] = NoRune;
        return t;
    }
}
