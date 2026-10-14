using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

internal static class ByteWriter
{
    public static void Ascii(this MemoryStream w, string s)
    {
        foreach (var c in s)
        {
            if (c > 0xff) throw new InvalidOperationException("non-Latin-1 character in PDF output");
            w.WriteByte((byte)c);
        }
    }
}

/// <summary>Go reference core/serialize.go: container объект доторх ШУУД утгыг дахин бичнэ, өөр объект руу заасныг "N G R".</summary>
internal static class Serializer
{
    private const int MaxDepth = 32;

    public static void Serialize(MemoryStream w, PdfValue v, uint container, int depth)
    {
        if (depth > MaxDepth) throw new PdfFormatException("pades: value nested too deeply");
        if (v.IsNull)
        {
            w.Ascii("null");
            return;
        }
        if (v.Ptr.Id != container)
        {
            w.Ascii(v.Ptr.Id.ToString(CultureInfo.InvariantCulture) + " " + v.Ptr.Gen.ToString(CultureInfo.InvariantCulture) + " R");
            return;
        }
        switch (v.Kind)
        {
            case PdfKind.String:
                w.Ascii(HexString(v.RawString));
                break;
            case PdfKind.Bool:
                w.Ascii(v.Bool ? "true" : "false");
                break;
            case PdfKind.Integer:
                w.Ascii(v.Int64.ToString(CultureInfo.InvariantCulture));
                break;
            case PdfKind.Real:
                w.Ascii(FormatReal(v.Float64));
                break;
            case PdfKind.Name:
                w.Ascii("/" + EscapeName(v.Name));
                break;
            case PdfKind.Dict:
                w.Ascii("<<");
                foreach (var key in v.Keys())
                {
                    w.Ascii(" /" + EscapeName(key) + " ");
                    Serialize(w, v.Key(key), container, depth + 1);
                }
                w.Ascii(" >>");
                break;
            case PdfKind.Array:
                w.Ascii("[");
                for (int i = 0; i < v.Len; i++)
                {
                    if (i > 0) w.Ascii(" ");
                    Serialize(w, v.Index(i), container, depth + 1);
                }
                w.Ascii("]");
                break;
            default:
                throw new PdfFormatException("pades: cannot copy a direct stream (or unknown value)");
        }
    }

    public static string SerializeToString(PdfValue v, uint container)
    {
        using var ms = new MemoryStream();
        Serialize(ms, v, container, 0);
        return Latin1.FromBytes(ms.ToArray());
    }

    /// <summary>PDF hex string — байтыг яг хэвээр, жижиг үсгээр.</summary>
    public static string HexString(string raw) => "<" + Convert.ToHexString(Latin1.ToBytes(raw)).ToLowerInvariant() + ">";

    public static string HexString(byte[] raw) => "<" + Convert.ToHexString(raw).ToLowerInvariant() + ">";

    /// <summary>Name-ийн regular-биш тэмдэгтийг #XX (ISO 32000-1 §7.3.5).</summary>
    public static string EscapeName(string n)
    {
        var b = new StringBuilder(n.Length);
        foreach (var ch in n)
        {
            int c = ch & 0xff;
            if (c < 0x21 || c > 0x7e || "#()<>[]{}/%".IndexOf((char)c) >= 0)
            {
                b.Append('#').Append(c.ToString("X2", CultureInfo.InvariantCulture));
                continue;
            }
            b.Append((char)c);
        }
        return b.ToString();
    }

    /// <summary>Go strconv.FormatFloat(f, 'f', -1, 64): round-trip хамгийн богино цифр, exponent-гүй.</summary>
    public static string FormatReal(double f)
    {
        if (double.IsNaN(f)) return "NaN";
        if (double.IsPositiveInfinity(f)) return "+Inf";
        if (double.IsNegativeInfinity(f)) return "-Inf";
        var r = f.ToString("R", CultureInfo.InvariantCulture);
        int e = r.IndexOfAny(new[] { 'E', 'e' });
        if (e < 0) return r;
        string mant = r[..e];
        int exp = int.Parse(r[(e + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        bool neg = mant.StartsWith('-');
        if (neg) mant = mant[1..];
        int dot = mant.IndexOf('.');
        string digits = dot < 0 ? mant : mant.Remove(dot, 1);
        int intLen = (dot < 0 ? mant.Length : dot) + exp;
        string res;
        if (intLen <= 0) res = "0." + new string('0', -intLen) + digits;
        else if (intLen >= digits.Length) res = digits + new string('0', intLen - digits.Length);
        else res = digits[..intLen] + "." + digits[intLen..];
        return neg ? "-" + res : res;
    }
}
