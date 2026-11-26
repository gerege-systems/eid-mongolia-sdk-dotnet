using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Validation;

// ValidatePdf-ийн хамгийн бага DER уншигч — TS SDK src/pades/asn1.ts-ийн порт (нэг байт tag, тодорхой урт ≤ 4 байт,
// minimal урт). Халдагчийн өгөгдлөөс уншина: урт бүрийг буферийн хязгаараар шалгана, рекурс үгүй (children нь нэг давхарга).

/// <summary>DER задлалтын алдаа.</summary>
internal sealed class Asn1Exception : Exception
{
    public Asn1Exception(string message) : base(message) { }
}

/// <summary>Нэг TLV: <see cref="Raw"/> — бүтэн TLV, <see cref="Value"/> — агуулга.</summary>
internal sealed class Asn1Node
{
    public Asn1Node(int tag, ReadOnlyMemory<byte> raw, ReadOnlyMemory<byte> value)
    {
        Tag = tag;
        Raw = raw;
        Value = value;
    }

    public int Tag { get; }
    public ReadOnlyMemory<byte> Raw { get; }
    public ReadOnlyMemory<byte> Value { get; }
}

internal static class Asn1
{
    public const int Boolean = 0x01;
    public const int Integer = 0x02;
    public const int BitString = 0x03;
    public const int OctetString = 0x04;
    public const int Oid = 0x06;
    public const int Enumerated = 0x0a;
    public const int Utf8String = 0x0c;
    public const int Sequence = 0x30;
    public const int Set = 0x31;
    public const int PrintableString = 0x13;
    public const int Ia5String = 0x16;
    public const int UtcTime = 0x17;
    public const int GeneralizedTime = 0x18;

    /// <summary>TS readNode: <paramref name="b"/>[off:]-аас нэг TLV.</summary>
    public static Asn1Node ReadNode(ReadOnlyMemory<byte> b, int off = 0)
    {
        var s = b.Span;
        if (off < 0 || (long)off + 2 > s.Length) throw new Asn1Exception("asn1: truncated");
        int tag = s[off];
        if ((tag & 0x1f) == 0x1f) throw new Asn1Exception("asn1: multi-byte tag");
        long len = s[off + 1];
        long p = off + 2;
        if ((len & 0x80) != 0)
        {
            int n = (int)(len & 0x7f);
            if (n == 0 || n > 4) throw new Asn1Exception("asn1: bad length");
            if (p + n > s.Length) throw new Asn1Exception("asn1: truncated");
            if (s[(int)p] == 0) throw new Asn1Exception("asn1: non-minimal length");
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + s[(int)p + i];
            if (len < 0x80) throw new Asn1Exception("asn1: non-minimal length");
            p += n;
        }
        if (p + len > s.Length) throw new Asn1Exception("asn1: truncated");
        return new Asn1Node(tag, b.Slice(off, (int)(p + len - off)), b.Slice((int)p, (int)len));
    }

    /// <summary>Ганц TLV, үлдэгдэлгүй.</summary>
    public static Asn1Node ParseOne(ReadOnlyMemory<byte> b)
    {
        var n = ReadNode(b, 0);
        if (n.Raw.Length != b.Length) throw new Asn1Exception("asn1: trailing data");
        return n;
    }

    /// <summary>Constructed утгын хүүхдүүд (нэг давхарга).</summary>
    public static List<Asn1Node> Children(Asn1Node n) => Children(n.Value);

    public static List<Asn1Node> Children(ReadOnlyMemory<byte> v)
    {
        var o = new List<Asn1Node>();
        for (int p = 0; p < v.Length;)
        {
            var c = ReadNode(v, p);
            o.Add(c);
            p += c.Raw.Length;
        }
        return o;
    }

    /// <summary>TS expect: n байгаа бөгөөд tag таарна.</summary>
    public static Asn1Node Expect(Asn1Node? n, int tag, string what)
    {
        if (n is null || n.Tag != tag) throw new Asn1Exception("asn1: expected " + what);
        return n;
    }

    /// <summary>Жагсаалтын i дэх элемент эсвэл null (TS <c>f[i]</c>).</summary>
    public static Asn1Node? At(List<Asn1Node> l, int i) => i >= 0 && i < l.Count ? l[i] : null;

    /// <summary>OID агуулга → "1.2.3" (TS oidString).</summary>
    public static string OidString(ReadOnlySpan<byte> v)
    {
        var parts = new List<BigInteger>();
        BigInteger cur = BigInteger.Zero;
        foreach (var b in v)
        {
            cur = (cur << 7) | (b & 0x7f);
            if ((b & 0x80) == 0)
            {
                parts.Add(cur);
                cur = BigInteger.Zero;
            }
        }
        if (parts.Count == 0) return "";
        var first = parts[0];
        BigInteger a = first < 40 ? 0 : first < 80 ? 1 : 2;
        var sb = new StringBuilder();
        sb.Append(a.ToString(CultureInfo.InvariantCulture)).Append('.').Append((first - a * 40).ToString(CultureInfo.InvariantCulture));
        for (int i = 1; i < parts.Count; i++) sb.Append('.').Append(parts[i].ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    public static string OidString(Asn1Node n) => OidString(n.Value.Span);

    /// <summary>INTEGER агуулга (two's complement) → тоо; хоосон бол алдаа (TS intValue).</summary>
    public static BigInteger IntValue(ReadOnlySpan<byte> v)
    {
        if (v.Length == 0) throw new Asn1Exception("asn1: empty INTEGER");
        return new BigInteger(v, isUnsigned: false, isBigEndian: true);
    }

    /// <summary>OID "1.2.3" → DER TLV (TS oid / extract oidBytes).</summary>
    public static byte[] OidTlv(string s)
    {
        var parts = s.Split('.');
        var body = new List<byte>();
        void Enc(BigInteger v)
        {
            var tmp = new List<byte> { (byte)(int)(v & 0x7f) };
            for (v >>= 7; v > 0; v >>= 7) tmp.Insert(0, (byte)((int)(v & 0x7f) | 0x80));
            body.AddRange(tmp);
        }
        Enc(BigInteger.Parse(parts[0], CultureInfo.InvariantCulture) * 40 + BigInteger.Parse(parts[1], CultureInfo.InvariantCulture));
        for (int i = 2; i < parts.Length; i++) Enc(BigInteger.Parse(parts[i], CultureInfo.InvariantCulture));
        return Tlv(Oid, body.ToArray());
    }

    public static byte[] Tlv(int tag, params byte[][] content)
    {
        int len = 0;
        foreach (var c in content) len += c.Length;
        var o = new List<byte>(len + 6) { (byte)tag };
        if (len < 0x80)
        {
            o.Add((byte)len);
        }
        else
        {
            var lb = new List<byte>();
            for (int x = len; x > 0; x >>= 8) lb.Insert(0, (byte)(x & 0xff));
            o.Add((byte)(0x80 | lb.Count));
            o.AddRange(lb);
        }
        foreach (var c in content) o.AddRange(c);
        return o.ToArray();
    }

    /// <summary>
    /// UTCTime/GeneralizedTime (TS parseTime + parsePreciseTime): JS Date.UTC-ийн мс (огнооны хэтрэлт дараагийн сар/он руу
    /// шилжинэ, 0–99 он → 1900+) ба секундын бутархай наносекундээр.
    /// </summary>
    public static PreciseTime ParsePreciseTime(Asn1Node n)
    {
        var s = Encoding.Latin1.GetString(n.Value.Span);
        int y, i;
        string mo, d, h, mi, sec, frac = "", z;
        if (n.Tag == UtcTime)
        {
            // ^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$
            if (!Digits(s, 0, 10)) throw new Asn1Exception("asn1: bad UTCTime");
            y = Num(s, 0, 2);
            y += y < 50 ? 2000 : 1900;
            mo = s.Substring(2, 2);
            d = s.Substring(4, 2);
            h = s.Substring(6, 2);
            mi = s.Substring(8, 2);
            i = 10;
            sec = "00";
            if (Digits(s, 10, 2))
            {
                sec = s.Substring(10, 2);
                i = 12;
            }
            z = s.Substring(i);
        }
        else if (n.Tag == GeneralizedTime)
        {
            // ^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?(Z|[+-]\d{4})$
            if (!Digits(s, 0, 14)) throw new Asn1Exception("asn1: bad GeneralizedTime");
            y = Num(s, 0, 4);
            mo = s.Substring(4, 2);
            d = s.Substring(6, 2);
            h = s.Substring(8, 2);
            mi = s.Substring(10, 2);
            sec = s.Substring(12, 2);
            i = 14;
            if (i < s.Length && s[i] == '.')
            {
                int j = i + 1;
                while (j < s.Length && s[j] >= '0' && s[j] <= '9') j++;
                if (j == i + 1) throw new Asn1Exception("asn1: bad GeneralizedTime");
                frac = s.Substring(i, j - i);
                i = j;
            }
            z = s.Substring(i);
        }
        else
        {
            throw new Asn1Exception("asn1: expected time");
        }
        if (!(z == "Z" || z.Length == 5 && (z[0] == '+' || z[0] == '-') && Digits(z, 1, 4))) throw new Asn1Exception("asn1: bad time zone");
        long ms = DateUtc(y, int.Parse(mo, CultureInfo.InvariantCulture) - 1, int.Parse(d, CultureInfo.InvariantCulture),
            int.Parse(h, CultureInfo.InvariantCulture), int.Parse(mi, CultureInfo.InvariantCulture), int.Parse(sec, CultureInfo.InvariantCulture));
        if (frac != "")
        {
            // Math.floor(Number("0" + frac) * 1000)
            ms += (long)Math.Floor(double.Parse("0" + frac, CultureInfo.InvariantCulture) * 1000);
        }
        if (z != "Z")
        {
            long off = (Num(z, 1, 2) * 60L + Num(z, 3, 2)) * 60_000L;
            ms += z[0] == '+' ? -off : off;
        }
        int nanos = 0;
        if (frac != "") nanos = int.Parse((frac.Substring(1) + "000000000").Substring(0, 9), CultureInfo.InvariantCulture);
        return new PreciseTime(ms, nanos);
    }

    private static bool Digits(string s, int at, int n)
    {
        if (at + n > s.Length) return false;
        for (int k = at; k < at + n; k++)
            if (s[k] < '0' || s[k] > '9') return false;
        return true;
    }

    private static int Num(string s, int at, int n) => int.Parse(s.AsSpan(at, n), NumberStyles.None, CultureInfo.InvariantCulture);

    /// <summary>JS Date.UTC(y, mo, d, h, mi, s) (mo 0-ээс; хэтрэлтийг шилжүүлнэ; 0 ≤ y ≤ 99 → 1900 + y).</summary>
    private static long DateUtc(int y, int mo, int d, int h, int mi, int s)
    {
        if (y >= 0 && y <= 99) y += 1900;
        int q = (int)Math.Floor(mo / 12.0);
        y += q;
        mo -= q * 12;
        long days = DaysFromCivil(y, mo + 1, 1) + (d - 1);
        return ((days * 24 + h) * 60 + mi) * 60_000L + s * 1000L;
    }

    /// <summary>Unix эпохоос хойших өдөр (proleptic Gregorian).</summary>
    private static long DaysFromCivil(long y, int m, int d)
    {
        y -= m <= 2 ? 1 : 0;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    /// <summary>TS digest: SHA-1/256/384/512.</summary>
    public static byte[] Digest(string hash, ReadOnlySpan<byte> b) => hash switch
    {
        "SHA-1" => SHA1.HashData(b),
        "SHA-256" => SHA256.HashData(b),
        "SHA-384" => SHA384.HashData(b),
        "SHA-512" => SHA512.HashData(b),
        _ => throw new ArgumentException("hash " + hash),
    };

    public static bool Equal(ReadOnlyMemory<byte> a, ReadOnlyMemory<byte> b) => a.Span.SequenceEqual(b.Span);

    public static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}

/// <summary>TS PreciseTime: JS Date-ийн мс (бутархайн мс-ийг оруулаад) ба секундын бутархай наносекундээр.</summary>
internal readonly record struct PreciseTime(long UnixMs, int Nanos);
