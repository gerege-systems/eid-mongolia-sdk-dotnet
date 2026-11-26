using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades.Validation;

// Revision-ийн шинжилгээнд (Revisions.cs) зориулсан ХАТУУ PDF задлагч — TS SDK src/pades/validate/pdfobj.ts (Go SDK
// pades/internal/validate/pdfobj.go — CA-ийн нийтийн шалгагчийн код)-ийн 1:1 порт. Зөвшөөрөгч биш, татгалзагч: ойлгоогүй зүйл
// бүр (давхар түлхүүр, танихгүй filter, хэт гүн бүтэц, /Encrypt, hybrid xref) алдаа болж, дуудагч нь «гарын үсгийн дараа
// өөрчлөгдсөн» гэж үзнэ (fail closed). Рекурс MaxDepth-ээр, нийт ажил PdfBudget-ээр (зангилаа, inflate) хязгаарлагдана.
//
// Утгын төрөл (Go ↔ C#): nil → null, bool → bool, int64 → long, float64 → PReal, pdfName → PName, pdfStr → PStr (latin1
// мөр), pdfRef → PRef, pdfArr → List&lt;object?&gt;, pdfDict → Dictionary&lt;string, object?&gt; (null утгагүй), pdfStream → PStream.

/// <summary>Go errPDFSyntax / errPDFLimit / errNotSignatureOnly — бүгд «зөвшөөрөгдөөгүй».</summary>
internal sealed class PdfObjException : Exception
{
    public PdfObjException(string message) : base(message) { }

    public static PdfObjException Syntax() => new("validate: PDF syntax not recognised");

    public static PdfObjException Limit() => new("validate: PDF analysis limit exceeded");
}

/// <summary>Go runtime panic (харьцуулагдахгүй төрлийг == харьцуулсан) — дуудагч recover хийнэ (кэшлэхгүй).</summary>
internal sealed class GoPanicException : Exception
{
    public GoPanicException(string message) : base(message) { }
}

internal sealed record PRef(int Num, int Gen);

internal sealed record PName(string V);

internal sealed record PStr(string V);

internal sealed record PReal(double V);

internal sealed class PStream
{
    public PStream(Dictionary<string, object?> dict, ReadOnlyMemory<byte> data)
    {
        Dict = dict;
        Data = data;
    }

    public Dictionary<string, object?> Dict { get; }
    public ReadOnlyMemory<byte> Data { get; }
}

internal sealed class ObjStm
{
    public byte[] Data { get; init; } = Array.Empty<byte>();
    public List<int> Nums { get; } = new();
    public List<int> Offs { get; } = new();
    public int First { get; init; }
}

internal sealed class CachedObj
{
    public int Num;
    public int Gen;
    public object? Val;
    public int End;
}

internal readonly record struct XrefEnt(int Kind, long Off, long Gen, long Idx);

internal sealed class XrefSection
{
    public long Off;
    public int Start;
    public int End;
    public Dictionary<string, object?> Trailer = new(StringComparer.Ordinal);
    public Dictionary<int, XrefEnt> Ents = new();
}

/// <summary>Нэг баримтын бүх харагдацад хуваалцах нөөц ба задлалтын кэш.</summary>
internal sealed class PdfBudget
{
    public const int MaxNodes = 1_000_000;
    public const int MaxInflate = 64 << 20;

    public int Nodes = MaxNodes;

    /// <summary>Дуудагчийн цуцлалт — Node() бүр 4096 зангилаа тутамд шалгана (хязгаартай ч урт ажлыг тасална).</summary>
    public System.Threading.CancellationToken Ct;
    public long Inflate = MaxInflate;
    public readonly Dictionary<(long Off, long Idx), CachedObj> Objs = new();
    public readonly Dictionary<long, ObjStm> Stms = new();

    public void Node()
    {
        if (--Nodes < 0) throw PdfObjException.Limit();
        if ((Nodes & 0xfff) == 0) Ct.ThrowIfCancellationRequested();
    }

    /// <summary>xref/object stream-ийн агуулга: filter-гүй эсвэл ганц FlateDecode (+ PNG predictor).</summary>
    public byte[] Decode(PStream s)
    {
        static object? Single(object? v)
        {
            if (v is not List<object?> a) return v;
            if (a.Count == 0) return null;
            if (a.Count == 1) return a[0];
            throw PdfObjException.Syntax();
        }
        var filter = Single(P.Get(s.Dict, "Filter"));
        if (filter is null) return s.Data.ToArray();
        if (!P.IfaceEq(filter, new PName("FlateDecode"))) throw PdfObjException.Syntax();
        var o = ZlibStrictLimited(s.Data.Span, Inflate);
        Inflate -= o.Length;
        if (Inflate < 0) throw PdfObjException.Limit();
        var parms = Single(P.Get(s.Dict, "DecodeParms"));
        if (parms is null) return o;
        if (parms is not Dictionary<string, object?> pd) throw PdfObjException.Syntax();
        long IntOr(string key, long def)
        {
            var v = P.Get(pd, key);
            if (v is null) return def;
            if (v is long l) return l;
            return -1;
        }
        long pred = IntOr("Predictor", 1);
        long cols = IntOr("Columns", 1);
        if (pred == 1) return o;
        if (pred < 10 || pred > 15 || cols < 1 || cols > 1L << 16 || IntOr("Colors", 1) != 1 || IntOr("BitsPerComponent", 8) != 8) throw PdfObjException.Syntax();
        return UnPng(o, (int)cols);
    }

    /// <summary>Go compress/zlib (+ LimitReader): header (FDICT хориотой), бүрэн deflate, adler32; хэтэрвэл limit.</summary>
    private static byte[] ZlibStrictLimited(ReadOnlySpan<byte> src, long limit)
    {
        if (src.Length < 2) throw PdfObjException.Syntax();
        int cmf = src[0], flg = src[1];
        if ((cmf & 0x0f) != 8 || cmf >> 4 > 7 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20) != 0) throw PdfObjException.Syntax();
        if (limit < 0) throw PdfObjException.Limit();
        int max = (int)Math.Min(limit, MaxInflate);
        // ZlibStrict: null = буруу эсвэл max-аас их — аль аль нь дуудагчид «зөвшөөрөгдөөгүй».
        return ZlibStrict.Decode(src, max) ?? throw PdfObjException.Syntax();
    }

    /// <summary>PNG мөрийн predictor-ийг буцаана (нэг байт = нэг пиксел).</summary>
    private static byte[] UnPng(byte[] input, int cols)
    {
        if (input.Length % (cols + 1) != 0) throw PdfObjException.Syntax();
        int rows = input.Length / (cols + 1);
        var o = new byte[rows * cols];
        var prev = new byte[cols];
        for (int r = 0; r < rows; r++)
        {
            int bas = r * (cols + 1);
            int ft = input[bas];
            var cur = new byte[cols];
            for (int i = 0; i < cols; i++)
            {
                int x = input[bas + 1 + i];
                int left = 0, upLeft = 0;
                if (i > 0)
                {
                    left = cur[i - 1];
                    upLeft = prev[i - 1];
                }
                int up = prev[i];
                switch (ft)
                {
                    case 0:
                        break;
                    case 1:
                        x = (x + left) & 0xff;
                        break;
                    case 2:
                        x = (x + up) & 0xff;
                        break;
                    case 3:
                        x = (x + ((left & up) + ((left ^ up) >> 1))) & 0xff;
                        break;
                    case 4:
                        {
                            int pa = Math.Abs(up - upLeft);
                            int pb = Math.Abs(left - upLeft);
                            int pc = Math.Abs(left + up - 2 * upLeft);
                            if (pa <= pb && pa <= pc) x = (x + left) & 0xff;
                            else if (pb <= pc) x = (x + up) & 0xff;
                            else x = (x + upLeft) & 0xff;
                            break;
                        }
                    default:
                        throw PdfObjException.Syntax();
                }
                cur[i] = (byte)x;
            }
            Array.Copy(cur, 0, o, r * cols, cols);
            prev = cur;
        }
        return o;
    }
}

/// <summary>Утгын туслахууд (TS isDict/dget/ifaceEq/pdfEqual/pdfRefs).</summary>
internal static class P
{
    public const int MaxDepth = 64;
    public const int MaxObjectNumber = 1 << 23;
    public const int EntFree = 1;
    public const int EntUse = 2;
    public const int EntComp = 3;
    public static readonly XrefEnt ZeroEnt = new(0, 0, 0, 0);

    /// <summary>Go <c>d[k]</c> — байхгүй бол null.</summary>
    public static object? Get(Dictionary<string, object?>? d, string k) => d is not null && d.TryGetValue(k, out var v) ? v : null;

    public static bool IsName(object? v, string s) => v is PName n && n.V == s;

    public static bool InUse(XrefEnt e) => e.Kind == EntUse || e.Kind == EntComp;

    public static XrefEnt Ent(Dictionary<int, XrefEnt> m, long n) => n >= int.MinValue && n <= int.MaxValue && m.TryGetValue((int)n, out var e) ? e : ZeroEnt;

    private static string KindOf(object v) => v switch
    {
        bool => "bool",
        long => "int",
        PReal => "real",
        PName => "name",
        PStr => "str",
        PRef => "ref",
        List<object?> => "arr",
        Dictionary<string, object?> => "dict",
        _ => "stream",
    };

    /// <summary>Go interface-ийн ==: төрөл өөр бол false; харьцуулагдахгүй (slice, map, stream) бол panic.</summary>
    public static bool IfaceEq(object? a, object? b)
    {
        if (a is null || b is null) return a is null && b is null;
        var ta = KindOf(a);
        if (ta != KindOf(b)) return false;
        switch (ta)
        {
            case "bool": return (bool)a == (bool)b;
            case "int": return (long)a == (long)b;
            case "real": return ((PReal)a).V == ((PReal)b).V;
            case "name": return ((PName)a).V == ((PName)b).V;
            case "str": return ((PStr)a).V == ((PStr)b).V;
            case "ref": return ((PRef)a).Num == ((PRef)b).Num && ((PRef)a).Gen == ((PRef)b).Gen;
        }
        throw new GoPanicException("comparing uncomparable type");
    }

    /// <summary>Бүтцийн тэнцүү байдал: ref-ийг дагахгүй, stream-ийг толь + түүхий байтаар; тоо төрлөөрөө (90 ≠ 90.0).</summary>
    public static bool PdfEqual(object? a, object? b)
    {
        if (a is null) return b is null;
        if (a is List<object?> la)
        {
            if (b is not List<object?> lb || la.Count != lb.Count) return false;
            for (int i = 0; i < la.Count; i++)
                if (!PdfEqual(la[i], lb[i])) return false;
            return true;
        }
        if (a is Dictionary<string, object?> da)
        {
            if (b is not Dictionary<string, object?> db || da.Count != db.Count) return false;
            foreach (var kv in da)
                if (!db.TryGetValue(kv.Key, out var bv) || !PdfEqual(kv.Value, bv)) return false;
            return true;
        }
        if (a is PStream sa)
        {
            if (b is not PStream sb || !sa.Data.Span.SequenceEqual(sb.Data.Span)) return false;
            return PdfEqual(sa.Dict, sb.Dict);
        }
        if (b is null) return false;
        return IfaceEq(a, b);
    }

    /// <summary>Утга доторх бүх ref (шууд давхарлалтаар; ref-ийг дагахгүй).</summary>
    public static void Refs(object? v, Action<PRef> f)
    {
        switch (v)
        {
            case PRef r:
                f(r);
                break;
            case List<object?> a:
                foreach (var e in a) Refs(e, f);
                break;
            case Dictionary<string, object?> d:
                foreach (var e in d.Values) Refs(e, f);
                break;
            case PStream s:
                Refs(s.Dict, f);
                break;
        }
    }

    public static bool IsPdfSpace(int c) => c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;

    public static bool IsPdfDelim(int c) => c is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

    /// <summary>Объект, xref хэсгүүдийн ХООРОНД зөвшөөрөгдөх зай (NUL, тайлбар үгүй).</summary>
    public static bool IsGapSpace(int c) => c == 9 || c == 10 || c == 12 || c == 13 || c == 32;

    public static bool AllGapSpace(ReadOnlySpan<byte> b)
    {
        foreach (var c in b)
            if (!IsGapSpace(c)) return false;
        return true;
    }

    public static bool IsDigit(int c) => c >= '0' && c <= '9';

    public static bool IsHex(int c) => c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';

    public static int HexVal(int c) => c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;

    public static string Str(byte[] b, int s, int e)
    {
        var sb = new StringBuilder(Math.Max(0, e - s));
        for (int i = s; i < e; i++) sb.Append((char)b[i]);
        return sb.ToString();
    }
}

internal sealed class PdfParser
{
    public PdfParser(byte[] b, int len, int pos, PdfBudget budget, bool strict = false)
    {
        B = b;
        Len = len;
        Pos = pos;
        Budget = budget;
        Strict = strict;
    }

    public byte[] B { get; }
    public int Len { get; }
    public int Pos;
    public PdfBudget Budget { get; }
    public bool Strict;

    private int At(int i) => i >= 0 && i < Len ? B[i] : -1;

    public void SkipGap()
    {
        while (Pos < Len && P.IsGapSpace(B[Pos])) Pos++;
    }

    public void SkipSpace()
    {
        if (Strict)
        {
            SkipGap();
            return;
        }
        while (Pos < Len && P.IsPdfSpace(B[Pos])) Pos++;
    }

    /// <summary>Зай ба тайлбар; хатуу горимд зөвхөн IsGapSpace.</summary>
    public void Skip()
    {
        if (Strict)
        {
            SkipGap();
            return;
        }
        while (Pos < Len)
        {
            int c = B[Pos];
            if (P.IsPdfSpace(c))
            {
                Pos++;
            }
            else if (c == '%')
            {
                while (Pos < Len && B[Pos] != 10 && B[Pos] != 13) Pos++;
            }
            else
            {
                return;
            }
        }
    }

    public bool Keyword(string k)
    {
        int e = Pos + k.Length;
        if (e > Len) return false;
        for (int i = 0; i < k.Length; i++)
            if (B[Pos + i] != k[i]) return false;
        if (e < Len && !P.IsPdfSpace(B[e]) && !P.IsPdfDelim(B[e])) return false;
        Pos = e;
        return true;
    }

    /// <summary>Go uint(): ≤ 18 цифр.</summary>
    public long? Uint()
    {
        int s = Pos;
        while (Pos < Len && P.IsDigit(B[Pos])) Pos++;
        if (Pos == s || Pos - s > 18)
        {
            Pos = s;
            return null;
        }
        return long.Parse(P.Str(B, s, Pos), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    public object? Value(int depth)
    {
        if (depth > P.MaxDepth) throw PdfObjException.Syntax();
        Budget.Node();
        Skip();
        if (Pos >= Len) throw PdfObjException.Syntax();
        int c = B[Pos];
        if (c == '/')
        {
            Pos++;
            return Name();
        }
        if (c == '(')
        {
            Pos++;
            return Literal();
        }
        if (c == '[')
        {
            Pos++;
            var arr = new List<object?>();
            while (true)
            {
                Skip();
                if (Pos < Len && B[Pos] == ']')
                {
                    Pos++;
                    return arr;
                }
                arr.Add(Value(depth + 1));
            }
        }
        if (c == '<')
        {
            if (Pos + 1 < Len && B[Pos + 1] == '<')
            {
                Pos += 2;
                return Dict(depth);
            }
            Pos++;
            return Hex();
        }
        if (P.IsDigit(c) || c == '+' || c == '-' || c == '.') return Number();
        if (Keyword("true")) return true;
        if (Keyword("false")) return false;
        if (Keyword("null")) return null;
        throw PdfObjException.Syntax();
    }

    public Dictionary<string, object?> Dict(int depth)
    {
        var d = new Dictionary<string, object?>(StringComparer.Ordinal);
        while (true)
        {
            Skip();
            if (Pos + 1 < Len && B[Pos] == '>' && B[Pos + 1] == '>')
            {
                Pos += 2;
                var nulls = new List<string>();
                foreach (var kv in d)
                    if (kv.Value is null) nulls.Add(kv.Key);
                foreach (var k in nulls) d.Remove(k);
                return d;
            }
            if (Pos >= Len || B[Pos] != '/') throw PdfObjException.Syntax();
            Pos++;
            var key = Name().V;
            bool dup = d.TryGetValue(key, out var old);
            var v = Value(depth + 1);
            if (dup && !P.PdfEqual(old, v)) throw PdfObjException.Syntax();
            d[key] = v;
        }
    }

    public PName Name()
    {
        var sb = new StringBuilder();
        while (Pos < Len && !P.IsPdfSpace(B[Pos]) && !P.IsPdfDelim(B[Pos]))
        {
            int c = B[Pos];
            if (c == '#')
            {
                if (Pos + 2 >= Len) throw PdfObjException.Syntax();
                if (!P.IsHex(B[Pos + 1]) || !P.IsHex(B[Pos + 2])) throw PdfObjException.Syntax();
                c = P.HexVal(B[Pos + 1]) << 4 | P.HexVal(B[Pos + 2]);
                Pos += 2;
            }
            sb.Append((char)c);
            Pos++;
        }
        return new PName(sb.ToString());
    }

    public PStr Literal()
    {
        var sb = new StringBuilder();
        for (int depth = 1; ; Pos++)
        {
            if (Pos >= Len) throw PdfObjException.Syntax();
            int c = B[Pos];
            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                if (--depth == 0)
                {
                    Pos++;
                    return new PStr(sb.ToString());
                }
            }
            else if (c == 0x0d)
            {
                if (Pos + 1 < Len && B[Pos + 1] == 0x0a) Pos++;
                c = 0x0a;
            }
            else if (c == '\\')
            {
                if (++Pos >= Len) throw PdfObjException.Syntax();
                int e = B[Pos];
                if (e == 'n')
                {
                    c = 0x0a;
                }
                else if (e == 'r')
                {
                    c = 0x0d;
                }
                else if (e == 't')
                {
                    c = 0x09;
                }
                else if (e == 'b')
                {
                    c = 0x08;
                }
                else if (e == 'f')
                {
                    c = 0x0c;
                }
                else if (e == 0x0a)
                {
                    continue;
                }
                else if (e == 0x0d)
                {
                    if (Pos + 1 < Len && B[Pos + 1] == 0x0a) Pos++;
                    continue;
                }
                else if (e >= '0' && e <= '7')
                {
                    c = 0;
                    for (int i = 0; i < 3 && Pos < Len && B[Pos] >= '0' && B[Pos] <= '7'; i++)
                    {
                        c = ((c << 3) | (B[Pos] - '0')) & 0xff;
                        Pos++;
                    }
                    Pos--;
                }
                else
                {
                    c = e;
                }
            }
            sb.Append((char)c);
        }
    }

    public PStr Hex()
    {
        var digits = new StringBuilder();
        for (; ; Pos++)
        {
            if (Pos >= Len) throw PdfObjException.Syntax();
            int c = B[Pos];
            if (c == '>')
            {
                Pos++;
                break;
            }
            if (!P.IsPdfSpace(c)) digits.Append((char)c);
        }
        if (digits.Length % 2 == 1) digits.Append('0');
        var sb = new StringBuilder(digits.Length / 2);
        for (int i = 0; i < digits.Length; i += 2)
        {
            if (!P.IsHex(digits[i]) || !P.IsHex(digits[i + 1])) throw PdfObjException.Syntax();
            sb.Append((char)(P.HexVal(digits[i]) << 4 | P.HexVal(digits[i + 1])));
        }
        return new PStr(sb.ToString());
    }

    /// <summary>Бүхэл/бодит тоо, эсвэл «n g R» заалт.</summary>
    public object? Number()
    {
        int s = Pos;
        while (Pos < Len && (P.IsDigit(B[Pos]) || B[Pos] == '+' || B[Pos] == '-' || B[Pos] == '.')) Pos++;
        string tok = P.Str(B, s, Pos);
        if (Pos < Len && !P.IsPdfSpace(B[Pos]) && !P.IsPdfDelim(B[Pos])) throw PdfObjException.Syntax();
        if (tok.Contains('.'))
        {
            // ^[+-]?([0-9]+\.[0-9]*|\.[0-9]+)$
            int k = tok.Length > 0 && (tok[0] == '+' || tok[0] == '-') ? 1 : 0;
            int a = k;
            while (k < tok.Length && P.IsDigit(tok[k])) k++;
            int intDigits = k - a;
            if (k >= tok.Length || tok[k] != '.') throw PdfObjException.Syntax();
            k++;
            int b = k;
            while (k < tok.Length && P.IsDigit(tok[k])) k++;
            if (k != tok.Length || (intDigits == 0 && k == b)) throw PdfObjException.Syntax();
            var f = double.Parse(tok, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
            if (!double.IsFinite(f)) throw PdfObjException.Syntax();
            return new PReal(f);
        }
        // ^[+-]?[0-9]+$ ба int64 муж (урт цифрийг BigInteger-ээр задлахгүй: 19-өөс олон ач холбогдолтой цифр = мужаас гадна)
        int j = tok.Length > 0 && (tok[0] == '+' || tok[0] == '-') ? 1 : 0;
        if (j >= tok.Length) throw PdfObjException.Syntax();
        for (int i = j; i < tok.Length; i++)
            if (!P.IsDigit(tok[i])) throw PdfObjException.Syntax();
        int z = j;
        while (z < tok.Length - 1 && tok[z] == '0') z++;
        if (tok.Length - z > 19) throw PdfObjException.Syntax();
        if (!long.TryParse(tok.AsSpan(z), NumberStyles.None, CultureInfo.InvariantCulture, out var mag))
        {
            // 19 цифр: 9223372036854775808 (= −int64 min) л зөвшөөрөгдөнө
            if (tok[0] == '-' && tok.AsSpan(z).SequenceEqual("9223372036854775808")) return long.MinValue;
            throw PdfObjException.Syntax();
        }
        long n = tok[0] == '-' ? -mag : mag;
        if (n >= 0 && tok[0] != '+')
        {
            int save = Pos;
            Skip();
            var g = Uint();
            if (g is { } gv)
            {
                Skip();
                if (Keyword("R"))
                {
                    if (n >= P.MaxObjectNumber || gv > 65535) throw PdfObjException.Syntax();
                    return new PRef((int)n, (int)gv);
                }
            }
            Pos = save;
        }
        return n;
    }

    /// <summary>«n g obj … endobj». length — шууд бус /Length-ийг тухайн харагдацад задална (null бол алдаа).</summary>
    public CachedObj Indirect(Func<PRef, long>? length)
    {
        SkipSpace();
        var n = Uint();
        SkipSpace();
        var g = Uint();
        SkipSpace();
        if (n is not { } nv || g is not { } gv || nv >= P.MaxObjectNumber || gv > 65535 || !Keyword("obj")) throw PdfObjException.Syntax();
        var o = new CachedObj { Num = (int)nv, Gen = (int)gv };
        o.Val = Value(0);
        Skip();
        if (o.Val is Dictionary<string, object?> d && Keyword("stream"))
        {
            if (Pos < Len && B[Pos] == 0x0d) Pos++;
            if (Pos >= Len || B[Pos] != 0x0a) throw PdfObjException.Syntax();
            Pos++;
            long size;
            var l = P.Get(d, "Length");
            if (l is long li)
            {
                size = li;
            }
            else if (l is PRef lr)
            {
                if (length is null) throw PdfObjException.Syntax();
                size = length(lr);
            }
            else
            {
                throw PdfObjException.Syntax();
            }
            if (size < 0 || size > Len - Pos) throw PdfObjException.Syntax();
            int sz = (int)size;
            o.Val = new PStream(d, new ReadOnlyMemory<byte>(B, Pos, sz));
            Pos += sz;
            SkipSpace();
            if (!Keyword("endstream")) throw PdfObjException.Syntax();
            Skip();
        }
        if (!Keyword("endobj")) throw PdfObjException.Syntax();
        return o;
    }

    /// <summary>«startxref N %%EOF»; N.</summary>
    public long? Startxref()
    {
        SkipGap();
        if (!Keyword("startxref")) return null;
        SkipGap();
        var n = Uint();
        SkipGap();
        if (n is not { } nv || nv > Len || P.Str(B, Pos, Math.Min(Len, Pos + 5)) != "%%EOF") return null;
        Pos += 5;
        return nv;
    }

    public int Peek(int i) => At(i);
}

/// <summary>Баримтын нэг төлөв (эхний N байт) дахь xref гинж ба объектууд.</summary>
internal sealed class PdfView
{
    private const int MaxXrefSections = 128;

    public PdfView(byte[] b, int len, PdfBudget budget)
    {
        B = b;
        Len = len;
        Budget = budget;
    }

    public byte[] B { get; }
    public int Len { get; }
    public PdfBudget Budget { get; }
    public List<XrefSection> Sections { get; } = new();
    public Dictionary<int, XrefEnt> Xref { get; } = new();
    public Dictionary<string, object?> Trailer { get; private set; } = new(StringComparer.Ordinal);
    private readonly Dictionary<int, object?> _objs = new();
    private bool _inLength;
    private bool _usedLength;
    private Dictionary<int, List<int>>? _refs;

    /// <summary>b[i] эсвэл -1 (TS undefined).</summary>
    public int ByteAt(long i) => i >= 0 && i < Len ? B[i] : -1;

    public PdfParser Parser(int pos) => new(B, Len, pos, Budget);

    private static XrefEnt UseEnt(long off, long gen) => off == 0 ? new XrefEnt(P.EntFree, 0, 0, 0) : new XrefEnt(P.EntUse, off, gen, 0);

    public XrefSection Section(long off)
    {
        var p = Parser((int)off);
        p.SkipGap();
        var sec = new XrefSection { Off = off, Start = p.Pos };
        int c0 = p.Peek(p.Pos);
        if (p.Pos >= Len || (c0 != 'x' && !P.IsDigit(c0))) throw PdfObjException.Syntax();
        void Set(long num, XrefEnt e)
        {
            if (num >= P.MaxObjectNumber) throw PdfObjException.Syntax();
            if (sec.Ents.ContainsKey((int)num)) throw PdfObjException.Syntax();
            sec.Ents[(int)num] = e;
            Budget.Node();
        }
        if (p.Keyword("xref"))
        {
            while (true)
            {
                p.SkipSpace();
                if (p.Keyword("trailer")) break;
                var first = p.Uint();
                p.SkipSpace();
                var count = p.Uint();
                if (first is not { } fv || count is not { } cv || fv >= P.MaxObjectNumber || cv > P.MaxObjectNumber) throw PdfObjException.Syntax();
                p.SkipGap();
                for (long i = 0; i < cv; i++)
                {
                    if (p.Pos + 20 > Len) throw PdfObjException.Syntax();
                    string row = P.Str(B, p.Pos, p.Pos + 20);
                    string os = row.Substring(0, 10);
                    string gs = row.Substring(11, 5);
                    string eol = row.Substring(18);
                    if (!AllDigits(os) || !AllDigits(gs) || row[10] != ' ' || row[16] != ' ' || (eol != " \n" && eol != " \r" && eol != "\r\n"))
                        throw PdfObjException.Syntax();
                    long o = long.Parse(os, NumberStyles.None, CultureInfo.InvariantCulture);
                    int g = int.Parse(gs, NumberStyles.None, CultureInfo.InvariantCulture);
                    if (o > Len || g > 65535) throw PdfObjException.Syntax();
                    XrefEnt e;
                    if (row[17] == 'n') e = UseEnt(o, g);
                    else if (row[17] == 'f') e = new XrefEnt(P.EntFree, 0, 0, 0);
                    else throw PdfObjException.Syntax();
                    p.Pos += 20;
                    Set(fv + i, e);
                }
            }
            if (p.Value(0) is not Dictionary<string, object?> t) throw PdfObjException.Syntax();
            sec.Trailer = t;
            sec.End = p.Pos;
            return sec;
        }
        var ind = p.Indirect(null);
        if (ind.Val is not PStream st || !P.IfaceEq(P.Get(st.Dict, "Type"), new PName("XRef"))) throw PdfObjException.Syntax();
        var data = Budget.Decode(st);
        if (P.Get(st.Dict, "W") is not List<object?> w || w.Count != 3) throw PdfObjException.Syntax();
        var width = new int[3];
        for (int k = 0; k < 3; k++)
        {
            if (w[k] is not long x || x < 0 || x > 7) throw PdfObjException.Syntax();
            width[k] = (int)x;
        }
        if (P.Get(st.Dict, "Size") is not long size || size < 0) throw PdfObjException.Syntax();
        var index = new List<object?> { 0L, size };
        if (st.Dict.ContainsKey("Index"))
        {
            if (P.Get(st.Dict, "Index") is not List<object?> ix || ix.Count % 2 != 0) throw PdfObjException.Syntax();
            index = ix;
        }
        int rowLen = width[0] + width[1] + width[2];
        if (rowLen == 0) throw PdfObjException.Syntax();
        int cur = 0;
        long Field(int n)
        {
            long x = 0;
            for (int k = 0; k < n; k++) x = x * 256 + data[cur + k];
            cur += n;
            return x;
        }
        for (int k = 0; k < index.Count; k += 2)
        {
            if (index[k] is not long first || index[k + 1] is not long count || first < 0 || first >= P.MaxObjectNumber || count < 0 ||
                count > (data.Length - cur) / rowLen)
                throw PdfObjException.Syntax();
            for (long j = 0; j < count; j++)
            {
                long kind = 1;
                if (width[0] > 0) kind = Field(width[0]);
                long f2 = Field(width[1]);
                long f3 = Field(width[2]);
                XrefEnt e;
                if (kind == 0) e = new XrefEnt(P.EntFree, 0, 0, 0);
                else if (kind == 1) e = UseEnt(f2, f3);
                else if (kind == 2) e = new XrefEnt(P.EntComp, f2, 0, f3);
                else throw PdfObjException.Syntax();
                Set(first + j, e);
            }
        }
        if (cur != data.Length) throw PdfObjException.Syntax();
        sec.Trailer = st.Dict;
        sec.End = p.Pos;
        return sec;
    }

    private static bool AllDigits(string s)
    {
        if (s.Length == 0) return false;
        foreach (var c in s)
            if (!P.IsDigit(c)) return false;
        return true;
    }

    /// <summary>Ашиглагдаж буй num объектыг задална (толгойн дугаар/үе xref-тэй таарах ёстой).</summary>
    public object? Get(int num)
    {
        if (_objs.TryGetValue(num, out var hit)) return hit;
        object? val;
        var e = P.Ent(Xref, num);
        if (e.Kind == P.EntUse)
        {
            if (e.Off >= Len) throw PdfObjException.Syntax();
            var key = (e.Off, -1L);
            if (!Budget.Objs.TryGetValue(key, out var o) || o.End > Len)
            {
                var p = Parser((int)e.Off);
                _usedLength = false;
                o = p.Indirect(Length);
                o.End = p.Pos;
                if (!_usedLength) Budget.Objs[key] = o;
            }
            if (o.Num != num || o.Gen != e.Gen) throw PdfObjException.Syntax();
            val = o.Val;
        }
        else if (e.Kind == P.EntComp)
        {
            var st = ObjStmAt(e.Off);
            if (e.Idx >= st.Nums.Count || st.Nums[(int)e.Idx] != num || (long)st.First + st.Offs[(int)e.Idx] > st.Data.Length) throw PdfObjException.Syntax();
            var key = (P.Ent(Xref, e.Off).Off, e.Idx);
            if (!Budget.Objs.TryGetValue(key, out var o))
            {
                var p = new PdfParser(st.Data, st.Data.Length, st.First + st.Offs[(int)e.Idx], Budget);
                o = new CachedObj { Val = p.Value(0) };
                Budget.Objs[key] = o;
            }
            val = o.Val;
        }
        else
        {
            throw PdfObjException.Syntax();
        }
        _objs[num] = val;
        return val;
    }

    /// <summary>ref-ийн заасан объект; ашиглагдаагүй дугаар бол null, үе таарахгүй бол алдаа.</summary>
    public object? Deref(PRef r)
    {
        var e = P.Ent(Xref, r.Num);
        if (!P.InUse(e)) return null;
        if ((e.Kind == P.EntUse && e.Gen != r.Gen) || (e.Kind == P.EntComp && r.Gen != 0)) throw PdfObjException.Syntax();
        return Get(r.Num);
    }

    public object? Resolve(object? x) => x is PRef r ? Deref(r) : x;

    private long Length(PRef r)
    {
        if (_inLength) throw PdfObjException.Syntax();
        _inLength = true;
        try
        {
            if (Deref(r) is not long o) throw PdfObjException.Syntax();
            _usedLength = true;
            return o;
        }
        finally
        {
            _inLength = false;
        }
    }

    /// <summary>Индирект /Length-ийг энэ харагдацад (Classifier.structure-ийн хатуу задлалтад).</summary>
    public long LengthOf(PRef r) => Length(r);

    public ObjStm ObjStmAt(long num)
    {
        if (P.Ent(Xref, num).Kind != P.EntUse) throw PdfObjException.Syntax();
        var o = Get((int)num);
        long off = P.Ent(Xref, num).Off;
        if (Budget.Stms.TryGetValue(off, out var cached)) return cached;
        if (o is not PStream s) throw PdfObjException.Syntax();
        var n = P.Get(s.Dict, "N");
        var first = P.Get(s.Dict, "First");
        if (n is not long nv || first is not long fv || P.Get(s.Dict, "Length") is not long || !P.IfaceEq(P.Get(s.Dict, "Type"), new PName("ObjStm")) ||
            P.Get(s.Dict, "Extends") is not null)
            throw PdfObjException.Syntax();
        var data = Budget.Decode(s);
        if (nv < 0 || nv > data.Length || fv < 0 || fv > data.Length) throw PdfObjException.Syntax();
        var st = new ObjStm { Data = data, First = (int)fv };
        var p = new PdfParser(data, st.First, 0, Budget);
        for (long i = 0; i < nv; i++)
        {
            p.SkipSpace();
            var id = p.Uint();
            p.SkipSpace();
            var so = p.Uint();
            if (id is not { } idv || so is not { } sov || idv >= P.MaxObjectNumber || sov > data.Length) throw PdfObjException.Syntax();
            Budget.Node();
            st.Nums.Add((int)idv);
            st.Offs.Add((int)sov);
        }
        Budget.Stms[off] = st;
        return st;
    }

    /// <summary>Ашиглагдаж буй БҮХ объектыг задалж, объект бүрээс гарах ref-ийн дугааруудыг буцаана.</summary>
    public Dictionary<int, List<int>> Graph()
    {
        if (_refs is not null) return _refs;
        var refs = new Dictionary<int, List<int>>();
        foreach (var kv in Xref)
        {
            if (!P.InUse(kv.Value)) continue;
            var o = Get(kv.Key);
            var outl = new List<int>();
            P.Refs(o, r => outl.Add(r.Num));
            refs[kv.Key] = outl;
        }
        _refs = refs;
        return refs;
    }

    /// <summary>b-ийн (эхний len байт) сүүлийн startxref-ээс /Prev гинжийг дагаж xref-ийг нийлүүлнэ.</summary>
    public static PdfView Open(byte[] b, int len, PdfBudget budget)
    {
        var v = new PdfView(b, len, budget);
        int tail = Math.Max(0, len - 1024);
        int i = LastIndex(b, len, tail, "startxref"u8);
        if (i < 0) throw PdfObjException.Syntax();
        var p = v.Parser(i);
        var off = p.Startxref();
        if (off is not { } o0 || !P.AllGapSpace(b.AsSpan(p.Pos, len - p.Pos))) throw PdfObjException.Syntax();
        long off2 = o0;
        var seen = new HashSet<long>();
        while (true)
        {
            if (v.Sections.Count == MaxXrefSections || seen.Contains(off2) || off2 >= len) throw PdfObjException.Syntax();
            seen.Add(off2);
            var sec = v.Section(off2);
            v.Sections.Add(sec);
            if (P.Get(sec.Trailer, "Encrypt") is not null || P.Get(sec.Trailer, "XRefStm") is not null) throw PdfObjException.Syntax();
            if (!sec.Trailer.ContainsKey("Prev")) break;
            if (P.Get(sec.Trailer, "Prev") is not long prev || prev < 0 || prev >= len) throw PdfObjException.Syntax();
            off2 = prev;
        }
        foreach (var sec in v.Sections)
            foreach (var kv in sec.Ents)
                v.Xref.TryAdd(kv.Key, kv.Value);
        v.Trailer = v.Sections[0].Trailer;
        if (P.Get(v.Trailer, "Size") is not long size) throw PdfObjException.Syntax();
        foreach (var kv in v.Xref)
            if (P.InUse(kv.Value) && (kv.Key >= size || kv.Key == 0)) throw PdfObjException.Syntax();
        return v;
    }

    private static int LastIndex(byte[] b, int len, int from, ReadOnlySpan<byte> s)
    {
        for (int i = len - s.Length; i >= from; i--)
            if (b.AsSpan(i, s.Length).SequenceEqual(s)) return i;
        return -1;
    }
}
