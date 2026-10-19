using System;
using System.Collections.Generic;
using System.Globalization;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

// Occupancy scanner — PLACEMENT_SPEC.md §2–§5, a 1:1 port of the Go reference pades/internal/core/occupancy.go.
// A pure function of the page objects: it never renders and never loads a font program.
//
// Arithmetic (§2): IEEE-754 binary64, only + − × ÷, Math.Min/Max/Abs/Floor/Ceiling. Every product is rounded on its own
// and terms are summed left to right exactly as written below. C# evaluates `a * b + c` as two rounded operations and
// RyuJIT never contracts them into a fused multiply-add (FMA is only emitted for explicit Math.FusedMultiplyAdd /
// Fma intrinsics, which this file must never use); there is no fast-math mode. Keep each expression in the spec's
// order — do not "simplify" (a·x + c·y + e is not e + a·x + c·y in floating point).

/// <summary>The page could not be scanned within the rules (limit, unsupported filter, broken stream) — PLACEMENT_SPEC §5.</summary>
internal sealed class UnscannableException : Exception
{
    public UnscannableException(string message) : base(message) { }
}

internal static class Occupancy
{
    // Limits (PLACEMENT_SPEC.md §5).
    private const int MaxBytes = 4 << 20; // decoded content bytes, page + every form execution
    private const int MaxOps = 100_000; // operators executed, page + forms
    private const int MaxDepth = 8; // form XObject nesting (page content = 0)
    private const int MaxSave = 64; // q nesting per content stream
    private const int MaxOperands = 65_536; // operand objects pending at one operator (nested array elements count)
    private const int MaxNesting = 32; // array / dictionary nesting in an operand
    private const int MaxAnnots = 10_000; // /Annots entries
    private const int MaxWEntries = 65_536; // CIDFont /W: elements read (outer array, and each inner array)
    private const int MaxWAssign = 262_144; // CIDFont /W: CID assignments attempted before reading stops
    private const int MaxNumLen = 32; // a longer numeric token is not a number
    private const double Clamp = 1e7; // box coordinates are clamped to ±Clamp pt before quantising
    private const int MaxInherit = 32; // /Parent chain for /Resources

    /// <summary>
    /// The occupied boxes of a page in default user space, h100, outward-rounded, in emission order (content stream, then
    /// /Annots). <paramref name="box"/> = the page's normalised CropBox/MediaBox (h100), used only for the background-fill
    /// rule. Returns <c>null</c> when the page is unscannable — never throws (Go recovers the reader's panics too).
    /// </summary>
    public static List<long[]>? Scan(PdfValue page, long[] box)
    {
        try
        {
            var s = new Scanner(box);
            var content = s.PageContent(page.Key("Contents"));
            var res = Inherited(page, "Resources");
            s.Run(content, res, GState.Initial, 0);
            s.Annots(page.Key("Annots"));
            return s.Boxes;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    private static PdfValue Inherited(PdfValue page, string key)
    {
        var v = page;
        for (int i = 0; i < MaxInherit; i++)
        {
            var x = v.Key(key);
            if (!x.IsNull) return x;
            v = v.Key("Parent");
            if (v.Kind != PdfKind.Dict) break;
        }
        return default;
    }

    // ── Geometry ──

    private readonly record struct Matrix(double A, double B, double C, double D, double E, double F)
    {
        public static readonly Matrix Identity = new(1, 0, 0, 1, 0, 0);

        /// <summary>m × n (row-vector convention, ISO 32000-1 §8.3.4): each product rounded, summed left to right.</summary>
        public static Matrix Mul(Matrix m, Matrix n) => new(
            m.A * n.A + m.B * n.C,
            m.A * n.B + m.B * n.D,
            m.C * n.A + m.D * n.C,
            m.C * n.B + m.D * n.D,
            m.E * n.A + m.F * n.C + n.E,
            m.E * n.B + m.F * n.D + n.F);

        /// <summary>(x, y) × m: x' = a·x + c·y + e, y' = b·x + d·y + f.</summary>
        public (double X, double Y) Apply(double x, double y) => (A * x + C * y + E, B * x + D * y + F);

        public bool Finite => double.IsFinite(A) && double.IsFinite(B) && double.IsFinite(C) && double.IsFinite(D) &&
                              double.IsFinite(E) && double.IsFinite(F);
    }

    /// <summary>A float bounding box being accumulated (mutable struct: use it through fields/locals only).</summary>
    private struct Rect
    {
        public double X0, Y0, X1, Y1;

        public Rect(double x0, double y0, double x1, double y1)
        {
            X0 = x0;
            Y0 = y0;
            X1 = x1;
            Y1 = y1;
        }

        public static Rect Point(double x, double y) => new(x, y, x, y);

        public void Add(double x, double y)
        {
            X0 = Math.Min(X0, x);
            Y0 = Math.Min(Y0, y);
            X1 = Math.Max(X1, x);
            Y1 = Math.Max(Y1, y);
        }
    }

    /// <summary>Outward to h100 after clamping to ±Clamp pt: floor(min·100), ceil(max·100). NaN → unscannable.</summary>
    private static long[] Quantise(Rect r)
    {
        static double C(double v)
        {
            if (double.IsNaN(v)) throw new UnscannableException("NaN");
            return Math.Min(Math.Max(v, -Clamp), Clamp);
        }
        double x0 = C(r.X0), y0 = C(r.Y0), x1 = C(r.X1), y1 = C(r.Y1);
        return new[] { (long)Math.Floor(x0 * 100), (long)Math.Floor(y0 * 100), (long)Math.Ceiling(x1 * 100), (long)Math.Ceiling(y1 * 100) };
    }

    /// <summary>
    /// Go int(f) for a PDF number: truncation toward zero, saturating outside the int64 range (NaN → 0). Go's own
    /// out-of-range conversion is platform-dependent; .NET 8's (long) cast is too — saturation keeps the result the same
    /// on every runtime. Every such value is out of the CID / code range and is ignored anyway.
    /// </summary>
    private static long Trunc(double v)
    {
        if (double.IsNaN(v)) return 0;
        if (v >= 9223372036854775807.0) return long.MaxValue;
        if (v <= -9223372036854775808.0) return long.MinValue;
        return (long)v;
    }

    // ── Fonts (PLACEMENT_SPEC.md §3.4) ──

    private enum FontKind
    {
        Simple, // 1-byte codes, /Widths
        Identity, // Type0 + /Identity-H|V: 2-byte codes, /W + /DW
        Composite, // Type0, any other /Encoding: 1-byte codes, 1000
        Default, // Type3, missing font, no Tf: 1-byte codes, 1000
    }

    private sealed class Font
    {
        public static readonly Font Default = new(FontKind.Default);

        public Font(FontKind kind) => Kind = kind;

        public FontKind Kind { get; }
        public long First;
        public readonly List<double> Widths = new(); // simple: /Widths (non-number → NaN = not given)
        public double Missing = 1000; // simple: FontDescriptor /MissingWidth if > 0
        public double Dw = 1000; // identity: /DW
        public readonly Dictionary<long, double> W = new();

        /// <summary>A string's codes: (w0 in glyph units, is it the 1-byte code 32 of a word-spacing font).</summary>
        public void Glyphs(byte[] b, Action<double, bool> fn)
        {
            if (Kind == FontKind.Identity)
            {
                for (int i = 0; i + 1 < b.Length; i += 2)
                {
                    long cid = b[i] << 8 | b[i + 1];
                    fn(W.TryGetValue(cid, out var w) ? w : Dw, false);
                }
                return;
            }
            foreach (var c in b)
            {
                double w = 1000.0;
                if (Kind == FontKind.Simple)
                {
                    w = Missing;
                    long i = c - First;
                    if (i >= 0 && i < Widths.Count && !double.IsNaN(Widths[(int)i])) w = Widths[(int)i];
                }
                fn(w, Kind != FontKind.Composite && c == ' ');
            }
        }
    }

    private static bool Number(PdfValue v, out double x)
    {
        if (v.Kind is PdfKind.Integer or PdfKind.Real)
        {
            x = v.Float64;
            return true;
        }
        x = 0;
        return false;
    }

    private static Font LoadFont(PdfValue v)
    {
        switch (v.Key("Subtype").Name)
        {
            case "Type3":
                return Font.Default;
            case "Type0":
                var enc = v.Key("Encoding");
                if (enc.Kind != PdfKind.Name || enc.Name is not ("Identity-H" or "Identity-V")) return new Font(FontKind.Composite);
                var f = new Font(FontKind.Identity);
                var d = v.Key("DescendantFonts").Index(0);
                if (Number(d.Key("DW"), out var dw)) f.Dw = dw;
                ReadW(f, d.Key("W"));
                return f;
        }
        var sf = new Font(FontKind.Simple);
        if (Number(v.Key("FirstChar"), out var fc)) sf.First = Trunc(fc);
        var ws = v.Key("Widths");
        for (int i = 0, n = Math.Min(ws.Len, 256); i < n; i++) sf.Widths.Add(Number(ws.Index(i), out var x) ? x : double.NaN);
        if (Number(v.Key("FontDescriptor").Key("MissingWidth"), out var mw) && mw > 0) sf.Missing = mw;
        return sf;
    }

    /// <summary>CIDFont /W: `c [w…]` and `c1 c2 w`; the first assignment of a CID wins; budgeted (§3.4).</summary>
    private static void ReadW(Font f, PdfValue w)
    {
        int n = Math.Min(w.Len, MaxWEntries);
        int budget = MaxWAssign;
        bool Set(long cid, double val)
        {
            if (--budget < 0) return false;
            if (cid >= 0 && cid <= 0xFFFF) f.W.TryAdd(cid, val);
            return true;
        }
        for (int i = 0; i < n;)
        {
            if (!Number(w.Index(i), out var c0) || i + 1 >= n) return;
            var arr = w.Index(i + 1);
            if (arr.Kind == PdfKind.Array)
            {
                for (int j = 0, m = Math.Min(arr.Len, MaxWEntries); j < m; j++)
                    if (Number(arr.Index(j), out var x) && !Set(Trunc(c0) + j, x)) return;
                i += 2;
                continue;
            }
            bool ok1 = Number(w.Index(i + 1), out var c1);
            bool ok2 = Number(w.Index(i + 2), out var xv);
            if (!ok1 || !ok2 || i + 2 >= n) return;
            long hi = Trunc(c1);
            for (long c = Math.Max(Trunc(c0), 0); c <= hi && c <= 0xFFFF; c++)
                if (!Set(c, xv)) return;
            i += 3;
        }
    }

    // ── Content-stream lexer (PLACEMENT_SPEC.md §3.1) ──

    private enum OpKind
    {
        Num,
        Str,
        Name,
        Arr,
        Dict,
        Other, // true/false/null, or any keyword inside an array/dictionary
    }

    private sealed class Operand
    {
        public static readonly Operand OtherValue = new(OpKind.Other);

        public Operand(OpKind kind) => Kind = kind;

        public OpKind Kind { get; }
        public double Num;
        public byte[] Str = Array.Empty<byte>();
        public string Name = "";
        public List<Operand>? Arr;
    }

    private enum Tok
    {
        Eof,
        Obj,
        Keyword,
        ArrEnd,
        DictEnd,
    }

    private static bool IsSpace(byte c) => c is 0 or 9 or 10 or 12 or 13 or 32;

    private static bool IsDelim(byte c) => c is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    /// <summary>[+-]?(\d+(\.\d*)?|\.\d+), at most MaxNumLen bytes.</summary>
    private static bool IsNumber(ReadOnlySpan<byte> t)
    {
        if (t.Length == 0 || t.Length > MaxNumLen) return false;
        int i = 0;
        if (t[0] is (byte)'+' or (byte)'-') i++;
        int digits = 0;
        bool dot = false;
        for (; i < t.Length; i++)
        {
            byte c = t[i];
            if (c is >= (byte)'0' and <= (byte)'9') digits++;
            else if (c == '.' && !dot) dot = true;
            else return false;
        }
        return digits > 0;
    }

    private static int Unhex(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        _ => -1,
    };

    private sealed class ContentLexer
    {
        private readonly byte[] _b;

        public ContentLexer(byte[] b) => _b = b;

        public int Pos;

        public byte[] Data => _b;

        private void SkipSpace()
        {
            while (Pos < _b.Length)
            {
                byte c = _b[Pos];
                if (IsSpace(c))
                {
                    Pos++;
                }
                else if (c == '%')
                {
                    while (Pos < _b.Length && _b[Pos] != '\r' && _b[Pos] != '\n') Pos++;
                }
                else
                {
                    return;
                }
            }
        }

        private ReadOnlySpan<byte> Regular()
        {
            int s = Pos;
            while (Pos < _b.Length && !IsSpace(_b[Pos]) && !IsDelim(_b[Pos])) Pos++;
            return _b.AsSpan(s, Pos - s);
        }

        /// <summary>After '(' : balanced parentheses, escapes; EOF ends the string.</summary>
        private byte[] Literal()
        {
            var o = new List<byte>();
            int depth = 1;
            while (Pos < _b.Length)
            {
                byte c = _b[Pos++];
                switch (c)
                {
                    case (byte)'(':
                        depth++;
                        break;
                    case (byte)')':
                        if (--depth == 0) return o.ToArray();
                        break;
                    case (byte)'\\':
                        if (Pos >= _b.Length) return o.ToArray();
                        byte e = _b[Pos++];
                        switch (e)
                        {
                            case (byte)'n':
                                c = (byte)'\n';
                                break;
                            case (byte)'r':
                                c = (byte)'\r';
                                break;
                            case (byte)'t':
                                c = (byte)'\t';
                                break;
                            case (byte)'b':
                                c = (byte)'\b';
                                break;
                            case (byte)'f':
                                c = (byte)'\f';
                                break;
                            case (byte)'\r':
                                if (Pos < _b.Length && _b[Pos] == '\n') Pos++;
                                continue;
                            case (byte)'\n':
                                continue;
                            default:
                                if (e is >= (byte)'0' and <= (byte)'7')
                                {
                                    int v = e - '0';
                                    for (int k = 0; k < 2 && Pos < _b.Length && _b[Pos] >= '0' && _b[Pos] <= '7'; k++)
                                        v = v * 8 + (_b[Pos++] - '0');
                                    c = (byte)v;
                                }
                                else
                                {
                                    c = e;
                                }
                                break;
                        }
                        break;
                }
                o.Add(c);
            }
            return o.ToArray();
        }

        /// <summary>After '&lt;' : hex digits, other bytes skipped, odd final nibble padded with 0; '&gt;' or EOF ends it.</summary>
        private byte[] HexString()
        {
            var o = new List<byte>();
            int hi = 0;
            bool half = false;
            while (Pos < _b.Length)
            {
                byte c = _b[Pos++];
                if (c == '>') break;
                int v = Unhex(c);
                if (v < 0) continue;
                if (half) o.Add((byte)(hi << 4 | v));
                else hi = v;
                half = !half;
            }
            if (half) o.Add((byte)(hi << 4));
            return o.ToArray();
        }

        /// <summary>After '/' : regular bytes, #xx decoded (Latin-1, as PDF object names).</summary>
        private string NameToken()
        {
            var t = Regular();
            var o = new List<byte>(t.Length);
            for (int i = 0; i < t.Length; i++)
            {
                if (t[i] == '#' && i + 2 < t.Length)
                {
                    int h = Unhex(t[i + 1]), lo = Unhex(t[i + 2]);
                    if (h >= 0 && lo >= 0)
                    {
                        o.Add((byte)(h << 4 | lo));
                        i += 2;
                        continue;
                    }
                }
                o.Add(t[i]);
            }
            return Latin1.FromBytes(o.ToArray());
        }

        /// <summary>One token. Keywords come back as Tok.Keyword with kw set; '{' '}' and stray ')' are skipped.</summary>
        public Tok Next(out Operand o, out string kw)
        {
            kw = "";
            o = Operand.OtherValue;
            while (true)
            {
                SkipSpace();
                if (Pos >= _b.Length) return Tok.Eof;
                byte c = _b[Pos];
                switch (c)
                {
                    case (byte)'(':
                        Pos++;
                        o = new Operand(OpKind.Str) { Str = Literal() };
                        return Tok.Obj;
                    case (byte)'<':
                        if (Pos + 1 < _b.Length && _b[Pos + 1] == '<')
                        {
                            Pos += 2;
                            o = new Operand(OpKind.Dict);
                            kw = "<<";
                            return Tok.Obj;
                        }
                        Pos++;
                        o = new Operand(OpKind.Str) { Str = HexString() };
                        return Tok.Obj;
                    case (byte)'>':
                        if (Pos + 1 < _b.Length && _b[Pos + 1] == '>')
                        {
                            Pos += 2;
                            return Tok.DictEnd;
                        }
                        Pos++;
                        continue;
                    case (byte)'[':
                        Pos++;
                        o = new Operand(OpKind.Arr) { Arr = new List<Operand>() };
                        kw = "[";
                        return Tok.Obj;
                    case (byte)']':
                        Pos++;
                        return Tok.ArrEnd;
                    case (byte)'/':
                        Pos++;
                        o = new Operand(OpKind.Name) { Name = NameToken() };
                        return Tok.Obj;
                    case (byte)')':
                    case (byte)'{':
                    case (byte)'}':
                        Pos++;
                        continue;
                }
                var t = Regular();
                if (IsNumber(t))
                {
                    // Correctly rounded (IEEE round-to-nearest-even) like Go strconv.ParseFloat for this grammar.
                    o = new Operand(OpKind.Num)
                    {
                        Num = double.Parse(t, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture),
                    };
                    return Tok.Obj;
                }
                var s = Latin1.FromBytes(t);
                if (s is "true" or "false" or "null") return Tok.Obj;
                kw = s;
                return Tok.Keyword;
            }
        }

        /// <summary>
        /// Completes an array or dictionary opened by Next (open = "[" or "&lt;&lt;"). Inside, every token is an element;
        /// EOF ends the content (returns true). Nesting &gt; MaxNesting or too many elements → unscannable.
        /// </summary>
        public bool Object(Operand o, string open, int depth, ref int count)
        {
            if (open == "") return false;
            if (depth >= MaxNesting) throw new UnscannableException("nesting");
            while (true)
            {
                var k = Next(out var e, out var kw);
                switch (k)
                {
                    case Tok.Eof:
                        return true;
                    case Tok.ArrEnd:
                        if (open == "[") return false;
                        continue;
                    case Tok.DictEnd:
                        if (open == "<<") return false;
                        continue;
                    case Tok.Keyword:
                        e = Operand.OtherValue;
                        break;
                    case Tok.Obj:
                        if (Object(e, kw, depth + 1, ref count)) return true;
                        break;
                }
                if (++count > MaxOperands) throw new UnscannableException("operands");
                if (open == "[") o.Arr!.Add(e);
            }
        }
    }

    // ── Interpreter (PLACEMENT_SPEC.md §3.2–§3.6) ──

    /// <summary>Graphics + text state (value type: q/Q and form calls copy it).</summary>
    private struct GState
    {
        public Matrix Ctm;
        public double Lw;
        public bool FillWhite, StrokeWhite;
        public double Tc, Tw, Th, Tl, Tfs, Trise;
        public Font Font;

        public static GState Initial => new() { Ctm = Matrix.Identity, Lw = 1, Th = 1, Font = Font.Default };
    }

    private sealed class Subpath
    {
        public double Sx, Sy, Cx, Cy; // start and current point (device space)
        public Rect Bbox;
        public readonly List<Rect> Segs = new();
    }

    private sealed class Scanner
    {
        private readonly long[] _page;
        private readonly Dictionary<uint, Font> _fonts = new();
        private int _bytes;
        private int _ops;

        public Scanner(long[] page) => _page = page;

        public List<long[]> Boxes { get; } = new();

        private void Emit(Rect r) => Boxes.Add(Quantise(r));

        /// <summary>Go: fonts are cached by the value's object id (the containing object for a direct dictionary), id 0 never.</summary>
        private Font LookupFont(PdfValue v)
        {
            if (v.Kind != PdfKind.Dict) return Font.Default;
            uint id = v.Ptr.Id;
            if (id != 0 && _fonts.TryGetValue(id, out var f)) return f;
            f = LoadFont(v);
            if (id != 0) _fonts[id] = f;
            return f;
        }

        /// <summary>Decoded bytes of a content/form stream: no filter, or exactly FlateDecode without parameters.</summary>
        private byte[] Stream(PdfValue v)
        {
            if (v.Kind != PdfKind.Stream) throw new UnscannableException("not a stream");
            var f = v.Key("Filter");
            var p = v.Key("DecodeParms");
            bool flate;
            if (f.IsNull && p.IsNull) flate = false;
            else if (f.Kind == PdfKind.Name && f.Name == "FlateDecode" && p.IsNull) flate = true;
            else if (f.Kind == PdfKind.Array && f.Len == 1 && f.Index(0).Kind == PdfKind.Name && f.Index(0).Name == "FlateDecode" &&
                     (p.IsNull || (p.Kind == PdfKind.Array && p.Len == 1 && p.Index(0).IsNull))) flate = true;
            else throw new UnscannableException("filter");
            int left = MaxBytes - _bytes;
            var raw = v.RawStreamBytes();
            byte[] b;
            if (flate)
            {
                b = ZlibStrict.Decode(raw, left) ?? throw new UnscannableException("flate");
            }
            else
            {
                if (raw.Length > left) throw new UnscannableException("content bytes");
                b = raw.ToArray();
            }
            _bytes += b.Length;
            return b;
        }

        /// <summary>/Contents: absent → empty; a stream; or an array of streams joined with LF.</summary>
        public byte[] PageContent(PdfValue c)
        {
            switch (c.Kind)
            {
                case PdfKind.Null:
                    return Array.Empty<byte>();
                case PdfKind.Stream:
                    return Stream(c);
                case PdfKind.Array:
                    var o = new List<byte>();
                    for (int i = 0; i < c.Len; i++)
                    {
                        var b = Stream(c.Index(i));
                        if (i > 0) o.Add((byte)'\n');
                        o.AddRange(b);
                    }
                    return o.ToArray();
            }
            throw new UnscannableException("/Contents");
        }

        /// <summary>The operands if they are exactly n numbers.</summary>
        private static double[]? Nums(List<Operand> ops, int n)
        {
            if (ops.Count != n) return null;
            var o = new double[n];
            for (int i = 0; i < n; i++)
            {
                if (ops[i].Kind != OpKind.Num) return null;
                o[i] = ops[i].Num;
            }
            return o;
        }

        private static Matrix M(double[] v) => new(v[0], v[1], v[2], v[3], v[4], v[5]);

        private static Matrix Advance(Matrix tlm, double tx, double ty)
        {
            var m = Matrix.Mul(new Matrix(1, 0, 0, 1, tx, ty), tlm);
            if (!m.Finite) throw new UnscannableException("text matrix");
            return m;
        }

        /// <summary>
        /// Executes one content stream (page content or a form) from graphics state g, with its own operand stack, q stack,
        /// path and text matrices.
        /// </summary>
        public void Run(byte[] content, PdfValue res, GState g, int depth)
        {
            var l = new ContentLexer(content);
            var stack = new List<GState>();
            var path = new List<Subpath>();
            Matrix tm = Matrix.Identity, tlm = Matrix.Identity;
            var ops = new List<Operand>();
            int count = 0;
            while (true)
            {
                var k = l.Next(out var o, out var kw);
                switch (k)
                {
                    case Tok.Eof:
                        return;
                    case Tok.ArrEnd:
                    case Tok.DictEnd:
                        continue;
                    case Tok.Obj:
                        if (l.Object(o, kw, 0, ref count)) return;
                        if (++count > MaxOperands) throw new UnscannableException("operands");
                        ops.Add(o);
                        continue;
                }
                if (++_ops > MaxOps) throw new UnscannableException("operators");
                var args = ops;
                ops = new List<Operand>();
                count = 0;
                double[]? v;
                switch (kw)
                {
                    case "q":
                    case "Q":
                    case "BT":
                        if (args.Count != 0) break;
                        if (kw == "BT")
                        {
                            tm = tlm = Matrix.Identity;
                        }
                        else if (kw == "Q")
                        {
                            if (stack.Count > 0)
                            {
                                g = stack[^1];
                                stack.RemoveAt(stack.Count - 1);
                            }
                        }
                        else
                        {
                            if (stack.Count >= MaxSave) throw new UnscannableException("q nesting");
                            stack.Add(g);
                        }
                        break;
                    case "cm":
                        if ((v = Nums(args, 6)) is not null)
                        {
                            g.Ctm = Matrix.Mul(M(v), g.Ctm);
                            if (!g.Ctm.Finite) throw new UnscannableException("CTM");
                        }
                        break;
                    case "w":
                        if ((v = Nums(args, 1)) is not null) g.Lw = v[0];
                        break;
                    case "g":
                        if ((v = Nums(args, 1)) is not null) g.FillWhite = v[0] >= 1;
                        break;
                    case "G":
                        if ((v = Nums(args, 1)) is not null) g.StrokeWhite = v[0] >= 1;
                        break;
                    case "rg":
                        if ((v = Nums(args, 3)) is not null) g.FillWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1;
                        break;
                    case "RG":
                        if ((v = Nums(args, 3)) is not null) g.StrokeWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1;
                        break;
                    case "k":
                        if ((v = Nums(args, 4)) is not null) g.FillWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0;
                        break;
                    case "K":
                        if ((v = Nums(args, 4)) is not null) g.StrokeWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0;
                        break;
                    case "cs":
                    case "sc":
                    case "scn":
                        g.FillWhite = false;
                        break;
                    case "CS":
                    case "SC":
                    case "SCN":
                        g.StrokeWhite = false;
                        break;

                    // ── Path construction (points transformed by the CTM when given) ──
                    case "m":
                        if ((v = Nums(args, 2)) is not null)
                        {
                            var (x, y) = g.Ctm.Apply(v[0], v[1]);
                            path.Add(new Subpath { Sx = x, Sy = y, Cx = x, Cy = y, Bbox = Rect.Point(x, y) });
                        }
                        break;
                    case "l":
                    case "c":
                    case "v":
                    case "y":
                        {
                            int n = kw == "l" ? 2 : kw == "c" ? 6 : 4;
                            v = Nums(args, n);
                            if (v is null || path.Count == 0) break;
                            var sp = path[^1];
                            var seg = Rect.Point(sp.Cx, sp.Cy);
                            for (int i = 0; i < n; i += 2)
                            {
                                var (x, y) = g.Ctm.Apply(v[i], v[i + 1]);
                                seg.Add(x, y);
                                sp.Bbox.Add(x, y);
                                sp.Cx = x;
                                sp.Cy = y;
                            }
                            sp.Segs.Add(seg);
                            break;
                        }
                    case "h":
                        if (args.Count == 0 && path.Count > 0) ClosePath(path[^1]);
                        break;
                    case "re":
                        if ((v = Nums(args, 4)) is not null)
                        {
                            var (x0, y0) = g.Ctm.Apply(v[0], v[1]);
                            var p1 = g.Ctm.Apply(v[0] + v[2], v[1]);
                            var p2 = g.Ctm.Apply(v[0] + v[2], v[1] + v[3]);
                            var p3 = g.Ctm.Apply(v[0], v[1] + v[3]);
                            var sp = new Subpath { Sx = x0, Sy = y0, Cx = x0, Cy = y0, Bbox = Rect.Point(x0, y0) };
                            foreach (var (px, py) in new[] { p1, p2, p3 })
                            {
                                var seg = Rect.Point(sp.Cx, sp.Cy);
                                seg.Add(px, py);
                                sp.Segs.Add(seg);
                                sp.Bbox.Add(px, py);
                                sp.Cx = px;
                                sp.Cy = py;
                            }
                            ClosePath(sp);
                            path.Add(sp);
                        }
                        break;
                    case "S":
                    case "s":
                    case "f":
                    case "F":
                    case "f*":
                    case "B":
                    case "B*":
                    case "b":
                    case "b*":
                    case "n":
                        {
                            if (args.Count != 0) break;
                            if (kw is "s" or "b" or "b*" && path.Count > 0) ClosePath(path[^1]);
                            bool fill = kw is not ("S" or "s" or "n");
                            bool stroke = kw is "S" or "s" or "B" or "B*" or "b" or "b*";
                            if (fill && !g.FillWhite) Fill(path);
                            if (stroke && !g.StrokeWhite) Stroke(path, g);
                            path = new List<Subpath>();
                            break;
                        }

                    // ── Text ──
                    case "Tc":
                        if ((v = Nums(args, 1)) is not null) g.Tc = v[0];
                        break;
                    case "Tw":
                        if ((v = Nums(args, 1)) is not null) g.Tw = v[0];
                        break;
                    case "Tz":
                        if ((v = Nums(args, 1)) is not null) g.Th = v[0] / 100;
                        break;
                    case "TL":
                        if ((v = Nums(args, 1)) is not null) g.Tl = v[0];
                        break;
                    case "Ts":
                        if ((v = Nums(args, 1)) is not null) g.Trise = v[0];
                        break;
                    case "Tf":
                        if (args.Count == 2 && args[0].Kind == OpKind.Name && args[1].Kind == OpKind.Num)
                        {
                            g.Font = LookupFont(res.Key("Font").Key(args[0].Name));
                            g.Tfs = args[1].Num;
                        }
                        break;
                    case "Td":
                    case "TD":
                        if ((v = Nums(args, 2)) is not null)
                        {
                            if (kw == "TD") g.Tl = -v[1];
                            tlm = Advance(tlm, v[0], v[1]);
                            tm = tlm;
                        }
                        break;
                    case "T*":
                        if (args.Count == 0)
                        {
                            tlm = Advance(tlm, 0, -g.Tl);
                            tm = tlm;
                        }
                        break;
                    case "Tm":
                        if ((v = Nums(args, 6)) is not null) tm = tlm = M(v);
                        break;
                    case "Tj":
                    case "'":
                    case "\"":
                    case "TJ":
                        {
                            List<Operand> items;
                            if (kw is "Tj" or "'" && args.Count == 1 && args[0].Kind == OpKind.Str)
                            {
                                items = args;
                            }
                            else if (kw == "\"" && args.Count == 3 && args[0].Kind == OpKind.Num && args[1].Kind == OpKind.Num && args[2].Kind == OpKind.Str)
                            {
                                g.Tw = args[0].Num;
                                g.Tc = args[1].Num;
                                items = args.GetRange(2, 1);
                            }
                            else if (kw == "TJ" && args.Count == 1 && args[0].Kind == OpKind.Arr)
                            {
                                items = args[0].Arr!;
                            }
                            else
                            {
                                break;
                            }
                            if (kw is "'" or "\"")
                            {
                                tlm = Advance(tlm, 0, -g.Tl);
                                tm = tlm;
                            }
                            tm = Show(items, g, tm);
                            break;
                        }
                    case "Do":
                        if (args.Count == 1 && args[0].Kind == OpKind.Name) Do(res.Key("XObject").Key(args[0].Name), res, g, depth);
                        break;
                    case "BI":
                        InlineImage(l, g.Ctm);
                        break;
                }
            }
        }

        private void Do(PdfValue x, PdfValue res, GState g, int depth)
        {
            switch (x.Key("Subtype").Name)
            {
                case "Image":
                    UnitSquare(g.Ctm);
                    return;
                case "Form":
                    if (x.Kind != PdfKind.Stream) return;
                    if (depth + 1 > MaxDepth) throw new UnscannableException("form depth");
                    var fm = Matrix.Identity;
                    var m = x.Key("Matrix");
                    if (m.Kind == PdfKind.Array && m.Len == 6)
                    {
                        var v = new double[6];
                        bool ok = true;
                        for (int i = 0; i < 6 && ok; i++) ok = Number(m.Index(i), out v[i]);
                        if (ok) fm = M(v);
                    }
                    var ctm = Matrix.Mul(fm, g.Ctm);
                    if (!ctm.Finite) throw new UnscannableException("form matrix");
                    var fres = x.Key("Resources");
                    if (fres.Kind != PdfKind.Dict) fres = res;
                    var b = Stream(x);
                    var fg = g;
                    fg.Ctm = ctm;
                    Run(b, fres, fg, depth + 1);
                    return;
            }
        }

        private static void ClosePath(Subpath sp)
        {
            var seg = Rect.Point(sp.Cx, sp.Cy);
            seg.Add(sp.Sx, sp.Sy);
            sp.Segs.Add(seg);
            sp.Cx = sp.Sx;
            sp.Cy = sp.Sy;
        }

        /// <summary>One box per subpath; a subpath box covering ≥ half of the page box is a background and is skipped.</summary>
        private void Fill(List<Subpath> path)
        {
            foreach (var sp in path)
            {
                var q = Quantise(sp.Bbox);
                // Area of the box clipped to the page box, integer arithmetic (≤ 8e18, fits in long).
                long w = Math.Min(q[2], _page[2]) - Math.Max(q[0], _page[0]);
                long h = Math.Min(q[3], _page[3]) - Math.Max(q[1], _page[1]);
                if (w > 0 && h > 0 && 2 * w * h >= (_page[2] - _page[0]) * (_page[3] - _page[1])) continue;
                Boxes.Add(q);
            }
        }

        /// <summary>One box per segment, widened by half the line width mapped through the CTM (|a|+|c|, |b|+|d|).</summary>
        private void Stroke(List<Subpath> path, GState g)
        {
            double hw = Math.Abs(g.Lw) / 2;
            double ex = hw * Math.Abs(g.Ctm.A) + hw * Math.Abs(g.Ctm.C);
            double ey = hw * Math.Abs(g.Ctm.B) + hw * Math.Abs(g.Ctm.D);
            foreach (var sp in path)
                foreach (var r in sp.Segs)
                    Emit(new Rect(r.X0 - ex, r.Y0 - ey, r.X1 + ex, r.Y1 + ey));
        }

        private void UnitSquare(Matrix ctm)
        {
            var (x, y) = ctm.Apply(0, 0);
            var r = Rect.Point(x, y);
            foreach (var (px, py) in new (double, double)[] { (1, 0), (0, 1), (1, 1) })
            {
                var (qx, qy) = ctm.Apply(px, py);
                r.Add(qx, qy);
            }
            Emit(r);
        }

        /// <summary>
        /// One box per string/array operand: [min, max] of glyph extents in text space × [rise − 0.3·Tfs, rise + Tfs],
        /// through Tm then the CTM. Returns the advanced Tm.
        /// </summary>
        private Matrix Show(List<Operand> items, GState g, Matrix tm)
        {
            double x = 0.0;
            bool hasExt = false;
            double ext0 = 0, ext1 = 0;
            foreach (var it in items)
            {
                switch (it.Kind)
                {
                    case OpKind.Num:
                        x -= it.Num / 1000 * g.Tfs * g.Th;
                        break;
                    case OpKind.Str:
                        g.Font.Glyphs(it.Str, (w0, space) =>
                        {
                            double gw = w0 / 1000 * g.Tfs * g.Th;
                            double lo = Math.Min(x, x + gw), hi = Math.Max(x, x + gw);
                            if (!hasExt)
                            {
                                ext0 = lo;
                                ext1 = hi;
                                hasExt = true;
                            }
                            else
                            {
                                ext0 = Math.Min(ext0, lo);
                                ext1 = Math.Max(ext1, hi);
                            }
                            double adv = w0 / 1000 * g.Tfs + g.Tc;
                            if (space) adv += g.Tw;
                            x += adv * g.Th;
                        });
                        break;
                }
            }
            if (hasExt)
            {
                double ya = g.Trise + g.Tfs * -0.3, yb = g.Trise + g.Tfs;
                Rect r = default;
                bool first = true;
                foreach (var (px, py) in new[] { (ext0, ya), (ext1, ya), (ext0, yb), (ext1, yb) })
                {
                    var (tx, ty) = tm.Apply(px, py);
                    var (dx, dy) = g.Ctm.Apply(tx, ty);
                    if (first)
                    {
                        r = Rect.Point(dx, dy);
                        first = false;
                    }
                    else
                    {
                        r.Add(dx, dy);
                    }
                }
                Emit(r);
            }
            tm = Matrix.Mul(new Matrix(1, 0, 0, 1, x, 0), tm);
            if (!tm.Finite) throw new UnscannableException("text matrix");
            return tm;
        }

        /// <summary>
        /// BI &lt;key value&gt;… ID &lt;data&gt; EI: data ends at the first "EI" preceded by a whitespace byte and followed by
        /// a whitespace byte or the end of the content. No EI → the content ends (no box).
        /// </summary>
        private void InlineImage(ContentLexer l, Matrix ctm)
        {
            int count = 0;
            while (true)
            {
                var k = l.Next(out var o, out var kw);
                if (k == Tok.Eof) return;
                if (k == Tok.Obj)
                {
                    if (l.Object(o, kw, 0, ref count)) return;
                    continue;
                }
                if (k == Tok.Keyword && kw == "ID") break;
            }
            var b = l.Data;
            if (l.Pos < b.Length && IsSpace(b[l.Pos])) l.Pos++;
            for (int p = l.Pos; p + 1 < b.Length; p++)
            {
                if (b[p] == 'E' && b[p + 1] == 'I' && p > 0 && IsSpace(b[p - 1]) && (p + 2 == b.Length || IsSpace(b[p + 2])))
                {
                    l.Pos = p + 2;
                    UnitSquare(ctm);
                    return;
                }
            }
            l.Pos = b.Length;
        }

        /// <summary>/Rect of every annotation except /Popup, hidden (/F bit 2) or NoView (/F bit 6) and zero-area rects.</summary>
        public void Annots(PdfValue a)
        {
            if (a.Kind != PdfKind.Array) return;
            if (a.Len > MaxAnnots) throw new UnscannableException("annotations");
            for (int i = 0; i < a.Len; i++)
            {
                var an = a.Index(i);
                if (an.Kind != PdfKind.Dict || an.Key("Subtype").Name == "Popup") continue;
                var f = an.Key("F");
                if (f.Kind == PdfKind.Integer && (f.Int64 & (2 | 32)) != 0) continue;
                var r = an.Key("Rect");
                if (r.Kind != PdfKind.Array || r.Len != 4) continue;
                var v = new double[4];
                bool ok = true;
                for (int j = 0; j < 4 && ok; j++) ok = Number(r.Index(j), out v[j]);
                if (!ok || v[0] == v[2] || v[1] == v[3]) continue;
                Emit(new Rect(Math.Min(v[0], v[2]), Math.Min(v[1], v[3]), Math.Max(v[0], v[2]), Math.Max(v[1], v[3])));
            }
        }
    }
}
