using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Threading;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>PDF-ийн бүтэц хэт гүн давхарласан эсвэл хэт төвөгтэй (<see cref="Structure.Check"/>).</summary>
internal sealed class PdfStructureException : Exception
{
    public PdfStructureException() : base("PDF structure is too deeply nested or too complex") { }
}

/// <summary>
/// PRECHECKS #2a/#2b — Go reference <c>validate.CheckStructure</c> (nesting.go + objstm.go)-ийн порт. <see cref="PdfDocument"/>
/// (digitorus/pdf-ийн порт) нь массив/толийг рекурсээр задалдаг, ObjStm-ийн агуулагч ба толгойн лавлагааг мөчлөгийн
/// хамгаалалтгүй resolve хийдэг тул гүн давхарласан эсвэл мөчлөгтэй баримт <c>StackOverflowException</c>-оор процессыг
/// унагана (catch барихгүй). Тиймээс задлахаас ӨМНӨ: объект задлагдаж эхэлж болох бүх цэгээс (`obj`/`trailer`-ийн дараа,
/// FlateDecode /Type /ObjStm-ийн толгойн offset бүрээс) эхний объектын давхарлалт &gt; 256; уншилтын/inflate төсөв;
/// trailer эсвэл xref stream-ийн /Size &gt; 2^21; ObjStm өөрийгөө/харилцан агуулах, толгойн лавлагаа ObjStm руу,
/// /Extends мөчлөг эсвэл &gt; 64 → <see cref="PdfStructureException"/> (fail-closed). Хамгаалалтын нэг давхарга.
/// </summary>
internal static class Structure
{
    public const int MaxNesting = 256;
    private const long NestScanFactor = 16;
    private const long MaxObjStmBytes = 32 << 20;
    private const long MaxXrefSize = 1 << 21;
    private const int MaxObjStmChain = 64;

    /// <summary>xref хэсгийн дээд тоо: `trailer`-ийн араах толь + /Type /XRef толь (Go maxXrefSections).</summary>
    internal const int MaxXrefSections = 128;

    /// <summary>
    /// ObjStm-ийн гишүүн хайлтын ажлын дээд хэмжээ: Σ (толгойд уншсан «дугаар offset» хосын тоо × задалсан өгөгдлийн урт)
    /// (Go maxObjStmWork). Go-ийн уншигч гишүүн бүрд stream-ийг дахин задалж толгойг эхнээс нь уншдаг тул тайлан ижил байхын
    /// тулд .NET (толгойг нэг удаа индексжүүлдэг) ч мөн адил татгалзана.
    /// </summary>
    private const long MaxObjStmWork = 1L << 30;

    /// <summary>trailer / xref stream-ийн /Encrypt: лавлагаа эсвэл шууд толь (<c>/EncryptMetadata</c> биш). Go <c>\s</c> = [\t\n\f\r ].</summary>
    internal static readonly Regex EncryptRef =
        new(@"/Encrypt(?:[\t\n\f\r ]+[0-9]+[\t\n\f\r ]+[0-9]+[\t\n\f\r ]+R|[\t\n\f\r ]*<<)", RegexOptions.CultureInvariant);

    private static readonly byte[][] Keywords = { "obj"u8.ToArray(), "trailer"u8.ToArray() };

    /// <exception cref="PdfStructureException"/>
    public static void Check(byte[] doc, CancellationToken ct = default)
    {
        var s = new Scan(NestScanFactor * doc.Length + (1 << 20), MaxObjStmBytes);
        foreach (var kw in Keywords)
        {
            for (int i = 0; ;)
            {
                ct.ThrowIfCancellationRequested();
                int j = doc.AsSpan(i).IndexOf(kw);
                if (j < 0) break;
                int k = i + j;
                int at = k + kw.Length;
                i = at;
                // Токен нь хоёр талдаа зай/хязгаарлагчтай (`endobj`, `objx` — өөр түлхүүр үг).
                if (k > 0 && !Lexer.IsSpace(doc[k - 1]) && !Lexer.IsDelim(doc[k - 1]) ||
                    at < doc.Length && !Lexer.IsSpace(doc[at]) && !Lexer.IsDelim(doc[at]))
                    continue;
                s.FromTrailer = kw.Length == 7; // "trailer"
                s.Object(doc, at, doc.Length, true);
            }
        }
        if (s.BigSize || s.Sections > MaxXrefSections || s.XrefEntries > MaxXrefSize) throw new PdfStructureException();
        CheckObjStmGraph(doc);
    }

    private enum Tok
    {
        Eof,
        Err,
        Arr,
        ArrEnd,
        Dict,
        DictEnd,
        Name,
        Word,
        Str,
    }

    /// <summary>digitorus buffer.readToken-ийн давталт (зөвхөн бүтэц).</summary>
    private sealed class Lex
    {
        public readonly byte[] B;
        public readonly int End;
        public int Pos;
        public string Val = "";

        public Lex(byte[] b, int pos, int end)
        {
            B = b;
            Pos = pos;
            End = end;
        }

        public Tok Next()
        {
            var b = B;
            while (true)
            {
                while (Pos < End && Lexer.IsSpace(b[Pos])) Pos++;
                if (Pos < End && b[Pos] == '%')
                {
                    while (Pos < End && b[Pos] != '\r' && b[Pos] != '\n') Pos++;
                    continue;
                }
                break;
            }
            if (Pos >= End) return Tok.Eof;
            byte c = b[Pos++];
            switch (c)
            {
                case (byte)'<':
                    if (Pos < End && b[Pos] == '<')
                    {
                        Pos++;
                        return Tok.Dict;
                    }
                    while (Pos < End && b[Pos] != '>') Pos++;
                    Pos++;
                    return Tok.Str;
                case (byte)'(':
                    for (int depth = 1; Pos < End && depth > 0; Pos++)
                    {
                        switch (b[Pos])
                        {
                            case (byte)'(':
                                depth++;
                                break;
                            case (byte)')':
                                depth--;
                                break;
                            case (byte)'\\':
                                Pos++;
                                break;
                        }
                    }
                    return Tok.Str;
                case (byte)'[':
                    return Tok.Arr;
                case (byte)']':
                    return Tok.ArrEnd;
                case (byte)'{':
                case (byte)'}':
                    Val = ((char)c).ToString();
                    return Tok.Word;
                case (byte)'/':
                    {
                        var name = new List<byte>();
                        while (Pos < End && !Lexer.IsDelim(b[Pos]) && !Lexer.IsSpace(b[Pos]))
                        {
                            if (b[Pos] == '#' && Pos + 2 < End && Hex(b[Pos + 1]) >= 0 && Hex(b[Pos + 2]) >= 0)
                            {
                                name.Add((byte)(Hex(b[Pos + 1]) << 4 | Hex(b[Pos + 2])));
                                Pos += 3;
                                continue;
                            }
                            name.Add(b[Pos]);
                            Pos++;
                        }
                        Val = Latin1.FromBytes(name.ToArray());
                        return Tok.Name;
                    }
                case (byte)'>':
                    if (Pos < End && b[Pos] == '>')
                    {
                        Pos++;
                        return Tok.DictEnd;
                    }
                    return Tok.Err;
                case (byte)')':
                    return Tok.Err;
            }
            int start = Pos - 1;
            while (Pos < End && !Lexer.IsDelim(b[Pos]) && !Lexer.IsSpace(b[Pos])) Pos++;
            Val = Latin1.FromBytes(b.AsSpan(start, Pos - start));
            return Tok.Word;
        }

        private static int Hex(byte x) =>
            x >= '0' && x <= '9' ? x - '0' : x >= 'a' && x <= 'f' ? x - 'a' + 10 : x >= 'A' && x <= 'F' ? x - 'A' + 10 : -1;
    }

    /// <summary>Go strconv.ParseInt(s, 10, 64): (алдаагүй эсэх, утга — синтакс алдаа → 0, хэтрэлт → ±MaxInt64).</summary>
    private static bool ParseInt(string s, out long v)
    {
        v = 0;
        int i = s.Length > 0 && (s[0] == '+' || s[0] == '-') ? 1 : 0;
        if (i == s.Length) return false;
        for (int k = i; k < s.Length; k++)
            if (s[k] < '0' || s[k] > '9') return false;
        if (long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out v)) return true;
        v = s[0] == '-' ? long.MinValue : long.MaxValue;
        return false;
    }

    private static bool IsInt(string s) => ParseInt(s, out _);

    private sealed class Frame
    {
        public bool Dict;
        public bool ExpectKey;
        public string Key = "";
    }

    /// <summary>
    /// Дээд түвшний толийн /Type /Filter /DecodeParms /N /First; xref stream-д /W ба /Index-ийн бүхэл утгууд (давхар түлхүүрийн
    /// сүүлийнх; бүхэл биш элемент → *Bad — уншигч өөрөө алдаа өгнө), /Size, шууд бүхэл /Length (-1 — байхгүй).
    /// </summary>
    private sealed class ObjStmInfo
    {
        public string Typ = "", Filter = "";
        public int Filters;
        public bool Parms, Indirect;
        public long First, NCount;
        public List<long> W = new(), Index = new();
        public bool WBad, IndexBad, WSet, IndexSet;
        public long Size;
        public bool SizeSet;
        public long Length = -1;
    }

    private sealed class Scan
    {
        private long _budget;
        private long _inflateLeft;

        /// <summary>Дээд түвшний /Size &gt; MaxXrefSize.</summary>
        public bool BigSize;

        /// <summary>Одоогийн дээд түвшний объект `trailer` түлхүүр үгийн араас (Check тавина).</summary>
        public bool FromTrailer;

        /// <summary>
        /// xref хэсгийн тоо (`trailer`-ийн араах толь + /Type /XRef толь), бүх xref stream-ийн мөрийн нийлбэр (/Index-ийн тоонууд,
        /// /Index байхгүй бол /Size), ObjStm-ийн гишүүн хайлтын ажил (<see cref="MaxObjStmWork"/>).
        /// </summary>
        public long Sections, XrefEntries, ObjStmWork;

        public Scan(long budget, long inflateLeft)
        {
            _budget = budget;
            _inflateLeft = inflateLeft;
        }

        /// <summary>b[start:end]-аас уншигчийн нэг объектыг (давхар `N G obj`-ийг оруулаад) гүнээр шалгана.</summary>
        public void Object(byte[] b, int start, int end, bool allowStream)
        {
            var l = new Lex(b, start, end);
            try
            {
                Body(l, start, allowStream);
            }
            finally
            {
                _budget -= l.Pos - start;
            }
        }

        private void Body(Lex l, int start, bool allowStream)
        {
            var stack = new List<Frame>();
            var info = new ObjStmInfo();
            bool trailer = FromTrailer && allowStream;
            FromTrailer = false;
            while (true)
            {
                if (_budget - (l.Pos - start) < 0) throw new PdfStructureException();
                var tok = l.Next();
                int top = stack.Count - 1;
                if (top >= 0 && stack[top].Dict && stack[top].ExpectKey)
                {
                    if (tok == Tok.DictEnd)
                    {
                        stack.RemoveAt(top);
                        if (stack.Count == 0)
                        {
                            if (trailer) Sections++;
                            if (allowStream && !trailer && info.Typ == "XRef") XrefStm(info);
                            if (allowStream && (info.Typ == "ObjStm" || info.Typ == "XRef" || info.Indirect)) ObjStm(l, info);
                            return;
                        }
                        var p = stack[^1];
                        p.ExpectKey = p.Dict;
                        continue;
                    }
                    if (tok == Tok.Name)
                    {
                        stack[top].Key = l.Val;
                        stack[top].ExpectKey = false;
                        continue;
                    }
                    return; // non-name key — уншигч энд унана
                }
                // Утга уншина.
                switch (tok)
                {
                    case Tok.Eof:
                    case Tok.Err:
                    case Tok.DictEnd:
                        return;
                    case Tok.Arr:
                    case Tok.Dict:
                        if (stack.Count >= MaxNesting) throw new PdfStructureException();
                        if (stack.Count == 1 && stack[0].Dict && stack[0].Key == "DecodeParms") info.Parms = true;
                        if (stack.Count == 1 && stack[0].Dict && stack[0].Key == "Filter")
                        {
                            info.Filter = ""; // давхар түлхүүрийн сүүлийнх; массивын нэрсийг NoteScalar тоолно (Go 900de73)
                            info.Filters = 0;
                        }
                        if (stack.Count == 1 && stack[0].Dict && stack[0].Key == "W")
                        {
                            info.W = new List<long>();
                            info.WSet = true;
                            info.WBad = tok != Tok.Arr;
                        }
                        if (stack.Count == 1 && stack[0].Dict && stack[0].Key == "Index")
                        {
                            info.Index = new List<long>();
                            info.IndexSet = true;
                            info.IndexBad = tok != Tok.Arr;
                        }
                        if (stack.Count == 2 && stack[0].Dict && stack[0].Key == "W") info.WBad = true; // массив доторх массив/толь — бүхэл биш
                        if (stack.Count == 2 && stack[0].Dict && stack[0].Key == "Index") info.IndexBad = true;
                        stack.Add(new Frame { Dict = tok == Tok.Dict, ExpectKey = tok == Tok.Dict });
                        continue;
                    case Tok.ArrEnd:
                        if (top < 0 || stack[top].Dict) return;
                        stack.RemoveAt(top);
                        break;
                    case Tok.Word:
                        {
                            bool done = false;
                            if (IsInt(l.Val))
                            {
                                int save = l.Pos;
                                var saveVal = l.Val;
                                if (l.Next() == Tok.Word && IsInt(l.Val))
                                {
                                    var t3 = l.Next();
                                    if (t3 == Tok.Word && l.Val == "R")
                                    {
                                        if (stack.Count == 1 && stack[0].Dict && stack[0].Key is "Type" or "Filter" or "DecodeParms" or "N" or "First")
                                            info.Indirect = true;
                                        // /Filter [6 0 R] — уншигч Index()-ээр resolve хийж задална (Go 900de73).
                                        if (stack.Count == 2 && stack[0].Dict && stack[0].Key == "Filter") info.Indirect = true;
                                        // /W, /Index-ийн лавлагаа (массив эсвэл элемент) — уншигч resolve хийхгүй, алдаа өгнө.
                                        if (stack.Count is 1 or 2 && stack[0].Dict)
                                        {
                                            if (stack[0].Key == "W")
                                            {
                                                info.WSet = true;
                                                info.WBad = true;
                                            }
                                            else if (stack[0].Key == "Index")
                                            {
                                                info.IndexSet = true;
                                                info.IndexBad = true;
                                            }
                                        }
                                        done = true; // лавлагаа = нэг утга
                                    }
                                    else if (t3 == Tok.Word && l.Val == "obj")
                                    {
                                        continue; // давхар `N G obj` — дараагийн утга нь энэ объектын үргэлжлэл
                                    }
                                }
                                if (!done)
                                {
                                    l.Pos = save;
                                    l.Val = saveVal;
                                }
                            }
                            if (!done) NoteScalar(stack, info, tok, l.Val);
                            break;
                        }
                    case Tok.Name:
                    case Tok.Str:
                        NoteScalar(stack, info, tok, l.Val);
                        break;
                }
                // Нэг утга дууслаа.
                if (stack.Count == 0) return;
                var f = stack[^1];
                if (f.Dict) f.ExpectKey = true;
            }
        }

        /// <summary>Дээд түвшний толийн (ба /Filter массивын) энгийн утгыг тэмдэглэнэ.</summary>
        private void NoteScalar(List<Frame> stack, ObjStmInfo info, Tok tok, string val)
        {
            if (stack.Count == 1 && stack[0].Dict)
            {
                switch (stack[0].Key)
                {
                    case "Type":
                        if (tok == Tok.Name) info.Typ = val;
                        break;
                    case "Filter":
                        if (tok == Tok.Name)
                        {
                            info.Filter = val;
                            info.Filters = 1;
                        }
                        else
                        {
                            info.Filter = ""; // null → уншигч шүүлтүүргүй уншина; давхар түлхүүрийн сүүлийнх (Go 900de73)
                            info.Filters = 0;
                        }
                        break;
                    case "DecodeParms":
                        if (!(tok == Tok.Word && val == "null")) info.Parms = true;
                        break;
                    case "N":
                        ParseInt(val, out info.NCount);
                        break;
                    case "Size":
                        {
                            bool ok = ParseInt(val, out long n);
                            if (tok == Tok.Word && ok && n > MaxXrefSize) BigSize = true;
                            info.Size = n;
                            info.SizeSet = tok == Tok.Word && ok;
                            break;
                        }
                    case "First":
                        ParseInt(val, out info.First);
                        break;
                    case "Length":
                        info.Length = tok == Tok.Word && ParseInt(val, out long len) && len >= 0 ? len : -1;
                        break;
                    case "W":
                        info.W = new List<long>();
                        info.WSet = true;
                        info.WBad = true;
                        break;
                    case "Index":
                        info.Index = new List<long>();
                        info.IndexSet = true;
                        info.IndexBad = true;
                        break;
                }
            }
            else if (stack.Count == 2 && stack[0].Dict && stack[0].Key == "Filter" && !stack[1].Dict && tok == Tok.Name)
            {
                info.Filter = val;
                info.Filters++;
            }
            else if (stack.Count == 2 && stack[0].Dict && !stack[1].Dict && (stack[0].Key == "W" || stack[0].Key == "Index"))
            {
                bool ok = ParseInt(val, out long n);
                ok = tok == Tok.Word && ok;
                if (stack[0].Key == "W")
                {
                    info.W.Add(n);
                    info.WBad = info.WBad || !ok;
                }
                else
                {
                    info.Index.Add(n);
                    info.IndexBad = info.IndexBad || !ok;
                }
            }
        }

        /// <summary>`stream`-ийн араас FlateDecode өгөгдлийг (zlib өөрөө төгсөнө) задалж, толгойн offset бүрээс объектыг шалгана.</summary>
        private void ObjStm(Lex l, ObjStmInfo info)
        {
            if (l.Next() != Tok.Word || l.Val != "stream") return;
            if (info.Indirect) throw new PdfStructureException(); // /Type /Filter /N /First лавлагаагаар — хууль ёсны баримтад гардаггүй
            if (info.Typ != "ObjStm" && info.Typ != "XRef") return;
            var b = l.B;
            int p = Math.Min(l.Pos, l.End);
            if (p < l.End && b[p] == '\r') p++;
            if (p < l.End && b[p] == '\n') p++;
            if (info.Typ == "XRef")
            {
                XrefData(b, p, l.End, info);
                return;
            }
            if (info.Filters == 0)
            {
                // Шахаагүй ObjStm — өгөгдөл нь файлын үлдсэн хэсэг (дээд хязгаар); ажлын тооцоонд шууд /Length (байвал).
                long pairs0 = ObjStmData(b, p, l.End, info);
                long n0 = l.End - p;
                if (info.Length >= 0) n0 = Math.Min(n0, info.Length);
                ChargeObjStm(pairs0, n0);
                return;
            }
            if (info.Filters > 1) throw new PdfStructureException(); // уншигч [/FlateDecode /FlateDecode …]-г гинжлэн задалдаг — давтахгүй (Go 900de73)
            if (info.Filter != "FlateDecode") return; // уншигч дэмжихгүй шүүлтүүр
            if (info.Parms) throw new PdfStructureException(); // predictor-тэй ObjStm-ийг давтахгүй — fail-closed
            var data = Inflate(b, p, l.End, _inflateLeft);
            if (data is null) return; // уншигч мөн задалж чадахгүй
            _inflateLeft -= data.Length;
            _budget -= data.Length;
            long pairs = ObjStmData(data, 0, data.Length, info);
            ChargeObjStm(pairs, data.Length);
        }

        /// <summary>Нэг ObjStm-ийн гишүүн хайлтын ажил (хосын тоо × өгөгдлийн урт)-ыг <see cref="MaxObjStmWork"/>-оос хасна (Go chargeObjStm).</summary>
        private void ChargeObjStm(long pairs, long n)
        {
            if (pairs > 0 && n > 0 && pairs > (MaxObjStmWork - ObjStmWork) / n) throw new PdfStructureException();
            ObjStmWork += pairs * n;
        }

        /// <summary>
        /// Go xrefStm — xref stream-ийн толь (/Type /XRef): хэсгийн тоо; /W-ийн элемент 0…8, мөрийн урт &gt; 0; /Index-ийн хос бүр
        /// start, count ≥ 0, start+count ≤ 2^21; бүх xref stream-ийн мөрийн нийлбэр (/Index байхгүй бол /Size) ≤ 2^21. Бүхэл биш /
        /// дутуу /W /Index-ийг уншигч өөрөө татгалзана — энд шийдэхгүй.
        /// </summary>
        private void XrefStm(ObjStmInfo info)
        {
            Sections++;
            if (info.WSet && !info.WBad && info.W.Count >= 3)
            {
                long row = 0;
                foreach (var w in info.W)
                {
                    if (w < 0 || w > 8) throw new PdfStructureException();
                    row += w;
                }
                if (row == 0) throw new PdfStructureException();
            }
            if (info.IndexSet && !info.IndexBad && info.Index.Count % 2 == 0)
            {
                for (int i = 0; i < info.Index.Count; i += 2)
                {
                    long start = info.Index[i], n = info.Index[i + 1];
                    if (start < 0 || n < 0 || start > MaxXrefSize || n > MaxXrefSize - start) throw new PdfStructureException();
                    XrefEntries += n;
                }
            }
            else if (!info.IndexSet && info.SizeSet && info.Size >= 0)
            {
                XrefEntries += Math.Min(info.Size, MaxXrefSize + 1);
            }
            if (XrefEntries > MaxXrefSize) throw new PdfStructureException();
        }

        /// <summary>
        /// Go xrefData — xref stream-ийн өгөгдөл: олон шүүлтүүр → алдаа (уншигч гинжлэн задалдаг); FlateDecode бол задалж (zlib өөрөө
        /// төгсөнө; predictor-ийг тооцохгүй — хэмжээ л) ObjStm-тэй хуваалцсан задлалтын төсвөөс хасна.
        /// </summary>
        private void XrefData(byte[] b, int p, int end, ObjStmInfo info)
        {
            if (info.Filters == 0) return;
            if (info.Filters > 1) throw new PdfStructureException();
            if (info.Filter != "FlateDecode") return;
            var data = Inflate(b, p, end, _inflateLeft);
            if (data is null) return;
            _inflateLeft -= data.Length;
        }

        /// <summary>Go zlib.NewReader + io.ReadAll(LimitReader): толгой буруу → null; дундаас эвдэрвэл тэр хүртэлх өгөгдөл.</summary>
        private static byte[]? Inflate(byte[] b, int p, int end, long limit)
        {
            if (end - p < 2) return null;
            byte cmf = b[p], flg = b[p + 1];
            if ((cmf & 0x0f) != 8 || cmf >> 4 > 7 || (cmf << 8 | flg) % 31 != 0 || (flg & 0x20) != 0) return null;
            using var zs = new ZLibStream(new MemoryStream(b, p, end - p, writable: false), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            var buf = new byte[64 << 10];
            try
            {
                while (true)
                {
                    int n = zs.Read(buf, 0, buf.Length);
                    if (n == 0) break;
                    ms.Write(buf, 0, n);
                    if (ms.Length > limit) throw new PdfStructureException();
                }
            }
            catch (InvalidDataException)
            {
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Go objStmData — толгойн «дугаар offset» хос бүрийн объектыг (өгөгдөл = b[start:end]) шалгана. Offset-ийг уншигчтай яг
        /// ижлээр: бүхэл бус токен = 0, сөрөг offset ба /First, int64-ийн wrap хэвээр; `first`-ийг нэг л удаа; өгөгдлийн
        /// төгсгөлөөс цааш — алгасна; сөрөг байрлал → алдаа. Буцаах утга — уншсан хосын тоо (эхний токен нь EOF биш давталт).
        /// </summary>
        private long ObjStmData(byte[] b, int start, int end, ObjStmInfo info)
        {
            var l = new Lex(b, start, end);
            long len = end - start;
            long pairs = 0;
            bool firstDone = false;
            for (long i = 0; i < info.NCount; i++)
            {
                if (l.Next() == Tok.Eof) break;
                pairs++;
                long off = 0;
                if (l.Next() == Tok.Word && ParseInt(l.Val, out long v)) off = v;
                long at = unchecked(info.First + off);
                if (at < 0) throw new PdfStructureException();
                if (at >= len || (at == info.First && firstDone)) continue;
                firstDone = firstDone || at == info.First;
                if (_budget < 0) throw new PdfStructureException();
                Object(b, (int)(start + at), end, false);
            }
            if (_budget < 0) throw new PdfStructureException();
            return pairs;
        }
    }

    /// <summary>
    /// Go checkObjStmGraph (PRECHECKS #2b): ObjStm доторх объектын агуулагч stream нь өөрөө ObjStm-д; агуулагч (ба /Extends-ээр
    /// холбогдсон) stream-ийн толгойн лавлагаа ObjStm доторх объект руу; /Extends мөчлөг эсвэл &gt; 64 → алдаа. Уншигч
    /// нээгдэхгүй/задрахгүй бол энд шийдэхгүй (дуудагч өөрөө PDF_INVALID болгоно).
    /// </summary>
    private static void CheckObjStmGraph(byte[] doc)
    {
        PdfDocument r;
        try
        {
            r = PdfDocument.Open(doc);
        }
        catch (Exception e) when (Prechecks.IsParseError(e))
        {
            return;
        }
        var xr = r.Xref;
        bool Registered(ObjPtr p) => p.Id < (uint)xr.Count && xr[(int)p.Id].Ptr == p;
        bool InStream(ObjPtr p) => Registered(p) && xr[(int)p.Id].InStream;
        var containers = new List<ObjPtr>();
        var have = new HashSet<ObjPtr>();
        foreach (var e in xr)
        {
            if (!e.InStream) continue;
            if (InStream(e.Stream)) throw new PdfStructureException();
            if (have.Add(e.Stream)) containers.Add(e.Stream);
        }
        foreach (var c in containers)
        {
            var seen = new HashSet<ObjPtr>();
            for (var p = c; Registered(p);)
            {
                if (seen.Contains(p) || seen.Count > MaxObjStmChain) throw new PdfStructureException();
                seen.Add(p);
                PdfValue v;
                try
                {
                    v = r.Resolve(p, p);
                }
                catch (Exception e) when (Prechecks.IsParseError(e))
                {
                    return; // уншигч энд унадаг баримт — дуудагч PDF_INVALID
                }
                if (v.Data is not PdfStream s) break;
                bool bad = false;
                WalkRefs(s.Header, 0, x => bad |= InStream(x));
                if (bad) throw new PdfStructureException();
                if (s.Header.GetValueOrDefault("Extends") is not ObjPtr ext) break;
                p = ext;
            }
        }
    }

    /// <summary>Go walkRefs — задалсан утга (dict / array) доторх бүх лавлагаа.</summary>
    private static void WalkRefs(object? v, int depth, Action<ObjPtr> fn)
    {
        if (depth > MaxNesting) return;
        switch (v)
        {
            case ObjPtr p:
                fn(p);
                break;
            case PdfDict d:
                foreach (var x in d.Values) WalkRefs(x, depth + 1, fn);
                break;
            case PdfArray a:
                foreach (var x in a) WalkRefs(x, depth + 1, fn);
                break;
        }
    }
}
