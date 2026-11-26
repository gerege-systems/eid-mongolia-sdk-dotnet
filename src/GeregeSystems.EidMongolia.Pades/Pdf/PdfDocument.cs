using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

internal readonly record struct XrefEntry(ObjPtr Ptr, bool InStream, ObjPtr Stream, long Offset);

/// <summary>
/// PDF уншигч — digitorus/pdf read.go-ийн семантик (xref table/stream, /Prev гинж, object stream, FlateDecode +
/// PNG-Up predictor). Шифрлэлтийг тайлахгүй (шифрлэгдсэн баримтыг Prepare өмнө нь татгалздаг).
/// </summary>
internal sealed class PdfDocument
{
    /// <summary>Нэг FlateDecode stream-ийн тайлсан хэмжээний дээд хязгаар (TS reader zlibInflate-тэй ижил).</summary>
    internal const int MaxInflate = 64 << 20;

    /// <summary>Нэг баримт нээх бүрийн нийт FlateDecode тайлалтын төсөв (xref stream, ObjStm, DSS — бүгд хамт).</summary>
    internal const long MaxDocInflate = 256L << 20;

    /// <summary>xref хэсгийн дээд тоо (startxref-ийн хэсэг + /Prev гинж; TS reader MAX_XREF_SECTIONS, Go maxXrefSections).</summary>
    private const int MaxXrefSections = Structure.MaxXrefSections;

    /// <summary>xref stream-ийн мөрийн нийт тоо: max(/Size, 2^21) (TS reader MAX_XREF_ROWS, Go maxXrefSize).</summary>
    private const long MaxXrefRows = 1 << 21;

    private long _inflateLeft = MaxDocInflate;
    private long _xrefRows;

    /// <summary>ObjStm бүрийн задалсан өгөгдөл ба толгойн индекс (гишүүн бүрд толгойг эхнээс нь дахин уншихгүй).</summary>
    private readonly Dictionary<ObjPtr, ObjStmIndex> _objStms = new();

    private readonly byte[] _f;
    private readonly Dictionary<ObjPtr, object?> _cache = new();
    private readonly Dictionary<ObjPtr, byte[]> _streamData = new();
    private List<XrefEntry> _xref = new();
    private PdfDict _trailer = new();
    private ObjPtr _trailerPtr;

    public string PdfVersion { get; }

    /// <summary>"table" | "stream".</summary>
    public string XrefType { get; private set; } = "";

    /// <summary>Сүүлийн startxref-ийн утга (шинэ revision-ийн /Prev).</summary>
    public long XrefStartPos { get; private set; }

    public IReadOnlyList<XrefEntry> Xref => _xref;

    public byte[] Bytes => _f;

    private PdfDocument(byte[] f, string version)
    {
        _f = f;
        PdfVersion = version;
    }

    public PdfValue Trailer => new(this, _trailerPtr, _trailer);

    public static PdfDocument Open(byte[] f)
    {
        if (f.Length < 10) throw new PdfFormatException("not a PDF file: invalid header");
        bool v1 = f[0] == '%' && f[1] == 'P' && f[2] == 'D' && f[3] == 'F' && f[4] == '-' && f[5] == '1' && f[6] == '.' && f[7] >= '0' && f[7] <= '7';
        bool v2 = f[0] == '%' && f[1] == 'P' && f[2] == 'D' && f[3] == 'F' && f[4] == '-' && f[5] == '2' && f[6] == '.' && f[7] == '0';
        if (!v1 && !v2) throw new PdfFormatException("not a PDF file: invalid header");
        var doc = new PdfDocument(f, Latin1.FromBytes(f.AsSpan(5, 3)));

        int eofEnd = LastIndexOf(f, f.Length, "%%EOF"u8);
        if (eofEnd < 0) throw new PdfFormatException("not a PDF file: missing %%EOF");
        eofEnd += 5;
        // Go: %%EOF-ийн өмнөх 200 байтаас «startxref»-ийн сүүлийн мөрийг хайна (200-аас богино бол олдохгүй).
        if (eofEnd < 200) throw new PdfFormatException("malformed PDF file: missing final startxref");
        int winStart = eofEnd - 200;
        int i = FindLastLine(f, winStart, eofEnd, "startxref"u8);
        if (i < 0) throw new PdfFormatException("malformed PDF file: missing final startxref");

        var b = new Lexer(f, winStart + i, f.Length);
        if (b.ReadToken() is not PdfKeyword { Value: "startxref" })
            throw new PdfFormatException("malformed PDF file: missing startxref");
        if (b.ReadToken() is not long startxref)
            throw new PdfFormatException("malformed PDF file: startxref not followed by integer");
        doc.XrefStartPos = startxref;
        if (startxref < 0 || startxref >= f.Length) throw new PdfFormatException("malformed PDF: startxref out of range");

        doc.ReadXref(new Lexer(f, (int)startxref, f.Length));
        return doc;
    }

    private static int LastIndexOf(byte[] f, int end, ReadOnlySpan<byte> s) => f.AsSpan(0, end).LastIndexOf(s);

    private static int FindLastLine(byte[] f, int start, int end, ReadOnlySpan<byte> s)
    {
        var buf = f.AsSpan(start, end - start);
        int max = buf.Length;
        while (true)
        {
            int i = buf[..max].LastIndexOf(s);
            if (i <= 0 || i + s.Length >= buf.Length) return -1;
            byte before = buf[i - 1], after = buf[i + s.Length];
            if ((before == '\n' || before == '\r') && (after == '\n' || after == '\r')) return i;
            max = i;
        }
    }

    private void ReadXref(Lexer b)
    {
        var tok = b.ReadToken();
        if (tok is PdfKeyword { Value: "xref" })
        {
            ReadXrefTable(b);
            return;
        }
        if (tok is long)
        {
            b.UnreadToken(tok);
            ReadXrefStream(b);
            return;
        }
        throw new PdfFormatException("malformed PDF: cross-reference table not found");
    }

    private void ReadXrefStream(Lexer b)
    {
        if (b.ReadObject() is not ObjDef { Obj: PdfStream strm } def)
            throw new PdfFormatException("malformed PDF: cross-reference table not found");
        if (strm.Header.GetValueOrDefault("Type") is not PdfName { Value: "XRef" })
            throw new PdfFormatException("malformed PDF: xref stream does not have type XRef");
        if (strm.Header.GetValueOrDefault("Size") is not long size)
            throw new PdfFormatException("malformed PDF: xref stream missing Size");
        if (size < 0 || size > 1 << 23) throw new PdfFormatException("malformed PDF: xref /Size");

        var table = new List<XrefEntry>(new XrefEntry[size]);
        ReadXrefStreamData(strm, table, size);

        var seen = new HashSet<long>();
        for (var prevoff = strm.Header.GetValueOrDefault("Prev"); prevoff != null;)
        {
            if (prevoff is not long off) throw new PdfFormatException("malformed PDF: xref Prev is not integer");
            if (!seen.Add(off)) throw new PdfFormatException("malformed PDF: xref Prev loop detected");
            if (seen.Count >= MaxXrefSections) throw new PdfFormatException("malformed PDF: xref Prev chain too long");
            if (off < 0 || off >= _f.Length) throw new PdfFormatException("malformed PDF: xref Prev out of range");
            if (new Lexer(_f, (int)off, _f.Length).ReadObject() is not ObjDef { Obj: PdfStream prev })
                throw new PdfFormatException("malformed PDF: xref prev stream not found");
            prevoff = prev.Header.GetValueOrDefault("Prev");
            var pv = new PdfValue(this, default, prev);
            if (pv.Key("Type").Name != "XRef") throw new PdfFormatException("malformed PDF: xref prev stream does not have type XRef");
            long psize = pv.Key("Size").Int64;
            if (psize > size) throw new PdfFormatException("malformed PDF: xref prev stream larger than last stream");
            ReadXrefStreamData(prev, table, psize);
        }

        XrefType = "stream";
        _xref = table;
        _trailer = strm.Header;
        _trailerPtr = def.Ptr;
    }

    private void ReadXrefStreamData(PdfStream strm, List<XrefEntry> table, long size)
    {
        var index = strm.Header.GetValueOrDefault("Index") as PdfArray ?? new PdfArray { 0L, size };
        if (index.Count % 2 != 0) throw new PdfFormatException("invalid Index array");
        if (strm.Header.GetValueOrDefault("W") is not PdfArray ww) throw new PdfFormatException("xref stream missing W array");
        var w = new List<int>();
        foreach (var x in ww)
        {
            if (x is not long i || i < 0 || i > 8) throw new PdfFormatException("invalid W array");
            w.Add((int)i);
        }
        if (w.Count < 3) throw new PdfFormatException("invalid W array");
        int wtotal = 0;
        foreach (var x in w) wtotal += x;
        // /W [0 0 0] — мөр бүр 0 байт: том /Index-ээр хязгааргүй давталт (TS reader, Go precheck xrefStm).
        if (wtotal <= 0) throw new PdfFormatException("xref stream: zero row width");
        long maxRows = Math.Max(size, MaxXrefRows);
        for (int k = 0; k + 1 < index.Count; k += 2)
        {
            if (index[k + 1] is long cnt && cnt > 0)
            {
                _xrefRows += Math.Min(cnt, maxRows + 1);
                if (_xrefRows > maxRows) throw new PdfFormatException("xref stream: too many entries");
            }
        }

        var data = StreamBytes(new PdfValue(this, default, strm), strm, structural: true);
        int p = 0;
        for (int k = 0; k + 1 < index.Count; k += 2)
        {
            if (index[k] is not long start || index[k + 1] is not long n)
                throw new PdfFormatException("malformed Index pair");
            for (long i = 0; i < n; i++)
            {
                if (p + wtotal > data.Length) throw new PdfFormatException("error reading xref stream: unexpected EOF");
                long v1 = w[0] == 0 ? 1 : DecodeInt(data, p, w[0]);
                long v2 = DecodeInt(data, p + w[0], w[1]);
                long v3 = DecodeInt(data, p + w[0] + w[1], w[2]);
                p += wtotal;
                long xl = start + i;
                if (xl < 0 || xl > 1 << 23) throw new PdfFormatException("xref index out of range");
                int x = (int)xl;
                while (table.Count <= x) table.Add(default);
                if (table[x].Ptr != default) continue;
                switch (v1)
                {
                    case 0:
                        table[x] = new XrefEntry(new ObjPtr(0, 65535), false, default, 0);
                        break;
                    case 1:
                        table[x] = new XrefEntry(new ObjPtr((uint)x, (ushort)v3), false, default, v2);
                        break;
                    case 2:
                        table[x] = new XrefEntry(new ObjPtr((uint)x, 0), true, new ObjPtr((uint)v2, 0), v3);
                        break;
                }
            }
        }
    }

    private static long DecodeInt(byte[] b, int off, int n)
    {
        long x = 0;
        for (int i = 0; i < n; i++) x = x << 8 | b[off + i];
        return x;
    }

    private void ReadXrefTable(Lexer b)
    {
        var table = new List<XrefEntry>();
        ReadXrefTableData(b, table);
        if (b.ReadObject() is not PdfDict trailer)
            throw new PdfFormatException("malformed PDF: xref table not followed by trailer dictionary");

        var seen = new HashSet<long>();
        for (var prevoff = trailer.GetValueOrDefault("Prev"); prevoff != null;)
        {
            if (prevoff is not long off) throw new PdfFormatException("malformed PDF: xref Prev is not integer");
            if (!seen.Add(off)) throw new PdfFormatException("malformed PDF: xref Prev loop detected");
            if (seen.Count >= MaxXrefSections) throw new PdfFormatException("malformed PDF: xref Prev chain too long");
            if (off < 0 || off >= _f.Length) throw new PdfFormatException("malformed PDF: xref Prev out of range");
            var pb = new Lexer(_f, (int)off, _f.Length);
            if (pb.ReadToken() is not PdfKeyword { Value: "xref" })
                throw new PdfFormatException("malformed PDF: xref Prev does not point to xref");
            ReadXrefTableData(pb, table);
            if (pb.ReadObject() is not PdfDict pt)
                throw new PdfFormatException("malformed PDF: xref Prev table not followed by trailer dictionary");
            prevoff = pt.GetValueOrDefault("Prev");
        }

        if (trailer.GetValueOrDefault("Size") is not long size)
            throw new PdfFormatException("malformed PDF: trailer missing /Size entry");
        if (size >= 0 && size < table.Count) table.RemoveRange((int)size, table.Count - (int)size);

        XrefType = "table";
        _xref = table;
        _trailer = trailer;
        _trailerPtr = default;
    }

    private static void ReadXrefTableData(Lexer b, List<XrefEntry> table)
    {
        while (true)
        {
            var tok = b.ReadToken();
            if (tok is PdfKeyword { Value: "trailer" }) break;
            if (tok is not long start || b.ReadToken() is not long n)
                throw new PdfFormatException("malformed xref table");
            for (long i = 0; i < n; i++)
            {
                var offTok = b.ReadToken();
                var genTok = b.ReadToken();
                var allocTok = b.ReadToken();
                if (offTok is not long off || genTok is not long gen || allocTok is not PdfKeyword alloc ||
                    alloc.Value != "f" && alloc.Value != "n")
                    throw new PdfFormatException("malformed xref table");
                long xl = start + i;
                if (xl < 0 || xl > 1 << 23) throw new PdfFormatException("xref index out of range");
                int x = (int)xl;
                while (table.Count <= x) table.Add(default);
                if (alloc.Value == "n" && table[x].Offset == 0)
                    table[x] = new XrefEntry(new ObjPtr((uint)x, (ushort)gen), false, default, off);
            }
        }
    }

    /// <summary>Go Reader.resolve: заалтыг объект болгож, утгын Ptr-ийг (заалт бол объектын, эс бөгөөс эцгийн) тавина.</summary>
    public PdfValue Resolve(ObjPtr parent, object? x)
    {
        if (x is ObjPtr ptr)
        {
            if (ptr.Id >= (uint)_xref.Count) return default;
            var xr = _xref[(int)ptr.Id];
            if (xr.Ptr != ptr || !xr.InStream && xr.Offset == 0) return default;
            if (!_cache.TryGetValue(ptr, out var obj))
            {
                obj = xr.InStream ? LoadFromObjStm(parent, xr, ptr) : LoadDirect(xr, ptr);
                _cache[ptr] = obj;
            }
            x = obj;
            parent = ptr;
        }

        return x switch
        {
            null or bool or long or double or PdfName or PdfDict or PdfArray or PdfStream or PdfString => new PdfValue(this, parent, x),
            _ => throw new PdfFormatException("unexpected value type in resolve"),
        };
    }

    private object? LoadDirect(XrefEntry xr, ObjPtr ptr)
    {
        if (xr.Offset < 0 || xr.Offset >= _f.Length) throw new PdfFormatException("object offset out of range");
        var obj = new Lexer(_f, (int)xr.Offset, _f.Length).ReadObject();
        if (obj is not ObjDef def) throw new PdfFormatException($"loading {ptr.Id} {ptr.Gen} R: not an object definition");
        if (def.Ptr != ptr) throw new PdfFormatException($"loading {ptr.Id} {ptr.Gen} R: found {def.Ptr.Id} {def.Ptr.Gen}");
        return def.Obj;
    }

    private object? LoadFromObjStm(ObjPtr parent, XrefEntry xr, ObjPtr ptr)
    {
        var strm = Resolve(parent, xr.Stream);
        for (int guard = 0; guard < 64; guard++)
        {
            if (strm.Kind != PdfKind.Stream) throw new PdfFormatException("not a stream");
            if (strm.Key("Type").Name != "ObjStm") throw new PdfFormatException("not an object stream");
            long n = strm.Key("N").Int64;
            long first = strm.Key("First").Int64;
            if (first == 0) throw new PdfFormatException("missing First");
            if (strm.Data is not PdfStream objStm) throw new PdfFormatException("not a stream");
            // Толгойг нэг л удаа (хэрэгтэй хүртлээ) уншиж индекслэнэ (TS reader ObjStmIndex) — гишүүн бүрд толгойг эхнээс нь
            // уншвал n гишүүнтэй ObjStm-д O(n × өгөгдөл). Утга нь өмнөх давталттай ижил: эхний таарсан хос, бүхэл биш id/off → 0,
            // /N эсвэл EOF хүртэл; толгойн алдаа зөвхөн тэр хүртэл олдоогүй гишүүнд.
            if (!_objStms.TryGetValue(objStm.Ptr, out var ix))
            {
                ix = new ObjStmIndex(StreamBytes(strm, objStm, structural: true), n);
                if (objStm.Ptr != default) _objStms[objStm.Ptr] = ix;
            }
            if (ix.Lookup(ptr.Id) is { } off)
            {
                long at = first + off;
                if (at < 0 || at > ix.Data.Length) throw new PdfFormatException("object stream offset out of range");
                var b = new Lexer(ix.Data, 0, ix.Data.Length) { AllowEof = true };
                b.SeekForward((int)at);
                return b.ReadObject();
            }
            var ext = strm.Key("Extends");
            if (ext.Kind != PdfKind.Stream) throw new PdfFormatException("cannot find object in stream");
            strm = ext;
        }
        throw new PdfFormatException("object stream Extends loop");
    }

    /// <summary>
    /// Stream-ийн тайлсан агуулга (Go Value.Reader + io.ReadAll). structural — xref stream / ObjStm: олон шүүлтүүрийн гинжийг
    /// татгалзана (халдагч FlateDecode-ийг давхарлаж тайлалтыг өсгөхгүй).
    /// </summary>
    internal byte[] StreamBytes(PdfValue v, PdfStream s, bool structural = false)
    {
        if (_streamData.TryGetValue(s.Ptr, out var cached) && s.Ptr != default) return cached;
        byte[] raw = RawStreamBytes(v, s).ToArray();

        var filter = v.Key("Filter");
        var param = v.Key("DecodeParms");
        byte[] data = raw;
        switch (filter.Kind)
        {
            case PdfKind.Null:
                break;
            case PdfKind.Name:
                data = ApplyFilter(data, filter.Name, param);
                break;
            case PdfKind.Array:
                if (structural && filter.Len > 1) throw new PdfFormatException("multiple filters on a structural stream");
                for (int i = 0; i < filter.Len; i++) data = ApplyFilter(data, filter.Index(i).Name, param.Index(i));
                break;
            default:
                throw new PdfFormatException("unsupported filter");
        }
        if (s.Ptr != default) _streamData[s.Ptr] = data;
        return data;
    }

    /// <summary>Stream-ийн тайлаагүй өгөгдөл: «stream» EOL-ийн дараах /Length байт (файлын төгсгөлөөр тасална).</summary>
    internal ReadOnlySpan<byte> RawStreamBytes(PdfValue v, PdfStream s)
    {
        long len = v.Key("Length").Int64;
        long start = s.Offset;
        long avail = Math.Max(0, _f.Length - start);
        long n = Math.Clamp(len, 0, avail);
        return _f.AsSpan((int)start, (int)n);
    }

    private byte[] ApplyFilter(byte[] data, string name, PdfValue param)
    {
        if (name != "FlateDecode") throw new PdfFormatException("unknown filter " + name);
        byte[] inflated;
        try
        {
            using var zs = new ZLibStream(new MemoryStream(data), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            // TS reader zlibInflate-ийн 64 MiB хязгаар: халдагчийн PDF-ийн (жишээ нь xref stream) zip bomb санах ойг дүүргэхгүй.
            var buf = new byte[64 << 10];
            int n;
            while ((n = zs.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > MaxInflate || ms.Length > _inflateLeft) throw new PdfFormatException("zlib: output over limit");
            }
            inflated = ms.ToArray();
            _inflateLeft -= inflated.Length;
        }
        catch (InvalidDataException e)
        {
            throw new PdfFormatException("zlib: " + e.Message, e);
        }
        var pred = param.Key("Predictor");
        if (pred.Kind == PdfKind.Null) return inflated;
        if (pred.Int64 != 12 || pred.Kind != PdfKind.Integer) throw new PdfFormatException("unknown predictor");
        long columns = param.Key("Columns").Int64;
        if (columns < 0 || columns > 1 << 20) throw new PdfFormatException("bad Columns");
        int row = 1 + (int)columns;
        var hist = new byte[row];
        using var outMs = new MemoryStream();
        for (int p = 0; p + row <= inflated.Length; p += row)
        {
            if (inflated[p] != 2) throw new PdfFormatException("malformed PNG-Up encoding");
            for (int i = 0; i < row; i++) hist[i] += inflated[p + i];
            outMs.Write(hist, 1, row - 1);
        }
        if (inflated.Length % row != 0) throw new PdfFormatException("PNG-Up: partial row");
        return outMs.ToArray();
    }
}

/// <summary>
/// Нэг ObjStm-ийн задалсан өгөгдөл ба толгойн «дугаар offset» хосын индекс — хэрэгтэй хүртлээ л уншина (TS reader ObjStmIndex).
/// Толгойн лексерийн алдаа нь тэр байрлалаас хойшхи хосыг хайсан lookup бүрд дахин шидэгдэнэ (өмнөх давталттай ижил).
/// </summary>
internal sealed class ObjStmIndex
{
    private readonly Lexer _lx;
    private readonly long _n;
    private readonly Dictionary<uint, long> _offs = new();
    private long _read;
    private bool _done;
    private System.Runtime.ExceptionServices.ExceptionDispatchInfo? _err;

    public ObjStmIndex(byte[] data, long n)
    {
        Data = data;
        _n = n;
        _lx = new Lexer(data, 0, data.Length) { AllowEof = true };
    }

    public byte[] Data { get; }

    /// <summary>id-ийн эхний таарсан offset; толгойд алга бол null.</summary>
    public long? Lookup(uint id)
    {
        if (_offs.TryGetValue(id, out var hit)) return hit;
        _err?.Throw();
        while (!_done && _read < _n)
        {
            object? idTok, offTok;
            try
            {
                idTok = _lx.ReadToken();
                offTok = _lx.ReadToken();
            }
            catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
            {
                _err = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e);
                throw;
            }
            _read++;
            if (idTok == Lexer.Eof || offTok == Lexer.Eof)
            {
                _done = true; // /N нь stream-ээс урт — үлдсэн мөр байхгүй
                break;
            }
            uint idn = idTok is long a ? (uint)a : 0;
            long o = offTok is long b ? b : 0;
            _offs.TryAdd(idn, o);
            if (idn == id) return o;
        }
        return null;
    }
}
