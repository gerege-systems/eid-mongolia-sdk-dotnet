using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>
/// Нэг incremental update (revision) бичигч — Go reference core/incremental.go. base-ийн байт өөрчлөгдөхгүй: гаралт =
/// base + "\n" + шинэ объектууд + xref + trailer. Xref stream-ийг ШАХАЛТГҮЙ бичнэ (/Filter-гүй — хэл хоорондын байт
/// ижил байдлын шийдвэр, 2026-10-14).
/// </summary>
internal sealed class Incremental
{
    private readonly record struct Entry(uint Id, ushort Gen, long Offset);

    private readonly List<Entry> _entries = new();
    private uint _nextId;

    public PdfDocument Doc { get; }

    public MemoryStream Out { get; }

    public bool IsStream { get; }

    private Incremental(PdfDocument doc, bool stream, uint nextId, byte[] baseBytes)
    {
        Doc = doc;
        IsStream = stream;
        _nextId = nextId;
        Out = new MemoryStream(baseBytes.Length + (64 << 10));
        Out.Write(baseBytes);
        Out.WriteByte((byte)'\n');
    }

    public static Incremental Open(byte[] baseBytes)
    {
        PdfDocument doc;
        try
        {
            doc = PdfDocument.Open(baseBytes);
        }
        catch (PdfFormatException)
        {
            throw;
        }
        catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException or OverflowException or InvalidCastException)
        {
            throw new PdfFormatException("pades: PDF parse: " + e.Message, e);
        }
        if (!doc.Trailer.Key("Encrypt").IsNull) throw new PdfFormatException("pades: encrypted PDF");
        if (doc.Trailer.Key("Root").Kind != PdfKind.Dict) throw new PdfFormatException("pades: Catalog missing");
        bool stream = doc.XrefType switch
        {
            "table" => false,
            "stream" => true,
            _ => throw new PdfFormatException("pades: xref type"),
        };
        uint maxId = 0;
        foreach (var x in doc.Xref)
            if (x.Ptr.Id > maxId) maxId = x.Ptr.Id;
        long size = doc.Trailer.Key("Size").Int64;
        if (size <= 0 || size > 1 << 23) throw new PdfFormatException("pades: bad /Size");
        return new Incremental(doc, stream, Math.Max((uint)size, maxId + 1), baseBytes);
    }

    public uint Reserve() => _nextId++;

    public long WriteObject(uint id, byte[] body) => WriteObjectGen(id, 0, body);

    /// <summary>Объект бичиж xref-д бүртгэнэ; body-ийн эхлэх байрлалыг буцаана.</summary>
    public long WriteObjectGen(uint id, ushort gen, byte[] body)
    {
        Out.WriteByte((byte)'\n');
        _entries.Add(new Entry(id, gen, Out.Length));
        Out.Ascii(id.ToString(CultureInfo.InvariantCulture) + " " + gen.ToString(CultureInfo.InvariantCulture) + " obj\n");
        long start = Out.Length;
        Out.Write(TrimSpace(body));
        Out.Ascii("\nendobj\n");
        return start;
    }

    public (uint Id, long Start) AddObject(byte[] body)
    {
        var id = Reserve();
        return (id, WriteObject(id, body));
    }

    /// <summary>Go bytes.TrimSpace (ASCII зай: \t \n \v \f \r, зай, U+0085, U+00A0 — ASCII биелд хангалттай).</summary>
    private static ReadOnlySpan<byte> TrimSpace(byte[] b)
    {
        int s = 0, e = b.Length;
        while (s < e && IsAsciiSpace(b[s])) s++;
        while (e > s && IsAsciiSpace(b[e - 1])) e--;
        return b.AsSpan(s, e - s);
    }

    private static bool IsAsciiSpace(byte c) => c is (byte)'\t' or (byte)'\n' or 0x0b or (byte)'\f' or (byte)'\r' or (byte)' ';

    public PdfValue Root => Doc.Trailer.Key("Root");

    /// <summary>Catalog-ийн skip-ээс бусад түлхүүрийг "  /Key value\n" хэлбэрээр.</summary>
    public void CatalogCopy(MemoryStream w, params string[] skip)
    {
        var root = Root;
        var rp = root.Ptr;
        foreach (var key in root.Keys())
        {
            if (key == "Type" || Array.IndexOf(skip, key) >= 0) continue;
            w.Ascii("  /" + Serializer.EscapeName(key) + " ");
            Serializer.Serialize(w, root.Key(key), rp.Id, 0);
            w.Ascii("\n");
        }
    }

    /// <summary>xref (base-тэй ижил төрөл) + trailer бичиж гаралтыг буцаана.</summary>
    public byte[] Finish(uint root)
    {
        if (_entries.Count == 0) throw new InvalidOperationException("pades: no new objects");
        Out.WriteByte((byte)'\n');
        long xrefStart = Out.Length;
        uint xid = 0;
        if (IsStream)
        {
            xid = Reserve();
            _entries.Add(new Entry(xid, 0, xrefStart));
        }
        _entries.Sort((a, b) => a.Id.CompareTo(b.Id));
        var runs = new List<(int Start, int Count)>();
        for (int i = 0; i < _entries.Count; i++)
        {
            var e = _entries[i];
            if (i > 0 && e.Id == _entries[i - 1].Id) throw new InvalidOperationException("pades: duplicate object number");
            if (i > 0 && e.Id == _entries[i - 1].Id + 1)
            {
                runs[^1] = (runs[^1].Start, runs[^1].Count + 1);
                continue;
            }
            runs.Add((i, 1));
        }
        long prev = Doc.XrefStartPos;
        var tr = Doc.Trailer;
        var extra = new StringBuilder();
        var info = tr.Key("Info");
        if (!info.IsNull)
        {
            if (info.Ptr == tr.Ptr)
            {
                extra.Append(" /Info ").Append(Serializer.SerializeToString(info, tr.Ptr.Id));
            }
            else
            {
                extra.Append(CultureInfo.InvariantCulture, $" /Info {info.Ptr.Id} {info.Ptr.Gen} R");
            }
        }
        var id = tr.Key("ID");
        if (id.Kind == PdfKind.Array && id.Len == 2)
        {
            extra.Append(" /ID [").Append(Serializer.HexString(id.Index(0).RawString)).Append(' ')
                .Append(Serializer.HexString(id.Index(1).RawString)).Append(']');
        }

        if (!IsStream)
        {
            Out.Ascii("xref\n");
            foreach (var (s, n) in runs)
            {
                Out.Ascii(_entries[s].Id.ToString(CultureInfo.InvariantCulture) + " " + n.ToString(CultureInfo.InvariantCulture) + "\n");
                for (int i = s; i < s + n; i++)
                    Out.Ascii(_entries[i].Offset.ToString("D10", CultureInfo.InvariantCulture) + " " +
                              _entries[i].Gen.ToString("D5", CultureInfo.InvariantCulture) + " n\r\n");
            }
            Out.Ascii(string.Create(CultureInfo.InvariantCulture,
                $"trailer\n<< /Size {_nextId} /Root {root} 0 R{extra} /Prev {prev} >>\nstartxref\n{xrefStart}\n%%EOF\n"));
            return Out.ToArray();
        }

        // Xref stream (шахалтгүй): мөр бүр [1 4 1]; /Size = xid + 1.
        var rows = new MemoryStream();
        foreach (var e in _entries)
        {
            if (e.Offset > uint.MaxValue) throw new InvalidOperationException("pades: offset does not fit 4 bytes");
            if (e.Gen > 0xff) throw new InvalidOperationException("pades: generation does not fit 1 byte");
            rows.WriteByte(1);
            uint off = (uint)e.Offset;
            rows.WriteByte((byte)(off >> 24));
            rows.WriteByte((byte)(off >> 16));
            rows.WriteByte((byte)(off >> 8));
            rows.WriteByte((byte)off);
            rows.WriteByte((byte)e.Gen);
        }
        var index = new StringBuilder();
        for (int i = 0; i < runs.Count; i++)
        {
            if (i > 0) index.Append(' ');
            index.Append(CultureInfo.InvariantCulture, $"{_entries[runs[i].Start].Id} {runs[i].Count}");
        }
        Out.Ascii(string.Create(CultureInfo.InvariantCulture,
            $"{xid} 0 obj\n<< /Type /XRef /Length {rows.Length} /W [1 4 1] /Prev {prev} /Size {_nextId} /Index [{index}] /Root {root} 0 R{extra} >>\nstream\n"));
        rows.Position = 0;
        rows.CopyTo(Out);
        Out.Ascii(string.Create(CultureInfo.InvariantCulture, $"\nendstream\nendobj\nstartxref\n{xrefStart}\n%%EOF\n"));
        return Out.ToArray();
    }
}
