using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>Placement — the visible stamp's final position (null for an invisible signature).</summary>
internal sealed record PreparedRevision(byte[] Pdf, long[] ByteRange, byte[] Digest, string FieldName, PlaceResult? Placement = null);

/// <summary>Go reference core/signature.go — гарын үсгийн revision (placeholder), CMS суулгах.</summary>
internal static class SignatureRevision
{
    /// <summary>Хэмжсэн дээд CMS (14 KiB) × 2 — /Contents-ийн тогтмол багтаамж (binary байт).</summary>
    public const int MeasuredMaxCms = 14 << 10;
    public const int PlaceholderBytes = 2 * MeasuredMaxCms;
    public const string SubFilter = "ETSI.CAdES.detached";
    public const int ReasonMaxUnits = 127;
    private const int ByteRangeWidth = 40;
    private const int MaxDepth = 32;

    /// <summary>
    /// vis өгсөн бол харагдах widget (APPEARANCE_SPEC.md): /Rect нь vis.Page хуудсан дээр, /F 4, /AP /N form XObject (+ 2
    /// фонт), widget тэр хуудасны /Annots-д. vis.Name нь /Name-тэй ижил (бичигдэх ёстой — эс бөгөөс AppearanceException).
    /// </summary>
    public static PreparedRevision Prepare(byte[] baseBytes, DateTimeOffset signingTime, string signerName, string reason, Visible? vis = null)
    {
        var inc = Incremental.Open(baseBytes);
        var root = inc.Root;
        var acro = root.Key("AcroForm");
        var fields = acro.Key("Fields");
        var names = new HashSet<string>(StringComparer.Ordinal);
        int sigFields = 0;
        for (int i = 0; i < fields.Len; i++)
        {
            var f = fields.Index(i);
            names.Add(f.Key("T").Text);
            if (f.Key("FT").Name == "Sig") sigFields++;
        }
        int k = sigFields + 1;
        while (names.Contains("Signature " + k.ToString(CultureInfo.InvariantCulture))) k++;
        var fieldName = "Signature " + k.ToString(CultureInfo.InvariantCulture);

        uint sigId = inc.Reserve(), fieldId = inc.Reserve(), catId = inc.Reserve();
        // харагдах: form, F1 ×5, F2 ×5, зураг бүрд 2 (APPEARANCE_SPEC.md §6.2)
        var apIds = new uint[vis is null ? 0 : SignatureAppearance.ObjectCount(vis.Sig, vis.Stamp)];
        for (int i = 0; i < apIds.Length; i++) apIds[i] = inc.Reserve();

        // ── Sig толь (placeholder) ──
        var sig = new MemoryStream();
        sig.Ascii("<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /" + SubFilter + "\n /ByteRange ");
        int brAt = (int)sig.Length;
        sig.Ascii(new string(' ', ByteRangeWidth));
        sig.Ascii("\n /Contents <");
        int contentsAt = (int)sig.Length - 1;
        sig.Write(Zeros(2 * PlaceholderBytes));
        sig.Ascii(">\n /M " + PdfDate(signingTime));
        var n = SigText(signerName, 120);
        if (n != "") sig.Ascii("\n /Name " + n);
        var r = SigText(reason, ReasonMaxUnits);
        if (r != "") sig.Ascii("\n /Reason " + r);
        sig.Ascii("\n>>");
        long sigStart = inc.WriteObject(sigId, sig.ToArray());

        // ── Талбар + widget ──
        PdfValue page;
        bool hasPage;
        PlaceResult? placed = null;
        if (vis is null)
        {
            // Үл харагдах (digitorus createVisualSignature, invisible): эхний хуудас.
            var fld = new MemoryStream();
            fld.Ascii("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n");
            (page, hasPage) = FirstPage(root.Key("Pages"), 0);
            if (hasPage) fld.Ascii(string.Create(CultureInfo.InvariantCulture, $"  /P {page.Ptr.Id} {page.Ptr.Gen} R\n"));
            fld.Ascii(string.Create(CultureInfo.InvariantCulture, $"  /F 132\n  /FT /Sig\n  /T ({fieldName})\n  /V {sigId} 0 R\n>>"));
            inc.WriteObject(fieldId, fld.ToArray());
        }
        else
        {
            if (n == "" || GoText.TrimSpace(signerName) != vis.Name) throw new AppearanceException("/Name бичигдэхгүй нэр");
            (page, hasPage) = SignatureAppearance.NthPage(root.Key("Pages"), vis.Page);
            if (!hasPage) throw new AppearanceException("хуудас " + vis.Page.ToString(CultureInfo.InvariantCulture) + " алга");
            var (box, rot) = SignatureAppearance.PageGeometry(page);
            var rect = SignatureAppearance.Rect(box, rot, vis.X, vis.Y, vis.W, vis.H);
            // PLACEMENT_SPEC.md: move off existing page content (Exact: only report it); the requested rect stays when
            // nothing is free.
            placed = StampPlacement.Choose(page, box, rot, vis.X, vis.Y, vis.W, vis.H, vis.Exact);
            if (placed.Status == PlacementStatus.Moved) rect = SignatureAppearance.Rect(box, rot, placed.X, placed.Y, vis.W, vis.H);
            var bodies = SignatureAppearance.Objects(new AppearanceParams(vis.W, vis.H, rot, vis.Name, vis.Role, vis.Lang, vis.Date, vis.Url, vis.Sig, vis.Stamp), apIds);
            inc.WriteObject(fieldId, SignatureAppearance.Widget(fieldName, rect, page.Ptr.Id, page.Ptr.Gen, sigId, apIds[0]));
            for (int i = 0; i < bodies.Length; i++) inc.WriteObject(apIds[i], bodies[i]);
        }
        if (hasPage) AddWidgetToPage(inc, page, fieldId);

        // ── Шинэ Catalog ──
        var cat = new MemoryStream();
        cat.Ascii("<<\n  /Type /Catalog\n");
        if (root.Key("Version").IsNull &&
            double.TryParse(inc.Doc.PdfVersion, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) && v < 1.5)
            cat.Ascii("  /Version /1.5\n");
        inc.CatalogCopy(cat, "AcroForm");
        cat.Ascii("  /AcroForm <<");
        if (acro.Kind == PdfKind.Dict)
        {
            var ap = acro.Ptr;
            foreach (var key in acro.Keys())
            {
                if (key is "Fields" or "SigFlags") continue;
                cat.Ascii(" /" + Serializer.EscapeName(key) + " ");
                Serializer.Serialize(cat, acro.Key(key), ap.Id, 0);
            }
        }
        cat.Ascii(" /Fields [");
        var fp = fields.Ptr;
        for (int i = 0; i < fields.Len; i++)
        {
            Serializer.Serialize(cat, fields.Index(i), fp.Id, 0);
            cat.Ascii(" ");
        }
        cat.Ascii(string.Create(CultureInfo.InvariantCulture, $"{fieldId} 0 R] /SigFlags 3 >>\n>>"));
        inc.WriteObject(catId, cat.ToArray());

        var doc = inc.Finish(catId);
        long a = sigStart + contentsAt;
        long b = a + 2L * PlaceholderBytes + 2;
        if (doc[a] != '<' || doc[b - 1] != '>') throw new InvalidOperationException("pades: placeholder position");
        var br = new[] { 0, a, b, doc.Length - b };
        var field = string.Create(CultureInfo.InvariantCulture, $"[{br[0]} {br[1]} {br[2]} {br[3]}]");
        if (field.Length > ByteRangeWidth) throw new InvalidOperationException("pades: ByteRange does not fit");
        Encoding.ASCII.GetBytes(field).CopyTo(doc, sigStart + brAt);
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(doc, 0, (int)a);
        h.AppendData(doc, (int)b, doc.Length - (int)b);
        return new PreparedRevision(doc, br, h.GetHashAndReset(), fieldName, placed);
    }

    private static byte[] Zeros(int n)
    {
        var z = new byte[n];
        Array.Fill(z, (byte)'0');
        return z;
    }

    /// <summary>placeholder-т CMS-ийг жижиг hex-ээр бичнэ; багтахгүй бол PLACEHOLDER_OVERFLOW (тайрахгүй).</summary>
    public static byte[] EmbedCms(byte[] prepared, long[] br, byte[] cms)
    {
        if (cms.Length == 0) throw new InvalidOperationException("pades: empty CMS");
        if (cms.Length > PlaceholderBytes) throw new EidPadesException("PLACEHOLDER_OVERFLOW", $"CMS {cms.Length} > {PlaceholderBytes} bytes");
        long a = br[1], b = br[2];
        if (br[0] != 0 || a <= 0 || b != a + 2L * PlaceholderBytes + 2 || b + br[3] != prepared.Length ||
            prepared[a] != '<' || prepared[b - 1] != '>')
            throw new InvalidOperationException("pades: ByteRange does not match the prepared document");
        for (long i = a + 1; i < b - 1; i++)
            if (prepared[i] != '0') throw new InvalidOperationException("pades: placeholder already filled");
        var outBytes = (byte[])prepared.Clone();
        var hex = Encoding.ASCII.GetBytes(Convert.ToHexString(cms).ToLowerInvariant());
        hex.CopyTo(outBytes, a + 1);
        return outBytes;
    }

    /// <summary>ByteRange-ийн заасан /Contents (hex тайлсан, тэг дүүргэлттэй) — DSS VRI түлхүүрт.</summary>
    public static byte[] SignatureContents(byte[] signed, long[] br)
    {
        long a = br[1], b = br[2];
        if (br[0] != 0 || a <= 0 || b <= a + 2 || b > signed.Length || signed[a] != '<' || signed[b - 1] != '>')
            throw new InvalidOperationException("pades: ByteRange does not point at /Contents");
        var hex = Encoding.ASCII.GetString(signed, (int)a + 1, (int)(b - a - 2));
        if (hex.Length % 2 != 0) throw new InvalidOperationException("pades: /Contents hex odd length");
        return Convert.FromHexString(hex);
    }

    private static void AddWidgetToPage(Incremental inc, PdfValue page, uint widget)
    {
        var pgp = page.Ptr;
        var annots = page.Key("Annots");
        if (!annots.IsNull && annots.Kind != PdfKind.Array) throw new PdfFormatException("pades: page /Annots is not an array");
        var ap = annots.Ptr;
        var arr = new MemoryStream();
        arr.Ascii("[");
        for (int i = 0; i < annots.Len; i++)
        {
            Serializer.Serialize(arr, annots.Index(i), ap.Id, 0);
            arr.Ascii(" ");
        }
        arr.Ascii(widget.ToString(CultureInfo.InvariantCulture) + " 0 R]");
        if (!annots.IsNull && ap != pgp)
        {
            inc.WriteObjectGen(ap.Id, ap.Gen, arr.ToArray());
            return;
        }
        var b = new MemoryStream();
        b.Ascii("<<");
        foreach (var key in page.Keys())
        {
            if (key == "Annots") continue;
            b.Ascii(" /" + Serializer.EscapeName(key) + " ");
            Serializer.Serialize(b, page.Key(key), pgp.Id, 0);
        }
        b.Ascii(" /Annots ");
        arr.Position = 0;
        arr.CopyTo(b);
        b.Ascii(" >>");
        inc.WriteObjectGen(pgp.Id, pgp.Gen, b.ToArray());
    }

    /// <summary>
    /// /Name, /Reason-ийн PDF text string (hex): ASCII бол шууд, эс бөгөөс BOM-той UTF-16BE. Удирдах тэмдэгт, maxUnits-ээс
    /// урт, PDF-ийн бүтцийн түлхүүр үг агуулсан эсвэл хоосон бол "" (бичихгүй).
    /// </summary>
    public static string SigText(string? s, int maxUnits)
    {
        s = GoText.TrimSpace(s ?? "");
        if (s == "" || !GoText.IsValidUtf16(s) || s.Length > maxUnits) return "";
        bool ascii = true;
        foreach (var rune in s.EnumerateRunes())
        {
            int r = rune.Value;
            if (r < 0x20 || r == 0x7f || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control) return "";
            if (r > 0x7e) ascii = false;
        }
        if (s.Contains(" obj", StringComparison.Ordinal) || s.Contains("endobj", StringComparison.Ordinal) ||
            s.Contains("stream", StringComparison.Ordinal) || s.Contains("xref", StringComparison.Ordinal) ||
            s.Contains("trailer", StringComparison.Ordinal) || s.Contains("%%EOF", StringComparison.Ordinal))
            return "";
        if (ascii) return Serializer.HexString(Encoding.ASCII.GetBytes(s));
        var raw = new byte[2 + 2 * s.Length];
        raw[0] = 0xfe;
        raw[1] = 0xff;
        for (int i = 0; i < s.Length; i++)
        {
            raw[2 + 2 * i] = (byte)(s[i] >> 8);
            raw[3 + 2 * i] = (byte)s[i];
        }
        return Serializer.HexString(raw);
    }

    private static (PdfValue Page, bool Ok) FirstPage(PdfValue v, int depth)
    {
        if (depth > MaxDepth) return (default, false);
        switch (v.Key("Type").Name)
        {
            case "Page":
                return (v, true);
            case "Pages":
                var kids = v.Key("Kids");
                for (int i = 0; i < kids.Len; i++)
                {
                    var (p, ok) = FirstPage(kids.Index(i), depth + 1);
                    if (ok) return (p, true);
                }
                break;
        }
        return (default, false);
    }

    /// <summary>"(D:YYYYMMDDHHmmSS+HH'mm')" — t-ийн өөрийн offset-оор.</summary>
    public static string PdfDate(DateTimeOffset t)
    {
        var off = t.Offset;
        char sign = '+';
        if (off < TimeSpan.Zero)
        {
            sign = '-';
            off = -off;
        }
        return string.Create(CultureInfo.InvariantCulture,
            $"(D:{t:yyyyMMddHHmmss}{sign}{off.Hours:00}'{off.Minutes:00}')");
    }
}

internal static class GoText
{
    /// <summary>Go strings.TrimSpace (Unicode White_Space).</summary>
    public static string TrimSpace(string s)
    {
        int st = 0, e = s.Length;
        while (st < e && IsSpace(s[st])) st++;
        while (e > st && IsSpace(s[e - 1])) e--;
        return s[st..e];
    }

    private static bool IsSpace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u0085' or '\u00a0' or '\u1680' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' ||
        c >= '\u2000' && c <= '\u200a';

    public static bool IsValidUtf16(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(s[i]))
            {
                return false;
            }
        }
        return true;
    }
}
