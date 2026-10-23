using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

// Харагдах гарын үсэг — APPEARANCE_SPEC.md (pades-client/1), Go reference core/appearance.go-ийн 1:1 порт.
// Widget нь сонгосон хуудсан дээр /Rect-тэй, /AP /N нь шахалтгүй form XObject (verify хуудасны фонт, өөрийн QR).
// Бүх урт/координат 1/100 pt-ийн БҮХЭЛ тоо (h100): бичихдээ Num100.

/// <summary>Харагдах гарын үсгийн байршил/хэмжээ/хуудас буруу эсвэл бичвэр багтахгүй (REQUEST_INVALID).</summary>
internal sealed class AppearanceException : Exception
{
    public AppearanceException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// SignatureRevision.Prepare-ийн харагдах оролт: байршил (харагдах хуудасны орон зайд, h100) ба бичвэр. Page — 1-ээс,
/// шийдэгдсэн (0 биш); Date — «YYYY-MM-DD HH:MM (+08)»; Url — https://ca.eidmongolia.mn/verify/&lt;docID&gt;/&lt;revIndex&gt;;
/// Exact — <c>appearance.exact</c> (PLACEMENT_SPEC.md §6a): never moved, the scan only sets the status.
/// </summary>
/// Sig, Stamp — the signature / organization-stamp images (APPEARANCE_SPEC.md §6; null = none). Stamp needs Role; W, H is
/// then the whole widget rect (box + the stamp's overflow above it).
internal sealed record Visible(int Page, long X, long Y, long W, long H, string Name, string Role, string Lang, string Date, string Url, bool Exact = false,
    ApImage? Sig = null, ApImage? Stamp = null);

/// <summary>
/// W, H — харагдах (эргүүлэлтийн дараах) өргөн, өндөр, h100; Rotate — 0 | 90 | 180 | 270; Sig, Stamp — APPEARANCE_SPEC.md §6
/// (null = none; both null = the §3 layout, byte-identical to golden v9).
/// </summary>
internal sealed record AppearanceParams(long W, long H, int Rotate, string Name, string Role, string Lang, string Date, string Url,
    ApImage? Sig = null, ApImage? Stamp = null);

/// <summary>
/// Go core.PDFImage (APPEARANCE_SPEC.md §6.1): one ink colour (3 bytes) + an 8-bit alpha channel. Alpha is a zlib stream
/// that inflates to exactly W·H bytes; it is written into the PDF verbatim as the /SMask stream — never compressed here.
/// </summary>
internal sealed record ApImage(int W, int H, int[] Color, byte[] Alpha);

internal static class SignatureAppearance
{
    private const long Pad = 400, Gap = 400, MinModule = 100;
    private const int MaxSize = 11, MinSize = 7, BodyDelta = 2, Leading = 125, Descent = 25, MaxLines = 2, MaxDepth = 32;

    /// <summary>Өргөн/өндрийн дээд хэмжээ (14400 pt), h100.</summary>
    public const long MaxSide = 1440000;

    private static readonly Dictionary<string, string> Labels = new(StringComparer.Ordinal)
    {
        ["mn"] = "eID Mongolia-аар зурсан",
        ["en"] = "Signed with eID Mongolia",
    };

    /// <summary>PDF image limits (APPEARANCE_SPEC.md §6.1).</summary>
    public const int MaxImageSide = 1600, MaxImageAlphaBytes = 300 << 10;

    /// <summary>
    /// Go core.CheckPDFImage (APPEARANCE_SPEC.md §6.1): 1 ≤ W, H ≤ 1600; colour 0–255; 1 ≤ len(Alpha) ≤ 300 KiB; Alpha is one
    /// zlib stream (Go compress/zlib semantics, valid Adler-32, no trailing bytes) inflating to exactly W·H bytes.
    /// </summary>
    public static void CheckImage(ApImage im)
    {
        if (im.W < 1 || im.H < 1 || im.W > MaxImageSide || im.H > MaxImageSide) throw new AppearanceException("зураг: хэмжээ 1…1600 px");
        if (im.Color is not { Length: 3 }) throw new AppearanceException("зураг: өнгө [r, g, b]");
        foreach (var c in im.Color)
            if (c is < 0 or > 255) throw new AppearanceException("зураг: өнгө 0…255");
        if (im.Alpha is null || im.Alpha.Length == 0 || im.Alpha.Length > MaxImageAlphaBytes) throw new AppearanceException("зураг: alpha 1 B…300 KiB");
        int want = im.W * im.H;
        var raw = ZlibStrict.Decode(im.Alpha, want, out int used);
        if (raw is null || raw.Length != want || used != im.Alpha.Length)
            throw new AppearanceException("зураг: alpha нь яг өргөн×өндөр байт биш (эсвэл эвдэрсэн)");
    }

    /// <summary>APPEARANCE_SPEC.md §6.3 geometry (h100): box height, QR/text row height, image placements [dx dy dw dh] (null = none).</summary>
    private sealed record ImageLayout(long BoxH, long RowH, long[]? Sig, long[]? Stamp);

    /// <summary>fit-contain (iw × ih px) into bw × bh (h100); the other side floor-scaled, at least 1.</summary>
    private static (long Dw, long Dh) Fit(long iw, long ih, long bw, long bh) =>
        iw * bh >= ih * bw ? (bw, Math.Max(1, bw * ih / iw)) : (Math.Max(1, bh * iw / ih), bh);

    private static ImageLayout LayoutImages(AppearanceParams p)
    {
        if (p.Sig is null && p.Stamp is null) return new ImageLayout(p.H, p.H, null, null);
        long boxH = p.Stamp is null ? p.H : p.H * 4 / 5;
        long band = boxH * 9 / 22;
        long rowH = boxH - band;
        long sh = band * 14 / 15, sy = rowH - band * 2 / 15;
        long sx = (p.W - p.W * 15 / 22) / 2, sw = p.W * 15 / 22;
        long[]? stamp = null, sig = null;
        if (p.Stamp is not null)
        {
            long d = boxH * 2 / 3;
            long qx = Math.Min(p.W * 41 / 60 - d / 2, p.W - d);
            if (qx < 0 || d <= 0) throw new AppearanceException("хэт жижиг (зурагтай дүрслэл)");
            var (dw, dh) = Fit(p.Stamp.W, p.Stamp.H, d, d);
            stamp = new[] { qx + (d - dw) / 2, p.H - d + (d - dh) / 2, dw, dh };
            sx = p.W / 30;
            sw = qx + d / 2 - sx;
        }
        if (p.Sig is not null)
        {
            if (sw <= 0 || sh <= 0) throw new AppearanceException("хэт жижиг (зурагтай дүрслэл)");
            var (dw, dh) = Fit(p.Sig.W, p.Sig.H, sw, sh);
            long dx = p.Stamp is null ? sx + (sw - dw) / 2 : sx;
            sig = new[] { dx, sy + (sh - dh) / 2, dw, dh };
        }
        return new ImageLayout(boxH, rowH, sig, stamp);
    }

    /// <summary>`q dw 0 0 dh dx dy cm /&lt;name&gt; Do Q` (APPEARANCE_SPEC.md §6.4).</summary>
    private static void DrawImage(VerifyPage.Writer w, string name, long[] r) =>
        w.Op("q " + Num100(r[2]) + " 0 0 " + Num100(r[3]) + " " + Num100(r[0]) + " " + Num100(r[1]) + " cm /" + name + " Do Q");

    /// <summary>pt → h100: floor(v × 100 + 0.5).</summary>
    public static long Round100(double v) => (long)Math.Floor(v * 100 + 0.5);

    /// <summary>h100 → PDF тоо: «N», «N.d», «N.dd» (төгсгөлийн тэггүй), сөрөгт «-».</summary>
    public static string Num100(long v)
    {
        var sign = "";
        if (v < 0)
        {
            sign = "-";
            v = -v;
        }
        var s = sign + (v / 100).ToString(CultureInfo.InvariantCulture);
        long f = v % 100;
        if (f != 0)
            s += f % 10 == 0 ? "." + (f / 10).ToString(CultureInfo.InvariantCulture) : "." + f.ToString("00", CultureInfo.InvariantCulture);
        return s;
    }

    private static (string Cm, long Bw, long Bh) Rotation(int rot, long w, long h) => rot switch
    {
        0 => ("", w, h),
        90 => ("0 1 -1 0 " + Num100(h) + " 0 cm", h, w),
        180 => ("-1 0 0 -1 " + Num100(w) + " " + Num100(h) + " cm", w, h),
        270 => ("0 -1 1 0 0 " + Num100(w) + " cm", h, w),
        _ => throw new AppearanceException("/Rotate " + rot.ToString(CultureInfo.InvariantCulture)),
    };

    private sealed record Line(int Font, int Size, string Color, string Text);

    /// <summary>Form XObject-ийн content stream (APPEARANCE_SPEC.md §3).</summary>
    public static byte[] Content(AppearanceParams p, PageFont reg, PageFont bld)
    {
        if (!Labels.TryGetValue(p.Lang, out var label)) throw new AppearanceException("хэл " + p.Lang);
        if (!VerifyPage.AsciiUrl(p.Url)) throw new AppearanceException("URL ASCII биш");
        if (p.W <= 0 || p.H <= 0 || p.W > MaxSide || p.H > MaxSide) throw new AppearanceException("хэмжээ");
        if (p.Stamp is not null && p.Role == "") throw new AppearanceException("тамгын зураг зөвхөн байгууллагын нэрийн өмнөөс (claimedRole)");
        if (p.Sig is not null) CheckImage(p.Sig);
        if (p.Stamp is not null) CheckImage(p.Stamp);
        var il = LayoutImages(p);
        long rowH = il.RowH;
        bool[][] m;
        try
        {
            m = Qr.Encode(Encoding.ASCII.GetBytes(p.Url));
        }
        catch (ArgumentException e)
        {
            throw new AppearanceException(e.Message, e);
        }
        int n = m.Length;
        long mod = (rowH - 2 * Pad) / n;
        if (mod < MinModule) throw new AppearanceException("хэт жижиг (өндөр ≥ " + Num100(2 * Pad + n * MinModule) + " pt)");
        long tx = Pad + mod * n + Gap;
        long tw = p.W - tx - Pad;
        var w = new VerifyPage.Writer(reg, bld);
        List<Line>? lines = null;
        for (int f = MaxSize; f >= MinSize && lines is null && tw > 0; f--) lines = Layout(w, p, label, f, tw, rowH);
        if (lines is null) throw new AppearanceException("хэт жижиг (бичвэр багтахгүй)");
        long total = 0;
        foreach (var l in lines) total += l.Size * Leading;
        var (cm, _, _) = Rotation(p.Rotate, p.W, p.H);
        w.Op("/EIDVerify <</URL (" + p.Url + ")>> BDC");
        if (cm != "")
        {
            w.Op("q");
            w.Op(cm);
        }
        w.Op(VerifyPage.ColOk + " RG");
        w.Op("1 w");
        w.Op("0.5 0.5 " + Num100(p.W - 100) + " " + Num100(il.BoxH - 100) + " re S");
        if (p.Sig is not null || p.Stamp is not null)
        {
            w.Op("0.5 w");
            w.Op("0 " + Num100(rowH) + " m " + Num100(p.W) + " " + Num100(rowH) + " l S");
        }
        if (il.Sig is not null) DrawImage(w, "Sig", il.Sig);
        w.Op("q " + Num100(mod) + " 0 0 " + Num100(mod) + " " + Num100(Pad) + " " + Num100((rowH - mod * n) / 2) + " cm");
        w.Op("0 0 0 rg");
        for (int r = 0; r < n; r++)
        {
            for (int c = 0; c < n;)
            {
                if (!m[r][c])
                {
                    c++;
                    continue;
                }
                int s = c;
                while (c < n && m[r][c]) c++;
                w.Op(string.Create(CultureInfo.InvariantCulture, $"{s} {n - 1 - r} {c - s} 1 re"));
            }
        }
        w.Op("f");
        w.Op("Q");
        long cursor = rowH - Pad - (rowH - 2 * Pad - total) / 2;
        foreach (var l in lines)
        {
            cursor -= l.Size * Leading;
            w.Op(l.Color + " rg");
            w.Op(string.Create(CultureInfo.InvariantCulture,
                $"BT /F{l.Font} {l.Size} Tf {Num100(tx)} {Num100(cursor + l.Size * Descent)} Td {w.GlyphHex(l.Font, l.Text)} Tj ET"));
        }
        if (il.Stamp is not null) DrawImage(w, "Stamp", il.Stamp);
        if (cm != "") w.Op("Q");
        w.Op("EMC");
        return Latin1.ToBytes(w.Ops.ToString());
    }

    private static List<Line>? Layout(VerifyPage.Writer w, AppearanceParams p, string label, int f, long tw, long rowH)
    {
        int b = f - BodyDelta;
        int limit = checked((int)(tw * 10)); // h100 → 1/1000 pt; tw ≤ 1440000
        var lines = new List<Line>();
        foreach (var t in w.WrapLimit(2, f, p.Name, limit, MaxLines)) lines.Add(new Line(2, f, VerifyPage.ColText, t));
        if (p.Role != "")
            foreach (var t in w.WrapLimit(1, b, p.Role, limit, MaxLines)) lines.Add(new Line(1, b, VerifyPage.ColText, t));
        lines.Add(new Line(1, b, VerifyPage.ColOk, label));
        lines.Add(new Line(1, b, VerifyPage.ColMuted, p.Date));
        long total = 0;
        foreach (var l in lines)
        {
            if (l.Text == "" || w.Width1000(l.Font, l.Size, l.Text) > limit) return null;
            total += l.Size * Leading;
        }
        return total > rowH - 2 * Pad ? null : lines;
    }

    /// <summary>The number of objects <see cref="Objects"/> writes: 11 (form, F1 ×5, F2 ×5) + 2 per image.</summary>
    public static int ObjectCount(ApImage? sig, ApImage? stamp) => 11 + (sig is null ? 0 : 2) + (stamp is null ? 0 : 2);

    /// <summary>
    /// /AP /N form XObject ба түүний 2 фонт (11 объект) + зураг бүрд 2 (APPEARANCE_SPEC.md §6.2): ids = [form, F1 ×5, F2 ×5,
    /// (Sig base, Sig mask), (Stamp base, Stamp mask)]. Буцаах нь объектын бие (ids-ийн дарааллаар).
    /// </summary>
    public static byte[][] Objects(AppearanceParams p, uint[] ids)
    {
        if (ids.Length != ObjectCount(p.Sig, p.Stamp)) throw new AppearanceException("объектын тоо");
        var reg = PageFont.Regular.Value;
        var bld = PageFont.Bold.Value;
        var (_, bw, bh) = Rotation(p.Rotate, p.W, p.H);
        var content = Content(p, reg, bld);
        var res = "/Font << /F1 " + ids[1].ToString(CultureInfo.InvariantCulture) + " 0 R /F2 " + ids[6].ToString(CultureInfo.InvariantCulture) + " 0 R >>";
        var imgs = new List<byte[]>();
        if (p.Sig is not null || p.Stamp is not null)
        {
            res += " /XObject <<";
            int next = 11;
            foreach (var (name, im) in new[] { ("Sig", p.Sig), ("Stamp", p.Stamp) })
            {
                if (im is null) continue;
                uint baseId = ids[next], maskId = ids[next + 1];
                next += 2;
                res += " /" + name + " " + baseId.ToString(CultureInfo.InvariantCulture) + " 0 R";
                imgs.Add(VerifyPage.StreamObj(" /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /SMask " +
                                              maskId.ToString(CultureInfo.InvariantCulture) + " 0 R",
                    new[] { (byte)im.Color[0], (byte)im.Color[1], (byte)im.Color[2] }));
                imgs.Add(VerifyPage.StreamObj(string.Create(CultureInfo.InvariantCulture,
                    $" /Type /XObject /Subtype /Image /Width {im.W} /Height {im.H} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode"), im.Alpha));
            }
            res += " >>";
        }
        var o = new List<byte[]>(ids.Length)
        {
            VerifyPage.StreamObj(" /Type /XObject /Subtype /Form /BBox [0 0 " + Num100(bw) + " " + Num100(bh) + "] /Resources << " + res + " >>", content),
        };
        o.AddRange(VerifyPage.FontBodies(ids[1..6], reg));
        o.AddRange(VerifyPage.FontBodies(ids[6..11], bld));
        o.AddRange(imgs);
        return o.ToArray();
    }

    /// <summary>Харагдах гарын үсгийн талбар/widget-ийн бие (APPEARANCE_SPEC.md §2). rect — хэрэглэгчийн орон зай (h100).</summary>
    public static byte[] Widget(string fieldName, long[] rect, uint pageId, ushort pageGen, uint sigId, uint formId) =>
        Encoding.ASCII.GetBytes(string.Create(CultureInfo.InvariantCulture,
            $"<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [{Num100(rect[0])} {Num100(rect[1])} {Num100(rect[2])} {Num100(rect[3])}]\n  /P {pageId} {pageGen} R\n  /F 4\n  /FT /Sig\n  /T ({fieldName})\n  /V {sigId} 0 R\n  /AP << /N {formId} 0 R >>\n>>"));

    /// <summary>Харагдах (x, y, w, h) → хэрэглэгчийн орон зайн /Rect (APPEARANCE_SPEC.md §1).</summary>
    public static long[] Rect(long[] box, int rot, long x, long y, long w, long h)
    {
        long bw = box[2] - box[0], bh = box[3] - box[1];
        var (vw, vh) = rot is 90 or 270 ? (bh, bw) : (bw, bh);
        if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > vw || y + h > vh)
            throw new AppearanceException("тэгш өнцөгт хуудасны (CropBox) гадна");
        (long, long) Pt(long vx, long vy) => rot switch
        {
            90 => (box[2] - vy, box[1] + vx),
            180 => (box[2] - vx, box[3] - vy),
            270 => (box[0] + vy, box[3] - vx),
            _ => (box[0] + vx, box[1] + vy),
        };
        var (x1, y1) = Pt(x, y);
        var (x2, y2) = Pt(x + w, y + h);
        return new[] { Math.Min(x1, x2), Math.Min(y1, y2), Math.Max(x1, x2), Math.Max(y1, y2) };
    }

    /// <summary>Хуудасны (удамшсан) CropBox (байхгүй бол MediaBox) h100-аар хэвийн болгосон ба /Rotate (0–270).</summary>
    public static (long[] Box, int Rot) PageGeometry(PdfValue page)
    {
        PdfValue Inh(string key)
        {
            var v = page;
            for (int i = 0; i < MaxDepth; i++)
            {
                var x = v.Key(key);
                if (!x.IsNull) return x;
                v = v.Key("Parent");
                if (v.Kind != PdfKind.Dict) break;
            }
            return default;
        }
        var b = Inh("CropBox");
        if (b.IsNull) b = Inh("MediaBox");
        if (b.Kind != PdfKind.Array || b.Len != 4) throw new AppearanceException("хуудасны MediaBox алга");
        var f = new long[4];
        for (int i = 0; i < 4; i++)
        {
            var e = b.Index(i);
            if (e.Kind is not (PdfKind.Integer or PdfKind.Real)) throw new AppearanceException("хуудасны хайрцаг буруу");
            double v = e.Float64;
            if (!double.IsFinite(v) || Math.Abs(v) > 1e7) throw new AppearanceException("хуудасны хайрцаг буруу");
            f[i] = Round100(v);
        }
        var box = new[] { Math.Min(f[0], f[2]), Math.Min(f[1], f[3]), Math.Max(f[0], f[2]), Math.Max(f[1], f[3]) };
        int rot = 0;
        var r = Inh("Rotate");
        if (!r.IsNull)
        {
            if (r.Kind != PdfKind.Integer || r.Int64 % 90 != 0) throw new AppearanceException("хуудасны /Rotate 90-ийн үржвэр биш");
            rot = (int)((r.Int64 % 360 + 360) % 360);
        }
        return (box, rot);
    }

    /// <summary>/Pages модны n дэх (1-ээс) /Page (модны дарааллаар, гүн ≤ 32).</summary>
    public static (PdfValue Page, bool Ok) NthPage(PdfValue root, int n)
    {
        if (n < 1) return (default, false);
        (PdfValue, bool) Walk(PdfValue v, int depth)
        {
            if (depth > MaxDepth) return (default, false);
            switch (v.Key("Type").Name)
            {
                case "Page":
                    n--;
                    return (v, n == 0);
                case "Pages":
                    var kids = v.Key("Kids");
                    for (int i = 0; i < kids.Len; i++)
                    {
                        var (p, ok) = Walk(kids.Index(i), depth + 1);
                        if (ok) return (p, true);
                        if (n <= 0) break;
                    }
                    break;
            }
            return (default, false);
        }
        return Walk(root, 0);
    }

    /// <summary>
    /// Go core.DefaultStampPage (PLACEMENT_SPEC.md §1a): <c>appearance.page</c> 0 үеийн хуудас — баримтын (модны
    /// дарааллаар) eID verify хуудас БИШ сүүлийн хуудас (1-ээс) ба хуудасны тоо. Verify хуудас = /Annots-д
    /// <c>/Subtype /Link</c>, <c>/A &lt;&lt; /S /URI /URI verifyUri &gt;&gt;</c> annotation-тай (байт-ижил). Бүх хуудас verify
    /// бол сүүлийнх. Хуудсыг уншиж чадахгүй бол агуулгын хуудас.
    /// </summary>
    public static (int Page, int N) DefaultStampPage(byte[] doc, string verifyUri)
    {
        var pages = PageList(Incremental.Open(doc).Root.Key("Pages"));
        int n = pages.Count;
        for (int i = n - 1; i >= 0; i--)
            if (!IsVerifyPage(pages[i], verifyUri)) return (i + 1, n);
        return (n, n);
    }

    /// <summary>Go core.pageList: /Page объектууд /Pages модны дарааллаар (гүн ≤ 32, хамгийн ихдээ 65 537).</summary>
    internal static List<PdfValue> PageList(PdfValue root)
    {
        var pages = new List<PdfValue>();
        void Walk(PdfValue v, int depth)
        {
            if (depth > MaxDepth || pages.Count > 1 << 16) return;
            switch (v.Key("Type").Name)
            {
                case "Page":
                    pages.Add(v);
                    break;
                case "Pages":
                    var kids = v.Key("Kids");
                    for (int i = 0; i < kids.Len; i++) Walk(kids.Index(i), depth + 1);
                    break;
            }
        }
        Walk(root, 0);
        return pages;
    }

    /// <summary>
    /// Go core.SuggestVisible (PLACEMENT_SPEC.md §6, §6b): the placement SignatureRevision.Prepare would choose, without
    /// writing anything. page 0 → the last page that is not a verify page of verifyUri ("" = none skipped → the last page);
    /// x, y, w, h in h100. The rect must lie inside the page (AppearanceException otherwise), exactly as for Prepare.
    /// Pages — the visible size (h100) of every page; null = that page's geometry is unreadable.
    /// </summary>
    public static (int Page, PlaceResult Placement, (long W, long H)?[] Pages) Suggest(byte[] doc, string verifyUri, int page, long x, long y,
        long w, long h, bool exact)
    {
        var pages = PageList(Incremental.Open(doc).Root.Key("Pages"));
        int n = pages.Count;
        if (page == 0)
        {
            page = n;
            for (int i = n - 1; verifyUri != "" && i >= 0; i--)
            {
                if (!IsVerifyPage(pages[i], verifyUri))
                {
                    page = i + 1;
                    break;
                }
            }
        }
        if (page < 1 || page > n)
            throw new AppearanceException(string.Create(CultureInfo.InvariantCulture, $"page {page} > хуудасны тоо {n}"));
        var sizes = new (long W, long H)?[n];
        for (int i = 0; i < n; i++)
        {
            try
            {
                var (b, r) = PageGeometry(pages[i]);
                long vw = b[2] - b[0], vh = b[3] - b[1];
                sizes[i] = r is 90 or 270 ? (vh, vw) : (vw, vh);
            }
            catch (AppearanceException)
            {
            }
        }
        var (box, rot) = PageGeometry(pages[page - 1]);
        Rect(box, rot, x, y, w, h);
        return (page, StampPlacement.Choose(pages[page - 1], box, rot, x, y, w, h, exact), sizes);
    }

    /// <summary>Go isVerifyPage-ийн уншиx /Annots-ийн дээд тоо (PLACEMENT_SPEC §3.7-тэй ижил).</summary>
    private const int MaxVerifyAnnots = 10000;

    /// <summary>Go isVerifyPage: хуудсын /Annots-д verifyUri руу заасан Link байгаа эсэх. Уншиж чадахгүй → false.</summary>
    internal static bool IsVerifyPage(PdfValue page, string verifyUri)
    {
        try
        {
            var annots = page.Key("Annots");
            if (annots.Kind != PdfKind.Array) return false;
            int m = Math.Min(annots.Len, MaxVerifyAnnots);
            for (int i = 0; i < m; i++)
            {
                var a = annots.Index(i);
                if (a.Kind != PdfKind.Dict || a.Key("Subtype").Name != "Link") continue;
                var act = a.Key("A");
                if (act.Kind == PdfKind.Dict && act.Key("S").Name == "URI" && act.Key("URI").Kind == PdfKind.String &&
                    string.Equals(act.Key("URI").RawString, verifyUri, StringComparison.Ordinal))
                    return true;
            }
        }
        catch (Exception e) when (Prechecks.IsParseError(e))
        {
        }
        return false;
    }

    /// <summary>Баримтын /Pages модны /Page объектын тоо (модыг тоолно, /Count-д итгэхгүй).</summary>
    public static int PageCount(byte[] doc)
    {
        var inc = Incremental.Open(doc);
        int n = 0;
        void Walk(PdfValue v, int depth)
        {
            if (depth > MaxDepth || n > 1 << 16) return;
            switch (v.Key("Type").Name)
            {
                case "Page":
                    n++;
                    break;
                case "Pages":
                    var kids = v.Key("Kids");
                    for (int i = 0; i < kids.Len; i++) Walk(kids.Index(i), depth + 1);
                    break;
            }
        }
        Walk(inc.Root.Key("Pages"), 0);
        return n;
    }
}
