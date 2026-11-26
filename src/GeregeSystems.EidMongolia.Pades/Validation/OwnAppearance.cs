using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades.Validation;

/// <summary>
/// Харагдах гарын үсгийн own-signer хэлбэр (APPEARANCE_SPEC.md §5 Validator) — TS SDK src/pades/validate/appearance.ts (Go
/// pades/internal/validate/appearance.go)-ийн порт. PAdES бичигчийн харагдах widget, /AP /N form XObject ба 2 фонтыг (11
/// объект) гарын үсгийн өөрийн өгөгдлөөс (/Name, /M, claimedRole, revIndex, docID) энэ SDK-ийн бичигчийн кодоор
/// (<see cref="SignatureAppearance"/>) ДАХИН ҮҮСГЭЖ, задалсан объект бүрийг бүтцээр (толь + stream-ийн түүхий байт) тулгана.
/// </summary>
internal static class OwnAppearance
{
    public const string VerifyPrefix = "https://ca.eidmongolia.mn/verify/";

    /// <summary>/EIDVerify BDC мөрийн эхний 10 байт: e-Seal-ийн form stream-д QR-тэй тамгыг сонгоно (§6.3).</summary>
    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("/EIDVerify");

    private static readonly Regex UrlRe = new(
        @"^/EIDVerify <</URL \(https://ca\.eidmongolia\.mn/verify/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]?)\)>> BDC\n",
        RegexOptions.CultureInvariant);

    private static PdfObjException Fail() => Classifier.NotSignatureOnly();

    /// <summary>own горимын харагдах widget d (объект widget): widget ба /AP-ийн 11 объект яг PAdES бичигчийнх.</summary>
    public static void OwnVisible(Classifier c, Dictionary<string, object?> d, int widget)
    {
        if (!Classifier.OnlyKeys(d, "Type", "Subtype", "Rect", "P", "F", "FT", "T", "V", "AP")) throw Fail();
        var pr0 = P.Get(d, "P");
        var sr0 = P.Get(d, "V");
        var ap0 = P.Get(d, "AP");
        var t0 = P.Get(d, "T");
        if (pr0 is not PRef pr || sr0 is not PRef sr || ap0 is not Dictionary<string, object?> ap || t0 is not PStr t || !Classifier.OnlyKeys(ap, "N") ||
            !c.Pages.Contains(pr.Num))
            throw Fail();
        if (P.Get(ap, "N") is not PRef nr) throw Fail();
        var (box, rot) = PageGeometry(c, pr.Num);
        if (P.Get(d, "Rect") is not List<object?> ra || ra.Count != 4) throw Fail();
        var rect = new long[4];
        for (int i = 0; i < 4; i++)
        {
            var v = PdfNumber(ra[i]) ?? throw Fail();
            rect[i] = SignatureAppearance.Round100(v);
        }
        if (rect[0] >= rect[2] || rect[1] >= rect[3] || rect[0] < box[0] || rect[1] < box[1] || rect[2] > box[2] || rect[3] > box[3]) throw Fail();
        long w = rect[2] - rect[0];
        long h = rect[3] - rect[1];
        if (rot == 90 || rot == 270) (w, h) = (h, w);
        SameObject(c, widget, Latin1.ToBytes(VisibleWidget(t.V, rect, pr.Num, pr.Gen, sr.Num, nr.Num)));
        var sd = c.Fin.Deref(sr);
        if (sd is not Dictionary<string, object?> sdd || !c.Sigs.TryGetValue(sr.Num, out var meta) || !meta.RoleOk) throw Fail();
        var ns0 = P.Get(sdd, "Name");
        var ms0 = P.Get(sdd, "M");
        // Sig dict-ийн шалгалт OwnTextLimit-ээс урт /Name-ийг ямар ч байсан татгалзана; энд эрт татгалзсанаар олон мегабайтын
        // нэр доорх (квадрат) мөр хуваалтад орохгүй.
        if (ns0 is not PStr ns || ms0 is not PStr ms || ns.V.Length > Classifier.OwnTextLimit) throw Fail();
        var m = ms.V;
        if (!OwnText.OwnDate(m) || m.Substring(16) != "+08'00'") throw Fail();
        var date = m.Substring(2, 4) + "-" + m.Substring(6, 2) + "-" + m.Substring(8, 2) + " " + m.Substring(10, 2) + ":" + m.Substring(12, 2) + " (+08)";
        var ids = ApIds(c, nr);
        if (c.Fin.Get(ids[0]) is not PStream form) throw Fail();
        // Гэрчилгээ хувилбарыг сонгоно (§6.1/§6.3): иргэн → иргэний дардас (/EIDVerify мөр заавал); e-Seal → тамга, хадгалсан
        // stream-ийн өгөгдөл (тайлахгүй) /EIDVerify-ээр эхэлбэл QR-тэй (§6.5), эс бөгөөс QR-гүй (§6.2). Нэг хувилбар унавал нөгөөг
        // оролдохгүй.
        bool seal = meta.Seal;
        string role = "", url = "";
        if (!seal || form.Data.Span.StartsWith(Marker))
        {
            var head = Latin1.FromBytes(form.Data.Span[..Math.Min(form.Data.Length, 200)]);
            var sm = UrlRe.Match(head);
            if (!sm.Success || sm.Groups[2].Value != meta.RevIndex.ToString(CultureInfo.InvariantCulture) || (c.DocId != "" && sm.Groups[1].Value != c.DocId))
                throw Fail();
            if (!seal) role = meta.Role;
            url = VerifyPrefix + sm.Groups[1].Value + "/" + sm.Groups[2].Value;
        }
        var name = OwnText.PdfTextString(ns);
        var uids = new uint[ids.Length];
        for (int i = 0; i < ids.Length; i++) uids[i] = (uint)ids[i];
        foreach (var lang in new[] { "mn", "en" })
        {
            byte[][] bodies;
            try
            {
                bodies = SignatureAppearance.Objects(new AppearanceParams(w, h, rot, name, role, lang, date, url, seal), uids, sealQr: seal && url != "");
            }
            catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
            {
                throw Fail();
            }
            bool match = true;
            for (int i = 0; i < bodies.Length; i++)
            {
                try
                {
                    SameObject(c, ids[i], bodies[i]);
                }
                catch (PdfObjException)
                {
                    match = false;
                    break;
                }
            }
            if (match) return;
        }
        throw Fail();
    }

    /// <summary>TS visibleWidget (latin1): харагдах гарын үсгийн талбар/widget-ийн бие (APPEARANCE_SPEC.md §2).</summary>
    private static string VisibleWidget(string fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId) =>
        "<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [" + SignatureAppearance.Num100(rect[0]) + " " + SignatureAppearance.Num100(rect[1]) + " " +
        SignatureAppearance.Num100(rect[2]) + " " + SignatureAppearance.Num100(rect[3]) + "]\n  /P " + pageId.ToString(CultureInfo.InvariantCulture) + " " +
        pageGen.ToString(CultureInfo.InvariantCulture) + " R\n  /F 4\n  /FT /Sig\n  /T (" + fieldName + ")\n  /V " + sigId.ToString(CultureInfo.InvariantCulture) +
        " 0 R\n  /AP << /N " + formId.ToString(CultureInfo.InvariantCulture) + " 0 R >>\n>>";

    /// <summary>/AP /N-ээс 11 объектын дугаар (Objects-ийн дарааллаар); бүгд шинэ, үе 0, давхардалгүй.</summary>
    private static int[] ApIds(Classifier c, PRef n)
    {
        var refs = new List<PRef> { n };
        Dictionary<string, object?> Get(PRef r)
        {
            var o = c.Fin.Deref(r);
            if (o is Dictionary<string, object?> d) return d;
            if (o is PStream s) return s.Dict;
            throw Fail();
        }
        var form = Get(n);
        var res = P.Get(form, "Resources");
        var fonts = P.Get(res as Dictionary<string, object?>, "Font");
        foreach (var key in new[] { "F1", "F2" })
        {
            if (P.Get(fonts as Dictionary<string, object?>, key) is not PRef t0) throw Fail();
            var td = Get(t0);
            var desc = P.Get(td, "DescendantFonts");
            var tu = P.Get(td, "ToUnicode");
            if ((desc is List<object?> dl ? dl.Count : 0) != 1 || tu is not PRef tur) throw Fail();
            if (((List<object?>)desc!)[0] is not PRef cid) throw Fail();
            var cd = Get(cid);
            if (P.Get(cd, "FontDescriptor") is not PRef fd) throw Fail();
            var fdd = Get(fd);
            if (P.Get(fdd, "FontFile2") is not PRef ff) throw Fail();
            refs.AddRange(new[] { t0, cid, fd, ff, tur });
        }
        var seen = new HashSet<int>();
        var ids = new int[refs.Count];
        for (int i = 0; i < refs.Count; i++)
        {
            var r = refs[i];
            if (r.Gen != 0 || !c.IsNew.Contains(r.Num) || seen.Contains(r.Num)) throw Fail();
            seen.Add(r.Num);
            ids[i] = r.Num;
        }
        return ids;
    }

    private static bool IsSpaceByte(byte x) => x == 9 || x == 10 || x == 11 || x == 12 || x == 13 || x == 32;

    /// <summary>num объект нь body-г (PAdES бичигчийн бие) задалсантай бүтцээрээ тэнцүү.</summary>
    private static void SameObject(Classifier c, int num, byte[] body)
    {
        int s = 0, e = body.Length;
        while (s < e && IsSpaceByte(body[s])) s++;
        while (e > s && IsSpaceByte(body[e - 1])) e--;
        var pre = Latin1.ToBytes(num.ToString(CultureInfo.InvariantCulture) + " 0 obj\n");
        var post = Latin1.ToBytes("\nendobj\n");
        var src = new byte[pre.Length + (e - s) + post.Length];
        pre.CopyTo(src, 0);
        Array.Copy(body, s, src, pre.Length, e - s);
        post.CopyTo(src, pre.Length + (e - s));
        var p = new PdfParser(src, src.Length, 0, c.Fin.Budget);
        var want = p.Indirect(null);
        var got = c.Fin.Get(num);
        if (!P.PdfEqual(got, want.Val)) throw Fail();
    }

    /// <summary>Хуудасны (/Parent-ээр удамшсан) CropBox (байхгүй бол MediaBox), h100-аар, ба /Rotate.</summary>
    private static (long[] Box, int Rot) PageGeometry(Classifier c, int num)
    {
        object? Inh(string key)
        {
            object? cur = new PRef(num, 0);
            for (int i = 0; i < 32; i++)
            {
                if (cur is not PRef cr) return null;
                if (c.Fin.Get(cr.Num) is not Dictionary<string, object?> o) throw Fail();
                if (o.ContainsKey(key)) return c.Fin.Resolve(P.Get(o, key));
                cur = P.Get(o, "Parent");
            }
            throw Fail();
        }
        var b = Inh("CropBox") ?? Inh("MediaBox");
        if (b is not List<object?> bl || bl.Count != 4) throw Fail();
        var f = new long[4];
        for (int i = 0; i < 4; i++) f[i] = SignatureAppearance.Round100(PdfNumber(bl[i]) ?? throw Fail());
        var box = new[] { Math.Min(f[0], f[2]), Math.Min(f[1], f[3]), Math.Max(f[0], f[2]), Math.Max(f[1], f[3]) };
        int rot = 0;
        var r = Inh("Rotate");
        if (r is not null)
        {
            if (r is not long rl || rl % 90 != 0) throw Fail();
            rot = (int)(((rl % 360) + 360) % 360);
        }
        return (box, rot);
    }

    /// <summary>Бүхэл эсвэл бодит тоо (|v| ≤ 1e7).</summary>
    private static double? PdfNumber(object? x)
    {
        double v;
        if (x is long l) v = l;
        else if (x is PReal r) v = r.V;
        else return null;
        return !double.IsNaN(v) && Math.Abs(v) <= 1e7 ? v : null;
    }
}
