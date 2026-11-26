using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>PRECHECKS.md (pades-client/1) — validator-гүй «хөнгөн» шалгуур, Go reference precheck.go-ийн дарааллаар.</summary>
internal static class Prechecks
{
    private const string OidTimeStampToken = "1.2.840.113549.1.9.16.2.14";

    internal sealed record SigDict(uint Obj, long[]? ByteRange, string SubFilter, string Type, string ContentsRaw);

    /// <summary>
    /// (шинэ баримт эсэх, энэ гарын үсгийн revIndex, шалгасан e-Seal гарын үсгүүд — Sig толины объектын дугаар → байрлал;
    /// APPEARANCE_SPEC.md §6.6 <see cref="DocIdFromStamps"/>). Алдаа бол EidPadesException (Go precheck).
    /// </summary>
    public static (bool NewDoc, int RevIndex, Dictionary<uint, int> Seals) Run(byte[] doc, IReadOnlyList<X509Certificate2> issuers)
    {
        if (Encrypted(doc)) throw new EidPadesException("PDF_ENCRYPTED", "encrypted PDF is not supported");
        List<SigDict> sigs;
        bool locked, hasDss;
        try
        {
            (sigs, locked, hasDss) = Scan(doc);
        }
        catch (Exception e) when (IsParseError(e))
        {
            throw new EidPadesException("PDF_INVALID", "not a PDF or damaged", e);
        }
        if (sigs.Count == 0) return (true, 1, new Dictionary<uint, int>());
        if (sigs.Count >= EidPades.MaxSignatures) throw new EidPadesException("PDF_TOO_MANY_SIGNATURES", "too many signatures");
        var leaves = new X509Certificate2[sigs.Count];
        var stamped = new bool[sigs.Count];
        for (int i = 0; i < sigs.Count; i++)
        {
            try
            {
                (leaves[i], stamped[i]) = CheckSignature(doc, sigs[i]);
            }
            catch (Exception e) when (e is FormatException or CryptographicException or AsnContentException or ArgumentException)
            {
                throw new EidPadesException("PDF_PRIOR_SIGNATURE_INVALID", "prior signature is invalid: " + e.Message, e);
            }
        }
        if (locked) throw new EidPadesException("PDF_LOCKED", "document is locked by a certification (DocMDP P=1) signature");
        for (int i = 0; i < sigs.Count; i++)
        {
            if (sigs[i].SubFilter != "ETSI.CAdES.detached" || !IssuedByAny(leaves[i], issuers) || !stamped[i] || !hasDss)
                throw new EidPadesException("PDF_FOREIGN_SIGNATURE", "document carries a signature that is not an eID signature");
        }
        return (false, sigs.Count + 1, StampSources(sigs, leaves));
    }

    /// <summary>
    /// APPEARANCE_SPEC.md §6.6 алхам 2.2-ийн эх (Go <c>stampSources</c>): шалгасан гарын үсгүүдээс ЗӨВХӨН e-Seal гэрчилгээтэй нь,
    /// Sig толины объектын дугаар → байрлал (1 + ByteRange[2]+[3] нь бага шалгасан гарын үсгийн тоо). Иргэний гарын үсэг хэзээ
    /// ч docId-ийн эх болохгүй.
    /// </summary>
    private static Dictionary<uint, int> StampSources(List<SigDict> sigs, X509Certificate2[] leaves)
    {
        var output = new Dictionary<uint, int>();
        for (int i = 0; i < sigs.Count; i++)
        {
            if (!EidPades.IsSealCertificate(leaves[i])) continue;
            var s = sigs[i].ByteRange!;
            int rev = 1;
            foreach (var o in sigs)
                if (o.ByteRange![2] + o.ByteRange[3] < s[2] + s[3]) rev++;
            output[sigs[i].Obj] = rev;
        }
        return output;
    }

    internal static bool IsParseError(Exception e) =>
        e is PdfFormatException or FormatException or IndexOutOfRangeException or ArgumentException or OverflowException or InvalidCastException
            or InvalidOperationException;

    public static bool Encrypted(byte[] doc)
    {
        PdfDocument r;
        try
        {
            r = PdfDocument.Open(doc);
        }
        catch (Exception e) when (IsParseError(e))
        {
            return Structure.EncryptRef.IsMatch(Latin1.FromBytes(doc));
        }
        try
        {
            return !r.Trailer.Key("Encrypt").IsNull;
        }
        catch (Exception e) when (IsParseError(e))
        {
            return false;
        }
    }

    /// <summary>Сүүлийн revision-ий xref-ээр хүрэх объект бүрээс /ByteRange ба /Contents бүхий толь (дугаараар), DocMDP P=1, /DSS.</summary>
    public static (List<SigDict> Sigs, bool Locked, bool HasDss) Scan(byte[] doc)
    {
        var r = PdfDocument.Open(doc);
        var root = r.Trailer.Key("Root");
        if (root.Kind != PdfKind.Dict) throw new PdfFormatException("Catalog missing");
        bool hasDss = root.Key("DSS").Kind == PdfKind.Dict;
        bool locked = DocMdpP1(root.Key("Perms").Key("DocMDP"));
        var sigs = new List<SigDict>();
        foreach (var x in r.Xref)
        {
            var v = r.Resolve(x.Ptr, x.Ptr);
            if (v.Kind != PdfKind.Dict || v.Key("ByteRange").IsNull || v.Key("Contents").IsNull) continue;
            var brv = v.Key("ByteRange");
            List<long>? br = new();
            for (int i = 0; i < brv.Len; i++)
            {
                var e = brv.Index(i);
                if (e.Kind != PdfKind.Integer)
                {
                    br = null;
                    break;
                }
                br.Add(e.Int64);
            }
            if (DocMdpP1(v)) locked = true;
            sigs.Add(new SigDict(x.Ptr.Id, br?.ToArray(), v.Key("SubFilter").Name, v.Key("Type").Name, v.Key("Contents").RawString));
        }
        sigs.Sort((a, b) => a.Obj.CompareTo(b.Obj));
        return (sigs, locked, hasDss);
    }

    private static bool DocMdpP1(PdfValue sig)
    {
        var refs = sig.Key("Reference");
        for (int i = 0; i < refs.Len; i++)
        {
            var e = refs.Index(i);
            var m = e.Key("TransformMethod");
            var p = e.Key("TransformParams").Key("P");
            if ((m.IsNull || m.Name == "DocMDP") && p.Kind == PdfKind.Integer && p.Int64 == 1) return true;
        }
        return false;
    }

    /// <summary>PRECHECKS #8: ByteRange, %%EOF, /Contents → CMS (signer ганц), криптограф шалгалт. (leaf, timestamp-тэй эсэх).</summary>
    public static (X509Certificate2 Leaf, bool Stamped) CheckSignature(byte[] doc, SigDict s)
    {
        var br = s.ByteRange;
        if (br is null || br.Length != 4 || br[0] != 0 || br[1] <= 0 || br[2] <= br[1] + 1 || br[3] < 0 || br[2] + br[3] > doc.Length)
            throw new FormatException("bad ByteRange");
        long a = br[1], b = br[2];
        if (doc[a] != '<' || doc[b - 1] != '>') throw new FormatException("ByteRange does not point at /Contents");
        int end = (int)(b + br[3]);
        while (end > 0 && (doc[end - 1] == '\r' || doc[end - 1] == '\n')) end--;
        if (end < 5 || !doc.AsSpan(end - 5, 5).SequenceEqual("%%EOF"u8)) throw new FormatException("ByteRange does not end at %%EOF");
        if ((b - a - 2) % 2 != 0) throw new FormatException("/Contents hex odd");
        var raw = Convert.FromHexString(Latin1.FromBytes(doc.AsSpan((int)a + 1, (int)(b - a - 2))));
        var der = FirstSequence(raw) ?? throw new FormatException("CMS is not DER");
        var signedBytes = new byte[a + br[3]];
        Array.Copy(doc, 0, signedBytes, 0, a);
        Array.Copy(doc, b, signedBytes, a, br[3]);
        var cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(der);
        if (cms.SignerInfos.Count != 1) throw new FormatException("CMS signer count is not 1");
        var si = cms.SignerInfos[0];
        var leaf = si.Certificate ?? throw new FormatException("signer certificate missing");
        si.CheckSignature(verifySignatureOnly: true);
        bool stamped = false;
        foreach (var at in si.UnsignedAttributes)
            stamped |= at.Oid?.Value == OidTimeStampToken;
        return (leaf, stamped);
    }

    /// <summary>Эхний ASN.1 SEQUENCE элемент (тэг дүүргэлт хаягдана).</summary>
    public static byte[]? FirstSequence(byte[] raw)
    {
        try
        {
            if (raw.Length == 0 || raw[0] != 0x30) return null;
            AsnDecoder.ReadEncodedValue(raw, AsnEncodingRules.BER, out _, out _, out int consumed);
            return raw.AsSpan(0, consumed).ToArray();
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static bool IssuedByAny(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> issuers)
    {
        foreach (var iss in issuers)
            if (leaf.IssuerName.RawData.AsSpan().SequenceEqual(iss.SubjectName.RawData) && X509Util.CheckSignatureFrom(leaf, iss)) return true;
        return false;
    }

    /// <summary>Гарын үсэгтэй баримтын docID: /Subtype /Link annotation-ийн /A /URI = verify URL + UUID (эхнийх).</summary>
    public static string DocIdFromPage(byte[] doc)
    {
        try
        {
            var r = PdfDocument.Open(doc);
            foreach (var x in r.Xref)
            {
                var v = r.Resolve(x.Ptr, x.Ptr);
                if (v.Kind != PdfKind.Dict || v.Key("Subtype").Name != "Link") continue;
                var u = v.Key("A").Key("URI").RawString;
                if (u.StartsWith(EidPades.PageVerifyUrl, StringComparison.Ordinal) && EidPades.IsUuid(u[EidPades.PageVerifyUrl.Length..]))
                    return u[EidPades.PageVerifyUrl.Length..];
            }
        }
        catch (Exception e) when (IsParseError(e))
        {
        }
        return "";
    }

    /// <summary>QR-тэй дардасны form stream-ийн эхний мөр (APPEARANCE_SPEC.md §5 алхам 6; Go <c>stampMarkerRe</c>): docId = 1-р бүлэг.</summary>
    private static readonly Regex StampMarker = new(
        @"^/EIDVerify <</URL \(https://ca\.eidmongolia\.mn/verify/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]?)\)>> BDC\n",
        RegexOptions.CultureInvariant);

    /// <summary>Маркерын мөрийн дээд урт (байт) — form stream-ээс уншина (Go <c>stampMarkerMax</c>).</summary>
    private const int StampMarkerMax = 128;

    /// <summary>
    /// Prepare-ийн docId дүрмийн 2.2-р алхам (APPEARANCE_SPEC.md §6.6; Go verify.go <c>docIDFromStamps</c>): шалгасан e-Seal
    /// гарын үсгүүдийн (<paramref name="seals"/> — Sig толины объектын дугаар → байрлал) хамгийн ЭРТ зурсан, /EIDVerify
    /// тэмдэгтэй дардасны docId. Widget = сүүлийн revision-ий xref-ийн толь, ӨӨРИЙН <c>/FT /Sig</c>, ӨӨРИЙН <c>/V</c> нь seals-ийн
    /// аль нэг толь руу ШУУД БУС лавлагаа. (1) e-Seal гарын үсэг бүрийн widget-ийг тоолно (/V-г resolve хийхгүй); (2) яг НЭГ
    /// widget-тэй гарын үсгийн дардсыг л уншина. <c>/AP</c> → толь, <c>/N</c> → stream, <c>/Filter</c> алга эсвэл ШУУД null;
    /// stream-ийн эхний ≤ 128 байт маркераар эхэлж, маркерын rev = тэр гарын үсгийн байрлал. Хамгийн бага ByteRange[2] +
    /// ByteRange[3] (тэнцвэл объектын дугаар бага). Алга → "". Ганц widget-тэй нэр дэвшигчийн уншилт бүтэлгүйтвэл алдаа
    /// (дуудагч PDF_INVALID); бусад уншигдахгүй объектыг алгасна.
    /// </summary>
    public static string DocIdFromStamps(byte[] doc, IReadOnlyDictionary<uint, int> seals)
    {
        if (seals.Count == 0) return "";
        var r = PdfDocument.Open(doc);
        var xr = r.Xref;
        var widgets = new Dictionary<uint, int>();
        var first = new Dictionary<uint, int>();
        for (int i = 0; i < xr.Count; i++)
        {
            var xp = xr[i].Ptr;
            PdfValue v;
            try
            {
                v = r.Resolve(xp, xp);
            }
            catch (Exception e) when (IsParseError(e))
            {
                continue;
            }
            // /V — ШУУД БУС лавлагаа (түүхий утга; resolve хийхгүй), xref-д бүртгэлтэй (дугаар + үе) e-Seal гарын үсэг рүү.
            if (v.Data is not PdfDict d || d.GetValueOrDefault("V") is not ObjPtr sp) continue;
            uint obj = sp.Id;
            if (!seals.ContainsKey(obj) || obj >= (uint)xr.Count || xr[(int)obj].Ptr != sp) continue;
            string ft;
            try
            {
                ft = v.Key("FT").Name;
            }
            catch (Exception e) when (IsParseError(e))
            {
                continue;
            }
            if (ft != "Sig") continue;
            widgets[obj] = widgets.GetValueOrDefault(obj) + 1;
            if (widgets[obj] == 1) first[obj] = i;
        }
        string id = "";
        long best = long.MaxValue;
        uint bestObj = 0;
        foreach (var (obj, n) in widgets)
        {
            if (n != 1) continue;
            var (docId, end) = ReadStamp(r, xr[first[obj]].Ptr, xr[(int)obj].Ptr, seals[obj]);
            if (docId == "" || end < 0) continue;
            if (end < best || end == best && obj < bestObj)
            {
                (best, bestObj, id) = (end, obj, docId);
            }
        }
        return id;
    }

    /// <summary>Ганц widget-тэй e-Seal гарын үсгийн дардасны маркерын docId ба ByteRange[2]+[3] (буруу бол -1; Go <c>readStamp</c>).</summary>
    private static (string DocId, long End) ReadStamp(PdfDocument r, ObjPtr widget, ObjPtr sig, int rev)
    {
        var w = r.Resolve(default, widget);
        var s = r.Resolve(default, sig);
        long end = -1;
        var br = s.Key("ByteRange");
        if (br.Len == 4 && br.Index(2).Kind == PdfKind.Integer && br.Index(3).Kind == PdfKind.Integer)
            end = br.Index(2).Int64 + br.Index(3).Int64;
        var ap = w.Key("AP");
        var n = ap.Key("N");
        if (ap.Kind != PdfKind.Dict || n.Kind != PdfKind.Stream) return ("", end);
        // /Filter: алга эсвэл ШУУД null л; шууд бус лавлагааны утга нь заасан объектын ptr-тэй, шууд утга нь stream-ийнхтэй.
        var f = n.Key("Filter");
        if (!f.IsNull || f.Ptr != n.Ptr) return ("", end);
        _ = n.Key("DecodeParms");
        var raw = n.RawStreamBytes();
        var head = Latin1.FromBytes(raw[..Math.Min(raw.Length, StampMarkerMax)]);
        var m = StampMarker.Match(head);
        if (m.Success && m.Groups[2].Value == rev.ToString(CultureInfo.InvariantCulture)) return (m.Groups[1].Value, end);
        return ("", end);
    }
}
