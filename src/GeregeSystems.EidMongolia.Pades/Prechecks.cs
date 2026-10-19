using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>PRECHECKS.md (pades-client/1) — validator-гүй «хөнгөн» шалгуур, Go reference precheck.go-ийн дарааллаар.</summary>
internal static class Prechecks
{
    private const string OidTimeStampToken = "1.2.840.113549.1.9.16.2.14";

    internal sealed record SigDict(uint Obj, long[]? ByteRange, string SubFilter, string Type, string ContentsRaw);

    /// <summary>(шинэ баримт эсэх, энэ гарын үсгийн revIndex). Алдаа бол EidPadesException.</summary>
    public static (bool NewDoc, int RevIndex) Run(byte[] doc, IReadOnlyList<X509Certificate2> issuers)
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
        if (sigs.Count == 0) return (true, 1);
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
        return (false, sigs.Count + 1);
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
}
