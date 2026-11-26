using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Text;
using System.Threading;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades.Validation;

/// <summary>Задлах үе шатны алдаа (TS ExtractError): not_pdf, encrypted, no_signature, too_many, structure.</summary>
internal sealed class ExtractException : Exception
{
    public ExtractException(string code, Exception? inner = null) : base(code, inner)
    {
        Code = code;
    }

    public string Code { get; }
}

internal sealed class RawTimestamp
{
    public GoTime Time = GoTime.Zero;
    public string Serial = "";
    public bool Matches;
    public bool WeakDigest;
    public byte[]? TsaCert;
    public List<byte[]> Certs = new();
}

internal sealed class RawDss
{
    public List<byte[]> Certs = new();
    public List<byte[]> Ocsps = new();
    public List<byte[]> Crls = new();

    // Баримт бүрт OCSP/CRL-ийг нэг удаа задалж, (нотолгоо, гэрчилгээ, олгогч) бүрийн гарын үсгийн шалгалтыг нэг удаа хийнэ —
    // олон гарын үсэг × гинж × DSS-ийн зүйлийн давталтаар ажлыг өсгөхгүй.
    private List<ValCrl?>? _crls;
    private readonly Dictionary<(int, string, string), ValOcspResp?> _plain = new();
    private readonly Dictionary<(int, string, string), ValOcspResp?> _for = new();
    private readonly Dictionary<(int, string, string), bool> _crlFor = new();

    public ValCrl? Crl(int i)
    {
        _crls ??= Crls.ConvertAll(ValRevocation.ParseCrl);
        return _crls[i];
    }

    /// <summary>ParseOcsp(der, cert.serial, issuer) эсвэл задрахгүй бол null (LTV хамралт).</summary>
    public ValOcspResp? OcspPlain(int i, ValCert cert, ValCert issuer)
    {
        var key = (i, cert.Id, issuer.Id);
        if (_plain.TryGetValue(key, out var hit)) return hit;
        ValOcspResp? r;
        try
        {
            r = ValRevocation.ParseOcsp(Ocsps[i], cert.SerialValue, issuer);
        }
        catch (Exception e) when (ValRevocation.IsParse(e))
        {
            r = null;
        }
        _plain[key] = r;
        return r;
    }

    /// <summary>DssStatus.OcspFor-ийн кэштэй хувилбар.</summary>
    public ValOcspResp? OcspFor(int i, ValCert cert, ValCert issuer)
    {
        var key = (i, cert.Id, issuer.Id);
        if (_for.TryGetValue(key, out var hit)) return hit;
        var r = DssStatus.OcspFor(Ocsps[i], cert, issuer);
        _for[key] = r;
        return r;
    }

    /// <summary>ValRevocation.CrlFor-ийн кэштэй хувилбар (задрахгүй CRL — false).</summary>
    public bool CrlFor(int i, ValCert cert, ValCert issuer)
    {
        var key = (i, cert.Id, issuer.Id);
        if (_crlFor.TryGetValue(key, out var hit)) return hit;
        var crl = Crl(i);
        bool ok = crl is not null && ValRevocation.CrlFor(crl, cert, issuer);
        _crlFor[key] = ok;
        return ok;
    }
}

/// <summary>Go/TS RawSignature.</summary>
internal sealed class RawSignature
{
    public string SignerName = "";
    public string Reason = "";
    public string Location = "";
    public GoTime? ClaimedTime;
    public bool Malformed;
    public bool Integrity;
    public bool WeakDigest;
    public bool CoversWhole;
    public bool LaterSignaturesOnly;
    public int LaterSignatures;
    public bool LaterVisible;
    public bool Visible;
    public long SignedEnd;
    public int ObjNum;
    public long[]? ByteRange;
    public byte[]? Leaf;
    public List<byte[]> Certs = new();
    public RawTimestamp? Timestamp;
    public string SubFilter = "";

    /// <summary>"" | "match" | "mismatch".</summary>
    public string SigningCertV2 = "";
    public bool SigningTimeAttr;
    public List<string> ClaimedRoles = new();
    public string CmsSha256 = "";
    public string MessageDigest = "";
    public RawDss? Dss;
}

/// <summary>
/// Задлах үе шат — TS SDK src/pades/validate/extract.ts (CA server/internal/validate/extract.go)-ийн порт. Итгэлийн шийдвэр
/// гаргахгүй: баримтаас баримт (байт, гэрчилгээ, криптограф таарсан эсэх) л. PDF уншигч нь энэ багцын digitorus/pdf-ийн порт
/// (<see cref="PdfDocument"/>); задлахаас өмнө <see cref="Structure.Check"/> (гүн давхарлалт, ObjStm-ийн төсөв).
/// </summary>
internal static class Extract
{
    /// <summary>PDF-ийн дээд хэмжээ (CA MaxPDFBytes).</summary>
    public const int MaxPdfBytes = 10 << 20;
    private const int MaxSignatures = 16;
    private const int MaxDssItems = 64;
    private const int MaxDssStream = 1 << 20;
    private const int MaxCmsCerts = 32;
    private const int MaxDssTotal = 8 << 20;

    private const string OidSignedData = "1.2.840.113549.1.7.2";
    private const string OidMessageDigest = "1.2.840.113549.1.9.4";
    private const string OidSigningTime = "1.2.840.113549.1.9.5";
    private const string OidSigningCertV2 = "1.2.840.113549.1.9.16.2.47";
    private const string OidTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    private const string OidSignerAttrV2 = "0.4.0.19122.1.1";
    private const string OidRole = "2.5.4.72";

    private static readonly HashSet<string> Strong = new(StringComparer.Ordinal) { ValCert.OidSha256, ValCert.OidSha384, ValCert.OidSha512 };

    private static bool IsUuid(string s)
    {
        if (s.Length != 36) return false;
        for (int i = 0; i < 36; i++)
        {
            char c = s[i];
            if (i is 8 or 13 or 18 or 23)
            {
                if (c != '-') return false;
            }
            else if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Extract (profile own — CA-ийн prod горим): бүх /Type /Sig гарын үсгийг задална.</summary>
    public static (List<RawSignature> Sigs, string DocId) Run(byte[] doc, CancellationToken ct)
    {
        // Уншигчийн рекурс хязгааргүй — гүн давхарласан баримтыг задлахаас өмнө (Go CheckStructure).
        try
        {
            Structure.Check(doc, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
        {
            // PdfStructureException эсвэл бүтцийн шалгагчийн гэнэтийн алдаа — аль аль нь PDF_INVALID (TS validate.ts).
            throw new ExtractException("structure", e);
        }
        PdfDocument rdr;
        try
        {
            rdr = PdfDocument.Open(doc);
        }
        catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
        {
            throw new ExtractException(Structure.EncryptRef.IsMatch(Latin1.FromBytes(doc)) ? "encrypted" : "not_pdf", e);
        }
        var sigs = new List<RawSignature>();
        var visible = new Dictionary<uint, bool>();
        string docId = "";
        RawDss? dss = null;
        try
        {
            // /Encrypt — ямар ч шифрлэлт (хоосон нууц үгтэй ч) encrypted; Keys() — resolve хийхгүй.
            if (new List<string>(rdr.Trailer.Keys()).Contains("Encrypt")) throw new ExtractException("encrypted");
            foreach (var x in rdr.Xref)
            {
                ct.ThrowIfCancellationRequested();
                var obj = rdr.Resolve(x.Ptr, x.Ptr);
                if (obj.Kind != PdfKind.Dict) continue;
                if (obj.Key("FT").Name == "Sig" && obj.Key("V").Kind == PdfKind.Dict)
                {
                    var vp = obj.Key("V").Ptr;
                    if (vp.Id != x.Ptr.Id) visible[vp.Id] = (visible.TryGetValue(vp.Id, out var was) && was) || WidgetVisible(obj);
                }
                if (docId == "" && obj.Key("Subtype").Name == "Link")
                {
                    var u = obj.Key("A").Key("URI").RawString;
                    if (u.StartsWith(OwnAppearance.VerifyPrefix, StringComparison.Ordinal) && IsUuid(u.Substring(OwnAppearance.VerifyPrefix.Length)))
                        docId = u.Substring(OwnAppearance.VerifyPrefix.Length);
                }
                if (obj.Key("Contents").IsNull || obj.Key("ByteRange").IsNull) continue;
                var t = obj.Key("Type").Name;
                if (t != "" && t != "Sig") continue;
                if (sigs.Count == MaxSignatures) throw new ExtractException("too_many");
                var s = ExtractSignature(doc, obj);
                s.ObjNum = (int)x.Ptr.Id;
                sigs.Add(s);
            }
            if (sigs.Count == 0) throw new ExtractException("no_signature");
            foreach (var s in sigs) s.Visible = visible.TryGetValue((uint)s.ObjNum, out var v) && v;
            dss = ExtractDss(rdr.Trailer.Key("Root").Key("DSS"), doc.Length);
        }
        catch (ExtractException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            throw new ExtractException("not_pdf", e); // Go: panic → recover → ErrNotPDF
        }
        if (dss is not null)
            foreach (var s in sigs) s.Dss = dss;
        // Зөвхөн бүрэн бүтэн (Integrity) гарын үсэг л «гарын үсгийн өргөтгөл» болно (Go extract.go extractWith): криптографаар
        // таараагүй гарын үсэгтэй revision DSS-only горимд орж татгалзагдана.
        var known = new Dictionary<int, long[]>();
        var metas = new Dictionary<int, SigMeta>();
        foreach (var s in sigs)
        {
            if (s.Malformed || !s.Integrity) continue;
            known[s.ObjNum] = s.ByteRange!;
            metas[s.ObjNum] = new SigMeta
            {
                RevIndex = 1,
                Role = "",
                RoleOk = s.ClaimedRoles.Count <= 1,
                Seal = ValCert.SealCertificateDer(s.Leaf),
            };
        }
        foreach (var kv in metas)
        {
            var br = known[kv.Key];
            foreach (var s in sigs)
            {
                if (!s.Malformed && s.SignedEnd < br[2] + br[3]) kv.Value.RevIndex++;
                if (s.ObjNum == kv.Key && s.ClaimedRoles.Count == 1) kv.Value.Role = s.ClaimedRoles[0];
            }
        }
        Revisions? revs = null;
        foreach (var s in sigs)
        {
            ct.ThrowIfCancellationRequested();
            if (s.Malformed || s.CoversWhole) continue;
            revs ??= new Revisions(doc, known, ownProfile: true, ct) { Sigs = metas, DocId = docId };
            var later = revs.Later(s.SignedEnd);
            s.LaterSignaturesOnly = later.SignaturesOnly;
            s.LaterSignatures = later.Signatures;
            s.LaterVisible = later.Visible;
        }
        return (sigs, docId);
    }

    /// <summary>widget харагдах: /AP-тэй эсвэл /Rect-ийн өргөн, өндөр хоёулаа 0 биш.</summary>
    private static bool WidgetVisible(PdfValue w)
    {
        if (!w.Key("AP").IsNull) return true;
        var r = w.Key("Rect");
        if (r.Kind != PdfKind.Array || r.Len != 4) return false;
        return r.Index(0).Float64 != r.Index(2).Float64 && r.Index(1).Float64 != r.Index(3).Float64;
    }

    /// <summary>digitorus Value.Text().</summary>
    private static string ValueText(PdfValue v) => v.Kind == PdfKind.String ? GoFmt.PdfText(Latin1.ToBytes(v.RawString)) : "";

    private static RawSignature ExtractSignature(byte[] doc, PdfValue obj)
    {
        var s = new RawSignature
        {
            SignerName = ValueText(obj.Key("Name")),
            Reason = ValueText(obj.Key("Reason")),
            Location = ValueText(obj.Key("Location")),
        };
        var m = obj.Key("M");
        if (!m.IsNull && ParsePdfDate(ValueText(m)) is { } ct) s.ClaimedTime = ct;
        var contents = Latin1.ToBytes(obj.Key("Contents").RawString);
        var br = ByteRangeOf(obj.Key("ByteRange"));
        var sb = SignedBytes(doc, br, contents);
        if (sb is null)
        {
            s.Malformed = true;
            return s;
        }
        s.CoversWhole = sb.Value.Whole;
        s.SignedEnd = br![2] + br[3];
        s.ByteRange = br;
        s.SubFilter = obj.Key("SubFilter").Name;

        var p7 = ParsePkcs7(contents);
        if (p7 is null || p7.Signers.Count != 1 || !BoundedCerts(p7.Certs))
        {
            s.Malformed = true;
            return s;
        }
        var si = p7.Signers[0];
        var leaf = OnlySigner(p7);
        if (leaf is null)
        {
            s.Malformed = true;
            return s;
        }
        s.Leaf = leaf.Raw;
        if (CmsDer(contents) is { } der) s.CmsSha256 = Asn1.Hex(Asn1.Digest("SHA-256", der));
        var (certV2, signingTime) = SignedAttrChecks(si.AuthAttrs, leaf);
        s.SigningCertV2 = certV2;
        s.SigningTimeAttr = signingTime;
        s.ClaimedRoles = ClaimedRoles(si.AuthAttrs);
        foreach (var a in si.AuthAttrs)
        {
            if (a.Type == OidMessageDigest && FirstOctet(a.Values) is { } md) s.MessageDigest = Asn1.Hex(md);
        }
        foreach (var c in p7.Certs)
            if (!c.Raw.AsSpan().SequenceEqual(leaf.Raw)) s.Certs.Add(c.Raw);
        // SignerInfo-ийн гарын үсгийн алгоритм (sha1WithRSAEncryption, ecdsa-with-SHA1 …) сул бол digest SHA-256 байсан ч сул
        // (Go extract.go weakSignatureOID).
        s.WeakDigest = !Strong.Contains(si.DigestAlg) || WeakSignatureOids.Contains(si.EncAlg);
        s.Integrity = VerifyPkcs7(p7, sb.Value.Signed);
        s.Timestamp = ExtractTimestamp(si);
        return s;
    }

    /// <summary>Go weakSignatureOIDs: SignerInfo.signatureAlgorithm-д сул (MD2/MD5/SHA-1-тэй RSA, DSA, ECDSA).</summary>
    internal static readonly HashSet<string> WeakSignatureOids = new(StringComparer.Ordinal)
    {
        "1.2.840.113549.1.1.2", // md2WithRSAEncryption
        "1.2.840.113549.1.1.4", // md5WithRSAEncryption
        "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
        "1.2.840.10040.4.3", // dsa-with-sha1
        "1.2.840.10045.4.1", // ecdsa-with-SHA1
        "1.3.14.3.2.29", // sha1WithRSASignature (OIW)
    };

    // Баримтад суулгасан гэрчилгээний хязгаар (Go extract.go): CMS бүрд ≤ 32, RSA модуль ≤ 8192 бит, илтгэгч ≤ 2^32−1, serial ≤ 160 бит.
    private const int MaxRsaBits = 8192;
    private const int MaxSerialBits = 160;

    /// <summary>Эерэг big-endian байтын (тэргүүлэх 0x00-ийг алгасаад) битийн урт (TS bitLength).</summary>
    private static long BitLength(ReadOnlySpan<byte> b)
    {
        int i = 0;
        while (i < b.Length && b[i] == 0) i++;
        if (i == b.Length) return 0;
        return (long)(b.Length - i - 1) * 8 + (32 - BitOperations.LeadingZeroCount((uint)b[i]));
    }

    /// <summary>INTEGER агуулгын (two's complement) абсолют утгын битийн урт — Go big.Int.BitLen (TS intBitLength).</summary>
    internal static long IntBitLength(ReadOnlySpan<byte> v)
    {
        if (v.Length == 0 || (v[0] & 0x80) == 0) return BitLength(v);
        if (v.Length > 64) return (long)v.Length * 8; // сөрөг, хэт урт — хязгаараас ихийг л мэдэхэд хангалттай
        return (long)BigInteger.Abs(new BigInteger(v, isUnsigned: false, isBigEndian: true)).GetBitLength();
    }

    /// <summary>Go boundedCert: serial ≤ 160 бит; RSA бол модуль ≤ 8192 бит, илтгэгч ≤ 2^32−1 (задрахгүй RSA түлхүүр — хязгаараас гадна).</summary>
    internal static bool BoundedCert(ValCert c)
    {
        if (IntBitLength(c.Serial) > MaxSerialBits) return false;
        if (c.KeyAlg != ValCert.OidRsaEncryption) return true;
        try
        {
            var k = Asn1.Children(Asn1.Expect(Asn1.ParseOne(c.PublicKey), Asn1.Sequence, "RSAPublicKey"));
            var n = Asn1.Expect(Asn1.At(k, 0), Asn1.Integer, "n").Value.Span;
            var e = Asn1.Expect(Asn1.At(k, 1), Asn1.Integer, "e").Value.Span;
            return BitLength(n) <= MaxRsaBits && BitLength(e) <= 32;
        }
        catch (Exception ex) when (IsParse(ex))
        {
            return false;
        }
    }

    /// <summary>Go boundedCerts: ≤ <see cref="MaxCmsCerts"/>, тус бүр <see cref="BoundedCert"/>.</summary>
    internal static bool BoundedCerts(List<ValCert> cs) => cs.Count <= MaxCmsCerts && cs.TrueForAll(BoundedCert);

    // ── PKCS#7 (digitorus/pkcs7-ийн хэрэгтэй дэд хэсэг) ──

    internal sealed record Attr(string Type, ReadOnlyMemory<byte> Values);

    internal sealed class SignerInfo
    {
        public byte[] Issuer = Array.Empty<byte>();
        public BigInteger Serial;
        public string DigestAlg = "";
        public List<Attr> AuthAttrs = new();
        public byte[]? AuthRaw;
        public string EncAlg = "";
        public byte[] Sig = Array.Empty<byte>();
        public List<Attr> UnauthAttrs = new();
    }

    internal sealed class Pkcs7
    {
        public byte[] Content = Array.Empty<byte>();
        public List<ValCert> Certs = new();
        public List<SignerInfo> Signers = new();
    }

    private static bool IsParse(Exception e) => ValRevocation.IsParse(e);

    /// <summary>digitorus pkcs7.Parse: эхний TLV — ContentInfo{SignedData}; гэрчилгээ бүр задрах ёстой.</summary>
    internal static Pkcs7? ParsePkcs7(ReadOnlyMemory<byte> data)
    {
        try
        {
            if (data.Length == 0) return null;
            var ci = Asn1.Children(Asn1.Expect(Asn1.ReadNode(data, 0), Asn1.Sequence, "ContentInfo"));
            if (Asn1.OidString(Asn1.Expect(Asn1.At(ci, 0), Asn1.Oid, "contentType")) != OidSignedData) return null;
            var sd = Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(ci, 1), 0xa0, "[0]")), 0), Asn1.Sequence, "SignedData"));
            int i = 0;
            Asn1.Expect(Asn1.At(sd, i++), Asn1.Integer, "version");
            Asn1.Expect(Asn1.At(sd, i++), Asn1.Set, "digestAlgorithms");
            var eci = Asn1.Children(Asn1.Expect(Asn1.At(sd, i++), Asn1.Sequence, "EncapsulatedContentInfo"));
            var content = Array.Empty<byte>();
            if (Asn1.At(eci, 1) is { } ec)
            {
                var inner = Asn1.At(Asn1.Children(Asn1.Expect(ec, 0xa0, "eContent")), 0);
                if (inner?.Tag == Asn1.OctetString)
                {
                    content = inner.Value.ToArray();
                }
                else if (inner?.Tag == 0x24)
                {
                    var ms = new MemoryStream();
                    foreach (var x in Asn1.Children(inner)) ms.Write(x.Value.Span);
                    content = ms.ToArray();
                }
            }
            var p7 = new Pkcs7 { Content = content };
            if (Asn1.At(sd, i)?.Tag == 0xa0)
            {
                // Гэрчилгээний тоо/хэмжээний хязгаарыг дуудагч BoundedCerts-ээр шалгана (Go: pkcs7.Parse-ийн дараа) — цагийн
                // тэмдгийн токенд хязгаар хэтэрсэн ч TSTInfo-ийн цаг/serial тайланд орно.
                foreach (var c in Asn1.Children(sd[i])) p7.Certs.Add(ValCert.Parse(c.Raw));
                i++;
            }
            if (Asn1.At(sd, i)?.Tag == 0xa1) i++;
            foreach (var n in Asn1.Children(Asn1.Expect(Asn1.At(sd, i), Asn1.Set, "signerInfos"))) p7.Signers.Add(ParseSignerInfo(n));
            return p7;
        }
        catch (Exception e) when (IsParse(e))
        {
            return null;
        }
    }

    private static List<Attr> ParseAttrs(Asn1Node n)
    {
        var o = new List<Attr>();
        foreach (var a in Asn1.Children(n))
        {
            var p = Asn1.Children(Asn1.Expect(a, Asn1.Sequence, "Attribute"));
            o.Add(new Attr(Asn1.OidString(Asn1.Expect(Asn1.At(p, 0), Asn1.Oid, "attr type")), Asn1.Expect(Asn1.At(p, 1), Asn1.Set, "attr values").Value));
        }
        return o;
    }

    private static SignerInfo ParseSignerInfo(Asn1Node n)
    {
        var f = Asn1.Children(Asn1.Expect(n, Asn1.Sequence, "SignerInfo"));
        int i = 0;
        Asn1.Expect(Asn1.At(f, i++), Asn1.Integer, "version");
        var ias = Asn1.Children(Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "IssuerAndSerialNumber"));
        var si = new SignerInfo
        {
            Issuer = Asn1.Expect(Asn1.At(ias, 0), Asn1.Sequence, "issuer").Raw.ToArray(),
            Serial = Asn1.IntValue(Asn1.Expect(Asn1.At(ias, 1), Asn1.Integer, "serial").Value.Span),
        };
        si.DigestAlg = Asn1.OidString(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "digestAlg")), 0), Asn1.Oid, "alg"));
        if (Asn1.At(f, i)?.Tag == 0xa0)
        {
            si.AuthAttrs = ParseAttrs(f[i]);
            var raw = f[i].Raw.ToArray();
            raw[0] = 0x31;
            si.AuthRaw = raw;
            i++;
        }
        si.EncAlg = Asn1.OidString(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "encAlg")), 0), Asn1.Oid, "alg"));
        si.Sig = Asn1.Expect(Asn1.At(f, i++), Asn1.OctetString, "signature").Value.ToArray();
        if (Asn1.At(f, i)?.Tag == 0xa1) si.UnauthAttrs = ParseAttrs(f[i++]);
        return si;
    }

    /// <summary>GetOnlySigner: ганц signer-ийн гэрчилгээ (RawIssuer + serial тоогоор).</summary>
    internal static ValCert? OnlySigner(Pkcs7 p7)
    {
        if (p7.Signers.Count != 1) return null;
        return FindSigner(p7, p7.Signers[0]);
    }

    private static ValCert? FindSigner(Pkcs7 p7, SignerInfo si)
    {
        foreach (var c in p7.Certs)
        {
            try
            {
                if (c.RawIssuer.AsSpan().SequenceEqual(si.Issuer) && c.SerialValue == si.Serial) return c;
            }
            catch (Asn1Exception)
            {
                // хоосон serial — таарахгүй
            }
        }
        return null;
    }

    private static readonly Dictionary<string, string> HashForOid = new(StringComparer.Ordinal)
    {
        [ValCert.OidSha1] = "SHA-1",
        ["1.2.840.10045.4.1"] = "SHA-1",
        ["1.2.840.10040.4.1"] = "SHA-1",
        ["1.2.840.10040.4.3"] = "SHA-1",
        [ValCert.OidRsaEncryption] = "SHA-1",
        [ValCert.OidSha256] = "SHA-256",
        [ValCert.OidEcdsaSha256] = "SHA-256",
        [ValCert.OidSha384] = "SHA-384",
        [ValCert.OidEcdsaSha384] = "SHA-384",
        [ValCert.OidSha512] = "SHA-512",
        [ValCert.OidEcdsaSha512] = "SHA-512",
    };

    private static readonly HashSet<string> RsaEnc = new(StringComparer.Ordinal)
    {
        ValCert.OidRsaEncryption, "1.2.840.113549.1.1.5", ValCert.OidSha256WithRsa, ValCert.OidSha384WithRsa, ValCert.OidSha512WithRsa,
    };

    private static readonly HashSet<string> EcdsaCurveEnc = new(StringComparer.Ordinal) { ValCert.OidP256, ValCert.OidP384, ValCert.OidP521 };

    /// <summary>digitorus getSignatureAlgorithm → x509 гарын үсгийн алгоритмын OID (null — дэмжигдэхгүй).</summary>
    private static string? SigAlgOid(string encAlg, string digestAlg)
    {
        switch (encAlg)
        {
            case "1.2.840.10045.4.1":
                return "1.2.840.10045.4.1";
            case ValCert.OidEcdsaSha256:
            case ValCert.OidEcdsaSha384:
            case ValCert.OidEcdsaSha512:
                return encAlg;
        }
        if (RsaEnc.Contains(encAlg))
        {
            return digestAlg switch
            {
                ValCert.OidSha1 => "1.2.840.113549.1.1.5",
                ValCert.OidSha256 => ValCert.OidSha256WithRsa,
                ValCert.OidSha384 => ValCert.OidSha384WithRsa,
                ValCert.OidSha512 => ValCert.OidSha512WithRsa,
                _ => null,
            };
        }
        if (EcdsaCurveEnc.Contains(encAlg))
        {
            return digestAlg switch
            {
                ValCert.OidSha1 => "1.2.840.10045.4.1",
                ValCert.OidSha256 => ValCert.OidEcdsaSha256,
                ValCert.OidSha384 => ValCert.OidEcdsaSha384,
                ValCert.OidSha512 => ValCert.OidEcdsaSha512,
                _ => null,
            };
        }
        return null; // DSA, Ed25519 — eID-д хэрэглэгддэггүй
    }

    private static Asn1Node AlgNode(string oid) => Asn1.ParseOne(Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv(oid)));

    /// <summary>digitorus pkcs7.Verify (truststore nil): messageDigest, signingTime ∈ cert validity, гарын үсэг.</summary>
    private static bool VerifyPkcs7(Pkcs7 p7, byte[] content)
    {
        if (p7.Signers.Count == 0) return false;
        foreach (var si in p7.Signers)
        {
            var ee = FindSigner(p7, si);
            if (ee is null) return false;
            byte[] signed = content;
            if (si.AuthAttrs.Count > 0)
            {
                Attr? mdAttr = null;
                foreach (var a in si.AuthAttrs)
                {
                    if (a.Type == OidMessageDigest)
                    {
                        mdAttr = a;
                        break;
                    }
                }
                var md = mdAttr is null ? null : FirstOctet(mdAttr.Values);
                if (md is null) return false;
                if (!HashForOid.TryGetValue(si.DigestAlg, out var hash)) return false;
                if (!md.AsSpan().SequenceEqual(Asn1.Digest(hash, content))) return false;
                signed = si.AuthRaw!;
                foreach (var a in si.AuthAttrs)
                {
                    if (a.Type != OidSigningTime) continue;
                    if (AttrTime(a.Values) is { } t && (t > ee.NotAfter.UnixMs || t < ee.NotBefore.UnixMs)) return false;
                    break;
                }
            }
            var alg = SigAlgOid(si.EncAlg, si.DigestAlg);
            if (alg is null) return false;
            if (!ee.Verify(AlgNode(alg), signed, si.Sig)) return false;
        }
        return true;
    }

    private static byte[]? FirstOctet(ReadOnlyMemory<byte> values)
    {
        try
        {
            var n = Asn1.ReadNode(values, 0);
            return n.Tag == Asn1.OctetString ? n.Value.ToArray() : null;
        }
        catch (Asn1Exception)
        {
            return null;
        }
    }

    /// <summary>signingTime атрибутын цаг (JS мс) эсвэл null.</summary>
    private static long? AttrTime(ReadOnlyMemory<byte> values)
    {
        try
        {
            var n = Asn1.ReadNode(values, 0);
            if (n.Tag != Asn1.UtcTime && n.Tag != Asn1.GeneralizedTime) return null;
            return Asn1.ParsePreciseTime(n).UnixMs;
        }
        catch (Exception e) when (IsParse(e))
        {
            return null;
        }
    }

    /// <summary>/Contents-ийн эхний ASN.1 элемент (placeholder-ийн тэг дүүргэлтгүй CMS).</summary>
    private static byte[]? CmsDer(byte[] contents)
    {
        try
        {
            var n = Asn1.ReadNode(contents, 0);
            return n.Tag == Asn1.Sequence ? n.Raw.ToArray() : null;
        }
        catch (Asn1Exception)
        {
            return null;
        }
    }

    // ── signedAttrs ──

    /// <summary>signingCertificateV2 нь leaf-тэй таарах эсэх, signingTime байгаа эсэх (Go signedAttrChecks).</summary>
    private static (string CertV2, bool SigningTime) SignedAttrChecks(List<Attr> attrs, ValCert leaf)
    {
        string certV2 = "";
        bool signingTime = false;
        foreach (var a in attrs)
        {
            if (a.Type == OidSigningTime)
            {
                signingTime = true;
                continue;
            }
            if (a.Type != OidSigningCertV2) continue;
            if (certV2 != "")
            {
                certV2 = "mismatch";
                continue;
            }
            certV2 = "mismatch";
            try
            {
                var top = Asn1.ReadNode(a.Values, 0);
                if (top.Raw.Length != a.Values.Length || top.Tag != Asn1.Sequence) continue;
                var scf = Asn1.Children(top);
                // Go struct{ Certs []essCertIDv2 } — нэмэлт талбар (policies) байвал Unmarshal алдаа.
                if (scf.Count != 1 || scf[0].Tag != Asn1.Sequence) continue;
                var ids = Asn1.Children(scf[0]);
                if (ids.Count == 0) continue;
                var id = Asn1.Children(Asn1.Expect(ids[0], Asn1.Sequence, "ESSCertIDv2"));
                int k = 0;
                string? hash = "SHA-256";
                if (Asn1.At(id, k)?.Tag == Asn1.Sequence)
                {
                    var alg = Asn1.OidString(Asn1.Expect(Asn1.At(Asn1.Children(id[k]), 0), Asn1.Oid, "alg"));
                    hash = alg == ValCert.OidSha256 ? "SHA-256" : alg == ValCert.OidSha384 ? "SHA-384" : alg == ValCert.OidSha512 ? "SHA-512" : null;
                    k++;
                }
                var certHash = Asn1.Expect(Asn1.At(id, k++), Asn1.OctetString, "certHash").Value;
                BigInteger? serial = null;
                if (Asn1.At(id, k) is { } isn)
                {
                    var iss = Asn1.Children(Asn1.Expect(isn, Asn1.Sequence, "IssuerSerial"));
                    serial = Asn1.IntValue(Asn1.Expect(Asn1.At(iss, 1), Asn1.Integer, "serial").Value.Span);
                    k++;
                }
                if (k != id.Count || hash is null) continue;
                if (!certHash.Span.SequenceEqual(Asn1.Digest(hash, leaf.Raw))) continue;
                if (serial is { } sv && sv != leaf.SerialValue) continue;
                certV2 = "match";
            }
            catch (Exception e) when (IsParse(e))
            {
                // mismatch
            }
        }
        return (certV2, signingTime);
    }

    private const int MaxClaimedRoles = 4;
    private const int MaxClaimedRoleRunes = 900;

    /// <summary>signer-attributes-v2 claimedAttributes / id-at-role (UTF8String/PrintableString).</summary>
    private static List<string> ClaimedRoles(List<Attr> attrs)
    {
        var o = new List<string>();
        foreach (var a in attrs)
        {
            if (a.Type != OidSignerAttrV2) continue;
            try
            {
                var seq = Asn1.ReadNode(a.Values, 0);
                if (seq.Tag != Asn1.Sequence) continue;
                var first = seq.Value.Length > 0 ? Asn1.ReadNode(seq.Value, 0) : null;
                if (first is null || first.Tag != 0xa0) continue;
                var list = Asn1.ReadNode(first.Value, 0);
                if (list.Tag != Asn1.Sequence) continue;
                int p = 0;
                while (p < list.Value.Length && o.Count < MaxClaimedRoles)
                {
                    Asn1Node at;
                    try
                    {
                        at = Asn1.ReadNode(list.Value, p);
                    }
                    catch (Asn1Exception)
                    {
                        break;
                    }
                    p += at.Raw.Length;
                    if (at.Tag != Asn1.Sequence) break;
                    var parts = Asn1.Children(at);
                    var p0 = Asn1.At(parts, 0);
                    var p1 = Asn1.At(parts, 1);
                    if (p0?.Tag != Asn1.Oid || p1?.Tag != Asn1.Set) break;
                    if (Asn1.OidString(p0) != OidRole) continue;
                    int q = 0;
                    var vals = p1.Value;
                    while (q < vals.Length && o.Count < MaxClaimedRoles)
                    {
                        Asn1Node v;
                        try
                        {
                            v = Asn1.ReadNode(vals, q);
                        }
                        catch (Asn1Exception)
                        {
                            break;
                        }
                        q += v.Raw.Length;
                        if (v.Tag != Asn1.Utf8String && v.Tag != Asn1.PrintableString) continue;
                        if (ValidClaimedRole(v.Value.Span) is { } r) o.Add(r);
                    }
                }
            }
            catch (Exception e) when (IsParse(e))
            {
                // алгасна
            }
        }
        return o;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Go validClaimedRole: хоосон биш, хүчинтэй UTF-8, ≤ 900 rune, удирдах (Cc) ба формат (Cf) тэмдэгтгүй.</summary>
    private static string? ValidClaimedRole(ReadOnlySpan<byte> b)
    {
        string s;
        try
        {
            s = StrictUtf8.GetString(b);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
        if (s.Length == 0) return null;
        int runes = 0;
        foreach (var r in s.EnumerateRunes())
        {
            runes++;
            var cat = Rune.GetUnicodeCategory(r);
            if (cat is UnicodeCategory.Control or UnicodeCategory.Format) return null;
        }
        return runes > MaxClaimedRoleRunes ? null : s;
    }

    // ── RFC 3161 ──

    private static readonly Dictionary<string, string> TsHash = new(StringComparer.Ordinal)
    {
        [ValCert.OidSha1] = "SHA-1",
        [ValCert.OidSha256] = "SHA-256",
        [ValCert.OidSha384] = "SHA-384",
        [ValCert.OidSha512] = "SHA-512",
    };

    private static RawTimestamp? ExtractTimestamp(SignerInfo si)
    {
        foreach (var a in si.UnauthAttrs)
        {
            if (a.Type != OidTimeStampToken) continue;
            var o = new RawTimestamp();
            // digitorus/timestamp.Parse: гэрчилгээ байвал токены гарын үсгийг шалгана, TSTInfo задална.
            var tok = ParsePkcs7(a.Values);
            if (tok is null) return o;
            if (tok.Certs.Count > 0 && !VerifyPkcs7(tok, tok.Content)) return o;
            string hashAlg, serial;
            ReadOnlyMemory<byte> hashed;
            GoTime time;
            try
            {
                var info = Asn1.Children(Asn1.Expect(Asn1.ParseOne(tok.Content), Asn1.Sequence, "TSTInfo"));
                var mi = Asn1.Children(Asn1.Expect(Asn1.At(info, 2), Asn1.Sequence, "messageImprint"));
                hashAlg = Asn1.OidString(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(mi, 0), Asn1.Sequence, "alg")), 0), Asn1.Oid, "alg"));
                hashed = Asn1.Expect(Asn1.At(mi, 1), Asn1.OctetString, "hashedMessage").Value;
                if (hashed.Length == 0) return o;
                var sv = Asn1.Expect(Asn1.At(info, 3), Asn1.Integer, "serial").Value.Span;
                // TSTInfo serialNumber ≤ 160 бит (Go extract.go: timestamp.Parse-ийн дараа, цаг/serial тавихаас өмнө).
                if (IntBitLength(sv) > MaxSerialBits) return o;
                serial = GoFmt.HexSerial(sv);
                time = GoTime.FromPrecise(Asn1.ParsePreciseTime(Asn1.Expect(Asn1.At(info, 4), Asn1.GeneralizedTime, "genTime")));
            }
            catch (Exception e) when (IsParse(e))
            {
                return o;
            }
            o.Time = time;
            o.Serial = serial;
            if (tok.Signers.Count != 1 || !BoundedCerts(tok.Certs)) return o;
            var tsa = OnlySigner(tok);
            if (tsa is null) return o;
            o.TsaCert = tsa.Raw;
            foreach (var c in tok.Certs)
                if (!c.Raw.AsSpan().SequenceEqual(tsa.Raw)) o.Certs.Add(c.Raw);
            bool hasH = TsHash.TryGetValue(hashAlg, out var h);
            o.WeakDigest = !Strong.Contains(tok.Signers[0].DigestAlg) || !(hasH && h != "SHA-1");
            if (!hasH) return o;
            o.Matches = hashed.Span.SequenceEqual(Asn1.Digest(h!, si.Sig));
            return o;
        }
        return null;
    }

    // ── ByteRange / огноо / DSS ──

    /// <summary>ByteRange [0 a b c]: завсар нь ЗӨВХӨН энэ толийн /Contents-ийн &lt;hex&gt;.</summary>
    private static (byte[] Signed, bool Whole)? SignedBytes(byte[] doc, long[]? br, byte[] contents)
    {
        if (br is null || br.Length != 4) return null;
        long n = doc.Length;
        long a0 = br[0], l0 = br[1], a1 = br[2], l1 = br[3];
        if (a0 != 0 || l0 <= 0 || l1 < 0 || a1 <= l0 || a1 > n || l1 > n - a1) return null;
        var gap = doc.AsSpan((int)l0, (int)(a1 - l0));
        if (gap.Length < 2 || gap[0] != '<' || gap[gap.Length - 1] != '>') return null;
        var hex = gap[1..^1];
        if (hex.Length % 2 != 0) return null;
        foreach (var c in hex)
            if (!P.IsHex(c)) return null;
        if (hex.Length / 2 != contents.Length) return null;
        for (int i = 0; i < contents.Length; i++)
            if ((P.HexVal(hex[2 * i]) << 4 | P.HexVal(hex[2 * i + 1])) != contents[i]) return null;
        var signed = new byte[l0 + l1];
        Array.Copy(doc, 0, signed, 0, l0);
        Array.Copy(doc, a1, signed, l0, l1);
        return (signed, a1 + l1 == n);
    }

    private static long[]? ByteRangeOf(PdfValue v)
    {
        if (v.Kind != PdfKind.Array || v.Len != 4) return null;
        var o = new long[4];
        for (int i = 0; i < 4; i++)
        {
            var e = v.Index(i);
            if (e.Kind != PdfKind.Integer) return null;
            o[i] = e.Int64;
        }
        return o;
    }

    /// <summary>Go parsePDFDate: "D:" хасаж, "'"-ийг устгаад 20060102150405[-0700|Z0700|Z|].</summary>
    public static GoTime? ParsePdfDate(string raw)
    {
        var s = (raw.StartsWith("D:", StringComparison.Ordinal) ? raw.Substring(2) : raw).Replace("'", "", StringComparison.Ordinal);
        // ^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{4})?$
        if (s.Length < 14) return null;
        for (int i = 0; i < 14; i++)
            if (s[i] < '0' || s[i] > '9') return null;
        var z = s.Substring(14);
        if (!(z == "" || z == "Z" || z.Length == 5 && (z[0] == '+' || z[0] == '-') && IsDigits(z, 1, 4))) return null;
        int y = Num(s, 0, 4), mo = Num(s, 4, 2), d = Num(s, 6, 2), h = Num(s, 8, 2), mi = Num(s, 10, 2), se = Num(s, 12, 2);
        if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null;
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int dim = mo == 2 ? (leap ? 29 : 28) : DateTime.DaysInMonth(2000, mo);
        if (d > dim) return null;
        long off = 0;
        if (z != "" && z != "Z")
        {
            int oh = Num(z, 1, 2), om = Num(z, 3, 2);
            if (oh > 24 || om > 59) return null;
            off = (oh * 60L + om) * 60 * (z[0] == '+' ? 1 : -1);
        }
        if (y < 1) return null;
        long sec = new DateTimeOffset(y, mo, d, h, mi, se, TimeSpan.Zero).ToUnixTimeSeconds();
        return new GoTime(sec - off, 0);
    }

    private static bool IsDigits(string s, int at, int n)
    {
        for (int i = at; i < at + n; i++)
            if (s[i] < '0' || s[i] > '9') return false;
        return true;
    }

    private static int Num(string s, int at, int n) => int.Parse(s.AsSpan(at, n), NumberStyles.None, CultureInfo.InvariantCulture);

    /// <summary>/DSS-ийн /Certs /OCSPs /CRLs stream-уудыг тайлж уншина; задрахгүй / хязгаар хэтэрсэнийг алгасна.</summary>
    private static RawDss? ExtractDss(PdfValue dss, int docLen)
    {
        if (dss.Kind != PdfKind.Dict) return null;
        // Нэг объектыг олон удаа заасныг нэг удаа (тайлалт, OCSP/CRL шалгалтыг давтахгүй); нийт тайлсан байт ≤ MaxDssTotal.
        long total = 0;
        List<byte[]> Read(string key)
        {
            var arr = dss.Key(key);
            var o = new List<byte[]>();
            var seen = new HashSet<ObjPtr>();
            for (int i = 0; i < arr.Len && i < MaxDssItems; i++)
            {
                var e = arr.Index(i);
                if (e.Kind != PdfKind.Stream || (e.Ptr != default && !seen.Add(e.Ptr))) continue;
                var b = StreamData(e, docLen);
                if (b is null || b.Length > MaxDssStream || total + b.Length > MaxDssTotal) continue;
                total += b.Length;
                o.Add(b);
            }
            return o;
        }
        return new RawDss { Certs = Read("Certs"), Ocsps = Read("OCSPs"), Crls = Read("CRLs") };
    }

    /// <summary>
    /// TS reader streamData (DSS-д): /Length файлаас хэтэрвэл алдаа; FlateDecode (+ PNG-Up predictor 12). Тайлалт
    /// <see cref="MaxDssStream"/>-аас хэтэрмэгц зогсоно (тэр stream-ийг алгасна — zip bomb санах ойг дүүргэхгүй). Алдаа → null.
    /// </summary>
    private static byte[]? StreamData(PdfValue v, int docLen)
    {
        try
        {
            if (v.Data is not PdfStream ps) return null;
            long n = v.Key("Length").Int64;
            if (n < 0 || ps.Offset + n > docLen) return null;
            byte[] data = v.RawStreamBytes().ToArray();
            var filter = v.Key("Filter");
            var param = v.Key("DecodeParms");
            switch (filter.Kind)
            {
                case PdfKind.Null:
                    break;
                case PdfKind.Name:
                    data = ApplyFilter(data, filter.Name, param);
                    break;
                case PdfKind.Array:
                    for (int i = 0; i < filter.Len; i++) data = ApplyFilter(data, filter.Index(i).Name, param.Index(i));
                    break;
                default:
                    return null;
            }
            return data;
        }
        catch (Exception e) when (e is PdfFormatException or InvalidDataException or IOException or ArgumentException or OverflowException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static byte[] ApplyFilter(byte[] data, string name, PdfValue param)
    {
        if (name != "FlateDecode") throw new PdfFormatException("unknown filter " + name);
        var o = ZlibInflate(data, MaxDssStream + 1);
        var pred = param.Key("Predictor");
        if (pred.Kind == PdfKind.Null) return o;
        if (pred.Kind != PdfKind.Integer || pred.Int64 != 12) throw new PdfFormatException("unknown predictor");
        // pngUpReader: мөр бүр [2, columns байт]; hist-д нэмнэ (hist[0] гаралтад орохгүй); буруу мөрөөс өмнөхийг буцаана.
        long columns = param.Key("Columns").Int64;
        if (columns < 0 || columns > MaxDssStream) throw new PdfFormatException("bad Columns");
        int row = 1 + (int)columns;
        var hist = new byte[row];
        int rows = o.Length / row;
        var res = new byte[rows * (int)columns];
        for (int r = 0; r < rows; r++)
        {
            if (o[r * row] != 2) return res.AsSpan(0, r * (int)columns).ToArray();
            for (int i = 0; i < row; i++) hist[i] = (byte)(hist[i] + o[r * row + i]);
            Array.Copy(hist, 1, res, r * (int)columns, (int)columns);
        }
        return res;
    }

    /// <summary>zlib (header шалгана, FDICT хориотой); гаралт <paramref name="limit"/>-д хүрмэгц зогсоно.</summary>
    private static byte[] ZlibInflate(byte[] src, int limit)
    {
        if (src.Length < 2) throw new PdfFormatException("zlib: header");
        int cmf = src[0], flg = src[1];
        if ((cmf & 0x0f) != 8 || cmf >> 4 > 7 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20) != 0) throw new PdfFormatException("zlib: header");
        using var zs = new ZLibStream(new MemoryStream(src, writable: false), CompressionMode.Decompress);
        using var ms = new MemoryStream();
        var buf = new byte[64 << 10];
        int k;
        while ((k = zs.Read(buf, 0, buf.Length)) > 0)
        {
            ms.Write(buf, 0, k);
            if (ms.Length >= limit) break;
        }
        return ms.ToArray();
    }
}
