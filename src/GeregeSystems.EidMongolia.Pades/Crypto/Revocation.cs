using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

/// <summary>
/// Цуцлалтын нотолгооны (OCSP/CRL) шинэлэг байдал ба тохирлын нэг дүрэм — Go reference
/// <c>pades/internal/validate/revocation.go</c>-ийн порт (Go v0.8.0, TS 0.21.0-тэй ижил).
/// </summary>
internal static class Revocation
{
    /// <summary>nextUpdate-гүй (эсвэл шалгах цагийг хамраагүй) хариуны thisUpdate нь шалгах цагаас хамгийн ихдээ ийм хугацаагаар өмнө.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    /// <summary>Responder ба шалгагчийн цагийн зөрүүний хүлцэл.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Go validate.FreshAt — хариу <paramref name="at"/> агшны «good» нотолгоо болох эсэх: thisUpdate нь now+skew-ээс хожуу биш;
    /// nextUpdate (байвал) at−skew-ээс өмнө биш; thisUpdate ≥ at − 24ц, эсвэл [thisUpdate, nextUpdate] нь at-ийг хамарна.
    /// </summary>
    public static bool FreshAt(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, DateTimeOffset at, DateTimeOffset now)
    {
        if (thisUpdate > now + ClockSkew) return false;
        if (nextUpdate is { } nu && nu < at - ClockSkew) return false;
        if (!(thisUpdate < at - MaxAge)) return true;
        return nextUpdate is not null && !(thisUpdate > at);
    }

    /// <summary>
    /// Go validate.CRLFor — CRL нь cert-ийн олгогчийнх: нэр = cert.Issuer = issuer.Subject (түүхий байт), AKI (хоёуланд байвал)
    /// = issuer-ийн SKI, гарын үсэг issuer-ийн түлхүүрээр.
    /// </summary>
    public static bool CrlFor(Crl crl, X509Certificate2 cert, X509Certificate2 issuer)
    {
        if (!crl.RawIssuer.AsSpan().SequenceEqual(cert.IssuerName.RawData) || !crl.RawIssuer.AsSpan().SequenceEqual(issuer.SubjectName.RawData))
            return false;
        var ski = SubjectKeyId(issuer);
        if (crl.AuthorityKeyId.Length > 0 && ski.Length > 0 && !crl.AuthorityKeyId.AsSpan().SequenceEqual(ski)) return false;
        return X509Util.CheckCrlSignatureFrom(crl.Der, issuer);
    }

    /// <summary>Go validate.CRLListed — cert-ийн serial CRL-д байгаа эсэх.</summary>
    public static bool CrlListed(Crl crl, X509Certificate2 cert)
    {
        var serial = Cms.Serial(cert);
        foreach (var s in crl.Revoked)
            if (s == serial) return true;
        return false;
    }

    /// <summary>
    /// Go validate.OCSPCertIDMatches — OCSP хариуны cert-ийн serial-тэй SingleResponse БҮР нь issuer-ийн CertID-тэй
    /// (issuerNameHash = H(issuer subject), issuerKeyHash = H(issuer subjectPublicKey); SHA-1/256/384/512) бөгөөд дор хаяж
    /// нэг нь байна. Зөвхөн serial-аар сонговол өөр олгогчийн ижил serial-ийн хариу энэ гэрчилгээнд тооцогдоно.
    /// </summary>
    public static bool OcspCertIdMatches(byte[] der, X509Certificate2 cert, X509Certificate2 issuer)
    {
        try
        {
            var keyBits = issuer.PublicKey.EncodedKeyValue.RawData;
            var resp = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            var st = resp.ReadEnumeratedBytes().Span;
            if (st.Length != 1 || st[0] != 0) return false;
            var rb = resp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
            rb.ReadObjectIdentifier();
            var basic = new AsnReader(rb.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
            var tbs = basic.ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) tbs.ReadEncodedValue(); // version
            tbs.ReadEncodedValue(); // responderID
            tbs.ReadGeneralizedTime(); // producedAt
            var singles = tbs.ReadSequence();
            var serial = Cms.Serial(cert);
            bool found = false;
            while (singles.HasData)
            {
                var certId = singles.ReadSequence().ReadSequence();
                var hashOid = certId.ReadSequence().ReadObjectIdentifier();
                var nameHash = certId.ReadOctetString();
                var keyHash = certId.ReadOctetString();
                BigInteger sn = certId.ReadInteger();
                if (sn != serial) continue;
                var h = HashOf(hashOid);
                if (h is null) return false;
                if (!nameHash.AsSpan().SequenceEqual(h(issuer.SubjectName.RawData)) || !keyHash.AsSpan().SequenceEqual(h(keyBits))) return false;
                found = true;
            }
            return found;
        }
        catch (Exception e) when (e is AsnContentException or CryptographicException or FormatException)
        {
            return false;
        }
    }

    private static Func<byte[], byte[]>? HashOf(string oid) => oid switch
    {
        "1.3.14.3.2.26" => SHA1.HashData,
        "2.16.840.1.101.3.4.2.1" => SHA256.HashData,
        "2.16.840.1.101.3.4.2.2" => SHA384.HashData,
        "2.16.840.1.101.3.4.2.3" => SHA512.HashData,
        _ => null,
    };

    private static byte[] SubjectKeyId(X509Certificate2 c)
    {
        foreach (var e in c.Extensions)
            if (e is X509SubjectKeyIdentifierExtension ski)
                return ski.SubjectKeyIdentifierBytes.ToArray();
        return Array.Empty<byte>();
    }

    /// <summary>Алдааны текстэд гэрчилгээг нэрээр (CN = иргэний овог нэр, PII) биш serial-аар заана (Go certRef).</summary>
    public static string CertRef(X509Certificate2 c)
    {
        var s = c.SerialNumber.TrimStart('0').ToLowerInvariant();
        return "serial " + (s == "" ? "0" : s);
    }
}
