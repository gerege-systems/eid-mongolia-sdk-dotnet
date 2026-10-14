using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

/// <summary>CMS SignedData (CAdES baseline, detached) — Go reference core/cms.go-тэй байт-ижил.</summary>
internal static class Cms
{
    public const string OidData = "1.2.840.113549.1.7.1";
    public const string OidSignedData = "1.2.840.113549.1.7.2";
    public const string OidContentType = "1.2.840.113549.1.9.3";
    public const string OidMessageDigest = "1.2.840.113549.1.9.4";
    public const string OidSigningCertV2 = "1.2.840.113549.1.9.16.2.47";
    public const string OidTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    public const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    public const string OidSha256WithRsa = "1.2.840.113549.1.1.11";
    public const string OidEcdsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string OidSignerAttrV2 = "0.4.0.19122.1.1";
    public const string OidRole = "2.5.4.72";
    public const int ClaimedRoleMaxRunes = 900;

    public static BigInteger Serial(X509Certificate2 c) => new(c.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true);

    public static bool IsRsa(X509Certificate2 c) => c.PublicKey.Oid.Value == "1.2.840.113549.1.1.1";

    public static bool IsEc(X509Certificate2 c) => c.PublicKey.Oid.Value == "1.2.840.10045.2.1";

    /// <summary>signedAttrs (DER SET OF, tag 0x31): contentType, messageDigest, signingCertificateV2 [+ signer-attributes-v2].</summary>
    public static byte[] SignedAttributes(byte[] messageDigest, X509Certificate2 signer, string? claimedRole)
    {
        if (messageDigest.Length != 32) throw new ArgumentException("pades: messageDigest is not SHA-256");
        claimedRole ??= "";
        if (claimedRole != "" && (!GoText.IsValidUtf16(claimedRole) || RuneCount(claimedRole) > ClaimedRoleMaxRunes))
            throw new EidPadesException("REQUEST_INVALID", "claimedRole: invalid or too long");
        var certHash = SHA256.HashData(signer.RawData);

        var attrs = new List<byte[]>
        {
            Attr(OidContentType, Der.Oid(OidData)),
            Attr(OidMessageDigest, Der.OctetString(messageDigest)),
            Attr(OidSigningCertV2,
                Der.Seq( // SigningCertificateV2
                    Der.Seq( // certs
                        Der.Seq( // ESSCertIDv2
                            Der.OctetString(certHash),
                            Der.Seq( // IssuerSerial
                                Der.Seq(Der.Tlv(0xA4, signer.IssuerName.RawData)), // GeneralNames { directoryName [4] }
                                Der.Integer(Serial(signer))))))),
        };
        if (claimedRole != "")
        {
            attrs.Add(Attr(OidSignerAttrV2,
                Der.Seq( // SignerAttributeV2
                    Der.Tlv(0xA0, // claimedAttributes [0] EXPLICIT
                        Der.Seq( // ClaimedAttributes
                            Der.Seq(Der.Oid(OidRole), Der.SetOf(Der.Utf8String(claimedRole))))))));
        }
        attrs.Sort(Der.Compare);
        return Der.SetOf(attrs.ToArray());
    }

    private static byte[] Attr(string oid, byte[] value) => Der.Seq(Der.Oid(oid), Der.SetOf(value));

    private static int RuneCount(string s)
    {
        int n = 0;
        foreach (var _ in s.EnumerateRunes()) n++;
        return n;
    }

    public static byte[] Dtbs(byte[] signedAttrs) => SHA256.HashData(signedAttrs);

    /// <summary>ContentInfo{SignedData}: certificates = signer + chain (байтаар эрэмбэлсэн), SignerInfo + signatureTimeStampToken.</summary>
    public static byte[] Assemble(byte[] signedAttrs, X509Certificate2 signer, IReadOnlyList<X509Certificate2> chain, byte[] signature, byte[] tst)
    {
        if (signedAttrs.Length < 2 || signedAttrs[0] != 0x31) throw new InvalidOperationException("pades: signedAttrs is not a DER SET");
        string sigAlg;
        if (IsRsa(signer)) sigAlg = OidSha256WithRsa;
        else if (IsEc(signer)) sigAlg = OidEcdsaWithSha256;
        else throw new EidPadesException("SIGNER_INVALID", "unsupported signer key type (RSA or ECDSA)");
        var implicitAttrs = (byte[])signedAttrs.Clone();
        implicitAttrs[0] = 0xA0;

        var certs = new List<byte[]> { signer.RawData };
        foreach (var c in chain)
            if (!c.RawData.AsSpan().SequenceEqual(signer.RawData)) certs.Add(c.RawData);
        certs.Sort(Der.Compare);

        var signerInfo = new List<byte[]>
        {
            Der.Integer(1),
            Der.Seq(signer.IssuerName.RawData, Der.Integer(Serial(signer))),
            Der.AlgId(OidSha256, false),
            implicitAttrs,
            Der.AlgId(sigAlg, sigAlg == OidSha256WithRsa),
            Der.OctetString(signature),
        };
        if (tst.Length > 0)
            signerInfo.Add(Der.Tlv(0xA1, Der.Seq(Der.Oid(OidTimeStampToken), Der.SetOf(tst))));

        return Der.Seq(
            Der.Oid(OidSignedData),
            Der.Tlv(0xA0,
                Der.Seq(
                    Der.Integer(1),
                    Der.SetOf(Der.AlgId(OidSha256, false)),
                    Der.Seq(Der.Oid(OidData)),
                    Der.Tlv(0xA0, certs),
                    Der.SetOf(Der.Seq(signerInfo.ToArray())))));
    }
}
