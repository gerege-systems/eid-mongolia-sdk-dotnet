using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

/// <summary>Гэрчилгээ/CRL/OCSP-ийн гарын үсэг ба өргөтгөл — Go crypto/x509-ийн хэрэгтэй хэсэг.</summary>
internal static class X509Util
{
    public const string OidKpTimeStamping = "1.3.6.1.5.5.7.3.8";
    public const string OidKpOcspSigning = "1.3.6.1.5.5.7.3.9";
    private const string OidExtKeyUsage = "2.5.29.37";
    private const string OidCrlDp = "2.5.29.31";
    private const string OidAia = "1.3.6.1.5.5.7.1.1";
    private const string OidAdOcsp = "1.3.6.1.5.5.7.48.1";

    public static X509Certificate2 Parse(byte[] der)
    {
        try
        {
            return new X509Certificate2(der);
        }
        catch (CryptographicException e)
        {
            throw new FormatException("certificate: " + e.Message, e);
        }
    }

    public static bool Equal(X509Certificate2 a, X509Certificate2 b) => a.RawData.AsSpan().SequenceEqual(b.RawData);

    /// <summary>SIGNED{tbs} бүтэц: (tbs-ийн DER, алгоритм, гарын үсгийн байт).</summary>
    public static (byte[] Tbs, AlgorithmId Alg, byte[] Signature) SplitSigned(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var seq = r.ReadSequence();
        var tbs = seq.ReadEncodedValue().ToArray();
        var alg = AlgorithmId.Read(seq);
        var sig = seq.ReadBitString(out _);
        return (tbs, alg, sig);
    }

    /// <summary>Go x509.Certificate.CheckSignatureFrom: parent нь CA (BasicConstraints), KeyUsage-д certSign, SHA-1 хориотой.</summary>
    public static bool CheckSignatureFrom(X509Certificate2 c, X509Certificate2 parent)
    {
        if (!IsCaFor(parent, X509KeyUsageFlags.KeyCertSign)) return false;
        var (tbs, alg, sig) = SplitSigned(c.RawData);
        return Verify(parent, alg, tbs, sig, allowSha1: false);
    }

    /// <summary>Go x509.RevocationList.CheckSignatureFrom.</summary>
    public static bool CheckCrlSignatureFrom(byte[] crlDer, X509Certificate2 parent)
    {
        if (!IsCaFor(parent, X509KeyUsageFlags.CrlSign)) return false;
        var (tbs, alg, sig) = SplitSigned(crlDer);
        return Verify(parent, alg, tbs, sig, allowSha1: false);
    }

    private static bool IsCaFor(X509Certificate2 parent, X509KeyUsageFlags need)
    {
        X509BasicConstraintsExtension? bc = null;
        X509KeyUsageExtension? ku = null;
        foreach (var e in parent.Extensions)
        {
            if (e is X509BasicConstraintsExtension b) bc = b;
            if (e is X509KeyUsageExtension k) ku = k;
        }
        if (parent.Version == 3 && bc is null || bc is not null && !bc.CertificateAuthority) return false;
        if (ku is not null && ku.KeyUsages != X509KeyUsageFlags.None && (ku.KeyUsages & need) == 0) return false;
        return true;
    }

    /// <summary>Go Certificate.CheckSignature(algo, signed, signature) — RSA PKCS#1 v1.5 / PSS, ECDSA.</summary>
    public static bool Verify(X509Certificate2 key, AlgorithmId alg, byte[] data, byte[] sig, bool allowSha1)
    {
        try
        {
            switch (alg.Oid)
            {
                case "1.2.840.113549.1.1.5": return allowSha1 && Rsa(key, data, sig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.11": return Rsa(key, data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.12": return Rsa(key, data, sig, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.13": return Rsa(key, data, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.10": return Pss(key, alg, data, sig);
                case "1.2.840.10045.4.1": return allowSha1 && Ec(key, data, sig, HashAlgorithmName.SHA1);
                case "1.2.840.10045.4.3.2": return Ec(key, data, sig, HashAlgorithmName.SHA256);
                case "1.2.840.10045.4.3.3": return Ec(key, data, sig, HashAlgorithmName.SHA384);
                case "1.2.840.10045.4.3.4": return Ec(key, data, sig, HashAlgorithmName.SHA512);
                default: return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool Rsa(X509Certificate2 key, byte[] data, byte[] sig, HashAlgorithmName h, RSASignaturePadding p)
    {
        using var rsa = key.GetRSAPublicKey();
        return rsa is not null && rsa.VerifyData(data, sig, h, p);
    }

    private static bool Ec(X509Certificate2 key, byte[] data, byte[] sig, HashAlgorithmName h)
    {
        using var ec = key.GetECDsaPublicKey();
        return ec is not null && ec.VerifyData(data, sig, h, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static bool Pss(X509Certificate2 key, AlgorithmId alg, byte[] data, byte[] sig)
    {
        // RSASSA-PSS-params: hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2], trailerField [3].
        if (alg.Params is null) return false;
        var r = new AsnReader(alg.Params, AsnEncodingRules.DER).ReadSequence();
        HashAlgorithmName h = HashAlgorithmName.SHA1;
        if (r.HasData && r.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var hr = r.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            h = HashFromOid(AlgorithmId.Read(hr).Oid);
        }
        using var rsa = key.GetRSAPublicKey();
        return rsa is not null && h != HashAlgorithmName.SHA1 && rsa.VerifyData(data, sig, h, RSASignaturePadding.Pss);
    }

    public static HashAlgorithmName HashFromOid(string oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
        "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
        _ => default,
    };

    /// <summary>EKU өргөтгөл яг нэг, critical, зөвхөн timeStamping (RFC 3161 §2.3; Go eidcrypto.IsTSASigningCert).</summary>
    public static bool IsTsaSigningCert(X509Certificate2 c)
    {
        int n = 0;
        foreach (var e in c.Extensions)
        {
            if (e.Oid?.Value != OidExtKeyUsage) continue;
            n++;
            try
            {
                var r = new AsnReader(e.RawData, AsnEncodingRules.DER);
                var seq = r.ReadSequence();
                if (r.HasData) return false;
                var oids = new List<string>();
                while (seq.HasData) oids.Add(seq.ReadObjectIdentifier());
                if (!e.Critical || oids.Count != 1 || oids[0] != OidKpTimeStamping) return false;
            }
            catch (AsnContentException)
            {
                return false;
            }
        }
        return n == 1;
    }

    public static bool HasEku(X509Certificate2 c, string oid)
    {
        foreach (var e in c.Extensions)
            if (e is X509EnhancedKeyUsageExtension eku)
                foreach (var o in eku.EnhancedKeyUsages)
                    if (o.Value == oid) return true;
        return false;
    }

    /// <summary>AIA-ийн OCSP URI-ууд (Go Certificate.OCSPServer, дарааллаар).</summary>
    public static List<string> OcspServers(X509Certificate2 c)
    {
        var list = new List<string>();
        foreach (var e in c.Extensions)
        {
            if (e.Oid?.Value != OidAia) continue;
            var seq = new AsnReader(e.RawData, AsnEncodingRules.DER).ReadSequence();
            while (seq.HasData)
            {
                var ad = seq.ReadSequence();
                var method = ad.ReadObjectIdentifier();
                var tag = ad.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
                {
                    var uri = ad.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));
                    if (method == OidAdOcsp) list.Add(uri);
                }
                else
                {
                    ad.ReadEncodedValue();
                }
            }
        }
        return list;
    }

    /// <summary>CRL DP-ийн fullName URI-ууд (Go Certificate.CRLDistributionPoints).</summary>
    public static List<string> CrlDistributionPoints(X509Certificate2 c)
    {
        var list = new List<string>();
        foreach (var e in c.Extensions)
        {
            if (e.Oid?.Value != OidCrlDp) continue;
            var seq = new AsnReader(e.RawData, AsnEncodingRules.DER).ReadSequence();
            while (seq.HasData)
            {
                var dp = seq.ReadSequence();
                if (!dp.HasData || !dp.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) continue;
                var dpName = dp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                if (!dpName.HasData || !dpName.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) continue;
                var full = dpName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                while (full.HasData)
                {
                    var t = full.PeekTag();
                    if (t.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
                        list.Add(full.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)));
                    else
                        full.ReadEncodedValue();
                }
            }
        }
        return list;
    }

    public static DateTimeOffset ReadTime(AsnReader r)
    {
        var t = r.PeekTag();
        if (t.HasSameClassAndValue(Asn1Tag.UtcTime)) return r.ReadUtcTime();
        return r.ReadGeneralizedTime();
    }
}

internal sealed record AlgorithmId(string Oid, byte[]? Params)
{
    public static AlgorithmId Read(AsnReader r)
    {
        var s = r.ReadSequence();
        var oid = s.ReadObjectIdentifier();
        byte[]? p = s.HasData ? s.ReadEncodedValue().ToArray() : null;
        return new AlgorithmId(oid, p);
    }
}

/// <summary>X.509 CRL (Go x509.ParseRevocationList-ийн хэрэгтэй хэсэг).</summary>
internal sealed class Crl
{
    public byte[] Der { get; private init; } = Array.Empty<byte>();
    public byte[] RawIssuer { get; private init; } = Array.Empty<byte>();
    public DateTimeOffset ThisUpdate { get; private init; }
    public DateTimeOffset? NextUpdate { get; private init; }

    /// <summary>authorityKeyIdentifier-ийн keyIdentifier (хоосон — байхгүй).</summary>
    public byte[] AuthorityKeyId { get; private set; } = Array.Empty<byte>();

    public List<BigInteger> Revoked { get; } = new();

    public static Crl Parse(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var cl = r.ReadSequence();
        if (r.HasData) throw new FormatException("crl: trailing data");
        var tbs = cl.ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) tbs.ReadInteger();
        AlgorithmId.Read(tbs);
        var issuer = tbs.ReadEncodedValue().ToArray();
        var thisUpdate = X509Util.ReadTime(tbs);
        DateTimeOffset? next = null;
        if (tbs.HasData && (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) || tbs.PeekTag().HasSameClassAndValue(Asn1Tag.GeneralizedTime)))
            next = X509Util.ReadTime(tbs);
        var crl = new Crl { Der = der, RawIssuer = issuer, ThisUpdate = thisUpdate, NextUpdate = next };
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            var rev = tbs.ReadSequence();
            while (rev.HasData)
            {
                var e = rev.ReadSequence();
                crl.Revoked.Add(e.ReadInteger());
            }
        }
        var ctx0 = new Asn1Tag(TagClass.ContextSpecific, 0);
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(ctx0))
        {
            var exts = tbs.ReadSequence(ctx0).ReadSequence();
            while (exts.HasData)
            {
                var ext = exts.ReadSequence();
                var oid = ext.ReadObjectIdentifier();
                if (ext.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean)) ext.ReadBoolean();
                var val = ext.ReadOctetString();
                if (oid != "2.5.29.35") continue;
                var aki = new AsnReader(val, AsnEncodingRules.DER).ReadSequence();
                if (aki.HasData && aki.PeekTag().HasSameClassAndValue(ctx0)) crl.AuthorityKeyId = aki.ReadOctetString(ctx0);
            }
        }
        return crl;
    }
}
