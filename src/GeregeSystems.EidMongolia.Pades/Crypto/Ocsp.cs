using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

internal enum OcspStatus
{
    Good,
    Revoked,
    Unknown,
}

internal sealed class OcspResponse
{
    public OcspStatus Status { get; init; }
    public DateTimeOffset ThisUpdate { get; init; }
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>Delegated responder-ийн гэрчилгээ (certs[0]); байхгүй бол null.</summary>
    public X509Certificate2? Certificate { get; init; }
}

/// <summary>RFC 6960 OCSP — Go golang.org/x/crypto/ocsp-ийн CreateRequest/ParseResponseForCert-тэй ижил байт/семантик.</summary>
internal static class Ocsp
{
    private const string OidSha1 = "1.3.14.3.2.26";
    private const string OidBasic = "1.3.6.1.5.5.7.48.1.1";

    /// <summary>OCSPRequest{ tbsRequest{ requestList{ Request{ CertID(SHA-1, NULL params) } } } } — version/requestorName/extensions-гүй.</summary>
    public static byte[] CreateRequest(X509Certificate2 cert, X509Certificate2 issuer)
    {
        var nameHash = SHA1.HashData(issuer.SubjectName.RawData);
        var keyHash = SHA1.HashData(issuer.PublicKey.EncodedKeyValue.RawData);
        var certId = Der.Seq(Der.AlgId(OidSha1, true), Der.OctetString(nameHash), Der.OctetString(keyHash), Der.Integer(Cms.Serial(cert)));
        return Der.Seq(Der.Seq(Der.Seq(Der.Seq(certId))));
    }

    /// <summary>Go ocsp.ParseResponseForCert: cert-ийн серийн хариуг сонгож, гарын үсгийг (delegated бол issuer-ээр баталгаажсан responder-оор) шалгана.</summary>
    public static OcspResponse ParseForCert(byte[] der, X509Certificate2 cert, X509Certificate2 issuer)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var resp = r.ReadSequence();
        var stBytes = resp.ReadEnumeratedBytes().Span;
        int status = stBytes.Length == 1 ? stBytes[0] : -1;
        if (status != 0) throw new FormatException("ocsp: response status " + status);
        var rb = resp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        if (rb.ReadObjectIdentifier() != OidBasic) throw new FormatException("ocsp: bad response type");
        var basicDer = rb.ReadOctetString();

        var basic = new AsnReader(basicDer, AsnEncodingRules.DER).ReadSequence();
        var tbsRaw = basic.ReadEncodedValue().ToArray();
        var alg = AlgorithmId.Read(basic);
        var sig = basic.ReadBitString(out _);
        X509Certificate2? responder = null;
        if (basic.HasData && basic.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var certs = basic.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
            if (certs.HasData) responder = X509Util.Parse(certs.ReadEncodedValue().ToArray());
        }

        var tbs = new AsnReader(tbsRaw, AsnEncodingRules.DER).ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) tbs.ReadEncodedValue(); // version
        tbs.ReadEncodedValue(); // responderID
        tbs.ReadGeneralizedTime(); // producedAt
        var responses = tbs.ReadSequence();
        OcspResponse? match = null;
        var serial = Cms.Serial(cert);
        if (!responses.HasData) throw new FormatException("ocsp: no responses");
        while (responses.HasData)
        {
            var single = responses.ReadSequence();
            var certId = single.ReadSequence();
            AlgorithmId.Read(certId);
            certId.ReadOctetString();
            certId.ReadOctetString();
            BigInteger sn = certId.ReadInteger();
            var stTag = single.PeekTag();
            OcspStatus st;
            if (stTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) st = OcspStatus.Good;
            else if (stTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1))) st = OcspStatus.Revoked;
            else st = OcspStatus.Unknown;
            single.ReadEncodedValue();
            var thisUpdate = single.ReadGeneralizedTime();
            DateTimeOffset? next = null;
            if (single.HasData && single.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                next = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadGeneralizedTime();
            if (match is null && sn == serial)
                match = new OcspResponse { Status = st, ThisUpdate = thisUpdate, NextUpdate = next, Certificate = responder };
        }
        if (match is null) throw new FormatException("ocsp: no response matching the supplied certificate");

        if (responder is not null)
        {
            if (!X509Util.Verify(responder, alg, tbsRaw, sig, allowSha1: true)) throw new FormatException("ocsp: bad signature on embedded certificate");
            var (rtbs, ralg, rsig) = X509Util.SplitSigned(responder.RawData);
            if (!X509Util.Verify(issuer, ralg, rtbs, rsig, allowSha1: true)) throw new FormatException("ocsp: responder not signed by issuer");
        }
        else if (!X509Util.Verify(issuer, alg, tbsRaw, sig, allowSha1: true))
        {
            throw new FormatException("ocsp: bad signature");
        }
        return match;
    }

    /// <summary>Хариуг олгогч өөрөө, эсвэл OCSPSigning EKU-тэй responder зурсан.</summary>
    public static bool ResponderOk(OcspResponse r, X509Certificate2 issuer) =>
        r.Certificate is null || X509Util.Equal(r.Certificate, issuer) || X509Util.HasEku(r.Certificate, X509Util.OidKpOcspSigning);
}
