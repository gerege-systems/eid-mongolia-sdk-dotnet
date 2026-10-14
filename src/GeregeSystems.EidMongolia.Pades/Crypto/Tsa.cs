using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

internal sealed record TimestampResult(byte[] RawToken, DateTimeOffset Time, List<X509Certificate2> Certificates);

/// <summary>RFC 3161 — Go reference tsa.go: хүсэлт (SHA-256, 64 бит nonce, certReq), хариуг бүрэн шалгана.</summary>
internal static class Tsa
{
    private static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(10);

    /// <summary>TimeStampReq{ version 1, messageImprint{ sha256 (NULL params), hash }, nonce, certReq TRUE }.</summary>
    public static byte[] Request(byte[] hash, BigInteger nonce) =>
        Der.Seq(
            Der.Integer(1),
            Der.Seq(Der.AlgId(Cms.OidSha256, true), Der.OctetString(hash)),
            Der.Integer(nonce),
            Der.True);

    public static async Task<TimestampResult> TimestampAsync(Fetcher f, string tsaUrl, byte[] signature,
        IReadOnlyList<X509Certificate2> roots, IReadOnlyList<X509Certificate2> inter, DateTimeOffset now, byte[] nonceBytes, CancellationToken ct)
    {
        var sum = SHA256.HashData(signature);
        var nonce = new BigInteger(nonceBytes, isUnsigned: true, isBigEndian: true);
        var body = await f.DoAsync(HttpMethod.Post, tsaUrl, "application/timestamp-query", Request(sum, nonce), ct).ConfigureAwait(false);

        var raw = ParseResponse(body);
        if (!Rfc3161TimestampToken.TryDecode(raw, out var token, out int consumed) || consumed != raw.Length || token is null)
            throw new FormatException("tsa: token parse");
        var info = token.TokenInfo;
        var gotNonce = info.GetNonce();
        if (gotNonce is null || new BigInteger(gotNonce.Value.Span, isUnsigned: false, isBigEndian: true) != nonce)
            throw new FormatException("tsa: nonce mismatch");
        if (info.HashAlgorithmId.Value != Cms.OidSha256 || !info.GetMessageHash().Span.SequenceEqual(sum))
            throw new FormatException("tsa: timestamp hash does not match");

        var certs = TokenCertificates(raw);
        if (!token.VerifySignatureForHash(sum, HashAlgorithmName.SHA256, out var signer, new X509Certificate2Collection(certs.ToArray())) || signer is null)
            throw new FormatException("tsa: token signature");
        if (!X509Util.IsTsaSigningCert(signer))
            throw new FormatException("tsa: signer EKU is not critical {timeStamping} (RFC 3161 §2.3)");
        VerifyChain(signer, certs, roots, inter, info.Timestamp);
        var d = now - info.Timestamp;
        if (d > MaxSkew || d < -MaxSkew) throw new FormatException("tsa: genTime differs from local time");
        if (certs.Count == 0) throw new FormatException("tsa: token has no certificates");
        return new TimestampResult(raw, info.Timestamp, certs);
    }

    /// <summary>TimeStampResp — status granted(0)/grantedWithMods(1), token-ийн түүхий DER.</summary>
    private static byte[] ParseResponse(byte[] body)
    {
        var r = new AsnReader(body, AsnEncodingRules.BER);
        var resp = r.ReadSequence();
        if (r.HasData) throw new FormatException("tsa: trailing data");
        var status = resp.ReadSequence();
        var st = status.ReadInteger();
        if (st != 0 && st != 1) throw new FormatException("tsa: status " + st);
        if (!resp.HasData) throw new FormatException("tsa: no token");
        return resp.ReadEncodedValue().ToArray();
    }

    /// <summary>Token-ий SignedData.certificates — кодчилсон дарааллаар (Go pkcs7.Certificates).</summary>
    public static List<X509Certificate2> TokenCertificates(byte[] token)
    {
        var list = new List<X509Certificate2>();
        var ci = new AsnReader(token, AsnEncodingRules.BER).ReadSequence();
        ci.ReadObjectIdentifier();
        var sd = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        sd.ReadInteger();
        sd.ReadSetOf(true);
        sd.ReadSequence();
        if (sd.HasData && sd.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var set = sd.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 0));
            while (set.HasData)
            {
                var tag = set.PeekTag();
                var enc = set.ReadEncodedValue().ToArray();
                if (tag.HasSameClassAndValue(Asn1Tag.Sequence)) list.Add(X509Util.Parse(enc));
            }
        }
        return list;
    }

    private static void VerifyChain(X509Certificate2 signer, List<X509Certificate2> tokenCerts, IReadOnlyList<X509Certificate2> roots,
        IReadOnlyList<X509Certificate2> inter, DateTimeOffset at)
    {
        using var chain = new X509Chain();
        var p = chain.ChainPolicy;
        p.TrustMode = X509ChainTrustMode.CustomRootTrust;
        foreach (var r in roots) p.CustomTrustStore.Add(r);
        foreach (var c in tokenCerts)
            if (!X509Util.Equal(c, signer)) p.ExtraStore.Add(c);
        foreach (var c in inter)
            if (!X509Util.Equal(c, signer)) p.ExtraStore.Add(c);
        p.RevocationMode = X509RevocationMode.NoCheck;
        p.VerificationTime = at.UtcDateTime;
        p.ApplicationPolicy.Add(new Oid(X509Util.OidKpTimeStamping));
        p.DisableCertificateDownloads = true;
        if (!chain.Build(signer)) throw new FormatException("tsa: certificate chain: " + Describe(chain));
    }

    private static string Describe(X509Chain chain)
    {
        var parts = new List<string>();
        foreach (var s in chain.ChainStatus) parts.Add(s.Status.ToString());
        return string.Join(",", parts);
    }
}
