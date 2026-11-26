using System;
using System.Collections.Generic;
using System.Numerics;

namespace GeregeSystems.EidMongolia.Pades.Validation;

/// <summary>Задалсан CRL (TS ParsedCRL).</summary>
internal sealed class ValCrl
{
    public byte[] RawIssuer { get; init; } = Array.Empty<byte>();
    public byte[] Tbs { get; init; } = Array.Empty<byte>();
    public Asn1Node SigAlg { get; init; } = null!;
    public byte[] Sig { get; init; } = Array.Empty<byte>();
    public GoTime ThisUpdate { get; init; }

    /// <summary>Тэг — байхгүй.</summary>
    public GoTime NextUpdate { get; init; }

    /// <summary>authorityKeyIdentifier-ийн keyIdentifier (хоосон — байхгүй).</summary>
    public byte[] AuthorityKeyId { get; init; } = Array.Empty<byte>();
    public List<(BigInteger Serial, GoTime Time)> Revoked { get; } = new();
}

/// <summary>OCSP SingleResponse (TS OCSPResp).</summary>
internal sealed class ValOcspResp
{
    public string Status { get; init; } = "";
    public BigInteger Serial { get; init; }
    public PreciseTime ThisUpdate { get; init; }
    public PreciseTime? NextUpdate { get; init; }
    public PreciseTime? RevokedAt { get; init; }
    public ValCert? Certificate { get; init; }
}

/// <summary>OCSP задрахгүй / шалгалт унав (TS-д throw).</summary>
internal sealed class ValOcspException : Exception
{
    public ValOcspException(string message) : base(message) { }
}

/// <summary>
/// Цуцлалтын нотолгооны (OCSP/CRL) шинэлэг байдал ба тохирлын дүрэм — TS SDK src/pades/revocation.ts ба ltv.ts-ийн OCSP
/// задлагч (Go validate.FreshAt / OCSPCertIDMatches / CRLFor / CRLListed, x/crypto/ocsp ParseResponseForCert)-ийн порт. Энэ
/// нь PAdES LTV-ийн 24 цагийн дүрэм (RP checker-ийн 48 цагийн дүрэмтэй холихгүй).
/// </summary>
internal static class ValRevocation
{
    public const long MaxAgeMs = 24 * 3600_000L;
    public const long ClockSkewMs = 5 * 60_000L;
    private const string OidAki = "2.5.29.35";
    private const string OidOcspBasic = "1.3.6.1.5.5.7.48.1.1";

    /// <summary>SHA-1/MD5 гарын үсгийн алгоритм (Go CheckSignature татгалзана).</summary>
    public static readonly HashSet<string> Sha1Sig = new(StringComparer.Ordinal)
    {
        "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.10040.4.3", "1.2.840.113549.1.1.4",
    };

    private static readonly Dictionary<string, string> OcspHashes = new(StringComparer.Ordinal)
    {
        ["1.3.14.3.2.26"] = "SHA-1",
        ["2.16.840.1.101.3.4.2.1"] = "SHA-256",
        ["2.16.840.1.101.3.4.2.2"] = "SHA-384",
        ["2.16.840.1.101.3.4.2.3"] = "SHA-512",
    };

    /// <summary>Go validate.FreshAt.</summary>
    public static bool FreshAt(GoTime thisUpdate, GoTime nextUpdate, GoTime at, GoTime now)
    {
        if (thisUpdate.IsZero || GoTime.After(thisUpdate, now.AddMs(ClockSkewMs))) return false;
        if (!nextUpdate.IsZero && GoTime.Before(nextUpdate, at.AddMs(-ClockSkewMs))) return false;
        if (!GoTime.Before(thisUpdate, at.AddMs(-MaxAgeMs))) return true;
        return !nextUpdate.IsZero && !GoTime.After(thisUpdate, at);
    }

    /// <summary>OCSP SingleResponse-ийн thisUpdate/nextUpdate-ийг FreshAt-д.</summary>
    public static bool OcspFreshAt(ValOcspResp resp, GoTime at, GoTime now) =>
        FreshAt(GoTime.FromPrecise(resp.ThisUpdate), resp.NextUpdate is { } nu ? GoTime.FromPrecise(nu) : GoTime.Zero, at, now);

    /// <summary>Go validate.OCSPCertIDMatches.</summary>
    public static bool OcspCertIdMatches(byte[] der, ValCert cert, ValCert issuer)
    {
        try
        {
            var top = Asn1.Children(Asn1.Expect(Asn1.ReadNode(der), Asn1.Sequence, "OCSPResponse"));
            var st = Asn1.Expect(Asn1.At(top, 0), Asn1.Enumerated, "status");
            if (st.Value.Length != 1 || st.Value.Span[0] != 0) return false;
            var rb = Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(top, 1), 0xa0, "responseBytes")), 0), Asn1.Sequence, "ResponseBytes"));
            Asn1.Expect(Asn1.At(rb, 0), Asn1.Oid, "responseType");
            var basic = Asn1.Children(Asn1.Expect(Asn1.ReadNode(Asn1.Expect(Asn1.At(rb, 1), Asn1.OctetString, "response").Value), Asn1.Sequence, "BasicOCSPResponse"));
            var tf = Asn1.Children(Asn1.Expect(Asn1.At(basic, 0), Asn1.Sequence, "tbsResponseData"));
            int i = 0;
            if (Asn1.At(tf, i)?.Tag == 0xa0) i++;
            if (Asn1.At(tf, i++) is null) return false; // responderID
            Asn1.Expect(Asn1.At(tf, i++), Asn1.GeneralizedTime, "producedAt");
            var singles = Asn1.Children(Asn1.Expect(Asn1.At(tf, i), Asn1.Sequence, "responses"));
            var serial = cert.SerialValue;
            bool found = false;
            foreach (var single in singles)
            {
                var cid = Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(single, Asn1.Sequence, "SingleResponse")), 0), Asn1.Sequence, "CertID"));
                var alg = Asn1.OidString(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(cid, 0), Asn1.Sequence, "hashAlgorithm")), 0), Asn1.Oid, "hash"));
                var nameHash = Asn1.Expect(Asn1.At(cid, 1), Asn1.OctetString, "issuerNameHash").Value;
                var keyHash = Asn1.Expect(Asn1.At(cid, 2), Asn1.OctetString, "issuerKeyHash").Value;
                if (Asn1.IntValue(Asn1.Expect(Asn1.At(cid, 3), Asn1.Integer, "serial").Value.Span) != serial) continue;
                if (!OcspHashes.TryGetValue(alg, out var h)) return false;
                if (!nameHash.Span.SequenceEqual(Asn1.Digest(h, issuer.RawSubject)) || !keyHash.Span.SequenceEqual(Asn1.Digest(h, issuer.PublicKey))) return false;
                found = true;
            }
            return found;
        }
        catch (Exception e) when (IsParse(e))
        {
            return false;
        }
    }

    internal static bool IsParse(Exception e) =>
        e is Asn1Exception or ValCertException or ValOcspException or ArgumentException or IndexOutOfRangeException or FormatException or OverflowException;

    private static bool IsTime(Asn1Node? n) => n is not null && (n.Tag == Asn1.UtcTime || n.Tag == Asn1.GeneralizedTime);

    /// <summary>x509.ParseRevocationList-ийн хэрэгтэй хэсэг; задрахгүй бол null.</summary>
    public static ValCrl? ParseCrl(byte[] der)
    {
        try
        {
            var top = Asn1.Children(Asn1.Expect(Asn1.ParseOne(der), Asn1.Sequence, "CertificateList"));
            var tbs = Asn1.Expect(Asn1.At(top, 0), Asn1.Sequence, "TBSCertList");
            var sigAlg = Asn1.Expect(Asn1.At(top, 1), Asn1.Sequence, "sigAlg");
            var sigBits = Asn1.Expect(Asn1.At(top, 2), Asn1.BitString, "sig");
            var f = Asn1.Children(tbs);
            int i = 0;
            if (Asn1.At(f, i)?.Tag == Asn1.Integer) i++;
            Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "signature");
            var issuer = Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "issuer");
            var tu = Asn1.At(f, i++);
            if (!IsTime(tu)) return null;
            var thisUpdate = GoTime.FromPrecise(Asn1.ParsePreciseTime(tu!));
            var nextUpdate = GoTime.Zero;
            if (IsTime(Asn1.At(f, i))) nextUpdate = GoTime.FromPrecise(Asn1.ParsePreciseTime(f[i++]));
            var revoked = new List<(BigInteger, GoTime)>();
            if (Asn1.At(f, i)?.Tag == Asn1.Sequence)
            {
                foreach (var e in Asn1.Children(f[i++]))
                {
                    var p = Asn1.Children(Asn1.Expect(e, Asn1.Sequence, "entry"));
                    revoked.Add((Asn1.IntValue(Asn1.Expect(Asn1.At(p, 0), Asn1.Integer, "serial").Value.Span),
                        GoTime.FromPrecise(Asn1.ParsePreciseTime(Asn1.At(p, 1) ?? throw new Asn1Exception("revocationDate")))));
                }
            }
            byte[] aki = Array.Empty<byte>();
            if (Asn1.At(f, i)?.Tag == 0xa0)
            {
                foreach (var ext in Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(f[i]), 0), Asn1.Sequence, "extensions")))
                {
                    var e = Asn1.Children(ext);
                    if (Asn1.OidString(Asn1.Expect(Asn1.At(e, 0), Asn1.Oid, "extnID")) != OidAki) continue;
                    foreach (var x in Asn1.Children(Asn1.ParseOne(Asn1.Expect(Asn1.At(e, e.Count - 1), Asn1.OctetString, "extnValue").Value)))
                    {
                        if (x.Tag == 0x80)
                        {
                            aki = x.Value.ToArray();
                            break;
                        }
                    }
                }
            }
            var crl = new ValCrl
            {
                RawIssuer = issuer.Raw.ToArray(),
                Tbs = tbs.Raw.ToArray(),
                SigAlg = sigAlg,
                Sig = sigBits.Value.Length > 0 ? sigBits.Value.Span[1..].ToArray() : Array.Empty<byte>(),
                ThisUpdate = thisUpdate,
                NextUpdate = nextUpdate,
                AuthorityKeyId = aki,
            };
            crl.Revoked.AddRange(revoked);
            return crl;
        }
        catch (Exception e) when (IsParse(e))
        {
            return null;
        }
    }

    /// <summary>Go RevocationList.CheckSignatureFrom (SHA-1 татгалзана).</summary>
    private static bool CrlSignedBy(ValCrl crl, ValCert issuer)
    {
        if ((issuer.Version == 3 && !issuer.BasicConstraintsValid) || (issuer.BasicConstraintsValid && !issuer.IsCa)) return false;
        if (issuer.KeyUsage != 0 && (issuer.KeyUsage & (1 << 6)) == 0) return false;
        try
        {
            if (Sha1Sig.Contains(Asn1.OidString(Asn1.Children(crl.SigAlg)[0]))) return false;
        }
        catch (Exception e) when (IsParse(e))
        {
            return false;
        }
        return issuer.Verify(crl.SigAlg, crl.Tbs, crl.Sig);
    }

    private static byte[] SubjectKeyId(ValCert c)
    {
        if (c.Extension("2.5.29.14") is not { } v) return Array.Empty<byte>();
        try
        {
            var n = Asn1.ParseOne(v);
            return n.Tag == Asn1.OctetString ? n.Value.ToArray() : Array.Empty<byte>();
        }
        catch (Asn1Exception)
        {
            return Array.Empty<byte>();
        }
    }

    /// <summary>Go validate.CRLFor.</summary>
    public static bool CrlFor(ValCrl crl, ValCert cert, ValCert issuer)
    {
        if (!crl.RawIssuer.AsSpan().SequenceEqual(cert.RawIssuer) || !crl.RawIssuer.AsSpan().SequenceEqual(issuer.RawSubject)) return false;
        var ski = SubjectKeyId(issuer);
        if (crl.AuthorityKeyId.Length > 0 && ski.Length > 0 && !crl.AuthorityKeyId.AsSpan().SequenceEqual(ski)) return false;
        return CrlSignedBy(crl, issuer);
    }

    /// <summary>Go validate.CRLListed — cert-ийн serial crl-д байвал цуцалсан цаг.</summary>
    public static GoTime? CrlListed(ValCrl crl, ValCert cert)
    {
        var serial = cert.SerialValue;
        foreach (var e in crl.Revoked)
            if (e.Serial == serial) return e.Time;
        return null;
    }

    // ── OCSP ──

    /// <summary>x/crypto/ocsp CreateRequest (SHA-1 CertID) — TS ocspRequest.</summary>
    public static byte[] OcspRequest(ValCert c, ValCert issuer)
    {
        var keyHash = Asn1.Digest("SHA-1", issuer.PublicKey);
        var nameHash = Asn1.Digest("SHA-1", issuer.RawSubject);
        var certId = Asn1.Tlv(Asn1.Sequence,
            Asn1.Tlv(Asn1.Sequence, Asn1.OidTlv(ValCert.OidSha1), new byte[] { 0x05, 0x00 }),
            Asn1.Tlv(Asn1.OctetString, nameHash),
            Asn1.Tlv(Asn1.OctetString, keyHash),
            Asn1.Tlv(Asn1.Integer, c.Serial));
        return Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Sequence, Asn1.Tlv(Asn1.Sequence, certId))));
    }

    /// <summary>
    /// x/crypto/ocsp ParseResponseForCert (TS parseOCSP): serial өгвөл тэр serial-ийн хариу, эс бөгөөс яг нэг хариу. issuer
    /// өгвөл гарын үсгийг шалгана. Алдаа бүр <see cref="ValOcspException"/> / задлалтын алдаа.
    /// </summary>
    public static ValOcspResp ParseOcsp(byte[] der, BigInteger? serial, ValCert? issuer)
    {
        var top = Asn1.Children(Asn1.Expect(Asn1.ParseOne(der), Asn1.Sequence, "OCSPResponse"));
        var stv = Asn1.Expect(Asn1.At(top, 0), Asn1.Enumerated, "status").Value.Span;
        if (stv.Length == 0 || stv[0] != 0) throw new ValOcspException("OCSP response status");
        var rb = Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(Asn1.Expect(Asn1.At(top, 1), 0xa0, "responseBytes")), 0), Asn1.Sequence, "ResponseBytes"));
        if (Asn1.OidString(Asn1.Expect(Asn1.At(rb, 0), Asn1.Oid, "responseType")) != OidOcspBasic) throw new ValOcspException("bad OCSP response type");
        var basic = Asn1.Children(Asn1.Expect(Asn1.ParseOne(Asn1.Expect(Asn1.At(rb, 1), Asn1.OctetString, "response").Value), Asn1.Sequence, "BasicOCSPResponse"));
        var tbs = Asn1.Expect(Asn1.At(basic, 0), Asn1.Sequence, "tbsResponseData");
        var sigAlg = Asn1.Expect(Asn1.At(basic, 1), Asn1.Sequence, "sigAlg");
        var sigBitsN = Asn1.Expect(Asn1.At(basic, 2), Asn1.BitString, "signature").Value;
        var sigBits = sigBitsN.Length > 0 ? sigBitsN.Span[1..].ToArray() : Array.Empty<byte>();
        var tf = Asn1.Children(tbs);
        int i = 0;
        if (Asn1.At(tf, 0)?.Tag == 0xa0) i++;
        var rid = Asn1.At(tf, i++) ?? throw new ValOcspException("responder id");
        if (rid.Tag != 0xa1 && rid.Tag != 0xa2) throw new ValOcspException("invalid responder id tag");
        i++; // producedAt
        var responses = Asn1.Children(Asn1.Expect(Asn1.At(tf, i), Asn1.Sequence, "responses"));
        List<Asn1Node>? single = null;
        if (serial is { } sn)
        {
            if (responses.Count == 0) throw new ValOcspException("OCSP response contains bad number of responses");
            foreach (var r in responses)
            {
                var fr = Asn1.Children(r);
                var cidr = Asn1.Children(Asn1.At(fr, 0) ?? throw new ValOcspException("CertID"));
                if (Asn1.IntValue(Asn1.Expect(Asn1.At(cidr, 3), Asn1.Integer, "serial").Value.Span) == sn)
                {
                    single = fr;
                    break;
                }
            }
            if (single is null) throw new ValOcspException("no response matching the supplied certificate");
        }
        else
        {
            if (responses.Count != 1) throw new ValOcspException("OCSP response contains bad number of responses");
            single = Asn1.Children(responses[0]);
        }
        ValCert? certificate = null;
        if (Asn1.At(basic, 3)?.Tag == 0xa0)
        {
            var certs = Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(basic[3]), 0), Asn1.Sequence, "certs"));
            if (certs.Count > 0) certificate = ValCert.Parse(certs[0].Raw);
        }
        if (certificate is not null)
        {
            if (!certificate.Verify(sigAlg, tbs.Raw.Span, sigBits)) throw new ValOcspException("bad signature on embedded certificate");
            if (issuer is not null && !issuer.Verify(certificate.SigAlg, certificate.Tbs, certificate.Signature)) throw new ValOcspException("bad OCSP signature");
        }
        else if (issuer is not null && !issuer.Verify(sigAlg, tbs.Raw.Span, sigBits))
        {
            throw new ValOcspException("bad OCSP signature");
        }
        var cid = Asn1.Children(Asn1.At(single, 0) ?? throw new ValOcspException("CertID"));
        var hashAlg = Asn1.OidString(Asn1.Children(Asn1.At(cid, 0) ?? throw new ValOcspException("hash"))[0]);
        if (!OcspHashes.ContainsKey(hashAlg)) throw new ValOcspException("unsupported issuer hash algorithm");
        var st = Asn1.At(single, 1) ?? throw new ValOcspException("OCSP certStatus");
        string status = st.Tag switch
        {
            0x80 => "good",
            0xa1 => "revoked",
            0x82 => "unknown",
            _ => throw new ValOcspException("OCSP certStatus"),
        };
        PreciseTime? revokedAt = status == "revoked"
            ? Asn1.ParsePreciseTime(Asn1.Expect(Asn1.At(Asn1.Children(st), 0), Asn1.GeneralizedTime, "revocationTime"))
            : null;
        var thisUpdate = Asn1.ParsePreciseTime(Asn1.Expect(Asn1.At(single, 2), Asn1.GeneralizedTime, "thisUpdate"));
        PreciseTime? nextUpdate = null;
        for (int k = 3; k < single.Count; k++)
        {
            var x = single[k];
            if (x.Tag == 0xa0) nextUpdate = Asn1.ParsePreciseTime(Asn1.Children(x)[0]);
            if (x.Tag == 0xa1)
            {
                foreach (var ext in Asn1.Children(Asn1.Children(x)[0]))
                {
                    var e = Asn1.Children(ext);
                    var b = Asn1.At(e, 1);
                    if (b?.Tag == Asn1.Boolean && b.Value.Length > 0 && b.Value.Span[0] != 0) throw new ValOcspException("unsupported critical extension");
                }
            }
        }
        return new ValOcspResp
        {
            Status = status,
            Serial = Asn1.IntValue(Asn1.Expect(Asn1.At(cid, 3), Asn1.Integer, "serial").Value.Span),
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate,
            RevokedAt = revokedAt,
            Certificate = certificate,
        };
    }

    /// <summary>
    /// TS parseOCSPFrom — RFC 6960 §4.2.2.2: олгогч өөрөө зурж өөрийн гэрчилгээг шигтгэсэн хариуг олгогчийн түлхүүрээр шалгана.
    /// </summary>
    public static ValOcspResp ParseOcspFrom(byte[] der, BigInteger? serial, ValCert issuer)
    {
        try
        {
            return ParseOcsp(der, serial, issuer);
        }
        catch (Exception e) when (IsParse(e))
        {
            ValOcspResp alt;
            try
            {
                alt = ParseOcsp(der, serial, null);
            }
            catch (Exception e2) when (IsParse(e2))
            {
                throw;
            }
            if (alt.Certificate is not null && ValCert.SameCertKey(alt.Certificate, issuer) && OcspSignedBy(der, issuer)) return alt;
            throw;
        }
    }

    /// <summary>BasicOCSPResponse-ийн гарын үсэг k-ийн түлхүүрээр.</summary>
    private static bool OcspSignedBy(byte[] der, ValCert k)
    {
        try
        {
            var top = Asn1.Children(Asn1.ParseOne(der));
            var rb = Asn1.Children(Asn1.Children(top[1])[0]);
            var basic = Asn1.Children(Asn1.ParseOne(rb[1].Value));
            var bits = basic[2].Value;
            return bits.Length > 0 && k.Verify(basic[1], basic[0].Raw.Span, bits.Span[1..]);
        }
        catch (Exception e) when (IsParse(e))
        {
            return false;
        }
    }

    /// <summary>TS evaluate responderOK: олгогч өөрөө, эсвэл OCSPSigning EKU-тэй responder.</summary>
    public static bool ResponderOk(ValOcspResp resp, ValCert issuer)
    {
        if (resp.Certificate is null || resp.Certificate.Raw.AsSpan().SequenceEqual(issuer.Raw)) return true;
        return resp.Certificate.ExtKeyUsage.Contains(ValCert.OidKpOcspSigning);
    }
}
