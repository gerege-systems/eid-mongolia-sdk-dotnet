using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace GeregeSystems.EidMongolia.Pades.Validation;

/// <summary>X.509 extension (TS Extension).</summary>
internal sealed record ValExtension(string Oid, bool Critical, ReadOnlyMemory<byte> Value);

/// <summary>Гэрчилгээ задрахгүй (TS CertError).</summary>
internal sealed class ValCertException : Exception
{
    public ValCertException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// ValidatePdf-ийн X.509 — TS SDK src/pades/x509.ts parseCertificate/verifySignature-ийн порт (тайлангийн утгууд TS/Go-тэй
/// ижил байхын тулд core-ийн чанд <c>ParsedCert</c> биш). Нэмэлт (fail-closed, owner-ийн шийдвэр): RSA түлхүүр &lt; 2048 бит
/// бол ямар ч гарын үсэг таарахгүй.
/// </summary>
internal sealed class ValCert
{
    public const string OidRsaEncryption = "1.2.840.113549.1.1.1";
    public const string OidRsaPss = "1.2.840.113549.1.1.10";
    public const string OidSha256WithRsa = "1.2.840.113549.1.1.11";
    public const string OidSha384WithRsa = "1.2.840.113549.1.1.12";
    public const string OidSha512WithRsa = "1.2.840.113549.1.1.13";
    public const string OidEcPublicKey = "1.2.840.10045.2.1";
    public const string OidEcdsaSha256 = "1.2.840.10045.4.3.2";
    public const string OidEcdsaSha384 = "1.2.840.10045.4.3.3";
    public const string OidEcdsaSha512 = "1.2.840.10045.4.3.4";
    public const string OidP256 = "1.2.840.10045.3.1.7";
    public const string OidP384 = "1.3.132.0.34";
    public const string OidP521 = "1.3.132.0.35";
    public const string OidSha1 = "1.3.14.3.2.26";
    public const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    public const string OidSha384 = "2.16.840.1.101.3.4.2.2";
    public const string OidSha512 = "2.16.840.1.101.3.4.2.3";
    public const string OidExtKeyUsage = "2.5.29.37";
    public const string OidKeyUsage = "2.5.29.15";
    public const string OidBasicConstraints = "2.5.29.19";
    public const string OidNameConstraints = "2.5.29.30";
    public const string OidCrlDp = "2.5.29.31";
    public const string OidAia = "1.3.6.1.5.5.7.1.1";
    public const string OidOcspMethod = "1.3.6.1.5.5.7.48.1";
    public const string OidKpTimeStamping = "1.3.6.1.5.5.7.3.8";
    public const string OidKpOcspSigning = "1.3.6.1.5.5.7.3.9";
    public const string OidKpAny = "2.5.29.37.0";

    /// <summary>RSA modulus-ийн доод хэмжээ (бит) — core <c>ParsedCert.MinRsaBits</c>-тэй ижил.</summary>
    public const int MinRsaBits = 2048;

    /// <summary>RSA modulus-ийн дээд хэмжээ (бит) — халдагчийн асар том түлхүүрээр шалгалтыг удаашруулахгүй.</summary>
    public const int MaxRsaBits = 8192;

    /// <summary>RSA public exponent ≤ 2^32 − 1 (их бол тэр гэрчилгээ ашиглагдахгүй).</summary>
    private static bool SmallExponent(RSA rsa)
    {
        var e = rsa.ExportParameters(false).Exponent;
        if (e is null) return false;
        int i = 0;
        while (i < e.Length && e[i] == 0) i++;
        return e.Length - i <= 4;
    }

    private ValCert()
    {
    }

    public byte[] Raw { get; private init; } = Array.Empty<byte>();
    public byte[] Tbs { get; private init; } = Array.Empty<byte>();
    public int Version { get; private init; }

    /// <summary>INTEGER агуулга.</summary>
    public byte[] Serial { get; private init; } = Array.Empty<byte>();
    public Asn1Node SigAlg { get; private init; } = null!;
    public byte[] Signature { get; private init; } = Array.Empty<byte>();
    public byte[] RawIssuer { get; private init; } = Array.Empty<byte>();
    public byte[] RawSubject { get; private init; } = Array.Empty<byte>();

    /// <summary>SubjectPublicKeyInfo TLV.</summary>
    public byte[] Spki { get; private init; } = Array.Empty<byte>();
    public string KeyAlg { get; private init; } = "";
    public string? Curve { get; private init; }

    /// <summary>BIT STRING-ийн түлхүүрийн байт (unused-bits байтгүй).</summary>
    public byte[] PublicKey { get; private init; } = Array.Empty<byte>();
    public PreciseTime NotBefore { get; private init; }
    public PreciseTime NotAfter { get; private init; }
    public List<ValExtension> Extensions { get; } = new();
    public List<string> OcspServers { get; } = new();
    public List<string> CrlDps { get; } = new();
    public bool IsCa { get; private set; }
    public bool BasicConstraintsValid { get; private set; }

    /// <summary>Go x509.KeyUsage bit-үүд (0 = байхгүй); bit 0 = digitalSignature.</summary>
    public int KeyUsage { get; private set; }
    public List<string> ExtKeyUsage { get; private set; } = new();

    public GoTime NotBeforeGo => GoTime.FromUnixMs(NotBefore.UnixMs);
    public GoTime NotAfterGo => GoTime.FromUnixMs(NotAfter.UnixMs);

    public BigInteger SerialValue => Asn1.IntValue(Serial);

    private string? _id;

    /// <summary>DER-ийн SHA-256 hex — кэш/давхардлын түлхүүр.</summary>
    public string Id => _id ??= Asn1.Hex(Asn1.Digest("SHA-256", Raw));

    public ReadOnlyMemory<byte>? Extension(string oid)
    {
        foreach (var e in Extensions)
            if (e.Oid == oid) return e.Value;
        return null;
    }

    private static byte[] BitString(Asn1Node? n)
    {
        Asn1.Expect(n, Asn1.BitString, "BIT STRING");
        if (n!.Value.Length == 0) throw new Asn1Exception("BIT STRING empty");
        return n.Value.Span[1..].ToArray();
    }

    /// <summary>TS parseCertificate.</summary>
    public static ValCert Parse(ReadOnlyMemory<byte> der)
    {
        try
        {
            var top = Asn1.ParseOne(der);
            Asn1.Expect(top, Asn1.Sequence, "Certificate");
            var parts = Asn1.Children(top);
            var tbs = Asn1.Expect(Asn1.At(parts, 0), Asn1.Sequence, "TBSCertificate");
            var f = Asn1.Children(tbs);
            int i = 0;
            int version = 1;
            if (Asn1.At(f, 0)?.Tag == 0xa0)
            {
                var v = Asn1.Expect(Asn1.At(Asn1.Children(f[0]), 0), Asn1.Integer, "version");
                version = (v.Value.Length > 0 ? v.Value.Span[0] : throw new Asn1Exception("version")) + 1;
                i++;
            }
            var serial = Asn1.Expect(Asn1.At(f, i++), Asn1.Integer, "serial").Value.ToArray();
            i++; // signature AlgorithmIdentifier
            var issuer = Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "issuer");
            var validity = Asn1.Children(Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "validity"));
            var subject = Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "subject");
            var spki = Asn1.Expect(Asn1.At(f, i++), Asn1.Sequence, "SPKI");
            var sp = Asn1.Children(spki);
            var algParts = Asn1.Children(Asn1.Expect(Asn1.At(sp, 0), Asn1.Sequence, "AlgorithmIdentifier"));
            var keyAlg = Asn1.OidString(Asn1.Expect(Asn1.At(algParts, 0), Asn1.Oid, "alg"));
            string? curve = keyAlg == OidEcPublicKey && Asn1.At(algParts, 1)?.Tag == Asn1.Oid ? Asn1.OidString(algParts[1]) : null;
            var exts = new List<ValExtension>();
            for (; i < f.Count; i++)
            {
                if (f[i].Tag != 0xa3) continue;
                foreach (var e in Asn1.Children(Asn1.Expect(Asn1.At(Asn1.Children(f[i]), 0), Asn1.Sequence, "extensions")))
                {
                    var p = Asn1.Children(e);
                    var o = Asn1.OidString(Asn1.Expect(Asn1.At(p, 0), Asn1.Oid, "ext oid"));
                    bool critical = false;
                    var val = Asn1.At(p, 1);
                    if (val?.Tag == Asn1.Boolean)
                    {
                        critical = val.Value.Length > 0 && val.Value.Span[0] != 0;
                        val = Asn1.At(p, 2);
                    }
                    exts.Add(new ValExtension(o, critical, Asn1.Expect(val, Asn1.OctetString, "ext value").Value));
                }
            }
            var c = new ValCert
            {
                Raw = top.Raw.ToArray(),
                Tbs = tbs.Raw.ToArray(),
                Version = version,
                Serial = serial,
                SigAlg = Asn1.Expect(Asn1.At(parts, 1), Asn1.Sequence, "sigAlg"),
                Signature = BitString(Asn1.At(parts, 2)),
                RawIssuer = issuer.Raw.ToArray(),
                RawSubject = subject.Raw.ToArray(),
                Spki = spki.Raw.ToArray(),
                KeyAlg = keyAlg,
                Curve = curve,
                PublicKey = BitString(Asn1.At(sp, 1)),
                NotBefore = Asn1.ParsePreciseTime(Asn1.At(validity, 0) ?? throw new Asn1Exception("validity")),
                NotAfter = Asn1.ParsePreciseTime(Asn1.At(validity, 1) ?? throw new Asn1Exception("validity")),
            };
            // Subject/Issuer-ийг энд задална: тайлангийн нэр (NameString) хожим унавал баримт бүхэлдээ биш энэ гарын үсэг л
            // malformed_signature болно.
            GoFmt.CheckName(c.RawSubject);
            GoFmt.CheckName(c.RawIssuer);
            c.Extensions.AddRange(exts);
            foreach (var e in exts) c.ParseExtension(e);
            return c;
        }
        catch (Exception e) when (e is Asn1Exception or FormatException or OverflowException or ArgumentException or IndexOutOfRangeException)
        {
            throw new ValCertException("certificate: " + e.Message, e);
        }
    }

    /// <summary>keyUsage BIT STRING агуулга → Go x509.KeyUsage: зөвхөн bit 0–8.</summary>
    private static int KeyUsageBits(ReadOnlySpan<byte> bs)
    {
        int ku = 0;
        for (int k = 0; k < 9 && 1 + (k >> 3) < bs.Length; k++)
            if ((bs[1 + (k >> 3)] & (0x80 >> (k & 7))) != 0) ku |= 1 << k;
        return ku;
    }

    private void ParseExtension(ValExtension e)
    {
        var n = Asn1.ParseOne(e.Value);
        switch (e.Oid)
        {
            case OidBasicConstraints:
                {
                    BasicConstraintsValid = true;
                    var p = Asn1.Children(n);
                    var b = Asn1.At(p, 0);
                    IsCa = b?.Tag == Asn1.Boolean && b.Value.Length > 0 && b.Value.Span[0] != 0;
                    break;
                }
            case OidKeyUsage:
                KeyUsage = KeyUsageBits(n.Value.Span);
                break;
            case OidExtKeyUsage:
                {
                    // SEQUENCE OF OBJECT IDENTIFIER — бусад нь гэрчилгээг задрахгүй болгоно (Go шиг).
                    var l = new List<string>();
                    foreach (var x in Asn1.Children(Asn1.Expect(n, Asn1.Sequence, "EKU SEQUENCE")))
                        l.Add(Asn1.OidString(Asn1.Expect(x, Asn1.Oid, "EKU OID")));
                    ExtKeyUsage = l;
                    break;
                }
            case OidAia:
                foreach (var ad in Asn1.Children(n))
                {
                    var p = Asn1.Children(ad);
                    var m = Asn1.At(p, 0);
                    var loc = Asn1.At(p, 1);
                    if (m is not null && loc is not null && Asn1.OidString(m) == OidOcspMethod && loc.Tag == 0x86)
                        OcspServers.Add(Latin1String(loc.Value.Span));
                }
                break;
            case OidCrlDp:
                foreach (var dp in Asn1.Children(n))
                {
                    foreach (var f in Asn1.Children(dp))
                    {
                        if (f.Tag != 0xa0) continue; // distributionPoint
                        foreach (var fn in Asn1.Children(f))
                        {
                            if (fn.Tag != 0xa0) continue; // fullName
                            foreach (var gn in Asn1.Children(fn))
                                if (gn.Tag == 0x86) CrlDps.Add(Latin1String(gn.Value.Span));
                        }
                    }
                }
                break;
        }
    }

    private static string Latin1String(ReadOnlySpan<byte> b) => System.Text.Encoding.Latin1.GetString(b);

    /// <summary>APPEARANCE_SPEC.md §6.1 — e-Seal гэрчилгээ: CA биш, KU nonRepudiation, digitalSignature үгүй, EKU үгүй.</summary>
    public bool IsSealCertificate => !IsCa && (KeyUsage & 2) != 0 && (KeyUsage & 1) == 0 && ExtKeyUsage.Count == 0;

    /// <summary>TS sealCertificateDER — задрахгүй бол false.</summary>
    public static bool SealCertificateDer(byte[]? der)
    {
        if (der is null) return false;
        try
        {
            return Parse(der).IsSealCertificate;
        }
        catch (ValCertException)
        {
            return false;
        }
    }

    /// <summary>Go IsTSASigningCert: EKU яг нэг, critical, яг { timeStamping }.</summary>
    public bool IsTsaSigningCert()
    {
        ValExtension? e = null;
        int n = 0;
        foreach (var x in Extensions)
        {
            if (x.Oid != OidExtKeyUsage) continue;
            n++;
            e = x;
        }
        if (n != 1) return false;
        try
        {
            var oids = Asn1.Children(Asn1.ParseOne(e!.Value));
            return e.Critical && oids.Count == 1 && oids[0].Tag == Asn1.Oid && Asn1.OidString(oids[0]) == OidKpTimeStamping;
        }
        catch (Asn1Exception)
        {
            return false;
        }
    }

    // ── гарын үсэг ──

    private sealed record Scheme(string Kind, HashAlgorithmName Hash, int Salt);

    private static HashAlgorithmName? HashByOid(string oid) => oid switch
    {
        OidSha1 => HashAlgorithmName.SHA1,
        OidSha256 => HashAlgorithmName.SHA256,
        OidSha384 => HashAlgorithmName.SHA384,
        OidSha512 => HashAlgorithmName.SHA512,
        _ => null,
    };

    private static Scheme SchemeFor(Asn1Node alg)
    {
        var p = Asn1.Children(alg);
        var o = Asn1.OidString(Asn1.Expect(Asn1.At(p, 0), Asn1.Oid, "sigAlg"));
        switch (o)
        {
            case "1.2.840.113549.1.1.5": return new Scheme("rsa", HashAlgorithmName.SHA1, 0);
            case OidSha256WithRsa: return new Scheme("rsa", HashAlgorithmName.SHA256, 0);
            case OidSha384WithRsa: return new Scheme("rsa", HashAlgorithmName.SHA384, 0);
            case OidSha512WithRsa: return new Scheme("rsa", HashAlgorithmName.SHA512, 0);
            case "1.2.840.10045.4.1": return new Scheme("ecdsa", HashAlgorithmName.SHA1, 0);
            case OidEcdsaSha256: return new Scheme("ecdsa", HashAlgorithmName.SHA256, 0);
            case OidEcdsaSha384: return new Scheme("ecdsa", HashAlgorithmName.SHA384, 0);
            case OidEcdsaSha512: return new Scheme("ecdsa", HashAlgorithmName.SHA512, 0);
            case OidRsaPss:
                {
                    // RSASSA-PSS-params { [0] hashAlgorithm, [1] maskGen, [2] saltLength }
                    var hash = HashAlgorithmName.SHA1;
                    int salt = 20;
                    if (Asn1.At(p, 1) is { } prm)
                    {
                        foreach (var f in Asn1.Children(prm))
                        {
                            if (f.Tag == 0xa0) hash = HashByOid(Asn1.OidString(Asn1.Children(Asn1.Children(f)[0])[0])) ?? hash;
                            if (f.Tag == 0xa2) salt = Asn1.Children(f)[0].Value.Span[0];
                        }
                    }
                    return new Scheme("pss", hash, salt);
                }
        }
        throw new ValCertException("unsupported signature algorithm: " + o);
    }

    private static int HashLen(HashAlgorithmName h) =>
        h == HashAlgorithmName.SHA1 ? 20 : h == HashAlgorithmName.SHA256 ? 32 : h == HashAlgorithmName.SHA384 ? 48 : h == HashAlgorithmName.SHA512 ? 64 : -1;

    /// <summary>
    /// TS verifySignature: <paramref name="alg"/> (AlgorithmIdentifier TLV)-ийн гарын үсэг энэ гэрчилгээний түлхүүрээр. Алдаа бүр
    /// false. PSS: .NET нь saltLength = hLen-ийг л шалгадаг (Go x509-тэй ижил) — өөр бол false.
    /// </summary>
    public bool Verify(Asn1Node alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig)
    {
        Scheme sch;
        try
        {
            sch = SchemeFor(alg);
        }
        catch (Exception e) when (e is ValCertException or Asn1Exception or ArgumentException or IndexOutOfRangeException)
        {
            return false;
        }
        return VerifyWith(sch, data, sig);
    }

    private bool VerifyWith(Scheme sch, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig)
    {
        try
        {
            if (sch.Kind == "ecdsa")
            {
                if (KeyAlg != OidEcPublicKey || Curve is not (OidP256 or OidP384 or OidP521)) return false;
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(Spki, out _);
                return ec.VerifyData(data, sig, sch.Hash, DSASignatureFormat.Rfc3279DerSequence);
            }
            if (KeyAlg != OidRsaEncryption) return false;
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Spki, out _);
            if (rsa.KeySize < MinRsaBits || rsa.KeySize > MaxRsaBits || !SmallExponent(rsa)) return false;
            if (sch.Kind == "pss")
            {
                // Go x509: PSS зөвхөн SHA-256/384/512, saltLength = hLen.
                if (sch.Hash == HashAlgorithmName.SHA1 || sch.Salt != HashLen(sch.Hash)) return false;
                return rsa.VerifyData(data, sig, sch.Hash, RSASignaturePadding.Pss);
            }
            return rsa.VerifyData(data, sig, sch.Hash, RSASignaturePadding.Pkcs1);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or FormatException)
        {
            return false;
        }
    }

    /// <summary>Go Certificate.CheckSignatureFrom (SHA-1/MD5 татгалзана; TS evaluate checkSigFrom).</summary>
    public bool CheckSignatureFrom(ValCert parent)
    {
        if ((parent.Version == 3 && !parent.BasicConstraintsValid) || (parent.BasicConstraintsValid && !parent.IsCa)) return false;
        if (parent.KeyUsage != 0 && (parent.KeyUsage & (1 << 5)) == 0) return false;
        try
        {
            if (ValRevocation.Sha1Sig.Contains(Asn1.OidString(Asn1.Children(SigAlg)[0]))) return false;
        }
        catch (Exception e) when (e is Asn1Exception or ArgumentException)
        {
            return false;
        }
        return parent.Verify(SigAlg, Tbs, Signature);
    }

    /// <summary>a, b нь ижил гэрчилгээ (байт-ижил) эсвэл ижил subject + түлхүүр (TS sameCertKey).</summary>
    public static bool SameCertKey(ValCert a, ValCert b) =>
        a.Raw.AsSpan().SequenceEqual(b.Raw) || (a.RawSubject.AsSpan().SequenceEqual(b.RawSubject) && a.Spki.AsSpan().SequenceEqual(b.Spki));
}
