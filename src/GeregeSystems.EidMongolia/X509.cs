using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GeregeSystems.EidMongolia;

// Validator / OCSP-ийн X.509 давхарга: DER-ийг System.Formats.Asn1-ээр шууд задалж, гарын үсгийг RSA/ECDsa-аар шалгана.
// X509Chain (Windows CAPI / Linux OpenSSL / macOS — платформ бүрд өөр, AIA татаж болзошгүй) ХЭРЭГЛЭХГҮЙ: гинжийг
// ResponseValidator өөрөө угсарна (TS validator.ts verifyChain).
//
// Задлалт ШАЛГАДАГ: чанд DER (AsnReader DER горим, дотоод бүтцийн араас илүү байт үгүй); version 1–3; tbs ба гадна
// signatureAlgorithm байт-ижил; давхардсан extension; issuer/subject Name-ийн утгын мөрийн төрөл (Go parseName-ийн
// жагсаалт); basicConstraints, keyUsage, extKeyUsage, SKI, AKI keyIdentifier, certificatePolicies (OID-ууд),
// authorityInfoAccess (OCSP URI)-ийн бүтэц; RSA (rsaEncryption) / EC (P-256/384/521) түлхүүрийн import; RSA modulus
// ≥ 2048 бит, exponent сондгой ба ≥ 3 (сул бол WeakKey — гарын үсэгт хэзээ ч тэнцэхгүй).
// Задлалт ШАЛГАДАГГҮЙ (Go crypto/x509-тэй ижил гэж ҮЗЭХГҮЙ): subjectAltName, nameConstraints (байвал гинж fail-closed),
// cRLDistributionPoints, policy qualifiers / constraints / mappings-ийн агуулга; сөрөг serial; extension ба version-ий
// уялдаа; issuer/subjectUniqueID; UTCTime/GeneralizedTime-ийн оны дүрэм (AsnReader-ийн DER дүрэм л); Ed25519 ба бусад
// түлхүүрийн төрөл (KeyKind.Other — гарын үсэгт тэнцэхгүй).

/// <summary>AlgorithmIdentifier: OID + параметрийн түүхий DER (алга бол null).</summary>
internal sealed record AlgorithmId(string Oid, byte[]? Parameters)
{
    public static AlgorithmId Read(AsnReader r)
    {
        var s = r.ReadSequence();
        var oid = s.ReadObjectIdentifier();
        byte[]? p = s.HasData ? s.ReadEncodedValue().ToArray() : null;
        s.ThrowIfNotEmpty();
        return new AlgorithmId(oid, p);
    }

    public static AlgorithmId Parse(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var a = Read(r);
        r.ThrowIfNotEmpty();
        return a;
    }
}

/// <summary>X.509 extension: OID, critical, extnValue-ийн агуулга.</summary>
internal sealed record CertExtension(string Oid, bool Critical, byte[] Value);

/// <summary>Нийтийн түлхүүрийн төрөл.</summary>
internal enum KeyKind
{
    Other,
    Rsa,
    Ec,
}

/// <summary>Задалсан X.509 гэрчилгээ (Go x509.Certificate-ийн validator/OCSP-д хэрэгтэй хэсэг).</summary>
internal sealed class ParsedCert
{
    public const string OidSubjectKeyId = "2.5.29.14";
    public const string OidKeyUsage = "2.5.29.15";
    public const string OidBasicConstraints = "2.5.29.19";
    public const string OidNameConstraints = "2.5.29.30";
    public const string OidCertificatePolicies = "2.5.29.32";
    public const string OidAuthorityKeyId = "2.5.29.35";
    public const string OidExtKeyUsage = "2.5.29.37";
    public const string OidAuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    public const string OidQcStatements = "1.3.6.1.5.5.7.1.3";
    private const string OidAdOcsp = "1.3.6.1.5.5.7.48.1";
    private const string OidRsaEncryption = "1.2.840.113549.1.1.1";
    private const string OidEcPublicKey = "1.2.840.10045.2.1";
    public const string OidP256 = "1.2.840.10045.3.1.7";

    /// <summary>KeyUsage-ийн эхний байт (digitalSignature 0x80, nonRepudiation 0x40, keyEncipherment 0x20, keyCertSign 0x04).</summary>
    public const int KuDigitalSignature = 0x80;
    public const int KuContentCommitment = 0x40;
    public const int KuKeyEncipherment = 0x20;
    public const int KuKeyCertSign = 0x04;

    /// <summary>RSA modulus-ийн доод хэмжээ (бит): leaf, CA, OCSP responder бүгдэд.</summary>
    public const int MinRsaBits = 2048;

    private ParsedCert()
    {
    }

    public byte[] Raw { get; private set; } = Array.Empty<byte>();
    public byte[] Tbs { get; private set; } = Array.Empty<byte>();
    public AlgorithmId SignatureAlgorithm { get; private set; } = new("", null);
    public byte[] Signature { get; private set; } = Array.Empty<byte>();
    public byte[] SerialBytes { get; private set; } = Array.Empty<byte>();
    public BigInteger Serial { get; private set; }
    public byte[] RawIssuer { get; private set; } = Array.Empty<byte>();
    public byte[] RawSubject { get; private set; } = Array.Empty<byte>();
    public DateTimeOffset NotBefore { get; private set; }
    public DateTimeOffset NotAfter { get; private set; }
    public byte[] Spki { get; private set; } = Array.Empty<byte>();
    public byte[] PublicKeyBits { get; private set; } = Array.Empty<byte>();
    public KeyKind KeyKind { get; private set; }
    /// <summary>RSA modulus-ийн бит; бусад түлхүүрт 0.</summary>
    public int RsaBits { get; private set; }
    /// <summary>
    /// RSA түлхүүр сул: modulus &lt; <see cref="MinRsaBits"/>, эсвэл exponent тэгш / &lt; 3. Ийм түлхүүрээр
    /// <see cref="Verifies"/> ба validator-ийн гарын үсгийн шалгалт үргэлж false; leaf бол cert.weak_key.
    /// </summary>
    public bool WeakKey { get; private set; }
    /// <summary>EC түлхүүрийн namedCurve OID; бусад үед "".</summary>
    public string Curve { get; private set; } = "";
    public IReadOnlyList<CertExtension> Extensions { get; private set; } = Array.Empty<CertExtension>();
    public bool IsCa { get; private set; }
    /// <summary>basicConstraints-ийн pathLenConstraint; алга бол null.</summary>
    public int? PathLen { get; private set; }
    public bool HasKeyUsage { get; private set; }
    public int KeyUsage { get; private set; }
    /// <summary>ExtKeyUsage OID-ууд; extension алга бол хоосон.</summary>
    public IReadOnlyList<string> Eku { get; private set; } = Array.Empty<string>();
    public byte[]? SubjectKeyId { get; private set; }
    public byte[]? AuthorityKeyId { get; private set; }
    public IReadOnlyList<string> Policies { get; private set; } = Array.Empty<string>();
    /// <summary>AIA-ийн OCSP URI-ууд, дарааллаар (Go Certificate.OCSPServer).</summary>
    public IReadOnlyList<string> OcspServers { get; private set; } = Array.Empty<string>();
    public CertSubject Subject { get; private set; } = new();
    /// <summary>Subject-д SERIALNUMBER (2.5.4.5) эсвэл CN (2.5.4.3) нэгээс олон удаа (validator татгалзана).</summary>
    public bool DuplicateSubjectIdentity { get; private set; }

    public bool IsP256 => KeyKind == KeyKind.Ec && Curve == OidP256;

    public CertExtension? Extension(string oid)
    {
        foreach (var e in Extensions)
        {
            if (e.Oid == oid)
            {
                return e;
            }
        }
        return null;
    }

    /// <summary>Serial-ийн hex (Go <c>SerialNumber.Text(16)</c>: жижиг үсэг, тэргүүлэх 0-гүй).</summary>
    public string SerialHex()
    {
        var v = Serial;
        var neg = v.Sign < 0;
        if (neg)
        {
            v = BigInteger.Negate(v);
        }
        var hex = Convert.ToHexString(v.ToByteArray(isUnsigned: true, isBigEndian: true)).ToLowerInvariant().TrimStart('0');
        return (neg ? "-" : "") + (hex.Length == 0 ? "0" : hex);
    }

    /// <summary>Нийтийн <see cref="X509Certificate2"/> (үр дүнд); энэ гэрчилгээний DER-ээс.</summary>
    public X509Certificate2 ToX509() => X509Loader.Load(Raw);

    /// <summary>a, b нь ижил гэрчилгээ (байт-ижил) эсвэл ижил subject + түлхүүр (Go ocsp.go sameCertKey).</summary>
    public static bool SameCertKey(ParsedCert a, ParsedCert b) =>
        a.Raw.AsSpan().SequenceEqual(b.Raw) ||
        (a.RawSubject.AsSpan().SequenceEqual(b.RawSubject) && a.Spki.AsSpan().SequenceEqual(b.Spki));

    /// <summary>DER гэрчилгээг задална; буруу бол <see cref="FormatException"/>.</summary>
    public static ParsedCert Parse(byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);
        try
        {
            return ParseCore(der);
        }
        catch (Exception e) when (e is AsnContentException or CryptographicException or ArgumentException or OverflowException)
        {
            throw new FormatException("x509: " + e.Message, e);
        }
    }

    /// <summary>PEM мөр дэх бүх CERTIFICATE блок (Go pem.Decode давталт); блок алга бол <see cref="FormatException"/>.</summary>
    public static List<ParsedCert> ParsePem(string pem)
    {
        var list = new List<ParsedCert>();
        var rest = (pem ?? "").AsSpan();
        while (PemEncoding.TryFind(rest, out var f))
        {
            if (rest[f.Label].SequenceEqual("CERTIFICATE"))
            {
                var buf = new byte[f.DecodedDataLength];
                if (!Convert.TryFromBase64Chars(rest[f.Base64Data], buf, out var n))
                {
                    throw new FormatException("PEM base64 буруу");
                }
                list.Add(Parse(buf[..n]));
            }
            rest = rest[f.Location.End..];
        }
        if (list.Count == 0)
        {
            throw new FormatException("PEM CERTIFICATE блок алга");
        }
        return list;
    }

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n);

    internal static DateTimeOffset ReadTime(AsnReader r) =>
        r.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? r.ReadUtcTime() : r.ReadGeneralizedTime();

    private static byte[] ReadName(AsnReader r)
    {
        if (!r.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            throw new FormatException("x509: Name SEQUENCE биш");
        }
        return r.ReadEncodedValue().ToArray();
    }

    private static ParsedCert ParseCore(byte[] der)
    {
        var top = new AsnReader(der, AsnEncodingRules.DER);
        var certSeq = top.ReadSequence();
        top.ThrowIfNotEmpty();
        var tbsRaw = certSeq.ReadEncodedValue().ToArray();
        var outerAlg = certSeq.ReadEncodedValue().ToArray();
        var signature = certSeq.ReadBitString(out var unused);
        certSeq.ThrowIfNotEmpty();
        if (unused != 0)
        {
            throw new FormatException("x509: signatureValue BIT STRING буруу");
        }

        var tbs = new AsnReader(tbsRaw, AsnEncodingRules.DER).ReadSequence();
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(0)))
        {
            var v = tbs.ReadSequence(Ctx(0));
            if (!v.TryReadInt32(out var version) || version < 0 || version > 2)
            {
                throw new FormatException("x509: version буруу");
            }
            v.ThrowIfNotEmpty();
        }
        var serial = tbs.ReadIntegerBytes().ToArray();
        var innerAlg = tbs.ReadEncodedValue().ToArray();
        if (!innerAlg.AsSpan().SequenceEqual(outerAlg))
        {
            throw new FormatException("x509: гарын үсгийн алгоритм tbsCertificate-тэй таарахгүй");
        }
        var issuer = ReadName(tbs);
        var validity = tbs.ReadSequence();
        var notBefore = ReadTime(validity);
        var notAfter = ReadTime(validity);
        validity.ThrowIfNotEmpty();
        var subject = ReadName(tbs);
        var spki = tbs.ReadEncodedValue().ToArray();
        var spkiSeq = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
        var keyAlg = AlgorithmId.Read(spkiSeq);
        var keyBits = spkiSeq.ReadBitString(out _);
        spkiSeq.ThrowIfNotEmpty();
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(1)))
        {
            tbs.ReadEncodedValue();
        }
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(2)))
        {
            tbs.ReadEncodedValue();
        }
        var exts = new List<CertExtension>();
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(3)))
        {
            var wrap = tbs.ReadSequence(Ctx(3));
            var seq = wrap.ReadSequence();
            wrap.ThrowIfNotEmpty();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (seq.HasData)
            {
                var e = seq.ReadSequence();
                var oid = e.ReadObjectIdentifier();
                var critical = false;
                if (e.HasData && e.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                {
                    critical = e.ReadBoolean();
                }
                var value = e.ReadOctetString();
                e.ThrowIfNotEmpty();
                if (!seen.Add(oid))
                {
                    throw new FormatException("x509: давхардсан extension " + oid);
                }
                exts.Add(new CertExtension(oid, critical, value));
            }
        }
        tbs.ThrowIfNotEmpty();

        // Go parseName: Name-ийн утга бүр дэмжигдэх мөрийн төрөл (issuer ба subject).
        CertSubject.FromName(issuer);
        var c = new ParsedCert
        {
            Raw = der,
            Tbs = tbsRaw,
            SignatureAlgorithm = AlgorithmId.Parse(outerAlg),
            Signature = signature,
            SerialBytes = serial,
            Serial = new BigInteger(serial, isUnsigned: false, isBigEndian: true),
            RawIssuer = issuer,
            RawSubject = subject,
            NotBefore = notBefore,
            NotAfter = notAfter,
            Spki = spki,
            PublicKeyBits = keyBits,
            Extensions = exts,
            Subject = CertSubject.FromName(subject),
            DuplicateSubjectIdentity = CertSubject.HasDuplicateIdentity(subject),
        };
        c.SetKey(keyAlg);
        foreach (var e in exts)
        {
            c.Apply(e);
        }
        return c;
    }

    /// <summary>
    /// Түлхүүрийн төрөл; RSA/EC бол import хийж шалгана (Go ParseCertificate түлхүүрийг задалдаг). RSA-ийн modulus-ийн бит
    /// ба exponent-ийг <see cref="WeakKey"/>-д (Go crypto/rsa &lt; 1024-ийг татгалздаг; SDK-ийн доод хэмжээ 2048).
    /// </summary>
    private void SetKey(AlgorithmId keyAlg)
    {
        if (keyAlg.Oid == OidRsaEncryption)
        {
            KeyKind = KeyKind.Rsa;
            using var k = CreateRsa();
            var p = k.ExportParameters(false);
            var m = p.Modulus ?? Array.Empty<byte>();
            var i = 0;
            while (i < m.Length && m[i] == 0)
            {
                i++;
            }
            RsaBits = i == m.Length ? 0 : (m.Length - i) * 8 - (BitOperations.LeadingZeroCount((uint)m[i]) - 24);
            var e = new BigInteger(p.Exponent ?? Array.Empty<byte>(), isUnsigned: true, isBigEndian: true);
            WeakKey = RsaBits < MinRsaBits || e < 3 || e.IsEven;
            return;
        }
        if (keyAlg.Oid == OidEcPublicKey)
        {
            if (keyAlg.Parameters is null)
            {
                throw new FormatException("x509: EC namedCurve алга");
            }
            var r = new AsnReader(keyAlg.Parameters, AsnEncodingRules.DER);
            Curve = r.ReadObjectIdentifier();
            r.ThrowIfNotEmpty();
            if (Curve is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34" or "1.3.132.0.35"))
            {
                throw new FormatException("x509: дэмжигдээгүй EC муруй " + Curve);
            }
            KeyKind = KeyKind.Ec;
            CreateEcdsa().Dispose();
        }
    }

    private void Apply(CertExtension e)
    {
        var r = new AsnReader(e.Value, AsnEncodingRules.DER);
        switch (e.Oid)
        {
            case OidBasicConstraints:
                {
                    var s = r.ReadSequence();
                    if (s.HasData && s.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    {
                        IsCa = s.ReadBoolean();
                    }
                    if (s.HasData)
                    {
                        if (!s.TryReadInt32(out var n) || n < 0)
                        {
                            throw new FormatException("x509: basicConstraints pathLen буруу");
                        }
                        PathLen = n;
                    }
                    s.ThrowIfNotEmpty();
                    break;
                }
            case OidKeyUsage:
                {
                    var bits = r.ReadBitString(out _);
                    HasKeyUsage = true;
                    KeyUsage = bits.Length > 0 ? bits[0] : 0;
                    break;
                }
            case OidExtKeyUsage:
                {
                    var s = r.ReadSequence();
                    var list = new List<string>();
                    while (s.HasData)
                    {
                        list.Add(s.ReadObjectIdentifier());
                    }
                    Eku = list;
                    break;
                }
            case OidSubjectKeyId:
                SubjectKeyId = r.ReadOctetString();
                break;
            case OidAuthorityKeyId:
                {
                    var s = r.ReadSequence();
                    if (s.HasData && s.PeekTag().HasSameClassAndValue(Ctx(0)))
                    {
                        AuthorityKeyId = s.ReadOctetString(Ctx(0));
                    }
                    while (s.HasData)
                    {
                        s.ReadEncodedValue();
                    }
                    break;
                }
            case OidCertificatePolicies:
                {
                    var s = r.ReadSequence();
                    var list = new List<string>();
                    while (s.HasData)
                    {
                        var pi = s.ReadSequence();
                        list.Add(pi.ReadObjectIdentifier());
                        while (pi.HasData)
                        {
                            pi.ReadEncodedValue();
                        }
                    }
                    Policies = list;
                    break;
                }
            case OidAuthorityInfoAccess:
                {
                    var s = r.ReadSequence();
                    var list = new List<string>();
                    while (s.HasData)
                    {
                        var ad = s.ReadSequence();
                        var method = ad.ReadObjectIdentifier();
                        if (ad.PeekTag().HasSameClassAndValue(Ctx(6)))
                        {
                            var uri = ad.ReadCharacterString(UniversalTagNumber.IA5String, Ctx(6));
                            if (method == OidAdOcsp)
                            {
                                list.Add(uri);
                            }
                        }
                        else
                        {
                            ad.ReadEncodedValue();
                        }
                        ad.ThrowIfNotEmpty();
                    }
                    OcspServers = list;
                    break;
                }
            default:
                return;
        }
        r.ThrowIfNotEmpty();
    }

    public RSA CreateRsa()
    {
        var k = RSA.Create();
        try
        {
            k.ImportSubjectPublicKeyInfo(Spki, out _);
            return k;
        }
        catch
        {
            k.Dispose();
            throw;
        }
    }

    public ECDsa CreateEcdsa()
    {
        var k = ECDsa.Create();
        try
        {
            k.ImportSubjectPublicKeyInfo(Spki, out _);
            return k;
        }
        catch
        {
            k.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Энэ гэрчилгээний түлхүүрээр <paramref name="data"/> дээрх гарын үсэг (Go x509 <c>checkSignature</c>): RSA PKCS#1
    /// v1.5, RSASSA-PSS (Go-ийн хүлээн авдаг гурван параметр л), ECDSA (ASN.1 DER). SHA-1 зөвхөн
    /// <paramref name="allowSha1"/> үед (Go: гинжид хориотой, OCSP-д зөвшөөрнө).
    /// </summary>
    public bool Verifies(AlgorithmId alg, byte[] data, byte[] signature, bool allowSha1)
    {
        try
        {
            switch (alg.Oid)
            {
                case "1.2.840.113549.1.1.5":
                    return allowSha1 && RsaVerify(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.11":
                    return RsaVerify(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.12":
                    return RsaVerify(data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.13":
                    return RsaVerify(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                case "1.2.840.113549.1.1.10":
                    return PssHash(alg) is { } h && RsaVerify(data, signature, h, RSASignaturePadding.Pss);
                case "1.2.840.10045.4.1":
                    return allowSha1 && EcVerify(data, signature, HashAlgorithmName.SHA1);
                case "1.2.840.10045.4.3.2":
                    return EcVerify(data, signature, HashAlgorithmName.SHA256);
                case "1.2.840.10045.4.3.3":
                    return EcVerify(data, signature, HashAlgorithmName.SHA384);
                case "1.2.840.10045.4.3.4":
                    return EcVerify(data, signature, HashAlgorithmName.SHA512);
                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private bool RsaVerify(byte[] data, byte[] signature, HashAlgorithmName h, RSASignaturePadding p)
    {
        if (KeyKind != KeyKind.Rsa || WeakKey)
        {
            return false;
        }
        using var k = CreateRsa();
        return signature.Length == (k.KeySize + 7) / 8 && k.VerifyData(data, signature, h, p);
    }

    private bool EcVerify(byte[] data, byte[] signature, HashAlgorithmName h)
    {
        if (KeyKind != KeyKind.Ec || !IsDerEcdsaSignature(signature))
        {
            return false;
        }
        using var k = CreateEcdsa();
        return k.VerifyData(data, signature, h, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } — чанд DER, r, s &gt; 0 (Go ecdsa.VerifyASN1-ийн задлалт).</summary>
    internal static bool IsDerEcdsaSignature(byte[] sig)
    {
        try
        {
            var r = new AsnReader(sig, AsnEncodingRules.DER);
            var s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            var a = s.ReadInteger();
            var b = s.ReadInteger();
            s.ThrowIfNotEmpty();
            return a.Sign > 0 && b.Sign > 0;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    /// <summary>
    /// RSASSA-PSS-params (Go x509 getSignatureAlgorithmFromAI): hash [0], MGF1 [1] ижил hash-тай, saltLength [2] = hLen,
    /// trailerField [3] = 1 — SHA-256/384/512 гурван хувилбараас өөр бол null (дэмжигдэхгүй).
    /// </summary>
    private static HashAlgorithmName? PssHash(AlgorithmId alg)
    {
        if (alg.Parameters is null)
        {
            return null;
        }
        try
        {
            var r = new AsnReader(alg.Parameters, AsnEncodingRules.DER);
            var s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            var h0 = s.ReadSequence(Ctx(0));
            var hash = AlgorithmId.Read(h0);
            h0.ThrowIfNotEmpty();
            var m1 = s.ReadSequence(Ctx(1));
            var mgf = AlgorithmId.Read(m1);
            m1.ThrowIfNotEmpty();
            var s2 = s.ReadSequence(Ctx(2));
            if (!s2.TryReadInt32(out var salt))
            {
                return null;
            }
            s2.ThrowIfNotEmpty();
            var trailer = 1;
            if (s.HasData)
            {
                var s3 = s.ReadSequence(Ctx(3));
                if (!s3.TryReadInt32(out trailer))
                {
                    return null;
                }
                s3.ThrowIfNotEmpty();
            }
            s.ThrowIfNotEmpty();
            if (mgf.Oid != "1.2.840.113549.1.1.8" || mgf.Parameters is null || trailer != 1 || !NullOrAbsent(hash.Parameters))
            {
                return null;
            }
            var mgfHash = AlgorithmId.Parse(mgf.Parameters);
            if (mgfHash.Oid != hash.Oid || !NullOrAbsent(mgfHash.Parameters))
            {
                return null;
            }
            return (hash.Oid, salt) switch
            {
                ("2.16.840.1.101.3.4.2.1", 32) => HashAlgorithmName.SHA256,
                ("2.16.840.1.101.3.4.2.2", 48) => HashAlgorithmName.SHA384,
                ("2.16.840.1.101.3.4.2.3", 64) => HashAlgorithmName.SHA512,
                _ => null,
            };
        }
        catch (AsnContentException)
        {
            return null;
        }

        static bool NullOrAbsent(byte[]? p) => p is null || (p.Length == 2 && p[0] == 0x05 && p[1] == 0x00);
    }
}

/// <summary><see cref="X509Certificate2"/> үүсгэгч (net9+ X509CertificateLoader; net8 конструктор).</summary>
internal static class X509Loader
{
    public static X509Certificate2 Load(byte[] der)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(der);
#else
        return new X509Certificate2(der);
#endif
    }
}
