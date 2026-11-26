using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Qr;

// Core-ийн «Миний QR». Нийтийн төрлүүд (нэр, namespace, гишүүд) GeregeSystems.EidMongolia.Pades 0.16.0-ийнхтэй ЯГ ижил —
// 0.17.0-оос Pades эдгээрийг [TypeForwardedTo]-оор энд дамжуулна (Pades Properties/TypeForwards.cs; CI compat job). Нийтийн
// гишүүн өөрчлөх / хасах нь Pades 0.16.0-ийн хэрэглэгчдийг эвдэнэ.
// Дотоод хэрэгжүүлэлт нь core-ийн хуваалцсан шалгагч дээр: гинж — ResponseValidator.FindPath (X509Chain биш, платформ
// бүрд ижил), цуцлалт — OcspRevocationChecker (Go/TS дүрэм: OCSP unknown → revoked, thisUpdate ≤ 48 ц).

/// <summary>
/// «Миний QR» (гэрээ <c>myqr-2026-10-26</c>): иргэн апп дээрээ <c>EIDMN-QR1:&lt;token&gt;</c> харуулна → RP
/// <see cref="EidQrClient.StartAsync"/> (<c>POST /authentication/qr</c>) → иргэн PIN2-оор зөвшөөрнө → иргэний өөрийн
/// QUALIFIED SIGN түлхүүрээр зурсан PS256 JWS (<c>x5c</c>) ирнэ → <see cref="VerifyAsync"/> (гэрээний §6.1, 13 алхам)
/// нь «Миний мэдээлэл»-ийг (апп дээр хадгалсан яг тэр dict, payload-ийн дарааллаар) буцаана. RP-д зөвхөн
/// <c>QR_PRESENT</c> эрх. Go / TS SDK-тэй ижил дүрэм (testdata/myqr_vectors.json).
/// </summary>
public static class EidQr
{
    /// <summary>Иргэний аппын QR-ийн угтвар: <c>EIDMN-QR1:&lt;token&gt;</c>.</summary>
    public const string Prefix = "EIDMN-QR1:";

    /// <summary>Presentation JWS-ийн хүлээгдэх <c>iss</c>.</summary>
    public const string DefaultIssuer = "https://ca.eidmongolia.mn";

    /// <summary>eID Mongolia Issuing CA (04)-ийн Subject Key Identifier — <see cref="QrTrust.AllowedIssuerSkis"/>-ийн анхдагч.</summary>
    public const string CitizenIssuingCaSki = "b8a37f2c64ad677912db7d9e34f246358a2fb909";

    /// <summary>JWS-ийн <c>typ</c>.</summary>
    public const string JwsType = "eidmn-myqr+jwt";

    internal const int MaxJws = 524288;
    internal const int MaxFields = 128;
    internal const int MaxKeyChars = 64;
    internal const int MaxValueBytes = 2048;
    internal const int MaxPhotoBytes = 153600;
    internal const long MaxAgeSeconds = 300;
    internal const long SkewSeconds = 60;
    internal const int MinRsaBits = 2048;

    private static readonly Lazy<ParsedCert> NationalRoot = new(() => ParsedCert.ParsePem(EidTrust.NationalRootCaPem).Single());

    /// <summary>Анхдагч цуцлалт (<see cref="QrTrust.Revocation"/> null): хуваалцсан, «good»-ийг кэшлэдэг шалгагч.</summary>
    private static readonly Lazy<OcspRevocationChecker> DefaultOcsp = new(() => new OcspRevocationChecker());

    private static readonly Regex TokenRe = new("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant);
    private static readonly Regex SegRe = new("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex SourceRe = new("^[a-z0-9_-]{1,32}$", RegexOptions.CultureInvariant);
    private static readonly char[] AsciiWs = { ' ', '\t', '\n', '\r', '\f', '\v' };

    /// <summary>
    /// Скан хийсэн мөр: ASCII зай тайрч, <c>EIDMN-QR1:</c> угтвар + 43 тэмдэгт base64url токен. Бусад бол
    /// <see cref="EidQrException"/> <c>QR_FORMAT_INVALID</c>.
    /// </summary>
    public static (string Token, string Qr) Parse(string? scanned)
    {
        var s = (scanned ?? "").Trim(AsciiWs);
        if (!s.StartsWith(Prefix, StringComparison.Ordinal) || !TokenRe.IsMatch(s.Substring(Prefix.Length)))
        {
            throw new EidQrException(EidQrErrorCodes.FormatInvalid, "eID «Миний QR» биш");
        }
        return (s.Substring(Prefix.Length), s);
    }

    /// <summary>
    /// Presentation JWS-ийг гэрээний §6.1-ээр шалгана (эхний алдаа дээр зогсож <see cref="EidQrException"/> §6.2-ийн
    /// кодтой). Сүлжээ зөвхөн цуцлалтын шалгалтад (анхдагч — гэрчилгээний AIA-ийн OCSP). Хүлээн авсан байтаар шалгана —
    /// дахин сериалчлахгүй.
    /// </summary>
    public static async Task<QrResult> VerifyAsync(string jws, QrExpect expect, QrTrust? trust = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(expect);
        trust ??= new QrTrust();
        var now = expect.Now ?? DateTimeOffset.UtcNow;

        // 1. Бүтэц.
        if (string.IsNullOrEmpty(jws) || jws.Length > MaxJws)
        {
            throw Err(EidQrErrorCodes.JwsMalformed, "JWS хоосон эсвэл хэт урт");
        }
        var seg = jws.Split('.');
        if (seg.Length != 3 || !seg.All(x => SegRe.IsMatch(x)))
        {
            throw Err(EidQrErrorCodes.JwsMalformed, "compact JWS биш");
        }

        // 2–3. Header (x5c-ийн DER-ийг SDK-ийн задлагчаар — Go x509.ParseCertificate-ийн хатуу дүрэм).
        var (leafDer, interDer) = ParseHeader(seg[0]);
        ParsedCert leafP, interP;
        try
        {
            leafP = ParsedCert.Parse(leafDer);
            interP = ParsedCert.Parse(interDer);
        }
        catch (FormatException)
        {
            throw Err(EidQrErrorCodes.HeaderInvalid, "x5c гэрчилгээ биш");
        }

        // 4. Гинж + навчны профайл.
        var issuerP = CheckChain(leafP, interP, trust, now);
        X509Certificate2 leaf, issuer;
        try
        {
            leaf = leafP.ToX509();
        }
        catch (CryptographicException)
        {
            throw Err(EidQrErrorCodes.HeaderInvalid, "x5c гэрчилгээ биш");
        }
        try
        {
            issuer = issuerP.ToX509();
        }
        catch (CryptographicException)
        {
            leaf.Dispose();
            throw Err(EidQrErrorCodes.HeaderInvalid, "x5c гэрчилгээ биш");
        }

        try
        {
            // 5. Цуцлалт (Go qrRevocation): revoked → QR_CERT_REVOKED; unknown / алдаа → hard-fail бол QR_REVOCATION_UNKNOWN.
            string status;
            try
            {
                status = trust.Revocation is { } rev
                    ? await rev(leaf, issuer).ConfigureAwait(false)
                    : await DefaultRevocationAsync(leaf, issuer, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                status = "unknown";
            }
            if (status == "revoked")
            {
                throw Err(EidQrErrorCodes.CertRevoked, "гэрчилгээ цуцлагдсан (serial " + leafP.SerialHex() + ")");
            }
            if (status != "good" && !trust.RevocationSoftFail)
            {
                throw Err(EidQrErrorCodes.RevocationUnknown, "цуцлалтын төлөв тодорхойгүй (serial " + leafP.SerialHex() + ")");
            }

            // 6. Гарын үсэг: RSASSA-PSS SHA-256, MGF1-SHA-256, salt 32 (.NET PSS = hLen) — ирсэн ASCII байт дээр.
            var signingInput = Encoding.ASCII.GetBytes(seg[0] + "." + seg[1]);
            var sig = B64UrlOrNull(seg[2]);
            using (var rsa = leafP.CreateRsa())
            {
                bool ok;
                try
                {
                    ok = sig is not null && rsa.VerifyData(signingInput, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                }
                catch (CryptographicException)
                {
                    ok = false;
                }
                if (!ok)
                {
                    throw Err(EidQrErrorCodes.SignatureInvalid, "гарын үсэг таарсангүй");
                }
            }

            // 7–12. Payload.
            var pb = B64UrlOrNull(seg[1]) ?? throw Err(EidQrErrorCodes.JwsMalformed, "payload base64url биш");
            using var doc = ParseObjectOrNull(pb) ?? throw Err(EidQrErrorCodes.JwsMalformed, "payload JSON объект биш");
            var c = doc.RootElement;
            if (NamesOrNull(c) is null)
            {
                // Go jsonObject: давхардсан / уншигдахгүй түлхүүр → QR_JWS_MALFORMED.
                throw Err(EidQrErrorCodes.JwsMalformed, "payload-ийн түлхүүр буруу эсвэл давхардсан");
            }
            var subject = leafP.Subject;
            var etsi = subject.SerialNumber;
            var (iat, data, source, photo) = CheckClaims(c, expect, etsi, now);

            // 13. Нэрс Go ParseSubject-ийнх (GN/SN эхнийх; SERIALNUMBER/CN давхардсаныг CheckChain татгалзсан).
            var signer = new QrSigner(leaf, etsi, Opt(subject.GivenName), Opt(subject.Surname), Opt(subject.CommonName));
            var sha = Convert.ToHexString(SHA256.HashData(signingInput)).ToLowerInvariant();
            return new QrResult(jws, c.Clone(), data, source, photo, signer, DateTimeOffset.FromUnixTimeSeconds(iat), sha);
        }
        catch
        {
            leaf.Dispose();
            throw;
        }
        finally
        {
            // Олгогчийг зөвхөн цуцлалтын шалгалтад хэрэглэнэ (QrSigner-т орохгүй).
            issuer.Dispose();
        }
    }

    internal static EidQrException Err(string code, string reason) => new(code, reason);

    private static string? Opt(string v) => v.Length > 0 ? v : null;

    private static (byte[] Leaf, byte[] Inter) ParseHeader(string seg0)
    {
        EidQrException Bad(string r) => Err(EidQrErrorCodes.HeaderInvalid, r);
        var hb = B64UrlOrNull(seg0) ?? throw Bad("header base64url биш");
        using var hdr = ParseObjectOrNull(hb) ?? throw Bad("header JSON объект биш");
        var h = hdr.RootElement;
        var names = NamesOrNull(h) ?? throw Bad("header-ийн түлхүүр буруу эсвэл давхардсан");
        if (names.Count != 3 || !names.OrderBy(n => n, StringComparer.Ordinal).SequenceEqual(new[] { "alg", "typ", "x5c" }))
        {
            throw Bad("header-ийн гишүүд яг alg, typ, x5c биш");
        }
        if (StrOrNull(h.GetProperty("alg")) != "PS256")
        {
            throw Bad("alg PS256 биш");
        }
        if (StrOrNull(h.GetProperty("typ")) != JwsType)
        {
            throw Bad("typ " + JwsType + " биш");
        }
        var x5c = h.GetProperty("x5c");
        if (x5c.ValueKind != JsonValueKind.Array || x5c.GetArrayLength() != 2)
        {
            throw Bad("x5c 2 элементтэй массив биш");
        }
        var ders = new byte[2][];
        for (int i = 0; i < 2; i++)
        {
            var e = x5c[i];
            if (StrOrNull(e) is not { Length: > 0 } s)
            {
                throw Bad("x5c элемент хоосон эсвэл тэмдэгт мөр биш");
            }
            ders[i] = StdB64OrNull(s) ?? throw Bad("x5c стандарт base64 биш");
        }
        return (ders[0], ders[1]);
    }

    /// <summary>
    /// §6.1 алхам 4 (Go validator <c>qrChain</c>): навч CA биш, RSA ≥ 2048 (сул exponent-гүй), subject-д SERIALNUMBER/CN
    /// давхардаагүй (.NET-ийн нэмэлт), хугацаа ± 60 с, KeyUsage contentCommitment, түвшин QUALIFIED/QSCD (qcStatements);
    /// гинж навч → (x5c[1] ∪ intermediates) → anchors — core-ийн замын угсралт (<see cref="ResponseValidator.FindPath"/>,
    /// EKU шалгахгүй = Go <c>ExtKeyUsageAny</c>; name constraints / үл таних critical extension fail-closed), шууд issuer-ийн
    /// SKI allowlist-д байх замыг сонгоно. Шууд issuer-ийг буцаана.
    /// </summary>
    private static ParsedCert CheckChain(ParsedCert leaf, ParsedCert inter, QrTrust trust, DateTimeOffset now)
    {
        EidQrException Bad(string r) => Err(EidQrErrorCodes.ChainInvalid, r);
        if (leaf.IsCa)
        {
            throw Bad("навч CA гэрчилгээ");
        }
        if (leaf.KeyKind != KeyKind.Rsa || leaf.RsaBits < MinRsaBits || leaf.WeakKey)
        {
            throw Bad("RSA ≥ 2048 бит түлхүүр биш");
        }
        if (leaf.DuplicateSubjectIdentity)
        {
            throw Bad("гэрчилгээний subject-д SERIALNUMBER эсвэл CN давхардсан");
        }
        var skew = TimeSpan.FromSeconds(SkewSeconds);
        if (now + skew < leaf.NotBefore || now - skew > leaf.NotAfter)
        {
            throw Bad("гэрчилгээ хүчинтэй хугацаанд биш (serial " + leaf.SerialHex() + ")");
        }
        if ((leaf.KeyUsage & ParsedCert.KuContentCommitment) == 0)
        {
            throw Bad("KeyUsage-д contentCommitment алга");
        }
        string level;
        try
        {
            level = ResponseValidator.LevelOf(leaf, SignatureProtocols.RawDigestSignature);
        }
        catch (EidValidationException)
        {
            throw Bad("qcStatements буруу");
        }
        if (level is not (CertificateLevels.Qualified or CertificateLevels.Qscd))
        {
            throw Bad("гэрчилгээ QUALIFIED биш (QcCompliance алга)");
        }
        var anchors = trust.Anchors is { Count: > 0 } a ? a.Select(Parse).ToList() : new List<ParsedCert> { NationalRoot.Value };
        var intermediates = new List<ParsedCert> { inter };
        if (trust.Intermediates is { } ti)
        {
            intermediates.AddRange(ti.Select(Parse));
        }
        else
        {
            intermediates.AddRange(EidTrust.CitizenIntermediates);
        }
        var allowed = new HashSet<string>(
            (trust.AllowedIssuerSkis is { Count: > 0 } s ? s : new[] { CitizenIssuingCaSki })
                .Select(x => x.Replace(":", "", StringComparison.Ordinal).Trim().ToLowerInvariant()),
            StringComparer.Ordinal);
        var built = ResponseValidator.FindPath(leaf, anchors, intermediates, null, now, path =>
        {
            var ski = path[0].SubjectKeyId is { Length: > 0 } k ? k : leaf.AuthorityKeyId;
            return ski is { Length: > 0 } && allowed.Contains(Convert.ToHexString(ski).ToLowerInvariant());
        });
        if (built.Path is { Count: > 0 } p)
        {
            return p[0];
        }
        if (built.Rejected)
        {
            throw Bad("олгогч CA зөвшөөрөгдөөгүй");
        }
        throw Bad("гинж итгэмжлэгдсэн root хүрэхгүй" + (built.Fail is { } f ? ": " + f.Text : ""));

        static ParsedCert Parse(X509Certificate2 c)
        {
            try
            {
                return ParsedCert.Parse(c.RawData);
            }
            catch (FormatException e)
            {
                throw new ArgumentException("eid: QrTrust-ийн гэрчилгээ задарсангүй: " + e.Message, "trust", e);
            }
        }
    }

    /// <summary>
    /// Анхдагч цуцлалт: core-ийн <see cref="OcspRevocationChecker"/> (навчны AIA-ийн OCSP; Go/TS дүрэм — OCSP unknown →
    /// "revoked", thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate өнгөрөөгүй; issuer leaf-ийг гаргасан эсэх ба CertID-ийг
    /// тулгана). Хариугүй бол <see cref="EidOcspException"/> — <see cref="VerifyAsync"/> "unknown" болгоно.
    /// </summary>
    internal static async Task<string> DefaultRevocationAsync(X509Certificate2 leaf, X509Certificate2? issuer, CancellationToken ct)
    {
        var status = await DefaultOcsp.Value.CheckAsync(leaf, issuer, ct).ConfigureAwait(false);
        return status switch
        {
            RevocationStatus.Good => "good",
            RevocationStatus.Revoked => "revoked",
            _ => "unknown",
        };
    }

    private static (long Iat, List<KeyValuePair<string, string>> Data, string Source, byte[]? Photo) CheckClaims(
        JsonElement c, QrExpect expect, string etsi, DateTimeOffset now)
    {
        EidQrException Claims(string r) => Err(EidQrErrorCodes.ClaimsInvalid, r);
        var iss = string.IsNullOrEmpty(expect.Issuer) ? DefaultIssuer : expect.Issuer;
        if (Str(c, "iss") != iss)
        {
            throw Claims("iss таарсангүй");
        }
        if (Str(c, "sub") is not { } sub || etsi.Length == 0 || sub != etsi)
        {
            throw Claims("sub гэрчилгээний serialNumber-тэй таарсангүй");
        }
        var rpName = Str(c, "rp_name");
        var statement = Str(c, "statement");
        var nonce = Str(c, "nonce");
        var sid = Str(c, "sid");
        var aud = Str(c, "aud");
        if (rpName is null || statement is null || nonce is null || sid is null || aud is null)
        {
            throw Claims("rp_name/statement/nonce/sid/aud тэмдэгт мөр биш");
        }
        if (!Int(c, "iat", out var iat) || !Int(c, "exp", out var exp))
        {
            throw Claims("iat/exp бүхэл тоо биш");
        }
        if (statement != Statement(rpName))
        {
            throw Claims("statement загвартай таарсангүй");
        }
        // 8–10.
        if (string.IsNullOrEmpty(expect.RpUuid) || !string.Equals(aud.ToLowerInvariant(), expect.RpUuid.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw Err(EidQrErrorCodes.AudienceMismatch, "aud (RP UUID) таарсангүй");
        }
        if (string.IsNullOrEmpty(expect.SessionId) || sid != expect.SessionId)
        {
            throw Err(EidQrErrorCodes.SessionMismatch, "sid таарсангүй");
        }
        if (string.IsNullOrEmpty(expect.Nonce) || nonce != expect.Nonce)
        {
            throw Err(EidQrErrorCodes.NonceMismatch, "nonce таарсангүй");
        }
        // 11.
        var span = exp - iat;
        if (span <= 0 || span > MaxAgeSeconds)
        {
            throw Claims("exp − iat нь (0, 300] биш");
        }
        var nowMs = now.ToUnixTimeMilliseconds();
        if (iat > (nowMs / 1000.0) + SkewSeconds)
        {
            throw Err(EidQrErrorCodes.NotYetValid, "iat ирээдүйд");
        }
        if (!(nowMs < (exp + SkewSeconds) * 1000))
        {
            throw Err(EidQrErrorCodes.Expired, "presentation хугацаа дууссан");
        }
        // 12.
        if (!c.TryGetProperty("data", out var d))
        {
            throw Err(EidQrErrorCodes.DataInvalid, "data алга");
        }
        var (data, source, photo) = CheckData(d);
        return (iat, data, source, photo);
    }

    internal static string Statement(string rpName) => "Та " + rpName + "-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна";

    private static (List<KeyValuePair<string, string>> Data, string Source, byte[]? Photo) CheckData(JsonElement d)
    {
        EidQrException Bad(string r) => Err(EidQrErrorCodes.DataInvalid, r);
        if (d.ValueKind != JsonValueKind.Object)
        {
            throw Bad("data объект биш");
        }
        string? source = null;
        JsonElement? fields = null;
        string? photoB64 = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var m in d.EnumerateObject())
        {
            var name = NameOrNull(m) ?? throw Bad("data-ийн түлхүүр буруу (UTF-16)");
            if (!seen.Add(name))
            {
                throw Bad("data-д давхардсан гишүүн");
            }
            switch (name)
            {
                case "source":
                    source = StrOrNull(m.Value) ?? throw Bad("source тэмдэгт мөр биш");
                    break;
                case "fields":
                    fields = m.Value;
                    break;
                case "photo":
                    photoB64 = StrOrNull(m.Value) ?? throw Bad("photo тэмдэгт мөр биш");
                    break;
                default:
                    throw Bad("data-д илүү гишүүн");
            }
        }
        if (source is null || !SourceRe.IsMatch(source))
        {
            throw Bad("source буруу");
        }
        if (fields is not { ValueKind: JsonValueKind.Object } f)
        {
            throw Bad("fields объект биш");
        }
        var list = new List<KeyValuePair<string, string>>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var kv in f.EnumerateObject())
        {
            if (list.Count >= MaxFields)
            {
                throw Bad("fields > 128");
            }
            string key, val;
            try
            {
                key = kv.Name;
                val = kv.Value.ValueKind == JsonValueKind.String ? kv.Value.GetString()! : throw Bad("утга тэмдэгт мөр биш");
            }
            catch (InvalidOperationException)
            {
                throw Bad("UTF-8/UTF-16 буруу");
            }
            if (!keys.Add(key))
            {
                throw Bad("fields-д давхардсан түлхүүр");
            }
            if (!KeyOk(key))
            {
                throw Bad("түлхүүр буруу (1–64 code point, хяналтын тэмдэгтгүй)");
            }
            if (!WellFormed(val) || Encoding.UTF8.GetByteCount(val) > MaxValueBytes || val.Contains('\0'))
            {
                throw Bad("утга > 2048 байт эсвэл буруу");
            }
            list.Add(new KeyValuePair<string, string>(key, val));
        }
        byte[]? photo = null;
        if (photoB64 is not null)
        {
            photo = StdB64OrNull(photoB64);
            if (photo is null || photo.Length > MaxPhotoBytes || photo.Length < 3 || photo[0] != 0xFF || photo[1] != 0xD8 || photo[2] != 0xFF)
            {
                throw Bad("photo: strict base64 JPEG ≤ 150 KiB биш");
            }
        }
        // §1.3: fields хоосон бол photo заавал.
        if (list.Count == 0 && photo is null)
        {
            throw Bad("fields хоосон, photo алга");
        }
        return (list, source, photo);
    }

    private static bool WellFormed(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(s[i]))
            {
                return false;
            }
        }
        return true;
    }

    private static bool KeyOk(string k)
    {
        if (!WellFormed(k)) return false;
        int n = 0;
        foreach (var r in k.EnumerateRunes())
        {
            if (r.Value <= 0x1F || (r.Value >= 0x7F && r.Value <= 0x9F)) return false;
            n++;
        }
        return n >= 1 && n <= MaxKeyChars;
    }

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) ? StrOrNull(v) : null;

    /// <summary>
    /// JSON мөрийн утга; мөр биш эсвэл UTF-16 болгож чадахгүй (ганц surrogate <c>"\udc00"</c> — <c>GetString</c>-ийн
    /// InvalidOperationException) бол null — дуудагч нь өөрийн <see cref="EidQrException"/> кодоор татгалзана.
    /// </summary>
    internal static string? StrOrNull(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        try
        {
            return e.GetString();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static string? NameOrNull(JsonProperty p)
    {
        try
        {
            return p.Name;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Объектын түлхүүрүүд дарааллаар; уншигдахгүй эсвэл давхардсан түлхүүр байвал null (Go <c>jsonObject</c>).</summary>
    internal static List<string>? NamesOrNull(JsonElement o)
    {
        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in o.EnumerateObject())
        {
            if (NameOrNull(p) is not { } n || !seen.Add(n))
            {
                return null;
            }
            names.Add(n);
        }
        return names;
    }

    private static bool Int(JsonElement o, string name, out long n)
    {
        n = 0;
        return o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out n);
    }

    private static JsonDocument? ParseObjectOrNull(byte[] b)
    {
        JsonDocument d;
        try
        {
            d = JsonDocument.Parse(b);
        }
        catch (JsonException)
        {
            return null;
        }
        if (d.RootElement.ValueKind != JsonValueKind.Object)
        {
            d.Dispose();
            return null;
        }
        return d;
    }

    internal static byte[]? B64UrlOrNull(string s)
    {
        if (!SegRe.IsMatch(s) || s.Length % 4 == 1) return null;
        var t = s.Replace('-', '+').Replace('_', '/');
        t = t.PadRight(t.Length + ((4 - (t.Length % 4)) % 4), '=');
        try
        {
            return Convert.FromBase64String(t);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>Strict стандарт base64 (padding-тэй, мөр таслалгүй, канон): дахин кодлоход яг ижил байх ёстой.</summary>
    internal static byte[]? StdB64OrNull(string s)
    {
        if (s.Length % 4 != 0) return null;
        foreach (var ch in s)
        {
            if (!(ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=')) return null;
        }
        byte[] b;
        try
        {
            b = Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
        return Convert.ToBase64String(b) == s ? b : null;
    }

    /// <summary>Тест/stub-д: гэрчилгээний serial (жижиг hex, эхний тэггүй) — vector-ийн <c>revocation</c> түлхүүр.</summary>
    internal static string SerialHex(X509Certificate2 c)
    {
        var s = c.SerialNumber.TrimStart('0').ToLowerInvariant();
        return s == "" ? "0" : s;
    }
}

/// <summary><see cref="EidQrClient.StartAsync"/>-ийн оролт.</summary>
/// <param name="Qr">Скан хийсэн мөр (<c>EIDMN-QR1:&lt;token&gt;</c>).</param>
/// <param name="Nonce">RP nonce (16–128 printable ASCII); null бол SDK base64url(16 санамсаргүй байт) = 22 тэмдэгт үүсгэнэ.</param>
/// <param name="RelyingPartyName">Дэд системийн шошго (лог); null бол <see cref="EidQrOptions.RpName"/>. JWS-д бүртгэлийн нэр орно.</param>
public sealed record QrStartRequest(string Qr, string? Nonce = null, string? RelyingPartyName = null);

/// <summary>Эхлүүлсэн session — JSON-оор хадгалж (stateless backend) Result/Check/Verify-д дамжуулна.</summary>
/// <param name="SessionId">CA-ийн session ID.</param>
/// <param name="Nonce">JWS-д хүлээгдэх nonce.</param>
public sealed record QrSession(string SessionId, string Nonce);

/// <summary>Гарын үсэг зурсан иргэн (гэрчилгээний subject-ээс).</summary>
/// <param name="Certificate">Иргэний QUALIFIED SIGN гэрчилгээ (x5c[0]).</param>
/// <param name="Etsi">ETSI дугаар (subject serialNumber = JWS <c>sub</c>), ж: PNOMN-….</param>
/// <param name="GivenName">Нэр (GN).</param>
/// <param name="Surname">Овог (SN).</param>
/// <param name="CommonName">CN.</param>
public sealed record QrSigner(X509Certificate2 Certificate, string Etsi, string? GivenName, string? Surname, string? CommonName);

/// <summary>Шалгагдсан «Миний QR» presentation.</summary>
/// <param name="Jws">Түүхий compact JWS (аудит / маргаан).</param>
/// <param name="Claims">Payload (iss, sub, aud, rp_name, sid, nonce, iat, exp, statement, data).</param>
/// <param name="Data">«Миний мэдээлэл»-ийн <c>fields</c> — payload-ийн дарааллаар, түлхүүр яг хэвээр.</param>
/// <param name="Source">Мэдээллийн эх сурвалж (<c>data.source</c>: dan, passport, citizenid …).</param>
/// <param name="Photo">Нүүрний JPEG (байвал).</param>
/// <param name="Signer">Иргэн.</param>
/// <param name="SignedAt"><c>iat</c>.</param>
/// <param name="Sha256">hex SHA-256(signingInput) — CA-ийн аудитын <c>qrsha</c>-тэй тэнцүү.</param>
public sealed record QrResult(string Jws, JsonElement Claims, IReadOnlyList<KeyValuePair<string, string>> Data,
    string Source, byte[]? Photo, QrSigner Signer, DateTimeOffset SignedAt, string Sha256);

/// <summary><see cref="EidQr.VerifyAsync"/>-ийн хүлээлт.</summary>
/// <param name="RpUuid">Таны RP UUID (<c>aud</c>, том/жижиг үсэг ялгахгүй).</param>
/// <param name="SessionId"><see cref="QrSession.SessionId"/>.</param>
/// <param name="Nonce"><see cref="QrSession.Nonce"/> (яг).</param>
/// <param name="Issuer">null = <see cref="EidQr.DefaultIssuer"/>.</param>
/// <param name="Now">null = одоо.</param>
public sealed record QrExpect(string RpUuid, string SessionId, string Nonce, string? Issuer = null, DateTimeOffset? Now = null);

/// <summary>Итгэлийн тохиргоо; null талбар бүр анхдагчтай.</summary>
/// <param name="Anchors">Итгэмжлэгдсэн root (null/хоосон = шигтгэсэн үндэсний root 01).</param>
/// <param name="Intermediates">Завсрын CA (null = шигтгэсэн 02–04, <see cref="EidTrust.CitizenIntermediatesPem"/>). x5c[1] үргэлж зөвхөн завсрын нэр дэвшигч.</param>
/// <param name="AllowedIssuerSkis">Навчийг шууд гаргасан CA-ийн SKI (hex, ":" зөвшөөрнө; null/хоосон = <see cref="EidQr.CitizenIssuingCaSki"/>).</param>
/// <param name="Revocation">
/// (навч, олгогч) → "good" | "revoked" | "unknown"; null = AIA-ийн OCSP (<see cref="OcspRevocationChecker"/>: OCSP unknown →
/// "revoked", 48 ц). Exception = "unknown". Олгогчийн гэрчилгээг <see cref="EidQr.VerifyAsync"/> дуусахад Dispose хийнэ —
/// хадгалах бол хуулбарла.
/// </param>
/// <param name="RevocationSoftFail">true бол "unknown"-г хүлээн авна (анхдагч hard-fail).</param>
public sealed record QrTrust(IReadOnlyList<X509Certificate2>? Anchors = null, IReadOnlyList<X509Certificate2>? Intermediates = null,
    IReadOnlyList<string>? AllowedIssuerSkis = null, Func<X509Certificate2, X509Certificate2?, Task<string>>? Revocation = null,
    bool RevocationSoftFail = false);

/// <summary><see cref="EidQrClient.CheckAsync(QrSession, CancellationToken)"/>-ийн хариу.</summary>
/// <param name="Complete">false бол иргэн хараахан хариулаагүй.</param>
/// <param name="Result">Complete бол шалгасан presentation.</param>
public sealed record QrCheck(bool Complete, QrResult? Result);

/// <summary>Алдааны кодууд (<see cref="EidQrException.Code"/>) — Go / TS SDK-тэй ижил.</summary>
public static class EidQrErrorCodes
{
    /// <summary>Скан хийсэн мөр eID «Миний QR» биш (клиент талын).</summary>
    public const string FormatInvalid = "QR_FORMAT_INVALID";
    /// <summary>404: токен танигдахгүй / хугацаа дууссан (120 с) / ашиглагдсан → шинэ QR гаргуул.</summary>
    public const string TokenInvalid = "QR_TOKEN_INVALID";
    /// <summary>ResultAsync-ийн хүлээх хугацаа дууссан ч иргэн хараахан хариулаагүй (CA-ийн session идэвхтэй) — дахин Result / Check.</summary>
    public const string Pending = "QR_PENDING";
    /// <summary>Session амжилтгүй (<see cref="EidQrException.EndResult"/>: USER_REFUSED, TIMEOUT г.м.).</summary>
    public const string SessionFailed = "SESSION_FAILED";
    /// <summary>RP-API-ийн бусад HTTP алдаа (серверийн code-гүй); <see cref="EidQrException.HttpStatus"/>-г үз.</summary>
    public const string HttpError = "HTTP_ERROR";
    /// <summary>Сүлжээ / timeout.</summary>
    public const string NetworkError = "NETWORK_ERROR";
    /// <summary>JWS-ийн бүтэц / payload JSON буруу.</summary>
    public const string JwsMalformed = "QR_JWS_MALFORMED";
    /// <summary>header (alg PS256, typ, x5c 2 гэрчилгээ) буруу.</summary>
    public const string HeaderInvalid = "QR_HEADER_INVALID";
    /// <summary>Гинж / навчны профайл (QUALIFIED, contentCommitment, олгогч SKI, RSA ≥ 2048, хугацаа).</summary>
    public const string ChainInvalid = "QR_CHAIN_INVALID";
    /// <summary>Иргэний гэрчилгээ цуцлагдсан.</summary>
    public const string CertRevoked = "QR_CERT_REVOKED";
    /// <summary>Цуцлалтын төлөв тодорхойгүй (hard-fail).</summary>
    public const string RevocationUnknown = "QR_REVOCATION_UNKNOWN";
    /// <summary>PS256 гарын үсэг таарсангүй.</summary>
    public const string SignatureInvalid = "QR_SIGNATURE_INVALID";
    /// <summary>Claim (iss, sub, statement, iat/exp …) буруу.</summary>
    public const string ClaimsInvalid = "QR_CLAIMS_INVALID";
    /// <summary>aud ≠ RP UUID.</summary>
    public const string AudienceMismatch = "QR_AUDIENCE_MISMATCH";
    /// <summary>sid ≠ session.</summary>
    public const string SessionMismatch = "QR_SESSION_MISMATCH";
    /// <summary>nonce ≠ таны nonce.</summary>
    public const string NonceMismatch = "QR_NONCE_MISMATCH";
    /// <summary>iat ирээдүйд (+60 с-ээс их).</summary>
    public const string NotYetValid = "QR_NOT_YET_VALID";
    /// <summary>exp + 60 с өнгөрсөн.</summary>
    public const string Expired = "QR_EXPIRED";
    /// <summary>data (source, fields, photo) хязгаар зөрчсөн.</summary>
    public const string DataInvalid = "QR_DATA_INVALID";
    /// <summary>410 — presentation аль хэдийн нэг удаа уншигдсан эсвэл хугацаа дууссан → шинэ QR уншуул.</summary>
    public const string PresentationGone = "QR_PRESENTATION_GONE";
}

/// <summary>«Миний QR»-ийн алдаа. <see cref="Code"/> тогтвортой — үүгээр салаална; <see cref="Exception.Message"/> зөвхөн лог.</summary>
public sealed class EidQrException : Exception
{
    /// <summary>Тогтвортой код: <see cref="EidQrErrorCodes"/>-ийн нэг, эсвэл серверийн <c>code</c> (ж: REQUEST_INVALID).</summary>
    public string Code { get; }

    /// <summary>RP-API-ийн HTTP статус (серверийн алдаанд), бусад үед null.</summary>
    public int? HttpStatus { get; init; }

    /// <summary><c>SESSION_FAILED</c>-д session-ий endResult (USER_REFUSED, TIMEOUT …).</summary>
    public string? EndResult { get; init; }

    /// <summary>Шинэ алдаа.</summary>
    public EidQrException(string code, string reason, Exception? inner = null) : base(code + ": " + reason, inner)
    {
        Code = code;
    }
}
