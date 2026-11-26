using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Иргэний USB токен (PKCS#11, EC P-256; Go <c>TokenService</c>, TS <c>TokenApi</c>):
/// <list type="bullet">
/// <item>гэрчилгээ олголт (CA docs/TOKEN_CERT.md, RP-д TOKEN_ISSUE эрх): <see cref="IssueCertificateAsync"/> → иргэн утсаараа
/// PIN2-оор батална → <c>client.Session.PollAsync</c> (<see cref="TokenCertSessionBlock.Status"/> = ISSUED) →
/// <see cref="CertificateResultAsync"/> → <see cref="VerifyTokenCertificates"/>;</item>
/// <item>токеноор нэвтрэлт (docs/TOKEN_AUTH.md, AUTH эрх): <see cref="AuthChallengeAsync"/> → токен
/// <see cref="TokenAuthDigest"/>-ийг CKM_ECDSA-аар зурна (түүхий r||s) → <see cref="AuthVerifyAsync"/>.</item>
/// </list>
/// Алдаа: <see cref="EidException.Code"/> ∈ <see cref="TokenErrorCodes.All"/> (TOKEN_LIMIT_REACHED → <see cref="TokenLimitOf"/>);
/// түр алдаа (RATE_LIMITED, STATE_UNAVAILABLE, ISSUANCE_PENDING) — <see cref="EidException.Retryable"/> + RetryAfter.
/// </summary>
public sealed class TokenService
{
    /// <summary><see cref="TokenCertInput.AppTransaction"/>-ийн дээд хэмжээ (CA-ийн хязгаар, 16 KiB, UTF-8 байт).</summary>
    public const int MaxAppTransactionBytes = 16 << 10;

    /// <summary>CA олголт дуусаагүй бол ≤ 15 с хүлээдэг.</summary>
    private static readonly TimeSpan ResultTimeout = TimeSpan.FromSeconds(30);

    private static readonly Regex RpUuidRe = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z", RegexOptions.CultureInvariant);

    private readonly EidClient _c;

    internal TokenService(EidClient c) => _c = c;

    /// <summary>
    /// <c>POST /token/certificate</c>: токены AUTH + SIGN гэрчилгээ олголт эхлүүлнэ (иргэн утсаараа батална). CA-ийн буцаасан
    /// CSR hash-ууд илгээсэнтэй таарахгүй бол <see cref="EidValidationException"/>. Сунгалт scope-ийг хадгална (өөр scope бол
    /// 409 TOKEN_SCOPE_CHANGE); бусад 409/400 — <see cref="TokenErrorCodes.All"/>.
    /// </summary>
    /// <exception cref="ArgumentException">Заавал талбар дутуу (хүсэлт явахгүй).</exception>
    /// <exception cref="EidAppTransactionTooLargeException">AppTransaction &gt; 16 KiB (хүсэлт явахгүй).</exception>
    public async Task<TokenCertStart> IssueCertificateAsync(TokenCertInput input, CancellationToken ct = default)
    {
        var req = CertRequest(input);
        var r = await _c.Http.PostJsonAsync<TokenIssueWireResponse>(RpRoutes.TokenCertificate.Expand(), req, null, ct).ConfigureAwait(false)
            ?? new TokenIssueWireResponse();
        if (!HexSha256Equal(r.CsrAuthSha256, input.CsrAuth) || !HexSha256Equal(r.CsrSignSha256, input.CsrSign))
        {
            throw new EidValidationException(ValidationReasons.TokenCsrMismatch, "token: CA-ийн csrAuthSha256/csrSignSha256 илгээсэн CSR-тэй таарсангүй");
        }
        return new TokenCertStart
        {
            SessionId = r.SessionId ?? "",
            Vc = r.Vc ?? "",
            CsrAuthSha256 = (r.CsrAuthSha256 ?? "").ToLowerInvariant(),
            CsrSignSha256 = (r.CsrSignSha256 ?? "").ToLowerInvariant(),
            ExpiresAt = r.ExpiresAt ?? "",
            Supersedes = r.Supersedes,
        };
    }

    /// <summary>
    /// <c>POST /token/certificate {"dryRun": true}</c>: <see cref="IssueCertificateAsync"/>-ийн бүх шалгалт ижил кодтой, гэхдээ
    /// session / push үүсэхгүй. Хариунд <c>dryRun: true</c> алга бол <see cref="EidValidationException"/>.
    /// </summary>
    public async Task<TokenCertPreview> PreviewCertificateAsync(TokenCertInput input, CancellationToken ct = default)
    {
        var req = CertRequest(input) with { DryRun = true };
        var r = await _c.Http.PostJsonAsync<TokenPreviewWireResponse>(RpRoutes.TokenCertificate.Expand(), req, null, ct).ConfigureAwait(false);
        if (r is not { DryRun: true })
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "token: dryRun хариу биш (CA dryRun-ийг дэмжихгүй)");
        }
        return new TokenCertPreview { Supersedes = r.Supersedes };
    }

    /// <summary>Оролтыг шалгаж биеийг угсарна (Go <c>certRequest</c>; CA DisallowUnknownFields — яг эдгээр талбар).</summary>
    private TokenCertWireRequest CertRequest(TokenCertInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (string.IsNullOrWhiteSpace(input.SignerEtsi) || input.CsrAuth is not { Length: > 0 } || input.CsrSign is not { Length: > 0 } ||
            string.IsNullOrWhiteSpace(input.TokenSerial))
        {
            throw new ArgumentException("eid: token: SignerEtsi, CsrAuth, CsrSign, TokenSerial шаардлагатай", nameof(input));
        }
        if (input.AppTransaction is { } at && Encoding.UTF8.GetByteCount(at) > MaxAppTransactionBytes)
        {
            throw new EidAppTransactionTooLargeException();
        }
        var creds = _c.Options.Credentials;
        return new TokenCertWireRequest
        {
            RelyingPartyUuid = creds.RpUuid,
            RelyingPartyName = creds.RpName,
            Signer = new Dictionary<string, string> { ["etsi"] = input.SignerEtsi.Trim() },
            CsrAuth = Convert.ToBase64String(input.CsrAuth),
            CsrSign = Convert.ToBase64String(input.CsrSign),
            TokenSerial = input.TokenSerial.Trim(),
            TokenLabel = Wire.NullIfEmpty(input.TokenLabel),
            OnBehalfOf = (input.OnBehalfOf ?? "").Trim(),
            AppTransaction = Wire.NullIfEmpty((input.AppTransaction ?? "").Trim()),
        };
    }

    /// <summary>
    /// <c>GET /token/certificate/{sessionID}</c>: олгосон AUTH + SIGN гэрчилгээ + гинж (зөвхөн үүсгэсэн RP, 24 цаг идэмпотент).
    /// Токенд бичихээс өмнө <see cref="VerifyTokenCertificates"/>. Нөхцөл өөрчлөгдсөн бол 409; 410 RESULT_EXPIRED.
    /// </summary>
    public async Task<TokenCertResult> CertificateResultAsync(string sessionId, CancellationToken ct = default)
    {
        var path = RpRoutes.TokenCertificateResult.Expand(sessionId);
        var raw = await _c.Http.GetRawAsync(path, ResultTimeout, ct).ConfigureAwait(false);
        var r = EidHttp.Decode<TokenCertResult>(raw, "GET", path) ?? new TokenCertResult();
        return r with { Raw = RawJson.Element(raw) };
    }

    /// <summary>
    /// Олгосон AUTH/SIGN гэрчилгээ бүр задарч, илгээсэн CSR-ийн public key-тэй (SPKI, байт-ижил) таарахыг шалгана (Go
    /// <c>VerifyTokenCertificates</c>). Таарахгүй бол <see cref="EidValidationException"/> — гэрчилгээг токенд бүү бич.
    /// </summary>
    /// <exception cref="ArgumentException">CSR задарсангүй.</exception>
    /// <exception cref="EidValidationException">Гэрчилгээ алга / задарсангүй (<see cref="ValidationReasons.ResponseMalformed"/>,
    /// <see cref="ValidationReasons.CertMalformed"/>) эсвэл түлхүүр таарсангүй (<see cref="ValidationReasons.TokenCsrMismatch"/>).</exception>
    public static void VerifyTokenCertificates(TokenCertResult result, byte[] csrAuth, byte[] csrSign)
    {
        if (result?.Auth is null || result.Sign is null)
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "token: auth/sign гэрчилгээ алга");
        }
        foreach (var (name, item, csr) in new[] { ("auth", result.Auth!, csrAuth), ("sign", result.Sign!, csrSign) })
        {
            byte[] want;
            try
            {
                want = CsrSpki(csr ?? throw new ArgumentNullException(name == "auth" ? nameof(csrAuth) : nameof(csrSign)));
            }
            catch (AsnContentException e)
            {
                throw new ArgumentException("eid: token: " + name + " CSR задарсангүй", name == "auth" ? nameof(csrAuth) : nameof(csrSign), e);
            }
            if (!B64.TryDecodeStd(item.Certificate ?? "", out var der))
            {
                throw new EidValidationException(ValidationReasons.ResponseMalformed, "token: " + name + " гэрчилгээ base64 буруу");
            }
            ParsedCert crt;
            try
            {
                crt = ParsedCert.Parse(der);
            }
            catch (FormatException e)
            {
                throw new EidValidationException(ValidationReasons.CertMalformed, "token: " + name + " гэрчилгээ задарсангүй", e);
            }
            if (!crt.Spki.AsSpan().SequenceEqual(want))
            {
                throw new EidValidationException(ValidationReasons.TokenCsrMismatch, "token: " + name + " гэрчилгээний түлхүүр CSR-ийнхтэй таарсангүй");
            }
        }
    }

    /// <summary>PKCS#10 CertificationRequest-ийн subjectPKInfo-ийн түүхий DER (Go <c>RawSubjectPublicKeyInfo</c>).</summary>
    internal static byte[] CsrSpki(byte[] der)
    {
        var top = new AsnReader(der, AsnEncodingRules.DER);
        var req = top.ReadSequence();
        top.ThrowIfNotEmpty();
        var info = req.ReadSequence();
        info.ReadInteger();
        info.ReadSequence(); // subject Name
        var spki = info.ReadEncodedValue().ToArray();
        var spkiSeq = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
        spkiSeq.ReadSequence(); // algorithm
        spkiSeq.ReadBitString(out _);
        spkiSeq.ThrowIfNotEmpty();
        if (info.HasData)
        {
            info.ReadEncodedValue(); // [0] attributes
        }
        info.ThrowIfNotEmpty();
        req.ReadSequence(); // signatureAlgorithm
        req.ReadBitString(out _);
        req.ThrowIfNotEmpty();
        return spki;
    }

    /// <summary><c>POST /token/auth/challenge</c>: энэ RP-д холбогдсон нэг удаагийн challenge (2 мин).</summary>
    public async Task<TokenAuthChallenge> AuthChallengeAsync(CancellationToken ct = default)
    {
        var creds = _c.Options.Credentials;
        var body = new Dictionary<string, string> { ["relyingPartyUUID"] = creds.RpUuid, ["relyingPartyName"] = creds.RpName };
        return await _c.Http.PostJsonAsync<TokenAuthChallenge>(RpRoutes.TokenAuthChallenge.Expand(), body, null, ct).ConfigureAwait(false)
            ?? new TokenAuthChallenge();
    }

    /// <summary>
    /// <c>POST /token/auth/verify</c>: токены AUTH гэрчилгээ (DER) + challenge дээрх түүхий r||s (64 байт). CA руу
    /// илгээхээс ӨМНӨ SDK: challenge.RpUuid == энэ RP, гарын үсэг <see cref="TokenAuthDigest"/> дээр гэрчилгээний EC P-256
    /// түлхүүрээр таарах, гэрчилгээ <see cref="EidClientOptions.Trust"/>-аар (хугацаа, зориулалт auth, гинж, issuer
    /// allowlist) хүчинтэйг шалгана (эс бөгөөс <see cref="EidValidationException"/>, CA руу явахгүй); дараа нь CA-ийн
    /// endResult == OK ба identity.etsi == гэрчилгээний SERIALNUMBER. Цуцлалтыг CA шалгана; RP нэмж
    /// <see cref="ResponseValidator.CheckRevocationAsync"/> дуудаж болно. Challenge нэг удаагийн.
    /// </summary>
    /// <exception cref="ArgumentException">challenge (ChallengeId) эсвэл signature алга.</exception>
    public async Task<TokenAuthResult> AuthVerifyAsync(TokenAuthChallenge challenge, byte[] certificateDer, byte[] signature, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(certificateDer);
        ParsedCert crt;
        try
        {
            crt = ParsedCert.Parse(certificateDer);
        }
        catch (FormatException e)
        {
            throw new EidValidationException(ValidationReasons.CertMalformed, "token auth: гэрчилгээ задарсангүй", e);
        }
        if (challenge is null || string.IsNullOrEmpty(challenge.ChallengeId) || signature is not { Length: > 0 })
        {
            throw new ArgumentException("eid: token auth: challenge (ChallengeId, Challenge, RpUuid) ба signature шаардлагатай");
        }
        if (!string.Equals(challenge.RpUuid, _c.Options.Credentials.RpUuid, StringComparison.OrdinalIgnoreCase))
        {
            throw new EidValidationException(ValidationReasons.TokenChallenge, "token auth: challenge өөр RP-д холбогдсон (rpUUID)");
        }
        byte[] digest;
        try
        {
            digest = TokenAuthDigest(challenge.RpUuid, challenge.Challenge);
        }
        catch (ArgumentException e)
        {
            throw new EidValidationException(ValidationReasons.TokenChallenge, "token auth: challenge/rpUUID хэлбэр буруу", e);
        }
        if (!VerifyTokenSignature(crt, digest, signature))
        {
            throw new EidValidationException(ValidationReasons.TokenSignature, "token auth: гарын үсэг challenge-тэй таарсангүй (EC P-256 r||s)");
        }
        _c.Validator.VerifyTokenAuthCertificate(crt);
        var body = new Dictionary<string, string>
        {
            ["challengeId"] = challenge.ChallengeId,
            ["certificate"] = Convert.ToBase64String(certificateDer),
            ["signature"] = Convert.ToBase64String(signature),
        };
        var path = RpRoutes.TokenAuthVerify.Expand();
        var raw = await _c.Http.PostRawAsync(path, body, null, ct).ConfigureAwait(false);
        var r = EidHttp.Decode<TokenVerifyWireResponse>(raw, "POST", path) ?? new TokenVerifyWireResponse();
        if (r.Result?.EndResult != EndResults.Ok)
        {
            throw new EidValidationException(ValidationReasons.TokenIdentity, "token auth: endResult OK биш");
        }
        var identity = r.Identity ?? new TokenIdentity();
        if (string.IsNullOrEmpty(identity.Etsi) || identity.Etsi != crt.Subject.SerialNumber)
        {
            throw new EidValidationException(ValidationReasons.TokenIdentity, "token auth: identity.etsi нь гэрчилгээний SERIALNUMBER биш");
        }
        return new TokenAuthResult
        {
            Identity = identity,
            SerialHex = r.Cert?.SerialHex ?? "",
            NotAfter = r.Cert?.NotAfter ?? default,
            Organization = r.Organization is { Etsi.Length: > 0 } org ? org : null,
            Raw = RawJson.Element(raw),
        };
    }

    /// <summary>Токены түүхий r||s (P-256, 64 байт) digest дээр гэрчилгээний түлхүүрээр таарах эсэх (Go <c>verifyTokenSignature</c>).</summary>
    internal static bool VerifyTokenSignature(ParsedCert crt, byte[] digest, byte[] sig)
    {
        if (!crt.IsP256 || sig.Length != 64)
        {
            return false;
        }
        try
        {
            using var ec = crt.CreateEcdsa();
            return ec.VerifyHash(digest, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Токены зурах 32 байт: SHA-256("eID-TOKEN-AUTH" || rpUUID || challenge) (docs/TOKEN_AUTH.md; Go <c>TokenAuthDigest</c>).
    /// <paramref name="rpUuid"/> — challenge хариуны RpUuid (жижиг үсгийн 36 тэмдэгт), <paramref name="challengeB64"/> — 32 байт
    /// стандарт base64.
    /// </summary>
    /// <exception cref="ArgumentException">rpUuid эсвэл challenge хэлбэр буруу.</exception>
    public static byte[] TokenAuthDigest(string rpUuid, string challengeB64)
    {
        if (rpUuid is null || !RpUuidRe.IsMatch(rpUuid))
        {
            throw new ArgumentException("eid: token auth: rpUUID жижиг үсгийн 36 тэмдэгт UUID биш", nameof(rpUuid));
        }
        if (!B64.TryDecodeStd(challengeB64 ?? "", out var ch) || ch.Length != 32)
        {
            throw new ArgumentException("eid: token auth: challenge 32 байт base64 биш", nameof(challengeB64));
        }
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData("eID-TOKEN-AUTH"u8);
        h.AppendData(Encoding.ASCII.GetBytes(rpUuid));
        h.AppendData(ch);
        return h.GetHashAndReset();
    }

    /// <summary>Discovery (<c>/.well-known/eid</c>)-ийн <c>tokenCertificate</c> блок; блок алга (хуучин CA) бол Enabled false.</summary>
    public async Task<TokenCertInfo> CertificateInfoAsync(CancellationToken ct = default)
    {
        var raw = await _c.Http.GetRawAsync(RpRoutes.DiscoveryPath, null, ct).ConfigureAwait(false);
        return Discovery.Block<TokenCertInfo>(raw, "tokenCertificate", (v, e) => v with { Raw = e });
    }

    /// <summary>
    /// <paramref name="error"/> нь 409 TOKEN_LIMIT_REACHED бол түүний {kind, limit, organization} (Go <c>TokenLimitOf</c>).
    /// Гэрээнээс гадуур хэлбэр бол null — татгалзал хүчинтэй хэвээр, дэлгэрэнгүйгүй.
    /// </summary>
    public static TokenLimit? TokenLimitOf(Exception? error)
    {
        if (error is not EidApiException { Code: TokenErrorCodes.TokenLimitReached } api)
        {
            return null;
        }
        try
        {
            using var d = JsonDocument.Parse(api.Body);
            var o = d.RootElement;
            if (o.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            var kind = o.TryGetProperty("kind", out var k) ? k : default;
            if (kind.ValueKind is not (JsonValueKind.String or JsonValueKind.Null or JsonValueKind.Undefined) ||
                !o.TryGetProperty("limit", out var l) || l.ValueKind != JsonValueKind.Number || !l.TryGetInt32(out var limit) || limit < 0)
            {
                return null;
            }
            var org = o.TryGetProperty("organization", out var og) ? og : default;
            if (org.ValueKind is not (JsonValueKind.String or JsonValueKind.Null or JsonValueKind.Undefined))
            {
                return null;
            }
            switch (kind.ValueKind == JsonValueKind.String ? kind.GetString() : "")
            {
                case TokenKinds.Personal:
                    return new TokenLimit(TokenKinds.Personal, limit, null);
                case TokenKinds.Organization:
                    return org.ValueKind == JsonValueKind.String && org.GetString() is { } s && s.StartsWith("NTRMN-", StringComparison.Ordinal)
                        ? new TokenLimit(TokenKinds.Organization, limit, s)
                        : null;
                default:
                    return null;
            }
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>hexDigest нь data-ийн SHA-256 эсэх (том/жижиг үсэг хамаагүй; Go <c>hexSHA256Equal</c>).</summary>
    private static bool HexSha256Equal(string? hexDigest, byte[] data)
    {
        byte[] want;
        try
        {
            want = Convert.FromHexString((hexDigest ?? "").Trim());
        }
        catch (FormatException)
        {
            return false;
        }
        return want.Length == 32 && CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), want);
    }
}

/// <summary>Discovery-ийн дэд блок задлах туслах.</summary>
internal static class Discovery
{
    /// <summary>
    /// Discovery JSON-ийн <paramref name="name"/> блокийг <typeparamref name="T"/> болгоно; блок алга / null бол
    /// <c>new T()</c>. <paramref name="withRaw"/> — блокийн түүхий JSON-ийг тавина.
    /// </summary>
    public static T Block<T>(byte[] raw, string name, Func<T, JsonElement, T> withRaw) where T : class, new()
    {
        JsonDocument d;
        try
        {
            d = JsonDocument.Parse(raw);
        }
        catch (JsonException e)
        {
            throw new EidException("eid: GET " + RpRoutes.DiscoveryPath + ": хариу задарсангүй", e);
        }
        using (d)
        {
            if (d.RootElement.ValueKind != JsonValueKind.Object || !d.RootElement.TryGetProperty(name, out var b) || b.ValueKind == JsonValueKind.Null)
            {
                return new T();
            }
            T? v;
            try
            {
                v = b.Deserialize<T>(EidHttp.Json);
            }
            catch (JsonException e)
            {
                throw new EidException("eid: GET " + RpRoutes.DiscoveryPath + ": " + name + " задарсангүй", e);
            }
            return withRaw(v ?? new T(), b.Clone());
        }
    }
}

/// <summary><see cref="TokenService.IssueCertificateAsync"/> / <see cref="TokenService.PreviewCertificateAsync"/>-ийн оролт.</summary>
public sealed record TokenCertInput
{
    /// <summary>Иргэн (PNOMN-…), батлах push түүний утсанд очно.</summary>
    public string SignerEtsi { get; init; } = "";

    /// <summary>AUTH түлхүүрийн PKCS#10 DER (EC P-256, ecdsa-with-SHA256, ≤ 4 KiB).</summary>
    public byte[] CsrAuth { get; init; } = Array.Empty<byte>();

    /// <summary>SIGN түлхүүрийн PKCS#10 DER (AUTH-аас өөр түлхүүр).</summary>
    public byte[] CsrSign { get; init; } = Array.Empty<byte>();

    /// <summary>Токены serial ([A-Za-z0-9-]{1,64}).</summary>
    public string TokenSerial { get; init; } = "";

    /// <summary>Заавал биш (≤ 64); null / "" бол илгээхгүй.</summary>
    public string? TokenLabel { get; init; }

    /// <summary>Байгууллагын токен (NTRMN-…); null / "" = хувийн токен (талбар "" утгаар илгээгдэнэ).</summary>
    public string? OnBehalfOf { get; init; }

    /// <summary>
    /// Заавал биш: macOS App Store build-ийн StoreKit 2 AppTransaction JWS (≤ <see cref="TokenService.MaxAppTransactionBytes"/>).
    /// null / "" бол илгээхгүй; хүчингүй бол CA 400 APP_ATTESTATION_INVALID.
    /// </summary>
    public string? AppTransaction { get; init; }
}

/// <summary>Олголтын эхлэлийн хариу: утсанд очсон SIGN session.</summary>
public sealed record TokenCertStart
{
    /// <summary>Session ID (<c>client.Session.PollAsync</c>).</summary>
    public string SessionId { get; init; } = "";

    /// <summary>Иргэнд ХАРУУЛАХ баталгаажуулах код (ПИН биш).</summary>
    public string Vc { get; init; } = "";

    /// <summary>hex(SHA-256(CSR AUTH)), жижиг үсгээр; SDK илгээсэн CSR-тэй тулгасан.</summary>
    public string CsrAuthSha256 { get; init; } = "";

    /// <summary>hex(SHA-256(CSR SIGN)), жижиг үсгээр.</summary>
    public string CsrSignSha256 { get; init; } = "";

    /// <summary>CA-ийн expiresAt (RFC 3339) эсвэл "".</summary>
    public string ExpiresAt { get; init; } = "";

    /// <summary>
    /// Хувийн олголтод хязгаар хүрсэн үед олголт амжилттай болоход автоматаар цуцлагдах өөр serial-тай хувийн токенууд (CA
    /// 2026-10-19). Бусад үед null. PIN2-оос өмнө иргэнд анхааруул.
    /// </summary>
    public IReadOnlyList<TokenSupersede>? Supersedes { get; init; }
}

/// <summary><see cref="TokenCertStart.Supersedes"/>-ийн нэг мөр.</summary>
public sealed record TokenSupersede
{
    /// <summary>Солигдох токены serial.</summary>
    [JsonPropertyName("tokenSerial")]
    public string TokenSerial { get; init; } = "";
}

/// <summary><see cref="TokenService.PreviewCertificateAsync"/>-ийн хариу.</summary>
public sealed record TokenCertPreview
{
    /// <summary>Бодит олголт амжилттай болоход солигдох хувийн токенууд (байхгүй бол null).</summary>
    public IReadOnlyList<TokenSupersede>? Supersedes { get; init; }
}

/// <summary>Олгосон нэг гэрчилгээ.</summary>
public sealed record TokenCertItem
{
    /// <summary>base64 DER.</summary>
    [JsonPropertyName("certificate")]
    public string Certificate { get; init; } = "";

    /// <summary>PEM.</summary>
    [JsonPropertyName("certificatePem")]
    public string CertificatePem { get; init; } = "";

    /// <summary>Serial (hex).</summary>
    [JsonPropertyName("serialHex")]
    public string SerialHex { get; init; } = "";

    /// <summary>RFC 3339.</summary>
    [JsonPropertyName("notBefore")]
    public string NotBefore { get; init; } = "";

    /// <summary>RFC 3339.</summary>
    [JsonPropertyName("notAfter")]
    public string NotAfter { get; init; } = "";
}

/// <summary><c>GET /token/certificate/{sessionID}</c>-ийн хариу.</summary>
public sealed record TokenCertResult
{
    /// <summary><see cref="TokenCertStatuses"/>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    /// <summary>AUTH гэрчилгээ.</summary>
    [JsonPropertyName("auth")]
    public TokenCertItem? Auth { get; init; }

    /// <summary>SIGN гэрчилгээ.</summary>
    [JsonPropertyName("sign")]
    public TokenCertItem? Sign { get; init; }

    /// <summary>base64 DER: 04, 03, 02 (root-гүй).</summary>
    [JsonPropertyName("chain")]
    public IReadOnlyList<string>? Chain { get; init; }

    /// <summary>Гинж PEM-ээр.</summary>
    [JsonPropertyName("chainPem")]
    public string ChainPem { get; init; } = "";

    /// <summary>Хувийн токенд null.</summary>
    [JsonPropertyName("organization")]
    public TokenOrganization? Organization { get; init; }

    /// <summary>TOKEN.</summary>
    [JsonPropertyName("keyMedium")]
    public string KeyMedium { get; init; } = "";

    /// <summary>certificateLevel.</summary>
    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary><c>POST /token/auth/challenge</c>-ийн хариу. Токен <see cref="TokenService.TokenAuthDigest"/>(RpUuid, Challenge)-ийг зурна.</summary>
public sealed record TokenAuthChallenge
{
    /// <summary>Challenge ID.</summary>
    [JsonPropertyName("challengeId")]
    public string ChallengeId { get; init; } = "";

    /// <summary>base64 (32 байт).</summary>
    [JsonPropertyName("challenge")]
    public string Challenge { get; init; } = "";

    /// <summary>CA-ийн холбосон RP (жижиг үсэг) — hash-д ЯГ ЭНЭ мөр орно.</summary>
    [JsonPropertyName("rpUUID")]
    public string RpUuid { get; init; } = "";

    /// <summary>Дуусах цаг.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>CA-ийн баталгаажуулсан иргэн (нэр — KYC бүртгэлээс, кирилл).</summary>
public sealed record TokenIdentity
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("etsi")]
    public string Etsi { get; init; } = "";

    /// <summary>Нэр.</summary>
    [JsonPropertyName("givenName")]
    public string GivenName { get; init; } = "";

    /// <summary>Овог.</summary>
    [JsonPropertyName("surname")]
    public string Surname { get; init; } = "";
}

/// <summary><c>POST /token/auth/verify</c>-ийн шалгасан хариу (identity нь гэрчилгээний subject-тэй SDK тулгасан).</summary>
public sealed record TokenAuthResult
{
    /// <summary>Иргэн.</summary>
    public TokenIdentity Identity { get; init; } = new();

    /// <summary>Гэрчилгээний serial (hex).</summary>
    public string SerialHex { get; init; } = "";

    /// <summary>Гэрчилгээний дуусах хугацаа.</summary>
    public DateTimeOffset NotAfter { get; init; }

    /// <summary>Токен байгууллагад холбогдсон бол; эс бөгөөс null.</summary>
    public TokenOrganization? Organization { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    public JsonElement? Raw { get; init; }
}

/// <summary>Discovery (<c>/.well-known/eid</c>)-ийн <c>tokenCertificate</c> блок.</summary>
public sealed record TokenCertInfo
{
    /// <summary>Олголт идэвхтэй эсэх.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    /// <summary>POST олголтын бүтэн URL.</summary>
    [JsonPropertyName("issue")]
    public string Issue { get; init; } = "";

    /// <summary>GET үр дүнгийн URL template ({sessionID}).</summary>
    [JsonPropertyName("result")]
    public string Result { get; init; } = "";

    /// <summary>Шаардлагатай RP эрх (TOKEN_ISSUE).</summary>
    [JsonPropertyName("permission")]
    public string Permission { get; init; } = "";

    /// <summary>certificateLevel.</summary>
    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";

    /// <summary>Түлхүүрийн алгоритм.</summary>
    [JsonPropertyName("keyAlgorithm")]
    public string KeyAlgorithm { get; init; } = "";

    /// <summary>"optional": хоосон = хувийн токен.</summary>
    [JsonPropertyName("onBehalfOf")]
    public string OnBehalfOf { get; init; } = "";

    /// <summary>true: сунгалт scope-ийг хадгална (өөр scope бол 409 TOKEN_SCOPE_CHANGE). Хуучин CA-д false.</summary>
    [JsonPropertyName("scopeLockedOnRenewal")]
    public bool ScopeLockedOnRenewal { get; init; }

    /// <summary>"optional": AppTransaction-ийг CA хүлээн авна. Хуучин CA-д "".</summary>
    [JsonPropertyName("appTransaction")]
    public string AppTransaction { get; init; } = "";

    /// <summary>true: хувийн хязгаар хүрсэн үед Supersedes ирнэ (409 биш). Хуучин CA-д false.</summary>
    [JsonPropertyName("personalAutoSupersede")]
    public bool PersonalAutoSupersede { get; init; }

    /// <summary>true: <see cref="TokenService.PreviewCertificateAsync"/> дэмжигдэнэ. Хуучин CA-д false.</summary>
    [JsonPropertyName("dryRun")]
    public bool DryRun { get; init; }

    /// <summary>Блокийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>409 TOKEN_LIMIT_REACHED-ийн дэлгэрэнгүй (<see cref="TokenService.TokenLimitOf"/>).</summary>
/// <param name="Kind"><see cref="TokenKinds"/>.</param>
/// <param name="Limit">Хязгаар (0 = тухайн төрлийн олголт хаалттай).</param>
/// <param name="Organization">Зөвхөн ORGANIZATION-д (NTRMN-…); бусад үед null.</param>
public sealed record TokenLimit(string Kind, int Limit, string? Organization);

/// <summary>Токены хязгаарын төрөл (<see cref="TokenLimit.Kind"/>).</summary>
public static class TokenKinds
{
    /// <summary>Хувийн токен.</summary>
    public const string Personal = "PERSONAL";
    /// <summary>Байгууллагын токен.</summary>
    public const string Organization = "ORGANIZATION";
}

/// <summary>
/// Токены олголт / үр дүн / нэвтрэлтийн CA кодууд (Go <c>Code*</c>, <c>TokenErrorCodes</c>; CA tokencert.go,
/// token_auth.go). Хуваалцсан кодууд (<see cref="EidErrorCodes"/>, <see cref="PdfErrorCodes"/>) <see cref="All"/>-д орно.
/// </summary>
public static class TokenErrorCodes
{
    /// <summary>409: иргэний токены хязгаар хүрсэн (<see cref="TokenService.TokenLimitOf"/>).</summary>
    public const string TokenLimitReached = "TOKEN_LIMIT_REACHED";
    /// <summary>409: TokenSerial өөр иргэнд хүчинтэй гэрчилгээтэй бүртгэлтэй.</summary>
    public const string TokenInUse = "TOKEN_IN_USE";
    /// <summary>409: сунгалт scope-ийг солих гэсэн (override үгүй).</summary>
    public const string TokenScopeChange = "TOKEN_SCOPE_CHANGE";
    /// <summary>409: иргэн «Бүртгэл устгах» хүсэлт өгсөн.</summary>
    public const string AccountDeletePending = "ACCOUNT_DELETE_PENDING";
    /// <summary>400: AppTransaction ирсэн боловч хүчингүй (push явахгүй).</summary>
    public const string AppAttestationInvalid = "APP_ATTESTATION_INVALID";
    /// <summary>409: өөр CSR-тэй олголт хүлээгдэж байна.</summary>
    public const string TokenIssuancePending = "TOKEN_ISSUANCE_PENDING";
    /// <summary>409: иргэний латин нэр бүртгэлгүй.</summary>
    public const string KycIncomplete = "KYC_INCOMPLETE";
    /// <summary>409: идэвхтэй eID утас алга.</summary>
    public const string NoActiveDevice = "NO_ACTIVE_DEVICE";
    /// <summary>409: CSR-ийн түлхүүрт гэрчилгээ аль хэдийн олгогдсон.</summary>
    public const string CsrKeyReused = "CSR_KEY_REUSED";
    /// <summary>400: CSR буруу.</summary>
    public const string CsrInvalid = "CSR_INVALID";
    /// <summary>400: зөвхөн EC P-256, ecdsa-with-SHA256.</summary>
    public const string CsrKeyUnsupported = "CSR_KEY_UNSUPPORTED";
    /// <summary>400: CSR-ийн proof-of-possession буруу.</summary>
    public const string CsrSignatureInvalid = "CSR_SIGNATURE_INVALID";
    /// <summary>400: CsrAuth ба CsrSign ижил түлхүүртэй.</summary>
    public const string CsrKeysIdentical = "CSR_KEYS_IDENTICAL";
    /// <summary>Session ErrorCode / үр дүнгийн 409: гэрчилгээ олгогдсонгүй.</summary>
    public const string IssuanceFailed = "ISSUANCE_FAILED";
    /// <summary>410: олголтын үр дүнгийн хугацаа (24 ц) дууссан.</summary>
    public const string ResultExpired = "RESULT_EXPIRED";
    /// <summary>Session ErrorCode: батлах гарын үсэг session/CSR-тэй таарсангүй.</summary>
    public const string CsrDigestMismatch = "CSR_DIGEST_MISMATCH";
    /// <summary>Session ErrorCode: иргэний гарын үсгийн гэрчилгээ солигдсон.</summary>
    public const string SignerCertChanged = "SIGNER_CERT_CHANGED";
    /// <summary>Session ErrorCode: CA-ийн дотоод алдаа.</summary>
    public const string IssuanceError = "ISSUANCE_ERROR";
    /// <summary>Session ErrorCode: бүртгэлийн давхардал.</summary>
    public const string RegistryFailed = "REGISTRY_FAILED";
    /// <summary>403: токеноор нэвтрэлт зөвхөн бүртгэлтэй RP-д.</summary>
    public const string RpRequired = "RP_REQUIRED";
    /// <summary>410: challenge олдсонгүй эсвэл хугацаа дууссан.</summary>
    public const string ChallengeExpired = "CHALLENGE_EXPIRED";
    /// <summary>409: challenge аль хэдийн ашиглагдсан.</summary>
    public const string ChallengeUsed = "CHALLENGE_USED";
    /// <summary>400: гэрчилгээ буруу.</summary>
    public const string CertInvalid = "CERT_INVALID";
    /// <summary>409: гэрчилгээ идэвхгүй, цуцлагдсан эсвэл хугацаа дууссан.</summary>
    public const string CertNotActive = "CERT_NOT_ACTIVE";

    /// <summary>Бүх тогтвортой код (Go <c>TokenErrorCodes</c>-тэй ижил дараалал).</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        TokenLimitReached, TokenInUse, TokenScopeChange, AccountDeletePending, AppAttestationInvalid,
        TokenIssuancePending, KycIncomplete, NoActiveDevice, CsrKeyReused, CsrInvalid,
        CsrKeyUnsupported, CsrSignatureInvalid, CsrKeysIdentical, IssuanceFailed, ResultExpired,
        CsrDigestMismatch, SignerCertChanged, IssuanceError, RegistryFailed,
        RpRequired, ChallengeExpired, ChallengeUsed, CertInvalid, CertNotActive,
        EidErrorCodes.RequestInvalid, PdfErrorCodes.SignatureInvalid, PdfErrorCodes.SessionMismatch, PdfErrorCodes.SessionNotComplete,
        PdfErrorCodes.SessionFailed, EidErrorCodes.RepresentationRevoked, EidErrorCodes.RepresentationDenied,
        EidErrorCodes.RepresentationPending, EidErrorCodes.RepresentationExpired, EidErrorCodes.OrgNotActive, EidErrorCodes.OrgNotFound,
        EidErrorCodes.SignerUnidentified, EidErrorCodes.RateLimited, EidErrorCodes.StateUnavailable, EidErrorCodes.IssuancePending,
    };
}

/// <summary>
/// <see cref="TokenCertInput.AppTransaction"/> &gt; <see cref="TokenService.MaxAppTransactionBytes"/> — SDK CA руу
/// илгээхгүй (Go <c>ErrAppTransactionTooLarge</c>, TS <c>AppTransactionTooLargeError</c>).
/// </summary>
public sealed class EidAppTransactionTooLargeException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidAppTransactionTooLargeException() : base("eid: token: AppTransaction 16 KiB-аас их")
    {
    }
}

/// <summary><c>POST /token/certificate</c>-ийн бие (Go <c>tokenCertRequest</c>; CA DisallowUnknownFields).</summary>
internal sealed record TokenCertWireRequest
{
    [JsonPropertyName("relyingPartyUUID")]
    public string RelyingPartyUuid { get; init; } = "";

    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    [JsonPropertyName("signer")]
    public Dictionary<string, string> Signer { get; init; } = new();

    [JsonPropertyName("csrAuth")]
    public string CsrAuth { get; init; } = "";

    [JsonPropertyName("csrSign")]
    public string CsrSign { get; init; } = "";

    [JsonPropertyName("tokenSerial")]
    public string TokenSerial { get; init; } = "";

    /// <summary>omitempty.</summary>
    [JsonPropertyName("tokenLabel")]
    public string? TokenLabel { get; init; }

    /// <summary>Go-д omitempty-гүй: "" ч илгээгдэнэ.</summary>
    [JsonPropertyName("onBehalfOf")]
    public string OnBehalfOf { get; init; } = "";

    [JsonPropertyName("flow")]
    public string Flow { get; init; } = "notification";

    /// <summary>omitempty.</summary>
    [JsonPropertyName("appTransaction")]
    public string? AppTransaction { get; init; }

    /// <summary>omitempty (зөвхөн PreviewCertificate-д true).</summary>
    [JsonPropertyName("dryRun")]
    public bool? DryRun { get; init; }
}

internal sealed record TokenIssueWireResponse
{
    [JsonPropertyName("sessionID")]
    public string? SessionId { get; init; }

    [JsonPropertyName("vc")]
    [JsonConverter(typeof(VcConverter))]
    public string? Vc { get; init; }

    [JsonPropertyName("csrAuthSha256")]
    public string? CsrAuthSha256 { get; init; }

    [JsonPropertyName("csrSignSha256")]
    public string? CsrSignSha256 { get; init; }

    [JsonPropertyName("expiresAt")]
    public string? ExpiresAt { get; init; }

    [JsonPropertyName("supersedes")]
    public IReadOnlyList<TokenSupersede>? Supersedes { get; init; }
}

internal sealed record TokenPreviewWireResponse
{
    [JsonPropertyName("dryRun")]
    public bool DryRun { get; init; }

    [JsonPropertyName("supersedes")]
    public IReadOnlyList<TokenSupersede>? Supersedes { get; init; }
}

internal sealed record TokenVerifyWireResponse
{
    [JsonPropertyName("result")]
    public TokenVerifyWireResult? Result { get; init; }

    [JsonPropertyName("identity")]
    public TokenIdentity? Identity { get; init; }

    [JsonPropertyName("cert")]
    public TokenVerifyWireCert? Cert { get; init; }

    [JsonPropertyName("organization")]
    public TokenOrganization? Organization { get; init; }
}

internal sealed record TokenVerifyWireResult
{
    [JsonPropertyName("endResult")]
    public string? EndResult { get; init; }
}

internal sealed record TokenVerifyWireCert
{
    [JsonPropertyName("serialHex")]
    public string? SerialHex { get; init; }

    [JsonPropertyName("notAfter")]
    public DateTimeOffset NotAfter { get; init; }
}
