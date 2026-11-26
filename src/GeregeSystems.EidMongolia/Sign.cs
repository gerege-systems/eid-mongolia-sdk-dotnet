using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>Гарын үсгийн session-ий нэмэлт тохиргоо (Go <c>SignOptions</c>). null = анхдагч.</summary>
public sealed record SignOptions
{
    /// <summary>null / "" = client-ийн анхдагч certLevel.</summary>
    public string? CertificateLevel { get; init; }

    /// <summary>
    /// Ижил төхөөрөмжийн буцах https URL (<c>initialCallbackUrl</c>). Device link-д Web2App/App2App холбоос зөвхөн үүнтэй
    /// session-д хүчинтэй; host нь RP-ийн callbackHosts-д байх ёстой.
    /// </summary>
    public string? CallbackUrl { get; init; }

    /// <summary>Digest-ийн hash; null / "" = SHA-256. Digest-ийн урт = hLen.</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>
    /// null / "" = rsassa-pss (PKCS#1 v1.5 нь deprecated); <see cref="SignService.DigestForSignerAsync"/> /
    /// <see cref="SignService.DeviceLinkForSignerAsync"/>-д null / "" = sha256WithRSAEncryption (PAdES/CMS).
    /// </summary>
    public string? SignatureAlgorithm { get; init; }

    /// <summary>
    /// Байгууллагын нэрийн өмнөөс (NTRMN-&lt;бүртгэл&gt;). Гарын үсэг иргэний PIN2 гэрчилгээгээр; байгууллага digest-д
    /// ОРОХГҮЙ. Татгалзвал <see cref="EidException.Code"/> ∈ <see cref="EidErrorCodes.OnBehalfErrorCodes"/>.
    /// </summary>
    public string? OnBehalfOf { get; init; }

    /// <summary>Баримтын нэр: CA-ийн /verify хуудас ба иргэний түүхэнд харагдана. Заавал биш.</summary>
    public string? FileName { get; init; }
}

/// <summary>Certificate-choice session-ий тохиргоо (Go <c>CertChoiceOptions</c>). null = анхдагч.</summary>
public sealed record CertChoiceOptions
{
    /// <summary>null / "" = client-ийн анхдагч certLevel.</summary>
    public string? CertificateLevel { get; init; }

    /// <summary>
    /// ЗӨВХӨН <see cref="SignService.CertificateChoiceDeviceLinkAsync"/>: ижил төхөөрөмжийн буцах https URL
    /// (<c>initialCallbackUrl</c>). Өгвөл Web2App/App2App холбоос боломжтой болж, утас linked SIGN дууссаны дараа энэ
    /// URL-ийг <c>sessionSecretDigest</c> + <c>sessionId</c>-тай нээнэ (<see cref="EidCrypto.VerifySessionSecretDigest"/>).
    /// <see cref="SignService.CertificateChoiceByEtsiAsync"/> үүнийг илгээхгүй.
    /// </summary>
    public string? CallbackUrl { get; init; }
}

/// <summary>
/// Certificate-choice-оор сонгосон гарын үсэг зурагч (TS <c>SignerRef</c>; Go <c>Signer</c>-ийн хүсэлтэд хэрэгтэй хэсэг):
/// гэрчилгээг сонгосон ЯГ ТЭР төхөөрөмжийн <see cref="DocumentNumber"/>, ба linked sign-ийн
/// <see cref="CertChoiceSessionId"/>. Validator-ын ValidateCertificateChoice-ийн үр дүнгээс бөглөнө.
/// </summary>
/// <param name="DocumentNumber">Гэрчилгээг сонгосон төхөөрөмж (sign session-ийг ҮҮГЭЭР эхлүүлнэ).</param>
/// <param name="CertChoiceSessionId">Certificate-choice session (linkedSessionID); null / "" бол /notification/document замаар.</param>
public sealed record SignerRef(string DocumentNumber, string? CertChoiceSessionId = null);

/// <summary>
/// Гарын үсгийн үйлчилгээ (Go <c>SignService</c>, TS <c>SignApi</c>): иргэн PIN2 (non-repudiation)-оор баримтын digest-д
/// гарын үсэг зурна; certificate-choice (Smart-ID v3) — PIN-гүй гэрчилгээ сонгуулах.
/// </summary>
public sealed class SignService
{
    private readonly EidClient _c;

    internal SignService(EidClient c) => _c = c;

    /// <summary>
    /// Бэлэн digest (стандарт base64)-ээр push sign: РД / civil_id / ETSI. Олон утастай иргэнд CA etsi-г ЭХНИЙ идэвхтэй
    /// төхөөрөмж рүү шийднэ — гэрчилгээг урьдчилж мэдэх шаардлагатай (PAdES/CMS) бол
    /// <see cref="CertificateChoiceByEtsiAsync"/> → <see cref="DigestForSignerAsync"/>.
    /// </summary>
    public Task<NotificationSession> DigestByEtsiAsync(string id, string digestB64, IEnumerable<Interaction>? interactions,
        SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = BuildBody(digestB64, interactions, options, SignatureAlgorithms.RsassaPss);
        return NotificationAsync(RpRoutes.SignNotificationEtsi.Expand(id), body, sc, ct);
    }

    /// <summary>Бэлэн digest-ээр push sign, баримтын дугаараар (тодорхой төхөөрөмж).</summary>
    public Task<NotificationSession> DigestByDocumentAsync(string documentNumber, string digestB64,
        IEnumerable<Interaction>? interactions, SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = BuildBody(digestB64, interactions, options, SignatureAlgorithms.RsassaPss);
        return NotificationAsync(RpRoutes.SignNotificationDocument.Expand(documentNumber), body, sc, ct);
    }

    /// <summary>Текстийн (UTF-8) SHA-256 digest-ийг дотроо тооцоод push sign.</summary>
    public Task<NotificationSession> TextByEtsiAsync(string id, string text, IEnumerable<Interaction>? interactions,
        SignOptions? options = null, CancellationToken ct = default) =>
        DigestByEtsiAsync(id, EidCrypto.Sha256Base64(Encoding.UTF8.GetBytes(text ?? throw new ArgumentNullException(nameof(text)))),
            interactions, options, ct);

    /// <summary>
    /// QR / Web2App / App2App sign: тодорхой иргэн (РД / civil_id / ETSI). Web2App/App2App-д <see cref="SignOptions.CallbackUrl"/>
    /// заавал. Холбоосыг <see cref="DeviceLinkSession.BuildLink"/>-ээр угсарна.
    /// </summary>
    public Task<DeviceLinkSession> DeviceLinkByEtsiAsync(string id, string digestB64, IEnumerable<Interaction>? interactions,
        SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = BuildBody(digestB64, interactions, options, SignatureAlgorithms.RsassaPss);
        return DeviceLinkAsync(RpRoutes.SignDeviceLinkEtsi.Expand(id), body, sc, ct);
    }

    /// <summary>QR / Web2App / App2App sign, баримтын дугаараар (тодорхой төхөөрөмж).</summary>
    public Task<DeviceLinkSession> DeviceLinkByDocumentAsync(string documentNumber, string digestB64,
        IEnumerable<Interaction>? interactions, SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = BuildBody(digestB64, interactions, options, SignatureAlgorithms.RsassaPss);
        return DeviceLinkAsync(RpRoutes.SignDeviceLinkDocument.Expand(documentNumber), body, sc, ct);
    }

    /// <summary>
    /// Certificate-choice-оор сонгосон ЯГ ТЭР төхөөрөмж рүү push sign. <see cref="SignerRef.CertChoiceSessionId"/> байвал
    /// <c>/signature/notification/linked/{documentNumber}</c> (<c>linkedSessionID</c>), эс бөгөөс
    /// <c>/signature/notification/document/{documentNumber}</c>. Анхдагч sha256WithRSAEncryption + SHA-256 (digest = 32
    /// байт DTBS); digest-ийн урт буруу бол хүсэлт явахгүй.
    /// </summary>
    /// <exception cref="ArgumentException">DocumentNumber хоосон, digest стандарт base64 биш эсвэл урт буруу.</exception>
    public Task<NotificationSession> DigestForSignerAsync(SignerRef signer, string digestB64, IEnumerable<Interaction>? interactions,
        SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = SignerBody(signer, digestB64, interactions, options);
        var linked = (signer.CertChoiceSessionId ?? "").Trim();
        if (linked.Length > 0)
        {
            body.LinkedSessionId = linked;
            return NotificationAsync(RpRoutes.SignNotificationLinked.Expand(signer.DocumentNumber), body, sc, ct);
        }
        return NotificationAsync(RpRoutes.SignNotificationDocument.Expand(signer.DocumentNumber), body, sc, ct);
    }

    /// <summary><see cref="DigestForSignerAsync"/>-ийн QR / Web2App / App2App хувилбар: <c>/signature/device-link/document/{documentNumber}</c>.</summary>
    /// <exception cref="ArgumentException">DocumentNumber хоосон, digest стандарт base64 биш эсвэл урт буруу.</exception>
    public Task<DeviceLinkSession> DeviceLinkForSignerAsync(SignerRef signer, string digestB64, IEnumerable<Interaction>? interactions,
        SignOptions? options = null, CancellationToken ct = default)
    {
        var (body, sc) = SignerBody(signer, digestB64, interactions, options);
        return DeviceLinkAsync(RpRoutes.SignDeviceLinkDocument.Expand(signer.DocumentNumber), body, sc, ct);
    }

    /// <summary>
    /// Push: иргэний (РД / civil_id / ETSI) утас руу гэрчилгээ сонгуулах хүсэлт (CERT эрх). Үр дүнг
    /// <see cref="SessionService.WaitForResultAsync"/> → validator-ын ValidateCertificateChoice.
    /// </summary>
    public async Task<NotificationSession> CertificateChoiceByEtsiAsync(string id, CertChoiceOptions? options = null,
        CancellationToken ct = default)
    {
        var path = RpRoutes.CertChoiceEtsi.Expand(id);
        var sent = _c.Clock.GetUtcNow();
        var r = await Wire.StartAsync(_c, path, CertChoiceBody(options), ct).ConfigureAwait(false);
        return new NotificationSession { SessionId = r.SessionId ?? "", Vc = r.Vc ?? "", ExpiresAt = r.ExpiresAtOr(sent, _c.SignSessionTtl) };
    }

    /// <summary>
    /// Device link: иргэн хэн болохыг урьдчилж мэдэхгүй үед гэрчилгээ сонгуулах (QR; <see cref="CertChoiceOptions.CallbackUrl"/>-тай
    /// бол Web2App/App2App ч). CERT эрх.
    /// </summary>
    public async Task<DeviceLinkSession> CertificateChoiceDeviceLinkAsync(CertChoiceOptions? options = null, CancellationToken ct = default)
    {
        var path = RpRoutes.CertChoiceDeviceLink.Expand();
        var body = CertChoiceBody(options);
        body.InitialCallbackUrl = Wire.NullIfEmpty((options?.CallbackUrl ?? "").Trim());
        var sent = _c.Clock.GetUtcNow();
        var r = await Wire.StartAsync(_c, path, body, ct).ConfigureAwait(false);
        return new DeviceLinkSession
        {
            SessionId = r.SessionId ?? "",
            SessionToken = r.SessionToken ?? "",
            SessionSecret = r.SessionSecret ?? "",
            DeviceLinkBase = r.DeviceLinkBase ?? "",
            Vc = r.Vc ?? "",
            ReceivedAt = _c.Clock.GetUtcNow(),
            SessionType = DeviceLinkSessionTypes.Cert,
            RelyingPartyName = body.RelyingPartyName,
            CallbackUrl = body.InitialCallbackUrl,
            ExpiresAt = r.ExpiresAtOr(sent, _c.SignSessionTtl),
        };
    }

    /// <summary>v3 nested body + RP-д хадгалах SignContext (ижил утгуудаас — байт зөрөхгүй). Go sign.go <c>body</c>.</summary>
    internal (SignRequest Body, SignContext Sign) BuildBody(string digestB64, IEnumerable<Interaction>? interactions, SignOptions? o,
        string defaultAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(digestB64);
        o ??= new SignOptions();
        var ib64 = EidCrypto.InteractionsToBase64(interactions);
        var sc = new SignContext
        {
            Digest = digestB64,
            HashAlgorithm = Wire.OrDefault(o.HashAlgorithm, HashAlgorithms.Sha256),
            SignatureAlgorithm = Wire.OrDefault(o.SignatureAlgorithm, defaultAlgorithm),
            RelyingPartyName = _c.RpName,
            Interactions = ib64,
            InitialCallbackUrl = (o.CallbackUrl ?? "").Trim(),
        };
        var body = new SignRequest
        {
            RelyingPartyUuid = _c.Options.Credentials.RpUuid,
            RelyingPartyName = sc.RelyingPartyName,
            CertificateLevel = Wire.OrDefault(o.CertificateLevel, _c.DefaultCertificateLevel),
            SignatureProtocolParameters = new SignProtocolParams
            {
                Digest = digestB64,
                SignatureAlgorithm = sc.SignatureAlgorithm,
                SignatureAlgorithmParameters = new HashParam { HashAlgorithm = sc.HashAlgorithm },
            },
            Interactions = ib64,
            InitialCallbackUrl = Wire.NullIfEmpty(sc.InitialCallbackUrl),
            OnBehalfOf = Wire.NullIfEmpty((o.OnBehalfOf ?? "").Trim()),
            FileName = Wire.NullIfEmpty((o.FileName ?? "").Trim()),
        };
        return (body, sc);
    }

    /// <summary>
    /// Signer-ийн гэрчилгээнд зориулсан body: PAdES-ийн анхдагч (sha256WithRSAEncryption, SHA-256), digest-ийн урт hash-тай
    /// таарахыг session эхлүүлэхээс ӨМНӨ шалгана (Go <c>signerBody</c>).
    /// </summary>
    private (SignRequest Body, SignContext Sign) SignerBody(SignerRef? signer, string digestB64, IEnumerable<Interaction>? interactions,
        SignOptions? o)
    {
        if (signer is null || string.IsNullOrWhiteSpace(signer.DocumentNumber))
        {
            throw new ArgumentException("eid: Signer.DocumentNumber хоосон — ValidateCertificateChoice-ийн үр дүнг өг", nameof(signer));
        }
        var (body, sc) = BuildBody(digestB64, interactions, o, SignatureAlgorithms.Sha256WithRsa);
        var size = sc.HashAlgorithm switch
        {
            HashAlgorithms.Sha256 => 32,
            HashAlgorithms.Sha384 => 48,
            HashAlgorithms.Sha512 => 64,
            _ => throw new ArgumentException("eid: дэмжигдээгүй hashAlgorithm: " + sc.HashAlgorithm, nameof(o)),
        };
        if (!B64.TryDecodeStd(digestB64, out var d) || d.Length != size)
        {
            throw new ArgumentException(
                "eid: digest нь стандарт base64, " + sc.HashAlgorithm + "-ийн урт (" + size + " байт) байх ёстой", nameof(digestB64));
        }
        return (body, sc);
    }

    private CertChoiceRequest CertChoiceBody(CertChoiceOptions? o) => new()
    {
        RelyingPartyUuid = _c.Options.Credentials.RpUuid,
        RelyingPartyName = _c.RpName,
        CertificateLevel = Wire.NullIfEmpty(Wire.OrDefault(o?.CertificateLevel, _c.DefaultCertificateLevel)),
    };

    private async Task<NotificationSession> NotificationAsync(string path, SignRequest body, SignContext sc, CancellationToken ct)
    {
        var sent = _c.Clock.GetUtcNow();
        var r = await Wire.StartAsync(_c, path, body, ct).ConfigureAwait(false);
        // Sign урсгалд rpChallenge байхгүй — гарын үсэг digest-ийн эсрэг баталгаажна.
        return new NotificationSession { SessionId = r.SessionId ?? "", Vc = r.Vc ?? "", Sign = sc, ExpiresAt = r.ExpiresAtOr(sent, _c.SignSessionTtl) };
    }

    private async Task<DeviceLinkSession> DeviceLinkAsync(string path, SignRequest body, SignContext sc, CancellationToken ct)
    {
        var sent = _c.Clock.GetUtcNow();
        var r = await Wire.StartAsync(_c, path, body, ct).ConfigureAwait(false);
        return new DeviceLinkSession
        {
            SessionId = r.SessionId ?? "",
            SessionToken = r.SessionToken ?? "",
            SessionSecret = r.SessionSecret ?? "",
            DeviceLinkBase = r.DeviceLinkBase ?? "",
            Vc = r.Vc ?? "",
            ReceivedAt = _c.Clock.GetUtcNow(),
            SessionType = DeviceLinkSessionTypes.Sign,
            Sign = sc,
            ExpiresAt = r.ExpiresAtOr(sent, _c.SignSessionTtl),
        };
    }
}

/// <summary>RAW_DIGEST_SIGNATURE <c>signatureProtocolParameters</c> (Go <c>signProtocolParams</c>).</summary>
internal sealed class SignProtocolParams
{
    [JsonPropertyName("digest")]
    public string Digest { get; init; } = "";

    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; init; } = "";

    [JsonPropertyName("signatureAlgorithmParameters")]
    public HashParam SignatureAlgorithmParameters { get; init; } = new();
}

/// <summary>Sign start-ын бие (Go <c>signRequest</c>; талбарын дараалал ижил, null = omitempty).</summary>
internal sealed class SignRequest
{
    [JsonPropertyName("relyingPartyUUID")]
    public string RelyingPartyUuid { get; init; } = "";

    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";

    [JsonPropertyName("signatureProtocol")]
    public string SignatureProtocol { get; init; } = "RAW_DIGEST_SIGNATURE";

    [JsonPropertyName("signatureProtocolParameters")]
    public SignProtocolParams SignatureProtocolParameters { get; init; } = new();

    [JsonPropertyName("interactions")]
    public string Interactions { get; init; } = "";

    [JsonPropertyName("initialCallbackUrl")]
    public string? InitialCallbackUrl { get; init; }

    [JsonPropertyName("onBehalfOf")]
    public string? OnBehalfOf { get; init; }

    [JsonPropertyName("fileName")]
    public string? FileName { get; init; }

    /// <summary>Зөвхөн /signature/notification/linked: өмнөх certificate-choice session.</summary>
    [JsonPropertyName("linkedSessionID")]
    public string? LinkedSessionId { get; set; }
}

/// <summary>
/// CA <c>dto.CertificateChoiceRequest</c> (үл мэдэгдэх талбарыг CA 400-аар татгалздаг — interactions БАЙХГҮЙ;
/// initialCallbackUrl зөвхөн device-link).
/// </summary>
internal sealed class CertChoiceRequest
{
    [JsonPropertyName("relyingPartyUUID")]
    public string RelyingPartyUuid { get; init; } = "";

    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    [JsonPropertyName("certificateLevel")]
    public string? CertificateLevel { get; init; }

    [JsonPropertyName("initialCallbackUrl")]
    public string? InitialCallbackUrl { get; set; }
}
