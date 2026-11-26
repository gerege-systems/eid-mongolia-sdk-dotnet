using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Байгууллагын цахим тамга (e-Seal; Go <c>SealService</c>, TS <c>SealApi</c>): eID-ийн серверт хадгалагдах байгууллагын
/// түлхүүрээр digest тамгална. Интерактив биш — хариу шууд (session-гүй). RP-д тухайн байгууллагын <c>SEAL:&lt;orgEtsi&gt;</c>
/// эрх хэрэгтэй (үгүй бол <see cref="EidForbiddenException"/> 403). 409 бүр тогтвортой code-той
/// (<see cref="SealErrorCodes.All"/>; төрөлжсөн <see cref="EidSealNotIssuedException"/> г.м.). Хэт олон хүсэлтэд 429 —
/// <see cref="EidException.Retryable"/> / <see cref="EidException.RetryAfter"/>. Оператор олголт/тамгалалтыг унтраасан бол
/// 503 <see cref="EidSealServiceDisabledException"/> (<see cref="EidApiException.Service"/> = <see cref="SealServices"/>) —
/// давтахгүй. PDF тамгалах бол <c>GeregeSystems.EidMongolia.Pades</c>-ийн <c>EidPades.SealAsync</c>.
/// <para>
/// Тамганы гэрчилгээ олгох: <see cref="RequestCertificateAsync"/> → 202 PENDING; байгууллагын ADMIN eID аппаараа PIN2-оор
/// батална; <see cref="CertificateRequestAsync"/> / <see cref="WaitForCertificateAsync"/>. Тамганы эрх (RP-ийн санаачилсан,
/// CA V156): <see cref="RequestGrantAsync"/> → <see cref="GrantStatusAsync"/> / <see cref="WaitForGrantAsync"/>.
/// </para>
/// </summary>
public sealed class SealService
{
    /// <summary>Хүлээлтийн анхдагч дээд хугацаа (CA-ийн батлах цонх = sign session TTL + 2 мин-ээс урт).</summary>
    public static readonly TimeSpan DefaultWaitTimeout = TimeSpan.FromMinutes(15);

    /// <summary>Poll хоорондын анхдагч зай (CA зөвлөмж 2–5 с).</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(3);

    private readonly EidClient _c;

    internal SealService(EidClient c) => _c = c;

    /// <summary>
    /// <c>GET /seal/certificate/{orgEtsi}</c>: байгууллагын одоогийн тамганы гэрчилгээ (PAdES-ийн SignerCert). Идэвхтэй
    /// гэрчилгээ алга бол 409: <see cref="EidSealNotIssuedException"/>, <see cref="EidSealCertRevokedException"/>,
    /// <see cref="EidSealCertExpiredException"/>, <see cref="EidSealCertNotYetValidException"/>.
    /// </summary>
    /// <exception cref="EidValidationException">Хариунд гэрчилгээ алга (<see cref="ValidationReasons.ResponseMalformed"/>).</exception>
    public async Task<SealCertificate> CertificateAsync(string orgEtsi, CancellationToken ct = default)
    {
        var c = await _c.Http.GetJsonAsync<SealCertificate>(RpRoutes.SealCertificate.Expand(orgEtsi), null, ct).ConfigureAwait(false);
        if (c is null || c.Certificate is not { Length: > 0 })
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "seal certificate хоосон");
        }
        return c;
    }

    /// <summary>
    /// <c>POST /seal/certificate/{orgEtsi}</c>: тамганы гэрчилгээний ХҮСЭЛТ (202, PENDING). PENDING хүсэлт байвал CA түүнийг
    /// буцаана (шинэ push үгүй). Алдаа: 409 <see cref="EidSealApproverUnavailableException"/>, 409
    /// <see cref="EidOrgNotActiveException"/>, 403, 404, 429 (байгууллагад цагт 5), 503
    /// <see cref="EidSealServiceDisabledException"/> (Service = issuance).
    /// </summary>
    public async Task<SealCertificateRequest> RequestCertificateAsync(string orgEtsi, CancellationToken ct = default)
    {
        var r = await _c.Http.PostJsonAsync<SealCertificateRequest>(RpRoutes.SealCertificateRequest.Expand(orgEtsi), new Dictionary<string, string>(), null, ct)
            .ConfigureAwait(false);
        return CheckRequest(r);
    }

    /// <summary>
    /// <c>GET /seal/certificate/{orgEtsi}/requests/{requestId}</c>: хүсэлтийн төлөв; ISSUED үед
    /// <see cref="SealCertificateRequest.Certificate"/> бөглөгдөнө. Олдоогүй → 404 <see cref="EidSealRequestNotFoundException"/>.
    /// </summary>
    public async Task<SealCertificateRequest> CertificateRequestAsync(string orgEtsi, string requestId, CancellationToken ct = default)
    {
        var r = await _c.Http.GetJsonAsync<SealCertificateRequest>(RpRoutes.SealCertificateRequestStatus.Expand(orgEtsi, requestId), null, ct)
            .ConfigureAwait(false);
        return CheckRequest(r);
    }

    private static SealCertificateRequest CheckRequest(SealCertificateRequest? r)
    {
        if (r is null || string.IsNullOrEmpty(r.RequestId) || string.IsNullOrEmpty(r.Status))
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "seal хүсэлтийн хариунд requestId/status алга");
        }
        if (r.Status == SealRequestStatuses.Issued && r.Certificate?.Certificate is not { Length: > 0 })
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "ISSUED seal хүсэлтэд certificate алга");
        }
        return r;
    }

    /// <summary>
    /// Хүсэлт ISSUED болтол <see cref="SealWaitOptions.Interval"/> тутамд асууж олгогдсон гэрчилгээг буцаана (Go
    /// <c>WaitForCertificate</c>). REJECTED / EXPIRED / FAILED → <see cref="EidSealRequestException"/>; Timeout дуусвал
    /// Outcome <see cref="SealRequestStatuses.Timeout"/> (хүсэлт PENDING хэвээр). Түр алдаа (<see cref="EidException.Retryable"/>)
    /// — RetryAfter-ийг хүлээгээд үргэлжилнэ; бусад алдаа шууд (503 SEAL_SERVICE_DISABLED давтахгүй).
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> цуцлагдсан.</exception>
    public async Task<SealCertificate> WaitForCertificateAsync(string orgEtsi, string requestId, SealWaitOptions? options = null, CancellationToken ct = default)
    {
        var (interval, timeout) = WaitParams(options);
        var sw = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var wait = interval;
            try
            {
                var r = await CertificateRequestAsync(orgEtsi, requestId, ct).ConfigureAwait(false);
                switch (r.Status)
                {
                    case SealRequestStatuses.Issued:
                        return r.Certificate!;
                    case SealRequestStatuses.Rejected or SealRequestStatuses.Expired or SealRequestStatuses.Failed:
                        throw new EidSealRequestException(r.Status, r.RequestId, r.Failure);
                }
            }
            catch (EidApiException e) when (e.Retryable)
            {
                wait = e.RetryAfter is { } ra && ra > interval ? ra : interval;
            }
            var left = timeout - sw.Elapsed;
            if (left <= TimeSpan.Zero)
            {
                throw new EidSealRequestException(SealRequestStatuses.Timeout, requestId, null);
            }
            await Task.Delay(wait < left ? wait : left, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>POST /seal/{orgEtsi}</c>: digest-ийг байгууллагын тамгаар тамгална (Go <c>Seal</c>). Хариуны гарын үсгийг хариуны
    /// гэрчилгээгээр digest дээр шалгаж, e-Seal гэрчилгээ (<see cref="IsSealCertificate"/>) мөн эсэхийг тулгана. Гинж/цуцлалтыг
    /// энэ шалгахгүй (PAdES <c>EidPades.SealAsync</c> нь OCSP/CRL + self-validation хийнэ). Алдаа: 403 (SEAL эрхгүй), 429,
    /// 503 <see cref="EidSealServiceDisabledException"/> (Service = sealing), 409 <see cref="SealErrorCodes.All"/>.
    /// </summary>
    /// <param name="orgEtsi">NTRMN-…</param>
    /// <param name="digest">Hash-ийн урттай digest.</param>
    /// <param name="hashAlgorithm"><see cref="HashAlgorithms"/>; null / "" = SHA-256.</param>
    /// <param name="options">
    /// .NET-ийн нэмэлт (CA V158 <c>dto.SealRequest</c>; Go/TS одоогоор илгээдэггүй): QR-тэй дардасны <c>docId</c> /
    /// <c>revIndex</c> — хоёулаа эсвэл аль нь ч үгүй.
    /// </param>
    /// <param name="ct">Цуцлалт.</param>
    /// <exception cref="ArgumentException">hash дэмжигдэхгүй, digest-ийн урт буруу, эсвэл docId/revIndex-ийн зөвхөн нэг нь (хүсэлт явахгүй).</exception>
    /// <exception cref="EidValidationException">Хариу буруу, гэрчилгээ e-Seal биш, эсвэл гарын үсэг таарсангүй.</exception>
    public async Task<SealResult> SealAsync(string orgEtsi, byte[] digest, string? hashAlgorithm = null, SealDigestOptions? options = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(digest);
        var hash = string.IsNullOrEmpty(hashAlgorithm) ? HashAlgorithms.Sha256 : hashAlgorithm;
        var size = EidCrypto.HashSize(hash);
        if (size == 0)
        {
            throw new ArgumentException("eid: seal: дэмжигдээгүй hashAlgorithm: " + hash, nameof(hashAlgorithm));
        }
        if (digest.Length != size)
        {
            throw new ArgumentException("eid: seal: digest нь " + hash + "-ийн урт (" + size + " байт) байх ёстой", nameof(digest));
        }
        var docId = options?.DocId is { Length: > 0 } d ? d : null;
        var revIndex = options?.RevIndex is { } ri && ri != 0 ? ri : (int?)null;
        if ((docId is null) != (revIndex is null) || revIndex is < 1)
        {
            throw new ArgumentException("eid: seal: DocId ба RevIndex (≥ 1) хоёулаа эсвэл аль нь ч үгүй", nameof(options));
        }
        var body = new SealWireRequest
        {
            Digest = Convert.ToBase64String(digest),
            HashType = hash.Replace("-", "", StringComparison.Ordinal),
            DocId = docId,
            RevIndex = revIndex,
        };
        var path = RpRoutes.Seal.Expand(orgEtsi);
        var raw = await _c.Http.PostRawAsync(path, body, null, ct).ConfigureAwait(false);
        var r = EidHttp.Decode<SealWireResponse>(raw, "POST", path);
        if (r?.Signature?.Value is not { Length: > 0 } sigB64 || r!.Cert?.Value is not { Length: > 0 } certB64)
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "seal хариунд signature/cert алга");
        }
        if (!B64.TryDecodeStd(sigB64, out var sig))
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "seal signature base64 биш");
        }
        if (!B64.TryDecodeStd(certB64, out var certDer))
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "seal cert base64 биш");
        }
        ParsedCert cert;
        try
        {
            cert = ParsedCert.Parse(certDer);
        }
        catch (FormatException e)
        {
            throw new EidValidationException(ValidationReasons.CertMalformed, "seal cert задарсангүй", e);
        }
        if (!IsSeal(cert))
        {
            throw new EidValidationException(ValidationReasons.SealNotSealCertificate, "хариуны гэрчилгээ e-Seal биш (KeyUsage)");
        }
        if (!VerifyEcdsaDer(cert, digest, sig))
        {
            throw new EidValidationException(ValidationReasons.SealSignature, "seal гарын үсэг digest-тэй таарсангүй");
        }
        return new SealResult
        {
            OrgEtsi = r!.OrgEtsi ?? "",
            Signature = sig,
            SignatureAlgorithm = r.Signature!.SignatureAlgorithm ?? "",
            Certificate = certDer,
            CertificateLevel = r.Cert!.CertificateLevel ?? "",
            SealedAt = r.SealedAt,
            Raw = RawJson.Element(raw),
        };
    }

    /// <summary>Go <c>ecdsa.VerifyASN1</c>: EC түлхүүр, ASN.1 DER гарын үсэг.</summary>
    private static bool VerifyEcdsaDer(ParsedCert cert, byte[] digest, byte[] sig)
    {
        if (cert.KeyKind != KeyKind.Ec || !ParsedCert.IsDerEcdsaSignature(sig))
        {
            return false;
        }
        try
        {
            using var ec = cert.CreateEcdsa();
            return ec.VerifyHash(digest, sig, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// e-Seal профайл (Go <c>IsSealCertificate</c>): CA биш, KeyUsage-д nonRepudiation (contentCommitment) байгаа,
    /// digitalSignature байхгүй, EKU-ийн зорилго байхгүй. Задрахгүй / null бол false.
    /// </summary>
    public static bool IsSealCertificate(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return false;
        }
        try
        {
            return IsSeal(ParsedCert.Parse(certificate.RawData));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool IsSeal(ParsedCert c) =>
        !c.IsCa && (c.KeyUsage & ParsedCert.KuContentCommitment) != 0 && (c.KeyUsage & ParsedCert.KuDigitalSignature) == 0 && c.Eku.Count == 0;

    // ── тамганы эрхийн хүсэлт (CA V156; Go seal_grant.go) ──

    /// <summary>
    /// <c>POST /seal/grants {orgEtsi, sessionId}</c>: байгууллагын тамга ашиглах эрхийн ХҮСЭЛТ (202, PENDING).
    /// <paramref name="sessionId"/> — энэ RP-ийн эхлүүлж сүүлийн 5 минутад OK-оор дууссан НЭВТРЭЛТИЙН session; тэр хүн
    /// байгууллагын REGISTRY CEO байх ёстой. Ижил session-оор дахин дуудвал ижил PENDING. Алдаа: <see cref="SealGrantErrorCodes.All"/>
    /// (403 <see cref="EidForbiddenException"/>: RP_NOT_REGISTERED, NOT_ORG_CEO; бусад нь <see cref="EidApiException"/>), 429.
    /// </summary>
    /// <exception cref="ArgumentException">orgEtsi эсвэл sessionId хоосон (хүсэлт явахгүй).</exception>
    public async Task<SealGrant> RequestGrantAsync(string orgEtsi, string sessionId, CancellationToken ct = default)
    {
        var org = (orgEtsi ?? "").Trim();
        var sid = (sessionId ?? "").Trim();
        if (org.Length == 0 || sid.Length == 0)
        {
            throw new ArgumentException("eid: RequestGrant: orgEtsi ба sessionId шаардлагатай");
        }
        var g = await _c.Http.PostJsonAsync<SealGrant>(RpRoutes.SealGrants.Expand(), new SealGrantWireRequest { OrgEtsi = org, SessionId = sid }, null, ct)
            .ConfigureAwait(false);
        return CheckGrant(g);
    }

    /// <summary><c>GET /seal/grants/{grantId}</c>: хүсэлтийн төлөв. Олдоогүй → 404 <see cref="EidSealGrantNotFoundException"/>.</summary>
    /// <exception cref="ArgumentException">grantId хоосон.</exception>
    public async Task<SealGrant> GrantStatusAsync(string grantId, CancellationToken ct = default)
    {
        var id = (grantId ?? "").Trim();
        if (id.Length == 0)
        {
            throw new ArgumentException("eid: GrantStatus: grantId шаардлагатай", nameof(grantId));
        }
        var g = await _c.Http.GetJsonAsync<SealGrant>(RpRoutes.SealGrantStatus.Expand(id), null, ct).ConfigureAwait(false);
        return CheckGrant(g);
    }

    private static SealGrant CheckGrant(SealGrant? g)
    {
        if (g is null || string.IsNullOrEmpty(g.GrantId) || string.IsNullOrEmpty(g.Status))
        {
            throw new EidValidationException(ValidationReasons.ResponseMalformed, "тамганы эрхийн хариунд grantId/status алга");
        }
        return g;
    }

    /// <summary>
    /// Хүсэлт APPROVED болтол <see cref="GrantStatusAsync"/>-ийг асууж түүнийг буцаана (Go <c>WaitForGrant</c>). REJECTED /
    /// EXPIRED / FAILED / REVOKED → <see cref="EidSealGrantException"/>; Timeout дуусвал Outcome
    /// <see cref="SealGrantStatuses.Timeout"/>. Түр алдаа — RetryAfter-ийг хүлээгээд үргэлжилнэ; бусад алдаа шууд.
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> цуцлагдсан.</exception>
    public async Task<SealGrant> WaitForGrantAsync(string grantId, SealWaitOptions? options = null, CancellationToken ct = default)
    {
        var (interval, timeout) = WaitParams(options);
        var sw = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var wait = interval;
            try
            {
                var g = await GrantStatusAsync(grantId, ct).ConfigureAwait(false);
                switch (g.Status)
                {
                    case SealGrantStatuses.Approved:
                        return g;
                    case SealGrantStatuses.Rejected or SealGrantStatuses.Expired or SealGrantStatuses.Failed or SealGrantStatuses.Revoked:
                        throw new EidSealGrantException(g.Status, g.GrantId, g.Failure);
                }
            }
            catch (EidApiException e) when (e.Retryable)
            {
                wait = e.RetryAfter is { } ra && ra > interval ? ra : interval;
            }
            var left = timeout - sw.Elapsed;
            if (left <= TimeSpan.Zero)
            {
                throw new EidSealGrantException(SealGrantStatuses.Timeout, grantId, null);
            }
            await Task.Delay(wait < left ? wait : left, ct).ConfigureAwait(false);
        }
    }

    private static (TimeSpan Interval, TimeSpan Timeout) WaitParams(SealWaitOptions? o) =>
        (o?.Interval is { } i && i > TimeSpan.Zero ? i : DefaultPollInterval,
         o?.Timeout is { } t && t > TimeSpan.Zero ? t : DefaultWaitTimeout);
}

/// <summary><c>POST /seal/{orgEtsi}</c>-ийн бие (CA <c>dto.SealRequest</c>-ийн дэд олонлог; CA DisallowUnknownFields).</summary>
internal sealed record SealWireRequest
{
    [JsonPropertyName("digest")]
    public string Digest { get; init; } = "";

    [JsonPropertyName("hashType")]
    public string HashType { get; init; } = "";

    [JsonPropertyName("docId")]
    public string? DocId { get; init; }

    [JsonPropertyName("revIndex")]
    public int? RevIndex { get; init; }
}

/// <summary>CA <c>dto.SealResponse</c>.</summary>
internal sealed record SealWireResponse
{
    [JsonPropertyName("orgEtsi")]
    public string? OrgEtsi { get; init; }

    [JsonPropertyName("signature")]
    public SealWireSignature? Signature { get; init; }

    [JsonPropertyName("cert")]
    public SealWireCert? Cert { get; init; }

    [JsonPropertyName("sealedAt")]
    public DateTimeOffset SealedAt { get; init; }
}

internal sealed record SealWireSignature
{
    [JsonPropertyName("value")]
    public string? Value { get; init; }

    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; init; }
}

internal sealed record SealWireCert
{
    [JsonPropertyName("value")]
    public string? Value { get; init; }

    [JsonPropertyName("certificateLevel")]
    public string? CertificateLevel { get; init; }
}

/// <summary><c>POST /seal/grants</c>-ийн бие (CA handlers_seal_grant_rp.go; DisallowUnknownFields).</summary>
internal sealed record SealGrantWireRequest
{
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";

    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = "";
}

/// <summary><see cref="SealService.SealAsync"/>-ийн нэмэлт талбарууд (CA V158). Хоёулаа эсвэл аль нь ч үгүй.</summary>
public sealed record SealDigestOptions
{
    /// <summary>Баримтын ID (QR-тэй тамганы <c>/verify/&lt;docId&gt;/&lt;revIndex&gt;</c>).</summary>
    public string? DocId { get; init; }

    /// <summary>Гарын үсгийн байрлал (≥ 1).</summary>
    public int? RevIndex { get; init; }
}

/// <summary><c>GET /seal/certificate/{orgEtsi}</c>-ийн хариу (CA <c>dto.SealCertificateResponse</c>).</summary>
public sealed record SealCertificate
{
    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";

    /// <summary>DER (JSON-д base64).</summary>
    [JsonPropertyName("certificate")]
    public byte[] Certificate { get; init; } = Array.Empty<byte>();

    /// <summary>Serial.</summary>
    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; init; } = "";

    /// <summary>Subject DN.</summary>
    [JsonPropertyName("subjectDn")]
    public string SubjectDn { get; init; } = "";

    /// <summary>Issuer DN.</summary>
    [JsonPropertyName("issuerDn")]
    public string IssuerDn { get; init; } = "";

    /// <summary>Хүчинтэй эхлэх.</summary>
    [JsonPropertyName("notBefore")]
    public DateTimeOffset NotBefore { get; init; }

    /// <summary>Хүчинтэй дуусах.</summary>
    [JsonPropertyName("notAfter")]
    public DateTimeOffset NotAfter { get; init; }

    /// <summary>Гэрчилгээнээс өөрөөс нь (QcSSCD байвал QSCD, үгүй бол QUALIFIED).</summary>
    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";
}

/// <summary><c>POST /seal/{orgEtsi}</c>-ийн шалгасан үр дүн.</summary>
public sealed record SealResult
{
    /// <summary>NTRMN-…</summary>
    public string OrgEtsi { get; init; } = "";

    /// <summary>Digest дээрх ECDSA гарын үсэг (ASN.1 DER).</summary>
    public byte[] Signature { get; init; } = Array.Empty<byte>();

    /// <summary>ж: ecdsa-with-SHA256.</summary>
    public string SignatureAlgorithm { get; init; } = "";

    /// <summary>Тамгалсан гэрчилгээ (DER).</summary>
    public byte[] Certificate { get; init; } = Array.Empty<byte>();

    /// <summary>Гэрчилгээний түвшин.</summary>
    public string CertificateLevel { get; init; } = "";

    /// <summary>Тамгалсан цаг.</summary>
    public DateTimeOffset SealedAt { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    public JsonElement? Raw { get; init; }
}

/// <summary>Тамганы гэрчилгээний хүсэлтийн төлөв (<see cref="SealCertificateRequest.Status"/>).</summary>
public static class SealRequestStatuses
{
    /// <summary>PENDING.</summary>
    public const string Pending = "PENDING";
    /// <summary>APPROVED — батлагдсан, гэрчилгээ олгогдож байна.</summary>
    public const string Approved = "APPROVED";
    /// <summary>ISSUED — Certificate бөглөгдсөн.</summary>
    public const string Issued = "ISSUED";
    /// <summary>REJECTED.</summary>
    public const string Rejected = "REJECTED";
    /// <summary>EXPIRED.</summary>
    public const string Expired = "EXPIRED";
    /// <summary>FAILED (Failure: SEAL_ISSUANCE_FAILED | PUSH_FAILED | SEAL_SERVICE_DISABLED).</summary>
    public const string Failed = "FAILED";
    /// <summary><see cref="EidSealRequestException.Outcome"/>: хүлээлтийн хугацаа дууссан (серверийн төлөв биш).</summary>
    public const string Timeout = "TIMEOUT";
}

/// <summary>
/// <c>POST /seal/certificate/{orgEtsi}</c> (202) ба <c>GET …/requests/{requestId}</c>-ийн хариу (CA
/// <c>dto.SealCertificateRequestResponse</c>).
/// </summary>
public sealed record SealCertificateRequest
{
    /// <summary>Хүсэлтийн ID.</summary>
    [JsonPropertyName("requestId")]
    public string RequestId { get; init; } = "";

    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";

    /// <summary><see cref="SealRequestStatuses"/>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    /// <summary>Үүссэн цаг.</summary>
    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>Батлах хугацааны төгсгөл (дараа нь EXPIRED).</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Шийдвэрлэсэн цаг.</summary>
    [JsonPropertyName("decidedAt")]
    public DateTimeOffset? DecidedAt { get; init; }

    /// <summary>PIN2 push илгээсэн ADMIN-ийн тоо.</summary>
    [JsonPropertyName("approvers")]
    public int Approvers { get; init; }

    /// <summary>FAILED/EXPIRED үеийн машин код.</summary>
    [JsonPropertyName("failure")]
    public string? Failure { get; init; }

    /// <summary>ISSUED үед гэрчилгээ.</summary>
    [JsonPropertyName("certificate")]
    public SealCertificate? Certificate { get; init; }
}

/// <summary><see cref="EidApiException.Service"/>-ийн утгууд (503 SEAL_SERVICE_DISABLED).</summary>
public static class SealServices
{
    /// <summary>Тамганы гэрчилгээний олголт (<c>POST /seal/certificate/{orgEtsi}</c>).</summary>
    public const string Issuance = "issuance";
    /// <summary>Тамгалалт (<c>POST /seal/{orgEtsi}</c>).</summary>
    public const string Sealing = "sealing";
}

/// <summary>Тамганы замуудын тогтвортой CA кодууд (Go <c>SealErrorCodes</c>, TS <c>SEAL_ERROR_CODES</c>-тэй ижил дараалал).</summary>
public static class SealErrorCodes
{
    /// <summary>Бүх код. 429 RATE_LIMITED ба 403 энд орохгүй.</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        EidErrorCodes.OrgNotActive, EidErrorCodes.SealNotIssued, EidErrorCodes.SealCertRevoked, EidErrorCodes.SealKeyUnavailable,
        EidErrorCodes.SealCertExpired, EidErrorCodes.SealCertNotYetValid, EidErrorCodes.SealApproverUnavailable,
        EidErrorCodes.SealRequestNotFound, EidErrorCodes.SealServiceDisabled,
    };
}

/// <summary><see cref="SealService.WaitForCertificateAsync"/> / <see cref="SealService.WaitForGrantAsync"/>-ийн сонголт.</summary>
public sealed record SealWaitOptions
{
    /// <summary>Нийт хүлээх дээд хугацаа; null / ≤ 0 = <see cref="SealService.DefaultWaitTimeout"/>.</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>Poll хоорондын зай; null / ≤ 0 = <see cref="SealService.DefaultPollInterval"/>. Retry-After илүү бол түүнийг.</summary>
    public TimeSpan? Interval { get; init; }
}

/// <summary>
/// <see cref="SealService.WaitForCertificateAsync"/>: хүсэлт гэрчилгээгүй дууссан (Go <c>SealRequestError</c>). Outcome =
/// REJECTED / EXPIRED / FAILED (Failure-д код) → шинэ хүсэлт; <see cref="SealRequestStatuses.Timeout"/> — хүсэлт PENDING
/// хэвээр (ижил RequestId-аар дахин хүлээж болно).
/// </summary>
public sealed class EidSealRequestException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidSealRequestException(string outcome, string requestId, string? failure)
        : base("eid: тамганы гэрчилгээний хүсэлт " + outcome + (string.IsNullOrEmpty(failure) ? "" : " (" + failure + ")"))
    {
        Outcome = outcome;
        RequestId = requestId;
        Failure = string.IsNullOrEmpty(failure) ? null : failure;
    }

    /// <summary><see cref="SealRequestStatuses"/>.</summary>
    public string Outcome { get; }

    /// <summary>Хүсэлтийн ID.</summary>
    public string RequestId { get; }

    /// <summary>CA-ийн failure код; алга бол null.</summary>
    public string? Failure { get; }

    /// <summary>FAILED хүсэлтийн Failure = SEAL_SERVICE_DISABLED (Go <c>errors.Is(err, ErrSealServiceDisabled)</c>).</summary>
    public bool IsServiceDisabled => Failure == EidErrorCodes.SealServiceDisabled;

    /// <inheritdoc/>
    public override string? Code => Failure;
}

/// <summary>Тамганы эрхийн хүсэлтийн төлөв (<see cref="SealGrant.Status"/>).</summary>
public static class SealGrantStatuses
{
    /// <summary>PENDING.</summary>
    public const string Pending = "PENDING";
    /// <summary>APPROVED — эрх үүссэн.</summary>
    public const string Approved = "APPROVED";
    /// <summary>REJECTED.</summary>
    public const string Rejected = "REJECTED";
    /// <summary>EXPIRED.</summary>
    public const string Expired = "EXPIRED";
    /// <summary>FAILED (Failure-д код).</summary>
    public const string Failed = "FAILED";
    /// <summary>REVOKED — зөвшөөрсний дараа цуцлагдсан.</summary>
    public const string Revoked = "REVOKED";
    /// <summary><see cref="EidSealGrantException.Outcome"/>: хүлээлтийн хугацаа дууссан (серверийн төлөв биш).</summary>
    public const string Timeout = "TIMEOUT";
}

/// <summary><c>POST /seal/grants</c> (202) ба <c>GET /seal/grants/{grantId}</c>-ийн хариу (CA <c>dto.RPSealGrantStatus</c>).</summary>
public sealed record SealGrant
{
    /// <summary>Эрхийн ID.</summary>
    [JsonPropertyName("grantId")]
    public string GrantId { get; init; } = "";

    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";

    /// <summary><see cref="SealGrantStatuses"/>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    /// <summary>PENDING хүсэлтийг зөвшөөрөх хугацааны төгсгөл.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Захирал PIN2-оор зөвшөөрсөн цаг.</summary>
    [JsonPropertyName("approvedAt")]
    public DateTimeOffset? ApprovedAt { get; init; }

    /// <summary>Цуцалсан цаг.</summary>
    [JsonPropertyName("revokedAt")]
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>FAILED / EXPIRED / REVOKED-ийн машин код.</summary>
    [JsonPropertyName("failure")]
    public string? Failure { get; init; }
}

/// <summary>Тамганы эрхийн хүсэлтийн тогтвортой CA кодууд (Go <c>SealGrantErrorCodes</c>; 400 ба 429 орохгүй).</summary>
public static class SealGrantErrorCodes
{
    /// <summary>Бүх код (403-ууд <see cref="EidForbiddenException.Code"/>, бусад <see cref="EidApiException"/>).</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        EidErrorCodes.RpNotRegistered, EidErrorCodes.NotOrgCeo, EidErrorCodes.AuthSessionNotFound, EidErrorCodes.OrgNotFound,
        EidErrorCodes.AuthSessionWrongFlow, EidErrorCodes.AuthSessionNotCompleted, EidErrorCodes.AuthSessionTooOld,
        EidErrorCodes.AuthSessionAlreadyUsed, EidErrorCodes.OrgNotActive, EidErrorCodes.RpNotActive,
        EidErrorCodes.SealGrantAlreadyApproved, EidErrorCodes.RpPermissionsFull, EidErrorCodes.SealApproverUnavailable,
        EidErrorCodes.SealGrantNotFound,
    };
}

/// <summary>
/// <see cref="SealService.WaitForGrantAsync"/>: хүсэлт APPROVED-гүй дууссан (Go <c>SealGrantError</c>). Outcome = REJECTED /
/// EXPIRED / FAILED / REVOKED → шинэ нэвтрэлт + RequestGrant; <see cref="SealGrantStatuses.Timeout"/> — PENDING хэвээр.
/// </summary>
public sealed class EidSealGrantException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidSealGrantException(string outcome, string grantId, string? failure)
        : base("eid: тамганы эрхийн хүсэлт " + outcome + (string.IsNullOrEmpty(failure) ? "" : " (" + failure + ")"))
    {
        Outcome = outcome;
        GrantId = grantId;
        Failure = string.IsNullOrEmpty(failure) ? null : failure;
    }

    /// <summary><see cref="SealGrantStatuses"/>.</summary>
    public string Outcome { get; }

    /// <summary>Эрхийн хүсэлтийн ID.</summary>
    public string GrantId { get; }

    /// <summary>CA-ийн failure код; алга бол null.</summary>
    public string? Failure { get; }

    /// <inheritdoc/>
    public override string? Code => Failure;
}
