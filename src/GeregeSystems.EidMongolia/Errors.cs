using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;

namespace GeregeSystems.EidMongolia;

// SDK-ийн төрөлжсөн алдаанууд (TS errors.ts, Go errors.go-той нэг мөр). RP backend эдгээрийг төрлөөр нь (эсвэл
// Code-оор) ялган барьж хэрэглэгчид зөв мессеж/үйлдэл сонгоно: EidAuthenticationException → тохиргооны алдаа,
// EidSessionFailedException{USER_REFUSED} → дахин оролд, EidValidationException → хариунд ИТГЭХГҮЙ.

/// <summary>
/// SDK-ийн бүх алдааны суурь. <see cref="Code"/> — серверийн тогтвортой код (байхгүй бол null), <see cref="Status"/> —
/// HTTP статус (HTTP-ийн бус алдаанд null), <see cref="RetryAfter"/> — серверийн Retry-After, <see cref="Retryable"/> —
/// ижил хүсэлтийг <see cref="RetryAfter"/>-ийн дараа давтаж болох эсэх. SDK өөрөө автоматаар давтахгүй.
/// </summary>
public class EidException : Exception
{
    /// <summary>Шинэ алдаа.</summary>
    public EidException(string message, Exception? innerException = null) : base(message, innerException)
    {
    }

    /// <summary>Серверийн тогтвортой алдааны код (<c>{"code"}</c>); байхгүй бол null.</summary>
    public virtual string? Code => null;

    /// <summary>HTTP статус; HTTP хариутай холбоогүй алдаанд null.</summary>
    public virtual int? Status => null;

    /// <summary>Хариуны Retry-After (секунд эсвэл HTTP-огноо задалсан); байхгүй/буруу бол null.</summary>
    public virtual TimeSpan? RetryAfter => null;

    /// <summary>CA-ийн түр алдаа: <see cref="RetryAfter"/>-ийн дараа ижил хүсэлтийг давтаж болно.</summary>
    public virtual bool Retryable => false;
}

/// <summary>
/// HTTP 401 — API secret буруу эсвэл байхгүй (тохиргооны алдаа). CA-ийн өөрийн 401 нь JSON <c>{"error"[,"code"]}</c> —
/// <see cref="ServerMessage"/> (ба байвал <see cref="Code"/>) бөглөгдөнө; JSON биш (proxy / nginx) бол хоёул null.
/// </summary>
public sealed class EidAuthenticationException : EidException
{
    private readonly string? _code;

    internal EidAuthenticationException(string? code, string? serverMessage, string body, HttpResponseHeaders? headers)
        : base("eid: API secret буруу эсвэл байхгүй (401" + (code is null ? "" : " " + code) + ")")
    {
        _code = code;
        ServerMessage = serverMessage;
        Body = body;
        Headers = headers;
    }

    /// <inheritdoc/>
    public override string? Code => _code;

    /// <inheritdoc/>
    public override int? Status => 401;

    /// <summary>Серверийн <c>{"error"}</c> текст (логт); JSON биш бол null.</summary>
    public string? ServerMessage { get; }

    /// <summary>Хариуны бие (64 KiB хүртэл таслагдсан).</summary>
    public string Body { get; }

    /// <summary>Хариуны header-ууд.</summary>
    public HttpResponseHeaders? Headers { get; }
}

/// <summary>
/// HTTP 403 — IP allowlist/mTLS зөвшөөрөөгүй, RP-д эрх алга, эсвэл <c>onBehalfOf</c>-ийн төлөөлөл татгалзсан. Сервер
/// <c>{"error","code"}</c> буцаасан бол <see cref="Code"/> (ж: <see cref="EidErrorCodes.RepresentationDenied"/>).
/// </summary>
public sealed class EidForbiddenException : EidException
{
    private readonly string? _code;
    private readonly TimeSpan? _retryAfter;

    internal EidForbiddenException(string? code, string? serverMessage, TimeSpan? retryAfter, HttpResponseHeaders? headers)
        : base(serverMessage is null
            ? "eid: IP allowlist эсвэл mTLS зөвшөөрөөгүй (403)"
            : "eid: RP-API 403" + (code is null ? "" : " " + code) + ": " + serverMessage)
    {
        _code = code;
        _retryAfter = retryAfter;
        ServerMessage = serverMessage;
        Headers = headers;
    }

    /// <inheritdoc/>
    public override string? Code => _code;

    /// <inheritdoc/>
    public override int? Status => 403;

    /// <inheritdoc/>
    public override TimeSpan? RetryAfter => _retryAfter;

    /// <summary>Серверийн <c>{"error"}</c> текст (логт; хэрэглэгчид шууд харуулахгүй); байхгүй бол null.</summary>
    public string? ServerMessage { get; }

    /// <summary>Хариуны header-ууд.</summary>
    public HttpResponseHeaders? Headers { get; }
}

/// <summary>
/// RP-API-аас ирсэн бусад HTTP алдаа (3xx/4xx/5xx, 401/403-аас бусад). Танигдсан <see cref="Code"/> бүр өөрийн дэд
/// ангитай (ж: <see cref="EidNoSigningCertificateException"/>); танигдаагүй бол энэ анги.
/// </summary>
public class EidApiException : EidException
{
    private readonly int _status;
    private readonly string? _code;
    private readonly TimeSpan? _retryAfter;

    /// <summary>Шинэ алдаа (SDK-ийн HTTP давхарга үүсгэнэ).</summary>
    public EidApiException(int status, string body, string? code, string? service, TimeSpan? retryAfter, HttpResponseHeaders? headers)
        : base("eid: RP-API " + status + ": " + body)
    {
        _status = status;
        _code = code;
        _retryAfter = retryAfter;
        Body = body;
        Service = service;
        Headers = headers;
    }

    /// <inheritdoc/>
    public override string? Code => _code;

    /// <inheritdoc/>
    public override int? Status => _status;

    /// <inheritdoc/>
    public override TimeSpan? RetryAfter => _retryAfter;

    /// <summary>Хариуны бие (64 KiB хүртэл таслагдсан).</summary>
    public string Body { get; }

    /// <summary>
    /// Серверийн <c>{"service"}</c> (мөр): <see cref="EidErrorCodes.SealServiceDisabled"/>-д унтраалттай үйлчилгээ
    /// (<c>issuance</c> | <c>sealing</c>); бусад алдаанд null.
    /// </summary>
    public string? Service { get; }

    /// <summary>Хариуны header-ууд.</summary>
    public HttpResponseHeaders? Headers { get; }

    /// <summary>
    /// <see cref="EidErrorCodes.RetryableCodes"/>-ийн нэг, эсвэл 429/503 + Retry-After. 503
    /// <see cref="EidErrorCodes.SealServiceDisabled"/> — хэзээ ч үгүй.
    /// </summary>
    public override bool Retryable
    {
        get
        {
            if (_code == EidErrorCodes.SealServiceDisabled)
            {
                return false;
            }
            if (_code is not null && EidErrorCodes.RetryableCodes.Contains(_code))
            {
                return true;
            }
            return (_status == 429 || _status == 503) && _retryAfter is { } r && r > TimeSpan.Zero;
        }
    }
}

/// <summary>409 <c>NO_SIGNING_CERTIFICATE</c> — иргэнд (баримтад) идэвхтэй SIGN гэрчилгээ алга; session үүсээгүй.</summary>
public sealed class EidNoSigningCertificateException : EidApiException
{
    internal EidNoSigningCertificateException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>CERT_CHOICE_INVALID</c> — linked sign-ийн certificate-choice session хүчингүй; дахин эхлүүлнэ.</summary>
public sealed class EidCertChoiceInvalidException : EidApiException
{
    internal EidCertChoiceInvalidException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>400 <c>REQUEST_INVALID</c> — хүсэлтийн бие/талбар буруу (програмын алдаа).</summary>
public sealed class EidRequestInvalidException : EidApiException
{
    internal EidRequestInvalidException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>404 <c>QR_TOKEN_INVALID</c> («Миний QR») — токен танигдахгүй / хугацаа дууссан / ашиглагдсан.</summary>
public sealed class EidQrTokenInvalidException : EidApiException
{
    internal EidQrTokenInvalidException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>ORG_NOT_ACTIVE</c> (тамганы зам) — байгууллага eID-д ACTIVE биш; давтахгүй.</summary>
public sealed class EidOrgNotActiveException : EidApiException
{
    internal EidOrgNotActiveException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_NOT_ISSUED</c> — байгууллагад тамганы гэрчилгээ олгогдоогүй.</summary>
public sealed class EidSealNotIssuedException : EidApiException
{
    internal EidSealNotIssuedException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_CERT_REVOKED</c> — тамганы гэрчилгээ цуцлагдсан.</summary>
public sealed class EidSealCertRevokedException : EidApiException
{
    internal EidSealCertRevokedException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_KEY_UNAVAILABLE</c> — тамганы түлхүүр eID-ийн одоогийн тохиргоонд алга (серверийн тал).</summary>
public sealed class EidSealKeyUnavailableException : EidApiException
{
    internal EidSealKeyUnavailableException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_CERT_EXPIRED</c> — тамганы гэрчилгээний хугацаа дууссан.</summary>
public sealed class EidSealCertExpiredException : EidApiException
{
    internal EidSealCertExpiredException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_CERT_NOT_YET_VALID</c> — тамганы гэрчилгээний хүчинтэй хугацаа эхлээгүй.</summary>
public sealed class EidSealCertNotYetValidException : EidApiException
{
    internal EidSealCertNotYetValidException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_APPROVER_UNAVAILABLE</c> — идэвхтэй eID төхөөрөмжтэй ADMIN төлөөлөгч алга.</summary>
public sealed class EidSealApproverUnavailableException : EidApiException
{
    internal EidSealApproverUnavailableException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>404 <c>SEAL_REQUEST_NOT_FOUND</c> — тамганы гэрчилгээний хүсэлт олдсонгүй.</summary>
public sealed class EidSealRequestNotFoundException : EidApiException
{
    internal EidSealRequestNotFoundException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>
/// 503 <c>SEAL_SERVICE_DISABLED</c> — оператор тамганы үйлчилгээг (<see cref="EidApiException.Service"/>:
/// <c>issuance</c> | <c>sealing</c>) унтраасан. <see cref="Retryable"/> үргэлж false.
/// </summary>
public sealed class EidSealServiceDisabledException : EidApiException
{
    internal EidSealServiceDisabledException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }

    /// <summary>Үргэлж false — proxy Retry-After нэмсэн ч давтахгүй.</summary>
    public override bool Retryable => false;
}

/// <summary>409 <c>AUTH_SESSION_WRONG_FLOW</c> (тамганы эрхийн хүсэлт) — session AUTHENTICATION биш.</summary>
public sealed class EidAuthSessionWrongFlowException : EidApiException
{
    internal EidAuthSessionWrongFlowException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>AUTH_SESSION_NOT_COMPLETED</c> — session дуусаагүй эсвэл OK биш.</summary>
public sealed class EidAuthSessionNotCompletedException : EidApiException
{
    internal EidAuthSessionNotCompletedException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>AUTH_SESSION_TOO_OLD</c> — session дууссанаас хойш 5 минутаас их.</summary>
public sealed class EidAuthSessionTooOldException : EidApiException
{
    internal EidAuthSessionTooOldException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>AUTH_SESSION_ALREADY_USED</c> — session өөр хүсэлтийн үндэс болсон.</summary>
public sealed class EidAuthSessionAlreadyUsedException : EidApiException
{
    internal EidAuthSessionAlreadyUsedException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>404 <c>AUTH_SESSION_NOT_FOUND</c> — session байхгүй эсвэл өөр RP-ийнх.</summary>
public sealed class EidAuthSessionNotFoundException : EidApiException
{
    internal EidAuthSessionNotFoundException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>SEAL_GRANT_ALREADY_APPROVED</c> — RP тухайн байгууллагад тамганы эрхтэй аль хэдийн.</summary>
public sealed class EidSealGrantAlreadyApprovedException : EidApiException
{
    internal EidSealGrantAlreadyApprovedException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>404 <c>SEAL_GRANT_NOT_FOUND</c> — тамганы эрхийн хүсэлт олдсонгүй.</summary>
public sealed class EidSealGrantNotFoundException : EidApiException
{
    internal EidSealGrantNotFoundException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>RP_NOT_ACTIVE</c> — RP идэвхтэй биш.</summary>
public sealed class EidRpNotActiveException : EidApiException
{
    internal EidRpNotActiveException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>409 <c>RP_PERMISSIONS_FULL</c> — RP-ийн эрхийн жагсаалт дүүрсэн.</summary>
public sealed class EidRpPermissionsFullException : EidApiException
{
    internal EidRpPermissionsFullException(int s, string b, string? c, string? sv, TimeSpan? r, HttpResponseHeaders? h)
        : base(s, b, c, sv, r, h)
    {
    }
}

/// <summary>
/// Сүлжээ/timeout — upstream хариу өгсөнгүй. <see cref="Op"/> ба мессежид хувь хүний таних тэмдэг ОРОХГҮЙ (замын
/// <c>/etsi/{…}</c>, <c>/document/{…}</c> → <c>…</c>) — шууд лог руу бичиж болно. Дуудагчийн
/// <see cref="System.Threading.CancellationToken"/> цуцлагдвал энэ биш, <see cref="OperationCanceledException"/>.
/// </summary>
public sealed class EidNetworkException : EidException
{
    internal EidNetworkException(string op, bool timeout, Exception? inner)
        : base(timeout ? "eid: хүсэлт хугацаа хэтэрлээ: " + op : "eid: сүлжээний алдаа (" + op + ")", inner)
    {
        Op = op;
        IsTimeout = timeout;
    }

    /// <summary>"GET /session/…" (таних тэмдэг хасагдсан зам).</summary>
    public string Op { get; }

    /// <summary>Хүсэлт хугацаа хэтэрсэн.</summary>
    public bool IsTimeout { get; }
}

/// <summary>Хариуны бие SDK-ийн хязгаараас (JSON 4 MiB) хэтэрсэн; бие таслагдаж задлагдахгүй.</summary>
public sealed class EidResponseTooLargeException : EidException
{
    internal EidResponseTooLargeException(string op, long limit) : base("eid: " + op + ": хариу " + limit + " байтаас их")
    {
        Op = op;
        Limit = limit;
    }

    /// <summary>Method + таних тэмдэггүй зам.</summary>
    public string Op { get; }

    /// <summary>Хязгаар (байт).</summary>
    public long Limit { get; }
}

/// <summary>
/// Session амжилтгүй дууссан (endResult ≠ OK): TIMEOUT, USER_REFUSED*, DOCUMENT_UNUSABLE г.м. <see cref="EndResult"/>-оор
/// салгаж RP UI-д тохирох мессеж харуулна.
/// </summary>
public sealed class EidSessionFailedException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidSessionFailedException(string endResult) : base("eid: session амжилтгүй: " + endResult)
    {
        EndResult = endResult;
    }

    /// <summary>Серверийн endResult (<see cref="EndResults"/>).</summary>
    public string EndResult { get; }
}

/// <summary>
/// Хариуны баталгаажуулалт бүтэлгүйтсэн: гинж итгэлцэлгүй, гарын үсэг таарсангүй, certLevel хүрэлцээгүй г.м. ЭНЭ
/// алдаа гарвал хариунд ИТГЭХГҮЙ. <see cref="Reason"/> — тогтвортой шалтгааны түлхүүр (<see cref="ValidationReasons"/>,
/// cross-SDK conformance корпусын reason key); <see cref="Exception.Message"/> — монгол тайлбар (програмаар тулгахгүй).
/// <see cref="Exception.InnerException"/> — үндсэн шалтгаан (байвал).
/// </summary>
public sealed class EidValidationException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    /// <param name="reason">Тогтвортой түлхүүр (<see cref="ValidationReasons"/>).</param>
    /// <param name="message">Монгол тайлбар (иргэний нэр/РД оруулахгүй — serial л).</param>
    /// <param name="cause">Үндсэн шалтгаан.</param>
    public EidValidationException(string reason, string message, Exception? cause = null) : base("eid: баталгаажуулалт: " + message, cause)
    {
        Reason = reason;
    }

    /// <summary>Тогтвортой шалтгааны түлхүүр (<see cref="ValidationReasons"/>) — RP програмаар салгахад үүнийг хэрэглэнэ.</summary>
    public string Reason { get; }
}

/// <summary>
/// <see cref="EidValidationException.Reason"/>-ийн тогтвортой түлхүүрүүд — cross-SDK conformance корпусын (Go
/// <c>testdata/conformance/README.md</c> §rp-validate) reason key-тэй ижил. Шалгалтын дараалал: эхэнд бүтэлгүйтсэн
/// шалгалтын түлхүүр.
/// </summary>
public static class ValidationReasons
{
    /// <summary>Хариу (SessionResult) алга.</summary>
    public const string ResponseMissing = "response.missing";
    /// <summary>ValidateAuth-д ACSP контекст алга.</summary>
    public const string AcspMissing = "acsp.missing";
    /// <summary>state ≠ COMPLETE.</summary>
    public const string SessionNotComplete = "session.not_complete";
    /// <summary>signatureProtocol нь ACSP_V2 (auth) / RAW_DIGEST_SIGNATURE (sign)-ээс өөр.</summary>
    public const string ProtocolMismatch = "protocol.mismatch";
    /// <summary>cert.value алга.</summary>
    public const string NoCertificate = "response.no_certificate";
    /// <summary>signature.value алга.</summary>
    public const string NoSignature = "response.no_signature";
    /// <summary>result.documentNumber алга.</summary>
    public const string NoDocumentNumber = "response.no_document_number";
    /// <summary>Гэрчилгээ base64 DER X.509 биш.</summary>
    public const string CertMalformed = "cert.malformed";
    /// <summary>Гэрчилгээ хүчинтэй болоогүй (now + skew &lt; notBefore).</summary>
    public const string CertNotYetValid = "cert.not_yet_valid";
    /// <summary>Гэрчилгээний хугацаа дууссан (now − skew &gt; notAfter).</summary>
    public const string CertExpired = "cert.expired";
    /// <summary>Нэвтрэлтийн гэрчилгээнд KeyUsage digitalSignature алга.</summary>
    public const string PurposeAuthDigitalSignature = "purpose.auth_digital_signature";
    /// <summary>Нэвтрэлтийн гэрчилгээнд EKU clientAuth / anyExtendedKeyUsage алга.</summary>
    public const string PurposeAuthClientAuth = "purpose.auth_client_auth";
    /// <summary>Гарын үсгийн гэрчилгээнд KeyUsage nonRepudiation (contentCommitment) алга.</summary>
    public const string PurposeSignNonRepudiation = "purpose.sign_non_repudiation";
    /// <summary>Trust anchor тохируулаагүй.</summary>
    public const string TrustNoAnchor = "trust.no_anchor";
    /// <summary>Leaf эсвэл гинжийн CA-д SDK-ийн жагсаалтад байхгүй critical extension.</summary>
    public const string ChainCriticalExtension = "chain.critical_extension";
    /// <summary>Гинжийн CA (anchor ч мөн)-д nameConstraints — fail-closed.</summary>
    public const string ChainNameConstraints = "chain.name_constraints";
    /// <summary>pathLenConstraint зөрчсөн.</summary>
    public const string ChainPathLen = "chain.path_len";
    /// <summary>Leaf эсвэл CA-ийн EKU энэ зориулалтыг (auth → clientAuth, sign → emailProtection) агуулаагүй.</summary>
    public const string ChainEku = "chain.eku";
    /// <summary>Issuer CA биш эсвэл KeyUsage-д keyCertSign алга.</summary>
    public const string ChainNotCa = "chain.not_ca";
    /// <summary>Гинжийн CA хүчинтэй хугацаанаас гадуур.</summary>
    public const string ChainExpired = "chain.expired";
    /// <summary>Leaf-ээс trust anchor хүртэл зам алга.</summary>
    public const string ChainUntrusted = "chain.untrusted";
    /// <summary>Шууд issuer-ийн SKI (эсвэл leaf-ийн AKI) зөвшөөрөгдсөн жагсаалтад алга.</summary>
    public const string IssuerNotAllowed = "issuer.not_allowed";
    /// <summary>qcStatements extension SEQUENCE OF SEQUENCE биш.</summary>
    public const string LevelQcMalformed = "level.qc_malformed";
    /// <summary>Хариуны certificateLevel гэрчилгээнээс тогтоосноос өндөр.</summary>
    public const string LevelClaimedHigher = "level.claimed_higher";
    /// <summary>Үнэлэгдсэн түвшин шаардсанаас бага.</summary>
    public const string LevelInsufficient = "level.insufficient";
    /// <summary>serverRandom алга эсвэл 18 байтаас богино.</summary>
    public const string AuthServerRandom = "auth.server_random";
    /// <summary>userChallenge нь 43 тэмдэгт base64url биш.</summary>
    public const string AuthUserChallenge = "auth.user_challenge";
    /// <summary>flowType нь санал болгосон урсгалд (acsp.flowTypes) алга.</summary>
    public const string AuthFlowNotOffered = "auth.flow_not_offered";
    /// <summary>ExpectedFlowType ≠ flowType (auth ба sign).</summary>
    public const string FlowMismatch = "flow.mismatch";
    /// <summary>Web2App/App2App-д userChallengeVerifier өгөөгүй.</summary>
    public const string AuthVerifierRequired = "auth.verifier_required";
    /// <summary>BASE64URL(SHA-256(verifier)) ≠ userChallenge.</summary>
    public const string AuthVerifierMismatch = "auth.verifier_mismatch";
    /// <summary>interactionTypeUsed алга.</summary>
    public const string AuthInteractionTypeMissing = "auth.interaction_type_missing";
    /// <summary>ExpectedCertificate-тэй байт-ижил биш.</summary>
    public const string SignCertificateMismatch = "sign.certificate_mismatch";
    /// <summary>Үл мэдэх signatureAlgorithm эсвэл дэмжигдээгүй hash.</summary>
    public const string AlgUnsupported = "alg.unsupported";
    /// <summary>Алгоритм ба түлхүүрийн төрөл таарахгүй.</summary>
    public const string AlgKeyMismatch = "alg.key_mismatch";
    /// <summary>PSS MGF1 hash ≠ hash.</summary>
    public const string AlgMgf1 = "alg.mgf1";
    /// <summary>PSS saltLength ≠ hLen.</summary>
    public const string AlgSaltLength = "alg.salt_length";
    /// <summary>ecdsa-with-SHA256 хариу SHA-256 биш session-д.</summary>
    public const string AlgEcdsaHash = "alg.ecdsa_hash";
    /// <summary>Хүссэн алгоритм ≠ хариуны (ecdsa-with-SHA256 үргэлж зөвшөөрөгдөнө).</summary>
    public const string AlgMismatch = "alg.mismatch";
    /// <summary>Хариуны hash ≠ хүссэн.</summary>
    public const string AlgHashMismatch = "alg.hash_mismatch";
    /// <summary>signature.initialCallbackUrl нь хоосон ч биш, RP-ийн callback ч биш (эсвэл Web2App/App2App-д ≠ callback).</summary>
    public const string AuthCallbackUrl = "auth.callback_url";
    /// <summary>ACSP_V2 гарын үсэг таарсангүй.</summary>
    public const string AuthSignature = "auth.signature";
    /// <summary>digest стандарт base64 биш (Go-ийн шалгалт).</summary>
    public const string SignDigestBase64 = "sign.digest_base64";
    /// <summary>digest-ийн урт ≠ hash-ийн урт.</summary>
    public const string SignDigestLength = "sign.digest_length";
    /// <summary>Prehashed гарын үсэг digest-тэй таарсангүй.</summary>
    public const string SignSignature = "sign.signature";
    /// <summary>Гэрчилгээ цуцлагдсан (OCSP revoked, мөн unknown).</summary>
    public const string RevocationRevoked = "revocation.revoked";
    /// <summary>Цуцлалтын төлөв тогтоогдсонгүй (hard-fail).</summary>
    public const string RevocationUnknown = "revocation.unknown";
}

/// <summary>
/// Device link угсрах боломжгүй: deviceLinkBase https биш, token/lang/secret хэлбэр буруу, эсвэл төрөлд хэрэгтэй
/// талбар дутуу. Session-ийг дахин эхлүүлнэ; холбоосыг таахгүй.
/// </summary>
public sealed class EidDeviceLinkException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidDeviceLinkException(string reason) : base("eid: BuildDeviceLink: " + reason)
    {
        Reason = reason;
    }

    /// <summary>Шалтгаан.</summary>
    public string Reason { get; }
}

/// <summary>CA-ийн тогтвортой алдааны кодууд (<see cref="EidException.Code"/>) — Go <c>Code*</c> тогтмолуудтай ижил.</summary>
public static class EidErrorCodes
{
    /// <summary>409: иргэнд идэвхтэй SIGN гэрчилгээ алга (sign ба certificate-choice start).</summary>
    public const string NoSigningCertificate = "NO_SIGNING_CERTIFICATE";
    /// <summary>409: linked sign-ийн certificate-choice session хүчингүй.</summary>
    public const string CertChoiceInvalid = "CERT_CHOICE_INVALID";
    /// <summary>400: хүсэлт буруу.</summary>
    public const string RequestInvalid = "REQUEST_INVALID";
    /// <summary>429: хүсэлтийн хязгаар; Retry-After.</summary>
    public const string RateLimited = "RATE_LIMITED";
    /// <summary>503: state store түр хүрэхгүй; Retry-After.</summary>
    public const string StateUnavailable = "STATE_UNAVAILABLE";
    /// <summary>503: токены гэрчилгээ олгогдож байна; Retry-After.</summary>
    public const string IssuancePending = "ISSUANCE_PENDING";
    /// <summary>403: идэвхтэй төлөөлөгч биш.</summary>
    public const string RepresentationDenied = "REPRESENTATION_DENIED";
    /// <summary>403: PIN2-оор баталгаажуулаагүй (MANAGER).</summary>
    public const string RepresentationPending = "REPRESENTATION_PENDING";
    /// <summary>403: хугацааны гадна.</summary>
    public const string RepresentationExpired = "REPRESENTATION_EXPIRED";
    /// <summary>Байгууллага ACTIVE биш: onBehalfOf урсгалд 403, тамганы замд 409.</summary>
    public const string OrgNotActive = "ORG_NOT_ACTIVE";
    /// <summary>403: anonymous session.</summary>
    public const string SignerUnidentified = "SIGNER_UNIDENTIFIED";
    /// <summary>404: байгууллага олдсонгүй.</summary>
    public const string OrgNotFound = "ORG_NOT_FOUND";
    /// <summary>403: session-оос хойш төлөөлөл хасагдсан.</summary>
    public const string RepresentationRevoked = "REPRESENTATION_REVOKED";
    /// <summary>404: «Миний QR» токен хүчингүй.</summary>
    public const string QrTokenInvalid = "QR_TOKEN_INVALID";
    /// <summary>409: тамганы гэрчилгээ олгогдоогүй.</summary>
    public const string SealNotIssued = "SEAL_NOT_ISSUED";
    /// <summary>409: тамганы гэрчилгээ цуцлагдсан.</summary>
    public const string SealCertRevoked = "SEAL_CERT_REVOKED";
    /// <summary>409: тамганы түлхүүр алга.</summary>
    public const string SealKeyUnavailable = "SEAL_KEY_UNAVAILABLE";
    /// <summary>409: тамганы гэрчилгээний хугацаа дууссан.</summary>
    public const string SealCertExpired = "SEAL_CERT_EXPIRED";
    /// <summary>409: тамганы гэрчилгээ хүчинтэй болоогүй.</summary>
    public const string SealCertNotYetValid = "SEAL_CERT_NOT_YET_VALID";
    /// <summary>409: батлах ADMIN алга.</summary>
    public const string SealApproverUnavailable = "SEAL_APPROVER_UNAVAILABLE";
    /// <summary>404: тамганы гэрчилгээний хүсэлт олдсонгүй.</summary>
    public const string SealRequestNotFound = "SEAL_REQUEST_NOT_FOUND";
    /// <summary>503: тамганы үйлчилгээ унтраалттай (давтахгүй).</summary>
    public const string SealServiceDisabled = "SEAL_SERVICE_DISABLED";
    /// <summary>403: RP бүртгэлгүй (тамганы эрхийн хүсэлт).</summary>
    public const string RpNotRegistered = "RP_NOT_REGISTERED";
    /// <summary>403: иргэн байгууллагын захирал биш.</summary>
    public const string NotOrgCeo = "NOT_ORG_CEO";
    /// <summary>404: auth session олдсонгүй.</summary>
    public const string AuthSessionNotFound = "AUTH_SESSION_NOT_FOUND";
    /// <summary>409: auth session биш.</summary>
    public const string AuthSessionWrongFlow = "AUTH_SESSION_WRONG_FLOW";
    /// <summary>409: auth session дуусаагүй.</summary>
    public const string AuthSessionNotCompleted = "AUTH_SESSION_NOT_COMPLETED";
    /// <summary>409: auth session хэт хуучин.</summary>
    public const string AuthSessionTooOld = "AUTH_SESSION_TOO_OLD";
    /// <summary>409: auth session ашиглагдсан.</summary>
    public const string AuthSessionAlreadyUsed = "AUTH_SESSION_ALREADY_USED";
    /// <summary>409: RP идэвхтэй биш.</summary>
    public const string RpNotActive = "RP_NOT_ACTIVE";
    /// <summary>409: тамганы эрх аль хэдийн батлагдсан.</summary>
    public const string SealGrantAlreadyApproved = "SEAL_GRANT_ALREADY_APPROVED";
    /// <summary>409: RP-ийн эрхийн жагсаалт дүүрсэн.</summary>
    public const string RpPermissionsFull = "RP_PERMISSIONS_FULL";
    /// <summary>404: тамганы эрхийн хүсэлт олдсонгүй.</summary>
    public const string SealGrantNotFound = "SEAL_GRANT_NOT_FOUND";

    /// <summary>Түр (давтаж болох) алдааны кодууд — <see cref="EidException.Retryable"/>.</summary>
    public static IReadOnlyList<string> RetryableCodes { get; } = new[] { RateLimited, StateUnavailable, IssuancePending };

    /// <summary><c>onBehalfOf</c> урсгалын бүх татгалзлын код.</summary>
    public static IReadOnlyList<string> OnBehalfErrorCodes { get; } = new[]
    {
        RepresentationDenied, RepresentationPending, RepresentationExpired, OrgNotActive, SignerUnidentified, OrgNotFound,
        RepresentationRevoked,
    };
}
