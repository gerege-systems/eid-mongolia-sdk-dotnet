using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace GeregeSystems.EidMongolia;

// RP-API-ийн wire-contract төрлүүд (Go types.go, TS types.ts). JSON талбарын нэр серверийн RP-API v3-тай ЯГ ИЖИЛ
// (camelCase). Утгууд нь string — CA шинэ утга нэмбэл SDK задлалт унахгүй.

/// <summary>Гэрчилгээний баталгаажуулалтын түвшин (eIDAS LoA). ADVANCED &lt; QUALIFIED &lt; QSCD.</summary>
public static class CertificateLevels
{
    /// <summary>ADVANCED.</summary>
    public const string Advanced = "ADVANCED";
    /// <summary>QUALIFIED (анхдагч).</summary>
    public const string Qualified = "QUALIFIED";
    /// <summary>QSCD.</summary>
    public const string Qscd = "QSCD";
}

/// <summary>Гарын үсгийн алгоритм. rsassa-pss анхдагч; ecdsa-with-SHA256 — хуучин threshold-ECDSA гэрчилгээ.</summary>
public static class SignatureAlgorithms
{
    /// <summary>RSASSA-PSS.</summary>
    public const string RsassaPss = "rsassa-pss";
    /// <summary>PKCS#1 v1.5 SHA-256.</summary>
    public const string Sha256WithRsa = "sha256WithRSAEncryption";
    /// <summary>PKCS#1 v1.5 SHA-384.</summary>
    public const string Sha384WithRsa = "sha384WithRSAEncryption";
    /// <summary>PKCS#1 v1.5 SHA-512.</summary>
    public const string Sha512WithRsa = "sha512WithRSAEncryption";
    /// <summary>ECDSA P-256 SHA-256.</summary>
    public const string EcdsaWithSha256 = "ecdsa-with-SHA256";
}

/// <summary>Hash алгоритм (Smart-ID v3 нэршил).</summary>
public static class HashAlgorithms
{
    /// <summary>SHA-256.</summary>
    public const string Sha256 = "SHA-256";
    /// <summary>SHA-384.</summary>
    public const string Sha384 = "SHA-384";
    /// <summary>SHA-512.</summary>
    public const string Sha512 = "SHA-512";
}

/// <summary>Урсгалын төрөл (хариуны <c>signature.flowType</c>).</summary>
public static class FlowTypes
{
    /// <summary>QR.</summary>
    public const string Qr = "QR";
    /// <summary>App2App.</summary>
    public const string App2App = "App2App";
    /// <summary>Web2App.</summary>
    public const string Web2App = "Web2App";
    /// <summary>Notification (push).</summary>
    public const string Notification = "Notification";
}

/// <summary>Session-ийн төлөв (<c>state</c>).</summary>
public static class SessionStates
{
    /// <summary>RUNNING.</summary>
    public const string Running = "RUNNING";
    /// <summary>COMPLETE.</summary>
    public const string Complete = "COMPLETE";
}

/// <summary>Гарын үсгийн протокол (<c>signatureProtocol</c>).</summary>
public static class SignatureProtocols
{
    /// <summary>Нэвтрэлт: ACSP_V2 payload дээрх гарын үсэг.</summary>
    public const string AcspV2 = "ACSP_V2";
    /// <summary>Гарын үсэг: RP-ийн digest дээрх (prehashed) гарын үсэг.</summary>
    public const string RawDigestSignature = "RAW_DIGEST_SIGNATURE";
}

/// <summary>Session-ийн эцсийн үр дүнгийн түгээмэл утгууд (<c>result.endResult</c>).</summary>
public static class EndResults
{
    /// <summary>OK.</summary>
    public const string Ok = "OK";
    /// <summary>USER_REFUSED.</summary>
    public const string UserRefused = "USER_REFUSED";
    /// <summary>USER_REFUSED_DISPLAYTEXTANDPIN.</summary>
    public const string UserRefusedDisplayTextAndPin = "USER_REFUSED_DISPLAYTEXTANDPIN";
    /// <summary>USER_REFUSED_VC_CHOICE.</summary>
    public const string UserRefusedVcChoice = "USER_REFUSED_VC_CHOICE";
    /// <summary>USER_REFUSED_CONFIRMATIONMESSAGE.</summary>
    public const string UserRefusedConfirmationMessage = "USER_REFUSED_CONFIRMATIONMESSAGE";
    /// <summary>USER_REFUSED_CERT_CHOICE.</summary>
    public const string UserRefusedCertChoice = "USER_REFUSED_CERT_CHOICE";
    /// <summary>TIMEOUT.</summary>
    public const string Timeout = "TIMEOUT";
    /// <summary>DOCUMENT_UNUSABLE.</summary>
    public const string DocumentUnusable = "DOCUMENT_UNUSABLE";
    /// <summary>WRONG_VC.</summary>
    public const string WrongVc = "WRONG_VC";
    /// <summary>PROTOCOL_FAILURE.</summary>
    public const string ProtocolFailure = "PROTOCOL_FAILURE";
}

/// <summary>
/// Иргэний утсан дээр харагдах харилцан үйлдэл. <c>displayTextAndPIN</c> нь PIN асууж текст харуулна. DisplayText60 —
/// 60 тэмдэгт хүртэл; DisplayText200 — 200 хүртэл. Хоосон (null эсвэл "") талбар илгээгдэхгүй (Go omitempty).
/// </summary>
public sealed record Interaction
{
    /// <summary><c>displayTextAndPIN</c> | <c>confirmationMessage</c> | <c>confirmationMessageAndVerificationCodeChoice</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "";

    /// <summary>60 тэмдэгт хүртэл.</summary>
    [JsonPropertyName("displayText60")]
    public string? DisplayText60 { get; init; }

    /// <summary>200 тэмдэгт хүртэл.</summary>
    [JsonPropertyName("displayText200")]
    public string? DisplayText200 { get; init; }
}

/// <summary>
/// Auth session-ийн ACSP_V2 контекст: RP хүсэлтэд илгээсэн утгууд. Validator үүн + хариугаар payload-ийг дахин угсарна.
/// RP үүнийг session-тэй хамт серверт хадгална (JSON-оор хадгалж болно).
/// </summary>
public sealed record AcspContext
{
    /// <summary>Илгээсэн rpChallenge (base64).</summary>
    [JsonPropertyName("rpChallenge")]
    public string RpChallenge { get; init; } = "";

    /// <summary>Илгээсэн relyingPartyName.</summary>
    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    /// <summary>brokeredRpName (одоогоор "").</summary>
    [JsonPropertyName("brokeredRpName")]
    public string BrokeredRpName { get; init; } = "";

    /// <summary>Илгээсэн interactions-ийн base64 МӨР (дахин serialize хийхгүй).</summary>
    [JsonPropertyName("interactions")]
    public string Interactions { get; init; } = "";

    /// <summary>Илгээсэн initialCallbackUrl, байхгүй бол "".</summary>
    [JsonPropertyName("initialCallbackUrl")]
    public string InitialCallbackUrl { get; init; } = "";

    /// <summary>RP-ийн санал болгосон урсгалууд; хариуны flowType эдгээрийн нэг байх ёстой.</summary>
    [JsonPropertyName("flowTypes")]
    public IReadOnlyList<string> FlowTypes { get; init; } = Array.Empty<string>();

    /// <summary>Хүссэн гарын үсгийн алгоритм.</summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; init; } = "";

    /// <summary>Хүссэн hash алгоритм.</summary>
    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; init; } = "";
}

/// <summary>
/// Sign session-ий хүсэлтэд илгээсэн утгууд ЯГ ХЭВЭЭР: ValidateSign ба device link-д. RP session-тэй хамт хадгална.
/// </summary>
public sealed record SignContext
{
    /// <summary>Илгээсэн digest (стандарт base64, ЯГ ХЭВЭЭР — device link-ийн authCode-д ордог).</summary>
    [JsonPropertyName("digest")]
    public string Digest { get; init; } = "";

    /// <summary>Hash алгоритм.</summary>
    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; init; } = "";

    /// <summary>Гарын үсгийн алгоритм.</summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; init; } = "";

    /// <summary>Илгээсэн relyingPartyName.</summary>
    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    /// <summary>Илгээсэн interactions-ийн base64 МӨР.</summary>
    [JsonPropertyName("interactions")]
    public string Interactions { get; init; } = "";

    /// <summary>Илгээсэн initialCallbackUrl, байхгүй бол "".</summary>
    [JsonPropertyName("initialCallbackUrl")]
    public string InitialCallbackUrl { get; init; } = "";
}

/// <summary>
/// Push (notification) session эхлүүлсний хариу. <see cref="Vc"/> — иргэний дэлгэцэд ХАРУУЛАХ 5 оронтой код (ПИН БИШ).
/// </summary>
public sealed record NotificationSession
{
    /// <summary>Session ID.</summary>
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = "";

    /// <summary>Баталгаажуулах код (зөвхөн харуулна).</summary>
    [JsonPropertyName("vc")]
    public string Vc { get; init; } = "";

    /// <summary>RP-ийн илгээсэн challenge (base64); sign session-д "".</summary>
    [JsonPropertyName("rpChallenge")]
    public string RpChallenge { get; init; } = "";

    /// <summary>Auth session-д validator-т өгөх контекст; бусад үед null.</summary>
    [JsonPropertyName("acsp")]
    public AcspContext? Acsp { get; init; }

    /// <summary>Sign session-ий контекст; бусад үед null.</summary>
    [JsonPropertyName("sign")]
    public SignContext? Sign { get; init; }

    /// <summary>Session дуусах мөч (CA-ийн expiresAt, эсвэл тооцоолсон); мэдэгдэхгүй бол null.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>
/// Device-link (QR/Web2App/App2App) session. <see cref="SessionToken"/>, <see cref="SessionSecret"/>-ийг ЗӨВХӨН
/// backend-д хадгална — браузер/апп руу бүү гарга.
/// </summary>
public sealed record DeviceLinkSession
{
    /// <summary>Session ID.</summary>
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = "";

    /// <summary>sessionToken (холбоосонд).</summary>
    [JsonPropertyName("sessionToken")]
    public string SessionToken { get; init; } = "";

    /// <summary>sessionSecret (стандарт base64) — authCode-ийн HMAC түлхүүр. ЗӨВХӨН backend-д.</summary>
    [JsonPropertyName("sessionSecret")]
    public string SessionSecret { get; init; } = "";

    /// <summary>Холбоосын суурь URL; холбоосыг <see cref="DeviceLink.Build"/>-ээр угсарна.</summary>
    [JsonPropertyName("deviceLinkBase")]
    public string DeviceLinkBase { get; init; } = "";

    /// <summary>5 оронтой баталгаажуулах код (ПИН БИШ).</summary>
    [JsonPropertyName("vc")]
    public string Vc { get; init; } = "";

    /// <summary>RP-ийн илгээсэн challenge.</summary>
    [JsonPropertyName("rpChallenge")]
    public string RpChallenge { get; init; } = "";

    /// <summary>Auth session-ий контекст.</summary>
    [JsonPropertyName("acsp")]
    public AcspContext? Acsp { get; init; }

    /// <summary>RP backend хариуг хүлээн авсан мөч (QR-ийн elapsedSeconds-ийн эх).</summary>
    [JsonPropertyName("receivedAt")]
    public DateTimeOffset ReceivedAt { get; init; }

    /// <summary>auth | sign | cert (<see cref="DeviceLinkSessionTypes"/>); хуучин хадгалсан session-д "" = auth.</summary>
    [JsonPropertyName("sessionType")]
    public string? SessionType { get; init; }

    /// <summary>Sign session-ий контекст.</summary>
    [JsonPropertyName("sign")]
    public SignContext? Sign { get; init; }

    /// <summary>Certificate-choice session-ий хүсэлтэд илгээсэн нэр.</summary>
    [JsonPropertyName("relyingPartyName")]
    public string? RelyingPartyName { get; init; }

    /// <summary>Certificate-choice device-link хүсэлтэд илгээсэн initialCallbackUrl (null = QR-only).</summary>
    [JsonPropertyName("callbackUrl")]
    public string? CallbackUrl { get; init; }

    /// <summary>Session дуусах мөч; мэдэгдэхгүй бол null.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// <see cref="DeviceLink.Build"/>-ийн оролт (Go <c>DeviceLinkSession.LinkInput</c>): auth — Acsp, sign — Sign, cert —
    /// RelyingPartyName + CallbackUrl. <paramref name="lang"/> — ISO 639-2 (mon, eng).
    /// </summary>
    public DeviceLinkInput LinkInput(string deviceLinkType, string lang) => DeviceLink.InputOf(this, deviceLinkType, lang);

    /// <summary>
    /// Холбоос угсарна (<see cref="DeviceLinkTypes"/>). QR-ийг секунд тутам дахин угсрах тул HTTP poll-д хүсэлт бүрд
    /// дууд, SSE/WebSocket-д <see cref="TickQrAsync(string, TimeSpan, CancellationToken)"/>. <paramref name="now"/> null = одоо.
    /// </summary>
    /// <exception cref="EidDeviceLinkException">Оролт буруу (ж: Web2App-д callback-гүй session).</exception>
    public string BuildLink(string deviceLinkType, string lang, DateTimeOffset? now = null) =>
        DeviceLink.Build(LinkInput(deviceLinkType, lang) with { Now = now });

    /// <summary>QR холбоосыг шууд, дараа нь <paramref name="interval"/> тутам гаргана (<see cref="DeviceLink.TickQrAsync(DeviceLinkInput, TimeSpan, CancellationToken)"/>).</summary>
    public IAsyncEnumerable<string> TickQrAsync(string lang, TimeSpan interval, CancellationToken ct = default) =>
        DeviceLink.TickQrAsync(LinkInput(DeviceLinkTypes.Qr, lang), interval, ct);

    /// <summary><see cref="TickQrAsync(string, TimeSpan, CancellationToken)"/>, өгсөн цагаар (тест).</summary>
    public IAsyncEnumerable<string> TickQrAsync(string lang, TimeSpan interval, TimeProvider timeProvider, CancellationToken ct = default) =>
        DeviceLink.TickQrAsync(LinkInput(DeviceLinkTypes.Qr, lang), interval, timeProvider, ct);
}

/// <summary>Discovery-ийн <c>sessionTtl</c>: CA-ийн нэвтрэлт / гарын үсгийн session-ий амьдрах хугацаа. Алга бол Zero.</summary>
/// <param name="Auth">Нэвтрэлтийн session.</param>
/// <param name="Sign">Гарын үсгийн session.</param>
public sealed record SessionTtl(TimeSpan Auth, TimeSpan Sign);

/// <summary>rsassa-pss хариуны параметр (<c>signature.signatureAlgorithmParameters</c>).</summary>
public sealed record SignatureAlgorithmParameters
{
    /// <summary>Hash алгоритм.</summary>
    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; init; } = "";

    /// <summary>MGF.</summary>
    [JsonPropertyName("maskGenAlgorithm")]
    public MaskGenAlgorithm? MaskGenAlgorithm { get; init; }

    /// <summary>Salt урт; null = хариунд алга.</summary>
    [JsonPropertyName("saltLength")]
    public int? SaltLength { get; init; }

    /// <summary>Trailer field.</summary>
    [JsonPropertyName("trailerField")]
    public string? TrailerField { get; init; }
}

/// <summary>PSS MGF1 параметр.</summary>
public sealed record MaskGenAlgorithm
{
    /// <summary>Алгоритм.</summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; init; } = "";

    /// <summary>Параметр.</summary>
    [JsonPropertyName("parameters")]
    public MaskGenParameters? Parameters { get; init; }
}

/// <summary>MGF1-ийн hash.</summary>
public sealed record MaskGenParameters
{
    /// <summary>Hash алгоритм.</summary>
    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; init; } = "";
}

/// <summary>
/// Session-ий person блок (CA бүртгэлээс). ГАРЫН ҮСЭГТ ОРДОГГҮЙ — validator-оор баталгаажсаны дараа <see cref="CivilId"/>-г
/// гэрчилгээний SERIALNUMBER (PNOMN-&lt;civilId&gt;)-тэй тулгаж л хэрэглэнэ. FirstName = нэр, LastName = ЭЦГИЙН нэр,
/// FamilyName = УРГИЙН овог.
/// </summary>
public sealed record Person
{
    /// <summary>Нэр.</summary>
    [JsonPropertyName("firstName")]
    public string? FirstName { get; init; }
    /// <summary>Эцгийн нэр.</summary>
    [JsonPropertyName("lastName")]
    public string? LastName { get; init; }
    /// <summary>Ургийн овог.</summary>
    [JsonPropertyName("familyName")]
    public string? FamilyName { get; init; }
    /// <summary>Нэр (латин).</summary>
    [JsonPropertyName("firstNameEn")]
    public string? FirstNameEn { get; init; }
    /// <summary>Эцгийн нэр (латин).</summary>
    [JsonPropertyName("lastNameEn")]
    public string? LastNameEn { get; init; }
    /// <summary>Иргэний дугаар.</summary>
    [JsonPropertyName("civilId")]
    public string? CivilId { get; init; }
    /// <summary>Регистрийн дугаар.</summary>
    [JsonPropertyName("regNo")]
    public string? RegNo { get; init; }
    /// <summary>YYYY-MM-DD.</summary>
    [JsonPropertyName("birthDate")]
    public string? BirthDate { get; init; }
    /// <summary>M | F | X.</summary>
    [JsonPropertyName("gender")]
    public string? Gender { get; init; }
    /// <summary>core.gerege.mn-ий дотоод дугаар; 0 = тулгагдаагүй.</summary>
    [JsonPropertyName("geID")]
    public long GeId { get; init; }
    /// <summary>Харьяалал (ISO 3166-1 alpha-3); SDK шалгахгүй.</summary>
    [JsonPropertyName("nationality")]
    public string? Nationality { get; init; }
}

/// <summary>Session-ий байгууллагын блок (бүртгэлээс real-time). Эрх хураагдсан бол Role/RightType "".</summary>
public sealed record OrgResult
{
    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";
    /// <summary>Байгууллагын нэр.</summary>
    [JsonPropertyName("orgName")]
    public string OrgName { get; init; } = "";
    /// <summary>Албан тушаалын машин утга.</summary>
    [JsonPropertyName("role")]
    public string Role { get; init; } = "";
    /// <summary>Албан тушаалын хүнд харуулах нэр.</summary>
    [JsonPropertyName("roleLabel")]
    public string? RoleLabel { get; init; }
    /// <summary>ADMIN | MANAGER.</summary>
    [JsonPropertyName("rightType")]
    public string RightType { get; init; } = "";
    /// <summary>Эрхийн төрлийн хүнд харуулах нэр.</summary>
    [JsonPropertyName("rightTypeLabel")]
    public string? RightTypeLabel { get; init; }
}

/// <summary>Иргэний төлөөлж чадах нэг байгууллага.</summary>
public sealed record Representation
{
    /// <summary>NTRMN-&lt;бүртгэл&gt; — OnBehalfOf-д өгөх утга.</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";
    /// <summary>Байгууллагын регистр.</summary>
    [JsonPropertyName("orgRegister")]
    public string OrgRegister { get; init; } = "";
    /// <summary>Нэр.</summary>
    [JsonPropertyName("orgName")]
    public string OrgName { get; init; } = "";
    /// <summary>Нэр (англи).</summary>
    [JsonPropertyName("orgNameEn")]
    public string? OrgNameEn { get; init; }
    /// <summary>Албан тушаалын машин утга.</summary>
    [JsonPropertyName("role")]
    public string? Role { get; init; }
    /// <summary>Албан тушаалын хүнд харуулах нэр.</summary>
    [JsonPropertyName("roleLabel")]
    public string? RoleLabel { get; init; }
    /// <summary>ADMIN | MANAGER.</summary>
    [JsonPropertyName("rightType")]
    public string RightType { get; init; } = "";
    /// <summary>Эрхийн төрлийн хүнд харуулах нэр.</summary>
    [JsonPropertyName("rightTypeLabel")]
    public string? RightTypeLabel { get; init; }
    /// <summary>REGISTRY | MANUAL.</summary>
    [JsonPropertyName("source")]
    public string Source { get; init; } = "";
    /// <summary>Эх үүсвэрийн хүнд харуулах нэр.</summary>
    [JsonPropertyName("sourceLabel")]
    public string? SourceLabel { get; init; }
    /// <summary>PAdES signer-attributes-v2-д бичих мэдүүлсэн үүрэг (CA тооцоолно; ӨӨРЧЛӨЛГҮЙ дамжуулна).</summary>
    [JsonPropertyName("claimedRole")]
    public string? ClaimedRole { get; init; }
    /// <summary>ISO 8601.</summary>
    [JsonPropertyName("validFrom")]
    public string ValidFrom { get; init; } = "";
    /// <summary>ISO 8601; null = хугацаагүй.</summary>
    [JsonPropertyName("validTo")]
    public string? ValidTo { get; init; }
}

/// <summary><c>GET /organization/representations/etsi/{personEtsi}</c> хариу.</summary>
public sealed record RepresentationsResponse
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";
    /// <summary>Төлөөллүүд.</summary>
    [JsonPropertyName("representations")]
    public IReadOnlyList<Representation> Representations { get; init; } = Array.Empty<Representation>();
}

/// <summary>Токены гэрчилгээ олголтын төлөв (<see cref="TokenCertSessionBlock.Status"/>).</summary>
public static class TokenCertStatuses
{
    /// <summary>PENDING.</summary>
    public const string Pending = "PENDING";
    /// <summary>ISSUED.</summary>
    public const string Issued = "ISSUED";
    /// <summary>FAILED.</summary>
    public const string Failed = "FAILED";
    /// <summary>EXPIRED.</summary>
    public const string Expired = "EXPIRED";
}

/// <summary><c>GET /session/{id}</c>-ийн <c>tokenCertificate</c> блок.</summary>
public sealed record TokenCertSessionBlock
{
    /// <summary>Төлөв.</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";
    /// <summary>FAILED үеийн код.</summary>
    [JsonPropertyName("errorCode")]
    public string? ErrorCode { get; init; }
    /// <summary>AUTH гэрчилгээний serial (hex).</summary>
    [JsonPropertyName("authSerialHex")]
    public string? AuthSerialHex { get; init; }
    /// <summary>SIGN гэрчилгээний serial (hex).</summary>
    [JsonPropertyName("signSerialHex")]
    public string? SignSerialHex { get; init; }
}

/// <summary>«Миний QR» session-ий presentation блок (ШАЛГААГҮЙ JWS).</summary>
public sealed record SessionPresentation
{
    /// <summary>Иргэний PS256 JWS.</summary>
    [JsonPropertyName("jws")]
    public string Jws { get; init; } = "";
}

/// <summary>
/// Session poll-ийн нэгтгэсэн үр дүн (validator-т орох түүхий материал). Хариунд байхгүй мөр талбар "" байна. Задлалт
/// (<c>GET /session/{id}</c>) дараагийн багцад.
/// </summary>
public sealed record SessionResult
{
    /// <summary>RUNNING | COMPLETE.</summary>
    public string State { get; init; } = "";
    /// <summary>endResult.</summary>
    public string EndResult { get; init; } = "";
    /// <summary>Төхөөрөмжийн documentNumber.</summary>
    public string DocumentNumber { get; init; } = "";
    /// <summary>Иргэний X.509 гэрчилгээ (DER, base64).</summary>
    public string CertificateDerB64 { get; init; } = "";
    /// <summary>certificateLevel.</summary>
    public string CertificateLevel { get; init; } = "";
    /// <summary>Гарын үсэг (base64).</summary>
    public string SignatureValueB64 { get; init; } = "";
    /// <summary>Гарын үсгийн алгоритм.</summary>
    public string SignatureAlgorithm { get; init; } = "";
    /// <summary>ACSP_V2 | RAW_DIGEST_SIGNATURE.</summary>
    public string SignatureProtocol { get; init; } = "";
    /// <summary>ACSP_V2: серверийн санамсаргүй утга (base64).</summary>
    public string ServerRandom { get; init; } = "";
    /// <summary>ACSP_V2: утасны challenge (base64url).</summary>
    public string UserChallenge { get; init; } = "";
    /// <summary>Урсгал.</summary>
    public string FlowType { get; init; } = "";
    /// <summary>ACSP_V2 payload-д зурагдсан initialCallbackUrl; null = хариунд талбар алга (хуучин CA).</summary>
    public string? InitialCallbackUrl { get; init; }
    /// <summary>rsassa-pss параметр.</summary>
    public SignatureAlgorithmParameters? SignatureAlgorithmParameters { get; init; }
    /// <summary>interactionTypeUsed.</summary>
    public string InteractionTypeUsed { get; init; } = "";
    /// <summary>Байгууллагын нэрийн өмнөөс бол СЕРВЕР шалгасан блок; null = хувь хүн.</summary>
    public OrgResult? OnBehalfOf { get; init; }
    /// <summary>COMPLETE+OK auth session-ий person блок; ГАРЫН ҮСЭГТ ОРДОГГҮЙ.</summary>
    public Person? Person { get; init; }
    /// <summary>Токены гэрчилгээ олголтын блок.</summary>
    public TokenCertSessionBlock? TokenCertificate { get; init; }
    /// <summary>«Миний QR» presentation.</summary>
    public SessionPresentation? Presentation { get; init; }
    /// <summary>Серверийн хариуны түүхий JSON.</summary>
    public JsonElement? Raw { get; init; }
}

/// <summary>RP-ийн таних тэмдэг + API secret.</summary>
/// <param name="RpUuid">Бүртгэлтэй RP UUID (relyingPartyUUID).</param>
/// <param name="RpName">Дэд системийн нэр, ≤ 120 тэмдэгт.</param>
/// <param name="ApiSecret">rp_sk_…; зөвхөн backend-д.</param>
public sealed record EidCredentials(string RpUuid, string RpName, string ApiSecret)
{
    /// <summary>Secret-ийг логт гаргахгүй.</summary>
    public override string ToString() => "EidCredentials { RpUuid = " + RpUuid + ", RpName = " + RpName + ", ApiSecret = *** }";
}

/// <summary>Session-ий хугацааны туслах.</summary>
public static class SessionTimes
{
    /// <summary>
    /// CA-ийн SIGNATURE ба CERTIFICATE_CHOICE session-ий анхдагч хүчинтэй хугацаа (600 с). CA 2026-10-14-өөс start хариунд
    /// expiresAt буцаадаг — хуучин CA үед л үүгээр тооцоолно.
    /// </summary>
    public static readonly TimeSpan DefaultSignSessionTtl = TimeSpan.FromSeconds(600);

    /// <summary>Хүсэлт илгээхээс ӨМНӨХ цаг + ttl (ttl ≤ 0 бол <see cref="DefaultSignSessionTtl"/>) — консерватив.</summary>
    public static DateTimeOffset SessionExpiry(DateTimeOffset sentAt, TimeSpan ttl) =>
        sentAt + (ttl <= TimeSpan.Zero ? DefaultSignSessionTtl : ttl);
}
