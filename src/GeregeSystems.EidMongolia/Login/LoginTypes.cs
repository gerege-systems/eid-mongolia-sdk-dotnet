using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace GeregeSystems.EidMongolia.Login;

/// <summary>Нэвтрэлтийн горим (Go <c>eidlogin.Mode</c>, TS <c>EidLoginMode</c>).</summary>
public static class EidLoginModes
{
    /// <summary>Desktop QR.</summary>
    public const string Qr = "qr";
    /// <summary>Регистрийн дугаараар утас руу мэдэгдэл.</summary>
    public const string Push = "push";
    /// <summary>Утасны хөтчөөс eID апп руу (callback-тай).</summary>
    public const string Web2App = "web2app";
}

/// <summary>
/// Handler-ийн хөтөч рүү буцаах алдааны код (<c>{"error": …}</c>; Go/TS-тэй ижил 12 код, ижил HTTP статус). Callback-ийн
/// <c>?eid_error=</c>-д эдгээрээс гадна <c>expired</c>, <c>unbound</c>, <c>not_complete</c>, <c>VALIDATION</c> ба eID-ийн
/// endResult орно.
/// </summary>
public static class EidLoginErrors
{
    /// <summary>403 — <c>Sec-Fetch-Site</c> нь cross-site.</summary>
    public const string CrossSite = "cross_site";
    /// <summary>405 — буруу method (start-д GET зөвхөн <c>?mode=web2app</c>).</summary>
    public const string MethodNotAllowed = "method_not_allowed";
    /// <summary>415 — POST start JSON биш.</summary>
    public const string JsonRequired = "json_required";
    /// <summary>400 — JSON бие задарсангүй (эсвэл 4 KiB-ээс их).</summary>
    public const string InvalidBody = "invalid_body";
    /// <summary>400 — mode нь qr | push | web2app биш.</summary>
    public const string InvalidMode = "invalid_mode";
    /// <summary>400 — CallbackUrl тохируулаагүй тул web2app хаалттай.</summary>
    public const string Web2AppNotConfigured = "web2app_not_configured";
    /// <summary>400 — push-ийн idCode буруу хэлбэртэй.</summary>
    public const string InvalidId = "invalid_id";
    /// <summary>429 — хязгаарт хүрсэн (Retry-After: 60).</summary>
    public const string RateLimited = "rate_limited";
    /// <summary>503 — санах ойн сан дүүрсэн (Retry-After: 30).</summary>
    public const string Busy = "busy";
    /// <summary>502 — eID API-тай холбогдож чадсангүй (5xx, сүлжээ, 401/403, proxy).</summary>
    public const string EidUnavailable = "eid_unavailable";
    /// <summary>500 — дотоод алдаа (store, OnSuccess).</summary>
    public const string Internal = "internal";
    /// <summary>404 — замын сүүлийн хэсэг start | status | callback биш.</summary>
    public const string NotFound = "not_found";
}

/// <summary>Аудитын үйл явдлын төрөл (<see cref="EidLoginOptions.OnEvent"/>; Go <c>EventKind</c>, TS <c>EidLoginEventKind</c>).</summary>
public static class EidLoginEventKinds
{
    /// <summary>
    /// Push start амжилттай хариулсан (meta: mode, pushKey, decoy). decoy=true бол eID дугаарыг татгалзаж утас руу юу ч
    /// очоогүй — хөтөч рүү хэзээ ч илэрхийлэгдэхгүй, зөвхөн аудитад.
    /// </summary>
    public const string PushSent = "push_sent";
    /// <summary>Push хязгаарт хүрсэн, 429 (meta: mode, pushKey); sessionId null.</summary>
    public const string PushLimited = "push_limited";
    /// <summary>Иргэн утсан дээрээ татгалзсан (endResult USER_REFUSED*; meta: mode, endResult).</summary>
    public const string Refused = "refused";
    /// <summary>eID session хугацаа дууссан (endResult TIMEOUT эсвэл eID-д олдохгүй; meta: mode).</summary>
    public const string Expired = "expired";
    /// <summary>COMPLETE/OK боловч баталгаажуулалт унасан (meta: mode, reason = validation | revoked | revocation_unavailable).</summary>
    public const string Unverified = "unverified";
    /// <summary>Web2App callback эхлүүлсэн хөтчийн session-тэй холбогдоогүй (meta: mode, reason = unbound).</summary>
    public const string FlowRefused = "flow_refused";
    /// <summary>Иргэн баталгаажиж OnSuccess дуудагдсан (meta: mode, flow, revocation).</summary>
    public const string Success = "success";
    /// <summary>Бусад endResult (WRONG_VC, DOCUMENT_UNUSABLE г.м.; meta: mode, endResult).</summary>
    public const string Failed = "failed";
}

/// <summary>
/// Аудитын үйл явдал. Meta-д токен/нууц, регистрийн дугаар (PII) орохгүй: push-д pushKey =
/// HMAC-SHA256(<see cref="EidLoginOptions.AuditKey"/>, дугаар)-ын эхний 16 байтын hex.
/// </summary>
/// <param name="Kind"><see cref="EidLoginEventKinds"/>.</param>
/// <param name="SessionId">RP-API session id; push_limited-д null.</param>
/// <param name="Meta">mode, pushKey, decoy, reason, endResult, flow, revocation.</param>
public sealed record EidLoginEvent(string Kind, string? SessionId, IReadOnlyDictionary<string, object?> Meta);

/// <summary>Баталгаажсан иргэн (<see cref="EidLoginOptions.OnSuccess"/>-д; Go <c>Identity</c>, TS <c>EidLoginIdentity</c>).</summary>
public sealed record EidLoginIdentity
{
    /// <summary>RP-API session id — аудит, эсвэл энэ нэвтрэлтийг дараагийн алхамтай (гарын үсэг г.м.) холбоход.</summary>
    public string SessionId { get; init; } = "";

    /// <summary>Гэрчилгээний SERIALNUMBER (PNOMN-&lt;иргэний дугаар&gt;). Хэрэглэгчийг ҮҮГЭЭР таньна (нэрээр биш).</summary>
    public string Etsi { get; init; } = "";

    /// <summary>PNOMN-гүй иргэний дугаар; ETSI өөр хэлбэртэй бол null.</summary>
    public string? CivilId { get; init; }

    /// <summary>Гэрчилгээний нэр (латин).</summary>
    public string GivenName { get; init; } = "";

    /// <summary>Гэрчилгээний овог (латин).</summary>
    public string Surname { get; init; } = "";

    /// <summary>Гэрчилгээний улс.</summary>
    public string Country { get; init; } = "";

    /// <summary>
    /// Нэвтэрсэн төхөөрөмжийн UUID (RP-API documentNumber; иргэний бичиг баримтын дугаар биш) — Sign-ийн *ByDocument-аар
    /// ижил төхөөрөмж рүү гарын үсэг.
    /// </summary>
    public string DocumentNumber { get; init; } = "";

    /// <summary>Үр дүнгийн түвшин (<see cref="CertificateLevels"/>).</summary>
    public string CertificateLevel { get; init; } = "";

    /// <summary>Нэвтрэлтийн гэрчилгээ (ValidateAuth-аар гинж шалгагдсан).</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Гэрчилгээ (DER, base64).</summary>
    public string CertificateDerB64 { get; init; } = "";

    /// <summary>Гарын үсэг зурагдсан урсгал: QR | Notification | Web2App (<see cref="FlowTypes"/>).</summary>
    public string FlowType { get; init; } = "";

    /// <summary>Session-ий person блок (кирилл нэр г.м.) — гэрчилгээтэй таарсан үед л; эс бөгөөс null.</summary>
    public Person? Person { get; init; }

    /// <summary>
    /// Цуцлалтын шалгалтын дүн: Good, Unchecked (OCSP хариугүй, soft-fail-ээр зөвшөөрөв) эсвэл Skipped
    /// (<see cref="EidLoginOptions.DisableRevocation"/>). Аудитад хадгал.
    /// </summary>
    public RevocationStatus Revocation { get; init; }
}

/// <summary>QR/Web2App холбоос угсрах материал. <see cref="Secret"/> нь ЗӨВХӨН серверт.</summary>
public sealed record EidLoginLink
{
    /// <summary>deviceLinkBase.</summary>
    [JsonPropertyName("base")]
    public string Base { get; init; } = "";

    /// <summary>sessionToken.</summary>
    [JsonPropertyName("token")]
    public string Token { get; init; } = "";

    /// <summary>sessionSecret (стандарт base64) — authCode-ийн HMAC түлхүүр.</summary>
    [JsonPropertyName("secret")]
    public string Secret { get; init; } = "";

    /// <summary>Start хариуг хүлээн авсан мөч (QR-ийн elapsedSeconds).</summary>
    [JsonPropertyName("receivedAt")]
    public DateTimeOffset ReceivedAt { get; init; }

    /// <summary>ISO 639-2 (mon, eng).</summary>
    [JsonPropertyName("lang")]
    public string Lang { get; init; } = "";
}

/// <summary>
/// Серверт хадгалах нэвтрэлтийн төлөв (Go <c>Tx</c>, TS <c>EidLoginTx</c>); System.Text.Json-оор хадгалж болно. Хөтөч
/// зөвхөн HttpOnly cookie (<c>&lt;sessionId&gt;.&lt;binding&gt;</c>) авна.
/// </summary>
public sealed record EidLoginTx
{
    /// <summary>RP-API session id.</summary>
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = "";

    /// <summary>Cookie-ийн binding-ийн SHA-256 (hex); түүхий утга зөвхөн хөтчид.</summary>
    [JsonPropertyName("bindingHash")]
    public string BindingHash { get; init; } = "";

    /// <summary><see cref="EidLoginModes"/>.</summary>
    [JsonPropertyName("mode")]
    public string Mode { get; init; } = "";

    /// <summary>Нэвтрэлт дуусах мөч.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Баталгаажуулах код (зөвхөн харуулна).</summary>
    [JsonPropertyName("vc")]
    public string Vc { get; init; } = "";

    /// <summary>ACSP_V2 контекст (decoy-д null).</summary>
    [JsonPropertyName("acsp")]
    public AcspContext? Acsp { get; init; }

    /// <summary>QR/Web2App холбоосын материал; push-д null.</summary>
    [JsonPropertyName("link")]
    public EidLoginLink? Link { get; init; }

    /// <summary>eID татгалзсан push-ийн оронд өгсөн хуурмаг session (eID-д байхгүй; хэзээ ч дуусахгүй). Зөвхөн серверт.</summary>
    [JsonPropertyName("decoy")]
    public bool Decoy { get; init; }
}

/// <summary><see cref="EidLoginOptions.OnSuccess"/>-ийн хариу.</summary>
public sealed record EidLoginSuccess
{
    /// <summary>Нэвтэрсний дараах хуудас. Callback (Web2App)-д null бол <see cref="EidLoginOptions.SuccessRedirect"/>.</summary>
    public string? Redirect { get; init; }

    /// <summary>QR/push-ийн status хариунд <c>data</c> болж хөтчид очно (JSON, camelCase). Нууц бүү оруул.</summary>
    public object? Data { get; init; }

    /// <summary>
    /// Хариунд нэмэх header (ж: таны session-ийн <c>Set-Cookie</c> — нэмэгдэнэ; бусад нэр ижил header-ийг солино).
    /// ASP.NET Core adapter-т HttpContext.Response.Cookies-ийг шууд хэрэглэж болно.
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, string>>? Headers { get; init; }
}

/// <summary>Хүсэлтийн хүрээ — OnSuccess-д.</summary>
/// <param name="Request">Хүсэлт.</param>
/// <param name="Mode"><see cref="EidLoginModes"/>.</param>
public sealed record EidLoginContext(EidLoginRequest Request, string Mode);

/// <summary>Framework-аас хамааралгүй хүсэлт (TS <c>EidLoginRequest</c>).</summary>
public sealed class EidLoginRequest
{
    private static readonly IReadOnlyDictionary<string, string> NoHeaders = new Dictionary<string, string>();

    /// <summary>HTTP method (GET, POST …; том үсгээр).</summary>
    public required string Method { get; init; }

    /// <summary>Зам + query (<c>/auth/eid/status?…</c>) эсвэл бүтэн URL.</summary>
    public required string Url { get; init; }

    /// <summary>
    /// Header (нэр → утга; нэрийг том жижиг үсэг ялгахгүй хайна). Олон утгыг нэгтгэ: Cookie — "; ", бусад — ", ".
    /// </summary>
    public IReadOnlyDictionary<string, string> Headers { get; init; } = NoHeaders;

    /// <summary>POST-ийн түүхий бие (UTF-8 текст); 4 KiB-ээс их бол <c>invalid_body</c>.</summary>
    public string? Body { get; init; }

    /// <summary>
    /// Холболтын peer IP (TCP). <see cref="EidLoginClientIp.RemoteAddress"/> үүнийг уншина; proxy-ийн ард бол proxy-ийн IP.
    /// </summary>
    public string? RemoteIp { get; init; }

    /// <summary>Хост framework-ийн хүсэлтийн объект (ж: ASP.NET Core HttpContext) — handler хөндөхгүй.</summary>
    public object? HostContext { get; init; }
}

/// <summary>Handler-ийн хариу (статус, header-ууд дарааллаараа, бие).</summary>
public sealed class EidLoginResponse
{
    /// <summary>Шинэ хариу.</summary>
    public EidLoginResponse(int status, IReadOnlyList<KeyValuePair<string, string>> headers, string body)
    {
        Status = status;
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        Body = body ?? "";
    }

    /// <summary>HTTP статус.</summary>
    public int Status { get; }

    /// <summary>Header-ууд (Set-Cookie хэд хэдэн удаа байж болно).</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

    /// <summary>Бие (JSON эсвэл redirect-д "").</summary>
    public string Body { get; }

    /// <summary>Нэрээр эхний header (том жижиг үсэг ялгахгүй); алга бол null.</summary>
    public string? Header(string name)
    {
        foreach (var h in Headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }
        return null;
    }

    /// <summary>Нэрээр бүх header-ийн утга.</summary>
    public IEnumerable<string> HeaderValues(string name)
    {
        foreach (var h in Headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                yield return h.Value;
            }
        }
    }
}

/// <summary>Логийн түвшин (<see cref="EidLoginOptions.Log"/>).</summary>
public enum EidLoginLogLevel
{
    /// <summary>Анхааруулга (decoy, soft-fail, тохиргоо).</summary>
    Warning,
    /// <summary>Алдаа (eID API, store).</summary>
    Error,
}

/// <summary>Дотоод логийн бичлэг — иргэний мэдээлэл (регистр, нэр) орохгүй.</summary>
/// <param name="Level">Түвшин.</param>
/// <param name="Message">Монгол тайлбар.</param>
/// <param name="Exception">Шалтгаан (байвал).</param>
public sealed record EidLoginLogEntry(EidLoginLogLevel Level, string Message, Exception? Exception = null);
