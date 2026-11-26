using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Иргэний PKI самбар (Go <c>PersonService</c>, TS <c>PersonApi</c>; CA docs/EID_PERSON_PKI.md): гэрчилгээ, төхөөрөмж, үйл
/// ажиллагаа, нэгдсэн тоо, асран хамгаалж буй хүүхдүүд. RP-д PKI_READ эрх (админ тухайлан олгоно) БА иргэн сүүлийн 24
/// цагт танай RP-ээр амжилттай нэвтэрсэн байх ёстой — эс бөгөөс <see cref="EidForbiddenException"/> (403); иргэн олдохгүй
/// бол <see cref="EidApiException"/> 404. Хариу бүрийн <c>Raw</c> — серверийн түүхий JSON.
/// </summary>
public sealed class PersonService
{
    private readonly EidClient _c;

    internal PersonService(EidClient c) => _c = c;

    /// <summary><c>GET /certificates/etsi/{personEtsi}</c>: иргэний бүх гэрчилгээ + статусын тоолол.</summary>
    public async Task<PersonCertificates> CertificatesAsync(string personEtsi, CancellationToken ct = default)
    {
        var (r, raw) = await GetAsync<PersonCertificates>(RpRoutes.PersonCertificates.Expand(personEtsi), ct).ConfigureAwait(false);
        return r with { Certificates = r.Certificates ?? Array.Empty<PersonCertificate>(), Raw = raw };
    }

    /// <summary><c>GET /devices/etsi/{personEtsi}</c>: иргэний холбоотой төхөөрөмжүүд (идэвхтэй + идэвхгүй).</summary>
    public async Task<PersonDevices> DevicesAsync(string personEtsi, CancellationToken ct = default)
    {
        var (r, raw) = await GetAsync<PersonDevices>(RpRoutes.PersonDevices.Expand(personEtsi), ct).ConfigureAwait(false);
        return r with { Devices = r.Devices ?? Array.Empty<PersonDevice>(), Raw = raw };
    }

    /// <summary>
    /// <c>GET /rp/activity/etsi/{personEtsi}</c>: иргэний үйл ажиллагааны түүх (RP-scoped). <paramref name="query"/> null =
    /// серверийн анхдагч (limit 20, offset 0, бүх flow); тэг утгууд илгээгдэхгүй.
    /// </summary>
    public async Task<PersonActivity> ActivityAsync(string personEtsi, ActivityQuery? query = null, CancellationToken ct = default)
    {
        var path = RpRoutes.PersonActivity.Expand(personEtsi);
        if (query is not null)
        {
            // Go url.Values.Encode: түлхүүрээр эрэмбэлсэн (flow, limit, offset).
            var q = new List<string>();
            if (!string.IsNullOrEmpty(query.Flow))
            {
                q.Add("flow=" + Uri.EscapeDataString(query.Flow));
            }
            if (query.Limit > 0)
            {
                q.Add("limit=" + query.Limit.ToString(CultureInfo.InvariantCulture));
            }
            if (query.Offset > 0)
            {
                q.Add("offset=" + query.Offset.ToString(CultureInfo.InvariantCulture));
            }
            if (q.Count > 0)
            {
                path += "?" + string.Join("&", q);
            }
        }
        var (r, raw) = await GetAsync<PersonActivity>(path, ct).ConfigureAwait(false);
        return r with { Sessions = r.Sessions ?? Array.Empty<ActivityItem>(), Raw = raw };
    }

    /// <summary><c>GET /person/summary/etsi/{personEtsi}</c>: самбарын нэгдсэн тоо (нэг дуудлагаар).</summary>
    public async Task<PersonSummary> SummaryAsync(string personEtsi, CancellationToken ct = default)
    {
        var (r, raw) = await GetAsync<PersonSummary>(RpRoutes.PersonSummary.Expand(personEtsi), ct).ConfigureAwait(false);
        return r with { Raw = raw };
    }

    /// <summary><c>GET /person/children/etsi/{personEtsi}</c>: иргэний асран хамгаалж буй хүүхдүүд (зөвхөн унших).</summary>
    public async Task<PersonChildren> ChildrenAsync(string personEtsi, CancellationToken ct = default)
    {
        var (r, raw) = await GetAsync<PersonChildren>(RpRoutes.PersonChildren.Expand(personEtsi), ct).ConfigureAwait(false);
        return r with { Children = r.Children ?? Array.Empty<PersonChild>(), Raw = raw };
    }

    /// <summary>Түүхий хариуг задлаад Raw-тай буцаана (Go <c>PersonService.get</c>); хоосон бие → хоосон бичлэг.</summary>
    private async Task<(T Value, JsonElement? Raw)> GetAsync<T>(string path, CancellationToken ct) where T : class, new()
    {
        var raw = await _c.Http.GetRawAsync(path, null, ct).ConfigureAwait(false);
        return (EidHttp.Decode<T>(raw, "GET", path) ?? new T(), RawJson.Element(raw));
    }
}

/// <summary>Токенд холбогдсон байгууллага (<see cref="PersonCertificate.Organization"/>, <see cref="TokenCertResult.Organization"/>).</summary>
public sealed record TokenOrganization
{
    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("etsi")]
    public string Etsi { get; init; } = "";

    /// <summary>Нэр.</summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";
}

/// <summary>Иргэний нэг гэрчилгээ.</summary>
public sealed record PersonCertificate
{
    /// <summary>Төхөөрөмжийн documentNumber.</summary>
    [JsonPropertyName("documentNumber")]
    public string DocumentNumber { get; init; } = "";

    /// <summary>AUTH | SIGN | SEAL.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "";

    /// <summary>MOBILE | TOKEN | HSM (түлхүүрийн байршил).</summary>
    [JsonPropertyName("keyMedium")]
    public string KeyMedium { get; init; } = "";

    /// <summary>Serial.</summary>
    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; init; } = "";

    /// <summary>certificateLevel.</summary>
    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";

    /// <summary>VALID | REVOKED | EXPIRED | SUSPENDED.</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    /// <summary>Хүчинтэй эхлэх.</summary>
    [JsonPropertyName("notBefore")]
    public DateTimeOffset NotBefore { get; init; }

    /// <summary>Хүчинтэй дуусах.</summary>
    [JsonPropertyName("notAfter")]
    public DateTimeOffset NotAfter { get; init; }

    /// <summary>Олгогчийн DN.</summary>
    [JsonPropertyName("issuerDn")]
    public string IssuerDn { get; init; } = "";

    /// <summary>Олгосон мөч; хуучин CA-д null.</summary>
    [JsonPropertyName("issuedAt")]
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Цуцалсан мөч: REVOKED, мөн сунгалтаар солигдсон (SUSPENDED, RevocationReason "superseded") мөрд.</summary>
    [JsonPropertyName("revokedAt")]
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>RFC 5280 CRLReason-ийн нэр (keyCompromise, superseded г.м.); null/"" = цуцлаагүй.</summary>
    [JsonPropertyName("revocationReason")]
    public string? RevocationReason { get; init; }

    /// <summary>base64 DER (нийтийн артефакт).</summary>
    [JsonPropertyName("certValue")]
    public string? CertValue { get; init; }

    /// <summary>TOKEN мөрөнд токенд холбогдсон байгууллага; хувийн токенд null.</summary>
    [JsonPropertyName("organization")]
    public TokenOrganization? Organization { get; init; }

    /// <summary>TOKEN мөрөнд USB токены серийн дугаар; MOBILE/HSM мөр ба хуучин CA-д null.</summary>
    [JsonPropertyName("tokenSerial")]
    public string? TokenSerial { get; init; }
}

/// <summary>Гэрчилгээний статусын тоолол.</summary>
public sealed record CertCounts
{
    /// <summary>VALID.</summary>
    [JsonPropertyName("valid")]
    public int Valid { get; init; }

    /// <summary>REVOKED.</summary>
    [JsonPropertyName("revoked")]
    public int Revoked { get; init; }

    /// <summary>EXPIRED.</summary>
    [JsonPropertyName("expired")]
    public int Expired { get; init; }

    /// <summary>SUSPENDED.</summary>
    [JsonPropertyName("suspended")]
    public int Suspended { get; init; }

    /// <summary>Нийт.</summary>
    [JsonPropertyName("total")]
    public int Total { get; init; }
}

/// <summary><c>GET /certificates/etsi/{personEtsi}</c>-ийн хариу.</summary>
public sealed record PersonCertificates
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";

    /// <summary>Тоолол.</summary>
    [JsonPropertyName("counts")]
    public CertCounts Counts { get; init; } = new();

    /// <summary>Гэрчилгээнүүд.</summary>
    [JsonPropertyName("certificates")]
    public IReadOnlyList<PersonCertificate> Certificates { get; init; } = Array.Empty<PersonCertificate>();

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>Иргэний холбоотой төхөөрөмж.</summary>
public sealed record PersonDevice
{
    /// <summary>Төхөөрөмжийн ID.</summary>
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; init; }

    /// <summary>documentNumber.</summary>
    [JsonPropertyName("documentNumber")]
    public string DocumentNumber { get; init; } = "";

    /// <summary>APNS | FCM.</summary>
    [JsonPropertyName("platform")]
    public string? Platform { get; init; }

    /// <summary>Push topic.</summary>
    [JsonPropertyName("pushTopic")]
    public string? PushTopic { get; init; }

    /// <summary>Бүртгэсэн цаг.</summary>
    [JsonPropertyName("enrolledAt")]
    public DateTimeOffset EnrolledAt { get; init; }

    /// <summary>Идэвхтэй эсэх.</summary>
    [JsonPropertyName("active")]
    public bool Active { get; init; }

    /// <summary>Идэвхгүй болсон цаг.</summary>
    [JsonPropertyName("deactivatedAt")]
    public DateTimeOffset? DeactivatedAt { get; init; }
}

/// <summary><c>GET /devices/etsi/{personEtsi}</c>-ийн хариу.</summary>
public sealed record PersonDevices
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";

    /// <summary>Төхөөрөмжүүд.</summary>
    [JsonPropertyName("devices")]
    public IReadOnlyList<PersonDevice> Devices { get; init; } = Array.Empty<PersonDevice>();

    /// <summary>Идэвхтэй тоо.</summary>
    [JsonPropertyName("activeCount")]
    public int ActiveCount { get; init; }

    /// <summary>Нийт.</summary>
    [JsonPropertyName("total")]
    public int Total { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>
/// Иргэний үйл ажиллагааны нэг бичлэг (kind/reason-ийн хүснэгт: EID_PERSON_PKI §Activity; шинэ код нэмэгдэж болно —
/// танихгүйг ерөнхий текстээр харуул).
/// </summary>
public sealed record ActivityItem
{
    /// <summary>ID.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; init; }

    /// <summary>Session ID.</summary>
    [JsonPropertyName("sessionId")]
    public string? SessionId { get; init; }

    /// <summary>AUTH | SIGN | PIN_CHECK | ENROLL | TOKEN_AUTH | …</summary>
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = "";

    /// <summary>AUTHENTICATION | SIGNATURE (зөвхөн AUTH/SIGN).</summary>
    [JsonPropertyName("flow")]
    public string? Flow { get; init; }

    /// <summary>OK | DENIED | FAILED.</summary>
    [JsonPropertyName("outcome")]
    public string Outcome { get; init; } = "";

    /// <summary>Шалтгаан.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    /// <summary>PIN slot.</summary>
    [JsonPropertyName("pinSlot")]
    public string? PinSlot { get; init; }

    /// <summary>endResult.</summary>
    [JsonPropertyName("endResult")]
    public string? EndResult { get; init; }

    /// <summary>RP-ийн нэр.</summary>
    [JsonPropertyName("rpName")]
    public string? RpName { get; init; }

    /// <summary>Дэд системийн нэр.</summary>
    [JsonPropertyName("subsystemName")]
    public string? SubsystemName { get; init; }

    /// <summary>Баримтын текст.</summary>
    [JsonPropertyName("docText")]
    public string? DocText { get; init; }

    /// <summary>interactionType.</summary>
    [JsonPropertyName("interactionType")]
    public string? InteractionType { get; init; }

    /// <summary>documentNumber.</summary>
    [JsonPropertyName("documentNumber")]
    public string? DocumentNumber { get; init; }

    /// <summary>Клиентийн IP.</summary>
    [JsonPropertyName("clientIp")]
    public string? ClientIp { get; init; }

    /// <summary>Цаг.</summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Байгууллагын нэрийн өмнөөс бол байгууллагын нэр.</summary>
    [JsonPropertyName("onBehalfOfName")]
    public string? OnBehalfOfName { get; init; }
}

/// <summary>Flow тус бүрийн session-ий тоо.</summary>
public sealed record ActivityCounts
{
    /// <summary>AUTHENTICATION.</summary>
    [JsonPropertyName("authentication")]
    public int Authentication { get; init; }

    /// <summary>SIGNATURE.</summary>
    [JsonPropertyName("signature")]
    public int Signature { get; init; }
}

/// <summary><c>GET /rp/activity/etsi/{personEtsi}</c>-ийн хариу (RP-scoped; eID портал — бүрэн түүх).</summary>
public sealed record PersonActivity
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";

    /// <summary>Тоолол.</summary>
    [JsonPropertyName("counts")]
    public ActivityCounts Counts { get; init; } = new();

    /// <summary>Бичлэгүүд.</summary>
    [JsonPropertyName("sessions")]
    public IReadOnlyList<ActivityItem> Sessions { get; init; } = Array.Empty<ActivityItem>();

    /// <summary>Нийт.</summary>
    [JsonPropertyName("total")]
    public int Total { get; init; }

    /// <summary>Limit.</summary>
    [JsonPropertyName("limit")]
    public int Limit { get; init; }

    /// <summary>Offset.</summary>
    [JsonPropertyName("offset")]
    public int Offset { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary><see cref="PersonService.ActivityAsync"/>-ийн шүүлт. Тэг утга = серверийн анхдагч.</summary>
public sealed record ActivityQuery
{
    /// <summary>"AUTHENTICATION" | "SIGNATURE" | null (бүгд).</summary>
    public string? Flow { get; init; }

    /// <summary>1–200 (сервер хязгаарлана); 0 = анхдагч.</summary>
    public int Limit { get; init; }

    /// <summary>0 = эхнээс.</summary>
    public int Offset { get; init; }
}

/// <summary>
/// <c>GET /person/summary/etsi/{personEtsi}</c>: самбарын нэгдсэн тоо. Нэршил <see cref="Person"/>-тэй ижил (LastName =
/// ЭЦГИЙН нэр, FamilyName = УРГИЙН овог).
/// </summary>
public sealed record PersonSummary
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";

    /// <summary>Нэр.</summary>
    [JsonPropertyName("firstName")]
    public string? FirstName { get; init; }

    /// <summary>Эцгийн нэр.</summary>
    [JsonPropertyName("lastName")]
    public string? LastName { get; init; }

    /// <summary>Ургийн овог.</summary>
    [JsonPropertyName("familyName")]
    public string? FamilyName { get; init; }

    /// <summary>ISO 3166-1 alpha-3 (гэрчилгээний улс БИШ); мэдэгдэхгүй бол null.</summary>
    [JsonPropertyName("nationality")]
    public string? Nationality { get; init; }

    /// <summary>Гэрчилгээний тоолол.</summary>
    [JsonPropertyName("certificates")]
    public CertCounts Certificates { get; init; } = new();

    /// <summary>Үйл ажиллагааны тоолол.</summary>
    [JsonPropertyName("activity")]
    public ActivityCounts Activity { get; init; } = new();

    /// <summary>Идэвхтэй төхөөрөмж.</summary>
    [JsonPropertyName("devicesActive")]
    public int DevicesActive { get; init; }

    /// <summary>Нийт төхөөрөмж.</summary>
    [JsonPropertyName("devicesTotal")]
    public int DevicesTotal { get; init; }

    /// <summary>Төлөөллийн тоо.</summary>
    [JsonPropertyName("representationCount")]
    public int RepresentationCount { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>Асран хамгаалж буй хүүхэд.</summary>
public sealed record PersonChild
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("etsi")]
    public string Etsi { get; init; } = "";

    /// <summary>Регистр.</summary>
    [JsonPropertyName("regNo")]
    public string RegNo { get; init; } = "";

    /// <summary>«Овог Нэр».</summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    /// <summary>YYYY-MM-DD.</summary>
    [JsonPropertyName("birthDate")]
    public string? BirthDate { get; init; }

    /// <summary>Хүүхэд утсандаа eID бүртгүүлсэн эсэх.</summary>
    [JsonPropertyName("registered")]
    public bool Registered { get; init; }

    /// <summary>Гэрчилгээний дуусах хугацаа (18 нас); бүртгэлгүй бол null.</summary>
    [JsonPropertyName("certNotAfter")]
    public DateTimeOffset? CertNotAfter { get; init; }
}

/// <summary><c>GET /person/children/etsi/{personEtsi}</c>-ийн хариу.</summary>
public sealed record PersonChildren
{
    /// <summary>Хүүхдүүд.</summary>
    [JsonPropertyName("children")]
    public IReadOnlyList<PersonChild> Children { get; init; } = Array.Empty<PersonChild>();

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}
