using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Иргэний төлөөлж чадах (ACTIVE, хугацаа хүчинтэй) байгууллагууд ба тэдгээрийн RP тамганы эрхүүд (Go
/// <c>OrganizationService</c>, TS <c>OrganizationApi</c>). Иргэн сүүлийн 24 цагт танай RP-ээр нэвтэрсэн байх ёстой (үгүй
/// бол <see cref="EidForbiddenException"/> 403).
/// </summary>
public sealed class OrganizationService
{
    private readonly EidClient _c;

    internal OrganizationService(EidClient c) => _c = c;

    /// <summary>
    /// <c>GET /organization/representations/etsi/{personEtsi}</c>: OnBehalfOf-оос өмнө иргэнд сонгуулах байгууллагууд. Сонголт
    /// нь итгэх эх биш — сервер session эхлэхэд дахин шалгана. Хариунд personEtsi алга бол оролтын утга; representations
    /// null бол хоосон жагсаалт.
    /// </summary>
    public async Task<RepresentationsResponse> GetRepresentationsAsync(string personEtsi, CancellationToken ct = default)
    {
        var path = RpRoutes.OrgRepresentations.Expand(personEtsi);
        var raw = await _c.Http.GetRawAsync(path, null, ct).ConfigureAwait(false);
        var r = EidHttp.Decode<RepresentationsResponse>(raw, "GET", path) ?? new RepresentationsResponse();
        return r with
        {
            PersonEtsi = string.IsNullOrEmpty(r.PersonEtsi) ? personEtsi : r.PersonEtsi,
            Representations = r.Representations ?? Array.Empty<Representation>(),
            Raw = RawJson.Element(raw),
        };
    }

    /// <summary>
    /// <c>GET /organization/seal-grants/etsi/{personEtsi}</c> (PKI_READ эрх; Go <c>OrganizationService.SealGrants</c>): иргэн
    /// улсын бүртгэлээр Гүйцэтгэх захирал байгаа байгууллага бүр ба тэдгээрийн амьд (APPROVED / PENDING) RP тамганы эрхүүд
    /// (зөвхөн унших). Бусад RP-ийн эрхийг CA зөвхөн өөрийн порталд харуулдаг. Иргэн олдохгүй бол
    /// <see cref="EidApiException"/> 404.
    /// </summary>
    public async Task<OrgSealGrantsResponse> SealGrantsAsync(string personEtsi, CancellationToken ct = default)
    {
        var path = RpRoutes.OrgSealGrants.Expand(personEtsi);
        var raw = await _c.Http.GetRawAsync(path, null, ct).ConfigureAwait(false);
        var r = EidHttp.Decode<OrgSealGrantsResponse>(raw, "GET", path) ?? new OrgSealGrantsResponse();
        return r with
        {
            PersonEtsi = string.IsNullOrEmpty(r.PersonEtsi) ? personEtsi : r.PersonEtsi,
            Organizations = (r.Organizations ?? Array.Empty<OrgSealGrants>())
                .Select(o => o with { Grants = o.Grants ?? Array.Empty<OrgSealGrant>() }).ToList(),
            Raw = RawJson.Element(raw),
        };
    }
}

/// <summary><c>GET /organization/seal-grants/etsi/{personEtsi}</c>-ийн хариу (CA <c>dto.PersonOrgSealGrantsResponse</c>).</summary>
public sealed record OrgSealGrantsResponse
{
    /// <summary>PNOMN-…</summary>
    [JsonPropertyName("personEtsi")]
    public string PersonEtsi { get; init; } = "";

    /// <summary>Иргэн Гүйцэтгэх захирал байгаа байгууллагууд.</summary>
    [JsonPropertyName("organizations")]
    public IReadOnlyList<OrgSealGrants> Organizations { get; init; } = Array.Empty<OrgSealGrants>();

    /// <summary>Серверийн түүхий JSON (SDK задлаагүй шинэ талбарт).</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>Нэг байгууллага ба түүний RP тамганы эрхүүд.</summary>
public sealed record OrgSealGrants
{
    /// <summary>NTRMN-…</summary>
    [JsonPropertyName("orgEtsi")]
    public string OrgEtsi { get; init; } = "";

    /// <summary>Нэр.</summary>
    [JsonPropertyName("orgName")]
    public string OrgName { get; init; } = "";

    /// <summary>ACTIVE | SUSPENDED | REVOKED | …</summary>
    [JsonPropertyName("orgStatus")]
    public string OrgStatus { get; init; } = "";

    /// <summary>Эрхүүд (null бол хоосон жагсаалт).</summary>
    [JsonPropertyName("grants")]
    public IReadOnlyList<OrgSealGrant> Grants { get; init; } = Array.Empty<OrgSealGrant>();
}

/// <summary>Нэг RP-д байгууллагын тамга ашиглах эрх (CA <c>dto.MobileSealGrant</c>).</summary>
public sealed record OrgSealGrant
{
    /// <summary>Эрхийн ID.</summary>
    [JsonPropertyName("grantId")]
    public string GrantId { get; init; } = "";

    /// <summary>RP-ийн нэр.</summary>
    [JsonPropertyName("rpName")]
    public string RpName { get; init; } = "";

    /// <summary>RP-ийн домэйн (байвал).</summary>
    [JsonPropertyName("rpDomain")]
    public string? RpDomain { get; init; }

    /// <summary>APPROVED | PENDING (<see cref="SealGrantStatuses"/>).</summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    /// <summary>Үүссэн цаг.</summary>
    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>Шийдвэрлэсэн цаг.</summary>
    [JsonPropertyName("decidedAt")]
    public DateTimeOffset? DecidedAt { get; init; }

    /// <summary>Зөвхөн PENDING: зөвшөөрөх хугацааны төгсгөл.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Зөвшөөрсөн захирлын нэр.</summary>
    [JsonPropertyName("approverName")]
    public string? ApproverName { get; init; }

    /// <summary>
    /// Энэ RP байгууллагын нэрээр хийсэн амжилттай тамгалалт (нийт). CA статистикийг түр уншиж чадаагүй үед null
    /// («мэдэгдэхгүй», 0 биш).
    /// </summary>
    [JsonPropertyName("sealCount")]
    public long? SealCount { get; init; }

    /// <summary>Сүүлийн 30 өдрийн тамгалалт; мэдэгдэхгүй бол null.</summary>
    [JsonPropertyName("sealCount30d")]
    public long? SealCount30d { get; init; }

    /// <summary>Сүүлд тамгалсан цаг; хэзээ ч үгүй (эсвэл мэдэгдэхгүй) бол null.</summary>
    [JsonPropertyName("lastSealedAt")]
    public DateTimeOffset? LastSealedAt { get; init; }
}

/// <summary>Түүхий JSON-ийг <see cref="JsonElement"/> болгох туслах.</summary>
internal static class RawJson
{
    /// <summary>Хоосон бие бол null; бусад үед root-ийн хуулбар (биеийг өмнө нь амжилттай задалсан байх ёстой).</summary>
    public static JsonElement? Element(byte[] raw)
    {
        if (raw.AsSpan().Trim(" \t\r\n"u8).IsEmpty)
        {
            return null;
        }
        using var d = JsonDocument.Parse(raw);
        return d.RootElement.Clone();
    }
}
