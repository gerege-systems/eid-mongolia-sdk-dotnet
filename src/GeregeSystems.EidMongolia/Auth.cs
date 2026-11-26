using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>Нэвтрэлтийн session-ий нэмэлт тохиргоо (Go <c>AuthOptions</c>). null = анхдагч.</summary>
public sealed record AuthOptions
{
    /// <summary>Энэ session-ий certLevel (<see cref="CertificateLevels"/>); null / "" = client-ийн анхдагч.</summary>
    public string? CertificateLevel { get; init; }

    /// <summary>
    /// Ижил төхөөрөмжийн (Web2App/App2App) буцах https URL. Өгвөл <c>initialCallbackUrl</c>-аар илгээж, санал болгох
    /// урсгалд App2App, Web2App нэмэгдэнэ. Host нь RP-ийн callbackHosts-д байх ёстой.
    /// </summary>
    public string? CallbackUrl { get; init; }

    /// <summary>
    /// Байгууллагаар нэвтрэх: байгууллагын ETSI (NTRMN-&lt;бүртгэл&gt;). Сервер төлөөллийн эрхийг шалгана (эрхгүй бол 403
    /// <see cref="EidForbiddenException.Code"/>); дууссан session-д <see cref="SessionResult.OnBehalfOf"/>. ACSP_V2 гарын
    /// үсэгт ОРОХГҮЙ.
    /// </summary>
    public string? OnBehalfOf { get; init; }

    /// <summary>null / "" = rsassa-pss.</summary>
    public string? SignatureAlgorithm { get; init; }

    /// <summary>ACSP_V2 payload-ийн hash; null / "" = SHA-512 (Smart-ID v3 жишээтэй ижил).</summary>
    public string? HashAlgorithm { get; init; }
}

public sealed partial class AuthService
{
    /// <summary>
    /// Push: РД / иргэний дугаар / ETSI (PNOMN-…)-ээр (сервер төрлийг танина). Иргэний утас руу мэдэгдэл очно. Validator-т
    /// ExpectedFlowType = <see cref="FlowTypes.Notification"/>.
    /// </summary>
    public Task<NotificationSession> NotificationByEtsiAsync(string id, IEnumerable<Interaction>? interactions,
        AuthOptions? options = null, CancellationToken ct = default) =>
        NotificationAsync(RpRoutes.AuthNotificationEtsi.Expand(id), interactions, options, ct);

    /// <summary>Push: баримтын дугаараар (тодорхой төхөөрөмж рүү).</summary>
    public Task<NotificationSession> NotificationByDocumentAsync(string documentNumber, IEnumerable<Interaction>? interactions,
        AuthOptions? options = null, CancellationToken ct = default) =>
        NotificationAsync(RpRoutes.AuthNotificationDocument.Expand(documentNumber), interactions, options, ct);

    /// <summary>
    /// QR / Web2App / App2App: иргэн хэн болохыг урьдчилж мэдэхгүй. Холбоосыг <see cref="DeviceLinkSession.BuildLink"/> /
    /// <see cref="DeviceLinkSession.TickQrAsync(string, TimeSpan, CancellationToken)"/>-аар угсарна.
    /// </summary>
    public Task<DeviceLinkSession> DeviceLinkAnonymousAsync(IEnumerable<Interaction>? interactions,
        AuthOptions? options = null, CancellationToken ct = default) =>
        DeviceLinkAsync(RpRoutes.AuthDeviceLinkAnonymous.Expand(), interactions, options, ct);

    /// <summary>QR / Web2App / App2App: тодорхой иргэн (РД / civil_id / ETSI).</summary>
    public Task<DeviceLinkSession> DeviceLinkByEtsiAsync(string id, IEnumerable<Interaction>? interactions,
        AuthOptions? options = null, CancellationToken ct = default) =>
        DeviceLinkAsync(RpRoutes.AuthDeviceLinkEtsi.Expand(id), interactions, options, ct);

    /// <summary>v3 nested body + validator-т хэрэгтэй контекст (ижил утгуудаас — байт зөрөхгүй). Go auth.go <c>body</c>.</summary>
    internal (AuthRequest Body, AcspContext Acsp) BuildBody(IEnumerable<Interaction>? interactions, string flow, AuthOptions? o)
    {
        o ??= new AuthOptions();
        var challenge = _c.NewChallenge();
        var ib64 = EidCrypto.InteractionsToBase64(interactions);
        var callback = (o.CallbackUrl ?? "").Trim();
        var flows = new List<string> { flow };
        if (callback.Length > 0)
        {
            flows.Add(FlowTypes.App2App);
            flows.Add(FlowTypes.Web2App);
        }
        var acsp = new AcspContext
        {
            RpChallenge = challenge,
            RelyingPartyName = _c.RpName,
            BrokeredRpName = "",
            Interactions = ib64,
            InitialCallbackUrl = callback,
            FlowTypes = flows,
            SignatureAlgorithm = Wire.OrDefault(o.SignatureAlgorithm, SignatureAlgorithms.RsassaPss),
            HashAlgorithm = Wire.OrDefault(o.HashAlgorithm, HashAlgorithms.Sha512),
        };
        var body = new AuthRequest
        {
            RelyingPartyUuid = _c.Options.Credentials.RpUuid,
            RelyingPartyName = acsp.RelyingPartyName,
            CertificateLevel = Wire.OrDefault(o.CertificateLevel, _c.DefaultCertificateLevel),
            SignatureProtocolParameters = new AuthProtocolParams
            {
                RpChallenge = challenge,
                SignatureAlgorithm = acsp.SignatureAlgorithm,
                SignatureAlgorithmParameters = new HashParam { HashAlgorithm = acsp.HashAlgorithm },
            },
            Interactions = ib64,
            InitialCallbackUrl = Wire.NullIfEmpty(callback),
            OnBehalfOf = Wire.NullIfEmpty((o.OnBehalfOf ?? "").Trim()),
        };
        return (body, acsp);
    }

    private async Task<NotificationSession> NotificationAsync(string path, IEnumerable<Interaction>? interactions, AuthOptions? o,
        CancellationToken ct)
    {
        var (body, acsp) = BuildBody(interactions, FlowTypes.Notification, o);
        var r = await Wire.StartAsync(_c, path, body, ct).ConfigureAwait(false);
        return new NotificationSession
        {
            SessionId = r.SessionId ?? "",
            Vc = r.Vc ?? "",
            RpChallenge = acsp.RpChallenge,
            Acsp = acsp,
            ExpiresAt = r.CaExpiresAt(),
        };
    }

    private async Task<DeviceLinkSession> DeviceLinkAsync(string path, IEnumerable<Interaction>? interactions, AuthOptions? o,
        CancellationToken ct)
    {
        var (body, acsp) = BuildBody(interactions, FlowTypes.Qr, o);
        var r = await Wire.StartAsync(_c, path, body, ct).ConfigureAwait(false);
        return new DeviceLinkSession
        {
            SessionId = r.SessionId ?? "",
            SessionToken = r.SessionToken ?? "",
            SessionSecret = r.SessionSecret ?? "",
            DeviceLinkBase = r.DeviceLinkBase ?? "",
            Vc = r.Vc ?? "",
            RpChallenge = acsp.RpChallenge,
            Acsp = acsp,
            ReceivedAt = _c.Clock.GetUtcNow(),
            SessionType = DeviceLinkSessionTypes.Auth,
            ExpiresAt = r.CaExpiresAt(),
        };
    }
}

/// <summary>Auth/sign-ийн <c>signatureAlgorithmParameters</c>.</summary>
internal sealed class HashParam
{
    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; init; } = "";
}

/// <summary>ACSP_V2 <c>signatureProtocolParameters</c> (Go <c>authProtocolParams</c>).</summary>
internal sealed class AuthProtocolParams
{
    [JsonPropertyName("rpChallenge")]
    public string RpChallenge { get; init; } = "";

    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; init; } = "";

    [JsonPropertyName("signatureAlgorithmParameters")]
    public HashParam SignatureAlgorithmParameters { get; init; } = new();
}

/// <summary>Auth start-ын бие (Go <c>authRequest</c>; талбарын дараалал ижил, null = omitempty).</summary>
internal sealed class AuthRequest
{
    [JsonPropertyName("relyingPartyUUID")]
    public string RelyingPartyUuid { get; init; } = "";

    [JsonPropertyName("relyingPartyName")]
    public string RelyingPartyName { get; init; } = "";

    [JsonPropertyName("certificateLevel")]
    public string CertificateLevel { get; init; } = "";

    [JsonPropertyName("signatureProtocol")]
    public string SignatureProtocol { get; init; } = "ACSP_V2";

    [JsonPropertyName("signatureProtocolParameters")]
    public AuthProtocolParams SignatureProtocolParameters { get; init; } = new();

    [JsonPropertyName("interactions")]
    public string Interactions { get; init; } = "";

    [JsonPropertyName("initialCallbackUrl")]
    public string? InitialCallbackUrl { get; init; }

    [JsonPropertyName("onBehalfOf")]
    public string? OnBehalfOf { get; init; }
}

/// <summary>Session start-ын хариу (Go <c>sessionStartResponse</c>).</summary>
internal sealed class SessionStartResponse
{
    [JsonPropertyName("sessionID")]
    public string? SessionId { get; init; }

    [JsonPropertyName("sessionToken")]
    public string? SessionToken { get; init; }

    [JsonPropertyName("sessionSecret")]
    public string? SessionSecret { get; init; }

    [JsonPropertyName("deviceLinkBase")]
    public string? DeviceLinkBase { get; init; }

    /// <summary>vc нь мөр (device link) эсвэл <c>{"type","value"}</c> (notification).</summary>
    [JsonPropertyName("vc")]
    [JsonConverter(typeof(VcConverter))]
    public string? Vc { get; init; }

    /// <summary>CA-ийн session дуусах мөч (RFC 3339; CA 2026-10-14-өөс). Хуучин CA-д алга.</summary>
    [JsonPropertyName("expiresAt")]
    public string? ExpiresAt { get; init; }

    private static readonly string[] Rfc3339 = { "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK" };

    /// <summary>CA-ийн expiresAt; байхгүй / задрахгүй бол null (Go <c>caExpiresAt</c>).</summary>
    public DateTimeOffset? CaExpiresAt() =>
        ExpiresAt is { Length: > 0 } s && DateTimeOffset.TryParseExact(s, Rfc3339, CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var t)
            ? t
            : null;

    /// <summary>Sign / certificate-choice: CA-ийн expiresAt, байхгүй бол <see cref="SessionTimes.SessionExpiry"/>.</summary>
    public DateTimeOffset ExpiresAtOr(DateTimeOffset sent, TimeSpan ttl) => CaExpiresAt() ?? SessionTimes.SessionExpiry(sent, ttl);
}

/// <summary>vc: мөр эсвэл <c>{"value": …}</c> объект (Go <c>vcValue</c>).</summary>
internal sealed class VcConverter : JsonConverter<string?>
{
    public override bool HandleNull => true;

    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;
            case JsonTokenType.String:
                return reader.GetString();
            case JsonTokenType.StartObject:
                using (var d = JsonDocument.ParseValue(ref reader))
                {
                    foreach (var p in d.RootElement.EnumerateObject())
                    {
                        if (string.Equals(p.Name, "value", StringComparison.OrdinalIgnoreCase))
                        {
                            return p.Value.ValueKind switch
                            {
                                JsonValueKind.String => p.Value.GetString(),
                                JsonValueKind.Null => null,
                                _ => throw new JsonException("vc.value мөр биш"),
                            };
                        }
                    }
                    return null;
                }
            default:
                throw new JsonException("vc мөр эсвэл объект биш");
        }
    }

    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value);
}

/// <summary>Auth / Sign-ийн хуваалцсан wire туслахууд.</summary>
internal static class Wire
{
    public static string OrDefault(string? v, string def) => string.IsNullOrEmpty(v) ? def : v;

    public static string? NullIfEmpty(string? v) => string.IsNullOrEmpty(v) ? null : v;

    /// <summary>POST session start → хариу (хоосон бие = бүх талбар null).</summary>
    public static async Task<SessionStartResponse> StartAsync(EidClient c, string path, object body, CancellationToken ct) =>
        await c.Http.PostJsonAsync<SessionStartResponse>(path, body, null, ct).ConfigureAwait(false) ?? new SessionStartResponse();
}
