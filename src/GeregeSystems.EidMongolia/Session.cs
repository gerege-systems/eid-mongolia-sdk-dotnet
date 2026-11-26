using System;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary><see cref="SessionService.WaitForResultAsync"/>-ийн тохиргоо (Go <c>WaitOptions</c>). null / тэг = анхдагч.</summary>
public sealed record WaitOptions
{
    /// <summary>
    /// Нийт хүлээх хугацаа. null бол <see cref="ExpiresAt"/> + <see cref="SessionService.WaitGrace"/>; ExpiresAt алга бол
    /// discovery-ийн sessionTtl (max(auth, sign)) + grace; тэр нь ч мэдэгдэхгүй бол <see cref="SessionService.DefaultMaxWait"/>.
    /// Өгвөл үүнийг л дагана.
    /// </summary>
    public TimeSpan? MaxWait { get; init; }

    /// <summary>Session start хариуны ExpiresAt (<see cref="NotificationSession.ExpiresAt"/> / <see cref="DeviceLinkSession.ExpiresAt"/>). Өгвөл discovery-г татахгүй.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Нэг long-poll; null / ≤ 0 = <see cref="SessionService.DefaultServerPoll"/>.</summary>
    public TimeSpan? ServerPoll { get; init; }
}

/// <summary>
/// Session poll (Go <c>SessionService</c>, TS <c>SessionApi</c>). RP-API нь serverPoll хүртэл хүлээгээд (эсвэл иргэн хариу
/// өгмөгц) буцдаг тул хэдхэн дуудлагаар үр дүн авна.
/// </summary>
public sealed class SessionService
{
    /// <summary>Серверийн нэг long-poll-ийн дээд хугацаа.</summary>
    public static readonly TimeSpan DefaultServerPoll = TimeSpan.FromSeconds(30);

    /// <summary>
    /// WaitForResult-ийн нийт хүлээх хугацааны нөөц утга: MaxWait, ExpiresAt, discovery-ийн sessionTtl аль нь ч мэдэгдэхгүй үед
    /// (CA-ийн гарын үсгийн session-ий анхдагч 600 с).
    /// </summary>
    public static readonly TimeSpan DefaultMaxWait = TimeSpan.FromSeconds(600);

    /// <summary>
    /// ExpiresAt / discovery sessionTtl-ээс хойш нэмж хүлээх хугацаа: CA хугацаа дууссан session-ийг дараагийн poll-д
    /// COMPLETE/TIMEOUT болгодог тул сүүлчийн poll дуусах мөчөөс хойш явагдана.
    /// </summary>
    public static readonly TimeSpan WaitGrace = TimeSpan.FromSeconds(15);

    private readonly EidClient _c;

    internal SessionService(EidClient c) => _c = c;

    /// <summary>
    /// Нэг удаагийн long-poll (<c>GET /session/{id}?timeoutMs=…</c>); <paramref name="serverPoll"/> null / ≤ 0 бол
    /// <see cref="DefaultServerPoll"/>. HTTP timeout = serverPoll + 10 с.
    /// </summary>
    public async Task<SessionResult> PollAsync(string sessionId, TimeSpan? serverPoll = null, CancellationToken ct = default)
    {
        var poll = serverPoll is { } p && p > TimeSpan.Zero ? p : DefaultServerPoll;
        var path = RpRoutes.Session.Expand(sessionId) + "?timeoutMs=" +
            ((long)poll.TotalMilliseconds).ToString(CultureInfo.InvariantCulture);
        var raw = await _c.Http.GetRawAsync(path, poll + TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        if (raw.AsSpan().Trim(" \t\r\n"u8).IsEmpty)
        {
            return new SessionResult();
        }
        return Parse(raw, "eid: GET " + RpRoutes.MaskPath(path) + ": хариу задарсангүй");
    }

    /// <summary>
    /// COMPLETE болтол poll хийнэ. Анхдагчаар session-ий амьдрах хугацаа дуустал хүлээнэ (<see cref="WaitOptions.MaxWait"/>-ийг
    /// үз). Хугацаа дуустал COMPLETE болоогүй бол сүүлчийн (RUNNING) үр дүнг АЛДААГҮЙ буцаана — дуудагч EndResult == ""-ийг
    /// TIMEOUT мэт боловсруулна. COMPLETE ч OK биш үр дүн (USER_REFUSED г.м.) мөн алдаагүй буцна —
    /// <see cref="EnsureCompleteOk"/> эсвэл validator <see cref="EidSessionFailedException"/> болгоно.
    /// </summary>
    public async Task<SessionResult> WaitForResultAsync(string sessionId, WaitOptions? options = null, CancellationToken ct = default)
    {
        options ??= new WaitOptions();
        var poll = options.ServerPoll is { } p && p > TimeSpan.Zero ? p : DefaultServerPoll;
        var deadline = await WaitDeadlineAsync(options, ct).ConfigureAwait(false);
        var last = new SessionResult { State = SessionStates.Running };
        while (true)
        {
            var remaining = deadline - _c.Clock.GetUtcNow();
            if (remaining <= TimeSpan.Zero)
            {
                return last;
            }
            var r = await PollAsync(sessionId, Max(TimeSpan.FromSeconds(1), Min(poll, remaining)), ct).ConfigureAwait(false);
            last = r;
            if (r.State == SessionStates.Complete)
            {
                return r;
            }
        }
    }

    /// <summary>WaitForResult-ийн дуусах мөч: MaxWait &gt; ExpiresAt &gt; discovery sessionTtl &gt; DefaultMaxWait (Go <c>waitDeadline</c>).</summary>
    internal async Task<DateTimeOffset> WaitDeadlineAsync(WaitOptions o, CancellationToken ct)
    {
        var now = _c.Clock.GetUtcNow();
        if (o.MaxWait is { } mw && mw > TimeSpan.Zero)
        {
            return now + mw;
        }
        if (o.ExpiresAt is { } exp)
        {
            // Хугацаа аль хэдийн өнгөрсөн ч нэг poll хийнэ — CA-ийн COMPLETE/TIMEOUT-ийг авна.
            var d = exp + WaitGrace;
            return d > now + TimeSpan.FromSeconds(1) ? d : now + TimeSpan.FromSeconds(1);
        }
        // Session-ий төрөл (auth / sign) энд мэдэгдэхгүй — урт нь аюулгүй. Discovery татагдахгүй бол нөөц утга (алдаа биш).
        try
        {
            var st = await _c.Auth.SessionTtlAsync(ct).ConfigureAwait(false);
            var ttl = Max(st.Auth, st.Sign);
            if (ttl > TimeSpan.Zero)
            {
                return now + ttl + WaitGrace;
            }
        }
        catch (EidException)
        {
            // нөөц утга
        }
        return now + DefaultMaxWait;
    }

    /// <summary>
    /// COMPLETE + OK эсэх (Go/TS validator <c>sessionDone</c>): дуусаагүй бол <see cref="EidValidationException"/>,
    /// endResult ≠ OK бол <see cref="EidSessionFailedException"/> (EndResult хоосон бол "UNKNOWN").
    /// </summary>
    public static void EnsureCompleteOk(SessionResult result)
    {
        if (result is null)
        {
            throw new EidValidationException("хариу алга");
        }
        if (result.State != SessionStates.Complete)
        {
            throw new EidValidationException("session дуусаагүй (state=" + result.State + ")");
        }
        if (result.EndResult != EndResults.Ok)
        {
            throw new EidSessionFailedException(string.IsNullOrEmpty(result.EndResult) ? "UNKNOWN" : result.EndResult);
        }
    }

    /// <summary>
    /// RP-API-ийн session JSON-ийг <see cref="SessionResult"/> болгон задална (хадгалсан хариуг дахин шалгах, тестэд; Go
    /// <c>ParseSessionResult</c>). Буруу JSON бол <see cref="EidException"/>.
    /// </summary>
    public static SessionResult ParseSessionResult(byte[] raw)
    {
        ArgumentNullException.ThrowIfNull(raw);
        return Parse(raw, "eid: session JSON задарсангүй");
    }

    /// <summary><see cref="ParseSessionResult(byte[])"/> (UTF-8 текст).</summary>
    public static SessionResult ParseSessionResult(string json) =>
        ParseSessionResult(Encoding.UTF8.GetBytes(json ?? throw new ArgumentNullException(nameof(json))));

    private static SessionResult Parse(byte[] raw, string error)
    {
        RawSession? r;
        JsonElement root;
        try
        {
            r = JsonSerializer.Deserialize<RawSession>(raw, EidHttp.Json);
            using var d = JsonDocument.Parse(raw);
            root = d.RootElement.Clone();
        }
        catch (JsonException e)
        {
            throw new EidException(error, e);
        }
        return (r ?? new RawSession()).ToResult() with { Raw = root };
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;
}

/// <summary><c>GET /session/{id}</c>-ийн wire хэлбэр (Go session.go <c>rawSession</c>).</summary>
internal sealed class RawSession
{
    [JsonPropertyName("state")]
    public string? State { get; init; }

    [JsonPropertyName("result")]
    public RawResult? ResultBlock { get; init; }

    [JsonPropertyName("signatureProtocol")]
    public string? SignatureProtocol { get; init; }

    [JsonPropertyName("signature")]
    public RawSignature? Signature { get; init; }

    [JsonPropertyName("cert")]
    public RawCert? Cert { get; init; }

    [JsonPropertyName("interactionTypeUsed")]
    public string? InteractionTypeUsed { get; init; }

    [JsonPropertyName("onBehalfOf")]
    public OrgResult? OnBehalfOf { get; init; }

    [JsonPropertyName("person")]
    public Person? Person { get; init; }

    [JsonPropertyName("tokenCertificate")]
    public TokenCertSessionBlock? TokenCertificate { get; init; }

    [JsonPropertyName("presentation")]
    public SessionPresentation? Presentation { get; init; }

    internal sealed class RawResult
    {
        [JsonPropertyName("endResult")]
        public string? EndResult { get; init; }

        [JsonPropertyName("documentNumber")]
        public string? DocumentNumber { get; init; }
    }

    internal sealed class RawSignature
    {
        [JsonPropertyName("value")]
        public string? Value { get; init; }

        [JsonPropertyName("signatureAlgorithm")]
        public string? SignatureAlgorithm { get; init; }

        [JsonPropertyName("signatureProtocol")]
        public string? SignatureProtocol { get; init; }

        [JsonPropertyName("serverRandom")]
        public string? ServerRandom { get; init; }

        [JsonPropertyName("userChallenge")]
        public string? UserChallenge { get; init; }

        [JsonPropertyName("flowType")]
        public string? FlowType { get; init; }

        [JsonPropertyName("initialCallbackUrl")]
        public string? InitialCallbackUrl { get; init; }

        [JsonPropertyName("signatureAlgorithmParameters")]
        public SignatureAlgorithmParameters? SignatureAlgorithmParameters { get; init; }
    }

    internal sealed class RawCert
    {
        [JsonPropertyName("value")]
        public string? Value { get; init; }

        [JsonPropertyName("certificateLevel")]
        public string? CertificateLevel { get; init; }
    }

    /// <summary>Хоосон блокуудыг null болгоно (Go <c>rawSession.result</c>).</summary>
    public SessionResult ToResult()
    {
        var sig = Signature ?? new RawSignature();
        var proto = string.IsNullOrEmpty(SignatureProtocol) ? sig.SignatureProtocol : SignatureProtocol;
        var prm = sig.SignatureAlgorithmParameters;
        if (prm is not null && string.IsNullOrEmpty(prm.HashAlgorithm))
        {
            prm = null;
        }
        var org = OnBehalfOf;
        if (org is not null && string.IsNullOrEmpty(org.OrgEtsi))
        {
            org = null;
        }
        var person = Person;
        if (person is not null && IsEmpty(person))
        {
            person = null;
        }
        var tok = TokenCertificate;
        if (tok is not null && string.IsNullOrEmpty(tok.Status))
        {
            tok = null;
        }
        var pres = Presentation;
        if (pres is not null && string.IsNullOrEmpty(pres.Jws))
        {
            pres = null;
        }
        return new SessionResult
        {
            State = State ?? "",
            EndResult = ResultBlock?.EndResult ?? "",
            DocumentNumber = ResultBlock?.DocumentNumber ?? "",
            CertificateDerB64 = Cert?.Value ?? "",
            CertificateLevel = Cert?.CertificateLevel ?? "",
            SignatureValueB64 = sig.Value ?? "",
            SignatureAlgorithm = sig.SignatureAlgorithm ?? "",
            SignatureProtocol = proto ?? "",
            ServerRandom = sig.ServerRandom ?? "",
            UserChallenge = sig.UserChallenge ?? "",
            FlowType = sig.FlowType ?? "",
            InitialCallbackUrl = sig.InitialCallbackUrl,
            SignatureAlgorithmParameters = prm,
            InteractionTypeUsed = InteractionTypeUsed ?? "",
            OnBehalfOf = org,
            Person = person,
            TokenCertificate = tok,
            Presentation = pres,
        };
    }

    private static bool IsEmpty(Person p) =>
        string.IsNullOrEmpty(p.FirstName) && string.IsNullOrEmpty(p.LastName) && string.IsNullOrEmpty(p.FamilyName) &&
        string.IsNullOrEmpty(p.FirstNameEn) && string.IsNullOrEmpty(p.LastNameEn) && string.IsNullOrEmpty(p.CivilId) &&
        string.IsNullOrEmpty(p.RegNo) && string.IsNullOrEmpty(p.BirthDate) && string.IsNullOrEmpty(p.Gender) &&
        p.GeId == 0 && string.IsNullOrEmpty(p.Nationality);
}
