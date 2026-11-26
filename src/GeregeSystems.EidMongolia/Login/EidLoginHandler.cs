using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Login;

/// <summary>
/// «eID-ээр нэвтрэх» товчны (<c>&lt;eid-login-button&gt;</c>, TS SDK-ийн <c>button</c>) RP backend — framework-аас
/// хамааралгүй (Go <c>eidlogin.Handler</c>, TS <c>createEidLogin</c> / <c>handleRequest</c>-ийн порт; хариуны хэлбэр
/// ижил). Замын сүүлийн хэсгээр:
/// <code>
/// POST {base}/start    {"mode":"qr"} | {"mode":"push","idCode":"УБ12345678"} → {mode, vc, qr?, expiresIn}
/// GET  {base}/start?mode=web2app                     → 302 → eID апп (Web2App холбоос)
/// GET  {base}/status                                 → PENDING (+шинэ QR) | WAIT_CALLBACK | OK | FAILED | EXPIRED
/// GET  {base}/callback?sessionId&amp;userChallengeVerifier → Web2App буцалт: шалгаад 303
/// </code>
/// eID сервер Web2App callback-ийн замыг <c>/auth/eid/callback</c> болгож нормчилдог тул {base} = <c>/auth/eid</c>.
/// Төлөв (sessionToken, sessionSecret, ACSP) серверт (<see cref="IEidLoginStore"/>); хөтчид зөвхөн HttpOnly cookie
/// (<c>&lt;sessionId&gt;.&lt;binding&gt;</c>) — status/callback зөвхөн session-ийг эхлүүлсэн хөтчид хариулна. Иргэн зөвхөн
/// ValidateAuth (гинж + ACSP_V2 + flowType + Web2App-д verifier) ба цуцлалтын шалгалтын дараа OnSuccess-д. Push нь
/// бүртгэлтэй эсэхийг задлахгүй (decoy, push floor). Thread-safe; нэг instance-ийг бүх хүсэлтэд.
/// </summary>
public sealed class EidLoginHandler
{
    /// <summary>eID серверийн нормчилдог Web2App буцах зам.</summary>
    public const string CallbackPath = "/auth/eid/callback";

    /// <summary>POST start-ын биеийн дээд хэмжээ (байт).</summary>
    public const int MaxBodyBytes = 4 << 10;

    private const RegexOptions Ro = RegexOptions.CultureInvariant;
    private static readonly Regex IdRe = new(@"^(\p{L}{2}[0-9]{8}|[0-9]{8,14}|PNOMN-[0-9]{8,14})\z", Ro);
    private static readonly Regex UuidRe = new(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z", Ro);
    private static readonly Regex BindingRe = new(@"^[A-Za-z0-9_-]{43}\z", Ro);
    private static readonly Regex CivilRe = new(@"^PNOMN-([0-9]+)\z", Ro);
    private static readonly Regex CookieNameRe = new(@"^[!#$%&'*+.^_`|~0-9A-Za-z-]+\z", Ro);
    private static readonly JsonSerializerOptions DataJson = new(JsonSerializerDefaults.Web);

    private static readonly TimeSpan AuthTtlRefresh = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan AuthTtlRetry = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan CallbackPoll = TimeSpan.FromSeconds(10);

    private readonly EidClient _client;
    private readonly Func<EidLoginIdentity, EidLoginContext, CancellationToken, Task<EidLoginSuccess?>> _onSuccess;
    private readonly string? _callbackUrl;
    private readonly string _successRedirect;
    private readonly string _failureRedirect;
    private readonly string? _certLevel;
    private readonly Interaction[] _interactions;
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _poll;
    private readonly IEidLoginStore _store;
    private readonly string _cookieName;
    private readonly string _cookiePath;
    private readonly string? _cookieDomain;
    private readonly bool _secure;
    private readonly Dictionary<string, Func<string, CancellationToken, ValueTask<bool>>> _limits;
    private readonly Func<string, CancellationToken, ValueTask<bool>>? _extraLimit;
    private readonly Func<EidLoginRequest, string?>? _clientIp;
    private readonly Action<EidLoginLogEntry>? _log;
    private readonly bool _decoy;
    private readonly TimeSpan _floor;
    private readonly RevocationChecker? _revocation;
    private readonly RevocationMode _revocationMode;
    private readonly Func<EidLoginEvent, CancellationToken, Task>? _onEvent;
    private readonly byte[] _auditKey;
    private readonly TimeProvider _clock;

    // CA-ийн нэвтрэлтийн session-ий хугацаа (discovery sessionTtl.auth; хуучин CA-д бодит push-ээс ажигласан), кэштэй.
    private readonly SemaphoreSlim _ttlFetch = new(1, 1);
    private readonly object _ttlSync = new();
    private TimeSpan _caTtl;
    private DateTimeOffset _caTtlNext = DateTimeOffset.MinValue;

    /// <summary>Тохиргоог шалгаж handler үүсгэнэ.</summary>
    /// <exception cref="ArgumentException">Client / OnSuccess алга, CallbackUrl буруу, cookie / redirect / RateLimits буруу.</exception>
    public EidLoginHandler(EidLoginOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _client = options.Client ?? throw new ArgumentException("eidlogin: Client шаардлагатай", nameof(options));
        _onSuccess = options.OnSuccess ?? throw new ArgumentException("eidlogin: OnSuccess шаардлагатай", nameof(options));
        if (!string.IsNullOrEmpty(options.CallbackUrl))
        {
            if (!Uri.TryCreate(options.CallbackUrl, UriKind.Absolute, out var u) || u.Scheme != "https" || u.Host.Length == 0 ||
                u.AbsolutePath != CallbackPath)
            {
                throw new ArgumentException("eidlogin: CallbackUrl нь https://<таны host>" + CallbackPath + " байх ёстой", nameof(options));
            }
            _callbackUrl = options.CallbackUrl;
        }
        _successRedirect = string.IsNullOrEmpty(options.SuccessRedirect) ? "/" : options.SuccessRedirect;
        _failureRedirect = string.IsNullOrEmpty(options.FailureRedirect) ? "/" : options.FailureRedirect;
        foreach (var r in new[] { _successRedirect, _failureRedirect })
        {
            if (!Uri.TryCreate(r, UriKind.RelativeOrAbsolute, out _) || r.Any(char.IsControl))
            {
                throw new ArgumentException("eidlogin: redirect буруу URL: " + r, nameof(options));
            }
        }
        _certLevel = string.IsNullOrEmpty(options.CertificateLevel) ? null : options.CertificateLevel;
        _ttl = options.Ttl > TimeSpan.Zero ? options.Ttl : TimeSpan.FromMinutes(2);
        _poll = options.Poll > TimeSpan.Zero ? options.Poll : TimeSpan.FromSeconds(1);
        _clock = options.TimeProvider ?? TimeProvider.System;
        _store = options.Store ?? new MemoryEidLoginStore(timeProvider: _clock);
        _cookieName = string.IsNullOrEmpty(options.CookieName) ? "eid_login" : options.CookieName;
        _cookiePath = string.IsNullOrEmpty(options.CookiePath) ? "/" : options.CookiePath;
        _cookieDomain = string.IsNullOrEmpty(options.CookieDomain) ? null : options.CookieDomain;
        if (!CookieNameRe.IsMatch(_cookieName) || !IsCookieAttr(_cookiePath) || (_cookieDomain is not null && !IsCookieAttr(_cookieDomain)))
        {
            throw new ArgumentException("eidlogin: CookieName / CookiePath / CookieDomain буруу", nameof(options));
        }
        _secure = !options.InsecureCookie;
        _limits = BuildLimits(options.RateLimits, _clock);
        _extraLimit = options.RateLimit;
        _clientIp = options.ClientIp;
        _log = options.Log;
        _decoy = !options.DisableDecoy;
        _floor = options.DisablePushFloor ? TimeSpan.Zero : options.PushFloor > TimeSpan.Zero ? options.PushFloor : TimeSpan.FromSeconds(1);
        if (!options.DisableRevocation)
        {
            _revocation = options.Revocation ?? new OcspRevocationChecker().Checker;
            _revocationMode = options.RevocationMode ?? RevocationMode.SoftFail;
        }
        _onEvent = options.OnEvent;
        _auditKey = options.AuditKey is { Length: > 0 } k ? (byte[])k.Clone() : RandomNumberGenerator.GetBytes(32);
        var text = string.IsNullOrEmpty(options.DisplayText) ? _client.RpName + "-д нэвтрэх" : options.DisplayText;
        _interactions = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = TruncateRunes(text, 60) } };
        if (_clientIp is null)
        {
            Log(EidLoginLogLevel.Warning,
                "eidlogin: ClientIp алга — start:<ip> хязгаар ажиллахгүй; EidLoginClientIp.RemoteAddress эсвэл Forwarded(n) өг");
        }
    }

    /// <summary>Утсанд илгээх interactions (displayTextAndPIN).</summary>
    public IReadOnlyList<Interaction> Interactions => Array.AsReadOnly(_interactions);

    /// <summary>Замын сүүлийн хэсгээр (start | status | callback) чиглүүлнэ; бусад нь 404 <c>not_found</c>.</summary>
    public async Task<EidLoginResponse> HandleAsync(EidLoginRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            switch (LastSegment(SplitUrl(request.Url).Path))
            {
                case "start":
                    return await StartAsync(request, ct).ConfigureAwait(false);
                case "status":
                    return await StatusAsync(request, ct).ConfigureAwait(false);
                case "callback":
                    return await CallbackAsync(request, ct).ConfigureAwait(false);
                default:
                    return Error(404, EidLoginErrors.NotFound);
            }
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            // Дотоод мэдээллийг хөтчид гаргахгүй (TS handleRequest).
            Log(EidLoginLogLevel.Error, "eidlogin: дотоод алдаа", e);
            return e is EidAuthenticationException or EidForbiddenException
                ? Error(502, EidLoginErrors.EidUnavailable)
                : Error(500, EidLoginErrors.Internal);
        }
    }

    /// <summary>POST <c>{mode: qr|push}</c> эсвэл GET <c>?mode=web2app</c>.</summary>
    public async Task<EidLoginResponse> StartAsync(EidLoginRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        // CSRF: cross-site хүсэлтээр session/push эхлүүлэхгүй. POST нь JSON (simple request биш → CORS preflight).
        if (Header(request, "Sec-Fetch-Site") is not ("" or "same-origin" or "same-site" or "none"))
        {
            return Error(403, EidLoginErrors.CrossSite);
        }
        string mode, idRaw, langRaw;
        switch (request.Method)
        {
            case "GET":
                var query = ParseQuery(SplitUrl(request.Url).Query);
                if (QueryGet(query, "mode") != EidLoginModes.Web2App)
                {
                    return Error(405, EidLoginErrors.MethodNotAllowed);
                }
                (mode, idRaw, langRaw) = (EidLoginModes.Web2App, "", QueryGet(query, "lang"));
                break;
            case "POST":
                if (!IsJsonContentType(Header(request, "Content-Type")))
                {
                    return Error(415, EidLoginErrors.JsonRequired);
                }
                if (ParseStartBody(request.Body) is not { } b)
                {
                    return Error(400, EidLoginErrors.InvalidBody);
                }
                (mode, idRaw, langRaw) = b;
                break;
            default:
                return Error(405, EidLoginErrors.MethodNotAllowed);
        }
        if (mode is not (EidLoginModes.Qr or EidLoginModes.Push or EidLoginModes.Web2App))
        {
            return Error(400, EidLoginErrors.InvalidMode);
        }
        if (mode == EidLoginModes.Web2App && _callbackUrl is null)
        {
            return Error(400, EidLoginErrors.Web2AppNotConfigured);
        }
        var idCode = NormalizeId(idRaw);
        if (mode == EidLoginModes.Push && !IdRe.IsMatch(idCode))
        {
            return Error(400, EidLoginErrors.InvalidId);
        }

        async Task<EidLoginResponse> Limited()
        {
            if (mode == EidLoginModes.Push)
            {
                await EmitAsync(EidLoginEventKinds.PushLimited, null, Meta(("mode", mode), ("pushKey", PushKey(idCode))), ct).ConfigureAwait(false);
            }
            return Error(429, EidLoginErrors.RateLimited, ("Retry-After", "60"));
        }

        if (_clientIp?.Invoke(request) is { Length: > 0 } ip && !await AllowAsync("start", RateKeyIp(ip), ct).ConfigureAwait(false))
        {
            return await Limited().ConfigureAwait(false);
        }
        if (mode == EidLoginModes.Push && !await AllowAsync("push", idCode, ct).ConfigureAwait(false))
        {
            return await Limited().ConfigureAwait(false);
        }
        var lang = langRaw == "en" ? "eng" : "mon";
        var began = _clock.GetUtcNow();
        var ttl = _ttl;
        if (mode == EidLoginModes.Push)
        {
            // Бодит ба decoy push ижил хугацаа авна — CA-ийн хариунаас биш (decoy-д байхгүй), discovery-оос.
            var ca = await AuthTtlAsync(ct).ConfigureAwait(false);
            if (ca > TimeSpan.Zero && ca < ttl)
            {
                ttl = ca;
            }
        }
        Started? started = null;
        Exception? err = null;
        var decoy = false;
        try
        {
            started = await BeginAsync(request, mode, idCode, lang, ttl, ct).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            err = e;
        }
        if (err is not null && mode == EidLoginModes.Push && _decoy && IsRefusal(err))
        {
            // eID дугаарыг татгалзсан (танихгүй / ашиглах боломжгүй): ялгаатай хариу нь «энэ регистр бүртгэлтэй эсэх»-ийн
            // oracle болно. Хэн ч хариулаагүй push-тэй ижил decoy өгнө. Биеийг бичихгүй (дугаарыг давтаж болзошгүй).
            var ae = (EidApiException)err;
            Log(EidLoginLogLevel.Warning, "eidlogin: eID push-ийг татгалзсан (" + ae.Status + (ae.Code is null ? "" : " " + ae.Code) +
                "); decoy session-оор хариулав");
            err = null;
            try
            {
                started = await StartDecoyAsync(ttl, ct).ConfigureAwait(false);
                decoy = true;
            }
            catch (Exception e)
            {
                err = e;
            }
        }
        if (mode == EidLoginModes.Push && _floor > TimeSpan.Zero)
        {
            // Decoy микросекундэд, бодит push eID-ийн round trip-ээр бэлэн болно — хоёуланг ижил доод хугацаанд барина.
            await SleepAsync(began + _floor - _clock.GetUtcNow(), ct).ConfigureAwait(false);
        }
        if (err is not null || started is null)
        {
            // eID-ийн 5xx / холболт / 401-403 — манай талын тасалдал; бүртгэлтэй ба бүртгэлгүй дугаар ижил 502 авна.
            Log(EidLoginLogLevel.Error, "eidlogin: session эхлүүлж чадсангүй (" + mode + ")", err);
            if (err is EidApiException { Status: 429 })
            {
                return await Limited().ConfigureAwait(false);
            }
            if (err is EidLoginStoreFullException)
            {
                return Error(503, EidLoginErrors.Busy, ("Retry-After", "30"));
            }
            return Error(502, EidLoginErrors.EidUnavailable);
        }
        var (tx, binding, appLink, txTtl) = started;
        var expiresIn = (int)(txTtl.Ticks / TimeSpan.TicksPerSecond);
        var setCookie = CookieHeader(tx.SessionId + "." + binding, expiresIn);
        if (mode == EidLoginModes.Push)
        {
            await EmitAsync(EidLoginEventKinds.PushSent, tx.SessionId,
                Meta(("mode", mode), ("pushKey", PushKey(idCode)), ("decoy", decoy)), ct).ConfigureAwait(false);
        }
        if (mode == EidLoginModes.Web2App)
        {
            // iOS Universal Link зөвхөн хэрэглэгчийн tap-аас эхэлсэн redirect гинжид аппыг нээнэ — JS биш, 302.
            return new EidLoginResponse(302, new List<KeyValuePair<string, string>>
            {
                new("Location", appLink!),
                new("Cache-Control", "no-store"),
                new("Referrer-Policy", "no-referrer"),
                new("Set-Cookie", setCookie),
            }, "");
        }
        var qr = QrLink(tx);
        return Json(200, w =>
        {
            w.WriteString("mode", mode);
            w.WriteString("vc", tx.Vc);
            if (qr is not null)
            {
                w.WriteString("qr", qr);
            }
            w.WriteNumber("expiresIn", expiresIn);
        }, new KeyValuePair<string, string>("Set-Cookie", setCookie));
    }

    /// <summary>GET: PENDING (+шинэ QR, vc, expiresIn) | WAIT_CALLBACK | OK | FAILED | EXPIRED.</summary>
    public async Task<EidLoginResponse> StatusAsync(EidLoginRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Method != "GET")
        {
            return Error(405, EidLoginErrors.MethodNotAllowed);
        }
        EidLoginTx? tx;
        try
        {
            tx = await LoadTxAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: store", e);
            return Error(500, EidLoginErrors.Internal);
        }
        if (tx is null)
        {
            return Expired();
        }
        SessionResult res;
        if (tx.Decoy)
        {
            // eID-ээс асуухгүй (асуувал 404 → EXPIRED болж ялгарна): бодит long-poll шиг Poll-ын хугацаанд барина.
            await SleepAsync(_poll, ct).ConfigureAwait(false);
            res = new SessionResult { State = SessionStates.Running };
        }
        else
        {
            try
            {
                res = await _client.Session.PollAsync(tx.SessionId, _poll, ct).ConfigureAwait(false);
            }
            catch (EidApiException e) when (e.Status == 404)
            {
                await DeleteTxAsync(tx, ct).ConfigureAwait(false);
                await EmitAsync(EidLoginEventKinds.Expired, tx.SessionId, Meta(("mode", tx.Mode)), ct).ConfigureAwait(false);
                return Expired();
            }
            catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
            {
                Log(EidLoginLogLevel.Error, "eidlogin: session poll", e);
                return Error(502, EidLoginErrors.EidUnavailable);
            }
        }
        if (res.State != SessionStates.Complete)
        {
            var left = Math.Max(0, (int)((tx.ExpiresAt - _clock.GetUtcNow()).TotalSeconds + 0.999));
            var qr = QrLink(tx);
            var vc = tx.Vc;
            return Json(200, w =>
            {
                w.WriteString("state", "PENDING");
                if (qr is not null)
                {
                    w.WriteString("qr", qr);
                }
                w.WriteString("vc", vc);
                w.WriteNumber("expiresIn", left);
            });
        }
        if (res.EndResult != EndResults.Ok)
        {
            await DeleteTxAsync(tx, ct).ConfigureAwait(false);
            await EndEventAsync(tx, res.EndResult, ct).ConfigureAwait(false);
            if (tx.Mode == EidLoginModes.Push && res.EndResult == EndResults.Timeout)
            {
                // Хариугүй бодит push decoy-той ижил төгсөнө (EXPIRED) — FAILED/TIMEOUT нь «бүртгэлтэй» гэж хэлнэ.
                return Expired();
            }
            return Failed(OrUnknown(res.EndResult));
        }
        // Web2App-аар баталгаажсан session-ийг ЗӨВХӨН callback (userChallengeVerifier) дуусгана.
        if (tx.Mode == EidLoginModes.Web2App)
        {
            return Json(200, w => w.WriteString("state", "WAIT_CALLBACK"));
        }
        var flow = tx.Mode == EidLoginModes.Push ? FlowTypes.Notification : FlowTypes.Qr;
        EidLoginSuccess? s;
        try
        {
            s = await FinishAsync(request, tx, res, flow, null, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (IsValidation(e))
        {
            Log(EidLoginLogLevel.Warning, "eidlogin: баталгаажуулалт унасан", e);
            await DeleteTxAsync(tx, ct).ConfigureAwait(false);
            await UnverifiedAsync(tx, e, ct).ConfigureAwait(false);
            return Failed("VALIDATION");
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: дуусгаж чадсангүй", e);
            return Error(500, EidLoginErrors.Internal);
        }
        if (s is null)
        {
            return Expired();
        }
        var headers = Merge(JsonHeaders(new KeyValuePair<string, string>("Set-Cookie", ClearCookie)), s.Headers);
        var redirect = s.Redirect;
        var data = s.Data;
        return JsonWith(200, w =>
        {
            w.WriteString("state", "OK");
            if (!string.IsNullOrEmpty(redirect))
            {
                w.WriteString("redirect", redirect);
            }
            if (data is not null)
            {
                w.WritePropertyName("data");
                JsonSerializer.Serialize(w, data, data.GetType(), DataJson);
            }
        }, headers);
    }

    /// <summary>GET <c>/auth/eid/callback?sessionId&amp;userChallengeVerifier</c> (Web2App буцалт) → 303.</summary>
    public async Task<EidLoginResponse> CallbackAsync(EidLoginRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Method != "GET")
        {
            return Error(405, EidLoginErrors.MethodNotAllowed);
        }
        var q = ParseQuery(SplitUrl(request.Url).Query);
        var sid = QueryGet(q, "sessionId");
        var verifier = QueryGet(q, "userChallengeVerifier");
        EidLoginTx? tx;
        try
        {
            tx = await LoadTxAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: store", e);
            return Fail("internal");
        }
        // Эхлүүлсэн хөтчийн cookie заавал: өөр хөтчид нээгдсэн callback-ийг (хулгайлсан/илгээсэн URL) хүлээн авахгүй.
        if (tx is null)
        {
            return Fail("expired");
        }
        if (!string.Equals(tx.SessionId, sid, StringComparison.Ordinal) || tx.Mode != EidLoginModes.Web2App || verifier.Length == 0)
        {
            await EmitAsync(EidLoginEventKinds.FlowRefused, tx.SessionId, Meta(("mode", tx.Mode), ("reason", "unbound")), ct).ConfigureAwait(false);
            return Fail("unbound");
        }
        SessionResult res;
        try
        {
            res = await _client.Session.PollAsync(tx.SessionId, CallbackPoll, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: session poll", e);
            return Fail("eid_unavailable");
        }
        if (res.State != SessionStates.Complete)
        {
            return Fail("not_complete");
        }
        if (res.EndResult != EndResults.Ok)
        {
            await DeleteTxAsync(tx, ct).ConfigureAwait(false);
            await EndEventAsync(tx, res.EndResult, ct).ConfigureAwait(false);
            return Fail(OrUnknown(res.EndResult));
        }
        EidLoginSuccess? s;
        try
        {
            s = await FinishAsync(request, tx, res, FlowTypes.Web2App, verifier, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (IsValidation(e))
        {
            Log(EidLoginLogLevel.Warning, "eidlogin: баталгаажуулалт унасан", e);
            await DeleteTxAsync(tx, ct).ConfigureAwait(false);
            await UnverifiedAsync(tx, e, ct).ConfigureAwait(false);
            return Fail("VALIDATION");
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: дуусгаж чадсангүй", e);
            return Fail("internal");
        }
        if (s is null)
        {
            return Fail("expired");
        }
        var to = string.IsNullOrEmpty(s.Redirect) ? _successRedirect : s.Redirect;
        return Redirect(to, Merge(new List<KeyValuePair<string, string>> { new("Set-Cookie", ClearCookie) }, s.Headers));
    }

    // ---- урсгалын туслахууд ----

    private sealed record Started(EidLoginTx Tx, string Binding, string? AppLink, TimeSpan Ttl);

    /// <summary>eID session эхлүүлж tx-ийг хадгална. ttl — push-д discovery-оор таслагдсан; QR/web2app-д CA-ийн expiresAt-аар.</summary>
    private async Task<Started> BeginAsync(EidLoginRequest request, string mode, string idCode, string lang, TimeSpan ttl, CancellationToken ct)
    {
        var sent = _clock.GetUtcNow();
        var o = new AuthOptions { CertificateLevel = _certLevel };
        string sid, vc;
        AcspContext? acsp;
        EidLoginLink? link = null;
        string? appLink = null;
        if (mode == EidLoginModes.Push)
        {
            var s = await _client.Auth.NotificationByEtsiAsync(idCode, _interactions, o, ct).ConfigureAwait(false);
            (sid, vc, acsp) = (s.SessionId, s.Vc, s.Acsp);
            ObserveAuthTtl(sent, s.ExpiresAt);
        }
        else
        {
            if (mode == EidLoginModes.Web2App)
            {
                o = o with { CallbackUrl = EidLoginReturnHint.WithReturnHint(_callbackUrl!, Header(request, "User-Agent")) };
            }
            var s = await _client.Auth.DeviceLinkAnonymousAsync(_interactions, o, ct).ConfigureAwait(false);
            if (s.DeviceLinkBase.Length == 0 || s.SessionToken.Length == 0 || s.SessionSecret.Length == 0 || s.Acsp is null)
            {
                throw new EidException("eidlogin: eID хариунд device link талбар дутуу");
            }
            (sid, vc, acsp) = (s.SessionId, s.Vc, s.Acsp);
            if (s.ExpiresAt is { } exp)
            {
                var left = exp - _clock.GetUtcNow();
                left = TimeSpan.FromTicks(left.Ticks / TimeSpan.TicksPerSecond * TimeSpan.TicksPerSecond);
                if (left < ttl)
                {
                    ttl = left;
                }
            }
            link = new EidLoginLink { Base = s.DeviceLinkBase, Token = s.SessionToken, Secret = s.SessionSecret, ReceivedAt = s.ReceivedAt, Lang = lang };
            if (mode == EidLoginModes.Web2App)
            {
                appLink = DeviceLink.Build(new DeviceLinkInput
                {
                    DeviceLinkBase = s.DeviceLinkBase,
                    DeviceLinkType = DeviceLinkTypes.Web2App,
                    SessionToken = s.SessionToken,
                    SessionSecret = s.SessionSecret,
                    SessionType = DeviceLinkSessionTypes.Auth,
                    Lang = lang,
                    RpChallenge = s.Acsp.RpChallenge,
                    RelyingPartyName = s.Acsp.RelyingPartyName,
                    Interactions = s.Acsp.Interactions,
                    InitialCallbackUrl = s.Acsp.InitialCallbackUrl,
                });
            }
        }
        if (!UuidRe.IsMatch(sid))
        {
            throw new EidException("eidlogin: eID sessionID хэлбэр буруу");
        }
        if (ttl < TimeSpan.FromSeconds(1))
        {
            throw new EidException("eidlogin: eID session-ий хугацаа дууссан (expiresAt)");
        }
        var draft = new EidLoginTx { SessionId = sid, Mode = mode, Vc = vc, Acsp = acsp, Link = link };
        var (tx, binding) = await SaveAsync(draft, ttl, ct).ConfigureAwait(false);
        return new Started(tx, binding, appLink, ttl);
    }

    /// <summary>Cookie binding (32 санамсаргүй байт, base64url) үүсгэж tx-ийг ttl-тэй хадгална; хөтчид зөвхөн binding.</summary>
    private async Task<(EidLoginTx Tx, string Binding)> SaveAsync(EidLoginTx draft, TimeSpan ttl, CancellationToken ct)
    {
        var binding = B64.RawUrl(RandomNumberGenerator.GetBytes(32));
        var tx = draft with { BindingHash = Sha256Hex(binding), ExpiresAt = _clock.GetUtcNow() + ttl };
        await _store.SetAsync(tx, ttl, ct).ConfigureAwait(false);
        return (tx, binding);
    }

    /// <summary>
    /// eID-д байхгүй, хэзээ ч дуусахгүй push session: санамсаргүй UUID v4, eID-тэй ижил 5 оронтой vc (CA: %05d), бодит
    /// push-ийн ttl. Status нь Poll-ын хугацаанд барьж PENDING, TTL-ийн дараа EXPIRED — утсаа аваагүй иргэнтэй ижил.
    /// </summary>
    private async Task<Started> StartDecoyAsync(TimeSpan ttl, CancellationToken ct)
    {
        var id = RandomNumberGenerator.GetBytes(16);
        id[6] = (byte)((id[6] & 0x0f) | 0x40);
        id[8] = (byte)((id[8] & 0x3f) | 0x80);
        var h = Convert.ToHexString(id).ToLowerInvariant();
        var sid = h[..8] + "-" + h[8..12] + "-" + h[12..16] + "-" + h[16..20] + "-" + h[20..];
        var vc = RandomNumberGenerator.GetInt32(100000).ToString("D5", CultureInfo.InvariantCulture);
        var (tx, binding) = await SaveAsync(new EidLoginTx { SessionId = sid, Mode = EidLoginModes.Push, Vc = vc, Decoy = true }, ttl, ct)
            .ConfigureAwait(false);
        return new Started(tx, binding, null, ttl);
    }

    /// <summary>COMPLETE/OK-ийг шалгаж нэг удаа OnSuccess дуудна. null = зэрэг хүсэлт аль хэдийн дуусгасан.</summary>
    private async Task<EidLoginSuccess?> FinishAsync(EidLoginRequest request, EidLoginTx tx, SessionResult res, string flow, string? verifier,
        CancellationToken ct)
    {
        var v = _client.Validator.ValidateAuth(res, tx.Acsp!, new ValidateAuthOptions { ExpectedFlowType = flow, UserChallengeVerifier = verifier });
        RevocationStatus rev;
        try
        {
            rev = await _client.Validator.CheckRevocationWithAsync(v.Certificate, _revocation, _revocationMode, ct).ConfigureAwait(false);
        }
        catch (EidValidationException e)
        {
            throw new RevocationFailure(e.Reason == ValidationReasons.RevocationRevoked, e);
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            // Шалгагчийн өөрийн алдаа — итгэхгүй, гэхдээ 500 биш: баталгаажуулалт унасан.
            throw new RevocationFailure(false, e);
        }
        if (rev == RevocationStatus.Unchecked)
        {
            Log(EidLoginLogLevel.Warning, "eidlogin: OCSP хариугүй — цуцлалт шалгалгүй зөвшөөрөв (soft-fail), session " + tx.SessionId);
        }
        if (!await _store.DeleteAsync(tx.SessionId, ct).ConfigureAwait(false))
        {
            return null;
        }
        var civil = CivilRe.Match(v.Subject.SerialNumber);
        var id = new EidLoginIdentity
        {
            SessionId = tx.SessionId,
            Etsi = v.Subject.SerialNumber,
            CivilId = civil.Success ? civil.Groups[1].Value : null,
            GivenName = v.Subject.GivenName,
            Surname = v.Subject.Surname,
            Country = v.Subject.Country,
            DocumentNumber = v.DocumentNumber,
            CertificateLevel = v.CertificateLevel,
            Certificate = v.Certificate,
            CertificateDerB64 = Convert.ToBase64String(v.Certificate.RawData),
            FlowType = flow,
            Person = PersonMatchesCertificate(res.Person, v.Subject) ? res.Person : null,
            Revocation = rev,
        };
        var s = await _onSuccess(id, new EidLoginContext(request, tx.Mode), ct).ConfigureAwait(false) ?? new EidLoginSuccess();
        await EmitAsync(EidLoginEventKinds.Success, tx.SessionId,
            Meta(("mode", tx.Mode), ("flow", flow), ("revocation", RevocationString(rev))), ct).ConfigureAwait(false);
        return s;
    }

    /// <summary>Cookie → tx (binding таарсан, хугацаа дотор); олдохгүй бол null.</summary>
    private async Task<EidLoginTx?> LoadTxAsync(EidLoginRequest request, CancellationToken ct)
    {
        var raw = ReadCookie(Header(request, "Cookie"), _cookieName);
        var dot = raw.IndexOf('.');
        if (dot < 0)
        {
            return null;
        }
        var sid = raw[..dot];
        var binding = raw[(dot + 1)..];
        if (!UuidRe.IsMatch(sid) || !BindingRe.IsMatch(binding))
        {
            return null;
        }
        var tx = await _store.GetAsync(sid, ct).ConfigureAwait(false);
        if (tx is null || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(tx.BindingHash ?? ""), Encoding.ASCII.GetBytes(Sha256Hex(binding))))
        {
            return null;
        }
        if (_clock.GetUtcNow() >= tx.ExpiresAt)
        {
            await _store.DeleteAsync(sid, ct).ConfigureAwait(false);
            return null;
        }
        return tx;
    }

    private string? QrLink(EidLoginTx tx)
    {
        if (tx.Mode != EidLoginModes.Qr || tx.Link is null || tx.Acsp is null)
        {
            return null;
        }
        try
        {
            return DeviceLink.Build(new DeviceLinkInput
            {
                DeviceLinkBase = tx.Link.Base,
                DeviceLinkType = DeviceLinkTypes.Qr,
                SessionToken = tx.Link.Token,
                SessionSecret = tx.Link.Secret,
                SessionType = DeviceLinkSessionTypes.Auth,
                Lang = tx.Link.Lang,
                ReceivedAt = tx.Link.ReceivedAt,
                Now = _clock.GetUtcNow(),
                RpChallenge = tx.Acsp.RpChallenge,
                RelyingPartyName = tx.Acsp.RelyingPartyName,
                Interactions = tx.Acsp.Interactions,
            });
        }
        catch (EidDeviceLinkException e)
        {
            Log(EidLoginLogLevel.Error, "eidlogin: QR холбоос", e);
            return null;
        }
    }

    private async Task<bool> AllowAsync(string kind, string value, CancellationToken ct)
    {
        var key = kind + ":" + value;
        if (_limits.TryGetValue(kind, out var f) && !await f(key, ct).ConfigureAwait(false))
        {
            return false;
        }
        return _extraLimit is null || await _extraLimit(key, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// CA-ийн нэвтрэлтийн session-ий хугацаа (discovery sessionTtl.auth, 10 мин кэш, алдаа бол 1 мин дараа дахин). Татаж
    /// чадахгүй / хуучин CA бол өмнөх утга (бодит push-ээс ажигласан ч байж болно), эсвэл 0. Бодит ба decoy push хоёулаа
    /// дууддаг — ижил хоцрол.
    /// </summary>
    private async Task<TimeSpan> AuthTtlAsync(CancellationToken ct)
    {
        await _ttlFetch.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _clock.GetUtcNow();
            if (now > _caTtlNext)
            {
                _caTtlNext = now + AuthTtlRetry;
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeSpan.FromSeconds(2));
                    var st = await _client.Auth.SessionTtlAsync(cts.Token).ConfigureAwait(false);
                    _caTtlNext = now + AuthTtlRefresh;
                    if (st.Auth > TimeSpan.Zero)
                    {
                        lock (_ttlSync)
                        {
                            _caTtl = st.Auth;
                        }
                    }
                }
                catch (Exception e) when (!ct.IsCancellationRequested)
                {
                    Log(EidLoginLogLevel.Warning, "eidlogin: discovery sessionTtl", e);
                }
            }
            lock (_ttlSync)
            {
                return _caTtl;
            }
        }
        finally
        {
            _ttlFetch.Release();
        }
    }

    /// <summary>
    /// Хуучин CA (discovery-д sessionTtl алга): бодит push-ийн expiresAt − илгээсэн мөчөөс CA-ийн TTL-ийг тэмдэглэнэ
    /// (секундээр таслагддаг тул ±1 с). Discovery утга байвал хөндөхгүй.
    /// </summary>
    private void ObserveAuthTtl(DateTimeOffset sent, DateTimeOffset? expiresAt)
    {
        if (expiresAt is not { } exp)
        {
            return;
        }
        var d = TimeSpan.FromSeconds(Math.Round((exp - sent).TotalSeconds, MidpointRounding.AwayFromZero));
        if (d <= TimeSpan.Zero)
        {
            return;
        }
        lock (_ttlSync)
        {
            if (_caTtl == TimeSpan.Zero)
            {
                _caTtl = d;
            }
        }
    }

    private async Task SleepAsync(TimeSpan d, CancellationToken ct)
    {
        if (d <= TimeSpan.Zero)
        {
            return;
        }
        try
        {
            await Task.Delay(d, _clock, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Хүсэлт тасарсан — хүлээхгүй.
        }
    }

    private async Task DeleteTxAsync(EidLoginTx tx, CancellationToken ct)
    {
        try
        {
            await _store.DeleteAsync(tx.SessionId, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: store delete", e);
        }
    }

    // ---- аудит ----

    private async Task EmitAsync(string kind, string? sessionId, Dictionary<string, object?> meta, CancellationToken ct)
    {
        if (_onEvent is null)
        {
            return;
        }
        try
        {
            await _onEvent(new EidLoginEvent(kind, sessionId, meta), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log(EidLoginLogLevel.Error, "eidlogin: OnEvent", e);
        }
    }

    /// <summary>COMPLETE, endResult ≠ OK-ийн аудит.</summary>
    private Task EndEventAsync(EidLoginTx tx, string? endResult, CancellationToken ct)
    {
        var kind = (endResult ?? "").StartsWith(EndResults.UserRefused, StringComparison.Ordinal) ? EidLoginEventKinds.Refused
            : endResult == EndResults.Timeout ? EidLoginEventKinds.Expired
            : EidLoginEventKinds.Failed;
        return EmitAsync(kind, tx.SessionId, Meta(("mode", tx.Mode), ("endResult", OrUnknown(endResult))), ct);
    }

    private Task UnverifiedAsync(EidLoginTx tx, Exception e, CancellationToken ct)
    {
        var reason = e is RevocationFailure rf ? rf.Revoked ? "revoked" : "revocation_unavailable" : "validation";
        return EmitAsync(EidLoginEventKinds.Unverified, tx.SessionId, Meta(("mode", tx.Mode), ("reason", reason)), ct);
    }

    /// <summary>Регистрийн дугаарыг аудитад нэрлэх HMAC (дугаарын орон зай жижиг тул энгийн hash-ийг давтан тооцож болно).</summary>
    internal string PushKey(string idCode) =>
        Convert.ToHexString(HMACSHA256.HashData(_auditKey, Encoding.UTF8.GetBytes("eid-push-audit:" + idCode)), 0, 16).ToLowerInvariant();

    private static Dictionary<string, object?> Meta(params (string Key, object? Value)[] kv)
    {
        var m = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (k, v) in kv)
        {
            m[k] = v;
        }
        return m;
    }

    private static string RevocationString(RevocationStatus s) => s switch
    {
        RevocationStatus.Good => "good",
        RevocationStatus.Revoked => "revoked",
        RevocationStatus.Unchecked => "unchecked",
        RevocationStatus.Skipped => "skipped",
        _ => "unknown",
    };

    // ---- хариу ----

    private EidLoginResponse Expired() =>
        Json(200, w => w.WriteString("state", "EXPIRED"), new KeyValuePair<string, string>("Set-Cookie", ClearCookie));

    private EidLoginResponse Failed(string code) =>
        Json(200, w =>
        {
            w.WriteString("state", "FAILED");
            w.WriteString("error", code);
        }, new KeyValuePair<string, string>("Set-Cookie", ClearCookie));

    private EidLoginResponse Fail(string code) =>
        Redirect(FailTo(code), new List<KeyValuePair<string, string>> { new("Set-Cookie", ClearCookie) });

    private static EidLoginResponse Redirect(string to, List<KeyValuePair<string, string>> extra)
    {
        var h = new List<KeyValuePair<string, string>>
        {
            new("Location", to),
            new("Cache-Control", "no-store"),
            new("Referrer-Policy", "no-referrer"),
        };
        h.AddRange(extra);
        return new EidLoginResponse(303, h, "");
    }

    private static EidLoginResponse Error(int status, string code, params (string Name, string Value)[] extra)
    {
        var h = JsonHeaders();
        foreach (var (n, v) in extra)
        {
            h.Add(new(n, v));
        }
        return JsonWith(status, w => w.WriteString("error", code), h);
    }

    private static List<KeyValuePair<string, string>> JsonHeaders(params KeyValuePair<string, string>[] extra)
    {
        var h = new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "application/json; charset=utf-8"),
            new("Cache-Control", "no-store"),
        };
        h.AddRange(extra);
        return h;
    }

    private static EidLoginResponse Json(int status, Action<Utf8JsonWriter> body, params KeyValuePair<string, string>[] extra) =>
        JsonWith(status, body, JsonHeaders(extra));

    private static EidLoginResponse JsonWith(int status, Action<Utf8JsonWriter> body, List<KeyValuePair<string, string>> headers)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return new EidLoginResponse(status, headers, Encoding.UTF8.GetString(ms.ToArray()));
    }

    /// <summary>OnSuccess-ийн header: Set-Cookie нэмэгдэнэ, бусад нь ижил нэрийг солино (TS <c>mergeHeaders</c>).</summary>
    private static List<KeyValuePair<string, string>> Merge(List<KeyValuePair<string, string>> h, IReadOnlyList<KeyValuePair<string, string>>? extra)
    {
        foreach (var (k, v) in extra ?? Array.Empty<KeyValuePair<string, string>>())
        {
            if (!string.Equals(k, "Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                h.RemoveAll(x => string.Equals(x.Key, k, StringComparison.OrdinalIgnoreCase));
            }
            h.Add(new(k, v));
        }
        return h;
    }

    private string CookieHeader(string value, int maxAge)
    {
        var sb = new StringBuilder().Append(_cookieName).Append('=').Append(value).Append("; Path=").Append(_cookiePath);
        if (_cookieDomain is not null)
        {
            sb.Append("; Domain=").Append(_cookieDomain);
        }
        sb.Append("; Max-Age=").Append(Math.Max(0, maxAge).ToString(CultureInfo.InvariantCulture)).Append("; HttpOnly");
        if (_secure)
        {
            sb.Append("; Secure");
        }
        return sb.Append("; SameSite=Lax").ToString();
    }

    private string ClearCookie => CookieHeader("", 0);

    /// <summary>FailureRedirect + <c>eid_error=&lt;код&gt;</c> (өмнөх eid_error-ийг солино; fragment хадгална).</summary>
    private string FailTo(string code)
    {
        var target = _failureRedirect;
        var hash = target.IndexOf('#');
        var fragment = hash >= 0 ? target[hash..] : "";
        if (hash >= 0)
        {
            target = target[..hash];
        }
        var qi = target.IndexOf('?');
        var path = qi >= 0 ? target[..qi] : target;
        var kept = qi >= 0
            ? target[(qi + 1)..].Split('&').Where(p => p.Length > 0 && p.Split('=')[0] != "eid_error").ToList()
            : new List<string>();
        kept.Add("eid_error=" + Uri.EscapeDataString(code));
        return path + "?" + string.Join("&", kept) + fragment;
    }

    // ---- оролтын задлал ----

    /// <summary>Header-ийн утга (нэрийг том жижиг үсэг ялгахгүй); алга бол "".</summary>
    internal static string Header(EidLoginRequest request, string name)
    {
        if (request.Headers.TryGetValue(name, out var v))
        {
            return v ?? "";
        }
        foreach (var h in request.Headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value ?? "";
            }
        }
        return "";
    }

    private static string ReadCookie(string header, string name)
    {
        foreach (var part in header.Split(';'))
        {
            var i = part.IndexOf('=');
            if (i > 0 && part[..i].Trim() == name)
            {
                return part[(i + 1)..].Trim();
            }
        }
        return "";
    }

    private static (string Path, string Query) SplitUrl(string url)
    {
        var u = url ?? "";
        var hash = u.IndexOf('#');
        if (hash >= 0)
        {
            u = u[..hash];
        }
        if (!u.StartsWith('/') && Uri.TryCreate(u, UriKind.Absolute, out var abs))
        {
            u = abs.AbsolutePath + abs.Query;
        }
        var q = u.IndexOf('?');
        return q >= 0 ? (u[..q], u[(q + 1)..]) : (u, "");
    }

    private static string LastSegment(string path)
    {
        var p = path.TrimEnd('/');
        var i = p.LastIndexOf('/');
        return i >= 0 ? p[(i + 1)..] : p;
    }

    /// <summary>application/x-www-form-urlencoded query → (түлхүүр, утга) дарааллаар; буруу %-кодтой хэсгийг алгасна.</summary>
    internal static List<KeyValuePair<string, string>> ParseQuery(string query)
    {
        var list = new List<KeyValuePair<string, string>>();
        foreach (var part in query.Split('&'))
        {
            if (part.Length == 0)
            {
                continue;
            }
            var i = part.IndexOf('=');
            var k = i >= 0 ? part[..i] : part;
            var v = i >= 0 ? part[(i + 1)..] : "";
            try
            {
                list.Add(new(Unescape(k), Unescape(v)));
            }
            catch (FormatException)
            {
                // Go url.ParseQuery: буруу хэсгийг алгасна.
            }
        }
        return list;
    }

    private static string Unescape(string s)
    {
        s = s.Replace('+', ' ');
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '%' && (i + 2 >= s.Length || !Uri.IsHexDigit(s[i + 1]) || !Uri.IsHexDigit(s[i + 2])))
            {
                throw new FormatException("буруу %-код");
            }
        }
        return Uri.UnescapeDataString(s);
    }

    private static string QueryGet(List<KeyValuePair<string, string>> q, string key)
    {
        foreach (var p in q)
        {
            if (p.Key == key)
            {
                return p.Value;
            }
        }
        return "";
    }

    private static bool IsJsonContentType(string contentType)
    {
        var semi = contentType.IndexOf(';');
        var mt = (semi >= 0 ? contentType[..semi] : contentType).Trim();
        return string.Equals(mt, "application/json", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>POST start-ын бие → (mode, idCode, lang); задарсангүй бол null (Go: json.Decode алдаа → invalid_body).</summary>
    private static (string Mode, string IdCode, string Lang)? ParseStartBody(string? body)
    {
        var text = body ?? "";
        if (Encoding.UTF8.GetByteCount(text) > MaxBodyBytes)
        {
            return null;
        }
        try
        {
            using var d = JsonDocument.Parse(text);
            var root = d.RootElement;
            if (root.ValueKind == JsonValueKind.Null)
            {
                return ("", "", "");
            }
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            string? Field(string name)
            {
                if (!root.TryGetProperty(name, out var e) || e.ValueKind == JsonValueKind.Null)
                {
                    return "";
                }
                return e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            }
            if (Field("mode") is not { } mode || Field("idCode") is not { } id || Field("lang") is not { } lang)
            {
                return null;
            }
            return (mode, id, lang);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException)
        {
            // InvalidOperationException: GetString / нэрийн харьцуулалт ганц surrogate-тэй ("\udc00") мөрийг UTF-16 болгож
            // чадаагүй — 500 + stack trace биш, бусад буруу биетэй адил 400 invalid_body.
            return null;
        }
    }

    /// <summary>
    /// <c>start:&lt;ip&gt;</c> хязгаарын түлхүүрийн IP: IPv6 бол /64 угтвар (<c>2001:db8:1:2::/64</c> — нэг клиент /64-ийн
    /// дотор хаягаа сольж хязгаарыг тойрохгүй), IPv4-mapped IPv6 бол IPv4; IPv4 ба задрахгүй утга хэвээр.
    /// </summary>
    internal static string RateKeyIp(string ip)
    {
        if (ip.IndexOf(':') < 0 || !IPAddress.TryParse(ip, out var a) || a.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return ip;
        }
        if (a.IsIPv4MappedToIPv6)
        {
            return a.MapToIPv4().ToString();
        }
        var b = a.GetAddressBytes();
        Array.Clear(b, 8, 8);
        return new IPAddress(b).ToString() + "/64";
    }

    /// <summary>idCode: бүх хоосон зайг хасаж том үсгээр (Go <c>strings.ToUpper(strings.Join(strings.Fields(..), ""))</c>).</summary>
    internal static string NormalizeId(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (var c in raw)
        {
            if (!char.IsWhiteSpace(c))
            {
                sb.Append(c);
            }
        }
        return sb.ToString().ToUpperInvariant();
    }

    /// <summary>
    /// eID-ийн ӨӨРИЙН (JSON биетэй) 4xx: дугаарыг татгалзсан. JSON бус 4xx нь eID-ийн өмнөх proxy-ийнх — тасалдал. 401/403
    /// (тусдаа төрөл) ба 429 нь дугаараас хамаардаггүй тул decoy-гүй.
    /// </summary>
    internal static bool IsRefusal(Exception e)
    {
        if (e is not EidApiException { Status: >= 400 and < 500 and not 401 and not 403 and not 429 } ae)
        {
            return false;
        }
        try
        {
            using var d = JsonDocument.Parse(ae.Body.Trim());
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsValidation(Exception e) => e is EidValidationException or EidSessionFailedException or RevocationFailure;

    private static bool PersonMatchesCertificate(Person? p, CertSubject s) =>
        p is not null && !string.IsNullOrEmpty(p.CivilId) && s.SerialNumber.Length > 0 && s.SerialNumber == "PNOMN-" + p.CivilId;

    private static string OrUnknown(string? s) => string.IsNullOrEmpty(s) ? "UNKNOWN" : s;

    private static string Sha256Hex(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static string TruncateRunes(string s, int n)
    {
        var sb = new StringBuilder();
        var count = 0;
        foreach (var r in s.EnumerateRunes())
        {
            if (count++ == n)
            {
                break;
            }
            sb.Append(r.ToString());
        }
        return sb.ToString();
    }

    private static bool IsCookieAttr(string v) => v.All(c => c > 0x20 && c < 0x7f && c != ';' && c != ',');

    private static Dictionary<string, Func<string, CancellationToken, ValueTask<bool>>> BuildLimits(IDictionary<string, EidLoginRateRule>? user,
        TimeProvider clock)
    {
        var merged = EidLoginRateRule.Defaults();
        foreach (var (k, r) in user ?? new Dictionary<string, EidLoginRateRule>())
        {
            if (k is not ("start" or "push"))
            {
                throw new ArgumentException("eidlogin: RateLimits[\"" + k + "\"] — зөвхөн start | push", nameof(user));
            }
            merged[k] = r ?? EidLoginRateRule.Unlimited;
        }
        var outp = new Dictionary<string, Func<string, CancellationToken, ValueTask<bool>>>(StringComparer.Ordinal);
        foreach (var (k, r) in merged)
        {
            if (r.Func is not null)
            {
                outp[k] = r.Func;
            }
            else if (r.Max > 0)
            {
                if (r.Window <= TimeSpan.Zero)
                {
                    throw new ArgumentException("eidlogin: RateLimits[\"" + k + "\"].Window > 0 байх ёстой", nameof(user));
                }
                var lim = new WindowLimiter(r.Max, r.Window, WindowLimiter.DefaultMaxKeys, clock);
                outp[k] = (key, _) => new ValueTask<bool>(lim.Allow(key));
            }
        }
        return outp;
    }

    private void Log(EidLoginLogLevel level, string message, Exception? e = null) => _log?.Invoke(new EidLoginLogEntry(level, message, e));

    /// <summary>Гэрчилгээний цуцлалтын шалгалт унасан — FAILED VALIDATION (Go <c>revocationError</c>, TS <c>RevocationFailure</c>).</summary>
    private sealed class RevocationFailure : Exception
    {
        public RevocationFailure(bool revoked, Exception inner) : base("eidlogin: цуцлалт: " + inner.Message, inner) => Revoked = revoked;

        public bool Revoked { get; }
    }
}
