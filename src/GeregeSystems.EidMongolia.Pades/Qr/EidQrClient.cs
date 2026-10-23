using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Qr;

/// <summary><see cref="EidQrClient"/>-ийн тохиргоо.</summary>
public sealed class EidQrOptions
{
    /// <summary>RP-API-ийн суурь URL (https; http зөвхөн loopback).</summary>
    public string BaseUrl { get; init; } = "https://rp.eidmongolia.mn";
    /// <summary>RP UUID — JWS-ийн <c>aud</c>.</summary>
    public required string RpUuid { get; init; }
    /// <summary>Иргэний утсанд харагдах RP нэр.</summary>
    public required string RpName { get; init; }
    /// <summary>API secret (rp_sk_…) — зөвхөн RP-API руу (JWKS руу биш).</summary>
    public required string ApiSecret { get; init; }
    /// <summary>mTLS / proxy-д; null бол шинээр үүсгэнэ (client dispose хийхэд хаагдана).</summary>
    public HttpClient? HttpClient { get; init; }
    /// <summary>null = <see cref="EidQr.DefaultJwksUrl"/>.</summary>
    public string? JwksUrl { get; init; }
    /// <summary>null = <see cref="EidQr.DefaultIssuer"/>.</summary>
    public string? Issuer { get; init; }
    /// <summary>JWKS кэш (анхдагч 1 цаг); танихгүй kid ирвэл (≥ 30 с-ийн зайтай) дахин татна.</summary>
    public TimeSpan JwksCacheTtl { get; init; } = TimeSpan.FromHours(1);
    /// <summary>null = <see cref="EidQr.DefaultMaxAge"/>.</summary>
    public TimeSpan? MaxAge { get; init; }
    /// <summary>Нэг HTTP дуудлагын хугацаа (long-poll өөрийн урттай).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);
}

/// <summary>
/// «Миний QR» RP client: <see cref="EidQr.Parse"/> → <see cref="StartAsync"/> → <see cref="ResultAsync"/>. RP-д AUTH +
/// QR_PRESENT + аттрибут бүрд QR_ATTR:&lt;нэр&gt; эрх хэрэгтэй. Thread-safe.
/// </summary>
public sealed class EidQrClient : IDisposable
{
    private const int MaxJson = 4 << 20;
    private const int MaxJwks = 64 << 10;
    private static readonly TimeSpan ServerPoll = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultMaxWait = TimeSpan.FromSeconds(600);
    private static readonly TimeSpan WaitGrace = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan JwksMinRefresh = TimeSpan.FromSeconds(30);

    private readonly EidQrOptions _o;
    private readonly string _base;
    private readonly HttpClient _http;
    private readonly bool _owns;
    private readonly SemaphoreSlim _jwksLock = new(1, 1);
    private Jwks? _jwks;
    private DateTimeOffset _fetchedAt;
    private DateTimeOffset _lastAttempt;

    /// <summary>Шинэ client.</summary>
    public EidQrClient(EidQrOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrEmpty(_o.ApiSecret))
        {
            throw new ArgumentException("ApiSecret шаардлагатай", nameof(options));
        }
        _base = CheckUrl(_o.BaseUrl, "BaseUrl").TrimEnd('/');
        if (_o.HttpClient is { } hc)
        {
            _http = hc;
        }
        else
        {
            _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _owns = true;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_owns)
        {
            _http.Dispose();
        }
        _jwksLock.Dispose();
    }

    private static string CheckUrl(string url, string what)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !(u.Scheme == "https" || (u.Scheme == "http" && u.IsLoopback)))
        {
            throw new ArgumentException(what + " https байх ёстой (http зөвхөн loopback): " + url);
        }
        return url;
    }

    /// <summary>
    /// <c>POST /authentication/qr</c> — QR-ийн токеныг (нэг удаагийн) CA-д өгч иргэний утас руу хүсэлт илгээнэ;
    /// <see cref="QrSession.Vc"/>-г кассын дэлгэцэнд харуул. Алдаа: <c>QR_FORMAT_INVALID</c> / <c>QR_ATTRIBUTES_INVALID</c>
    /// (CA руу явахгүй), 404 <c>QR_TOKEN_INVALID</c> (шинэ QR гаргуул), 403 (QR_PRESENT / QR_ATTR:* эрх алга).
    /// </summary>
    public async Task<QrSession> StartAsync(QrStartRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var token = EidQr.Parse(request.Qr);
        var attrs = EidQr.CheckAttributes(request.Attributes);
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var nonce = string.IsNullOrWhiteSpace(request.Nonce) ? null : request.Nonce.Trim();
        var body = new Dictionary<string, object>
        {
            ["qr"] = EidQr.Prefix + token,
            ["attributes"] = attrs,
            ["relyingPartyUUID"] = _o.RpUuid,
            ["relyingPartyName"] = _o.RpName,
            ["signatureProtocol"] = "ACSP_V2",
            ["signatureProtocolParameters"] = new Dictionary<string, string> { ["rpChallenge"] = challenge },
        };
        if (nonce is not null)
        {
            body["nonce"] = nonce;
        }
        using var req = new HttpRequestMessage(HttpMethod.Post, _base + "/authentication/qr")
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        using var doc = await SendAsync(req, _o.Timeout, cancellationToken).ConfigureAwait(false);
        var r = doc.RootElement;
        var sid = r.TryGetProperty("sessionID", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
        if (string.IsNullOrEmpty(sid))
        {
            throw new EidQrException(EidQrErrorCodes.HttpError, "POST /authentication/qr: sessionID алга");
        }
        var vc = "";
        if (r.TryGetProperty("vc", out var v))
        {
            vc = v.ValueKind == JsonValueKind.String ? v.GetString()! :
                v.ValueKind == JsonValueKind.Object && v.TryGetProperty("value", out var vv) && vv.ValueKind == JsonValueKind.String ? vv.GetString()! : "";
        }
        DateTimeOffset? expiresAt = null;
        if (r.TryGetProperty("expiresAt", out var e) && e.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(e.GetString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var ea))
        {
            expiresAt = ea;
        }
        return new QrSession { SessionId = sid, Vc = vc, Nonce = nonce ?? challenge, Attributes = attrs, ExpiresAt = expiresAt };
    }

    /// <summary>
    /// Session дуустал long-poll хийж presentation-ийг CA-ийн JWKS-ээр шалгана. Татгалзсан / хугацаа дууссан бол
    /// <c>SESSION_FAILED</c> (<see cref="EidQrException.EndResult"/>); шалгалт унавал <c>QR_PRESENTATION_INVALID</c>
    /// (ИТГЭХГҮЙ); JWKS татагдахгүй бол <c>QR_JWKS_UNAVAILABLE</c> (дахин оролдож болно).
    /// </summary>
    /// <param name="session">StartAsync-ийн хариу.</param>
    /// <param name="maxWait">null бол session.ExpiresAt + 15 с, тэр нь ч алга бол 600 с.</param>
    /// <param name="cancellationToken">Цуцлах.</param>
    public async Task<QrPresentation> ResultAsync(QrSession session, TimeSpan? maxWait = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var now = DateTimeOffset.UtcNow;
        var deadline = maxWait is { } mw ? now + mw
            : session.ExpiresAt is { } ea ? (ea + WaitGrace > now + TimeSpan.FromSeconds(1) ? ea + WaitGrace : now + TimeSpan.FromSeconds(1))
            : now + DefaultMaxWait;
        while (true)
        {
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new EidQrException(EidQrErrorCodes.SessionFailed, "session хугацаа дууссан") { EndResult = "TIMEOUT" };
            }
            var poll = remaining < ServerPoll ? (remaining < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : remaining) : ServerPoll;
            var url = _base + "/session/" + Uri.EscapeDataString(session.SessionId) + "?timeoutMs=" + (long)poll.TotalMilliseconds;
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var doc = await SendAsync(req, poll + TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            var r = doc.RootElement;
            if (!r.TryGetProperty("state", out var st) || st.GetString() != "COMPLETE")
            {
                continue;
            }
            var end = r.TryGetProperty("result", out var res) && res.ValueKind == JsonValueKind.Object &&
                res.TryGetProperty("endResult", out var er) && er.ValueKind == JsonValueKind.String ? er.GetString() : null;
            if (end != "OK")
            {
                throw new EidQrException(EidQrErrorCodes.SessionFailed, "session амжилтгүй: " + end) { EndResult = end ?? "UNKNOWN" };
            }
            var jws = r.TryGetProperty("presentation", out var p) && p.ValueKind == JsonValueKind.Object &&
                p.TryGetProperty("jws", out var j) && j.ValueKind == JsonValueKind.String ? j.GetString() : null;
            if (string.IsNullOrEmpty(jws))
            {
                throw EidQr.Bad("хариунд presentation алга");
            }
            return await VerifyAsync(jws, session, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Хадгалсан presentation JWS-ийг QrSession-тэй тулгаж шалгана (JWKS кэш; танихгүй kid → нэг удаа дахин татна).</summary>
    public async Task<QrPresentation> VerifyAsync(string jws, QrSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var exp = new QrExpect
        {
            Issuer = _o.Issuer,
            Audience = _o.RpUuid,
            SessionId = session.SessionId,
            Nonce = session.Nonce,
            Attributes = session.Attributes,
            MaxAge = _o.MaxAge,
        };
        var p = EidQr.Verify(jws, await KeysAsync(false, cancellationToken).ConfigureAwait(false), exp, out var unknown);
        if (!unknown)
        {
            return p!;
        }
        p = EidQr.Verify(jws, await KeysAsync(true, cancellationToken).ConfigureAwait(false), exp, out unknown);
        return unknown ? throw EidQr.Bad("JWKS-д kid алга") : p!;
    }

    private async Task<Jwks> KeysAsync(bool force, CancellationToken ct)
    {
        await _jwksLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var fresh = _jwks is not null && now - _fetchedAt < _o.JwksCacheTtl;
            if (fresh && (!force || now - _lastAttempt < JwksMinRefresh))
            {
                return _jwks!;
            }
            _lastAttempt = now;
            var k = await FetchJwksAsync(ct).ConfigureAwait(false);
            _jwks = k;
            _fetchedAt = now;
            return k;
        }
        finally
        {
            _jwksLock.Release();
        }
    }

    private async Task<Jwks> FetchJwksAsync(CancellationToken ct)
    {
        var url = _o.JwksUrl ?? EidQr.DefaultJwksUrl;
        try
        {
            CheckUrl(url, "JwksUrl");
        }
        catch (ArgumentException e)
        {
            throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "JwksUrl https байх ёстой", e);
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_o.Timeout);
        try
        {
            // RP secret ЭНД ИЛГЭЭХГҮЙ — нийтийн түлхүүр.
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            if (res.StatusCode != HttpStatusCode.OK)
            {
                throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "HTTP " + (int)res.StatusCode);
            }
            var raw = await ReadLimitedAsync(res, MaxJwks, cts.Token).ConfigureAwait(false);
            var k = Jwks.Parse(Encoding.UTF8.GetString(raw));
            return k.Count == 0 ? throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "JWKS хоосон") : k;
        }
        catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "татагдсангүй", e);
        }
    }

    private async Task<JsonDocument> SendAsync(HttpRequestMessage req, TimeSpan timeout, CancellationToken ct)
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.ApiSecret);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        HttpResponseMessage res;
        try
        {
            res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new EidQrException(EidQrErrorCodes.NetworkError, req.Method + " " + req.RequestUri!.AbsolutePath, e);
        }
        using (res)
        {
            var raw = await ReadLimitedAsync(res, MaxJson, cts.Token).ConfigureAwait(false);
            if ((int)res.StatusCode >= 300)
            {
                string? code = null;
                string? msg = null;
                try
                {
                    using var ed = JsonDocument.Parse(raw);
                    if (ed.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        code = ed.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
                        msg = ed.RootElement.TryGetProperty("error", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
                    }
                }
                catch (JsonException)
                {
                    // proxy-ийн JSON биш хариу
                }
                throw new EidQrException(string.IsNullOrEmpty(code) ? EidQrErrorCodes.HttpError : code,
                    "RP-API " + (int)res.StatusCode + (msg is null ? "" : ": " + msg))
                { HttpStatus = (int)res.StatusCode };
            }
            try
            {
                return JsonDocument.Parse(raw.Length == 0 ? "{}"u8.ToArray() : raw);
            }
            catch (JsonException e)
            {
                throw new EidQrException(EidQrErrorCodes.HttpError, "хариу JSON биш", e) { HttpStatus = (int)res.StatusCode };
            }
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpResponseMessage res, int limit, CancellationToken ct)
    {
        if (res.Content.Headers.ContentLength > limit)
        {
            throw new EidQrException(EidQrErrorCodes.HttpError, "хариу хэт том");
        }
        using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buf = new byte[16 << 10];
        int n;
        while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > limit)
            {
                throw new EidQrException(EidQrErrorCodes.HttpError, "хариу хэт том");
            }
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }
}
