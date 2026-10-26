using System;
using System.Collections.Generic;
using System.IO;
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
    /// <summary>Дэд системийн шошго (<c>relyingPartyName</c>, CA лог). JWS / иргэний утсанд бүртгэлийн нэр харагдана.</summary>
    public required string RpName { get; init; }
    /// <summary>API secret (rp_sk_…) — зөвхөн RP-API руу.</summary>
    public required string ApiSecret { get; init; }
    /// <summary>mTLS / proxy-д; null бол шинээр үүсгэнэ (client dispose хийхэд хаагдана).</summary>
    public HttpClient? HttpClient { get; init; }
    /// <summary>null = <see cref="EidQr.DefaultIssuer"/>.</summary>
    public string? Issuer { get; init; }
    /// <summary>Нэг HTTP дуудлагын хугацаа (long-poll өөрийн урттай).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);
}

/// <summary>
/// «Миний QR» RP client: <see cref="EidQr.Parse"/> → <see cref="StartAsync"/> (<c>POST /authentication/qr</c>) →
/// <see cref="ResultAsync"/> / <see cref="CheckAsync(QrSession, CancellationToken)"/> (<c>GET /session/{id}</c>) →
/// иргэний PS256 JWS-ийг <see cref="EidQr.VerifyAsync"/>-аар шалгасан <see cref="QrResult"/>. RP-д зөвхөн
/// <c>QR_PRESENT</c> эрх. Thread-safe.
/// </summary>
public sealed class EidQrClient : IDisposable
{
    private const int MaxJson = 4 << 20;
    private static readonly TimeSpan ServerPoll = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultMaxWait = TimeSpan.FromSeconds(600);
    private static readonly TimeSpan DefaultCheckPoll = TimeSpan.FromSeconds(1);

    private readonly EidQrOptions _o;
    private readonly QrTrust? _trust;
    private readonly string _base;
    private readonly HttpClient _http;
    private readonly bool _owns;

    /// <summary>Шинэ client.</summary>
    /// <param name="options">RP-API тохиргоо.</param>
    /// <param name="trust">null = шигтгэсэн үндэсний root + завсрын, олгогч 04, AIA-ийн OCSP (hard-fail).</param>
    public EidQrClient(EidQrOptions options, QrTrust? trust = null)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrEmpty(_o.ApiSecret))
        {
            throw new ArgumentException("ApiSecret шаардлагатай", nameof(options));
        }
        _trust = trust;
        _base = CheckUrl(_o.BaseUrl, "BaseUrl").TrimEnd('/');
        if (_o.HttpClient is { } hc)
        {
            _http = hc;
        }
        else
        {
            _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = Timeout.InfiniteTimeSpan };
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
    }

    /// <summary>
    /// <c>POST /authentication/qr</c> — иргэний утас руу PIN2 хүсэлт илгээнэ. Буруу мөр <c>QR_FORMAT_INVALID</c> (CA руу
    /// явахгүй). Серверийн код дамжина: 404 <c>QR_TOKEN_INVALID</c> (шинэ QR), 409 <c>NO_SIGNING_CERTIFICATE</c>, 403 <c>PERMISSION_DENIED</c> /
    /// <c>RP_REQUIRED</c>, 429 <c>RATE_LIMITED</c>, 400 <c>REQUEST_INVALID</c>.
    /// </summary>
    public async Task<QrSession> StartAsync(QrStartRequest req, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(req);
        var (_, qr) = EidQr.Parse(req.Qr);
        var nonce = string.IsNullOrEmpty(req.Nonce) ? NewNonce() : req.Nonce;
        var body = new Dictionary<string, string>
        {
            ["qr"] = qr,
            ["relyingPartyUUID"] = _o.RpUuid,
            ["relyingPartyName"] = string.IsNullOrEmpty(req.RelyingPartyName) ? _o.RpName : req.RelyingPartyName,
            ["nonce"] = nonce,
        };
        using var msg = new HttpRequestMessage(HttpMethod.Post, _base + "/authentication/qr")
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        using var doc = await SendAsync(msg, _o.Timeout, ct).ConfigureAwait(false);
        var r = doc.RootElement;
        var sid = r.ValueKind == JsonValueKind.Object && r.TryGetProperty("sessionID", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
        if (string.IsNullOrEmpty(sid))
        {
            throw new EidQrException(EidQrErrorCodes.HttpError, "POST /authentication/qr: sessionID алга");
        }
        return new QrSession(sid, nonce);
    }

    /// <summary>base64url(16 CSPRNG байт) = 22 тэмдэгт.</summary>
    internal static string NewNonce() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Session дуустал long-poll хийж presentation-ийг шалгана. Татгалзсан / CA-ийн хугацаа дууссан бол
    /// <c>SESSION_FAILED</c> (<see cref="EidQrException.EndResult"/>); 410 → <c>QR_PRESENTATION_GONE</c> (нэг л удаа
    /// уншигдана — шинэ QR); шалгалт унавал §6.2-ийн <c>QR_*</c> код (ИТГЭХГҮЙ); <paramref name="maxWait"/> (анхдагч
    /// 600 с) дуусахад иргэн хариулаагүй бол <c>QR_PENDING</c>.
    /// </summary>
    public async Task<QrResult> ResultAsync(QrSession s, TimeSpan? maxWait = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(s);
        var deadline = DateTimeOffset.UtcNow + (maxWait is { } mw && mw > TimeSpan.Zero ? mw : DefaultMaxWait);
        while (true)
        {
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new EidQrException(EidQrErrorCodes.Pending, "иргэн хараахан хариулаагүй");
            }
            var poll = remaining < ServerPoll ? (remaining < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : remaining) : ServerPoll;
            var jws = await PollOnceAsync(s, poll, ct).ConfigureAwait(false);
            if (jws is not null)
            {
                return await VerifyAsync(jws, s, ct).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Нэг удаагийн шалгалт (CA дээр 1 с хүртэл хүлээнэ) — polling UI-д.</summary>
    public Task<QrCheck> CheckAsync(QrSession s, CancellationToken ct = default) => CheckAsync(s, DefaultCheckPoll, ct);

    /// <summary>
    /// Нэг удаагийн шалгалт: <c>GET /session/{id}</c> (<paramref name="serverPoll"/> хүртэл). Хариулаагүй бол
    /// <c>Complete == false</c>; бусад нь <see cref="ResultAsync"/>-тэй ижил.
    /// </summary>
    public async Task<QrCheck> CheckAsync(QrSession s, TimeSpan serverPoll, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(s);
        var jws = await PollOnceAsync(s, serverPoll > TimeSpan.Zero ? serverPoll : DefaultCheckPoll, ct).ConfigureAwait(false);
        return jws is null ? new QrCheck(false, null) : new QrCheck(true, await VerifyAsync(jws, s, ct).ConfigureAwait(false));
    }

    /// <summary>Хадгалсан JWS-ийг session-тэй тулгаж (aud = RpUuid, sid, nonce, iss = Options.Issuer) шалгана.</summary>
    public Task<QrResult> VerifyAsync(string jws, QrSession s, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(s);
        return EidQr.VerifyAsync(jws, new QrExpect(_o.RpUuid, s.SessionId, s.Nonce, _o.Issuer), _trust, ct);
    }

    /// <summary>Нэг poll: RUNNING бол null; COMPLETE+OK бол presentation.jws; бусад COMPLETE бол SESSION_FAILED; 410 → QR_PRESENTATION_GONE.</summary>
    private async Task<string?> PollOnceAsync(QrSession s, TimeSpan poll, CancellationToken ct)
    {
        var url = _base + "/session/" + Uri.EscapeDataString(s.SessionId) + "?timeoutMs=" + (long)poll.TotalMilliseconds;
        using var msg = new HttpRequestMessage(HttpMethod.Get, url);
        JsonDocument doc;
        try
        {
            doc = await SendAsync(msg, poll + TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        }
        catch (EidQrException e) when (e.HttpStatus == 410 && e.Code == EidQrErrorCodes.HttpError)
        {
            throw new EidQrException(EidQrErrorCodes.PresentationGone, "presentation аль хэдийн уншигдсан эсвэл хугацаа дууссан", e) { HttpStatus = 410 };
        }
        using (doc)
        {
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object || !r.TryGetProperty("state", out var st) || st.ValueKind != JsonValueKind.String || st.GetString() != "COMPLETE")
            {
                return null;
            }
            var end = r.TryGetProperty("result", out var res) && res.ValueKind == JsonValueKind.Object &&
                res.TryGetProperty("endResult", out var er) && er.ValueKind == JsonValueKind.String ? er.GetString() : null;
            if (end != "OK")
            {
                throw new EidQrException(EidQrErrorCodes.SessionFailed, "session амжилтгүй: " + end) { EndResult = end ?? "UNKNOWN" };
            }
            var jws = r.TryGetProperty("presentation", out var pr) && pr.ValueKind == JsonValueKind.Object &&
                pr.TryGetProperty("jws", out var j) && j.ValueKind == JsonValueKind.String ? j.GetString() : null;
            return string.IsNullOrEmpty(jws) ? throw new EidQrException(EidQrErrorCodes.JwsMalformed, "хариунд presentation.jws алга") : jws;
        }
    }

    private static string CheckUrl(string url, string what)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !(u.Scheme == "https" || (u.Scheme == "http" && u.IsLoopback)))
        {
            throw new ArgumentException(what + " https байх ёстой (http зөвхөн loopback): " + url);
        }
        return url;
    }

    /// <summary>RP-API дуудлага (Bearer): 2xx бол JSON; бусад бол серверийн <c>code</c> (эсвэл HTTP_ERROR) + HttpStatus.</summary>
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
