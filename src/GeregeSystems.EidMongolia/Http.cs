using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// RP-API HTTP давхарга (Go client.go <c>httpDoer</c>, TS http.ts): Bearer secret, timeout, Accept-Language, JSON 4 MiB
/// хязгаар, HTTP статусыг төрөлжсөн <see cref="EidException"/> руу буулгана. Thread-safe.
/// </summary>
internal sealed class EidHttp
{
    /// <summary>JSON хариуны дээд хэмжээ; хэтэрвэл <see cref="EidResponseTooLargeException"/> (таслахгүй).</summary>
    public const int MaxJsonBytes = 4 << 20;
    private const int MaxErrorBody = 64 << 10;

    internal static readonly JsonSerializerOptions Json = new()
    {
        // Go encoding/json шиг талбарын нэрийг том/жижиг үсэг үл харгалзан тааруулна.
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Серверийн <c>code</c> → <see cref="EidApiException"/>-ийн дэд анги (401/403-аас бусад статус).</summary>
    private static readonly Dictionary<string, Func<int, string, string?, string?, TimeSpan?, HttpResponseHeaders?, EidApiException>> Typed = new()
    {
        [EidErrorCodes.NoSigningCertificate] = (s, b, c, sv, r, h) => new EidNoSigningCertificateException(s, b, c, sv, r, h),
        [EidErrorCodes.CertChoiceInvalid] = (s, b, c, sv, r, h) => new EidCertChoiceInvalidException(s, b, c, sv, r, h),
        [EidErrorCodes.RequestInvalid] = (s, b, c, sv, r, h) => new EidRequestInvalidException(s, b, c, sv, r, h),
        [EidErrorCodes.QrTokenInvalid] = (s, b, c, sv, r, h) => new EidQrTokenInvalidException(s, b, c, sv, r, h),
        [EidErrorCodes.OrgNotActive] = (s, b, c, sv, r, h) => new EidOrgNotActiveException(s, b, c, sv, r, h),
        [EidErrorCodes.SealNotIssued] = (s, b, c, sv, r, h) => new EidSealNotIssuedException(s, b, c, sv, r, h),
        [EidErrorCodes.SealCertRevoked] = (s, b, c, sv, r, h) => new EidSealCertRevokedException(s, b, c, sv, r, h),
        [EidErrorCodes.SealKeyUnavailable] = (s, b, c, sv, r, h) => new EidSealKeyUnavailableException(s, b, c, sv, r, h),
        [EidErrorCodes.SealCertExpired] = (s, b, c, sv, r, h) => new EidSealCertExpiredException(s, b, c, sv, r, h),
        [EidErrorCodes.SealCertNotYetValid] = (s, b, c, sv, r, h) => new EidSealCertNotYetValidException(s, b, c, sv, r, h),
        [EidErrorCodes.SealApproverUnavailable] = (s, b, c, sv, r, h) => new EidSealApproverUnavailableException(s, b, c, sv, r, h),
        [EidErrorCodes.SealRequestNotFound] = (s, b, c, sv, r, h) => new EidSealRequestNotFoundException(s, b, c, sv, r, h),
        [EidErrorCodes.SealServiceDisabled] = (s, b, c, sv, r, h) => new EidSealServiceDisabledException(s, b, c, sv, r, h),
        [EidErrorCodes.AuthSessionWrongFlow] = (s, b, c, sv, r, h) => new EidAuthSessionWrongFlowException(s, b, c, sv, r, h),
        [EidErrorCodes.AuthSessionNotCompleted] = (s, b, c, sv, r, h) => new EidAuthSessionNotCompletedException(s, b, c, sv, r, h),
        [EidErrorCodes.AuthSessionTooOld] = (s, b, c, sv, r, h) => new EidAuthSessionTooOldException(s, b, c, sv, r, h),
        [EidErrorCodes.AuthSessionAlreadyUsed] = (s, b, c, sv, r, h) => new EidAuthSessionAlreadyUsedException(s, b, c, sv, r, h),
        [EidErrorCodes.AuthSessionNotFound] = (s, b, c, sv, r, h) => new EidAuthSessionNotFoundException(s, b, c, sv, r, h),
        [EidErrorCodes.SealGrantAlreadyApproved] = (s, b, c, sv, r, h) => new EidSealGrantAlreadyApprovedException(s, b, c, sv, r, h),
        [EidErrorCodes.SealGrantNotFound] = (s, b, c, sv, r, h) => new EidSealGrantNotFoundException(s, b, c, sv, r, h),
        [EidErrorCodes.SealNotFound] = (s, b, c, sv, r, h) => new EidSealNotFoundException(s, b, c, sv, r, h),
        [EidErrorCodes.SealDocMismatch] = (s, b, c, sv, r, h) => new EidSealDocMismatchException(s, b, c, sv, r, h),
        [EidErrorCodes.DocIdReserved] = (s, b, c, sv, r, h) => new EidDocIdReservedException(s, b, c, sv, r, h),
        [EidErrorCodes.RpNotActive] = (s, b, c, sv, r, h) => new EidRpNotActiveException(s, b, c, sv, r, h),
        [EidErrorCodes.RpPermissionsFull] = (s, b, c, sv, r, h) => new EidRpPermissionsFullException(s, b, c, sv, r, h),
    };

    private readonly string _base;
    private readonly string _secret;
    private readonly TimeSpan _timeout;
    private readonly HttpClient _http;
    private readonly string? _lang;

    public EidHttp(string baseUrl, string secret, TimeSpan timeout, HttpClient http, string? lang)
    {
        _base = baseUrl;
        _secret = secret;
        _timeout = timeout;
        _http = http;
        _lang = string.IsNullOrWhiteSpace(lang) ? null : lang.Trim();
    }

    /// <summary>POST JSON → T (хоосон хариу бол default).</summary>
    public async Task<T?> PostJsonAsync<T>(string path, object body, TimeSpan? timeout, CancellationToken ct)
    {
        var (_, raw) = await SendJsonAsync(HttpMethod.Post, path, Serialize(body), timeout, ct).ConfigureAwait(false);
        return Decode<T>(raw, "POST", path);
    }

    /// <summary>POST JSON + амжилттай хариуны статус (201 / 200-г ялгах: <c>POST /pdf/signatures</c>).</summary>
    public async Task<(int Status, T? Body)> PostJsonWithStatusAsync<T>(string path, object body, TimeSpan? timeout, CancellationToken ct)
    {
        var (status, raw) = await SendJsonAsync(HttpMethod.Post, path, Serialize(body), timeout, ct).ConfigureAwait(false);
        return (status, Decode<T>(raw, "POST", path));
    }

    /// <summary>GET → T (хоосон хариу бол default).</summary>
    public async Task<T?> GetJsonAsync<T>(string path, TimeSpan? timeout, CancellationToken ct)
    {
        var (_, raw) = await SendJsonAsync(HttpMethod.Get, path, null, timeout, ct).ConfigureAwait(false);
        return Decode<T>(raw, "GET", path);
    }

    /// <summary>GET → түүхий бие (4 MiB хүртэл).</summary>
    public async Task<byte[]> GetRawAsync(string path, TimeSpan? timeout, CancellationToken ct)
    {
        var (_, raw) = await SendJsonAsync(HttpMethod.Get, path, null, timeout, ct).ConfigureAwait(false);
        return raw;
    }

    /// <summary>POST JSON → түүхий бие (4 MiB хүртэл; Raw талбартай хариунд).</summary>
    public async Task<byte[]> PostRawAsync(string path, object body, TimeSpan? timeout, CancellationToken ct)
    {
        var (_, raw) = await SendJsonAsync(HttpMethod.Post, path, Serialize(body), timeout, ct).ConfigureAwait(false);
        return raw;
    }

    /// <summary>POST дурын (ж: multipart/form-data) бие → түүхий хариу (4 MiB хүртэл).</summary>
    public async Task<byte[]> PostBytesAsync(string path, byte[] body, string contentType, TimeSpan? timeout, CancellationToken ct)
    {
        var (_, raw) = await SendJsonAsync(HttpMethod.Post, path, body, timeout, ct, contentType).ConfigureAwait(false);
        return raw;
    }

    private static byte[] Serialize(object body) => JsonSerializer.SerializeToUtf8Bytes(body, body.GetType(), Json);

    internal static T? Decode<T>(byte[] raw, string method, string path)
    {
        if (raw.AsSpan().Trim(" \t\r\n"u8).IsEmpty)
        {
            return default;
        }
        try
        {
            return JsonSerializer.Deserialize<T>(raw, Json);
        }
        catch (JsonException e)
        {
            throw new EidException("eid: " + method + " " + RpRoutes.MaskPath(path) + ": хариу задарсангүй", e);
        }
    }

    private async Task<(int Status, byte[] Body)> SendJsonAsync(HttpMethod method, string path, byte[]? body, TimeSpan? timeout, CancellationToken ct,
        string contentType = "application/json")
    {
        var op = method.Method + " " + RpRoutes.MaskPath(path);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout is { } t && t > TimeSpan.Zero ? t : _timeout);
        using var req = new HttpRequestMessage(method, _base + path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
        if (_lang is not null)
        {
            req.Headers.TryAddWithoutValidation("Accept-Language", _lang);
        }
        if (body is not null)
        {
            req.Content = new ByteArrayContent(body);
            req.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        }
        try
        {
            using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            var status = (int)res.StatusCode;
            if (status >= 300)
            {
                var errRaw = await ReadAsync(res, MaxErrorBody, truncate: true, op, cts.Token).ConfigureAwait(false);
                throw MapError(status, errRaw, res.Headers, DateTimeOffset.UtcNow);
            }
            return (status, await ReadAsync(res, MaxJsonBytes, truncate: false, op, cts.Token).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException e)
        {
            throw new EidNetworkException(op, timeout: true, e);
        }
        catch (Exception e) when (e is HttpRequestException or IOException)
        {
            throw new EidNetworkException(op, timeout: false, e);
        }
    }

    /// <summary>
    /// Хариуны биеийг <paramref name="limit"/> хүртэл уншина. <paramref name="truncate"/> = false үед Content-Length эсвэл
    /// бодит урт хэтэрвэл <see cref="EidResponseTooLargeException"/>; true (алдааны бие) үед таслана.
    /// </summary>
    private static async Task<byte[]> ReadAsync(HttpResponseMessage res, int limit, bool truncate, string op, CancellationToken ct)
    {
        if (!truncate && res.Content.Headers.ContentLength > limit)
        {
            throw new EidResponseTooLargeException(op, limit);
        }
        using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buf = new byte[16 << 10];
        while (true)
        {
            var n = await s.ReadAsync(buf, ct).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }
            if (ms.Length + n > limit)
            {
                if (!truncate)
                {
                    throw new EidResponseTooLargeException(op, limit);
                }
                ms.Write(buf, 0, (int)(limit - ms.Length));
                break;
            }
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>Алдааны хариу → төрөлжсөн алдаа (Go <c>send</c>, TS <c>Http.send</c>).</summary>
    internal static EidException MapError(int status, byte[] raw, HttpResponseHeaders? headers, DateTimeOffset now)
    {
        var text = Encoding.UTF8.GetString(raw);
        var (msg, code, service) = ErrorBody(raw);
        var retry = ParseRetryAfter(headers is not null && headers.TryGetValues("Retry-After", out var v) ? v.FirstOrDefault() : null, now);
        switch (status)
        {
            case 401:
                return new EidAuthenticationException(code, msg, text, headers);
            case 403:
                return new EidForbiddenException(code, msg, retry, headers);
        }
        return code is not null && Typed.TryGetValue(code, out var make)
            ? make(status, text, code, service, retry, headers)
            : new EidApiException(status, text, code, service, retry, headers);
    }

    /// <summary>Серверийн алдааны JSON <c>{"error","code","service"}</c>; JSON биш (proxy) эсвэл хоосон мөр бол null.</summary>
    private static (string? Message, string? Code, string? Service) ErrorBody(byte[] raw)
    {
        try
        {
            using var d = JsonDocument.Parse(raw);
            if (d.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (null, null, null);
            }
            return (Str(d.RootElement, "error"), Str(d.RootElement, "code"), Str(d.RootElement, "service"));
        }
        catch (JsonException)
        {
            return (null, null, null);
        }

        static string? Str(JsonElement o, string name) =>
            o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 } s ? s : null;
    }

    private static readonly string[] HttpDateFormats =
    {
        "r", // RFC 1123: Sun, 06 Nov 1994 08:49:37 GMT
        "dddd, dd'-'MMM'-'yy HH':'mm':'ss 'GMT'", // RFC 850
        "ddd MMM d HH':'mm':'ss yyyy", // asctime
        "ddd MMM dd HH':'mm':'ss yyyy",
    };

    /// <summary>
    /// RFC 9110 §10.2.3: delay-seconds эсвэл HTTP-date (<paramref name="now"/>-оос хойшхи хугацаа). Буруу / өнгөрсөн /
    /// 24 цагаас их → null (Go <c>parseRetryAfter</c>).
    /// </summary>
    internal static TimeSpan? ParseRetryAfter(string? value, DateTimeOffset now)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0)
        {
            return null;
        }
        if (long.TryParse(v, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n))
        {
            return n <= 0 || n > 86_400 ? null : TimeSpan.FromSeconds(n);
        }
        if (DateTimeOffset.TryParseExact(v, HttpDateFormats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AllowWhiteSpaces, out var t) && t > now)
        {
            return t - now;
        }
        return null;
    }
}
