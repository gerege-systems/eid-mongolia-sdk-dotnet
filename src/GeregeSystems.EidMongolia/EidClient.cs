using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary><see cref="EidClient"/>-ийн тохиргоо (Go <c>Config</c>).</summary>
public sealed class EidClientOptions
{
    /// <summary>
    /// RP-API-ийн БҮТЭН суурь URL; SDK зам залгахаас өөр юу ч нэмэхгүй. null / "" = <see cref="EidClient.DefaultBaseUrl"/>.
    /// https заавал (http зөвхөн localhost/loopback).
    /// </summary>
    public string? BaseUrl { get; init; }

    /// <summary>RP таних мэдээлэл + API secret (заавал).</summary>
    public required EidCredentials Credentials { get; init; }

    /// <summary>Auth/sign бүрийн анхдагч certLevel (<see cref="CertificateLevels"/>). null = QUALIFIED.</summary>
    public string? DefaultCertificateLevel { get; init; }

    /// <summary>Нэг HTTP дуудлагын анхдагч хугацаа. null / ≤ 0 = 15 с. Long-poll ба PDF өөрийн уртыг хэрэглэнэ.</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>PDF гарын үсгийн бүртгэлийн (<c>POST /pdf/signatures</c>) хугацаа. null / ≤ 0 = <see cref="EidClient.DefaultPdfTimeout"/>.</summary>
    public TimeSpan? PdfTimeout { get; init; }

    /// <summary>
    /// Sign / certificate-choice session-ий ExpiresAt-ийг (CA expiresAt буцаагаагүй үед) тооцоолох хугацаа. null / ≤ 0 =
    /// <see cref="SessionTimes.DefaultSignSessionTtl"/>.
    /// </summary>
    public TimeSpan? SignSessionTtl { get; init; }

    /// <summary>
    /// Хүнд харуулах текстийн хэл (RoleLabel г.м.): дуудлага бүрд <c>Accept-Language</c> болж илгээгдэнэ ("mn" | "en").
    /// null / "" = илгээхгүй (сервер mn).
    /// </summary>
    public string? Language { get; init; }

    /// <summary>
    /// Цаг (session-ий ReceivedAt / ExpiresAt-ийн тооцоолол, <see cref="SessionService.WaitForResultAsync"/>-ийн хугацаа).
    /// null = <see cref="System.TimeProvider.System"/>; тестэд хянах боломжтой цаг өгнө.
    /// </summary>
    public TimeProvider? TimeProvider { get; init; }
}

/// <summary>
/// eID Mongolia RP-API client (Go <c>eid.Client</c>, TS <c>EidClient</c>-ийн .NET порт — хөгжүүлэлт явагдаж байна).
/// Одоогоор: тохиргоо, HTTP давхарга, алдаа, <see cref="Auth"/> (push / device link + discovery), <see cref="Sign"/>
/// (digest / text / linked / device link / certificate-choice), <see cref="Session"/> (poll / wait), <see cref="Pdf"/>
/// (<c>POST /pdf/signatures</c>). Validator дараагийн хувилбарт. mTLS: client certificate-тэй <see cref="HttpClient"/>-ийг
/// конструкторт өгнө. Thread-safe.
/// </summary>
public sealed class EidClient : IDisposable
{
    /// <summary>RP-API-ийн албан ёсны хост (/v3-гүй). mTLS-тэй RP ч мөн энэ хост.</summary>
    public const string DefaultBaseUrl = "https://rp.eidmongolia.mn";

    /// <summary>Нэг HTTP дуудлагын анхдагч хугацаа.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    /// <summary>PDF гарын үсгийн бүртгэлийн анхдагч хугацаа (CA CMS + TSA + LTV шалгадаг; nginx proxy_read_timeout-оос бага).</summary>
    public static readonly TimeSpan DefaultPdfTimeout = TimeSpan.FromSeconds(80);

    /// <summary>JSON хариуны дээд хэмжээ (4 MiB); хэтэрвэл <see cref="EidResponseTooLargeException"/>.</summary>
    public const int MaxJsonBytes = EidHttp.MaxJsonBytes;

    // Хуучин (0.2.x TS) хэлбэр: ca. хост руу /v3 залгадаг байсан — чимээгүй 404-ийн оронд тодорхой алдаа.
    private static readonly HashSet<string> LegacyHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "ca.eidmongolia.mn", "e-id.mn", "www.e-id.mn",
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    /// <summary>Тохиргоог шалгаж client үүсгэнэ.</summary>
    /// <param name="options">Тохиргоо.</param>
    /// <param name="httpClient">
    /// mTLS client certificate эсвэл proxy-тэй <see cref="HttpClient"/> (SDK dispose хийхгүй). SDK дуудлага бүрд өөрийн
    /// хугацааг тавьдаг тул <see cref="HttpClient.Timeout"/>-ийг <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>
    /// эсвэл <see cref="DefaultPdfTimeout"/>-оос их болго. null = шинэ client (redirect дагахгүй; <see cref="Dispose"/>-д хаагдана).
    /// </param>
    /// <exception cref="ArgumentException">ApiSecret хоосон, эсвэл BaseUrl буруу.</exception>
    public EidClient(EidClientOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Credentials, nameof(options) + ".Credentials");
        if (string.IsNullOrEmpty(options.Credentials.ApiSecret))
        {
            throw new ArgumentException("eid: Credentials.ApiSecret шаардлагатай", nameof(options));
        }
        BaseUrl = ResolveBaseUrl(options.BaseUrl);
        Options = options;
        if (httpClient is null)
        {
            _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttp = true;
        }
        else
        {
            _http = httpClient;
        }
        Timeout = options.Timeout is { } t && t > TimeSpan.Zero ? t : DefaultTimeout;
        PdfTimeout = options.PdfTimeout is { } pt && pt > TimeSpan.Zero ? pt : DefaultPdfTimeout;
        DefaultCertificateLevel = string.IsNullOrEmpty(options.DefaultCertificateLevel) ? CertificateLevels.Qualified : options.DefaultCertificateLevel;
        Http = new EidHttp(BaseUrl, options.Credentials.ApiSecret, Timeout, _http, options.Language);
        Clock = options.TimeProvider ?? TimeProvider.System;
        SignSessionTtl = options.SignSessionTtl is { } st && st > TimeSpan.Zero ? st : SessionTimes.DefaultSignSessionTtl;
        Auth = new AuthService(this);
        Sign = new SignService(this);
        Session = new SessionService(this);
        Pdf = new PdfService(this);
    }

    /// <summary>Шалгасан суурь URL (төгсгөлийн "/"-гүй).</summary>
    public string BaseUrl { get; }

    /// <summary>Анхны тохиргоо.</summary>
    public EidClientOptions Options { get; }

    /// <summary><c>Credentials.RpName</c> (иргэний утсанд харагдах RP нэр).</summary>
    public string RpName => Options.Credentials.RpName;

    /// <summary>Нэг HTTP дуудлагын хугацаа.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>PDF гарын үсгийн бүртгэлийн хугацаа.</summary>
    public TimeSpan PdfTimeout { get; }

    /// <summary>Auth/sign-ийн анхдагч certLevel.</summary>
    public string DefaultCertificateLevel { get; }

    /// <summary>Sign / certificate-choice session-ий ExpiresAt-ийн тооцоолол (CA expiresAt буцаагаагүй үед).</summary>
    public TimeSpan SignSessionTtl { get; }

    /// <summary>Нэвтрэлт: push / device link, discovery-ийн session TTL.</summary>
    public AuthService Auth { get; }

    /// <summary>Гарын үсэг: digest / text / linked / device link, certificate-choice.</summary>
    public SignService Sign { get; }

    /// <summary>Session poll / хүлээлт.</summary>
    public SessionService Session { get; }

    /// <summary>Клиент талын PAdES гарын үсгийн бүртгэл (<c>POST /pdf/signatures</c>).</summary>
    public PdfService Pdf { get; }

    internal EidHttp Http { get; }

    internal TimeProvider Clock { get; }

    /// <summary>RP challenge үүсгэгч (тестэд тогтмол утгаар солино; анхдагч 64 санамсаргүй байт).</summary>
    internal Func<string> NewChallenge { get; set; } = () => EidCrypto.RandomChallenge(64);

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    /// <summary>
    /// <paramref name="baseUrl"/>-ийг шалгаж, төгсгөлийн "/"-ийг хасна (null / "" = <see cref="DefaultBaseUrl"/>). https
    /// заавал (http зөвхөн localhost / loopback IP); хуучин ca. хост (/v3-тай байсан) бол тодорхой алдаа.
    /// </summary>
    /// <exception cref="ArgumentException">Дүрэм зөрчсөн URL.</exception>
    public static string ResolveBaseUrl(string? baseUrl)
    {
        var raw = (baseUrl ?? "").Trim();
        if (raw.Length == 0)
        {
            raw = DefaultBaseUrl;
        }
        raw = raw.TrimEnd('/');
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http") || u.Host.Length == 0)
        {
            throw new ArgumentException("eid: BaseUrl буруу URL: " + raw, nameof(baseUrl));
        }
        if (u.Scheme == "http" && !IsLoopback(u))
        {
            throw new ArgumentException("eid: BaseUrl https байх ёстой (http зөвхөн localhost/loopback): " + raw, nameof(baseUrl));
        }
        if (LegacyHosts.Contains(u.Host) && u.AbsolutePath == "/")
        {
            throw new ArgumentException(
                "eid: RP-API " + u.Host + "-аас " + DefaultBaseUrl + " руу шилжсэн (/v3-гүй) — BaseUrl-ийг " + DefaultBaseUrl +
                " болгоно уу (эсвэл хоосон орхи)", nameof(baseUrl));
        }
        return raw;
    }

    /// <summary>localhost эсвэл loopback IP (127.0.0.0/8, ::1): API secret сүлжээгээр нээлттэй явахгүй.</summary>
    private static bool IsLoopback(Uri u)
    {
        if (string.Equals(u.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (u.HostNameType is not (UriHostNameType.IPv4 or UriHostNameType.IPv6))
        {
            return false;
        }
        return IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip);
    }
}

/// <summary>
/// Нэвтрэлтийн үйлчилгээ (Go <c>AuthService</c>, TS <c>AuthApi</c>): иргэнийг PIN1-ээр нэвтрүүлнэ. Бүгд rpChallenge
/// үүсгэж, хариуны ACSP_V2 гарын үсгийг validator-оор шалгана.
/// </summary>
public sealed partial class AuthService
{
    private readonly EidClient _c;

    internal AuthService(EidClient c) => _c = c;

    /// <summary>
    /// Discovery (<c>/.well-known/eid</c>)-ийн <c>sessionTtl</c> (<c>{"auth": сек, "sign": сек}</c>): CA-ийн session-ий
    /// амьдрах хугацаа. Талбар алга (хуучин CA) бол <see cref="TimeSpan.Zero"/>.
    /// </summary>
    public async Task<SessionTtl> SessionTtlAsync(CancellationToken ct = default)
    {
        var raw = await _c.Http.GetRawAsync(RpRoutes.DiscoveryPath, null, ct).ConfigureAwait(false);
        return ParseSessionTtl(raw);
    }

    internal static SessionTtl ParseSessionTtl(byte[] raw)
    {
        TimeSpan auth = TimeSpan.Zero, sign = TimeSpan.Zero;
        JsonDocument d;
        try
        {
            d = JsonDocument.Parse(raw);
        }
        catch (JsonException e)
        {
            throw new EidException("eid: GET " + RpRoutes.DiscoveryPath + ": хариу задарсангүй", e);
        }
        using (d)
        {
            if (d.RootElement.ValueKind == JsonValueKind.Object &&
                d.RootElement.TryGetProperty("sessionTtl", out var t) && t.ValueKind == JsonValueKind.Object)
            {
                auth = Seconds(t, "auth");
                sign = Seconds(t, "sign");
            }
        }
        return new SessionTtl(auth, sign);

        static TimeSpan Seconds(JsonElement o, string name) =>
            o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) && n > 0
                ? TimeSpan.FromSeconds(n)
                : TimeSpan.Zero;
    }
}
