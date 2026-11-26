using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Qr;

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

    /// <summary>
    /// <see cref="EidClient.Validator"/>-ийн итгэлийн тохиргоо. Production-д
    /// <c>TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem }</c> ЗААВАЛ — null / anchor-гүй бол validator fail-closed
    /// (<see cref="ValidationReasons.TrustNoAnchor"/>).
    /// </summary>
    public TrustConfig? Trust { get; init; }

    /// <summary>
    /// <see cref="EidClient.Qr"/>-ийн итгэл («Миний QR»). null = шигтгэсэн үндэсний root + завсрын 02–04, олгогч 04, AIA-ийн
    /// OCSP (<see cref="OcspRevocationChecker"/>, hard-fail).
    /// </summary>
    public QrTrust? QrTrust { get; init; }
}

/// <summary>
/// eID Mongolia RP-API client (Go <c>eid.Client</c>, TS <c>EidClient</c>-ийн .NET порт): тохиргоо, HTTP давхарга, алдаа,
/// <see cref="Auth"/> (push / device link + discovery), <see cref="Sign"/> (digest / text / linked / device link /
/// certificate-choice), <see cref="Session"/> (poll / wait), <see cref="Pdf"/> (<c>POST /pdf/signatures</c>),
/// <see cref="Validator"/> (хариуны криптограф баталгаажуулалт, цуцлалт), <see cref="Organization"/>, <see cref="Person"/>,
/// <see cref="Seal"/>, <see cref="Token"/>, <see cref="ShareAsync"/>, <see cref="Qr"/> («Миний QR»). mTLS: client
/// certificate-тэй <see cref="HttpClient"/>-ийг конструкторт өгнө. Thread-safe.
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
    /// <exception cref="ArgumentException">ApiSecret хоосон, BaseUrl буруу, эсвэл Trust-ийн PEM / SKI буруу.</exception>
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
        // Trust-ийн PEM / SKI буруу бол HttpClient үүсгэхээс өмнө ArgumentException.
        Validator = new ResponseValidator(options.Trust, options.TimeProvider ?? TimeProvider.System);
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
        Organization = new OrganizationService(this);
        Person = new PersonService(this);
        Seal = new SealService(this);
        Token = new TokenService(this);
        Qr = new EidQrClient(new EidQrOptions
        {
            BaseUrl = BaseUrl,
            RpUuid = options.Credentials.RpUuid,
            RpName = options.Credentials.RpName,
            ApiSecret = options.Credentials.ApiSecret,
            HttpClient = _http,
            Timeout = Timeout,
        }, options.QrTrust);
    }

    /// <summary><see cref="ShareAsync"/>-ийн хүсэлтийн хугацаа: CA бүх хүлээн авагчид 120 с-д илгээнэ, nginx 150 с.</summary>
    public static readonly TimeSpan DefaultShareTimeout = TimeSpan.FromSeconds(150);

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

    /// <summary>Иргэний төлөөлж чадах байгууллагууд, байгууллагын RP тамганы эрхүүд.</summary>
    public OrganizationService Organization { get; }

    /// <summary>Иргэний PKI самбар (PKI_READ): гэрчилгээ, төхөөрөмж, үйл ажиллагаа, нэгдсэн тоо, хүүхдүүд.</summary>
    public PersonService Person { get; }

    /// <summary>Байгууллагын цахим тамга: гэрчилгээ, олголтын хүсэлт, тамганы эрх, digest тамгалах.</summary>
    public SealService Seal { get; }

    /// <summary>USB токен: гэрчилгээ олголт, токеноор нэвтрэлт.</summary>
    public TokenService Token { get; }

    /// <summary>«Миний QR» (<see cref="EidClientOptions.QrTrust"/>; энэ client-ийн HttpClient-ийг хуваалцана).</summary>
    public EidQrClient Qr { get; }

    /// <summary>
    /// <c>POST /share</c> (SIGN эрх; Go <c>Client.Share</c>): гарын үсэгтэй файлыг (PDF, eID-ийн хүчинтэй гарын үсэгтэй) 1–5
    /// хүлээн авагч руу имэйлээр, хавсралтаар илгээнэ; CA файлыг хадгалахгүй. HTTP хугацаа = <see cref="DefaultShareTimeout"/>.
    /// </summary>
    /// <exception cref="EidShareException">CA-ийн алдаа (Code ∈ <see cref="ShareErrorCodes.All"/>, 422-д Reason, 502-д Sent/Failed/Recipients).</exception>
    /// <exception cref="EidAuthenticationException">401.</exception>
    /// <exception cref="EidForbiddenException">403.</exception>
    /// <exception cref="EidNetworkException">Сүлжээ / timeout.</exception>
    public async Task<ShareResult> ShareAsync(ShareRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var (body, contentType) = ShareWire.Build(request);
        var path = RpRoutes.Share.Expand();
        byte[] raw;
        try
        {
            raw = await Http.PostBytesAsync(path, body, contentType, DefaultShareTimeout, ct).ConfigureAwait(false);
        }
        catch (EidApiException e)
        {
            throw new EidShareException(e);
        }
        var r = EidHttp.Decode<ShareResult>(raw, "POST", path) ?? new ShareResult();
        return r with { Raw = RawJson.Element(raw) };
    }

    /// <summary>Discovery (<c>/.well-known/eid</c>)-ийн share блок; блок алга (хуучин CA) бол Enabled false.</summary>
    public async Task<ShareInfo> ShareInfoAsync(CancellationToken ct = default)
    {
        var raw = await Http.GetRawAsync(RpRoutes.DiscoveryPath, null, ct).ConfigureAwait(false);
        return Discovery.Block<ShareInfo>(raw, "share", (v, e) => v with { Raw = e });
    }

    /// <summary>
    /// Session хариуны криптограф баталгаажуулалт (<see cref="ResponseValidator.ValidateAuth"/>,
    /// <see cref="ResponseValidator.ValidateSign"/>, <see cref="ResponseValidator.ValidateCertificateChoice"/>) ба цуцлалт
    /// (<see cref="ResponseValidator.CheckRevocationAsync"/>); <see cref="EidClientOptions.Trust"/> ба
    /// <see cref="EidClientOptions.TimeProvider"/>-оор.
    /// </summary>
    public ResponseValidator Validator { get; }

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
