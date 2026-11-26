using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

// OCSP цуцлалт шалгагч — Go ocsp.go NewOCSPChecker-ийн порт (TS ocsp.ts-тэй ижил дүрэм). OCSP-ийн DER-ийг
// golang.org/x/crypto/ocsp ParseResponseForCert-ийн дараалал, алдааны ангиллаар өөрөө задална (BCL-д нийтийн OCSP API
// алга). GeregeSystems.EidMongolia.Pades-ийн дотоод Crypto/Ocsp.cs-тэй давхардсан — WP 5-д нэг дор (core) нэгтгэнэ.

/// <summary><see cref="EidOcspException.Kind"/>-ийн утгууд (Go <c>OCSPErrorKind</c>; conformance корпусын <c>errorKind</c>).</summary>
public static class OcspErrorKinds
{
    /// <summary>Гэрчилгээний AIA-д дэмжигдэх (http/https) OCSP URL алга.</summary>
    public const string NoResponder = "no_responder";
    /// <summary>Олгогчийн гэрчилгээ олдоогүй (leaf эсвэл issuer null).</summary>
    public const string NoIssuer = "no_issuer";
    /// <summary>Хугацаа хэтэрсэн (2 с / нийт 3 с).</summary>
    public const string Timeout = "timeout";
    /// <summary>Холболтын бусад алдаа (DNS, TCP, TLS).</summary>
    public const string Network = "network";
    /// <summary>HTTP статус 200 биш, эсвэл хариу 16 KiB-аас их.</summary>
    public const string HttpStatus = "http_status";
    /// <summary>OCSP responseStatus амжилтгүй (malformedRequest, tryLater, unauthorized г.м.).</summary>
    public const string ResponderStatus = "responder_status";
    /// <summary>Хариу DER/ASN.1 задрахгүй.</summary>
    public const string Parse = "parse";
    /// <summary>Хариуны (эсвэл responder гэрчилгээний) гарын үсэг олгогчтой таарахгүй, responder-ийн EKU / хугацаа буруу.</summary>
    public const string Signature = "signature";
    /// <summary>Гарын үсэг зөв ч агуулга хүлээн авахгүй: өөр serial, thisUpdate хүрээнээс гадуур, nextUpdate өнгөрсөн.</summary>
    public const string Invalid = "invalid";
}

/// <summary>
/// <see cref="OcspRevocationChecker"/> хүчинтэй OCSP хариу авсангүй (Go <c>*OCSPError</c>, <c>ErrOCSPNoAnswer</c>).
/// <see cref="ResponseValidator.CheckRevocationAsync"/> үүнийг "unknown" гэж үзэж горимоор шийднэ. Мессеж PII-гүй.
/// </summary>
public sealed class EidOcspException : EidException
{
    internal EidOcspException(string kind, string? responder = null, int? httpStatus = null, string? detail = null, Exception? inner = null)
        : base(Format(kind, responder, detail ?? inner?.Message), inner)
    {
        Kind = kind;
        Responder = responder ?? "";
        HttpStatus = httpStatus;
    }

    /// <summary>Шалтгааны ангилал (<see cref="OcspErrorKinds"/>).</summary>
    public string Kind { get; }

    /// <summary>Оролдсон responder URL ("" — AIA алга / issuer алга).</summary>
    public string Responder { get; }

    /// <summary>Responder-ийн HTTP статус (<see cref="OcspErrorKinds.HttpStatus"/> үед).</summary>
    public int? HttpStatus { get; }

    private static string Format(string kind, string? responder, string? detail) =>
        "eid: OCSP " + kind + (string.IsNullOrEmpty(responder) ? "" : " (" + responder + ")") +
        (string.IsNullOrEmpty(detail) ? "" : ": " + detail);
}

/// <summary><see cref="OcspRevocationChecker"/>-ийн тохиргоо (Go <c>OCSPOptions</c>). Бүгд заавал биш.</summary>
public sealed record OcspOptions
{
    /// <summary>
    /// HTTP client; null = SDK-ийн client (redirect дагахгүй — responder нь CA-ийн гэрчилгээнд бичсэн URL; plain HTTP дээрх
    /// 302 нь өөр хэн нэгнийх). Хугацааг SDK хүсэлт бүрд тавина (2 с, нийт 3 с).
    /// </summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Цаг (тест); null = <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>"good" хариуг кэшлэх дээд хугацаа: бодит = min(CacheTtl, nextUpdate − одоо). Zero = 5 мин; сөрөг = кэшлэхгүй.</summary>
    public TimeSpan CacheTtl { get; init; }

    /// <summary>Шалгалт бүрийн дараа (кэшээс ч) синхрон дуудагдана: метрик / аудит. PII-гүй. Удаан ажил бүү хий.</summary>
    public Action<OcspObservation>? Observe { get; init; }
}

/// <summary>Нэг шалгалтын үр дүн (<see cref="OcspOptions.Observe"/>; Go <c>OCSPObservation</c>). Иргэний таних мэдээлэлгүй.</summary>
/// <param name="Status">Буцаасан төлөв (хариугүй бол <see cref="RevocationStatus.Unknown"/>).</param>
/// <param name="Responder">Хариулсан (эсвэл сүүлд оролдсон) responder URL; кэш / AIA алга бол "".</param>
/// <param name="Duration">Сүлжээгээр асуусан нийт хугацаа (кэшээс бол 0).</param>
/// <param name="Cached">Кэшээс хариулсан.</param>
/// <param name="Error">Хариугүй бол шалтгаан.</param>
public sealed record OcspObservation(RevocationStatus Status, string Responder, TimeSpan Duration, bool Cached, EidOcspException? Error);

/// <summary>
/// Гэрчилгээний AIA-д бичигдсэн OCSP responder-оос асууж цуцлалтын төлөвийг буцаана (Go <c>NewOCSPChecker</c>, TS
/// <c>ocspRevocationChecker</c>):
/// <list type="bullet">
/// <item>good → <see cref="RevocationStatus.Good"/> (min(5 мин, nextUpdate) кэшлэнэ);</item>
/// <item>revoked, мөн unknown (олгогч энэ serial-ийг олгоогүй — өөр хэн нэгний хийсэн гэрчилгээ) →
/// <see cref="RevocationStatus.Revoked"/>;</item>
/// <item>хариугүй (AIA алга, issuer алга, timeout, HTTP ≠ 200, &gt; 16 KiB, гарын үсэг/serial/хугацаа таараагүй) →
/// <see cref="EidOcspException"/> (<see cref="EidOcspException.Kind"/>) — <see cref="ResponseValidator"/>-ийн
/// <see cref="RevocationMode"/> шийднэ.</item>
/// </list>
/// Хариуг олгогч, эсвэл олгогчийн гаргасан id-kp-OCSPSigning EKU-тэй (одоо хүчинтэй, хариунд шигтгэсэн — RFC 6960
/// §4.2.2.2) responder зурсан, энэ serial-ийн тухай, thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate өнгөрөөгүй байх
/// ёстой. Thread-safe.
/// </summary>
public sealed class OcspRevocationChecker
{
    /// <summary>Нэг responder-т асуух хугацаа.</summary>
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(2);
    /// <summary>Нийт хугацаа (AIA-д олон URL байсан ч) — иргэн poll дээр хүлээж байна.</summary>
    public static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(3);
    /// <summary>"good"-ийн анхдагч кэш.</summary>
    public static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromMinutes(5);
    /// <summary>
    /// Хамгийн хуучин thisUpdate: CA хариу бүрийг шинээр зурдаг (thisUpdate = now, nextUpdate = +24 ц); энэ хязгаар нь
    /// цуцлалтаас өмнө авсан "good"-ийг plain HTTP-ээр давтан тоглуулахаас хамгаална.
    /// </summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromHours(48);
    /// <summary>thisUpdate-ийн ирээдүй рүү зөвшөөрөх цагийн зөрүү.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    /// <summary>Хариуны дээд хэмжээ (16 KiB).</summary>
    public const int MaxResponseBytes = 16 << 10;
    private const int CacheMax = 1024;
    private const string OidKpOcspSigning = "1.3.6.1.5.5.7.3.9";

    private static readonly HttpClient DefaultHttp = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = System.Threading.Timeout.InfiniteTimeSpan,
    };

    private readonly HttpClient _http;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _ttl;
    private readonly Action<OcspObservation>? _observe;
    private readonly Dictionary<string, (RevocationStatus Status, DateTimeOffset Expires)> _cache = new(StringComparer.Ordinal);
    private readonly object _mu = new();

    /// <summary>Шинэ шалгагч (өөрийн кэштэй).</summary>
    public OcspRevocationChecker(OcspOptions? options = null)
    {
        var o = options ?? new OcspOptions();
        _http = o.HttpClient ?? DefaultHttp;
        _clock = o.TimeProvider ?? TimeProvider.System;
        _ttl = o.CacheTtl == TimeSpan.Zero ? DefaultCacheTtl : o.CacheTtl;
        _observe = o.Observe;
    }

    /// <summary><see cref="TrustConfig.Revocation"/>-д өгөх delegate.</summary>
    public RevocationChecker Checker => CheckAsync;

    /// <summary>
    /// <paramref name="certificate"/>-ийн цуцлалтын төлөв: <see cref="RevocationStatus.Good"/> эсвэл
    /// <see cref="RevocationStatus.Revoked"/>. Хариугүй бол <see cref="EidOcspException"/>; дуудагчийн
    /// <paramref name="ct"/> цуцлагдвал <see cref="OperationCanceledException"/>.
    /// </summary>
    /// <param name="certificate">Иргэний гэрчилгээ.</param>
    /// <param name="issuer">Шууд олгогч (<see cref="ResponseValidator.CheckRevocationAsync"/> trust pool-оос олно).</param>
    /// <param name="ct">Цуцлалт.</param>
    public async Task<RevocationStatus> CheckAsync(X509Certificate2? certificate, X509Certificate2? issuer, CancellationToken ct = default)
    {
        if (certificate is null || issuer is null)
        {
            throw Fail(new EidOcspException(OcspErrorKinds.NoIssuer));
        }
        ParsedCert leaf, iss;
        try
        {
            leaf = ParsedCert.Parse(certificate.RawData);
            iss = ParsedCert.Parse(issuer.RawData);
        }
        catch (FormatException e)
        {
            throw Fail(new EidOcspException(OcspErrorKinds.NoIssuer, detail: e.Message, inner: e));
        }
        var key = Convert.ToHexString(SHA256.HashData(iss.Raw), 0, 8).ToLowerInvariant() + ":" + leaf.SerialHex();
        RevocationStatus? cached = null;
        lock (_mu)
        {
            if (_cache.TryGetValue(key, out var e) && _clock.GetUtcNow() < e.Expires)
            {
                cached = e.Status;
            }
        }
        if (cached is { } hit)
        {
            Emit(new OcspObservation(hit, "", TimeSpan.Zero, true, null));
            return hit;
        }
        using var total = CancellationTokenSource.CreateLinkedTokenSource(ct);
        total.CancelAfter(TotalTimeout);
        var sw = Stopwatch.StartNew();
        Answer a;
        try
        {
            a = await AskAsync(leaf, iss, ct, total.Token).ConfigureAwait(false);
        }
        catch (EidOcspException e)
        {
            Emit(new OcspObservation(RevocationStatus.Unknown, e.Responder, sw.Elapsed, false, e));
            throw;
        }
        var took = sw.Elapsed;
        // Зөвхөн "good"-ийг кэшлэнэ: revoked эцсийн, unknown нь дөнгөж олгогдсон гэрчилгээг кэшийн хугацаанд түгжихгүй.
        // Хугацаа = min(CacheTtl, NextUpdate − now) — responder-ийн өөрийн хүчинтэй хугацаанаас хэтрэхгүй.
        if (a.Status == RevocationStatus.Good && _ttl > TimeSpan.Zero)
        {
            var now = _clock.GetUtcNow();
            var exp = now + _ttl;
            if (a.NextUpdate is { } nu && nu < exp)
            {
                exp = nu;
            }
            if (exp > now)
            {
                lock (_mu)
                {
                    if (_cache.Count >= CacheMax)
                    {
                        _cache.Clear();
                    }
                    _cache[key] = (a.Status, exp);
                }
            }
        }
        Emit(new OcspObservation(a.Status, a.Responder, took, false, null));
        return a.Status;
    }

    private EidOcspException Fail(EidOcspException e)
    {
        Emit(new OcspObservation(RevocationStatus.Unknown, e.Responder, TimeSpan.Zero, false, e));
        return e;
    }

    private void Emit(OcspObservation o) => _observe?.Invoke(o);

    private readonly record struct Answer(RevocationStatus Status, DateTimeOffset? NextUpdate, string Responder);

    /// <summary>AIA-ийн URL-уудыг дарааллаар; эхний хүлээн авах хариу, эс бөгөөс сүүлийн шалтгаан (Go <c>ask</c>).</summary>
    private async Task<Answer> AskAsync(ParsedCert leaf, ParsedCert issuer, CancellationToken userCt, CancellationToken totalCt)
    {
        var req = CreateRequest(leaf, issuer);
        var last = new EidOcspException(OcspErrorKinds.NoResponder);
        foreach (var raw in leaf.OcspServers)
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps))
            {
                last = new EidOcspException(OcspErrorKinds.NoResponder, detail: "OCSP URL дэмжигдэхгүй: " + raw);
                continue;
            }
            var responder = u.OriginalString;
            byte[] der;
            try
            {
                der = await PostAsync(u, req, userCt, totalCt).ConfigureAwait(false);
            }
            catch (EidOcspException e)
            {
                last = e;
                continue;
            }
            var (resp, err) = Verify(der, leaf, issuer, responder);
            if (resp is null)
            {
                last = err!;
                continue;
            }
            return new Answer(resp.Status == OcspCertStatus.Good ? RevocationStatus.Good : RevocationStatus.Revoked, resp.NextUpdate, responder);
        }
        throw last;
    }

    private async Task<byte[]> PostAsync(Uri u, byte[] body, CancellationToken userCt, CancellationToken totalCt)
    {
        var responder = u.OriginalString;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(totalCt);
        cts.CancelAfter(RequestTimeout);
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
        using var msg = new HttpRequestMessage(HttpMethod.Post, u) { Content = content };
        msg.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/ocsp-response"));
        try
        {
            using var res = await _http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            var status = (int)res.StatusCode;
            if (status != 200)
            {
                throw new EidOcspException(OcspErrorKinds.HttpStatus, responder, status);
            }
            using var s = await res.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            using var ms = new MemoryStream();
            var buf = new byte[4096];
            while (true)
            {
                var n = await s.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }
                ms.Write(buf, 0, n);
                if (ms.Length > MaxResponseBytes)
                {
                    throw new EidOcspException(OcspErrorKinds.HttpStatus, responder, status, "хариу хэт том");
                }
            }
            return ms.ToArray();
        }
        catch (OperationCanceledException) when (userCt.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException e)
        {
            throw new EidOcspException(OcspErrorKinds.Timeout, responder, inner: e);
        }
        catch (Exception e) when (e is HttpRequestException or IOException)
        {
            throw new EidOcspException(cts.IsCancellationRequested ? OcspErrorKinds.Timeout : OcspErrorKinds.Network, responder, inner: e);
        }
    }

    /// <summary>
    /// Хариуг шалгана (Go <c>verify</c>): <see cref="OcspResponseParser.ParseForCert"/>; олгогч өөрийн гэрчилгээг шигтгэсэн
    /// бол (raw эсвэл subject + SPKI) issuer-ийн түлхүүрээр; delegated responder — OCSPSigning EKU, одоо хүчинтэй; serial,
    /// thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate өнгөрөөгүй.
    /// </summary>
    private (OcspParsed? Response, EidOcspException? Error) Verify(byte[] der, ParsedCert leaf, ParsedCert issuer, string responder)
    {
        OcspParsed resp;
        try
        {
            resp = OcspResponseParser.ParseForCert(der, leaf, issuer);
        }
        catch (OcspFormatException e)
        {
            // RFC 6960 §4.2.2.2: олгогч өөрөө зурсан хариу хүчинтэй. Олгогчийн ӨӨРИЙН гэрчилгээг шигтгэсэн хариуг x/crypto/ocsp
            // «bad signature» гэж татгалздаг — шигтгэсэн нь issuer мөн бол хариуг issuer-ийн түлхүүрээр шалгана (Go ocsp.go).
            OcspParsed? alt = null;
            try
            {
                alt = OcspResponseParser.ParseForCert(der, leaf, null);
            }
            catch (OcspFormatException)
            {
                // анхны алдааг буцаана
            }
            if (alt?.Certificate is { } ac && ParsedCert.SameCertKey(ac, issuer) &&
                issuer.Verifies(alt.SignatureAlgorithm, alt.Tbs, alt.Signature, allowSha1: true))
            {
                resp = alt;
            }
            else
            {
                return (null, new EidOcspException(e.Kind, responder, detail: e.Message));
            }
        }
        var now = _clock.GetUtcNow();
        if (resp.Certificate is { } rc && !ParsedCert.SameCertKey(rc, issuer))
        {
            if (!rc.Eku.Contains(OidKpOcspSigning))
            {
                return (null, new EidOcspException(OcspErrorKinds.Signature, responder, detail: "responder-ийн EKU OCSPSigning биш"));
            }
            if (now < rc.NotBefore || now > rc.NotAfter)
            {
                return (null, new EidOcspException(OcspErrorKinds.Signature, responder, detail: "responder-ийн гэрчилгээ хугацаандаа биш"));
            }
        }
        if (resp.Serial != leaf.Serial)
        {
            return (null, new EidOcspException(OcspErrorKinds.Invalid, responder, detail: "хариу өөр serial-ийн тухай"));
        }
        if (resp.ThisUpdate > now + ClockSkew || resp.ThisUpdate < now - MaxAge)
        {
            return (null, new EidOcspException(OcspErrorKinds.Invalid, responder, detail: "thisUpdate хүлээн авах хүрээнээс гадуур"));
        }
        if (resp.NextUpdate is { } nu && nu < now)
        {
            return (null, new EidOcspException(OcspErrorKinds.Invalid, responder, detail: "хариу хуучирсан (nextUpdate өнгөрсөн)"));
        }
        return (resp, null);
    }

    /// <summary>
    /// OCSPRequest (golang.org/x/crypto/ocsp CreateRequest, SHA-1 CertID): issuerNameHash = SHA-1(issuer subject DER),
    /// issuerKeyHash = SHA-1(subjectPublicKey BIT STRING), version/requestorName/extensions-гүй.
    /// </summary>
    internal static byte[] CreateRequest(ParsedCert leaf, ParsedCert issuer)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        using (w.PushSequence())
        using (w.PushSequence())
        using (w.PushSequence())
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.3.14.3.2.26");
                w.WriteNull();
            }
            w.WriteOctetString(SHA1.HashData(issuer.RawSubject));
            w.WriteOctetString(SHA1.HashData(issuer.PublicKeyBits));
            w.WriteInteger(leaf.SerialBytes);
        }
        return w.Encode();
    }
}

/// <summary>OCSP SingleResponse-ийн certStatus.</summary>
internal enum OcspCertStatus
{
    Good,
    Revoked,
    Unknown,
}

/// <summary>Задалсан BasicOCSPResponse (сонгосон SingleResponse-тэй; x/crypto/ocsp Response).</summary>
internal sealed class OcspParsed
{
    public OcspCertStatus Status { get; init; }
    public BigInteger Serial { get; init; }
    public DateTimeOffset ThisUpdate { get; init; }
    public DateTimeOffset? NextUpdate { get; init; }
    /// <summary>certs[0] (delegated responder эсвэл issuer өөрөө); алга бол null.</summary>
    public ParsedCert? Certificate { get; init; }
    public byte[] Tbs { get; init; } = Array.Empty<byte>();
    public AlgorithmId SignatureAlgorithm { get; init; } = new("", null);
    public byte[] Signature { get; init; } = Array.Empty<byte>();
}

/// <summary>OCSP хариу хүлээн авахгүй (<see cref="Kind"/> = <see cref="OcspErrorKinds"/>).</summary>
internal sealed class OcspFormatException : Exception
{
    public OcspFormatException(string kind, string message) : base(message) => Kind = kind;

    public string Kind { get; }
}

/// <summary>golang.org/x/crypto/ocsp ParseResponseForCert-ийн порт: шалгалтын дараалал ба алдааны ангилал ижил.</summary>
internal static class OcspResponseParser
{
    private const string OidBasic = "1.3.6.1.5.5.7.48.1.1";

    private sealed class Single
    {
        public string HashOid { get; init; } = "";
        public BigInteger Serial { get; init; }
        public OcspCertStatus Status { get; init; }
        public DateTimeOffset ThisUpdate { get; init; }
        public DateTimeOffset? NextUpdate { get; init; }
        public bool CriticalExtension { get; init; }
    }

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n);

    private static OcspFormatException ParseError(string message) => new(OcspErrorKinds.Parse, message);

    /// <summary>
    /// <paramref name="cert"/> — хариунаас serial-аар сонгох гэрчилгээ (null бол цорын ганц хариу); <paramref name="issuer"/>
    /// — гарын үсэг шалгах олгогч (null бол шалгахгүй, зөвхөн шигтгэсэн cert-ээр).
    /// </summary>
    public static OcspParsed ParseForCert(byte[] der, ParsedCert? cert, ParsedCert? issuer)
    {
        int status;
        string? type = null;
        byte[]? basicDer = null;
        try
        {
            var top = new AsnReader(der, AsnEncodingRules.DER);
            var resp = top.ReadSequence();
            var statusBytes = resp.ReadEnumeratedBytes();
            if (resp.HasData && resp.PeekTag().HasSameClassAndValue(Ctx(0)))
            {
                var wrap = resp.ReadSequence(Ctx(0));
                var rb = wrap.ReadSequence();
                wrap.ThrowIfNotEmpty();
                type = rb.ReadObjectIdentifier();
                basicDer = rb.ReadOctetString();
                rb.ThrowIfNotEmpty();
            }
            resp.ThrowIfNotEmpty();
            if (top.HasData)
            {
                throw ParseError("trailing data in OCSP response");
            }
            status = (int)new BigInteger(statusBytes.Span, isUnsigned: false, isBigEndian: true);
        }
        catch (Exception e) when (e is AsnContentException or OverflowException)
        {
            throw ParseError(e.Message);
        }
        if (status != 0)
        {
            throw new OcspFormatException(OcspErrorKinds.ResponderStatus, "OCSP response status " + status);
        }
        if (type != OidBasic || basicDer is null)
        {
            throw ParseError("bad OCSP response type");
        }

        byte[] tbsRaw;
        AlgorithmId alg;
        byte[] sig;
        byte[]? firstCert = null;
        Asn1Tag responderTag;
        byte[] responderId;
        var singles = new List<Single>();
        try
        {
            var br = new AsnReader(basicDer, AsnEncodingRules.DER);
            var basic = br.ReadSequence();
            if (br.HasData)
            {
                throw ParseError("trailing data in OCSP response");
            }
            tbsRaw = basic.ReadEncodedValue().ToArray();
            alg = AlgorithmId.Read(basic);
            sig = basic.ReadBitString(out _);
            if (basic.HasData && basic.PeekTag().HasSameClassAndValue(Ctx(0)))
            {
                var wrap = basic.ReadSequence(Ctx(0));
                var certs = wrap.ReadSequence();
                wrap.ThrowIfNotEmpty();
                if (certs.HasData)
                {
                    firstCert = certs.ReadEncodedValue().ToArray();
                }
                while (certs.HasData)
                {
                    certs.ReadEncodedValue();
                }
            }
            basic.ThrowIfNotEmpty();

            var tbs = new AsnReader(tbsRaw, AsnEncodingRules.DER).ReadSequence();
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(0)))
            {
                tbs.ReadEncodedValue();
            }
            responderTag = tbs.PeekTag();
            responderId = tbs.ReadEncodedValue().ToArray();
            tbs.ReadGeneralizedTime();
            var responses = tbs.ReadSequence();
            while (responses.HasData)
            {
                singles.Add(ReadSingle(responses.ReadSequence()));
            }
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Ctx(1)))
            {
                tbs.ReadEncodedValue();
            }
            tbs.ThrowIfNotEmpty();
        }
        catch (Exception e) when (e is AsnContentException or OverflowException)
        {
            throw ParseError(e.Message);
        }

        if (singles.Count == 0 || (cert is null && singles.Count > 1))
        {
            throw ParseError("OCSP response contains bad number of responses");
        }
        Single? single = null;
        if (cert is null)
        {
            single = singles[0];
        }
        else
        {
            foreach (var s in singles)
            {
                if (s.Serial == cert.Serial)
                {
                    single = s;
                    break;
                }
            }
            if (single is null)
            {
                throw new OcspFormatException(OcspErrorKinds.Invalid, "no response matching the supplied certificate");
            }
        }
        CheckResponderId(responderTag, responderId);
        ParsedCert? embedded = null;
        if (firstCert is not null)
        {
            try
            {
                embedded = ParsedCert.Parse(firstCert);
            }
            catch (FormatException e)
            {
                throw ParseError(e.Message);
            }
            if (!embedded.Verifies(alg, tbsRaw, sig, allowSha1: true))
            {
                throw new OcspFormatException(OcspErrorKinds.Signature, "bad signature on embedded certificate");
            }
            if (issuer is not null && !issuer.Verifies(embedded.SignatureAlgorithm, embedded.Tbs, embedded.Signature, allowSha1: true))
            {
                throw new OcspFormatException(OcspErrorKinds.Signature, "bad OCSP signature");
            }
        }
        else if (issuer is not null && !issuer.Verifies(alg, tbsRaw, sig, allowSha1: true))
        {
            throw new OcspFormatException(OcspErrorKinds.Signature, "bad OCSP signature");
        }
        if (single.CriticalExtension)
        {
            throw ParseError("unsupported critical extension");
        }
        if (single.HashOid is not ("1.3.14.3.2.26" or "2.16.840.1.101.3.4.2.1" or "2.16.840.1.101.3.4.2.2" or "2.16.840.1.101.3.4.2.3"))
        {
            throw ParseError("unsupported issuer hash algorithm");
        }
        return new OcspParsed
        {
            Status = single.Status,
            Serial = single.Serial,
            ThisUpdate = single.ThisUpdate,
            NextUpdate = single.NextUpdate,
            Certificate = embedded,
            Tbs = tbsRaw,
            SignatureAlgorithm = alg,
            Signature = sig,
        };
    }

    /// <summary>ResponderID CHOICE: byName [1] (Name), byKey [2] (OCTET STRING) — бусад нь parse алдаа (x/crypto/ocsp).</summary>
    private static void CheckResponderId(Asn1Tag tag, byte[] encoded)
    {
        try
        {
            var r = new AsnReader(encoded, AsnEncodingRules.DER);
            switch (tag.TagValue)
            {
                case 1:
                    {
                        var inner = r.ReadSequence(new Asn1Tag(tag.TagClass, 1, true));
                        inner.ReadSequence();
                        inner.ThrowIfNotEmpty();
                        return;
                    }
                case 2:
                    {
                        var inner = r.ReadSequence(new Asn1Tag(tag.TagClass, 2, true));
                        inner.ReadOctetString();
                        inner.ThrowIfNotEmpty();
                        return;
                    }
                default:
                    throw ParseError("invalid responder id tag");
            }
        }
        catch (AsnContentException)
        {
            throw ParseError(tag.TagValue == 1 ? "invalid responder name" : "invalid responder key hash");
        }
    }

    private static Single ReadSingle(AsnReader s)
    {
        var certId = s.ReadSequence();
        var hash = AlgorithmId.Read(certId);
        certId.ReadOctetString();
        certId.ReadOctetString();
        var serial = certId.ReadInteger();
        certId.ThrowIfNotEmpty();
        // certStatus: good [0] / revoked [1] / unknown [2]; x/crypto/ocsp-д аль нь ч биш бол revoked.
        var status = OcspCertStatus.Revoked;
        var tag = s.PeekTag();
        if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue is 0 or 1 or 2)
        {
            status = tag.TagValue switch
            {
                0 => OcspCertStatus.Good,
                2 => OcspCertStatus.Unknown,
                _ => OcspCertStatus.Revoked,
            };
            s.ReadEncodedValue();
        }
        var thisUpdate = s.ReadGeneralizedTime();
        DateTimeOffset? next = null;
        if (s.HasData && s.PeekTag().HasSameClassAndValue(Ctx(0)))
        {
            var nw = s.ReadSequence(Ctx(0));
            next = nw.ReadGeneralizedTime();
            nw.ThrowIfNotEmpty();
        }
        var critical = false;
        if (s.HasData && s.PeekTag().HasSameClassAndValue(Ctx(1)))
        {
            var ew = s.ReadSequence(Ctx(1));
            var exts = ew.ReadSequence();
            ew.ThrowIfNotEmpty();
            while (exts.HasData)
            {
                var e = exts.ReadSequence();
                e.ReadObjectIdentifier();
                if (e.HasData && e.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                {
                    critical |= e.ReadBoolean();
                }
                e.ReadOctetString();
                e.ThrowIfNotEmpty();
            }
        }
        s.ThrowIfNotEmpty();
        return new Single
        {
            HashOid = hash.Oid,
            Serial = serial,
            Status = status,
            ThisUpdate = thisUpdate,
            NextUpdate = next,
            CriticalExtension = critical,
        };
    }
}
