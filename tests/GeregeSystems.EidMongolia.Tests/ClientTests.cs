using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class ClientTests
{
    /// <summary>Хүсэлтийг барьж, өгсөн хариуг буцаадаг handler (сүлжээгүй).</summary>
    private sealed class Fake : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;

        public Fake(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;

        public HttpRequestMessage? Last { get; private set; }

        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Last = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return await _respond(request, ct);
        }
    }

    /// <summary>Content-Length-гүй (chunked) бие.</summary>
    private sealed class NoLengthContent : HttpContent
    {
        private readonly byte[] _data;

        public NoLengthContent(byte[] data) => _data = data;

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(_data, 0, _data.Length);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private static HttpResponseMessage Res(int status, string body, string? retryAfter = null)
    {
        var r = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8) };
        if (retryAfter is not null)
        {
            r.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }
        return r;
    }

    private static (EidClient Client, Fake Handler) Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond,
        string? language = null, TimeSpan? timeout = null)
    {
        var fake = new Fake(respond);
        var c = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp.example.mn/",
            Credentials = new EidCredentials("00000000-0000-0000-0000-000000000000", "Test RP", "rp_sk_test"),
            Language = language,
            Timeout = timeout,
        }, new HttpClient(fake));
        return (c, fake);
    }

    private static (EidClient Client, Fake Handler) Client(HttpResponseMessage res) => Client((_, _) => Task.FromResult(res));

    [Theory]
    [InlineData(null, "https://rp.eidmongolia.mn")]
    [InlineData("", "https://rp.eidmongolia.mn")]
    [InlineData("  https://rp.eidmongolia.mn//  ", "https://rp.eidmongolia.mn")]
    [InlineData("https://rp.example.mn/base/", "https://rp.example.mn/base")]
    [InlineData("http://localhost:8080", "http://localhost:8080")]
    [InlineData("http://LOCALHOST", "http://LOCALHOST")]
    [InlineData("http://127.0.0.1:9000", "http://127.0.0.1:9000")]
    [InlineData("http://127.10.0.1", "http://127.10.0.1")]
    [InlineData("http://[::1]:8443", "http://[::1]:8443")]
    [InlineData("https://ca.eidmongolia.mn/v3", "https://ca.eidmongolia.mn/v3")]
    public void ResolveBaseUrlAccepts(string? input, string want)
    {
        Assert.Equal(want, EidClient.ResolveBaseUrl(input));
    }

    [Theory]
    [InlineData("http://rp.eidmongolia.mn")]
    [InlineData("http://10.0.0.1")]
    [InlineData("http://localhost.example.mn")]
    [InlineData("ftp://rp.eidmongolia.mn")]
    [InlineData("rp.eidmongolia.mn")]
    [InlineData("/relative/path")]
    [InlineData("https://ca.eidmongolia.mn")]
    [InlineData("https://ca.eidmongolia.mn/")]
    [InlineData("https://e-id.mn")]
    [InlineData("https://www.e-id.mn")]
    public void ResolveBaseUrlRejects(string input)
    {
        Assert.Throws<ArgumentException>(() => EidClient.ResolveBaseUrl(input));
    }

    [Fact]
    public void ClientRequiresSecret()
    {
        Assert.Throws<ArgumentException>(() => new EidClient(new EidClientOptions { Credentials = new EidCredentials("u", "n", "") }));
        using var c = new EidClient(new EidClientOptions { Credentials = new EidCredentials("u", "n", "s") });
        Assert.Equal(EidClient.DefaultBaseUrl, c.BaseUrl);
        Assert.Equal(EidClient.DefaultTimeout, c.Timeout);
        Assert.Equal(TimeSpan.FromSeconds(80), c.PdfTimeout);
        Assert.Equal(CertificateLevels.Qualified, c.DefaultCertificateLevel);
        Assert.DoesNotContain("rp_sk", new EidCredentials("u", "n", "rp_sk_secret").ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendsBearerLanguageAndJson()
    {
        var (c, h) = Client((_, _) => Task.FromResult(Res(200, "{\"sessionID\":\"s1\"}")), language: " en ");
        var path = RpRoutes.AuthNotificationEtsi.Expand("PNOMN-TEST 01/x");
        var r = await c.Http.PostJsonAsync<JsonElement>(path, new { relyingPartyName = "Банк" }, null, CancellationToken.None);
        Assert.Equal("s1", r.GetProperty("sessionID").GetString());
        var req = h.Last!;
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("https://rp.example.mn/authentication/notification/etsi/PNOMN-TEST%2001%2Fx", req.RequestUri!.AbsoluteUri);
        Assert.Equal("Bearer", req.Headers.Authorization!.Scheme);
        Assert.Equal("rp_sk_test", req.Headers.Authorization.Parameter);
        Assert.Equal("en", Assert.Single(req.Headers.GetValues("Accept-Language")));
        Assert.Equal("application/json", req.Content!.Headers.ContentType!.ToString());
        using var body = JsonDocument.Parse(h.LastBody!);
        Assert.Equal("Банк", body.RootElement.GetProperty("relyingPartyName").GetString());
    }

    [Fact]
    public async Task OmitsAcceptLanguageByDefaultAndDecodesEmptyBody()
    {
        var (c, h) = Client(Res(200, ""));
        var r = await c.Http.GetJsonAsync<JsonElement?>(RpRoutes.Session.Expand("s1"), null, CancellationToken.None);
        Assert.Null(r);
        Assert.False(h.Last!.Headers.Contains("Accept-Language"));
        Assert.Null(h.Last.Content);
    }

    [Fact]
    public async Task InvalidJsonIsEidException()
    {
        var (c, _) = Client(Res(200, "{not json"));
        var e = await Assert.ThrowsAsync<EidException>(() => c.Http.GetJsonAsync<JsonElement>("/session/x", null, CancellationToken.None));
        Assert.IsAssignableFrom<JsonException>(e.InnerException);
    }

    [Theory]
    [InlineData(401, "{\"error\":\"bad secret\",\"code\":\"RP_SECRET_INVALID\"}", null, typeof(EidAuthenticationException), "RP_SECRET_INVALID", false)]
    [InlineData(401, "<html>401</html>", null, typeof(EidAuthenticationException), null, false)]
    [InlineData(403, "{\"error\":\"no\",\"code\":\"REPRESENTATION_DENIED\"}", "3", typeof(EidForbiddenException), "REPRESENTATION_DENIED", false)]
    [InlineData(403, "", null, typeof(EidForbiddenException), null, false)]
    [InlineData(409, "{\"error\":\"x\",\"code\":\"NO_SIGNING_CERTIFICATE\"}", null, typeof(EidNoSigningCertificateException), "NO_SIGNING_CERTIFICATE", false)]
    [InlineData(409, "{\"error\":\"x\",\"code\":\"CERT_CHOICE_INVALID\"}", null, typeof(EidCertChoiceInvalidException), "CERT_CHOICE_INVALID", false)]
    [InlineData(400, "{\"error\":\"x\",\"code\":\"REQUEST_INVALID\"}", null, typeof(EidRequestInvalidException), "REQUEST_INVALID", false)]
    [InlineData(409, "{\"error\":\"x\",\"code\":\"ORG_NOT_ACTIVE\"}", null, typeof(EidOrgNotActiveException), "ORG_NOT_ACTIVE", false)]
    [InlineData(404, "{\"error\":\"x\",\"code\":\"SEAL_GRANT_NOT_FOUND\"}", null, typeof(EidSealGrantNotFoundException), "SEAL_GRANT_NOT_FOUND", false)]
    [InlineData(429, "{\"error\":\"slow\",\"code\":\"RATE_LIMITED\"}", "7", typeof(EidApiException), "RATE_LIMITED", true)]
    [InlineData(503, "{\"error\":\"x\",\"code\":\"STATE_UNAVAILABLE\"}", null, typeof(EidApiException), "STATE_UNAVAILABLE", true)]
    [InlineData(503, "{\"error\":\"off\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"sealing\"}", "30", typeof(EidSealServiceDisabledException), "SEAL_SERVICE_DISABLED", false)]
    [InlineData(503, "<html>busy</html>", "5", typeof(EidApiException), null, true)]
    [InlineData(503, "<html>busy</html>", null, typeof(EidApiException), null, false)]
    [InlineData(429, "{}", "0", typeof(EidApiException), null, false)]
    [InlineData(500, "{\"error\":\"boom\"}", "5", typeof(EidApiException), null, false)]
    [InlineData(404, "{\"error\":\"x\",\"code\":\"SOMETHING_NEW\"}", null, typeof(EidApiException), "SOMETHING_NEW", false)]
    [InlineData(302, "", null, typeof(EidApiException), null, false)]
    public async Task MapsHttpErrors(int status, string body, string? retryAfter, Type type, string? code, bool retryable)
    {
        var (c, _) = Client(Res(status, body, retryAfter));
        var e = await Assert.ThrowsAnyAsync<EidException>(() => c.Http.PostJsonAsync<JsonElement>("/x", new { }, null, CancellationToken.None));
        Assert.IsType(type, e);
        Assert.Equal(code, e.Code);
        Assert.Equal(status, e.Status);
        Assert.Equal(retryable, e.Retryable);
        if (retryAfter is "7" or "30" or "3")
        {
            Assert.Equal(TimeSpan.FromSeconds(int.Parse(retryAfter, System.Globalization.CultureInfo.InvariantCulture)), e.RetryAfter);
        }
    }

    [Fact]
    public async Task ErrorDetailsAreExposed()
    {
        var (c, _) = Client(Res(503, "{\"error\":\"off\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"issuance\"}", "30"));
        var e = await Assert.ThrowsAsync<EidSealServiceDisabledException>(() => c.Http.GetJsonAsync<JsonElement>("/seal/certificate/NTRMN-1", null, CancellationToken.None));
        Assert.Equal("issuance", e.Service);
        Assert.Contains("SEAL_SERVICE_DISABLED", e.Body, StringComparison.Ordinal);
        Assert.Equal("30", Assert.Single(e.Headers!.GetValues("Retry-After")));

        (c, _) = Client(Res(401, "{\"error\":\"bad\",\"code\":\"X\"}"));
        var a = await Assert.ThrowsAsync<EidAuthenticationException>(() => c.Http.GetJsonAsync<JsonElement>("/x", null, CancellationToken.None));
        Assert.Equal("bad", a.ServerMessage);
        Assert.Contains("401 X", a.Message, StringComparison.Ordinal);

        (c, _) = Client(Res(403, "{\"error\":\"denied\",\"code\":\"REPRESENTATION_DENIED\"}"));
        var f = await Assert.ThrowsAsync<EidForbiddenException>(() => c.Http.GetJsonAsync<JsonElement>("/x", null, CancellationToken.None));
        Assert.Equal("denied", f.ServerMessage);
        Assert.Contains(f.Code!, EidErrorCodes.OnBehalfErrorCodes);
    }

    [Theory]
    [InlineData("5", 5.0)]
    [InlineData(" 120 ", 120.0)]
    [InlineData("86400", 86400.0)]
    [InlineData("0", null)]
    [InlineData("-1", null)]
    [InlineData("86401", null)]
    [InlineData("soon", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    [InlineData("Wed, 25 Nov 2026 12:00:30 GMT", 30.0)]
    [InlineData("Wednesday, 25-Nov-26 12:01:00 GMT", 60.0)]
    [InlineData("Wed Nov 25 12:00:10 2026", 10.0)]
    [InlineData("Wed, 25 Nov 2026 11:59:59 GMT", null)]
    public void ParsesRetryAfter(string? value, double? seconds)
    {
        var now = new DateTimeOffset(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
        TimeSpan? want = seconds is { } s ? TimeSpan.FromSeconds(s) : null;
        Assert.Equal(want, EidHttp.ParseRetryAfter(value, now));
    }

    [Fact]
    public async Task RejectsOversizedBodies()
    {
        var big = new byte[EidClient.MaxJsonBytes + 1];
        var (c, _) = Client(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(big) });
        var e = await Assert.ThrowsAsync<EidResponseTooLargeException>(() => c.Http.GetJsonAsync<JsonElement>("/session/s1", null, CancellationToken.None));
        Assert.Equal(EidClient.MaxJsonBytes, e.Limit);

        (c, _) = Client(new HttpResponseMessage(HttpStatusCode.OK) { Content = new NoLengthContent(big) });
        await Assert.ThrowsAsync<EidResponseTooLargeException>(() => c.Http.GetJsonAsync<JsonElement>("/session/s1", null, CancellationToken.None));

        // Яг хязгаар хүртэл зөвшөөрнө (JSON string).
        var ok = Encoding.ASCII.GetBytes("\"" + new string('a', EidClient.MaxJsonBytes - 2) + "\"");
        (c, _) = Client(new HttpResponseMessage(HttpStatusCode.OK) { Content = new NoLengthContent(ok) });
        var s = await c.Http.GetJsonAsync<string>("/session/s1", null, CancellationToken.None);
        Assert.Equal(EidClient.MaxJsonBytes - 2, s!.Length);

        // Алдааны том бие таслагдана (алдаа нь ResponseTooLarge биш).
        (c, _) = Client(new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new NoLengthContent(big) });
        var api = await Assert.ThrowsAsync<EidApiException>(() => c.Http.GetJsonAsync<JsonElement>("/x", null, CancellationToken.None));
        Assert.Equal(64 << 10, api.Body.Length);
    }

    [Fact]
    public async Task TimeoutIsNetworkErrorWithMaskedPath()
    {
        var (c, _) = Client(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Res(200, "{}");
        }, timeout: TimeSpan.FromMilliseconds(50));
        var e = await Assert.ThrowsAsync<EidNetworkException>(() =>
            c.Http.PostJsonAsync<JsonElement>(RpRoutes.AuthNotificationEtsi.Expand("PNOMN-SECRET1"), new { }, null, CancellationToken.None));
        Assert.True(e.IsTimeout);
        Assert.Equal("POST /authentication/notification/etsi/…", e.Op);
        Assert.DoesNotContain("PNOMN-SECRET1", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancellationIsOperationCanceled()
    {
        var (c, _) = Client(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Res(200, "{}");
        });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.Http.GetJsonAsync<JsonElement>("/x", null, cts.Token));
    }

    [Fact]
    public async Task TransportFailureIsNetworkError()
    {
        var (c, _) = Client((_, _) => throw new HttpRequestException("connection refused"));
        var e = await Assert.ThrowsAsync<EidNetworkException>(() =>
            c.Http.GetJsonAsync<JsonElement>(RpRoutes.PersonCertificates.Expand("PNOMN-SECRET2"), null, CancellationToken.None));
        Assert.False(e.IsTimeout);
        Assert.Equal("GET /certificates/etsi/…", e.Op);
        Assert.IsType<HttpRequestException>(e.InnerException);
    }

    [Fact]
    public async Task PostWithStatusReturnsSuccessStatus()
    {
        var (c, _) = Client(Res(201, "{\"docID\":\"d1\"}"));
        var (status, body) = await c.Http.PostJsonWithStatusAsync<JsonElement>(RpRoutes.PdfSignatures.Expand(), new { }, c.PdfTimeout, CancellationToken.None);
        Assert.Equal(201, status);
        Assert.Equal("d1", body.GetProperty("docID").GetString());
    }

    [Fact]
    public async Task SessionTtlFromDiscovery()
    {
        var (c, h) = Client(Res(200, "{\"rp_api_base\":\"https://rp.example.mn\",\"sessionTtl\":{\"auth\":300,\"sign\":900}}"));
        var ttl = await c.Auth.SessionTtlAsync();
        Assert.Equal(new SessionTtl(TimeSpan.FromSeconds(300), TimeSpan.FromSeconds(900)), ttl);
        Assert.Equal(HttpMethod.Get, h.Last!.Method);
        Assert.Equal("https://rp.example.mn/.well-known/eid", h.Last.RequestUri!.AbsoluteUri);

        Assert.Equal(new SessionTtl(TimeSpan.Zero, TimeSpan.Zero), AuthService.ParseSessionTtl("{}"u8.ToArray()));
        Assert.Equal(new SessionTtl(TimeSpan.Zero, TimeSpan.FromSeconds(1)),
            AuthService.ParseSessionTtl("{\"sessionTtl\":{\"auth\":-5,\"sign\":1}}"u8.ToArray()));
        Assert.Equal(new SessionTtl(TimeSpan.Zero, TimeSpan.Zero), AuthService.ParseSessionTtl("{\"sessionTtl\":{\"auth\":\"300\"}}"u8.ToArray()));
        Assert.Throws<EidException>(() => AuthService.ParseSessionTtl("nope"u8.ToArray()));
    }

    [Fact]
    public void SessionExpiryDefaultsTo600s()
    {
        var t = new DateTimeOffset(2026, 11, 25, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(t.AddSeconds(600), SessionTimes.SessionExpiry(t, TimeSpan.Zero));
        Assert.Equal(t.AddSeconds(60), SessionTimes.SessionExpiry(t, TimeSpan.FromSeconds(60)));
    }

    [Fact]
    public void WireTypesRoundTrip()
    {
        var s = new DeviceLinkSession
        {
            SessionId = "s1",
            SessionToken = "t",
            SessionSecret = "AA==",
            DeviceLinkBase = "https://ca.example.mn/dl",
            ReceivedAt = new DateTimeOffset(2026, 11, 25, 0, 0, 0, TimeSpan.Zero),
            SessionType = DeviceLinkSessionTypes.Auth,
            Acsp = new AcspContext { RpChallenge = "c", FlowTypes = new[] { FlowTypes.Qr } },
        };
        var json = JsonSerializer.Serialize(s, EidHttp.Json);
        Assert.Contains("\"sessionId\":\"s1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"flowTypes\":[\"QR\"]", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"sign\"", json, StringComparison.Ordinal);
        var back = JsonSerializer.Deserialize<DeviceLinkSession>(json, EidHttp.Json)!;
        Assert.Equal(s.ReceivedAt, back.ReceivedAt);
        Assert.Equal("c", back.Acsp!.RpChallenge);
        Assert.Equal(FlowTypes.Qr, back.Acsp.FlowTypes.Single());

        var reps = EidHttp.Decode<RepresentationsResponse>(
            "{\"personEtsi\":\"PNOMN-X\",\"representations\":[{\"orgEtsi\":\"NTRMN-1\",\"rightType\":\"ADMIN\",\"source\":\"REGISTRY\",\"validFrom\":\"2026-01-01\",\"future\":1}]}"u8.ToArray(),
            "GET", "/organization/representations/etsi/PNOMN-X")!;
        Assert.Equal("NTRMN-1", Assert.Single(reps.Representations).OrgEtsi);
    }
}
