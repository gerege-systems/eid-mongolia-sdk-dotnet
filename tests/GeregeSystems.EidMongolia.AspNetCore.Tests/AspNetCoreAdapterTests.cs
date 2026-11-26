using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using GeregeSystems.EidMongolia.Tests;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace GeregeSystems.EidMongolia.AspNetCore.Tests;

/// <summary>
/// ASP.NET Core adapter: process дотор Kestrel (127.0.0.1, port 0) дээр <c>AddEidMongolia</c> + <c>MapEidLogin</c>-ийг бодит
/// HTTP-ээр (TestHost package-гүй), мөн HttpContext ↔ EidLoginRequest/Response хөрвүүлэлтийг шууд шалгана.
/// </summary>
public class AspNetCoreAdapterTests
{
    private const string Callback = "https://bank.example.mn/auth/eid/callback";

    [Fact]
    public async Task MapEidLoginOverKestrel()
    {
        var fake = new FakeEid();
        var keys = new List<string>();
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddEidMongolia(_ => new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp-api.example.test",
            Credentials = new EidCredentials("rp-1", "Демо банк", "rp_sk_test"),
            Trust = new TrustConfig { AllowUntrusted = true, AllowAnyIssuer = true },
        }, new HttpClient(fake)));
        await using var app = builder.Build();
        app.MapEidLogin("/auth/eid", (http, id) =>
        {
            http.Response.Cookies.Append("app_session", "s1", new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/" });
            return Task.FromResult<EidLoginSuccess?>(new EidLoginSuccess { Redirect = "/dashboard", Data = new { user = id.Etsi } });
        }, o =>
        {
            o.CallbackUrl = Callback;
            o.FailureRedirect = "/login";
            o.DisablePushFloor = true;
            o.ClientIp = EidLoginClientIp.RemoteAddress;
            o.RateLimit = (k, _) =>
            {
                lock (keys)
                {
                    keys.Add(k);
                }
                return new ValueTask<bool>(true);
            };
        });
        await app.StartAsync();
        try
        {
            using var http = new HttpClient(new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false })
            {
                BaseAddress = new Uri(app.Urls.First()),
            };

            // QR start → HttpOnly/Secure/SameSite cookie, no-store.
            var start = await http.PostAsync("/auth/eid/start", new StringContent("{\"mode\":\"qr\"}", Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.OK, start.StatusCode);
            Assert.Equal("no-store", start.Headers.CacheControl?.ToString());
            var sb = JsonNode.Parse(await start.Content.ReadAsStringAsync())!.AsObject();
            Assert.Equal("expiresIn,mode,qr,vc", string.Join(",", sb.Select(p => p.Key).OrderBy(x => x, StringComparer.Ordinal)));
            var setCookie = start.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("eid_login=", StringComparison.Ordinal));
            Assert.Contains("; HttpOnly", setCookie);
            Assert.Contains("; Secure", setCookie);
            Assert.Contains("; SameSite=Lax", setCookie);
            var cookie = setCookie.Split(';')[0];
            lock (keys)
            {
                Assert.Equal(new[] { "start:127.0.0.1" }, keys);
            }

            // PENDING → OK; OnSuccess-ийн HttpContext cookie ба eid_login-ийн цэвэрлэгээ хоёулаа.
            Assert.Equal("PENDING", (string?)(await Get(http, "/auth/eid/status", cookie)).Json!["state"]);
            fake.Set("OK", "QR", "");
            var ok = await Get(http, "/auth/eid/status", cookie);
            Assert.Equal("OK", (string?)ok.Json!["state"]);
            Assert.Equal("/dashboard", (string?)ok.Json!["redirect"]);
            Assert.Equal(FakeEid.Etsi, (string?)ok.Json!["data"]!["user"]);
            var okCookies = ok.Res.Headers.GetValues("Set-Cookie").ToList();
            Assert.Contains(okCookies, c => c.StartsWith("app_session=s1", StringComparison.Ordinal));
            Assert.Contains(okCookies, c => c.StartsWith("eid_login=;", StringComparison.Ordinal) && c.Contains("Max-Age=0"));
            Assert.Equal("EXPIRED", (string?)(await Get(http, "/auth/eid/status", cookie)).Json!["state"]);

            // Алдааны хэлбэр ба статус.
            var cross = new HttpRequestMessage(HttpMethod.Post, "/auth/eid/start")
            {
                Content = new StringContent("{\"mode\":\"qr\"}", Encoding.UTF8, "application/json"),
            };
            cross.Headers.Add("Sec-Fetch-Site", "cross-site");
            var cr = await http.SendAsync(cross);
            Assert.Equal(HttpStatusCode.Forbidden, cr.StatusCode);
            Assert.Equal("{\"error\":\"cross_site\"}", await cr.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync("/auth/eid/other")).StatusCode);
            Assert.Equal(HttpStatusCode.MethodNotAllowed, (await http.PutAsync("/auth/eid/start", new StringContent("{}", Encoding.UTF8, "application/json"))).StatusCode);
            var big = await http.PostAsync("/auth/eid/start",
                new StringContent("{\"mode\":\"qr\",\"pad\":\"" + new string('x', 8192) + "\"}", Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, big.StatusCode);
            Assert.Contains("invalid_body", await big.Content.ReadAsStringAsync());

            // Web2App: 302 → eID апп; өөр хөтчийн callback → 303 failure.
            var w = await http.GetAsync("/auth/eid/start?mode=web2app");
            Assert.Equal(HttpStatusCode.Found, w.StatusCode);
            Assert.StartsWith("https://eid.example.test/dl?deviceLinkType=Web2App&", w.Headers.Location!.OriginalString);
            var cb = await http.GetAsync("/auth/eid/callback?sessionId=" + FakeEid.Sid + "&userChallengeVerifier=x");
            Assert.Equal(HttpStatusCode.SeeOther, cb.StatusCode);
            Assert.Equal("/login?eid_error=expired", cb.Headers.Location!.OriginalString);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task RequestAndResponseMapping()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.PathBase = "/app";
        ctx.Request.Path = "/auth/eid/start";
        ctx.Request.QueryString = new QueryString("?a=1");
        ctx.Request.Headers.Append("Cookie", "a=b");
        ctx.Request.Headers.Append("Cookie", "eid_login=x.y");
        ctx.Request.Headers.Append("X-Forwarded-For", "198.51.100.7");
        ctx.Request.Headers.Append("X-Forwarded-For", "10.0.0.2");
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(new string('z', 10_000)));
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:203.0.113.9");
        var req = await EidLoginHttp.ToRequestAsync(ctx);
        Assert.Equal("POST", req.Method);
        Assert.Equal("/app/auth/eid/start?a=1", req.Url);
        Assert.Equal("a=b; eid_login=x.y", req.Headers["cookie"]);
        Assert.Equal("10.0.0.2", EidLoginClientIp.Forwarded(1)(req));
        Assert.Equal("203.0.113.9", req.RemoteIp);
        Assert.Equal(EidLoginHandler.MaxBodyBytes + 1, req.Body!.Length);
        Assert.Same(ctx, req.HostContext);

        var get = new DefaultHttpContext();
        get.Request.Method = "GET";
        Assert.Null((await EidLoginHttp.ToRequestAsync(get)).Body);

        var outCtx = new DefaultHttpContext();
        outCtx.Response.Body = new MemoryStream();
        await EidLoginHttp.WriteAsync(outCtx, new EidLoginResponse(200, new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "application/json; charset=utf-8"),
            new("Set-Cookie", "a=1; Path=/"),
            new("Set-Cookie", "b=2; Path=/"),
        }, "{\"state\":\"Ok\"}"));
        Assert.Equal(200, outCtx.Response.StatusCode);
        Assert.Equal(new[] { "a=1; Path=/", "b=2; Path=/" }, outCtx.Response.Headers.SetCookie.ToArray());
        Assert.Equal("application/json; charset=utf-8", outCtx.Response.ContentType);
        outCtx.Response.Body.Position = 0;
        Assert.Equal("{\"state\":\"Ok\"}", await new StreamReader(outCtx.Response.Body).ReadToEndAsync());
    }

    [Fact]
    public void AddEidMongoliaRegistersClientAndDefaultStoreOnce()
    {
        var services = new ServiceCollection();
        var custom = new MemoryEidLoginStore(5);
        services.AddSingleton<IEidLoginStore>(custom);
        services.AddEidMongolia(new EidClientOptions { Credentials = new EidCredentials("rp", "RP", "x") });
        services.AddEidMongolia(_ => throw new InvalidOperationException("дахин бүртгэхгүй"));
        using var sp = services.BuildServiceProvider();
        Assert.NotNull(sp.GetRequiredService<EidClient>());
        Assert.Same(custom, sp.GetRequiredService<IEidLoginStore>());
        var def = new ServiceCollection().AddEidMongolia(new EidClientOptions { Credentials = new EidCredentials("rp", "RP", "x") });
        using var sp2 = def.BuildServiceProvider();
        Assert.IsType<MemoryEidLoginStore>(sp2.GetRequiredService<IEidLoginStore>());
    }

    private static async Task<(HttpResponseMessage Res, JsonObject? Json)> Get(HttpClient http, string path, string cookie)
    {
        var m = new HttpRequestMessage(HttpMethod.Get, path);
        m.Headers.Add("Cookie", cookie);
        var res = await http.SendAsync(m);
        var body = await res.Content.ReadAsStringAsync();
        return (res, body.Length > 0 ? JsonNode.Parse(body)!.AsObject() : null);
    }
}
