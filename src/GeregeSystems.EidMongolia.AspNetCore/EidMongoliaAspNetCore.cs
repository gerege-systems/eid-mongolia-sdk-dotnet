using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace GeregeSystems.EidMongolia.AspNetCore;

/// <summary>DI бүртгэл: <see cref="EidClient"/> (singleton) ба анхдагч <see cref="IEidLoginStore"/>.</summary>
public static class EidMongoliaServiceCollectionExtensions
{
    /// <summary>
    /// <see cref="EidClient"/>-ийг <paramref name="options"/>-оор singleton болгож, <see cref="IEidLoginStore"/> бүртгэгдээгүй
    /// бол <see cref="MemoryEidLoginStore"/> (нэг процесс) нэмнэ. Олон instance бол өөрийн store-оо (Redis г.м.) ӨМНӨ нь бүртгэ.
    /// </summary>
    public static IServiceCollection AddEidMongolia(this IServiceCollection services, EidClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return services.AddEidMongolia(_ => new EidClient(options));
    }

    /// <summary>
    /// <see cref="EidClient"/>-ийг factory-оор (ж: mTLS-тэй HttpClient) singleton болгоно; бусад нь
    /// <see cref="AddEidMongolia(IServiceCollection, EidClientOptions)"/>-тэй ижил.
    /// </summary>
    public static IServiceCollection AddEidMongolia(this IServiceCollection services, Func<IServiceProvider, EidClient> factory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.TryAddSingleton(factory);
        services.TryAddSingleton<IEidLoginStore>(sp => new MemoryEidLoginStore(timeProvider: sp.GetService<TimeProvider>()));
        return services;
    }
}

/// <summary>«eID-ээр нэвтрэх» товчны endpoint-ууд (<c>{prefix}/start</c>, <c>/status</c>, <c>/callback</c>).</summary>
public static class EidLoginEndpointRouteBuilderExtensions
{
    /// <summary>
    /// <paramref name="prefix"/> (Web2App-д заавал <c>/auth/eid</c> — eID сервер callback-ийг <c>/auth/eid/callback</c> болгож
    /// нормчилдог) доор <see cref="EidLoginHandler"/>-ийг холбоно. <paramref name="onSuccess"/> — иргэн баталгаажсан: таны
    /// session-ийг ШИНЭ id-тай үүсгэж <c>http.Response.Cookies</c>-оор тавь. Client / Store / Log нь
    /// <paramref name="configure"/>-д өгөөгүй бол DI-аас (<see cref="EidMongoliaServiceCollectionExtensions.AddEidMongolia(IServiceCollection, EidClientOptions)"/>,
    /// ILoggerFactory). ClientIp өгөөгүй бол <see cref="EidLoginClientIp.RemoteAddress"/> (<c>HttpContext.Connection.RemoteIpAddress</c>).
    /// Reverse proxy-ийн ард бол <c>app.UseForwardedHeaders()</c>-ийг (KnownProxies / KnownNetworks-тэй) <c>MapEidLogin</c>-оос
    /// ӨМНӨ ажиллуул, эсвэл <c>o.ClientIp = EidLoginClientIp.Forwarded(n)</c> (n = итгэмжит proxy-ийн тоо) — эс бөгөөс бүх
    /// хэрэглэгч proxy-ийн нэг IP-ийн <c>start</c> хязгаарыг хуваалцана. IP-ээр хязгаарлахгүй бол <c>o.ClientIp = _ =&gt; null</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapEidLogin(this IEndpointRouteBuilder endpoints, string prefix,
        Func<HttpContext, EidLoginIdentity, Task<EidLoginSuccess?>> onSuccess, Action<EidLoginOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(onSuccess);
        var sp = endpoints.ServiceProvider;
        var o = new EidLoginOptions();
        configure?.Invoke(o);
        o.Client ??= sp.GetRequiredService<EidClient>();
        o.Store ??= sp.GetService<IEidLoginStore>();
        o.TimeProvider ??= sp.GetService<TimeProvider>();
        o.ClientIp ??= EidLoginClientIp.RemoteAddress;
        if (o.Log is null && sp.GetService<ILoggerFactory>() is { } lf)
        {
            var logger = lf.CreateLogger("GeregeSystems.EidMongolia.Login");
            o.Log = e => logger.Log(e.Level == EidLoginLogLevel.Warning ? LogLevel.Warning : LogLevel.Error, e.Exception, "{Message}", e.Message);
        }
        o.OnSuccess = (id, ctx, _) => onSuccess((HttpContext)ctx.Request.HostContext!, id);
        return endpoints.MapEidLogin(prefix, new EidLoginHandler(o));
    }

    /// <summary>Бэлэн <see cref="EidLoginHandler"/>-ийг <paramref name="prefix"/> доор холбоно (OnSuccess-д HttpContext нь <c>ctx.Request.HostContext</c>).</summary>
    public static IEndpointConventionBuilder MapEidLogin(this IEndpointRouteBuilder endpoints, string prefix, EidLoginHandler handler)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(prefix);
        ArgumentNullException.ThrowIfNull(handler);
        return endpoints.Map(prefix.TrimEnd('/') + "/{action}", (RequestDelegate)(http => EidLoginHttp.HandleAsync(handler, http)));
    }
}

/// <summary>HttpContext ↔ <see cref="EidLoginRequest"/> / <see cref="EidLoginResponse"/>.</summary>
public static class EidLoginHttp
{
    /// <summary>Хүсэлтийг handler-ээр боловсруулж хариуг бичнэ.</summary>
    public static async Task HandleAsync(EidLoginHandler handler, HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(http);
        var req = await ToRequestAsync(http, http.RequestAborted).ConfigureAwait(false);
        var res = await handler.HandleAsync(req, http.RequestAborted).ConfigureAwait(false);
        await WriteAsync(http, res).ConfigureAwait(false);
    }

    /// <summary>
    /// HttpContext → <see cref="EidLoginRequest"/>: зам + query (PathBase-тэй), header (Cookie-г "; ", бусдыг ", "-ээр
    /// нэгтгэнэ), POST-ийн бие (<see cref="EidLoginHandler.MaxBodyBytes"/> + 1 байт хүртэл), RemoteIpAddress (IPv4-mapped →
    /// IPv4).
    /// </summary>
    public static async Task<EidLoginRequest> ToRequestAsync(HttpContext http, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in http.Request.Headers)
        {
            var sep = string.Equals(h.Key, "Cookie", StringComparison.OrdinalIgnoreCase) ? "; " : ", ";
            headers[h.Key] = string.Join(sep, h.Value.Where(v => v is not null));
        }
        string? body = null;
        if (HttpMethods.IsPost(http.Request.Method))
        {
            body = await ReadBodyAsync(http.Request.Body, EidLoginHandler.MaxBodyBytes + 1, ct).ConfigureAwait(false);
        }
        var ip = http.Connection.RemoteIpAddress;
        if (ip is not null && ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }
        return new EidLoginRequest
        {
            Method = http.Request.Method,
            Url = http.Request.GetEncodedPathAndQuery(),
            Headers = headers,
            Body = body,
            RemoteIp = ip?.ToString(),
            HostContext = http,
        };
    }

    /// <summary><see cref="EidLoginResponse"/>-ийг HttpResponse руу бичнэ (Set-Cookie бүрийг тусад нь).</summary>
    public static async Task WriteAsync(HttpContext http, EidLoginResponse res)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(res);
        http.Response.StatusCode = res.Status;
        foreach (var h in res.Headers)
        {
            http.Response.Headers.Append(h.Key, h.Value);
        }
        if (res.Body.Length > 0)
        {
            var bytes = Encoding.UTF8.GetBytes(res.Body);
            http.Response.ContentLength = bytes.Length;
            await http.Response.Body.WriteAsync(bytes, http.RequestAborted).ConfigureAwait(false);
        }
    }

    private static async Task<string> ReadBodyAsync(Stream s, int limit, CancellationToken ct)
    {
        var buf = new byte[limit];
        var n = 0;
        while (n < limit)
        {
            var r = await s.ReadAsync(buf.AsMemory(n, limit - n), ct).ConfigureAwait(false);
            if (r == 0)
            {
                break;
            }
            n += r;
        }
        return Encoding.UTF8.GetString(buf, 0, n);
    }
}
