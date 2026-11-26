using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace GeregeSystems.EidMongolia.Login;

/// <summary>
/// <see cref="EidLoginOptions.ClientIp"/>-ийн бэлэн дүрэм (Go <c>ForwardedClientIP</c> / <c>RemoteAddrIP</c>, TS
/// <c>trustProxy</c>). Proxy-ийн header-т зөвхөн ИТГЭМЖИТ proxy-ийн ард итгэнэ — эс бөгөөс клиент хуурамч header-ээр
/// <c>start:&lt;ip&gt;</c> хязгаарыг тойрно.
/// </summary>
public static class EidLoginClientIp
{
    /// <summary>
    /// Proxy-гүй (клиент шууд холбогддог) үед: <see cref="EidLoginRequest.RemoteIp"/>. ASP.NET Core-д ForwardedHeaders
    /// middleware (KnownProxies-тай) RemoteIpAddress-ийг аль хэдийн зассан бол мөн үүнийг хэрэглэнэ.
    /// </summary>
    public static string? RemoteAddress(EidLoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return string.IsNullOrEmpty(request.RemoteIp) ? null : request.RemoteIp;
    }

    /// <summary>
    /// Итгэмжит reverse proxy-ийн ард: <c>X-Forwarded-For</c>-ийн БАРУУНААС <paramref name="hops"/> дахь утга (hops = таны
    /// итгэмжит proxy-ийн тоо; nginx нэг бол 1); XFF алга бол <c>X-Real-IP</c>. XFF-д hop дутвал null (хуурамч header-ээр
    /// тойрохоос). Proxy-гүй үед бүү хэрэглэ.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hops"/> &lt; 1.</exception>
    public static Func<EidLoginRequest, string?> Forwarded(int hops)
    {
        if (hops < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(hops), "eidlogin: Forwarded hops >= 1 байх ёстой");
        }
        return r =>
        {
            ArgumentNullException.ThrowIfNull(r);
            var xff = EidLoginHandler.Header(r, "X-Forwarded-For")
                .Split(',')
                .Select(p => p.Trim())
                .Where(p => p.Length > 0)
                .ToList();
            if (xff.Count > 0)
            {
                return hops > xff.Count ? null : xff[xff.Count - hops];
            }
            var real = EidLoginHandler.Header(r, "X-Real-IP").Trim();
            return real.Length == 0 ? null : real;
        };
    }
}

/// <summary>
/// Апп approve-ийн дараа эхэлсэн хөтөч рүү буцах hint (CA docs/RP_GEREGE_INTEGRATION.md §1.1b; Go <c>WithReturnHint</c>,
/// TS <c>withReturnHint</c>).
/// </summary>
public static class EidLoginReturnHint
{
    private const RegexOptions Ci = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly (Regex Re, string Value)[] IosBrowsers =
    {
        (new Regex("CriOS", Ci), "googlechromes"),
        (new Regex("EdgiOS", Ci), "microsoft-edge-https"),
        (new Regex("FxiOS", Ci), "firefox"),
        (new Regex("OPT/", Ci), "touch-https"),
        (new Regex("OPiOS|OPR/", Ci), "opera-https"),
        (new Regex("DuckDuckGo", Ci), "ddgQuickLink"),
    };

    private static readonly (Regex Re, string Value)[] AndroidBrowsers =
    {
        (new Regex("EdgA/", Ci), "com.microsoft.emmx"),
        (new Regex("Opera Mini", Ci), "com.opera.mini.native"),
        (new Regex("OPR/", Ci), "com.opera.browser"),
        (new Regex("SamsungBrowser/", Ci), "com.sec.android.app.sbrowser"),
        (new Regex("YaBrowser/", Ci), "com.yandex.browser"),
        (new Regex("DuckDuckGo/", Ci), "com.duckduckgo.mobile.android"),
        (new Regex("Vivaldi/", Ci), "com.vivaldi.browser"),
        (new Regex("Firefox/", Ci), "org.mozilla.firefox"),
        (new Regex("Chrome/", Ci), "com.android.chrome"),
    };

    private static readonly Regex IosRe = new("iPhone|iPad|iPod", Ci);
    private static readonly Regex AndroidRe = new("Android", Ci);

    /// <summary>
    /// <paramref name="callbackUrl"/>-д буцах хөтчийн hint (<c>retScheme</c> iOS / <c>retPkg</c> Android) нэмнэ; танихгүй
    /// бол хэвээр. Query-ийн түлхүүрүүд Go <c>url.Values.Encode</c> шиг эрэмбэлэгдэнэ.
    /// </summary>
    public static string WithReturnHint(string callbackUrl, string? userAgent)
    {
        ArgumentNullException.ThrowIfNull(callbackUrl);
        var ua = userAgent ?? "";
        string key, val;
        if (IosRe.IsMatch(ua))
        {
            key = "retScheme";
            val = Pick(IosBrowsers, ua);
        }
        else if (AndroidRe.IsMatch(ua))
        {
            key = "retPkg";
            val = Pick(AndroidBrowsers, ua);
        }
        else
        {
            return callbackUrl;
        }
        if (val.Length == 0)
        {
            return callbackUrl;
        }
        var hash = callbackUrl.IndexOf('#');
        var fragment = hash >= 0 ? callbackUrl[hash..] : "";
        var noFragment = hash >= 0 ? callbackUrl[..hash] : callbackUrl;
        var q = noFragment.IndexOf('?');
        var path = q >= 0 ? noFragment[..q] : noFragment;
        var pairs = q >= 0 ? EidLoginHandler.ParseQuery(noFragment[(q + 1)..]) : new List<KeyValuePair<string, string>>();
        pairs.RemoveAll(p => p.Key == key);
        pairs.Add(new KeyValuePair<string, string>(key, val));
        var sb = new StringBuilder(path).Append('?');
        var first = true;
        foreach (var p in pairs.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (!first)
            {
                sb.Append('&');
            }
            first = false;
            sb.Append(Uri.EscapeDataString(p.Key)).Append('=').Append(Uri.EscapeDataString(p.Value));
        }
        return sb.Append(fragment).ToString();
    }

    private static string Pick((Regex Re, string Value)[] table, string ua)
    {
        foreach (var (re, value) in table)
        {
            if (re.IsMatch(ua))
            {
                return value;
            }
        }
        return "";
    }
}
