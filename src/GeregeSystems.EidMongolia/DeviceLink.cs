using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace GeregeSystems.EidMongolia;

/// <summary>Device link-ийн төрөл; апп гарын үсгийн flowType-д яг энэ утгыг зурна.</summary>
public static class DeviceLinkTypes
{
    /// <summary>QR (секунд тутам шинэчилнэ).</summary>
    public const string Qr = "QR";
    /// <summary>Web2App.</summary>
    public const string Web2App = "Web2App";
    /// <summary>App2App.</summary>
    public const string App2App = "App2App";
}

/// <summary>Device link session-ий урсгал.</summary>
public static class DeviceLinkSessionTypes
{
    /// <summary>Нэвтрэлт (ACSP_V2).</summary>
    public const string Auth = "auth";
    /// <summary>Гарын үсэг (RAW_DIGEST_SIGNATURE).</summary>
    public const string Sign = "sign";
    /// <summary>Certificate-choice.</summary>
    public const string Cert = "cert";
}

/// <summary><see cref="DeviceLink.Build"/>-ийн оролт (Go <c>DeviceLinkInput</c>).</summary>
public sealed record DeviceLinkInput
{
    /// <summary>Session start хариуны deviceLinkBase (query/fragment-гүй https URL).</summary>
    public string DeviceLinkBase { get; init; } = "";
    /// <summary><see cref="DeviceLinkTypes"/>.</summary>
    public string DeviceLinkType { get; init; } = "";
    /// <summary>Хариуны sessionToken, ЯГ ХЭВЭЭР.</summary>
    public string SessionToken { get; init; } = "";
    /// <summary>Хариуны sessionSecret (стандарт Base64, padding-тэй). ЗӨВХӨН backend-д.</summary>
    public string SessionSecret { get; init; } = "";
    /// <summary><see cref="DeviceLinkSessionTypes"/>.</summary>
    public string SessionType { get; init; } = "";
    /// <summary>ISO 639-2 гурван жижиг үсэг (mon, eng).</summary>
    public string Lang { get; init; } = "";
    /// <summary>RP backend session start хариуг хүлээн авсан мөч. QR-д заавал.</summary>
    public DateTimeOffset? ReceivedAt { get; init; }
    /// <summary>Одоогийн цаг (тест); null = одоо.</summary>
    public DateTimeOffset? Now { get; init; }
    /// <summary>auth: илгээсэн rpChallenge (base64 текстээрээ).</summary>
    public string? RpChallenge { get; init; }
    /// <summary>sign: илгээсэн digest (base64 текст).</summary>
    public string? Digest { get; init; }
    /// <summary>Session start хүсэлтэд илгээсэн ЯГ тэр нэр.</summary>
    public string RelyingPartyName { get; init; } = "";
    /// <summary>auth/sign: илгээсэн interactions-ийн base64 МӨР; cert: "".</summary>
    public string Interactions { get; init; } = "";
    /// <summary>Хүсэлтэд илгээсэн түүхий URL. Web2App/App2App-д заавал; QR-д authCode-д ОРОХГҮЙ.</summary>
    public string? InitialCallbackUrl { get; init; }
    /// <summary>null / "" = "smart-id".</summary>
    public string? SchemeName { get; init; }
    /// <summary>eID broker дэмждэггүй, "".</summary>
    public string BrokeredRpName { get; init; } = "";
}

/// <summary>
/// Device link v3 (Smart-ID RP-API v3 «dynamic link») — QR / Web2App / App2App холбоосыг RP BACKEND угсарна: authCode =
/// HMAC-SHA256(sessionSecret), QR-д elapsedSeconds секунд тутам шинэчлэгдэнэ. SessionSecret-ийг браузер/апп руу ХЭЗЭЭ Ч
/// бүү гарга. Go devicelink.go-ийн порт; CA-ийн golden векторуудаар батлагдсан.
/// </summary>
public static class DeviceLink
{
    private static readonly Regex TokenRe = new(@"^[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex LangRe = new(@"^[a-z]{3}\z", RegexOptions.CultureInvariant);
    private static readonly Regex StdB64Re = new(
        @"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z", RegexOptions.CultureInvariant);

    private static EidDeviceLinkException Err(string msg) => new(msg);

    /// <summary>
    /// Device link v3-ийг бүтнээр нь угсарна (…&amp;authCode=…). Цэвэр функц.
    /// <code>
    /// QR:      {base}?deviceLinkType=QR&amp;elapsedSeconds={E}&amp;sessionToken={T}&amp;sessionType={S}&amp;version=1.0&amp;lang={L}&amp;authCode={A}
    /// Web2App: {base}?deviceLinkType=Web2App&amp;sessionToken={T}&amp;sessionType={S}&amp;version=1.0&amp;lang={L}&amp;authCode={A}
    /// </code>
    /// QR холбоос ~20 секундэд хүчингүй болдог тул секунд тутам дахин дуудна (<see cref="TickQrAsync(DeviceLinkInput, TimeSpan, CancellationToken)"/>). Оролт буруу бол
    /// <see cref="EidDeviceLinkException"/>.
    /// </summary>
    public static string Build(DeviceLinkInput p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var b = (p.DeviceLinkBase ?? "").Trim();
        if (b.Length == 0)
        {
            throw Err("deviceLinkBase хоосон — device-link session-ий хариуг шалга");
        }
        if (!Uri.TryCreate(b, UriKind.Absolute, out var u))
        {
            throw Err("deviceLinkBase буруу URL: " + b);
        }
        if (u.Scheme != "https" || u.Host.Length == 0 || b.IndexOfAny(new[] { '?', '#' }) >= 0)
        {
            throw Err("deviceLinkBase нь query/fragment-гүй https URL байх ёстой");
        }
        if (p.DeviceLinkType is not (DeviceLinkTypes.Qr or DeviceLinkTypes.Web2App or DeviceLinkTypes.App2App))
        {
            throw Err("deviceLinkType " + p.DeviceLinkType + " (QR | Web2App | App2App)");
        }
        var protocol = p.SessionType switch
        {
            DeviceLinkSessionTypes.Auth => "ACSP_V2",
            DeviceLinkSessionTypes.Sign => "RAW_DIGEST_SIGNATURE",
            DeviceLinkSessionTypes.Cert => "",
            _ => throw Err("sessionType " + p.SessionType + " (auth | sign | cert)"),
        };
        if (!TokenRe.IsMatch(p.SessionToken ?? ""))
        {
            throw Err("sessionToken хэлбэр буруу");
        }
        if (!LangRe.IsMatch(p.Lang ?? ""))
        {
            throw Err("lang нь ISO 639-2 гурван жижиг үсэг (mon, eng)");
        }
        if (string.IsNullOrEmpty(p.SessionSecret) || !StdB64Re.IsMatch(p.SessionSecret) || !B64.TryDecodeStd(p.SessionSecret, out var key))
        {
            throw Err("sessionSecret стандарт Base64 (padding-тэй) биш");
        }

        string challenge;
        switch (p.SessionType)
        {
            case DeviceLinkSessionTypes.Auth:
                if (string.IsNullOrEmpty(p.RpChallenge))
                {
                    throw Err("auth session-д rpChallenge заавал");
                }
                challenge = p.RpChallenge;
                break;
            case DeviceLinkSessionTypes.Sign:
                if (string.IsNullOrEmpty(p.Digest))
                {
                    throw Err("sign session-д digest заавал");
                }
                challenge = p.Digest;
                break;
            default:
                if (!string.IsNullOrEmpty(p.RpChallenge) || !string.IsNullOrEmpty(p.Digest))
                {
                    throw Err("cert session-д rpChallenge/digest байхгүй");
                }
                challenge = "";
                break;
        }

        var qr = p.DeviceLinkType == DeviceLinkTypes.Qr;
        var callback = "";
        if (!qr)
        {
            callback = p.InitialCallbackUrl ?? "";
            if (callback.Length == 0)
            {
                throw Err(p.DeviceLinkType + " холбоос initialCallbackUrl-тай session-д л хүчинтэй");
            }
        }

        var elapsed = "";
        if (qr)
        {
            if (p.ReceivedAt is not { } received)
            {
                throw Err("QR холбоосонд ReceivedAt заавал");
            }
            var now = p.Now ?? DateTimeOffset.UtcNow;
            // Цаг ухарсан ч (NTP) сөрөг утга гаргахгүй — сервер ирээдүйн elapsed-ийг татгалздаг. Бүхэл секунд (доош).
            var d = now - received;
            var e = d <= TimeSpan.Zero ? 0 : d.Ticks / TimeSpan.TicksPerSecond;
            elapsed = "&elapsedSeconds=" + e.ToString(CultureInfo.InvariantCulture);
        }

        var unprotected = b + "?deviceLinkType=" + p.DeviceLinkType + elapsed +
            "&sessionToken=" + p.SessionToken + "&sessionType=" + p.SessionType +
            "&version=1.0&lang=" + p.Lang;
        var scheme = string.IsNullOrEmpty(p.SchemeName) ? "smart-id" : p.SchemeName;
        var payload = string.Join("|",
            scheme, protocol, challenge, B64.Std(p.RelyingPartyName ?? ""), B64.Std(p.BrokeredRpName ?? ""),
            p.Interactions ?? "", callback, unprotected);
        var mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payload));
        return unprotected + "&authCode=" + B64.RawUrl(mac);
    }

    /// <summary>
    /// Session start-ын хариу + хүсэлтийн утгуудаас <see cref="Build"/>-ийн оролт (auth: Acsp, sign: Sign, cert:
    /// RelyingPartyName + CallbackUrl). <paramref name="lang"/> — ISO 639-2 (mon, eng).
    /// </summary>
    public static DeviceLinkInput InputOf(DeviceLinkSession s, string deviceLinkType, string lang)
    {
        ArgumentNullException.ThrowIfNull(s);
        var input = new DeviceLinkInput
        {
            DeviceLinkBase = s.DeviceLinkBase,
            DeviceLinkType = deviceLinkType,
            SessionToken = s.SessionToken,
            SessionSecret = s.SessionSecret,
            SessionType = s.SessionType ?? "",
            Lang = lang,
            ReceivedAt = s.ReceivedAt == default ? null : s.ReceivedAt,
        };
        if (s.SessionType == DeviceLinkSessionTypes.Sign && s.Sign is { } sg)
        {
            return input with
            {
                Digest = sg.Digest,
                RelyingPartyName = sg.RelyingPartyName,
                Interactions = sg.Interactions,
                InitialCallbackUrl = sg.InitialCallbackUrl,
            };
        }
        if (s.SessionType == DeviceLinkSessionTypes.Cert)
        {
            return input with { RelyingPartyName = s.RelyingPartyName ?? "", InitialCallbackUrl = s.CallbackUrl };
        }
        if (s.Acsp is { } a)
        {
            // auth (хуучин хадгалсан session-д SessionType "").
            return input with
            {
                SessionType = DeviceLinkSessionTypes.Auth,
                RpChallenge = a.RpChallenge,
                RelyingPartyName = a.RelyingPartyName,
                Interactions = a.Interactions,
                InitialCallbackUrl = a.InitialCallbackUrl,
            };
        }
        return input;
    }

    /// <summary>
    /// SSE/WebSocket-д: QR холбоосыг шууд нэг удаа, дараа нь <paramref name="interval"/> (≤ 0 бол 1 с) тутам гаргана;
    /// <paramref name="ct"/> цуцлагдах хүртэл. Оролт буруу бол эхний алхамд <see cref="EidDeviceLinkException"/>. HTTP
    /// poll ашиглавал хэрэггүй — хүсэлт бүрд <see cref="Build"/> дууд.
    /// </summary>
    public static IAsyncEnumerable<string> TickQrAsync(DeviceLinkInput input, TimeSpan interval, CancellationToken ct = default) =>
        TickQrAsync(input, interval, TimeProvider.System, ct);

    /// <summary>
    /// <see cref="TickQrAsync(DeviceLinkInput, TimeSpan, CancellationToken)"/>, <paramref name="timeProvider"/>-ийн цаг ба
    /// таймераар (elapsedSeconds = timeProvider-ийн одоо − ReceivedAt).
    /// </summary>
    public static async IAsyncEnumerable<string> TickQrAsync(DeviceLinkInput input, TimeSpan interval, TimeProvider timeProvider,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (interval <= TimeSpan.Zero)
        {
            interval = TimeSpan.FromSeconds(1);
        }
        var qr = input with { DeviceLinkType = DeviceLinkTypes.Qr };
        yield return Build(qr with { Now = timeProvider.GetUtcNow() });
        using var timer = new PeriodicTimer(interval, timeProvider);
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            yield return Build(qr with { Now = timeProvider.GetUtcNow() });
        }
    }
}
