using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// SDK-ийн дууддаг RP-API зам (method + <c>{param}</c>-тай template). Бүх зам ЗӨВХӨН <see cref="RpRoutes"/>-д
/// тодорхойлогдоно (Go routes.go, TS contract.ts-тэй ижил): гэрээний тест (<c>contract.yml</c>) жагсаалтыг live
/// <c>/.well-known/eid</c>-тэй тулгадаг.
/// </summary>
internal readonly record struct RpRoute(string Method, string Path)
{
    /// <summary>
    /// Template-ийн <c>{param}</c>-уудыг дарааллаар нь escape хийсэн <paramref name="args"/>-аар орлуулна. Хоосон, <c>.</c>,
    /// <c>..</c> утгыг татгалзана: <c>Uri.EscapeDataString</c> цэгийг escape хийдэггүй тул System.Uri dot-segment-ийг
    /// арилгаж хүсэлтийг өөр зам руу (ж: <c>/session/..</c> → <c>/</c>) шилжүүлнэ.
    /// </summary>
    /// <exception cref="ArgumentException">Параметр хоосон, <c>.</c> эсвэл <c>..</c>.</exception>
    public string Expand(params string[] args)
    {
        foreach (var a in args)
        {
            CheckSegment(a);
        }
        var b = new StringBuilder();
        var rest = Path;
        foreach (var a in args)
        {
            var i = rest.IndexOf('{', StringComparison.Ordinal);
            var j = rest.IndexOf('}', StringComparison.Ordinal);
            if (i < 0 || j < i)
            {
                throw new InvalidOperationException("eid: route " + Path + ": параметр илүү");
            }
            b.Append(rest, 0, i);
            b.Append(Uri.EscapeDataString(a ?? throw new ArgumentNullException(nameof(args))));
            rest = rest[(j + 1)..];
        }
        if (rest.Contains('{', StringComparison.Ordinal))
        {
            throw new InvalidOperationException("eid: route " + Path + ": параметр дутуу");
        }
        b.Append(rest);
        return b.ToString();
    }

    /// <summary>Замын нэг сегментэд орох утга: null биш, хоосон биш, <c>.</c> / <c>..</c> биш.</summary>
    /// <exception cref="ArgumentException">Хоосон, <c>.</c> эсвэл <c>..</c>.</exception>
    internal static void CheckSegment(string? value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value is "" or "." or "..")
        {
            throw new ArgumentException("eid: замын параметр хоосон, \".\" эсвэл \"..\" байж болохгүй", nameof(value));
        }
    }
}

/// <summary>RP-API-ийн бүх зам (Go routes.go-той нэг мөр).</summary>
internal static class RpRoutes
{
    public static readonly RpRoute AuthNotificationEtsi = new("POST", "/authentication/notification/etsi/{semanticsIdentifier}");
    public static readonly RpRoute AuthNotificationDocument = new("POST", "/authentication/notification/document/{documentNumber}");
    public static readonly RpRoute AuthDeviceLinkAnonymous = new("POST", "/authentication/device-link/anonymous");
    public static readonly RpRoute AuthDeviceLinkEtsi = new("POST", "/authentication/device-link/etsi/{semanticsIdentifier}");
    public static readonly RpRoute AuthQr = new("POST", "/authentication/qr");
    public static readonly RpRoute SignNotificationEtsi = new("POST", "/signature/notification/etsi/{semanticsIdentifier}");
    public static readonly RpRoute SignNotificationDocument = new("POST", "/signature/notification/document/{documentNumber}");
    public static readonly RpRoute SignNotificationLinked = new("POST", "/signature/notification/linked/{documentNumber}");
    public static readonly RpRoute SignDeviceLinkEtsi = new("POST", "/signature/device-link/etsi/{semanticsIdentifier}");
    public static readonly RpRoute SignDeviceLinkDocument = new("POST", "/signature/device-link/document/{documentNumber}");
    public static readonly RpRoute CertChoiceDeviceLink = new("POST", "/signature/certificate-choice/device-link/anonymous");
    public static readonly RpRoute CertChoiceEtsi = new("POST", "/signature/certificate-choice/notification/etsi/{semanticsIdentifier}");
    public static readonly RpRoute PdfSignatures = new("POST", "/pdf/signatures");
    public static readonly RpRoute OrgRepresentations = new("GET", "/organization/representations/etsi/{personEtsi}");
    public static readonly RpRoute Session = new("GET", "/session/{sessionId}");
    public static readonly RpRoute PersonCertificates = new("GET", "/certificates/etsi/{personEtsi}");
    public static readonly RpRoute PersonDevices = new("GET", "/devices/etsi/{personEtsi}");
    public static readonly RpRoute PersonActivity = new("GET", "/rp/activity/etsi/{personEtsi}");
    public static readonly RpRoute PersonSummary = new("GET", "/person/summary/etsi/{personEtsi}");
    public static readonly RpRoute PersonChildren = new("GET", "/person/children/etsi/{personEtsi}");
    public static readonly RpRoute TokenCertificate = new("POST", "/token/certificate");
    public static readonly RpRoute TokenCertificateResult = new("GET", "/token/certificate/{sessionID}");
    public static readonly RpRoute TokenAuthChallenge = new("POST", "/token/auth/challenge");
    public static readonly RpRoute TokenAuthVerify = new("POST", "/token/auth/verify");
    public static readonly RpRoute Share = new("POST", "/share");
    public static readonly RpRoute SealCertificate = new("GET", "/seal/certificate/{orgEtsi}");
    public static readonly RpRoute SealCertificateRequest = new("POST", "/seal/certificate/{orgEtsi}");
    public static readonly RpRoute SealCertificateRequestStatus = new("GET", "/seal/certificate/{orgEtsi}/requests/{requestId}");
    public static readonly RpRoute Seal = new("POST", "/seal/{orgEtsi}");
    public static readonly RpRoute SealRegistrations = new("POST", "/seal/{orgEtsi}/registrations");
    public static readonly RpRoute SealGrants = new("POST", "/seal/grants");
    public static readonly RpRoute SealGrantStatus = new("GET", "/seal/grants/{grantId}");
    public static readonly RpRoute OrgSealGrants = new("GET", "/organization/seal-grants/etsi/{personEtsi}");

    /// <summary>Discovery (<c>/.well-known/eid</c>) — гэрээний жагсаалтад орохгүй.</summary>
    public const string DiscoveryPath = "/.well-known/eid";

    /// <summary>SDK-ийн хамардаг бүх RP-API зам (гэрээний тестэд).</summary>
    public static readonly IReadOnlyList<RpRoute> All = new[]
    {
        AuthNotificationEtsi, AuthNotificationDocument, AuthDeviceLinkAnonymous, AuthDeviceLinkEtsi,
        AuthQr,
        SignNotificationEtsi, SignNotificationDocument, SignNotificationLinked,
        SignDeviceLinkEtsi, SignDeviceLinkDocument,
        CertChoiceDeviceLink, CertChoiceEtsi,
        PdfSignatures,
        OrgRepresentations,
        Session,
        PersonCertificates, PersonDevices, PersonActivity, PersonSummary, PersonChildren,
        TokenCertificate, TokenCertificateResult,
        TokenAuthChallenge, TokenAuthVerify,
        Share,
        SealCertificate, SealCertificateRequest, SealCertificateRequestStatus, Seal, SealRegistrations,
        SealGrants, SealGrantStatus, OrgSealGrants,
    };

    /// <summary>
    /// CA-ийн гэрээнд байгаа ч live discovery-д хараахан жагсаагдаагүй замууд — гэрээний тест WARN болгоно (fail биш).
    /// </summary>
    public static readonly IReadOnlyList<RpRoute> Undiscovered = Array.Empty<RpRoute>();

    private static readonly Regex IdentifierInPath = new(
        @"/(etsi|document|linked|requests|seal(?:/certificate|/grants)?)/[^/?#\s]+", RegexOptions.CultureInvariant);

    /// <summary>
    /// Алдаа/логт орох зам: <c>/etsi/{…}</c>, <c>/document/{…}</c>, <c>/linked/{…}</c>, <c>/seal/[certificate/]{…}</c>,
    /// <c>/requests/{…}</c> → <c>…</c>, query хасагдана (Go maskPath).
    /// </summary>
    public static string MaskPath(string path)
    {
        var i = path.IndexOfAny(new[] { '?', '#' });
        if (i >= 0)
        {
            path = path[..i];
        }
        return IdentifierInPath.Replace(path, "/$1/…");
    }
}
