using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace GeregeSystems.EidMongolia.Qr;

/// <summary>
/// «Миний QR» (биечлэн шалгах): иргэн апп дээрээ нэг удаагийн QR (120 с) харуулна → RP скан хийж
/// <see cref="EidQrClient.StartAsync"/>-аар хүссэн аттрибутаа CA-аас асууна → иргэн утсан дээрээ PIN1-ээр зөвшөөрнө →
/// <see cref="EidQrClient.ResultAsync"/> нь CA-ийн ES256 presentation (JWS)-ийг JWKS-ээр шалгаж ЗӨВХӨН хүссэн
/// аттрибутуудыг буцаана. Go / TS SDK-тэй ижил дүрэм (testdata/qr_vectors.json — гурван SDK-д ижил).
/// </summary>
public static class EidQr
{
    /// <summary>Иргэний аппын QR-ийн угтвар: <c>EIDMN-QR1:&lt;token&gt;</c>.</summary>
    public const string Prefix = "EIDMN-QR1:";

    /// <summary>Presentation JWS-ийн хүлээгдэх <c>iss</c>.</summary>
    public const string DefaultIssuer = "https://ca.eidmongolia.mn";

    /// <summary>CA-ийн presentation гарын үсгийн нийтийн түлхүүрүүд (JWKS).</summary>
    public const string DefaultJwksUrl = "https://ca.eidmongolia.mn/.well-known/eid-jwks.json";

    /// <summary>Presentation-ийн <c>iat</c>-аас хойш хүлээн авах дээд хугацаа.</summary>
    public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(10);

    /// <summary><c>iat</c> ирээдүйд байж болох зөрүү.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    internal const int MaxJws = 16 << 10;

    private static readonly Regex TokenRe = new("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant);
    private static readonly Regex B64UrlRe = new("^[A-Za-z0-9_-]*$", RegexOptions.CultureInvariant);
    private static readonly Regex PhoneRe = new("^\\+[1-9][0-9]{6,14}$", RegexOptions.CultureInvariant);
    private static readonly Regex DateRe = new("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Скан хийсэн QR-ээс токен: <c>EIDMN-QR1:&lt;token&gt;</c> эсвэл зөвхөн токен (43 тэмдэгт base64url). Буруу бол
    /// <see cref="EidQrException"/> <c>QR_FORMAT_INVALID</c>.
    /// </summary>
    public static string Parse(string? scanned)
    {
        var s = (scanned ?? "").Trim();
        if (s.StartsWith(Prefix, StringComparison.Ordinal))
        {
            s = s.Substring(Prefix.Length);
        }
        if (!TokenRe.IsMatch(s))
        {
            throw new EidQrException(EidQrErrorCodes.FormatInvalid, "eID «Миний QR» биш");
        }
        return s;
    }

    internal static string[] CheckAttributes(IReadOnlyList<string>? attrs)
    {
        if (attrs is null || attrs.Count == 0)
        {
            throw new EidQrException(EidQrErrorCodes.AttributesInvalid, "аттрибут сонгоогүй");
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in attrs)
        {
            if (!QrAttributes.All.Contains(a))
            {
                throw new EidQrException(EidQrErrorCodes.AttributesInvalid, "каталогид алга: " + a);
            }
            if (!seen.Add(a))
            {
                throw new EidQrException(EidQrErrorCodes.AttributesInvalid, "давхардсан: " + a);
            }
        }
        return attrs.ToArray();
    }

    /// <summary>
    /// Compact JWS-ийг <paramref name="jwksJson"/>-ээр шалгаж (ES256, kid) claim-уудыг тулгана: iss, aud (RP UUID), sid,
    /// nonce, iat (≤ now+60 с, ≥ now−MaxAge), exp (байвал), attrs ∪ unavailable = хүссэн аттрибутууд яг, аттрибут бүрийн
    /// төрөл. Алдаа бол <see cref="EidQrException"/> <c>QR_PRESENTATION_INVALID</c> — хариунд ИТГЭХГҮЙ. Сүлжээгүй.
    /// </summary>
    public static QrPresentation VerifyPresentation(string jws, string jwksJson, QrExpect expect)
    {
        var keys = Jwks.Parse(jwksJson);
        var p = Verify(jws, keys, expect, out var unknownKid);
        return unknownKid ? throw Bad("JWKS-д kid алга") : p!;
    }

    internal static EidQrException Bad(string reason) => new(EidQrErrorCodes.PresentationInvalid, reason);

    internal static byte[] B64Url(string s)
    {
        if (!B64UrlRe.IsMatch(s) || s.Length % 4 == 1)
        {
            throw Bad("base64url буруу");
        }
        var t = s.Replace('-', '+').Replace('_', '/');
        t = t.PadRight(t.Length + ((4 - (t.Length % 4)) % 4), '=');
        try
        {
            return Convert.FromBase64String(t);
        }
        catch (FormatException)
        {
            throw Bad("base64url буруу");
        }
    }

    /// <summary>unknownKid = true бол JWKS-д kid алга (дуудагч дахин татаж болно); тэр үед null.</summary>
    internal static QrPresentation? Verify(string jws, Jwks keys, QrExpect exp, out bool unknownKid)
    {
        unknownKid = false;
        if (string.IsNullOrEmpty(jws) || jws.Length > MaxJws)
        {
            throw Bad("JWS хоосон эсвэл хэт урт");
        }
        var parts = jws.Split('.');
        if (parts.Length != 3)
        {
            throw Bad("compact JWS биш");
        }
        var hb = B64Url(parts[0]);
        var pb = B64Url(parts[1]);
        var sig = B64Url(parts[2]);

        string kid;
        using (var hdr = ParseObject(hb, "header"))
        {
            var h = hdr.RootElement;
            if (!h.TryGetProperty("alg", out var alg) || alg.ValueKind != JsonValueKind.String || alg.GetString() != "ES256")
            {
                throw Bad("alg ES256 биш");
            }
            if (h.TryGetProperty("crit", out _))
            {
                throw Bad("crit дэмжихгүй");
            }
            if (!h.TryGetProperty("kid", out var k) || k.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(k.GetString()))
            {
                throw Bad("kid алга");
            }
            kid = k.GetString()!;
        }
        using var key = keys.Find(kid);
        if (key is null)
        {
            unknownKid = true;
            return null;
        }
        if (sig.Length != 64)
        {
            throw Bad("ES256 гарын үсэг 64 байт биш");
        }
        if (!key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), sig, HashAlgorithmName.SHA256))
        {
            throw Bad("гарын үсэг таарсангүй");
        }
        using var payload = ParseObject(pb, "payload");
        return CheckClaims(payload.RootElement, jws, exp);
    }

    private static JsonDocument ParseObject(byte[] b, string what)
    {
        JsonDocument d;
        try
        {
            d = JsonDocument.Parse(b);
        }
        catch (JsonException)
        {
            throw Bad(what + " JSON биш");
        }
        if (d.RootElement.ValueKind != JsonValueKind.Object)
        {
            d.Dispose();
            throw Bad(what + " JSON объект биш");
        }
        return d;
    }

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static DateTimeOffset? NumericDate(JsonElement o, string name)
    {
        if (!o.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Number || !v.TryGetDouble(out var f) || f <= 0 || f > 1e11)
        {
            return null;
        }
        return DateTimeOffset.FromUnixTimeMilliseconds((long)(f * 1000));
    }

    private static QrPresentation CheckClaims(JsonElement c, string jws, QrExpect exp)
    {
        if (Str(c, "iss") != (string.IsNullOrEmpty(exp.Issuer) ? DefaultIssuer : exp.Issuer))
        {
            throw Bad("iss таарсангүй");
        }
        // aud = RP UUID (CA жижиг үсгээр бичнэ) — том/жижиг үсэг ялгахгүй.
        if (string.IsNullOrEmpty(exp.Audience) || !string.Equals(Str(c, "aud"), exp.Audience, StringComparison.OrdinalIgnoreCase))
        {
            throw Bad("aud (RP UUID) таарсангүй");
        }
        if (string.IsNullOrEmpty(exp.SessionId) || Str(c, "sid") != exp.SessionId)
        {
            throw Bad("sid таарсангүй");
        }
        if (string.IsNullOrEmpty(exp.Nonce) || Str(c, "nonce") != exp.Nonce)
        {
            throw Bad("nonce таарсангүй");
        }
        var sub = Str(c, "sub");
        if (string.IsNullOrEmpty(sub))
        {
            throw Bad("sub алга");
        }
        var now = exp.Now ?? DateTimeOffset.UtcNow;
        var maxAge = exp.MaxAge is { } m && m > TimeSpan.Zero ? m : DefaultMaxAge;
        var iat = NumericDate(c, "iat") ?? throw Bad("iat алга");
        if (iat > now + ClockSkew)
        {
            throw Bad("iat ирээдүйд");
        }
        if (now - iat > maxAge)
        {
            throw Bad("presentation хуучирсан");
        }
        if (c.TryGetProperty("exp", out _))
        {
            var e = NumericDate(c, "exp");
            if (e is null || now >= e.Value + ClockSkew)
            {
                throw Bad("exp дууссан");
            }
        }

        var want = new HashSet<string>(exp.Attributes ?? Array.Empty<string>(), StringComparer.Ordinal);
        var got = new HashSet<string>(StringComparer.Ordinal);
        var attrs = new QrAttrs();
        if (c.TryGetProperty("attrs", out var a))
        {
            if (a.ValueKind != JsonValueKind.Object)
            {
                throw Bad("attrs объект биш");
            }
            foreach (var prop in a.EnumerateObject())
            {
                if (!want.Contains(prop.Name))
                {
                    throw Bad("хүсээгүй аттрибут: " + prop.Name);
                }
                SetAttr(attrs, prop.Name, prop.Value);
                got.Add(prop.Name);
            }
        }
        var unavailable = new List<string>();
        if (c.TryGetProperty("unavailable", out var u))
        {
            if (u.ValueKind != JsonValueKind.Array)
            {
                throw Bad("unavailable массив биш");
            }
            foreach (var x in u.EnumerateArray())
            {
                var name = x.ValueKind == JsonValueKind.String ? x.GetString()! : null;
                if (name is null || !want.Contains(name) || got.Contains(name))
                {
                    throw Bad("unavailable буруу");
                }
                got.Add(name);
                unavailable.Add(name);
            }
        }
        if (got.Count != want.Count)
        {
            throw Bad("хүссэн аттрибутын хариу дутуу");
        }
        return new QrPresentation(sub!, attrs, unavailable, exp.SessionId!, iat, jws);
    }

    private static void SetAttr(QrAttrs a, string name, JsonElement v)
    {
        EidQrException Wrong() => Bad(name + "-ийн төрөл буруу");
        string NonEmpty() => v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : throw Wrong();
        switch (name)
        {
            case QrAttributes.AgeOver18:
            case QrAttributes.AgeOver21:
                if (v.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    throw Wrong();
                }
                if (name == QrAttributes.AgeOver18)
                {
                    a.AgeOver18 = v.GetBoolean();
                }
                else
                {
                    a.AgeOver21 = v.GetBoolean();
                }
                return;
            case QrAttributes.FullName:
                if (v.ValueKind != JsonValueKind.Object || Str(v, "surname") is not { } sn || Str(v, "givenName") is not { Length: > 0 } gn)
                {
                    throw Wrong();
                }
                a.FullName = new QrFullName(sn, gn);
                return;
            case QrAttributes.Phone:
                var p = NonEmpty();
                a.Phone = PhoneRe.IsMatch(p) ? p : throw Wrong();
                return;
            case QrAttributes.BirthDate:
                var d = NonEmpty();
                a.BirthDate = DateRe.IsMatch(d) && DateTime.TryParseExact(d, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)
                    ? d
                    : throw Wrong();
                return;
            case QrAttributes.CivilId:
                a.CivilId = NonEmpty();
                return;
        }
        throw Wrong();
    }
}

/// <summary>Аттрибутын каталог (CA гэрээ v1, 2026-10-23). RP-д аттрибут бүрийн <c>QR_ATTR:&lt;нэр&gt;</c> эрх хэрэгтэй.</summary>
public static class QrAttributes
{
    /// <summary>bool — 18 нас хүрсэн эсэх (төрсөн огноог задлахгүй).</summary>
    public const string AgeOver18 = "age_over_18";
    /// <summary>bool — 21 нас хүрсэн эсэх.</summary>
    public const string AgeOver21 = "age_over_21";
    /// <summary>{surname, givenName} — кирилл.</summary>
    public const string FullName = "full_name";
    /// <summary>E.164 утас.</summary>
    public const string Phone = "phone";
    /// <summary>YYYY-MM-DD (мэдрэмтгий).</summary>
    public const string BirthDate = "birth_date";
    /// <summary>Иргэний дугаар (мэдрэмтгий).</summary>
    public const string CivilId = "civil_id";

    /// <summary>Бүх аттрибут (баримтын дараалал).</summary>
    public static readonly IReadOnlyList<string> All = new[] { AgeOver18, AgeOver21, FullName, Phone, BirthDate, CivilId };
}

/// <summary>Алдааны кодууд (<see cref="EidQrException.Code"/>) — Go / TS SDK-тэй ижил.</summary>
public static class EidQrErrorCodes
{
    /// <summary>Скан хийсэн мөр eID «Миний QR» биш (клиент талын).</summary>
    public const string FormatInvalid = "QR_FORMAT_INVALID";
    /// <summary>404: токен танигдахгүй / хугацаа дууссан (120 с) / ашиглагдсан → шинэ QR гаргуул.</summary>
    public const string TokenInvalid = "QR_TOKEN_INVALID";
    /// <summary>Аттрибут хоосон / каталогид алга / давхардсан (клиент талын; CA руу явахгүй).</summary>
    public const string AttributesInvalid = "QR_ATTRIBUTES_INVALID";
    /// <summary>Presentation (JWS) шалгалтад унасан — хариунд ИТГЭХГҮЙ.</summary>
    public const string PresentationInvalid = "QR_PRESENTATION_INVALID";
    /// <summary>CA-ийн JWKS татагдсангүй (түр; дахин оролдож болно).</summary>
    public const string JwksUnavailable = "QR_JWKS_UNAVAILABLE";
    /// <summary>Session амжилтгүй (<see cref="EidQrException.EndResult"/>: USER_REFUSED, TIMEOUT г.м.).</summary>
    public const string SessionFailed = "SESSION_FAILED";
    /// <summary>RP-API-ийн бусад HTTP алдаа (серверийн code-гүй); <see cref="EidQrException.HttpStatus"/>-г үз.</summary>
    public const string HttpError = "HTTP_ERROR";
    /// <summary>Сүлжээ / timeout.</summary>
    public const string NetworkError = "NETWORK_ERROR";
}

/// <summary>«Миний QR»-ийн алдаа. <see cref="Code"/> тогтвортой — үүгээр салаална; <see cref="Exception.Message"/> зөвхөн лог.</summary>
public sealed class EidQrException : Exception
{
    /// <summary>Тогтвортой код: <see cref="EidQrErrorCodes"/>-ийн нэг, эсвэл серверийн <c>code</c> (ж: REQUEST_INVALID).</summary>
    public string Code { get; }

    /// <summary>RP-API-ийн HTTP статус (серверийн алдаанд), бусад үед null.</summary>
    public int? HttpStatus { get; init; }

    /// <summary><c>SESSION_FAILED</c>-д session-ий endResult (USER_REFUSED, TIMEOUT …).</summary>
    public string? EndResult { get; init; }

    /// <summary>Шинэ алдаа.</summary>
    public EidQrException(string code, string reason, Exception? inner = null) : base(code + ": " + reason, inner)
    {
        Code = code;
    }
}

/// <summary><see cref="EidQrClient.StartAsync"/>-ийн оролт.</summary>
public sealed class QrStartRequest
{
    /// <summary>Скан хийсэн агуулга (<c>EIDMN-QR1:&lt;token&gt;</c>) эсвэл <see cref="EidQr.Parse"/>-ийн токен.</summary>
    public required string Qr { get; init; }

    /// <summary>Хүсэх аттрибутууд (<see cref="QrAttributes"/>, ≥ 1, давхардалгүй).</summary>
    public required IReadOnlyList<string> Attributes { get; init; }

    /// <summary>RP-ийн nonce (сонголттой) — JWS-ийн <c>nonce</c>-д буцна; null бол rpChallenge.</summary>
    public string? Nonce { get; init; }
}

/// <summary>
/// <see cref="EidQrClient.StartAsync"/>-ийн хариу. <see cref="Vc"/>-г кассын дэлгэцэнд харуул. JSON-оор хадгалж
/// (stateless backend) <see cref="EidQrClient.ResultAsync"/>-д дамжуулна.
/// </summary>
public sealed class QrSession
{
    /// <summary>Session ID.</summary>
    [JsonPropertyName("sessionID")] public required string SessionId { get; init; }
    /// <summary>Баталгаажуулах код — иргэний утсанд ижил код.</summary>
    [JsonPropertyName("vc")] public string Vc { get; init; } = "";
    /// <summary>JWS-д хүлээгдэх nonce.</summary>
    [JsonPropertyName("nonce")] public required string Nonce { get; init; }
    /// <summary>Хүссэн аттрибутууд.</summary>
    [JsonPropertyName("attributes")] public required IReadOnlyList<string> Attributes { get; init; }
    /// <summary>CA-ийн session дуусах мөч (байвал).</summary>
    [JsonPropertyName("expiresAt")] public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>full_name аттрибут (кирилл).</summary>
public sealed record QrFullName(string Surname, string GivenName);

/// <summary>Баталгаажсан аттрибутууд — хүсээгүй / байхгүй нь null.</summary>
public sealed class QrAttrs
{
    /// <summary>age_over_18.</summary>
    public bool? AgeOver18 { get; internal set; }
    /// <summary>age_over_21.</summary>
    public bool? AgeOver21 { get; internal set; }
    /// <summary>full_name.</summary>
    public QrFullName? FullName { get; internal set; }
    /// <summary>phone (E.164).</summary>
    public string? Phone { get; internal set; }
    /// <summary>birth_date (YYYY-MM-DD).</summary>
    public string? BirthDate { get; internal set; }
    /// <summary>civil_id.</summary>
    public string? CivilId { get; internal set; }
}

/// <summary>Шалгагдсан presentation.</summary>
/// <param name="Sub">Энэ RP-д зориулсан тогтмол pairwise id (иргэний дугаар биш).</param>
/// <param name="Attrs">Хүссэн, байгаа аттрибутууд.</param>
/// <param name="Unavailable">Хүссэн боловч бүртгэлд байхгүй (алдаа биш).</param>
/// <param name="SessionId">Session ID.</param>
/// <param name="IssuedAt">iat.</param>
/// <param name="Jws">Түүхий compact JWS (аудит).</param>
public sealed record QrPresentation(string Sub, QrAttrs Attrs, IReadOnlyList<string> Unavailable, string SessionId, DateTimeOffset IssuedAt, string Jws);

/// <summary><see cref="EidQr.VerifyPresentation"/>-ийн хүлээлт.</summary>
public sealed class QrExpect
{
    /// <summary>null = <see cref="EidQr.DefaultIssuer"/>.</summary>
    public string? Issuer { get; init; }
    /// <summary>RP UUID.</summary>
    public required string Audience { get; init; }
    /// <summary><see cref="QrSession.SessionId"/>.</summary>
    public required string SessionId { get; init; }
    /// <summary><see cref="QrSession.Nonce"/>.</summary>
    public required string Nonce { get; init; }
    /// <summary><see cref="QrSession.Attributes"/>.</summary>
    public required IReadOnlyList<string> Attributes { get; init; }
    /// <summary>null = одоо.</summary>
    public DateTimeOffset? Now { get; init; }
    /// <summary>null = <see cref="EidQr.DefaultMaxAge"/>.</summary>
    public TimeSpan? MaxAge { get; init; }
}

/// <summary>EC P-256 түлхүүрүүд (JWKS).</summary>
internal sealed class Jwks
{
    private sealed record Jwk(string? Kid, string? Kty, string? Crv, string? X, string? Y, string? Alg, string? Use);

    private readonly List<Jwk> _keys;

    private Jwks(List<Jwk> keys) => _keys = keys;

    public int Count => _keys.Count;

    public static Jwks Parse(string json)
    {
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object || !d.RootElement.TryGetProperty("keys", out var ks) || ks.ValueKind != JsonValueKind.Array)
            {
                throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "JWKS-д keys алга");
            }
            return new Jwks(ks.EnumerateArray()
                .Where(k => k.ValueKind == JsonValueKind.Object)
                .Select(k => new Jwk(Get(k, "kid"), Get(k, "kty"), Get(k, "crv"), Get(k, "x"), Get(k, "y"), Get(k, "alg"), Get(k, "use")))
                .ToList());
        }
        catch (JsonException e)
        {
            throw new EidQrException(EidQrErrorCodes.JwksUnavailable, "JWKS JSON биш", e);
        }
    }

    /// <summary>kid-тэй ES256 түлхүүр; алга бол null; тохирохгүй бол QR_PRESENTATION_INVALID.</summary>
    public ECDsa? Find(string kid)
    {
        var j = _keys.FirstOrDefault(k => k.Kid == kid);
        if (j is null)
        {
            return null;
        }
        if (j.Kty != "EC" || j.Crv != "P-256" || (j.Alg is not null && j.Alg != "ES256") || (j.Use is not null && j.Use != "sig"))
        {
            throw EidQr.Bad("kid " + kid + " нь ES256 P-256 түлхүүр биш");
        }
        var x = EidQr.B64Url(j.X ?? "");
        var y = EidQr.B64Url(j.Y ?? "");
        if (x.Length != 32 || y.Length != 32)
        {
            throw EidQr.Bad("kid " + kid + ": x/y буруу");
        }
        try
        {
            return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
        }
        catch (CryptographicException)
        {
            throw EidQr.Bad("kid " + kid + ": цэг муруй дээр алга");
        }
    }

    private static string? Get(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
