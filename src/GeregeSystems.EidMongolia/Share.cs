using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GeregeSystems.EidMongolia;

// Гарын үсэгтэй файлыг имэйлээр дамжуулах — POST /share (CA docs/SHARE_EMAIL.md; Go share.go, TS share.ts). CA файлыг
// хадгалахгүй: eID-ийн хүчинтэй гарын үсэгтэй эсэхийг шалгаад имэйлээр дамжуулж хаяна. SIGN эрх. Имэйл/шалгагч
// тохируулаагүй үед 503 MAIL_UNAVAILABLE / VALIDATOR_UNAVAILABLE — ShareInfoAsync().Enabled-ээр урьдчилан шалга.

/// <summary><see cref="EidClient.ShareAsync"/>-ийн оролт. Хязгаар: discovery-ийн share блок (<see cref="EidClient.ShareInfoAsync"/>).</summary>
public sealed record ShareRequest
{
    /// <summary>Гарын үсэгтэй файл (одоогоор зөвхөн PDF), ≤ 3 080 192 байт.</summary>
    public byte[] File { get; init; } = Array.Empty<byte>();

    /// <summary>Хавсралтын нэр (≤ 120 тэмдэгт; .pdf); null / "" = "document.pdf".</summary>
    public string? Filename { get; init; }

    /// <summary>Хүлээн авагч, 1–5 (хүн бүрт тусдаа имэйл). Давхардвал 400 RECIPIENT_DUPLICATE.</summary>
    public IReadOnlyList<string> To { get; init; } = Array.Empty<string>();

    /// <summary>Имэйлийн гарчиг (≤ 150); CA «‹RP нэр›: …» угтвар тавина.</summary>
    public string? Subject { get; init; }

    /// <summary>Илгээгчийн тэмдэглэл (≤ 1000).</summary>
    public string? Message { get; init; }

    /// <summary>Имэйлийн хэл: "mn" (анхдагч, null) | "en".</summary>
    public string? Lang { get; init; }
}

/// <summary><c>POST /share</c>-ийн 200 хариу.</summary>
public sealed record ShareResult
{
    /// <summary>Илгээсэн имэйлийн тоо.</summary>
    [JsonPropertyName("sent")]
    public int Sent { get; init; }

    /// <summary>Файлын SHA-256 (hex).</summary>
    [JsonPropertyName("sha256")]
    public string Sha256 { get; init; } = "";

    /// <summary>Хүчинтэй eID гарын үсгийн тоо.</summary>
    [JsonPropertyName("signatures")]
    public int Signatures { get; init; }

    /// <summary>CA-д бүртгэлтэй бол баримтын ID; үгүй бол null.</summary>
    [JsonPropertyName("docID")]
    public string? DocId { get; init; }

    /// <summary>Серверийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary><c>POST /share</c>-ийн алдааны кодууд (<see cref="EidException.Code"/>; Go <c>ShareErrorCodes</c>).</summary>
public static class ShareErrorCodes
{
    /// <summary>400.</summary>
    public const string FileEmpty = "FILE_EMPTY";
    /// <summary>400.</summary>
    public const string RecipientRequired = "RECIPIENT_REQUIRED";
    /// <summary>400.</summary>
    public const string TooManyRecipients = "TOO_MANY_RECIPIENTS";
    /// <summary>400.</summary>
    public const string RecipientInvalid = "RECIPIENT_INVALID";
    /// <summary>400.</summary>
    public const string RecipientDuplicate = "RECIPIENT_DUPLICATE";
    /// <summary>413.</summary>
    public const string FileTooLarge = "FILE_TOO_LARGE";
    /// <summary>415.</summary>
    public const string FileTypeNotSupported = "FILE_TYPE_NOT_SUPPORTED";
    /// <summary>422 + <see cref="EidShareException.Reason"/>.</summary>
    public const string FileNotSigned = "FILE_NOT_SIGNED";
    /// <summary>502 + Sent/Failed/Recipients.</summary>
    public const string MailFailed = "MAIL_FAILED";
    /// <summary>503 (хуучин CA).</summary>
    public const string ShareDisabled = "SHARE_DISABLED";
    /// <summary>503.</summary>
    public const string MailUnavailable = "MAIL_UNAVAILABLE";
    /// <summary>503 (+ Retry-After).</summary>
    public const string ValidatorUnavailable = "VALIDATOR_UNAVAILABLE";
    /// <summary>503 + Retry-After.</summary>
    public const string ValidatorBusy = "VALIDATOR_BUSY";

    /// <summary>Бүх код (Go-той ижил дараалал; REQUEST_INVALID, RATE_LIMITED орно).</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        EidErrorCodes.RequestInvalid, FileEmpty, RecipientRequired, TooManyRecipients, RecipientInvalid,
        RecipientDuplicate, FileTooLarge, FileTypeNotSupported, FileNotSigned, EidErrorCodes.RateLimited,
        MailFailed, ShareDisabled, MailUnavailable, ValidatorUnavailable, ValidatorBusy,
    };
}

/// <summary>422 FILE_NOT_SIGNED-ийн шалтгаан (<see cref="EidShareException.Reason"/>).</summary>
public static class ShareReasons
{
    /// <summary>Файлд цахим гарын үсэг алга.</summary>
    public const string NoSignature = "no_signature";
    /// <summary>Эвдэрсэн / агуулга өөрчлөгдсөн / цуцлагдсан / хэт олон.</summary>
    public const string Invalid = "invalid";
    /// <summary>eID-ийн итгэмжлэгдсэн гинжид холбогдохгүй.</summary>
    public const string Untrusted = "untrusted";
}

/// <summary>Хүлээн авагчийн төлөв (<see cref="EidShareException.Recipients"/>).</summary>
public static class ShareRecipientStatuses
{
    /// <summary>Илгээсэн.</summary>
    public const string Sent = "sent";
    /// <summary>Илгээгдээгүй — зөвхөн эдгээрийг дахин илгээ.</summary>
    public const string Failed = "failed";
}

/// <summary>
/// <c>POST /share</c>-ийн CA алдаа (401/403-аас бусад 4xx/5xx; Go <c>*ShareError</c>). <see cref="EidApiException"/>-ийн
/// дэд анги (Status, Code, RetryAfter, Retryable); <see cref="Exception.InnerException"/> — SDK-ийн анхны төрөлжсөн алдаа
/// (ж: <see cref="EidRequestInvalidException"/>). JSON биш хариу (proxy) бол Code null.
/// </summary>
public sealed class EidShareException : EidApiException
{
    internal EidShareException(EidApiException e)
        : base(e.Status ?? 0, e.Body, e.Code, e.Service, e.RetryAfter, e.Headers, Format(e), e)
    {
        try
        {
            using var d = JsonDocument.Parse(e.Body);
            var o = d.RootElement;
            if (o.ValueKind == JsonValueKind.Object)
            {
                Reason = o.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String ? r.GetString() : null;
                Sent = o.TryGetProperty("sent", out var s) && s.TryGetInt32(out var sn) ? sn : 0;
                Failed = o.TryGetProperty("failed", out var f) && f.TryGetInt32(out var fn) ? fn : 0;
                if (o.TryGetProperty("recipients", out var rc) && rc.ValueKind == JsonValueKind.Array)
                {
                    Recipients = rc.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : "").ToList();
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            // JSON биш (proxy) — дэлгэрэнгүйгүй
        }
    }

    private static string Format(EidApiException e) =>
        e.Code is null
            ? "eid: share " + e.Status
            : "eid: share " + e.Status + " " + e.Code + (ReasonOf(e.Body) is { } r ? " (" + r + ")" : "");

    private static string? ReasonOf(string body)
    {
        try
        {
            using var d = JsonDocument.Parse(body);
            return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("reason", out var r) &&
                r.ValueKind == JsonValueKind.String && r.GetString() is { Length: > 0 } s
                ? s
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>422 FILE_NOT_SIGNED: <see cref="ShareReasons"/>; бусад үед null.</summary>
    public string? Reason { get; }

    /// <summary>502 MAIL_FAILED: амжилттай тоо.</summary>
    public int Sent { get; }

    /// <summary>502 MAIL_FAILED: амжилтгүй тоо.</summary>
    public int Failed { get; }

    /// <summary>
    /// 502 MAIL_FAILED: To-гийн дарааллаар <see cref="ShareRecipientStatuses"/>. Зөвхөн failed-ийг дахин илгээ; алга бол null.
    /// </summary>
    public IReadOnlyList<string>? Recipients { get; }
}

/// <summary>Discovery (<c>/.well-known/eid</c>)-ийн share блок.</summary>
public sealed record ShareInfo
{
    /// <summary>Имэйлийн үйлчилгээ ба шалгагч тохируулагдсан эсэх.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    /// <summary>Бүтэн URL.</summary>
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; init; } = "";

    /// <summary>Дэмжигдэх формат.</summary>
    [JsonPropertyName("formats")]
    public IReadOnlyList<ShareFormat> Formats { get; init; } = Array.Empty<ShareFormat>();

    /// <summary>Имэйлийн хэл (mn, en).</summary>
    [JsonPropertyName("languages")]
    public IReadOnlyList<string> Languages { get; init; } = Array.Empty<string>();

    /// <summary>Файлын дээд хэмжээ.</summary>
    [JsonPropertyName("maxFileBytes")]
    public int MaxFileBytes { get; init; }

    /// <summary>Нэрийн дээд урт.</summary>
    [JsonPropertyName("maxFilenameChars")]
    public int MaxFilenameChars { get; init; }

    /// <summary>Тэмдэглэлийн дээд урт.</summary>
    [JsonPropertyName("maxMessageChars")]
    public int MaxMessageChars { get; init; }

    /// <summary>Хүлээн авагчийн дээд тоо.</summary>
    [JsonPropertyName("maxRecipients")]
    public int MaxRecipients { get; init; }

    /// <summary>Гарчгийн дээд урт.</summary>
    [JsonPropertyName("maxSubjectChars")]
    public int MaxSubjectChars { get; init; }

    /// <summary>Шаардлагатай RP эрх (SIGN).</summary>
    [JsonPropertyName("permission")]
    public string Permission { get; init; } = "";

    /// <summary>Квот.</summary>
    [JsonPropertyName("quota")]
    public ShareQuota Quota { get; init; } = new();

    /// <summary>Хүчинтэй гарын үсэг шаардана.</summary>
    [JsonPropertyName("requiresValidSignature")]
    public bool RequiresValidSignature { get; init; }

    /// <summary>Блокийн түүхий JSON.</summary>
    [JsonIgnore]
    public JsonElement? Raw { get; init; }
}

/// <summary>Дэмжигдэх формат (одоогоор pdf).</summary>
public sealed record ShareFormat
{
    /// <summary>Нэр.</summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    /// <summary>Өргөтгөл (.pdf).</summary>
    [JsonPropertyName("extension")]
    public string Extension { get; init; } = "";

    /// <summary>MIME.</summary>
    [JsonPropertyName("mime")]
    public string Mime { get; init; } = "";
}

/// <summary>RP тутам цаг/өдөр (хүсэлт), хүлээн авагч тутам өдөр (имэйл).</summary>
public sealed record ShareQuota
{
    /// <summary>RP-д цагт.</summary>
    [JsonPropertyName("perRPHour")]
    public int PerRpHour { get; init; }

    /// <summary>RP-д өдөрт.</summary>
    [JsonPropertyName("perRPDay")]
    public int PerRpDay { get; init; }

    /// <summary>Хүлээн авагчид өдөрт.</summary>
    [JsonPropertyName("perRecipientDay")]
    public int PerRecipientDay { get; init; }
}

/// <summary>multipart/form-data бие (Go <c>shareBody</c>, mime/multipart.Writer-ийн байт хэлбэр).</summary>
internal static class ShareWire
{
    /// <summary>
    /// <c>POST /share</c>-ийн multipart талбарууд (CA parseShareRequest; үл мэдэгдэх талбар 400). Гэрээний тест
    /// discovery-ийн endpoints.share-тэй тулгана.
    /// </summary>
    public static readonly string[] FormFields = { "file", "filename", "to", "subject", "message", "lang" };

    /// <summary>
    /// Дараалал: to (бүгд), subject, message, lang, filename (хоосныг алгасна), дараа нь file. Файлын хэсгийн нэр зөвхөн
    /// printable ASCII (Content-Disposition); Unicode нэрийг filename талбараар (CA тэр талбарыг давуу үзнэ).
    /// </summary>
    public static (byte[] Body, string ContentType) Build(ShareRequest r)
    {
        // Go multipart.Writer randomBoundary: 30 санамсаргүй байт, hex.
        var boundary = Convert.ToHexString(RandomNumberGenerator.GetBytes(30)).ToLowerInvariant();
        using var ms = new MemoryStream();
        var first = true;

        void Part(string header)
        {
            Write(ms, (first ? "--" : "\r\n--") + boundary + "\r\n" + header + "\r\n\r\n");
            first = false;
        }

        void Field(string name, string value)
        {
            Part("Content-Disposition: form-data; name=\"" + Escape(name) + "\"");
            Write(ms, value);
        }

        foreach (var a in r.To ?? Array.Empty<string>())
        {
            Field("to", a ?? "");
        }
        foreach (var (k, v) in new[] { ("subject", r.Subject), ("message", r.Message), ("lang", r.Lang), ("filename", r.Filename) })
        {
            if (!string.IsNullOrEmpty(v))
            {
                Field(k, v);
            }
        }
        var partName = !string.IsNullOrEmpty(r.Filename) && IsPrintableAscii(r.Filename) ? r.Filename : "document.pdf";
        // Go CreatePart: header-ийн түлхүүр эрэмбэлэгдсэн (Content-Disposition, Content-Type).
        Part("Content-Disposition: form-data; name=\"file\"; filename=\"" + Escape(partName) + "\"\r\nContent-Type: application/pdf");
        ms.Write(r.File ?? Array.Empty<byte>());
        Write(ms, "\r\n--" + boundary + "--\r\n");
        return (ms.ToArray(), "multipart/form-data; boundary=" + boundary);
    }

    private static void Write(Stream s, string v) => s.Write(Encoding.UTF8.GetBytes(v));

    /// <summary>Go quoteEscaper: \ → \\, " → \".</summary>
    private static string Escape(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    private static bool IsPrintableAscii(string s)
    {
        foreach (var c in s)
        {
            if (c < 0x20 || c > 0x7e)
            {
                return false;
            }
        }
        return true;
    }
}
