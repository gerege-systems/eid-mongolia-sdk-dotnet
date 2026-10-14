using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GeregeSystems.EidMongolia.Pades
{
    /// <summary><c>Prepare</c>-ийн сонголт (Go <c>pades.PrepareOptions</c>-тэй 1:1; JSON түлхүүр lowerCamelCase).</summary>
    public sealed record PrepareOptions
    {
        /// <summary>Иргэний SIGN гэрчилгээний DER (signingCertificateV2-д). Заавал.</summary>
        [JsonPropertyName("signerCert")] public byte[] SignerCert { get; init; } = Array.Empty<byte>();

        /// <summary>Олгогчийн гинж DER (04, 03, 02). <c>null</c> = цөмд суулгасан eID гинж.</summary>
        [JsonPropertyName("chain")] public IReadOnlyList<byte[]>? Chain { get; init; }

        /// <summary>PDF <c>/Name</c>.</summary>
        [JsonPropertyName("signerName")] public string? SignerName { get; init; }

        /// <summary>PDF <c>/Reason</c> (≤127 UTF-16 нэгж, урт бол орхигдоно).</summary>
        [JsonPropertyName("reason")] public string? Reason { get; init; }

        /// <summary>onBehalfOf — CA баталсан албан тушаал (signedAttrs-д орно).</summary>
        [JsonPropertyName("claimedRole")] public string? ClaimedRole { get; init; }

        /// <summary>PDF <c>/M</c>. <c>null</c> = одоо.</summary>
        [JsonPropertyName("signingTime")] public DateTimeOffset? SigningTime { get; init; }

        /// <summary>Шалгах хуудас/QR-ийн UUID. <c>null</c> = цөм үүсгэнэ.</summary>
        [JsonPropertyName("docId")] public string? DocId { get; init; }

        /// <summary>Шалгах (QR) хуудас нэмэх — зөвхөн эхний eID гарын үсэгт.</summary>
        [JsonPropertyName("verifyPage")] public bool VerifyPage { get; init; }

        /// <summary>Шалгах хуудсанд харуулах файлын нэр (<see cref="VerifyPage"/> үед заавал, ≤120 тэмдэгт).</summary>
        [JsonPropertyName("fileName")] public string? FileName { get; init; }

        /// <summary>Шалгах хуудасны хэл: <c>mn</c> | <c>en</c>.</summary>
        [JsonPropertyName("lang")] public string? Lang { get; init; }

        /// <summary>Итгэлийн тулгуур DER (өмнөх гарын үсгийг шалгахад). <c>null</c> = Mongolian National Root CA.</summary>
        [JsonPropertyName("roots")] public IReadOnlyList<byte[]>? Roots { get; init; }
    }

    /// <summary><c>Complete</c>-ийн сонголт.</summary>
    public sealed record CompleteOptions
    {
        /// <summary>RFC 3161 TSA. <c>null</c> = цөмийн анхдагч (https://tsa.timeserver.mn/).</summary>
        [JsonPropertyName("tsaUrl")] public string? TsaUrl { get; init; }

        /// <summary>Итгэлийн тулгуур DER. <c>null</c> = Mongolian National Root CA.</summary>
        [JsonPropertyName("roots")] public IReadOnlyList<byte[]>? Roots { get; init; }
    }

    /// <summary><c>Verify</c>-ийн сонголт.</summary>
    public sealed record VerifyOptions
    {
        /// <summary>Итгэлийн тулгуур DER. <c>null</c> = Mongolian National Root CA.</summary>
        [JsonPropertyName("roots")] public IReadOnlyList<byte[]>? Roots { get; init; }

        /// <summary>Нэмэлт завсрын CA DER.</summary>
        [JsonPropertyName("intermediates")] public IReadOnlyList<byte[]>? Intermediates { get; init; }

        /// <summary>Нэмэлт eID олгогч CA DER.</summary>
        [JsonPropertyName("issuers")] public IReadOnlyList<byte[]>? Issuers { get; init; }

        /// <summary>Шалгах мөч. <c>null</c> = одоо.</summary>
        [JsonPropertyName("time")] public DateTimeOffset? Time { get; init; }
    }

    /// <summary><c>Prepare</c>-ийн үр дүн. <see cref="State"/>-г хадгалаад (утас/токен хүлээх үед) <c>CompleteAsync</c>-д өгнө.</summary>
    public sealed record PreparedDocument
    {
        /// <summary>SHA-256(signedAttrs) — утас/токен зурах 32 байт.</summary>
        [JsonPropertyName("dtbs")] public byte[] Dtbs { get; init; } = Array.Empty<byte>();

        /// <summary>messageDigest = SHA-256(ByteRange).</summary>
        [JsonPropertyName("digest")] public byte[] Digest { get; init; } = Array.Empty<byte>();

        /// <summary>Тунгалаг бус төлөв (serializable).</summary>
        [JsonPropertyName("state")] public byte[] State { get; init; } = Array.Empty<byte>();

        /// <summary>Баримтын UUID.</summary>
        [JsonPropertyName("docId")] public string DocId { get; init; } = "";
    }

    /// <summary>
    /// <c>CompleteAsync</c>-ийн үр дүн. <see cref="Cms"/>, <see cref="OutSha256"/>, <see cref="InSha256"/>,
    /// <see cref="HasPage"/>, <see cref="PageSha256"/> нь RP backend-ийн <c>RegisterSignature</c>
    /// (CA <c>POST /pdf/signatures</c>)-д шууд очно — PDF өөрөө явахгүй.
    /// </summary>
    public sealed record Completed
    {
        /// <summary>Гарын үсэгтэй PDF (PAdES B-LTA хүртэл, DSS-тэй).</summary>
        [JsonIgnore] public byte[] Pdf { get; init; } = Array.Empty<byte>();

        /// <summary>Суулгасан CMS (DER).</summary>
        [JsonPropertyName("cms")] public byte[] Cms { get; init; } = Array.Empty<byte>();

        /// <summary>Баримтын UUID.</summary>
        [JsonPropertyName("docId")] public string DocId { get; init; } = "";

        /// <summary>SHA-256(гаралтын PDF), hex.</summary>
        [JsonPropertyName("outSha256")] public string OutSha256 { get; init; } = "";

        /// <summary>SHA-256(оролтын PDF), hex.</summary>
        [JsonPropertyName("inSha256")] public string InSha256 { get; init; } = "";

        /// <summary>Шалгах (QR) хуудас нэмэгдсэн эсэх.</summary>
        [JsonPropertyName("hasPage")] public bool HasPage { get; init; }

        /// <summary>SHA-256(хуудас нэмсний дараах PDF), hex; хуудасгүй бол хоосон.</summary>
        [JsonPropertyName("pageSha256")] public string PageSha256 { get; init; } = "";

        /// <summary>Энэ гарын үсгийн дугаар (1…16).</summary>
        [JsonPropertyName("revIndex")] public int RevIndex { get; init; }

        /// <summary>Гарын үсгийн revision-ийн (DSS-ээс өмнөх) SHA-256, hex.</summary>
        [JsonPropertyName("sigRevSha256")] public string SigRevSha256 { get; init; } = "";

        /// <summary>Өмнөх гарын үсгүүдийн CMS DER-ийн SHA-256 (баримтын дарааллаар).</summary>
        [JsonPropertyName("priorCmsSha256")] public IReadOnlyList<string> PriorCmsSha256 { get; init; } = Array.Empty<string>();

        /// <summary>Гарын үсэг зурагчийн гэрчилгээ (DER).</summary>
        [JsonPropertyName("signerCert")] public byte[] SignerCert { get; init; } = Array.Empty<byte>();
    }

    /// <summary>Шалгалтын тайлан. Цөмийн JSON-г бүтнээр нь <see cref="Json"/>-д хадгална (шинэ талбар алдагдахгүй).</summary>
    public sealed class VerifyReport
    {
        internal VerifyReport(string json)
        {
            Json = json;
            using var doc = JsonDocument.Parse(json);
            Root = doc.RootElement.Clone();
        }

        /// <summary>Цөмийн түүхий JSON.</summary>
        public string Json { get; }

        /// <summary>Задласан JSON (property-уудыг шууд уншина).</summary>
        public JsonElement Root { get; }

        /// <summary>Баримтын нэгдсэн дүгнэлт: <c>valid</c> | <c>invalid</c> | <c>indeterminate</c>.</summary>
        public string Indication =>
            Root.ValueKind == JsonValueKind.Object && Root.TryGetProperty("indication", out var i) && i.ValueKind == JsonValueKind.String
                ? i.GetString() ?? "" : "";

        /// <inheritdoc />
        public override string ToString() => Json;
    }
}
