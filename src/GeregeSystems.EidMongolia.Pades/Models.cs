using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary><see cref="EidPades.Prepare"/>-ийн сонголт (Go <c>pades.PrepareOptions</c>-тэй 1:1).</summary>
public sealed record PrepareOptions
{
    /// <summary>Иргэний SIGN гэрчилгээний DER (signingCertificateV2-д). Заавал.</summary>
    public byte[] SignerCert { get; init; } = Array.Empty<byte>();

    /// <summary>Олгогч гинж DER (04, 03, 02). <c>null</c> = шигтгэсэн eID гинжээс SignerCert-ийн олгогчоор бүтээнэ.</summary>
    public IReadOnlyList<byte[]>? Chain { get; init; }

    /// <summary>PDF <c>/Name</c>. <c>null</c>/хоосон = гэрчилгээний GIVENNAME SURNAME (эсвэл CN).</summary>
    public string? SignerName { get; init; }

    /// <summary>PDF <c>/Reason</c> (≤ 127 UTF-16 нэгж, урт бол бичигдэхгүй).</summary>
    public string? Reason { get; init; }

    /// <summary>Байгууллагын нэрийн өмнөөс: CA-ийн representation хариуны <c>claimedRole</c> (signer-attributes-v2, ≤ 900 тэмдэгт).</summary>
    public string? ClaimedRole { get; init; }

    /// <summary>PDF <c>/M</c>. <c>null</c> = одоо. Үргэлж +08:00 бүсээр бичигдэнэ.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Баримтын UUID (жижиг үсэг). <c>null</c> = шинэ баримтад үүсгэнэ; гарын үсэгтэй баримтад хуудаснаас уншина.</summary>
    public string? DocId { get; init; }

    /// <summary>Баталгаажуулалтын (QR) хуудас нэмэх — зөвхөн гарын үсэггүй баримтад (эхний eID гарын үсэг).</summary>
    public bool VerifyPage { get; init; }

    /// <summary>Хуудсанд харуулах файлын нэр (<see cref="VerifyPage"/> үед заавал, ≤ 120 тэмдэгт).</summary>
    public string? FileName { get; init; }

    /// <summary>Хуудасны хэл: <c>mn</c> | <c>en</c>.</summary>
    public string? Lang { get; init; }
}

/// <summary><see cref="EidPades.CompleteAsync"/>-ийн сонголт.</summary>
public sealed record CompleteOptions
{
    /// <summary>RFC 3161 TSA. <c>null</c> = <see cref="EidPades.DefaultTsaUrl"/>.</summary>
    public string? TsaUrl { get; init; }

    /// <summary>Итгэлийн тулгуур DER (TSA гинж, LTV). <c>null</c> = Mongolian National Root CA.</summary>
    public IReadOnlyList<byte[]>? Roots { get; init; }

    /// <summary>TSA/OCSP/CRL-ийн HTTP (proxy, sandbox). <c>null</c> = timeout 10 с, redirect дагахгүй.</summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Цаг ба хүлээлт. <c>null</c> = <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>Тест: TSA nonce-ийн 8 байт (golden). Production-д криптограф санамсаргүй.</summary>
    internal Func<byte[]>? NonceSource { get; init; }

    /// <summary>Тест: OCSP хүлээлтийг орлох.</summary>
    internal Func<TimeSpan, CancellationToken, Task>? Sleep { get; init; }
}

/// <summary><see cref="EidPades.Prepare"/>-ийн үр дүн.</summary>
public sealed record PreparedDocument
{
    /// <summary>SHA-256(signedAttrs) — утас/токены зурах 32 байт.</summary>
    public byte[] Dtbs { get; init; } = Array.Empty<byte>();

    /// <summary>messageDigest = SHA-256(ByteRange).</summary>
    public byte[] Digest { get; init; } = Array.Empty<byte>();

    /// <summary>Баримтын UUID.</summary>
    public string DocId { get; init; } = "";

    /// <summary>Тунгалаг төлөв (Go reference-тэй ижил формат) — хүлээх хооронд хадгалж болно.</summary>
    public byte[] State { get; init; } = Array.Empty<byte>();
}

/// <summary>
/// <see cref="EidPades.CompleteAsync"/>-ийн үр дүн: гарын үсэгтэй PDF ба RP backend-ийн <c>RegisterSignature</c>
/// (CA <c>POST /pdf/signatures</c>)-д хэрэгтэй мета (hash нь жижиг hex). PDF өөрөө сервер рүү явахгүй.
/// </summary>
public sealed record Completed
{
    /// <summary>Гарын үсэгтэй PDF (PAdES-BASELINE-LT, DSS revision-тэй).</summary>
    public byte[] Pdf { get; init; } = Array.Empty<byte>();

    /// <summary>Баримтын UUID.</summary>
    public string DocId { get; init; } = "";

    /// <summary>/Contents-д суусан CMS (DER).</summary>
    public byte[] Cms { get; init; } = Array.Empty<byte>();

    /// <summary>SHA-256(гаралт).</summary>
    public string OutSha256 { get; init; } = "";

    /// <summary>SHA-256(Prepare-ийн оролт).</summary>
    public string InSha256 { get; init; } = "";

    /// <summary>Энэ гарын үсгийн өмнө баталгаажуулалтын хуудас нэмэгдсэн.</summary>
    public bool HasPage { get; init; }

    /// <summary>SHA-256(хуудас нэмсний дараах баримт); <see cref="HasPage"/> үед.</summary>
    public string PageSha256 { get; init; } = "";

    /// <summary>Гарын үсэг зурагчийн гэрчилгээ (DER).</summary>
    public byte[] SignerCert { get; init; } = Array.Empty<byte>();

    /// <summary>Энэ гарын үсгийн дугаар (1…16).</summary>
    public int RevIndex { get; init; }

    /// <summary>SHA-256(гарын үсгийн revision, DSS-ээс өмнө).</summary>
    public string SigRevSha256 { get; init; } = "";

    /// <summary>Өмнөх гарын үсгүүдийн CMS DER-ийн SHA-256 (баримтын дарааллаар).</summary>
    public IReadOnlyList<string> PriorCmsSha256 { get; init; } = Array.Empty<string>();
}
