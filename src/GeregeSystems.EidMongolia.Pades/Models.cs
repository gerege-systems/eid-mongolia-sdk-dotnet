using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    /// <summary>
    /// Where the verify page goes when it is added (<see cref="VerifyPage"/> on an unsigned document):
    /// <c>"last"</c> (default; also <c>null</c>/empty) or <c>"first"</c> (it becomes page 1). <see cref="Appearance.Page"/>,
    /// <see cref="EidPades.SuggestPlacement"/> and <see cref="Placement.Page"/> always count the pages of the input PDF
    /// as given — never the added page (PAGE_SPEC.md §8a, PLACEMENT_SPEC.md §1b). Other values → REQUEST_INVALID.
    /// </summary>
    public string? VerifyPagePosition { get; init; }

    /// <summary>Хуудсанд харуулах файлын нэр (<see cref="VerifyPage"/> үед заавал, ≤ 120 тэмдэгт).</summary>
    public string? FileName { get; init; }

    /// <summary>Хуудасны хэл: <c>mn</c> | <c>en</c>; <c>null</c>/хоосон = <c>mn</c>.</summary>
    public string? Lang { get; init; }

    /// <summary>Харагдах гарын үсэг (APPEARANCE_SPEC.md). <c>null</c> = үл харагдах (анхдагч, өмнөхтэй байт-ижил).</summary>
    public Appearance? Appearance { get; init; }
}

/// <summary>
/// Харагдах гарын үсгийн байршил (Go <c>pades.Appearance</c>, APPEARANCE_SPEC.md §1). Координат нь pt, тухайн хуудасны
/// CropBox (байхгүй бол MediaBox)-ийн /Rotate-ийн ДАРААХ (дэлгэцэнд харагдах) зүүн доод булангаас; X баруун тийш, Y дээш.
/// Утга бүр 0.01 pt хүртэл тойрогдоно. Өндөр ≥ 45 pt (QR), бичвэр багтахгүй бол REQUEST_INVALID.
/// </summary>
public sealed record Appearance
{
    /// <summary>
    /// Оролтын баримтын хуудас, 1-ээс (тодорхой дугаар — юуг ч алгасахгүй); 0 = оролтын eID verify хуудас БИШ сүүлийн
    /// хуудас: энэ Prepare-ийн нэмэх ба өмнөх revision-уудын нэмсэн verify хуудсууд тооцогдохгүй (PLACEMENT_SPEC.md §1a).
    /// </summary>
    public int Page { get; init; }

    /// <summary>Зүүн доод булангийн X (pt, 0…14400).</summary>
    public double X { get; init; }

    /// <summary>Зүүн доод булангийн Y (pt, 0…14400).</summary>
    public double Y { get; init; }

    /// <summary>Өргөн (pt, 0…14400).</summary>
    public double Width { get; init; }

    /// <summary>Өндөр (pt, 0…14400; ≥ 45).</summary>
    public double Height { get; init; }

    /// <summary><c>mn</c> | <c>en</c>; <c>null</c>/хоосон = <see cref="PrepareOptions.Lang"/> (тэр нь хоосон бол mn).</summary>
    public string? Lang { get; init; }

    /// <summary>
    /// Дүрслэлийг яг <see cref="Page"/>/<see cref="X"/>/<see cref="Y"/>/<see cref="Width"/>/<see cref="Height"/>-д зурна
    /// (иргэний өөрөө сонгосон байрлал) — агуулгаас зайлсхийж хэзээ ч шилжүүлэхгүй (JSON <c>exact</c>, PLACEMENT_SPEC.md §6a).
    /// Хуудсыг уншсаар байгаа тул <see cref="Placement.Status"/> нь <see cref="PlacementStatus.Requested"/>, доор нь агуулга
    /// байвал <see cref="PlacementStatus.Overlap"/>, уншиж чадаагүй бол <see cref="PlacementStatus.Unscanned"/>; хэзээ ч
    /// <see cref="PlacementStatus.Moved"/> биш. Тэгш өнцөгт хуудаснаас гарвал REQUEST_INVALID. <c>false</c> (анхдагч) =
    /// зөвхөн илүүд үзэх байрлал (өмнөхтэй байт-ижил).
    /// </summary>
    public bool Exact { get; init; }

    /// <summary>
    /// Иргэний гарын үсгийн зураг (CA: <c>GET /v3/person/etsi/{etsi}/signature-image</c>) — дүрслэлийн дотор зурна
    /// (APPEARANCE_SPEC.md §6). <c>null</c> = байхгүй (golden v9-тэй байт-ижил).
    /// </summary>
    public PdfImage? SignatureImage { get; init; }

    /// <summary>
    /// Байгууллагын тамганы зураг (CA: <c>representations[].stampImage</c>) — зөвхөн <see cref="PrepareOptions.ClaimedRole"/>
    /// (onBehalfOf)-той, эс бөгөөс REQUEST_INVALID. Дугуй тамга хайрцгийн баруун дээд буланд, дээш нь гарч зурагдана —
    /// <see cref="Width"/>/<see cref="Height"/> нь widget-ийн бүтэн тэгш өнцөгт (APPEARANCE_SPEC.md §6.3).
    /// <see cref="Width"/> = <see cref="Height"/> = 0 бол анхдагч хэмжээ: 220 × 64, гарын үсгийн зурагтай 220 × 110, тамгатай
    /// 240 × 147.5 (<see cref="EidPades.DefaultStampWidth"/>…).
    /// </summary>
    public PdfImage? StampImage { get; init; }
}

/// <summary>
/// CA-ийн өгөх «PDF зураг» (Go <c>pades.PDFImage</c>, APPEARANCE_SPEC.md §6.1): ганц бэхний өнгө + 8 битийн alpha. SDK
/// <see cref="Alpha"/>-г PDF-д байтаар нь (/SMask, /FlateDecode) бичнэ — runtime шахалт үгүй.
/// </summary>
public sealed record PdfImage
{
    /// <summary>Өргөн, px (1…1600).</summary>
    [JsonPropertyName("width")]
    public int Width { get; init; }

    /// <summary>Өндөр, px (1…1600).</summary>
    [JsonPropertyName("height")]
    public int Height { get; init; }

    /// <summary>[r, g, b], тус бүр 0…255.</summary>
    [JsonPropertyName("color")]
    public int[] Color { get; init; } = Array.Empty<int>();

    /// <summary>
    /// zlib stream (RFC 1950; stream-ийн ард илүү байт үгүй) — задлахад яг <see cref="Width"/>·<see cref="Height"/> байт,
    /// мөр дээрээс доош, PNG filter байтгүй; ≤ 300 KiB. JSON: base64.
    /// </summary>
    [JsonPropertyName("alpha")]
    public byte[] Alpha { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// CA-ийн хадгалсан PNG-ийн SHA-256 (64 жижиг hex) — PDF-д бичигдэхгүй, бүртгэлд очно
    /// (<see cref="Completed.Images"/> → <see cref="SignatureRegistration.Images"/>).
    /// </summary>
    [JsonPropertyName("sha256")]
    public string Sha256 { get; init; } = "";
}

/// <summary>
/// Дүрслэлд шигтгэсэн нэг зураг (Go <c>eid.PDFSignatureImage</c>): <see cref="Kind"/> = <c>signature</c> | <c>stamp</c>,
/// <see cref="Sha256"/> = CA-ийн хадгалсан PNG-ийн SHA-256.
/// </summary>
public sealed record PdfSignatureImage(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("sha256")] string Sha256)
{
    /// <summary>Иргэний гарын үсгийн зураг.</summary>
    public const string KindSignature = "signature";

    /// <summary>Байгууллагын тамганы зураг.</summary>
    public const string KindStamp = "stamp";
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

    /// <summary>
    /// Харагдах гарын үсгийн эцсийн байрлал ба шалтгаан (PLACEMENT_SPEC.md); <see cref="PrepareOptions.Appearance"/>-гүй бол
    /// <c>null</c>. <see cref="PlacementStatus.Overlap"/> / <see cref="PlacementStatus.Unscanned"/> үед хэрэглэгчид мэдэгдэх
    /// нь зүйтэй — гарын үсэг аль ч тохиолдолд хүчинтэй.
    /// </summary>
    public Placement? Placement { get; init; }
}

/// <summary>
/// Харагдах гарын үсгийн эцсийн тэгш өнцөгт (Go <c>pades.Placement</c>): <see cref="Appearance"/>-ийн координат (pt, харагдах
/// хуудасны зүүн доод булангаас) ба байрлалыг хэрхэн сонгосон. Дүрслэл хуудасны одоо байгаа агуулгаас (бичвэр, хүснэгт,
/// зураг, өмнөх гарын үсэг) зайлсхийнэ (PLACEMENT_SPEC.md).
/// </summary>
public sealed record Placement
{
    /// <summary>Дүрслэл байгаа хуудас (1-ээс).</summary>
    [JsonPropertyName("page")]
    public int Page { get; init; }

    /// <summary>Зүүн доод булангийн X (pt).</summary>
    [JsonPropertyName("x")]
    public double X { get; init; }

    /// <summary>Зүүн доод булангийн Y (pt).</summary>
    [JsonPropertyName("y")]
    public double Y { get; init; }

    /// <summary>Өргөн (pt).</summary>
    [JsonPropertyName("width")]
    public double Width { get; init; }

    /// <summary>Өндөр (pt).</summary>
    [JsonPropertyName("height")]
    public double Height { get; init; }

    /// <summary>Байрлалыг хэрхэн сонгосон (JSON: <c>requested</c> | <c>moved</c> | <c>overlap</c> | <c>unscanned</c>).</summary>
    [JsonPropertyName("status")]
    public PlacementStatus Status { get; init; }
}

/// <summary>
/// <see cref="EidPades.SuggestPlacement"/>-ийн үр дүн (Go <c>pades.Suggestion</c>, PLACEMENT_SPEC.md §6b), pt.
/// <see cref="Page"/>, <see cref="X"/>, <see cref="Y"/>, <see cref="Width"/>, <see cref="Height"/>, <see cref="Status"/> нь ижил
/// PDF ба <see cref="Appearance"/>-д <see cref="EidPades.Prepare"/>-ийн <see cref="PreparedDocument.Placement"/>-тэй тэнцүү
/// (гарын үсэггүй баримтад page 0 юуг ч алгасахгүй — §6b). Координат: харагдах хуудасны зүүн доод булангаас, X баруун, Y
/// дээш; дээд-зүүн эхтэй UI-д <c>top = PageHeight − Y − Height</c>.
/// </summary>
public sealed record PlacementSuggestion
{
    /// <summary>Шийдэгдсэн хуудас (1-ээс; page 0 → PLACEMENT_SPEC.md §1a).</summary>
    [JsonPropertyName("page")]
    public int Page { get; init; }

    /// <summary>Зүүн доод булангийн X (pt).</summary>
    [JsonPropertyName("x")]
    public double X { get; init; }

    /// <summary>Зүүн доод булангийн Y (pt).</summary>
    [JsonPropertyName("y")]
    public double Y { get; init; }

    /// <summary>Өргөн (pt).</summary>
    [JsonPropertyName("width")]
    public double Width { get; init; }

    /// <summary>Өндөр (pt).</summary>
    [JsonPropertyName("height")]
    public double Height { get; init; }

    /// <summary>Байрлалыг хэрхэн сонгосон (<see cref="Appearance.Exact"/> үед хэзээ ч <see cref="PlacementStatus.Moved"/> биш).</summary>
    [JsonPropertyName("status")]
    public PlacementStatus Status { get; init; }

    /// <summary><see cref="Page"/>-ийн харагдах өргөн (CropBox, байхгүй бол MediaBox, /Rotate-ийн дараа; pt).</summary>
    [JsonPropertyName("pageWidth")]
    public double PageWidth { get; init; }

    /// <summary><see cref="Page"/>-ийн харагдах өндөр (pt).</summary>
    [JsonPropertyName("pageHeight")]
    public double PageHeight { get; init; }

    /// <summary>Хуудасны тоо (/Pages модны дарааллаар).</summary>
    [JsonPropertyName("pageCount")]
    public int PageCount { get; init; }

    /// <summary>Хуудас бүрийн харагдах хэмжээ (индекс 0 = хуудас 1); {0, 0} = геометр нь уншигдахгүй хуудас.</summary>
    [JsonPropertyName("pages")]
    public IReadOnlyList<PageSize> Pages { get; init; } = Array.Empty<PageSize>();
}

/// <summary>Хуудасны харагдах хэмжээ, pt (<see cref="PlacementSuggestion.Pages"/>).</summary>
public sealed record PageSize
{
    /// <summary>Өргөн (pt).</summary>
    [JsonPropertyName("width")]
    public double Width { get; init; }

    /// <summary>Өндөр (pt).</summary>
    [JsonPropertyName("height")]
    public double Height { get; init; }
}

/// <summary><see cref="Placement.Status"/> — Go <c>Placement.Status</c>-ийн утгууд (JSON-д жижиг үсгээр).</summary>
[JsonConverter(typeof(PlacementStatusJsonConverter))]
public enum PlacementStatus
{
    /// <summary><c>requested</c> — хүссэн байрлал чөлөөтэй: <see cref="Appearance.X"/>/<see cref="Appearance.Y"/>-д зурсан.</summary>
    Requested,

    /// <summary><c>moved</c> — хүссэн байрлалд агуулга байсан тул эхний чөлөөт байрлал руу шилжсэн.</summary>
    Moved,

    /// <summary>
    /// <c>overlap</c> — чөлөөт байрлал алга (<see cref="Appearance.Exact"/>: хүссэн тэгш өнцөгтийн доор агуулга бий): хүссэн
    /// байрлалд агуулга дээгүүр зурсан.
    /// </summary>
    Overlap,

    /// <summary><c>unscanned</c> — хуудсыг хязгаарт багтааж уншиж чадсангүй (хэмжээ, шүүлтүүр): хүссэн байрлалд зурсан.</summary>
    Unscanned,
}

/// <summary><see cref="PlacementStatus"/> ↔ "requested" | "moved" | "overlap" | "unscanned".</summary>
internal sealed class PlacementStatusJsonConverter : JsonStringEnumConverter<PlacementStatus>
{
    public PlacementStatusJsonConverter() : base(JsonNamingPolicy.CamelCase, allowIntegerValues: false) { }
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

    /// <summary>Prepare-ийн цэвэрлэсэн баримтын нэр (CA бүртгэлийн <c>fileName</c>); өгөөгүй эсвэл буруу бол "".</summary>
    public string FileName { get; init; } = "";

    /// <summary>Энэ гарын үсгийн дугаар (1…16).</summary>
    public int RevIndex { get; init; }

    /// <summary>SHA-256(гарын үсгийн revision, DSS-ээс өмнө).</summary>
    public string SigRevSha256 { get; init; } = "";

    /// <summary>Өмнөх гарын үсгүүдийн CMS DER-ийн SHA-256 (баримтын дарааллаар).</summary>
    public IReadOnlyList<string> PriorCmsSha256 { get; init; } = Array.Empty<string>();

    /// <summary>
    /// CA-д ШУУД бүү илгээ — <see cref="PriorCmsSha256"/>-тэй хамт илгээвэл тоо нь revIndex − 1-ээс хэтэрч CA 400 буцаана;
    /// <see cref="EidPades.Registration"/>-ийг ашигла (зөвхөн <c>priorCmsSha256</c>, энэ нь <c>PriorSignatures</c>-д).
    /// Өмнөх гарын үсгүүдийн revision-ий SHA-256 (баримт[0 : ByteRange төгсгөл]) — <see cref="PriorCmsSha256"/>-тэй ижил
    /// дараалал; тус бүр нь тэр гарын үсгийн өөрийн <see cref="SigRevSha256"/>-тай тэнцүү.
    /// </summary>
    public IReadOnlyList<string> PriorRevisionSha256 { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Prepare-ийн <see cref="PrepareOptions.ClaimedRole"/> (signer-attributes-v2); байхгүй бол "". Байвал
    /// <see cref="EidPades.Registration"/>-д <see cref="RegistrationOptions.OnBehalfOf"/> заавал.
    /// </summary>
    public string ClaimedRole { get; init; } = "";

    /// <summary>
    /// Энэ гарын үсгийн дүрслэлд зурсан зургууд (<see cref="Appearance.SignatureImage"/>, дараа нь <see cref="Appearance.StampImage"/>);
    /// <see cref="EidPades.Registration"/> тэдгээрийг <c>images</c> болгон илгээнэ (APPEARANCE_SPEC.md §6.6). Зураггүй бол хоосон.
    /// </summary>
    public IReadOnlyList<PdfSignatureImage> Images { get; init; } = Array.Empty<PdfSignatureImage>();
}
