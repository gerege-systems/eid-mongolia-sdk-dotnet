using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary><see cref="PdfSignatureRegistration.Medium"/>-ийн утгууд.</summary>
public static class PdfMediums
{
    /// <summary>Утас (RAW_DIGEST_SIGNATURE session-тэй).</summary>
    public const string Phone = "phone";
    /// <summary>USB токен.</summary>
    public const string Token = "token";
}

/// <summary>
/// <c>POST /pdf/signatures</c>-ийн бие (Go <c>eid.PDFSignatureRegistration</c>, TS <c>RegisterSignatureInput</c>; CA
/// <c>dto.PDFSignatureRegisterRequest</c>-тэй ЯГ ижил — CA үл мэдэгдэх талбарыг 400-аар татгалздаг). PDF биш — клиент талын
/// PAdES-ийн CMS + файлын hash-ууд. <c>GeregeSystems.EidMongolia.Pades</c>-ийн <c>EidPades.Registration(...)</c>-ийн
/// <c>SignatureRegistration</c>-тэй JSON-оор ижил хэлбэртэй — талбар бүрийг шууд хуулна.
/// </summary>
public sealed record PdfSignatureRegistration
{
    /// <summary>Баримтын UUID.</summary>
    [JsonPropertyName("docID")]
    public string DocId { get; init; } = "";

    /// <summary>Энэ гарын үсгийн дугаар (1…16).</summary>
    [JsonPropertyName("revIndex")]
    public int RevIndex { get; init; }

    /// <summary><see cref="PdfMediums"/>.</summary>
    [JsonPropertyName("medium")]
    public string Medium { get; init; } = "";

    /// <summary>Утсанд заавал (RAW_DIGEST_SIGNATURE session).</summary>
    [JsonPropertyName("sessionID")]
    public string? SessionId { get; init; }

    /// <summary>CMS DER (JSON-д стандарт base64), ≤ 28 672 байт.</summary>
    [JsonPropertyName("cms")]
    public byte[] Cms { get; init; } = Array.Empty<byte>();

    /// <summary>Баримтын нэр.</summary>
    [JsonPropertyName("fileName")]
    public string FileName { get; init; } = "";

    /// <summary>SHA-256(оролтын PDF), hex.</summary>
    [JsonPropertyName("inSha256")]
    public string InSha256 { get; init; } = "";

    /// <summary>revIndex 1-д заавал (баталгаажуулалтын хуудастай).</summary>
    [JsonPropertyName("pageSha256")]
    public string? PageSha256 { get; init; }

    /// <summary>SHA-256(гарын үсгийн revision), hex.</summary>
    [JsonPropertyName("sigRevSha256")]
    public string SigRevSha256 { get; init; } = "";

    /// <summary>SHA-256(гаралт), hex.</summary>
    [JsonPropertyName("outSha256")]
    public string OutSha256 { get; init; } = "";

    /// <summary>Өмнөх (клиент талын) гарын үсгүүдийн CMS SHA-256.</summary>
    [JsonPropertyName("priorCmsSha256")]
    public IReadOnlyList<string>? PriorCmsSha256 { get; init; }

    /// <summary>Горим A-ийн (CA угсарсан) өмнөх гарын үсгүүдийн revision SHA-256.</summary>
    [JsonPropertyName("priorRevisionSha256")]
    public IReadOnlyList<string>? PriorRevisionSha256 { get; init; }

    /// <summary>NTRMN-…: байгууллагын нэрийн өмнөөс (CMS-ийн claimedRole-ийг CA тухайн мөчийн төлөөллөөр тулгана).</summary>
    [JsonPropertyName("onBehalfOf")]
    public string? OnBehalfOf { get; init; }

    /// <summary>Заавал биш (PNOMN-…): ирсэн бол CMS-ийн зурагчийн SERIALNUMBER-тэй тэнцүү (эс бөгөөс 409 SIGNER_MISMATCH).</summary>
    [JsonPropertyName("signerEtsi")]
    public string? SignerEtsi { get; init; }

    /// <summary>
    /// SDK-д л (CA руу илгээхгүй): өмнөх гарын үсэг бүрийн хоёр түлхүүр, баримтын дарааллаар. CA өмнөх мөр бүрийг өөрийнх нь
    /// түлхүүрээр таньдаг (клиент талын — CMS, горим A — revision). <see cref="PdfService.RegisterSignatureAsync"/> эхлээд
    /// <see cref="PriorCmsSha256"/>-аар илгээж, 409 PRIOR_MISMATCH бол эхний k-г revision-оор, өмнөх нь ≤ 4 бол бүх хослолыг
    /// оролдоно. <see cref="PriorRevisionSha256"/>-г гараар өгсөн бол оролдохгүй.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<PdfPriorSignature> PriorSignatures { get; init; } = Array.Empty<PdfPriorSignature>();
}

/// <summary>Өмнөх нэг гарын үсгийн хоёр түлхүүр (<see cref="PdfSignatureRegistration.PriorSignatures"/>).</summary>
/// <param name="CmsSha256">CMS DER-ийн SHA-256 — клиент талын мөр.</param>
/// <param name="RevisionSha256"><c>sha256(doc[0 : ByteRange[2]+ByteRange[3]])</c> — горим A-ийн мөр.</param>
public sealed record PdfPriorSignature(string CmsSha256, string RevisionSha256);

/// <summary><c>POST /pdf/signatures</c>-ийн хариу: 201 (шинэ) эсвэл 200 (ижил биеийн идэмпотент давталт — анхны хариу).</summary>
public sealed record PdfSignatureRegistered
{
    /// <summary>Баримтын UUID.</summary>
    [JsonPropertyName("docID")]
    public string DocId { get; init; } = "";

    /// <summary>Гарын үсгийн дугаар.</summary>
    [JsonPropertyName("revIndex")]
    public int RevIndex { get; init; }

    /// <summary>RFC 3339 (+08).</summary>
    [JsonPropertyName("registeredAt")]
    public string RegisteredAt { get; init; } = "";

    /// <summary>Нийтийн шалгах хуудас.</summary>
    [JsonPropertyName("verifyUrl")]
    public string VerifyUrl { get; init; } = "";

    /// <summary>true — 201 (шинээр бүртгэв); false — 200 (идэмпотент давталт).</summary>
    [JsonIgnore]
    public bool Created { get; init; }
}

/// <summary>
/// <c>POST /pdf/signatures</c>-ийн CA алдааны кодууд (<see cref="EidException.Code"/>; CA pades_register.go,
/// handlers_pdf.go). Go <c>PDFRegisterErrorCodes</c>, TS <c>PDF_REGISTER_ERROR_CODES</c>-тэй ижил дараалал.
/// </summary>
public static class PdfErrorCodes
{
    /// <summary>413: body 64 KiB-аас их.</summary>
    public const string RequestTooLarge = "REQUEST_TOO_LARGE";
    /// <summary>400: cms задарсангүй эсвэл профайлд нийцэхгүй.</summary>
    public const string CmsInvalid = "CMS_INVALID";
    /// <summary>400: CMS-ийн гарын үсэг signedAttrs-тэй таарахгүй.</summary>
    public const string SignatureInvalid = "SIGNATURE_INVALID";
    /// <summary>400: signatureTimeStampToken хүчингүй.</summary>
    public const string TimestampInvalid = "TIMESTAMP_INVALID";
    /// <summary>409: SignerEtsi нь CMS-ийн зурагчтай таарахгүй.</summary>
    public const string SignerMismatch = "SIGNER_MISMATCH";
    /// <summary>409: утасны SIGN гэрчилгээ хүчингүй.</summary>
    public const string SignerCertInvalid = "SIGNER_CERT_INVALID";
    /// <summary>409: токены гэрчилгээ хүчингүй.</summary>
    public const string TokenCertInvalid = "TOKEN_CERT_INVALID";
    /// <summary>403: OnBehalfOf нь токены байгууллагатай таарахгүй.</summary>
    public const string TokenOrgMismatch = "TOKEN_ORG_MISMATCH";
    /// <summary>409: session-ий digest / гарын үсэг / гэрчилгээ CMS-тэй таарахгүй.</summary>
    public const string SessionMismatch = "SESSION_MISMATCH";
    /// <summary>409: session дуусаагүй.</summary>
    public const string SessionNotComplete = "SESSION_NOT_COMPLETE";
    /// <summary>409: session амжилттай дуусаагүй.</summary>
    public const string SessionFailed = "SESSION_FAILED";
    /// <summary>409: claimedRole / onBehalfOf төлөөлөлтэй таарахгүй.</summary>
    public const string ClaimedRoleMismatch = "CLAIMED_ROLE_MISMATCH";
    /// <summary>409: docID аль хэдийн бүртгэлтэй.</summary>
    public const string DocIdConflict = "DOC_ID_CONFLICT";
    /// <summary>409: messageDigest, CMS эсвэл файлын hash өөр бүртгэлд бий.</summary>
    public const string RegistryConflict = "REGISTRY_CONFLICT";
    /// <summary>404: docID бүртгэлгүй.</summary>
    public const string DocNotFound = "DOC_NOT_FOUND";
    /// <summary>409: revIndex эсвэл prior* бүртгэлтэй таарахгүй.</summary>
    public const string PriorMismatch = "PRIOR_MISMATCH";

    /// <summary>Бүх код (бусад урсгалтай хуваалцдаг REQUEST_INVALID, REPRESENTATION_REVOKED, RATE_LIMITED, STATE_UNAVAILABLE орно).</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        EidErrorCodes.RequestInvalid, RequestTooLarge, CmsInvalid, SignatureInvalid, TimestampInvalid, SignerMismatch,
        SignerCertInvalid, TokenCertInvalid, TokenOrgMismatch, SessionMismatch, SessionNotComplete, SessionFailed,
        ClaimedRoleMismatch, EidErrorCodes.RepresentationRevoked, DocIdConflict, RegistryConflict, DocNotFound, PriorMismatch,
        EidErrorCodes.RateLimited, EidErrorCodes.StateUnavailable,
    };
}

/// <summary>PDF үйлчилгээ (Go <c>PDFService</c>): клиент талын PAdES гарын үсгийн бүртгэл.</summary>
public sealed class PdfService
{
    private readonly EidClient _c;

    internal PdfService(EidClient c) => _c = c;

    /// <summary>
    /// <c>POST /pdf/signatures</c> (SIGN эрх): клиент талын PAdES гарын үсгийг CA-ийн бүртгэлд (docID, /verify) оруулна.
    /// PAdES complete-ийн дараа заавал. Давталт идэмпотент (ижил бие → 200, <see cref="PdfSignatureRegistered.Created"/> false).
    /// HTTP хугацаа = <see cref="EidClient.PdfTimeout"/>.
    /// </summary>
    /// <exception cref="ArgumentException">docID / revIndex / cms / medium / sessionID / pageSha256-ийн дүрэм зөрчсөн (хүсэлт явахгүй).</exception>
    /// <exception cref="EidApiException">CA-ийн алдаа: <see cref="EidException.Code"/> ∈ <see cref="PdfErrorCodes.All"/>.</exception>
    public async Task<PdfSignatureRegistered> RegisterSignatureAsync(PdfSignatureRegistration registration, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        var r = registration;
        if (string.IsNullOrEmpty(r.DocId) || r.RevIndex < 1 || r.Cms is not { Length: > 0 })
        {
            throw new ArgumentException("eid: pdf register: docID, revIndex, cms заавал", nameof(registration));
        }
        if (r.Medium != PdfMediums.Phone && r.Medium != PdfMediums.Token)
        {
            throw new ArgumentException("eid: pdf register: medium нь phone | token", nameof(registration));
        }
        if (r.Medium == PdfMediums.Phone && string.IsNullOrEmpty(r.SessionId))
        {
            throw new ArgumentException("eid: pdf register: утсанд sessionID заавал", nameof(registration));
        }
        if (r.RevIndex == 1 && string.IsNullOrEmpty(r.PageSha256))
        {
            throw new ArgumentException("eid: pdf register: revIndex 1-д pageSha256 заавал (баталгаажуулалтын хуудастай)", nameof(registration));
        }
        EidApiException first;
        try
        {
            return await RegisterOnceAsync(r, ct).ConfigureAwait(false);
        }
        catch (EidApiException e) when (e.Code == PdfErrorCodes.PriorMismatch)
        {
            first = e;
        }
        var prior = r.PriorSignatures ?? Array.Empty<PdfPriorSignature>();
        if (r.PriorRevisionSha256 is { Count: > 0 } || prior.Count == 0 || prior.Count != r.RevIndex - 1)
        {
            throw first;
        }
        // Аль өмнөх мөр горим A (revision-оор) болохыг файлаас мэдэх аргагүй — хослолыг оролдоно (Go/TS priorSplits).
        foreach (var asRevision in PriorSplits(prior.Count))
        {
            var cms = new List<string>();
            var rev = new List<string>();
            for (var i = 0; i < prior.Count; i++)
            {
                if (asRevision[i])
                {
                    rev.Add(prior[i].RevisionSha256);
                }
                else
                {
                    cms.Add(prior[i].CmsSha256);
                }
            }
            try
            {
                return await RegisterOnceAsync(r with { PriorCmsSha256 = cms, PriorRevisionSha256 = rev }, ct).ConfigureAwait(false);
            }
            catch (EidApiException e) when (e.Code == PdfErrorCodes.PriorMismatch)
            {
                // дараагийн хослол
            }
        }
        throw first;
    }

    private async Task<PdfSignatureRegistered> RegisterOnceAsync(PdfSignatureRegistration r, CancellationToken ct)
    {
        // Go omitempty: хоосон мөр / жагсаалтыг илгээхгүй.
        var wire = r with
        {
            SessionId = Wire.NullIfEmpty(r.SessionId),
            PageSha256 = Wire.NullIfEmpty(r.PageSha256),
            PriorCmsSha256 = r.PriorCmsSha256 is { Count: > 0 } c ? c : null,
            PriorRevisionSha256 = r.PriorRevisionSha256 is { Count: > 0 } v ? v : null,
            OnBehalfOf = Wire.NullIfEmpty(r.OnBehalfOf),
            SignerEtsi = Wire.NullIfEmpty(r.SignerEtsi),
        };
        var (status, body) = await _c.Http.PostJsonWithStatusAsync<PdfSignatureRegistered>(
            RpRoutes.PdfSignatures.Expand(), wire, _c.PdfTimeout, ct).ConfigureAwait(false);
        return (body ?? new PdfSignatureRegistered()) with { Created = status == 201 };
    }

    /// <summary>
    /// PRIOR_MISMATCH-ийн дараах оролдлогууд (true = тухайн өмнөх гарын үсгийг revision-оор): эхлээд эхний k (k = 1…n),
    /// дараа нь n ≤ 4 бол үлдсэн бүх хослол. Go/TS <c>priorSplits</c>-тэй ижил дараалал.
    /// </summary>
    internal static List<bool[]> PriorSplits(int n)
    {
        var output = new List<bool[]>();
        var seen = new HashSet<int>();
        bool[] Mask(int m)
        {
            var b = new bool[n];
            for (var i = 0; i < n; i++)
            {
                b[i] = (m & (1 << i)) != 0;
            }
            return b;
        }
        for (var k = 1; k <= n; k++)
        {
            seen.Add((1 << k) - 1);
            output.Add(Mask((1 << k) - 1));
        }
        if (n <= 4)
        {
            for (var m = 1; m < 1 << n; m++)
            {
                if (!seen.Contains(m))
                {
                    output.Add(Mask(m));
                }
            }
        }
        return output;
    }
}
