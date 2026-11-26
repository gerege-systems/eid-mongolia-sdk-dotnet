using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// <c>POST /seal/{orgEtsi}/registrations</c>-ийн бие (CA V158 <c>dto.SealRegisterRequest</c>-тэй ЯГ ижил — CA
/// DisallowUnknownFields: medium, sessionID, onBehalfOf, signerEtsi, pageSha256 илгээвэл 400; Go <c>eid.SealRegistration</c>,
/// TS <c>SealRegisterInput</c>). Байгууллагын тамгатай PDF-ийн CMS + файлын hash-ууд (иргэний
/// <see cref="PdfSignatureRegistration"/>-тэй ижил тодорхойлолт). <c>GeregeSystems.EidMongolia.Pades</c>-ийн
/// <c>Completed.SealRegistration</c> эсвэл <c>EidPades.SealRegistration(completed)</c>-оор бөглөнө.
/// </summary>
public sealed record SealRegistration
{
    /// <summary>Баримтын UUID (жижиг үсэг).</summary>
    [JsonPropertyName("docID")]
    public string DocId { get; init; } = "";

    /// <summary>Тамганы файл дахь байрлал (1–16).</summary>
    [JsonPropertyName("revIndex")]
    public int RevIndex { get; init; }

    /// <summary>CMS DER (JSON-д base64), 1…28 672 байт.</summary>
    [JsonPropertyName("cms")]
    public byte[] Cms { get; init; } = Array.Empty<byte>();

    /// <summary>Заавал биш — <c>/verify</c>-д харагдах нэр (≤ 120 тэмдэгт); <c>null</c>/"" бол илгээхгүй.</summary>
    [JsonPropertyName("fileName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FileName { get; init; }

    /// <summary>SHA-256(тамгалахын өмнөх оролт), 64 жижиг hex.</summary>
    [JsonPropertyName("inSha256")]
    public string InSha256 { get; init; } = "";

    /// <summary>SHA-256(гаралт[0 : ByteRange[2]+ByteRange[3]]), 64 жижиг hex.</summary>
    [JsonPropertyName("sigRevSha256")]
    public string SigRevSha256 { get; init; } = "";

    /// <summary>SHA-256(гаралт), 64 жижиг hex.</summary>
    [JsonPropertyName("outSha256")]
    public string OutSha256 { get; init; } = "";

    /// <summary>Өмнөх (клиент талын) гарын үсгүүдийн CMS SHA-256.</summary>
    [JsonPropertyName("priorCmsSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? PriorCmsSha256 { get; init; }

    /// <summary>CA угсарсан (горим A) өмнөх гарын үсгүүдийн revision SHA-256; <see cref="PriorCmsSha256"/>-тай нийлээд = revIndex − 1.</summary>
    [JsonPropertyName("priorRevisionSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? PriorRevisionSha256 { get; init; }

    /// <summary>
    /// SDK-д л (CA руу илгээгдэхгүй): <see cref="PdfSignatureRegistration.PriorSignatures"/>-тэй ижил — 409 PRIOR_MISMATCH бол
    /// <see cref="SealService.RegisterSealedPdfAsync"/> өмнөх мөрийг revision-оор (горим A) тааруулж дахин оролдоно.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<PdfPriorSignature> PriorSignatures { get; init; } = Array.Empty<PdfPriorSignature>();

    /// <summary>
    /// CA-ийн <c>normalizeSealRegister</c>-ийн хэлбэрийн шалгалт (сүлжээгүй; Go <c>SealRegistration.Validate</c>): docID жижиг
    /// UUID, revIndex 1–16, fileName ≤ 120 тэмдэгт (өгсөн бол), inSha256 / sigRevSha256 / outSha256 ба prior* нь 64 жижиг hex,
    /// prior-ийн нийт тоо = revIndex − 1, cms 1…28 672 байт.
    /// </summary>
    /// <exception cref="ArgumentException">Дүрэм зөрчсөн.</exception>
    public void Validate()
    {
        static ArgumentException Bad(string m) => new("eid: seal register: " + m, "registration");
        if (!SealRegisterRules.DocId.IsMatch(DocId ?? ""))
        {
            throw Bad("docID нь жижиг үсгийн UUID");
        }
        if (RevIndex is < 1 or > 16)
        {
            throw Bad("revIndex 1–16");
        }
        var fn = (FileName ?? "").Trim();
        if (fn.Length > 0 && fn.EnumerateRunes().Count() > SealRegisterRules.MaxFileName)
        {
            throw Bad("fileName ≤ 120 тэмдэгт");
        }
        if (Cms is not { Length: > 0 } || Cms.Length > SealRegisterRules.MaxCms)
        {
            throw Bad("cms 1…28 672 байт");
        }
        if ((PriorCmsSha256?.Count ?? 0) + (PriorRevisionSha256?.Count ?? 0) != RevIndex - 1)
        {
            throw Bad("priorCmsSha256 + priorRevisionSha256 нийт revIndex − 1");
        }
        foreach (var (name, h) in new[] { ("inSha256", InSha256), ("sigRevSha256", SigRevSha256), ("outSha256", OutSha256) })
        {
            if (!SealRegisterRules.Hex64.IsMatch(h ?? ""))
            {
                throw Bad(name + " 64 жижиг hex");
            }
        }
        foreach (var h in (PriorCmsSha256 ?? Array.Empty<string>()).Concat(PriorRevisionSha256 ?? Array.Empty<string>()))
        {
            if (!SealRegisterRules.Hex64.IsMatch(h ?? ""))
            {
                throw Bad("prior* 64 жижиг hex");
            }
        }
    }
}

/// <summary>
/// <c>POST /seal/{orgEtsi}/registrations</c>-ийн CA алдааны кодууд (<see cref="EidException.Code"/>; CA
/// pades_seal_register.go <c>SealRegisterErrorCodes</c>, discovery <c>seal.registerErrorCodes</c>). Go
/// <c>SealRegisterErrorCodes</c>, TS <c>SEAL_REGISTER_ERROR_CODES</c>-тэй ижил дараалал. <c>SEAL:&lt;orgEtsi&gt;</c> эрхгүй RP →
/// 403 <see cref="EidForbiddenException"/> (code-гүй).
/// </summary>
public static class SealRegisterErrorCodes
{
    /// <summary>Бүх код, CA-ийн дарааллаар.</summary>
    public static IReadOnlyList<string> All { get; } = new[]
    {
        PdfErrorCodes.RequestTooLarge,
        EidErrorCodes.RequestInvalid,
        EidErrorCodes.RateLimited,
        EidErrorCodes.StateUnavailable,
        PdfErrorCodes.CmsInvalid,
        PdfErrorCodes.SignerMismatch,
        PdfErrorCodes.SignerCertInvalid,
        PdfErrorCodes.SignatureInvalid,
        EidErrorCodes.SealNotFound,
        EidErrorCodes.SealDocMismatch,
        PdfErrorCodes.TimestampInvalid,
        EidErrorCodes.DocIdReserved,
        PdfErrorCodes.DocIdConflict,
        PdfErrorCodes.PriorMismatch,
        PdfErrorCodes.RegistryConflict,
    };
}

/// <summary>Хэлбэрийн дүрэм — CA <c>normalizeSealRegister</c> (pades_seal_register.go) ба <c>sealReservation</c> (org.go).</summary>
internal static class SealRegisterRules
{
    public static readonly Regex DocId = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.CultureInvariant);
    public static readonly Regex Org = new("^NTRMN-[0-9A-Z]{1,58}$", RegexOptions.CultureInvariant);
    public static readonly Regex Hex64 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    public const int MaxFileName = 120;

    /// <summary>CA <c>padesRegisterMaxCMS</c> (= PAdES placeholder).</summary>
    public const int MaxCms = 28672;
}

public sealed partial class SealService
{
    /// <summary>
    /// <c>POST /seal/{orgEtsi}</c> <c>{digest, hashType: SHA256, docId, revIndex}</c> (CA V158; Go <c>SealForDocument</c>, TS
    /// <c>sealForDocument</c>): <see cref="SealAsync"/>-тэй ижил, нэмээд QR-тэй тамганы баримтын нөөц — дардасны QR
    /// (<c>/verify/&lt;docId&gt;/&lt;revIndex&gt;</c>) өөр гарын үсгийн бүртгэлд «хулгайлагдахгүй» (CA: бүртгэгдээгүй нөөц 7 хоногийн
    /// турш тэр docId-ийн дараагийн байрлалын бүртгэлийг DOC_ID_CONFLICT / DOC_ID_RESERVED-ээр хаана). Зөвхөн SHA-256 digest.
    /// Бүртгэлийн docID/revIndex нөөцтэй таарахгүй бол <see cref="RegisterSealedPdfAsync"/> 409 SEAL_DOC_MISMATCH.
    /// <c>EidPades.SealAsync</c> (<c>SealOptions.Qr</c>) үүнийг дуудна.
    /// </summary>
    /// <param name="orgEtsi">NTRMN-…</param>
    /// <param name="digest">SHA-256 digest (32 байт).</param>
    /// <param name="docId">Жижиг үсгийн UUID.</param>
    /// <param name="revIndex">1–16.</param>
    /// <param name="ct">Цуцлалт.</param>
    /// <exception cref="ArgumentException">docId жижиг UUID биш, revIndex 1–16-аас гадуур, эсвэл digest 32 байт биш (хүсэлт явахгүй).</exception>
    public Task<SealResult> SealForDocumentAsync(string orgEtsi, byte[] digest, string docId, int revIndex, CancellationToken ct = default)
    {
        if (!SealRegisterRules.DocId.IsMatch(docId ?? "") || revIndex is < 1 or > 16)
        {
            throw new ArgumentException("eid: seal: docId жижиг үсгийн UUID, revIndex 1–16", nameof(docId));
        }
        return SealAsync(orgEtsi, digest, HashAlgorithms.Sha256, new SealDigestOptions { DocId = docId, RevIndex = revIndex }, ct);
    }

    /// <summary>
    /// <c>POST /seal/{orgEtsi}/registrations</c> (<c>SEAL:&lt;orgEtsi&gt;</c> эрх, CA V158; Go <c>RegisterSealedPDF</c>, TS
    /// <c>registerSealedPdf</c>): байгууллагын тамгатай PDF-ийг CA-ийн бүртгэлд (<c>/verify/{docID}</c>, байгууллагын мөр) оруулна —
    /// иргэний <see cref="PdfService.RegisterSignatureAsync"/>-ийн тамганы хувилбар. <c>EidPades.SealAsync</c>-ийн дараа
    /// <c>Completed.SealRegistration</c>-оор. Нөхцөл (CA): тамгыг ЭНЭ RP <c>POST /seal/{orgEtsi}</c>-ээр хүссэн байх (CMS-ийн
    /// SHA-256(signedAttrs) = тамгалсан digest), тамгалснаас 7 хоногийн дотор, нөөцөлсөн docId/revIndex-тэй таарах. Давталт
    /// идэмпотент (ижил бие → 200, <see cref="PdfSignatureRegistered.Created"/> false). 409 PRIOR_MISMATCH бол
    /// <see cref="SealRegistration.PriorSignatures"/>-ээр (<see cref="PdfService.RegisterSignatureAsync"/>-тэй ижил дүрэм) дахин
    /// оролдоно. Хэлбэрийн алдааг (<see cref="SealRegistration.Validate"/>) сүлжээнд гаргахгүй. HTTP хугацаа =
    /// <see cref="EidClient.PdfTimeout"/>.
    /// </summary>
    /// <param name="orgEtsi">NTRMN-…</param>
    /// <param name="registration">Бие.</param>
    /// <param name="ct">Цуцлалт.</param>
    /// <exception cref="ArgumentException">orgEtsi эсвэл биеийн хэлбэр буруу (хүсэлт явахгүй).</exception>
    /// <exception cref="EidApiException">
    /// <see cref="EidException.Code"/> ∈ <see cref="SealRegisterErrorCodes.All"/> (<see cref="EidSealNotFoundException"/>,
    /// <see cref="EidSealDocMismatchException"/>, <see cref="EidDocIdReservedException"/> г.м.; 429 RATE_LIMITED — Retryable);
    /// 501 (CA-д PAdES тохируулаагүй).
    /// </exception>
    /// <exception cref="EidForbiddenException">403 — <c>SEAL:&lt;orgEtsi&gt;</c> эрхгүй.</exception>
    public async Task<PdfSignatureRegistered> RegisterSealedPdfAsync(string orgEtsi, SealRegistration registration, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        var org = (orgEtsi ?? "").Trim();
        if (!SealRegisterRules.Org.IsMatch(org.ToUpperInvariant()))
        {
            throw new ArgumentException("eid: seal register: orgEtsi нь NTRMN-…", nameof(orgEtsi));
        }
        var r = registration;
        r.Validate();
        EidApiException first;
        try
        {
            return await RegisterOnceAsync(org, r, ct).ConfigureAwait(false);
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
        // Аль өмнөх мөр горим A (revision-оор) болохыг файлаас мэдэх аргагүй — RegisterSignatureAsync-тэй ижил хослолууд.
        foreach (var asRevision in PdfService.PriorSplits(prior.Count))
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
                return await RegisterOnceAsync(org, r with { PriorCmsSha256 = cms, PriorRevisionSha256 = rev }, ct).ConfigureAwait(false);
            }
            catch (EidApiException e) when (e.Code == PdfErrorCodes.PriorMismatch)
            {
                // дараагийн хослол
            }
        }
        throw first;
    }

    private async Task<PdfSignatureRegistered> RegisterOnceAsync(string orgEtsi, SealRegistration r, CancellationToken ct)
    {
        // Go omitempty: хоосон мөр / жагсаалтыг илгээхгүй.
        var wire = r with
        {
            FileName = string.IsNullOrEmpty(r.FileName) ? null : r.FileName,
            PriorCmsSha256 = r.PriorCmsSha256 is { Count: > 0 } c ? c : null,
            PriorRevisionSha256 = r.PriorRevisionSha256 is { Count: > 0 } v ? v : null,
        };
        var (status, body) = await _c.Http.PostJsonWithStatusAsync<PdfSignatureRegistered>(
            RpRoutes.SealRegistrations.Expand(orgEtsi), wire, _c.PdfTimeout, ct).ConfigureAwait(false);
        return (body ?? new PdfSignatureRegistered()) with { Created = status == 201 };
    }
}
