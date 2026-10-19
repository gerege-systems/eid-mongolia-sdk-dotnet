using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using GeregeSystems.EidMongolia.Pades.Crypto;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary><see cref="EidPades.Registration"/>-ийн <see cref="Completed"/>-ээс гадуурх утгууд (Go <c>pades.RegistrationOptions</c>).</summary>
public sealed record RegistrationOptions
{
    /// <summary><c>phone</c> | <c>token</c>. <c>null</c> = <see cref="SessionId"/> байвал phone, эс бөгөөс token.</summary>
    public string? Medium { get; init; }

    /// <summary>Утсанд заавал: DTBS-ийг зурсан RAW_DIGEST_SIGNATURE session.</summary>
    public string? SessionId { get; init; }

    /// <summary>NTRMN-… (<see cref="PrepareOptions.ClaimedRole"/> өгсөн бол заавал).</summary>
    public string? OnBehalfOf { get; init; }
}

/// <summary>Өмнөх нэг гарын үсгийн хоёр түлхүүр (<see cref="SignatureRegistration.PriorSignatures"/>).</summary>
/// <param name="CmsSha256">CMS DER-ийн SHA-256 — клиент талын мөр.</param>
/// <param name="RevisionSha256"><c>sha256(doc[0 : ByteRange[2]+ByteRange[3]])</c> — CA угсарсан (горим A) мөр.</param>
public sealed record PriorSignature(string CmsSha256, string RevisionSha256);

/// <summary>
/// CA <c>POST /pdf/signatures</c>-ийн бие (CA <c>PDFSignatureRegisterRequest</c>; үл мэдэгдэх талбарыг 400-аар татгалздаг) —
/// <c>System.Text.Json</c>-оор шууд сериализ хийж илгээнэ. Go <c>eid.PDFSignatureRegistration</c>, TS
/// <c>RegisterSignatureInput</c>-тэй ижил.
/// </summary>
public sealed record SignatureRegistration
{
    /// <summary>Баримтын UUID.</summary>
    [JsonPropertyName("docID")]
    public string DocId { get; init; } = "";

    /// <summary>Энэ гарын үсгийн дугаар (1…16).</summary>
    [JsonPropertyName("revIndex")]
    public int RevIndex { get; init; }

    /// <summary><c>phone</c> | <c>token</c>.</summary>
    [JsonPropertyName("medium")]
    public string Medium { get; init; } = "";

    /// <summary>Утсанд заавал.</summary>
    [JsonPropertyName("sessionID")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SessionId { get; init; }

    /// <summary>CMS DER (JSON-д base64).</summary>
    [JsonPropertyName("cms")]
    public byte[] Cms { get; init; } = Array.Empty<byte>();

    /// <summary>Баримтын нэр.</summary>
    [JsonPropertyName("fileName")]
    public string FileName { get; init; } = "";

    /// <summary>SHA-256(Prepare-ийн оролт).</summary>
    [JsonPropertyName("inSha256")]
    public string InSha256 { get; init; } = "";

    /// <summary>revIndex 1-д заавал.</summary>
    [JsonPropertyName("pageSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PageSha256 { get; init; }

    /// <summary>SHA-256(гарын үсгийн revision).</summary>
    [JsonPropertyName("sigRevSha256")]
    public string SigRevSha256 { get; init; } = "";

    /// <summary>SHA-256(гаралт).</summary>
    [JsonPropertyName("outSha256")]
    public string OutSha256 { get; init; } = "";

    /// <summary>Өмнөх (клиент талын) гарын үсгүүдийн CMS SHA-256.</summary>
    [JsonPropertyName("priorCmsSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? PriorCmsSha256 { get; init; }

    /// <summary>
    /// CA угсарсан (горим A) өмнөх гарын үсгүүдийн revision SHA-256; <see cref="PriorCmsSha256"/>-тай нийлээд = revIndex − 1.
    /// <see cref="EidPades.Registration"/> тавихгүй — 409 <c>PRIOR_MISMATCH</c> бол <see cref="PriorSignatures"/>-ийн эхний k-г
    /// энд, үлдсэнийг <see cref="PriorCmsSha256"/>-д шилжүүлж дахин илгээнэ.
    /// </summary>
    [JsonPropertyName("priorRevisionSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? PriorRevisionSha256 { get; init; }

    /// <summary>NTRMN-…: байгууллагын нэрийн өмнөөс.</summary>
    [JsonPropertyName("onBehalfOf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OnBehalfOf { get; init; }

    /// <summary>Зурагчийн гэрчилгээний SERIALNUMBER (PNOMN-…); CA CMS-тэй тулгана.</summary>
    [JsonPropertyName("signerEtsi")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SignerEtsi { get; init; }

    /// <summary>
    /// SDK-д л (CA руу илгээгдэхгүй): өмнөх гарын үсэг бүрийн хоёр түлхүүр, баримтын дарааллаар. CA өмнөх мөр бүрийг өөрийн
    /// түлхүүрээр таньдаг (клиент талын — CMS, горим A — revision), файлаас ялгах боломжгүй.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<PriorSignature> PriorSignatures { get; init; } = Array.Empty<PriorSignature>();
}

public static partial class EidPades
{
    /// <summary>
    /// <see cref="Completed"/>-ээс CA-ийн бүртгэлийн биеийг бөглөнө (Go <c>pades.Registration</c>, TS <c>registrationFromCompleted</c>):
    /// өмнөх гарын үсгүүдийг зөвхөн <c>priorCmsSha256</c>-аар (revision-ийг <see cref="SignatureRegistration.PriorSignatures"/>-д)
    /// — хоёр жагсаалтыг хоёуланг нь бүтнээр илгээвэл CA 400 буцаадаг.
    /// </summary>
    /// <exception cref="EidPadesException">REQUEST_INVALID — эхний гарын үсэг хуудасгүй эсвэл fileName хоосон.</exception>
    public static SignatureRegistration Registration(Completed completed, RegistrationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(completed);
        var o = options ?? new RegistrationOptions();
        if (completed.RevIndex == 1 && !completed.HasPage)
            throw new EidPadesException("REQUEST_INVALID", "the first signature must carry the verification page (PrepareOptions.VerifyPage)");
        if (completed.FileName == "") throw new EidPadesException("REQUEST_INVALID", "fileName is empty (PrepareOptions.FileName)");
        var prior = new List<PriorSignature>();
        if (completed.PriorRevisionSha256.Count == completed.PriorCmsSha256.Count)
            for (int i = 0; i < completed.PriorCmsSha256.Count; i++)
                prior.Add(new PriorSignature(completed.PriorCmsSha256[i], completed.PriorRevisionSha256[i]));
        string? etsi = null;
        try
        {
            var v = LastAttr(X509Util.Parse(completed.SignerCert).SubjectName, "2.5.4.5");
            if (v != "") etsi = v;
        }
        catch (FormatException)
        {
        }
        return new SignatureRegistration
        {
            DocId = completed.DocId,
            RevIndex = completed.RevIndex,
            Medium = string.IsNullOrEmpty(o.Medium) ? string.IsNullOrEmpty(o.SessionId) ? "token" : "phone" : o.Medium,
            SessionId = string.IsNullOrEmpty(o.SessionId) ? null : o.SessionId,
            Cms = completed.Cms,
            FileName = completed.FileName,
            InSha256 = completed.InSha256,
            PageSha256 = completed.RevIndex == 1 ? completed.PageSha256 : null,
            SigRevSha256 = completed.SigRevSha256,
            OutSha256 = completed.OutSha256,
            PriorCmsSha256 = completed.PriorCmsSha256.Count > 0 ? new List<string>(completed.PriorCmsSha256) : null,
            OnBehalfOf = string.IsNullOrEmpty(o.OnBehalfOf) ? null : o.OnBehalfOf,
            SignerEtsi = etsi,
            PriorSignatures = prior,
        };
    }
}
