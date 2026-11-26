using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Validation;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary><see cref="EidPades.ValidatePdfAsync"/>-ийн тохиргоо (бүгд заавал биш; Go <c>pades.ValidateOptions</c>, TS <c>ValidatePdfOptions</c>).</summary>
public sealed record ValidatePdfOptions
{
    /// <summary>Итгэлийн тулгуур (DER); хоосон бол шигтгэсэн Mongolian National Root CA (01).</summary>
    public IReadOnlyList<byte[]>? Roots { get; init; }

    /// <summary>Нэмэлт завсрын CA (DER) — шигтгэсэн 02–05-аас гадна.</summary>
    public IReadOnlyList<byte[]>? Intermediates { get; init; }

    /// <summary>eID олгогч гэж үзэх нэмэлт CA (DER) — шигтгэсэн 04/05-аас гадна (тест).</summary>
    public IReadOnlyList<byte[]>? Issuers { get; init; }

    /// <summary>Шалгах цаг (цагийн тэмдэггүй гарын үсэгт ба цуцлалтын шинэлэг байдалд); null бол одоо.</summary>
    public DateTimeOffset? Time { get; init; }

    /// <summary>
    /// Сүлжээ рүү гарахгүй: цуцлалтыг зөвхөн баримтын DSS-ийн OCSP/CRL-ээс. Анхдагч false — eID-ийн гэрчилгээний AIA OCSP
    /// (эс бөгөөс CDP CRL)-ээс одоогийн төлөв, хариугүй бол DSS. Сүлжээгээр зөвхөн гэрчилгээний serial (OCSP хүсэлт) явна, баримт биш.
    /// </summary>
    public bool Offline { get; init; }

    /// <summary>OCSP/CRL татах HttpClient (анхдагч: 10 с timeout, redirect дагахгүй). Дуудагчийнх бол dispose хийхгүй.</summary>
    public HttpClient? HttpClient { get; init; }
}

/// <summary>Баримтын тайлан (CA <c>POST /v3/validate/pdf</c>-ийн JSON; Go <c>pades.Report</c>, TS <c>PdfReport</c>).</summary>
public sealed class PdfReport
{
    internal PdfReport()
    {
    }

    /// <summary>"valid" | "invalid" | "indeterminate" — гарын үсгүүдийн хамгийн муу нь.</summary>
    public string Indication { get; internal set; } = "valid";

    /// <summary>Гарын үсэг бүрийн тайлан (баримт дахь дарааллаар).</summary>
    public IReadOnlyList<SignatureReport> Signatures => SignatureList;

    internal List<SignatureReport> SignatureList { get; } = new();

    /// <summary>Go/CA-тэй ижил JSON (snake_case, хоосон заавал биш талбаргүй).</summary>
    public string ToJson()
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            w.WriteStartObject();
            w.WriteString("indication", Indication);
            w.WriteStartArray("signatures");
            foreach (var s in SignatureList) s.Write(w);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }
}

/// <summary>Нэг гарын үсгийн тайлан (Go <c>pades.SignatureReport</c>, TS <c>SignatureReport</c>).</summary>
public sealed class SignatureReport
{
    internal SignatureReport()
    {
    }

    /// <summary>"valid" | "invalid" | "indeterminate".</summary>
    public string Indication { get; internal set; } = "valid";

    /// <summary>Асуудлын кодууд (integrity_failed, malformed_signature, weak_algorithm, untrusted_chain, wrong_key_usage, revoked,
    /// revoked_after_signing, revocation_unavailable, expired, not_yet_valid, modified_after_signing, timestamp_invalid).</summary>
    public IReadOnlyList<string> Problems => ProblemList;

    internal List<string> ProblemList { get; } = new();

    /// <summary>Гарын үсэг зурагчийн нэр (гэрчилгээнээс; байгууллагын баримт гаргагчид — платформын баталсан /Name).</summary>
    public string SignerName { get; internal set; } = "";

    /// <summary>Sig dict-ийн /Name (баталгаагүй); null — байхгүй.</summary>
    public string? ClaimedName { get; internal set; }

    /// <summary>"platform_attested" | "certificate" | "unverified".</summary>
    public string SignerNameSource { get; internal set; } = "unverified";

    /// <summary>/Reason; null — байхгүй.</summary>
    public string? Reason { get; internal set; }

    /// <summary>/Location; null — байхгүй.</summary>
    public string? Location { get; internal set; }

    /// <summary>/M (RFC 3339, баталгаагүй); null — байхгүй.</summary>
    public string? ClaimedTime { get; internal set; }

    /// <summary>Итгэмжлэгдсэн цагийн тэмдгийн цаг (RFC 3339); null — алга.</summary>
    public string? SigningTime { get; internal set; }

    /// <summary>RFC 3161 цагийн тэмдэг; null — алга.</summary>
    public TimestampInfo? Timestamp { get; internal set; }

    /// <summary>ByteRange нь баримтын төгсгөл хүртэл.</summary>
    public bool CoversWholeDocument { get; internal set; }

    /// <summary>Гарын үсгийн дараах өөрчлөлт нь зөвхөн гарын үсэг/DSS.</summary>
    public bool ExtendedBySignaturesOnly { get; internal set; }

    /// <summary>Дараа нэмэгдсэн гарын үсгийн тоо.</summary>
    public int LaterSignatures { get; internal set; }

    /// <summary>Дараагийн гарын үсгүүдийн аль нэг нь харагдах.</summary>
    public bool VisibleLaterSignature { get; internal set; }

    /// <summary>Энэ гарын үсэг харагдах (widget /AP эсвэл хоосон биш /Rect).</summary>
    public bool Visible { get; internal set; }

    /// <summary>Гинж итгэлийн тулгуур хүртэл баталгаажсан.</summary>
    public bool ChainTrusted { get; internal set; }

    /// <summary>Гинжийн CN-үүд (leaf → root); итгэмжлэгдээгүй бол зөвхөн leaf.</summary>
    public IReadOnlyList<string> Chain => ChainList;

    internal List<string> ChainList { get; } = new();

    /// <summary>Гарын үсэг зурагчийн гэрчилгээ; null — CMS задрахгүй.</summary>
    public CertInfo? Certificate { get; internal set; }

    /// <summary>Регистрийн дугаар (SERIALNUMBER PNOMN-…); null — алга.</summary>
    public string? CivilId { get; internal set; }

    /// <summary>"phone" | "unknown" (локал шалгалт; "token" / "server_*" — зөвхөн CA бүртгэлээс).</summary>
    public string KeyMedium { get; internal set; } = "unknown";

    /// <summary>signer-attributes-v2 claimedRole-ууд; null — алга.</summary>
    public IReadOnlyList<string>? ClaimedRoles { get; internal set; }

    /// <summary>"PAdES-BASELINE-B" | "-T" | "-LT" (ETSI.CAdES.detached-д); null — бусад.</summary>
    public string? SignatureLevel { get; internal set; }

    /// <summary>LTV хамралт (гинж итгэмжлэгдсэн үед); null — бусад.</summary>
    public LtvInfo? Ltv { get; internal set; }

    /// <summary>"ADVANCED" | "QUALIFIED" | "QSCD" (гинж итгэмжлэгдсэн үед); null — бусад.</summary>
    public string? CertificateLevel { get; internal set; }

    internal void Write(Utf8JsonWriter w)
    {
        w.WriteStartObject();
        w.WriteString("indication", Indication);
        WriteStrings(w, "problems", ProblemList);
        w.WriteString("signer_name", SignerName);
        if (ClaimedName is not null) w.WriteString("claimed_name", ClaimedName);
        w.WriteString("signer_name_source", SignerNameSource);
        if (Reason is not null) w.WriteString("reason", Reason);
        if (Location is not null) w.WriteString("location", Location);
        if (ClaimedTime is not null) w.WriteString("claimed_time", ClaimedTime);
        if (SigningTime is not null) w.WriteString("signing_time", SigningTime);
        if (Timestamp is not null)
        {
            w.WriteStartObject("timestamp");
            w.WriteString("time", Timestamp.Time);
            w.WriteString("serial", Timestamp.Serial);
            w.WriteString("tsa", Timestamp.Tsa);
            w.WriteBoolean("trusted", Timestamp.Trusted);
            w.WriteEndObject();
        }
        w.WriteBoolean("covers_whole_document", CoversWholeDocument);
        w.WriteBoolean("extended_by_signatures_only", ExtendedBySignaturesOnly);
        w.WriteNumber("later_signatures", LaterSignatures);
        w.WriteBoolean("visible_later_signature", VisibleLaterSignature);
        w.WriteBoolean("visible", Visible);
        w.WriteBoolean("chain_trusted", ChainTrusted);
        WriteStrings(w, "chain", ChainList);
        if (Certificate is { } c)
        {
            w.WriteStartObject("certificate");
            w.WriteString("common_name", c.CommonName);
            w.WriteString("subject", c.Subject);
            w.WriteString("issuer", c.Issuer);
            w.WriteString("serial", c.Serial);
            w.WriteString("not_before", c.NotBefore);
            w.WriteString("not_after", c.NotAfter);
            w.WriteString("usage", c.Usage);
            w.WriteBoolean("issued_by_eid", c.IssuedByEid);
            w.WriteStartObject("revocation");
            w.WriteString("status", c.Revocation.Status);
            if (c.Revocation.RevokedAt is not null) w.WriteString("revoked_at", c.Revocation.RevokedAt);
            w.WriteEndObject();
            w.WriteEndObject();
        }
        if (CivilId is not null) w.WriteString("civil_id", CivilId);
        w.WriteString("key_medium", KeyMedium);
        if (ClaimedRoles is not null) WriteStrings(w, "claimed_roles", ClaimedRoles);
        if (SignatureLevel is not null) w.WriteString("signature_level", SignatureLevel);
        if (Ltv is not null)
        {
            w.WriteStartObject("ltv");
            w.WriteBoolean("complete", Ltv.Complete);
            WriteStrings(w, "missing", Ltv.Missing);
            w.WriteEndObject();
        }
        if (CertificateLevel is not null) w.WriteString("certificate_level", CertificateLevel);
        w.WriteEndObject();
    }

    private static void WriteStrings(Utf8JsonWriter w, string name, IEnumerable<string> list)
    {
        w.WriteStartArray(name);
        foreach (var s in list) w.WriteStringValue(s);
        w.WriteEndArray();
    }
}

/// <summary>Гэрчилгээний мэдээлэл (Go <c>pades.CertInfo</c>).</summary>
public sealed class CertInfo
{
    internal CertInfo()
    {
    }

    /// <summary>Subject CN.</summary>
    public string CommonName { get; internal set; } = "";

    /// <summary>Subject (Go pkix.Name.String()).</summary>
    public string Subject { get; internal set; } = "";

    /// <summary>Issuer (Go pkix.Name.String()).</summary>
    public string Issuer { get; internal set; } = "";

    /// <summary>Serial, hex том үсгээр.</summary>
    public string Serial { get; internal set; } = "";

    /// <summary>notBefore (RFC 3339).</summary>
    public string NotBefore { get; internal set; } = "";

    /// <summary>notAfter (RFC 3339).</summary>
    public string NotAfter { get; internal set; } = "";

    /// <summary>"sign" | "auth" | "seal" | "document_signer" | "timestamp" | "other".</summary>
    public string Usage { get; internal set; } = "other";

    /// <summary>eID-ийн олгогч (04/05 эсвэл <see cref="ValidatePdfOptions.Issuers"/>) олгосон.</summary>
    public bool IssuedByEid { get; internal set; }

    /// <summary>Цуцлалтын төлөв.</summary>
    public CertRevocation Revocation { get; internal set; } = new();
}

/// <summary>Цуцлалтын төлөв (Go <c>pades.Revocation</c>).</summary>
public sealed class CertRevocation
{
    internal CertRevocation()
    {
    }

    /// <summary>"good" | "revoked" | "unknown".</summary>
    public string Status { get; internal set; } = "unknown";

    /// <summary>Цуцалсан цаг (RFC 3339); null — цуцлагдаагүй.</summary>
    public string? RevokedAt { get; internal set; }
}

/// <summary>RFC 3161 цагийн тэмдэг (Go <c>pades.TimestampInfo</c>).</summary>
public sealed class TimestampInfo
{
    internal TimestampInfo()
    {
    }

    /// <summary>genTime (RFC 3339).</summary>
    public string Time { get; internal set; } = "";

    /// <summary>Serial, hex том үсгээр.</summary>
    public string Serial { get; internal set; } = "";

    /// <summary>TSA гэрчилгээний CN.</summary>
    public string Tsa { get; internal set; } = "";

    /// <summary>Токен зөв, TSA гинж итгэмжлэгдсэн.</summary>
    public bool Trusted { get; internal set; }
}

/// <summary>LTV хамралт (Go <c>pades.LTVInfo</c>).</summary>
public sealed class LtvInfo
{
    internal LtvInfo()
    {
    }

    /// <summary>Гинжийн (ба TSA гинжийн) root-оос бусад гэрчилгээ бүрд DSS-д шинэлэг OCSP/CRL бий.</summary>
    public bool Complete { get; internal set; }

    /// <summary>Нотолгоогүй гэрчилгээний CN-үүд.</summary>
    public IReadOnlyList<string> Missing => MissingList;

    internal List<string> MissingList { get; } = new();
}

public static partial class EidPades
{
    /// <summary>
    /// PDF доторх бүх PAdES/CMS гарын үсгийг шалгана (Go <c>pades.ValidatePDF</c>, TS <c>validatePdf</c>; CA-ийн
    /// <c>/v3/validate/pdf</c>-тэй ижил дүрэм ба JSON тайлан): ByteRange/messageDigest-ийн бүрэн бүтэн байдал, CMS гарын үсэг,
    /// гинж (үндэсний Root CA хүртэл; X509Chain биш — платформ бүрд ижил), KU/EKU, хугацаа, RFC 3161 цагийн тэмдэг, гарын үсгийн
    /// дараах revision (modified_after_signing; харагдах гарын үсэг — APPEARANCE_SPEC §5/§6), LTV, гэрчилгээний түвшин.
    /// Баримт хаашаа ч илгээгдэхгүй — онлайн цуцлалтад зөвхөн гэрчилгээний serial (OCSP) явна.
    /// </summary>
    /// <param name="pdf">Гарын үсэгтэй PDF (≤ 10 MiB).</param>
    /// <param name="options">Тохиргоо; null — анхдагч (шигтгэсэн гинж, одоо, онлайн).</param>
    /// <param name="cancellationToken">OCSP/CRL таталт болон гарын үсэг хоорондын шалгалтыг цуцална.</param>
    /// <exception cref="EidPadesException">
    /// PDF_TOO_LARGE, PDF_INVALID (задрахгүй, хэт гүн/төвөгтэй), PDF_ENCRYPTED (/Encrypt — хоосон нууц үгтэй ч),
    /// PDF_NO_SIGNATURE, PDF_TOO_MANY_SIGNATURES (&gt; 16), REQUEST_INVALID (Roots/Intermediates/Issuers задрахгүй).
    /// </exception>
    public static async Task<PdfReport> ValidatePdfAsync(byte[] pdf, ValidatePdfOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        var o = options ?? new ValidatePdfOptions();
        if (pdf.Length > Extract.MaxPdfBytes) throw new EidPadesException("PDF_TOO_LARGE", "PDF 10 MiB-аас их");
        var roots = o.Roots is { Count: > 0 } ? Ders(o.Roots, "roots") : new List<ValCert> { ValCert.Parse(Trust.NationalRoot.RawData) };
        var inter = new List<ValCert>();
        foreach (var c in Trust.Intermediates) inter.Add(ValCert.Parse(c.RawData));
        inter.AddRange(Ders(o.Intermediates, "intermediates"));
        var issuers = new List<ValCert>();
        foreach (var c in Trust.Issuers) issuers.Add(ValCert.Parse(c.RawData));
        issuers.AddRange(Ders(o.Issuers, "issuers"));

        List<RawSignature> sigs;
        try
        {
            (sigs, _) = Extract.Run(pdf, cancellationToken);
        }
        catch (ExtractException e)
        {
            throw e.Code switch
            {
                "no_signature" => new EidPadesException("PDF_NO_SIGNATURE", "баримтад цахим гарын үсэг алга", e),
                "too_many" => new EidPadesException("PDF_TOO_MANY_SIGNATURES", "баримтад хэт олон гарын үсэг байна", e),
                "encrypted" => new EidPadesException("PDF_ENCRYPTED", "шифрлэгдсэн PDF-ийг шалгах боломжгүй — нууцлалыг арилгаад дахин оролдоно уу", e),
                _ => new EidPadesException("PDF_INVALID", "PDF задарсангүй", e),
            };
        }

        var now = GoTime.FromDateTimeOffset(o.Time ?? DateTimeOffset.UtcNow);
        RawDss? dss = null;
        foreach (var s in sigs)
        {
            if (s.Dss is not null)
            {
                dss = s.Dss;
                break;
            }
        }
        IStatusSource status = new DssStatus(dss, now);
        Fetcher? fetcher = null;
        if (!o.Offline)
        {
            fetcher = new Fetcher(o.HttpClient);
            status = new OnlineStatus(fetcher, status, now);
        }
        try
        {
            var ev = new Evaluator(roots, inter, issuers, status, now);
            var rep = new PdfReport();
            foreach (var r in sigs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SignatureReport s;
                try
                {
                    s = await ev.EvaluateSignatureAsync(r, cancellationToken).ConfigureAwait(false);
                    if (s.ChainTrusted && r.Leaf is not null && Evaluator.SignLevelOf(ValCert.Parse(r.Leaf)) is { } lvl) s.CertificateLevel = lvl;
                }
                catch (Exception e) when (e is not OperationCanceledException && e is not EidPadesException)
                {
                    // Go: v.ValidatePDF алдаа → PDF_INVALID «шалгаж чадсангүй» (халдагчийн өгөгдлөөс гарсан гэнэтийн алдаа crash биш).
                    throw new EidPadesException("PDF_INVALID", "шалгаж чадсангүй", e);
                }
                s.KeyMedium = KeyMedium(s);
                rep.SignatureList.Add(s);
            }
            foreach (var s in rep.SignatureList)
            {
                if (s.Indication == "invalid")
                {
                    rep.Indication = "invalid";
                    break;
                }
                if (s.Indication == "indeterminate") rep.Indication = "indeterminate";
            }
            return rep;
        }
        finally
        {
            fetcher?.Dispose();
        }
    }

    private static List<ValCert> Ders(IReadOnlyList<byte[]>? list, string what)
    {
        var o = new List<ValCert>();
        if (list is null) return o;
        foreach (var d in list)
        {
            try
            {
                o.Add(ValCert.Parse(d ?? throw new ValCertException("null")));
            }
            catch (ValCertException e)
            {
                throw new EidPadesException("REQUEST_INVALID", what + ": " + e.Message, e);
            }
        }
        return o;
    }

    /// <summary>
    /// key_medium (CA !377) — локал шалгалтад зөвхөн гэрчилгээнээс: eID-ийн олгосон SIGN гэрчилгээ QUALIFIED/QSCD бол «phone»,
    /// бусад «unknown» (токен ба сервер талын утгыг зөвхөн CA бүртгэлээс).
    /// </summary>
    private static string KeyMedium(SignatureReport s)
    {
        var c = s.Certificate;
        if (c is not null && c.IssuedByEid && c.Usage == "sign" && (s.CertificateLevel == "QUALIFIED" || s.CertificateLevel == "QSCD")) return "phone";
        return "unknown";
    }
}
