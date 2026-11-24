using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>
/// <see cref="EidPades.SealAsync"/>-ийн сонголт — байгууллагын тамга (e-Seal). Баталгаажуулалтын (QR) хуудас нэмэхгүй.
/// Анхдагчаар тамга ХАРАГДАНА (Go <c>pades.SealOptions</c>, TS <c>sealPdf</c>-тэй ижил): баримтын сүүлийн (eID verify биш)
/// хуудсанд байгууллагын тамганы дардас (APPEARANCE_SPEC.md §6 — QR/холбоосгүй), баруун доод буланд, агуулгатай давхцвал
/// чөлөөт байрлал руу (PLACEMENT_SPEC.md). <see cref="Invisible"/> = <c>true</c> бол өмнөх хувилбартай байт-ижил үл харагдах
/// тамга.
/// </summary>
public sealed record SealOptions
{
    /// <summary>
    /// Байгууллагын тамганы гэрчилгээний DER (CA <c>GET /seal/certificate/{orgEtsi}</c>-ийн <c>certificate</c>, эсвэл
    /// <c>POST /seal/{orgEtsi}</c>-ийн <c>cert.value</c>). Заавал; KeyUsage = зөвхөн nonRepudiation, EKU-гүй.
    /// </summary>
    public byte[] SealCert { get; init; } = Array.Empty<byte>();

    /// <summary>Олгогч гинж DER. <c>null</c> = шигтгэсэн eID гинжээс SealCert-ийн олгогчоор бүтээнэ.</summary>
    public IReadOnlyList<byte[]>? Chain { get; init; }

    /// <summary>PDF <c>/Reason</c> (≤ 127 UTF-16 нэгж, урт бол бичигдэхгүй).</summary>
    public string? Reason { get; init; }

    /// <summary>PDF <c>/M</c>. <c>null</c> = одоо. Үргэлж +08:00 бүсээр бичигдэнэ.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>PDF <c>/Name</c> (дардасны эхний мөр). <c>null</c>/хоосон = гэрчилгээний CN (байгууллагын нэр).</summary>
    public string? SignerName { get; init; }

    /// <summary>
    /// Дардасны байршил (иргэний харагдах гарын үсэгтэй ижил утга: Page, X, Y, Width, Height, Lang, Exact); буруу эсвэл
    /// багтахгүй бол REQUEST_INVALID, гаралт хэмжээнээс хэтэрвэл PDF_TOO_LARGE. <c>null</c> = автомат (APPEARANCE_SPEC.md
    /// §6.4): сүүлийн (eID verify биш) хуудасны баруун доод буланд ≤ <see cref="EidPades.SealStampWidth"/> ×
    /// <see cref="EidPades.SealStampHeight"/> pt (жижиг хуудсанд багтаана), Exact биш; дардас хуудсанд багтахгүй эсвэл гаралт
    /// хэмжээнээс хэтрэх бол үл харагдах тамга (<see cref="Completed.Placement"/> = <c>null</c>). <see cref="Invisible"/> үед
    /// үл тооно.
    /// </summary>
    public Appearance? Appearance { get; init; }

    /// <summary>Дардасгүй, үл харагдах тамга — харагдах дардас нэмэгдэхээс өмнөх <see cref="EidPades.SealAsync"/>-тэй байт-ижил.</summary>
    public bool Invisible { get; init; }
}

public static partial class EidPades
{
    /// <summary>Автомат тамганы дардасны дээд өргөн (pt) — APPEARANCE_SPEC.md §6.4: w = min(220, pageWidth − 8).</summary>
    public const double SealStampWidth = 220;

    /// <summary>Автомат тамганы дардасны дээд өндөр (pt) — APPEARANCE_SPEC.md §6.4: h = min(64, pageHeight − 8).</summary>
    public const double SealStampHeight = 64;

    /// <summary>
    /// Автомат тамганы дардасны захын зай (pt) — APPEARANCE_SPEC.md §6.4: x = pageWidth − w − min(36, (pageWidth − w) / 2),
    /// y = min(36, (pageHeight − h) / 2).
    /// </summary>
    public const double SealStampMargin = 36;

    /// <summary>
    /// Байгууллагын тамга (e-Seal): PDF-д байгууллагын тамганы гэрчилгээгээр PAdES-BASELINE-LT гарын үсэг суулгана. Иргэн,
    /// PIN, апп оролцохгүй — <paramref name="sealDigest"/> нь RP backend-ийн CA <c>POST /seal/{orgEtsi}</c> дуудлага
    /// (<c>digest</c> = base64(DTBS), <c>hashType</c> = <c>SHA256</c>) бөгөөд хариуны <c>signature.value</c>-ийн base64
    /// задласан байтыг (ECDSA DER) буцаана. Verify хуудас нэмэхгүй (тамгыг CA-ийн <c>/verify/{docId}</c>-д бүртгэдэггүй).
    /// Анхдагчаар байгууллагын тамганы дардас харагдана (<see cref="SealOptions.Appearance"/>, <see cref="SealOptions.Invisible"/>);
    /// эцсийн байршил <see cref="Completed.Placement"/>-д. RFC 3161 timestamp заавал (TSA хүрэхгүй бол TSA_UNAVAILABLE).
    /// Go SDK v0.30.0 / TS SDK 0.48.0-аас өмнөх шалгагчид харагдах тамганы дардастай PDF-ийн өмнөх гарын үсгүүдийг өөрчлөгдсөн
    /// (modified) гэж мэдээлнэ — тэдгээр шинэчлэгдэх хүртэл <see cref="SealOptions.Invisible"/> = <c>true</c> ашиглана уу.
    /// </summary>
    /// <param name="pdf">Оролтын PDF.</param>
    /// <param name="options">Тамганы гэрчилгээ, гинж, /Reason, /M, /Name, дардас.</param>
    /// <param name="sealDigest">(DTBS 32 байт, цуцлалт) → гарын үсэг. Түүний exception өөрчлөгдөхгүй дамжина.</param>
    /// <param name="complete"><see cref="CompleteAsync"/>-ийн сонголт; <c>null</c> = анхдагч.</param>
    /// <param name="cancellationToken">Цуцлалт.</param>
    /// <exception cref="EidPadesException">
    /// SIGNER_INVALID (тамганы гэрчилгээ биш), <see cref="Prepare"/>-ийн алдаа (өгсөн <see cref="SealOptions.Appearance"/>
    /// буруу/багтахгүй бол REQUEST_INVALID, PDF_TOO_LARGE), SIGNATURE_INVALID (гарын үсэг DTBS / SealCert-тэй таарахгүй),
    /// TSA_UNAVAILABLE, LTV_UNAVAILABLE, …
    /// </exception>
    public static async Task<Completed> SealAsync(byte[] pdf, SealOptions options, Func<byte[], CancellationToken, Task<byte[]>> sealDigest,
        CompleteOptions? complete = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(sealDigest);
        X509Certificate2 cert;
        try
        {
            cert = X509Util.Parse(options.SealCert ?? Array.Empty<byte>());
        }
        catch (FormatException e)
        {
            throw new EidPadesException("SIGNER_INVALID", "sealCert could not be parsed", e);
        }
        if (!IsSealCertificate(cert))
            throw new EidPadesException("SIGNER_INVALID", "sealCert is not an e-Seal certificate (keyUsage nonRepudiation only, no EKU)");
        var name = options.SignerName;
        if (string.IsNullOrWhiteSpace(name) || GoText.TrimSpace(name) == "") name = LastAttr(cert.SubjectName, "2.5.4.3");

        var po = new PrepareOptions
        {
            SignerCert = cert.RawData,
            Chain = options.Chain,
            SignerName = name,
            Reason = options.Reason,
            SigningTime = options.SigningTime,
            VerifyPage = false,
        };
        bool auto = false;
        if (!options.Invisible)
        {
            po = po with { Appearance = options.Appearance ?? DefaultSealAppearance(pdf) };
            auto = options.Appearance is null && po.Appearance is not null;
        }
        PreparedDocument prepared;
        try
        {
            prepared = Prepare(pdf, po);
        }
        catch (EidPadesException e) when (auto && e.RawCode is "REQUEST_INVALID" or "PDF_TOO_LARGE")
        {
            // Автомат дардас хуудсанд багтсангүй (бичвэр, хайрцаг), эсвэл дардасны ~82 KB фонтоор гаралт хэмжээнээс хэтэрсэн —
            // дуудагч юу ч хүсээгүй тул үл харагдах тамга (APPEARANCE_SPEC.md §6.4).
            prepared = Prepare(pdf, po with { Appearance = null });
        }
        var signature = await sealDigest(prepared.Dtbs, cancellationToken).ConfigureAwait(false)
                        ?? throw new EidPadesException("SIGNATURE_INVALID", "sealDigest returned no signature");
        var done = await CompleteAsync(prepared.State, signature, complete, cancellationToken).ConfigureAwait(false);
        return done with { Placement = prepared.Placement };
    }

    /// <summary>
    /// Go defaultSealAppearance — автомат дардас (APPEARANCE_SPEC.md §6.4): хуудсыг НЭГ удаа шийднэ (SuggestPlacement-ийн
    /// page 0 = сүүлийн eID verify биш хуудас, PLACEMENT_SPEC §1a, §6b) ба түүнийг Page-ээр тодорхой дамжуулна; тэр хуудасны
    /// харагдах хэмжээнд багтаасан баруун доод булан, Exact биш. Хуудсыг уншиж чадахгүй эсвэл 8 pt-оос нарийн/намхан бол
    /// <c>null</c> (үл харагдах тамга; жинхэнэ алдааг Prepare өөрөө буцаана).
    /// </summary>
    internal static Appearance? DefaultSealAppearance(byte[] pdf)
    {
        PlacementSuggestion s;
        try
        {
            s = SuggestPlacement(pdf, new Appearance { Width = 1, Height = 1 });
        }
        catch (EidPadesException)
        {
            return null;
        }
        const double gap = 4; // хуудасны ирмэгээс дардас хүртэл хамгийн бага зай (pt)
        double w = Math.Min(SealStampWidth, s.PageWidth - 2 * gap), h = Math.Min(SealStampHeight, s.PageHeight - 2 * gap);
        if (w <= 0 || h <= 0) return null;
        return new Appearance
        {
            Page = s.Page,
            X = s.PageWidth - w - Math.Min(SealStampMargin, (s.PageWidth - w) / 2),
            Y = Math.Min(SealStampMargin, (s.PageHeight - h) / 2),
            Width = w,
            Height = h,
        };
    }

    /// <summary>
    /// Go <c>eid.IsSealCertificate</c> = APPEARANCE_SPEC.md §6.1 (тамганы дардасны хувилбар ба SealAsync-ийн гэрчилгээний
    /// шалгалт): CA биш (basicConstraints алга эсвэл cA = FALSE); keyUsage байгаа, bit 1 (nonRepudiation) тавигдсан, bit 0
    /// (digitalSignature) тавигдаагүй (бусад бит үл тооно); EKU-ийн зорилго алга (extendedKeyUsage алга эсвэл хоосон
    /// дараалал; таньдаг/танихгүй ямар ч зорилго → биш). Задарч чадахгүй эсвэл давхардсан өргөтгөл → биш.
    /// </summary>
    internal static bool IsSealCertificate(X509Certificate2 c)
    {
        bool ku = false, seenBc = false, seenKu = false, seenEku = false;
        try
        {
            foreach (var e in c.Extensions)
            {
                switch (e.Oid?.Value)
                {
                    case "2.5.29.19":
                        if (seenBc || BasicConstraintsCa(e.RawData)) return false;
                        seenBc = true;
                        break;
                    case "2.5.29.15":
                        if (seenKu) return false;
                        seenKu = true;
                        ku = KeyUsageSeal(e.RawData);
                        break;
                    case "2.5.29.37":
                        if (seenEku || HasEkuPurpose(e.RawData)) return false;
                        seenEku = true;
                        break;
                }
            }
        }
        catch (Exception e) when (e is AsnContentException or CryptographicException)
        {
            return false;
        }
        return ku;
    }

    /// <summary>BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.</summary>
    private static bool BasicConstraintsCa(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var seq = r.ReadSequence();
        r.ThrowIfNotEmpty();
        bool ca = seq.HasData && seq.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && seq.ReadBoolean();
        if (seq.HasData) seq.ReadInteger();
        seq.ThrowIfNotEmpty();
        return ca;
    }

    /// <summary>KeyUsage ::= BIT STRING — bit 1 (nonRepudiation) тавигдсан, bit 0 (digitalSignature) тавигдаагүй.</summary>
    private static bool KeyUsageSeal(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var bits = r.ReadBitString(out _);
        r.ThrowIfNotEmpty();
        bool Bit(int i) => i / 8 < bits.Length && (bits[i / 8] & (0x80 >> (i % 8))) != 0;
        return Bit(1) && !Bit(0);
    }

    /// <summary>ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId — ядаж нэг зорилго байгаа эсэх.</summary>
    private static bool HasEkuPurpose(byte[] der)
    {
        var r = new AsnReader(der, AsnEncodingRules.DER);
        var seq = r.ReadSequence();
        r.ThrowIfNotEmpty();
        bool any = false;
        while (seq.HasData)
        {
            seq.ReadObjectIdentifier();
            any = true;
        }
        return any;
    }
}
