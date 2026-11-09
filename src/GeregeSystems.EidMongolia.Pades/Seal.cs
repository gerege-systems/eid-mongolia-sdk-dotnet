using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary><see cref="EidPades.SealAsync"/>-ийн сонголт — байгууллагын тамга (e-Seal).</summary>
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

    /// <summary>PDF <c>/Name</c>. <c>null</c>/хоосон = гэрчилгээний CN (байгууллагын нэр).</summary>
    public string? SignerName { get; init; }
}

public static partial class EidPades
{
    /// <summary>
    /// Байгууллагын тамга (e-Seal): PDF-д байгууллагын тамганы гэрчилгээгээр PAdES-BASELINE-LT гарын үсэг суулгана. Иргэн,
    /// PIN, апп оролцохгүй — <paramref name="sealDigest"/> нь RP backend-ийн CA <c>POST /seal/{orgEtsi}</c> дуудлага
    /// (<c>digest</c> = base64(DTBS), <c>hashType</c> = <c>SHA256</c>) бөгөөд хариуны <c>signature.value</c>-ийн base64
    /// задласан байтыг (ECDSA DER) буцаана. Verify хуудас, харагдах дүрслэл нэмэхгүй (тамгыг CA-ийн <c>/verify/{docId}</c>-д
    /// бүртгэдэггүй). RFC 3161 timestamp заавал (TSA хүрэхгүй бол TSA_UNAVAILABLE).
    /// </summary>
    /// <param name="pdf">Оролтын PDF.</param>
    /// <param name="options">Тамганы гэрчилгээ, гинж, /Reason, /M, /Name.</param>
    /// <param name="sealDigest">(DTBS 32 байт, цуцлалт) → гарын үсэг. Түүний exception өөрчлөгдөхгүй дамжина.</param>
    /// <param name="complete"><see cref="CompleteAsync"/>-ийн сонголт; <c>null</c> = анхдагч.</param>
    /// <param name="cancellationToken">Цуцлалт.</param>
    /// <exception cref="EidPadesException">
    /// SIGNER_INVALID (тамганы гэрчилгээ биш), <see cref="Prepare"/>-ийн алдаа, SIGNATURE_INVALID (гарын үсэг DTBS /
    /// SealCert-тэй таарахгүй), TSA_UNAVAILABLE, LTV_UNAVAILABLE, …
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
        if (!IsSealCert(cert))
            throw new EidPadesException("SIGNER_INVALID", "sealCert is not an e-Seal certificate (keyUsage nonRepudiation only, no EKU)");
        var name = options.SignerName;
        if (string.IsNullOrWhiteSpace(name) || GoText.TrimSpace(name) == "") name = LastAttr(cert.SubjectName, "2.5.4.3");

        var prepared = Prepare(pdf, new PrepareOptions
        {
            SignerCert = cert.RawData,
            Chain = options.Chain,
            SignerName = name,
            Reason = options.Reason,
            SigningTime = options.SigningTime,
            VerifyPage = false,
        });
        var signature = await sealDigest(prepared.Dtbs, cancellationToken).ConfigureAwait(false)
                        ?? throw new EidPadesException("SIGNATURE_INVALID", "sealDigest returned no signature");
        return await CompleteAsync(prepared.State, signature, complete, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Validator-ийн «seal» хэрэглээ (Go certUsage): KeyUsage-д nonRepudiation байгаа, digitalSignature үгүй, EKU үгүй.</summary>
    internal static bool IsSealCert(X509Certificate2 c)
    {
        X509KeyUsageExtension? ku = null;
        foreach (var e in c.Extensions)
        {
            if (e.Oid?.Value == "2.5.29.37") return false;
            if (e is X509KeyUsageExtension k) ku = k;
        }
        return ku is not null && (ku.KeyUsages & X509KeyUsageFlags.NonRepudiation) != 0 &&
               (ku.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0;
    }
}
