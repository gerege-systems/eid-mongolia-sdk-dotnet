using System;

namespace GeregeSystems.EidMongolia.Pades
{
    /// <summary>Тогтвортой алдааны кодууд (Go reference <c>pades.Code*</c>-тэй 1:1).</summary>
    public enum EidPadesErrorCode
    {
        /// <summary>Танихгүй код (шинэ профайл). <see cref="EidPadesException.RawCode"/>-г үз.</summary>
        Unknown = 0,
        /// <summary>PDF_INVALID</summary>
        PdfInvalid,
        /// <summary>PDF_ENCRYPTED</summary>
        PdfEncrypted,
        /// <summary>PDF_LOCKED — DocMDP P=1.</summary>
        PdfLocked,
        /// <summary>PDF_TOO_LARGE</summary>
        PdfTooLarge,
        /// <summary>SIGNATURE_INVALID</summary>
        SignatureInvalid,
        /// <summary>TSA_UNAVAILABLE</summary>
        TsaUnavailable,
        /// <summary>LTV_UNAVAILABLE</summary>
        LtvUnavailable,
        /// <summary>SELF_VALIDATION_FAILED</summary>
        SelfValidationFailed,
        /// <summary>PLACEHOLDER_OVERFLOW</summary>
        PlaceholderOverflow,
        /// <summary>STATE_INVALID</summary>
        StateInvalid,
        /// <summary>PDF_TOO_MANY_SIGNATURES</summary>
        PdfTooManySignatures,
        /// <summary>PDF_PRIOR_SIGNATURE_INVALID</summary>
        PdfPriorSignatureInvalid,
        /// <summary>PDF_FOREIGN_SIGNATURE — өмнөх гарын үсэг eID-ийн хүчинтэй B-LT биш.</summary>
        PdfForeignSignature,
        /// <summary>SIGNER_INVALID — signerCert / гинж.</summary>
        SignerInvalid,
        /// <summary>REQUEST_INVALID — сонголт буруу (docId, lang, fileName, roots…).</summary>
        RequestInvalid,
        /// <summary>INTERNAL — дотоод алдаа.</summary>
        Internal,
    }

    /// <summary>
    /// <see cref="EidPades.CompleteAsync"/>: OCSP/CRL-ийн (олгогчийн гарын үсэгтэй) хариугаар гинжийн гэрчилгээ цуцлагдсан.
    /// <c>LTV_UNAVAILABLE</c>-ийн <see cref="Exception.InnerException"/> болж ирнэ — дахин оролдох утгагүй (Go
    /// <c>pades.ErrCertificateRevoked</c>, TS <c>CertificateRevokedError</c>). Мессежид гэрчилгээний serial (нэр биш).
    /// </summary>
    public sealed class CertificateRevokedException : Exception
    {
        /// <summary>Шинэ алдаа; <paramref name="certRef"/> — гэрчилгээний serial.</summary>
        public CertificateRevokedException(string certRef) : base("certificate revoked: " + certRef) { }
    }

    /// <summary>eID PAdES алдаа. <see cref="Code"/> тогтвортой — үүгээр салаална; <see cref="Exception.Message"/> зөвхөн лог/хүнд.</summary>
    public sealed class EidPadesException : Exception
    {
        /// <summary>Тогтвортой код.</summary>
        public EidPadesErrorCode Code { get; }

        /// <summary>Түүхий код (жишээ нь <c>PDF_INVALID</c>).</summary>
        public string RawCode { get; }

        /// <summary>Шинэ алдаа.</summary>
        public EidPadesException(string rawCode, string message, Exception? inner = null)
            : base(string.IsNullOrEmpty(message) ? rawCode : rawCode + ": " + message, inner)
        {
            RawCode = rawCode ?? "";
            Code = Parse(RawCode);
        }

        internal static EidPadesErrorCode Parse(string raw)
        {
            switch (raw)
            {
                case "PDF_INVALID": return EidPadesErrorCode.PdfInvalid;
                case "PDF_ENCRYPTED": return EidPadesErrorCode.PdfEncrypted;
                case "PDF_LOCKED": return EidPadesErrorCode.PdfLocked;
                case "PDF_TOO_LARGE": return EidPadesErrorCode.PdfTooLarge;
                case "SIGNATURE_INVALID": return EidPadesErrorCode.SignatureInvalid;
                case "TSA_UNAVAILABLE": return EidPadesErrorCode.TsaUnavailable;
                case "LTV_UNAVAILABLE": return EidPadesErrorCode.LtvUnavailable;
                case "SELF_VALIDATION_FAILED": return EidPadesErrorCode.SelfValidationFailed;
                case "PLACEHOLDER_OVERFLOW": return EidPadesErrorCode.PlaceholderOverflow;
                case "STATE_INVALID": return EidPadesErrorCode.StateInvalid;
                case "PDF_TOO_MANY_SIGNATURES": return EidPadesErrorCode.PdfTooManySignatures;
                case "PDF_PRIOR_SIGNATURE_INVALID": return EidPadesErrorCode.PdfPriorSignatureInvalid;
                case "PDF_FOREIGN_SIGNATURE": return EidPadesErrorCode.PdfForeignSignature;
                case "SIGNER_INVALID": return EidPadesErrorCode.SignerInvalid;
                case "REQUEST_INVALID": return EidPadesErrorCode.RequestInvalid;
                case "INTERNAL": return EidPadesErrorCode.Internal;
                default: return EidPadesErrorCode.Unknown;
            }
        }
    }
}
