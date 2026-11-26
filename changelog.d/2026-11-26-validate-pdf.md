### Added — `EidPades.ValidatePdfAsync` (ValidatePDF)

- **Юу:** гарын үсэгтэй/тамгалсан PDF-ийг бүрэн шалгах `EidPades.ValidatePdfAsync(pdf, ValidatePdfOptions?, CancellationToken)`
  (Go `pades.ValidatePDF`, TS `validatePdf`, CA `/v3/validate/pdf`-тэй ижил дүрэм, ижил JSON тайлан — `PdfReport.ToJson()`):
  ByteRange/messageDigest, CMS гарын үсэг (RSA PKCS#1/PSS, ECDSA), signing-certificate-v2, гинж (өөрийн path builder,
  X509Chain биш), RFC 3161 цагийн тэмдэг, DSS-ийн OCSP/CRL ба онлайн OCSP/CRL (PAdES LTV-ийн 24 цагийн дүрэм), гарын үсгийн
  дараах revision-ийн ангилал (modified_after_signing, харагдах гарын үсэг/тамга APPEARANCE_SPEC §5/§6 — QR-тэй тамга §6.5
  оролцуулан), LTV, `signature_level`, `certificate_level`, `key_medium`. Нийтийн төрлүүд: `ValidatePdfOptions`, `PdfReport`,
  `SignatureReport`, `CertInfo`, `CertRevocation`, `TimestampInfo`, `LtvInfo`.
- **Яагаад:** .NET SDK-д TS/Go-той ижил хүрээтэй PDF шалгалт (SDK parity WP 7).
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/ValidatePdf.cs`, `Validation/*` (шинэ); `Pdf/SignatureAppearance.cs`
  (`sealQr` сонголт — бичигчийн гаралт өөрчлөгдөөгүй); `Pdf/PdfDocument.cs` (FlateDecode тайлалт 64 MiB-аар хязгаарлагдсан —
  TS reader-тэй ижил, халдагчийн zip bomb санах ойг дүүргэхгүй); корпус `testdata/pades-validate` (`build/sync-validate.sh`,
  `build/go-sdk-validate.ref` = Go v0.31.0, CI `validate-sync`).
- **Шалгасан:** корпусын бүх тохиолдол (Go-ийн тайлантай deep-equal), SHA256SUMS, зорилтот сөрөг/fuzz тест — PR CI (windows +
  ubuntu).
