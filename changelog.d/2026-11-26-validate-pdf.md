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

### Fixed — халдагчийн PDF-ийн DoS (PR #51 review; Prepare/Seal-д ч хамаарна)

- `Pdf/Structure.cs`: Go 900de73 (v0.21.1)-ийн порт — тайлбар/мөр дэх `/Encrypt` бичвэр ObjStm-ийн шалгалтыг унтраахгүй;
  `/Filter [/FlateDecode /FlateDecode]` (2+ шүүлтүүр) → бүтцийн алдаа; давхар/`null` `/Filter` — сүүлийнх нь (уншигчтай ижил).
- `Pdf/Lexer.cs`: ReadObject/ReadArray/ReadDict-ийн рекурсын гүн ≤ 512 → `PdfFormatException` (PDF_INVALID), StackOverflow биш.
- `Pdf/PdfDocument.cs`: ObjStm-ийн `/N` давталт өгөгдлийн төгсгөлд зогсоно; xref `/Prev` гинж ≤ 128; нэг нээлтэд FlateDecode
  нийт ≤ 256 MiB; xref stream / ObjStm-д олон шүүлтүүр хориотой.
- ValidatePdf: CMS-д ≤ 32 гэрчилгээ, гэрчилгээний pool хэшээр; RSA ≤ 8192 бит, e ≤ 2^32−1; RSA-PSS SHA-1 татгалзана (Go-тэй
  ижил); гэрчилгээний нэрийг задлалтад шалгана (гэмтсэн бол тэр гарын үсэг `malformed_signature`); DSS-ийн нийт ≤ 8 MiB,
  объектын давхардалгүй, OCSP/CRL-ийг баримтад нэг удаа шалгана; задлах үе шатны бүх алдаа PDF_INVALID (OOM ба цуцлалтыг
  дамжуулна); бүтцийн шалгалт ба revision-ийн шинжилгээ CancellationToken-ийг дагана; `platform_attested` зөвхөн
  өөрчлөгдөөгүй баримтад (Go/TS-д мөн оруулах санал).
