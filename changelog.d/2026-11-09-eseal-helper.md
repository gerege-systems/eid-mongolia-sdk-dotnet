### Added — байгууллагын тамга (e-Seal): `EidPades.SealAsync`

- **Юу:** `EidPades.SealAsync(pdf, SealOptions, sealDigest, CompleteOptions?, ct)` → `Completed`. `SealOptions`: `SealCert`
  (заавал), `Chain`, `Reason`, `SigningTime`, `SignerName` (анхдагч = гэрчилгээний CN). Урсгал: гэрчилгээ тамганы
  профайл эсэх (KeyUsage nonRepudiation, digitalSignature үгүй, EKU үгүй — validator-ийн «seal»; үгүй бол
  `SIGNER_INVALID`) → `Prepare` (verify хуудас, харагдах дүрслэлгүй) → `sealDigest(DTBS)` (RP-ийн өөрийн CA
  `POST /seal/{orgEtsi}` дуудлага, `signature.value`) → `CompleteAsync` (TSA заавал → PAdES-BASELINE-LT). Буруу гарын
  үсэг `SIGNATURE_INVALID`; delegate-ийн exception өөрчлөгдөхгүй дамжина. SDK-д HTTP client нэмээгүй.
- **Яагаад:** CA-ийн e-Seal API (`GET /seal/certificate/{orgEtsi}`, `POST /seal/{orgEtsi}`)-г .NET RP-ууд PAdES-д
  шууд ашиглах.
- **Хаана:** `src/…/Seal.cs`, `tests/…/SealTests.cs` (+ `RevocationTests`-ийн OCSP туслахууд internal),
  `testdata/seal_response.json`, README «Байгууллагын тамга (e-Seal)».
- **Шалгасан:** CI `dotnet test` (Windows + Linux): тест 04-өөр олгосон ECDSA P-256 тамга + fake RFC 3161 TSA + OCSP →
  B-LT (timestamp, /DSS, CMS шалгалт); digitalSignature-тэй гэрчилгээ → `SIGNER_INVALID`; өөр түлхүүрийн гарын үсэг →
  `SIGNATURE_INVALID`; delegate-ийн exception дамжина; CA хариуны дээжийн `signature.value` нь digest дээр шалгагдана.
