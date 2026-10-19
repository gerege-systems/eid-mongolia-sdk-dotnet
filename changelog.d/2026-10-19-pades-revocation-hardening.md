### Security — `CompleteAsync`: OCSP/CRL тохирол ба шинэлэг байдал, revoked = хатуу алдаа; `Prepare`: бүтцийн урьдчилсан шалгалт (0.3.0)

- **Юу (зан төлөвийн өөрчлөлт — аюулгүй байдлын засвар; Go SDK v0.8.0 / TS 0.21.0-ийн порт):**
  - `CompleteAsync` (LTV цуглуулалт): OCSP хариу нь ЭНЭ гэрчилгээнийх — CertID = олгогчийн нэр/түлхүүрийн hash + serial
    (өмнө нь зөвхөн serial). CRL нь гэрчилгээний олгогчийнх — нэр = cert.Issuer = issuer.Subject, AKI = олгогчийн SKI,
    олгогчийн гарын үсэг. «good» нотолгоо одоо шинэлэг: thisUpdate ≤ одоо + 5 мин, nextUpdate ≥ одоо − 5 мин,
    thisUpdate ≥ одоо − 24 ц эсвэл [thisUpdate, nextUpdate] нь одоог хамарна (`Revocation.FreshAt`).
  - OCSP «revoked» эсвэл гэрчилгээг агуулсан CRL → тэр дор нь `LTV_UNAVAILABLE`, `InnerException` =
    `CertificateRevokedException` (шинэ public төрөл), дахин оролдохгүй. Өмнө нь revoked OCSP-г ерөнхий алдаа гэж алгасаад
    цэвэр CRL-ээр (эсвэл CRL хоосон) DSS угсарч **амжилттай** дуусдаг байв (10-15 SDK аудит).
  - `Prepare`: задлахаас өмнө PRECHECKS #2a/#2b — массив/толийн давхарлалт > 256, ObjStm өөрийгөө/харилцан агуулах, толгойн
    лавлагаа ObjStm руу, `/Extends` мөчлөг эсвэл > 64, `/Size` > 2^21 → `PDF_INVALID` (`CompleteAsync`-д state-ийн PDF →
    `STATE_INVALID`). Өмнө нь ийм баримт задлагчийн рекурсээр `StackOverflowException` өгч процессыг бүхэлд нь унагадаг
    байв (catch барихгүй).
  - PRECHECKS #4: `/Encrypt << … >>` шууд толь (уншигч нээж чадахгүй үед) → `PDF_ENCRYPTED` (өмнө нь `PDF_INVALID`).
  - LTV алдааны мессежээс гэрчилгээний subject (иргэний нэр — PII) хасагдаж serial-аар солигдсон.
- **Яагаад:** 10-15 SDK аудитын олдвор (fail-open цуцлалт, гүн рекурс) — Go/TS-тэй ижил дүрэм.
- **Хаана:** `Crypto/Revocation.cs` (шинэ: `FreshAt`, `CrlFor`, `CrlListed`, `OcspCertIdMatches`, `CertRef`),
  `Crypto/Ltv.cs`, `Crypto/X509Util.cs` (`Crl.ThisUpdate`, `AuthorityKeyId`), `Pdf/Structure.cs` (шинэ: Go
  `CheckStructure` + `checkObjStmGraph`), `Prechecks.cs`, `EidPades.cs`, `EidPadesException.cs`
  (`CertificateRevokedException`); `build/go-sdk.ref` → Go v0.8.0 (0fe194c), `testdata/golden` дахин синк (зөвхөн README
  өөрчлөгдсөн — prepare/complete-ийн гаралт v3-тай байт-ижил); `testdata/structure/` (Go/TS-ийн сөрөг оролт).
- **Шалгасан:** `dotnet test` (79: golden 17 кейс Go-тэй байт-ижил; `RevocationTests` — stale/expired/future/өөр CertID/өөр
  serial OCSP, өөр олгогч/stale/future CRL, revoked OCSP + цэвэр CRL, good OCSP + revoked CRL, Complete → LTV_UNAVAILABLE +
  CertificateRevokedException, мессежид нэр алга; `StructureTests` — давхарлалт 256/257/100 000, ObjStm мөчлөг/`/Length`,
  `/Size`, fuzz seed, `deep-nesting*.pdf`, `/Encrypt` шууд толь); `dotnet format --verify-no-changes`;
  `sync-golden.sh --check`.
