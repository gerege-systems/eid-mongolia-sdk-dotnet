# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

## 0.3.0 — 2026-10-19

### Added — `Completed.FileName`, `EidPades.Registration` (CA бүртгэлийн бие) (0.3.0)

- **Юу:** `Prepare`-ийн цэвэрлэсэн `fileName` state-ээр (`"fileName"`, Go state-тэй ижил түлхүүр) дамжиж
  `Completed.FileName`-д ирнэ. `EidPades.Registration(done, RegistrationOptions)` → `SignatureRegistration` —
  CA `POST /pdf/signatures`-ийн бие (JSON талбарын нэр CA DTO-тэй яг ижил; `System.Text.Json`-оор шууд сериализ): өмнөх
  гарын үсгүүд зөвхөн `priorCmsSha256`-аар, хос түлхүүр нь `PriorSignatures`-д (`[JsonIgnore]`); `medium` анхдагч =
  `SessionId` байвал phone, эс бөгөөс token; `signerEtsi` = гэрчилгээний SERIALNUMBER; эхний гарын үсэг хуудасгүй эсвэл
  fileName хоосон → `REQUEST_INVALID`. Go `pades.Registration`, TS `registrationFromCompleted`-тэй ижил хэлбэр.
- **Яагаад:** 10-15 аудит («Native PAdES»): .NET-ийн `Completed`-д fileName байгаагүй, `PriorCmsSha256` ба
  `PriorRevisionSha256` хоёулаа бүтэн ирдэг тул апп хоёуланг нь CA руу дамжуулахад 400 болдог.
- **Хаана:** `Registration.cs` (шинэ), `Models.cs`, `State.cs`, `EidPades.cs` (partial); README «Урсгал» алхам 4.
- **Шалгасан:** golden тест бүрд `Completed.FileName` = цэвэрлэсэн нэр, `Registration`-ийн JSON-д `priorRevisionSha256`
  алга, `PriorSignatures` = өмнөх кейсийн `sigRevSha256`, `signerEtsi`.
- **Үлдсэн:** 409 `PRIOR_MISMATCH`-ийн дахин оролдлого — .NET-д CA HTTP клиент байхгүй тул дуудагч (README-д заасан).

- **Release: nuget.org-д нийтэлнэ (Trusted Publishing).**
  - Юу: `release.yml` — `v*` tag дээр `GeregeSystems.EidMongolia.Pades` багцыг GitHub Release + GitHub Packages-аас гадна
    nuget.org-д push хийнэ; `NuGet/login@v1` (OIDC, `id-token: write`) богино хугацааны key авдаг тул repo secret хэрэггүй.
  - Яагаад: `dotnet add package GeregeSystems.EidMongolia.Pades` шууд ажиллахгүй байсан (зөвхөн GitHub Release `.nupkg`).
  - Хаана: nuget.org Trusted Publishing бодлого — эзэн `geregecore`, glob `GeregeSystems.EidMongolia.*`, workflow `release.yml`.
  - Шалгасан: workflow синтакс; бодит push дараагийн tag (0.3.0) дээр.

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

## 0.2.0 — 2026-10-15

- **PAdES: харагдах гарын үсэг (сонголттой), `Completed.PriorRevisionSha256` + golden v3.**
  - Юу: `PrepareOptions.Appearance` (`Appearance { Page, X, Y, Width, Height, Lang }`) — сонгосон хуудсан дээр `/Rect`-тэй
    widget (`/F 4`, `/P`, `/Annots`-ийн төгсгөлд), `/AP /N` шахалтгүй form XObject (verify хуудасны Noto Sans фонт, өөрийн
    QR `https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`, нэр/үүрэг/label/огноо, `/Rotate` 0/90/180/270-ийг content
    `cm`-ээр). `null` бол үл харагдах — golden v2-тэй байт-ижил. Байршил/хэмжээ/хуудас буруу, бичвэр багтахгүй, docId-гүй
    гарын үсэгтэй баримт → `REQUEST_INVALID`. `Completed.PriorRevisionSha256` — өмнөх гарын үсэг бүрийн revision-ий
    SHA-256 (`PriorCmsSha256`-тэй ижил дараалал; Go `PriorRevisionSHA256`). Энэ SDK-д CA register клиент байхгүй тул
    PRIOR_MISMATCH retry хамаарахгүй.
  - Яагаад: Go reference (`eid-mongolia-sdk-go` `pades-golden-v3` = 55bcb0a, `pades/APPEARANCE_SPEC.md`)-тэй native SDK
    бүр байт-ижил.
  - Хаана: `Pdf/SignatureAppearance.cs` (шинэ, Go `core/appearance.go`-ийн 1:1 порт), `Pdf/SignatureRevision.cs` (харагдах
    салаа), `Pdf/VerifyPage.cs` (`FontBodies`, `WrapLimit`, `GlyphHex` гаргасан — verify хуудасны байт өөрчлөгдөөгүй),
    `EidPades.cs` (`CheckAppearance`, `VisibleSpec`, prior revision), `Models.cs`; `build/go-sdk.ref` → 55bcb0a,
    `testdata/golden` дахин синк. `ErrorTests.EcdsaSignatureFormatsAreAccepted`-ийн CA/leaf хугацааны race (UtcNow хоёр
    удаа) засав.
  - Шалгасан: `dotnet test` — golden v3-ийн 17 кейс бүгд (харагдах 5 орно) гаралтын PDF бүхэлдээ Go-тэй байт-ижил,
    `PriorRevisionSha256` = өмнөх кейсийн `sigRevSha256`; Go `TestAppearanceRejects`-ийн толь (13 + 45 pt хамгийн бага,
    docId-гүй баримт); `dotnet format --verify-no-changes`; `sync-golden.sh --check`.

## 0.1.0 — 2026-10-14

- **Анхны хувилбар — `GeregeSystems.EidMongolia.Pades` (net8.0), native C# client-side PAdES** (профайл `pades-client/1`).
  Яагаад: PDF клиентээс гарахгүй (Smart-ID загвар); хэрэглэгчийн шийдвэрээр (2026-10-14) Go цөмийг DLL/WASM-аар түгээхгүй,
  платформ бүр өөрийн native SDK + нийтлэг conformance suite.
- `EidPades.Prepare` (PRECHECKS → bilingual verify хуудас (PAGE_SPEC, QR, Noto Sans subset) → гарын үсгийн revision →
  signedAttrs/DTBS → Go-тэй ижил формат state) ба `EidPades.CompleteAsync` (DTBS дээрх RSA/ECDSA шалгалт → RFC 3161 TSA
  → CMS → embed → OCSP/CRL (genTime-ийн дараа, үндэсний CRL толин) → шахалтгүй DSS revision → хөнгөн self-check) →
  `Completed` (CA `POST /pdf/signatures`-ийн мета). Validator-гүй. `EidPadesException` тогтвортой `Code`-той.
- Хаана: `src/GeregeSystems.EidMongolia.Pades/{Pdf,Crypto}`, golden `testdata/golden` (`build/sync-golden.sh`,
  eid-mongolia-sdk-go `pades-golden-v2` = `build/go-sdk.ref`). CI: Windows + Linux тест, `golden-sync`, `changelog`;
  release: `v*` tag → GitHub Release asset + GitHub Packages.
- Шалгасан: golden 12 тохиолдол (verify хуудас mn/en, xref table/stream/linearized, 2 дахь гарын үсэг, foreign,
  encrypted) — гаралтын PDF бүхэлдээ Go-тэй байт-ижил; eid-desktop (Swift) golden; алдааны замууд; ECDSA r‖s/DER.
