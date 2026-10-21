# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

## 0.8.0 — 2026-10-21

### Tests — pades golden v8 (verify page chain with non-zero object generations)

- **Юу:** golden-ийг eid-mongolia-sdk-go #40 (`21f8434`, `pades-golden-v8`) руу бэхэлсэн: `input/verify-gen1.pdf`
  (verify хуудас `6 1 obj`, docId Link `7 1 obj`, URI action `8 2 obj`) ба кейс `verify-gen1`, `page0-verify-gen1`,
  `page-explicit-verify-gen1`.
- **Яагаад:** PLACEMENT_SPEC §1a «Object generations» — docId-ийг xref-ийн бодит generation-оор уншина (Swift port 0 гэж
  таамагладаг байсныг CA репод зассан). .NET аль хэдийн зөв — кодын өөрчлөлтгүй.
- **Хаана:** `build/go-sdk.ref`, `testdata/golden/`.
- **Шалгасан:** `build/sync-golden.sh --check`; `dotnet test` — 182/182 (шинэ 3 `MatchesGoReference` кейс байт-ижил).

### Added — `PrepareOptions.VerifyPagePosition` ("last" | "first"), golden v9

- **Юу:** `VerifyPagePosition = "first"` — шалгах (QR) хуудас үндсэн `/Pages /Kids`-ийн эхэнд орж 1-р хуудас болно; анхдагч
  `"last"` (null/хоосон) өмнөхтэй байт-ижил; бусад утга `REQUEST_INVALID`. `Appearance.Page`, `SuggestPlacement`,
  `Placement.Page` оролтын PDF-ийн хуудсаар (SDK дотроо +1 болгож зурна).
- **Яагаад:** портал/desktop-ийн «Баталгаажуулалтын хуудсыг эхэнд» сонголт; Go v0.15.0 (#41), PAGE_SPEC §8a, PLACEMENT_SPEC §1b.
- **Хаана:** `Models.cs`, `EidPades.cs`, `Pdf/VerifyPage.cs`; `GoldenTests.cs` (manifest-ийн түлхүүр); `build/go-sdk.ref` →
  Go `9e76888` (`pades-golden-v9`), `testdata/golden/`.
- **Шалгасан:** CI (Windows + Linux `dotnet test`, golden-sync) — v9-ийн 8 `vpfirst-*` кейс Go-той байт-ижил.

## 0.7.0 — 2026-10-21

### Added — `Appearance.Exact` and `EidPades.SuggestPlacement` (golden v7)

- **What:** port of Go `eid-mongolia-sdk-go` #39 (247c964, v0.14.0, PLACEMENT_SPEC.md §6a/§6b).
  - `Appearance.Exact` (bool, default `false`): the stamp is drawn exactly at `Page/X/Y/Width/Height` and never moved.
    The rect must lie inside the page (`REQUEST_INVALID` otherwise, as before). The page is still scanned: `Placement.Status`
    = `Requested` when the rect (+4 pt) is free, `Overlap` when not, `Unscanned` when the scan fails; never `Moved`.
    `Exact = false` is byte-identical to golden v6.
  - `EidPades.SuggestPlacement(byte[] pdf, Appearance appearance)` → `PlacementSuggestion` (`Page`, `X`, `Y`, `Width`,
    `Height`, `Status`, `PageWidth`, `PageHeight`, `PageCount`, `Pages` = `IReadOnlyList<PageSize>`; pt): Prepare's
    placement without a certificate, signing or network. Checks in order: `PDF_TOO_LARGE` → `PDF_INVALID` (header,
    structure) → `REQUEST_INVALID` (values) → `PDF_ENCRYPTED` → `PDF_INVALID` (signature scan) → `REQUEST_INVALID` (page >
    count, geometry, rect outside the page). Page 0 on a signed document skips the verify pages of the docId read from its
    verify-page link; an unsigned document skips nothing (last page).
- **Why:** the portal and eid-desktop let the citizen preview the PDF and place the stamp themselves.
- **Where:** `Models.cs` (`Appearance.Exact`, `PlacementSuggestion`, `PageSize`), `EidPades.cs` (`SuggestPlacement`,
  `VisibleSpec`), `Pdf/Placement.cs` (`Choose(…, exact)` = Go `PlaceOnPage`), `Pdf/SignatureAppearance.cs` (`PageList`,
  `Suggest` = Go `SuggestVisible`), `Pdf/SignatureRevision.cs`; golden pin `build/go-sdk.ref` → 247c964 (golden v7: 5
  `exact-*` cases, `expect.suggestion` on every visible case, `suggestionError` on `exact-out-of-bounds`).
- **Verified:** `dotnet test` 179/179 locally (macOS arm64, .NET 8.0.426) — all 33 golden cases byte-identical incl. the
  5 new `exact-*` cases, `expect.suggestion` field-for-field on every visible case, suggestion ⊇ placement (except
  `page0-two-verify`); `ErrorTests.SuggestPlacement*` (Go `TestSuggestPlacementErrors`); CI Windows + Linux.

## 0.6.0 — 2026-10-20

### Fixed — `Registration`: medium ба claimedRole-ийг CA-аас өмнө шалгана

- **Юу:** `EidPades.Registration` — `Medium` хоосон бол `SessionId`-ээс тооцсоор (phone ⇔ sessionId); `phone` +
  `SessionId`-гүй, `token` + `SessionId`, бусад `Medium` утга → `REQUEST_INVALID`. `Completed.ClaimedRole` (шинэ;
  state-ээс) байхад `RegistrationOptions.OnBehalfOf` хоосон бол `REQUEST_INVALID`.
- **Яагаад:** 2026-10-20-ны SDK аудит — таван SDK (TS, Go, .NET, Swift, Kotlin) нэг дүрмээр; CA эдгээрийг хожим 400-аар
  татгалздаг байсан.
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/Registration.cs`, `Models.cs` (`Completed.ClaimedRole`), `EidPades.cs`,
  `README.md`; тест `ErrorTests.cs` (medium, claimedRole, RSASSA-PSS → `SIGNATURE_INVALID`), `GoldenTests.cs`.
- **Шалгасан:** CI `dotnet test` (Windows + Linux).

### Docs — README / XML doc нь 0.5.0-ийн API-тай нийцэв

- **Юу:** README-ийн жишээнд `using System.Text.Json;` дутуу байсан (`JsonSerializer` compile болдоггүй); `ClaimedRole`
  тавьсан жишээ `RegistrationOptions.OnBehalfOf`-гүй байсан (CA-д заавал). Алдааны хүснэгтэд `Internal` / `INTERNAL`
  нэмэв; `PDF_INVALID`-ийн бүтцийн хязгаарыг PRECHECKS #2a/#2b-тэй тулгав (`/Extends` > 64). XML doc:
  `PrepareOptions.Lang` хоосон = `mn`.
- **Яагаад:** Swift/Kotlin/Go баримттай нийцүүлэх аудит (2026-10-20); код өөрчлөгдөөгүй.
- **Хаана:** `README.md`, `src/GeregeSystems.EidMongolia.Pades/Models.cs` (зөвхөн `///`).
- **Шалгасан:** README-ийн урсгалын жишээг scratch console төсөлд (`ProjectReference` → src) `dotnet build` — алдаагүй;
  засвараас өмнө `CS0103 JsonSerializer`.

## 0.5.0 — 2026-10-19

### Changed — `Appearance.Page` 0 = the last page that is not an eID verify page (golden v6)

- **What:** port of Go `eid-mongolia-sdk-go` #35 (874ae48, PLACEMENT_SPEC.md §1a). `Page` 0 now skips the eID verify
  pages added by earlier revisions (as the verify page this Prepare adds was already not counted): pages are taken in
  `/Pages` tree order and scanned from the last; a verify page is one whose `/Annots` has a `/Subtype /Link` with
  `/A << /S /URI /URI (https://ca.eidmongolia.mn/verify/<docId>) >>` byte-equal to this document's docId — no text
  recognition; anything doubtful (another docId, a `/rev` suffix, unreadable) is a content page. Every page a verify page
  → the last page. An explicit `Page` 1…N is unchanged. `SignatureAppearance.DefaultStampPage` / `IsVerifyPage`.
- **Why:** the portal passes `page: 0` for the second signer — the stamp landed on the first signature's verify page.
- **Where:** `Pdf/SignatureAppearance.cs`, `EidPades.cs` (`VisibleSpec`), `Models.cs` (XML doc), README; golden pin
  `build/go-sdk.ref` → 874ae48 (golden v6: +5 cases, `input/two-verify.pdf`, `input/fake-verify.pdf`, `http/28…32`);
  `PlacementTests.DefaultStampPage*`.
- **Verified:** CI (Windows + Linux) — golden v6 byte-identical incl. the 5 new cases; v5 cases unchanged.


## 0.4.0 — 2026-10-19

### Changed — the visible stamp avoids existing page content (PLACEMENT_SPEC.md)

- **What:** port of Go `eid-mongolia-sdk-go` b5c1fdc (#33). `Appearance.X/Y` is now the preferred spot: before the
  widget is written the target page is scanned (content-stream text, paths, images, form XObjects, inline images,
  annotation `/Rect`s — no rendering, no font programs) and, when the requested rect (+4 pt) overlaps something, the
  stamp moves to the first free candidate (mirrored column, then up in 12 pt steps). New
  `PreparedDocument.Placement` (`Page, X, Y, Width, Height, Status`; `PlacementStatus` = `Requested | Moved | Overlap |
  Unscanned`, JSON lowercase like Go).
- **Why:** prod 2026-10-19 — on a LibreOffice-converted contract the stamp covered the last-page footer.
- **Where:** `Pdf/Occupancy.cs` (scanner, §2–§5), `Pdf/Placement.cs` (candidates, §6), `Pdf/ZlibStrict.cs` (strict
  zlib: header, Adler-32, truncation — `ZLibStream` silently accepts truncated streams), `Pdf/SignatureRevision.cs`,
  `Models.cs`, `EidPades.cs`; golden pin `build/go-sdk.ref` → 4e87dc1 (#34: golden v5 + `placement/`, 29 vector).
- **Verified:** `dotnet test` — all 21 `placement/vectors.json` vectors box-for-box, the 6 golden v5 cases and every
  existing golden case byte-identical with `expect.placement`; robustness tests on arbitrary/malformed content and
  Flate streams; `dotnet format --verify-no-changes`; `sync-golden.sh --check`.
- **Remaining:** release (version bump) — not part of this change.

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
