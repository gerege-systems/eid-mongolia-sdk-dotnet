# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

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
