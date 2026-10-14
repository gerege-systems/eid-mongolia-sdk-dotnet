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
