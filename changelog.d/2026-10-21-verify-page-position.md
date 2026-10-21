### Added — `PrepareOptions.VerifyPagePosition` ("last" | "first"), golden v9

- **Юу:** `VerifyPagePosition = "first"` — шалгах (QR) хуудас үндсэн `/Pages /Kids`-ийн эхэнд орж 1-р хуудас болно; анхдагч
  `"last"` (null/хоосон) өмнөхтэй байт-ижил; бусад утга `REQUEST_INVALID`. `Appearance.Page`, `SuggestPlacement`,
  `Placement.Page` оролтын PDF-ийн хуудсаар (SDK дотроо +1 болгож зурна).
- **Яагаад:** портал/desktop-ийн «Баталгаажуулалтын хуудсыг эхэнд» сонголт; Go v0.15.0 (#41), PAGE_SPEC §8a, PLACEMENT_SPEC §1b.
- **Хаана:** `Models.cs`, `EidPades.cs`, `Pdf/VerifyPage.cs`; `GoldenTests.cs` (manifest-ийн түлхүүр); `build/go-sdk.ref` →
  Go `9e76888` (`pades-golden-v9`), `testdata/golden/`.
- **Шалгасан:** CI (Windows + Linux `dotnet test`, golden-sync) — v9-ийн 8 `vpfirst-*` кейс Go-той байт-ижил.
