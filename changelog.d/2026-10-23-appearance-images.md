### Added — харагдах гарын үсэгт гарын үсгийн / байгууллагын тамганы зураг (golden v10)

- **Юу:** `Appearance.SignatureImage`, `Appearance.StampImage` (`PdfImage { Width, Height, Color, Alpha, Sha256 }`) —
  зураг widget-ийн `/AP /N` form дотор (1×1 DeviceRGB base + W×H /SMask, alpha нь оролтын zlib байтаар — runtime
  шахалт үгүй). `Width` = `Height` = 0 → анхдагч хэмжээ 220×64 / 220×110 / 240×147.5 (`EidPades.Default*Stamp*`),
  Prepare ба `SuggestPlacement` хоёуланд. Оролтын шалгалт (хэмжээ 1…1600, өнгө 0…255, alpha ≤ 300 KiB, нэг zlib stream
  яг W·H байт, ард нь илүү байтгүй, sha256 жижиг hex) → `REQUEST_INVALID`; `StampImage` нь `ClaimedRole`-гүй бол
  Prepare-д `REQUEST_INVALID`. `Completed.Images` → `SignatureRegistration.Images` (`images`, зураггүй бол талбаргүй).
- **Яагаад:** Go SDK-ийн APPEARANCE_SPEC §6 / PLACEMENT_SPEC §6c-ийн native порт (Go PR #44), байт-ижил.
- **Хаана:** `Pdf/SignatureAppearance.cs` (геометр §6.3, content §6.4, объект §6.2), `Pdf/SignatureRevision.cs`,
  `Pdf/ZlibStrict.cs` (ашигласан байтын тоо), `EidPades.cs`, `Models.cs`, `State.cs`, `Registration.cs`; golden
  `build/go-sdk.ref` → eid-mongolia-sdk-go `79e29f7` (feat/appearance-images; Go PR merge хийгдсэний дараа tag руу шилжүүлнэ).
- **Шалгасан:** `dotnet test` (net8.0, macOS) — 220/220, golden v10-ийн `img-*` 7 тохиолдол бүгд байт-ижил (v9 хэвээр);
  `AppearanceImageTests` — 13 буруу оролт, анхдагч хэмжээ, бүртгэлийн `images`. `dotnet format --verify-no-changes` цэвэр.
