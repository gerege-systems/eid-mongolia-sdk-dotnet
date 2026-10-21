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
