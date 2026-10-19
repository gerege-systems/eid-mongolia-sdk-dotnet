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
