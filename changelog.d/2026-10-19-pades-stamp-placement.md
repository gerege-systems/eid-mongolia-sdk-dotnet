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
  `Models.cs`, `EidPades.cs`; golden pin `build/go-sdk.ref` → b5c1fdc (golden v5 + `placement/`).
- **Verified:** `dotnet test` — all 21 `placement/vectors.json` vectors box-for-box, the 6 golden v5 cases and every
  existing golden case byte-identical with `expect.placement`; robustness tests on arbitrary/malformed content and
  Flate streams; `dotnet format --verify-no-changes`; `sync-golden.sh --check`.
- **Remaining:** release (version bump) — not part of this change.
