### Fixed — PDF lexer: массив доторх `endobj` дээр мөнхийн давталт

- **Юу:** `Lexer.ReadArray` массив дотор `endobj` таарвал `PdfFormatException` (Prepare → `PDF_INVALID`) шиднэ. Өмнө нь
  `ReadObject` `endobj`-г буцааж «уншаагүй» болгодог тул давталт ахихгүй, санах ой хязгааргүй өсдөг байв.
- **Яагаад:** хортой/эвдэрсэн PDF Prepare-ийг гацааж болох байв (Go SDK/CA-ийн digitorus fork-ийн засвартай ижил).
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/Pdf/Lexer.cs`; тест `tests/…/LexerTests.cs` (10 с-ийн хугацаатай).
  Бусад давталт (hex/literal мөр, EOF массив, Structure/Occupancy сканнер, ObjStm `/Extends`) аль хэдийн ахиц/хязгаартай.
- **Шалгасан:** GitHub Actions CI (Windows + Linux) — локалд dotnet байхгүй.
