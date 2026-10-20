### Docs — README / XML doc нь 0.5.0-ийн API-тай нийцэв

- **Юу:** README-ийн жишээнд `using System.Text.Json;` дутуу байсан (`JsonSerializer` compile болдоггүй); `ClaimedRole`
  тавьсан жишээ `RegistrationOptions.OnBehalfOf`-гүй байсан (CA-д заавал). Алдааны хүснэгтэд `Internal` / `INTERNAL`
  нэмэв; `PDF_INVALID`-ийн бүтцийн хязгаарыг PRECHECKS #2a/#2b-тэй тулгав (`/Extends` > 64). XML doc:
  `PrepareOptions.Lang` хоосон = `mn`.
- **Яагаад:** Swift/Kotlin/Go баримттай нийцүүлэх аудит (2026-10-20); код өөрчлөгдөөгүй.
- **Хаана:** `README.md`, `src/GeregeSystems.EidMongolia.Pades/Models.cs` (зөвхөн `///`).
- **Шалгасан:** README-ийн урсгалын жишээг scratch console төсөлд (`ProjectReference` → src) `dotnet build` — алдаагүй;
  засвараас өмнө `CS0103 JsonSerializer`.
