### Fixed — `Registration`: medium ба claimedRole-ийг CA-аас өмнө шалгана

- **Юу:** `EidPades.Registration` — `Medium` хоосон бол `SessionId`-ээс тооцсоор (phone ⇔ sessionId); `phone` +
  `SessionId`-гүй, `token` + `SessionId`, бусад `Medium` утга → `REQUEST_INVALID`. `Completed.ClaimedRole` (шинэ;
  state-ээс) байхад `RegistrationOptions.OnBehalfOf` хоосон бол `REQUEST_INVALID`.
- **Яагаад:** 2026-10-20-ны SDK аудит — таван SDK (TS, Go, .NET, Swift, Kotlin) нэг дүрмээр; CA эдгээрийг хожим 400-аар
  татгалздаг байсан.
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/Registration.cs`, `Models.cs` (`Completed.ClaimedRole`), `EidPades.cs`,
  `README.md`; тест `ErrorTests.cs` (medium, claimedRole, RSASSA-PSS → `SIGNATURE_INVALID`), `GoldenTests.cs`.
- **Шалгасан:** CI `dotnet test` (Windows + Linux).
