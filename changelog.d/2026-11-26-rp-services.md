# RP SDK цөм: Auth, Sign, certificate-choice, Session, PDF бүртгэл (нийтлэгдээгүй)

- **Юу:** `GeregeSystems.EidMongolia` цөмд —
  `client.Auth.NotificationByEtsiAsync` / `NotificationByDocumentAsync` / `DeviceLinkAnonymousAsync` / `DeviceLinkByEtsiAsync`
  (`AuthOptions`: certLevel, callbackUrl, onBehalfOf, алгоритм, hash; `AcspContext`-тэй session);
  `client.Sign.DigestByEtsiAsync` / `DigestByDocumentAsync` / `TextByEtsiAsync` / `DeviceLinkByEtsiAsync` /
  `DeviceLinkByDocumentAsync` / `DigestForSignerAsync` (linked) / `DeviceLinkForSignerAsync` /
  `CertificateChoiceByEtsiAsync` / `CertificateChoiceDeviceLinkAsync` (`SignOptions`, `CertChoiceOptions`, `SignerRef`,
  `SignContext`); `client.Session.PollAsync` / `WaitForResultAsync` (хугацаа: MaxWait → expiresAt → discovery sessionTtl →
  600 с, + 15 с grace), `SessionService.ParseSessionResult` (person, onBehalfOf, tokenCertificate, presentation),
  `SessionService.EnsureCompleteOk` (endResult ≠ OK → `EidSessionFailedException`); `client.Pdf.RegisterSignatureAsync`
  (`POST /pdf/signatures`, 201/200 `Created`, PRIOR_MISMATCH-ийн priorSplits давталт, `PdfErrorCodes`);
  `DeviceLinkSession.BuildLink` / `LinkInput` / `TickQrAsync`; `EidClientOptions.TimeProvider`.
- **Яагаад:** .NET SDK-г TS/Go-той ижил хүрээтэй server-side RP SDK болгох 2-р багц (Validator, OCSP, login, seal/token
  дараагийн PR-уудад). Go `auth.go`, `sign.go`, `certchoice.go`, `session.go`, `pdfregister.go`-ийн порт.
- **Хаана:** `src/GeregeSystems.EidMongolia/{Auth,Sign,Session,Pdf}.cs`, `EidClient.cs`, `Types.cs`, `DeviceLink.cs`;
  тест `tests/GeregeSystems.EidMongolia.Tests/{Auth,Sign,Session,Pdf,WireConformance}Tests.cs`, `Rig.cs`, гэрээний тест
  (`RouteTests.cs`: pdf/signatures бие, registerErrorCodes, seal блок ба кодууд). `GeregeSystems.EidMongolia.Pades`-ийн
  код, public API, багц өөрчлөгдөөгүй.
- **Хэрхэн шалгасан:** PR CI (Windows + Linux, net8.0 + net10.0) — fake `HttpMessageHandler`-ээр method / зам / биеийн
  JSON (Go/TS тестээс порт хийсэн wire кейсүүд), хариу задлалт, алдааны буулгалт, хянах боломжтой цагтай WaitForResult,
  auth / sign / cert device-link session → холбоос ба QR ticker нь CA `devicelink_golden.json`-тэй байт-ижил.
