# RP SDK цөм `GeregeSystems.EidMongolia` — суурь (хөгжүүлэлт явагдаж байна, нийтлэгдээгүй)

- **Юу:** шинэ төсөл `src/GeregeSystems.EidMongolia` (`net8.0` / `net10.0`, package хамааралгүй): `EidClient` +
  `EidClientOptions` / `EidCredentials` (BaseUrl-ийн дүрэм — https, http зөвхөн loopback, хуучин `ca.eidmongolia.mn`-д
  тодорхой алдаа; Bearer; timeout 15 с / PDF 80 с; `Accept-Language`; JSON 4 MiB; mTLS дуудагчийн `HttpClient`-ээр),
  `EidException`-ийн шатлал (`Code`, `Status`, `RetryAfter`, `Retryable`; CA-ийн код бүрийн дэд анги), Go `routes.go`-той
  ижил замын хүснэгт, wire DTO-ууд, discovery `client.Auth.SessionTtlAsync()`; крипто туслахууд — `Acsp` (ACSP_V2
  payload/digest), `EidCrypto.InteractionsToBase64` (JS `JSON.stringify`-тай байт-ижил тусгай бичигч), `DeviceLink.Build` /
  `TickQrAsync` (authCode = HMAC-SHA256), `SessionSecretDigest`, `RandomChallenge`, `UserChallengeOf`.
- **Яагаад:** .NET SDK-г TS/Go-той ижил хүрээтэй бүрэн server-side RP SDK болгох эхний багц (Auth / Sign / Session /
  Validator дараагийн PR-уудад). `GeregeSystems.EidMongolia.Pades`-ийн код ба public API өөрчлөгдөөгүй (QR төрлүүдийг
  цөм рүү зөөх нь дараагийн багцад).
- **Хаана:** `src/GeregeSystems.EidMongolia/`, `tests/GeregeSystems.EidMongolia.Tests/` (`net8.0` + `net10.0`),
  `testdata/devicelink_golden.json` (CA `server/internal/crypto/testdata/devicelink_golden.json`-ийн засваргүй хуулбар),
  `.github/workflows/contract.yml` (өдөр бүр live `/.well-known/eid`), CI-д .NET 8 runtime нэмсэн.
- **Хэрхэн шалгасан:** PR CI (Windows + Linux) — device-link golden 15 вектор (+999 мс floor), файлын SHA-256 түгжээ,
  Smart-ID ACSP_V2 SHA-512 вектор, interactions escape (кирилл, `<>&`, `\`, U+2028/2029, control, ганц surrogate), BaseUrl-ийн
  дүрэм, HTTP алдааны буулгалт (fake `HttpMessageHandler`), Retry-After, 4 MiB хязгаар, timeout / цуцлалт.
