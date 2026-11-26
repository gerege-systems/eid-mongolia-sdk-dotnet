# RP SDK цөм: байгууллага, иргэн, e-Seal, токен, share, «Миний QR» (нийтлэгдээгүй) + Pades My QR OCSP засвар

- **Юу (core `GeregeSystems.EidMongolia`, Go/TS-ийн порт):**
  `client.Organization` (`GetRepresentationsAsync`, `SealGrantsAsync`); `client.Person` (PKI_READ: `CertificatesAsync`,
  `DevicesAsync`, `ActivityAsync` + `ActivityQuery`, `SummaryAsync`, `ChildrenAsync`); `client.Seal` (`CertificateAsync`,
  `RequestCertificateAsync`, `CertificateRequestAsync`, `WaitForCertificateAsync`, `SealAsync` — хариуны ECDSA гарын үсэг ба
  e-Seal профайлыг тулгана, `SealDigestOptions` docId/revIndex (CA V158), `RequestGrantAsync`, `GrantStatusAsync`,
  `WaitForGrantAsync`, `IsSealCertificate`; `EidSealRequestException`, `EidSealGrantException`, `SealErrorCodes`,
  `SealGrantErrorCodes`); `client.Token` (`IssueCertificateAsync`, `PreviewCertificateAsync`, `CertificateResultAsync`,
  `CertificateInfoAsync`, `VerifyTokenCertificates`, `AuthChallengeAsync`, `AuthVerifyAsync` — CA руу илгээхээс өмнө rpUUID,
  `TokenAuthDigest`, EC P-256 r||s, гэрчилгээний гинж/зориулалт/issuer-ийг validator-ийн замын угсралтаар; `TokenLimitOf`,
  `TokenErrorCodes`); `client.ShareAsync` (multipart, Go mime/multipart-ийн байт хэлбэр) + `ShareInfoAsync`,
  `EidShareException`; `client.Qr` + `EidClientOptions.QrTrust` — core-ийн `GeregeSystems.EidMongolia.Qr` (нийтийн API
  Pades-ийнхтэй ижил; гинж — core-ийн замын угсралт (X509Chain биш), цуцлалт — `OcspRevocationChecker`: unknown →
  revoked, 48 ц).
- **Хатуурал (Go/TS-ээс хатуу, cross-SDK review S4/S5):** `OcspRevocationChecker` сүлжээнээс ӨМНӨ leaf-ийг өгсөн issuer
  гаргасныг шалгана (үгүй бол `no_issuer`), хариуны CertID-ийн issuerNameHash / issuerKeyHash-ийг тулгана (зөрвөл
  `invalid`); subject-д SERIALNUMBER эсвэл CN давхардсан гэрчилгээ → шинэ түлхүүр `subject.duplicate_identity`
  (validator, токены нэвтрэлт; My QR-д `QR_CHAIN_INVALID`). Нэмэлт .NET reason key: `response.malformed`,
  `seal.not_seal_certificate`, `seal.signature`, `token.csr_mismatch`, `token.challenge`, `token.signature`,
  `token.identity`. rp-validate 77 + OCSP 17 корпусын кейс өөрчлөгдөөгүй.
- **Засвар (нийтлэгдсэн `GeregeSystems.EidMongolia.Pades`):** «Миний QR»-ийн анхдагч цуцлалт OCSP `unknown`-ийг одоо
  `revoked` (`QR_CERT_REVOKED`) гэж үзнэ (өмнө нь `QR_REVOCATION_UNKNOWN`), хариуны шинэлэг байдал Go/TS-ийн 48 ц-ийн дүрэм
  (thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate өнгөрөөгүй); PAdES LTV-ийн 24 ц-ийн дүрэм хэвээр. Pades core-оос
  хамаарахгүй хэвээр.
- **Хойшлуулсан (0.17.0 lockstep release):** QR төрлүүдийг Pades-ээс core руу `[TypeForwardedTo]`-оор шилжүүлэх ба
  Pades-ийн дотоод OCSP/DER-ийг core руу нэгтгэх — `docs/release-0.17.0.md`.
- **Хаана:** `src/GeregeSystems.EidMongolia/{Organization,Person,Seal,Token,Share}.cs`, `Qr/{EidQr,EidQrClient}.cs`,
  `EidClient.cs`, `Http.cs`, `Errors.cs`, `Validator.cs` (`FindPath`), `Ocsp.cs`, `X509.cs`, `Subject.cs`, `Types.cs`;
  `src/GeregeSystems.EidMongolia.Pades/Qr/EidQr.cs`; тест `tests/GeregeSystems.EidMongolia.Tests/{Seal,Token,Share,
  OrganizationPerson,Qr}Tests.cs`, `NegativeTests`, `WireConformanceTests`, `RouteTests` (contract: share, tokenCertificate),
  `tests/GeregeSystems.EidMongolia.Pades.Tests/RevocationTests.cs`.
- **Хэрхэн шалгасан:** PR CI (Windows + Linux, net8.0 + net10.0) — Go seal/seal_grant/share/portal_gaps/client тестийн
  порт, myqr_vectors.json core QR дээр, корпус, contract.
