# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

## 0.17.0 — 2026-11-26

**Гол өөрчлөлт:** гурван багц нэг хувилбартай (lockstep) гарна. Шинэ **`GeregeSystems.EidMongolia`** — TypeScript ба Go
SDK-тэй ижил хүрээтэй бүрэн server-side RP SDK (Auth, Sign, Session, Validator, OCSP, PDF бүртгэл, байгууллага, иргэн,
e-Seal, USB токен, share, «Миний QR», «eID-ээр нэвтрэх» товчны backend). Шинэ **`GeregeSystems.EidMongolia.AspNetCore`** —
`AddEidMongolia` / `MapEidLogin`. **`GeregeSystems.EidMongolia.Pades`** одоо core-оос хамаарна: «Миний QR»-ийн 12 нийтийн
төрөл (`GeregeSystems.EidMongolia.Qr`) core руу шилжиж `[TypeForwardedTo]`-оор дамжуулагдана — 0.16.0-ийн эсрэг compile
хийсэн код дахин compile-гүйгээр ажиллана (нэр, namespace, гишүүд ижил). PAdES-ийн гаралт байт-ижил (golden өөрчлөгдөөгүй).

*English:* three packages now ship in lockstep. New **`GeregeSystems.EidMongolia`** is a full server-side relying-party SDK
with the same scope as the TypeScript and Go SDKs; new **`GeregeSystems.EidMongolia.AspNetCore`** adds `AddEidMongolia` /
`MapEidLogin`. **`GeregeSystems.EidMongolia.Pades`** now depends on the core package: the twelve public «My QR» types
(`GeregeSystems.EidMongolia.Qr`) moved to core and are type-forwarded, so code compiled against Pades 0.16.0 keeps working
without recompiling. PAdES output is byte-identical (golden vectors unchanged). Revocation in the login backend defaults to
soft-fail — set `RevocationMode.HardFail` for high-value relying parties.

### Security

- **RSA ≥ 2048 бит, exponent сондгой ба ≥ 3** — иргэний (leaf), CA, OCSP responder/issuer-ийн түлхүүрт (validator, «Миний
  QR», токены нэвтрэлт); сул leaf → `cert.weak_key`, сул trust pool → `ArgumentException`.
- **Гинжийн хатуу дүрэм (fail-closed, X509Chain-гүй, платформ бүрд ижил):** өөрийн DER замын угсралт (TS `verifyChain`-ийн
  порт) — basicConstraints/pathLen, keyCertSign, EKU давхарга, хугацаа, issuer SKI allowlist; name constraints-тэй CA (anchor
  ч мөн) ба танихгүй critical extension-ийг татгалзана; AIA татахгүй. «Миний QR» ч мөн энэ замаар (өмнө нь Pades-д X509Chain).
- **«Миний QR»-ийн OCSP `unknown` → revoked** (`QR_CERT_REVOKED`; олгогч энэ serial-ийг олгоогүй) ба хариуны шинэлэг байдал
  Go/TS-ийн 48 ц-ийн дүрэм (thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate өнгөрөөгүй). PAdES LTV-ийн 24 ц-ийн дүрэм хэвээр.
- **Issuer / CertID-ийн холбоос:** `OcspRevocationChecker` сүлжээнээс ӨМНӨ leaf-ийг өгсөн issuer гаргасныг шалгана (үгүй бол
  `no_issuer`), хариуны CertID-ийн issuerNameHash / issuerKeyHash-ийг тулгана (зөрвөл `invalid`).
- **Давхардсан subject-ийг татгалзана:** SERIALNUMBER эсвэл CN нь давхардсан гэрчилгээ → `subject.duplicate_identity`
  (validator, токены нэвтрэлт; «Миний QR»-д `QR_CHAIN_INVALID`).
- **Бие даасан review-ийн засварууд (#49):** login `POST start`-ийн ганц surrogate-тэй JSON → 400 `invalid_body` (өмнө нь
  хязгаараас өмнө 500); «Миний QR»-ийн header/payload/data-ийн мөр, түлхүүрийг аюулгүй уншина (`InvalidOperationException`
  биш `EidQrException`), payload-ийн давхардсан түлхүүр → `QR_JWS_MALFORMED` (Go `jsonObject`); ASP.NET `MapEidLogin`-ийн
  `ClientIp` анхдагч `EidLoginClientIp.RemoteAddress`, IPv6 клиентийн `start:` хязгаарын түлхүүр /64 угтвар; замын
  параметрт хоосон / `.` / `..` → `ArgumentException` (System.Uri dot-segment-ээр өөр зам руу шилжихгүй); `VerifyAsync`
  олгогчийн гэрчилгээг Dispose хийнэ.
- **Анхдагч цуцлалтын горимууд (тодорхой хэлэв):** login backend — `OcspRevocationChecker`, **soft-fail** (OCSP хариугүй
  бол иргэн нэвтэрнэ, `Revocation = Unchecked` + Warning); өндөр үнэ цэнтэй RP-д `RevocationMode = HardFail`. `Validator` —
  `TrustConfig.Revocation` өгөөгүй бол цуцлалт шалгахгүй (`Skipped`), өгвөл анхдагч hard-fail. «Миний QR» — AIA-ийн OCSP,
  hard-fail.

### Added — `GeregeSystems.EidMongolia` (RP SDK цөм, шинэ багц)

- **Client:** `EidClient` + `EidClientOptions` / `EidCredentials` — BaseUrl-ийн дүрэм (https; http зөвхөн loopback; хуучин
  `ca.eidmongolia.mn`-д тодорхой алдаа), Bearer, timeout 15 с / PDF 80 с, `Accept-Language`, JSON 4 MiB, mTLS дуудагчийн
  `HttpClient`-ээр, `TimeProvider`; `EidException`-ийн шатлал (`Code`, `Status`, `RetryAfter`, `Retryable`; CA-ийн код бүрийн
  дэд анги); Go `routes.go`-той ижил замын хүснэгт; discovery `client.Auth.SessionTtlAsync()`.
- **Auth / Sign / Session / PDF:** `client.Auth` (push — ETSI / document, device link — anonymous / ETSI; `AuthOptions`,
  `AcspContext`); `client.Sign` (digest, text, linked, device link, certificate-choice; `SignOptions`, `SignerRef`);
  `client.Session.PollAsync` / `WaitForResultAsync` (MaxWait → expiresAt → discovery sessionTtl → 600 с, + 15 с grace),
  `ParseSessionResult`, `EnsureCompleteOk`; `client.Pdf.RegisterSignatureAsync` (`POST /pdf/signatures`, PRIOR_MISMATCH-ийн
  давталт, `PdfErrorCodes`); `DeviceLinkSession.BuildLink` / `TickQrAsync`; крипто туслахууд (`Acsp`, `EidCrypto`,
  `DeviceLink` — authCode = HMAC-SHA256).
- **Validator:** `client.Validator` (`ResponseValidator`) — `ValidateAuth` (ACSP_V2, flowType relay хаалт,
  userChallengeVerifier, callback, алгоритм/hash downgrade хаалт), `ValidateSign` (RAW_DIGEST: RSA-PSS, PKCS#1 v1.5, ECDSA
  P-256), `ValidateCertificateChoice`, `CheckRevocationAsync` / `CheckRevocationWithAsync` (hard/soft-fail),
  `CertificateLevelOf`, `ParseSubject`; `TrustConfig`, `EidTrust` (шигтгэсэн 01–04); `OcspRevocationChecker` (Go `ocsp.go`:
  delegated responder, 2 с / нийт 3 с, 16 KiB, «good»-ийг кэшлэнэ); `EidValidationException.Reason` = тогтвортой түлхүүр
  (`ValidationReasons`).
- **Үйлчилгээ:** `client.Organization` (төлөөлөл, тамганы эрх), `client.Person` (PKI_READ: гэрчилгээ, төхөөрөмж, үйл
  ажиллагаа, хураангуй, хүүхдүүд), `client.Seal` (тамганы гэрчилгээ, хүсэлт, `SealAsync` — хариуны ECDSA ба e-Seal профайл,
  тамганы эрхийн хүсэлт), `client.Token` (USB токены гэрчилгээ, preview, үр дүн, `VerifyTokenCertificates`, токены нэвтрэлт
  — CA руу илгээхээс өмнө rpUUID, digest, гарын үсэг, гинжийг шалгана), `client.ShareAsync` / `ShareInfoAsync`, `client.Qr`
  («Миний QR» — `EidClientOptions.QrTrust`).
- **Conformance:** Go `testdata/conformance` (rp-conformance/1)-ийн байт-ижил хуулбар (`build/sync-conformance.sh`, CI
  `conformance-sync`): rp-validate 77, OCSP 17, wire 26, interactions, acsp_v2, eidlogin 24 сценари; CA-ийн device-link
  golden; `contract.yml` замын хүснэгтийг live `/.well-known/eid`-тэй өдөр бүр тулгана.

### Added — «eID-ээр нэвтрэх» товчны backend ба `GeregeSystems.EidMongolia.AspNetCore` (шинэ багц)

- **Юу:** `GeregeSystems.EidMongolia.Login.EidLoginHandler` (Go `eidlogin.Handler`, TS `createEidLogin`-ийн порт;
  framework-аас хамааралгүй): `POST start` (qr | push), `GET start?mode=web2app`, `GET status`, `GET callback` (Web2App);
  HttpOnly + Secure + SameSite=Lax cookie binding; `IEidLoginStore` + `MemoryEidLoginStore`; хязгаар (`EidLoginRateRule`:
  start 20/мин IP, push 3/мин дугаар); `EidLoginClientIp.RemoteAddress` / `Forwarded(n)`; decoy push ба 1 с push floor;
  ValidateAuth + OCSP (soft-fail анхдагч) дараа нэг удаа `OnSuccess`; `OnEvent` аудит (HMAC pushKey); 12 алдааны код Go/TS-тэй
  ижил. `GeregeSystems.EidMongolia.AspNetCore`: `services.AddEidMongolia(...)`, `app.MapEidLogin("/auth/eid", ...)`,
  `EidLoginHttp` (shared framework-аас өөр хамааралгүй).
- **Go/TS-ээс ялгаа:** `OnEvent`-ийн алдааг залгиж Log руу (TS); `data` нь camelCase JSON; JSON бие хатуу задлагдана;
  failure redirect-ийн query дараалал хадгалагдана.

### Changed — `GeregeSystems.EidMongolia.Pades` core-оос хамаарна; «Миний QR» core-д (type forwarding)

- **Юу:** Pades-д core руу хамаарал (`GeregeSystems.EidMongolia` 0.17.0); Pades-ийн «Миний QR»-ийн хуулбар устсан,
  `Properties/TypeForwards.cs` нь `EidQr`, `EidQrClient`, `EidQrOptions`, `EidQrException`, `EidQrErrorCodes`, `QrStartRequest`,
  `QrSession`, `QrSigner`, `QrResult`, `QrExpect`, `QrTrust`, `QrCheck`-ийг core руу дамжуулна. 0.16.0-ийн нийтийн гишүүдтэй
  гишүүн бүрээр ижил (v0.16.0 tag-тай тулгасан).
- **Зан төлөвийн ялгаа (API биш):** «Миний QR»-ийн гинж core-ийн замын угсралтаар (дээрх «Security»); `QrTrust.Intermediates`
  null бол шигтгэсэн 02–04 (өмнө нь 02–05 — 05 нь байгууллагын олгогч, иргэний гэрчилгээнд хэрэггүй; анхдагч олгогч 04 хэвээр);
  review-ийн засварууд (давхардсан payload түлхүүр, ганц surrogate).
- **Нэгтгээгүй (тайлбар):** Pades-ийн дотоод `Crypto/Ocsp.cs`, `Der`, `X509Util`, `Fetcher`, `Trust` core-ийнхтэй ижил зан
  төлөвтэй БИШ (PAdES LTV — Go `x/crypto/ocsp`-ийн `ParseResponseForCert`, SHA-1 responder-ийг зөвшөөрнө, 24 ц, CRL толин
  хуулбар; `Der` нь CMS-ийн байт-ижил бичигч; core-д зөвхөн RP-ийн хатуу уншигч) — нэгтгэвэл golden-ийн байт эсвэл LTV-ийн
  дүрэм өөрчлөгдөнө, тиймээс хэвээр үлдээв.
- **Багц:** гурван багц ижил metadata (Gerege Systems LLC, MIT, README, repository, SourceLink, `.snupkg` symbols), `net8.0`
  ба `net10.0`.

### Changed — README гурван хэлээр

- `README.md` (монгол), `README.en.md`, `README.zh-CN.md` — RP SDK-ийн бүрэн баримт (суулгах, client, auth push/QR, session,
  validator ба цуцлалтын горимууд, sign, PDF бүртгэл, тамга/байгууллага/иргэн/токен/share, «Миний QR», login backend +
  ASP.NET Core, proxy-ийн ард client IP), Pades хэрэглэгчдэд шилжих тэмдэглэл, Go/TS-тэй харьцуулсан дэмжлэгийн хүснэгт;
  кодын жишээний коммент тус бүрийн хэлээр.

### CI ба release

- `pack` нь гурван багцыг (+ `.snupkg`) гаргаж `build/check-packages.sh`-ээр шалгана (хувилбар, metadata, TFM бүрийн lib,
  Pades/AspNetCore → core 0.17.0 хамаарал, AspNetCore → `Microsoft.AspNetCore.App`).
- Шинэ `compat` job: Pades 0.16.0-ийн (nuget.org) эсрэг compile хийсэн «Миний QR» хэрэглэгч 0.17.0-ийн dll дээр дахин
  compile-гүйгээр ажиллана (12 төрөл core-оос ачаалагдана), мөн энэ репогийн эсрэг source-оор compile болно.
- `release.yml`: `v*` tag → CI → GitHub Release (nupkg + snupkg) → GitHub Packages → nuget.org; core эхэлж, дараа нь
  AspNetCore, Pades. Шинэ хоёр package ID-ийн nuget.org-ийн урьдчилсан нөхцөл — `docs/release-0.17.0.md`.

### Дараагийн ажил (cross-SDK, эхлээд corpus / Go / TS өөрчлөлт)

- Login cookie-д `__Host-` угтвар ба давхардсан login cookie-г татгалзах (review S3).
- Rate-limit түлхүүрт иргэний дугаарыг hash болгох (review S4).
- Validator-ийн issuer allowlist шууд issuer олдоогүй үед leaf-ийн AKI-д буцдаг дүрэм (Go/TS-тэй хамт).
- Энэ SDK-д хараахан байхгүй: `ValidatePDF` (PDF-ийн бүрэн шалгагч); байгууллагын тамганы бүртгэл (`POST
  /seal/{org}/registrations` — Go/TS-д ч хараахан алга); QR-тэй тамганы дардас (APPEARANCE_SPEC §6.5–6.6, Go v0.31.0 golden
  v13 — энэ SDK golden v12 дээр: QR-тэй тамгатай, verify хуудасгүй баримтад `Prepare` docId-г тамганаас авахгүй).

## 0.16.0 — 2026-11-24

**Гол өөрчлөлт:** `SealAsync` одоо анхдагчаар **харагдах байгууллагын тамганы дардас** зурна; `SealOptions.Invisible = true`
өмнөх гаралтыг (байт-ижил) сэргээнэ. Go SDK v0.30.0 / TS SDK 0.48.0-аас өмнөх шалгагчид харагдах тамганы дардастай PDF-ийн
өмнөх гарын үсгүүдийг өөрчлөгдсөн (modified) гэж мэдээлнэ; eID Mongolia CA-ийн шалгагч ба түүний /verify хуудас үүнийг
аль хэдийн дэмждэг. Тамганы гэрчилгээний шалгалт одоо специйн дүрмийг дагана: хоосон extendedKeyUsage-ийг хүлээн авна, CA
гэрчилгээг татгалзана.

*English:* `SealAsync` now draws a visible organisation seal stamp by default (`Invisible = true` restores the previous
output). Verifiers older than Go SDK v0.30.0 / TS SDK 0.48.0 report earlier signatures as modified on a PDF that received a
visible seal stamp; the eID Mongolia CA validator and its /verify page already support it. The seal-certificate gate now
follows the spec rule: an empty extendedKeyUsage is accepted, a CA certificate is rejected.

### Added — харагдах байгууллагын тамганы дардас (APPEARANCE_SPEC.md §6, golden v12); `SealAsync` анхдагчаар харагдана

- **Юу:** дардас бичигч гарын үсэг зурагчийн гэрчилгээгээр хувилбараа сонгоно (§6.1, `EidPades.IsSealCertificate`, internal):
  e-Seal гэрчилгээ (CA биш, keyUsage bit 1 тавигдсан ба bit 0 тавигдаагүй — бусад бит үл тооно, EKU-ийн зорилгогүй —
  extendedKeyUsage алга эсвэл хоосон) → **тамганы дардас**: иргэний дардастай ижил widget, 11 объект, F1/F2 фонт, form
  dictionary, байршил; `/EIDVerify` BDC, QR, URL, үүргийн мөр үгүй; бичвэр x = 4 pt-ээс, өргөн W − 8 pt; мөр: нэр (F2,
  11 → 7, ≤ 2 мөр), «eID Mongolia-аар тамгалсан» / "Sealed with eID Mongolia" (F1, f − 2, ногоон), огноо (F1, f − 2, саарал).
  Тамганы дардасд docId шаардахгүй. Бусад гэрчилгээ → иргэний дардас, байт өөрчлөгдөөгүй.
  `SealOptions.Appearance` (иргэний `Appearance`-тэй ижил талбар) ба `SealOptions.Invisible` нэмэгдсэн; `Completed.Placement`
  (зөвхөн `SealAsync` бөглөнө); `EidPades.SealStampWidth/Height/Margin` (220, 64, 36). **Анхдагч өөрчлөгдсөн:** аль нь ч
  өгөөгүй бол `SealAsync` дардсыг харуулна — сүүлийн (eID verify биш) хуудас, 220 × 64 pt, x = хуудасны өргөн − 256, y = 36,
  жижиг хуудсанд багтаасан (§6.4), Exact биш (PLACEMENT_SPEC-ээр агуулгаас зайлсхийнэ). Автомат дардас багтахгүй
  (`REQUEST_INVALID`) эсвэл гаралт хэмжээнээс хэтрэх (`PDF_TOO_LARGE`) бол үл харагдах тамга (`Placement = null`); өгсөн
  `Appearance` бол алдаа хэвээр. `Invisible = true` — өмнөх гаралттай байт-ижил. Тамгалагчийн (delegate) алдаа ба цуцлалт
  үл харагдах тамга руу шилжихгүй — өөрчлөгдөхгүй дамжина.
- **Анхаар:** Go SDK v0.30.0 / TS SDK 0.48.0-аас өмнөх шалгагчид харагдах тамганы дардастай PDF-ийн өмнөх гарын үсгүүдийг
  өөрчлөгдсөн (modified) гэж мэдээлнэ — тэдгээр шинэчлэгдэх хүртэл `Invisible = true`.
- **Гэрчилгээний шалгалт:** `SealAsync`-ийн `SIGNER_INVALID` шалгалт мөн §6.1 (Go `eid.IsSealCertificate`) болсон: хоосон
  extendedKeyUsage-тэй гэрчилгээг хүлээн авна (өмнө нь татгалздаг), CA гэрчилгээг татгалзана (өмнө нь шалгадаггүй).
  keyUsage/basicConstraints/EKU-г .NET-ийн декодероор биш DER-ээс шууд уншина; алдааны мессеж дүрмийг бүтнээр нь нэрлэнэ.
- **Яагаад:** Go SDK v0.30.0 (`SealPDF`) ба TS SDK 0.48.0 (`sealPdf`)-тэй ижил API, ижил байт.
- **Хаана:** `src/…/Pdf/SignatureAppearance.cs` (`SealContent`), `Pdf/SignatureRevision.cs`, `EidPades.cs` (`VisibleSpec`),
  `Seal.cs`, `Models.cs`; `build/go-sdk.ref` = d762ed8 (Go v0.30.0) + `testdata/golden` (pades-golden-v12: `seal-visible`,
  `seal-visible-en`, `seal-visible-third`, `pki/seal.pem`); README.
- **Шалгасан:** PR #40-ийн CI (Windows + Linux). `GoldenTests` — v12-ийн 3 тохиолдол Prepare/CompleteAsync-аар ба
  `SealAsync`-аар (автомат ба тодорхой байршил) бүхэлдээ байт-ижил, placement; бусад golden өөрчлөгдөөгүй.
  `SealTests` — §6.1 дүрэм (хоосон EKU = тамга, танихгүй/таньдаг EKU, CA, digitalSignature, keyUsage bit 32), 164 pt баримт
  → 156 × 64, x = 4; багтахгүй хуудас ба хэмжээний хязгаарын үл харагдах нөөц (DTBS = өмнөх `SealAsync`); `Invisible` DTBS =
  өмнөх `SealAsync`; delegate-ийн алдаа ба цуцлалт нөөц болохгүй.
- **Үлдсэн:** энэ SDK-д validator байхгүй тул §6.3 (дардсыг сэргээж тулгах) хэрэгжээгүй.

## 0.15.2 — 2026-11-16

### Changed — LTV: цуцлалтын эх сурвалжийн дараалал гэрчилгээний үүргээр (CA — CRL эхэлж, навч — OCSP эхэлж)

- **Юу:** `CompleteAsync`-ийн LTV цуглуулалт v0.15.x-ийн «гэрчилгээ бүрийн OCSP зэрэг + CA-д 3 с цонх»-ыг орлоно.
  **Навч** (гинж бүрийн эхний гэрчилгээ: иргэн, TSA) — OCSP эхэлж, энгийн 10 с timeout, thisUpdate > timestamp дахин
  оролдлоготой; CRL-ийг мөн татаж хүчинтэй бол хамт суулгана, хүчинтэй OCSP-гүй бол CRL хангана (өмнөхтэй ижил). **CA**
  (эхнийхээс хойшх гэрчилгээ бүр) — CRL эхэлж; олгогчийн хүчинтэй CRL авбал тэр гэрчилгээнд **OCSP хүсэлт огт илгээхгүй**;
  CRL-гүй / татаж чадаагүй / хүчингүй / хугацаа дууссан үед л OCSP (энгийн timeout). Навчны OCSP эхэнд нь зэрэг, CRL
  гинжийн дарааллаар (GET кэш, 4 MiB хязгаар), DSS-д гинжийн дарааллаар. `Ltv.OcspGrace` (internal) хасагдсан. Fail-closed,
  revoked хатуу алдаа, цуцлалт, ажиглагдаагүй exception үгүй — хэвээр; шалгалтын код өөрчлөгдөөгүй.
- **Яагаад:** эзний шийдвэр (2026-11-16): шаардлагагүй үед үндэсний CA-ийн OCSP responder (`ocsp.esign.gov.mn`, хариулдаггүй)
  руу огт хандахгүй — CA гэрчилгээг CRL хангана. Дүрэм нь хостын нэрээр биш, гэрчилгээний үүргээр. Go/TS/Swift/Android
  SDK-тай ижил дүрэм.
- **Үр дагавар:** эрүүл гинжийн DSS өөрчлөгдөнө — CA гэрчилгээ зөвхөн CRL өгнө (OCSP хариугүй). Golden-ууд Go reference
  `pades-golden-v11` (`build/go-sdk.ref` = d5a68ae) руу синк: DSS-ээс 04-ийн CA OCSP хасагдсан, 2 дахь гарын үсгийн 14
  тохиолдол шинэ TSA fixture-тэй; CA OCSP fixture (`ocsp.pki.test/03`) хасагдсан тул CA нөөц OCSP-ийн тестүүд хариугаа
  03-ийн тестийн түлхүүрээр өөрөө үүсгэнэ.
- **Хаана:** `src/…/Crypto/Ltv.cs`, `tests/…/RevocationTests.cs`, `build/go-sdk.ref` + `testdata/golden`, README (LTV/цуцлалтын дараалал, English).
- **Шалгасан:** PR-ийн CI (Windows + Linux) `dotnet test`. Шинэ тест: хүчинтэй CRL-тэй CA → хариугүй responder руу OCSP
  хүсэлт 0 (fake transport бүртгэлээр), шууд дуусна; дүрэм байрлалаар (CA байрлал дахь гэрчилгээ бүр); CA CRL-гүй / хугацаа
  дууссан / буруу олгогч / задрахгүй → OCSP нөөц; удаан CA OCSP нөөц хүлээгдэнэ; CA CRL ч OCSP ч алга → LTV incomplete;
  CA CRL-д цуцлагдсан → хатуу алдаа (OCSP хүсэлтгүй), CA OCSP нөөц revoked → хатуу алдаа; навч: удаан OCSP хүлээгдэнэ,
  хариугүй навч OCSP → бүтэн timeout-ын дараа CRL; дуудагчийн цуцлалт (навч ба CA нөөц OCSP үед).
- **Үлдсэн:** —

## 0.15.1 — 2026-11-16

### Fixed — LTV: навчны (иргэн, TSA) OCSP-г 3 с-ийн цонхоор таслахаа больсон

- **Юу:** v0.15.0-ийн OCSP цонх (`Ltv.OcspGrace`, 3 с) одоо зөвхөн **CA** гэрчилгээнд (гинжийн эхнийхээс хойшх байрлал)
  үйлчилнэ. Гинж бүрийн эхний гэрчилгээ — гарын үсэг зурагч (иргэн) ба TSA-ийн навч — хүчинтэй CRL байсан ч OCSP-оо
  v0.15.0-аас өмнөх шиг энгийн 10 с timeout-оор бүтэн хүлээнэ; хариу ирэхгүй бол timeout-ын дараа CRL-ээр. v0.15.0-ийн
  бусад зүйл хэвээр: OCSP зэрэг эхэлнэ, үр дүн гинжийн дарааллаар, fail-closed, revoked хатуу алдаа, цуцлалт,
  ажиглагдаагүй exception үгүй. Go/TS/Swift SDK-тай ижил дүрэм.
- **Яагаад:** аюулгүй талаас — саяхан цуцлагдсан эцсийн гэрчилгээ дахин гаргаагүй CRL-ээр зөвхөн OCSP 3 с-ээс
  удааширснаас болж давах ёсгүй, навчны «OCSP thisUpdate > timestamp» дахин оролдлого бүтэн цонхоо авах ёстой. Хариугүй
  responder-ийн асуудал (үндэсний хоёр CA гэрчилгээ, 2 × 10 с) CA байрлалд л байсан тул тэр засвар хэвээр.
- **Хаана:** `src/…/Crypto/Ltv.cs` (`CollectAsync` — `Job.Leaf` нөхцөл, `OcspGrace` баримт), `tests/…/RevocationTests.cs`,
  README (OCSP/CRL хэсэг, English).
- **Шалгасан:** PR-ийн CI (Windows + Linux) `dotnet test`: golden-ууд байт-ижил; шинэ тест — цонхоос удаан навчны OCSP +
  хүчинтэй CRL → хүлээгээд DSS-д суулгана (иргэн ба TSA навч); хариугүй навчны OCSP + хүчинтэй CRL → бүтэн timeout-ын
  (HttpClient.Timeout-оор 1 с) дараа CRL-ээр; хариугүй CA OCSP-ууд + хүчинтэй CRL → нийт ≈ нэг цонх (CA байрлалаар).
- **Үлдсэн:** —

## 0.15.0 — 2026-11-16

### Fixed — LTV: хариугүй OCSP responder `CompleteAsync`-ийг гэрчилгээ тус бүрд 10 с саатуулахаа больсон

- **Юу:** `CompleteAsync`-ийн LTV цуглуулалт гэрчилгээ бүрийн OCSP-г CRL-тэй **зэрэг** татна (бүх гэрчилгээний OCSP
  нэг дор эхэлнэ, CRL гинжийн дарааллаар, GET кэш хэвээр). Олгогчийн хүчинтэй CRL авсан гэрчилгээний OCSP-г цуглуулалт
  эхэлснээс хойш хамгийн ихдээ 3 с (`Ltv.OcspGrace`) хүлээгээд цуцална; хүчинтэй CRL-гүй бол OCSP энгийн 10 с timeout-тай
  (өмнөхтэй ижил). Хүлээн авах дүрэм (OCSP: гарын үсэг, responder EKU, CertID, шинэлэг байдал, навчны thisUpdate >
  timestamp; CRL: олгогчийн нэр/AKI/гарын үсэг, шинэлэг байдал) өөрчлөгдөөгүй; «revoked» хатуу алдаа хэвээр; аль нь ч
  хүчинтэй биш бол `LTV_UNAVAILABLE` хэвээр. DSS-ийн агуулга, дараалал эрүүл гинжид өөрчлөгдөөгүй (OCSP + CRL хоёулаа,
  гинжийн дарааллаар).
- **Яагаад:** үндэсний CA-ийн гэрчилгээнүүдийн (MNICA, Gerege Issuing CA) AIA OCSP `http://ocsp.esign.gov.mn` холболт
  хүлээж аваад хариулдаггүй үед гэрчилгээ бүр 10 с timeout идэж (2 × 10 с), Windows desktop-д гарын үсэг ~25 с болж
  байсан (8 хоногт 94-өөс 5). CRL нь аль хэдийн `crl.eidmongolia.mn` толин хуулбараас ирдэг.
- **Хаана:** `src/…/Crypto/Ltv.cs` (`CollectAsync`, `OcspAsync`, `OcspGrace`), `Crypto/Fetcher.cs` (баримт),
  `tests/…/RevocationTests.cs`, README (OCSP/CRL хэсэг, English).
- **Шалгасан:** PR-ийн CI (Windows + Linux) `dotnet test`: golden-ууд байт-ижил (эрүүл гинж); шинэ тест — эрүүл гинжийн
  DSS дараалал; хариугүй OCSP + хүчинтэй CRL → цонхонд CRL-ээр; хоёр хариугүй OCSP → нийт ≈ нэг цонх; CRL-гүй үед удаан
  OCSP-г таслахгүй; хог/олгогч биш зурсан OCSP → CRL, CRL-гүй бол `LtvException`; цонхонд ирсэн revoked → хатуу алдаа;
  дуудагчийн цуцлалт; UnobservedTaskException үгүй.
- **Үлдсэн:** TS (`eid-mongolia-sdk` `src/pades/ltv.ts`) ба Go (`eid-mongolia-sdk-go` `pades/ltv.go`) SDK-д ижил
  OCSP-эхлээд дараалсан хэв маяг (10 с) бий — тусад нь засна. Timestamp-ийн дараах хүлээлт (≈2 с, дээд тал 5 с)
  өөрчлөгдөөгүй.

### Changed — .NET 10 дэмжлэг (`net8.0;net10.0`)

- **Юу:** сан `net8.0;net10.0` multi-target болов (өмнө `net8.0`). `System.Security.Cryptography.Pkcs` net8.0 дээр
  8.0.2, net10.0 дээр 10.0.15. Тест төсөл `net10.0`. CI/release workflow .NET 10 SDK.
- **Яагаад:** .NET 8 runtime 2026-11-10-нд дэмжлэгээс гарсан. `net8.0` нь одоогийн хэрэглэгчдэд зориулан түр хадгалагдах
  бөгөөд дараагийн хувилбарт хасагдана.
- **Хаана:** `src/*/*.csproj`, `tests/*/*.csproj`, `.github/workflows/{ci,release}.yml`, `README.md`.
- **Шалгасан:** PR-ийн CI (Windows + Linux).

## 0.14.0 — 2026-11-09

### Added — байгууллагын тамга (e-Seal): `EidPades.SealAsync`

- **Юу:** `EidPades.SealAsync(pdf, SealOptions, sealDigest, CompleteOptions?, ct)` → `Completed`. `SealOptions`: `SealCert`
  (заавал), `Chain`, `Reason`, `SigningTime`, `SignerName` (анхдагч = гэрчилгээний CN). Урсгал: гэрчилгээ тамганы
  профайл эсэх (KeyUsage nonRepudiation, digitalSignature үгүй, EKU үгүй — validator-ийн «seal»; үгүй бол
  `SIGNER_INVALID`) → `Prepare` (verify хуудас, харагдах дүрслэлгүй) → `sealDigest(DTBS)` (RP-ийн өөрийн CA
  `POST /seal/{orgEtsi}` дуудлага, `signature.value`) → `CompleteAsync` (TSA заавал → PAdES-BASELINE-LT). Буруу гарын
  үсэг `SIGNATURE_INVALID`; delegate-ийн exception өөрчлөгдөхгүй дамжина. SDK-д HTTP client нэмээгүй.
- **Яагаад:** CA-ийн e-Seal API (`GET /seal/certificate/{orgEtsi}`, `POST /seal/{orgEtsi}`)-г .NET RP-ууд PAdES-д
  шууд ашиглах.
- **Хаана:** `src/…/Seal.cs`, `tests/…/SealTests.cs` (+ `RevocationTests`-ийн OCSP туслахууд internal),
  `testdata/seal_response.json`, README «Байгууллагын тамга (e-Seal)».
- **Шалгасан:** CI `dotnet test` (Windows + Linux): тест 04-өөр олгосон ECDSA P-256 тамга + fake RFC 3161 TSA + OCSP →
  B-LT (timestamp, /DSS, CMS шалгалт); digitalSignature-тэй гэрчилгээ → `SIGNER_INVALID`; өөр түлхүүрийн гарын үсэг →
  `SIGNATURE_INVALID`; delegate-ийн exception дамжина; CA хариуны дээжийн `signature.value` нь digest дээр шалгагдана.

## 0.13.0 — 2026-10-26

### Changed (BREAKING) — «Миний QR»: иргэний PIN2-оор зурсан «Миний мэдээлэл» (PS256 JWS)

- **Юу:** `GeregeSystems.EidMongolia.Qr` бүрэн солигдов. `EidQrClient.StartAsync(QrStartRequest(Qr, Nonce?, RelyingPartyName?))`
  → `POST /authentication/qr` `{qr, relyingPartyUUID, relyingPartyName, nonce}` (nonce өгөөгүй бол base64url(16 байт) =
  22 тэмдэгт) → `QrSession(SessionId, Nonce)`; `ResultAsync` / `CheckAsync` → `QrResult(Jws, Claims, Data, Source,
  Photo, Signer, SignedAt, Sha256)`; `EidQr.VerifyAsync(jws, QrExpect, QrTrust?)` — гэрээний §6.1 (header PS256 /
  `eidmn-myqr+jwt` / `x5c`, `X509Chain` CustomRootTrust, QcCompliance + contentCommitment + олгогч SKI + RSA ≥ 2048,
  OCSP hard-fail эсвэл `QrTrust.Revocation`, RSASSA-PSS, claims, `data` хязгаар). Шинэ кодууд `QR_JWS_MALFORMED` …
  `QR_PRESENTATION_GONE` (410). Хуучин аттрибут/ES256/JWKS API (QrAttributes, QrPresentation, VerifyPresentation,
  JwksUrl, MaxAge) хасагдав — хэрэглэгчгүй байсан.
- **Яагаад:** CA гэрээ `myqr-2026-10-26` (эзний шийдвэр: хувилбаржуулалтгүй, шууд солих).
- **Хаана:** `src/…/Qr/EidQr.cs`, `src/…/Qr/EidQrClient.cs`, `tests/…/QrTests.cs` (`testdata/qr_vectors.json` устгасан),
  README, csproj тайлбар. CA-ийн `testdata/myqr_vectors.json` (902e0b4e) хуулагдаж SHA-256 `MYQR_VECTORS_SHA256`-д бэхлэгдсэн — бүх кейс давсан.
- **Шалгасан:** `dotnet test` 215/215 (macOS, .NET 8.0.427), `dotnet format --verify-no-changes`; тест дотор үүсгэсэн
  PKI дээр §7-ийн кейсүүд (+ хил), stub RP-API (body, nonce 22, 404/403/409/410, USER_REFUSED, QR_PENDING).

## 0.12.0 — 2026-10-24

### Removed (BREAKING) — гарын үсгийн зураг / байгууллагын тамганы зураг

- **Юу:** 0.9.0-д нэмэгдсэн зургийн функц бүрэн хасагдав: `SignatureAppearance.SignatureImage` / `StampImage`,
  `PdfImage`, `Completed.Images` (бүртгэлийн `images`, 409 `IMAGE_MISMATCH` код), alpha/zlib FDICT шалгалт, зурагтай
  байрлал (220×110 / 240×147.5). Харагдах тамга өмнөх QR тамга руу буцна — гаралт 0.8.1-тэй байт-ижил. Эдгээрийг
  ашиглаж буй код compile хийгдэхгүй — устгана уу. «Миний QR» (`GeregeSystems.EidMongolia.Qr`) хэвээр.
- **Яагаад:** зургийн функцийг бүх системээс (CA, портал, апп, SDK) бүрэн хасах шийдвэр (2026-10-24).
- **Хаана:** #21-ийг revert; golden v10 → Go reference `9e76888` (`pades-golden-v9`, зурагтай 5 кейс хасагдсан).
- **Шалгасан:** `src/GeregeSystems.EidMongolia.Pades` (Qr-ээс бусад), `testdata/golden`, `build/go-sdk.ref` нь 0.8.1-тэй
  `git diff` хоосон; CI `dotnet test` (golden).

## 0.11.0 — 2026-10-23

### Added — «Миний QR»: нэг удаагийн шалгалт `check`; `result`-ийн хүлээлт дуусахад `QR_PENDING`

- **Юу:** `EidQrClient.CheckAsync(session, serverPoll?)` → `QrCheck(Complete, Presentation)` — нэг `GET /session/{id}` (анхдагч 1 с), COMPLETE+OK бол JWS/JWKS-ээр шалгасан presentation;
  татгалзсан / CA-ийн TIMEOUT бол SessionFailed. **Зан төлөвийн өөрчлөлт:** `result`-ийн өөрийн хүлээх хугацаа дуусахад
  (CA-ийн session идэвхтэй хэвээр) өмнө нь SessionFailed `TIMEOUT` байсан бол одоо `EidQrException` `QR_PENDING` (`EidQrErrorCodes.Pending`) — CA-ийн жинхэнэ `TIMEOUT`-оос
  ялгагдана.
- **Яагаад:** demo-ийн кассын хуудас polling хийхэд «иргэн хараахан зөвшөөрөөгүй» ба CA-ийн TIMEOUT ялгагдахгүй байсан
  (demo `session.poll` + `qr.verify`-ээр тойрсон) — SDK gap.
- **Хаана:** QR модуль, тест, README. Release 0.11.0.
- **Шалгасан:** stub CA: RUNNING → `check` RUNNING; COMPLETE → presentation; endResult TIMEOUT → SessionFailed (`result`, `check`);
  RUNNING + хүлээлт дууссан → `QR_PENDING`. Бүх тест, lint/format.

## 0.10.0 — 2026-10-23

### Added — «Миний QR» RP client (`GeregeSystems.EidMongolia.Qr`)

- **Юу:** `EidQr.Parse` (`EIDMN-QR1:<token>` эсвэл токен), `EidQrClient.StartAsync` → `POST /authentication/qr` (`qr`,
  `attributes`, ACSP_V2 rpChallenge 32 байт, `nonce`?) → `QrSession` (JSON-оор хадгална), `ResultAsync` → session
  long-poll + CA-ийн presentation JWS (ES256) шалгалт: JWKS (`JwksUrl`, анхдагч
  `https://ca.eidmongolia.mn/.well-known/eid-jwks.json`, 1 ц кэш, танихгүй kid → ≥30 с-ийн зайтай дахин татна, RP secret
  илгээхгүй), iss / aud (RP UUID) / sid / nonce / iat (+60 с, −10 мин) / exp, attrs ∪ unavailable = хүссэн яг, аттрибут
  бүрийн төрөл → `QrPresentation(Sub, Attrs, Unavailable, …)`. `EidQr.VerifyPresentation` (сүлжээгүй), `VerifyAsync`.
  `EidQrException.Code`: `QR_FORMAT_INVALID`, `QR_TOKEN_INVALID` (404), `QR_ATTRIBUTES_INVALID`,
  `QR_PRESENTATION_INVALID`, `QR_JWKS_UNAVAILABLE`, `SESSION_FAILED` (`EndResult`), серверийн code / `HTTP_ERROR`
  (`HttpStatus`), `NETWORK_ERROR`. Багц нэр хэвээр (`GeregeSystems.EidMongolia.Pades`), шинэ хамааралгүй.
- **Яагаад:** CA гэрээ «Миний QR» v1 (2026-10-23) — RP SDK тал (TS / Go-той ижил).
- **Хаана:** `src/…/Qr/EidQr.cs`, `src/…/Qr/EidQrClient.cs`, `tests/…/QrTests.cs`, `testdata/qr_vectors.json` (Go / TS-д
  ижил), README, csproj тайлбар.
- **Шалгасан:** `dotnet test` (229/229, macOS .NET 8.0.426), `dotnet format --verify-no-changes`; vector 11 parse + 30
  verify Go/TS/.NET гурвуулаа давсан; stub handler: body, nonce=rpChallenge, JWKS кэш + kid rotation, 404,
  USER_REFUSED, aud/attr/nonce зөрөх, JWKS алга/http.

## 0.9.0 — 2026-10-23

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
  `build/go-sdk.ref` → eid-mongolia-sdk-go v0.16.0 (`81402d6`).
- **alpha FDICT** — FLG-ийн FDICT бит тавигдсан alpha (DICTID = 1 ч) `REQUEST_INVALID` (Go v0.16.0-тэй ижил); README ба
  `SignatureRegistration.Images`-д 409 `IMAGE_MISMATCH` (CA одоогийн зурагтай таарахгүй).
- **Шалгасан:** `dotnet test` (net8.0, macOS) — 221/221, golden v10-ийн `img-*` 7 тохиолдол бүгд байт-ижил (v9 хэвээр);
  `AppearanceImageTests` — 14 буруу оролт (`alpha FDICT 1` орсон), анхдагч хэмжээ, бүртгэлийн `images`. `dotnet format --verify-no-changes` цэвэр.

## 0.8.1 — 2026-10-21

### Fixed — PDF lexer: массив доторх `endobj` дээр мөнхийн давталт

- **Юу:** `Lexer.ReadArray` массив дотор `endobj` таарвал `PdfFormatException` (Prepare → `PDF_INVALID`) шиднэ. Өмнө нь
  `ReadObject` `endobj`-г буцааж «уншаагүй» болгодог тул давталт ахихгүй, санах ой хязгааргүй өсдөг байв.
- **Яагаад:** хортой/эвдэрсэн PDF Prepare-ийг гацааж болох байв (Go SDK/CA-ийн digitorus fork-ийн засвартай ижил).
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/Pdf/Lexer.cs`; тест `tests/…/LexerTests.cs` (10 с-ийн хугацаатай).
  Бусад давталт (hex/literal мөр, EOF массив, Structure/Occupancy сканнер, ObjStm `/Extends`) аль хэдийн ахиц/хязгаартай.
- **Шалгасан:** CI (Windows + Linux `dotnet test`, PR #19) ногоон — локалд dotnet байхгүй.

## 0.8.0 — 2026-10-21

### Tests — pades golden v8 (verify page chain with non-zero object generations)

- **Юу:** golden-ийг eid-mongolia-sdk-go #40 (`21f8434`, `pades-golden-v8`) руу бэхэлсэн: `input/verify-gen1.pdf`
  (verify хуудас `6 1 obj`, docId Link `7 1 obj`, URI action `8 2 obj`) ба кейс `verify-gen1`, `page0-verify-gen1`,
  `page-explicit-verify-gen1`.
- **Яагаад:** PLACEMENT_SPEC §1a «Object generations» — docId-ийг xref-ийн бодит generation-оор уншина (Swift port 0 гэж
  таамагладаг байсныг CA репод зассан). .NET аль хэдийн зөв — кодын өөрчлөлтгүй.
- **Хаана:** `build/go-sdk.ref`, `testdata/golden/`.
- **Шалгасан:** `build/sync-golden.sh --check`; `dotnet test` — 182/182 (шинэ 3 `MatchesGoReference` кейс байт-ижил).

### Added — `PrepareOptions.VerifyPagePosition` ("last" | "first"), golden v9

- **Юу:** `VerifyPagePosition = "first"` — шалгах (QR) хуудас үндсэн `/Pages /Kids`-ийн эхэнд орж 1-р хуудас болно; анхдагч
  `"last"` (null/хоосон) өмнөхтэй байт-ижил; бусад утга `REQUEST_INVALID`. `Appearance.Page`, `SuggestPlacement`,
  `Placement.Page` оролтын PDF-ийн хуудсаар (SDK дотроо +1 болгож зурна).
- **Яагаад:** портал/desktop-ийн «Баталгаажуулалтын хуудсыг эхэнд» сонголт; Go v0.15.0 (#41), PAGE_SPEC §8a, PLACEMENT_SPEC §1b.
- **Хаана:** `Models.cs`, `EidPades.cs`, `Pdf/VerifyPage.cs`; `GoldenTests.cs` (manifest-ийн түлхүүр); `build/go-sdk.ref` →
  Go `9e76888` (`pades-golden-v9`), `testdata/golden/`.
- **Шалгасан:** CI (Windows + Linux `dotnet test`, golden-sync) — v9-ийн 8 `vpfirst-*` кейс Go-той байт-ижил.

## 0.7.0 — 2026-10-21

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

## 0.6.0 — 2026-10-20

### Fixed — `Registration`: medium ба claimedRole-ийг CA-аас өмнө шалгана

- **Юу:** `EidPades.Registration` — `Medium` хоосон бол `SessionId`-ээс тооцсоор (phone ⇔ sessionId); `phone` +
  `SessionId`-гүй, `token` + `SessionId`, бусад `Medium` утга → `REQUEST_INVALID`. `Completed.ClaimedRole` (шинэ;
  state-ээс) байхад `RegistrationOptions.OnBehalfOf` хоосон бол `REQUEST_INVALID`.
- **Яагаад:** 2026-10-20-ны SDK аудит — таван SDK (TS, Go, .NET, Swift, Kotlin) нэг дүрмээр; CA эдгээрийг хожим 400-аар
  татгалздаг байсан.
- **Хаана:** `src/GeregeSystems.EidMongolia.Pades/Registration.cs`, `Models.cs` (`Completed.ClaimedRole`), `EidPades.cs`,
  `README.md`; тест `ErrorTests.cs` (medium, claimedRole, RSASSA-PSS → `SIGNATURE_INVALID`), `GoldenTests.cs`.
- **Шалгасан:** CI `dotnet test` (Windows + Linux).

### Docs — README / XML doc нь 0.5.0-ийн API-тай нийцэв

- **Юу:** README-ийн жишээнд `using System.Text.Json;` дутуу байсан (`JsonSerializer` compile болдоггүй); `ClaimedRole`
  тавьсан жишээ `RegistrationOptions.OnBehalfOf`-гүй байсан (CA-д заавал). Алдааны хүснэгтэд `Internal` / `INTERNAL`
  нэмэв; `PDF_INVALID`-ийн бүтцийн хязгаарыг PRECHECKS #2a/#2b-тэй тулгав (`/Extends` > 64). XML doc:
  `PrepareOptions.Lang` хоосон = `mn`.
- **Яагаад:** Swift/Kotlin/Go баримттай нийцүүлэх аудит (2026-10-20); код өөрчлөгдөөгүй.
- **Хаана:** `README.md`, `src/GeregeSystems.EidMongolia.Pades/Models.cs` (зөвхөн `///`).
- **Шалгасан:** README-ийн урсгалын жишээг scratch console төсөлд (`ProjectReference` → src) `dotnet build` — алдаагүй;
  засвараас өмнө `CS0103 JsonSerializer`.

## 0.5.0 — 2026-10-19

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


## 0.4.0 — 2026-10-19

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
  `Models.cs`, `EidPades.cs`; golden pin `build/go-sdk.ref` → 4e87dc1 (#34: golden v5 + `placement/`, 29 vector).
- **Verified:** `dotnet test` — all 21 `placement/vectors.json` vectors box-for-box, the 6 golden v5 cases and every
  existing golden case byte-identical with `expect.placement`; robustness tests on arbitrary/malformed content and
  Flate streams; `dotnet format --verify-no-changes`; `sync-golden.sh --check`.
- **Remaining:** release (version bump) — not part of this change.

## 0.3.0 — 2026-10-19

### Added — `Completed.FileName`, `EidPades.Registration` (CA бүртгэлийн бие) (0.3.0)

- **Юу:** `Prepare`-ийн цэвэрлэсэн `fileName` state-ээр (`"fileName"`, Go state-тэй ижил түлхүүр) дамжиж
  `Completed.FileName`-д ирнэ. `EidPades.Registration(done, RegistrationOptions)` → `SignatureRegistration` —
  CA `POST /pdf/signatures`-ийн бие (JSON талбарын нэр CA DTO-тэй яг ижил; `System.Text.Json`-оор шууд сериализ): өмнөх
  гарын үсгүүд зөвхөн `priorCmsSha256`-аар, хос түлхүүр нь `PriorSignatures`-д (`[JsonIgnore]`); `medium` анхдагч =
  `SessionId` байвал phone, эс бөгөөс token; `signerEtsi` = гэрчилгээний SERIALNUMBER; эхний гарын үсэг хуудасгүй эсвэл
  fileName хоосон → `REQUEST_INVALID`. Go `pades.Registration`, TS `registrationFromCompleted`-тэй ижил хэлбэр.
- **Яагаад:** 10-15 аудит («Native PAdES»): .NET-ийн `Completed`-д fileName байгаагүй, `PriorCmsSha256` ба
  `PriorRevisionSha256` хоёулаа бүтэн ирдэг тул апп хоёуланг нь CA руу дамжуулахад 400 болдог.
- **Хаана:** `Registration.cs` (шинэ), `Models.cs`, `State.cs`, `EidPades.cs` (partial); README «Урсгал» алхам 4.
- **Шалгасан:** golden тест бүрд `Completed.FileName` = цэвэрлэсэн нэр, `Registration`-ийн JSON-д `priorRevisionSha256`
  алга, `PriorSignatures` = өмнөх кейсийн `sigRevSha256`, `signerEtsi`.
- **Үлдсэн:** 409 `PRIOR_MISMATCH`-ийн дахин оролдлого — .NET-д CA HTTP клиент байхгүй тул дуудагч (README-д заасан).

- **Release: nuget.org-д нийтэлнэ (Trusted Publishing).**
  - Юу: `release.yml` — `v*` tag дээр `GeregeSystems.EidMongolia.Pades` багцыг GitHub Release + GitHub Packages-аас гадна
    nuget.org-д push хийнэ; `NuGet/login@v1` (OIDC, `id-token: write`) богино хугацааны key авдаг тул repo secret хэрэггүй.
  - Яагаад: `dotnet add package GeregeSystems.EidMongolia.Pades` шууд ажиллахгүй байсан (зөвхөн GitHub Release `.nupkg`).
  - Хаана: nuget.org Trusted Publishing бодлого — эзэн `geregecore`, glob `GeregeSystems.EidMongolia.*`, workflow `release.yml`.
  - Шалгасан: workflow синтакс; бодит push дараагийн tag (0.3.0) дээр.

### Security — `CompleteAsync`: OCSP/CRL тохирол ба шинэлэг байдал, revoked = хатуу алдаа; `Prepare`: бүтцийн урьдчилсан шалгалт (0.3.0)

- **Юу (зан төлөвийн өөрчлөлт — аюулгүй байдлын засвар; Go SDK v0.8.0 / TS 0.21.0-ийн порт):**
  - `CompleteAsync` (LTV цуглуулалт): OCSP хариу нь ЭНЭ гэрчилгээнийх — CertID = олгогчийн нэр/түлхүүрийн hash + serial
    (өмнө нь зөвхөн serial). CRL нь гэрчилгээний олгогчийнх — нэр = cert.Issuer = issuer.Subject, AKI = олгогчийн SKI,
    олгогчийн гарын үсэг. «good» нотолгоо одоо шинэлэг: thisUpdate ≤ одоо + 5 мин, nextUpdate ≥ одоо − 5 мин,
    thisUpdate ≥ одоо − 24 ц эсвэл [thisUpdate, nextUpdate] нь одоог хамарна (`Revocation.FreshAt`).
  - OCSP «revoked» эсвэл гэрчилгээг агуулсан CRL → тэр дор нь `LTV_UNAVAILABLE`, `InnerException` =
    `CertificateRevokedException` (шинэ public төрөл), дахин оролдохгүй. Өмнө нь revoked OCSP-г ерөнхий алдаа гэж алгасаад
    цэвэр CRL-ээр (эсвэл CRL хоосон) DSS угсарч **амжилттай** дуусдаг байв (10-15 SDK аудит).
  - `Prepare`: задлахаас өмнө PRECHECKS #2a/#2b — массив/толийн давхарлалт > 256, ObjStm өөрийгөө/харилцан агуулах, толгойн
    лавлагаа ObjStm руу, `/Extends` мөчлөг эсвэл > 64, `/Size` > 2^21 → `PDF_INVALID` (`CompleteAsync`-д state-ийн PDF →
    `STATE_INVALID`). Өмнө нь ийм баримт задлагчийн рекурсээр `StackOverflowException` өгч процессыг бүхэлд нь унагадаг
    байв (catch барихгүй).
  - PRECHECKS #4: `/Encrypt << … >>` шууд толь (уншигч нээж чадахгүй үед) → `PDF_ENCRYPTED` (өмнө нь `PDF_INVALID`).
  - LTV алдааны мессежээс гэрчилгээний subject (иргэний нэр — PII) хасагдаж serial-аар солигдсон.
- **Яагаад:** 10-15 SDK аудитын олдвор (fail-open цуцлалт, гүн рекурс) — Go/TS-тэй ижил дүрэм.
- **Хаана:** `Crypto/Revocation.cs` (шинэ: `FreshAt`, `CrlFor`, `CrlListed`, `OcspCertIdMatches`, `CertRef`),
  `Crypto/Ltv.cs`, `Crypto/X509Util.cs` (`Crl.ThisUpdate`, `AuthorityKeyId`), `Pdf/Structure.cs` (шинэ: Go
  `CheckStructure` + `checkObjStmGraph`), `Prechecks.cs`, `EidPades.cs`, `EidPadesException.cs`
  (`CertificateRevokedException`); `build/go-sdk.ref` → Go v0.8.0 (0fe194c), `testdata/golden` дахин синк (зөвхөн README
  өөрчлөгдсөн — prepare/complete-ийн гаралт v3-тай байт-ижил); `testdata/structure/` (Go/TS-ийн сөрөг оролт).
- **Шалгасан:** `dotnet test` (79: golden 17 кейс Go-тэй байт-ижил; `RevocationTests` — stale/expired/future/өөр CertID/өөр
  serial OCSP, өөр олгогч/stale/future CRL, revoked OCSP + цэвэр CRL, good OCSP + revoked CRL, Complete → LTV_UNAVAILABLE +
  CertificateRevokedException, мессежид нэр алга; `StructureTests` — давхарлалт 256/257/100 000, ObjStm мөчлөг/`/Length`,
  `/Size`, fuzz seed, `deep-nesting*.pdf`, `/Encrypt` шууд толь); `dotnet format --verify-no-changes`;
  `sync-golden.sh --check`.

## 0.2.0 — 2026-10-15

- **PAdES: харагдах гарын үсэг (сонголттой), `Completed.PriorRevisionSha256` + golden v3.**
  - Юу: `PrepareOptions.Appearance` (`Appearance { Page, X, Y, Width, Height, Lang }`) — сонгосон хуудсан дээр `/Rect`-тэй
    widget (`/F 4`, `/P`, `/Annots`-ийн төгсгөлд), `/AP /N` шахалтгүй form XObject (verify хуудасны Noto Sans фонт, өөрийн
    QR `https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`, нэр/үүрэг/label/огноо, `/Rotate` 0/90/180/270-ийг content
    `cm`-ээр). `null` бол үл харагдах — golden v2-тэй байт-ижил. Байршил/хэмжээ/хуудас буруу, бичвэр багтахгүй, docId-гүй
    гарын үсэгтэй баримт → `REQUEST_INVALID`. `Completed.PriorRevisionSha256` — өмнөх гарын үсэг бүрийн revision-ий
    SHA-256 (`PriorCmsSha256`-тэй ижил дараалал; Go `PriorRevisionSHA256`). Энэ SDK-д CA register клиент байхгүй тул
    PRIOR_MISMATCH retry хамаарахгүй.
  - Яагаад: Go reference (`eid-mongolia-sdk-go` `pades-golden-v3` = 55bcb0a, `pades/APPEARANCE_SPEC.md`)-тэй native SDK
    бүр байт-ижил.
  - Хаана: `Pdf/SignatureAppearance.cs` (шинэ, Go `core/appearance.go`-ийн 1:1 порт), `Pdf/SignatureRevision.cs` (харагдах
    салаа), `Pdf/VerifyPage.cs` (`FontBodies`, `WrapLimit`, `GlyphHex` гаргасан — verify хуудасны байт өөрчлөгдөөгүй),
    `EidPades.cs` (`CheckAppearance`, `VisibleSpec`, prior revision), `Models.cs`; `build/go-sdk.ref` → 55bcb0a,
    `testdata/golden` дахин синк. `ErrorTests.EcdsaSignatureFormatsAreAccepted`-ийн CA/leaf хугацааны race (UtcNow хоёр
    удаа) засав.
  - Шалгасан: `dotnet test` — golden v3-ийн 17 кейс бүгд (харагдах 5 орно) гаралтын PDF бүхэлдээ Go-тэй байт-ижил,
    `PriorRevisionSha256` = өмнөх кейсийн `sigRevSha256`; Go `TestAppearanceRejects`-ийн толь (13 + 45 pt хамгийн бага,
    docId-гүй баримт); `dotnet format --verify-no-changes`; `sync-golden.sh --check`.

## 0.1.0 — 2026-10-14

- **Анхны хувилбар — `GeregeSystems.EidMongolia.Pades` (net8.0), native C# client-side PAdES** (профайл `pades-client/1`).
  Яагаад: PDF клиентээс гарахгүй (Smart-ID загвар); хэрэглэгчийн шийдвэрээр (2026-10-14) Go цөмийг DLL/WASM-аар түгээхгүй,
  платформ бүр өөрийн native SDK + нийтлэг conformance suite.
- `EidPades.Prepare` (PRECHECKS → bilingual verify хуудас (PAGE_SPEC, QR, Noto Sans subset) → гарын үсгийн revision →
  signedAttrs/DTBS → Go-тэй ижил формат state) ба `EidPades.CompleteAsync` (DTBS дээрх RSA/ECDSA шалгалт → RFC 3161 TSA
  → CMS → embed → OCSP/CRL (genTime-ийн дараа, үндэсний CRL толин) → шахалтгүй DSS revision → хөнгөн self-check) →
  `Completed` (CA `POST /pdf/signatures`-ийн мета). Validator-гүй. `EidPadesException` тогтвортой `Code`-той.
- Хаана: `src/GeregeSystems.EidMongolia.Pades/{Pdf,Crypto}`, golden `testdata/golden` (`build/sync-golden.sh`,
  eid-mongolia-sdk-go `pades-golden-v2` = `build/go-sdk.ref`). CI: Windows + Linux тест, `golden-sync`, `changelog`;
  release: `v*` tag → GitHub Release asset + GitHub Packages.
- Шалгасан: golden 12 тохиолдол (verify хуудас mn/en, xref table/stream/linearized, 2 дахь гарын үсэг, foreign,
  encrypted) — гаралтын PDF бүхэлдээ Go-тэй байт-ижил; eid-desktop (Swift) golden; алдааны замууд; ECDSA r‖s/DER.
