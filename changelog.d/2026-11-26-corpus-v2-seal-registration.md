### rp-conformance/2, тамганы бүртгэл (CA V158), PAdES golden v13

**Юу.** (1) Cross-SDK корпус `rp-conformance/2`-г Go `a537226`-оос (`build/go-sdk-conformance.ref`) дахин хуулж, бүхэлд нь
давна: rp-validate 88, OCSP 24, wire 26, eidlogin 34 сценари; eidlogin harness шинэ оролтуудыг (`wireCookieName`,
`cookieDomain`, `cookiePath`, `clientIp`, `auditKeyHex`, `rateLimits`, `cookieHeader`, `absentAttributes`) ойлгоно (танихгүй
түлхүүр → FAIL хэвээр). (2) Тамганы бүртгэл — `client.Seal.RegisterSealedPdfAsync(orgEtsi, SealRegistration)`
(`POST /seal/{orgEtsi}/registrations`; сүлжээгүй хэлбэрийн шалгалт, 201 → `Created`, PRIOR_MISMATCH-ийн хослолын давталт),
`client.Seal.SealForDocumentAsync` (`{docId, revIndex}` нөөц), `SealRegisterErrorCodes.All` (CA-ийн дараалал), шинэ кодууд
`SEAL_NOT_FOUND` / `SEAL_DOC_MISMATCH` / `DOC_ID_RESERVED` (`EidSealNotFoundException`, `EidSealDocMismatchException`,
`EidDocIdReservedException`). Pades: `SealOptions.Qr` / `DocId` / `FileName`, нөөцөлдөг `SealAsync` overload
(`SealReservation`; хуучин delegate хэвээр), `EidPades.SealRegistration(completed)`, `Completed.SealRegistration`; QR-тэй
тамганы дардас (APPEARANCE_SPEC §6.5) ба docId-ийн дүрэм (§6.6 — verify хуудас, дараа нь хамгийн эрт /EIDVerify тамга, дараа
нь options; гарын үсэгтэй баримтад санамсаргүй docId үүсгэхгүй). PAdES golden v12 → v13 (`build/go-sdk.ref` = Go `a537226`,
golden нь `499aa5c`-тэй ижил). (3) Гэрээний тест: `POST /seal/{orgEtsi}/registrations` замын хүснэгтэд (33 зам),
`endpoints.seal.registration`-ийн талбарууд, `seal.registerErrorCodes`, `{docId, revIndex}` нөөцийг live discovery-тэй тулгана.

**Яагаад.** Go #74/#75 ба TS #98/#99-тэй нийцэл (нэг корпус, нэг дүрэм) ба CA V158-ийн QR-тэй тамга.

**Хаана.** `src/GeregeSystems.EidMongolia/{Validator,Ocsp,SealRegister,Seal,Errors,Http,Routes}.cs`, `Login/*`;
`src/GeregeSystems.EidMongolia.Pades/{Seal,EidPades,Prechecks,Models}.cs`, `Pdf/SignatureAppearance.cs`; тестүүд;
`testdata/conformance`, `testdata/golden`; README (mn/en/zh).

**Шалгасан.** PR CI (windows + ubuntu, net8.0 + net10.0; `conformance-sync`, `golden-sync`, `compat`, `contract`). Локалд
dotnet ажиллуулаагүй.

### Security

- **Login cookie-ийн анхдагч нэр `__Host-eid_login`** (Secure, `CookieDomain`-гүй, `CookiePath` = `/` үед; бусад үед
  `eid_login`; өгсөн `CookieName` хэвээр). Шинэчилсний дараа явагдаж буй нэвтрэлт (хуучин `eid_login` cookie-тэй) НЭГ удаа
  `EXPIRED` болж дахин эхэлнэ. Хүсэлтэд login cookie нэгээс олон бол cookie-гүй гэж үзнэ (дэд домэйн / өөр замаас тарьсан
  cookie жинхэнийг сүүдэрлэхгүй) — status `EXPIRED`, callback `eid_error=expired`.
- **Rate-limit түлхүүр:** push нь `push:<pushKey>` (`AuditKey`-ийн HMAC, `OnEvent`-ийн `meta.pushKey`-тэй ижил) — регистрийн
  дугаар хязгаарлагч ба өөрийн `RateLimit` / `RateLimits[..].Func` hook-д ОЧИХГҮЙ. Өөрийн hook-оо `push:<idCode>`-оор
  тохируулсан бол шинэчил. `ClientIp` тохируулсан ч IP хоосон бол нийтийн `start:unknown` bucket (өмнө нь хязгааргүй); IPv6
  /64 түлхүүр нь 4 hextet, тэг хураахгүй (`fe80:0:0:0::/64`; өмнө нь `fe80::/64`), `[…]` ба `%zone` зөвшөөрнө. Санах ойн
  хязгаарлагч дүүрвэл шинэ түлхүүр татгалзагдахгүй — нэг нийтийн overflow bucket (`EidLoginRateRule.MaxKeys`, анхдагч 10 000).
- **Validator:** issuer allowlist нь олдсон issuer-ийн ЗӨВХӨН SKI-г (SKI extension-гүй CA-д RFC 5280 арга 1-ийн танигч)
  тулгана; leaf-ийн AKI зөвхөн issuer олдоогүй үед (AllowUntrusted) — өмнө нь SKI-гүй issuer-т leaf-ийн AKI-д буцдаг байсан.
- **OCSP:** өгсөн issuer CA биш эсвэл RSA түлхүүр сул бол кэш/сүлжээнээс өмнө `no_issuer`; delegated responder-ийн сул RSA
  түлхүүр → `signature`; serial-тай БҮХ SingleResponse-ийн CertID issuer-тэй таарна (эс бөгөөс `invalid`).
- Reason key-ийн нэр өөрчлөгдөөгүй: .NET 0.17.0-ийн `cert.weak_key`, `subject.duplicate_identity` нь корпусын нэр, шалгах
  дараалал (`cert.malformed`-ийн дараа) аль хэдийн ижил.
