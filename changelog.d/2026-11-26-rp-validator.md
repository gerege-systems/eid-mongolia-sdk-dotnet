# RP SDK цөм: Validator, trust roots, OCSP цуцлалт шалгагч, subject (нийтлэгдээгүй)

- **Юу:** `GeregeSystems.EidMongolia` цөмд —
  `client.Validator` (`ResponseValidator`): `ValidateAuth` (ACSP_V2: flowType relay хаалт, userChallengeVerifier,
  callback-ийн дүрэм, алгоритм/hash downgrade хаалт, гарын үсэг), `ValidateSign` (RAW_DIGEST: prehashed RSA-PSS
  (salt = hLen), PKCS#1 v1.5, ECDSA P-256 ASN.1 DER), `ValidateCertificateChoice` → `Signer` (`SignerRef` руу далд
  хөрвүүлэлт — `Sign.DigestForSignerAsync`-д шууд), `CheckRevocationAsync` / `CheckRevocationWithAsync` (hard/soft-fail),
  `CertificateLevelOf`, `ParseSubject` (`CertSubject`), `SignedCallbackUrl`, `VerifyPrehashedSignature`;
  `TrustConfig` (`EidClientOptions.Trust`), `EidTrust` (шигтгэсэн 01–04, `CitizenIssuingCaSki`);
  `OcspRevocationChecker` (`OcspOptions`, `OcspObservation`, `EidOcspException.Kind` = `OcspErrorKinds`);
  `EidValidationException.Reason` нь одоо тогтвортой түлхүүр (`ValidationReasons`, conformance корпусын reason key),
  монгол тайлбар нь `Message`-д.
- **Гинж:** X509Chain ХЭРЭГЛЭХГҮЙ — DER дээр (System.Formats.Asn1 + RSA/ECDsa) өөрийн замын угсралт (TS
  `verifyChain`-ийн порт): basicConstraints/pathLen, keyCertSign, EKU давхарга, хугацаа (leaf-д ClockSkew, CA-д хавчсан
  цаг), issuer SKI allowlist; fail-closed — name constraints-тэй CA (anchor ч мөн) ба жагсаалтад байхгүй critical
  extension татгалзана. Платформ (Windows/Linux) бүрд ижил, AIA татахгүй.
- **OCSP:** Go `ocsp.go`-ийн дүрэм: unknown → revoked, thisUpdate ∈ [now − 48 ц, now + 5 мин], nextUpdate, delegated
  responder (OCSPSigning EKU, хугацаа), олгогч өөрийгөө шигтгэсэн хариу, 2 с / нийт 3 с, 16 KiB, «good»-ийг
  min(5 мин, nextUpdate) кэшлэнэ. Pades-ийн дотоод `Crypto/Ocsp.cs`-тэй давхардсан — WP 5-д core руу нэгтгэнэ.
- **Conformance:** Go `testdata/conformance` (rp-conformance/1, `a0b00e248680`)-ийг `testdata/conformance` руу байт-ижил
  хуулав (`build/sync-conformance.sh`, `build/go-sdk-conformance.ref`, CI `conformance-sync` job; `pki/keys` хуулагдахгүй);
  манифестийн SHA-256 ба devicelink/myqr pin-ийг тест шалгана. `ConformanceTests`: rp-validate 77, OCSP 17 (HTTP replay),
  wire 26, interactions_golden, acsp_v2. Хуучин алгасдаг wire ачаалагчийг устгав.
- **Аюулгүйн review-ийн засвар:** RSA түлхүүрийн доод хэмжээ 2048 бит, exponent сондгой ба ≥ 3 (leaf, CA, OCSP
  responder/issuer; сул leaf → шинэ .NET-only түлхүүр `cert.weak_key`, сул trust pool → `ArgumentException`; корпус ба
  бодит 01–04-ийн бүх RSA түлхүүр 2048/4096 — нэг ч кейс өөрчлөгдөөгүй); үл мэдэх `TrustConfig.RequiredLevel` →
  `ArgumentException` (өмнө нь чимээгүй QUALIFIED); гарын үсгийн сөрөг тестүүд (`NegativeTests`: leaf TBS / гарын
  үсгийн байт, завсрын CA-ийн гарын үсэг, өөр түлхүүрээр зурсан issuer нэр + AKI-тай leaf, ACSP_V2 / RAW_DIGEST гарын
  үсэг ба payload/digest, OCSP хариуны гарын үсэг, CA-тай холбоогүй ба хугацаа дууссан delegated responder); бодит
  гинж 01 → 02 → 03 → 04-ийг замын угсралтын бүх CA шалгалтаар тогтмол цагт.
- **Мэдэгдэж буй follow-up (cross-SDK — эхлээд Go/TS/корпуст, энэ PR-д өөрчлөөгүй):** S3 — issuer allowlist шууд
  issuer олдоогүй үед leaf-ийн AKI-д буцдаг; S4 — давхардсан SERIALNUMBER / CN-ийн дүрэм (Go сүүлийнх, TS эхнийх);
  S5 — OCSP-д сүлжээнээс өмнө issuer-ийг шалгах ба CertID-ийн issuerNameHash / issuerKeyHash-ийг тулгах.
- **Хаана:** `src/GeregeSystems.EidMongolia/{Validator,Ocsp,X509,Subject,Roots}.cs`, `Trust/0[1-4]*.pem`, `Errors.cs`,
  `EidClient.cs`; тест `tests/GeregeSystems.EidMongolia.Tests/{Conformance,Validator,Negative}Tests.cs`.
  `GeregeSystems.EidMongolia.Pades` өөрчлөгдөөгүй (My QR-ийн OCSP `unknown` → revoked засвар WP 5-д QR төрлүүдтэй хамт).
- **Хэрхэн шалгасан:** PR CI (Windows + Linux, net8.0 + net10.0) — корпусын бүх кейс, `conformance-sync --check`.
