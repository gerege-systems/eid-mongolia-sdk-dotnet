Монгол · [English](README.en.md) · [中文](README.zh-CN.md)

# eid-mongolia-sdk-dotnet

**eID Mongolia**-ийн .NET (C#) SDK — relying party (RP)-ийн backend-д: иргэнийг нэвтрүүлэх (push, QR, Web2App), гарын үсэг
зуруулах, хариуг криптограф шалгах (гинж, ACSP_V2 / RAW_DIGEST, OCSP), PDF-ийн гарын үсгийн бүртгэл, байгууллага / иргэн /
e-Seal / USB токен / share үйлчилгээ, «Миний QR», «eID-ээр нэвтрэх» товчны backend (ASP.NET Core adapter-тай), мөн
client-side PAdES — PDF баримт eID сервер рүү **хэзээ ч явахгүй** (Smart-ID загвар): баримтыг клиент дээр бэлдэж
(`Prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB токеноор зуруулаад, гарын үсгийг клиент дээр PDF-д суулгана
(`CompleteAsync`; PAdES-BASELINE-LT — RFC 3161 timestamp, OCSP/CRL, DSS).

Энэ нь Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go)) ба TypeScript SDK-ийн
**native C# порт** — native код, DLL, WASM үгүй. CI нь Windows ба Linux дээр Go-ийн PAdES golden vector-уудтай (verify хуудас,
QR, xref, CMS, TSA/OCSP/CRL хүсэлт, DSS) **байт-ижил** гаралтыг, cross-SDK conformance корпусыг (`testdata/conformance`:
validator, OCSP, wire, login backend) шалгадаг.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

| Багц (NuGet) | Юу | Хамаарал |
|---|---|---|
| `GeregeSystems.EidMongolia` | RP SDK: `EidClient` (Auth, Sign, Session, Validator, PDF бүртгэл, Organization, Person, Seal, Token, Share, «Миний QR»), `OcspRevocationChecker`, `EidLoginHandler` | — |
| `GeregeSystems.EidMongolia.AspNetCore` | `services.AddEidMongolia(...)`, `app.MapEidLogin(...)` | core + ASP.NET Core shared framework |
| `GeregeSystems.EidMongolia.Pades` | Client-side PAdES: `EidPades.Prepare` / `CompleteAsync` / `SealAsync` / `Registration`; PDF шалгах `ValidatePdfAsync` | core + `System.Security.Cryptography.Pkcs` (Microsoft) |

- Гурвуулаа нэг хувилбартай (lockstep), `net8.0` ба `net10.0` (multi-target). `net8.0`-ийн runtime 2026-11-10-нд дэмжлэгээс
  гарсан; одоогийн relying party-ууд restore хийж чадахын тулд түр хадгалсан бөгөөд дараагийн хувилбаруудын нэгд хасна.
- Thread-safe, глобал төлөвгүй: нэг `EidClient`-ийг (singleton) бүх хүсэлтэд. API secret зөвхөн backend-д.
- PDF-ийн бүрэн шалгагч — `EidPades.ValidatePdfAsync` (Go `pades.ValidatePDF`, TS `validatePdf`-тэй ижил тайлан; «PDF шалгах»).

## Суулгах

[nuget.org](https://www.nuget.org/profiles/geregecore)-оос:

```bash
dotnet add package GeregeSystems.EidMongolia --version 0.18.0             # RP SDK
dotnet add package GeregeSystems.EidMongolia.AspNetCore --version 0.18.0  # ASP.NET Core-д (core-ийг дагуулна)
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.18.0       # client-side PAdES (core-ийг дагуулна)
```

Хувилбар бүрийн `.nupkg` (+ `.snupkg` symbols) [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases)-д
мөн бий.

## RP SDK — `GeregeSystems.EidMongolia`

Go `eid` ба TS `EidClient`-ийн порт, package хамааралгүй. RP-API: `https://rp.eidmongolia.mn` (анхдагч).

### Client

```csharp
using GeregeSystems.EidMongolia;

// Нэг удаа үүсгэж (singleton) бүх хүсэлтэд хэрэглэнэ.
var client = new EidClient(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "Миний банк", apiSecret), // RP UUID, бүртгэлтэй нэр, API secret
    Trust = new TrustConfig
    {
        TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem },        // production-д ЗААВАЛ (үгүй бол validator fail-closed)
        Revocation = new OcspRevocationChecker().Checker,              // цуцлалт — доорх «Цуцлалт»
        RevocationMode = RevocationMode.HardFail,
    },
    Language = "mn",                                                   // Accept-Language (mn | en)
});
```

- `BaseUrl`: https заавал (http зөвхөн localhost/loopback); хуучин `ca.eidmongolia.mn` хостод тодорхой алдаа. Timeout
  анхдагч 15 с (PDF бүртгэл 80 с), JSON хариу ≤ 4 MiB.
- mTLS: client certificate-тэй `HttpClient`-ийг хоёр дахь аргументаар өгнө (`new EidClient(options, httpClient)`; SDK
  dispose хийхгүй; дуудлага бүрд өөрийн хугацааг тавьдаг тул `HttpClient.Timeout`-ийг `Timeout.InfiniteTimeSpan` болго).
- Алдаа: `EidException` (`Code`, `Status`, `RetryAfter`, `Retryable`) → `EidAuthenticationException` (401),
  `EidForbiddenException` (403), `EidApiException` (CA-ийн код бүрийн дэд анги), `EidNetworkException`,
  `EidResponseTooLargeException`, `EidSessionFailedException` (endResult ≠ OK), `EidValidationException` (`Reason` —
  тогтвортой түлхүүр, `ValidationReasons`), `EidDeviceLinkException`. Салаалахдаа `Code` / `Reason`-ийг ашиглана.

### Нэвтрэлт — push (иргэний утас руу мэдэгдэл)

```csharp
var login = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Миний банк-д нэвтрэх" } };

NotificationSession s = await client.Auth.NotificationByEtsiAsync(etsi, login); // etsi = "PNOMN-…"; эсвэл ByDocumentAsync
Show(s.Vc);                                                                       // хэрэглэгчид баталгаажуулах код
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId, new WaitOptions { ExpiresAt = s.ExpiresAt });
VerifiedIdentity id = client.Validator.ValidateAuth(r, s.Acsp!);                  // гинж, ACSP_V2 гарын үсэг, түвшин, зориулалт
await client.Validator.CheckRevocationAsync(id.Certificate);                      // TrustConfig.Revocation-оор (доор)
// id.Subject.SerialNumber (PNOMN-…), id.Subject.GivenName / Surname, id.CertificateLevel, id.DocumentNumber
```

`ValidateAuth` endResult ≠ OK бол `EidSessionFailedException` (USER_REFUSED, TIMEOUT …), хариунд итгэхгүй бол
`EidValidationException` шиднэ. `AuthOptions`: `CertificateLevel`, `CallbackUrl`, `OnBehalfOf` (байгууллагын нэрийн өмнөөс),
`SignatureAlgorithm`, `HashAlgorithm`.

### Нэвтрэлт — QR, Web2App, App2App (device link)

```csharp
DeviceLinkSession d = await client.Auth.DeviceLinkAnonymousAsync(login);             // эсвэл DeviceLinkByEtsiAsync(etsi, …)
// QR: холбоос секунд тутам шинэчлэгдэнэ (authCode = HMAC-SHA256). SSE / WebSocket-д:
//   await foreach (var link in d.TickQrAsync("mon", TimeSpan.FromSeconds(1), ct)) Send(link);
// HTTP poll-д хүсэлт бүрд: d.BuildLink(DeviceLinkTypes.Qr, "mon").
SessionResult r = await client.Session.WaitForResultAsync(d.SessionId);
VerifiedIdentity id = client.Validator.ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Qr });
```

Web2App: `DeviceLinkAnonymousAsync(login, new AuthOptions { CallbackUrl = "https://bank.example.mn/auth/eid/callback" })`
→ хөтчийг `d.BuildLink(DeviceLinkTypes.Web2App, "mon")` руу илгээнэ → callback-ийн `sessionId` + `userChallengeVerifier` →
`ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Web2App, UserChallengeVerifier = verifier })`.
`d`-ийн `SessionId`, `SessionToken`, `SessionSecret`, `Acsp`-ийг серверт хадгална (хөтөч рүү хэзээ ч бүү илгээ). Бэлэн
шийдэл — доорх «eID-ээр нэвтрэх» товчны backend.

`client.Session.PollAsync(sessionId)` — нэг long-poll; `WaitForResultAsync` нь `MaxWait` → `ExpiresAt` → discovery
`sessionTtl` → 600 с хүртэл (+15 с) давтана. `client.Auth.SessionTtlAsync()` — discovery-ийн session-ий хугацаа.

### Цуцлалт (revocation) — анхдагч горимууд

| Хаана | Анхдагч | Тайлбар |
|---|---|---|
| `client.Validator.CheckRevocationAsync` | `TrustConfig.Revocation` өгөөгүй бол **шалгахгүй** (`RevocationStatus.Skipped`); өгвөл **hard-fail** | OCSP хариугүй → `EidValidationException` (`ValidationReasons.RevocationUnknown`); `RevocationMode.SoftFail` → `Unchecked` |
| «eID-ээр нэвтрэх» backend (`EidLoginHandler`) | `OcspRevocationChecker`, **soft-fail** | OCSP хариугүй бол иргэн нэвтэрнэ (`Identity.Revocation == Unchecked`, Warning лог) — CA-ийн responder унахад бүх хэрэглэгч түгжигдэхгүйн тулд |
| «Миний QR» | AIA-ийн OCSP, **hard-fail** | `QrTrust.RevocationSoftFail = true` бол "unknown"-г хүлээн авна |

**Анхаар: login backend-ийн цуцлалт анхдагчаар soft-fail.** Өндөр үнэ цэнтэй RP (банк, санхүү, төрийн үйлчилгээ, гэрээ
баталгаажуулалт) `o.RevocationMode = RevocationMode.HardFail` тохируулахыг зөвлөнө — тэгвэл OCSP хариугүй үед нэвтрэлт
`FAILED` (`revocation_unavailable`) болно. OCSP-ийн дүрэм Go/TS-тэй ижил: `unknown` → revoked, thisUpdate ∈ [now − 48 ц,
now + 5 мин], nextUpdate өнгөрөөгүй, delegated responder (OCSPSigning EKU), хүсэлт 2 с / нийт 3 с, «good»-ийг ≤ 5 мин
кэшлэнэ; .NET нэмэлтээр сүлжээнээс өмнө issuer leaf-ийг гаргасныг ба хариуны CertID-ийн issuer hash-ийг тулгана.

Гинжийн шалгалт X509Chain-гүй (платформ бүрд ижил): basicConstraints/pathLen, keyCertSign, EKU, хугацаа, иргэний олгогчийн
SKI allowlist (анхдагч 04), RSA ≥ 2048 (exponent сондгой ≥ 3); name constraints-тэй CA, танихгүй critical extension,
SERIALNUMBER/CN давхардсан subject-ийг татгалзана (fail-closed).

### Гарын үсэг ба PAdES

```csharp
using GeregeSystems.EidMongolia.Pades;

// 1. Иргэний SIGN гэрчилгээг сонгуулна.
var cc = await client.Sign.CertificateChoiceByEtsiAsync(etsi);
Signer signer = client.Validator.ValidateCertificateChoice(await client.Session.WaitForResultAsync(cc.SessionId));

// 2. PDF-ийг клиент дээр бэлдэнэ (сүлжээгүй).
var prepared = EidPades.Prepare(pdf, new PrepareOptions { SignerCert = signer.Certificate.RawData, FileName = "Гэрээ №1.pdf", VerifyPage = true });
var dtbs = Convert.ToBase64String(prepared.Dtbs);

// 3. Сонгосон гэрчилгээгээр утсан дээр зуруулна (RAW_DIGEST_SIGNATURE) ба шалгана.
var sign = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Гэрээ №1-д гарын үсэг зурах" } };
NotificationSession s = await client.Sign.DigestForSignerAsync(signer, dtbs, sign);
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId);
VerifiedSignature v = client.Validator.ValidateSign(r, dtbs, HashAlgorithms.Sha256, new ValidateSignOptions { ExpectedCertificate = signer.Certificate });
await client.Validator.CheckRevocationAsync(v.Certificate);

// 4. Гарын үсгийг PDF-д суулгана (TSA, OCSP/CRL) — доорх «PAdES».
Completed done = await EidPades.CompleteAsync(prepared.State, Convert.FromBase64String(v.SignatureValueB64), cancellationToken: ct);
```

Бусад: `Sign.DigestByEtsiAsync` / `DigestByDocumentAsync` / `TextByEtsiAsync` (хэш эсвэл текст), `DeviceLinkByEtsiAsync` /
`DeviceLinkByDocumentAsync` / `DeviceLinkForSignerAsync` (QR / Web2App-аар зуруулах), `CertificateChoiceDeviceLinkAsync`;
`SignOptions`: `CertificateLevel`, `CallbackUrl`, `HashAlgorithm`, `SignatureAlgorithm`, `OnBehalfOf`, `FileName`.

### PDF-ийн гарын үсгийн бүртгэл (`POST /pdf/signatures`)

PAdES complete-ийн дараа заавал (docId, `/verify` хуудас). `EidPades.Registration`-ийн бие core-ийн
`PdfSignatureRegistration`-тэй ижил хэлбэртэй:

```csharp
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions { SessionId = s.SessionId });
PdfSignatureRegistered ok = await client.Pdf.RegisterSignatureAsync(new PdfSignatureRegistration
{
    DocId = reg.DocId, RevIndex = reg.RevIndex, Medium = reg.Medium, SessionId = reg.SessionId, Cms = reg.Cms,
    FileName = reg.FileName, InSha256 = reg.InSha256, PageSha256 = reg.PageSha256, SigRevSha256 = reg.SigRevSha256,
    OutSha256 = reg.OutSha256, PriorCmsSha256 = reg.PriorCmsSha256, PriorRevisionSha256 = reg.PriorRevisionSha256,
    OnBehalfOf = reg.OnBehalfOf, SignerEtsi = reg.SignerEtsi,
    PriorSignatures = reg.PriorSignatures.Select(p => new PdfPriorSignature(p.CmsSha256, p.RevisionSha256)).ToList(),
});
// ok.DocId; ok.Created == false — ижил бие дахин илгээгдсэн (идэмпотент). 409 PRIOR_MISMATCH-ийг SDK өөрөө давтана.
```

Алдааны код: `PdfErrorCodes`.

### Байгууллага, иргэн, тамга, токен, share

- **Байгууллага** — `client.Organization.GetRepresentationsAsync(personEtsi)` (иргэн аль байгууллагыг төлөөлөх эрхтэй —
  `OnBehalfOf` / `ClaimedRole`-д), `SealGrantsAsync(personEtsi)`.
- **Иргэн (PKI_READ эрх)** — `client.Person.CertificatesAsync`, `DevicesAsync`, `ActivityAsync(etsi, ActivityQuery)`,
  `SummaryAsync`, `ChildrenAsync`.
- **Байгууллагын тамга (e-Seal)** — `client.Seal.CertificateAsync(orgEtsi)`, `RequestCertificateAsync` /
  `CertificateRequestAsync` / `WaitForCertificateAsync`, `SealAsync(orgEtsi, digest)` (хариуны ECDSA гарын үсэг ба e-Seal
  профайлыг тулгана), тамганы эрх `RequestGrantAsync` / `GrantStatusAsync` / `WaitForGrantAsync`, `SealService.IsSealCertificate`.
  PDF-ийг тамгалах:

  ```csharp
  var cert = await client.Seal.CertificateAsync(orgEtsi);
  Completed stamped = await EidPades.SealAsync(pdf, new SealOptions { SealCert = cert.Certificate, Reason = "Байгууллагын тамга" },
      async (dtbs, ct) => (await client.Seal.SealAsync(orgEtsi, dtbs, ct: ct)).Signature, cancellationToken: ct);
  ```

  **QR-тэй тамга ба CA-ийн бүртгэл** (CA V158, Go/TS-тэй ижил): `SealOptions.Qr = true` нь дардсанд
  `https://ca.eidmongolia.mn/verify/<docId>/<revIndex>` QR зурна; нөөцөлдөг delegate (`SealReservation`) заавал — QR-тэй дардас
  бодитоор зурагдсан үед л нөөц ирнэ, тэгвэл `client.Seal.SealForDocumentAsync`. Дараа нь `done.SealRegistration`-ийг 7
  хоногийн дотор `client.Seal.RegisterSealedPdfAsync`-ээр бүртгэнэ (`/verify/{docId}`-д байгууллагын мөр; 201 → `Created`,
  ижил биеийн давталт 200; 409 `PRIOR_MISMATCH` бол SDK өмнөх мөрийн хослолыг өөрөө оролдоно). QR-гүй тамгыг ч бүртгэж болно
  (`done.SealRegistration` нь docId мэдэгдэх үед үргэлж бөглөгдөнө). Алдааны код — `SealRegisterErrorCodes.All` (CA-ийн
  дарааллаар; `EidSealNotFoundException`, `EidSealDocMismatchException`, `EidDocIdReservedException`).

  ```csharp
  Completed done = await EidPades.SealAsync(pdf, new SealOptions
  {
      SealCert = cert.Certificate,
      Qr = true,                    // DocId = null: шинэ баримтад санамсаргүй; гарын үсэгтэйд verify хуудас / QR тамгаас
      FileName = "Нэхэмжлэх.pdf",   // /verify-д харагдах нэр (PDF-д бичигдэхгүй)
  }, async (dtbs, reservation, ct) => (reservation is null
      ? await client.Seal.SealAsync(orgEtsi, dtbs, ct: ct)
      : await client.Seal.SealForDocumentAsync(orgEtsi, dtbs, reservation.DocId, reservation.RevIndex, ct)).Signature,
      cancellationToken: ct);
  PdfSignatureRegistered reg = await client.Seal.RegisterSealedPdfAsync(orgEtsi, done.SealRegistration!, ct);
  ```
- **USB токен** — `client.Token.IssueCertificateAsync` / `PreviewCertificateAsync` / `CertificateResultAsync` /
  `CertificateInfoAsync`, `TokenService.VerifyTokenCertificates`, токены нэвтрэлт `AuthChallengeAsync` → токен дээр зурах →
  `AuthVerifyAsync` (CA руу илгээхээс өмнө digest, гарын үсэг, гинжийг локалд шалгана), `TokenService.TokenAuthDigest`.
- **Share** — `client.ShareAsync(new ShareRequest { File = signedPdf, Filename = "Гэрээ.pdf", To = new[] { "user@example.mn" } })`
  (гарын үсэгтэй PDF-ийг 1–5 хүлээн авагч руу eID-ийн имэйлээр), `ShareInfoAsync()` (хязгаар).

### «eID-ээр нэвтрэх» товчны backend (`EidLoginHandler`, ASP.NET Core)

TS SDK-ийн `<eid-login-button>`-ийн backend: `POST {base}/start` (`{"mode":"qr"}` | `{"mode":"push","idCode":"УБ12345678"}`),
`GET {base}/start?mode=web2app`, `GET {base}/status`, `GET {base}/callback` (Web2App). Framework-аас хамааралгүй цөм —
`GeregeSystems.EidMongolia.Login.EidLoginHandler` (`HandleAsync(EidLoginRequest)` → `EidLoginResponse`); ASP.NET Core-д
`GeregeSystems.EidMongolia.AspNetCore`:

```csharp
using GeregeSystems.EidMongolia;
using GeregeSystems.EidMongolia.AspNetCore;
using GeregeSystems.EidMongolia.Login;
using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

builder.Services.AddEidMongolia(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "Миний банк", apiSecret),
    Trust = new TrustConfig { TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem } },
});
// Reverse proxy (nginx г.м.)-ийн ард: зөвхөн өөрийн proxy-д итгэж RemoteIpAddress-ийг засна.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Add(IPAddress.Parse("192.0.2.10")); // таны proxy-ийн хаяг
});
var app = builder.Build();
app.UseForwardedHeaders();
app.MapEidLogin("/auth/eid", async (http, id) =>
{
    // Иргэнийг id.Etsi (PNOMN-…)-ээр таньж ШИНЭ session үүсгэнэ (session fixation).
    await SignInAsync(http, id.Etsi);
    return new EidLoginSuccess { Redirect = "/dashboard" };
}, o =>
{
    o.CallbackUrl = "https://bank.example.mn/auth/eid/callback"; // Web2App (зам заавал /auth/eid/callback)
    o.FailureRedirect = "/login";
    o.RevocationMode = RevocationMode.HardFail;                   // өндөр үнэ цэнтэй RP-д (анхдагч soft-fail)
});
```

**Client IP ба proxy.** `start`-ийн хязгаар (нэг IP-ээс 60 с-д 20) клиентийн IP-ээр. `MapEidLogin`-ийн анхдагч
`o.ClientIp = EidLoginClientIp.RemoteAddress` (`HttpContext.Connection.RemoteIpAddress`). Reverse proxy-ийн ард:
(а) дээрх шиг `UseForwardedHeaders`-ийг `KnownProxies` / `KnownNetworks`-тэй `MapEidLogin`-оос өмнө, эсвэл (б)
`o.ClientIp = EidLoginClientIp.Forwarded(n)` (n = итгэмжит proxy-ийн тоо; `X-Forwarded-For`-ийн баруунаас n дахь утга). Аль
нь ч үгүй бол бүх хэрэглэгч proxy-ийн нэг IP-ийн хязгаарыг хуваалцана; proxy-гүй үед `Forwarded(n)` бүү хэрэглэ (header
хуурамчаар бичигдэнэ). IPv6 клиентийн түлхүүр нь /64 угтвар (`start:2001:db8:1:2::/64`); `ClientIp` тохируулсан ч IP
тодорхойгүй бол хязгааргүй биш — нийтийн `start:unknown` bucket. Push-ийн түлхүүр нь `push:<pushKey>` (`AuditKey`-ийн HMAC,
`OnEvent`-ийн `meta.pushKey`-тэй ижил) — регистрийн дугаар хязгаарлагч ба `RateLimit` hook-д очихгүй. Санах ойн хязгаарлагч
төрөл тус бүрд `EidLoginRateRule.MaxKeys` (анхдагч 10 000) түлхүүр хадгална; дүүрвэл шинэ түлхүүрүүд нэг нийтийн overflow
bucket-д тоологдоно (татгалзахгүй, байгаа тоолуурыг арилгахгүй).

**Cookie.** Анхдагч нэр `__Host-eid_login` (Secure, `CookieDomain`-гүй, `CookiePath` = `/` — хөтөч дэд домэйноос тарьсан
cookie-г энэ нэрээр хүлээн авахгүй); `InsecureCookie`, `CookieDomain` эсвэл өөр `CookiePath` үед `eid_login`; `CookieName`-ийг
өгвөл хэвээр. Хүсэлтэд энэ нэртэй cookie нэгээс олон бол cookie-гүй гэж үзнэ (status → `EXPIRED`, callback →
`eid_error=expired`).

Аюулгүй байдал Go `eidlogin` / TS `createEidLogin`-тэй ижил: төлөв серверт (`IEidLoginStore`; анхдагч `MemoryEidLoginStore` —
нэг процесс, 10 000 дээд хэмжээ; олон instance бол Redis г.м. өөрийн store-оо `AddEidMongolia`-аас ӨМНӨ бүртгэ), хөтчид
зөвхөн HttpOnly + Secure + SameSite=Lax cookie (`<sessionId>.<binding>`, binding-ийн SHA-256-г тогтмол хугацаанд тулгана),
`Sec-Fetch-Site` cross-site → 403, хязгаар (start: нэг IP-ээс 60 с-д 20; push: нэг дугаарт 60 с-д 3), бүртгэлгүй дугаарт
decoy session + push-ийн 1 с доод хугацаа, ValidateAuth + OCSP (**soft-fail анхдагч**, дээрх «Цуцлалт») дараа л `OnSuccess`
(нэг удаа), аудитын `OnEvent` (регистрийн оронд HMAC pushKey). Хариуны хэлбэр ба 12 алдааны код нь cross-SDK корпусын
`testdata/conformance/eidlogin/scenarios.json`-оор (34 сценари, eidlogin/2) тулгагдана. Бусад framework-д `EidLoginHandler`-ийг шууд
дуудна (`EidLoginRequest` — method, URL, header, бие, `RemoteIp`).

## «Миний QR» — иргэний «Миний мэдээлэл» (`GeregeSystems.EidMongolia.Qr`)

0.17.0-оос core багцад (`client.Qr` эсвэл `new EidQrClient(...)`); namespace ба API 0.13.0–0.16.0-ийн Pades-ийнхтэй ижил
(Pades нь type forwarding-оор дамжуулна). Иргэн eID апп дээрээ «Миний QR»-ийг харуулна (`EIDMN-QR1:<token>`, 120 с, нэг
удаагийн) → RP скан хийж `POST /authentication/qr` → иргэн утсан дээрээ нэг өгүүлбэр хараад **PIN2**-оор зөвшөөрнө →
RP иргэний «Миний мэдээлэл»-ийг (апп дээр хадгалсан dict яг хэвээр + нүүрний JPEG) иргэний өөрийн QUALIFIED SIGN
түлхүүрээр зурсан **PS256 JWS** (`typ` = `eidmn-myqr+jwt`, `x5c` = [иргэний гэрчилгээ, олгогч CA]) хэлбэрээр авна. CA
утгыг хадгалахгүй; presentation нэг л удаа уншигдана (дахин уншвал 410 `QR_PRESENTATION_GONE`). RP-д зөвхөн
`QR_PRESENT` эрх.

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "Касс 3", ApiSecret = secret }); // эсвэл client.Qr
try
{
    QrSession s = await qr.StartAsync(new QrStartRequest(scanned)); // nonce өгөөгүй бол SDK 22 тэмдэгт үүсгэнэ
    QrResult r = await qr.ResultAsync(s);                            // эсвэл polling UI-д: CheckAsync(s) → QrCheck
    foreach (var (key, value) in r.Data) Show(key, value);          // payload-ийн дарааллаар, түлхүүр яг хэвээр
    // r.Source (dan, passport, citizenid …), r.Photo (JPEG | null), r.Signer.Etsi / GivenName / Surname,
    // r.SignedAt, r.Sha256 (= CA аудитын qrsha), r.Jws (маргаанд хадгалж болно)
}
catch (EidQrException e) when (e.Code == EidQrErrorCodes.TokenInvalid) { /* 404 — шинэ QR гаргуул */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.SessionFailed) { /* e.EndResult: USER_REFUSED, TIMEOUT */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.PresentationGone) { /* 410 — дахин QR уншуул */ }
catch (EidQrException e) when (e.Code.StartsWith("QR_", StringComparison.Ordinal)) { /* шалгалт унасан — ИТГЭХГҮЙ */ }
```

`EidQr.VerifyAsync(jws, new QrExpect(rpUuid, sessionId, nonce), trust?)` — хадгалсан JWS-ийг (сүлжээ зөвхөн OCSP)
дахин шалгана. Шалгалт (Go / TS SDK-тэй ижил, CA-ийн `testdata/myqr_vectors.json`): JWS ≤ 512 KiB, 3 сегмент → header яг
`alg` PS256 / `typ` / `x5c` 2 гэрчилгээ (давхардсан түлхүүргүй) → гинж (core-ийн замын угсралт — дээрх «Цуцлалт»; x5c[1]
зөвхөн завсрын нэр дэвшигч, ±60 с) + навч: CA биш, KeyUsage contentCommitment, QcCompliance (QUALIFIED), олгогчийн SKI ∈
`AllowedIssuerSkis` (анхдагч 04 `EidQr.CitizenIssuingCaSki`), RSA ≥ 2048, SERIALNUMBER/CN давхардаагүй → цуцлалт (анхдагч
AIA-ийн OCSP, hard-fail; OCSP `unknown` → revoked) → RSASSA-PSS SHA-256 (salt 32) → payload (давхардсан түлхүүргүй) `iss`,
`sub` = гэрчилгээний serialNumber, `statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж
байна», `aud` = RP UUID (том/жижиг үсэг ялгахгүй), `sid`, `nonce` (яг), 0 < exp − iat ≤ 300, iat ≤ одоо + 60, одоо < exp + 60
→ `data` (`source` `^[a-z0-9_-]{1,32}$`; `fields` ≤ 128, түлхүүр 1–64 code point хяналтын тэмдэгтгүй, утга зөвхөн тэмдэгт мөр
≤ 2048 байт; `photo` strict base64 JPEG ≤ 150 KiB; `fields` хоосон бол `photo` заавал; илүү гишүүнгүй).

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)` — null бол шигтгэсэн үндэсний root
+ 02–04 завсрын, олгогч 04, OCSP. `Revocation` = `(навч, олгогч) → "good" | "revoked" | "unknown"` (өөрийн кэш/CRL эсвэл
тест stub; олгогчийн гэрчилгээг `VerifyAsync` дуусахад dispose хийнэ); exception = "unknown". `RevocationSoftFail = true` бол
"unknown"-г хүлээн авна. `EidClientOptions.QrTrust` — `client.Qr`-ийн итгэл.

Кодууд (`EidQrException.Code`): `QR_FORMAT_INVALID` (CA руу явахгүй), `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`,
`QR_CHAIN_INVALID`, `QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`,
`QR_AUDIENCE_MISMATCH`, `QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`,
`QR_PRESENTATION_GONE` (410), `QR_PENDING` (`ResultAsync`-ийн `maxWait` дууссан — дахин дуудаж болно), `SESSION_FAILED`
(`EndResult`), серверийн `code` `HttpStatus`-тай (400 `REQUEST_INVALID`, 403 `PERMISSION_DENIED` / `RP_REQUIRED`, 404
`QR_TOKEN_INVALID`, 409 `NO_SIGNING_CERTIFICATE`, 429 `RATE_LIMITED`), `HTTP_ERROR`, `NETWORK_ERROR`.

## PAdES (`GeregeSystems.EidMongolia.Pades`) — урсгал

```csharp
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// 1. Бэлдэх — сүлжээгүй. SignerCert = иргэний SIGN гэрчилгээ (CA-ийн сессийн хариунаас, DER).
var prepared = EidPades.Prepare(pdfBytes, new PrepareOptions
{
    SignerCert = signCertDer,
    Reason = "Гэрээ баталгаажуулав",
    ClaimedRole = representation.ClaimedRole, // байгууллагын нэрийн өмнөөс бол (CA-ийн representation хариунаас)
    VerifyPage = true,                         // шалгах (QR) хуудас — зөвхөн эхний eID гарын үсэгт
    // VerifyPagePosition = "first",           // 0.8.0+: QR хуудас 1-р хуудас болно (анхдагч "last"); Appearance.Page,
                                               // SuggestPlacement, Placement.Page оролтын PDF-ийн хуудсаар (PAGE_SPEC §8a)
    FileName = "Гэрээ №1.pdf",
    Lang = "mn",                               // mn (анхдагч) | en
    // Сонголттой харагдах гарын үсэг (APPEARANCE_SPEC.md): pt, хуудасны харагдах зүүн доод булангаас; Page 0 = eID verify
    // хуудас биш сүүлийн хуудас (PLACEMENT_SPEC §1a). Өндөр ≥ 45 pt; багтахгүй бол REQUEST_INVALID. null = үл харагдах.
    Appearance = new Appearance { X = 36, Y = 36, Width = 220, Height = 64 },
});
// prepared.Placement — харагдах гарын үсгийн эцсийн байрлал (доорх «Байршил»).

// 2. prepared.Dtbs (32 байт)-ийг RP backend-ээр CA-ийн signature session-д өгч утсаар зуруулна
//    (RAW_DIGEST_SIGNATURE), эсвэл USB токеноор (PKCS#11) локалд зурна. prepared.State-г хүлээх хооронд хадгалж болно
//    (формат нь Go reference-тэй ижил).

// 3. Суулгах — TSA, OCSP/CRL сүлжээ. Гарын үсэг: RSA PKCS#1 v1.5, ECDSA r‖s эсвэл DER — гэрчилгээгээр автоматаар.
Completed done = await EidPades.CompleteAsync(prepared.State, signature, cancellationToken: ct);
File.WriteAllBytes("signed.pdf", done.Pdf);

// 4. Бүртгэх — CA POST /pdf/signatures-ийн бие (PDF биш, зөвхөн мета). JSON-оор шууд илгээж болно:
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions
{
    SessionId = sessionId,                     // утсанд заавал; токенд өгөхгүй (Medium = token)
    OnBehalfOf = orgRegNo,                     // NTRMN-… — ClaimedRole өгсөн бол заавал
});
string body = JsonSerializer.Serialize(reg);
```

`Medium` хоосон бол `SessionId`-ээс тооцно (байвал `phone`, үгүй бол `token` — CA-ийн дүрэм phone ⇔ sessionID).
`Registration` CA-ийн өмнө шууд `REQUEST_INVALID` шиднэ: `phone` + `SessionId`-гүй, `token` + `SessionId`, бусад
`Medium` утга, эсвэл `done.ClaimedRole` (Prepare-ийн `ClaimedRole`) байхад `OnBehalfOf` хоосон.

`Registration` өмнөх гарын үсгүүдийг зөвхөн `priorCmsSha256`-аар илгээнэ — `done.PriorCmsSha256` ба
`done.PriorRevisionSha256`-г **хоёуланг нь** бүтнээр илгээвэл CA 400 буцаана. Өмнөх гарын үсэг CA-д угсарсан (горим A)
байвал CA 409 `PRIOR_MISMATCH` буцаана: `reg.PriorSignatures`-ийн эхний k-гийн `RevisionSha256`-г `PriorRevisionSha256`-д,
үлдсэний `CmsSha256`-г `PriorCmsSha256`-д тавьж дахин илгээнэ (Go/TS SDK-ийн `RegisterSignature` үүнийг өөрөө хийдэг).

`CompleteOptions`: `TsaUrl` (анхдагч `https://tsa.timeserver.mn/`), `Roots` (тест PKI), `HttpClient` (proxy/sandbox;
анхдагч нь timeout 10 с, redirect дагахгүй), `TimeProvider`. Үндэсний CRL (`esign.gov.mn`)-ийг eID-ийн https толин
хуулбараас татна (WIRE.md §3).

## Алдаа

Бүх алдаа `EidPadesException`; салаалахдаа `Code`-ийг (тогтвортой) ашиглана, `Message` зөвхөн лог/хүнд.

| `Code` | Код | Утга |
|---|---|---|
| `PdfInvalid` | `PDF_INVALID` | PDF задрахгүй; бүтэц хэт гүн (давхарлалт > 256) эсвэл ObjStm мөчлөг, `/Extends` > 64, `/Size` > 2^21, xref хэсэг > 128, xref stream-ийн `/W` `/Index` хязгаар, ObjStm-ийн ажил > 1 GiB (PRECHECKS #2a/#2b) |
| `PdfEncrypted` | `PDF_ENCRYPTED` | Шифрлэгдсэн PDF |
| `PdfLocked` | `PDF_LOCKED` | DocMDP P=1 — өөрчлөхийг хориглосон |
| `PdfTooLarge` | `PDF_TOO_LARGE` | 9.75 MiB (оролт) / 10 MiB (гаралт)-аас их |
| `PdfTooManySignatures` | `PDF_TOO_MANY_SIGNATURES` | 16-аас олон гарын үсэг |
| `PdfPriorSignatureInvalid` | `PDF_PRIOR_SIGNATURE_INVALID` | Өмнөх гарын үсэг эвдэрсэн |
| `PdfForeignSignature` | `PDF_FOREIGN_SIGNATURE` | Өмнөх гарын үсэг eID-ийн B-LT биш |
| `SignerInvalid` | `SIGNER_INVALID` | signerCert / гинж буруу |
| `RequestInvalid` | `REQUEST_INVALID` | Сонголт буруу (docId, lang, fileName, claimedRole…) |
| `SignatureInvalid` | `SIGNATURE_INVALID` | Гарын үсэг DTBS / SignerCert-тэй таарахгүй |
| `TsaUnavailable` | `TSA_UNAVAILABLE` | TSA хариу өгсөнгүй / token хүчингүй |
| `LtvUnavailable` | `LTV_UNAVAILABLE` | OCSP/CRL бүрэн авч чадсангүй; `InnerException is CertificateRevokedException` бол гинжийн гэрчилгээ цуцлагдсан — дахин оролдохгүй |
| `SelfValidationFailed` | `SELF_VALIDATION_FAILED` | Гаралт өөрийн шалгалтыг давсангүй |
| `PlaceholderOverflow` | `PLACEHOLDER_OVERFLOW` | CMS placeholder-т багтсангүй |
| `StateInvalid` | `STATE_INVALID` | `State` эвдэрсэн (эсвэл түүний PDF-ийн бүтэц хэт гүн/төвөгтэй) |
| `Internal` | `INTERNAL` | SDK-ийн дотоод алдаа |
| `Unknown` | бусад | Шинэ код — `RawCode`-ийг үз |

### Харагдах гарын үсгийн байршил

`Appearance.X/Y` нь **хүссэн** байрлал. Prepare нь зорилтот хуудсыг (бичвэр, хүснэгтийн зураас, зураг, form XObject,
өмнөх гарын үсэг зэрэг annotation-ий `/Rect`) рендергүйгээр уншаад, хүссэн тэгш өнцөгт (+4 pt) агуулгатай давхцвал
дүрслэлийг эхний чөлөөт байрлал руу шилжүүлнэ: толин тусгал багана ижил өндөрт (баруун доод → зүүн доод), дараа нь хүссэн
баганаар 12 pt-ээр дээш, дараа нь толин баганаар дээш. Үр дүн `prepared.Placement` (`Page`, `X`, `Y`, `Width`, `Height` —
pt; `Status`):

| `PlacementStatus` | JSON | Утга |
|---|---|---|
| `Requested` | `requested` | Хүссэн байрлал чөлөөтэй |
| `Moved` | `moved` | Чөлөөт байрлал руу шилжсэн (`X`, `Y` нь шинэ байрлал) |
| `Overlap` | `overlap` | Чөлөөт байрлал алга — хүссэн байрлалд агуулга дээгүүр зурсан |
| `Unscanned` | `unscanned` | Хуудсыг хязгаарт багтааж уншиж чадсангүй (4 MiB, 100 000 оператор, дэмжигдээгүй шүүлтүүр…) — хүссэн байрлалд |

`Overlap` / `Unscanned`-ийг хэрэглэгчид мэдэгдэх нь зүйтэй; гарын үсэг аль ч тохиолдолд хүчинтэй. Дүрэм: Go репогийн
`pades/PLACEMENT_SPEC.md` (Go-той байт-ижил; `testdata/golden/placement/vectors.json`-оор box бүрийг тулгана).

**Иргэн өөрөө байрлуулах** (PLACEMENT_SPEC §6a/§6b). `EidPades.SuggestPlacement(pdf, appearance)` нь Prepare-ийн
байршлыг гарын үсэг, гэрчилгээ, сүлжээгүйгээр ажиллуулж анхдагч байрлал, хуудасны хэмжээг буцаана; иргэн урьдчилан
харах дээр чирж байрлуулсны дараа `Appearance.Exact = true`-аар Prepare дуудвал дүрслэл яг тэр тэгш өнцөгтөд зурагдана
(хэзээ ч шилжихгүй; доор нь агуулга байвал `Status = Overlap`, хуудаснаас гарвал `REQUEST_INVALID`):

```csharp
var s = EidPades.SuggestPlacement(pdf, new Appearance { X = 340, Y = 36, Width = 220, Height = 64 });
// s.Page, s.X, s.Y, s.Width, s.Height, s.Status — Prepare-ийн Placement-тэй ижил; s.PageWidth/PageHeight,
// s.PageCount, s.Pages[i].Width/Height (pt). UI (дээд-зүүн эх, s px/pt): left = X·s, top = (PageHeight − Y − Height)·s.
var prepared = EidPades.Prepare(pdf, opts with
{
    Appearance = new Appearance { Page = s.Page, X = x, Y = y, Width = s.Width, Height = s.Height, Exact = true },
});
```

`SuggestPlacement`-ийн алдаа: `PDF_TOO_LARGE`, `PDF_INVALID`, `REQUEST_INVALID`, `PDF_ENCRYPTED`. Өмнөх гарын үсэг
(`PDF_FOREIGN_SIGNATURE`…) ба нэр дүрслэлд багтах эсэхийг Prepare л шалгана. Page 0: гарын үсэгтэй баримтад verify
хуудасны холбоосын docId-оор verify хуудсуудыг алгасна; гарын үсэггүй баримтад юуг ч алгасахгүй (сүүлийн хуудас).

Prepare-ийн шалгуурууд нь Go reference-ийн `pades/PRECHECKS.md`-ийн дарааллаар (#2a/#2b бүтэц, #4 `/Encrypt` лавлагаа
эсвэл шууд толь). `CompleteAsync`-ийн OCSP нь гэрчилгээний CertID (олгогчийн нэр/түлхүүрийн hash + serial)-тай, CRL нь
олгогчийнх (нэр, AKI = SKI, гарын үсэг) байх ба аль аль нь шинэлэг (thisUpdate ≤ одоо + 5 мин; nextUpdate-гүй бол
thisUpdate ≥ одоо − 24 ц) байна.

**Цуцлалтын эх сурвалжийн дараалал (гэрчилгээний үүргээр, хостын нэрээр биш):**

- **Навч** — гинж бүрийн эхний гэрчилгээ (иргэн, TSA): **OCSP эхэлж**, энгийн 10 с timeout-оор бүтэн (thisUpdate нь
  timestamp-аас хожуу байх, дахин оролдлоготой). CRL-ийг мөн татна: хоёулаа хүчинтэй бол хоёуланг нь DSS-д суулгана,
  хүчинтэй OCSP авч чадаагүй бол CRL хангана.
- **CA** — гинжийн эхнийхээс хойшх гэрчилгээ бүр: **CRL эхэлж**. Олгогчийн хүчинтэй CRL (гарын үсэг, хугацаа, `esign.gov.mn`
  → eID толин хуулбар) авбал тэр гэрчилгээнд **OCSP хүсэлт огт илгээхгүй** (жишээ нь хариулдаггүй `ocsp.esign.gov.mn` руу
  очихгүй). CRL байхгүй / татаж чадаагүй / хүчингүй / хугацаа дууссан үед л OCSP (энгийн 10 с timeout).
- Навчны OCSP-г эхэнд нь зэрэг эхлүүлж, CRL-ийг гинжийн дарааллаар татна (нэг цуглуулалтын дотор CRL-ийг дахин татахгүй,
  хариу 4 MiB-аар хязгаартай); үр дүнг гинжийн дарааллаар DSS-д нэмнэ. Аль нэг эх сурвалжийн «revoked» — хатуу алдаа;
  гэрчилгээнд хүчинтэй CRL ч, OCSP ч байхгүй бол `LTV_UNAVAILABLE` (fail-closed).

## Байгууллагын тамга (e-Seal)

`EidPades.SealAsync` — PDF-д байгууллагын тамганы гэрчилгээгээр PAdES-BASELINE-LT гарын үсэг суулгана. Иргэн, PIN, апп
оролцохгүй: SDK DTBS-ийг бэлдээд (verify хуудасгүй — тамгыг CA-ийн `/verify/{docId}`-д бүртгэдэггүй) таны delegate-ийг
дуудна; delegate нь RP backend-ийн өөрийн `HttpClient`-ээр CA `POST /seal/{orgEtsi}` хийж `signature.value`-ийг буцаана.
Pades багц өөрөө HTTP client агуулахгүй — delegate-д core-ийн `client.Seal.SealAsync`-ийг шууд хэрэглэж болно (дээрх «Байгууллага, иргэн, тамга, токен, share»); доорх жишээ гараар бичсэн HTTP-ээр.

**Анхдагчаар тамга харагдана** (Go `SealPDF`, TS `sealPdf`-тэй ижил; Go репогийн `pades/APPEARANCE_SPEC.md` §6):
баримтын сүүлийн (eID verify биш) хуудсанд байгууллагын тамганы дардас — нэр, «eID Mongolia-аар тамгалсан» / "Sealed with
eID Mongolia", огноо; QR, холбоос, үүргийн мөргүй. Байршил: 220 × 64 pt, `x = хуудасны өргөн − 256`, `y = 36` (жижиг
хуудсанд багтаана, жишээ нь 164 pt баримт → 156 × 64, x = 4), агуулгатай давхцвал чөлөөт байрлал руу (дээрх «Харагдах
гарын үсгийн байршил»). Үр дүн `done.Placement`. Автомат дардас хуудсанд багтахгүй эсвэл гаралтыг 10 MiB-аас хэтрүүлэх
бол алдаагүйгээр үл харагдах тамга гаргана (`Placement = null`). `SealOptions.Appearance`-аар байршлыг өөрөө өгнө (иргэний
`Appearance`-тэй ижил талбар; багтахгүй бол `REQUEST_INVALID` / `PDF_TOO_LARGE`). `SealOptions.Invisible = true` — өмнөх
хувилбартай байт-ижил үл харагдах тамга. Go SDK v0.30.0 / TS SDK 0.48.0-аас өмнөх шалгагчид харагдах тамганы дардастай
PDF-ийн өмнөх гарын үсгүүдийг өөрчлөгдсөн (modified) гэж мэдээлнэ — тэдгээр шинэчлэгдэх хүртэл `Invisible = true` ашиглана уу.
Дардасны хувилбарыг зөвхөн гарын үсэг зурагчийн гэрчилгээ сонгоно: e-Seal гэрчилгээгээр `Prepare` + `Appearance` дуудвал
мөн тамганы дардас зурагдана.

```csharp
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// SealCert: CA GET /seal/certificate/{orgEtsi} → "certificate" (base64 DER).
Completed done = await EidPades.SealAsync(pdfBytes, new SealOptions
{
    SealCert = Convert.FromBase64String(sealCertB64),
    Reason = "Байгууллагын тамга",            // SignerName = гэрчилгээний CN (байгууллагын нэр), Chain = шигтгэсэн eID гинж
}, async (dtbs, ct) =>
{
    using var req = new HttpRequestMessage(HttpMethod.Post, $"https://rp.eidmongolia.mn/seal/{orgEtsi}")
    {
        Content = JsonContent.Create(new { digest = Convert.ToBase64String(dtbs), hashType = "SHA256" }),
    };
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rpSecret);
    using var resp = await http.SendAsync(req, ct);
    resp.EnsureSuccessStatusCode();                    // 403 = SEAL:<orgEtsi> эрхгүй; 429 = түр хязгаарлагдсан
    using var body = JsonDocument.Parse(await resp.Content.ReadAsStreamAsync(ct));
    return Convert.FromBase64String(body.RootElement.GetProperty("signature").GetProperty("value").GetString()!);
}, cancellationToken: ct);
File.WriteAllBytes("sealed.pdf", done.Pdf);
```

- RP-д `SEAL:<orgEtsi>` эрх хэрэгтэй (үгүй бол 403). 429 — хурдны хязгаар: хэсэг хүлээгээд дахин оролдоно (delegate-ийн
  exception SDK-ээр өөрчлөгдөхгүй дамжина).
- RFC 3161 timestamp заавал — TSA хүрэхгүй бол `TSA_UNAVAILABLE` (timestamp-гүй тамга гаргахгүй).
- `SealCert` нь тамганы профайл байх ёстой (CA биш, KeyUsage-д nonRepudiation байгаа ба digitalSignature үгүй, EKU-ийн
  зорилгогүй — extendedKeyUsage алга эсвэл хоосон) — үгүй бол `SIGNER_INVALID`. Гарын үсэг DTBS / `SealCert`-тэй таарахгүй бол `SIGNATURE_INVALID`.
- Тамганы гэрчилгээг core-ийн `client.Seal.RequestCertificateAsync` / `WaitForCertificateAsync`-аар хүсэх, эсвэл CA / админ консолоор олгоно.

## Pades хэрэглэгчдэд — 0.16.0 → 0.17.0

- `GeregeSystems.EidMongolia.Pades` 0.17.0 нь `GeregeSystems.EidMongolia` 0.17.0-ийг автоматаар татна. PAdES-ийн API ба
  гаралт өөрчлөгдөөгүй (golden байт-ижил).
- «Миний QR» (`GeregeSystems.EidMongolia.Qr`: `EidQr`, `EidQrClient`, `EidQrOptions`, `EidQrException`, `EidQrErrorCodes`,
  `QrStartRequest`, `QrSession`, `QrSigner`, `QrResult`, `QrExpect`, `QrTrust`, `QrCheck`) core руу шилжсэн; Pades
  `[TypeForwardedTo]`-оор дамжуулна — `using` ба код хэвээр, 0.16.0-ийн эсрэг compile хийсэн dll **дахин compile-гүйгээр**
  ажиллана (CI `compat` job: nuget.org-ийн 0.16.0-ийн эсрэг compile хийсэн хэрэглэгчийг 0.17.0-ийн dll дээр ажиллуулдаг).
- Зан төлөвийн ялгаа (API биш): «Миний QR»-ийн гинж X509Chain-ийн оронд core-ийн замын угсралтаар — name constraints,
  танихгүй critical extension, давхардсан SERIALNUMBER/CN, RSA < 2048-ийг `QR_CHAIN_INVALID`; `QrTrust.Intermediates` null бол
  02–04 (өмнө нь 02–05); payload-ийн давхардсан түлхүүр → `QR_JWS_MALFORMED`; `QrSession.SessionId` хоосон / `.` / `..` →
  `ArgumentException`. Бодит eID гинжид нөлөөгүй.
- RP-ийн шинэ ажилд (нэвтрэлт, гарын үсгийн session, бүртгэл) core-ийн `EidClient`-ийг хэрэглэнэ — README-ийн «PAdES»-ийн
  гараар бичсэн `HttpClient` жишээнүүдийн оронд `client.Sign` / `client.Seal` / `client.Pdf`.

## PDF шалгах (`EidPades.ValidatePdfAsync`)

Гарын үсэгтэй / тамгалсан PDF-ийг бүрэн шалгана — Go `pades.ValidatePDF`, TS `validatePdf` ба CA-ийн `POST /v3/validate/pdf`-тэй
**ижил дүрэм, ижил JSON тайлан** (`PdfReport.ToJson()`; CA-ийн бүртгэлийн `session_id` / `doc_id` / `on_behalf_of_*` /
`stamp_lookup` байхгүй). Баримт хаашаа ч илгээгдэхгүй — онлайн цуцлалтад зөвхөн гэрчилгээний serial (OCSP хүсэлт) явна.

```csharp
using GeregeSystems.EidMongolia.Pades;

PdfReport rep = await EidPades.ValidatePdfAsync(pdfBytes, new ValidatePdfOptions
{
    // Roots / Intermediates / Issuers — анхдагчаар шигтгэсэн үндэсний Root CA (01), 02–05, eID олгогч 04/05.
    // Time — шалгах цаг (анхдагч одоо); Offline = true — зөвхөн баримтын DSS; HttpClient — OCSP/CRL (тест/proxy).
}, ct);
if (rep.Indication != "valid") { /* rep.Signatures[i].Problems */ }
string json = rep.ToJson();
```

- Шалгалт: ByteRange (завсар нь зөвхөн тухайн /Contents) ба messageDigest, CMS/CAdES гарын үсэг (RSA PKCS#1, RSA-PSS, ECDSA;
  RSA < 2048 бит хүлээн авахгүй), signing-certificate-v2, гинж (өөрийн path builder — X509Chain биш, Windows/Linux-д ижил;
  танихгүй critical extension ба name constraints-тэй CA-г татгалзана), KU/EKU (`usage`), хугацаа, RFC 3161 цагийн тэмдэг
  (TSA гинж, timeStamping EKU), цуцлалт, LTV хамралт, `signature_level` (B/T/LT), `certificate_level`, `key_medium`.
- Гарын үсгийн дараах өөрчлөлт: revision бүрийг задалсан объектын графаар харьцуулна (CA-ийн нийтийн шалгагчийн дүрэм) —
  зөвхөн гарын үсэг/DSS нэмсэн бол `extended_by_signatures_only`; харагдах гарын үсэг ба байгууллагын тамганы дардасыг
  (QR-тэй/QR-гүй, APPEARANCE_SPEC §5/§6) бичигчийн кодоор дахин үүсгэж тулгана; бусад бүх зүйл `modified_after_signing`.
  Зөвхөн бүрэн бүтэн (криптографаар таарсан) хожмын гарын үсэг л «гарын үсгээр өргөтгөсөн» гэж тооцогдоно (дардасны
  `/Name`-ийг гэрчилгээний нэртэй харьцуулахгүй — eID desktop клиент тэнд порталын кирилл нэр бичдэг,
  `PrepareOptions.SignerName` дурын нэр өгч болно; `signer_name` үргэлж гэрчилгээнээс, корпус v15). Гарын үсгийн revision-оос хойш xref-ийн мөр
  өөрчлөгдөөгүй объект (ба түүний ObjStm) тэр revision дотор бүтнээрээ задрах ёстой (shadow attack — эс бөгөөс
  `modified_after_signing`). `platform_attested` нэр зөвхөн өөрчлөгдөөгүй (эсвэл зөвхөн гарын үсгээр өргөтгөсөн) баримтад.
- Цуцлалт (eID-ийн 04/05-ийн гэрчилгээнд): онлайн — AIA OCSP, эс бөгөөс CDP CRL (олгогчийн гарын үсэг, CertID); хариугүй
  эсвэл `Offline` бол баримтын DSS-ийн OCSP/CRL; нотолгоо шалгах цагт шинэлэг байх ёстой (PAdES LTV-ийн 24 цагийн дүрэм,
  RP-ийн OCSP шалгагчийн 48 цагийн дүрмээс тусдаа). Аль нь ч үгүй бол `revocation_unavailable` (indeterminate).
- Алдаа (`EidPadesException.RawCode`): `PDF_TOO_LARGE` (> 10 MiB), `PDF_INVALID`, `PDF_ENCRYPTED` (/Encrypt — хоосон нууц
  үгтэй ч), `PDF_NO_SIGNATURE`, `PDF_TOO_MANY_SIGNATURES` (> 16), `REQUEST_INVALID` (Roots/Intermediates/Issuers задрахгүй).
- Халдагчийн PDF-ийн хязгаар (Go/TS-тэй ижил — хэтэрвэл `PDF_INVALID`): задлахаас өмнө бүтцийн шалгалт — давхарлалт ≤ 256;
  xref хэсэг ≤ 128 (128-аас олон incremental update-тэй баримт `PDF_INVALID`); xref stream-ийн `/W` элемент бүр 0…8, мөрийн
  урт > 0, `/Index` start + count ≤ 2^21, бүх xref stream-ийн мөр ≤ 2^21; xref stream / ObjStm-д ганц шүүлтүүр; задалсан xref
  stream + ObjStm нийт ≤ 32 MiB; ObjStm-ийн гишүүн хайлтын ажил (толгойн хос × задалсан урт, нийлбэр) ≤ 1 GiB (маш олон
  гишүүнтэй ObjStm `PDF_INVALID`). Гарын үсэг: CMS ба цагийн тэмдгийн токен бүрд ≤ 32 гэрчилгээ, RSA ≤ 8192 бит, e ≤ 2^32−1,
  гэрчилгээ/TSTInfo-ийн serial ≤ 160 бит (утга) — хэтэрвэл тэр гарын үсэг `malformed_signature`; SHA-1/MD5/MD2-той SignerInfo
  гарын үсгийн алгоритм `weak_algorithm`. DSS: stream ≤ 1 MiB (≤ 64 ширхэг), тайлсан нийт ≤ 8 MiB, давхар заасан stream-ийг нэг
  удаа. .NET-ийн нэмэлт хамгаалалт (тайланд нөлөөгүй): revision-ийн задлагчид рекурс ≤ 64, нийт ≤ 1 000 000 зангилаа, inflate
  ≤ 64 MiB, объектын дугаар < 2^23; уншигчид FlateDecode тус бүр ≤ 64 MiB, нэг нээлтэд нийт ≤ 256 MiB, рекурс ≤ 512; ObjStm-ийн
  толгойг нэг удаа индексжүүлнэ; гинжийн угсралт ≤ 100 оролдлого; OCSP хариу ≤ 16 KiB, HTTP ≤ 4 MiB, 10 с.
- Conformance: `testdata/pades-validate` = Go `9f68390`-ийн `pades/testdata/validate` (корпус v15, 80 тохиолдол; + заасан
  golden файлууд) (`./build/sync-validate.sh`, CI `validate-sync`); тохиолдол бүрийн тайланг Go-ийнхтэй deep-equal
  (`ValidatePdfCorpusTests`).

## Go / TS-тэй харьцуулсан дэмжлэг

| Боломж | .NET 0.18.0 | Go | TS |
|---|---|---|---|
| Client, алдаа, замын хүснэгт, discovery | ✓ | ✓ | ✓ |
| Нэвтрэлт: push, device link (QR / Web2App / App2App), QR ticker | ✓ | ✓ | ✓ |
| Гарын үсэг: digest / text / linked, certificate choice, onBehalfOf | ✓ | ✓ | ✓ |
| Session poll / wait | ✓ | ✓ | ✓ |
| Validator (гинж, ACSP_V2, RAW_DIGEST) + OCSP шалгагч | ✓ | ✓ | ✓ |
| PDF гарын үсгийн бүртгэл (`POST /pdf/signatures`) | ✓ | ✓ | ✓ |
| Байгууллага, иргэн (PKI_READ) | ✓ | ✓ | ✓ |
| e-Seal: гэрчилгээ, тамганы эрх, digest тамгалах, PDF тамгалах | ✓ | ✓ | ✓ |
| USB токен (гэрчилгээ, нэвтрэлт) | ✓ | ✓ | ✓ |
| Share | ✓ | ✓ | ✓ |
| «Миний QR» | ✓ | ✓ | ✓ |
| «eID-ээр нэвтрэх» backend | ✓ (+ ASP.NET Core) | ✓ (`net/http`) | ✓ (+ `<eid-login-button>`) |
| PAdES prepare / complete / suggestPlacement / бүртгэлийн бие | ✓ | ✓ | ✓ |
| PDF-ийн бүрэн шалгагч (`ValidatePDF`) | ✓ `ValidatePdfAsync` (pades-validate/1) | ✓ | ✓ |
| QR-тэй тамганы дардас (APPEARANCE_SPEC §6.5–6.6, golden v13: шалгагч, `SealAsync` ба `Prepare`-ийн docId) | ✓ | ✓ v0.31.0 | ✓ 0.49.0 |
| Тамганы бүртгэл (`POST /seal/{org}/registrations`), `SealForDocument` | ✓ | ✓ main | ✓ main |
| Cross-SDK корпус rp-conformance/2 (validator, OCSP, нэвтрэлтийн backend) | ✓ | ✓ main | ✓ main |
| `pdfDigest`, хөтчийн entry, `convert` | — | — | ✓ (TS-д л) |

## Хөгжүүлэлт

- Профайлын дүрэм: Go репогийн `pades/PROFILE.md`, `PAGE_SPEC.md`, `PRECHECKS.md`, `WIRE.md`, `APPEARANCE_SPEC.md`,
  `PLACEMENT_SPEC.md`.
- Golden: `testdata/golden` = Go репогийн `pades/testdata/golden`-ийн хуулбар, `build/go-sdk.ref` commit-оос
  (`./build/sync-golden.sh`; CI `golden-sync` job нь `--check`-ээр тулгана). **Тестийн PKI-ийн хувийн түлхүүр** нь
  зөвхөн тест — бодит гинжид итгэгдэхгүй.
- Тест (`dotnet test`): golden тохиолдол бүр Prepare → manifest-ийн гарын үсэг → CompleteAsync (HTTP fixture replay,
  тогтмол nonce/цаг) → гаралтын PDF-ийг Go-ийнхтэй **бүхэлд нь** байт-түвшинд тулгана; eid-desktop (Swift)-ийн golden;
  алдааны замууд; ECDSA (r‖s, DER); цуцлалтын дүрэм (`RevocationTests` — 04-ийн түлхүүрээр зурсан OCSP/CRL); бүтцийн
  шалгалт (`StructureTests`, `testdata/structure` — Go/TS-ийн оролтууд); дүрслэлийн байршил (`PlacementTests` — Go-ийн
  `placement/vectors.json`-ийн box бүр, нэр дэвшигчдийн дараалал, эвдэрсэн content/Flate stream дээр алдаа шидэхгүй);
  харагдах golden тохиолдол бүрд `SuggestPlacement` (`expect.suggestion` талбар бүрээр, `suggestionError`).
- Фонт (`Assets/`): Noto Sans subset, SIL OFL 1.1 — Go reference-ийн `pades/assets/fonts`-тай ижил байт.
- PDF уншигч/бичигч нь digitorus/pdf (BSD-3) ба digitorus/pdfsign (BSD-2)-ийн семантикийг давтана — лиценз `Pdf/LICENSE.*`.
- RP SDK: `testdata/conformance` = Go репогийн `testdata/conformance` (rp-conformance/2)-ийн байт-ижил хуулбар
  (`./build/sync-conformance.sh`; CI `conformance-sync`); тест `tests/GeregeSystems.EidMongolia.Tests` ба
  `tests/GeregeSystems.EidMongolia.AspNetCore.Tests` (`net8.0` + `net10.0`); `build/compat` — Pades 0.16.0-тэй binary
  нийцэл (CI `compat`); `build/check-packages.sh` — гурван багцын metadata ба хамаарал (CI `pack`).

## Release

1. `release/<хувилбар>` салбар: гурван csproj-ийн `<Version>`-г ижил утгаар өсгөж (lockstep), `changelog.d/*`-ийг
   `CHANGELOG.md`-ийн шинэ хэсэгт нэгтгээд устгана → PR → merge.
2. main дээр `git tag v<хувилбар> && git push origin v<хувилбар>`.
3. `.github/workflows/release.yml`: CI-г бүтнээр нь (Windows + Linux, compat, pack + `build/check-packages.sh`) ажиллуулж,
   tag = `<Version>` эсэхийг шалгаад гурван `.nupkg` (+ `.snupkg`)-г GitHub Release asset болгон, GitHub Packages (NuGet) болон
   nuget.org (Trusted Publishing) руу хамаарлын дарааллаар (core → AspNetCore → Pades) нийтэлнэ. Шинэ package ID-ийн
   nuget.org-ийн урьдчилсан нөхцөл: [docs/release-0.17.0.md](docs/release-0.17.0.md).

## Лиценз

MIT — [LICENSE](LICENSE). Гуравдагч: Noto Sans (OFL 1.1), digitorus/pdf (BSD-3), digitorus/pdfsign (BSD-2) — NuGet багцын
`licenses/`.
