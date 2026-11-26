Монгол · [English](README.en.md) · [中文](README.zh-CN.md)

# eid-mongolia-sdk-dotnet

**eID Mongolia** client-side PAdES — .NET (C#) SDK. PDF баримт eID сервер рүү **хэзээ ч явахгүй** (Smart-ID загвар):
баримтыг клиент дээр бэлдэж (`Prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB токеноор зуруулаад,
гарын үсгийг клиент дээр PDF-д суулгана (`CompleteAsync`). Гаралт нь PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL,
DSS).

Энэ нь Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, профайл
`pades-client/1`)-ийн **native C# порт** — native код, DLL, WASM үгүй. Go-ийн golden vector-уудтай (verify хуудас, QR,
xref, CMS, TSA/OCSP/CRL хүсэлт, DSS) **байт-ижил** гаргадгийг CI Windows ба Linux дээр шалгадаг.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

- Багц: NuGet `GeregeSystems.EidMongolia.Pades`, `net8.0` ба `net10.0` (multi-target). `net8.0`-ийн runtime 2026-11-10-нд дэмжлэгээс гарсан; одоогийн relying party-ууд restore хийж чадахын тулд түр хадгалсан бөгөөд дараагийн хувилбарт хасна. Хамаарал: зөвхөн `System.Security.Cryptography.Pkcs` (Microsoft).
- Thread-safe, глобал төлөвгүй. Сүлжээ зөвхөн `CompleteAsync`-д (TSA, OCSP/CRL).
- Бүрэн шалгагч (validator) энд **байхгүй** — шалгалт: файлын SHA-256-аар CA-ийн бүртгэлээс, бүрэн криптограф шалгалт Go
  backend SDK-д.

English: [README.en.md](README.en.md) · 中文: [README.zh-CN.md](README.zh-CN.md)

## Суулгах

[nuget.org](https://www.nuget.org/packages/GeregeSystems.EidMongolia.Pades)-оос:

```bash
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.16.0
```

Хувилбар бүрийн `.nupkg` [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases)-д мөн бий.

## Урсгал

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
| `PdfInvalid` | `PDF_INVALID` | PDF задрахгүй; бүтэц хэт гүн (давхарлалт > 256) эсвэл ObjStm мөчлөг, `/Extends` > 64, `/Size` > 2^21 (PRECHECKS #2a/#2b) |
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
SDK энд HTTP client агуулахгүй.

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
- Тамганы гэрчилгээг CA / админ консолоор олгоно — энэ SDK-д олгох функц байхгүй.

## «Миний QR» — иргэний «Миний мэдээлэл» (`GeregeSystems.EidMongolia.Qr`, 0.13.0)

PAdES-ээс тусдаа, ижил багцад. Иргэн eID апп дээрээ «Миний QR»-ийг харуулна (`EIDMN-QR1:<token>`, 120 с, нэг
удаагийн) → RP скан хийж `POST /authentication/qr` → иргэн утсан дээрээ нэг өгүүлбэр хараад **PIN2**-оор зөвшөөрнө →
RP иргэний «Миний мэдээлэл»-ийг (апп дээр хадгалсан dict яг хэвээр + нүүрний JPEG) иргэний өөрийн QUALIFIED SIGN
түлхүүрээр зурсан **PS256 JWS** (`typ` = `eidmn-myqr+jwt`, `x5c` = [иргэний гэрчилгээ, олгогч CA]) хэлбэрээр авна. CA
утгыг хадгалахгүй; presentation нэг л удаа уншигдана (дахин уншвал 410 `QR_PRESENTATION_GONE`). RP-д зөвхөн
`QR_PRESENT` эрх.

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "Касс 3", ApiSecret = secret });
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
`alg` PS256 / `typ` / `x5c` 2 гэрчилгээ → гинж (`X509Chain` CustomRootTrust; x5c[1] зөвхөн завсрын нэр дэвшигч, ±60 с) +
навч: CA биш, KeyUsage contentCommitment, QcCompliance (QUALIFIED), олгогчийн SKI ∈ `AllowedIssuerSkis` (анхдагч 04
`EidQr.CitizenIssuingCaSki`), RSA ≥ 2048 → цуцлалт (анхдагч AIA-ийн OCSP, hard-fail) → RSASSA-PSS SHA-256 (salt 32) →
`iss`, `sub` = гэрчилгээний serialNumber, `statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг
хуваалцах гэж байна», `aud` = RP UUID (том/жижиг үсэг ялгахгүй), `sid`, `nonce` (яг), 0 < exp − iat ≤ 300, iat ≤ одоо + 60,
одоо < exp + 60 → `data` (`source` `^[a-z0-9_-]{1,32}$`; `fields` ≤ 128, түлхүүр 1–64 code point хяналтын тэмдэгтгүй,
утга зөвхөн тэмдэгт мөр ≤ 2048 байт; `photo` strict base64 JPEG ≤ 150 KiB; `fields` хоосон бол `photo` заавал; илүү
гишүүнгүй).

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)` — null бол шигтгэсэн үндэсний root
+ 02–05 завсрын, олгогч 04, OCSP. `Revocation` = `(навч, олгогч) → "good" | "revoked" | "unknown"` (өөрийн кэш/CRL эсвэл
тест stub); exception = "unknown". `RevocationSoftFail = true` бол "unknown"-г хүлээн авна.

Кодууд (`EidQrException.Code`): `QR_FORMAT_INVALID` (CA руу явахгүй), `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`,
`QR_CHAIN_INVALID`, `QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`,
`QR_AUDIENCE_MISMATCH`, `QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`,
`QR_PRESENTATION_GONE` (410), `QR_PENDING` (`ResultAsync`-ийн `maxWait` дууссан — дахин дуудаж болно), `SESSION_FAILED`
(`EndResult`), серверийн `code` `HttpStatus`-тай (400 `REQUEST_INVALID`, 403 `PERMISSION_DENIED` / `RP_REQUIRED`, 404
`QR_TOKEN_INVALID`, 409 `NO_SIGNING_CERTIFICATE`, 429 `RATE_LIMITED`), `HTTP_ERROR`, `NETWORK_ERROR`.
## RP SDK цөм — `GeregeSystems.EidMongolia` (хөгжүүлэлт явагдаж байна)

> **Хөгжүүлэлт явагдаж байна — NuGet-д хараахан нийтлэгдээгүй.** Зорилго: TypeScript ба Go SDK-тэй ижил хүрээтэй бүрэн
> server-side RP SDK (Auth, Sign, Session, Validator, OCSP, Login backend …). Нийтэлтэл API өөрчлөгдөж болно.

Одоо байгаа хэсэг (`src/GeregeSystems.EidMongolia`, package хамааралгүй, `net8.0` / `net10.0`):

- `EidClient` + `EidClientOptions` / `EidCredentials` — BaseUrl-ийн дүрэм (https; http зөвхөн loopback; хуучин
  `ca.eidmongolia.mn` хостод тодорхой алдаа), Bearer, timeout (анхдагч 15 с, PDF 80 с), `Accept-Language`, JSON 4 MiB
  хязгаар; mTLS — client certificate-тэй `HttpClient`-ийг конструкторт өгнө. `client.Auth.SessionTtlAsync()` —
  discovery-ийн `sessionTtl`.
- Алдаа: `EidException` (`Code`, `Status`, `RetryAfter`, `Retryable`) → `EidAuthenticationException` (401),
  `EidForbiddenException` (403), `EidApiException` (код бүрийн дэд ангитай), `EidNetworkException`,
  `EidResponseTooLargeException`, `EidSessionFailedException`, `EidValidationException`, `EidDeviceLinkException`.
- Крипто: `Acsp.BuildV2Payload` / `V2Digest`, `EidCrypto.InteractionsToBase64` (JS `JSON.stringify`-тай байт-ижил),
  `DeviceLink.Build` / `TickQrAsync` (authCode = HMAC-SHA256), `EidCrypto.SessionSecretDigest`, `RandomChallenge`,
  `UserChallengeOf`.
- Шалгалт: CA-ийн device-link golden (`testdata/devicelink_golden.json`, SHA-256 тестэд түгжсэн), Smart-ID ACSP_V2
  вектор, interactions escape; `.github/workflows/contract.yml` нь замын хүснэгтийг live `/.well-known/eid`-тэй өдөр бүр
  тулгана.

### «eID-ээр нэвтрэх» товчны backend (`EidLoginHandler`, ASP.NET Core)

TS SDK-ийн `<eid-login-button>`-ийн backend: `POST {base}/start`, `GET {base}/status`, `GET {base}/callback` (Web2App).
Framework-аас хамааралгүй цөм — `GeregeSystems.EidMongolia.Login.EidLoginHandler` (`HandleAsync(EidLoginRequest)` →
`EidLoginResponse`); ASP.NET Core-д `GeregeSystems.EidMongolia.AspNetCore` (shared framework-аас өөр хамааралгүй):

```csharp
using GeregeSystems.EidMongolia;
using GeregeSystems.EidMongolia.AspNetCore;
using GeregeSystems.EidMongolia.Login;

builder.Services.AddEidMongolia(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "Миний банк", apiSecret),
    Trust = new TrustConfig { TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem } },
});
var app = builder.Build();
app.UseForwardedHeaders(); // proxy-ийн ард: KnownProxies-тай тохируулсны дараа RemoteIpAddress зөв
app.MapEidLogin("/auth/eid", async (http, id) =>
{
    // Иргэнийг id.Etsi (PNOMN-…)-ээр таньж ШИНЭ session үүсгэнэ (session fixation).
    await SignInAsync(http, id.Etsi);
    return new EidLoginSuccess { Redirect = "/dashboard" };
}, o =>
{
    o.CallbackUrl = "https://bank.example.mn/auth/eid/callback"; // Web2App (зам заавал /auth/eid/callback)
    o.FailureRedirect = "/login";
    o.ClientIp = EidLoginClientIp.RemoteAddress; // эсвэл EidLoginClientIp.Forwarded(1) — итгэмжит nginx-ийн ард
});
```

Аюулгүй байдал Go `eidlogin` / TS `createEidLogin`-тэй ижил: төлөв серверт (`IEidLoginStore`, анхдагч санах ойн 10 000
дээд хэмжээтэй), хөтчид зөвхөн HttpOnly + Secure + SameSite=Lax cookie (`<sessionId>.<binding>`, binding-ийн SHA-256-г
тогтмол хугацаанд тулгана), `Sec-Fetch-Site` cross-site → 403, хязгаар (start: нэг IP-ээс 60 с-д 20; push: нэг дугаарт
60 с-д 3), бүртгэлгүй дугаарт decoy session + push-ийн 1 с доод хугацаа, ValidateAuth + OCSP (soft-fail анхдагч) дараа
л `OnSuccess` (нэг удаа), аудитын `OnEvent` (регистрийн оронд HMAC pushKey). Хариуны хэлбэр ба 12 алдааны код нь
cross-SDK корпусын `testdata/conformance/eidlogin/scenarios.json`-оор (24 сценари) тулгагдана.

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

## Release

1. `release/<хувилбар>` салбар: csproj-ийн `<Version>`-г өсгөж, `changelog.d/*`-ийг `CHANGELOG.md`-ийн шинэ хэсэгт
   нэгтгээд устгана → PR → merge.
2. main дээр `git tag v<хувилбар> && git push origin v<хувилбар>`.
3. `.github/workflows/release.yml`: CI-г бүтнээр нь (Windows + Linux) ажиллуулж, tag = `<Version>` эсэхийг шалгаад
   `.nupkg`-г GitHub Release asset болгон, GitHub Packages (NuGet) болон nuget.org (Trusted Publishing) руу нийтэлнэ.

## Лиценз

MIT — [LICENSE](LICENSE). Гуравдагч: Noto Sans (OFL 1.1), digitorus/pdf (BSD-3), digitorus/pdfsign (BSD-2) — NuGet багцын
`licenses/`.
