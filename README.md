# eid-mongolia-sdk-dotnet

**eID Mongolia** client-side PAdES — .NET (C#) SDK. PDF баримт eID сервер рүү **хэзээ ч явахгүй** (Smart-ID загвар):
баримтыг клиент дээр бэлдэж (`Prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB токеноор зуруулаад,
гарын үсгийг клиент дээр PDF-д суулгана (`CompleteAsync`). Гаралт нь PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL,
DSS).

Энэ нь Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, профайл
`pades-client/1`)-ийн **native C# порт** — native код, DLL, WASM үгүй. Go-ийн golden vector-уудтай (verify хуудас, QR,
xref, CMS, TSA/OCSP/CRL хүсэлт, DSS) **байт-ижил** гаргадгийг CI Windows ба Linux дээр шалгадаг.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

- Багц: NuGet `GeregeSystems.EidMongolia.Pades`, `net8.0`. Хамаарал: зөвхөн `System.Security.Cryptography.Pkcs` (Microsoft).
- Thread-safe, глобал төлөвгүй. Сүлжээ зөвхөн `CompleteAsync`-д (TSA, OCSP/CRL).
- Бүрэн шалгагч (validator) энд **байхгүй** — шалгалт: файлын SHA-256-аар CA-ийн бүртгэлээс, бүрэн криптограф шалгалт Go
  backend SDK-д.

[English summary](#english)

## Суулгах

[nuget.org](https://www.nuget.org/packages/GeregeSystems.EidMongolia.Pades)-оос:

```bash
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.8.0
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

---

## English

Client-side PAdES for eID Mongolia in pure C# (.NET 8). The PDF never leaves the client: `Prepare` writes the signature
revision (optionally a bilingual verification page with a QR code) and returns the 32-byte DTBS; the citizen signs it on
their phone (CA signature session, `RAW_DIGEST_SIGNATURE`) or USB token; `CompleteAsync` verifies the signature, gets an
RFC 3161 timestamp, embeds the CAdES CMS, collects OCSP/CRL and appends a DSS revision (PAdES-BASELINE-LT). `PrepareOptions.Appearance` adds an optional visible signature widget (QR, signer
name/role, date — APPEARANCE_SPEC.md); `X/Y` is the preferred spot — the stamp moves off existing page content to
the first free spot and `PreparedDocument.Placement` reports where it went and why (`Requested | Moved | Overlap |
Unscanned`, PLACEMENT_SPEC.md). `Appearance.Page` 0 = the last page that is not an eID verify page (earlier revisions'
verify pages — a `/Link` to `https://ca.eidmongolia.mn/verify/<docId>` — are skipped; PLACEMENT_SPEC §1a).
`Appearance.Exact = true` draws the stamp exactly at the requested rect (a position the signer chose on a page preview):
never moved, status `Requested` or `Overlap`. `VerifyPagePosition = "first"` (0.8.0+) puts the verify page at page 1
(default `"last"`); page numbers in `Appearance.Page`, `SuggestPlacement` and `Placement.Page` always count the input
PDF's pages (PAGE_SPEC §8a, PLACEMENT_SPEC §1b). `EidPades.SuggestPlacement(pdf, appearance)` runs Prepare's placement
without a certificate, signing or network and returns the resolved page, rect, status and every page's visible size
(`PlacementSuggestion`, PLACEMENT_SPEC §6b). `Completed`
carries the metadata the RP backend registers with the CA (`POST /pdf/signatures`); `EidPades.Registration(done, …)`
builds that request body (serialize it with `System.Text.Json`). OCSP/CRL evidence must match the certificate's CertID /
issuer and be fresh; a revoked answer fails `CompleteAsync` with `LTV_UNAVAILABLE` whose `InnerException` is
`CertificateRevokedException` (do not retry). Install: `dotnet add package GeregeSystems.EidMongolia.Pades` (nuget.org). This is a native port of the Go
reference (`eid-mongolia-sdk-go/pades`, profile `pades-client/1`); CI proves byte-identical output against the Go golden
vectors on Windows and Linux. No validator is shipped — verification is a hash lookup against the CA registry, full
cryptographic validation lives in the Go backend SDK. Errors are `EidPadesException` with a stable `Code`.
