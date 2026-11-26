# 0.17.0 lockstep release

Гурван багц нэг хувилбараар, нэг tag-аар гарна: `GeregeSystems.EidMongolia` (core, ШИНЭ ID),
`GeregeSystems.EidMongolia.AspNetCore` (ШИНЭ ID), `GeregeSystems.EidMongolia.Pades` (0.16.0 нийтлэгдсэн; одоо core-оос
хамаарна). Бэлтгэл `release/0.17.0-prep` салбарт хийгдсэн; tag ба нийтлэлт эзний зөвшөөрлөөр.

## Хийгдсэн алхмууд

1. Pades → core `ProjectReference` (pack-д `GeregeSystems.EidMongolia` 0.17.0 хамаарал болно — CI шалгана).
2. `src/GeregeSystems.EidMongolia.Pades/Qr/` устсан; `src/GeregeSystems.EidMongolia.Pades/Properties/TypeForwards.cs` нь
   `EidQr`, `EidQrClient`, `EidQrOptions`, `EidQrException`, `EidQrErrorCodes`, `QrStartRequest`, `QrSession`, `QrSigner`,
   `QrResult`, `QrExpect`, `QrTrust`, `QrCheck`-ийг `[assembly: TypeForwardedTo]`-оор core руу дамжуулна.
3. Pades-ийн QR тестүүд (`QrTests.cs`, `RevocationTests`-ийн `MyQrDefaultRevocation*`) устсан — core-ийн `QrTests`
   (myqr_vectors.json-тэй) үлдэнэ; LTV-ийн 24 ц ба QR-ийн 48 ц тусдаа гэдгийг `LtvFreshnessStaysSeparateFromMyQrOcsp` шалгана.
4. Нийтийн гадаргуу: v0.16.0 tag-ийн `src/GeregeSystems.EidMongolia.Pades/Qr/*.cs`-ийн `public` мөр бүр (төрөл, гишүүн,
   тогтмол, параметрийн анхдагч утга, nullability, `required`, record-ын positional параметр) core-ийн
   `src/GeregeSystems.EidMongolia/Qr/*.cs`-тэй **яг ижил** (мөр-мөрөөр тулгасан). 0.16.0-д нийтийн nested төрөл, `protected`
   гишүүн байгаагүй.
5. Binary нийцэл — CI `compat` job (`build/compat/PadesQrCompat`): nuget.org-ийн Pades **0.16.0**-ийн эсрэг compile хийсэн
   хэрэглэгч 12 төрлийн бүх нийтийн гишүүнийг (конструктор, getter, `with`, `EidQr.Parse`/`VerifyAsync`, `EidQrClient`-ийн
   бүх метод сүлжээ хаалттай `HttpClient`-ээр, `EidQrException`, 20 код) дуудна: (а) 0.16.0-ийн dll дээр (суурь), (б) dll-ийг
   0.17.0-ийн Pades + core-оор сольж **дахин compile-гүйгээр** — төрлүүд `GeregeSystems.EidMongolia` assembly-аас
   ачаалагдах ёстой, (в) энэ репогийн Pades-ийн эсрэг source-оор compile.
6. Pades-ийн дотоод `Crypto/Ocsp.cs`, `Der`, `X509Util`, `Fetcher`, `Trust`-ийг core руу **нэгтгээгүй**: зан төлөв нь ижил
   биш — PAdES LTV нь Go `x/crypto/ocsp` `ParseResponseForCert`-ийн семантик (SHA-1 responder гарын үсгийг зөвшөөрнө, 24 ц,
   CRL ба үндэсний CRL-ийн толин хуулбар), `Der` нь CMS/OCSP хүсэлтийн байт-ижил бичигч; core-ийн `OcspRevocationChecker` /
   `ParsedCert` нь RP-ийн хатуу уншигч (48 ц, unknown → revoked, CertID issuer hash, RSA ≥ 2048). Нэгтгэвэл golden-ийн байт
   эсвэл LTV-ийн дүрэм өөрчлөгдөнө. Шигтгэсэн 01–04 PEM хоёр сборкод байт-ижил (core тест шалгана); Pades-д 05 нэмэлт.

## Зан төлөвийн ялгаа (API биш) — Pades 0.16.0 → 0.17.0 «Миний QR»

- Гинж: X509Chain-ийн оронд core-ийн замын угсралт — name constraints-тэй CA, танихгүй critical extension, давхардсан
  SERIALNUMBER/CN, RSA < 2048 / сул exponent-ийг `QR_CHAIN_INVALID`-ээр татгалзана (бодит eID гинж 01 → 04-т нөлөөгүй).
- `QrTrust.Intermediates` null бол шигтгэсэн 02–04 (өмнө нь 02–05; 05 нь байгууллагын олгогч, анхдагч allowlist нь 04).
- Review засварууд: payload-ийн давхардсан түлхүүр → `QR_JWS_MALFORMED`; ганц surrogate → `QR_*` код (өмнө нь
  `InvalidOperationException`); `QrSession.SessionId` хоосон / `.` / `..` → `ArgumentException`.
- `QrTrust.Revocation`-д өгөгдсөн олгогчийн `X509Certificate2` нь `VerifyAsync` дуусахад Dispose хийгдэнэ.

## Release workflow юу нийтлэх вэ

`v0.17.0` tag push → `release.yml`: `ci.yml` бүтнээрээ (Windows + Linux test, golden/conformance sync, compat, pack +
`build/check-packages.sh`) → `nupkg` artifact-аас:

1. `build/check-packages.sh nupkg 0.17.0` — яг 3 `.nupkg` + 3 `.snupkg`, хувилбар = tag.
2. GitHub Release `v0.17.0`: `GeregeSystems.EidMongolia.0.17.0.nupkg/.snupkg`, `…AspNetCore.0.17.0.nupkg/.snupkg`,
   `…Pades.0.17.0.nupkg/.snupkg`.
3. GitHub Packages (`nuget.pkg.github.com/gerege-systems`): core → AspNetCore → Pades (`--no-symbols`, `--skip-duplicate`).
4. nuget.org (Trusted Publishing, `NuGet/login@v1`, user `geregecore`): core → AspNetCore → Pades (`.snupkg` автоматаар
   symbol server руу, `--skip-duplicate`).

## nuget.org — tag хийхээс ӨМНӨ эзний хийх зүйл

Шинэ хоёр ID (`GeregeSystems.EidMongolia`, `GeregeSystems.EidMongolia.AspNetCore`) nuget.org-д хараахан алга (2026-11-26:
flat container 404); Pades-ийн эзэн `geregecore`, «verified» тэмдэггүй (prefix reservation алга).

1. **Trusted Publishing policy:** nuget.org → `geregecore` → Trusted Publishing-д энэ репогийн policy (Repository owner
   `gerege-systems`, Repository `eid-mongolia-sdk-dotnet`, Workflow file `release.yml`, Package owner `geregecore`) идэвхтэй
   эсэх, мөн **шинэ package ID** push хийх эрхтэй эсэхийг шалгах. Policy нь багцын эзнээр (`geregecore`) хамаардаг тул шинэ
   ID-ууд `geregecore`-ийн өмчид үүснэ; хэрэв түр key шинэ ID-г татгалзвал policy-г шинэчлэх (эсвэл nuget.org-ийн дэмжлэгээр
   тодруулах) хүртэл tag хийхгүй — хагас нийтлэлт (core ороод Pades орохгүй) нь Pades 0.17.0-ийн хэрэглэгчийг эвдэхгүй ч
   lockstep-ийг эвдэнэ.
2. **ID / prefix хамгаалалт (зөвлөмж):** `GeregeSystems.EidMongolia` prefix reservation-ийг `geregecore`-д хүсэх
   (account@nuget.org; ID squatting-оос хамгаална, «verified» тэмдэг). Заавал биш — ID-ууд одоо чөлөөтэй.
3. **GitHub Packages:** байгууллагын тохиргоо `GITHUB_TOKEN`-д шинэ package үүсгэхийг зөвшөөрдөг эсэх (өмнө нь зөвхөн Pades
   байсан). Хориглосон бол GitHub Packages алхам унана — nuget.org алхам түүний дараа тул нийтлэлт зогсоно.
4. `CHANGELOG.md`-ийн `## 0.17.0 — 2026-11-26` огноог tag хийх өдрөөр солих (өөр өдөр бол).

## Tag хийх дараалал (эзэн)

1. #49 (review засвар) → main; дараа нь энэ PR (main руу автоматаар retarget) → main. Хоёулаа ногоон CI-тай.
2. main дээр: `git tag v0.17.0 && git push origin v0.17.0`.
3. Release workflow ногоон, nuget.org-д гурван багц indexed болсны дараа: `dotnet add package GeregeSystems.EidMongolia
   --version 0.17.0` цэвэр төсөлд restore хийгдэхийг, Pades 0.16.0 → 0.17.0 шинэчлэлт дахин compile-гүйгээр ажиллахыг шалгах.
