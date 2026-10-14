# eid-mongolia-sdk-dotnet

**eID Mongolia** client-side PAdES — Windows (.NET) wrapper. PDF баримт eID сервер рүү **хэзээ ч явахгүй**
(Smart-ID загвар): баримтыг клиент дээр бэлдэж (`Prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB
токеноор зуруулаад, гарын үсгийг клиент дээр PDF-д суулгана (`CompleteAsync`). Цөм нь бусад платформтой нэг Go сан
([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`) — Windows-д `eidpades.dll`
(`go build -buildmode=c-shared ./capi`) болж P/Invoke-оор дуудагдана, тиймээс гаралт iOS/Android/Go/WASM-тай байт
бүрээрээ ижил.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

- Багц: NuGet `GeregeSystems.EidMongolia.Pades` — `netstandard2.0` + `net8.0`.
- Native: `runtimes/win-x64/native/eidpades.dll`, `runtimes/win-arm64/native/eidpades.dll`.
- Thread-safe, глобал төлөвгүй. Сүлжээ зөвхөн `CompleteAsync`-д (TSA, OCSP/CRL).

[English summary](#english)

## Суулгах

Багцыг [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases)-ээс `.nupkg` татаж локал
эх сурвалжаас, эсвэл GitHub Packages-ээс:

```bash
dotnet nuget add source https://nuget.pkg.github.com/gerege-systems/index.json -n gerege -u <github-user> -p <PAT read:packages>
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.1.0
```

.NET Framework (net4x) дээр native DLL-ийг гаралтын хавтас руу хуулахын тулд төсөлдөө
`<RuntimeIdentifier>win-x64</RuntimeIdentifier>` (эсвэл `win-arm64`) тавина. .NET 8 дээр автоматаар.

## Урсгал

```csharp
using GeregeSystems.EidMongolia.Pades;

// 1. Бэлдэх — сүлжээгүй. SignerCert = иргэний SIGN гэрчилгээ (CA-ийн сессээс ирсэн DER).
var prepared = EidPades.Prepare(pdfBytes, new PrepareOptions
{
    SignerCert = signCertDer,
    SignerName = "БАТ-ЭРДЭНЭ Болд",
    Reason = "Гэрээ баталгаажуулав",
    ClaimedRole = representation.ClaimedRole, // байгууллагын нэрийн өмнөөс бол (CA-ийн representation хариунаас)
    VerifyPage = true,                         // шалгах (QR) хуудас — зөвхөн эхний eID гарын үсэгт
    Lang = "mn",
});

// 2. prepared.Dtbs (32 байт)-ийг RP backend-ээр CA-ийн signature session-д өгч утсаар зуруулна
//    (RAW_DIGEST_SIGNATURE), эсвэл USB токеноор (PKCS#11) локалд зурна. prepared.State-г хүлээх хооронд хадгалж болно.

// 3. Суулгах — TSA, OCSP/CRL сүлжээ; гарын үсэг: r||s, DER ECDSA эсвэл PKCS#1 v1.5 (RSA) — цөм өөрөө танина.
Completed done = await EidPades.CompleteAsync(prepared.State, signature);
File.WriteAllBytes("signed.pdf", done.Pdf);

// 4. Бүртгэх — RP backend SDK-ийн RegisterSignature (CA POST /pdf/signatures) руу PDF биш зөвхөн мета:
//    done.DocId, done.Cms, done.OutSha256, done.InSha256, done.HasPage, done.PageSha256.

// Шалгах — сүлжээгүй.
VerifyReport report = EidPades.Verify(File.ReadAllBytes("signed.pdf"));
Console.WriteLine(report.Json);
```

`CompleteAsync` нь native дуудлагыг thread pool дээр ажиллуулна. `CancellationToken` эхлэхээс өмнө л шалгагдана —
эхэлсэн дуудлагыг цөмийн timeout дуусгана.

## Алдаа

Бүх алдаа `EidPadesException`; салаалахдаа `Code`-ийг (тогтвортой) ашиглана, `Message` зөвхөн лог/хүнд.

| `Code` | Цөмийн код | Утга |
|---|---|---|
| `PdfInvalid` | `PDF_INVALID` | PDF задрахгүй |
| `PdfEncrypted` | `PDF_ENCRYPTED` | Нууцлагдсан PDF |
| `PdfLocked` | `PDF_LOCKED` | DocMDP P=1 — өөрчлөхийг хориглосон |
| `PdfTooLarge` | `PDF_TOO_LARGE` | Хэмжээ хэтэрсэн |
| `SignatureInvalid` | `SIGNATURE_INVALID` | Гарын үсэг DTBS / SignerCert-тэй таарахгүй |
| `TsaUnavailable` | `TSA_UNAVAILABLE` | TSA хариу өгсөнгүй |
| `LtvUnavailable` | `LTV_UNAVAILABLE` | OCSP/CRL авч чадсангүй |
| `SelfValidationFailed` | `SELF_VALIDATION_FAILED` | Гаралт өөрийн шалгалтыг давсангүй |
| `PlaceholderOverflow` | `PLACEHOLDER_OVERFLOW` | CMS placeholder-т багтсангүй |
| `StateInvalid` | `STATE_INVALID` | `State` эвдэрсэн / өөр хувилбарынх |
| `NativeUnavailable` | — | `eidpades.dll` ачаалагдсангүй (RID дэмжигдэхгүй / файл алга) |
| `Unknown` | бусад | Шинэ цөмийн код — `RawCode`-ийг үз |

## Хөгжүүлэлт

- Цөмийн хувилбар `build/go-sdk.ref`-д commit sha-гаар тогтмол. Шинэчлэхдээ sha-г солиод PR нээнэ — CI DLL-ийг
  тэр commit-оос build хийж golden vector-уудыг ажиллуулна.
- CI (`.github/workflows/ci.yml`, windows-latest): `build/build-native.ps1` → x64 (MinGW gcc) ба arm64 (llvm-mingw
  cross) `eidpades.dll` → `dotnet format --verify-no-changes`, build, xUnit (win-x64 DLL-ээр, `testdata/pades-client/`
  golden vector) → `dotnet pack` (хоёр RID багтсаныг шалгана). arm64 DLL build хийгдэнэ, тест нь x64 runner дээр
  ажиллахгүй.
- Golden vector: CA репогийн `testdata/pades-client/`-ийн хуулбар — эх сурвалжаа өөрчилвөл энд дахин хуулна.
- Локалд (Windows): `./build/build-native.ps1 -Arch x64; dotnet test`.

## Release

1. `release/<хувилбар>` салбар: `src/GeregeSystems.EidMongolia.Pades/*.csproj`-ийн `<Version>`-г өсгөж,
   `changelog.d/*` фрагментуудыг `CHANGELOG.md`-ийн шинэ хэсэгт нэгтгээд устгана → PR → merge.
2. main дээр `git tag v<хувилбар> && git push origin v<хувилбар>`.
3. `.github/workflows/release.yml`: CI-г бүтнээр нь ажиллуулж, tag = `<Version>` эсэхийг шалгаад `.nupkg`-г GitHub
   Release asset болгон, мөн GitHub Packages (NuGet) руу нийтэлнэ.

## Лиценз

MIT — [LICENSE](LICENSE).

---

## English

Client-side PAdES for eID Mongolia on Windows/.NET. The PDF never leaves the client: `Prepare` builds the signature
placeholder and returns the 32-byte DTBS, the citizen signs it on their phone (CA signature session,
`RAW_DIGEST_SIGNATURE`) or USB token, and `CompleteAsync` embeds the CMS with an RFC 3161 timestamp and LTV data (DSS),
then self-validates. `Completed` carries the metadata the RP backend registers with the CA (`POST /pdf/signatures`).
The core is the shared Go library (`eid-mongolia-sdk-go/pades`) built as `eidpades.dll` (`win-x64`, `win-arm64`), so
output is byte-identical to the iOS/Android/Go/WASM builds. Errors are `EidPadesException` with a stable `Code`.
