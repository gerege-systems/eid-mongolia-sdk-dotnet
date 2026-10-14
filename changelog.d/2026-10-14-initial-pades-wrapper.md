- **Анхны хувилбар — `GeregeSystems.EidMongolia.Pades`** (netstandard2.0 + net8.0): Go цөмийн (`eid-mongolia-sdk-go`
  `capi`, `build/go-sdk.ref`) `eidpades.dll`-ийн P/Invoke wrapper. `EidPades.Prepare` / `CompleteAsync` (→ `Completed`:
  Pdf, Cms, DocId, OutSha256, InSha256, HasPage, PageSha256, RevIndex, SigRevSha256, PriorCmsSha256, SignerCert) /
  `Verify` (→ `VerifyReport`) / `Version`; `EidPadesException` тогтвортой `Code`-той; Go-гийн буферийг `SafeHandle` +
  `eid_free`-ээр чөлөөлнө. Яагаад: PDF клиентээс гарахгүй (Smart-ID загвар) — Windows клиентэд нэг цөм.
- CI (windows-latest): `eidpades.dll` x64 (MinGW) + arm64 (llvm-mingw cross) → xUnit golden vector (`testdata/pades-client`,
  `tools/genvectors`-ээр Go цөмөөс) → nupkg (`runtimes/win-x64|win-arm64/native/`). Release: `v*` tag → GitHub Release
  asset + GitHub Packages. `changelog` guard job.
- Шалгасан: CI (Windows runner) — Prepare DTBS/digest/state Go-той байт-ижил, Verify тайлан ижил, Complete гарын үсэг
  шалгах (r||s ба DER) → TSA алхам хүрнэ.
- Цөм `feat/pades-core` 56a26eb руу (SigningTime → +08:00 нормчлол, WASM/FS засвар); vector `tools/genvectors`-оор дахин үүссэн.
