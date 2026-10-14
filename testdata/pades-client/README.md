# pades-client golden vectors (.NET)

`vectors.json` — Go цөмөөс (`coreCommit`, `build/go-sdk.ref`) `tools/genvectors`-оор үүсгэсэн. .NET тест (`GoldenTests`)
тэдгээрийг `eidpades.dll`-ээр дахин ажиллуулж байт бүрээр (DTBS, messageDigest, state sha256, Verify тайлан) тулгана.

- `input/base-*.pdf`, `input/*-dss.pdf`, `pki/desktop-root.pem` — `eid-mongolia-sdk-go/pades/testdata/golden/desktop`-ийн
  хуулбар (eid-desktop-ийн Swift port-той байт-ижил гэж баталгаажсан).
- `pki/root.der`, `pki/leaf.der`, `pki/leaf.key` — **ЗӨВХӨН ТЕСТИЙН** P-256 гинж (2026–2046), генератор шинээр үүсгэнэ.
  Ямар ч бодит гинжид итгэгдэхгүй; тестээс өөр зориулалтаар бүү ашигла.

Цөмийн ref солигдвол: `./build/build-native.ps1 -Arch x64` (эсвэл `artifacts/go-sdk`-д тэр commit-ийг clone) →
`cd tools/genvectors && go run . ../../artifacts/go-sdk/pades/testdata/golden/desktop ../../testdata/pades-client ../../build/go-sdk.ref`.
