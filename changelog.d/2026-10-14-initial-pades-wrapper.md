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
