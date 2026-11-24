### Added — харагдах байгууллагын тамганы дардас (APPEARANCE_SPEC.md §6, golden v12); `SealAsync` анхдагчаар харагдана

- **Юу:** дардас бичигч гарын үсэг зурагчийн гэрчилгээгээр хувилбараа сонгоно (§6.1, `EidPades.IsSealCertificate`, internal):
  e-Seal гэрчилгээ (CA биш, keyUsage bit 1 тавигдсан ба bit 0 тавигдаагүй — бусад бит үл тооно, EKU-ийн зорилгогүй —
  extendedKeyUsage алга эсвэл хоосон) → **тамганы дардас**: иргэний дардастай ижил widget, 11 объект, F1/F2 фонт, form
  dictionary, байршил; `/EIDVerify` BDC, QR, URL, үүргийн мөр үгүй; бичвэр x = 4 pt-ээс, өргөн W − 8 pt; мөр: нэр (F2,
  11 → 7, ≤ 2 мөр), «eID Mongolia-аар тамгалсан» / "Sealed with eID Mongolia" (F1, f − 2, ногоон), огноо (F1, f − 2, саарал).
  Тамганы дардасд docId шаардахгүй. Бусад гэрчилгээ → иргэний дардас, байт өөрчлөгдөөгүй.
  `SealOptions.Appearance` (иргэний `Appearance`-тэй ижил талбар) ба `SealOptions.Invisible` нэмэгдсэн; `Completed.Placement`
  (зөвхөн `SealAsync` бөглөнө); `EidPades.SealStampWidth/Height/Margin` (220, 64, 36). **Анхдагч өөрчлөгдсөн:** аль нь ч
  өгөөгүй бол `SealAsync` дардсыг харуулна — сүүлийн (eID verify биш) хуудас, 220 × 64 pt, x = хуудасны өргөн − 256, y = 36,
  жижиг хуудсанд багтаасан (§6.4), Exact биш (PLACEMENT_SPEC-ээр агуулгаас зайлсхийнэ). Автомат дардас багтахгүй
  (`REQUEST_INVALID`) эсвэл гаралт хэмжээнээс хэтрэх (`PDF_TOO_LARGE`) бол үл харагдах тамга (`Placement = null`); өгсөн
  `Appearance` бол алдаа хэвээр. `Invisible = true` — өмнөх гаралттай байт-ижил.
- **Анхаар:** Go SDK v0.30.0 / TS SDK 0.48.0-аас өмнөх шалгагчид харагдах тамганы дардастай PDF-ийн өмнөх гарын үсгүүдийг
  өөрчлөгдсөн (modified) гэж мэдээлнэ — тэдгээр шинэчлэгдэх хүртэл `Invisible = true`.
- **Гэрчилгээний шалгалт:** `SealAsync`-ийн `SIGNER_INVALID` шалгалт мөн §6.1 (Go `eid.IsSealCertificate`) болсон: хоосон
  extendedKeyUsage-тэй гэрчилгээг хүлээн авна (өмнө нь татгалздаг), CA гэрчилгээг татгалзана (өмнө нь шалгадаггүй).
  keyUsage/basicConstraints/EKU-г .NET-ийн декодероор биш DER-ээс шууд уншина.
- **Яагаад:** Go SDK v0.30.0 (`SealPDF`) ба TS SDK 0.48.0 (`sealPdf`)-тэй ижил API, ижил байт.
- **Хаана:** `src/…/Pdf/SignatureAppearance.cs` (`SealContent`), `Pdf/SignatureRevision.cs`, `EidPades.cs` (`VisibleSpec`),
  `Seal.cs`, `Models.cs`; `build/go-sdk.ref` = d762ed8 (Go v0.30.0) + `testdata/golden` (pades-golden-v12: `seal-visible`,
  `seal-visible-en`, `seal-visible-third`, `pki/seal.pem`); README.
- **Шалгасан:** PR-ийн CI (Windows + Linux). `GoldenTests` — v12-ийн 3 тохиолдол Prepare/CompleteAsync-аар ба
  `SealAsync`-аар (автомат ба тодорхой байршил) бүхэлдээ байт-ижил, placement; бусад golden өөрчлөгдөөгүй.
  `SealTests` — §6.1 дүрэм (хоосон EKU = тамга, танихгүй/таньдаг EKU, CA, digitalSignature, keyUsage bit 32), 164 pt баримт
  → 156 × 64, x = 4; багтахгүй хуудас ба хэмжээний хязгаарын үл харагдах нөөц (DTBS = өмнөх `SealAsync`); `Invisible` DTBS =
  өмнөх `SealAsync`.
- **Үлдсэн:** энэ SDK-д validator байхгүй тул §6.3 (дардсыг сэргээж тулгах) хэрэгжээгүй.
