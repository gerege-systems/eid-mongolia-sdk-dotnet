### Tests — pades golden v8 (verify page chain with non-zero object generations)

- **Юу:** golden-ийг eid-mongolia-sdk-go #40 (`21f8434`, `pades-golden-v8`) руу бэхэлсэн: `input/verify-gen1.pdf`
  (verify хуудас `6 1 obj`, docId Link `7 1 obj`, URI action `8 2 obj`) ба кейс `verify-gen1`, `page0-verify-gen1`,
  `page-explicit-verify-gen1`.
- **Яагаад:** PLACEMENT_SPEC §1a «Object generations» — docId-ийг xref-ийн бодит generation-оор уншина (Swift port 0 гэж
  таамагладаг байсныг CA репод зассан). .NET аль хэдийн зөв — кодын өөрчлөлтгүй.
- **Хаана:** `build/go-sdk.ref`, `testdata/golden/`.
- **Шалгасан:** `build/sync-golden.sh --check`; `dotnet test` — 182/182 (шинэ 3 `MatchesGoReference` кейс байт-ижил).
