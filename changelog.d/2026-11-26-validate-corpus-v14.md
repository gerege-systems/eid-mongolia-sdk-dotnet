### Security — `ValidatePdfAsync` хатууруулалт (корпус v14; Go PR #76, TS PR #100-ийн порт)

- **Юу:**
  - Shadow attack: гарын үсгийн revision-оос хойш xref-ийн мөр өөрчлөгдөөгүй объект (ба түүний ObjStm) тэр revision дотор
    бүтнээрээ задрах ёстой — `/Length` нь гарын үсгийн мужаас цааш үргэлжилж хожмын revision-ийн байтаар «гүйцдэг» stream →
    `modified_after_signing` (өмнө нь `valid`).
  - Хожмын гарын үсгийн итгэл: зөвхөн бүрэн бүтэн (integrity) хожмын гарын үсэг л «гарын үсгээр өргөтгөсөн» гэж тооцогдоно;
    харагдах дардасны `/Name` нь тэр гарын үсгийн гэрчилгээний харуулах нэртэй (GIVENNAME SURNAME, эс бөгөөс CN) яг тэнцүү
    байх ёстой. **Интеграторт:** өөр нэртэй дардас (эсвэл эвдэрсэн хожмын гарын үсэг) нэмсэн баримтад өмнөх гарын үсгүүд
    `modified_after_signing` болно.
  - SignerInfo-ийн гарын үсгийн алгоритм SHA-1/MD5/MD2 (sha1/md5/md2WithRSA, dsa-with-sha1, ecdsa-with-SHA1, OIW sha1WithRSA)
    → `weak_algorithm` (digest SHA-256 байсан ч).
  - Бүтцийн урьдчилсан шалгалт (Go `CheckStructure`-тай ижил): xref хэсэг ≤ 128, xref stream-ийн `/W` элемент 0…8 ба мөрийн
    урт > 0, `/Index` start + count ≤ 2^21, бүх xref stream-ийн мөр ≤ 2^21, xref stream-д ганц шүүлтүүр, задалсан xref stream
    32 MiB-ийн төсөвт (ObjStm-тэй хамт), ObjStm-ийн гишүүн хайлтын ажил ≤ 1 GiB; ObjStm-ийн offset-ийг уншигчтай яг ижлээр
    (бүхэл бус → 0, сөрөг байрлал → алдаа). **Интеграторт:** 128-аас олон incremental update-тэй эсвэл маш олон ObjStm
    гишүүнтэй баримт `PDF_INVALID` (Prepare/Seal-д ч).
  - Гэрчилгээний хязгаар: CMS ба цагийн тэмдгийн токен бүрд ≤ 32 гэрчилгээ, RSA ≤ 8192 бит, e ≤ 2^32−1, serial ≤ 160 бит —
    гарын үсэгт `malformed_signature`, токенд TSA-гүй (TSTInfo-ийн цаг хэвээр — Go-той ижил); TSTInfo serial > 160 бит →
    цагийн тэмдэг задрахгүй.
  - Уншигч: ObjStm-ийн толгойг нэг удаа индексжүүлнэ (гишүүн бүрд дахин уншихгүй); xref stream-ийн мөрийн урт 0 ба нийт мөр
    > max(/Size, 2^21) → алдаа; xref хэсэг ≤ 128 (өмнө нь 129).
  - `platform_attested` зөвхөн `covers_whole_document` эсвэл `extended_by_signatures_only` үед — өмнөх .NET-ийн нэмэлт одоо
    Go/TS-ийн дүрэм (тайлбар л өөрчлөгдсөн).
- **Яагаад:** .NET/Java порт review-ийн дараах reference-ийн хатууруулалт; тайлан Go/TS-тэй байт-ижил байх.
- **Хаана:** `Pdf/Structure.cs`, `Pdf/PdfDocument.cs`, `Validation/Extract.cs`, `Validation/Revisions.cs`,
  `Validation/OwnAppearance.cs`, `Validation/Evaluate.cs`; корпус `testdata/pades-validate` = Go `222acbd` (v14, 80
  тохиолдол; `build/go-sdk-validate.ref`); README (3 хэл) — хязгаарын жагсаалт.
- **Шалгасан:** корпусын 80 тохиолдол Go-ийн тайлантай deep-equal, `ValidatePdfHardeningTests`-ийн шинэ тестүүд — PR CI
  (windows + ubuntu).
