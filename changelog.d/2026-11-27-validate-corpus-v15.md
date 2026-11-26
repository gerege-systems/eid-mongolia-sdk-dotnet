### Changed — `ValidatePdfAsync`: харагдах дардасны `/Name`-ийг гэрчилгээний нэртэй харьцуулахгүй (корпус v15; Go 9f68390)

- **Юу:** own-signer харагдах дардасны `/Name` нь гарын үсгийн гэрчилгээний харуулах нэртэй тэнцүү байх шаардлагыг хасав —
  бүрэн бүтэн хожмын гарын үсэг, widget ба дардас нь өөрийн `/Name`-ээр бичигчийн гаралттай таарвал нэр ямар ч байсан
  «зөвхөн гарын үсгээр өргөтгөсөн». `/Name`-ийн уртын хязгаар ба дардасны бусад шалгалт хэвээр; integrity-д унасан хожмын
  гарын үсэг өргөтгөл биш хэвээр (өмнөх нь `modified_after_signing`). `signer_name` гэрчилгээнээс, `claimed_name` = `/Name`.
- **Яагаад:** гаргасан eID Windows desktop клиент `/Name`-д порталын кирилл нэр бичдэг (гэрчилгээнийх латин), интегратор
  `PrepareOptions.SignerName` өгч болно — хууль ёсны хамтран гарын үсэг зурсан баримт `modified_after_signing` болж байсан;
  итгэмжлэгдээгүй зурагч гэрчилгээнийхээ нэрийг өөрөө сонгодог тул харьцуулалт хамгаалалт нэмдэггүй.
- **Хаана:** `Validation/OwnAppearance.cs`, `Validation/Extract.cs`, `Validation/Revisions.cs` (`SigMeta.Name` хасагдсан),
  `Validation/Evaluate.cs` (`DisplayName` дахин private); корпус `testdata/pades-validate` = Go `9f68390` (v15, 80 тохиолдол;
  зөвхөн `later-stamp-name-mismatch`-ийн хүлээгдэх тайлан өөрчлөгдсөн); README (3 хэл).
- **Шалгасан:** корпусын 80 тохиолдол Go-ийн тайлантай deep-equal; `LaterStampName_NotComparedWithCertificate`,
  `LaterSignatureFailingIntegrity_StillModifiesEarlier` — PR CI (windows + ubuntu). Локалд dotnet ажиллуулаагүй.
