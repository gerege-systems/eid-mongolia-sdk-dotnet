### Added — `Completed.FileName`, `EidPades.Registration` (CA бүртгэлийн бие) (0.3.0)

- **Юу:** `Prepare`-ийн цэвэрлэсэн `fileName` state-ээр (`"fileName"`, Go state-тэй ижил түлхүүр) дамжиж
  `Completed.FileName`-д ирнэ. `EidPades.Registration(done, RegistrationOptions)` → `SignatureRegistration` —
  CA `POST /pdf/signatures`-ийн бие (JSON талбарын нэр CA DTO-тэй яг ижил; `System.Text.Json`-оор шууд сериализ): өмнөх
  гарын үсгүүд зөвхөн `priorCmsSha256`-аар, хос түлхүүр нь `PriorSignatures`-д (`[JsonIgnore]`); `medium` анхдагч =
  `SessionId` байвал phone, эс бөгөөс token; `signerEtsi` = гэрчилгээний SERIALNUMBER; эхний гарын үсэг хуудасгүй эсвэл
  fileName хоосон → `REQUEST_INVALID`. Go `pades.Registration`, TS `registrationFromCompleted`-тэй ижил хэлбэр.
- **Яагаад:** 10-15 аудит («Native PAdES»): .NET-ийн `Completed`-д fileName байгаагүй, `PriorCmsSha256` ба
  `PriorRevisionSha256` хоёулаа бүтэн ирдэг тул апп хоёуланг нь CA руу дамжуулахад 400 болдог.
- **Хаана:** `Registration.cs` (шинэ), `Models.cs`, `State.cs`, `EidPades.cs` (partial); README «Урсгал» алхам 4.
- **Шалгасан:** golden тест бүрд `Completed.FileName` = цэвэрлэсэн нэр, `Registration`-ийн JSON-д `priorRevisionSha256`
  алга, `PriorSignatures` = өмнөх кейсийн `sigRevSha256`, `signerEtsi`.
- **Үлдсэн:** 409 `PRIOR_MISMATCH`-ийн дахин оролдлого — .NET-д CA HTTP клиент байхгүй тул дуудагч (README-д заасан).
