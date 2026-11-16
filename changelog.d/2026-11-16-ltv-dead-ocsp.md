### Fixed — LTV: хариугүй OCSP responder `CompleteAsync`-ийг гэрчилгээ тус бүрд 10 с саатуулахаа больсон

- **Юу:** `CompleteAsync`-ийн LTV цуглуулалт гэрчилгээ бүрийн OCSP-г CRL-тэй **зэрэг** татна (бүх гэрчилгээний OCSP
  нэг дор эхэлнэ, CRL гинжийн дарааллаар, GET кэш хэвээр). Олгогчийн хүчинтэй CRL авсан гэрчилгээний OCSP-г цуглуулалт
  эхэлснээс хойш хамгийн ихдээ 3 с (`Ltv.OcspGrace`) хүлээгээд цуцална; хүчинтэй CRL-гүй бол OCSP энгийн 10 с timeout-тай
  (өмнөхтэй ижил). Хүлээн авах дүрэм (OCSP: гарын үсэг, responder EKU, CertID, шинэлэг байдал, навчны thisUpdate >
  timestamp; CRL: олгогчийн нэр/AKI/гарын үсэг, шинэлэг байдал) өөрчлөгдөөгүй; «revoked» хатуу алдаа хэвээр; аль нь ч
  хүчинтэй биш бол `LTV_UNAVAILABLE` хэвээр. DSS-ийн агуулга, дараалал эрүүл гинжид өөрчлөгдөөгүй (OCSP + CRL хоёулаа,
  гинжийн дарааллаар).
- **Яагаад:** үндэсний CA-ийн гэрчилгээнүүдийн (MNICA, Gerege Issuing CA) AIA OCSP `http://ocsp.esign.gov.mn` холболт
  хүлээж аваад хариулдаггүй үед гэрчилгээ бүр 10 с timeout идэж (2 × 10 с), Windows desktop-д гарын үсэг ~25 с болж
  байсан (8 хоногт 94-өөс 5). CRL нь аль хэдийн `crl.eidmongolia.mn` толин хуулбараас ирдэг.
- **Хаана:** `src/…/Crypto/Ltv.cs` (`CollectAsync`, `OcspAsync`, `OcspGrace`), `Crypto/Fetcher.cs` (баримт),
  `tests/…/RevocationTests.cs`, README (OCSP/CRL хэсэг, English).
- **Шалгасан:** PR-ийн CI (Windows + Linux) `dotnet test`: golden-ууд байт-ижил (эрүүл гинж); шинэ тест — эрүүл гинжийн
  DSS дараалал; хариугүй OCSP + хүчинтэй CRL → цонхонд CRL-ээр; хоёр хариугүй OCSP → нийт ≈ нэг цонх; CRL-гүй үед удаан
  OCSP-г таслахгүй; хог/олгогч биш зурсан OCSP → CRL, CRL-гүй бол `LtvException`; цонхонд ирсэн revoked → хатуу алдаа;
  дуудагчийн цуцлалт; UnobservedTaskException үгүй.
- **Үлдсэн:** TS (`eid-mongolia-sdk` `src/pades/ltv.ts`) ба Go (`eid-mongolia-sdk-go` `pades/ltv.go`) SDK-д ижил
  OCSP-эхлээд дараалсан хэв маяг (10 с) бий — тусад нь засна. Timestamp-ийн дараах хүлээлт (≈2 с, дээд тал 5 с)
  өөрчлөгдөөгүй.
