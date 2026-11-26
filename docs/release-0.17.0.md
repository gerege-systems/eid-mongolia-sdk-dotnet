# 0.17.0 lockstep release — хойшлуулсан алхмууд

`GeregeSystems.EidMongolia` (core) хараахан нийтлэгдээгүй; `GeregeSystems.EidMongolia.Pades` нийтлэгдсэн. Нийтлэгдсэн
Pades нь нийтлэгдээгүй core руу төрөл дамжуулбал хэрэглэгчийн build эвдэрнэ — тиймээс доорх алхмуудыг ЗӨВХӨН гурван
багцыг (core, Pades, AspNetCore) нэг tag-аар зэрэг гаргах `release/0.17.0` салбарт хийнэ.

## «Миний QR» төрлүүдийг core руу шилжүүлэх (type forwarding)

Одоогийн байдал: `GeregeSystems.EidMongolia.Qr`-ийн нийтийн төрлүүд хоёр сборкод ижил нэр, namespace, гишүүдтэй:
`src/GeregeSystems.EidMongolia/Qr/` (core — хуваалцсан замын угсралт + `OcspRevocationChecker`) ба
`src/GeregeSystems.EidMongolia.Pades/Qr/` (Pades — X509Chain + дотоод OCSP; WP 5-д OCSP `unknown` → revoked, 48 ц
засвартай).

Release-ийн үед:

1. `GeregeSystems.EidMongolia.Pades.csproj`-д core руу `ProjectReference` (pack-д PackageReference болж lockstep хувилбартай).
2. `src/GeregeSystems.EidMongolia.Pades/Qr/EidQr.cs`, `EidQrClient.cs`-ийг устгана.
3. Pades-д `Properties/TypeForwards.cs` нэмнэ — нийтийн төрөл бүрд `[assembly: TypeForwardedTo(typeof(...))]`:
   `EidQr`, `EidQrClient`, `EidQrOptions`, `EidQrException`, `EidQrErrorCodes`, `QrStartRequest`, `QrSession`,
   `QrSigner`, `QrResult`, `QrExpect`, `QrTrust`, `QrCheck`.
4. Pades-ийн QR тестүүд (`tests/GeregeSystems.EidMongolia.Pades.Tests/QrTests.cs`, `RevocationTests`-ийн
   `MyQrDefaultRevocation*`) core-ийн `QrTests`-тэй давхардана — Pades-ээс устгаж, core-ийнх үлдэнэ.
5. Шалгах: core ба Pades-ийн QR нийтийн гишүүд ижил (нэр, параметр, буцаах төрөл) — Pades 0.16.0-ийн эсрэг compile
   хийсэн жишээ (`EidQr.VerifyAsync`, `new EidQrClient(...)`) 0.17.0-ийн dll дээр дахин compile-гүйгээр ажиллах.
6. Pades-ийн дотоод `Crypto/Ocsp.cs`, `Der`, `X509Util`, `Fetcher`, `Trust`-ийг core руу нэгтгэх (InternalsVisibleTo
   Pades) — тусдаа алхам, PAdES golden (Windows + Linux) ногоон байх ёстой.

## Бусад

- `release.yml` нь одоо зөвхөн Pades nupkg-ийн нэрийг шалгадаг — гурван nupkg болгох (WP 6).
- nuget.org-д шинэ package ID-уудын Trusted Publishing policy (эсвэл ID prefix reservation) — эзний зөвшөөрлөөр.
