# Security: login backend ба үйлчилгээний бие даасан review-ийн засварууд (нийтлэгдээгүй core)

- **Юу:**
  - **S1** — `EidLoginHandler` `POST start`: ганц surrogate-тэй JSON мөр (`{"mode":"\udc00"}`) `GetString` /
    `TryGetProperty`-д `InvalidOperationException` шидэж, хязгаараас ӨМНӨ 500 + stack trace лог болдог байсан → 400
    `invalid_body` (JSON бус бусад задлалтын алдаа ч мөн).
  - **S2** — «Миний QR» (`EidQr.VerifyAsync`, core ба Pades-ийн хуулбар): header / payload / data-ийн мөр ба түлхүүрийг
    аюулгүй уншина (`StrOrNull`, `NamesOrNull`) — `InvalidOperationException` гарахгүй: header → `QR_HEADER_INVALID`,
    payload-ийн түлхүүр → `QR_JWS_MALFORMED`, claim-ийн утга → `QR_CLAIMS_INVALID` (Go `jsonString` !ok шиг), data →
    `QR_DATA_INVALID`. Payload-ийн давхардсан түлхүүрийг татгалзана (Go `jsonObject`; өмнө нь сүүлийнх нь ялдаг байсан) →
    `QR_JWS_MALFORMED`; header-ийнх аль хэдийн `QR_HEADER_INVALID`. Олгогчийн `X509Certificate2`-г `VerifyAsync`
    дуусахад Dispose хийнэ (core).
  - **S5** — ASP.NET Core `MapEidLogin`: `ClientIp` өгөөгүй бол анхдагч `EidLoginClientIp.RemoteAddress` (өмнө нь IP-ээр
    хязгаарладаггүй, зөвхөн Warning); reverse proxy-ийн ард `UseForwardedHeaders` эсвэл `Forwarded(n)` гэж баримтжуулсан.
    Neutral handler: `start:<ip>` түлхүүр IPv6-д **/64 угтвар** (`start:2001:db8:1:2::/64`), IPv4-mapped → IPv4; IPv4 ба
    задрахгүй утга хэвээр (RemoteAddress, Forwarded, өөрийн функц — бүгдэд).
  - **S6** — `RpRoute.Expand`: хоосон, `.`, `..` параметрийг `ArgumentException`-оор татгалзана (`Uri.EscapeDataString`
    цэгийг escape хийдэггүй тул System.Uri `/session/..`-г өөр зам руу шилжүүлдэг байсан) — бүх үйлчилгээ ба core QR
    client; Pades QR client-д ижил шалгалт.
  - eidlogin conformance harness: танихгүй `scenario` / алхам / `request` / `expect` / `setCookie` түлхүүр → FAIL (шинэ
    corpus түлхүүр хоосон PASS болохгүй); `cookieFrom` эх алхам cookie тавиагүй бол FAIL.
- **Яагаад:** бие даасан security review (шийдвэр: засварын дараа release; bypass олдоогүй).
- **Хаана:** `src/GeregeSystems.EidMongolia/Login/EidLoginHandler.cs`, `Login/LoginOptions.cs`, `Qr/EidQr.cs`, `Routes.cs`,
  `src/GeregeSystems.EidMongolia.AspNetCore/EidMongoliaAspNetCore.cs`, `src/GeregeSystems.EidMongolia.Pades/Qr/*.cs`;
  тест `Login/LoginSecurityTests.cs`, `Login/LoginConformanceTests.cs`, `QrTests.cs` (core + Pades), `RouteTests.cs`,
  `AspNetCoreAdapterTests.cs`.
- **Хэрхэн шалгасан:** PR CI (Windows + Linux, net8.0 + net10.0) — шинэ тестүүд (ганц surrogate body/header/payload/data,
  payload-ийн давхардсан түлхүүр, IPv6 /64 түлхүүр ба хязгаар, dot-segment) ба eidlogin corpus-ийн 24 сценари (IPv6
  түлхүүр corpus-д алга — өөрчлөгдөөгүй).
- **Дараагийн ажил (cross-SDK, эхлээд corpus өөрчлөлт хэрэгтэй — энэ PR-д ороогүй):** S3 — login cookie-д `__Host-`
  угтвар ба давхардсан login cookie-г татгалзах; S4 — rate-limit түлхүүрт иргэний дугаарыг hash болгох; цуцлалтын
  soft-fail анхдагчийн баримт бичиг — release-ийн README-д (0.17.0 prep).
