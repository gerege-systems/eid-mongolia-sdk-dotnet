### Removed (BREAKING) — гарын үсгийн зураг / байгууллагын тамганы зураг

- **Юу:** 0.9.0-д нэмэгдсэн зургийн функц бүрэн хасагдав: `SignatureAppearance.SignatureImage` / `StampImage`,
  `PdfImage`, `Completed.Images` (бүртгэлийн `images`, 409 `IMAGE_MISMATCH` код), alpha/zlib FDICT шалгалт, зурагтай
  байрлал (220×110 / 240×147.5). Харагдах тамга өмнөх QR тамга руу буцна — гаралт 0.8.1-тэй байт-ижил. Эдгээрийг
  ашиглаж буй код compile хийгдэхгүй — устгана уу. «Миний QR» (`GeregeSystems.EidMongolia.Qr`) хэвээр.
- **Яагаад:** зургийн функцийг бүх системээс (CA, портал, апп, SDK) бүрэн хасах шийдвэр (2026-10-24).
- **Хаана:** #21-ийг revert; golden v10 → Go reference `9e76888` (`pades-golden-v9`, зурагтай 5 кейс хасагдсан).
- **Шалгасан:** `src/GeregeSystems.EidMongolia.Pades` (Qr-ээс бусад), `testdata/golden`, `build/go-sdk.ref` нь 0.8.1-тэй
  `git diff` хоосон; CI `dotnet test` (golden).

