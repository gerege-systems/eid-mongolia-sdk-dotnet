### Added — «Миний QR»: нэг удаагийн шалгалт `check`; `result`-ийн хүлээлт дуусахад `QR_PENDING`

- **Юу:** `EidQrClient.CheckAsync(session, serverPoll?)` → `QrCheck(Complete, Presentation)` — нэг `GET /session/{id}` (анхдагч 1 с), COMPLETE+OK бол JWS/JWKS-ээр шалгасан presentation;
  татгалзсан / CA-ийн TIMEOUT бол SessionFailed. **Зан төлөвийн өөрчлөлт:** `result`-ийн өөрийн хүлээх хугацаа дуусахад
  (CA-ийн session идэвхтэй хэвээр) өмнө нь SessionFailed `TIMEOUT` байсан бол одоо `EidQrException` `QR_PENDING` (`EidQrErrorCodes.Pending`) — CA-ийн жинхэнэ `TIMEOUT`-оос
  ялгагдана.
- **Яагаад:** demo-ийн кассын хуудас polling хийхэд «иргэн хараахан зөвшөөрөөгүй» ба CA-ийн TIMEOUT ялгагдахгүй байсан
  (demo `session.poll` + `qr.verify`-ээр тойрсон) — SDK gap.
- **Хаана:** QR модуль, тест, README. Release 0.11.0.
- **Шалгасан:** stub CA: RUNNING → `check` RUNNING; COMPLETE → presentation; endResult TIMEOUT → SessionFailed (`result`, `check`);
  RUNNING + хүлээлт дууссан → `QR_PENDING`. Бүх тест, lint/format.
