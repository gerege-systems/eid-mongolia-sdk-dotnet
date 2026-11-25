[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eid-mongolia-sdk-dotnet

**eID Mongolia** client-side PAdES — .NET (C#) SDK. The PDF document **never goes to the eID server** (Smart-ID model):
the document is prepared on the client (`Prepare`), only the 32-byte hash (DTBS) is signed by the citizen's phone or a USB token,
and the signature is embedded into the PDF on the client (`CompleteAsync`). The output is PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL,
DSS).

This is a **native C# port** of the Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, profile
`pades-client/1`) — no native code, DLLs or WASM. CI verifies on Windows and Linux that it produces **byte-identical** output to the Go golden vectors (verify page, QR,
xref, CMS, TSA/OCSP/CRL requests, DSS).

Full documentation: <https://developer.eidmongolia.mn/#overview>.

- Package: NuGet `GeregeSystems.EidMongolia.Pades`, `net8.0` and `net10.0` (multi-target). The `net8.0` runtime went out of support on 2026-11-10; it is kept temporarily so that current relying parties can still restore, and will be dropped in the next release. Dependency: only `System.Security.Cryptography.Pkcs` (Microsoft).
- Thread-safe, no global state. Network only in `CompleteAsync` (TSA, OCSP/CRL).
- There is **no** full validator here — verification: by the file's SHA-256 against the CA registry; full cryptographic validation in the Go
  backend SDK.

## Install

From [nuget.org](https://www.nuget.org/packages/GeregeSystems.EidMongolia.Pades):

```bash
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.16.0
```

The `.nupkg` of each release is also available on [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases).

## Flow

```csharp
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// 1. Бэлдэх — сүлжээгүй. SignerCert = иргэний SIGN гэрчилгээ (CA-ийн сессийн хариунаас, DER).
var prepared = EidPades.Prepare(pdfBytes, new PrepareOptions
{
    SignerCert = signCertDer,
    Reason = "Гэрээ баталгаажуулав",
    ClaimedRole = representation.ClaimedRole, // байгууллагын нэрийн өмнөөс бол (CA-ийн representation хариунаас)
    VerifyPage = true,                         // шалгах (QR) хуудас — зөвхөн эхний eID гарын үсэгт
    // VerifyPagePosition = "first",           // 0.8.0+: QR хуудас 1-р хуудас болно (анхдагч "last"); Appearance.Page,
                                               // SuggestPlacement, Placement.Page оролтын PDF-ийн хуудсаар (PAGE_SPEC §8a)
    FileName = "Гэрээ №1.pdf",
    Lang = "mn",                               // mn (анхдагч) | en
    // Сонголттой харагдах гарын үсэг (APPEARANCE_SPEC.md): pt, хуудасны харагдах зүүн доод булангаас; Page 0 = eID verify
    // хуудас биш сүүлийн хуудас (PLACEMENT_SPEC §1a). Өндөр ≥ 45 pt; багтахгүй бол REQUEST_INVALID. null = үл харагдах.
    Appearance = new Appearance { X = 36, Y = 36, Width = 220, Height = 64 },
});
// prepared.Placement — харагдах гарын үсгийн эцсийн байрлал (доорх «Байршил»).

// 2. prepared.Dtbs (32 байт)-ийг RP backend-ээр CA-ийн signature session-д өгч утсаар зуруулна
//    (RAW_DIGEST_SIGNATURE), эсвэл USB токеноор (PKCS#11) локалд зурна. prepared.State-г хүлээх хооронд хадгалж болно
//    (формат нь Go reference-тэй ижил).

// 3. Суулгах — TSA, OCSP/CRL сүлжээ. Гарын үсэг: RSA PKCS#1 v1.5, ECDSA r‖s эсвэл DER — гэрчилгээгээр автоматаар.
Completed done = await EidPades.CompleteAsync(prepared.State, signature, cancellationToken: ct);
File.WriteAllBytes("signed.pdf", done.Pdf);

// 4. Бүртгэх — CA POST /pdf/signatures-ийн бие (PDF биш, зөвхөн мета). JSON-оор шууд илгээж болно:
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions
{
    SessionId = sessionId,                     // утсанд заавал; токенд өгөхгүй (Medium = token)
    OnBehalfOf = orgRegNo,                     // NTRMN-… — ClaimedRole өгсөн бол заавал
});
string body = JsonSerializer.Serialize(reg);
```

If `Medium` is empty it is derived from `SessionId` (`phone` if present, otherwise `token` — the CA rule is phone ⇔ sessionID).
`Registration` throws `REQUEST_INVALID` directly, before the CA does, for: `phone` without `SessionId`, `token` with `SessionId`, any other
`Medium` value, or an empty `OnBehalfOf` when `done.ClaimedRole` (the `ClaimedRole` from Prepare) is set.

`Registration` sends earlier signatures only by `priorCmsSha256` — sending **both** `done.PriorCmsSha256` and
`done.PriorRevisionSha256` in full makes the CA return 400. If an earlier signature was assembled at the CA (mode A), the CA returns
409 `PRIOR_MISMATCH`: put the `RevisionSha256` of the first k entries of `reg.PriorSignatures` into `PriorRevisionSha256`, and the
`CmsSha256` of the rest into `PriorCmsSha256`, then resend (the `RegisterSignature` of the Go/TS SDKs does this itself).

`CompleteOptions`: `TsaUrl` (default `https://tsa.timeserver.mn/`), `Roots` (test PKI), `HttpClient` (proxy/sandbox;
the default has a 10 s timeout and does not follow redirects), `TimeProvider`. The national CRL (`esign.gov.mn`) is fetched from the eID https mirror
(WIRE.md §3).

## Errors

All errors are `EidPadesException`; branch on the (stable) `Code`, `Message` is only for logs/humans.

| `Code` | Wire code | Meaning |
|---|---|---|
| `PdfInvalid` | `PDF_INVALID` | The PDF cannot be parsed; structure too deep (nesting > 256) or an ObjStm cycle, `/Extends` > 64, `/Size` > 2^21 (PRECHECKS #2a/#2b) |
| `PdfEncrypted` | `PDF_ENCRYPTED` | Encrypted PDF |
| `PdfLocked` | `PDF_LOCKED` | DocMDP P=1 — modification forbidden |
| `PdfTooLarge` | `PDF_TOO_LARGE` | Larger than 9.75 MiB (input) / 10 MiB (output) |
| `PdfTooManySignatures` | `PDF_TOO_MANY_SIGNATURES` | More than 16 signatures |
| `PdfPriorSignatureInvalid` | `PDF_PRIOR_SIGNATURE_INVALID` | An earlier signature is broken |
| `PdfForeignSignature` | `PDF_FOREIGN_SIGNATURE` | An earlier signature is not an eID B-LT |
| `SignerInvalid` | `SIGNER_INVALID` | signerCert / chain is wrong |
| `RequestInvalid` | `REQUEST_INVALID` | Invalid option (docId, lang, fileName, claimedRole…) |
| `SignatureInvalid` | `SIGNATURE_INVALID` | The signature does not match the DTBS / SignerCert |
| `TsaUnavailable` | `TSA_UNAVAILABLE` | The TSA did not respond / the token is invalid |
| `LtvUnavailable` | `LTV_UNAVAILABLE` | OCSP/CRL could not be fully obtained; if `InnerException is CertificateRevokedException`, a certificate in the chain is revoked — do not retry |
| `SelfValidationFailed` | `SELF_VALIDATION_FAILED` | The output failed its own validation |
| `PlaceholderOverflow` | `PLACEHOLDER_OVERFLOW` | Did not fit in the CMS placeholder |
| `StateInvalid` | `STATE_INVALID` | `State` is corrupt (or its PDF structure is too deep/complex) |
| `Internal` | `INTERNAL` | Internal SDK error |
| `Unknown` | other | A new code — see `RawCode` |

### Visible signature placement

`Appearance.X/Y` is the **requested** position. Prepare reads the target page (text, table rules, images, form XObjects,
and the `/Rect` of annotations such as earlier signatures) without rendering it, and if the requested rectangle (+4 pt) overlaps content,
it moves the stamp to the first free position: the mirrored column at the same height (bottom right → bottom left), then up by 12 pt in the requested
column, then up in the mirrored column. The result is `prepared.Placement` (`Page`, `X`, `Y`, `Width`, `Height` —
pt; `Status`):

| `PlacementStatus` | JSON | Meaning |
|---|---|---|
| `Requested` | `requested` | The requested position is free |
| `Moved` | `moved` | Moved to a free position (`X`, `Y` are the new position) |
| `Overlap` | `overlap` | No free position — drawn over content at the requested position |
| `Unscanned` | `unscanned` | The page could not be read within the limits (4 MiB, 100 000 operators, unsupported filter…) — at the requested position |

It is advisable to tell the user about `Overlap` / `Unscanned`; the signature is valid in every case. Rules: the Go repo's
`pades/PLACEMENT_SPEC.md` (byte-identical with Go; every box is checked against `testdata/golden/placement/vectors.json`).

**Citizen-placed stamp** (PLACEMENT_SPEC §6a/§6b). `EidPades.SuggestPlacement(pdf, appearance)` runs Prepare's
placement without signature, certificate or network and returns the default position and the page sizes; after the citizen drags the stamp into place on a
preview, calling Prepare with `Appearance.Exact = true` draws the stamp exactly in that rectangle
(it never moves; if there is content underneath, `Status = Overlap`; if it leaves the page, `REQUEST_INVALID`):

```csharp
var s = EidPades.SuggestPlacement(pdf, new Appearance { X = 340, Y = 36, Width = 220, Height = 64 });
// s.Page, s.X, s.Y, s.Width, s.Height, s.Status — Prepare-ийн Placement-тэй ижил; s.PageWidth/PageHeight,
// s.PageCount, s.Pages[i].Width/Height (pt). UI (дээд-зүүн эх, s px/pt): left = X·s, top = (PageHeight − Y − Height)·s.
var prepared = EidPades.Prepare(pdf, opts with
{
    Appearance = new Appearance { Page = s.Page, X = x, Y = y, Width = s.Width, Height = s.Height, Exact = true },
});
```

`SuggestPlacement` errors: `PDF_TOO_LARGE`, `PDF_INVALID`, `REQUEST_INVALID`, `PDF_ENCRYPTED`. Only Prepare checks earlier signatures
(`PDF_FOREIGN_SIGNATURE`…) and whether the name fits in the stamp. Page 0: in a signed document, verify
pages are skipped by the docId of the verify page's link; in an unsigned document nothing is skipped (the last page).

Prepare's checks follow the order of the Go reference's `pades/PRECHECKS.md` (#2a/#2b structure, #4 `/Encrypt` reference
or direct dictionary). In `CompleteAsync`, an OCSP response must carry the certificate's CertID (issuer name/key hash + serial), a CRL must be
the issuer's (name, AKI = SKI, signature), and both must be fresh (thisUpdate ≤ now + 5 min; if there is no nextUpdate,
thisUpdate ≥ now − 24 h).

**Revocation source order (by certificate role, not by host name):**

- **Leaf** — the first certificate of each chain (citizen, TSA): **OCSP first**, with a plain 10 s timeout, complete (thisUpdate must not be
  later than the timestamp, with retries). The CRL is fetched too: if both are valid, both are embedded in the DSS;
  if no valid OCSP could be obtained, the CRL suffices.
- **CA** — every certificate after the first in the chain: **CRL first**. If the issuer's valid CRL (signature, validity period, `esign.gov.mn`
  → eID mirror) is obtained, **no OCSP request is sent at all** for that certificate (so it does not go to e.g. the unresponsive `ocsp.esign.gov.mn`).
  OCSP (plain 10 s timeout) is used only when the CRL is missing / could not be fetched / is invalid / is expired.
- Leaf OCSP requests are started up front in parallel, and CRLs are fetched in chain order (a CRL is not refetched within one collection,
  responses are capped at 4 MiB); results are added to the DSS in chain order. A "revoked" from any source is a hard error;
  if a certificate has neither a valid CRL nor a valid OCSP, `LTV_UNAVAILABLE` (fail-closed).

## Organization seal (e-Seal)

`EidPades.SealAsync` — embeds a PAdES-BASELINE-LT signature into a PDF using an organization seal certificate. No citizen, PIN or app
is involved: the SDK prepares the DTBS (without a verify page — seals are not registered at the CA's `/verify/{docId}`) and calls your delegate;
the delegate makes the CA `POST /seal/{orgEtsi}` call with the RP backend's own `HttpClient` and returns `signature.value`.
This SDK does not contain an HTTP client here.

**The seal is visible by default** (same as Go `SealPDF` and TS `sealPdf`; the Go repo's `pades/APPEARANCE_SPEC.md` §6):
an organization seal stamp on the document's last (non-eID-verify) page — name, "Sealed with eID Mongolia" / «eID Mongolia-аар тамгалсан», date; no QR,
link or role line. Placement: 220 × 64 pt, `x = page width − 256`, `y = 36` (fitted on small
pages, e.g. a 164 pt document → 156 × 64, x = 4), moved to a free position if it overlaps content (see "Visible signature
placement" above). The result is `done.Placement`. If the automatic stamp does not fit the page or would push the output over 10 MiB,
an invisible seal is produced without error (`Placement = null`). Give the placement yourself with `SealOptions.Appearance` (same fields as the citizen's
`Appearance`; if it does not fit, `REQUEST_INVALID` / `PDF_TOO_LARGE`). `SealOptions.Invisible = true` — an invisible seal byte-identical to the
previous version. Verifiers older than Go SDK v0.30.0 / TS SDK 0.48.0 report earlier signatures of a PDF carrying a visible seal stamp
as modified — use `Invisible = true` until those are updated.
Only the signer's certificate selects the stamp variant: calling `Prepare` + `Appearance` with an e-Seal certificate
also draws the seal stamp.

```csharp
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// SealCert: CA GET /seal/certificate/{orgEtsi} → "certificate" (base64 DER).
Completed done = await EidPades.SealAsync(pdfBytes, new SealOptions
{
    SealCert = Convert.FromBase64String(sealCertB64),
    Reason = "Байгууллагын тамга",            // SignerName = гэрчилгээний CN (байгууллагын нэр), Chain = шигтгэсэн eID гинж
}, async (dtbs, ct) =>
{
    using var req = new HttpRequestMessage(HttpMethod.Post, $"https://rp.eidmongolia.mn/seal/{orgEtsi}")
    {
        Content = JsonContent.Create(new { digest = Convert.ToBase64String(dtbs), hashType = "SHA256" }),
    };
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rpSecret);
    using var resp = await http.SendAsync(req, ct);
    resp.EnsureSuccessStatusCode();                    // 403 = SEAL:<orgEtsi> эрхгүй; 429 = түр хязгаарлагдсан
    using var body = JsonDocument.Parse(await resp.Content.ReadAsStreamAsync(ct));
    return Convert.FromBase64String(body.RootElement.GetProperty("signature").GetProperty("value").GetString()!);
}, cancellationToken: ct);
File.WriteAllBytes("sealed.pdf", done.Pdf);
```

- The RP needs the `SEAL:<orgEtsi>` permission (otherwise 403). 429 — rate limit: wait a while and retry (an exception from the
  delegate is passed through by the SDK unchanged).
- An RFC 3161 timestamp is mandatory — if the TSA is unreachable, `TSA_UNAVAILABLE` (no seal is issued without a timestamp).
- `SealCert` must be a seal profile (not a CA, KeyUsage has nonRepudiation and not digitalSignature, no EKU
  purposes — extendedKeyUsage absent or empty) — otherwise `SIGNER_INVALID`. If the signature does not match the DTBS / `SealCert`, `SIGNATURE_INVALID`.
- Seal certificates are issued by the CA / admin console — this SDK has no issuing function.

## "My QR" — the citizen's "My info" (`GeregeSystems.EidMongolia.Qr`, 0.13.0)

Separate from PAdES, in the same package. The citizen shows "My QR" in their eID app (`EIDMN-QR1:<token>`, 120 s, single
use) → the RP scans it and calls `POST /authentication/qr` → the citizen sees one sentence on their phone and approves with **PIN2** →
the RP receives the citizen's "My info" (the dict stored in the app exactly as is + a face JPEG) as a **PS256 JWS** signed with the citizen's own QUALIFIED SIGN
key (`typ` = `eidmn-myqr+jwt`, `x5c` = [citizen certificate, issuing CA]). The CA does not
store the value; the presentation can be read only once (a second read returns 410 `QR_PRESENTATION_GONE`). The RP needs only the
`QR_PRESENT` permission.

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "Касс 3", ApiSecret = secret });
try
{
    QrSession s = await qr.StartAsync(new QrStartRequest(scanned)); // nonce өгөөгүй бол SDK 22 тэмдэгт үүсгэнэ
    QrResult r = await qr.ResultAsync(s);                            // эсвэл polling UI-д: CheckAsync(s) → QrCheck
    foreach (var (key, value) in r.Data) Show(key, value);          // payload-ийн дарааллаар, түлхүүр яг хэвээр
    // r.Source (dan, passport, citizenid …), r.Photo (JPEG | null), r.Signer.Etsi / GivenName / Surname,
    // r.SignedAt, r.Sha256 (= CA аудитын qrsha), r.Jws (маргаанд хадгалж болно)
}
catch (EidQrException e) when (e.Code == EidQrErrorCodes.TokenInvalid) { /* 404 — шинэ QR гаргуул */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.SessionFailed) { /* e.EndResult: USER_REFUSED, TIMEOUT */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.PresentationGone) { /* 410 — дахин QR уншуул */ }
catch (EidQrException e) when (e.Code.StartsWith("QR_", StringComparison.Ordinal)) { /* шалгалт унасан — ИТГЭХГҮЙ */ }
```

`EidQr.VerifyAsync(jws, new QrExpect(rpUuid, sessionId, nonce), trust?)` — re-verifies a stored JWS (network only for OCSP).
Verification (same as the Go / TS SDKs, the CA's `testdata/myqr_vectors.json`): JWS ≤ 512 KiB, 3 segments → header exactly
`alg` PS256 / `typ` / `x5c` with 2 certificates → chain (`X509Chain` CustomRootTrust; x5c[1] is only an intermediate candidate, ±60 s) +
leaf: not a CA, KeyUsage contentCommitment, QcCompliance (QUALIFIED), issuer SKI ∈ `AllowedIssuerSkis` (default the 04
`EidQr.CitizenIssuingCaSki`), RSA ≥ 2048 → revocation (default the AIA OCSP, hard-fail) → RSASSA-PSS SHA-256 (salt 32) →
`iss`, `sub` = the certificate's serialNumber, `statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг
хуваалцах гэж байна» ("You are about to share all information in the "My info" section with {rp_name}"), `aud` = RP UUID (case-insensitive), `sid`, `nonce` (exact), 0 < exp − iat ≤ 300, iat ≤ now + 60,
now < exp + 60 → `data` (`source` `^[a-z0-9_-]{1,32}$`; `fields` ≤ 128, key 1–64 code points without control characters,
value only a string ≤ 2048 bytes; `photo` strict base64 JPEG ≤ 150 KiB; if `fields` is empty, `photo` is required; no extra
members).

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)` — if null: the embedded national root
+ the 02–05 intermediates, issuer 04, OCSP. `Revocation` = `(leaf, issuer) → "good" | "revoked" | "unknown"` (your own cache/CRL or
a test stub); an exception = "unknown". With `RevocationSoftFail = true`, "unknown" is accepted.

Codes (`EidQrException.Code`): `QR_FORMAT_INVALID` (does not go to the CA), `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`,
`QR_CHAIN_INVALID`, `QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`,
`QR_AUDIENCE_MISMATCH`, `QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`,
`QR_PRESENTATION_GONE` (410), `QR_PENDING` (the `maxWait` of `ResultAsync` elapsed — it can be called again), `SESSION_FAILED`
(`EndResult`), the server's `code` with `HttpStatus` (400 `REQUEST_INVALID`, 403 `PERMISSION_DENIED` / `RP_REQUIRED`, 404
`QR_TOKEN_INVALID`, 409 `NO_SIGNING_CERTIFICATE`, 429 `RATE_LIMITED`), `HTTP_ERROR`, `NETWORK_ERROR`.

## Development

- Profile rules: the Go repo's `pades/PROFILE.md`, `PAGE_SPEC.md`, `PRECHECKS.md`, `WIRE.md`, `APPEARANCE_SPEC.md`,
  `PLACEMENT_SPEC.md`.
- Golden: `testdata/golden` = a copy of the Go repo's `pades/testdata/golden`, from the `build/go-sdk.ref` commit
  (`./build/sync-golden.sh`; the CI `golden-sync` job checks it with `--check`). **The test PKI's private keys** are
  for tests only — they are not trusted in any real chain.
- Tests (`dotnet test`): for every golden case, Prepare → the manifest's signature → CompleteAsync (HTTP fixture replay,
  fixed nonce/time) → the output PDF is compared with Go's **in full**, at byte level; the eid-desktop (Swift) golden;
  error paths; ECDSA (r‖s, DER); revocation rules (`RevocationTests` — OCSP/CRL signed with the 04 key); structure
  checks (`StructureTests`, `testdata/structure` — inputs from Go/TS); stamp placement (`PlacementTests` — every box of Go's
  `placement/vectors.json`, candidate order, no exception on corrupt content/Flate streams);
  `SuggestPlacement` for every visible golden case (every `expect.suggestion` field, `suggestionError`).
- Font (`Assets/`): Noto Sans subset, SIL OFL 1.1 — the same bytes as the Go reference's `pades/assets/fonts`.
- The PDF reader/writer repeats the semantics of digitorus/pdf (BSD-3) and digitorus/pdfsign (BSD-2) — licenses in `Pdf/LICENSE.*`.

## Release

1. On a `release/<version>` branch: bump the csproj `<Version>`, merge `changelog.d/*` into a new section of `CHANGELOG.md`
   and delete the fragments → PR → merge.
2. On main: `git tag v<version> && git push origin v<version>`.
3. `.github/workflows/release.yml`: runs the full CI (Windows + Linux), checks that the tag = `<Version>`, then publishes
   the `.nupkg` as a GitHub Release asset, and to GitHub Packages (NuGet) and nuget.org (Trusted Publishing).

## License

MIT — [LICENSE](LICENSE). Third party: Noto Sans (OFL 1.1), digitorus/pdf (BSD-3), digitorus/pdfsign (BSD-2) — in the NuGet package's
`licenses/`.
