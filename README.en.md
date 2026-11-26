[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eid-mongolia-sdk-dotnet

The **eID Mongolia** .NET (C#) SDK for relying-party (RP) backends: citizen authentication (push, QR, Web2App), signing
sessions, cryptographic validation of the responses (chain, ACSP_V2 / RAW_DIGEST, OCSP), PDF signature registration,
organisation / person / e-Seal / USB token / share services, «My QR», the «Sign in with eID» button backend (with an
ASP.NET Core adapter), and client-side PAdES — the PDF document **never goes to the eID server** (Smart-ID model): the
document is prepared on the client (`Prepare`), only the 32-byte hash (DTBS) is signed by the citizen's phone or a USB
token, and the signature is embedded into the PDF on the client (`CompleteAsync`; PAdES-BASELINE-LT — RFC 3161 timestamp,
OCSP/CRL, DSS).

This is a **native C# port** of the Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go))
and the TypeScript SDK — no native code, DLLs or WASM. CI verifies on Windows and Linux that the PAdES output is
**byte-identical** to the Go golden vectors (verify page, QR, xref, CMS, TSA/OCSP/CRL requests, DSS) and runs the cross-SDK
conformance corpus (`testdata/conformance`: validator, OCSP, wire, login backend).

Full documentation: <https://developer.eidmongolia.mn/#overview>.

| Package (NuGet) | What | Dependencies |
|---|---|---|
| `GeregeSystems.EidMongolia` | RP SDK: `EidClient` (Auth, Sign, Session, Validator, PDF registration, Organization, Person, Seal, Token, Share, «My QR»), `OcspRevocationChecker`, `EidLoginHandler` | — |
| `GeregeSystems.EidMongolia.AspNetCore` | `services.AddEidMongolia(...)`, `app.MapEidLogin(...)` | core + the ASP.NET Core shared framework |
| `GeregeSystems.EidMongolia.Pades` | Client-side PAdES: `EidPades.Prepare` / `CompleteAsync` / `SealAsync` / `Registration` | core + `System.Security.Cryptography.Pkcs` (Microsoft) |

- All three share one version (lockstep), `net8.0` and `net10.0` (multi-target). The `net8.0` runtime went out of support
  on 2026-11-10; it is kept temporarily so that current relying parties can still restore, and will be dropped in a
  coming release.
- Thread-safe, no global state: use one `EidClient` (singleton) for all requests. The API secret stays on the backend.
- A full PDF validator (`ValidatePDF`) is **not available yet** in this SDK — use Go `pades.ValidatePDF` or TS `validatePdf`
  (see «Support compared with Go / TS»).

## Install

From [nuget.org](https://www.nuget.org/profiles/geregecore):

```bash
dotnet add package GeregeSystems.EidMongolia --version 0.17.0             # RP SDK
dotnet add package GeregeSystems.EidMongolia.AspNetCore --version 0.17.0  # for ASP.NET Core (brings core)
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.17.0       # client-side PAdES (brings core)
```

The `.nupkg` (+ `.snupkg` symbols) of each release is also available on
[GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases).

## RP SDK — `GeregeSystems.EidMongolia`

A port of Go `eid` and TS `EidClient`, with no package dependencies. RP-API: `https://rp.eidmongolia.mn` (default).

### Client

```csharp
using GeregeSystems.EidMongolia;

// Create once (singleton) and use it for every request.
var client = new EidClient(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "My Bank", apiSecret),   // RP UUID, registered name, API secret
    Trust = new TrustConfig
    {
        TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem },        // REQUIRED in production (otherwise the validator fails closed)
        Revocation = new OcspRevocationChecker().Checker,              // revocation — see «Revocation» below
        RevocationMode = RevocationMode.HardFail,
    },
    Language = "en",                                                   // Accept-Language (mn | en)
});
```

- `BaseUrl`: https is required (http only for localhost/loopback); a clear error for the legacy `ca.eidmongolia.mn` host.
  Default timeout 15 s (PDF registration 80 s), JSON responses ≤ 4 MiB.
- mTLS: pass an `HttpClient` with a client certificate as the second argument (`new EidClient(options, httpClient)`; the SDK
  does not dispose it; it sets its own timeout per call, so set `HttpClient.Timeout` to `Timeout.InfiniteTimeSpan`).
- Errors: `EidException` (`Code`, `Status`, `RetryAfter`, `Retryable`) → `EidAuthenticationException` (401),
  `EidForbiddenException` (403), `EidApiException` (a subclass per CA code), `EidNetworkException`,
  `EidResponseTooLargeException`, `EidSessionFailedException` (endResult ≠ OK), `EidValidationException` (`Reason` — a
  stable key, `ValidationReasons`), `EidDeviceLinkException`. Branch on `Code` / `Reason`.

### Authentication — push (notification to the citizen's phone)

```csharp
var login = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Sign in to My Bank" } };

NotificationSession s = await client.Auth.NotificationByEtsiAsync(etsi, login); // etsi = "PNOMN-…"; or ByDocumentAsync
Show(s.Vc);                                                                       // verification code for the user
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId, new WaitOptions { ExpiresAt = s.ExpiresAt });
VerifiedIdentity id = client.Validator.ValidateAuth(r, s.Acsp!);                  // chain, ACSP_V2 signature, level, purpose
await client.Validator.CheckRevocationAsync(id.Certificate);                      // with TrustConfig.Revocation (below)
// id.Subject.SerialNumber (PNOMN-…), id.Subject.GivenName / Surname, id.CertificateLevel, id.DocumentNumber
```

`ValidateAuth` throws `EidSessionFailedException` when endResult ≠ OK (USER_REFUSED, TIMEOUT …) and
`EidValidationException` when the response cannot be trusted. `AuthOptions`: `CertificateLevel`, `CallbackUrl`, `OnBehalfOf`
(on behalf of an organisation), `SignatureAlgorithm`, `HashAlgorithm`.

### Authentication — QR, Web2App, App2App (device link)

```csharp
DeviceLinkSession d = await client.Auth.DeviceLinkAnonymousAsync(login);             // or DeviceLinkByEtsiAsync(etsi, …)
// QR: the link changes every second (authCode = HMAC-SHA256). For SSE / WebSocket:
//   await foreach (var link in d.TickQrAsync("eng", TimeSpan.FromSeconds(1), ct)) Send(link);
// For HTTP polling, on every request: d.BuildLink(DeviceLinkTypes.Qr, "eng").
SessionResult r = await client.Session.WaitForResultAsync(d.SessionId);
VerifiedIdentity id = client.Validator.ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Qr });
```

Web2App: `DeviceLinkAnonymousAsync(login, new AuthOptions { CallbackUrl = "https://bank.example.mn/auth/eid/callback" })`
→ send the browser to `d.BuildLink(DeviceLinkTypes.Web2App, "eng")` → the callback's `sessionId` + `userChallengeVerifier` →
`ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Web2App, UserChallengeVerifier = verifier })`.
Keep `d.SessionId`, `SessionToken`, `SessionSecret` and `Acsp` on the server (never send them to the browser). Ready-made
solution: the «Sign in with eID» button backend below.

`client.Session.PollAsync(sessionId)` — a single long-poll; `WaitForResultAsync` repeats it up to `MaxWait` → `ExpiresAt` →
the discovery `sessionTtl` → 600 s (+15 s). `client.Auth.SessionTtlAsync()` — the session lifetimes from discovery.

### Revocation — default modes

| Where | Default | Notes |
|---|---|---|
| `client.Validator.CheckRevocationAsync` | **not checked** without `TrustConfig.Revocation` (`RevocationStatus.Skipped`); with a checker **hard-fail** | no OCSP answer → `EidValidationException` (`ValidationReasons.RevocationUnknown`); `RevocationMode.SoftFail` → `Unchecked` |
| «Sign in with eID» backend (`EidLoginHandler`) | `OcspRevocationChecker`, **soft-fail** | without an OCSP answer the citizen is signed in (`Identity.Revocation == Unchecked`, Warning log) — so that an outage of the CA responder does not lock out every user |
| «My QR» | the AIA OCSP, **hard-fail** | `QrTrust.RevocationSoftFail = true` accepts "unknown" |

**Note: revocation in the login backend defaults to soft-fail.** High-value relying parties (banks, finance, government
services, contract signing) should set `o.RevocationMode = RevocationMode.HardFail` — the sign-in then ends `FAILED`
(`revocation_unavailable`) when OCSP does not answer. The OCSP rules match Go/TS: `unknown` → revoked, thisUpdate ∈
[now − 48 h, now + 5 min], nextUpdate not passed, delegated responder (OCSPSigning EKU), 2 s per request / 3 s total,
«good» cached ≤ 5 min; in addition .NET checks before any network call that the issuer signed the leaf, and matches the
response CertID issuer hashes.

Chain validation does not use X509Chain (identical on every platform): basicConstraints/pathLen, keyCertSign, EKU, validity,
the citizen issuer SKI allowlist (default 04), RSA ≥ 2048 (odd exponent ≥ 3); CAs with name constraints, unknown critical
extensions and subjects with duplicate SERIALNUMBER/CN are rejected (fail-closed).

### Signing and PAdES

```csharp
using GeregeSystems.EidMongolia.Pades;

// 1. Let the citizen choose the SIGN certificate.
var cc = await client.Sign.CertificateChoiceByEtsiAsync(etsi);
Signer signer = client.Validator.ValidateCertificateChoice(await client.Session.WaitForResultAsync(cc.SessionId));

// 2. Prepare the PDF on the client (no network).
var prepared = EidPades.Prepare(pdf, new PrepareOptions { SignerCert = signer.Certificate.RawData, FileName = "Contract No 1.pdf", VerifyPage = true });
var dtbs = Convert.ToBase64String(prepared.Dtbs);

// 3. Have it signed on the phone with the chosen certificate (RAW_DIGEST_SIGNATURE) and validate.
var sign = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Sign contract No 1" } };
NotificationSession s = await client.Sign.DigestForSignerAsync(signer, dtbs, sign);
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId);
VerifiedSignature v = client.Validator.ValidateSign(r, dtbs, HashAlgorithms.Sha256, new ValidateSignOptions { ExpectedCertificate = signer.Certificate });
await client.Validator.CheckRevocationAsync(v.Certificate);

// 4. Embed the signature into the PDF (TSA, OCSP/CRL) — see «PAdES» below.
Completed done = await EidPades.CompleteAsync(prepared.State, Convert.FromBase64String(v.SignatureValueB64), cancellationToken: ct);
```

Others: `Sign.DigestByEtsiAsync` / `DigestByDocumentAsync` / `TextByEtsiAsync` (hash or text), `DeviceLinkByEtsiAsync` /
`DeviceLinkByDocumentAsync` / `DeviceLinkForSignerAsync` (signing via QR / Web2App), `CertificateChoiceDeviceLinkAsync`;
`SignOptions`: `CertificateLevel`, `CallbackUrl`, `HashAlgorithm`, `SignatureAlgorithm`, `OnBehalfOf`, `FileName`.

### PDF signature registration (`POST /pdf/signatures`)

Required after PAdES complete (docId, the `/verify` page). The body from `EidPades.Registration` has the same shape as
core's `PdfSignatureRegistration`:

```csharp
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions { SessionId = s.SessionId });
PdfSignatureRegistered ok = await client.Pdf.RegisterSignatureAsync(new PdfSignatureRegistration
{
    DocId = reg.DocId, RevIndex = reg.RevIndex, Medium = reg.Medium, SessionId = reg.SessionId, Cms = reg.Cms,
    FileName = reg.FileName, InSha256 = reg.InSha256, PageSha256 = reg.PageSha256, SigRevSha256 = reg.SigRevSha256,
    OutSha256 = reg.OutSha256, PriorCmsSha256 = reg.PriorCmsSha256, PriorRevisionSha256 = reg.PriorRevisionSha256,
    OnBehalfOf = reg.OnBehalfOf, SignerEtsi = reg.SignerEtsi,
    PriorSignatures = reg.PriorSignatures.Select(p => new PdfPriorSignature(p.CmsSha256, p.RevisionSha256)).ToList(),
});
// ok.DocId; ok.Created == false — the same body was sent again (idempotent). The SDK retries 409 PRIOR_MISMATCH itself.
```

Error codes: `PdfErrorCodes`.

### Organisation, person, seal, token, share

- **Organisation** — `client.Organization.GetRepresentationsAsync(personEtsi)` (which organisations the citizen may
  represent — for `OnBehalfOf` / `ClaimedRole`), `SealGrantsAsync(personEtsi)`.
- **Person (PKI_READ permission)** — `client.Person.CertificatesAsync`, `DevicesAsync`, `ActivityAsync(etsi, ActivityQuery)`,
  `SummaryAsync`, `ChildrenAsync`.
- **Organisation seal (e-Seal)** — `client.Seal.CertificateAsync(orgEtsi)`, `RequestCertificateAsync` /
  `CertificateRequestAsync` / `WaitForCertificateAsync`, `SealAsync(orgEtsi, digest)` (checks the returned ECDSA signature
  and the e-Seal profile), seal grants `RequestGrantAsync` / `GrantStatusAsync` / `WaitForGrantAsync`,
  `SealService.IsSealCertificate`. Sealing a PDF:

  ```csharp
  var cert = await client.Seal.CertificateAsync(orgEtsi);
  Completed stamped = await EidPades.SealAsync(pdf, new SealOptions { SealCert = cert.Certificate, Reason = "Organisation seal" },
      async (dtbs, ct) => (await client.Seal.SealAsync(orgEtsi, dtbs, ct: ct)).Signature, cancellationToken: ct);
  ```
- **USB token** — `client.Token.IssueCertificateAsync` / `PreviewCertificateAsync` / `CertificateResultAsync` /
  `CertificateInfoAsync`, `TokenService.VerifyTokenCertificates`, token authentication `AuthChallengeAsync` → sign on the
  token → `AuthVerifyAsync` (checks the digest, signature and chain locally before calling the CA),
  `TokenService.TokenAuthDigest`.
- **Share** — `client.ShareAsync(new ShareRequest { File = signedPdf, Filename = "Contract.pdf", To = new[] { "user@example.mn" } })`
  (sends a signed PDF to 1–5 recipients by eID e-mail), `ShareInfoAsync()` (limits).

### «Sign in with eID» button backend (`EidLoginHandler`, ASP.NET Core)

The backend of the TS SDK's `<eid-login-button>`: `POST {base}/start` (`{"mode":"qr"}` | `{"mode":"push","idCode":"УБ12345678"}`),
`GET {base}/start?mode=web2app`, `GET {base}/status`, `GET {base}/callback` (Web2App). A framework-neutral core —
`GeregeSystems.EidMongolia.Login.EidLoginHandler` (`HandleAsync(EidLoginRequest)` → `EidLoginResponse`); for ASP.NET Core,
`GeregeSystems.EidMongolia.AspNetCore`:

```csharp
using GeregeSystems.EidMongolia;
using GeregeSystems.EidMongolia.AspNetCore;
using GeregeSystems.EidMongolia.Login;
using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

builder.Services.AddEidMongolia(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "My Bank", apiSecret),
    Trust = new TrustConfig { TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem } },
});
// Behind a reverse proxy (nginx etc.): trust only your own proxy and let it fix RemoteIpAddress.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Add(IPAddress.Parse("192.0.2.10")); // your proxy's address
});
var app = builder.Build();
app.UseForwardedHeaders();
app.MapEidLogin("/auth/eid", async (http, id) =>
{
    // Identify the citizen by id.Etsi (PNOMN-…) and create a NEW session (session fixation).
    await SignInAsync(http, id.Etsi);
    return new EidLoginSuccess { Redirect = "/dashboard" };
}, o =>
{
    o.CallbackUrl = "https://bank.example.mn/auth/eid/callback"; // Web2App (the path must be /auth/eid/callback)
    o.FailureRedirect = "/login";
    o.RevocationMode = RevocationMode.HardFail;                   // for high-value relying parties (default soft-fail)
});
```

**Client IP and proxies.** The `start` limit (20 per 60 s per IP) is keyed by the client IP. `MapEidLogin` defaults to
`o.ClientIp = EidLoginClientIp.RemoteAddress` (`HttpContext.Connection.RemoteIpAddress`). Behind a reverse proxy, either
(a) run `UseForwardedHeaders` with `KnownProxies` / `KnownNetworks` before `MapEidLogin` as above, or (b) set
`o.ClientIp = EidLoginClientIp.Forwarded(n)` (n = the number of trusted proxies; the n-th `X-Forwarded-For` value from the
right). With neither, all users share the proxy's single IP limit; never use `Forwarded(n)` without a proxy (the header can
be forged). IPv6 clients are keyed by their /64 prefix (`start:2001:db8:1:2::/64`).

Security matches Go `eidlogin` / TS `createEidLogin`: state on the server (`IEidLoginStore`; default `MemoryEidLoginStore` —
one process, at most 10 000 entries; with several instances register your own store, e.g. Redis, BEFORE `AddEidMongolia`),
the browser only gets an HttpOnly + Secure + SameSite=Lax cookie (`<sessionId>.<binding>`, the binding's SHA-256 compared in
constant time), `Sec-Fetch-Site` cross-site → 403, limits (start: 20 per 60 s per IP; push: 3 per 60 s per number), decoy
sessions for unregistered numbers + a 1 s push floor, `OnSuccess` only after ValidateAuth + OCSP (**soft-fail by default**,
see «Revocation» above) and only once, an audit `OnEvent` (an HMAC pushKey instead of the national ID). The response shapes
and the 12 error codes are checked against the cross-SDK corpus `testdata/conformance/eidlogin/scenarios.json`
(24 scenarios). For other frameworks call `EidLoginHandler` directly (`EidLoginRequest` — method, URL, headers, body,
`RemoteIp`).

## "My QR" — the citizen's "My info" (`GeregeSystems.EidMongolia.Qr`)

Since 0.17.0 in the core package (`client.Qr` or `new EidQrClient(...)`); the namespace and API are the same as in Pades
0.13.0–0.16.0 (Pades forwards the types). The citizen shows "My QR" in their eID app (`EIDMN-QR1:<token>`, 120 s, single
use) → the RP scans it and calls `POST /authentication/qr` → the citizen sees one sentence on their phone and approves with **PIN2** →
the RP receives the citizen's "My info" (the dict stored in the app exactly as is + a face JPEG) as a **PS256 JWS** signed with the citizen's own QUALIFIED SIGN
key (`typ` = `eidmn-myqr+jwt`, `x5c` = [citizen certificate, issuing CA]). The CA does not
store the value; the presentation can be read only once (a second read returns 410 `QR_PRESENTATION_GONE`). The RP needs only the
`QR_PRESENT` permission.

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "Till 3", ApiSecret = secret }); // or client.Qr
try
{
    QrSession s = await qr.StartAsync(new QrStartRequest(scanned)); // if no nonce is given, the SDK generates 22 characters
    QrResult r = await qr.ResultAsync(s);                            // or for a polling UI: CheckAsync(s) → QrCheck
    foreach (var (key, value) in r.Data) Show(key, value);          // in payload order, keys exactly as they are
    // r.Source (dan, passport, citizenid …), r.Photo (JPEG | null), r.Signer.Etsi / GivenName / Surname,
    // r.SignedAt, r.Sha256 (= the CA's audit qrsha), r.Jws (can be kept for a dispute)
}
catch (EidQrException e) when (e.Code == EidQrErrorCodes.TokenInvalid) { /* 404 — ask for a new QR */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.SessionFailed) { /* e.EndResult: USER_REFUSED, TIMEOUT */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.PresentationGone) { /* 410 — scan the QR again */ }
catch (EidQrException e) when (e.Code.StartsWith("QR_", StringComparison.Ordinal)) { /* a check failed — DO NOT TRUST */ }
```

`EidQr.VerifyAsync(jws, new QrExpect(rpUuid, sessionId, nonce), trust?)` — re-verifies a stored JWS (network only for OCSP).
Verification (same as the Go / TS SDKs, the CA's `testdata/myqr_vectors.json`): JWS ≤ 512 KiB, 3 segments → header exactly
`alg` PS256 / `typ` / `x5c` with 2 certificates (no duplicate keys) → chain (core's path builder — see «Revocation» above;
x5c[1] is only an intermediate candidate, ±60 s) + leaf: not a CA, KeyUsage contentCommitment, QcCompliance (QUALIFIED),
issuer SKI ∈ `AllowedIssuerSkis` (default the 04 `EidQr.CitizenIssuingCaSki`), RSA ≥ 2048, no duplicate SERIALNUMBER/CN →
revocation (default the AIA OCSP, hard-fail; OCSP `unknown` → revoked) → RSASSA-PSS SHA-256 (salt 32) → payload (no
duplicate keys) `iss`, `sub` = the certificate's serialNumber, `statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх
мэдээллийг хуваалцах гэж байна» ("You are about to share all information in the "My info" section with {rp_name}"), `aud` = RP UUID (case-insensitive), `sid`, `nonce` (exact), 0 < exp − iat ≤ 300, iat ≤ now + 60,
now < exp + 60 → `data` (`source` `^[a-z0-9_-]{1,32}$`; `fields` ≤ 128, key 1–64 code points without control characters,
value only a string ≤ 2048 bytes; `photo` strict base64 JPEG ≤ 150 KiB; if `fields` is empty, `photo` is required; no extra
members).

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)` — if null: the embedded national root
+ the 02–04 intermediates, issuer 04, OCSP. `Revocation` = `(leaf, issuer) → "good" | "revoked" | "unknown"` (your own cache/CRL or
a test stub; the issuer certificate is disposed when `VerifyAsync` returns); an exception = "unknown". With
`RevocationSoftFail = true`, "unknown" is accepted. `EidClientOptions.QrTrust` — the trust for `client.Qr`.

Codes (`EidQrException.Code`): `QR_FORMAT_INVALID` (does not go to the CA), `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`,
`QR_CHAIN_INVALID`, `QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`,
`QR_AUDIENCE_MISMATCH`, `QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`,
`QR_PRESENTATION_GONE` (410), `QR_PENDING` (the `maxWait` of `ResultAsync` elapsed — it can be called again), `SESSION_FAILED`
(`EndResult`), the server's `code` with `HttpStatus` (400 `REQUEST_INVALID`, 403 `PERMISSION_DENIED` / `RP_REQUIRED`, 404
`QR_TOKEN_INVALID`, 409 `NO_SIGNING_CERTIFICATE`, 429 `RATE_LIMITED`), `HTTP_ERROR`, `NETWORK_ERROR`.

## PAdES (`GeregeSystems.EidMongolia.Pades`) — flow

```csharp
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// 1. Prepare — no network. SignerCert = the citizen's SIGN certificate (from the CA's session response, DER).
var prepared = EidPades.Prepare(pdfBytes, new PrepareOptions
{
    SignerCert = signCertDer,
    Reason = "Contract confirmed",
    ClaimedRole = representation.ClaimedRole, // when signing on behalf of an organization (from the CA's representation response)
    VerifyPage = true,                         // the verification (QR) page — only for the first eID signature
    // VerifyPagePosition = "first",           // 0.8.0+: the QR page becomes page 1 (default "last"); Appearance.Page,
                                               // SuggestPlacement and Placement.Page count by the input PDF's pages (PAGE_SPEC §8a)
    FileName = "Contract No. 1.pdf",
    Lang = "mn",                               // mn (default) | en
    // Optional visible signature (APPEARANCE_SPEC.md): pt, from the visible bottom-left corner of the page; Page 0 = the last page,
    // NOT the eID verify page (PLACEMENT_SPEC §1a). Height ≥ 45 pt; REQUEST_INVALID if it does not fit. null = invisible.
    Appearance = new Appearance { X = 36, Y = 36, Width = 220, Height = 64 },
});
// prepared.Placement — the final placement of the visible signature (see "Placement" below).

// 2. Give prepared.Dtbs (32 bytes), via the RP backend, to the CA's signature session so it is signed on the phone
//    (RAW_DIGEST_SIGNATURE), or sign locally with a USB token (PKCS#11). prepared.State may be stored while waiting
//    (its format is identical to the Go reference).

// 3. Embed — TSA, OCSP/CRL network. Signature: RSA PKCS#1 v1.5, ECDSA r‖s or DER — detected automatically from the certificate.
Completed done = await EidPades.CompleteAsync(prepared.State, signature, cancellationToken: ct);
File.WriteAllBytes("signed.pdf", done.Pdf);

// 4. Register — the body of the CA's POST /pdf/signatures (not the PDF, metadata only). It can be sent directly as JSON:
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions
{
    SessionId = sessionId,                     // required for a phone; omit for a token (Medium = token)
    OnBehalfOf = orgRegNo,                     // NTRMN-… — required if ClaimedRole is given
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
// s.Page, s.X, s.Y, s.Width, s.Height, s.Status — the same as Prepare's Placement; s.PageWidth/PageHeight,
// s.PageCount, s.Pages[i].Width/Height (pt). UI (top-left origin, s px/pt): left = X·s, top = (PageHeight − Y − Height)·s.
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
The Pades package itself has no HTTP client — the delegate can call core's `client.Seal.SealAsync` directly (see «Organisation, person, seal, token, share» above); the example below uses hand-written HTTP.

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
    Reason = "Organization seal",            // SignerName = the certificate's CN (the organization's name), Chain = the embedded eID chain
}, async (dtbs, ct) =>
{
    using var req = new HttpRequestMessage(HttpMethod.Post, $"https://rp.eidmongolia.mn/seal/{orgEtsi}")
    {
        Content = JsonContent.Create(new { digest = Convert.ToBase64String(dtbs), hashType = "SHA256" }),
    };
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rpSecret);
    using var resp = await http.SendAsync(req, ct);
    resp.EnsureSuccessStatusCode();                    // 403 = no SEAL:<orgEtsi> permission; 429 = temporarily rate-limited
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
- Seal certificates are requested with core's `client.Seal.RequestCertificateAsync` / `WaitForCertificateAsync`, or issued by the CA / admin console.

## For Pades users — 0.16.0 → 0.17.0

- `GeregeSystems.EidMongolia.Pades` 0.17.0 pulls in `GeregeSystems.EidMongolia` 0.17.0 automatically. The PAdES API and
  output are unchanged (golden byte-identical).
- «My QR» (`GeregeSystems.EidMongolia.Qr`: `EidQr`, `EidQrClient`, `EidQrOptions`, `EidQrException`, `EidQrErrorCodes`,
  `QrStartRequest`, `QrSession`, `QrSigner`, `QrResult`, `QrExpect`, `QrTrust`, `QrCheck`) moved to core; Pades forwards it
  with `[TypeForwardedTo]` — your `using` and code stay the same, and assemblies compiled against 0.16.0 run **without
  recompiling** (the CI `compat` job runs a consumer compiled against 0.16.0 from nuget.org on the 0.17.0 assemblies).
- Behaviour differences (not API): the «My QR» chain is built by core's path builder instead of X509Chain — name
  constraints, unknown critical extensions, duplicate SERIALNUMBER/CN and RSA < 2048 give `QR_CHAIN_INVALID`;
  `QrTrust.Intermediates` = null means 02–04 (before: 02–05); duplicate payload keys → `QR_JWS_MALFORMED`; an empty / `.` /
  `..` `QrSession.SessionId` → `ArgumentException`. The real eID chain is not affected.
- For new RP work (authentication, signing sessions, registration) use core's `EidClient` — `client.Sign` / `client.Seal` /
  `client.Pdf` instead of the hand-written `HttpClient` examples in the «PAdES» section.

## Support compared with Go / TS

| Feature | .NET 0.17.0 | Go | TS |
|---|---|---|---|
| Client, errors, route table, discovery | ✓ | ✓ | ✓ |
| Authentication: push, device link (QR / Web2App / App2App), QR ticker | ✓ | ✓ | ✓ |
| Signing: digest / text / linked, certificate choice, onBehalfOf | ✓ | ✓ | ✓ |
| Session poll / wait | ✓ | ✓ | ✓ |
| Validator (chain, ACSP_V2, RAW_DIGEST) + OCSP checker | ✓ | ✓ | ✓ |
| PDF signature registration (`POST /pdf/signatures`) | ✓ | ✓ | ✓ |
| Organisation, person (PKI_READ) | ✓ | ✓ | ✓ |
| e-Seal: certificate, seal grants, seal a digest, seal a PDF | ✓ | ✓ | ✓ |
| USB token (certificate, authentication) | ✓ | ✓ | ✓ |
| Share | ✓ | ✓ | ✓ |
| «My QR» | ✓ | ✓ | ✓ |
| «Sign in with eID» backend | ✓ (+ ASP.NET Core) | ✓ (`net/http`) | ✓ (+ `<eid-login-button>`) |
| PAdES prepare / complete / suggestPlacement / registration body | ✓ | ✓ | ✓ |
| Full PDF validator (`ValidatePDF`) | — | ✓ | ✓ |
| Seal stamp with QR (APPEARANCE_SPEC §6.5–6.6, golden v13: validator and `Prepare` docId) | — (golden v12) | ✓ v0.31.0 | ✓ 0.49.0 |
| Seal registration (`POST /seal/{org}/registrations`) | — | — | — |
| `pdfDigest`, browser entry, `convert` | — | — | ✓ (TS only) |

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
- RP SDK: `testdata/conformance` = a byte-identical copy of the Go repo's `testdata/conformance` (rp-conformance/1)
  (`./build/sync-conformance.sh`; CI `conformance-sync`); tests `tests/GeregeSystems.EidMongolia.Tests` and
  `tests/GeregeSystems.EidMongolia.AspNetCore.Tests` (`net8.0` + `net10.0`); `build/compat` — binary compatibility with
  Pades 0.16.0 (CI `compat`); `build/check-packages.sh` — metadata and dependencies of the three packages (CI `pack`).

## Release

1. On a `release/<version>` branch: bump `<Version>` in the three csproj files to the same value (lockstep), merge
   `changelog.d/*` into a new section of `CHANGELOG.md` and delete the fragments → PR → merge.
2. On main: `git tag v<version> && git push origin v<version>`.
3. `.github/workflows/release.yml`: runs the full CI (Windows + Linux, compat, pack + `build/check-packages.sh`), checks that
   the tag = `<Version>`, then publishes the three `.nupkg` (+ `.snupkg`) as GitHub Release assets, and to GitHub Packages
   (NuGet) and nuget.org (Trusted Publishing) in dependency order (core → AspNetCore → Pades). nuget.org prerequisites for
   new package IDs: [docs/release-0.17.0.md](docs/release-0.17.0.md).

## License

MIT — [LICENSE](LICENSE). Third party: Noto Sans (OFL 1.1), digitorus/pdf (BSD-3), digitorus/pdfsign (BSD-2) — in the NuGet package's
`licenses/`.
