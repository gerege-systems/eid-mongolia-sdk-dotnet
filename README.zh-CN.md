[Монгол](README.md) · [English](README.en.md) · 中文

# eid-mongolia-sdk-dotnet

**eID Mongolia** 的 .NET (C#) SDK，面向依赖方（relying party，RP）后端：公民身份认证（push、QR、Web2App）、签名会话、
对响应进行密码学验证（证书链、ACSP_V2 / RAW_DIGEST、OCSP）、PDF 签名登记、机构 / 个人 / e-Seal / USB 令牌 / share 服务、
“我的 QR”、“使用 eID 登录”按钮后端（附 ASP.NET Core 适配器），以及客户端 PAdES——PDF 文档**绝不会发送到 eID 服务器**
（Smart-ID 模式）：文档在客户端准备（`Prepare`），只有 32 字节的哈希（DTBS）交由公民的手机或 USB 令牌签名，签名再由客户端
嵌入 PDF（`CompleteAsync`；PAdES-BASELINE-LT——RFC 3161 时间戳、OCSP/CRL、DSS）。

这是 Go 参考实现（[eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go)）和 TypeScript SDK 的
**原生 C# 移植**——没有原生代码、DLL 或 WASM。CI 在 Windows 和 Linux 上验证 PAdES 输出与 Go 的 golden vector（验证页、QR、
xref、CMS、TSA/OCSP/CRL 请求、DSS）**字节级完全一致**，并运行跨 SDK 一致性语料（`testdata/conformance`：validator、OCSP、
wire、登录后端）。

完整文档：<https://developer.eidmongolia.mn/#overview>。

| 包（NuGet） | 内容 | 依赖 |
|---|---|---|
| `GeregeSystems.EidMongolia` | RP SDK：`EidClient`（Auth、Sign、Session、Validator、PDF 登记、Organization、Person、Seal、Token、Share、“我的 QR”）、`OcspRevocationChecker`、`EidLoginHandler` | — |
| `GeregeSystems.EidMongolia.AspNetCore` | `services.AddEidMongolia(...)`、`app.MapEidLogin(...)` | core + ASP.NET Core 共享框架 |
| `GeregeSystems.EidMongolia.Pades` | 客户端 PAdES：`EidPades.Prepare` / `CompleteAsync` / `SealAsync` / `Registration`；PDF 验证 `ValidatePdfAsync` | core + `System.Security.Cryptography.Pkcs`（Microsoft） |

- 三个包版本一致（lockstep），`net8.0` 和 `net10.0`（多目标）。`net8.0` 运行时已于 2026-11-10 结束支持；为了让现有依赖方仍能
  restore，暂时保留，将在后续版本中移除。
- 线程安全，无全局状态：所有请求共用一个 `EidClient`（单例）。API secret 只保存在后端。
- 完整的 PDF 验证——`EidPades.ValidatePdfAsync`（与 Go `pades.ValidatePDF`、TS `validatePdf` 报告相同；见“验证 PDF”）。

## 安装

从 [nuget.org](https://www.nuget.org/profiles/geregecore)：

```bash
dotnet add package GeregeSystems.EidMongolia --version 0.17.0             # RP SDK
dotnet add package GeregeSystems.EidMongolia.AspNetCore --version 0.17.0  # 用于 ASP.NET Core（会带上 core）
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.17.0       # 客户端 PAdES（会带上 core）
```

每个版本的 `.nupkg`（+ `.snupkg` 符号包）也可在 [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases) 获取。

## RP SDK——`GeregeSystems.EidMongolia`

Go `eid` 与 TS `EidClient` 的移植，无包依赖。RP-API：`https://rp.eidmongolia.mn`（默认）。

### Client

```csharp
using GeregeSystems.EidMongolia;

// 只创建一次（单例），所有请求共用。
var client = new EidClient(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "我的银行", apiSecret),   // RP UUID、登记名称、API secret
    Trust = new TrustConfig
    {
        TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem },        // 生产环境必须设置（否则 validator 拒绝一切）
        Revocation = new OcspRevocationChecker().Checker,              // 吊销检查——见下文“吊销”
        RevocationMode = RevocationMode.HardFail,
    },
    Language = "en",                                                   // Accept-Language（mn | en）
});
```

- `BaseUrl`：必须为 https（http 仅限 localhost/loopback）；旧主机 `ca.eidmongolia.mn` 会得到明确的错误。默认超时 15 秒
  （PDF 登记 80 秒），JSON 响应 ≤ 4 MiB。
- mTLS：将带客户端证书的 `HttpClient` 作为第二个参数传入（`new EidClient(options, httpClient)`；SDK 不会释放它；SDK 每次调用
  自行设置超时，因此请把 `HttpClient.Timeout` 设为 `Timeout.InfiniteTimeSpan`）。
- 错误：`EidException`（`Code`、`Status`、`RetryAfter`、`Retryable`）→ `EidAuthenticationException`（401）、
  `EidForbiddenException`（403）、`EidApiException`（每个 CA 错误码一个子类）、`EidNetworkException`、
  `EidResponseTooLargeException`、`EidSessionFailedException`（endResult ≠ OK）、`EidValidationException`（`Reason`——稳定的键，
  `ValidationReasons`）、`EidDeviceLinkException`。请按 `Code` / `Reason` 分支处理。

### 认证——push（向公民手机推送通知）

```csharp
var login = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "登录我的银行" } };

NotificationSession s = await client.Auth.NotificationByEtsiAsync(etsi, login); // etsi = "PNOMN-…"；或 ByDocumentAsync
Show(s.Vc);                                                                       // 向用户显示的验证码
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId, new WaitOptions { ExpiresAt = s.ExpiresAt });
VerifiedIdentity id = client.Validator.ValidateAuth(r, s.Acsp!);                  // 证书链、ACSP_V2 签名、等级、用途
await client.Validator.CheckRevocationAsync(id.Certificate);                      // 使用 TrustConfig.Revocation（见下文）
// id.Subject.SerialNumber (PNOMN-…), id.Subject.GivenName / Surname, id.CertificateLevel, id.DocumentNumber
```

endResult ≠ OK 时 `ValidateAuth` 抛出 `EidSessionFailedException`（USER_REFUSED、TIMEOUT …），响应不可信时抛出
`EidValidationException`。`AuthOptions`：`CertificateLevel`、`CallbackUrl`、`OnBehalfOf`（代表机构）、`SignatureAlgorithm`、
`HashAlgorithm`。

### 认证——QR、Web2App、App2App（device link）

```csharp
DeviceLinkSession d = await client.Auth.DeviceLinkAnonymousAsync(login);             // 或 DeviceLinkByEtsiAsync(etsi, …)
// QR：链接每秒更新（authCode = HMAC-SHA256）。用于 SSE / WebSocket：
//   await foreach (var link in d.TickQrAsync("eng", TimeSpan.FromSeconds(1), ct)) Send(link);
// 用于 HTTP 轮询时，每次请求调用：d.BuildLink(DeviceLinkTypes.Qr, "eng")。
SessionResult r = await client.Session.WaitForResultAsync(d.SessionId);
VerifiedIdentity id = client.Validator.ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Qr });
```

Web2App：`DeviceLinkAnonymousAsync(login, new AuthOptions { CallbackUrl = "https://bank.example.mn/auth/eid/callback" })`
→ 将浏览器跳转到 `d.BuildLink(DeviceLinkTypes.Web2App, "eng")` → 回调中的 `sessionId` + `userChallengeVerifier` →
`ValidateAuth(r, d.Acsp!, new ValidateAuthOptions { ExpectedFlowType = FlowTypes.Web2App, UserChallengeVerifier = verifier })`。
`d.SessionId`、`SessionToken`、`SessionSecret` 和 `Acsp` 保存在服务器端（绝不发送给浏览器）。现成方案：下文的“使用 eID 登录”
按钮后端。

`client.Session.PollAsync(sessionId)`——一次长轮询；`WaitForResultAsync` 会重复轮询，直到 `MaxWait` → `ExpiresAt` →
discovery 的 `sessionTtl` → 600 秒（+15 秒）。`client.Auth.SessionTtlAsync()`——discovery 中的会话时长。

### 吊销——默认模式

| 位置 | 默认 | 说明 |
|---|---|---|
| `client.Validator.CheckRevocationAsync` | 未设置 `TrustConfig.Revocation` 时**不检查**（`RevocationStatus.Skipped`）；设置后为 **hard-fail** | 无 OCSP 应答 → `EidValidationException`（`ValidationReasons.RevocationUnknown`）；`RevocationMode.SoftFail` → `Unchecked` |
| “使用 eID 登录”后端（`EidLoginHandler`） | `OcspRevocationChecker`，**soft-fail** | 无 OCSP 应答时公民仍可登录（`Identity.Revocation == Unchecked`，记录 Warning）——避免 CA 应答器故障时锁住所有用户 |
| “我的 QR” | AIA 中的 OCSP，**hard-fail** | `QrTrust.RevocationSoftFail = true` 时接受 "unknown" |

**注意：登录后端的吊销检查默认为 soft-fail。** 高价值依赖方（银行、金融、政务服务、合同签署）应设置
`o.RevocationMode = RevocationMode.HardFail`——OCSP 无应答时登录将以 `FAILED`（`revocation_unavailable`）结束。OCSP 规则与
Go/TS 相同：`unknown` → 视为已吊销，thisUpdate ∈ [now − 48 小时, now + 5 分钟]，nextUpdate 未过期，委托应答器（OCSPSigning
EKU），单次请求 2 秒 / 总计 3 秒，“good” 缓存 ≤ 5 分钟；此外 .NET 在任何网络请求之前检查 issuer 确实签发了该证书，并核对
响应 CertID 中的 issuer 哈希。

证书链验证不使用 X509Chain（各平台一致）：basicConstraints/pathLen、keyCertSign、EKU、有效期、公民签发 CA 的 SKI 白名单
（默认 04）、RSA ≥ 2048（指数为奇数且 ≥ 3）；带 name constraints 的 CA、未知的关键扩展以及 SERIALNUMBER/CN 重复的 subject
一律拒绝（fail-closed）。

### 签名与 PAdES

```csharp
using GeregeSystems.EidMongolia.Pades;

// 1. 让公民选择 SIGN 证书。
var cc = await client.Sign.CertificateChoiceByEtsiAsync(etsi);
Signer signer = client.Validator.ValidateCertificateChoice(await client.Session.WaitForResultAsync(cc.SessionId));

// 2. 在客户端准备 PDF（无网络）。
var prepared = EidPades.Prepare(pdf, new PrepareOptions { SignerCert = signer.Certificate.RawData, FileName = "合同1号.pdf", VerifyPage = true });
var dtbs = Convert.ToBase64String(prepared.Dtbs);

// 3. 用所选证书在手机上签名（RAW_DIGEST_SIGNATURE）并验证。
var sign = new[] { new Interaction { Type = "displayTextAndPIN", DisplayText60 = "签署合同1号" } };
NotificationSession s = await client.Sign.DigestForSignerAsync(signer, dtbs, sign);
SessionResult r = await client.Session.WaitForResultAsync(s.SessionId);
VerifiedSignature v = client.Validator.ValidateSign(r, dtbs, HashAlgorithms.Sha256, new ValidateSignOptions { ExpectedCertificate = signer.Certificate });
await client.Validator.CheckRevocationAsync(v.Certificate);

// 4. 将签名嵌入 PDF（TSA、OCSP/CRL）——见下文“PAdES”。
Completed done = await EidPades.CompleteAsync(prepared.State, Convert.FromBase64String(v.SignatureValueB64), cancellationToken: ct);
```

其他：`Sign.DigestByEtsiAsync` / `DigestByDocumentAsync` / `TextByEtsiAsync`（哈希或文本）、`DeviceLinkByEtsiAsync` /
`DeviceLinkByDocumentAsync` / `DeviceLinkForSignerAsync`（通过 QR / Web2App 签名）、`CertificateChoiceDeviceLinkAsync`；
`SignOptions`：`CertificateLevel`、`CallbackUrl`、`HashAlgorithm`、`SignatureAlgorithm`、`OnBehalfOf`、`FileName`。

### PDF 签名登记（`POST /pdf/signatures`）

PAdES complete 之后必须登记（docId、`/verify` 页面）。`EidPades.Registration` 生成的请求体与 core 的
`PdfSignatureRegistration` 结构相同：

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
// ok.DocId；ok.Created == false——相同请求体被重复发送（幂等）。409 PRIOR_MISMATCH 由 SDK 自动重试。
```

错误码：`PdfErrorCodes`。

### 机构、个人、印章、令牌、share

- **机构**——`client.Organization.GetRepresentationsAsync(personEtsi)`（公民可代表哪些机构——用于 `OnBehalfOf` /
  `ClaimedRole`）、`SealGrantsAsync(personEtsi)`。
- **个人（需要 PKI_READ 权限）**——`client.Person.CertificatesAsync`、`DevicesAsync`、`ActivityAsync(etsi, ActivityQuery)`、
  `SummaryAsync`、`ChildrenAsync`。
- **机构印章（e-Seal）**——`client.Seal.CertificateAsync(orgEtsi)`、`RequestCertificateAsync` /
  `CertificateRequestAsync` / `WaitForCertificateAsync`、`SealAsync(orgEtsi, digest)`（核对返回的 ECDSA 签名和 e-Seal 证书
  配置）、印章授权 `RequestGrantAsync` / `GrantStatusAsync` / `WaitForGrantAsync`、`SealService.IsSealCertificate`。
  为 PDF 加盖印章：

  ```csharp
  var cert = await client.Seal.CertificateAsync(orgEtsi);
  Completed stamped = await EidPades.SealAsync(pdf, new SealOptions { SealCert = cert.Certificate, Reason = "机构印章" },
      async (dtbs, ct) => (await client.Seal.SealAsync(orgEtsi, dtbs, ct: ct)).Signature, cancellationToken: ct);
  ```

  **带 QR 的印章与 CA 登记**（CA V158，与 Go/TS 一致）：`SealOptions.Qr = true` 在印章外观中绘制
  `https://ca.eidmongolia.mn/verify/<docId>/<revIndex>` QR；必须使用预留式委托（`SealReservation`）——只有实际绘制了 QR 印章时
  才会传入预留，此时调用 `client.Seal.SealForDocumentAsync`。之后在 7 天内用 `client.Seal.RegisterSealedPdfAsync` 登记
  `done.SealRegistration`（`/verify/{docId}` 上的机构行；201 → `Created`，相同请求体重试为 200；409 `PRIOR_MISMATCH` 时 SDK
  自动尝试先前签名行的组合）。无 QR 的印章同样可以登记（只要 docId 已知，`done.SealRegistration` 就会被填充）。错误码：
  `SealRegisterErrorCodes.All`（CA 顺序；`EidSealNotFoundException`、`EidSealDocMismatchException`、`EidDocIdReservedException`）。

  ```csharp
  Completed done = await EidPades.SealAsync(pdf, new SealOptions
  {
      SealCert = cert.Certificate,
      Qr = true,                    // DocId = null：新文档随机生成；已签名文档取自验证页 / QR 印章
      FileName = "发票.pdf",        // 在 /verify 上显示的名称（不写入 PDF）
  }, async (dtbs, reservation, ct) => (reservation is null
      ? await client.Seal.SealAsync(orgEtsi, dtbs, ct: ct)
      : await client.Seal.SealForDocumentAsync(orgEtsi, dtbs, reservation.DocId, reservation.RevIndex, ct)).Signature,
      cancellationToken: ct);
  PdfSignatureRegistered reg = await client.Seal.RegisterSealedPdfAsync(orgEtsi, done.SealRegistration!, ct);
  ```
- **USB 令牌**——`client.Token.IssueCertificateAsync` / `PreviewCertificateAsync` / `CertificateResultAsync` /
  `CertificateInfoAsync`、`TokenService.VerifyTokenCertificates`，令牌认证 `AuthChallengeAsync` → 在令牌上签名 →
  `AuthVerifyAsync`（调用 CA 之前在本地核对摘要、签名和证书链）、`TokenService.TokenAuthDigest`。
- **Share**——`client.ShareAsync(new ShareRequest { File = signedPdf, Filename = "Contract.pdf", To = new[] { "user@example.mn" } })`
  （通过 eID 邮件将已签名 PDF 发送给 1–5 位收件人）、`ShareInfoAsync()`（限额）。

### “使用 eID 登录”按钮后端（`EidLoginHandler`，ASP.NET Core）

TS SDK `<eid-login-button>` 的后端：`POST {base}/start`（`{"mode":"qr"}` | `{"mode":"push","idCode":"УБ12345678"}`）、
`GET {base}/start?mode=web2app`、`GET {base}/status`、`GET {base}/callback`（Web2App）。与框架无关的核心——
`GeregeSystems.EidMongolia.Login.EidLoginHandler`（`HandleAsync(EidLoginRequest)` → `EidLoginResponse`）；ASP.NET Core 使用
`GeregeSystems.EidMongolia.AspNetCore`：

```csharp
using GeregeSystems.EidMongolia;
using GeregeSystems.EidMongolia.AspNetCore;
using GeregeSystems.EidMongolia.Login;
using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

builder.Services.AddEidMongolia(new EidClientOptions
{
    Credentials = new EidCredentials(rpUuid, "我的银行", apiSecret),
    Trust = new TrustConfig { TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem } },
});
// 位于反向代理（nginx 等）之后：只信任你自己的代理，由它修正 RemoteIpAddress。
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Add(IPAddress.Parse("192.0.2.10")); // 你的代理地址
});
var app = builder.Build();
app.UseForwardedHeaders();
app.MapEidLogin("/auth/eid", async (http, id) =>
{
    // 通过 id.Etsi（PNOMN-…）识别公民，并创建新的 session（防止 session fixation）。
    await SignInAsync(http, id.Etsi);
    return new EidLoginSuccess { Redirect = "/dashboard" };
}, o =>
{
    o.CallbackUrl = "https://bank.example.mn/auth/eid/callback"; // Web2App（路径必须为 /auth/eid/callback）
    o.FailureRedirect = "/login";
    o.RevocationMode = RevocationMode.HardFail;                   // 高价值依赖方（默认 soft-fail）
});
```

**客户端 IP 与代理。** `start` 限流（每个 IP 每 60 秒 20 次）按客户端 IP 计算。`MapEidLogin` 默认
`o.ClientIp = EidLoginClientIp.RemoteAddress`（`HttpContext.Connection.RemoteIpAddress`）。位于反向代理之后时：(a) 如上所示，
在 `MapEidLogin` 之前配置带 `KnownProxies` / `KnownNetworks` 的 `UseForwardedHeaders`，或 (b) 设置
`o.ClientIp = EidLoginClientIp.Forwarded(n)`（n = 受信任代理的数量；取 `X-Forwarded-For` 从右数第 n 个值）。两者都不做时，
所有用户共享代理那一个 IP 的限额；没有代理时切勿使用 `Forwarded(n)`（该请求头可被伪造）。IPv6 客户端按 /64 前缀计
（`start:2001:db8:1:2::/64`）；已配置 `ClientIp` 但 IP 未知时并非不限流，而是共享的 `start:unknown` 桶。push 的键为
`push:<pushKey>`（`AuditKey` 的 HMAC，与 `OnEvent` 的 `meta.pushKey` 相同）——身份证号不会进入限流器或 `RateLimit` 钩子。内存限流器
每类最多保存 `EidLoginRateRule.MaxKeys` 个键（默认 10 000）；表满时新键计入同一个共享的溢出桶（不会直接拒绝，也不会驱逐已有计数）。

**Cookie。** 默认名称为 `__Host-eid_login`（Secure、无 `CookieDomain`、`CookiePath` = `/`——浏览器不会接受从兄弟主机植入的同名
cookie）；设置了 `InsecureCookie`、`CookieDomain` 或其他 `CookiePath` 时为 `eid_login`；显式设置的 `CookieName` 原样使用。请求中
该名称的 cookie 多于一个时视为没有登录 cookie（status → `EXPIRED`，callback → `eid_error=expired`）。

安全性与 Go `eidlogin` / TS `createEidLogin` 一致：状态保存在服务器（`IEidLoginStore`；默认 `MemoryEidLoginStore`——单进程，
最多 10 000 条；多实例部署时请在 `AddEidMongolia` 之前注册自己的 store，如 Redis），浏览器只拿到 HttpOnly + Secure +
SameSite=Lax cookie（`<sessionId>.<binding>`，binding 的 SHA-256 以恒定时间比较），`Sec-Fetch-Site` 为 cross-site → 403，
限流（start：每个 IP 每 60 秒 20 次；push：每个号码每 60 秒 3 次），对未登记号码使用诱饵（decoy）会话 + push 1 秒下限，
只有在 ValidateAuth + OCSP（**默认 soft-fail**，见上文“吊销”）之后才调用 `OnSuccess`（且只调用一次），审计用 `OnEvent`
（以 HMAC pushKey 代替身份证号）。响应结构和 12 个错误码通过跨 SDK 语料 `testdata/conformance/eidlogin/scenarios.json`
（34 个场景，eidlogin/2）校验。其他框架可直接调用 `EidLoginHandler`（`EidLoginRequest`——方法、URL、请求头、请求体、`RemoteIp`）。

## “我的 QR”——公民的“我的信息”（`GeregeSystems.EidMongolia.Qr`）

自 0.17.0 起位于 core 包（`client.Qr` 或 `new EidQrClient(...)`）；命名空间和 API 与 Pades 0.13.0–0.16.0 相同（Pades 通过类型
转发提供）。公民在其 eID App 中出示“我的 QR”（`EIDMN-QR1:<token>`，120 秒，一次
性）→ RP 扫描后调用 `POST /authentication/qr` → 公民在手机上看到一句话，并用 **PIN2** 同意 →
RP 取得公民的“我的信息”（App 中保存的 dict 原样不变 + 人脸 JPEG），形式为用公民自己的 QUALIFIED SIGN
密钥签名的 **PS256 JWS**（`typ` = `eidmn-myqr+jwt`，`x5c` = [公民证书, 颁发 CA]）。CA 不
保存该值；presentation 只能被读取一次（再次读取会返回 410 `QR_PRESENTATION_GONE`）。RP 只需
`QR_PRESENT` 权限。

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "收银台 3", ApiSecret = secret }); // 或 client.Qr
try
{
    QrSession s = await qr.StartAsync(new QrStartRequest(scanned)); // 若未提供 nonce，SDK 会生成 22 个字符
    QrResult r = await qr.ResultAsync(s);                            // 或用于轮询 UI：CheckAsync(s) → QrCheck
    foreach (var (key, value) in r.Data) Show(key, value);          // 按 payload 的顺序，键保持原样
    // r.Source (dan, passport, citizenid …), r.Photo (JPEG | null), r.Signer.Etsi / GivenName / Surname,
    // r.SignedAt, r.Sha256 (= CA 审计中的 qrsha), r.Jws (可保留用于争议)
}
catch (EidQrException e) when (e.Code == EidQrErrorCodes.TokenInvalid) { /* 404——请重新生成 QR */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.SessionFailed) { /* e.EndResult: USER_REFUSED, TIMEOUT */ }
catch (EidQrException e) when (e.Code == EidQrErrorCodes.PresentationGone) { /* 410——请重新扫描 QR */ }
catch (EidQrException e) when (e.Code.StartsWith("QR_", StringComparison.Ordinal)) { /* 检查失败——不要信任 */ }
```

`EidQr.VerifyAsync(jws, new QrExpect(rpUuid, sessionId, nonce), trust?)`——重新验证已保存的 JWS（网络仅用于 OCSP）。
验证（与 Go / TS SDK 一致，CA 的 `testdata/myqr_vectors.json`）：JWS ≤ 512 KiB，3 段 → header 必须恰好为
`alg` PS256 / `typ` / 含 2 张证书的 `x5c`（无重复键）→ 证书链（core 的路径构建——见上文“吊销”；x5c[1] 仅作为中间证书候选，
±60 秒）+ 叶子证书：非 CA，KeyUsage 为 contentCommitment，QcCompliance（QUALIFIED），颁发者 SKI ∈ `AllowedIssuerSkis`
（默认为 04 `EidQr.CitizenIssuingCaSki`），RSA ≥ 2048，SERIALNUMBER/CN 不重复 → 吊销检查（默认使用 AIA 的 OCSP，hard-fail；
OCSP `unknown` → 视为已吊销）→ RSASSA-PSS SHA-256（salt 32）→ payload（无重复键）`iss`，`sub` = 证书的 serialNumber，
`statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг
хуваалцах гэж байна»（“您即将向 {rp_name} 分享‘我的信息’部分的全部信息”），`aud` = RP UUID（不区分大小写），`sid`，`nonce`（完全一致），0 < exp − iat ≤ 300，iat ≤ 当前 + 60，
当前 < exp + 60 → `data`（`source` 须匹配 `^[a-z0-9_-]{1,32}$`；`fields` ≤ 128 项，键为 1–64 个 code point 且不含控制字符，
值只能是 ≤ 2048 字节的字符串；`photo` 为严格 base64 的 JPEG ≤ 150 KiB；`fields` 为空时 `photo` 必须存在；不得有多余
成员）。

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)`——为 null 时使用内置的国家根证书
+ 02–04 中间证书、颁发者 04、OCSP。`Revocation` = `(叶子, 颁发者) → "good" | "revoked" | "unknown"`（你自己的缓存/CRL 或
测试 stub；`VerifyAsync` 返回时会释放颁发者证书）；抛出异常 = "unknown"。`RevocationSoftFail = true` 时接受 "unknown"。
`EidClientOptions.QrTrust`——`client.Qr` 的信任配置。

错误码（`EidQrException.Code`）：`QR_FORMAT_INVALID`（不会发往 CA）、`QR_JWS_MALFORMED`、`QR_HEADER_INVALID`、
`QR_CHAIN_INVALID`、`QR_CERT_REVOKED`、`QR_REVOCATION_UNKNOWN`、`QR_SIGNATURE_INVALID`、`QR_CLAIMS_INVALID`、
`QR_AUDIENCE_MISMATCH`、`QR_SESSION_MISMATCH`、`QR_NONCE_MISMATCH`、`QR_NOT_YET_VALID`、`QR_EXPIRED`、`QR_DATA_INVALID`、
`QR_PRESENTATION_GONE`（410）、`QR_PENDING`（`ResultAsync` 的 `maxWait` 已到——可再次调用）、`SESSION_FAILED`
（`EndResult`）、带 `HttpStatus` 的服务器 `code`（400 `REQUEST_INVALID`，403 `PERMISSION_DENIED` / `RP_REQUIRED`，404
`QR_TOKEN_INVALID`，409 `NO_SIGNING_CERTIFICATE`，429 `RATE_LIMITED`）、`HTTP_ERROR`、`NETWORK_ERROR`。

## PAdES（`GeregeSystems.EidMongolia.Pades`）——流程

```csharp
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// 1. 准备——无需网络。SignerCert = 公民的 SIGN 证书（来自 CA 的 session 响应，DER 格式）。
var prepared = EidPades.Prepare(pdfBytes, new PrepareOptions
{
    SignerCert = signCertDer,
    Reason = "合同已确认",
    ClaimedRole = representation.ClaimedRole, // 以组织名义签名时使用（来自 CA 的 representation 响应）
    VerifyPage = true,                         // 验证（QR）页——仅用于第一个 eID 签名
    // VerifyPagePosition = "first",           // 0.8.0+：QR 页成为第 1 页（默认 "last"）；Appearance.Page、
                                               // SuggestPlacement、Placement.Page 按输入 PDF 的页码计算（PAGE_SPEC §8a）
    FileName = "合同第1号.pdf",
    Lang = "mn",                               // mn（默认）| en
    // 可选的可见签名（APPEARANCE_SPEC.md）：单位 pt，自页面可见的左下角起算；Page 0 = 最后一页，
    // 而不是 eID verify 页（PLACEMENT_SPEC §1a）。高度 ≥ 45 pt；放不下则为 REQUEST_INVALID。null = 不可见。
    Appearance = new Appearance { X = 36, Y = 36, Width = 220, Height = 64 },
});
// prepared.Placement——可见签名的最终位置（见下文“位置”）。

// 2. 通过 RP 后端将 prepared.Dtbs（32 字节）交给 CA 的 signature session，由手机签名
//    （RAW_DIGEST_SIGNATURE），或在本地使用 USB 令牌（PKCS#11）签名。等待期间可以保存 prepared.State
//    （格式与 Go reference 相同）。

// 3. 嵌入——使用 TSA、OCSP/CRL 网络。签名：RSA PKCS#1 v1.5、ECDSA r‖s 或 DER——根据证书自动识别。
Completed done = await EidPades.CompleteAsync(prepared.State, signature, cancellationToken: ct);
File.WriteAllBytes("signed.pdf", done.Pdf);

// 4. 登记——CA 的 POST /pdf/signatures 请求体（不是 PDF，仅为元数据）。可直接以 JSON 发送：
SignatureRegistration reg = EidPades.Registration(done, new RegistrationOptions
{
    SessionId = sessionId,                     // 手机必须提供；令牌则不提供（Medium = token）
    OnBehalfOf = orgRegNo,                     // NTRMN-…——提供 ClaimedRole 时必须填写
});
string body = JsonSerializer.Serialize(reg);
```

若 `Medium` 为空，则由 `SessionId` 推断（有则为 `phone`，否则为 `token`——CA 的规则是 phone ⇔ sessionID）。
`Registration` 会在 CA 之前直接抛出 `REQUEST_INVALID`：`phone` 但没有 `SessionId`、`token` 但带有 `SessionId`、其他
`Medium` 取值，或者存在 `done.ClaimedRole`（Prepare 的 `ClaimedRole`）而 `OnBehalfOf` 为空。

`Registration` 仅通过 `priorCmsSha256` 发送先前的签名——若**同时**完整发送 `done.PriorCmsSha256` 和
`done.PriorRevisionSha256`，CA 会返回 400。若先前的签名是在 CA 端组装的（模式 A），CA 会返回
409 `PRIOR_MISMATCH`：把 `reg.PriorSignatures` 前 k 项的 `RevisionSha256` 放入 `PriorRevisionSha256`，其余项的
`CmsSha256` 放入 `PriorCmsSha256`，然后重新发送（Go/TS SDK 的 `RegisterSignature` 会自动完成这一步）。

`CompleteOptions`：`TsaUrl`（默认 `https://tsa.timeserver.mn/`）、`Roots`（测试 PKI）、`HttpClient`（代理/沙箱；
默认超时 10 秒，且不跟随重定向）、`TimeProvider`。国家 CRL（`esign.gov.mn`）从 eID 的 https 镜像下载
（WIRE.md §3）。

## 错误

所有错误均为 `EidPadesException`；分支处理时请使用（稳定的）`Code`，`Message` 仅供日志/人阅读。

| `Code` | 代码 | 含义 |
|---|---|---|
| `PdfInvalid` | `PDF_INVALID` | PDF 无法解析；结构过深（嵌套 > 256）或存在 ObjStm 循环、`/Extends` > 64、`/Size` > 2^21、xref 段 > 128、xref 流 `/W` `/Index` 限制、ObjStm 工作量 > 1 GiB（PRECHECKS #2a/#2b） |
| `PdfEncrypted` | `PDF_ENCRYPTED` | PDF 已加密 |
| `PdfLocked` | `PDF_LOCKED` | DocMDP P=1——禁止修改 |
| `PdfTooLarge` | `PDF_TOO_LARGE` | 超过 9.75 MiB（输入）/ 10 MiB（输出） |
| `PdfTooManySignatures` | `PDF_TOO_MANY_SIGNATURES` | 签名超过 16 个 |
| `PdfPriorSignatureInvalid` | `PDF_PRIOR_SIGNATURE_INVALID` | 先前的签名已损坏 |
| `PdfForeignSignature` | `PDF_FOREIGN_SIGNATURE` | 先前的签名不是 eID 的 B-LT |
| `SignerInvalid` | `SIGNER_INVALID` | signerCert / 证书链错误 |
| `RequestInvalid` | `REQUEST_INVALID` | 选项错误（docId、lang、fileName、claimedRole…） |
| `SignatureInvalid` | `SIGNATURE_INVALID` | 签名与 DTBS / SignerCert 不匹配 |
| `TsaUnavailable` | `TSA_UNAVAILABLE` | TSA 无响应 / token 无效 |
| `LtvUnavailable` | `LTV_UNAVAILABLE` | 未能完整获取 OCSP/CRL；若 `InnerException is CertificateRevokedException`，则证书链中的证书已被吊销——不要重试 |
| `SelfValidationFailed` | `SELF_VALIDATION_FAILED` | 输出未通过自身校验 |
| `PlaceholderOverflow` | `PLACEHOLDER_OVERFLOW` | 超出 CMS 占位符容量 |
| `StateInvalid` | `STATE_INVALID` | `State` 已损坏（或其 PDF 结构过深/过于复杂） |
| `Internal` | `INTERNAL` | SDK 内部错误 |
| `Unknown` | 其他 | 新的错误码——请查看 `RawCode` |

### 可见签名的位置

`Appearance.X/Y` 是**请求的**位置。Prepare 不做渲染，直接读取目标页面（文本、表格线、图片、form XObject，
以及先前签名等注释的 `/Rect`），若请求的矩形（+4 pt）与内容重叠，
就把签章移到第一个空闲位置：先是同一高度的镜像列（右下 → 左下），然后在请求的列中上移 12 pt，
再在镜像列中上移。结果为 `prepared.Placement`（`Page`、`X`、`Y`、`Width`、`Height`——
单位 pt；`Status`）：

| `PlacementStatus` | JSON | 含义 |
|---|---|---|
| `Requested` | `requested` | 请求的位置空闲 |
| `Moved` | `moved` | 已移到空闲位置（`X`、`Y` 为新位置） |
| `Overlap` | `overlap` | 没有空闲位置——在请求的位置覆盖在内容之上绘制 |
| `Unscanned` | `unscanned` | 页面无法在限制范围内读完（4 MiB、100 000 个操作符、不支持的过滤器…）——放在请求的位置 |

建议将 `Overlap` / `Unscanned` 告知用户；无论哪种情况，签名都有效。规则：Go 仓库的
`pades/PLACEMENT_SPEC.md`（与 Go 字节级一致；每个 box 都与 `testdata/golden/placement/vectors.json` 比对）。

**公民自行摆放**（PLACEMENT_SPEC §6a/§6b）。`EidPades.SuggestPlacement(pdf, appearance)` 在没有签名、证书和网络的情况下运行 Prepare 的
定位逻辑，返回默认位置和页面尺寸；公民在预览上拖动摆放后，
以 `Appearance.Exact = true` 调用 Prepare，签章就会精确绘制在该矩形内
（绝不会移动；若其下有内容则 `Status = Overlap`，若超出页面则 `REQUEST_INVALID`）：

```csharp
var s = EidPades.SuggestPlacement(pdf, new Appearance { X = 340, Y = 36, Width = 220, Height = 64 });
// s.Page, s.X, s.Y, s.Width, s.Height, s.Status — 与 Prepare 的 Placement 相同; s.PageWidth/PageHeight,
// s.PageCount, s.Pages[i].Width/Height (pt). UI（原点在左上角，s px/pt）: left = X·s, top = (PageHeight − Y − Height)·s.
var prepared = EidPades.Prepare(pdf, opts with
{
    Appearance = new Appearance { Page = s.Page, X = x, Y = y, Width = s.Width, Height = s.Height, Exact = true },
});
```

`SuggestPlacement` 的错误：`PDF_TOO_LARGE`、`PDF_INVALID`、`REQUEST_INVALID`、`PDF_ENCRYPTED`。先前的签名
（`PDF_FOREIGN_SIGNATURE`…）以及姓名能否放进签章，只有 Prepare 才会检查。Page 0：对已有签名的文档，
按验证页链接中的 docId 跳过验证页；对没有签名的文档则什么都不跳过（即最后一页）。

Prepare 的检查顺序与 Go 参考实现的 `pades/PRECHECKS.md` 一致（#2a/#2b 结构，#4 `/Encrypt` 引用
或直接字典）。`CompleteAsync` 中的 OCSP 必须带有证书的 CertID（颁发者名称/密钥哈希 + 序列号），CRL 必须是
颁发者的（名称、AKI = SKI、签名），且两者都必须是新鲜的（thisUpdate ≤ 当前 + 5 分钟；若没有 nextUpdate，则
thisUpdate ≥ 当前 − 24 小时）。

**吊销信息来源的顺序（按证书角色，而非按主机名）：**

- **叶子证书**——每条证书链的第一张证书（公民、TSA）：**先 OCSP**，使用普通的 10 秒超时，要求完整（thisUpdate 不得
  晚于时间戳，并带重试）。同时也会下载 CRL：两者都有效则都嵌入 DSS；
  若未能取得有效的 OCSP，则以 CRL 为准。
- **CA**——证书链中第一张之后的每张证书：**先 CRL**。若取得颁发者的有效 CRL（签名、有效期、`esign.gov.mn`
  → eID 镜像），则对该证书**完全不发送 OCSP 请求**（例如不会去访问不响应的 `ocsp.esign.gov.mn`）。
  只有在没有 CRL / 下载失败 / 无效 / 已过期时才使用 OCSP（普通 10 秒超时）。
- 叶子证书的 OCSP 一开始就并行发起，CRL 按证书链顺序下载（同一次收集中不重复下载 CRL，
  响应上限 4 MiB）；结果按证书链顺序加入 DSS。任一来源的“已吊销”都是硬错误；
  若某证书既没有有效的 CRL 也没有有效的 OCSP，则返回 `LTV_UNAVAILABLE`（fail-closed）。

## 机构印章（e-Seal）

`EidPades.SealAsync`——使用机构印章证书向 PDF 嵌入 PAdES-BASELINE-LT 签名。不涉及公民、PIN 和 App：
SDK 准备好 DTBS（不含验证页——印章不会登记到 CA 的 `/verify/{docId}`）后调用你的 delegate；
delegate 使用 RP 后端自己的 `HttpClient` 向 CA 发起 `POST /seal/{orgEtsi}`，并返回 `signature.value`。
Pades 包本身不包含 HTTP client——委托中可直接调用 core 的 `client.Seal.SealAsync`（见上文“机构、个人、印章、令牌、share”）；下面的示例使用手写 HTTP。

**印章默认可见**（与 Go 的 `SealPDF`、TS 的 `sealPdf` 一致；Go 仓库的 `pades/APPEARANCE_SPEC.md` §6）：
在文档最后一页（非 eID 验证页）显示机构印章——名称、“eID Mongolia-аар тамгалсан” / "Sealed with
eID Mongolia"、日期；没有 QR、链接和角色行。位置：220 × 64 pt，`x = 页面宽度 − 256`，`y = 36`（小
页面会自动缩小，例如 164 pt 的文档 → 156 × 64，x = 4），若与内容重叠则移到空闲位置（见上文“可见签名
的位置”）。结果为 `done.Placement`。若自动生成的印章放不进页面，或会使输出超过 10 MiB，
则无错误地生成不可见印章（`Placement = null`）。可通过 `SealOptions.Appearance` 自行指定位置（与公民的
`Appearance` 字段相同；放不下则 `REQUEST_INVALID` / `PDF_TOO_LARGE`）。`SealOptions.Invisible = true`——与之前版本
字节级一致的不可见印章。早于 Go SDK v0.30.0 / TS SDK 0.48.0 的验证器会把带有可见印章的
PDF 的先前签名报告为已被修改（modified）——在它们升级之前请使用 `Invisible = true`。
印章样式仅由签名者的证书决定：用 e-Seal 证书调用 `Prepare` + `Appearance`
同样会绘制印章。

```csharp
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades;

// SealCert: CA GET /seal/certificate/{orgEtsi} → "certificate" (base64 DER).
Completed done = await EidPades.SealAsync(pdfBytes, new SealOptions
{
    SealCert = Convert.FromBase64String(sealCertB64),
    Reason = "组织印章",            // SignerName = 证书的 CN（组织名称），Chain = 内置的 eID 证书链
}, async (dtbs, ct) =>
{
    using var req = new HttpRequestMessage(HttpMethod.Post, $"https://rp.eidmongolia.mn/seal/{orgEtsi}")
    {
        Content = JsonContent.Create(new { digest = Convert.ToBase64String(dtbs), hashType = "SHA256" }),
    };
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rpSecret);
    using var resp = await http.SendAsync(req, ct);
    resp.EnsureSuccessStatusCode();                    // 403 = 没有 SEAL:<orgEtsi> 权限；429 = 暂时被限流
    using var body = JsonDocument.Parse(await resp.Content.ReadAsStreamAsync(ct));
    return Convert.FromBase64String(body.RootElement.GetProperty("signature").GetProperty("value").GetString()!);
}, cancellationToken: ct);
File.WriteAllBytes("sealed.pdf", done.Pdf);
```

- RP 需要 `SEAL:<orgEtsi>` 权限（否则 403）。429 为限流：稍等后重试（delegate 抛出的
  异常会被 SDK 原样透传）。
- 必须有 RFC 3161 时间戳——若 TSA 不可达，返回 `TSA_UNAVAILABLE`（不会签发没有时间戳的印章）。
- `SealCert` 必须符合印章配置文件（不是 CA，KeyUsage 含 nonRepudiation 且不含 digitalSignature，没有 EKU
  用途——extendedKeyUsage 缺失或为空）——否则 `SIGNER_INVALID`。若签名与 DTBS / `SealCert` 不匹配，则 `SIGNATURE_INVALID`。
- 印章证书可通过 core 的 `client.Seal.RequestCertificateAsync` / `WaitForCertificateAsync` 申请，或由 CA / 管理控制台签发。

## 致 Pades 用户——0.16.0 → 0.17.0

- `GeregeSystems.EidMongolia.Pades` 0.17.0 会自动引入 `GeregeSystems.EidMongolia` 0.17.0。PAdES 的 API 和输出不变
  （golden 字节一致）。
- “我的 QR”（`GeregeSystems.EidMongolia.Qr`：`EidQr`、`EidQrClient`、`EidQrOptions`、`EidQrException`、`EidQrErrorCodes`、
  `QrStartRequest`、`QrSession`、`QrSigner`、`QrResult`、`QrExpect`、`QrTrust`、`QrCheck`）已移至 core；Pades 通过
  `[TypeForwardedTo]` 转发——`using` 和代码保持不变，针对 0.16.0 编译的程序集**无需重新编译**即可运行（CI `compat` 作业会在
  0.17.0 的程序集上运行一个针对 nuget.org 上 0.16.0 编译的使用方程序）。
- 行为差异（非 API）：“我的 QR”的证书链改由 core 的路径构建（而非 X509Chain）——name constraints、未知关键扩展、
  SERIALNUMBER/CN 重复以及 RSA < 2048 返回 `QR_CHAIN_INVALID`；`QrTrust.Intermediates` 为 null 时为 02–04（之前为 02–05）；
  payload 重复键 → `QR_JWS_MALFORMED`；`QrSession.SessionId` 为空 / `.` / `..` → `ArgumentException`。真实 eID 证书链不受影响。
- 新的 RP 工作（认证、签名会话、登记）请使用 core 的 `EidClient`——用 `client.Sign` / `client.Seal` / `client.Pdf` 代替
  “PAdES”一节中手写 `HttpClient` 的示例。

## 验证 PDF（`EidPades.ValidatePdfAsync`）

完整验证已签名或已盖章的 PDF——与 Go `pades.ValidatePDF`、TS `validatePdf` 及 CA 的 `POST /v3/validate/pdf` **规则相同、JSON
报告相同**（`PdfReport.ToJson()`；不含 CA 登记字段 `session_id` / `doc_id` / `on_behalf_of_*` / `stamp_lookup`）。文档不会被发送到任何
地方——在线吊销检查只发送证书序列号（OCSP 请求）。

```csharp
using GeregeSystems.EidMongolia.Pades;

PdfReport rep = await EidPades.ValidatePdfAsync(pdfBytes, new ValidatePdfOptions
{
    // Roots / Intermediates / Issuers —— 默认：内置的国家根 CA（01）、02–05、eID 签发者 04/05。
    // Time —— 验证时间（默认当前）；Offline = true —— 仅使用文档的 DSS；HttpClient —— OCSP/CRL（测试/代理）。
}, ct);
if (rep.Indication != "valid") { /* rep.Signatures[i].Problems */ }
string json = rep.ToJson();
```

- 检查项：ByteRange（间隙恰好是该 /Contents）与 messageDigest、CMS/CAdES 签名（RSA PKCS#1、RSA-PSS、ECDSA；拒绝小于 2048
  位的 RSA 密钥）、signing-certificate-v2、证书链（自建路径构建——不使用 X509Chain，Windows 与 Linux 结果一致；拒绝未知的关键
  扩展及带名称约束的 CA）、KU/EKU（`usage`）、有效期、RFC 3161 时间戳（TSA 链、timeStamping EKU）、吊销、LTV 覆盖、
  `signature_level`（B/T/LT）、`certificate_level`、`key_medium`。
- 签名后的修改：每个后续修订都按解析后的对象图比较（CA 公共验证器的规则）——仅新增签名/DSS 时为 `extended_by_signatures_only`；
  可见签名与机构印章外观（带/不带 QR，APPEARANCE_SPEC §5/§6）用写入器代码重新生成后比对；其他一律为 `modified_after_signing`。
  只有通过完整性校验的后续签名才算作“仅由签名扩展”（外观的 `/Name` 不与证书名称比较——eID 桌面客户端在此写入门户的西里尔文
  姓名，`PrepareOptions.SignerName` 也可设置任意名称；`signer_name` 始终取自证书，语料 v15）。自签名修订以来 xref 条目未变的每个对象（及其对象流）
  必须能在该修订内完整解析（shadow attack——否则为 `modified_after_signing`）。`platform_attested` 姓名只在文档未被修改（或仅由
  签名扩展）时显示。
- 吊销（eID 04/05 签发的证书）：在线——AIA OCSP，否则 CDP CRL（签发者签名、CertID）；无响应或 `Offline` 时使用文档 DSS 中的
  OCSP/CRL；证据须在验证时间是新鲜的（PAdES LTV 的 24 小时规则，与 RP OCSP 检查器的 48 小时规则分开）。都没有时为
  `revocation_unavailable`（indeterminate）。
- 错误（`EidPadesException.RawCode`）：`PDF_TOO_LARGE`（> 10 MiB）、`PDF_INVALID`、`PDF_ENCRYPTED`（/Encrypt——即使密码为空）、
  `PDF_NO_SIGNATURE`、`PDF_TOO_MANY_SIGNATURES`（> 16）、`REQUEST_INVALID`（Roots/Intermediates/Issuers 无法解析）。
- 针对攻击者可控 PDF 的限制（与 Go/TS 相同——超出时为 `PDF_INVALID`）：解析前的结构检查——嵌套 ≤ 256；xref 段 ≤ 128
  （超过 128 次增量更新的文档为 `PDF_INVALID`）；xref 流的每个 `/W` 项为 0…8 且行宽 > 0，`/Index` 的 start + count ≤ 2^21，
  所有 xref 流的行数合计 ≤ 2^21；xref 流与对象流只允许单个过滤器；解压后的 xref 流 + 对象流合计 ≤ 32 MiB；对象流成员查找工作量
  （头部条目数 × 解压长度之和）≤ 1 GiB（成员极多的对象流为 `PDF_INVALID`）。签名：每个 CMS 或时间戳令牌 ≤ 32 个证书，
  RSA ≤ 8192 位，e ≤ 2^32−1，证书/TSTInfo 序列号 ≤ 160 位（数值）——否则该签名为 `malformed_signature`；SignerInfo 签名算法为
  SHA-1/MD5/MD2 时为 `weak_algorithm`。DSS：流 ≤ 1 MiB（每类 ≤ 64 个），解码合计 ≤ 8 MiB，被重复引用的流只读取一次。.NET 额外
  防护（不影响报告）：修订解析器递归 ≤ 64、节点 ≤ 1,000,000、解压 ≤ 64 MiB、对象号 < 2^23；读取器每个 FlateDecode 流 ≤ 64 MiB、
  每次打开合计 ≤ 256 MiB、递归 ≤ 512，对象流头部只建立一次索引；证书链构建 ≤ 100 次尝试；OCSP 响应 ≤ 16 KiB，HTTP ≤ 4 MiB、10 秒。
- 一致性：`testdata/pades-validate` = Go `9f68390` 的 `pades/testdata/validate`（语料 v15，80 个用例；及其引用的 golden 文件）
  （`./build/sync-validate.sh`，CI `validate-sync`）；每个用例的报告与 Go 的报告深度相等（`ValidatePdfCorpusTests`）。

## 与 Go / TS 的功能对比

| 功能 | .NET 0.17.0 | Go | TS |
|---|---|---|---|
| Client、错误、路由表、discovery | ✓ | ✓ | ✓ |
| 认证：push、device link（QR / Web2App / App2App）、QR ticker | ✓ | ✓ | ✓ |
| 签名：digest / text / linked、证书选择、onBehalfOf | ✓ | ✓ | ✓ |
| 会话 poll / wait | ✓ | ✓ | ✓ |
| Validator（证书链、ACSP_V2、RAW_DIGEST）+ OCSP 检查器 | ✓ | ✓ | ✓ |
| PDF 签名登记（`POST /pdf/signatures`） | ✓ | ✓ | ✓ |
| 机构、个人（PKI_READ） | ✓ | ✓ | ✓ |
| e-Seal：证书、印章授权、对摘要盖章、对 PDF 盖章 | ✓ | ✓ | ✓ |
| USB 令牌（证书、认证） | ✓ | ✓ | ✓ |
| Share | ✓ | ✓ | ✓ |
| “我的 QR” | ✓ | ✓ | ✓ |
| “使用 eID 登录”后端 | ✓（+ ASP.NET Core） | ✓（`net/http`） | ✓（+ `<eid-login-button>`） |
| PAdES prepare / complete / suggestPlacement / 登记请求体 | ✓ | ✓ | ✓ |
| 完整 PDF 验证器（`ValidatePDF`） | ✓ `ValidatePdfAsync`（pades-validate/1） | ✓ | ✓ |
| 带 QR 的印章外观（APPEARANCE_SPEC §6.5–6.6，golden v13：验证器、`SealAsync` 与 `Prepare` 的 docId） | ✓ main | ✓ v0.31.0 | ✓ 0.49.0 |
| 印章登记（`POST /seal/{org}/registrations`）、`SealForDocument` | ✓ main | ✓ main | ✓ main |
| 跨 SDK 语料 rp-conformance/2（验证器、OCSP、登录后端） | ✓ main | ✓ main | ✓ main |
| `pdfDigest`、浏览器入口、`convert` | — | — | ✓（仅 TS） |

## 开发

- 配置文件规则：Go 仓库的 `pades/PROFILE.md`、`PAGE_SPEC.md`、`PRECHECKS.md`、`WIRE.md`、`APPEARANCE_SPEC.md`、
  `PLACEMENT_SPEC.md`。
- Golden：`testdata/golden` = Go 仓库 `pades/testdata/golden` 的副本，来自 `build/go-sdk.ref` 提交
  （`./build/sync-golden.sh`；CI 的 `golden-sync` job 用 `--check` 比对）。**测试 PKI 的私钥**
  仅用于测试——在任何真实证书链中都不被信任。
- 测试（`dotnet test`）：每个 golden 用例依次执行 Prepare → manifest 中的签名 → CompleteAsync（HTTP fixture 回放，
  固定 nonce/时间）→ 将输出 PDF 与 Go 的输出在字节级**整体**比对；eid-desktop（Swift）的 golden；
  错误路径；ECDSA（r‖s、DER）；吊销规则（`RevocationTests`——用 04 的密钥签名的 OCSP/CRL）；结构
  检查（`StructureTests`，`testdata/structure`——来自 Go/TS 的输入）；签章位置（`PlacementTests`——Go 的
  `placement/vectors.json` 中的每个 box、候选顺序、遇到损坏的 content/Flate 流不抛异常）；
  对每个可见的 golden 用例运行 `SuggestPlacement`（逐个 `expect.suggestion` 字段，`suggestionError`）。
- 字体（`Assets/`）：Noto Sans 子集，SIL OFL 1.1——与 Go 参考实现的 `pades/assets/fonts` 字节相同。
- PDF 读写器沿用 digitorus/pdf（BSD-3）和 digitorus/pdfsign（BSD-2）的语义——许可证见 `Pdf/LICENSE.*`。
- RP SDK：`testdata/conformance` = Go 仓库 `testdata/conformance`（rp-conformance/2）的字节一致副本
  （`./build/sync-conformance.sh`；CI `conformance-sync`）；测试 `tests/GeregeSystems.EidMongolia.Tests` 和
  `tests/GeregeSystems.EidMongolia.AspNetCore.Tests`（`net8.0` + `net10.0`）；`build/compat`——与 Pades 0.16.0 的二进制兼容性
  （CI `compat`）；`build/check-packages.sh`——三个包的元数据与依赖（CI `pack`）。

## Release

1. 在 `release/<版本>` 分支：把三个 csproj 的 `<Version>` 提升为同一值（lockstep），将 `changelog.d/*` 合并进
   `CHANGELOG.md` 的新章节并删除这些片段 → PR → merge。
2. 在 main 上：`git tag v<版本> && git push origin v<版本>`。
3. `.github/workflows/release.yml`：运行完整 CI（Windows + Linux、compat、pack + `build/check-packages.sh`），检查 tag =
   `<Version>`，然后按依赖顺序（core → AspNetCore → Pades）将三个 `.nupkg`（+ `.snupkg`）发布为 GitHub Release 附件，
   并发布到 GitHub Packages（NuGet）和 nuget.org（Trusted Publishing）。新包 ID 在 nuget.org 上的前置条件：
   [docs/release-0.17.0.md](docs/release-0.17.0.md)。

## 许可证

MIT——[LICENSE](LICENSE)。第三方：Noto Sans（OFL 1.1）、digitorus/pdf（BSD-3）、digitorus/pdfsign（BSD-2）——位于 NuGet 包的
`licenses/` 中。
