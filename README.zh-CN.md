[Монгол](README.md) · [English](README.en.md) · 中文

# eid-mongolia-sdk-dotnet

**eID Mongolia** 客户端 PAdES — .NET (C#) SDK。PDF 文档**绝不会发送到 eID 服务器**（Smart-ID 模式）：
文档在客户端准备（`Prepare`），只有 32 字节的哈希（DTBS）交由公民的手机或 USB 令牌签名，
签名再由客户端嵌入 PDF（`CompleteAsync`）。输出为 PAdES-BASELINE-LT（RFC 3161 时间戳、OCSP/CRL、
DSS）。

这是 Go 参考实现（[eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) 的 `pades`，配置文件
`pades-client/1`）的**原生 C# 移植**——没有原生代码、DLL 或 WASM。CI 在 Windows 和 Linux 上验证其输出与 Go 的 golden vector（验证页、QR、
xref、CMS、TSA/OCSP/CRL 请求、DSS）**字节级完全一致**。

完整文档：<https://developer.eidmongolia.mn/#overview>。

- 包：NuGet `GeregeSystems.EidMongolia.Pades`，`net8.0` 和 `net10.0`（多目标）。`net8.0` 运行时已于 2026-11-10 结束支持；为了让现有依赖方（relying party）仍能 restore，暂时保留，将在下一个版本中移除。依赖：仅 `System.Security.Cryptography.Pkcs`（Microsoft）。
- 线程安全，无全局状态。仅 `CompleteAsync` 使用网络（TSA、OCSP/CRL）。
- 这里**没有**完整的验证器（validator）——验证方式：通过文件的 SHA-256 向 CA 登记簿查询；完整的密码学验证在 Go
  后端 SDK 中。

## 安装

从 [nuget.org](https://www.nuget.org/packages/GeregeSystems.EidMongolia.Pades)：

```bash
dotnet add package GeregeSystems.EidMongolia.Pades --version 0.16.0
```

每个版本的 `.nupkg` 也可在 [GitHub Releases](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet/releases) 获取。

## 流程

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
| `PdfInvalid` | `PDF_INVALID` | PDF 无法解析；结构过深（嵌套 > 256）或存在 ObjStm 循环、`/Extends` > 64、`/Size` > 2^21（PRECHECKS #2a/#2b） |
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
本 SDK 不包含 HTTP client。

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
- 印章证书由 CA / 管理控制台签发——本 SDK 没有签发功能。

## “我的 QR”——公民的“我的信息”（`GeregeSystems.EidMongolia.Qr`，0.13.0）

独立于 PAdES，位于同一个包中。公民在其 eID App 中出示“我的 QR”（`EIDMN-QR1:<token>`，120 秒，一次
性）→ RP 扫描后调用 `POST /authentication/qr` → 公民在手机上看到一句话，并用 **PIN2** 同意 →
RP 取得公民的“我的信息”（App 中保存的 dict 原样不变 + 人脸 JPEG），形式为用公民自己的 QUALIFIED SIGN
密钥签名的 **PS256 JWS**（`typ` = `eidmn-myqr+jwt`，`x5c` = [公民证书, 颁发 CA]）。CA 不
保存该值；presentation 只能被读取一次（再次读取会返回 410 `QR_PRESENTATION_GONE`）。RP 只需
`QR_PRESENT` 权限。

```csharp
using GeregeSystems.EidMongolia.Qr;

using var qr = new EidQrClient(new EidQrOptions { RpUuid = rpUuid, RpName = "收银台 3", ApiSecret = secret });
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
`alg` PS256 / `typ` / 含 2 张证书的 `x5c` → 证书链（`X509Chain` CustomRootTrust；x5c[1] 仅作为中间证书候选，±60 秒）+
叶子证书：非 CA，KeyUsage 为 contentCommitment，QcCompliance（QUALIFIED），颁发者 SKI ∈ `AllowedIssuerSkis`（默认为 04
`EidQr.CitizenIssuingCaSki`），RSA ≥ 2048 → 吊销检查（默认使用 AIA 的 OCSP，hard-fail）→ RSASSA-PSS SHA-256（salt 32）→
`iss`，`sub` = 证书的 serialNumber，`statement` = «Та {rp_name}-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг
хуваалцах гэж байна»（“您即将向 {rp_name} 分享‘我的信息’部分的全部信息”），`aud` = RP UUID（不区分大小写），`sid`，`nonce`（完全一致），0 < exp − iat ≤ 300，iat ≤ 当前 + 60，
当前 < exp + 60 → `data`（`source` 须匹配 `^[a-z0-9_-]{1,32}$`；`fields` ≤ 128 项，键为 1–64 个 code point 且不含控制字符，
值只能是 ≤ 2048 字节的字符串；`photo` 为严格 base64 的 JPEG ≤ 150 KiB；`fields` 为空时 `photo` 必须存在；不得有多余
成员）。

`QrTrust(Anchors, Intermediates, AllowedIssuerSkis, Revocation, RevocationSoftFail)`——为 null 时使用内置的国家根证书
+ 02–05 中间证书、颁发者 04、OCSP。`Revocation` = `(叶子, 颁发者) → "good" | "revoked" | "unknown"`（你自己的缓存/CRL 或
测试 stub）；抛出异常 = "unknown"。`RevocationSoftFail = true` 时接受 "unknown"。

错误码（`EidQrException.Code`）：`QR_FORMAT_INVALID`（不会发往 CA）、`QR_JWS_MALFORMED`、`QR_HEADER_INVALID`、
`QR_CHAIN_INVALID`、`QR_CERT_REVOKED`、`QR_REVOCATION_UNKNOWN`、`QR_SIGNATURE_INVALID`、`QR_CLAIMS_INVALID`、
`QR_AUDIENCE_MISMATCH`、`QR_SESSION_MISMATCH`、`QR_NONCE_MISMATCH`、`QR_NOT_YET_VALID`、`QR_EXPIRED`、`QR_DATA_INVALID`、
`QR_PRESENTATION_GONE`（410）、`QR_PENDING`（`ResultAsync` 的 `maxWait` 已到——可再次调用）、`SESSION_FAILED`
（`EndResult`）、带 `HttpStatus` 的服务器 `code`（400 `REQUEST_INVALID`，403 `PERMISSION_DENIED` / `RP_REQUIRED`，404
`QR_TOKEN_INVALID`，409 `NO_SIGNING_CERTIFICATE`，429 `RATE_LIMITED`）、`HTTP_ERROR`、`NETWORK_ERROR`。

## RP SDK 核心——`GeregeSystems.EidMongolia`（开发中）

> **开发中——尚未发布到 NuGet。** 目标：与 TypeScript 和 Go SDK 范围相同的完整服务端 RP SDK（Auth、Sign、Session、
> Validator、OCSP、登录后端……）。发布前 API 可能变化。

目前已有（`src/GeregeSystems.EidMongolia`，无包依赖，`net8.0` / `net10.0`）：

- `EidClient` + `EidClientOptions` / `EidCredentials`——BaseUrl 规则（https；http 仅限 loopback；旧的
  `ca.eidmongolia.mn` 主机给出明确错误）、Bearer 认证、超时（默认 15 秒，PDF 80 秒）、`Accept-Language`、JSON 4 MiB
  上限；mTLS——向构造函数传入带客户端证书的 `HttpClient`。`client.Auth.SessionTtlAsync()`——discovery 的 `sessionTtl`。
- 错误：`EidException`（`Code`、`Status`、`RetryAfter`、`Retryable`）→ `EidAuthenticationException`（401）、
  `EidForbiddenException`（403）、`EidApiException`（每个已知代码有子类）、`EidNetworkException`、
  `EidResponseTooLargeException`、`EidSessionFailedException`、`EidValidationException`、`EidDeviceLinkException`。
- 加密：`Acsp.BuildV2Payload` / `V2Digest`、`EidCrypto.InteractionsToBase64`（与 JS `JSON.stringify` 字节一致）、
  `DeviceLink.Build` / `TickQrAsync`（authCode = HMAC-SHA256）、`EidCrypto.SessionSecretDigest`、`RandomChallenge`、
  `UserChallengeOf`。
- 验证：CA 的 device-link golden（`testdata/devicelink_golden.json`，测试中固定 SHA-256）、Smart-ID ACSP_V2 向量、
  interactions 转义；`.github/workflows/contract.yml` 每天将路由表与线上 `/.well-known/eid` 对照。

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

## Release

1. 在 `release/<版本>` 分支：提升 csproj 的 `<Version>`，把 `changelog.d/*` 合并到 `CHANGELOG.md` 的新版本章节
   并删除这些片段 → PR → merge。
2. 在 main 上：`git tag v<版本> && git push origin v<版本>`。
3. `.github/workflows/release.yml`：完整运行 CI（Windows + Linux），检查 tag = `<Version>`，然后把
   `.nupkg` 作为 GitHub Release 资产发布，并发布到 GitHub Packages（NuGet）和 nuget.org（Trusted Publishing）。

## 许可证

MIT——[LICENSE](LICENSE)。第三方：Noto Sans（OFL 1.1）、digitorus/pdf（BSD-3）、digitorus/pdfsign（BSD-2）——位于 NuGet 包的
`licenses/` 中。
