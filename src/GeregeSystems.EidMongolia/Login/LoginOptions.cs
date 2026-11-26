using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Login;

/// <summary>
/// <see cref="EidLoginHandler"/>-ийн тохиргоо (Go <c>eidlogin.Config</c>, TS <c>EidLoginOptions</c>). Тохиргоог handler
/// үүсгэх үед нэг удаа уншина.
/// </summary>
public sealed class EidLoginOptions
{
    /// <summary>RP-API client (заавал). Validator-ийн Trust (production-д TrustAnchorsPem) нь энэ client-ийнх.</summary>
    public EidClient? Client { get; set; }

    /// <summary>
    /// RP-ийн session-ийг ЭНД үүсгэнэ (иргэн баталгаажсан, нэг удаа л дуудагдана): хэрэглэгчийг <see cref="EidLoginIdentity.Etsi"/>-ээр
    /// таньж, ШИНЭ session id (session fixation) үүсгээд cookie-г <see cref="EidLoginSuccess.Headers"/>-ээр (эсвэл хост
    /// framework-аар) буцаа. Алдаа шидвэл 500 <c>internal</c> / callback-д <c>eid_error=internal</c>. Заавал.
    /// </summary>
    public Func<EidLoginIdentity, EidLoginContext, CancellationToken, Task<EidLoginSuccess?>>? OnSuccess { get; set; }

    /// <summary>
    /// Web2App буцах https URL (host нь RP-ийн callbackHosts-д, зам нь ЗААВАЛ <c>/auth/eid/callback</c>). null / "" бол
    /// <c>mode=web2app</c> 400 — QR/push л ажиллана.
    /// </summary>
    public string? CallbackUrl { get; set; }

    /// <summary>Callback амжилттай (OnSuccess Redirect өгөөгүй) бол. Анхдагч "/".</summary>
    public string? SuccessRedirect { get; set; }

    /// <summary>Callback амжилтгүй бол, <c>?eid_error=&lt;код&gt;</c> нэмэгдэнэ. Анхдагч "/".</summary>
    public string? FailureRedirect { get; set; }

    /// <summary>Утсанд харагдах текст (≤ 60 тэмдэгт, илүүг таслана). Анхдагч «&lt;RpName&gt;-д нэвтрэх».</summary>
    public string? DisplayText { get; set; }

    /// <summary>Нэвтрэлтийн certLevel; null = client-ийн анхдагч.</summary>
    public string? CertificateLevel { get; set; }

    /// <summary>
    /// Нэвтрэлтийн хугацаа (≤ 0 = 2 мин). CA-ийн session-оос урт байхгүй: QR/web2app-д min(Ttl, CA-ийн expiresAt − одоо);
    /// push-д (бодит ба decoy ижил) min(Ttl, discovery sessionTtl.auth) — хугацааны зөрүү бүртгэлтэй эсэхийн oracle болохгүй.
    /// </summary>
    public TimeSpan Ttl { get; set; }

    /// <summary>Status-ийн нэг дуудлагад eID-ийг хүлээх (≤ 0 = 1 с).</summary>
    public TimeSpan Poll { get; set; }

    /// <summary>Төлөвийн сан; null = <see cref="MemoryEidLoginStore"/>.</summary>
    public IEidLoginStore? Store { get; set; }

    /// <summary>
    /// Cookie-ийн нэр. Анхдагч (rp-conformance/2): Secure, Domain алга, Path=/ үед <c>__Host-eid_login</c> (хөтөч дэд домэйн /
    /// өөр замаас тарьсан cookie-г энэ нэрээр хүлээн авахгүй), бусад үед (InsecureCookie, CookieDomain, өөр CookiePath)
    /// <c>eid_login</c>. Өгсөн нэрийг хэвээр хэрэглэнэ. Хүсэлтэд энэ нэртэй cookie нэгээс олон бол cookie-гүй гэж үзнэ.
    /// </summary>
    public string? CookieName { get; set; }

    /// <summary>Cookie-ийн Path (анхдагч "/").</summary>
    public string? CookiePath { get; set; }

    /// <summary>Cookie-ийн Domain (анхдагч алга — зөвхөн тухайн host).</summary>
    public string? CookieDomain { get; set; }

    /// <summary>Secure тэмдэггүй cookie — ЗӨВХӨН http dev-д.</summary>
    public bool InsecureCookie { get; set; }

    /// <summary>
    /// Төрөл тус бүрийн хязгаар ("start" — <c>start:&lt;ip&gt;</c>, "push" — <c>push:&lt;pushKey&gt;</c>);
    /// <see cref="EidLoginRateRule.Defaults"/>-тэй НЭГТГЭГДЭНЭ: өгсөн төрөл анхдагчийг дарна, өгөөгүй нь анхдагчаараа.
    /// Тухайн төрлийг хязгааргүй болгох бол <see cref="EidLoginRateRule.Unlimited"/>. Өөр түлхүүр → ArgumentException.
    /// </summary>
    public IDictionary<string, EidLoginRateRule>? RateLimits { get; set; }

    /// <summary>
    /// Бүх түлхүүрт (<c>start:&lt;ip&gt;</c>, <c>push:&lt;pushKey&gt;</c>) дуудагдах нэмэлт шалгалт; false → 429. Анхдагч
    /// хязгаар ДЭЭР нэмэгдэнэ (хоёулаа зөвшөөрөх ёстой). rp-conformance/2-оос түлхүүрт регистрийн дугаар ОРОХГҮЙ: pushKey =
    /// <see cref="OnEvent"/>-ийн meta.pushKey (<see cref="AuditKey"/>-ийн HMAC, 32 hex); IP тодорхойгүй бол <c>start:unknown</c>.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<bool>>? RateLimit { get; set; }

    /// <summary>
    /// <c>start:&lt;ip&gt;</c> хязгаарын клиент IP: шууд холбогддог бол <see cref="EidLoginClientIp.RemoteAddress"/>,
    /// итгэмжит reverse proxy-ийн ард <see cref="EidLoginClientIp.Forwarded"/>(n), эсвэл өөрийн функц. null бол IP-ээр
    /// хязгаарлахгүй (handler үүсэхэд нэг удаа Warning) — Go/TS-тэй ижил дүрэм; таамаглаж header-т итгэхгүй. Өгсөн ч null /
    /// "" буцаавал хязгааргүй биш — нийтийн <c>start:unknown</c> bucket. Буцаасан IPv6
    /// хаягийн түлхүүр нь /64 угтвар (<c>start:2001:db8:1:2::/64</c>); IPv4 хэвээр. ASP.NET Core-ийн <c>MapEidLogin</c>-д
    /// анхдагч нь <see cref="EidLoginClientIp.RemoteAddress"/>.
    /// </summary>
    public Func<EidLoginRequest, string?>? ClientIp { get; set; }

    /// <summary>Дотоод лог (анхдагч алга). Иргэний мэдээлэл бичихгүй.</summary>
    public Action<EidLoginLogEntry>? Log { get; set; }

    /// <summary>
    /// eID push-ийг дугаарын шалтгаанаар татгалзвал (eID-ийн JSON 4xx) decoy-ийн оронд 502 <c>eid_unavailable</c>. АНХААР:
    /// тэгвэл <c>/start</c> нь «энэ регистр eID-д бүртгэлтэй эсэх»-ийг хэнд ч хэлдэг oracle болно — дотоод/тестийн орчинд л.
    /// </summary>
    public bool DisableDecoy { get; set; }

    /// <summary>
    /// Push start-ийн хариу (бодит, decoy, 502) хамгийн багадаа энэ хугацаанд гарна (≤ 0 = 1 с): decoy микросекундэд,
    /// бодит push eID-ийн round trip-ээр бэлэн болдог тул цаг нь л ялгана. Хүсэлт тасарвал хүлээхгүй. 429 ба 400-д хамаарахгүй.
    /// </summary>
    public TimeSpan PushFloor { get; set; }

    /// <summary>PushFloor-ийг унтраана. АНХААР: decoy-г хариуны хугацаагаар ялгаж болно.</summary>
    public bool DisablePushFloor { get; set; }

    /// <summary>
    /// Иргэний гэрчилгээний цуцлалт шалгагч (OnSuccess-ийн өмнө). null = <see cref="OcspRevocationChecker"/> (гэрчилгээний
    /// AIA OCSP). Цуцлагдсан / олгогч мэдэхгүй → FAILED <c>VALIDATION</c>.
    /// </summary>
    public RevocationChecker? Revocation { get; set; }

    /// <summary>
    /// OCSP хариугүй үед: null = <see cref="EidMongolia.RevocationMode.SoftFail"/> (зөвшөөрч Warning бичнэ,
    /// Identity.Revocation = Unchecked — CA-ийн responder унавал бүх иргэн түгжигдэхгүй); HardFail — FAILED <c>VALIDATION</c>.
    /// </summary>
    public RevocationMode? RevocationMode { get; set; }

    /// <summary>Цуцлалт шалгахгүй (Identity.Revocation = Skipped). АНХААР: цуцалсан (хулгайлагдсан утасны) гэрчилгээгээр нэвтэрнэ.</summary>
    public bool DisableRevocation { get; set; }

    /// <summary>
    /// Аудитын hook (<see cref="EidLoginEventKinds"/>); хариу өгөхөөс өмнө await хийгдэнэ — удаан ажлыг өөрөө async болго.
    /// Шидсэн алдаа нь <see cref="Log"/> руу (урсгалыг зогсоохгүй).
    /// </summary>
    public Func<EidLoginEvent, CancellationToken, Task>? OnEvent { get; set; }

    /// <summary>
    /// pushKey-ийн HMAC түлхүүр (≥ 32 байт санал болгоно). null бол санамсаргүй — pushKey зөвхөн процесс дотор тогтвортой;
    /// instance/restart хооронд харьцуулах бол тогтмол нууц өг.
    /// </summary>
    public byte[]? AuditKey { get; set; }

    /// <summary>Цаг (push floor, decoy poll, хугацаа, хязгаар); null = систем. Тестэд удирддаг цаг өгнө.</summary>
    public TimeProvider? TimeProvider { get; set; }
}
