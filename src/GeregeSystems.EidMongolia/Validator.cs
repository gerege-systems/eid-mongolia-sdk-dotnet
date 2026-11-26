using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia;

/// <summary>Цуцлалтын төлөв (Go <c>RevocationStatus</c>).</summary>
public enum RevocationStatus
{
    /// <summary>Олгогч хүчинтэй гэж хариулсан.</summary>
    Good,
    /// <summary>Цуцлагдсан (OCSP unknown — олгогч энэ serial-ийг олгоогүй — мөн энд).</summary>
    Revoked,
    /// <summary>Тогтоогдсонгүй (хариугүй).</summary>
    Unknown,
    /// <summary><see cref="ResponseValidator.CheckRevocationAsync"/>: "unknown", soft-fail горимд зөвшөөрөгдсөн.</summary>
    Unchecked,
    /// <summary><see cref="ResponseValidator.CheckRevocationAsync"/>: checker тохируулаагүй (асуугаагүй).</summary>
    Skipped,
}

/// <summary>"unknown" төлөвийн шийдвэр (Go <c>RevocationMode</c>).</summary>
public enum RevocationMode
{
    /// <summary>"unknown"-г татгалзана (анхдагч).</summary>
    HardFail,
    /// <summary>"unknown"-г зөвшөөрнө.</summary>
    SoftFail,
}

/// <summary>
/// Иргэний гэрчилгээ цуцлагдсан эсэхийг шалгах hook (OCSP / CRL; Go <c>RevocationChecker</c>). <paramref name="issuer"/> —
/// trust pool-оос олдсон шууд issuer (олдоогүй бол null). Хариугүй үед <see cref="RevocationStatus.Unknown"/> буцаах
/// эсвэл <see cref="EidOcspException"/> шиднэ (шалтгаан хадгалагдана); сүлжээний алдааг Good гэж ҮЗЭХГҮЙ. Бэлэн
/// хэрэгжүүлэлт: <see cref="OcspRevocationChecker.Checker"/>.
/// </summary>
/// <param name="certificate">Иргэний гэрчилгээ.</param>
/// <param name="issuer">Шууд issuer; олдоогүй бол null.</param>
/// <param name="ct">Цуцлалт.</param>
public delegate Task<RevocationStatus> RevocationChecker(X509Certificate2 certificate, X509Certificate2? issuer, CancellationToken ct);

/// <summary>Validator-ийн итгэлийн тохиргоо (Go <c>TrustConfig</c>, TS <c>TrustConfig</c>).</summary>
public sealed record TrustConfig
{
    /// <summary>
    /// Trust anchor (Root CA) PEM-үүд (ж: <see cref="EidTrust.NationalRootCaPem"/>). Production-д ЗААВАЛ — хоосон бол
    /// ValidateAuth/ValidateSign <see cref="ValidationReasons.TrustNoAnchor"/> (<see cref="AllowUntrusted"/>-аар л алгасна).
    /// </summary>
    public IReadOnlyList<string>? TrustAnchorsPem { get; init; }

    /// <summary>
    /// Завсрын CA PEM-үүд (нэг мөрөнд олон гэрчилгээ байж болно). null бол <see cref="EidTrust.CitizenIntermediatesPem"/>
    /// (02 → 03 → 04); хоосон жагсаалт = завсрын CA-гүй.
    /// </summary>
    public IReadOnlyList<string>? IntermediatesPem { get; init; }

    /// <summary>Шаардах certLevel (null / "" = QUALIFIED). Шаардсанаас дээш түвшнийг хүлээн авна (QSCD ⊇ QUALIFIED).</summary>
    public string? RequiredLevel { get; init; }

    /// <summary>Гэрчилгээний хугацааг шалгахад зөвшөөрөх цагийн зөрүү (анхдагч 0).</summary>
    public TimeSpan ClockSkew { get; init; }

    /// <summary>Trust anchor өгөөгүй ч баталгаажуулалт үргэлжлүүлнэ (гинж шалгахгүй). ЗӨВХӨН dev/тест.</summary>
    public bool AllowUntrusted { get; init; }

    /// <summary>Цуцлалт шалгагч; null бол <see cref="ResponseValidator.CheckRevocationAsync"/> → <see cref="RevocationStatus.Skipped"/>.</summary>
    public RevocationChecker? Revocation { get; init; }

    /// <summary>"unknown" төлөвийн шийдвэр (анхдагч <see cref="RevocationMode.HardFail"/>).</summary>
    public RevocationMode RevocationMode { get; init; }

    /// <summary>
    /// Иргэний гэрчилгээг шууд гаргасан CA-ийн Subject Key Identifier (hex, ":" зөвшөөрнө). Хоосон бол trust anchor
    /// тохируулсан үед <c>[<see cref="EidTrust.CitizenIssuingCaSki"/>]</c>. Өгвөл энэ жагсаалтаар (үргэлж, AllowUntrusted
    /// үед ч) шалгана.
    /// </summary>
    public IReadOnlyList<string>? AllowedIssuerSkis { get; init; }

    /// <summary>Анхдагч issuer allowlist-ийг унтраана (AllowedIssuerSkis өгсөн бол түүгээр шалгасаар). Тест/dev.</summary>
    public bool AllowAnyIssuer { get; init; }

    /// <summary>Гэрчилгээний зориулалтыг (auth → KU digitalSignature + EKU clientAuth; sign → KU nonRepudiation) шалгахгүй. Зөвлөхгүй.</summary>
    public bool SkipKeyUsageCheck { get; init; }

    /// <summary>ACSP_V2 payload-ийн scheme нэр (CA-ийн capabilities.acsp_scheme_name); null / "" = "smart-id".</summary>
    public string? SchemeName { get; init; }
}

/// <summary><see cref="ResponseValidator.ValidateAuth"/>-ийн нэмэлт шалгалт (device-link relay хаалт).</summary>
public sealed record ValidateAuthOptions
{
    /// <summary>
    /// RP-ийн ХАРУУЛСАН холбоосын төрөл (эсвэл push, <see cref="FlowTypes"/>). Өгвөл гарын үсэг зурагдсан flowType ЯГ ИЖИЛ
    /// байх ёстой: QR хуудас → QR; гар утасны браузер дахь товч → Web2App; RP-ийн апп → App2App; push → Notification.
    /// Web2App/App2App үед <see cref="UserChallengeVerifier"/> ЗААВАЛ.
    /// </summary>
    public string? ExpectedFlowType { get; init; }

    /// <summary>
    /// Callback URL-ийн userChallengeVerifier параметр. Өгвөл (null биш) BASE64URL(SHA-256(verifier)) нь гарын үсэг
    /// зурагдсан userChallenge-тэй таарна.
    /// </summary>
    public string? UserChallengeVerifier { get; init; }
}

/// <summary><see cref="ResponseValidator.ValidateSign"/>-ийн нэмэлт шалгалт.</summary>
public sealed record ValidateSignOptions
{
    /// <summary>
    /// RP-ийн эхлүүлсэн урсгал. Өгвөл хариуны flowType ЯГ ИЖИЛ. RAW_DIGEST_SIGNATURE-д flowType гарын үсэгт ОРДОГГҮЙ — энэ
    /// нь RP-API хариуны тулгалт, криптограф баталгаа биш.
    /// </summary>
    public string? ExpectedFlowType { get; init; }

    /// <summary>
    /// Хүсэлтэд илгээсэн signatureAlgorithm (<see cref="SignContext.SignatureAlgorithm"/>). Өгвөл хариуны RSA алгоритм ЯГ
    /// ИЖИЛ; хуучин threshold-ECDSA credential-ийн ecdsa-with-SHA256-г зөвхөн EC P-256 + SHA-256 үед зөвшөөрнө.
    /// </summary>
    public string? ExpectedAlgorithm { get; init; }

    /// <summary>Урьдчилж мэдсэн гэрчилгээ (<see cref="Signer.Certificate"/>). Өгвөл хариуны гэрчилгээ байт-ижил.</summary>
    public X509Certificate2? ExpectedCertificate { get; init; }
}

/// <summary>Баталгаажсан иргэн (auth; Go <c>VerifiedIdentity</c>).</summary>
public sealed record VerifiedIdentity
{
    /// <summary>Төхөөрөмжийн documentNumber.</summary>
    public string DocumentNumber { get; init; } = "";

    /// <summary>Иргэний X.509 гэрчилгээ.</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Задалсан subject (нэр, ETSI дугаар).</summary>
    public CertSubject Subject { get; init; } = new();

    /// <summary>Түүхий subject DN (платформын <see cref="X500DistinguishedName.Name"/> хэлбэр).</summary>
    public string SubjectDn { get; init; } = "";

    /// <summary>Үнэлэгдсэн түвшин: хариуны certificateLevel ба гэрчилгээнээс тогтоосны бага нь.</summary>
    public string CertificateLevel { get; init; } = "";
}

/// <summary>Баталгаажсан гарын үсэг (sign; Go <c>VerifiedSignature</c>).</summary>
public sealed record VerifiedSignature
{
    /// <summary>Төхөөрөмжийн documentNumber.</summary>
    public string DocumentNumber { get; init; } = "";

    /// <summary>Гарын үсэг (base64).</summary>
    public string SignatureValueB64 { get; init; } = "";

    /// <summary>Хариуны signatureAlgorithm.</summary>
    public string SignatureAlgorithm { get; init; } = "";

    /// <summary>Иргэний SIGN гэрчилгээ.</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Задалсан subject.</summary>
    public CertSubject Subject { get; init; } = new();

    /// <summary>Түүхий subject DN.</summary>
    public string SubjectDn { get; init; } = "";

    /// <summary>Үнэлэгдсэн түвшин.</summary>
    public string CertificateLevel { get; init; } = "";
}

/// <summary>
/// Certificate-choice-оор баталгаажсан гарын үсэг зурагч (Go <c>Signer</c>, TS <c>Signer</c>): гарын үсгийн гэрчилгээ +
/// түүнийг эзэмшдэг ЯГ ТЭР төхөөрөмжийн documentNumber. <see cref="SignService.DigestForSignerAsync"/> /
/// <see cref="SignService.DeviceLinkForSignerAsync"/>-д шууд (<see cref="SignerRef"/> руу далд хөрвүүлэлтээр) өгнө.
/// </summary>
public sealed record Signer
{
    /// <summary>Гэрчилгээг сонгосон төхөөрөмж (sign session-ийг ҮҮГЭЭР эхлүүлнэ).</summary>
    public string DocumentNumber { get; init; } = "";

    /// <summary>Иргэний SIGN гэрчилгээ (KeyUsage contentCommitment).</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Гэрчилгээний DER, стандарт base64.</summary>
    public string CertificateDerB64 { get; init; } = "";

    /// <summary>Үнэлэгдсэн түвшин.</summary>
    public string CertificateLevel { get; init; } = "";

    /// <summary>Задалсан subject.</summary>
    public CertSubject Subject { get; init; } = new();

    /// <summary>Certificate-choice session (linked sign-ийн linkedSessionID); null / "" бол /notification/document замаар.</summary>
    public string? CertChoiceSessionId { get; init; }

    /// <summary><see cref="SignService"/>-д өгөх хэсэг.</summary>
    public SignerRef Ref => new(DocumentNumber, CertChoiceSessionId);

    /// <summary><see cref="Ref"/>.</summary>
    public static implicit operator SignerRef(Signer signer) => (signer ?? throw new ArgumentNullException(nameof(signer))).Ref;
}

/// <summary>
/// RP-API-аас ирсэн session хариуг КРИПТОГРАФААР баталгаажуулна (Go <c>eid.Validator</c>, TS <c>ResponseValidator</c>).
/// SDK-ийн гол аюулгүйн давхарга: endResult == OK гэдэгт ДАНГААР нь итгэхгүй —
/// <list type="number">
/// <item>state == COMPLETE ба endResult == OK (эс бөгөөс <see cref="EidSessionFailedException"/>);</item>
/// <item>иргэний гэрчилгээг trust anchor хүртэл гинжээр: SDK-ийн өөрийн замын угсралт (OS-ийн X509Chain биш —
/// платформ бүрд ижил, AIA татахгүй) — basicConstraints/pathLen, keyCertSign, EKU давхарга, хугацаа, гарын үсэг;
/// fail-closed: name constraints-тэй CA ба жагсаалтад байхгүй critical extension → татгалзана;</item>
/// <item>гэрчилгээ (ба гинжийн CA) хүчинтэй хугацаанд, issuer allowlist, шаардсан certLevel;</item>
/// <item>гарын үсгийг иргэний түлхүүрээр: auth → ACSP_V2 payload, sign → RP-ийн digest.</item>
/// </list>
/// Аль нэг алхам бүтэлгүйтвэл <see cref="EidValidationException"/> (<see cref="EidValidationException.Reason"/> —
/// <see cref="ValidationReasons"/>) — хариунд ИТГЭХГҮЙ. Thread-safe.
/// </summary>
public sealed class ResponseValidator
{
    private const string EkuAny = "2.5.29.37.0";
    private const string EkuClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string EkuEmailProtection = "1.3.6.1.5.5.7.3.4";
    private const string OidQcCompliance = "0.4.0.1862.1.1";
    private const string OidQcSscd = "0.4.0.1862.1.4";
    /// <summary>Монголын үндэсний PKI-ийн certificate policy (CA crypto/ca_policy.go NationalPolicyOID).</summary>
    private const string OidNationalPolicy = "2.16.496.1.101.1.2.8";
    private const int MaxChainCas = 8;

    /// <summary>SDK-ийн ойлгодог critical extension-ууд (Go handledCritical, TS HANDLED_CRITICAL); бусад critical → татгалзана.</summary>
    private static readonly HashSet<string> HandledCritical = new(StringComparer.Ordinal)
    {
        "2.5.29.14", // subjectKeyIdentifier
        "2.5.29.15", // keyUsage
        "2.5.29.17", // subjectAltName
        "2.5.29.19", // basicConstraints
        "2.5.29.30", // nameConstraints (CA-д — CaFail fail-closed)
        "2.5.29.31", // cRLDistributionPoints
        "2.5.29.32", // certificatePolicies
        "2.5.29.35", // authorityKeyIdentifier
        "2.5.29.37", // extKeyUsage
        "1.3.6.1.5.5.7.1.1", // authorityInfoAccess
    };

    private static readonly Dictionary<string, int> LevelRank = new(StringComparer.Ordinal)
    {
        [CertificateLevels.Advanced] = 1,
        [CertificateLevels.Qualified] = 2,
        [CertificateLevels.Qscd] = 3,
    };

    private readonly IReadOnlyList<ParsedCert> _anchors;
    private readonly IReadOnlyList<ParsedCert> _intermediates;
    private readonly string _requiredLevel;
    private readonly TimeSpan _skew;
    private readonly bool _allowUntrusted;
    private readonly RevocationChecker? _revocation;
    private readonly RevocationMode _revocationMode;
    private readonly HashSet<string>? _allowedIssuers;
    private readonly bool _checkKeyUsage;
    private readonly string? _schemeName;
    private readonly TimeProvider _clock;

    /// <summary>PEM-үүдийг задалж validator үүсгэнэ (Go <c>NewValidator</c>).</summary>
    /// <param name="trust">Итгэлийн тохиргоо; null = хоосон (anchor-гүй — fail-closed).</param>
    /// <param name="timeProvider">Цаг (гэрчилгээний хугацааны шалгалт); null = <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentException">PEM задарсангүй эсвэл AllowedIssuerSkis hex биш.</exception>
    public ResponseValidator(TrustConfig? trust = null, TimeProvider? timeProvider = null)
    {
        var t = trust ?? new TrustConfig();
        _anchors = ParsePems(t.TrustAnchorsPem ?? Array.Empty<string>(), nameof(TrustConfig.TrustAnchorsPem));
        _intermediates = t.IntermediatesPem is null
            ? EidTrust.CitizenIntermediates
            : ParsePems(t.IntermediatesPem, nameof(TrustConfig.IntermediatesPem));
        IReadOnlyList<string>? skis = t.AllowedIssuerSkis is { Count: > 0 } given
            ? given
            : !t.AllowAnyIssuer && _anchors.Count > 0 ? new[] { EidTrust.CitizenIssuingCaSki } : null;
        if (skis is not null)
        {
            _allowedIssuers = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in skis)
            {
                var ski = (s ?? "").Trim().Replace(":", "", StringComparison.Ordinal).ToLowerInvariant();
                if (!IsHex(ski))
                {
                    throw new ArgumentException("eid: AllowedIssuerSkis: \"" + s + "\" hex key identifier биш", nameof(trust));
                }
                _allowedIssuers.Add(ski);
            }
        }
        _requiredLevel = string.IsNullOrEmpty(t.RequiredLevel) ? CertificateLevels.Qualified : t.RequiredLevel;
        _skew = t.ClockSkew;
        _allowUntrusted = t.AllowUntrusted;
        _revocation = t.Revocation;
        _revocationMode = t.RevocationMode;
        _checkKeyUsage = !t.SkipKeyUsageCheck;
        _schemeName = t.SchemeName;
        _clock = timeProvider ?? TimeProvider.System;
    }

    private static List<ParsedCert> ParsePems(IReadOnlyList<string> pems, string field)
    {
        var list = new List<ParsedCert>();
        foreach (var p in pems)
        {
            try
            {
                list.AddRange(ParsedCert.ParsePem(p));
            }
            catch (FormatException e)
            {
                throw new ArgumentException("eid: " + field + ": " + e.Message, field, e);
            }
        }
        return list;
    }

    private static bool IsHex(string s)
    {
        if (s.Length == 0 || s.Length % 2 != 0)
        {
            return false;
        }
        foreach (var c in s)
        {
            if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    private static EidValidationException Invalid(string reason, string message) => new(reason, message);

    // ── нийтийн API ──

    /// <summary>
    /// Auth session-ийн хариуг бүрэн шалгаж баталгаажсан иргэнийг буцаана (Go <c>ValidateAuth</c>). <paramref name="acsp"/> —
    /// session эхлүүлэхэд SDK-ийн буцаасан (RP хадгалсан) контекст. Цуцлалтыг дараа нь <see cref="CheckRevocationAsync"/>.
    /// </summary>
    /// <exception cref="EidSessionFailedException">COMPLETE, endResult ≠ OK.</exception>
    /// <exception cref="EidValidationException">Хариунд итгэхгүй (<see cref="EidValidationException.Reason"/>).</exception>
    public VerifiedIdentity ValidateAuth(SessionResult result, AcspContext acsp, ValidateAuthOptions? options = null)
    {
        if (acsp is null)
        {
            throw Invalid(ValidationReasons.AcspMissing, "ACSP контекст алга");
        }
        var o = options ?? new ValidateAuthOptions();
        var (leaf, level) = Precheck(result, SignatureProtocols.AcspV2);
        var serverRandom = result.ServerRandom ?? "";
        if (!B64.TryDecodeStd(serverRandom, out var sr) || sr.Length < 18)
        {
            throw Invalid(ValidationReasons.AuthServerRandom, "serverRandom алга/богино");
        }
        var userChallenge = result.UserChallenge ?? "";
        if (!IsUserChallenge(userChallenge))
        {
            throw Invalid(ValidationReasons.AuthUserChallenge, "userChallenge буруу хэлбэртэй");
        }
        var flow = result.FlowType ?? "";
        if (flow.Length == 0 || !(acsp.FlowTypes ?? Array.Empty<string>()).Contains(flow, StringComparer.Ordinal))
        {
            throw Invalid(ValidationReasons.AuthFlowNotOffered, "flowType " + flow + " нь санал болгосон урсгалд байхгүй");
        }
        if (!string.IsNullOrEmpty(o.ExpectedFlowType) && flow != o.ExpectedFlowType)
        {
            throw Invalid(ValidationReasons.FlowMismatch, "flowType " + flow + " ≠ эхлүүлсэн урсгал " + o.ExpectedFlowType + " (relay байж болзошгүй)");
        }
        var sameDevice = o.ExpectedFlowType is FlowTypes.Web2App or FlowTypes.App2App;
        if (sameDevice && string.IsNullOrEmpty(o.UserChallengeVerifier))
        {
            throw Invalid(ValidationReasons.AuthVerifierRequired, o.ExpectedFlowType + " урсгалд callback-ийн userChallengeVerifier заавал");
        }
        // TS validator.ts: өгсөн (null биш) verifier заавал таарна — Go-д "" нь «өгөөгүй».
        if (o.UserChallengeVerifier is not null && EidCrypto.UserChallengeOf(o.UserChallengeVerifier) != userChallenge)
        {
            throw Invalid(ValidationReasons.AuthVerifierMismatch, "userChallengeVerifier нь гарын үсэг зурагдсан userChallenge-тэй таарсангүй");
        }
        if (string.IsNullOrEmpty(result.InteractionTypeUsed))
        {
            throw Invalid(ValidationReasons.AuthInteractionTypeMissing, "interactionTypeUsed алга");
        }
        var (alg, hash) = AlgorithmOf(result, leaf, acsp.SignatureAlgorithm ?? "", acsp.HashAlgorithm ?? "");
        var cb = SignedCallbackUrl(result.InitialCallbackUrl, acsp.InitialCallbackUrl ?? "", flow);
        var payload = Acsp.BuildV2Payload(new AcspV2Params
        {
            SchemeName = _schemeName,
            ServerRandom = serverRandom,
            RpChallenge = acsp.RpChallenge ?? "",
            UserChallenge = userChallenge,
            RelyingPartyName = acsp.RelyingPartyName ?? "",
            BrokeredRpName = acsp.BrokeredRpName ?? "",
            Interactions = acsp.Interactions ?? "",
            InteractionTypeUsed = result.InteractionTypeUsed,
            InitialCallbackUrl = cb,
            FlowType = flow,
        });
        if (!VerifyPayload(payload, result.SignatureValueB64, leaf, alg, hash))
        {
            throw Invalid(ValidationReasons.AuthSignature, "auth гарын үсэг ACSP_V2 payload-той таарсангүй (хуурамч хариу байж болзошгүй)");
        }
        var cert = Load(leaf);
        return new VerifiedIdentity
        {
            DocumentNumber = result.DocumentNumber,
            Certificate = cert,
            Subject = leaf.Subject,
            SubjectDn = cert.SubjectName.Name,
            CertificateLevel = level,
        };
    }

    /// <summary>
    /// Sign session-ийн хариуг бүрэн шалгаж баталгаажсан гарын үсгийг буцаана (Go <c>ValidateSign</c>).
    /// <paramref name="digestB64"/> — хүсэлтэд илгээсэн digest; <paramref name="hashAlgorithm"/> — түүнийг үүсгэсэн hash
    /// (null / "" = SHA-256).
    /// </summary>
    /// <exception cref="EidSessionFailedException">COMPLETE, endResult ≠ OK.</exception>
    /// <exception cref="EidValidationException">Хариунд итгэхгүй.</exception>
    public VerifiedSignature ValidateSign(SessionResult result, string digestB64, string? hashAlgorithm = null, ValidateSignOptions? options = null)
    {
        var (leaf, level) = Precheck(result, SignatureProtocols.RawDigestSignature);
        var o = options ?? new ValidateSignOptions();
        if (!string.IsNullOrEmpty(o.ExpectedFlowType) && result.FlowType != o.ExpectedFlowType)
        {
            throw Invalid(ValidationReasons.FlowMismatch, "flowType " + result.FlowType + " ≠ эхлүүлсэн урсгал " + o.ExpectedFlowType + " (relay байж болзошгүй)");
        }
        if (o.ExpectedCertificate is not null && !leaf.Raw.AsSpan().SequenceEqual(o.ExpectedCertificate.RawData))
        {
            throw Invalid(ValidationReasons.SignCertificateMismatch,
                "гэрчилгээ certificate-choice-оор сонгосонтой таарахгүй (serial " + leaf.SerialHex() + ")");
        }
        var want = string.IsNullOrEmpty(hashAlgorithm) ? HashAlgorithms.Sha256 : hashAlgorithm;
        if (!B64.TryDecodeStd(digestB64 ?? "", out var digest))
        {
            throw Invalid(ValidationReasons.SignDigestBase64, "digest base64 буруу");
        }
        var (alg, h) = AlgorithmOf(result, leaf, o.ExpectedAlgorithm ?? "", want);
        if (digest.Length != EidCrypto.HashSize(h))
        {
            throw Invalid(ValidationReasons.SignDigestLength, "digest урт hashAlgorithm-тай таарахгүй");
        }
        if (!VerifyPrehashed(digest, result.SignatureValueB64, leaf, alg, h))
        {
            throw Invalid(ValidationReasons.SignSignature, "гарын үсэг өгсөн digest-тэй таарсангүй");
        }
        var cert = Load(leaf);
        return new VerifiedSignature
        {
            DocumentNumber = result.DocumentNumber,
            SignatureValueB64 = result.SignatureValueB64,
            SignatureAlgorithm = result.SignatureAlgorithm,
            Certificate = cert,
            Subject = leaf.Subject,
            SubjectDn = cert.SubjectName.Name,
            CertificateLevel = level,
        };
    }

    /// <summary>
    /// Certificate-choice session-ий хариуг шалгана (Go <c>ValidateCertificateChoice</c>): COMPLETE/OK, гэрчилгээ ба
    /// documentNumber, хугацаа, зориулалт (contentCommitment), гинж, issuer, certLevel. Энэ хариунд гарын үсэг БАЙХГҮЙ —
    /// иргэнийг таниагүй (нэвтрэлт биш); зөвхөн дараагийн sign session-ий гэрчилгээг урьдчилж мэдэхэд.
    /// </summary>
    /// <param name="result">Certificate-choice session-ий хариу.</param>
    /// <param name="certChoiceSessionId">Certificate-choice session-ий ID (linked sign-д).</param>
    /// <exception cref="EidSessionFailedException">COMPLETE, endResult ≠ OK.</exception>
    /// <exception cref="EidValidationException">Хариунд итгэхгүй.</exception>
    public Signer ValidateCertificateChoice(SessionResult result, string? certChoiceSessionId = null)
    {
        SessionService.EnsureCompleteOk(result);
        var (leaf, level) = LeafOf(result, SignatureProtocols.RawDigestSignature);
        return new Signer
        {
            DocumentNumber = result.DocumentNumber,
            Certificate = Load(leaf),
            CertificateDerB64 = Convert.ToBase64String(leaf.Raw),
            CertificateLevel = level,
            Subject = leaf.Subject,
            CertChoiceSessionId = certChoiceSessionId,
        };
    }

    /// <summary>
    /// Тохируулсан <see cref="TrustConfig.Revocation"/>-оор гэрчилгээний төлвийг шалгана (Go <c>CheckRevocationStatus</c>).
    /// ValidateAuth/ValidateSign-ийн дараа дуудна. <see cref="RevocationStatus.Good"/> — хүчинтэй;
    /// <see cref="RevocationStatus.Unchecked"/> — "unknown", soft-fail; <see cref="RevocationStatus.Skipped"/> — checker алга.
    /// </summary>
    /// <exception cref="EidValidationException">
    /// <see cref="ValidationReasons.RevocationRevoked"/>, эсвэл hard-fail горимд <see cref="ValidationReasons.RevocationUnknown"/>
    /// (<see cref="Exception.InnerException"/> = <see cref="EidOcspException"/> байж болно).
    /// </exception>
    public Task<RevocationStatus> CheckRevocationAsync(X509Certificate2 certificate, CancellationToken ct = default) =>
        CheckRevocationWithAsync(certificate, _revocation, _revocationMode, ct);

    /// <summary>
    /// <see cref="CheckRevocationAsync"/>-тэй ижил, гэхдээ өгсөн checker ба горимоор (issuer-ийг validator-ийн trust pool-оос
    /// олно; Go <c>CheckRevocationWith</c>). checker null бол <see cref="RevocationStatus.Skipped"/>. Checker-ийн
    /// <see cref="EidOcspException"/>-ээс бусад алдаа дамжина (итгэхгүй).
    /// </summary>
    public async Task<RevocationStatus> CheckRevocationWithAsync(X509Certificate2 certificate, RevocationChecker? checker,
        RevocationMode mode = RevocationMode.HardFail, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (checker is null)
        {
            return RevocationStatus.Skipped;
        }
        ParsedCert leaf;
        try
        {
            leaf = ParsedCert.Parse(certificate.RawData);
        }
        catch (FormatException e)
        {
            throw new EidValidationException(ValidationReasons.CertMalformed, "гэрчилгээ задарсангүй: " + e.Message, e);
        }
        var found = FindIssuer(leaf);
        using var issuer = found is null ? null : Load(found);
        RevocationStatus status;
        EidOcspException? noAnswer = null;
        try
        {
            status = await checker(certificate, issuer, ct).ConfigureAwait(false);
        }
        catch (EidOcspException e)
        {
            noAnswer = e;
            status = RevocationStatus.Unknown;
        }
        switch (status)
        {
            case RevocationStatus.Good:
                return RevocationStatus.Good;
            case RevocationStatus.Revoked:
                throw Invalid(ValidationReasons.RevocationRevoked, "гэрчилгээ цуцлагдсан (revoked)");
        }
        if (mode == RevocationMode.SoftFail)
        {
            return RevocationStatus.Unchecked;
        }
        if (noAnswer is not null)
        {
            throw new EidValidationException(ValidationReasons.RevocationUnknown,
                "гэрчилгээний revocation төлөв тогтоогдсонгүй (hard-fail): " + noAnswer.Message, noAnswer);
        }
        throw Invalid(ValidationReasons.RevocationUnknown, "гэрчилгээний revocation төлөв тогтоогдсонгүй (hard-fail)");
    }

    /// <summary>
    /// Гэрчилгээнээс тогтоох түвшин (Go <c>CertificateLevelOf</c>, CA crypto/ca_profile.go): qcStatements-д QcCompliance →
    /// QUALIFIED (+ QcSSCD → QSCD), QcCompliance-гүй → ADVANCED; qcStatements алга бол нэвтрэлтийн (ACSP_V2) гэрчилгээ
    /// KeyUsage keyEncipherment эсвэл EKU clientAuth + emailProtection ба үндэсний policy 2.16.496.1.101.1.2.8 → QUALIFIED,
    /// бусад → ADVANCED.
    /// </summary>
    /// <param name="certificate">Гэрчилгээ.</param>
    /// <param name="protocol"><see cref="SignatureProtocols"/>.</param>
    /// <exception cref="EidValidationException">Гэрчилгээ задарсангүй эсвэл qcStatements буруу.</exception>
    public static string CertificateLevelOf(X509Certificate2 certificate, string protocol)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return LevelOf(ParseOrInvalid(certificate.RawData), protocol);
    }

    /// <summary>Гэрчилгээний subject-оос нэр, ETSI дугаар, улсыг задална (Go <c>ParseSubject</c>).</summary>
    /// <exception cref="EidValidationException">Гэрчилгээ задарсангүй.</exception>
    public static CertSubject ParseSubject(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return ParseOrInvalid(certificate.RawData).Subject;
    }

    /// <summary>
    /// ACSP_V2 payload-ийн initialCallbackUrl (Go <c>SignedCallbackURL</c>): хариуны утгыг (signature.initialCallbackUrl)
    /// зөвхөн "" эсвэл RP-ийн илгээсэн callback-тай байт-ижил бол хэрэглэнэ; Web2App/App2App-д заавал RP-ийн callback.
    /// Талбар алга (null — хуучин CA) → RP-ийн callback.
    /// </summary>
    /// <exception cref="EidValidationException"><see cref="ValidationReasons.AuthCallbackUrl"/>.</exception>
    public static string SignedCallbackUrl(string? fromResponse, string rpCallback, string flowType)
    {
        rpCallback ??= "";
        if (fromResponse is null)
        {
            return rpCallback;
        }
        if (fromResponse.Length > 0 && fromResponse != rpCallback)
        {
            throw Invalid(ValidationReasons.AuthCallbackUrl,
                "signature.initialCallbackUrl нь хоосон ч биш, илгээсэн callback ч биш (хуурамч хариу байж болзошгүй)");
        }
        if (flowType is FlowTypes.Web2App or FlowTypes.App2App && fromResponse != rpCallback)
        {
            throw Invalid(ValidationReasons.AuthCallbackUrl, flowType + " урсгалд signature.initialCallbackUrl нь илгээсэн callback байх ёстой");
        }
        return fromResponse;
    }

    /// <summary>
    /// Бэлэн digest дээрх гарын үсэг (Go <c>VerifyPrehashedSignature</c>): rsassa-pss (MGF1 ижил hash, salt = hLen),
    /// shaNNNWithRSAEncryption (PKCS#1 v1.5), ecdsa-with-SHA256 (P-256, SHA-256, ASN.1 DER — IEEE P1363 биш). Алгоритм ба
    /// түлхүүрийн төрөл таарахгүй, эсвэл гэрчилгээ задрахгүй бол false.
    /// </summary>
    public static bool VerifyPrehashedSignature(byte[] digest, string signatureB64, X509Certificate2 certificate, string algorithm, string hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ParsedCert c;
        try
        {
            c = ParsedCert.Parse(certificate.RawData);
        }
        catch (FormatException)
        {
            return false;
        }
        return VerifyPrehashed(digest, signatureB64, c, algorithm, hashAlgorithm);
    }

    /// <summary>Payload (auth) дээрх гарын үсэг: HASH(payload)-ийг <see cref="VerifyPrehashedSignature"/>-аар (Go <c>VerifyPayloadSignature</c>).</summary>
    public static bool VerifyPayloadSignature(byte[] payload, string signatureB64, X509Certificate2 certificate, string algorithm, string hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return EidCrypto.HashSize(hashAlgorithm) != 0 &&
            VerifyPrehashedSignature(EidCrypto.Hash(hashAlgorithm, payload), signatureB64, certificate, algorithm, hashAlgorithm);
    }

    // ── дотоод ──

    private static ParsedCert ParseOrInvalid(byte[] der)
    {
        try
        {
            return ParsedCert.Parse(der);
        }
        catch (FormatException e)
        {
            throw new EidValidationException(ValidationReasons.CertMalformed, "гэрчилгээ задарсангүй: " + e.Message, e);
        }
    }

    private static X509Certificate2 Load(ParsedCert c)
    {
        try
        {
            return c.ToX509();
        }
        catch (CryptographicException e)
        {
            throw new EidValidationException(ValidationReasons.CertMalformed, "гэрчилгээ задарсангүй: " + e.Message, e);
        }
    }

    private static bool IsUserChallenge(string s)
    {
        if (s.Length != 43)
        {
            return false;
        }
        foreach (var c in s)
        {
            if (c is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-'))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>state/endResult, протокол, гэрчилгээ, гарын үсэг байгаа эсэх, дараа нь <see cref="LeafOf"/> (Go <c>precheck</c>).</summary>
    private (ParsedCert Leaf, string Level) Precheck(SessionResult result, string protocol)
    {
        SessionService.EnsureCompleteOk(result);
        if (!string.IsNullOrEmpty(result.SignatureProtocol) && result.SignatureProtocol != protocol)
        {
            throw Invalid(ValidationReasons.ProtocolMismatch, "signatureProtocol " + result.SignatureProtocol + " ≠ " + protocol);
        }
        if (string.IsNullOrEmpty(result.CertificateDerB64))
        {
            throw Invalid(ValidationReasons.NoCertificate, "хариунд гэрчилгээ алга");
        }
        if (string.IsNullOrEmpty(result.SignatureValueB64))
        {
            throw Invalid(ValidationReasons.NoSignature, "хариунд гарын үсэг алга");
        }
        return LeafOf(result, protocol);
    }

    /// <summary>Хариуны гэрчилгээ: documentNumber, задлалт, хугацаа, зориулалт, гинж, issuer, certLevel (Go <c>leafOf</c>).</summary>
    private (ParsedCert Leaf, string Level) LeafOf(SessionResult result, string protocol)
    {
        if (string.IsNullOrEmpty(result.CertificateDerB64))
        {
            throw Invalid(ValidationReasons.NoCertificate, "хариунд гэрчилгээ алга");
        }
        if (string.IsNullOrEmpty(result.DocumentNumber))
        {
            throw Invalid(ValidationReasons.NoDocumentNumber, "хариунд documentNumber алга");
        }
        if (!B64.TryDecodeStd(result.CertificateDerB64, out var der))
        {
            throw Invalid(ValidationReasons.CertMalformed, "гэрчилгээ base64 буруу");
        }
        var leaf = ParseOrInvalid(der);
        var now = _clock.GetUtcNow();
        CheckValidity(leaf, now);
        VerifyCertificate(leaf, protocol, now);
        var fromCert = LevelOf(leaf, protocol);
        var level = EffectiveLevel(result.CertificateLevel ?? "", fromCert);
        CheckLevel(level);
        return (leaf, level);
    }

    /// <summary>Алдааны текстэд subject (иргэний нэр/PNOMN) биш serial (hex) орно.</summary>
    private void CheckValidity(ParsedCert c, DateTimeOffset now)
    {
        if (now + _skew < c.NotBefore)
        {
            throw Invalid(ValidationReasons.CertNotYetValid, "гэрчилгээ хүчинтэй болоогүй байна (serial " + c.SerialHex() + ")");
        }
        if (now - _skew > c.NotAfter)
        {
            throw Invalid(ValidationReasons.CertExpired, "гэрчилгээний хугацаа дууссан (serial " + c.SerialHex() + ")");
        }
    }

    /// <summary>Зориулалт, trust anchor, гинж, issuer (Go <c>verifyCertificate</c>; allowUntrusted үед issuer-ийг TS шиг шалгасаар).</summary>
    private void VerifyCertificate(ParsedCert leaf, string protocol, DateTimeOffset now)
    {
        CheckPurpose(leaf, protocol);
        if (_anchors.Count == 0)
        {
            if (!_allowUntrusted)
            {
                throw Invalid(ValidationReasons.TrustNoAnchor,
                    "trust anchor тохируулаагүй — итгэлцэл шалгах боломжгүй (production-д TrustAnchorsPem өг, эсвэл AllowUntrusted)");
            }
        }
        else
        {
            VerifyChain(leaf, protocol == SignatureProtocols.AcspV2 ? EkuClientAuth : EkuEmailProtection, now);
        }
        CheckIssuer(leaf);
    }

    /// <summary>
    /// Зориулалт (CA crypto/ca_profile.go): ACSP_V2 → KU digitalSignature + EKU clientAuth (эсвэл any); RAW_DIGEST_SIGNATURE
    /// → KU contentCommitment.
    /// </summary>
    private void CheckPurpose(ParsedCert leaf, string protocol)
    {
        if (!_checkKeyUsage)
        {
            return;
        }
        if (protocol == SignatureProtocols.AcspV2)
        {
            if ((leaf.KeyUsage & ParsedCert.KuDigitalSignature) == 0)
            {
                throw Invalid(ValidationReasons.PurposeAuthDigitalSignature, "нэвтрэлтийн гэрчилгээнд KeyUsage digitalSignature алга");
            }
            if (!leaf.Eku.Contains(EkuClientAuth) && !leaf.Eku.Contains(EkuAny))
            {
                throw Invalid(ValidationReasons.PurposeAuthClientAuth,
                    "нэвтрэлтийн гэрчилгээнд ExtKeyUsage clientAuth алга (гарын үсгийн гэрчилгээ байж болзошгүй)");
            }
            return;
        }
        if ((leaf.KeyUsage & ParsedCert.KuContentCommitment) == 0)
        {
            throw Invalid(ValidationReasons.PurposeSignNonRepudiation, "гарын үсгийн гэрчилгээнд KeyUsage nonRepudiation (contentCommitment) алга");
        }
    }

    /// <summary>AllowedIssuerSkis үед шууд issuer-ийн SKI (issuer-т алга бол leaf-ийн AKI) жагсаалтад байх ёстой.</summary>
    private void CheckIssuer(ParsedCert leaf)
    {
        if (_allowedIssuers is null)
        {
            return;
        }
        var ski = leaf.AuthorityKeyId;
        if (FindIssuer(leaf) is { SubjectKeyId: { Length: > 0 } s })
        {
            ski = s;
        }
        if (ski is not { Length: > 0 } || !_allowedIssuers.Contains(Convert.ToHexString(ski).ToLowerInvariant()))
        {
            throw Invalid(ValidationReasons.IssuerNotAllowed, "гэрчилгээг гаргасан CA зөвшөөрөгдсөн иргэний issuer биш (allowedIssuerSkis)");
        }
    }

    /// <summary>leaf-ийн шууд issuer (revocation шалгагчид): intermediates, дараа нь anchors (Go <c>findIssuer</c>).</summary>
    internal ParsedCert? FindIssuer(ParsedCert leaf)
    {
        foreach (var c in _intermediates.Concat(_anchors))
        {
            if (CanSignCerts(c) && SignedBy(leaf, c))
            {
                return c;
            }
        }
        return null;
    }

    private static bool CanSignCerts(ParsedCert c) => c.IsCa && (!c.HasKeyUsage || (c.KeyUsage & ParsedCert.KuKeyCertSign) != 0);

    private void CheckLevel(string level)
    {
        var need = LevelRank.TryGetValue(_requiredLevel, out var n) ? n : 2;
        var got = LevelRank.TryGetValue(level, out var g) ? g : 0;
        if (got < need)
        {
            throw Invalid(ValidationReasons.LevelInsufficient, "гэрчилгээний түвшин хүрэлцэхгүй: " + level + " < " + _requiredLevel);
        }
    }

    /// <summary>Хариуны түвшин гэрчилгээнийхээс өндөр бол алдаа; бага бол хариуных; алга/үл таних бол гэрчилгээнийх.</summary>
    private static string EffectiveLevel(string claimed, string fromCert)
    {
        if (!LevelRank.TryGetValue(claimed, out var c))
        {
            return fromCert;
        }
        if (c > LevelRank[fromCert])
        {
            throw Invalid(ValidationReasons.LevelClaimedHigher, "хариуны certificateLevel " + claimed + " гэрчилгээнээс (" + fromCert + ") өндөр");
        }
        return claimed;
    }

    /// <summary>Go <c>CertificateLevelOf</c>.</summary>
    private static string LevelOf(ParsedCert c, string protocol)
    {
        if (c.Extension(ParsedCert.OidQcStatements) is { } qc)
        {
            bool compliance = false, sscd = false;
            try
            {
                var r = new AsnReader(qc.Value, AsnEncodingRules.DER);
                var seq = r.ReadSequence();
                r.ThrowIfNotEmpty();
                while (seq.HasData)
                {
                    if (!seq.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                    {
                        throw Invalid(ValidationReasons.LevelQcMalformed, "qcStatements буруу");
                    }
                    var id = seq.ReadSequence().ReadObjectIdentifier();
                    compliance |= id == OidQcCompliance;
                    sscd |= id == OidQcSscd;
                }
            }
            catch (AsnContentException)
            {
                throw Invalid(ValidationReasons.LevelQcMalformed, "qcStatements буруу");
            }
            return !compliance ? CertificateLevels.Advanced : sscd ? CertificateLevels.Qscd : CertificateLevels.Qualified;
        }
        if (protocol == SignatureProtocols.AcspV2 && ((c.KeyUsage & ParsedCert.KuKeyEncipherment) != 0 || IsCitizenAuthToken(c)))
        {
            return CertificateLevels.Qualified;
        }
        return CertificateLevels.Advanced;
    }

    /// <summary>P-CITIZEN-AUTH-TOKEN: EKU clientAuth + emailProtection ба certificatePolicies-д үндэсний OID.</summary>
    private static bool IsCitizenAuthToken(ParsedCert c) =>
        c.Eku.Contains(EkuClientAuth) && c.Eku.Contains(EkuEmailProtection) && c.Policies.Contains(OidNationalPolicy);

    /// <summary>
    /// Хариуны signatureAlgorithm + hash-ийг RP-ийн хүссэнтэй ба гэрчилгээний түлхүүрийн төрөлтэй тулгана (downgrade / alg
    /// confusion хаалт; Go validator.go <c>algorithmOf</c>, шалгалтын дараалал Go-ийнх).
    /// </summary>
    private static (string Alg, string Hash) AlgorithmOf(SessionResult r, ParsedCert leaf, string wantAlg, string wantHash)
    {
        var alg = r.SignatureAlgorithm ?? "";
        string hash;
        switch (alg)
        {
            case SignatureAlgorithms.RsassaPss:
                {
                    if (leaf.KeyKind != KeyKind.Rsa)
                    {
                        throw Invalid(ValidationReasons.AlgKeyMismatch, "rsassa-pss нь RSA бус гэрчилгээтэй");
                    }
                    var p = r.SignatureAlgorithmParameters;
                    hash = p?.HashAlgorithm ?? "";
                    var size = EidCrypto.HashSize(hash);
                    if (size == 0)
                    {
                        throw Invalid(ValidationReasons.AlgUnsupported, "дэмжигдээгүй hashAlgorithm: " + hash);
                    }
                    var mgf = p?.MaskGenAlgorithm?.Parameters?.HashAlgorithm;
                    if (!string.IsNullOrEmpty(mgf) && mgf != hash)
                    {
                        throw Invalid(ValidationReasons.AlgMgf1, "MGF1 hash нь hashAlgorithm-аас өөр");
                    }
                    if (p?.SaltLength is { } salt && salt != size)
                    {
                        throw Invalid(ValidationReasons.AlgSaltLength, "saltLength ≠ hLen");
                    }
                    break;
                }
            case SignatureAlgorithms.Sha256WithRsa or SignatureAlgorithms.Sha384WithRsa or SignatureAlgorithms.Sha512WithRsa:
                if (leaf.KeyKind != KeyKind.Rsa)
                {
                    throw Invalid(ValidationReasons.AlgKeyMismatch, alg + " нь RSA бус гэрчилгээтэй");
                }
                hash = "SHA-" + alg.Substring(3, 3);
                break;
            case SignatureAlgorithms.EcdsaWithSha256:
                if (!leaf.IsP256)
                {
                    throw Invalid(ValidationReasons.AlgKeyMismatch, alg + " нь EC P-256 бус гэрчилгээтэй");
                }
                hash = HashAlgorithms.Sha256;
                if (wantHash != hash)
                {
                    // CA ECDSA credential-аар SHA-256-аас өөр hash зурдаггүй — ийм хариу серверээс гарахгүй.
                    throw Invalid(ValidationReasons.AlgEcdsaHash, "ecdsa-with-SHA256 хариу " + wantHash + " хүссэн session-д боломжгүй (ECDSA credential зөвхөн SHA-256)");
                }
                break;
            default:
                throw Invalid(ValidationReasons.AlgUnsupported, "дэмжигдээгүй signatureAlgorithm: " + alg);
        }
        if (wantAlg.Length > 0 && alg != wantAlg && alg != SignatureAlgorithms.EcdsaWithSha256)
        {
            throw Invalid(ValidationReasons.AlgMismatch, "signatureAlgorithm " + alg + " ≠ хүссэн " + wantAlg);
        }
        if (hash != wantHash)
        {
            throw Invalid(ValidationReasons.AlgHashMismatch, "hashAlgorithm " + hash + " ≠ хүссэн " + wantHash);
        }
        return (alg, hash);
    }

    private static bool VerifyPayload(byte[] payload, string signatureB64, ParsedCert leaf, string alg, string hash) =>
        EidCrypto.HashSize(hash) != 0 && VerifyPrehashed(EidCrypto.Hash(hash, payload), signatureB64, leaf, alg, hash);

    /// <summary>
    /// Go <c>VerifyPrehashedSignature</c>: rsassa-pss → <see cref="RSA.VerifyHash(byte[], byte[], HashAlgorithmName, RSASignaturePadding)"/>
    /// + <see cref="RSASignaturePadding.Pss"/> (.NET-ийн salt = hLen; параметрийг <see cref="AlgorithmOf"/> урьдчилж
    /// шалгасан); PKCS#1 v1.5; ECDSA P-256 → <see cref="ECDsa.VerifyHash(byte[], byte[], DSASignatureFormat)"/>
    /// + <see cref="DSASignatureFormat.Rfc3279DerSequence"/> (P1363 биш).
    /// </summary>
    private static bool VerifyPrehashed(byte[] digest, string signatureB64, ParsedCert leaf, string alg, string hash)
    {
        if (digest is null || !B64.TryDecodeStd(signatureB64 ?? "", out var sig) || sig.Length == 0)
        {
            return false;
        }
        var size = EidCrypto.HashSize(hash);
        if (size == 0 || digest.Length != size)
        {
            return false;
        }
        try
        {
            switch (leaf.KeyKind)
            {
                case KeyKind.Rsa:
                    {
                        using var rsa = leaf.CreateRsa();
                        if (sig.Length != (rsa.KeySize + 7) / 8)
                        {
                            return false;
                        }
                        if (alg == SignatureAlgorithms.RsassaPss)
                        {
                            return rsa.VerifyHash(digest, sig, EidCrypto.HashName(hash), RSASignaturePadding.Pss);
                        }
                        if (alg.StartsWith("sha", StringComparison.Ordinal) && alg.EndsWith("WithRSAEncryption", StringComparison.Ordinal))
                        {
                            return rsa.VerifyHash(digest, sig, EidCrypto.HashName(hash), RSASignaturePadding.Pkcs1);
                        }
                        return false;
                    }
                case KeyKind.Ec:
                    {
                        if (alg != SignatureAlgorithms.EcdsaWithSha256 || hash != HashAlgorithms.Sha256 || !leaf.IsP256 ||
                            !ParsedCert.IsDerEcdsaSignature(sig))
                        {
                            return false;
                        }
                        using var ec = leaf.CreateEcdsa();
                        return ec.VerifyHash(digest, sig, DSASignatureFormat.Rfc3279DerSequence);
                    }
                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // ── гинж (TS validator.ts verifyChain / caReason / criticalReason / ekuReason-ийн порт) ──

    private readonly record struct Fail(string Key, string Text);

    /// <summary>
    /// RFC 5280 замын шалгалт, SDK-ийн өөрийн угсралт (TS validator.ts <c>verifyChain</c>): leaf-ээс trust anchor хүртэлх
    /// замыг anchors, дараа нь intermediates-аас (backtracking-тай, ≤ 8 CA) угсарна. Issuer бүр: subject = child.issuer
    /// (DER байт), AKI/SKI (хоёулаа байвал) таарах, гарын үсэг (SHA-1 хориотой — Go), <see cref="CaFail"/>. Leaf-ийн үл
    /// таних critical extension ба EKU-г эхэлж шалгана. Цаг = now, leaf-ийн хүчинтэй хугацаанд хавчсан (ClockSkew-ийн
    /// хүрээнд). Хүчинтэй зам олдвол амжина; үгүй бол эхэлж тааралдсан CA-ийн шалтгаан, тэр нь ч алга бол chain.untrusted.
    /// certificatePolicies шалгахгүй.
    /// </summary>
    private void VerifyChain(ParsedCert leaf, string usage, DateTimeOffset at)
    {
        var now = at < leaf.NotBefore ? leaf.NotBefore : at > leaf.NotAfter ? leaf.NotAfter : at;
        if ((CriticalFail(leaf) ?? EkuFail(leaf, usage)) is { } lf)
        {
            throw Invalid(lf.Key, "гэрчилгээний гинж хүчингүй: " + lf.Text);
        }
        Fail? first = null;
        var candidates = _anchors.Select(c => (Cert: c, Anchor: true)).Concat(_intermediates.Select(c => (Cert: c, Anchor: false))).ToList();

        bool Extend(ParsedCert cur, List<ParsedCert> cas)
        {
            if (cas.Count >= MaxChainCas)
            {
                return false;
            }
            foreach (var (cand, isAnchor) in candidates)
            {
                if (cas.Contains(cand) || !SignedBy(cur, cand))
                {
                    continue;
                }
                if (CaFail(cand, cas.Count, now, usage) is { } bad)
                {
                    first ??= bad;
                    continue;
                }
                if (isAnchor || Extend(cand, new List<ParsedCert>(cas) { cand }))
                {
                    return true;
                }
            }
            return false;
        }

        if (Extend(leaf, new List<ParsedCert>()))
        {
            return;
        }
        if (first is { } f)
        {
            throw Invalid(f.Key, "гэрчилгээний гинж хүчингүй: " + f.Text);
        }
        throw Invalid(ValidationReasons.ChainUntrusted, "гэрчилгээний итгэлцлийн гинж trust anchor (Root CA) хүрсэнгүй");
    }

    /// <summary>child-ийг cand гаргасан эсэх: issuer нэр = subject (байт), AKI/SKI (хоёулаа байвал) таарах, гарын үсэг.</summary>
    private static bool SignedBy(ParsedCert child, ParsedCert cand)
    {
        if (!child.RawIssuer.AsSpan().SequenceEqual(cand.RawSubject))
        {
            return false;
        }
        if (child.AuthorityKeyId is { Length: > 0 } aki && cand.SubjectKeyId is { Length: > 0 } ski && !aki.AsSpan().SequenceEqual(ski))
        {
            return false;
        }
        return cand.Verifies(child.SignatureAlgorithm, child.Tbs, child.Signature, allowSha1: false);
    }

    /// <summary>Issuer CA-ийн шалгалт (TS <c>caReason</c>-ийн дараалал); below = энэ CA-аас доорх завсрын CA-ийн тоо.</summary>
    private static Fail? CaFail(ParsedCert ca, int below, DateTimeOffset now, string usage)
    {
        if (!ca.IsCa)
        {
            return new Fail(ValidationReasons.ChainNotCa, "завсрын гэрчилгээ CA биш эсвэл keyCertSign эрхгүй");
        }
        if (ca.HasKeyUsage && (ca.KeyUsage & ParsedCert.KuKeyCertSign) == 0)
        {
            return new Fail(ValidationReasons.ChainNotCa, "CA-ийн KeyUsage-д keyCertSign алга");
        }
        if (now < ca.NotBefore || now > ca.NotAfter)
        {
            return new Fail(ValidationReasons.ChainExpired, "гинжийн гэрчилгээний хугацаа дууссан эсвэл хүчинтэй болоогүй");
        }
        if (ca.PathLen is { } pathLen && below > pathLen)
        {
            return new Fail(ValidationReasons.ChainPathLen, "pathLenConstraint зөрчсөн (завсрын CA хэт олон)");
        }
        if (ca.Extension(ParsedCert.OidNameConstraints) is not null)
        {
            return new Fail(ValidationReasons.ChainNameConstraints, "CA-д name constraints байна (SDK үнэлдэггүй — fail-closed)");
        }
        return CriticalFail(ca) ?? EkuFail(ca, usage);
    }

    private static Fail? CriticalFail(ParsedCert c)
    {
        foreach (var e in c.Extensions)
        {
            if (e.Critical && !HandledCritical.Contains(e.Oid))
            {
                return new Fail(ValidationReasons.ChainCriticalExtension, "үл таних critical extension");
            }
        }
        return null;
    }

    /// <summary>EKU тавьсан бол <paramref name="usage"/> эсвэл anyExtendedKeyUsage агуулах ёстой (EKU-гүй = дурын).</summary>
    private static Fail? EkuFail(ParsedCert c, string usage) =>
        c.Eku.Count > 0 && !c.Eku.Contains(usage) && !c.Eku.Contains(EkuAny)
            ? new Fail(ValidationReasons.ChainEku, "гэрчилгээний ExtKeyUsage энэ үйлдэлд тохирохгүй (гинжийн EKU)")
            : null;
}
