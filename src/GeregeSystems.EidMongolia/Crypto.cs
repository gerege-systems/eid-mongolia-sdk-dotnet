using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Крипто туслахууд — digest, санамсаргүй challenge, interactions, linked signing-ийн sessionSecretDigest (Go crypto.go,
/// certchoice.go, validator.go <c>UserChallengeOf</c>).
/// </summary>
public static class EidCrypto
{
    /// <summary>SHA-256 digest, стандарт base64. Sign урсгалын баримтын digest үүсгэхэд.</summary>
    public static string Sha256Base64(ReadOnlySpan<byte> data) => B64.Std(SHA256.HashData(data));

    /// <summary>Санамсаргүй RP challenge (<paramref name="bytes"/> ≤ 0 бол 64 байт), стандарт base64.</summary>
    public static string RandomChallenge(int bytes = 64) =>
        B64.Std(RandomNumberGenerator.GetBytes(bytes <= 0 ? 64 : bytes));

    /// <summary>
    /// Interactions массивыг RP-API v3-ийн base64 мөр болгоно — JS <c>JSON.stringify</c>-тай байт-ижил (TS/Go SDK-тэй
    /// ижил). RP энэ МӨРИЙГ хадгалж validator-т өгнө (дахин serialize хийхгүй). null = <c>[]</c>.
    /// </summary>
    public static string InteractionsToBase64(IEnumerable<Interaction>? interactions) =>
        B64.Std(JsJson.Interactions(interactions));

    /// <summary>
    /// Linked signing-ийн callback-ийн <c>sessionSecretDigest</c>: BASE64URL-NOPAD(SHA-256(base64-decode(sessionSecret))).
    /// sessionSecret — стандарт base64 (CA-ийн хэлбэр), үгүй бол base64url. Буруу оролтод <see cref="EidDeviceLinkException"/>.
    /// </summary>
    public static string SessionSecretDigest(string sessionSecret)
    {
        var s = (sessionSecret ?? "").Trim();
        if (s.Length == 0)
        {
            throw new EidDeviceLinkException("sessionSecret хоосон");
        }
        if (!B64.TryDecodeAny(s, out var key))
        {
            throw new EidDeviceLinkException("sessionSecret base64 биш");
        }
        return B64.RawUrl(SHA256.HashData(key));
    }

    /// <summary>
    /// Callback-ээр ирсэн <c>sessionSecretDigest</c>-ийг sessionSecret-ийнхтэй тогтмол хугацаанд тулгана. Буруу
    /// хэлбэртэй / хоосон оролтод false.
    /// </summary>
    public static bool VerifySessionSecretDigest(string? digest, string? sessionSecret)
    {
        if (string.IsNullOrEmpty(digest) || sessionSecret is null)
        {
            return false;
        }
        string want;
        try
        {
            want = SessionSecretDigest(sessionSecret);
        }
        catch (EidDeviceLinkException)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(digest), Encoding.UTF8.GetBytes(want));
    }

    /// <summary>
    /// userChallenge = BASE64URL-NOPAD(SHA-256(UTF8(verifier))) — ижил төхөөрөмжийн урсгалын callback-ийн
    /// <c>userChallengeVerifier</c>-ээс.
    /// </summary>
    public static string UserChallengeOf(string verifier) =>
        B64.RawUrl(SHA256.HashData(Encoding.UTF8.GetBytes(verifier ?? throw new ArgumentNullException(nameof(verifier)))));

    /// <summary>"SHA-256" | "SHA-384" | "SHA-512" → digest; бусад нэрэнд <see cref="EidValidationException"/>.</summary>
    internal static byte[] Hash(string? name, ReadOnlySpan<byte> data) => name switch
    {
        HashAlgorithms.Sha256 => SHA256.HashData(data),
        HashAlgorithms.Sha384 => SHA384.HashData(data),
        HashAlgorithms.Sha512 => SHA512.HashData(data),
        _ => throw new EidValidationException(ValidationReasons.AlgUnsupported, "дэмжигдээгүй hashAlgorithm: " + name),
    };

    /// <summary>Hash-ийн урт (байт); дэмжигдээгүй нэрэнд 0 (Go <c>cryptoHash(..).Size()</c>).</summary>
    internal static int HashSize(string? name) => name switch
    {
        HashAlgorithms.Sha256 => 32,
        HashAlgorithms.Sha384 => 48,
        HashAlgorithms.Sha512 => 64,
        _ => 0,
    };

    /// <summary>"SHA-256" | "SHA-384" | "SHA-512" → <see cref="HashAlgorithmName"/>; бусад нэрэнд default.</summary>
    internal static HashAlgorithmName HashName(string? name) => name switch
    {
        HashAlgorithms.Sha256 => HashAlgorithmName.SHA256,
        HashAlgorithms.Sha384 => HashAlgorithmName.SHA384,
        HashAlgorithms.Sha512 => HashAlgorithmName.SHA512,
        _ => default,
    };
}

/// <summary>ACSP_V2 payload-ийн бүх орц (Smart-ID v3 §ACSP_V2 digest calculation).</summary>
public sealed record AcspV2Params
{
    /// <summary>null / "" = "smart-id".</summary>
    public string? SchemeName { get; init; }
    /// <summary>base64, хариунаас ЯГ ТЭР ХЭВЭЭР.</summary>
    public string ServerRandom { get; init; } = "";
    /// <summary>base64, RP-ийн илгээсэн.</summary>
    public string RpChallenge { get; init; } = "";
    /// <summary>base64url 43 тэмдэгт, хариунаас.</summary>
    public string UserChallenge { get; init; } = "";
    /// <summary>Хүсэлтэд илгээсэн түүхий мөр.</summary>
    public string RelyingPartyName { get; init; } = "";
    /// <summary>Одоогоор "".</summary>
    public string BrokeredRpName { get; init; } = "";
    /// <summary>Хүсэлтэд илгээсэн interactions-ийн base64 МӨР.</summary>
    public string Interactions { get; init; } = "";
    /// <summary>Хариунаас.</summary>
    public string InteractionTypeUsed { get; init; } = "";
    /// <summary>Payload-д зурагдсан түүхий мөр, байхгүй бол "".</summary>
    public string InitialCallbackUrl { get; init; } = "";
    /// <summary>Хариунаас.</summary>
    public string FlowType { get; init; } = "";
}

/// <summary>
/// ACSP_V2 payload (Smart-ID RP-API v3 signature_protocols-тэй БАЙТ-ИЖИЛ: сервер, утас, RP SDK '|'-ээр холбосон нэг
/// мөрийг угсарна — нэг байт зөрвөл гарын үсэг таарахгүй).
/// </summary>
public static class Acsp
{
    /// <summary>
    /// Гарын үсэг зурагдах UTF-8 байтууд:
    /// <c>schemeName|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType</c>.
    /// </summary>
    public static byte[] BuildV2Payload(AcspV2Params p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var scheme = string.IsNullOrEmpty(p.SchemeName) ? "smart-id" : p.SchemeName;
        var ih = SHA256.HashData(Encoding.UTF8.GetBytes(p.Interactions ?? ""));
        return Encoding.UTF8.GetBytes(string.Join("|",
            scheme,
            "ACSP_V2",
            p.ServerRandom,
            p.RpChallenge,
            p.UserChallenge,
            B64.Std(p.RelyingPartyName ?? ""),
            B64.Std(p.BrokeredRpName ?? ""),
            B64.Std(ih),
            p.InteractionTypeUsed,
            p.InitialCallbackUrl,
            p.FlowType));
    }

    /// <summary>HASH_{hashAlgorithm}(payload). Дэмжигдээгүй hash-д <see cref="EidValidationException"/>.</summary>
    public static byte[] V2Digest(AcspV2Params p, string hashAlgorithm) =>
        EidCrypto.Hash(hashAlgorithm, BuildV2Payload(p));
}
