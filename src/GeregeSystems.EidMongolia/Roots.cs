using System;
using System.Collections.Generic;
using System.IO;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Нийтийн eID PKI-ийн SDK-д суусан гэрчилгээнүүд (Go <c>roots.go</c> <c>NationalRootCAPEM</c> /
/// <c>CitizenIntermediatesPEM</c>, TS <c>NATIONAL_ROOT_CA_PEM</c> / <c>CITIZEN_INTERMEDIATES_PEM</c>-тэй байт-ижил).
/// Production-д <c>TrustConfig.TrustAnchorsPem = new[] { EidTrust.NationalRootCaPem }</c>.
/// </summary>
public static class EidTrust
{
    /// <summary>
    /// eID Mongolia Issuing CA (04)-ийн Subject Key Identifier: иргэний утасны болон USB токены AUTH/SIGN гэрчилгээг
    /// гаргадаг цорын ганц CA. <see cref="TrustConfig.AllowedIssuerSkis"/>-ийн анхдагч.
    /// </summary>
    public const string CitizenIssuingCaSki = "b8a37f2c64ad677912db7d9e34f246358a2fb909";

    private static readonly Lazy<string[]> Pems = new(() => new[]
    {
        Load("01-mongolian-national-root-ca"),
        Load("02-mongolian-national-issuing-ca-mddc"),
        Load("03-gerege-issuing-ca"),
        Load("04-eid-mongolia-issuing-ca"),
    });

    private static readonly Lazy<IReadOnlyList<ParsedCert>> Parsed = new(() =>
    {
        var list = new List<ParsedCert>();
        foreach (var p in Pems.Value[1..])
        {
            list.AddRange(ParsedCert.ParsePem(p));
        }
        return list;
    });

    /// <summary>
    /// Mongolian National Root CA (01) — итгэлийн тулгуур. Нийтийн эх:
    /// https://ca.eidmongolia.mn/pki/mongolian-national-root-ca.cer. SHA-256 fingerprint
    /// CB:E7:F3:FE:1F:04:80:37:C2:15:DA:32:1E:58:CA:A4:F3:63:DE:9E:54:BB:C4:42:A3:BF:D6:2F:AD:83:44:82.
    /// </summary>
    public static string NationalRootCaPem => Pems.Value[0];

    /// <summary>
    /// Иргэний гэрчилгээний завсрын CA-ууд: 02 Mongolian National Issuing CA (MDDC) → 03 Gerege Issuing CA → 04 eID
    /// Mongolia Issuing CA (SKI = <see cref="CitizenIssuingCaSki"/>). RP-API хариунд гинж ирдэггүй —
    /// <see cref="TrustConfig.IntermediatesPem"/> null бол эдгээр.
    /// </summary>
    public static IReadOnlyList<string> CitizenIntermediatesPem => Array.AsReadOnly(Pems.Value[1..]);

    internal static IReadOnlyList<ParsedCert> CitizenIntermediates => Parsed.Value;

    private static string Load(string name)
    {
        using var s = typeof(EidTrust).Assembly.GetManifestResourceStream("eid.core." + name + ".pem")
                      ?? throw new InvalidOperationException("eid: шигтгэсэн гэрчилгээ алга: " + name);
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
