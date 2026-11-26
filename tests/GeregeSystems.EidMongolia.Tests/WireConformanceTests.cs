using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// Нэг wire вектор: SDK-ийн нэг дуудлага (<see cref="Op"/> + <see cref="Args"/>) → хүлээгдэж буй HTTP хүсэлт (method, зам,
/// биеийн JSON — утгаар тулгана) + хиймэл хариу. Go/TS тестээс гараар порт хийсэн .NET-ийн нэмэлт кейсүүд; cross-SDK
/// корпусын wire векторууд <see cref="ConformanceTests.Wire"/>-д.
/// </summary>
public sealed record WireCase(string Name, string Source, string Op, string Args, string Method, string Path, string? Body,
    int Status, string Response)
{
    public override string ToString() => Name;
}

public class WireConformanceTests
{
    private static JsonSerializerOptions J => EidHttp.Json;

    private static T Arg<T>(JsonElement a, string name) => a.TryGetProperty(name, out var v) ? v.Deserialize<T>(J)! : default!;

    /// <summary>Op → SDK дуудлага. Corpus-ийн op нэр Go/TS-ийн method нэр (жижиг үсгээр эхэлсэн).</summary>
    private static readonly Dictionary<string, Func<EidClient, JsonElement, Task>> Ops = new(StringComparer.Ordinal)
    {
        ["auth.notificationByEtsi"] = (c, a) => c.Auth.NotificationByEtsiAsync(Arg<string>(a, "id"), Arg<Interaction[]>(a, "interactions"), Arg<AuthOptions?>(a, "options")),
        ["auth.notificationByDocument"] = (c, a) => c.Auth.NotificationByDocumentAsync(Arg<string>(a, "documentNumber"), Arg<Interaction[]>(a, "interactions"), Arg<AuthOptions?>(a, "options")),
        ["auth.deviceLinkAnonymous"] = (c, a) => c.Auth.DeviceLinkAnonymousAsync(Arg<Interaction[]>(a, "interactions"), Arg<AuthOptions?>(a, "options")),
        ["auth.deviceLinkByEtsi"] = (c, a) => c.Auth.DeviceLinkByEtsiAsync(Arg<string>(a, "id"), Arg<Interaction[]>(a, "interactions"), Arg<AuthOptions?>(a, "options")),
        ["sign.digestByEtsi"] = (c, a) => c.Sign.DigestByEtsiAsync(Arg<string>(a, "id"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.digestByDocument"] = (c, a) => c.Sign.DigestByDocumentAsync(Arg<string>(a, "documentNumber"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.textByEtsi"] = (c, a) => c.Sign.TextByEtsiAsync(Arg<string>(a, "id"), Arg<string>(a, "text"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.deviceLinkByEtsi"] = (c, a) => c.Sign.DeviceLinkByEtsiAsync(Arg<string>(a, "id"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.deviceLinkByDocument"] = (c, a) => c.Sign.DeviceLinkByDocumentAsync(Arg<string>(a, "documentNumber"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.digestForSigner"] = (c, a) => c.Sign.DigestForSignerAsync(Arg<SignerRef>(a, "signer"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.deviceLinkForSigner"] = (c, a) => c.Sign.DeviceLinkForSignerAsync(Arg<SignerRef>(a, "signer"), Arg<string>(a, "digest"), Arg<Interaction[]>(a, "interactions"), Arg<SignOptions?>(a, "options")),
        ["sign.certificateChoiceByEtsi"] = (c, a) => c.Sign.CertificateChoiceByEtsiAsync(Arg<string>(a, "id"), Arg<CertChoiceOptions?>(a, "options")),
        ["sign.certificateChoiceDeviceLink"] = (c, a) => c.Sign.CertificateChoiceDeviceLinkAsync(Arg<CertChoiceOptions?>(a, "options")),
        ["session.poll"] = (c, a) => c.Session.PollAsync(Arg<string>(a, "sessionId"), TimeSpan.FromMilliseconds(Arg<int>(a, "serverPollMs"))),
        ["pdf.registerSignature"] = (c, a) => c.Pdf.RegisterSignatureAsync(Arg<PdfSignatureRegistration>(a, "registration")),
    };

    private const string Push = "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"90177\"}}";
    private const string Ix = "[{\"type\":\"displayTextAndPIN\",\"displayText60\":\"Нэвтрэх\"}]";
    private const string IxB64 = AuthTests.LoginInteractionsB64;
    private const string D = "LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=";

    private static string AuthBody(string extra = "", string level = "QUALIFIED", string alg = "rsassa-pss", string hash = "SHA-512") =>
        "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"" + level + "\"," +
        "\"signatureProtocol\":\"ACSP_V2\",\"signatureProtocolParameters\":{\"rpChallenge\":\"" + Rig.Challenge + "\"," +
        "\"signatureAlgorithm\":\"" + alg + "\",\"signatureAlgorithmParameters\":{\"hashAlgorithm\":\"" + hash + "\"}}," +
        "\"interactions\":\"" + IxB64 + "\"" + extra + "}";

    private static string SignBody(string extra = "", string alg = "rsassa-pss", string interactions = IxB64) =>
        "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"QUALIFIED\"," +
        "\"signatureProtocol\":\"RAW_DIGEST_SIGNATURE\",\"signatureProtocolParameters\":{\"digest\":\"" + D + "\"," +
        "\"signatureAlgorithm\":\"" + alg + "\",\"signatureAlgorithmParameters\":{\"hashAlgorithm\":\"SHA-256\"}}," +
        "\"interactions\":\"" + interactions + "\"" + extra + "}";

    /// <summary>Go/TS тестийн кейсүүдээс гараар порт хийсэн wire векторууд (Source = эх тест).</summary>
    internal static IEnumerable<WireCase> PortedCases()
    {
        WireCase W(string name, string source, string op, string args, string method, string path, string? body, string response = Push) =>
            new(name, source, op, args, method, path, body, 200, response);
        yield return W("auth-push-etsi-callback-obo", "go client_test.go TestAuth_RequestBodyAndParse", "auth.notificationByEtsi",
            "{\"id\":\"PNOMN-12345678\",\"interactions\":" + Ix + ",\"options\":{\"callbackUrl\":\" https://rp.test/cb \",\"onBehalfOf\":\" NTRMN-6235972 \"}}",
            "POST", "/authentication/notification/etsi/PNOMN-12345678",
            AuthBody(",\"initialCallbackUrl\":\"https://rp.test/cb\",\"onBehalfOf\":\"NTRMN-6235972\""));
        yield return W("auth-push-document-options", "ts auth.ts baseBody (certificateLevel/algorithm options)", "auth.notificationByDocument",
            "{\"documentNumber\":\"PNOMN-1-MOCK-Q\",\"interactions\":" + Ix + ",\"options\":{\"certificateLevel\":\"QSCD\",\"signatureAlgorithm\":\"sha256WithRSAEncryption\",\"hashAlgorithm\":\"SHA-256\"}}",
            "POST", "/authentication/notification/document/PNOMN-1-MOCK-Q", AuthBody(level: "QSCD", alg: "sha256WithRSAEncryption", hash: "SHA-256"));
        yield return W("auth-devicelink-anonymous", "go client_test.go TestAuth_RequestBodyAndParse", "auth.deviceLinkAnonymous",
            "{\"interactions\":" + Ix + "}", "POST", "/authentication/device-link/anonymous", AuthBody(), SignTests.DlReply);
        yield return W("auth-devicelink-etsi", "ts auth.ts deviceLinkByEtsi", "auth.deviceLinkByEtsi",
            "{\"id\":\"PNOMN-1\",\"interactions\":" + Ix + "}", "POST", "/authentication/device-link/etsi/PNOMN-1", AuthBody(), SignTests.DlReply);
        yield return W("sign-push-etsi-obo", "go client_test.go TestSign_Body", "sign.textByEtsi",
            "{\"id\":\"PNOMN-1\",\"text\":\"x\",\"options\":{\"onBehalfOf\":\"NTRMN-6235972\"}}",
            "POST", "/signature/notification/etsi/PNOMN-1", SignBody(",\"onBehalfOf\":\"NTRMN-6235972\"", interactions: "W10="));
        yield return W("sign-push-document", "go sign.go DigestByDocument", "sign.digestByDocument",
            "{\"documentNumber\":\"DOC-1\",\"digest\":\"" + D + "\",\"interactions\":" + Ix + ",\"options\":{\"fileName\":\" a.pdf \"}}",
            "POST", "/signature/notification/document/DOC-1", SignBody(",\"fileName\":\"a.pdf\""));
        yield return W("sign-devicelink-etsi", "go sign_gaps_test.go TestSignDeviceLink", "sign.deviceLinkByEtsi",
            "{\"id\":\"PNOMN-12345678\",\"digest\":\"" + D + "\",\"interactions\":" + Ix + ",\"options\":{\"callbackUrl\":\" https://rp.example.mn/cb \",\"fileName\":\"Гэрээ.pdf\",\"onBehalfOf\":\"NTRMN-6235972\",\"signatureAlgorithm\":\"sha256WithRSAEncryption\"}}",
            "POST", "/signature/device-link/etsi/PNOMN-12345678",
            SignBody(",\"initialCallbackUrl\":\"https://rp.example.mn/cb\",\"fileName\":\"Гэрээ.pdf\",\"onBehalfOf\":\"NTRMN-6235972\"", alg: "sha256WithRSAEncryption"),
            SignTests.DlReply);
        yield return W("sign-devicelink-document", "go sign_gaps_test.go TestSignDeviceLink", "sign.deviceLinkByDocument",
            "{\"documentNumber\":\"PNOMN-12345678-MOCK-Q\",\"digest\":\"" + D + "\",\"interactions\":" + Ix + "}",
            "POST", "/signature/device-link/document/PNOMN-12345678-MOCK-Q", SignBody(), SignTests.DlReply);
        yield return W("sign-for-signer-linked", "go sign_gaps_test.go TestDigestForSigner", "sign.digestForSigner",
            "{\"signer\":{\"documentNumber\":\"PNOMN-1-ABCD-Q\",\"certChoiceSessionId\":\"cc-1\"},\"digest\":\"" + D + "\",\"interactions\":" + Ix + "}",
            "POST", "/signature/notification/linked/PNOMN-1-ABCD-Q", SignBody(",\"linkedSessionID\":\"cc-1\"", alg: "sha256WithRSAEncryption"));
        yield return W("sign-for-signer-document", "go sign_gaps_test.go TestDigestForSigner", "sign.digestForSigner",
            "{\"signer\":{\"documentNumber\":\"DOC-1\"},\"digest\":\"" + D + "\",\"interactions\":" + Ix + "}",
            "POST", "/signature/notification/document/DOC-1", SignBody(alg: "sha256WithRSAEncryption"));
        yield return W("sign-devicelink-for-signer", "go sign_gaps_test.go TestDigestForSigner", "sign.deviceLinkForSigner",
            "{\"signer\":{\"documentNumber\":\"PNOMN-1-ABCD-Q\",\"certChoiceSessionId\":\"cc-1\"},\"digest\":\"" + D + "\",\"interactions\":" + Ix + "}",
            "POST", "/signature/device-link/document/PNOMN-1-ABCD-Q", SignBody(alg: "sha256WithRSAEncryption"), SignTests.DlReply);
        yield return W("certchoice-etsi", "go sign_gaps_test.go TestCertificateChoice", "sign.certificateChoiceByEtsi",
            "{\"id\":\"PNOMN-12345678\",\"options\":{\"callbackUrl\":\"https://rp.example.mn/cb\"}}",
            "POST", "/signature/certificate-choice/notification/etsi/PNOMN-12345678",
            "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"QUALIFIED\"}");
        yield return W("certchoice-devicelink-callback", "go certchoice_callback_test.go TestCertificateChoiceDeviceLink_Callback", "sign.certificateChoiceDeviceLink",
            "{\"options\":{\"certificateLevel\":\"QSCD\",\"callbackUrl\":\" https://rp.example.mn/auth/eid/callback?value=abc \"}}",
            "POST", "/signature/certificate-choice/device-link/anonymous",
            "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\",\"certificateLevel\":\"QSCD\",\"initialCallbackUrl\":\"https://rp.example.mn/auth/eid/callback?value=abc\"}",
            SignTests.DlReply);
        yield return W("session-poll", "go client_test.go TestSession_PollAndWait", "session.poll",
            "{\"sessionId\":\"abc/def\",\"serverPollMs\":2000}", "GET", "/session/abc%2Fdef?timeoutMs=2000", null, "{\"state\":\"RUNNING\"}");
        yield return W("pdf-register-phone", "go pdfregister_test.go TestRegisterSignature", "pdf.registerSignature",
            "{\"registration\":{\"docID\":\"d\",\"revIndex\":1,\"medium\":\"phone\",\"sessionID\":\"s\",\"cms\":\"MAE=\",\"fileName\":\"a.pdf\",\"inSha256\":\"in\",\"pageSha256\":\"pg\",\"sigRevSha256\":\"sr\",\"outSha256\":\"out\",\"signerEtsi\":\"PNOMN-1\"}}",
            "POST", "/pdf/signatures",
            "{\"docID\":\"d\",\"revIndex\":1,\"medium\":\"phone\",\"sessionID\":\"s\",\"cms\":\"MAE=\",\"fileName\":\"a.pdf\",\"inSha256\":\"in\",\"pageSha256\":\"pg\",\"sigRevSha256\":\"sr\",\"outSha256\":\"out\",\"signerEtsi\":\"PNOMN-1\"}",
            "{\"docID\":\"d\",\"revIndex\":1,\"registeredAt\":\"x\",\"verifyUrl\":\"v\"}");
    }

    public static IEnumerable<object[]> PortedNames() => PortedCases().Select(c => new object[] { c.Name });

    [Theory]
    [MemberData(nameof(PortedNames))]
    public Task PortedWireCase(string name) => Run(PortedCases().Single(c => c.Name == name));

    [Fact]
    public void PortedCaseNamesAreUnique()
    {
        var names = PortedCases().Select(c => c.Name).ToList();
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    private static async Task Run(WireCase c)
    {
        Assert.True(Ops.TryGetValue(c.Op, out var op), c.Name + ": op " + c.Op + "-ийн driver алга");
        var (client, h, _) = Rig.Create(_ => Rig.Json(c.Status, c.Response));
        using var args = JsonDocument.Parse(c.Args);
        await op!(client, args.RootElement);
        var r = Assert.Single(h.Requests);
        Assert.Equal(c.Method, r.Method);
        Assert.Equal(c.Path, r.PathAndQuery);
        if (c.Body is null)
        {
            Assert.Null(r.Body);
        }
        else
        {
            JsonAssert.Equivalent(c.Body, r.Json(), c.Name + " (" + c.Source + ")");
        }
    }
}
