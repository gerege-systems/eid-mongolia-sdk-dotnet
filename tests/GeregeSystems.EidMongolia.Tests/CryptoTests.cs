using System;
using System.Text;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class CryptoTests
{
    /// <summary>
    /// Smart-ID RP-API v3 docs (signature_protocols.html)-ийн албан ёсны вектор. CA сервер (acsp_test.go), iOS, Android,
    /// TS, Go SDK бүгд ЭНЭ digest-ийг гаргана (Go crypto_test.go smartIDVector).
    /// </summary>
    private static readonly AcspV2Params SkVector = new()
    {
        ServerRandom = "MTlop6EXCrQ6FOErcKjxUhbV",
        RpChallenge = "GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==",
        UserChallenge = "GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00",
        RelyingPartyName = "DEMO",
        BrokeredRpName = "Example RP",
        Interactions = "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d",
        InteractionTypeUsed = "confirmationMessage",
        InitialCallbackUrl = "https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ",
        FlowType = "Web2App",
    };

    [Fact]
    public void AcspV2MatchesSmartIdVector()
    {
        var d = Acsp.V2Digest(SkVector, HashAlgorithms.Sha512);
        Assert.Equal("pKOjbNl/5Fy8NfrFqsj6pSn8W8O+Ik8rM33QSsbyD3J9qDJvEm90SboUciuY4wHGWa0Pnq8BgT3NJKmJiUDfKg==", Convert.ToBase64String(d));

        var s = Encoding.UTF8.GetString(Acsp.BuildV2Payload(SkVector with { BrokeredRpName = "", InitialCallbackUrl = "" }));
        Assert.StartsWith("smart-id|ACSP_V2|MTlop6EXCrQ6FOErcKjxUhbV|", s, StringComparison.Ordinal);
        Assert.Contains("|REVNTw==||", s, StringComparison.Ordinal);
        Assert.EndsWith("|confirmationMessage||Web2App", s, StringComparison.Ordinal);

        Assert.Throws<EidValidationException>(() => Acsp.V2Digest(SkVector, "MD5"));
        Assert.Equal(48, Acsp.V2Digest(SkVector, HashAlgorithms.Sha384).Length);
        Assert.Equal(32, Acsp.V2Digest(SkVector, HashAlgorithms.Sha256).Length);
    }

    private static string Json(params Interaction[] items) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(EidCrypto.InteractionsToBase64(items)));

    [Fact]
    public void InteractionsMatchSmartIdVector()
    {
        var got = EidCrypto.InteractionsToBase64(new[]
        {
            new Interaction { Type = "confirmationMessage", DisplayText200 = "Longer description of the transaction context" },
            new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Short description of the transaction context" },
        });
        Assert.Equal(SkVector.Interactions, got);
    }

    [Fact]
    public void InteractionsKeepHtmlAndCyrillicRaw()
    {
        // JSON.stringify-тай ижил: HTML escape хийхгүй, кирилл UTF-8 хэвээр (Go TestInteractionsToBase64_SmartIDVector).
        Assert.Equal("[{\"type\":\"displayTextAndPIN\",\"displayText60\":\"Банк <А&Б>\"}]",
            Json(new Interaction { Type = "displayTextAndPIN", DisplayText60 = "Банк <А&Б>" }));
        var raw = Convert.FromBase64String(EidCrypto.InteractionsToBase64(new[] { new Interaction { Type = "x", DisplayText60 = "Б" } }));
        Assert.Equal(new byte[] { 0xD0, 0x91 }, raw.AsSpan(30, 2).ToArray());
    }

    [Fact]
    public void InteractionsKeepLineSeparatorsRaw()
    {
        // Go TestInteractionsToBase64_LineSeparators: U+2028/2029 түүхийгээр, «\» → «\\».
        var got = Json(new Interaction { Type = "x", DisplayText60 = "a b c \\u2028 \\ " });
        Assert.Equal("[{\"type\":\"x\",\"displayText60\":\"a b c \\\\u2028 \\\\ \"}]", got);
    }

    [Fact]
    public void InteractionsEscapeLikeJsonStringify()
    {
        var input = "\"\\\b\f\n\r\t\u0000\u0001\u001f\u007f/";
        var want = "[{\"type\":\"x\",\"displayText60\":\"" +
            "\\\"" + "\\\\" + "\\b" + "\\f" + "\\n" + "\\r" + "\\t" + "\\u0000" + "\\u0001" + "\\u001f" + "\u007f" + "/" +
            "\"}]";
        Assert.Equal(want, Json(new Interaction { Type = "x", DisplayText60 = input }));

        // Ганц surrogate → \uXXXX (жижиг hex, well-formed JSON.stringify); бүтэн хос → түүхий UTF-8.
        Assert.Equal("[{\"type\":\"x\",\"displayText60\":\"a\\ud800b\\udc00\"}]",
            Json(new Interaction { Type = "x", DisplayText60 = "a\ud800b\udc00" }));
        var emoji = Convert.FromBase64String(EidCrypto.InteractionsToBase64(new[] { new Interaction { Type = "😀" } }));
        Assert.Equal(new byte[] { 0xF0, 0x9F, 0x98, 0x80 }, emoji.AsSpan(10, 4).ToArray());
    }

    [Fact]
    public void InteractionsOmitEmptyTextAndKeepFieldOrder()
    {
        Assert.Equal("W10=", EidCrypto.InteractionsToBase64(null));
        Assert.Equal("W10=", EidCrypto.InteractionsToBase64(Array.Empty<Interaction>()));
        Assert.Equal("[{\"type\":\"x\"}]", Json(new Interaction { Type = "x", DisplayText60 = "", DisplayText200 = null }));
        Assert.Equal("[{\"type\":\"x\",\"displayText60\":\"a\",\"displayText200\":\"b\"}]",
            Json(new Interaction { DisplayText200 = "b", DisplayText60 = "a", Type = "x" }));
    }

    [Fact]
    public void Sha256AndChallenge()
    {
        Assert.Equal("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", EidCrypto.Sha256Base64("abc"u8));
        var c = EidCrypto.RandomChallenge();
        Assert.Equal(64, Convert.FromBase64String(c).Length);
        Assert.NotEqual(c, EidCrypto.RandomChallenge(0));
        Assert.Equal(32, Convert.FromBase64String(EidCrypto.RandomChallenge(32)).Length);
    }

    [Fact]
    public void SessionSecretDigestMatchesGo()
    {
        // Go certchoice_callback_test.go TestSessionSecretDigest.
        const string secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        const string want = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0";
        Assert.Equal(want, EidCrypto.SessionSecretDigest(secret));
        Assert.Equal(want, EidCrypto.SessionSecretDigest("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));
        Assert.True(EidCrypto.VerifySessionSecretDigest(want, secret));
        Assert.False(EidCrypto.VerifySessionSecretDigest("Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN1", secret));
        Assert.False(EidCrypto.VerifySessionSecretDigest("", secret));
        Assert.False(EidCrypto.VerifySessionSecretDigest(want[..10], secret));
        Assert.False(EidCrypto.VerifySessionSecretDigest(want, ""));
        Assert.False(EidCrypto.VerifySessionSecretDigest(want, "***"));
        Assert.Throws<EidDeviceLinkException>(() => EidCrypto.SessionSecretDigest("***"));
        Assert.Throws<EidDeviceLinkException>(() => EidCrypto.SessionSecretDigest(" "));
    }

    [Fact]
    public void UserChallengeOfIsBase64UrlSha256()
    {
        Assert.Equal("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", EidCrypto.UserChallengeOf("abc"));
        Assert.Matches("^[A-Za-z0-9_-]{43}$", EidCrypto.UserChallengeOf("dGVzdC12ZXJpZmllci0zMi1ieXRlcy14eHh4eHh4eHg"));
    }

    [Theory]
    [InlineData("AAEC", true)]
    [InlineData("AAE=", true)]
    [InlineData("AA==", true)]
    [InlineData("AAE", false)]
    [InlineData("A===", false)]
    [InlineData("AA=A", false)]
    [InlineData("AA E", false)]
    [InlineData("AA\nE", false)]
    [InlineData("-_8=", false)]
    public void StrictStdBase64(string s, bool ok)
    {
        Assert.Equal(ok, B64.TryDecodeStd(s, out _));
    }
}
