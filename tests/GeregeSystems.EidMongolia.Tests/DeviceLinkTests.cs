using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// testdata/devicelink_golden.json — ca-eidmongolia-mn server/internal/crypto/testdata/devicelink_golden.json-ийн ЗАСВАРГҮЙ
/// хуулбар (Go testdata, TS test/fixtures-тэй байт-ижил). Сервер, iOS, Android, TS, Go, .NET бүгд байт-ижил гаргана.
/// </summary>
public class DeviceLinkTests
{
    /// <summary>
    /// Canonical файлын sha256 (Go devicelink_test.go-тэй ижил). CA векторыг шинэчилбэл файлыг ЗАСВАРГҮЙ хуулж, энэ утгыг
    /// хамт шинэчилнэ.
    /// </summary>
    private const string GoldenSha256 = "56eb99061af2059d7604c2eb0b8b5d178dd4b789cbfc5db30b03aca99f26a716";

    private static readonly DateTimeOffset ReceivedAt = DateTimeOffset.FromUnixTimeMilliseconds(1_790_000_000_123);

    private static string GoldenPath => Path.Combine(AppContext.BaseDirectory, "testdata", "devicelink_golden.json");

    private static JsonElement Golden()
    {
        using var d = JsonDocument.Parse(File.ReadAllBytes(GoldenPath));
        return d.RootElement.Clone();
    }

    private static string S(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    private static DeviceLinkInput Input(JsonElement g, string name, TimeSpan extra)
    {
        foreach (var v in g.GetProperty("vectors").EnumerateArray())
        {
            if (S(v, "name") != name)
            {
                continue;
            }
            var i = v.GetProperty("input");
            var e = i.TryGetProperty("elapsedSeconds", out var es) && es.ValueKind == JsonValueKind.Number ? es.GetInt64() : 0;
            var sessionType = S(i, "sessionType");
            var cd = S(i, "rpChallengeOrDigest");
            return new DeviceLinkInput
            {
                DeviceLinkBase = S(i, "deviceLinkBase"),
                DeviceLinkType = S(i, "deviceLinkType"),
                SessionToken = S(i, "sessionToken"),
                SessionSecret = S(i, "sessionSecret"),
                SessionType = sessionType,
                Lang = S(i, "lang"),
                ReceivedAt = ReceivedAt,
                Now = ReceivedAt + TimeSpan.FromSeconds(e) + extra,
                RelyingPartyName = S(i, "relyingPartyName"),
                Interactions = S(i, "interactions"),
                InitialCallbackUrl = S(i, "initialCallbackUrl"),
                SchemeName = S(i, "schemeName"),
                BrokeredRpName = S(i, "brokeredRpName"),
                RpChallenge = sessionType == DeviceLinkSessionTypes.Auth ? cd : null,
                Digest = sessionType == DeviceLinkSessionTypes.Sign ? cd : null,
            };
        }
        throw new InvalidOperationException("golden вектор алга: " + name);
    }

    [Fact]
    public void GoldenFileIsPinned()
    {
        var got = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(GoldenPath))).ToLowerInvariant();
        Assert.Equal(GoldenSha256, got);
    }

    [Fact]
    public void BuildMatchesGoldenVectors()
    {
        var g = Golden();
        var vectors = g.GetProperty("vectors");
        Assert.Equal(15, vectors.GetArrayLength());
        var produced = new List<string>();
        foreach (var v in vectors.EnumerateArray())
        {
            var name = S(v, "name");
            var want = S(v, "deviceLink");
            foreach (var extra in new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(999) })
            {
                var got = DeviceLink.Build(Input(g, name, extra));
                Assert.True(want == got, name + " (+" + extra + ")\n got " + got + "\nwant " + want);
                produced.Add(got);
            }
            Assert.EndsWith("&authCode=" + S(v, "authCode"), want, StringComparison.Ordinal);
        }
        foreach (var bad in g.GetProperty("invalid").EnumerateArray())
        {
            Assert.DoesNotContain(S(bad, "link"), produced);
        }
    }

    [Fact]
    public void CallbackOnlyForSameDevice()
    {
        var g = Golden();
        var qr = Input(g, "eid-qr-auth-e0", TimeSpan.Zero);
        Assert.Equal(DeviceLink.Build(qr), DeviceLink.Build(qr with { InitialCallbackUrl = "" }));
        var w = Input(g, "eid-web2app-auth", TimeSpan.Zero);
        Assert.NotEqual(DeviceLink.Build(w), DeviceLink.Build(w with { InitialCallbackUrl = "https://rp.example.mn/other" }));
    }

    [Fact]
    public void ElapsedIsFlooredAndNeverNegative()
    {
        var qr = Input(Golden(), "eid-qr-auth-e7", TimeSpan.Zero);
        Assert.Contains("&elapsedSeconds=7&", DeviceLink.Build(qr with { Now = ReceivedAt + TimeSpan.FromMilliseconds(7999) }), StringComparison.Ordinal);
        Assert.Contains("&elapsedSeconds=0&", DeviceLink.Build(qr with { Now = ReceivedAt - TimeSpan.FromSeconds(3) }), StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> InvalidCases()
    {
        var g = Golden();
        var qr = Input(g, "eid-qr-auth-e0", TimeSpan.Zero);
        var w = Input(g, "eid-web2app-auth", TimeSpan.Zero);
        yield return new object[] { "http base", qr with { DeviceLinkBase = "http://ca.eidmongolia.mn/dl" } };
        yield return new object[] { "scheme base", qr with { DeviceLinkBase = "eidmongolia://approve" } };
        yield return new object[] { "base query", qr with { DeviceLinkBase = "https://ca.eidmongolia.mn/dl?x=1" } };
        yield return new object[] { "base empty", qr with { DeviceLinkBase = "" } };
        yield return new object[] { "type", qr with { DeviceLinkType = "Notification" } };
        yield return new object[] { "sessionType", qr with { SessionType = "login" } };
        yield return new object[] { "token &", qr with { SessionToken = "abc&vc=1" } };
        yield return new object[] { "token newline", qr with { SessionToken = "abc\n" } };
        yield return new object[] { "token empty", qr with { SessionToken = "" } };
        yield return new object[] { "lang 2", qr with { Lang = "mn" } };
        yield return new object[] { "lang upper", qr with { Lang = "MON" } };
        yield return new object[] { "lang newline", qr with { Lang = "mon\n" } };
        yield return new object[] { "secret url", qr with { SessionSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" } };
        yield return new object[] { "secret empty", qr with { SessionSecret = "" } };
        yield return new object[] { "auth no challenge", qr with { RpChallenge = "" } };
        yield return new object[] { "sign no digest", qr with { SessionType = DeviceLinkSessionTypes.Sign, RpChallenge = "" } };
        yield return new object[] { "cert challenge", qr with { SessionType = DeviceLinkSessionTypes.Cert } };
        yield return new object[] { "QR no receivedAt", qr with { ReceivedAt = null } };
        yield return new object[] { "Web2App no callback", w with { InitialCallbackUrl = "" } };
        yield return new object[] { "App2App no callback", w with { DeviceLinkType = DeviceLinkTypes.App2App, InitialCallbackUrl = null } };
    }

    [Theory]
    [MemberData(nameof(InvalidCases))]
    public void BuildRejectsInvalidInput(string name, DeviceLinkInput input)
    {
        Assert.False(string.IsNullOrEmpty(name));
        Assert.Throws<EidDeviceLinkException>(() => DeviceLink.Build(input));
    }

    [Fact]
    public void InputOfSessionUsesStoredContext()
    {
        var g = Golden();
        var w = Input(g, "eid-web2app-auth", TimeSpan.Zero);
        var s = new DeviceLinkSession
        {
            SessionId = "s1",
            SessionToken = w.SessionToken,
            SessionSecret = w.SessionSecret,
            DeviceLinkBase = w.DeviceLinkBase,
            ReceivedAt = ReceivedAt,
            Acsp = new AcspContext
            {
                RpChallenge = w.RpChallenge!,
                RelyingPartyName = w.RelyingPartyName,
                Interactions = w.Interactions,
                InitialCallbackUrl = w.InitialCallbackUrl!,
            },
        };
        var input = DeviceLink.InputOf(s, DeviceLinkTypes.Web2App, w.Lang) with { SchemeName = w.SchemeName, BrokeredRpName = w.BrokeredRpName };
        Assert.Equal(DeviceLink.Build(w), DeviceLink.Build(input));
        Assert.Throws<EidDeviceLinkException>(() => DeviceLink.Build(DeviceLink.InputOf(s with { ReceivedAt = default }, DeviceLinkTypes.Qr, "mon")));
    }

    [Fact]
    public async Task TickQrYieldsFreshLinks()
    {
        var input = Input(Golden(), "eid-qr-auth-e0", TimeSpan.Zero) with { ReceivedAt = DateTimeOffset.UtcNow, Now = null };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var links = new List<string>();
        await foreach (var l in DeviceLink.TickQrAsync(input, TimeSpan.FromMilliseconds(5), cts.Token))
        {
            links.Add(l);
            if (links.Count == 3)
            {
                break;
            }
        }
        Assert.Equal(3, links.Count);
        Assert.Contains("deviceLinkType=QR&elapsedSeconds=0&", links[0], StringComparison.Ordinal);

        await Assert.ThrowsAsync<EidDeviceLinkException>(async () =>
        {
            await foreach (var _ in DeviceLink.TickQrAsync(input with { SessionSecret = "" }, TimeSpan.Zero, cts.Token))
            {
            }
        });
    }
}
