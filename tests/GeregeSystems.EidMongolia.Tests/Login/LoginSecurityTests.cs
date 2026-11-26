using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// Go <c>eidlogin/security_test.go</c>, <c>eidlogin_test.go</c> ба TS <c>login.test.ts</c>-ийн корпуст ороогүй аюулгүйн
/// тохиолдлууд: push floor (удирддаг цаг), бодит гарын үсэгтэй OK зам, нэг удаагийн амжилт / replay, cookie binding ба
/// session fixation, cross-site, decoy, цуцлалт, хязгаар, store-ийн дээд хэмжээ.
/// </summary>
public class LoginSecurityTests
{
    private const string IphoneChrome =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120.0 Mobile/15E148 Safari/604.1";

    private const string Verifier = "dGVzdC12ZXJpZmllci0zMi1ieXRlcy14eHh4eHh4eHg";

    private static Dictionary<string, string> H(params (string K, string V)[] kv) =>
        kv.ToDictionary(x => x.K, x => x.V, StringComparer.OrdinalIgnoreCase);

    // ---- бодит гарын үсэгтэй OK зам, нэг удаа ----

    [Fact]
    public async Task QrFlowSucceedsOnceThenExpired()
    {
        var e = LoginEnv.Create();
        var s = await e.StartQr();
        Assert.Equal(200, s.Code);
        Assert.Equal("expiresIn,mode,qr,vc", s.Keys());
        Assert.Equal("12345", s.Str("vc"));
        Assert.StartsWith("https://eid.example.test/dl?deviceLinkType=QR&elapsedSeconds=", s.Str("qr"));
        Assert.Equal("no-store", s.Raw.Header("Cache-Control"));
        Assert.False(e.Fake.LastStart!.ContainsKey("initialCallbackUrl"), "QR session-д callback илгээх ёсгүй");
        var cookie = s.LoginCookie();

        var p = await e.Status(cookie);
        Assert.Equal("PENDING", p.Str("state"));
        Assert.Contains("deviceLinkType=QR", p.Str("qr"));

        e.Fake.Set("OK", "QR", "");
        var ok = await e.Status(cookie);
        Assert.Equal("OK", ok.Str("state"));
        Assert.Equal("/dashboard", ok.Str("redirect"));
        Assert.Equal(FakeEid.Etsi, (string?)ok.Body!["data"]!["user"]);
        var id = Assert.Single(e.Ids);
        Assert.Equal("111949212017", id.CivilId);
        Assert.Equal(FlowTypes.Qr, id.FlowType);
        Assert.Equal("BAT", id.GivenName);
        Assert.Equal("DORJ", id.Surname);
        Assert.Equal("MN", id.Country);
        Assert.Equal(FakeEid.Sid, id.SessionId);
        Assert.Equal("doc-1", id.DocumentNumber);
        Assert.Equal(CertificateLevels.Qualified, id.CertificateLevel);
        Assert.Equal(Convert.ToBase64String(e.Fake.CertDer), id.CertificateDerB64);
        Assert.Equal("Бат", id.Person?.FirstName);
        // Анхдагч OCSP шалгагч: тестийн гэрчилгээнд AIA алга → хариугүй → soft-fail.
        Assert.Equal(RevocationStatus.Unchecked, id.Revocation);
        var cookies = ok.Raw.HeaderValues("Set-Cookie").ToList();
        Assert.Contains("app_session=s1; Path=/; HttpOnly", cookies);
        Assert.True(ok.ClearsCookie());
        Assert.Equal(EidLoginEventKinds.Success, e.Events[^1].Kind);
        Assert.Equal("unchecked", e.Events[^1].Meta["revocation"]);

        // Replay: дууссан оролдлогын cookie дахин хэрэглэгдэхгүй, OnSuccess нэг л удаа.
        var again = await e.Status(cookie);
        Assert.Equal("EXPIRED", again.Str("state"));
        Assert.Single(e.Ids);
    }

    [Fact]
    public async Task ConcurrentStatusCallsSucceedOnce()
    {
        var e = LoginEnv.Create();
        var cookie = (await e.StartQr()).LoginCookie();
        e.Fake.Set("OK", "QR", "");
        var all = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => e.Status(cookie)));
        Assert.Single(all, r => r.Str("state") == "OK");
        Assert.All(all, r => Assert.True(r.Str("state") is "OK" or "EXPIRED", r.Raw.Body));
        Assert.Single(e.Ids);
    }

    [Fact]
    public async Task PushFlowRateLimitAndPathEscaping()
    {
        var e = LoginEnv.Create();
        Assert.Equal(400, (await e.StartPush("abc")).Code);
        var s = await e.StartPush("уб 12345678");
        Assert.Equal(200, s.Code);
        Assert.Equal("54321", s.Str("vc"));
        Assert.Null(s.Body!["qr"]);
        Assert.Equal("/authentication/notification/etsi/" + Uri.EscapeDataString("УБ12345678"), e.Fake.LastPath);
        e.Fake.Set("OK", "Notification", "");
        var ok = await e.Status(s.LoginCookie());
        Assert.Equal("OK", ok.Str("state"));
        Assert.Equal(FlowTypes.Notification, Assert.Single(e.Ids).FlowType);
        await e.StartPush("УБ12345678");
        await e.StartPush("УБ12345678");
        var limited = await e.StartPush("УБ12345678");
        Assert.Equal(429, limited.Code);
        Assert.Equal("rate_limited", limited.Str("error"));
        Assert.Equal("60", limited.Raw.Header("Retry-After"));
    }

    [Fact]
    public async Task Web2AppFlowRequiresBoundBrowserAndVerifier()
    {
        var e = LoginEnv.Create();
        var s = await e.Do("GET", "/auth/eid/start?mode=web2app&lang=en", headers: H(("User-Agent", IphoneChrome)));
        Assert.Equal(302, s.Code);
        Assert.StartsWith("https://eid.example.test/dl?deviceLinkType=Web2App&sessionToken=tok_ABC-123&sessionType=auth&version=1.0&lang=eng&authCode=",
            s.Raw.Header("Location"));
        Assert.Equal("no-referrer", s.Raw.Header("Referrer-Policy"));
        Assert.Equal(LoginEnv.CallbackUrl + "?retScheme=googlechromes", (string?)e.Fake.LastStart!["initialCallbackUrl"]);
        var cookie = s.LoginCookie();
        e.Fake.Set("OK", "Web2App", Verifier);
        var w = await e.Status(cookie);
        Assert.Equal("WAIT_CALLBACK", w.Str("state"));
        Assert.Empty(e.Ids);

        var cb = "/auth/eid/callback?retScheme=googlechromes&sessionId=" + FakeEid.Sid + "&userChallengeVerifier=" + Verifier;
        // Өөр хөтөч (cookie-гүй) — verifier зөв ч хүлээн авахгүй (login CSRF).
        var other = await e.Do("GET", cb);
        Assert.Equal(303, other.Code);
        Assert.Equal("/login?eid_error=expired", other.Raw.Header("Location"));
        Assert.Empty(e.Ids);
        // Буруу verifier → VALIDATION.
        var bad = await e.Do("GET", cb.Replace(Verifier, "wrong-verifier"), headers: H(("Cookie", cookie)));
        Assert.Equal("/login?eid_error=VALIDATION", bad.Raw.Header("Location"));
        Assert.Empty(e.Ids);

        e = LoginEnv.Create();
        s = await e.Do("GET", "/auth/eid/start?mode=web2app", headers: H(("User-Agent", IphoneChrome)));
        cookie = s.LoginCookie();
        e.Fake.Set("OK", "Web2App", Verifier);
        var r = await e.Do("GET", cb, headers: H(("Cookie", cookie)));
        Assert.Equal(303, r.Code);
        Assert.Equal("/dashboard", r.Raw.Header("Location"));
        Assert.Equal("no-store", r.Raw.Header("Cache-Control"));
        Assert.Contains("app_session=s1; Path=/; HttpOnly", r.Raw.HeaderValues("Set-Cookie"));
        Assert.True(r.ClearsCookie());
        Assert.Equal(FlowTypes.Web2App, Assert.Single(e.Ids).FlowType);
        // Replay of a completed attempt.
        var replay = await e.Do("GET", cb, headers: H(("Cookie", cookie)));
        Assert.Equal("/login?eid_error=expired", replay.Raw.Header("Location"));
        Assert.Single(e.Ids);
    }

    [Fact]
    public async Task CallbackUnboundAndQrSessionViaCallback()
    {
        var e = LoginEnv.Create();
        var cookie = (await e.Do("GET", "/auth/eid/start?mode=web2app", headers: H(("User-Agent", IphoneChrome)))).LoginCookie();
        e.Fake.Set("OK", "Web2App", "v");
        foreach (var target in new[]
        {
            "/auth/eid/callback?sessionId=" + FakeEid.Sid,
            "/auth/eid/callback?sessionId=11111111-1111-4111-8111-111111111111&userChallengeVerifier=v",
            "/auth/eid/callback?sessionId=" + FakeEid.Sid.ToUpperInvariant() + "&userChallengeVerifier=v",
        })
        {
            var r = await e.Do("GET", target, headers: H(("Cookie", cookie)));
            Assert.Equal("/login?eid_error=unbound", r.Raw.Header("Location"));
        }
        Assert.Empty(e.Ids);
        Assert.All(e.Events, ev => Assert.Equal(EidLoginEventKinds.FlowRefused, ev.Kind));

        // QR-ээр эхэлсэн оролдлогыг callback-аар дуусгах боломжгүй.
        var q = LoginEnv.Create();
        var qc = (await q.StartQr()).LoginCookie();
        q.Fake.Set("OK", "Web2App", "v");
        var qr = await q.Do("GET", "/auth/eid/callback?sessionId=" + FakeEid.Sid + "&userChallengeVerifier=v", headers: H(("Cookie", qc)));
        Assert.Equal("/login?eid_error=unbound", qr.Raw.Header("Location"));
        Assert.Empty(q.Ids);
    }

    [Fact]
    public async Task FlowRelayAndTamperedSignatureFailValidation()
    {
        // QR-ээр эхэлсэн session-ийг Notification-аар зурсан (relay) → flowType таарахгүй.
        var e = LoginEnv.Create();
        var c = (await e.StartQr()).LoginCookie();
        e.Fake.Set("OK", "Notification", "");
        var r = await e.Status(c);
        Assert.Equal("FAILED", r.Str("state"));
        Assert.Equal("VALIDATION", r.Str("error"));
        Assert.True(r.ClearsCookie());
        Assert.Empty(e.Ids);

        e = LoginEnv.Create();
        c = (await e.StartQr()).LoginCookie();
        e.Fake.SetTamper(true);
        e.Fake.Set("OK", "QR", "");
        r = await e.Status(c);
        Assert.Equal("VALIDATION", r.Str("error"));
        Assert.Empty(e.Ids);
        var ev = Assert.Single(e.Events);
        Assert.Equal(EidLoginEventKinds.Unverified, ev.Kind);
        Assert.Equal("validation", ev.Meta["reason"]);
        // Дараагийн status — tx устсан.
        Assert.Equal("EXPIRED", (await e.Status(c)).Str("state"));
    }

    // ---- cookie binding, session fixation ----

    [Fact]
    public async Task StatusRequiresTheBindingCookie()
    {
        var e = LoginEnv.Create();
        var cookie = (await e.StartQr()).LoginCookie();
        var value = cookie["eid_login=".Length..];
        var forged = new[]
        {
            "",
            "eid_login=" + FakeEid.Sid,
            "eid_login=" + FakeEid.Sid + "." + new string('A', 43),
            cookie[..^1] + (cookie[^1] == 'x' ? "y" : "x"),
            "eid_login=" + FakeEid.Sid.ToUpperInvariant() + value[36..],
            cookie + ".extra",
            "other=" + value,
        };
        foreach (var c in forged)
        {
            var r = await e.Status(c);
            Assert.Equal("EXPIRED", r.Str("state"));
            Assert.True(r.ClearsCookie(), c);
        }
        // Жинхэнэ cookie хэвээр ажиллана (forged оролдлого устгаагүй).
        Assert.Equal("PENDING", (await e.Status(cookie)).Str("state"));
        // Олон cookie-ийн дунд байсан ч олдоно.
        Assert.Equal("PENDING", (await e.Status("a=b; " + cookie + "; c=d")).Str("state"));
    }

    [Fact]
    public async Task StartIgnoresAttackerSuppliedCookie()
    {
        // Session fixation: халдагч өөрийн оролдлогын cookie-г хохирогчид тавьсан ч start шинэ sid.binding гаргана; хуучин
        // binding шинэ оролдлогод хүрэхгүй.
        var e = LoginEnv.Create();
        var attacker = (await e.StartQr()).LoginCookie();
        var victim = await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("Cookie", attacker)));
        var vc = victim.LoginCookie();
        Assert.NotEqual(attacker, vc);
        Assert.Equal(attacker[..("eid_login=".Length + 36)], vc[..("eid_login=".Length + 36)]);
        // FakeEid ижил sessionID буцаадаг тул store-ийн бичлэгийг хохирогчийн оролдлого дарсан: халдагчийн binding хүчингүй.
        Assert.Equal("EXPIRED", (await e.Status(attacker)).Str("state"));
        Assert.Equal("PENDING", (await e.Status(vc)).Str("state"));
    }

    // ---- CSRF, method, body ----

    [Fact]
    public async Task CrossSiteAndRequestShapes()
    {
        var e = LoginEnv.Create();
        var cross = await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("Sec-Fetch-Site", "cross-site")));
        Assert.Equal(403, cross.Code);
        Assert.Equal("cross_site", cross.Str("error"));
        Assert.Empty(cross.Raw.HeaderValues("Set-Cookie"));
        Assert.Equal(403, (await e.Do("GET", "/auth/eid/start?mode=web2app", headers: H(("Sec-Fetch-Site", "cross-site")))).Code);
        foreach (var site in new[] { "same-origin", "same-site", "none" })
        {
            Assert.Equal(200, (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("Sec-Fetch-Site", site)))).Code);
        }
        Assert.Equal(415, (await e.Do("POST", "/auth/eid/start", "mode=qr", H(("Content-Type", "application/x-www-form-urlencoded")))).Code);
        Assert.Equal(415, (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("Content-Type", "text/plain")))).Code);
        Assert.Equal(200, (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("Content-Type", "Application/JSON; charset=utf-8")))).Code);
        Assert.Equal(405, (await e.Do("GET", "/auth/eid/start?mode=qr")).Code);
        Assert.Equal(405, (await e.Do("PUT", "/auth/eid/start", "{\"mode\":\"qr\"}")).Code);
        Assert.Equal(405, (await e.Do("POST", "/auth/eid/status", "{}")).Code);
        Assert.Equal(405, (await e.Do("POST", "/auth/eid/callback", "{}")).Code);
        var nf = await e.Do("GET", "/auth/eid/other");
        Assert.Equal(404, nf.Code);
        Assert.Equal("not_found", nf.Str("error"));
        Assert.Equal(400, (await e.Do("POST", "/auth/eid/start", "{\"mode\":")).Code);
        Assert.Equal("invalid_body", (await e.Do("POST", "/auth/eid/start", "[1]")).Str("error"));
        Assert.Equal("invalid_body", (await e.Do("POST", "/auth/eid/start", "{\"mode\":5}")).Str("error"));
        // Ганц surrogate (утга ба түлхүүрт) — GetString / TryGetProperty-ийн InvalidOperationException 500 болохгүй.
        foreach (var lone in new[] { "{\"mode\":\"\\udc00\"}", "{\"mode\":\"qr\",\"idCode\":\"\\ud800x\"}", "{\"\\udc00\":1,\"mode\":\"qr\"}" })
        {
            var r = await e.Do("POST", "/auth/eid/start", lone);
            Assert.True(r.Code is 400 or 200, lone + " → " + r.Code);
            if (r.Code == 400)
            {
                Assert.Equal("invalid_body", r.Str("error"));
            }
        }
        Assert.Equal("invalid_body", (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"\\udc00\"}")).Str("error"));
        Assert.Equal("invalid_mode", (await e.Do("POST", "/auth/eid/start", "null")).Str("error"));
        Assert.Equal("invalid_mode", (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"sms\"}")).Str("error"));
        var big = "{\"mode\":\"qr\",\"pad\":\"" + new string('x', EidLoginHandler.MaxBodyBytes) + "\"}";
        Assert.Equal("invalid_body", (await e.Do("POST", "/auth/eid/start", big)).Str("error"));
        // Бүтэн URL ба төгсгөлийн "/" — сүүлийн хэсгээр.
        Assert.Equal(200, (await e.Do("POST", "https://rp.example.test/auth/eid/start/", "{\"mode\":\"qr\"}")).Code);
    }

    // ---- decoy, push floor (удирддаг цаг) ----

    [Fact]
    public async Task PushDecoyIndistinguishableWithTimingFloor()
    {
        var e = LoginEnv.Create();
        var real = await e.StartPush("УБ12345678");
        e.Fake.SetRefuse("json400");
        var decoy = await e.StartPush("УБ87654321");
        Assert.Equal(200, real.Code);
        Assert.Equal(200, decoy.Code);
        Assert.Equal(real.Keys(), decoy.Keys());
        Assert.Equal("push", decoy.Str("mode"));
        Assert.Equal(real.Num("expiresIn"), decoy.Num("expiresIn"));
        Assert.Matches("^[0-9]{5}$", decoy.Str("vc"));
        Assert.Equal(real.MaxAge(), decoy.MaxAge());
        // Хоёулаа ижил доод хугацаанд (цаг зогссон: эхлэл = одоо → бүтэн 1 с).
        Assert.Equal(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1) }, e.Time.Sleeps);
        var rc = real.LoginCookie();
        var dc = decoy.LoginCookie();
        Assert.Matches("^eid_login=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.[A-Za-z0-9_-]{43}$", dc);

        // Status: хоёулаа PENDING, ижил талбарууд; decoy eID-ээс асуухгүй, Poll-ын хугацаанд барина.
        e.Time.ClearSleeps();
        var rp = await e.Status(rc);
        var dp = await e.Status(dc);
        Assert.Equal("PENDING", rp.Str("state"));
        Assert.Equal("PENDING", dp.Str("state"));
        Assert.Equal(rp.Keys(), dp.Keys());
        Assert.Equal(decoy.Str("vc"), dp.Str("vc"));
        Assert.Equal(new[] { TimeSpan.FromSeconds(1) }, e.Time.Sleeps);
        Assert.False(e.Fake.PolledOther);

        // TTL-ийн дараа EXPIRED (бодиттой ижил зам — хугацаа).
        e.Time.Now += TimeSpan.FromMinutes(3);
        Assert.Equal("EXPIRED", (await e.Status(dc)).Str("state"));

        Assert.Equal(new[] { EidLoginEventKinds.PushSent, EidLoginEventKinds.PushSent }, e.Kinds);
        Assert.False((bool)e.Events[0].Meta["decoy"]!);
        Assert.True((bool)e.Events[1].Meta["decoy"]!);
        var k0 = (string)e.Events[0].Meta["pushKey"]!;
        Assert.Matches("^[0-9a-f]{32}$", k0);
        Assert.NotEqual(k0, e.Events[1].Meta["pushKey"]);
        // Аудит ба логт регистрийн дугаар (PII) орохгүй.
        foreach (var ev in e.Events)
        {
            Assert.DoesNotContain(ev.Meta.Values, v => v is string str && (str.Contains("12345678") || str.Contains("87654321")));
        }
        Assert.DoesNotContain(e.Logs, l => (l.Message + l.Exception?.Message).Contains("87654321"));
    }

    [Fact]
    public async Task PushFloorCountsFromStartOfRequest()
    {
        var e = LoginEnv.Create(o => o.PushFloor = TimeSpan.FromSeconds(2));
        // eID-ийн round trip 300 мс (удирддаг цаг) → үлдсэн 1.7 с-ийг л хүлээнэ.
        e.Fake.OnRequest = req =>
        {
            if (req.RequestUri!.AbsolutePath.StartsWith("/authentication/notification/", StringComparison.Ordinal))
            {
                e.Time.Now += TimeSpan.FromMilliseconds(300);
            }
        };
        Assert.Equal(200, (await e.StartPush("УБ12345678")).Code);
        Assert.Equal(new[] { TimeSpan.FromMilliseconds(1700) }, e.Time.Sleeps);
        // QR-д floor хамаарахгүй; 400 ба хязгаарын 429-д ч мөн.
        e.Time.ClearSleeps();
        await e.StartQr();
        await e.StartPush("abc");
        Assert.Empty(e.Time.Sleeps);
    }

    [Fact]
    public async Task PushOutageIsNotDecoyButKeepsFloor()
    {
        foreach (var mode in new[] { "500", "proxy400", "401" })
        {
            var e = LoginEnv.Create();
            e.Fake.SetRefuse(mode);
            var r = await e.StartPush("УБ12345678");
            Assert.Equal(502, r.Code);
            Assert.Equal("eid_unavailable", r.Str("error"));
            Assert.Empty(r.Raw.HeaderValues("Set-Cookie"));
            Assert.Empty(e.Events);
            Assert.Equal(new[] { TimeSpan.FromSeconds(1) }, e.Time.Sleeps);
        }
        // eID-ийн 429 — хязгаар (push_limited), decoy биш.
        var l = LoginEnv.Create();
        l.Fake.SetRefuse("429");
        var lr = await l.StartPush("УБ12345678");
        Assert.Equal(429, lr.Code);
        Assert.Equal(new[] { EidLoginEventKinds.PushLimited }, l.Kinds);
    }

    [Fact]
    public async Task DecoyAndFloorOptOut()
    {
        var e = LoginEnv.Create(o =>
        {
            o.DisableDecoy = true;
            o.DisablePushFloor = true;
        });
        e.Fake.SetRefuse("json400");
        Assert.Equal(502, (await e.StartPush("УБ12345678")).Code);
        Assert.Empty(e.Time.Sleeps);
    }

    [Fact]
    public async Task DecoyIsRateLimitedToo()
    {
        var e = LoginEnv.Create();
        e.Fake.SetRefuse("json400");
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(200, (await e.StartPush("УБ12345678")).Code);
        }
        Assert.Equal(429, (await e.StartPush("уб1234 5678")).Code);
        Assert.Equal(new[] { EidLoginEventKinds.PushSent, EidLoginEventKinds.PushSent, EidLoginEventKinds.PushSent, EidLoginEventKinds.PushLimited }, e.Kinds);
        Assert.Null(e.Events[3].SessionId);
    }

    [Fact]
    public async Task PushTimeoutLooksLikeDecoy()
    {
        var e = LoginEnv.Create();
        var s = await e.StartPush("УБ12345678");
        e.Fake.Set("TIMEOUT", "", "");
        var r = await e.Status(s.LoginCookie());
        Assert.Equal("state", r.Keys());
        Assert.Equal("EXPIRED", r.Str("state"));
        Assert.Equal(new[] { EidLoginEventKinds.PushSent, EidLoginEventKinds.Expired }, e.Kinds);
    }

    [Fact]
    public async Task TtlFromDiscoveryAndCaExpiresAt()
    {
        var e = LoginEnv.Create();
        e.Fake.SetTtl(60, TimeSpan.FromSeconds(59.5));
        var real = await e.StartPush("УБ12345678");
        e.Fake.SetRefuse("json400");
        var decoy = await e.StartPush("УБ87654321");
        Assert.Equal(60, real.Num("expiresIn"));
        Assert.Equal(60, decoy.Num("expiresIn"));
        Assert.Equal("60", real.MaxAge());
        Assert.Equal("60", decoy.MaxAge());

        // Хуучин CA (discovery-д sessionTtl алга): бодит push-ийн expiresAt-аас ажигласныг дараагийн decoy авна.
        var old = LoginEnv.Create(o => o.Ttl = TimeSpan.FromMinutes(10));
        old.Fake.SetTtl(0, TimeSpan.FromSeconds(300));
        await old.StartPush("УБ12345678");
        old.Fake.SetRefuse("json400");
        var od = await old.StartPush("УБ87654321");
        Assert.InRange(od.Num("expiresIn")!.Value, 299, 301);

        // QR: CA-ийн expiresAt нь TTL-ээс эрт бол түүгээр.
        var q = LoginEnv.Create();
        q.Fake.SetTtl(0, TimeSpan.FromSeconds(45));
        var x = await q.StartQr();
        Assert.InRange(x.Num("expiresIn")!.Value, 43, 45);
        Assert.Equal(x.Num("expiresIn")!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), x.MaxAge());
        Assert.Equal(120, (await LoginEnv.Create().StartQr()).Num("expiresIn"));
    }

    // ---- цуцлалт ----

    public static IEnumerable<object[]> RevocationCases() => new[]
    {
        new object[] { "revoked", "FAILED", "revoked" },
        new object[] { "checker-error", "FAILED", "revocation_unavailable" },
        new object[] { "hard-fail-unknown", "FAILED", "revocation_unavailable" },
        new object[] { "default-soft", "OK", "unchecked" },
        new object[] { "good", "OK", "good" },
        new object[] { "disabled", "OK", "skipped" },
    };

    [Theory]
    [MemberData(nameof(RevocationCases))]
    public async Task Revocation(string name, string state, string outcome)
    {
        Action<EidLoginOptions>? mod = name switch
        {
            "revoked" => o => o.Revocation = (_, _, _) => Task.FromResult(RevocationStatus.Revoked),
            "checker-error" => o => o.Revocation = (_, _, _) => throw new InvalidOperationException("boom"),
            "hard-fail-unknown" => o => o.RevocationMode = RevocationMode.HardFail,
            "good" => o => o.Revocation = (_, _, _) => Task.FromResult(RevocationStatus.Good),
            "disabled" => o => o.DisableRevocation = true,
            _ => null,
        };
        var e = LoginEnv.Create(mod);
        var c = (await e.StartQr()).LoginCookie();
        e.Fake.Set("OK", "QR", "");
        var r = await e.Status(c);
        Assert.Equal(200, r.Code);
        Assert.Equal(state, r.Str("state"));
        var last = e.Events[^1];
        if (state == "FAILED")
        {
            Assert.Equal("VALIDATION", r.Str("error"));
            Assert.Empty(e.Ids);
            Assert.Equal(EidLoginEventKinds.Unverified, last.Kind);
            Assert.Equal(outcome, last.Meta["reason"]);
            return;
        }
        Assert.Single(e.Ids);
        Assert.Equal(EidLoginEventKinds.Success, last.Kind);
        Assert.Equal(outcome, last.Meta["revocation"]);
    }

    [Fact]
    public async Task EndResultEvents()
    {
        var e = LoginEnv.Create();
        foreach (var end in new[] { "USER_REFUSED", "WRONG_VC", "TIMEOUT" })
        {
            e.Fake.Set("", "", "");
            var c = (await e.StartQr()).LoginCookie();
            e.Fake.Set(end, "QR", "");
            var r = await e.Status(c);
            Assert.Equal("FAILED", r.Str("state"));
            Assert.Equal(end, r.Str("error"));
        }
        Assert.Equal(new[] { EidLoginEventKinds.Refused, EidLoginEventKinds.Failed, EidLoginEventKinds.Expired }, e.Kinds);
        Assert.Equal("WRONG_VC", e.Events[1].Meta["endResult"]);
        Assert.Equal(FakeEid.Sid, e.Events[0].SessionId);
    }

    // ---- хязгаар, client IP ----

    [Fact]
    public async Task RateLimitHooksAndClientIp()
    {
        var keys = new List<string>();
        var e = LoginEnv.Create(o =>
        {
            o.RateLimit = (k, _) =>
            {
                keys.Add(k);
                return new ValueTask<bool>(!k.StartsWith("start:", StringComparison.Ordinal));
            };
            o.ClientIp = _ => "203.0.113.5";
        });
        Assert.Equal(429, (await e.StartQr()).Code);
        Assert.Equal(new[] { "start:203.0.113.5" }, keys);

        // RateLimits-ийн start-ийг солиход push-ийн анхдагч (3/мин) хэвээр.
        keys.Clear();
        var m = LoginEnv.Create(o =>
        {
            o.RateLimits = new Dictionary<string, EidLoginRateRule>
            {
                ["start"] = new EidLoginRateRule
                {
                    Func = (k, _) =>
                    {
                        keys.Add(k);
                        return new ValueTask<bool>(true);
                    },
                },
            };
            o.ClientIp = EidLoginClientIp.RemoteAddress;
        });
        var codes = new List<int>();
        for (var i = 0; i < 4; i++)
        {
            codes.Add((await m.Do("POST", "/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", ip: "203.0.113.5")).Code);
        }
        Assert.Equal(new[] { 200, 200, 200, 429 }, codes);
        Assert.Equal(4, keys.Count);
        Assert.All(keys, k => Assert.Equal("start:203.0.113.5", k));

        // Нэмэлт RateLimit нь анхдагч татгалзсан үед дуудагдахгүй.
        keys.Clear();
        var add = LoginEnv.Create(o => o.RateLimit = (k, _) =>
        {
            keys.Add(k);
            return new ValueTask<bool>(true);
        });
        for (var i = 0; i < 4; i++)
        {
            await add.StartPush("УБ12345678");
        }
        Assert.Equal(3, keys.Count);

        // Push-ийн дүрмийг солих / унтраах.
        var one = LoginEnv.Create(o => o.RateLimits = new Dictionary<string, EidLoginRateRule> { ["push"] = new() { Max = 1, Window = TimeSpan.FromMinutes(1) } });
        Assert.Equal(200, (await one.StartPush("УБ12345678")).Code);
        Assert.Equal(429, (await one.StartPush("УБ12345678")).Code);
        var off = LoginEnv.Create(o => o.RateLimits = new Dictionary<string, EidLoginRateRule> { ["push"] = EidLoginRateRule.Unlimited });
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(200, (await off.StartPush("УБ12345678")).Code);
        }

        // Анхдагч start: нэг IP-ээс 60 с-д 20, өөр IP хөндөгдөхгүй; цонх өнгөрвөл дахин.
        var st = LoginEnv.Create(o => o.ClientIp = EidLoginClientIp.RemoteAddress);
        for (var i = 0; i < 20; i++)
        {
            Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "192.0.2.1")).Code);
        }
        Assert.Equal(429, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "192.0.2.1")).Code);
        Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "192.0.2.2")).Code);
        // IP мэдэгдэхгүй (RemoteIp алга) — нийтийн start:unknown bucket (rp-conformance/2; энд анхны хүсэлт).
        Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}")).Code);
        st.Time.Now += TimeSpan.FromSeconds(61);
        Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "192.0.2.1")).Code);
    }

    [Fact]
    public void RateLimitDefaultsAndValidation()
    {
        var d = EidLoginRateRule.Defaults();
        Assert.Equal(2, d.Count);
        Assert.Equal(3, d["push"].Max);
        Assert.Equal(TimeSpan.FromMinutes(1), d["push"].Window);
        Assert.Equal(20, d["start"].Max);
        d["push"] = EidLoginRateRule.Unlimited;
        Assert.Equal(3, EidLoginRateRule.Defaults()["push"].Max);
        using var client = new EidClient(new EidClientOptions { Credentials = new EidCredentials("rp", "RP", "x") });
        foreach (var rl in new[]
        {
            new Dictionary<string, EidLoginRateRule> { ["pin"] = new() },
            new Dictionary<string, EidLoginRateRule> { ["push"] = new() { Max = 1 } },
        })
        {
            Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions
            {
                Client = client,
                OnSuccess = (_, _, _) => Task.FromResult<EidLoginSuccess?>(null),
                RateLimits = rl,
            }));
        }
    }

    [Fact]
    public void ForwardedClientIpTrustsOnlyConfiguredHops()
    {
        var r = new EidLoginRequest
        {
            Method = "GET",
            Url = "/",
            RemoteIp = "10.0.0.1",
            Headers = H(("X-Forwarded-For", "198.51.100.7, 10.0.0.3, 10.0.0.2"), ("X-Real-IP", "10.0.0.9")),
        };
        Assert.Equal("10.0.0.2", EidLoginClientIp.Forwarded(1)(r));
        Assert.Equal("10.0.0.3", EidLoginClientIp.Forwarded(2)(r));
        Assert.Equal("198.51.100.7", EidLoginClientIp.Forwarded(3)(r));
        Assert.Null(EidLoginClientIp.Forwarded(4)(r));
        var noXff = new EidLoginRequest { Method = "GET", Url = "/", RemoteIp = "10.0.0.1", Headers = H(("x-real-ip", " 10.0.0.9 ")) };
        Assert.Equal("10.0.0.9", EidLoginClientIp.Forwarded(1)(noXff));
        Assert.Equal("10.0.0.1", EidLoginClientIp.RemoteAddress(noXff));
        Assert.Null(EidLoginClientIp.RemoteAddress(new EidLoginRequest { Method = "GET", Url = "/" }));
        Assert.Throws<ArgumentOutOfRangeException>(() => EidLoginClientIp.Forwarded(0));
    }

    [Fact]
    public async Task ForwardedClientIpRateLimitKey()
    {
        var keys = new List<string>();
        var e = LoginEnv.Create(o =>
        {
            o.RateLimit = (k, _) =>
            {
                keys.Add(k);
                return new ValueTask<bool>(true);
            };
            o.ClientIp = EidLoginClientIp.Forwarded(1);
        });
        // Клиент зүүн талын утгыг хуурамчаар бичсэн ч proxy-ийн нэмсэн баруун утга л тооцогдоно.
        Assert.Equal(200, (await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("X-Forwarded-For", "1.2.3.4, 198.51.100.7")))).Code);
        Assert.Equal(new[] { "start:198.51.100.7" }, keys);

        // IPv6 → /64 угтвар (Forwarded ба RemoteAddress хоёуланд).
        keys.Clear();
        await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("X-Forwarded-For", "2001:db8:1:2:aaaa:bbbb:cccc:dddd")));
        await e.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", H(("X-Forwarded-For", "2001:db8:1:2::9")));
        Assert.Equal(new[] { "start:2001:db8:1:2::/64", "start:2001:db8:1:2::/64" }, keys);
        keys.Clear();
        var ra = LoginEnv.Create(o =>
        {
            o.RateLimit = (k, _) =>
            {
                keys.Add(k);
                return new ValueTask<bool>(true);
            };
            o.ClientIp = EidLoginClientIp.RemoteAddress;
        });
        await ra.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "2001:db8:ffff:1:2:3:4:5");
        await ra.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "203.0.113.7");
        Assert.Equal(new[] { "start:2001:db8:ffff:1::/64", "start:203.0.113.7" }, keys);
    }

    [Fact]
    public async Task Ipv6ClientsShareOneStartLimitPerSlash64()
    {
        var st = LoginEnv.Create(o => o.ClientIp = EidLoginClientIp.RemoteAddress);
        for (var i = 0; i < 20; i++)
        {
            Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "2001:db8:1:2::" + (i + 1).ToString("x", System.Globalization.CultureInfo.InvariantCulture))).Code);
        }
        Assert.Equal(429, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "2001:db8:1:2:ffff::1")).Code);
        Assert.Equal(200, (await st.Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}", ip: "2001:db8:1:3::1")).Code);
    }

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64")]
    [InlineData("2001:DB8:0:0::1", "2001:db8:0:0::/64")]
    [InlineData("fe80::1%2", "fe80:0:0:0::/64")]
    [InlineData("fe80::1%eth0", "fe80:0:0:0::/64")]
    [InlineData("[2001:db8:0001:0003::1]", "2001:db8:1:3::/64")]
    [InlineData("::1", "0:0:0:0::/64")]
    [InlineData("::ffff:203.0.113.9", "203.0.113.9")]
    [InlineData("not-an-ip", "not-an-ip")]
    [InlineData("2001:db8::zz", "2001:db8::zz")]
    public void RateKeyIpUsesSlash64ForIpv6(string ip, string want)
    {
        Assert.Equal(want, EidLoginHandler.RateKeyIp(ip));
    }

    [Fact]
    public void WindowLimiterFullUsesOverflowBucket()
    {
        var t = new FakeTime(DateTimeOffset.UtcNow);
        var lim = new WindowLimiter(1, TimeSpan.FromMilliseconds(50), 3, t);
        Assert.True(lim.Allow("push:victim"));
        Assert.False(lim.Allow("push:victim"));
        Assert.True(lim.Allow("a"));
        Assert.True(lim.Allow("b"));
        // Хүснэгт дүүрсэн: шинэ түлхүүрүүд нэг нийтийн overflow bucket-д (татгалзахгүй, байгаа тоолуурыг арилгахгүй).
        Assert.True(lim.Allow("c"));
        Assert.False(lim.Allow("d"));
        Assert.False(lim.Allow("push:victim"));
        t.Now += TimeSpan.FromMilliseconds(60);
        Assert.True(lim.Allow("d"));
    }

    // ---- store ----

    [Fact]
    public async Task MemoryStoreEvictsOnlyExpiredAndRefusesWhenFull()
    {
        var t = new FakeTime(DateTimeOffset.UtcNow);
        var s = new MemoryEidLoginStore(2, t);
        await s.SetAsync(new EidLoginTx { SessionId = "a" }, TimeSpan.FromMinutes(1), default);
        await s.SetAsync(new EidLoginTx { SessionId = "b" }, TimeSpan.FromMilliseconds(1), default);
        t.Now += TimeSpan.FromMilliseconds(5);
        await s.SetAsync(new EidLoginTx { SessionId = "c" }, TimeSpan.FromMinutes(1), default);
        await Assert.ThrowsAsync<EidLoginStoreFullException>(() => s.SetAsync(new EidLoginTx { SessionId = "d" }, TimeSpan.FromMinutes(1), default));
        await s.SetAsync(new EidLoginTx { SessionId = "a" }, TimeSpan.FromMinutes(1), default);
        Assert.NotNull(await s.GetAsync("a", default));
        Assert.Null(await s.GetAsync("b", default));
        Assert.True(await s.DeleteAsync("a", default));
        Assert.False(await s.DeleteAsync("a", default));
        t.Now += TimeSpan.FromMinutes(2);
        Assert.Null(await s.GetAsync("c", default));
        Assert.Equal(MemoryEidLoginStore.DefaultMax, new MemoryEidLoginStore().Max);
        Assert.Throws<ArgumentOutOfRangeException>(() => new MemoryEidLoginStore(0));

        var full = LoginEnv.Create(o => o.Store = new FullStore());
        var r = await full.StartQr();
        Assert.Equal(503, r.Code);
        Assert.Equal("busy", r.Str("error"));
        Assert.Equal("30", r.Raw.Header("Retry-After"));
        var broken = LoginEnv.Create(o => o.Store = new BrokenStore());
        var b = await broken.Status("eid_login=" + FakeEid.Sid + "." + new string('A', 43));
        Assert.Equal(500, b.Code);
        Assert.Equal("internal", b.Str("error"));
        Assert.DoesNotContain("store down", b.Raw.Body);
    }

    private sealed class FullStore : IEidLoginStore
    {
        public Task<EidLoginTx?> GetAsync(string sessionId, CancellationToken ct) => Task.FromResult<EidLoginTx?>(null);

        public Task SetAsync(EidLoginTx tx, TimeSpan ttl, CancellationToken ct) => throw new EidLoginStoreFullException();

        public Task<bool> DeleteAsync(string sessionId, CancellationToken ct) => Task.FromResult(false);
    }

    private sealed class BrokenStore : IEidLoginStore
    {
        public Task<EidLoginTx?> GetAsync(string sessionId, CancellationToken ct) => throw new InvalidOperationException("store down");

        public Task SetAsync(EidLoginTx tx, TimeSpan ttl, CancellationToken ct) => throw new InvalidOperationException("store down");

        public Task<bool> DeleteAsync(string sessionId, CancellationToken ct) => throw new InvalidOperationException("store down");
    }

    // ---- тохиргоо, туслахууд ----

    [Fact]
    public async Task ConfigValidationAndDefaults()
    {
        using var client = new EidClient(new EidClientOptions { Credentials = new EidCredentials("rp", "RP", "x") });
        Task<EidLoginSuccess?> Ok(EidLoginIdentity i, EidLoginContext c, CancellationToken ct) => Task.FromResult<EidLoginSuccess?>(null);
        foreach (var cb in new[] { "https://bank.mn/eid/cb", "http://bank.mn/auth/eid/callback", "/auth/eid/callback" })
        {
            Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions { Client = client, OnSuccess = Ok, CallbackUrl = cb }));
        }
        Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions { Client = client }));
        Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions { OnSuccess = Ok }));
        Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions { Client = client, OnSuccess = Ok, CookieName = "a b" }));
        Assert.Throws<ArgumentException>(() => new EidLoginHandler(new EidLoginOptions { Client = client, OnSuccess = Ok, CookiePath = "/;x" }));
        var logs = new List<EidLoginLogEntry>();
        var h = new EidLoginHandler(new EidLoginOptions { Client = client, OnSuccess = Ok, Log = logs.Add });
        Assert.Equal("RP-д нэвтрэх", Assert.Single(h.Interactions).DisplayText60);
        // ClientIp өгөөгүй — нэг удаа анхааруулна.
        Assert.Contains(logs, l => l.Level == EidLoginLogLevel.Warning && l.Message.Contains("ClientIp"));
        // 60 тэмдэгт (code point) хүртэл таслана — surrogate pair хуваагдахгүй.
        var longText = string.Concat(Enumerable.Repeat("\U0001F600", 61));
        var t = new EidLoginHandler(new EidLoginOptions { Client = client, OnSuccess = Ok, DisplayText = longText });
        Assert.Equal(string.Concat(Enumerable.Repeat("\U0001F600", 60)), t.Interactions[0].DisplayText60);

        var e = LoginEnv.Create(o => o.CallbackUrl = null);
        Assert.Equal("web2app_not_configured", (await e.Do("GET", "/auth/eid/start?mode=web2app")).Str("error"));
        Assert.Equal("Демо банк-д нэвтрэх", e.H.Interactions[0].DisplayText60);
    }

    [Fact]
    public async Task FailureRedirectKeepsQueryAndFragment()
    {
        var e = LoginEnv.Create(o => o.FailureRedirect = "/login?next=%2Fhome&eid_error=old#top");
        var r = await e.Do("GET", "/auth/eid/callback?sessionId=x&userChallengeVerifier=y");
        Assert.Equal("/login?next=%2Fhome&eid_error=expired#top", r.Raw.Header("Location"));
        var abs = LoginEnv.Create(o => o.FailureRedirect = "https://bank.example.mn/login");
        Assert.Equal("https://bank.example.mn/login?eid_error=expired",
            (await abs.Do("GET", "/auth/eid/callback")).Raw.Header("Location"));
    }

    [Fact]
    public void WithReturnHint()
    {
        const string cb = LoginEnv.CallbackUrl;
        Assert.Equal(cb + "?retScheme=googlechromes", EidLoginReturnHint.WithReturnHint(cb, IphoneChrome));
        Assert.Equal(cb + "?retPkg=com.sec.android.app.sbrowser", EidLoginReturnHint.WithReturnHint(cb,
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 SamsungBrowser/24.0"));
        Assert.Equal(cb, EidLoginReturnHint.WithReturnHint(cb, "Mozilla/5.0 (Macintosh) Safari/605"));
        Assert.Equal(cb, EidLoginReturnHint.WithReturnHint(cb, null));
        Assert.Equal(cb + "?a=1&retScheme=firefox", EidLoginReturnHint.WithReturnHint(cb + "?a=1", "iPhone FxiOS/1"));
    }

    [Fact]
    public async Task OnEventFailureDoesNotBreakFlow()
    {
        var e = LoginEnv.Create(o => o.OnEvent = (_, _) => throw new InvalidOperationException("audit down"));
        var s = await e.StartPush("УБ12345678");
        Assert.Equal(200, s.Code);
        Assert.Contains(e.Logs, l => l.Message.Contains("OnEvent"));
    }

    [Fact]
    public async Task OnSuccessErrorIsInternalWithoutDetails()
    {
        var e = LoginEnv.Create(o => o.OnSuccess = (_, _, _) => throw new InvalidOperationException("db password=hunter2"));
        var c = (await e.StartQr()).LoginCookie();
        e.Fake.Set("OK", "QR", "");
        var r = await e.Status(c);
        Assert.Equal(500, r.Code);
        Assert.Equal("{\"error\":\"internal\"}", r.Raw.Body);
    }

    [Fact]
    public void PushKeyIsKeyedHmac()
    {
        using var client = new EidClient(new EidClientOptions { Credentials = new EidCredentials("rp", "RP", "x") });
        EidLoginHandler Make(byte[]? k) => new(new EidLoginOptions
        {
            Client = client,
            OnSuccess = (_, _, _) => Task.FromResult<EidLoginSuccess?>(null),
            AuditKey = k,
        });
        var key = new byte[32];
        var a = Make(key).PushKey("УБ12345678");
        Assert.Equal(a, Make(key).PushKey("УБ12345678"));
        Assert.Matches("^[0-9a-f]{32}$", a);
        Assert.NotEqual(a, Make(null).PushKey("УБ12345678"));
        Assert.NotEqual(a, Make(key).PushKey("УБ12345679"));
    }

    [Fact]
    public void IdNormalisationAndRefusalClassification()
    {
        Assert.Equal("УБ12345678", EidLoginHandler.NormalizeId(" уб 1234\t5678 "));
        Assert.True(EidLoginHandler.IsRefusal(new EidApiException(400, "{\"error\":\"x\"}", null, null, null, null)));
        Assert.True(EidLoginHandler.IsRefusal(new EidApiException(404, " {\"error\":\"x\"} ", null, null, null, null)));
        Assert.False(EidLoginHandler.IsRefusal(new EidApiException(400, "<html></html>", null, null, null, null)));
        Assert.False(EidLoginHandler.IsRefusal(new EidApiException(429, "{}", null, null, null, null)));
        Assert.False(EidLoginHandler.IsRefusal(new EidApiException(500, "{}", null, null, null, null)));
        Assert.False(EidLoginHandler.IsRefusal(new InvalidOperationException()));
    }
}
