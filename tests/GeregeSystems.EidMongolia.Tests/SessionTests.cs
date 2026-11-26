using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class SessionTests
{
    private static int TimeoutMs(Recorded r) =>
        int.Parse(r.PathAndQuery.Split("timeoutMs=")[1], System.Globalization.CultureInfo.InvariantCulture);

    // Go client_test.go TestParseSessionResult.
    [Fact]
    public void ParsesAcspResult()
    {
        var r = SessionService.ParseSessionResult("""
            {"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"AB1234567"},"signatureProtocol":"ACSP_V2",
             "signature":{"value":"c2ln","serverRandom":"+wVP2U/SMKVkVrggDjNTXFV/","userChallenge":"TLSjYRH2oYw8tW2bq0it0IUb7WIFkCLgF8NTc7-4Zq4",
               "flowType":"Notification","signatureAlgorithm":"rsassa-pss",
               "signatureAlgorithmParameters":{"hashAlgorithm":"SHA-512","maskGenAlgorithm":{"algorithm":"id-mgf1","parameters":{"hashAlgorithm":"SHA-512"}},"saltLength":64,"trailerField":"0xbc"}},
             "cert":{"value":"Y2VydA==","certificateLevel":"QUALIFIED"},"interactionTypeUsed":"displayTextAndPIN"}
            """);
        Assert.Equal("COMPLETE", r.State);
        Assert.Equal("OK", r.EndResult);
        Assert.Equal("AB1234567", r.DocumentNumber);
        Assert.Equal("ACSP_V2", r.SignatureProtocol);
        Assert.Equal("+wVP2U/SMKVkVrggDjNTXFV/", r.ServerRandom);
        Assert.Equal("TLSjYRH2oYw8tW2bq0it0IUb7WIFkCLgF8NTc7-4Zq4", r.UserChallenge);
        Assert.Equal("Notification", r.FlowType);
        Assert.Equal("rsassa-pss", r.SignatureAlgorithm);
        Assert.Equal("SHA-512", r.SignatureAlgorithmParameters!.HashAlgorithm);
        Assert.Equal(64, r.SignatureAlgorithmParameters.SaltLength);
        Assert.Equal("id-mgf1", r.SignatureAlgorithmParameters.MaskGenAlgorithm!.Algorithm);
        Assert.Equal("SHA-512", r.SignatureAlgorithmParameters.MaskGenAlgorithm.Parameters!.HashAlgorithm);
        Assert.Equal("0xbc", r.SignatureAlgorithmParameters.TrailerField);
        Assert.Equal("c2ln", r.SignatureValueB64);
        Assert.Equal("Y2VydA==", r.CertificateDerB64);
        Assert.Equal("QUALIFIED", r.CertificateLevel);
        Assert.Equal("displayTextAndPIN", r.InteractionTypeUsed);
        Assert.Null(r.OnBehalfOf);
        Assert.Null(r.InitialCallbackUrl);
        Assert.Null(r.Person);
        Assert.Equal("AB1234567", r.Raw!.Value.GetProperty("result").GetProperty("documentNumber").GetString());
    }

    // Go client_test.go TestParseSessionResult (onBehalfOf, initialCallbackUrl "").
    [Fact]
    public void ParsesOnBehalfOfAndCallback()
    {
        var r = SessionService.ParseSessionResult("""
            {"state":"COMPLETE","signature":{"initialCallbackUrl":""},"onBehalfOf":{"orgEtsi":"NTRMN-6235972","orgName":"Гэрэгэ Системс ХХК"}}
            """);
        Assert.Equal("", r.InitialCallbackUrl);
        Assert.Equal("NTRMN-6235972", r.OnBehalfOf!.OrgEtsi);
        Assert.Equal("", r.OnBehalfOf.RightType);

        r = SessionService.ParseSessionResult("""
            {"state":"COMPLETE","result":{"endResult":"OK"},
             "onBehalfOf":{"orgEtsi":"NTRMN-6235972","orgName":"Гэрэгэ Системс ХХК","role":"ceo","roleLabel":"Гүйцэтгэх захирал","rightType":"ADMIN"}}
            """);
        Assert.Equal("ADMIN", r.OnBehalfOf!.RightType);
        Assert.Equal("ceo", r.OnBehalfOf.Role);
        Assert.Equal("Гүйцэтгэх захирал", r.OnBehalfOf.RoleLabel);
        Assert.Null(SessionService.ParseSessionResult("{\"state\":\"RUNNING\"}").OnBehalfOf);
        Assert.Null(SessionService.ParseSessionResult("{\"state\":\"COMPLETE\",\"onBehalfOf\":{\"orgEtsi\":\"\"}}").OnBehalfOf);
    }

    // TS session.ts parsePerson / parseTokenCert / parsePresentation, Go rawSession.result.
    [Fact]
    public void ParsesPersonTokenAndPresentationBlocks()
    {
        var r = SessionService.ParseSessionResult("""
            {"state":"COMPLETE","result":{"endResult":"OK"},"signatureProtocol":"",
             "signature":{"signatureProtocol":"RAW_DIGEST_SIGNATURE"},
             "person":{"firstName":"Бат","lastName":"Дорж","familyName":"Боржигон","firstNameEn":"Bat","lastNameEn":"Dorj",
               "civilId":"123456789012","regNo":"АА00000000","birthDate":"2000-01-01","gender":"M","geID":42,"nationality":"MNG"},
             "tokenCertificate":{"status":"ISSUED","authSerialHex":"0a","signSerialHex":"0b"},
             "presentation":{"jws":"a.b.c"}}
            """);
        Assert.Equal("RAW_DIGEST_SIGNATURE", r.SignatureProtocol);
        var p = r.Person!;
        Assert.Equal("Бат", p.FirstName);
        Assert.Equal("Дорж", p.LastName);
        Assert.Equal("Боржигон", p.FamilyName);
        Assert.Equal("Bat", p.FirstNameEn);
        Assert.Equal("Dorj", p.LastNameEn);
        Assert.Equal("123456789012", p.CivilId);
        Assert.Equal("АА00000000", p.RegNo);
        Assert.Equal("2000-01-01", p.BirthDate);
        Assert.Equal("M", p.Gender);
        Assert.Equal(42, p.GeId);
        Assert.Equal("MNG", p.Nationality);
        Assert.Equal(TokenCertStatuses.Issued, r.TokenCertificate!.Status);
        Assert.Equal("0b", r.TokenCertificate.SignSerialHex);
        Assert.Equal("a.b.c", r.Presentation!.Jws);

        r = SessionService.ParseSessionResult("""
            {"state":"COMPLETE","person":{"firstName":"","geID":0},"tokenCertificate":{"status":""},"presentation":{"jws":""},
             "signature":{"signatureAlgorithmParameters":{"hashAlgorithm":""}}}
            """);
        Assert.Null(r.Person);
        Assert.Null(r.TokenCertificate);
        Assert.Null(r.Presentation);
        Assert.Null(r.SignatureAlgorithmParameters);
    }

    [Fact]
    public void ParseIsCaseInsensitiveAndTolerant()
    {
        // Go encoding/json-той ижил: талбарын нэр том/жижиг үсэг үл харгалзана, үл мэдэгдэх талбарыг алгасна.
        var r = SessionService.ParseSessionResult("{\"State\":\"COMPLETE\",\"Result\":{\"EndResult\":\"USER_REFUSED\"},\"future\":{\"x\":1}}");
        Assert.Equal("COMPLETE", r.State);
        Assert.Equal("USER_REFUSED", r.EndResult);
        Assert.Equal("", r.DocumentNumber);
        Assert.Equal("", SessionService.ParseSessionResult("null").State);
        var e = Assert.Throws<EidException>(() => SessionService.ParseSessionResult("{nope"));
        Assert.IsAssignableFrom<JsonException>(e.InnerException);
        Assert.Throws<EidException>(() => SessionService.ParseSessionResult("{\"state\":1}"));
    }

    [Theory]
    [InlineData("COMPLETE", "OK", null)]
    [InlineData("COMPLETE", "USER_REFUSED", "USER_REFUSED")]
    [InlineData("COMPLETE", "TIMEOUT", "TIMEOUT")]
    [InlineData("COMPLETE", "", "UNKNOWN")]
    [InlineData("RUNNING", "", "validation")]
    public void EnsureCompleteOkMapsEndResults(string state, string endResult, string? failure)
    {
        var r = new SessionResult { State = state, EndResult = endResult };
        if (failure is null)
        {
            SessionService.EnsureCompleteOk(r);
            return;
        }
        if (failure == "validation")
        {
            Assert.Throws<EidValidationException>(() => SessionService.EnsureCompleteOk(r));
            return;
        }
        Assert.Equal(failure, Assert.Throws<EidSessionFailedException>(() => SessionService.EnsureCompleteOk(r)).EndResult);
    }

    // Go client_test.go TestSession_PollAndWait.
    [Fact]
    public async Task PollAndWaitUntilComplete()
    {
        var n = 0;
        var (c, h, _) = Rig.Create(r =>
        {
            if (r.Path == "/.well-known/eid")
            {
                return Rig.Json(200, "{\"sessionTtl\":{\"auth\":300,\"sign\":600}}");
            }
            return Rig.Json(200, Interlocked.Increment(ref n) < 3 ? "{\"state\":\"RUNNING\"}" : "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\"}}");
        });
        var res = await c.Session.WaitForResultAsync("abc/def", new WaitOptions { ServerPoll = TimeSpan.FromSeconds(2) });
        Assert.Equal(SessionStates.Complete, res.State);
        Assert.Equal(3, n);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/session/abc%2Fdef?timeoutMs=2000", h.Last.PathAndQuery);
        Assert.Equal("/.well-known/eid", h.Requests[0].Path);
    }

    [Fact]
    public async Task PollDefaultsAndEmptyBody()
    {
        var (c, h, _) = Rig.Create(200, "");
        var r = await c.Session.PollAsync("s1");
        Assert.Equal("", r.State);
        Assert.Equal("/session/s1?timeoutMs=30000", h.Last.PathAndQuery);
        Assert.Null(h.Last.Body);
    }

    [Fact]
    public async Task PollMapsHttpErrors()
    {
        var (c, _, _) = Rig.Create(401, "boom");
        await Assert.ThrowsAsync<EidAuthenticationException>(() => c.Session.PollAsync("x", TimeSpan.FromSeconds(1)));
        (c, _, _) = Rig.Create(403, "<html>nginx</html>");
        var f = await Assert.ThrowsAsync<EidForbiddenException>(() => c.Session.PollAsync("x", TimeSpan.FromSeconds(1)));
        Assert.Null(f.Code);
        Assert.Contains("allowlist", f.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// MaxWait дуусвал сүүлчийн RUNNING-г алдаагүй буцаана (Go TestSession_PollAndWait 2-р хэсэг); poll бүр үлдсэн хугацаагаар
    /// хязгаарлагдана, доод тал нь 1 с. Цагийг fake handler poll бүрд timeoutMs-ээр урагшлуулна.
    /// </summary>
    [Fact]
    public async Task WaitStopsAtDeadlineWithControllableClock()
    {
        ManualClock? clock = null;
        var (c, h, ck) = Rig.Create(r =>
        {
            clock!.Now += TimeSpan.FromMilliseconds(TimeoutMs(r));
            return Rig.Json(200, "{\"state\":\"RUNNING\"}");
        });
        clock = ck;
        var start = ck.Now;
        var res = await c.Session.WaitForResultAsync("x", new WaitOptions { MaxWait = TimeSpan.FromSeconds(10.5), ServerPoll = TimeSpan.FromSeconds(4) });
        Assert.Equal(SessionStates.Running, res.State);
        Assert.Equal(new[] { 4000, 4000, 2500 }, h.Requests.Select(TimeoutMs).ToArray());
        Assert.Equal(start + TimeSpan.FromSeconds(10.5), ck.Now);

        // Үлдсэн 0.3 с → 1 с-ийн доод хязгаар.
        h.Requests.Clear();
        ck.Now = start;
        await c.Session.WaitForResultAsync("x", new WaitOptions { MaxWait = TimeSpan.FromMilliseconds(300) });
        Assert.Equal(new[] { 1000 }, h.Requests.Select(TimeoutMs).ToArray());
    }

    [Fact]
    public async Task WaitReturnsNonOkCompleteWithoutThrowing()
    {
        var (c, _, _) = Rig.Create(200, "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"USER_REFUSED\"}}");
        var r = await c.Session.WaitForResultAsync("x", new WaitOptions { MaxWait = TimeSpan.FromSeconds(5) });
        Assert.Equal("USER_REFUSED", r.EndResult);
        Assert.Equal("USER_REFUSED", Assert.Throws<EidSessionFailedException>(() => SessionService.EnsureCompleteOk(r)).EndResult);
    }

    // Go client_test.go TestWaitDeadline: MaxWait > ExpiresAt > discovery sessionTtl > DefaultMaxWait.
    [Fact]
    public async Task WaitDeadlineOrder()
    {
        var (c, h, ck) = Rig.Create(200, "{\"sessionTtl\":{\"auth\":300,\"sign\":600}}");
        var now = ck.Now;
        Assert.Equal(now + TimeSpan.FromSeconds(600) + SessionService.WaitGrace, await c.Session.WaitDeadlineAsync(new WaitOptions(), default));
        Assert.Equal("/.well-known/eid", h.Last.Path);

        var n = h.Requests.Count;
        var exp = now + TimeSpan.FromSeconds(280);
        Assert.Equal(exp + SessionService.WaitGrace, await c.Session.WaitDeadlineAsync(new WaitOptions { ExpiresAt = exp }, default));
        Assert.Equal(now + TimeSpan.FromSeconds(1), await c.Session.WaitDeadlineAsync(new WaitOptions { ExpiresAt = now - TimeSpan.FromHours(1) }, default));
        Assert.Equal(now + TimeSpan.FromSeconds(42),
            await c.Session.WaitDeadlineAsync(new WaitOptions { MaxWait = TimeSpan.FromSeconds(42), ExpiresAt = exp }, default));
        Assert.Equal(n, h.Requests.Count);

        // Хуучин CA (sessionTtl алга) эсвэл discovery унасан → DefaultMaxWait (600 с).
        foreach (var (status, body) in new[] { (200, "{\"version\":\"v3\"}"), (503, "{}"), (200, "not json") })
        {
            var (c2, _, ck2) = Rig.Create(status, body);
            Assert.Equal(ck2.Now + SessionService.DefaultMaxWait, await c2.Session.WaitDeadlineAsync(new WaitOptions(), default));
        }
    }

    [Fact]
    public async Task WaitPastExpiresAtPollsOnce()
    {
        var (c, h, _) = Rig.Create(r => Rig.Json(200, "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"TIMEOUT\"}}"));
        var r = await c.Session.WaitForResultAsync("x", new WaitOptions { ExpiresAt = Rig.T0 - TimeSpan.FromMinutes(5) });
        Assert.Equal("TIMEOUT", r.EndResult);
        Assert.Equal("/session/x?timeoutMs=1000", Assert.Single(h.Requests).PathAndQuery);
    }

    [Fact]
    public async Task WaitHonoursCancellation()
    {
        var (c, _, _) = Rig.Create(200, "{\"state\":\"RUNNING\"}");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            c.Session.WaitForResultAsync("x", new WaitOptions { MaxWait = TimeSpan.FromSeconds(5) }, cts.Token));
    }
}
