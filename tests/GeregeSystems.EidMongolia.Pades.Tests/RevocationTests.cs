using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Complete-ийн LTV цуглуулалт (Go v0.8.0 ltv.go / TS 0.21.0): иргэний OCSP/CRL-ийг 04-ийн түлхүүрээр зурсан хувилбараар
/// сольж (бусад нь golden HTTP fixture), CertID/олгогч/шинэлэг байдал ба revoked = хатуу алдаа дүрмийг шалгана.
/// </summary>
public class RevocationTests
{
    private static readonly JsonElement Manifest = LoadManifest();

    private static JsonElement LoadManifest()
    {
        using var d = JsonDocument.Parse(Fixtures.Read("manifest.json"));
        return d.RootElement.Clone();
    }

    private static readonly DateTimeOffset Now = DateTimeOffset.Parse(Manifest.GetProperty("now").GetString()!, CultureInfo.InvariantCulture);
    private static readonly DateTimeOffset SigningTime = DateTimeOffset.Parse(Manifest.GetProperty("signingTime").GetString()!, CultureInfo.InvariantCulture);

    internal static X509Certificate2 Cert(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name + ".pem")));

    internal static X509Certificate2 WithKey(string name)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name + ".key.pem")));
        return Cert(name).CopyWithPrivateKey(rsa);
    }

    private static readonly X509Certificate2 Citizen = Cert("citizen");
    private static readonly X509Certificate2 Ca04 = Cert("04");

    internal enum St
    {
        Good,
        Revoked,
    }

    /// <summary>RFC 6960 OCSPResponse (successful, basic), <paramref name="signer"/>-ийн түлхүүрээр, certs-гүй (олгогч өөрөө зурсан).</summary>
    internal static byte[] OcspResponse(X509Certificate2 signer, X509Certificate2 nameFrom, BigInteger serial, St st, DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate)
    {
        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
                tbs.WriteOctetString(SHA1.HashData(signer.PublicKey.EncodedKeyValue.RawData));
            tbs.WriteGeneralizedTime(Now, omitFractionalSeconds: true);
            using (tbs.PushSequence())
            using (tbs.PushSequence())
            {
                using (tbs.PushSequence())
                {
                    using (tbs.PushSequence())
                    {
                        tbs.WriteObjectIdentifier("1.3.14.3.2.26");
                        tbs.WriteNull();
                    }
                    tbs.WriteOctetString(SHA1.HashData(nameFrom.SubjectName.RawData));
                    tbs.WriteOctetString(SHA1.HashData(Ca04.PublicKey.EncodedKeyValue.RawData));
                    tbs.WriteInteger(serial);
                }
                if (st == St.Good)
                {
                    tbs.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0));
                }
                else
                {
                    using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                        tbs.WriteGeneralizedTime(thisUpdate.AddDays(-1), omitFractionalSeconds: true);
                }
                tbs.WriteGeneralizedTime(thisUpdate, omitFractionalSeconds: true);
                if (nextUpdate is { } nu)
                {
                    using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        tbs.WriteGeneralizedTime(nu, omitFractionalSeconds: true);
                }
            }
        }
        var tbsDer = tbs.Encode();
        using var key = signer.GetRSAPrivateKey()!;
        var sig = key.SignData(tbsDer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var basic = new AsnWriter(AsnEncodingRules.DER);
        using (basic.PushSequence())
        {
            basic.WriteEncodedValue(tbsDer);
            using (basic.PushSequence())
            {
                basic.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                basic.WriteNull();
            }
            basic.WriteBitString(sig);
        }
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteEncodedValue(new byte[] { 0x0a, 0x01, 0x00 }); // responseStatus successful
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
                w.WriteOctetString(basic.Encode());
            }
        }
        return w.Encode();
    }

    private static byte[] Ocsp(St st, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate = null, string nameFrom = "04", BigInteger? serial = null) =>
        OcspResponse(WithKey("04"), Cert(nameFrom), serial ?? Cms.Serial(Citizen), st, thisUpdate, nextUpdate);

    private static byte[] Crl(string issuer, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, bool listCitizen)
    {
        var b = new CertificateRevocationListBuilder();
        if (listCitizen) b.AddEntry(Citizen.SerialNumberBytes.Span, thisUpdate.AddDays(-1));
        return b.Build(WithKey(issuer), BigInteger.One, nextUpdate, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, thisUpdate);
    }

    /// <summary>
    /// Иргэний OCSP (POST ocsp/04, иргэний хүсэлт) ба 04.crl-ийг солино (null → 404); бусад нь golden replay.
    /// <c>delay</c> ("METHOD URL" → хүлээлт) — хариугүй/удаан responder-ийг дуурайна (ct-г хүндэтгэнэ).
    /// </summary>
    private sealed class Handler : HttpMessageHandler
    {
        private readonly byte[]? _ocsp;
        private readonly byte[]? _crl;
        private readonly Func<string, CancellationToken, Task>? _delay;

        public Handler(byte[]? ocsp, byte[]? crl, Func<string, CancellationToken, Task>? delay = null)
        {
            _ocsp = ocsp;
            _crl = crl;
            _delay = delay;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(ct);
            var url = request.RequestUri!.ToString();
            if (_delay is not null) await _delay(request.Method.Method + " " + url, ct);
            if (url == "http://ocsp.pki.test/04" && body.AsSpan().SequenceEqual(Crypto.Ocsp.CreateRequest(Citizen, Ca04))) return Reply(_ocsp);
            if (url == "http://crl.pki.test/04.crl") return Reply(_crl);
            var key = request.Method.Method + " " + url + " " + Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant()[..16];
            return Reply(Manifest.GetProperty("http").TryGetProperty(key, out var f) ? Fixtures.Read(f.GetString()!.Split('/')) : null);
        }

        private static HttpResponseMessage Reply(byte[]? b) =>
            b is null ? new HttpResponseMessage(HttpStatusCode.NotFound) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(b) };
    }

    private static Task<DssData> Collect(byte[]? ocsp, byte[]? crl, Func<string, CancellationToken, Task>? delay = null, TimeSpan? grace = null,
        CancellationToken ct = default)
    {
        var f = new Fetcher(new HttpClient(new Handler(ocsp, crl, delay)));
        return Ltv.CollectAsync(f, Now, SigningTime, new[] { Cert("root") }, grace ?? Ltv.OcspGrace, ct,
            new[] { Citizen, Ca04, Cert("03"), Cert("02") });
    }

    // Хариугүй responder (TCP хүлээж аваад хариулдаггүй): ct цуцлагдтал хүлээнэ.
    private static Func<string, CancellationToken, Task> Hang(params string[] keys) =>
        (k, ct) => keys.Contains(k) ? Task.Delay(Timeout.InfiniteTimeSpan, ct) : Task.CompletedTask;

    private static Func<string, CancellationToken, Task> Slow(string key, TimeSpan by) =>
        (k, ct) => k == key ? Task.Delay(by, ct) : Task.CompletedTask;

    private const string CitizenOcsp = "POST http://ocsp.pki.test/04"; // иргэний (навч) OCSP
    private const string Ca04Ocsp = "POST http://ocsp.pki.test/03"; // 04-ийн (завсрын CA) OCSP
    private const string CitizenCrl = "GET http://crl.pki.test/04.crl";

    private static byte[] Replayed(string key) =>
        Fixtures.Read(Manifest.GetProperty("http").GetProperty(key + " e3b0c44298fc1c14").GetString()!.Split('/'));

    private static readonly DateTimeOffset Fresh = Now.AddSeconds(-10);

    [Fact]
    public async Task GoodOcspAndCleanCrlAreCollected()
    {
        var d = await Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false));
        Assert.NotEmpty(d.Ocsps);
        Assert.NotEmpty(d.Crls);
    }

    [Fact]
    public async Task RevokedOcspIsHardFailureEvenWithCleanCrl()
    {
        var e = await Assert.ThrowsAsync<CertificateRevokedException>(() =>
            Collect(Ocsp(St.Revoked, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false)));
        Assert.DoesNotContain("GOLDEN", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public Task RevokedCrlIsHardFailureEvenWithGoodOcsp() =>
        Assert.ThrowsAsync<CertificateRevokedException>(() =>
            Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), true)));

    public static IEnumerable<object[]> RejectedOcsp() => new[]
    {
        new object[] { "stale (thisUpdate −48h, no nextUpdate)", Ocsp(St.Good, Now.AddHours(-48)) },
        new object[] { "expired (nextUpdate −1h)", Ocsp(St.Good, Now.AddHours(-30), Now.AddHours(-1)) },
        new object[] { "future (thisUpdate +1h)", Ocsp(St.Good, Now.AddHours(1), Now.AddDays(1)) },
        new object[] { "foreign CertID (issuerNameHash of 03)", Ocsp(St.Good, Fresh, Now.AddDays(1), nameFrom: "03") },
        new object[] { "other serial", Ocsp(St.Good, Fresh, Now.AddDays(1), serial: 4242) },
    };

    [Theory]
    [MemberData(nameof(RejectedOcsp))]
    public async Task RejectedOcspWithoutCrlFails(string name, byte[] ocsp)
    {
        var e = await Assert.ThrowsAnyAsync<Exception>(() => Collect(ocsp, null));
        Assert.True(e is LtvException, name + ": " + e.GetType().Name);
        Assert.DoesNotContain("GOLDEN", e.Message, StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> RejectedCrl() => new[]
    {
        new object[] { "wrong issuer (03)", Crl("03", Now.AddHours(-1), Now.AddDays(1), false) },
        new object[] { "stale (nextUpdate −47h)", Crl("04", Now.AddHours(-48), Now.AddHours(-47), false) },
        new object[] { "future (thisUpdate +1h)", Crl("04", Now.AddHours(1), Now.AddDays(1), false) },
    };

    [Theory]
    [MemberData(nameof(RejectedCrl))]
    public async Task RejectedCrlWithoutOcspFails(string name, byte[] crl)
    {
        var e = await Assert.ThrowsAnyAsync<Exception>(() => Collect(null, crl));
        Assert.True(e is LtvException, name + ": " + e.GetType().Name);
    }

    // ── Хариугүй OCSP responder: OCSP ба CRL зэрэг, хүчинтэй CRL-тэй бол OCSP-г цонхоор (Ltv.OcspGrace) хязгаарлана ──

    /// <summary>Эрүүл гинж: OCSP ба CRL хоёулаа, гинжийн дарааллаар (дараалсан хувилбартай ижил; golden-ууд байт-түвшинд тулгана).</summary>
    [Fact]
    public async Task HealthyChainKeepsOcspAndCrlInChainOrder()
    {
        var ocsp = Ocsp(St.Good, Fresh, Now.AddDays(1));
        var crl = Crl("04", Now.AddHours(-1), Now.AddDays(1), false);
        var d = await Collect(ocsp, crl);
        Assert.Equal(2, d.Ocsps.Count);
        Assert.Equal(ocsp, d.Ocsps[0]);
        Assert.True(Revocation.OcspCertIdMatches(d.Ocsps[1], Ca04, Cert("03")));
        Assert.Equal(new[] { crl, Replayed("GET http://crl.pki.test/03.crl"), Replayed("GET http://crl.pki.test/02.crl"), Replayed("GET http://crl.pki.test/root.crl") },
            d.Crls);
        var idx = new[] { Citizen, Ca04, Cert("03"), Cert("02") }.Select(c => d.Certs.FindIndex(b => b.AsSpan().SequenceEqual(c.RawData))).ToArray();
        Assert.True(idx[0] == 0 && idx[0] < idx[1] && idx[1] < idx[2] && idx[2] < idx[3], string.Join(",", idx));
    }

    /// <summary>04-ийн OCSP хариулдаггүй, CRL хүчинтэй → цонхын дотор CRL-ээр дуусна (өмнө нь 10 с timeout).</summary>
    [Fact]
    public async Task DeadOcspFallsBackToCrlWithinGrace()
    {
        var sw = Stopwatch.StartNew();
        var d = await Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false), Hang(Ca04Ocsp),
            TimeSpan.FromMilliseconds(300));
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
        Assert.Single(d.Ocsps); // иргэнийх л
        Assert.Contains(d.Crls, b => b.AsSpan().SequenceEqual(Replayed("GET http://crl.pki.test/03.crl")));
    }

    /// <summary>Хоёр гэрчилгээний OCSP хариугүй → нийт ≈ нэг цонх (гэрчилгээ тус бүрд биш); цонхыг бүтнээр нь өгнө.</summary>
    [Fact]
    public async Task DeadOcspsCostOneGraceWindowNotOnePerCertificate()
    {
        var grace = TimeSpan.FromMilliseconds(1500);
        var sw = Stopwatch.StartNew();
        var d = await Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false), Hang(CitizenOcsp, Ca04Ocsp), grace);
        sw.Stop();
        Assert.True(sw.Elapsed >= TimeSpan.FromSeconds(1), "OCSP must get the grace window: " + sw.Elapsed);
        Assert.True(sw.Elapsed < 2 * grace - TimeSpan.FromMilliseconds(100), "dead responders must not add up: " + sw.Elapsed);
        Assert.Empty(d.Ocsps);
        Assert.Equal(4, d.Crls.Count);
    }

    /// <summary>Хүчинтэй CRL-гүй бол удаан OCSP-г цонхоор таслахгүй (fail-closed, өмнөхтэй ижил).</summary>
    [Fact]
    public async Task SlowOcspIsAwaitedWhenThereIsNoValidCrl()
    {
        var ocsp = Ocsp(St.Good, Fresh, Now.AddDays(1));
        var d = await Collect(ocsp, null, Slow(CitizenOcsp, TimeSpan.FromMilliseconds(800)), TimeSpan.FromMilliseconds(200));
        Assert.Equal(ocsp, d.Ocsps[0]);
    }

    public static IEnumerable<object[]> BadOcsp() => new[]
    {
        new object[] { "garbage", new byte[] { 0x30, 0x03, 0x0a, 0x01, 0x00 } },
        new object[] { "signed by a key other than the issuer (03)", OcspResponse(WithKey("03"), Ca04, Cms.Serial(Citizen), St.Good, Fresh, Now.AddDays(1)) },
    };

    /// <summary>Хүчингүй OCSP (задрахгүй / олгогч биш зурсан) → CRL; CRL ч байхгүй бол өмнөх шигээ LTV incomplete.</summary>
    [Theory]
    [MemberData(nameof(BadOcsp))]
    public async Task InvalidOcspFallsBackToCrlElseFails(string name, byte[] ocsp)
    {
        var d = await Collect(ocsp, Crl("04", Now.AddHours(-1), Now.AddDays(1), false));
        Assert.True(d.Ocsps.Count == 1 && !d.Ocsps[0].AsSpan().SequenceEqual(ocsp), name);
        var e = await Assert.ThrowsAsync<LtvException>(() => Collect(ocsp, null));
        Assert.Contains("no valid OCSP/CRL for serial", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Цонхын дотор ирсэн «revoked» OCSP нь хүчинтэй CRL байсан ч хатуу алдаа хэвээр.</summary>
    [Fact]
    public Task SlowRevokedOcspWithinGraceIsStillHardFailure() =>
        Assert.ThrowsAsync<CertificateRevokedException>(() =>
            Collect(Ocsp(St.Revoked, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false),
                Slow(CitizenOcsp, TimeSpan.FromMilliseconds(300)), TimeSpan.FromSeconds(3)));

    /// <summary>Дуудагчийн цуцлалт OCSP ба CRL хоёулаа хүлээж байхад шууд хүндэтгэгдэнэ.</summary>
    [Fact]
    public async Task CallerCancellationIsHonoured()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), null, Hang(CitizenOcsp, CitizenCrl), TimeSpan.FromSeconds(3), cts.Token));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
    }

    /// <summary>Алдаа/цуцлалтаар гарахад үлдсэн OCSP task-ууд цуцлагдаж ажиглагдана — UnobservedTaskException үгүй.</summary>
    [Fact]
    public async Task NoUnobservedTaskExceptions()
    {
        var seen = new List<string>();
        void On(object? s, UnobservedTaskExceptionEventArgs e)
        {
            lock (seen) seen.Add(e.Exception.ToString());
        }
        TaskScheduler.UnobservedTaskException += On;
        try
        {
            var sw = Stopwatch.StartNew();
            await Assert.ThrowsAsync<CertificateRevokedException>(() =>
                Collect(Ocsp(St.Revoked, Fresh, Now.AddDays(1)), Crl("04", Now.AddHours(-1), Now.AddDays(1), false), Hang(Ca04Ocsp), TimeSpan.FromSeconds(3)));
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                Collect(Ocsp(St.Good, Fresh, Now.AddDays(1)), null, Hang(CitizenOcsp, Ca04Ocsp, CitizenCrl), TimeSpan.FromSeconds(3), cts.Token));
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
        finally
        {
            TaskScheduler.UnobservedTaskException -= On;
        }
        lock (seen) Assert.DoesNotContain(seen, s => s.Contains("Pades.Crypto.Ltv", StringComparison.Ordinal));
    }

    /// <summary>Complete: revoked → LTV_UNAVAILABLE, InnerException = CertificateRevokedException, мессежид иргэний нэр алга.</summary>
    [Fact]
    public async Task CompleteMapsRevokedToLtvUnavailable()
    {
        const string name = "quartz-pdf13";
        var c = Manifest.GetProperty("cases").EnumerateArray().Single(x => x.GetProperty("name").GetString() == name);
        var p = c.GetProperty("prepare");
        var prep = EidPades.Prepare(Fixtures.Read(c.GetProperty("input").GetString()!.Split('/')), new PrepareOptions
        {
            SignerCert = Citizen.RawData,
            Chain = new[] { Ca04.RawData, Cert("03").RawData, Cert("02").RawData },
            SigningTime = SigningTime,
            DocId = p.GetProperty("docId").GetString(),
            VerifyPage = true,
            FileName = p.GetProperty("fileName").GetString(),
            Lang = p.GetProperty("lang").GetString(),
        });
        var nonce = SHA256.HashData(Encoding.UTF8.GetBytes("golden-nonce:" + name).Append((byte)0).ToArray())[..8];
        using var http = new HttpClient(new Handler(Ocsp(St.Revoked, Fresh, Now.AddDays(1)), null));
        var sig = Convert.FromHexString(c.GetProperty("expect").GetProperty("signature").GetString()!);
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(prep.State, sig, new CompleteOptions
        {
            TsaUrl = "http://tsa.pki.test/",
            Roots = new[] { Cert("root").RawData },
            HttpClient = http,
            TimeProvider = new Fixed(Now),
            NonceSource = () => nonce,
            Sleep = (_, _) => Task.CompletedTask,
        }));
        Assert.Equal(EidPadesErrorCode.LtvUnavailable, ex.Code);
        Assert.IsType<CertificateRevokedException>(ex.InnerException);
        Assert.DoesNotContain("GOLDEN", ex.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("TESTOV", ex.ToString(), StringComparison.Ordinal);
    }

    private sealed class Fixed : TimeProvider
    {
        private readonly DateTimeOffset _t;

        public Fixed(DateTimeOffset t) => _t = t;

        public override DateTimeOffset GetUtcNow() => _t.ToUniversalTime();
    }

    [Fact]
    public void FreshAtRules()
    {
        var at = Now;
        Assert.True(Revocation.FreshAt(at.AddHours(-23), null, at, at));
        Assert.False(Revocation.FreshAt(at.AddHours(-25), null, at, at)); // nextUpdate-гүй, 24ц-аас хуучин
        Assert.True(Revocation.FreshAt(at.AddHours(-25), at.AddHours(1), at, at)); // [this, next] at-ийг хамарна
        Assert.False(Revocation.FreshAt(at.AddMinutes(6), null, at, at)); // ирээдүй (> 5 мин skew)
        Assert.True(Revocation.FreshAt(at.AddMinutes(4), null, at, at));
        Assert.False(Revocation.FreshAt(at.AddHours(-2), at.AddMinutes(-6), at, at)); // nextUpdate өнгөрсөн
    }
}
