using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Go seal_test.go ба seal_grant_test.go-ийн порт (тест бүрд эх тестийн нэр).</summary>
public class SealTests
{
    private const string Org = "NTRMN-6235972";
    private const string ReqId = "5f0c2b1e-7a40-4c11-9a51-2f6e0d3c9b11";
    private const string GrantId = "0b7d2c9e-41f6-4a3d-8e52-7c1a9f0e6d24";
    private static readonly SealWaitOptions Fast = new() { Interval = TimeSpan.FromMilliseconds(1) };

    /// <summary>CA <c>dto.SealRequest</c>-ийн JSON түлхүүрүүд (DisallowUnknownFields).</summary>
    internal static readonly string[] CaSealRequestFields = { "relyingPartyUUID", "relyingPartyName", "digest", "hashType", "docId", "revIndex" };

    /// <summary>Go sealTestCert: EC P-256, self-signed, өгсөн KeyUsage.</summary>
    internal static (ECDsa Key, byte[] Der) SealCert(X509KeyUsageFlags ku)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=TEST ONLY seal, O=TEST ONLY", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(ku, true));
        using var c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
        return (key, c.RawData);
    }

    /// <summary>Go sealReply: CA dto.SealResponse хэлбэрээр, биеийн digest-ийг <paramref name="key"/>-ээр зурна.</summary>
    private static Func<Recorded, HttpResponseMessage> SealReply(ECDsa key, byte[] certDer) => r =>
    {
        var body = r.Json();
        if (body.EnumerateObject().Any(p => !CaSealRequestFields.Contains(p.Name)))
        {
            return Rig.Json(400, "{\"code\":\"REQUEST_INVALID\"}");
        }
        var digest = Convert.FromBase64String(body.GetProperty("digest").GetString()!);
        var sig = key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        return Rig.Json(200, "{\"orgEtsi\":\"" + Org + "\",\"signature\":{\"value\":\"" + Convert.ToBase64String(sig) +
            "\",\"signatureAlgorithm\":\"ecdsa-with-SHA256\"},\"cert\":{\"value\":\"" + Convert.ToBase64String(certDer) +
            "\",\"certificateLevel\":\"QUALIFIED\"},\"sealedAt\":\"2026-11-09T04:05:06Z\"}");
    };

    /// <summary>Go sealSeq: дарааллаар хариулна (сүүлийнхийг давтана).</summary>
    private static Func<Recorded, HttpResponseMessage> Seq(params (int Status, string Body, string? RetryAfter)[] steps)
    {
        var i = 0;
        return _ =>
        {
            var s = steps[Math.Min(Interlocked.Increment(ref i) - 1, steps.Length - 1)];
            return Rig.Json(s.Status, s.Body, s.RetryAfter);
        };
    }

    private static string ReqBody(string status, string extra = "") =>
        "{\"requestId\":\"" + ReqId + "\",\"orgEtsi\":\"" + Org + "\",\"status\":\"" + status +
        "\",\"createdAt\":\"2026-11-09T05:00:00Z\",\"expiresAt\":\"2026-11-09T05:07:00Z\"" + extra + "}";

    private static string IssuedBody(byte[] der) => ReqBody("ISSUED",
        ",\"decidedAt\":\"2026-11-09T05:01:00Z\",\"certificate\":{\"orgEtsi\":\"" + Org + "\",\"certificate\":\"" + Convert.ToBase64String(der) +
        "\",\"serialNumber\":\"88002\",\"subjectDn\":\"CN=x\",\"issuerDn\":\"CN=y\",\"notBefore\":\"2026-11-09T05:01:00Z\"," +
        "\"notAfter\":\"2029-11-09T05:01:00Z\",\"certificateLevel\":\"QUALIFIED\"}");

    private static string GrantBody(string status, string extra = "") =>
        "{\"grantId\":\"" + GrantId + "\",\"orgEtsi\":\"" + Org + "\",\"status\":\"" + status + "\",\"expiresAt\":\"2026-11-20T05:07:00Z\"" + extra + "}";

    // Go TestSeal_RequestAndVerify.
    [Fact]
    public async Task SealRequestAndVerify()
    {
        var (key, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        using var disposeKey = key;
        var (c, h, _) = Rig.Create(SealReply(key, der));
        var d = SHA256.HashData("doc"u8);
        var r = await c.Seal.SealAsync(Org, d);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/seal/" + Org, h.Last.Path);
        Assert.Equal("Bearer " + Rig.Creds.ApiSecret, h.Last.Request.Headers.Authorization!.ToString());
        JsonAssert.Equivalent("{\"digest\":\"" + Convert.ToBase64String(d) + "\",\"hashType\":\"SHA256\"}", h.Last.Json());
        Assert.Equal(Org, r.OrgEtsi);
        Assert.Equal(der, r.Certificate);
        Assert.Equal(CertificateLevels.Qualified, r.CertificateLevel);
        Assert.Equal("ecdsa-with-SHA256", r.SignatureAlgorithm);
        Assert.Equal(new DateTimeOffset(2026, 11, 9, 4, 5, 6, TimeSpan.Zero), r.SealedAt);
        Assert.NotNull(r.Raw);
        Assert.True(key.VerifyHash(d, r.Signature, DSASignatureFormat.Rfc3279DerSequence));
    }

    // .NET-ийн нэмэлт (CA V158 dto.SealRequest docId / revIndex).
    [Fact]
    public async Task SealDocIdRevIndex()
    {
        var (key, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        using var disposeKey = key;
        var (c, h, _) = Rig.Create(SealReply(key, der));
        var d = SHA256.HashData("doc"u8);
        await c.Seal.SealAsync(Org, d, null, new SealDigestOptions { DocId = "doc-1", RevIndex = 2 });
        JsonAssert.Equivalent("{\"digest\":\"" + Convert.ToBase64String(d) + "\",\"hashType\":\"SHA256\",\"docId\":\"doc-1\",\"revIndex\":2}", h.Last.Json());
        var n = h.Requests.Count;
        foreach (var bad in new[] { new SealDigestOptions { DocId = "doc-1" }, new SealDigestOptions { RevIndex = 1 }, new SealDigestOptions { DocId = "d", RevIndex = -1 } })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealAsync(Org, d, null, bad));
        }
        Assert.Equal(n, h.Requests.Count);
    }

    // Go TestSeal_HashTypes.
    [Fact]
    public async Task SealHashTypes()
    {
        var (key, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        using var disposeKey = key;
        var (c, h, _) = Rig.Create(SealReply(key, der));
        foreach (var (hash, n, wire) in new[] { (HashAlgorithms.Sha384, 48, "SHA384"), (HashAlgorithms.Sha512, 64, "SHA512") })
        {
            await c.Seal.SealAsync(Org, new byte[n], hash);
            Assert.Equal(wire, h.Last.Json().GetProperty("hashType").GetString());
        }
        var count = h.Requests.Count;
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealAsync(Org, new byte[32], HashAlgorithms.Sha384));
        Assert.Equal(count, h.Requests.Count);
    }

    // Go TestSeal_Rejects.
    [Fact]
    public async Task SealRejects()
    {
        var d = SHA256.HashData("doc"u8);
        var (k1, certDer) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k1.Dispose();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (c, _, _) = Rig.Create(SealReply(other, certDer));
        Assert.Equal(ValidationReasons.SealSignature, (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.SealAsync(Org, d))).Reason);

        var (signKey, signDer) = SealCert(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DigitalSignature);
        using (signKey)
        {
            (c, _, _) = Rig.Create(SealReply(signKey, signDer));
            Assert.Equal(ValidationReasons.SealNotSealCertificate, (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.SealAsync(Org, d))).Reason);
        }

        (c, _, _) = Rig.Create(200, "{\"orgEtsi\":\"" + Org + "\",\"signature\":null,\"cert\":null}");
        Assert.Equal(ValidationReasons.ResponseMalformed, (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.SealAsync(Org, d))).Reason);

        (c, _, _) = Rig.Create(403, "{\"code\":\"FORBIDDEN\",\"message\":\"SEAL permission алга\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c.Seal.SealAsync(Org, d));

        (c, _, _) = Rig.Create(_ => Rig.Json(429, "{\"code\":\"RATE_LIMITED\"}", "7"));
        var e = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.SealAsync(Org, d));
        Assert.True(e.Retryable);
        Assert.Equal(TimeSpan.FromSeconds(7), e.RetryAfter);
    }

    // Go TestSeal_Certificate.
    [Fact]
    public async Task SealCertificateGet()
    {
        var (k, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k.Dispose();
        var (c, h, _) = Rig.Create(200, "{\"orgEtsi\":\"" + Org + "\",\"certificate\":\"" + Convert.ToBase64String(der) + "\",\"serialNumber\":\"4242\"," +
            "\"subjectDn\":\"CN=x\",\"issuerDn\":\"CN=y\",\"notBefore\":\"2026-11-01T00:00:00Z\",\"notAfter\":\"2029-11-01T00:00:00Z\",\"certificateLevel\":\"QUALIFIED\"}");
        var sc = await c.Seal.CertificateAsync(Org);
        Assert.Equal(der, sc.Certificate);
        Assert.Equal("4242", sc.SerialNumber);
        Assert.Equal(CertificateLevels.Qualified, sc.CertificateLevel);
        Assert.Equal(2029, sc.NotAfter.Year);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/seal/certificate/" + Org, h.Last.Path);

        (c, _, _) = Rig.Create(404, "{\"code\":\"NOT_FOUND\"}");
        await Assert.ThrowsAsync<EidApiException>(() => c.Seal.CertificateAsync(Org));
        (c, _, _) = Rig.Create(200, "{\"orgEtsi\":\"" + Org + "\"}");
        Assert.Equal(ValidationReasons.ResponseMalformed, (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.CertificateAsync(Org))).Reason);
    }

    // Go TestIsSealCertificate.
    [Fact]
    public void IsSealCertificate()
    {
        var (k1, seal) = SealCert(X509KeyUsageFlags.NonRepudiation);
        var (k2, sign) = SealCert(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DigitalSignature);
        k1.Dispose();
        k2.Dispose();
        using var a = X509Loader.Load(seal);
        using var b = X509Loader.Load(sign);
        Assert.True(SealService.IsSealCertificate(a));
        Assert.False(SealService.IsSealCertificate(b));
        Assert.False(SealService.IsSealCertificate(null));
    }

    // Go TestSeal_RequestCertificate.
    [Fact]
    public async Task RequestCertificate()
    {
        var (c, h, _) = Rig.Create(202, ReqBody("PENDING", ",\"approvers\":2"));
        var r = await c.Seal.RequestCertificateAsync(Org);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/seal/certificate/" + Org, h.Last.Path);
        JsonAssert.Equivalent("{}", h.Last.Json());
        Assert.Equal(ReqId, r.RequestId);
        Assert.Equal(SealRequestStatuses.Pending, r.Status);
        Assert.Equal(2, r.Approvers);
        Assert.Equal(7, r.ExpiresAt.Minute);
        Assert.Null(r.Certificate);
    }

    // Go TestSeal_CertificateRequestIssued.
    [Fact]
    public async Task CertificateRequestIssued()
    {
        var (k, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k.Dispose();
        var (c, h, _) = Rig.Create(200, IssuedBody(der));
        var r = await c.Seal.CertificateRequestAsync(Org, ReqId);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/seal/certificate/" + Org + "/requests/" + ReqId, h.Last.Path);
        Assert.Equal(SealRequestStatuses.Issued, r.Status);
        Assert.NotNull(r.DecidedAt);
        Assert.Equal(der, r.Certificate!.Certificate);
        Assert.Equal("88002", r.Certificate.SerialNumber);
        foreach (var body in new[] { ReqBody("ISSUED"), "{\"status\":\"PENDING\"}" })
        {
            (c, _, _) = Rig.Create(200, body);
            Assert.Equal(ValidationReasons.ResponseMalformed,
                (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.CertificateRequestAsync(Org, ReqId))).Reason);
        }
    }

    // Go TestSeal_WaitForCertificate.
    [Fact]
    public async Task WaitForCertificate()
    {
        var (k, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k.Dispose();
        var (c, h, _) = Rig.Create(Seq((200, ReqBody("PENDING"), null), (200, ReqBody("APPROVED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\""), null),
            (200, IssuedBody(der), null)));
        var sc = await c.Seal.WaitForCertificateAsync(Org, ReqId, Fast);
        Assert.Equal(der, sc.Certificate);
        Assert.Equal(2029, sc.NotAfter.Year);
        Assert.Equal(3, h.Requests.Count);
    }

    // Go TestSeal_WaitForCertificateTerminal.
    [Theory]
    [InlineData("REJECTED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\"", null)]
    [InlineData("EXPIRED", ",\"failure\":\"EXPIRED\"", "EXPIRED")]
    [InlineData("FAILED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\",\"failure\":\"SEAL_ISSUANCE_FAILED\"", "SEAL_ISSUANCE_FAILED")]
    public async Task WaitForCertificateTerminal(string status, string extra, string? failure)
    {
        var (c, h, _) = Rig.Create(Seq((200, ReqBody("PENDING"), null), (200, ReqBody(status, extra), null)));
        var e = await Assert.ThrowsAsync<EidSealRequestException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId, Fast));
        Assert.Equal(status, e.Outcome);
        Assert.Equal(ReqId, e.RequestId);
        Assert.Equal(failure, e.Failure);
        Assert.False(e.IsServiceDisabled);
        Assert.Equal(2, h.Requests.Count);
    }

    // Go TestSeal_WaitForCertificateTimeoutAndCancel.
    [Fact]
    public async Task WaitForCertificateTimeoutAndCancel()
    {
        var (c, _, _) = Rig.Create(200, ReqBody("PENDING"));
        var e = await Assert.ThrowsAsync<EidSealRequestException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId,
            new SealWaitOptions { Interval = TimeSpan.FromMilliseconds(5), Timeout = TimeSpan.FromMilliseconds(30) }));
        Assert.Equal(SealRequestStatuses.Timeout, e.Outcome);
        Assert.Null(e.Failure);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId,
            new SealWaitOptions { Interval = TimeSpan.FromSeconds(10) }, cts.Token));
    }

    // Go TestSeal_WaitForCertificateRetryAfter.
    [Fact]
    public async Task WaitForCertificateRetryAfter()
    {
        var (k, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k.Dispose();
        var (c, h, _) = Rig.Create(Seq((429, "{\"error\":\"хэт олон\",\"code\":\"RATE_LIMITED\"}", "1"), (200, IssuedBody(der), null)));
        var sw = Stopwatch.StartNew();
        var sc = await c.Seal.WaitForCertificateAsync(Org, ReqId, Fast);
        Assert.Equal(der, sc.Certificate);
        Assert.True(sw.Elapsed >= TimeSpan.FromMilliseconds(950), "Retry-After дагаагүй: " + sw.Elapsed);
        Assert.Equal(2, h.Requests.Count);

        (c, h, _) = Rig.Create(404, "{\"error\":\"олдсонгүй\",\"code\":\"SEAL_REQUEST_NOT_FOUND\"}");
        var e = await Assert.ThrowsAsync<EidSealRequestNotFoundException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId, Fast));
        Assert.Equal(404, e.Status);
        Assert.Single(h.Requests);
    }

    // Go TestSeal_RequestCertificateErrors.
    [Fact]
    public async Task RequestCertificateErrors()
    {
        var (c, _, _) = Rig.Create(409, "{\"error\":\"ADMIN алга\",\"code\":\"SEAL_APPROVER_UNAVAILABLE\"}");
        var e = await Assert.ThrowsAsync<EidSealApproverUnavailableException>(() => c.Seal.RequestCertificateAsync(Org));
        Assert.Equal(409, e.Status);
        Assert.False(e.Retryable);

        (c, _, _) = Rig.Create(409, "{\"error\":\"байгууллага ACTIVE биш\"}");
        var e2 = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.RequestCertificateAsync(Org));
        Assert.Equal(409, e2.Status);
        Assert.Null(e2.Code);

        (c, _, _) = Rig.Create(403, "{\"error\":\"SEAL эрхгүй\",\"code\":\"PERMISSION_DENIED\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c.Seal.RequestCertificateAsync(Org));

        (c, _, _) = Rig.Create(_ => Rig.Json(429, "{\"error\":\"хэт олон\",\"code\":\"RATE_LIMITED\"}", "3600"));
        var e3 = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.RequestCertificateAsync(Org));
        Assert.True(e3.Retryable);
        Assert.Equal(TimeSpan.FromHours(1), e3.RetryAfter);
    }

    // Go TestSeal_ConflictCodes.
    [Theory]
    [InlineData("ORG_NOT_ACTIVE", typeof(EidOrgNotActiveException), false)]
    [InlineData("SEAL_NOT_ISSUED", typeof(EidSealNotIssuedException), true)]
    [InlineData("SEAL_CERT_REVOKED", typeof(EidSealCertRevokedException), true)]
    [InlineData("SEAL_KEY_UNAVAILABLE", typeof(EidSealKeyUnavailableException), false)]
    [InlineData("SEAL_CERT_EXPIRED", typeof(EidSealCertExpiredException), true)]
    [InlineData("SEAL_CERT_NOT_YET_VALID", typeof(EidSealCertNotYetValidException), true)]
    public async Task ConflictCodes(string code, Type type, bool onGet)
    {
        var d = SHA256.HashData("doc"u8);
        var body = "{\"error\":\"тамгалах боломжгүй\",\"code\":\"" + code + "\"}";
        var (c, h, _) = Rig.Create(409, body);
        var e = await Assert.ThrowsAnyAsync<EidApiException>(() => c.Seal.SealAsync(Org, d));
        Assert.IsType(type, e);
        Assert.Equal(409, e.Status);
        Assert.Equal(code, e.Code);
        Assert.False(e.Retryable);
        Assert.Single(h.Requests);
        if (onGet)
        {
            (c, _, _) = Rig.Create(409, body);
            Assert.IsType(type, await Assert.ThrowsAnyAsync<EidApiException>(() => c.Seal.CertificateAsync(Org)));
        }
    }

    // Go TestSeal_ConflictCodes (code-гүй / танигдаагүй 409, 403, SealErrorCodes дараалал).
    [Fact]
    public async Task ConflictCodesUnknownAndForbidden()
    {
        var d = SHA256.HashData("doc"u8);
        foreach (var body in new[] { "{\"error\":\"байгууллага ACTIVE биш\"}", "{\"error\":\"x\",\"code\":\"SEAL_SOMETHING_NEW\"}" })
        {
            var (c, _, _) = Rig.Create(409, body);
            var e = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.SealAsync(Org, d));
            Assert.Equal(409, e.Status);
        }
        var (c2, _, _) = Rig.Create(403, "{\"error\":\"идэвхгүй\",\"code\":\"ORG_NOT_ACTIVE\"}");
        var fe = await Assert.ThrowsAsync<EidForbiddenException>(() => c2.Seal.SealAsync(Org, d));
        Assert.Equal(EidErrorCodes.OrgNotActive, fe.Code);
        Assert.Equal(new[]
        {
            "ORG_NOT_ACTIVE", "SEAL_NOT_ISSUED", "SEAL_CERT_REVOKED", "SEAL_KEY_UNAVAILABLE", "SEAL_CERT_EXPIRED",
            "SEAL_CERT_NOT_YET_VALID", "SEAL_APPROVER_UNAVAILABLE", "SEAL_REQUEST_NOT_FOUND", "SEAL_SERVICE_DISABLED",
        }, SealErrorCodes.All);
    }

    // Go TestSeal_ServiceDisabled.
    [Fact]
    public async Task ServiceDisabled()
    {
        var d = SHA256.HashData("doc"u8);
        var (c, h, _) = Rig.Create(503, "{\"error\":\"унтраалттай\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"issuance\"}");
        var e = await Assert.ThrowsAsync<EidSealServiceDisabledException>(() => c.Seal.RequestCertificateAsync(Org));
        Assert.Equal(503, e.Status);
        Assert.Equal(SealServices.Issuance, e.Service);
        Assert.Null(e.RetryAfter);
        Assert.False(e.Retryable);
        Assert.Single(h.Requests);

        (c, _, _) = Rig.Create(503, "{\"error\":\"disabled\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"sealing\"}");
        Assert.Equal(SealServices.Sealing, (await Assert.ThrowsAsync<EidSealServiceDisabledException>(() => c.Seal.SealAsync(Org, d))).Service);

        // Proxy Retry-After нэмсэн ч давтахгүй.
        (c, h, _) = Rig.Create(_ => Rig.Json(503, "{\"error\":\"x\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"issuance\"}", "1"));
        var e2 = await Assert.ThrowsAsync<EidSealServiceDisabledException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId, Fast));
        Assert.False(e2.Retryable);
        Assert.Single(h.Requests);

        (c, h, _) = Rig.Create(200, ReqBody("FAILED", ",\"decidedAt\":\"2026-11-12T05:01:00Z\",\"failure\":\"SEAL_SERVICE_DISABLED\""));
        var se = await Assert.ThrowsAsync<EidSealRequestException>(() => c.Seal.WaitForCertificateAsync(Org, ReqId, Fast));
        Assert.Equal(SealRequestStatuses.Failed, se.Outcome);
        Assert.True(se.IsServiceDisabled);
        Assert.Equal(EidErrorCodes.SealServiceDisabled, se.Code);
        Assert.Single(h.Requests);
        Assert.False(new EidSealRequestException(SealRequestStatuses.Failed, ReqId, "SEAL_ISSUANCE_FAILED").IsServiceDisabled);
    }

    // Go TestSeal_Other503Unchanged.
    [Theory]
    [InlineData("{\"error\":\"state store\",\"code\":\"STATE_UNAVAILABLE\"}", "5", true)]
    [InlineData("<html>upstream</html>", "2", true)]
    [InlineData("{\"error\":\"түр алдаа\"}", null, false)]
    [InlineData("{\"error\":\"x\",\"code\":\"OTHER\",\"service\":7}", null, false)]
    public async Task Other503Unchanged(string body, string? retryAfter, bool retryable)
    {
        var (c, _, _) = Rig.Create(_ => Rig.Json(503, body, retryAfter));
        var e = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.SealAsync(Org, SHA256.HashData("doc"u8)));
        Assert.Equal(503, e.Status);
        Assert.Equal(retryable, e.Retryable);
        Assert.Null(e.Service);
    }

    // Go TestSeal_Other503Unchanged (WaitForCertificate: 503 + Retry-After-ийг дагана).
    [Fact]
    public async Task WaitForCertificateFollows503RetryAfter()
    {
        var (k, der) = SealCert(X509KeyUsageFlags.NonRepudiation);
        k.Dispose();
        var (c, h, _) = Rig.Create(Seq((503, "{\"error\":\"state store\",\"code\":\"STATE_UNAVAILABLE\"}", "1"), (200, IssuedBody(der), null)));
        Assert.Equal(der, (await c.Seal.WaitForCertificateAsync(Org, ReqId, Fast)).Certificate);
        Assert.Equal(2, h.Requests.Count);
    }

    // ── тамганы эрх (Go seal_grant_test.go) ──

    // Go TestSealGrant_Request.
    [Fact]
    public async Task GrantRequest()
    {
        var (c, h, _) = Rig.Create(r =>
        {
            var b = r.Json();
            return b.EnumerateObject().Count() == 2 && b.GetProperty("orgEtsi").GetString() == Org && b.GetProperty("sessionId").GetString() == "sess-1"
                ? Rig.Json(202, GrantBody("PENDING"))
                : Rig.Json(400, "{\"error\":\"JSON буруу\",\"code\":\"REQUEST_INVALID\"}");
        });
        var g = await c.Seal.RequestGrantAsync(" " + Org + " ", "sess-1");
        Assert.Equal(GrantId, g.GrantId);
        Assert.Equal(SealGrantStatuses.Pending, g.Status);
        Assert.Equal(Org, g.OrgEtsi);
        Assert.NotEqual(default, g.ExpiresAt);
        Assert.Null(g.ApprovedAt);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/seal/grants", h.Last.Path);
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.RequestGrantAsync("", "sess-1"));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.RequestGrantAsync(Org, " "));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.GrantStatusAsync(""));
        Assert.Single(h.Requests);
    }

    // Go TestSealGrant_StatusApproved.
    [Fact]
    public async Task GrantStatusApproved()
    {
        var (c, h, _) = Rig.Create(200, GrantBody("APPROVED", ",\"approvedAt\":\"2026-11-20T05:01:00Z\""));
        var g = await c.Seal.GrantStatusAsync(GrantId);
        Assert.Equal(SealGrantStatuses.Approved, g.Status);
        Assert.Equal(1, g.ApprovedAt!.Value.Minute);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/seal/grants/" + GrantId, h.Last.Path);
        (c, _, _) = Rig.Create(200, "{\"orgEtsi\":\"" + Org + "\"}");
        Assert.Equal(ValidationReasons.ResponseMalformed, (await Assert.ThrowsAsync<EidValidationException>(() => c.Seal.GrantStatusAsync(GrantId))).Reason);
    }

    // Go TestSealGrant_ErrorCodes.
    [Theory]
    [InlineData(400, "REQUEST_INVALID", typeof(EidRequestInvalidException))]
    [InlineData(403, "RP_NOT_REGISTERED", typeof(EidForbiddenException))]
    [InlineData(403, "NOT_ORG_CEO", typeof(EidForbiddenException))]
    [InlineData(404, "AUTH_SESSION_NOT_FOUND", typeof(EidAuthSessionNotFoundException))]
    [InlineData(404, "ORG_NOT_FOUND", typeof(EidApiException))]
    [InlineData(409, "AUTH_SESSION_WRONG_FLOW", typeof(EidAuthSessionWrongFlowException))]
    [InlineData(409, "AUTH_SESSION_NOT_COMPLETED", typeof(EidAuthSessionNotCompletedException))]
    [InlineData(409, "AUTH_SESSION_TOO_OLD", typeof(EidAuthSessionTooOldException))]
    [InlineData(409, "AUTH_SESSION_ALREADY_USED", typeof(EidAuthSessionAlreadyUsedException))]
    [InlineData(409, "ORG_NOT_ACTIVE", typeof(EidOrgNotActiveException))]
    [InlineData(409, "RP_NOT_ACTIVE", typeof(EidRpNotActiveException))]
    [InlineData(409, "SEAL_GRANT_ALREADY_APPROVED", typeof(EidSealGrantAlreadyApprovedException))]
    [InlineData(409, "RP_PERMISSIONS_FULL", typeof(EidRpPermissionsFullException))]
    [InlineData(409, "SEAL_APPROVER_UNAVAILABLE", typeof(EidSealApproverUnavailableException))]
    public async Task GrantErrorCodes(int status, string code, Type type)
    {
        var (c, _, _) = Rig.Create(status, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
        var e = await Assert.ThrowsAnyAsync<EidException>(() => c.Seal.RequestGrantAsync(Org, "sess-1"));
        Assert.IsType(type, e);
        Assert.Equal(code, e.Code);
        Assert.Equal(status, e.Status);
        Assert.False(e.Retryable);
        if (status != 400 && status != 403)
        {
            Assert.Contains(code, SealGrantErrorCodes.All);
        }
    }

    // Go TestSealGrant_ErrorCodes (429, 404 SEAL_GRANT_NOT_FOUND).
    [Fact]
    public async Task GrantRateLimitAndNotFound()
    {
        var (c, _, _) = Rig.Create(_ => Rig.Json(429, "{\"error\":\"хэт олон\",\"code\":\"RATE_LIMITED\"}", "3600"));
        var e = await Assert.ThrowsAsync<EidApiException>(() => c.Seal.RequestGrantAsync(Org, "sess-1"));
        Assert.True(e.Retryable);
        Assert.Equal(TimeSpan.FromHours(1), e.RetryAfter);
        (c, _, _) = Rig.Create(404, "{\"error\":\"олдсонгүй\",\"code\":\"SEAL_GRANT_NOT_FOUND\"}");
        await Assert.ThrowsAsync<EidSealGrantNotFoundException>(() => c.Seal.GrantStatusAsync(GrantId));
    }

    // Go TestSealGrant_Wait.
    [Fact]
    public async Task WaitForGrant()
    {
        var (c, h, _) = Rig.Create(Seq((200, GrantBody("PENDING"), null), (429, "{\"error\":\"хэт олон\",\"code\":\"RATE_LIMITED\"}", "1"),
            (200, GrantBody("APPROVED", ",\"approvedAt\":\"2026-11-20T05:01:00Z\""), null)));
        var sw = Stopwatch.StartNew();
        var g = await c.Seal.WaitForGrantAsync(GrantId, Fast);
        Assert.Equal(SealGrantStatuses.Approved, g.Status);
        Assert.Equal(3, h.Requests.Count);
        Assert.True(sw.Elapsed >= TimeSpan.FromMilliseconds(950), sw.Elapsed.ToString());
    }

    // Go TestSealGrant_WaitTerminal.
    [Theory]
    [InlineData("REJECTED", "", null)]
    [InlineData("EXPIRED", ",\"failure\":\"EXPIRED\"", "EXPIRED")]
    [InlineData("FAILED", ",\"failure\":\"PUSH_FAILED\"", "PUSH_FAILED")]
    [InlineData("REVOKED", ",\"approvedAt\":\"2026-11-20T05:01:00Z\",\"revokedAt\":\"2026-11-20T06:00:00Z\",\"failure\":\"CANCELLED\"", "CANCELLED")]
    public async Task WaitForGrantTerminal(string status, string extra, string? failure)
    {
        var (c, h, _) = Rig.Create(Seq((200, GrantBody("PENDING"), null), (200, GrantBody(status, extra), null)));
        var e = await Assert.ThrowsAsync<EidSealGrantException>(() => c.Seal.WaitForGrantAsync(GrantId, Fast));
        Assert.Equal(status, e.Outcome);
        Assert.Equal(GrantId, e.GrantId);
        Assert.Equal(failure, e.Failure);
        Assert.Equal(2, h.Requests.Count);
    }

    // Go TestSealGrant_WaitTerminal (timeout, цуцлалт, 404).
    [Fact]
    public async Task WaitForGrantTimeoutCancelNotFound()
    {
        var (c, _, _) = Rig.Create(200, GrantBody("PENDING"));
        var e = await Assert.ThrowsAsync<EidSealGrantException>(() => c.Seal.WaitForGrantAsync(GrantId,
            new SealWaitOptions { Interval = TimeSpan.FromMilliseconds(5), Timeout = TimeSpan.FromMilliseconds(30) }));
        Assert.Equal(SealGrantStatuses.Timeout, e.Outcome);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.Seal.WaitForGrantAsync(GrantId,
            new SealWaitOptions { Interval = TimeSpan.FromSeconds(10) }, cts.Token));
        var (c2, h2, _) = Rig.Create(404, "{\"error\":\"олдсонгүй\",\"code\":\"SEAL_GRANT_NOT_FOUND\"}");
        await Assert.ThrowsAsync<EidSealGrantNotFoundException>(() => c2.Seal.WaitForGrantAsync(GrantId, Fast));
        Assert.Single(h2.Requests);
    }

    /// <summary>Go contract_test.go TestContractSealDTO: SDK-ийн биеийн талбарууд CA dto.SealRequest-ийн дэд олонлог, digest + hashType заавал.</summary>
    [Fact]
    public void SealRequestFieldsAreCaDtoSubset()
    {
        var names = PdfTests.JsonNames(typeof(SealWireRequest)).ToList();
        Assert.All(names, n => Assert.Contains(n, CaSealRequestFields));
        Assert.Contains("digest", names);
        Assert.Contains("hashType", names);
        Assert.Equal(new[] { "orgEtsi", "sessionId" }, PdfTests.JsonNames(typeof(SealGrantWireRequest)).OrderBy(x => x, StringComparer.Ordinal));
    }
}
