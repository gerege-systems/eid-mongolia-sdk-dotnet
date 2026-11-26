using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Go sealregister_test.go-ийн порт (CA V158 тамганы бүртгэл ба docId/revIndex нөөц; тест бүрд эх тестийн нэр).</summary>
public class SealRegisterTests
{
    private const string Org = "NTRMN-6235972";
    private const string DocId = "3f0c2a8e-6b1d-4c55-9a77-000000000002";

    /// <summary>CA <c>dto.SealRegisterRequest</c>-ийн JSON түлхүүрүүд (ca-eidmongolia-mn main 70c0e09c, PR #78; DisallowUnknownFields).</summary>
    private static readonly string[] CaFields =
    {
        "docID", "revIndex", "cms", "fileName", "inSha256", "sigRevSha256", "outSha256", "priorCmsSha256", "priorRevisionSha256",
    };

    private const string Registered = "{\"docID\":\"" + DocId + "\",\"revIndex\":1,\"registeredAt\":\"2026-11-25T12:00:00+08:00\"," +
        "\"verifyUrl\":\"https://ca.eidmongolia.mn/verify/" + DocId + "\"}";

    private static string H64(char c) => new(c, 64);

    private static SealRegistration Reg() => new()
    {
        DocId = DocId,
        RevIndex = 1,
        Cms = new byte[] { 0x30, 1 },
        FileName = "Нэхэмжлэх.pdf",
        InSha256 = H64('a'),
        SigRevSha256 = H64('b'),
        OutSha256 = H64('c'),
    };

    private static bool UnknownField(Recorded r) => r.Json().EnumerateObject().Any(p => !CaFields.Contains(p.Name));

    [Fact]
    public void FieldsMatchCaDto()
    {
        Assert.Equal(CaFields.OrderBy(x => x, StringComparer.Ordinal), PdfTests.JsonNames(typeof(SealRegistration)).OrderBy(x => x, StringComparer.Ordinal));
    }

    // Go TestRegisterSealedPDF.
    [Fact]
    public async Task RegisterSealedPdf()
    {
        var status = 201;
        var (c, h, _) = Rig.Create(r => UnknownField(r)
            ? Rig.Json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}")
            : Rig.Json(status, Registered));
        var o = await c.Seal.RegisterSealedPdfAsync(" " + Org + " ", Reg());
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/seal/" + Org + "/registrations", h.Last.Path);
        Assert.Equal("Bearer " + Rig.Creds.ApiSecret, h.Last.Request.Headers.Authorization!.ToString());
        JsonAssert.Equivalent("{\"docID\":\"" + DocId + "\",\"revIndex\":1,\"cms\":\"MAE=\",\"fileName\":\"Нэхэмжлэх.pdf\",\"inSha256\":\"" + H64('a') +
            "\",\"sigRevSha256\":\"" + H64('b') + "\",\"outSha256\":\"" + H64('c') + "\"}", h.Last.Json());
        foreach (var k in new[] { "medium", "sessionID", "pageSha256", "onBehalfOf", "signerEtsi", "priorCmsSha256", "PriorSignatures" })
        {
            Assert.DoesNotContain("\"" + k + "\"", h.Last.Body, StringComparison.Ordinal);
        }
        Assert.True(o.Created);
        Assert.Equal(DocId, o.DocId);
        Assert.Equal(1, o.RevIndex);
        Assert.NotEqual("", o.VerifyUrl);
        Assert.NotEqual("", o.RegisteredAt);

        // fileName заавал биш — хоосон бол илгээхгүй; 200 = идэмпотент давталт.
        status = 200;
        o = await c.Seal.RegisterSealedPdfAsync(Org, Reg() with { FileName = "" });
        Assert.False(o.Created);
        Assert.DoesNotContain("fileName", h.Last.Body, StringComparison.Ordinal);
    }

    // Go TestRegisterSealedPDFValidate (CA «Хэлбэр → 400 REQUEST_INVALID» векторууд + orgEtsi): сүлжээнд гаргахгүй.
    [Fact]
    public async Task RegisterSealedPdfValidate()
    {
        var (c, h, _) = Rig.Create(201, Registered);
        var r = Reg();
        foreach (var bad in new[]
        {
            r with { DocId = DocId.ToUpperInvariant() },
            r with { RevIndex = 0 },
            r with { RevIndex = 17 },
            r with { PriorCmsSha256 = new[] { H64('d') } },
            r with { RevIndex = 2 },
            r with { RevIndex = 2, PriorRevisionSha256 = new[] { "x" } },
            r with { OutSha256 = "x" },
            r with { InSha256 = H64('A') },
            r with { SigRevSha256 = "" },
            r with { FileName = new string('а', 121) },
            r with { Cms = Array.Empty<byte>() },
            r with { Cms = new byte[28673] },
        })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.RegisterSealedPdfAsync(Org, bad));
        }
        foreach (var org in new[] { "", "PNOMN-1", "NTRMN-", "NTRMN-ab_c" })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.RegisterSealedPdfAsync(org, r));
        }
        Assert.Empty(h.Requests);
        // Хил: 120 тэмдэгт, 28 672 байт, prior revision + CMS холимог.
        (r with
        {
            FileName = new string('а', 120),
            Cms = new byte[28672],
            RevIndex = 3,
            PriorCmsSha256 = new[] { H64('d') },
            PriorRevisionSha256 = new[] { H64('e') },
        }).Validate();
    }

    // Go TestRegisterSealedPDFErrors: код бүр CA-ийн HTTP статусаар → EidApiException.Code (429/503 — Retryable, RetryAfter);
    // 403 code-гүй → EidForbiddenException; 501.
    [Fact]
    public async Task RegisterSealedPdfErrors()
    {
        var status = new Dictionary<string, int>
        {
            [PdfErrorCodes.RequestTooLarge] = 413, [EidErrorCodes.RequestInvalid] = 400, [EidErrorCodes.RateLimited] = 429,
            [EidErrorCodes.StateUnavailable] = 503, [PdfErrorCodes.CmsInvalid] = 400, [PdfErrorCodes.SignerMismatch] = 409,
            [PdfErrorCodes.SignerCertInvalid] = 409, [PdfErrorCodes.SignatureInvalid] = 400, [EidErrorCodes.SealNotFound] = 409,
            [EidErrorCodes.SealDocMismatch] = 409, [PdfErrorCodes.TimestampInvalid] = 400, [EidErrorCodes.DocIdReserved] = 409,
            [PdfErrorCodes.DocIdConflict] = 409, [PdfErrorCodes.PriorMismatch] = 409, [PdfErrorCodes.RegistryConflict] = 409,
        };
        Assert.Equal(status.Count, SealRegisterErrorCodes.All.Count);
        foreach (var code in SealRegisterErrorCodes.All)
        {
            var st = status[code];
            var (c, _, _) = Rig.Create(_ => Rig.Json(st, "{\"error\":\"x\",\"code\":\"" + code + "\"}", st is 429 or 503 ? "600" : null));
            var e = await Assert.ThrowsAnyAsync<EidApiException>(() => c.Seal.RegisterSealedPdfAsync(Org, Reg()));
            Assert.Equal(code, e.Code);
            Assert.Equal(st, e.Status);
            var retry = st is 429 or 503;
            Assert.Equal(retry, e.Retryable);
            if (retry)
            {
                Assert.Equal(TimeSpan.FromSeconds(600), e.RetryAfter);
            }
        }
        var (c1, _, _) = Rig.Create(409, "{\"error\":\"x\",\"code\":\"SEAL_NOT_FOUND\"}");
        await Assert.ThrowsAsync<EidSealNotFoundException>(() => c1.Seal.RegisterSealedPdfAsync(Org, Reg()));
        (c1, _, _) = Rig.Create(409, "{\"error\":\"x\",\"code\":\"SEAL_DOC_MISMATCH\"}");
        await Assert.ThrowsAsync<EidSealDocMismatchException>(() => c1.Seal.RegisterSealedPdfAsync(Org, Reg()));
        (c1, _, _) = Rig.Create(409, "{\"error\":\"x\",\"code\":\"DOC_ID_RESERVED\"}");
        await Assert.ThrowsAsync<EidDocIdReservedException>(() => c1.Seal.RegisterSealedPdfAsync(Org, Reg()));
        (c1, _, _) = Rig.Create(403, "{\"error\":\"SEAL эрхгүй\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c1.Seal.RegisterSealedPdfAsync(Org, Reg()));
        (c1, _, _) = Rig.Create(501, "{\"error\":\"тамганы бүртгэл тохируулаагүй\"}");
        Assert.Equal(501, (await Assert.ThrowsAnyAsync<EidApiException>(() => c1.Seal.RegisterSealedPdfAsync(Org, Reg()))).Status);
    }

    // Go TestRegisterSealedPDFPriorMismatch: өмнөх мөр горим A бол 409 PRIOR_MISMATCH → RegisterSignature-тэй ижил хослолоор дахин.
    [Fact]
    public async Task RegisterSealedPdfPriorMismatch()
    {
        var reg = Reg() with
        {
            RevIndex = 3,
            PriorCmsSha256 = new[] { H64('1'), H64('2') },
            PriorSignatures = new[] { new PdfPriorSignature(H64('1'), H64('3')), new PdfPriorSignature(H64('2'), H64('4')) },
        };

        async Task<(PdfSignatureRegistered? Out, int Calls, Exception? Err)> Try(SealRegistration r, string wantCms, string wantRev, string code)
        {
            var (c, h, _) = Rig.Create(q =>
            {
                if (UnknownField(q))
                {
                    return Rig.Json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}");
                }
                var j = q.Json();
                string Join(string k) => j.TryGetProperty(k, out var a) ? string.Join(",", a.EnumerateArray().Select(x => x.GetString())) : "";
                return Join("priorCmsSha256") == wantCms && Join("priorRevisionSha256") == wantRev
                    ? Rig.Json(201, Registered)
                    : Rig.Json(409, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
            });
            try
            {
                return (await c.Seal.RegisterSealedPdfAsync(Org, r), h.Requests.Count, null);
            }
            catch (EidException e)
            {
                return (null, h.Requests.Count, e);
            }
        }

        var (o, n, err) = await Try(reg, H64('2'), H64('3'), PdfErrorCodes.PriorMismatch);
        Assert.True(err is null && o!.Created && n == 2, "эхний мөр горим A: " + err + " " + n);
        (_, n, err) = await Try(reg, "-", "-", PdfErrorCodes.PriorMismatch);
        Assert.True(err is EidApiException { Code: PdfErrorCodes.PriorMismatch } && n == 4, "таарахгүй: " + err + " " + n);
        (_, n, err) = await Try(reg, "-", "-", EidErrorCodes.SealNotFound);
        Assert.True(err is EidSealNotFoundException && n == 1, "өөр алдаа шууд: " + err + " " + n);
        (_, n, err) = await Try(reg with { PriorCmsSha256 = new[] { H64('2') }, PriorRevisionSha256 = new[] { H64('3') } }, "-", "-",
            PdfErrorCodes.PriorMismatch);
        Assert.True(err is not null && n == 1, "гараар ангилсан: " + err + " " + n);
    }

    // Go TestSealRegisterErrorCodes: CA memory.SealRegisterErrorCodes (main 70c0e09c)-тэй ЯГ ижил дараалал, давхардалгүй.
    [Fact]
    public void ErrorCodesInCaOrder()
    {
        Assert.Equal(new[]
        {
            "REQUEST_TOO_LARGE", "REQUEST_INVALID", "RATE_LIMITED", "STATE_UNAVAILABLE", "CMS_INVALID", "SIGNER_MISMATCH",
            "SIGNER_CERT_INVALID", "SIGNATURE_INVALID", "SEAL_NOT_FOUND", "SEAL_DOC_MISMATCH", "TIMESTAMP_INVALID", "DOC_ID_RESERVED",
            "DOC_ID_CONFLICT", "PRIOR_MISMATCH", "REGISTRY_CONFLICT",
        }, SealRegisterErrorCodes.All);
    }

    // Go TestSealForDocument: POST /seal/{orgEtsi}-д {digest, hashType SHA256, docId, revIndex}; SealAsync нөөцгүй; буруу нөөц
    // (CA TestSealReservationValidation-ийн векторууд) сүлжээнд гарахгүй.
    [Fact]
    public async Task SealForDocument()
    {
        var (key, der) = SealTests.SealCert(X509KeyUsageFlags.NonRepudiation);
        using var disposeKey = key;
        var (c, h, _) = Rig.Create(r =>
        {
            var body = r.Json();
            if (body.EnumerateObject().Any(p => !SealTests.CaSealRequestFields.Contains(p.Name)))
            {
                return Rig.Json(400, "{\"code\":\"REQUEST_INVALID\"}");
            }
            var digest = Convert.FromBase64String(body.GetProperty("digest").GetString()!);
            var sig = key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
            return Rig.Json(200, "{\"orgEtsi\":\"" + Org + "\",\"signature\":{\"value\":\"" + Convert.ToBase64String(sig) +
                "\",\"signatureAlgorithm\":\"ecdsa-with-SHA256\"},\"cert\":{\"value\":\"" + Convert.ToBase64String(der) +
                "\",\"certificateLevel\":\"QUALIFIED\"},\"sealedAt\":\"2026-11-25T04:05:06Z\"}");
        });
        var d = SHA256.HashData("dtbs"u8);
        await c.Seal.SealForDocumentAsync(Org, d, DocId, 2);
        Assert.Equal("/seal/" + Org, h.Last.Path);
        JsonAssert.Equivalent("{\"digest\":\"" + Convert.ToBase64String(d) + "\",\"hashType\":\"SHA256\",\"docId\":\"" + DocId + "\",\"revIndex\":2}",
            h.Last.Json());
        await c.Seal.SealAsync(Org, d);
        Assert.DoesNotContain("docId", h.Last.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("revIndex", h.Last.Body, StringComparison.Ordinal);
        var n = h.Requests.Count;
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealForDocumentAsync(Org, d, DocId.ToUpperInvariant(), 1));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealForDocumentAsync(Org, d, DocId, 0));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealForDocumentAsync(Org, d, DocId, 17));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealForDocumentAsync(Org, d, "", 2));
        await Assert.ThrowsAsync<ArgumentException>(() => c.Seal.SealForDocumentAsync(Org, new byte[48], DocId, 1));
        Assert.Equal(n, h.Requests.Count);
    }

    // Go TestErrInvalidPathParameter (seal registration): хоосон / "." / ".." orgEtsi сүлжээнд гарахгүй.
    [Fact]
    public async Task RegistrationRouteRejectsDotSegments()
    {
        var (c, h, _) = Rig.Create(201, Registered);
        foreach (var bad in new[] { "", ".", ".." })
        {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => c.Seal.RegisterSealedPdfAsync(bad, Reg()));
            Assert.Throws<ArgumentException>(() => RpRoutes.SealRegistrations.Expand(bad));
        }
        Assert.Empty(h.Requests);
    }
}
