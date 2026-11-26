using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

public class PdfTests
{
    /// <summary>
    /// CA <c>dto.PDFSignatureRegisterRequest</c>-ийн JSON түлхүүрүүд (Go pdfregister_test.go <c>caRegisterRequest</c>; CA
    /// handler DisallowUnknownFields).
    /// </summary>
    internal static readonly string[] CaRegisterFields =
    {
        "docID", "revIndex", "medium", "sessionID", "cms", "fileName", "inSha256", "pageSha256", "sigRevSha256", "outSha256",
        "priorCmsSha256", "priorRevisionSha256", "onBehalfOf", "signerEtsi",
    };

    private static readonly PdfSignatureRegistration Reg = new()
    {
        DocId = "d",
        RevIndex = 1,
        Medium = PdfMediums.Phone,
        SessionId = "s",
        Cms = new byte[] { 0x30, 1 },
        FileName = "a.pdf",
        InSha256 = "in",
        PageSha256 = "pg",
        SigRevSha256 = "sr",
        OutSha256 = "out",
        SignerEtsi = "PNOMN-1",
    };

    /// <summary>CA-ийн DisallowUnknownFields-ийг дуурайна: үл мэдэгдэх түлхүүр бол 400 REQUEST_INVALID.</summary>
    private static bool UnknownField(Recorded r) => r.Json().EnumerateObject().Any(p => !CaRegisterFields.Contains(p.Name));

    internal static IEnumerable<string> JsonNames(Type t) =>
        t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetCustomAttribute<JsonIgnoreAttribute>() is null)
            .Select(p => p.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name ?? p.Name);

    [Fact]
    public void RegistrationFieldsMatchCaDto()
    {
        Assert.Equal(CaRegisterFields.OrderBy(x => x, StringComparer.Ordinal), JsonNames(typeof(PdfSignatureRegistration)).OrderBy(x => x, StringComparer.Ordinal));
    }

    // Go pdfregister_test.go TestRegisterSignature.
    [Fact]
    public async Task RegisterSignature()
    {
        var (c, h, _) = Rig.Create(r => UnknownField(r)
            ? Rig.Json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}")
            : Rig.Json(201, "{\"docID\":\"d\",\"revIndex\":1,\"registeredAt\":\"2026-10-14T12:00:00+08:00\",\"verifyUrl\":\"https://ca.eidmongolia.mn/verify/d\"}"));
        var o = await c.Pdf.RegisterSignatureAsync(Reg);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/pdf/signatures", h.Last.Path);
        JsonAssert.Equivalent("""
            {"docID":"d","revIndex":1,"medium":"phone","sessionID":"s","cms":"MAE=","fileName":"a.pdf","inSha256":"in",
             "pageSha256":"pg","sigRevSha256":"sr","outSha256":"out","signerEtsi":"PNOMN-1"}
            """, h.Last.Json());
        Assert.True(o.Created);
        Assert.Equal("d", o.DocId);
        Assert.Equal(1, o.RevIndex);
        Assert.Equal("2026-10-14T12:00:00+08:00", o.RegisteredAt);
        Assert.Equal("https://ca.eidmongolia.mn/verify/d", o.VerifyUrl);
        Assert.DoesNotContain("hasPage", h.Last.Body, StringComparison.Ordinal);

        var n = h.Requests.Count;
        foreach (var bad in new[]
        {
            Reg with { Medium = "x" },
            Reg with { SessionId = "" },
            Reg with { PageSha256 = "" },
            Reg with { Cms = Array.Empty<byte>() },
            Reg with { DocId = "" },
            Reg with { RevIndex = 0 },
        })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => c.Pdf.RegisterSignatureAsync(bad));
        }
        Assert.Equal(n, h.Requests.Count);

        // CA-ийн алдаа → EidApiException.Code.
        var (c2, _, _) = Rig.Create(409, "{\"error\":\"x\",\"code\":\"SIGNER_MISMATCH\"}");
        var e = await Assert.ThrowsAsync<EidApiException>(() => c2.Pdf.RegisterSignatureAsync(Reg));
        Assert.Equal(PdfErrorCodes.SignerMismatch, e.Code);
        Assert.Contains(e.Code!, PdfErrorCodes.All);
    }

    // Go pdfregister_test.go TestRegisterSignatureReplayAndPriorMismatch.
    [Fact]
    public async Task ReplayIsNotCreatedAndTokenOmitsEmptyFields()
    {
        var (c, h, _) = Rig.Create(200, "{\"docID\":\"d\",\"revIndex\":1,\"registeredAt\":\"x\",\"verifyUrl\":\"v\"}");
        var o = await c.Pdf.RegisterSignatureAsync(Reg with { Medium = PdfMediums.Token, SessionId = null, SignerEtsi = "", PriorCmsSha256 = Array.Empty<string>() });
        Assert.False(o.Created);
        Assert.Equal("cms,docID,fileName,inSha256,medium,outSha256,pageSha256,revIndex,sigRevSha256", h.Last.Keys());
    }

    private static readonly PdfSignatureRegistration Reg3 = Reg with
    {
        Medium = PdfMediums.Token,
        SessionId = null,
        SignerEtsi = null,
        RevIndex = 3,
        PageSha256 = null,
        PriorCmsSha256 = new[] { "c1", "c2" },
        PriorSignatures = new[] { new PdfPriorSignature("c1", "v1"), new PdfPriorSignature("c2", "v2") },
    };

    /// <summary>CA зөвхөн (wantCms, wantRev) хослолыг хүлээн авна; бусад нь <paramref name="code"/>.</summary>
    private static async Task<(PdfSignatureRegistered? Result, int Calls, EidException? Error)> Try(PdfSignatureRegistration reg, string wantCms, string wantRev, string code)
    {
        var (c, h, _) = Rig.Create(r =>
        {
            if (UnknownField(r))
            {
                return Rig.Json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}");
            }
            var b = r.Json();
            string Join(string k) => b.TryGetProperty(k, out var a) ? string.Join(",", a.EnumerateArray().Select(x => x.GetString())) : "";
            return Join("priorCmsSha256") == wantCms && Join("priorRevisionSha256") == wantRev
                ? Rig.Json(201, "{\"docID\":\"d\",\"revIndex\":3,\"registeredAt\":\"x\",\"verifyUrl\":\"v\"}")
                : Rig.Json(409, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
        });
        try
        {
            return (await c.Pdf.RegisterSignatureAsync(reg), h.Requests.Count, null);
        }
        catch (EidException e)
        {
            return (null, h.Requests.Count, e);
        }
    }

    [Fact]
    public async Task PriorMismatchRetriesSplits()
    {
        var (o, n, err) = await Try(Reg3, "c2", "v1", PdfErrorCodes.PriorMismatch);
        Assert.Null(err);
        Assert.True(o!.Created);
        Assert.Equal(2, n);

        (o, n, err) = await Try(Reg3, "c1", "v2", PdfErrorCodes.PriorMismatch);
        Assert.Null(err);
        Assert.Equal(4, n);

        (_, n, err) = await Try(Reg3, "-", "-", PdfErrorCodes.PriorMismatch);
        Assert.Equal(PdfErrorCodes.PriorMismatch, Assert.IsAssignableFrom<EidApiException>(err).Code);
        Assert.Equal(4, n);

        (_, n, err) = await Try(Reg3, "-", "-", PdfErrorCodes.RegistryConflict);
        Assert.Equal(PdfErrorCodes.RegistryConflict, err!.Code);
        Assert.Equal(1, n);

        // Гараар ангилсан → оролдохгүй.
        (_, n, err) = await Try(Reg3 with { PriorCmsSha256 = new[] { "c2" }, PriorRevisionSha256 = new[] { "v2" } }, "-", "-", PdfErrorCodes.PriorMismatch);
        Assert.NotNull(err);
        Assert.Equal(1, n);
    }

    // Go pdfregister_test.go TestPriorSplits.
    [Fact]
    public void PriorSplitsOrder()
    {
        var got = PdfService.PriorSplits(2);
        Assert.Equal(3, got.Count);
        Assert.Equal(new[] { true, false }, got[0]);
        Assert.Equal(new[] { true, true }, got[1]);
        Assert.Equal(new[] { false, true }, got[2]);
        Assert.Equal(6, PdfService.PriorSplits(6).Count);
        Assert.Equal(15, PdfService.PriorSplits(4).Count);
    }

    // Go pdfregister_test.go TestPDFRegisterErrorCodes.
    [Fact]
    public void ErrorCodesOrder()
    {
        Assert.Equal(new[]
        {
            "REQUEST_INVALID", "REQUEST_TOO_LARGE", "CMS_INVALID", "SIGNATURE_INVALID", "TIMESTAMP_INVALID",
            "SIGNER_MISMATCH", "SIGNER_CERT_INVALID", "TOKEN_CERT_INVALID", "TOKEN_ORG_MISMATCH", "SESSION_MISMATCH",
            "SESSION_NOT_COMPLETE", "SESSION_FAILED", "CLAIMED_ROLE_MISMATCH", "REPRESENTATION_REVOKED", "DOC_ID_CONFLICT",
            "REGISTRY_CONFLICT", "DOC_NOT_FOUND", "PRIOR_MISMATCH", "RATE_LIMITED", "STATE_UNAVAILABLE",
        }, PdfErrorCodes.All);
        Assert.Equal(PdfErrorCodes.All.Count, PdfErrorCodes.All.Distinct().Count());
    }

    [Fact]
    public async Task UsesPdfTimeout()
    {
        var (c, _, _) = Rig.Create(r => Rig.Json(201, "{}"));
        Assert.Equal(EidClient.DefaultPdfTimeout, c.PdfTimeout);
        var o = await c.Pdf.RegisterSignatureAsync(Reg);
        Assert.True(o.Created);
        Assert.Equal("", o.DocId);
    }
}
