using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Go share_test.go-ийн порт (POST /share multipart, ShareInfo).</summary>
public class ShareTests
{
    private const string Pdf = "%PDF-1.7\n…";

    private sealed record Part(string Name, string? Filename, string? ContentType, string Value);

    /// <summary>multipart/form-data биеийг хэсэг болгоно (Go readShareParts).</summary>
    private static List<Part> Parts(string contentType, string body)
    {
        Assert.StartsWith("multipart/form-data; boundary=", contentType, StringComparison.Ordinal);
        var boundary = contentType["multipart/form-data; boundary=".Length..];
        var chunks = body.Split("--" + boundary);
        Assert.Equal("", chunks[0]);
        Assert.Equal("--\r\n", chunks[^1]);
        var output = new List<Part>();
        foreach (var chunk in chunks[1..^1])
        {
            Assert.StartsWith("\r\n", chunk, StringComparison.Ordinal);
            Assert.EndsWith("\r\n", chunk, StringComparison.Ordinal);
            var c = chunk[2..^2];
            var sep = c.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var headers = c[..sep].Split("\r\n");
            var disp = headers.Single(x => x.StartsWith("Content-Disposition: form-data; ", StringComparison.Ordinal));
            string? Param(string key)
            {
                var i = disp.IndexOf(key + "=\"", StringComparison.Ordinal);
                return i < 0 ? null : disp[(i + key.Length + 2)..disp.IndexOf('"', i + key.Length + 2)];
            }
            var ct = headers.FirstOrDefault(x => x.StartsWith("Content-Type: ", StringComparison.Ordinal))?["Content-Type: ".Length..];
            output.Add(new Part(Param("name")!, Param("filename"), ct, c[(sep + 4)..]));
        }
        return output;
    }

    private static (EidClient Client, Recorder Http, Func<string> ContentType) Create(Func<Recorded, HttpResponseMessage> respond)
    {
        string? ct = null;
        var (c, h, _) = Rig.Create(r =>
        {
            ct = r.Request.Content?.Headers.ContentType?.ToString();
            return respond(r);
        });
        return (c, h, () => ct!);
    }

    private static ShareRequest Req(IReadOnlyList<string>? to = null) => new() { File = System.Text.Encoding.UTF8.GetBytes(Pdf), To = to ?? new[] { "a@x.mn" } };

    // Go TestShareRequestAndResult.
    [Fact]
    public async Task ShareRequestAndResult()
    {
        var (c, h, ct) = Create(_ => Rig.Json(200, "{\"sent\":2,\"sha256\":\"ab\",\"signatures\":1,\"docID\":\"d-1\"}"));
        var res = await c.ShareAsync(Req(new[] { "a@x.mn", "b@x.mn" }) with { Filename = "гэрээ.pdf", Subject = "Гэрээ", Message = "Зурна уу", Lang = "en" });
        Assert.Equal(2, res.Sent);
        Assert.Equal("ab", res.Sha256);
        Assert.Equal(1, res.Signatures);
        Assert.Equal("d-1", res.DocId);
        Assert.NotNull(res.Raw);
        Assert.Equal("POST", h.Last.Method);
        Assert.Equal("/share", h.Last.Path);
        Assert.Equal("Bearer " + Rig.Creds.ApiSecret, h.Last.Request.Headers.Authorization!.ToString());
        var parts = Parts(ct(), h.Last.Body!);
        Assert.Equal(new[]
        {
            new Part("to", null, null, "a@x.mn"), new Part("to", null, null, "b@x.mn"),
            new Part("subject", null, null, "Гэрээ"), new Part("message", null, null, "Зурна уу"), new Part("lang", null, null, "en"),
            new Part("filename", null, null, "гэрээ.pdf"),
            new Part("file", "document.pdf", "application/pdf", Pdf),
        }, parts);
        Assert.All(parts, p => Assert.Contains(p.Name, ShareWire.FormFields));
    }

    // Go mime/multipart.Writer-ийн байт хэлбэр (CA parseShareRequest).
    [Fact]
    public async Task ShareBodyIsGoMultipartBytes()
    {
        var (c, h, ct) = Create(_ => Rig.Json(200, "{\"sent\":1,\"sha256\":\"cd\",\"signatures\":2}"));
        await c.ShareAsync(Req() with { Filename = "a\"b\\c.pdf" });
        var b = ct()["multipart/form-data; boundary=".Length..];
        Assert.Matches("^[0-9a-f]{60}$", b);
        Assert.Equal(
            "--" + b + "\r\nContent-Disposition: form-data; name=\"to\"\r\n\r\na@x.mn" +
            "\r\n--" + b + "\r\nContent-Disposition: form-data; name=\"filename\"\r\n\r\na\"b\\c.pdf" +
            "\r\n--" + b + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\\\"b\\\\c.pdf\"\r\nContent-Type: application/pdf\r\n\r\n" + Pdf +
            "\r\n--" + b + "--\r\n", h.Last.Body);
    }

    // Go TestShareOptionalFieldsOmitted.
    [Fact]
    public async Task ShareOptionalFieldsOmitted()
    {
        var (c, h, ct) = Create(_ => Rig.Json(200, "{\"sent\":1,\"sha256\":\"cd\",\"signatures\":2}"));
        var res = await c.ShareAsync(Req());
        Assert.Null(res.DocId);
        var parts = Parts(ct(), h.Last.Body!);
        Assert.Equal(2, parts.Count);
        Assert.Equal("to", parts[0].Name);
        Assert.Equal("file", parts[1].Name);
        Assert.Equal("document.pdf", parts[1].Filename);
    }

    // Go TestShareErrors.
    [Fact]
    public async Task ShareErrors()
    {
        async Task<EidShareException> Fail(int status, string body, string? retryAfter = null)
        {
            var (c, _, _) = Rig.Create(_ => Rig.Json(status, body, retryAfter));
            var e = await Assert.ThrowsAsync<EidShareException>(() => c.ShareAsync(Req()));
            Assert.Equal(status, e.Status);
            Assert.StartsWith("eid: share ", e.Message, StringComparison.Ordinal);
            Assert.IsAssignableFrom<EidApiException>(e);
            return e;
        }

        var e = await Fail(422, "{\"error\":\"…\",\"code\":\"FILE_NOT_SIGNED\",\"reason\":\"untrusted\"}");
        Assert.Equal(ShareErrorCodes.FileNotSigned, e.Code);
        Assert.Equal(ShareReasons.Untrusted, e.Reason);

        e = await Fail(502, "{\"error\":\"…\",\"code\":\"MAIL_FAILED\",\"sent\":1,\"failed\":1,\"recipients\":[\"sent\",\"failed\"]}");
        Assert.Equal(ShareErrorCodes.MailFailed, e.Code);
        Assert.Equal(1, e.Sent);
        Assert.Equal(1, e.Failed);
        Assert.Equal(new[] { ShareRecipientStatuses.Sent, ShareRecipientStatuses.Failed }, e.Recipients);
        Assert.False(e.Retryable);

        e = await Fail(429, "{\"error\":\"…\",\"code\":\"RATE_LIMITED\"}", "30");
        Assert.Equal(TimeSpan.FromSeconds(30), e.RetryAfter);
        Assert.True(e.Retryable);

        e = await Fail(503, "{\"error\":\"…\",\"code\":\"VALIDATOR_BUSY\"}", "30");
        Assert.Equal(ShareErrorCodes.ValidatorBusy, e.Code);
        Assert.True(e.Retryable);

        e = await Fail(503, "{\"error\":\"…\",\"code\":\"SHARE_DISABLED\"}");
        Assert.Equal(ShareErrorCodes.ShareDisabled, e.Code);
        Assert.False(e.Retryable);

        e = await Fail(400, "{\"error\":\"…\",\"code\":\"REQUEST_INVALID\"}");
        Assert.IsType<EidRequestInvalidException>(e.InnerException);
        Assert.Equal(EidErrorCodes.RequestInvalid, e.Code);

        e = await Fail(413, "<html>nginx</html>");
        Assert.Null(e.Code);
        Assert.Equal("eid: share 413", e.Message);
    }

    // Go TestShareAuthErrors.
    [Fact]
    public async Task ShareAuthErrors()
    {
        var (c, _, _) = Rig.Create(401, "{\"error\":\"…\"}");
        await Assert.ThrowsAsync<EidAuthenticationException>(() => c.ShareAsync(Req()));
        (c, _, _) = Rig.Create(403, "{\"error\":\"…\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c.ShareAsync(Req()));
    }

    // Go TestShareInfo.
    [Fact]
    public async Task ShareInfo()
    {
        var (c, h, _) = Rig.Create(200, "{\"share\":{\"enabled\":false,\"endpoint\":\"https://rp.eidmongolia.mn/share\"," +
            "\"formats\":[{\"extension\":\".pdf\",\"mime\":\"application/pdf\",\"name\":\"pdf\"}],\"languages\":[\"mn\",\"en\"]," +
            "\"maxFileBytes\":3080192,\"maxFilenameChars\":120,\"maxMessageChars\":1000,\"maxRecipients\":5,\"maxSubjectChars\":150," +
            "\"permission\":\"SIGN\",\"quota\":{\"perRPDay\":200,\"perRPHour\":30,\"perRecipientDay\":10},\"requiresValidSignature\":true}}");
        var s = await c.ShareInfoAsync();
        Assert.Equal("/.well-known/eid", h.Last.Path);
        Assert.False(s.Enabled);
        Assert.Equal(3080192, s.MaxFileBytes);
        Assert.Equal(5, s.MaxRecipients);
        Assert.Equal(new ShareQuota { PerRpHour = 30, PerRpDay = 200, PerRecipientDay = 10 }, s.Quota);
        Assert.Equal(".pdf", Assert.Single(s.Formats).Extension);
        Assert.True(s.RequiresValidSignature);
        Assert.NotNull(s.Raw);

        (c, _, _) = Rig.Create(200, "{}");
        s = await c.ShareInfoAsync();
        Assert.False(s.Enabled);
        Assert.Null(s.Raw);
    }
}
