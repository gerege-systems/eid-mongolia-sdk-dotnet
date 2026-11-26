using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Qr;

// GeregeSystems.EidMongolia.Pades 0.16.0-ийн «Миний QR» нийтийн API-г (12 төрөл, гишүүн бүр) хэрэглэгч шиг дуудна —
// сүлжээгүй. Аргумент: төрлүүдийг ачаалах ёстой assembly-ийн нэр (0.16.0: GeregeSystems.EidMongolia.Pades; 0.17.0-д
// TypeForwardedTo-гоор GeregeSystems.EidMongolia). Алдаа бүрийг хэвлээд exit 1.
internal static class Program
{
    private static int _fail;

    private static async Task<int> Main(string[] args)
    {
        // EidQr: тогтмол, Parse, VerifyAsync.
        Check(EidQr.Prefix == "EIDMN-QR1:", "EidQr.Prefix");
        Check(EidQr.DefaultIssuer == "https://ca.eidmongolia.mn", "EidQr.DefaultIssuer");
        Check(EidQr.CitizenIssuingCaSki.Length == 40, "EidQr.CitizenIssuingCaSki");
        Check(EidQr.JwsType == "eidmn-myqr+jwt", "EidQr.JwsType");
        var tok = new string('A', 43);
        var (t, q) = EidQr.Parse(" " + EidQr.Prefix + tok + "\n");
        Check(t == tok && q == EidQr.Prefix + tok, "EidQr.Parse");
        await Expect(() => Task.FromResult(EidQr.Parse("x")), EidQrErrorCodes.FormatInvalid, "EidQr.Parse(x)");

        var expect = new QrExpect("00000000-0000-0000-0000-000000000000", "sid-1", "nonce-1", null, DateTimeOffset.UtcNow);
        Func<X509Certificate2, X509Certificate2?, Task<string>> rev = (_, _) => Task.FromResult("good");
        var trust = new QrTrust(Array.Empty<X509Certificate2>(), null, new[] { EidQr.CitizenIssuingCaSki }, rev, false);
        await Expect(() => EidQr.VerifyAsync("a.b", expect, trust, CancellationToken.None), EidQrErrorCodes.JwsMalformed, "EidQr.VerifyAsync");
        await Expect(() => EidQr.VerifyAsync("", expect), EidQrErrorCodes.JwsMalformed, "EidQr.VerifyAsync(default trust)");

        // Record-ууд: positional конструктор, getter, with, тэнцүү байдал.
        var start = new QrStartRequest(EidQr.Prefix + tok, "nonce-0123456789", "Касс 1");
        Check(start.Qr == EidQr.Prefix + tok && start.Nonce == "nonce-0123456789" && start.RelyingPartyName == "Касс 1", "QrStartRequest");
        Check(new QrStartRequest("x").Nonce is null, "QrStartRequest defaults");
        var s = new QrSession("sid-1", "nonce-1");
        Check(s.SessionId == "sid-1" && s.Nonce == "nonce-1" && (s with { Nonce = "x" }) != s && s == new QrSession("sid-1", "nonce-1"), "QrSession");
        Check(expect.RpUuid.Length == 36 && expect.SessionId == "sid-1" && expect.Nonce == "nonce-1" && expect.Issuer is null && expect.Now is not null, "QrExpect");
        Check(trust.Anchors!.Count == 0 && trust.Intermediates is null && trust.AllowedIssuerSkis!.Count == 1 && trust.Revocation == rev && !trust.RevocationSoftFail, "QrTrust");
        Check(new QrTrust().RevocationSoftFail == false, "QrTrust defaults");
        var signer = new QrSigner(null!, "PNOMN-1", "BAT", "DORJ", "DORJ BAT");
        Check(signer.Certificate is null && signer.Etsi == "PNOMN-1" && signer.GivenName == "BAT" && signer.Surname == "DORJ" && signer.CommonName == "DORJ BAT", "QrSigner");
        using var claims = JsonDocument.Parse("{\"iss\":\"x\"}");
        var data = new List<KeyValuePair<string, string>> { new("reg_no", "УБ90010112") };
        var result = new QrResult("h.p.s", claims.RootElement, data, "citizenid", null, signer, DateTimeOffset.UnixEpoch, "00");
        Check(result.Jws == "h.p.s" && result.Claims.GetProperty("iss").GetString() == "x" && result.Data.Count == 1 && result.Source == "citizenid" &&
              result.Photo is null && result.Signer == signer && result.SignedAt == DateTimeOffset.UnixEpoch && result.Sha256 == "00", "QrResult");
        var check = new QrCheck(true, result);
        Check(check.Complete && check.Result == result && !new QrCheck(false, null).Complete, "QrCheck");

        // EidQrException ба кодууд.
        var ex = new EidQrException(EidQrErrorCodes.SessionFailed, "x", new InvalidOperationException()) { HttpStatus = 409, EndResult = "USER_REFUSED" };
        Check(ex.Code == "SESSION_FAILED" && ex.HttpStatus == 409 && ex.EndResult == "USER_REFUSED" && ex.InnerException is not null, "EidQrException");
        foreach (var f in typeof(EidQrErrorCodes).GetFields())
        {
            Check(f.IsLiteral && f.GetRawConstantValue() is string, "EidQrErrorCodes." + f.Name);
        }
        Check(typeof(EidQrErrorCodes).GetFields().Length == 20, "EidQrErrorCodes: 20 код");

        // Client: options, конструктор, бүх метод — сүлжээ хаалттай HttpClient (→ NETWORK_ERROR).
        using var http = new HttpClient(new Offline());
        var opts = new EidQrOptions
        {
            BaseUrl = "https://rp.example.test",
            RpUuid = expect.RpUuid,
            RpName = "Касс 1",
            ApiSecret = "rp_sk_test",
            HttpClient = http,
            Issuer = null,
            Timeout = TimeSpan.FromSeconds(5),
        };
        Check(opts.BaseUrl == "https://rp.example.test" && opts.HttpClient == http && opts.Timeout == TimeSpan.FromSeconds(5), "EidQrOptions");
        using (var c = new EidQrClient(opts, trust))
        {
            await Expect(() => c.StartAsync(new QrStartRequest("not a qr")), EidQrErrorCodes.FormatInvalid, "EidQrClient.StartAsync(bad)");
            await Expect(() => c.StartAsync(start, CancellationToken.None), EidQrErrorCodes.NetworkError, "EidQrClient.StartAsync");
            await Expect(() => c.ResultAsync(s, TimeSpan.FromSeconds(2), CancellationToken.None), EidQrErrorCodes.NetworkError, "EidQrClient.ResultAsync");
            await Expect(() => c.CheckAsync(s, CancellationToken.None), EidQrErrorCodes.NetworkError, "EidQrClient.CheckAsync");
            await Expect(() => c.CheckAsync(s, TimeSpan.FromSeconds(1), CancellationToken.None), EidQrErrorCodes.NetworkError, "EidQrClient.CheckAsync(poll)");
            await Expect(() => c.VerifyAsync("a.b", s, CancellationToken.None), EidQrErrorCodes.JwsMalformed, "EidQrClient.VerifyAsync");
        }
        new EidQrClient(opts).Dispose();

        var asm = typeof(EidQr).Assembly.GetName();
        Console.WriteLine("GeregeSystems.EidMongolia.Qr: " + asm.Name + " " + asm.Version);
        foreach (var ty in new[]
        {
            typeof(EidQr), typeof(EidQrClient), typeof(EidQrOptions), typeof(EidQrException), typeof(EidQrErrorCodes), typeof(QrStartRequest),
            typeof(QrSession), typeof(QrSigner), typeof(QrResult), typeof(QrExpect), typeof(QrTrust), typeof(QrCheck),
        })
        {
            Check(ty.Assembly == typeof(EidQr).Assembly && ty.Namespace == "GeregeSystems.EidMongolia.Qr", ty.FullName + " (" + ty.Assembly.GetName().Name + ")");
        }
        if (args.Length > 0)
        {
            Check(asm.Name == args[0], "assembly " + asm.Name + " ≠ " + args[0]);
        }
        Console.WriteLine(_fail == 0 ? "compat OK" : "compat FAIL: " + _fail);
        return _fail == 0 ? 0 : 1;
    }

    private static async Task Expect<T>(Func<Task<T>> call, string code, string what)
    {
        try
        {
            await call();
            Check(false, what + ": " + code + " хүлээсэн, алдаагүй");
        }
        catch (EidQrException e)
        {
            Check(e.Code == code, what + ": " + code + " хүлээсэн, " + e.Code + " (" + e.Message + ")");
        }
        catch (Exception e)
        {
            Check(false, what + ": " + code + " хүлээсэн, " + e.GetType().FullName + ": " + e.Message);
        }
    }

    private static void Check(bool ok, string what)
    {
        if (!ok)
        {
            _fail++;
            Console.Error.WriteLine("FAIL: " + what);
        }
    }

    private sealed class Offline : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("offline (compat)");
    }
}
