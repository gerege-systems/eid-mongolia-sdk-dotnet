using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace GeregeSystems.EidMongolia.Tests;

public class RouteTests
{
    [Fact]
    public void RouteTableMirrorsGo()
    {
        // Go routes.go rpRoutes — 32 зам, давхардалгүй.
        Assert.Equal(32, RpRoutes.All.Count);
        Assert.Equal(RpRoutes.All.Count, RpRoutes.All.Select(r => r.Method + " " + r.Path).Distinct().Count());
        Assert.All(RpRoutes.All, r => Assert.Contains(r.Method, new[] { "GET", "POST" }));
        Assert.All(RpRoutes.All, r => Assert.StartsWith("/", r.Path, StringComparison.Ordinal));
    }

    [Fact]
    public void ExpandEscapesAndChecksArity()
    {
        Assert.Equal("/session/a%2Fb%3Fc", RpRoutes.Session.Expand("a/b?c"));
        Assert.Equal("/seal/certificate/NTRMN-1/requests/r1", RpRoutes.SealCertificateRequestStatus.Expand("NTRMN-1", "r1"));
        Assert.Equal("/pdf/signatures", RpRoutes.PdfSignatures.Expand());
        Assert.Throws<InvalidOperationException>(() => RpRoutes.Session.Expand());
        Assert.Throws<InvalidOperationException>(() => RpRoutes.PdfSignatures.Expand("x"));
        Assert.Throws<InvalidOperationException>(() => RpRoutes.SealCertificateRequestStatus.Expand("NTRMN-1"));
    }

    [Theory]
    [InlineData("/authentication/notification/etsi/PNOMN-X?x=1", "/authentication/notification/etsi/…")]
    [InlineData("/signature/notification/document/PNOMN-X-MOCK-Q#f", "/signature/notification/document/…")]
    [InlineData("/signature/notification/linked/PNOMN-X-MOCK-Q", "/signature/notification/linked/…")]
    [InlineData("/seal/certificate/NTRMN-1/requests/abc", "/seal/certificate/…/requests/…")]
    [InlineData("/seal/grants/g1", "/seal/grants/…")]
    [InlineData("/seal/NTRMN-1", "/seal/…")]
    [InlineData("/session/abc", "/session/abc")]
    [InlineData("/.well-known/eid", "/.well-known/eid")]
    public void MaskPathHidesIdentifiers(string path, string want)
    {
        Assert.Equal(want, RpRoutes.MaskPath(path));
    }
}

/// <summary>
/// SDK ↔ live <c>/.well-known/eid</c> гэрээ (Go contract_test.go, TS contract.test.ts). Сүлжээ шаарддаг тул зөвхөн
/// <c>EID_CONTRACT=1</c> үед (<c>.github/workflows/contract.yml</c>, өдөр бүр); бусад үед юу ч хийхгүй.
/// </summary>
public class ContractTests
{
    private const string DiscoveryUrl = "https://rp.eidmongolia.mn/.well-known/eid";
    private static readonly Regex EndpointRe = new(@"^(GET|POST|PUT|PATCH|DELETE)\s+(https?://\S+)");
    private static readonly Regex PlaceholderRe = new(@"\{[^}]*\}");

    private readonly ITestOutputHelper _out;

    public ContractTests(ITestOutputHelper output) => _out = output;

    private static string Norm(string method, string path)
    {
        var i = path.IndexOf('?', StringComparison.Ordinal);
        if (i >= 0)
        {
            path = path[..i];
        }
        return method + " " + PlaceholderRe.Replace(path, "{}");
    }

    private static void Collect(JsonElement v, List<(string Method, string Url)> output)
    {
        switch (v.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in v.EnumerateObject())
                {
                    Collect(p.Value, output);
                }
                break;
            case JsonValueKind.String:
                var m = EndpointRe.Match(v.GetString()!);
                if (m.Success)
                {
                    output.Add((m.Groups[1].Value, m.Groups[2].Value));
                }
                break;
        }
    }

    private void Warn(string title, IReadOnlyCollection<string> lines)
    {
        foreach (var l in lines)
        {
            _out.WriteLine("WARN: " + title + ": " + l);
        }
    }

    [Fact]
    [Trait("Category", "Contract")]
    public async Task RpRoutesMatchLiveDiscovery()
    {
        if (Environment.GetEnvironmentVariable("EID_CONTRACT") != "1")
        {
            _out.WriteLine("EID_CONTRACT != 1 — гэрээний тест алгасав");
            return;
        }
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        using var req = new HttpRequestMessage(HttpMethod.Get, DiscoveryUrl);
        req.Headers.Accept.ParseAdd("application/json");
        using var res = await http.SendAsync(req);
        Assert.True(res.IsSuccessStatusCode, "GET " + DiscoveryUrl + ": HTTP " + (int)res.StatusCode);
        using var d = JsonDocument.Parse(await res.Content.ReadAsByteArrayAsync());
        var rpBase = d.RootElement.GetProperty("rp_api_base").GetString();
        Assert.Equal(EidClient.DefaultBaseUrl, rpBase);

        var eps = new List<(string Method, string Url)>();
        Collect(d.RootElement.GetProperty("endpoints"), eps);
        Assert.NotEmpty(eps);

        string? RpKey((string Method, string Url) e) =>
            e.Url.StartsWith(rpBase + "/", StringComparison.Ordinal) ? Norm(e.Method, e.Url[rpBase!.Length..]) : null;

        var rp = new HashSet<string>(eps.Select(RpKey).OfType<string>(), StringComparer.Ordinal);
        var covered = new HashSet<string>(StringComparer.Ordinal);
        var missing = new List<string>();
        foreach (var r in RpRoutes.All)
        {
            var k = Norm(r.Method, r.Path);
            covered.Add(k);
            if (!rp.Contains(k))
            {
                missing.Add(r.Method + " " + r.Path);
            }
        }

        var undiscovered = new List<string>();
        var nowDiscovered = new List<string>();
        foreach (var r in RpRoutes.Undiscovered)
        {
            var k = Norm(r.Method, r.Path);
            covered.Add(k);
            (rp.Contains(k) ? nowDiscovered : undiscovered).Add(r.Method + " " + r.Path);
        }
        Warn("SDK зам CA-д бий ч discovery-д алга", undiscovered);
        Warn("discovery-д орсон — Undiscovered-оос All руу шилжүүл", nowDiscovered);

        var uncovered = eps.Where(e => RpKey(e) is not { } k || !covered.Contains(k))
            .Select(e => e.Method + " " + e.Url).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Warn("discovery-д байгаа ч SDK хамраагүй", uncovered);
        _out.WriteLine("SDK " + RpRoutes.All.Count + " зам тулгав; discovery-д SDK хамраагүй " + uncovered.Count + " (WARN)");

        Assert.True(missing.Count == 0, "SDK зам discovery-д алга:\n" + string.Join("\n", missing));
    }

    /// <summary>Live discovery (EID_CONTRACT=1 үед); бусад үед null.</summary>
    private async Task<JsonElement?> DiscoveryAsync()
    {
        if (Environment.GetEnvironmentVariable("EID_CONTRACT") != "1")
        {
            _out.WriteLine("EID_CONTRACT != 1 — гэрээний тест алгасав");
            return null;
        }
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        using var req = new HttpRequestMessage(HttpMethod.Get, DiscoveryUrl);
        req.Headers.Accept.ParseAdd("application/json");
        using var res = await http.SendAsync(req);
        Assert.True(res.IsSuccessStatusCode, "GET " + DiscoveryUrl + ": HTTP " + (int)res.StatusCode);
        using var d = JsonDocument.Parse(await res.Content.ReadAsByteArrayAsync());
        return d.RootElement.Clone();
    }

    /// <summary>
    /// Go contract_test.go TestContractPDFSignaturesBody: discovery-ийн endpoints.pdf.signatures-ийн биеийн талбарууд
    /// (<c>{a, b?, …}</c>) нь <see cref="PdfSignatureRegistration"/>-ийн JSON түлхүүрүүдтэй ЯГ тэнцүү (CA DisallowUnknownFields).
    /// </summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task PdfSignaturesBodyMatchesDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        var desc = d.GetProperty("endpoints").GetProperty("pdf").GetProperty("signatures").GetString() ?? "";
        int i = desc.IndexOf('{', StringComparison.Ordinal), j = desc.IndexOf('}', StringComparison.Ordinal);
        Assert.True(i >= 0 && j > i, "endpoints.pdf.signatures-д бие алга: " + desc);
        var want = desc[(i + 1)..j].Split(',').Select(f => f.Trim().TrimEnd('?')).OrderBy(x => x, StringComparer.Ordinal);
        var got = PdfTests.JsonNames(typeof(PdfSignatureRegistration)).OrderBy(x => x, StringComparer.Ordinal);
        Assert.Equal(want, got);
    }

    /// <summary>Go contract_test.go TestContractPDFRegisterErrorCodes: pdfSigning.registerErrorCodes == <see cref="PdfErrorCodes.All"/> (олонлогоор).</summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task PdfRegisterErrorCodesMatchDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        if (!d.TryGetProperty("pdfSigning", out var ps) || !ps.TryGetProperty("registerErrorCodes", out var codes))
        {
            Assert.Fail("pdfSigning.registerErrorCodes discovery-д алга");
            return;
        }
        var ca = codes.EnumerateArray().Select(x => x.GetString()!).Distinct().OrderBy(x => x, StringComparer.Ordinal);
        Assert.Equal(ca, PdfErrorCodes.All.Distinct().OrderBy(x => x, StringComparer.Ordinal));
    }

    /// <summary>Go contract_test.go TestContractSealSwitches: seal блокийн disabledCode == SEAL_SERVICE_DISABLED.</summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task SealSwitchesMatchDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        Assert.True(d.TryGetProperty("seal", out var s), "discovery-д seal блок алга");
        Assert.True(s.TryGetProperty("issuanceEnabled", out var ie) && ie.ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(s.TryGetProperty("sealingEnabled", out var se) && se.ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.Equal(EidErrorCodes.SealServiceDisabled, s.GetProperty("disabledCode").GetString());
    }

    /// <summary>
    /// Go contract_test.go TestContractSealErrorCodes: endpoints.seal.*-ийн тайлбарт нэрлэсэн тамганы code бүр
    /// <see cref="EidErrorCodes"/>-д байх ёстой, хүлээгдэж буй code-ууд тайлбарт байх ёстой.
    /// </summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task SealErrorCodesMatchDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        var known = typeof(EidErrorCodes).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral).Select(f => (string)f.GetRawConstantValue()!).ToHashSet(StringComparer.Ordinal);
        var codeRe = new Regex(@"\b(?:ORG_NOT_ACTIVE|SEAL_[A-Z_]+)\b");
        var named = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var errors = new List<string>();
        foreach (var p in d.GetProperty("endpoints").GetProperty("seal").EnumerateObject())
        {
            named[p.Name] = new HashSet<string>(StringComparer.Ordinal);
            foreach (Match m in codeRe.Matches(p.Value.GetString() ?? ""))
            {
                named[p.Name].Add(m.Value);
                if (!known.Contains(m.Value))
                {
                    errors.Add("endpoints.seal." + p.Name + ": SDK-д танигдаагүй code " + m.Value);
                }
            }
        }
        var want = new Dictionary<string, string[]>
        {
            ["seal"] = new[]
            {
                EidErrorCodes.OrgNotActive, EidErrorCodes.SealNotIssued, EidErrorCodes.SealCertRevoked, EidErrorCodes.SealKeyUnavailable,
                EidErrorCodes.SealCertExpired, EidErrorCodes.SealCertNotYetValid, EidErrorCodes.SealServiceDisabled,
            },
            ["certificate_get"] = new[] { EidErrorCodes.SealNotIssued, EidErrorCodes.SealCertRevoked, EidErrorCodes.SealCertExpired, EidErrorCodes.SealCertNotYetValid },
            ["certificate_issue"] = new[] { EidErrorCodes.OrgNotActive, EidErrorCodes.SealApproverUnavailable, EidErrorCodes.SealServiceDisabled },
            ["grant_request"] = new[] { EidErrorCodes.OrgNotActive, EidErrorCodes.SealGrantAlreadyApproved, EidErrorCodes.SealApproverUnavailable },
            ["grant_status"] = new[] { EidErrorCodes.SealGrantNotFound },
        };
        foreach (var (key, codes) in want)
        {
            foreach (var code in codes)
            {
                if (!named.TryGetValue(key, out var set) || !set.Contains(code))
                {
                    errors.Add("endpoints.seal." + key + "-д " + code + " алга");
                }
            }
        }
        Assert.True(errors.Count == 0, string.Join("\n", errors));
    }

    /// <summary>
    /// Go contract_test.go TestContractShare / TS contract.test.ts «Share»: endpoints.share-ийн multipart талбарууд
    /// (<c>{file, filename?, to (1–5), …}</c>) нь <see cref="ShareWire.FormFields"/>-тэй ЯГ тэнцүү (CA үл мэдэгдэх талбарыг
    /// 400-аар татгалздаг), share блок <see cref="ShareInfo"/>-д задарна.
    /// </summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task ShareMatchesDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        var rpBase = d.GetProperty("rp_api_base").GetString();
        var desc = d.GetProperty("endpoints").GetProperty("share").GetString() ?? "";
        Assert.StartsWith("POST " + rpBase + RpRoutes.Share.Path + " ", desc, StringComparison.Ordinal);
        int i = desc.IndexOf('{', StringComparison.Ordinal), j = desc.IndexOf('}', StringComparison.Ordinal);
        Assert.True(i >= 0 && j > i, "endpoints.share-д талбар алга: " + desc);
        var want = desc[(i + 1)..j].Split(',').Select(f =>
        {
            f = f.Trim();
            var k = f.IndexOf(' ', StringComparison.Ordinal); // "to (1–5)"
            return (k >= 0 ? f[..k] : f).TrimEnd('?');
        }).OrderBy(x => x, StringComparer.Ordinal);
        Assert.Equal(want, ShareWire.FormFields.OrderBy(x => x, StringComparer.Ordinal));
        var raw = System.Text.Encoding.UTF8.GetBytes(d.GetRawText());
        var s = Discovery.Block<ShareInfo>(raw, "share", (v, e) => v with { Raw = e });
        Assert.NotNull(s.Raw);
        Assert.Equal(rpBase + RpRoutes.Share.Path, s.Endpoint);
        Assert.True(s.MaxFileBytes > 0 && s.MaxRecipients > 0 && s.Formats.Count > 0, "share блок: " + s);
        Assert.True(s.Quota.PerRpHour > 0 && s.Quota.PerRpDay > 0 && s.Quota.PerRecipientDay > 0, "share.quota: " + s.Quota);
        _out.WriteLine("share.enabled=" + s.Enabled + " maxFileBytes=" + s.MaxFileBytes + " maxRecipients=" + s.MaxRecipients);
    }

    /// <summary>
    /// Go contract_test.go TestContractTokenCertificate: tokenCertificate блок <see cref="TokenCertInfo"/>-д задарч, issue/result
    /// нь <see cref="RpRoutes"/>-тэй таарна; scopeLockedOnRenewal, appTransaction "optional", personalAutoSupersede, dryRun.
    /// </summary>
    [Fact]
    [Trait("Category", "Contract")]
    public async Task TokenCertificateMatchesDiscovery()
    {
        if (await DiscoveryAsync() is not { } d)
        {
            return;
        }
        var rpBase = d.GetProperty("rp_api_base").GetString();
        var t = Discovery.Block<TokenCertInfo>(System.Text.Encoding.UTF8.GetBytes(d.GetRawText()), "tokenCertificate", (v, e) => v with { Raw = e });
        Assert.NotNull(t.Raw);
        Assert.Equal(rpBase + RpRoutes.TokenCertificate.Path, t.Issue);
        Assert.Equal(rpBase + RpRoutes.TokenCertificateResult.Path, t.Result);
        Assert.True(t.ScopeLockedOnRenewal, "scopeLockedOnRenewal");
        Assert.Equal("optional", t.AppTransaction);
        Assert.True(t.PersonalAutoSupersede, "personalAutoSupersede");
        Assert.True(t.DryRun, "dryRun");
    }
}
