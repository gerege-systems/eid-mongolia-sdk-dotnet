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
}
