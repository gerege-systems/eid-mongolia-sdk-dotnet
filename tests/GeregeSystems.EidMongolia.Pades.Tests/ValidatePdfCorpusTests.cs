using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// ValidatePDF conformance (pades-validate/1): Go SDK pades/testdata/validate (build/go-sdk-validate.ref,
/// build/sync-validate.sh) — тохиолдол бүрийн тайланг Go <c>pades.ValidatePDF</c>-ийн гаргасан JSON-той deep-equal (TS
/// validate-golden.test.ts-тэй ижил стандарт: <c>JSON.parse(JSON.stringify(report))</c> ≡ expect, алдаа бол
/// <c>{"error": code}</c>). Онлайн OCSP/CRL = тогтмол fixture (түлхүүр <c>METHOD URL sha256(body)[:16]</c>, бусад → 404).
/// </summary>
public class ValidatePdfCorpusTests
{
    internal static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "testdata", "pades-validate");
    private static readonly JsonElement Manifest = LoadManifest();

    private static JsonElement LoadManifest()
    {
        using var d = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Dir, "validate", "manifest.json")));
        return d.RootElement.Clone();
    }

    public static IEnumerable<object[]> Cases() =>
        Manifest.GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("name").GetString()! });

    private static JsonElement Case(string name) =>
        Manifest.GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);

    internal static byte[] Read(string rel) => File.ReadAllBytes(Path.Combine(Dir, Path.Combine(rel.Split('/'))));

    internal static byte[] PemDer(string rel)
    {
        var pem = Encoding.ASCII.GetString(Read(rel));
        var f = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[f.Base64Data]);
    }

    internal static List<byte[]> Ders(string key) => Manifest.GetProperty(key).EnumerateArray().Select(e => PemDer(e.GetString()!)).ToList();

    internal static DateTimeOffset ManifestTime => DateTimeOffset.Parse(Manifest.GetProperty("time").GetString()!, CultureInfo.InvariantCulture);

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    /// <summary>Корпусын хуулбар SHA256SUMS-тэй таарна; manifest-ийн заасан файл бүр бий; илүү файлгүй.</summary>
    [Fact]
    public void Manifest_HashesMatch()
    {
        var sums = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(Path.Combine(Dir, "SHA256SUMS")))
        {
            if (line.Length == 0) continue;
            var hash = line[..64];
            var path = line[66..];
            sums[path] = hash;
            Assert.True(Sha(Read(path)) == hash, "hash mismatch: " + path);
        }
        Assert.True(sums.ContainsKey("validate/manifest.json"));
        var files = Directory.GetFiles(Dir, "*", SearchOption.AllDirectories)
            .Select(p => Path.GetRelativePath(Dir, p).Replace('\\', '/'))
            .Where(p => p != "SHA256SUMS")
            .ToList();
        Assert.Equal(sums.Keys.OrderBy(x => x, StringComparer.Ordinal), files.OrderBy(x => x, StringComparer.Ordinal));
        var text = File.ReadAllText(Path.Combine(Dir, "validate", "manifest.json"));
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, "\"((?:golden|validate)/[^\"]+)\""))
        {
            var rel = m.Groups[1].Value;
            if (rel.StartsWith("validate/", StringComparison.Ordinal) || rel.StartsWith("golden/", StringComparison.Ordinal))
            {
                if (rel.EndsWith('/')) continue;
                Assert.True(sums.ContainsKey(rel) || sums.ContainsKey("validate/" + rel), "manifest-ийн файл SHA256SUMS-д алга: " + rel);
            }
        }
        Assert.Equal(67, Manifest.GetProperty("cases").GetArrayLength());
    }

    /// <summary>Корпусын HTTP replay (TS validate-golden.test.ts-ийн fetch-тэй ижил түлхүүр).</summary>
    internal sealed class Replay : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _files;

        public Replay(Dictionary<string, byte[]> files) => _files = files;

        public List<string> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            var key = request.Method.Method + " " + request.RequestUri!.OriginalString + " " + Sha(body)[..16];
            lock (Requests) Requests.Add(key);
            return _files.TryGetValue(key, out var b)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(b) }
                : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new ByteArrayContent(Array.Empty<byte>()) };
        }
    }

    internal static async Task<JsonNode?> Run(byte[] doc, ValidatePdfOptions o)
    {
        try
        {
            var rep = await EidPades.ValidatePdfAsync(doc, o);
            return JsonNode.Parse(rep.ToJson());
        }
        catch (EidPadesException e)
        {
            return new JsonObject { ["error"] = e.RawCode };
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MatchesGoReport(string name)
    {
        var c = Case(name);
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (c.TryGetProperty("http", out var http))
            foreach (var p in http.EnumerateObject()) files[p.Name] = Read("validate/" + p.Value.GetString()!);
        var replay = new Replay(files);
        using var client = new HttpClient(replay);
        bool national = c.TryGetProperty("nationalRoots", out var nr) && nr.GetBoolean();
        var time = c.TryGetProperty("time", out var t) ? DateTimeOffset.Parse(t.GetString()!, CultureInfo.InvariantCulture) : ManifestTime;
        var got = await Run(Read(c.GetProperty("input").GetString()!), new ValidatePdfOptions
        {
            Roots = national ? null : Ders("roots"),
            Issuers = Ders("issuers"),
            Time = time,
            Offline = c.GetProperty("offline").GetBoolean(),
            HttpClient = client,
        });
        if (c.GetProperty("offline").GetBoolean()) Assert.Empty(replay.Requests); // offline — сүлжээ рүү нэг ч хүсэлт үгүй
        var want = JsonNode.Parse(c.GetProperty("expect").GetRawText());
        Assert.True(JsonNode.DeepEquals(want, got), name + "\nwant: " + want!.ToJsonString() + "\ngot:  " + got!.ToJsonString());
    }
}
