using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Go reference-ийн golden (testdata/golden, build/go-sdk.ref) — тохиолдол бүрийг Prepare → (manifest-ийн гарын үсэг) →
/// CompleteAsync (HTTP fixture replay, тогтмол nonce/цаг)-аар давтаж БҮТЭН гаралтыг байт-түвшинд тулгана.
/// </summary>
public class GoldenTests
{
    private static readonly JsonElement Manifest = LoadManifest();

    private static JsonElement LoadManifest()
    {
        using var d = JsonDocument.Parse(Fixtures.Read("manifest.json"));
        return d.RootElement.Clone();
    }

    public static IEnumerable<object[]> Cases() =>
        Manifest.GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("name").GetString()! });

    private static JsonElement Case(string name) =>
        Manifest.GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);

    private static byte[] Pem(string name) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", name))).RawData;

    private static string? Str(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static DateTimeOffset Time(string k) => DateTimeOffset.Parse(Manifest.GetProperty(k).GetString()!, CultureInfo.InvariantCulture);

    private static byte[] Input(JsonElement c)
    {
        var input = c.GetProperty("input").GetString()!;
        return input.StartsWith("case:", StringComparison.Ordinal)
            ? Fixtures.Read("output", input[5..] + ".pdf")
            : Fixtures.Read(input.Split('/'));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MatchesGoReference(string name)
    {
        var c = Case(name);
        var p = c.GetProperty("prepare");
        var exp = c.GetProperty("expect");
        var input = Input(c);
        Assert.Equal(Str(exp, "inputSha256"), Fixtures.Sha(input));

        var opts = new PrepareOptions
        {
            SignerCert = Pem("citizen.pem"),
            Chain = new[] { Pem("04.pem"), Pem("03.pem"), Pem("02.pem") },
            SignerName = Str(p, "signerName"),
            Reason = Str(p, "reason"),
            ClaimedRole = Str(p, "claimedRole"),
            SigningTime = Time("signingTime"),
            DocId = Str(p, "docId"),
            VerifyPage = p.TryGetProperty("verifyPage", out var vp) && vp.GetBoolean(),
            VerifyPagePosition = Str(p, "verifyPagePosition"),
            FileName = Str(p, "fileName"),
            Lang = Str(p, "lang"),
            Appearance = p.TryGetProperty("appearance", out var ap) ? new Appearance
            {
                Page = ap.TryGetProperty("page", out var pg) ? pg.GetInt32() : 0,
                X = ap.GetProperty("x").GetDouble(),
                Y = ap.GetProperty("y").GetDouble(),
                Width = ap.GetProperty("width").GetDouble(),
                Height = ap.GetProperty("height").GetDouble(),
                Lang = Str(ap, "lang"),
                Exact = ap.TryGetProperty("exact", out var ex) && ex.GetBoolean(),
                // golden v10 (APPEARANCE_SPEC.md §6): the images inline, as Go pades.PDFImage JSON.
                SignatureImage = ap.TryGetProperty("signatureImage", out var si) ? JsonSerializer.Deserialize<PdfImage>(si.GetRawText()) : null,
                StampImage = ap.TryGetProperty("stampImage", out var ti) ? JsonSerializer.Deserialize<PdfImage>(ti.GetRawText()) : null,
            } : null,
        };

        // PLACEMENT_SPEC.md §6b (golden v7): SuggestPlacement on every visible case — expect.suggestion field-for-field,
        // or expect.suggestionError.
        PlacementSuggestion? sug = null;
        if (opts.Appearance is not null)
        {
            try
            {
                sug = EidPades.SuggestPlacement(input, opts.Appearance);
                Assert.Null(Str(exp, "suggestionError"));
                AssertSuggestion(exp.GetProperty("suggestion"), sug);
            }
            catch (EidPadesException e) when (Str(exp, "suggestionError") is not null)
            {
                Assert.Equal(Str(exp, "suggestionError"), e.RawCode);
                Assert.False(exp.TryGetProperty("suggestion", out var s) && s.ValueKind != JsonValueKind.Null, "suggestion and suggestionError");
            }
        }
        else
        {
            Assert.False(exp.TryGetProperty("suggestion", out _), "suggestion on an invisible case");
        }

        PreparedDocument prep;
        try
        {
            prep = EidPades.Prepare(input, opts);
        }
        catch (EidPadesException e) when (Str(exp, "error") is not null)
        {
            Assert.Equal(Str(exp, "error"), e.RawCode);
            return;
        }
        Assert.Null(Str(exp, "error"));
        Assert.True(opts.Appearance is null || sug is not null, "SuggestPlacement failed while Prepare succeeded");
        // page0-two-verify: an unsigned input whose verify pages carry the docId the caller passes to Prepare — the one case
        // where SuggestPlacement (nothing skipped on unsigned input) differs from Prepared.Placement (PLACEMENT_SPEC.md §6b).
        if (sug is not null && name != "page0-two-verify")
        {
            Assert.Equal(new Placement { Page = sug.Page, X = sug.X, Y = sug.Y, Width = sug.Width, Height = sug.Height, Status = sug.Status },
                prep.Placement);
        }
        var st = PrepState.Decode(prep.State);
        Assert.Equal(Str(exp, "docId"), prep.DocId);
        Assert.Equal(Str(exp, "digest"), Hex(prep.Digest));
        Assert.Equal(Str(exp, "signedAttrs"), Hex(st.SignedAttrs));
        Assert.Equal(Str(exp, "dtbs"), Hex(prep.Dtbs));
        Assert.Equal(exp.GetProperty("byteRange").EnumerateArray().Select(x => x.GetInt64()).ToArray(), st.ByteRange);
        Assert.Equal(Str(exp, "preparedSha256"), st.PreparedSha256);
        Assert.Equal(Str(exp, "pageSha256") ?? "", st.PageSha256);
        // PLACEMENT_SPEC.md (golden v5): the visible stamp's final rect and status; absent for invisible signatures.
        if (exp.TryGetProperty("placement", out var pl))
        {
            Assert.Equal(JsonSerializer.Deserialize<Placement>(pl.GetRawText()), prep.Placement);
            Assert.Equal(pl.GetProperty("status").GetString(), JsonSerializer.Serialize(prep.Placement!.Status).Trim('"'));
        }
        else
        {
            Assert.Null(prep.Placement);
        }

        var nonce = SHA256.HashData(Encoding.UTF8.GetBytes("golden-nonce:" + name).Append((byte)0).ToArray())[..8];
        using var http = new HttpClient(new Replay());
        var done = await EidPades.CompleteAsync(prep.State, Convert.FromHexString(Str(exp, "signature")!), new CompleteOptions
        {
            TsaUrl = "http://tsa.pki.test/",
            Roots = new[] { Pem("root.pem") },
            HttpClient = http,
            TimeProvider = new FixedTime(Time("now")),
            NonceSource = () => nonce,
            Sleep = (_, _) => Task.CompletedTask,
        });

        var want = Fixtures.Read("output", name + ".pdf");
        AssertSameBytes(want, done.Pdf, name);
        Assert.Equal(Str(exp, "outSha256"), done.OutSha256);
        Assert.Equal(Str(exp, "cmsSha256"), Fixtures.Sha(done.Cms));
        Assert.Equal(Str(exp, "sigRevSha256"), done.SigRevSha256);
        Assert.Equal(exp.GetProperty("revIndex").GetInt32(), done.RevIndex);
        Assert.Equal(exp.TryGetProperty("hasPage", out var hp) && hp.GetBoolean(), done.HasPage);
        var prior = exp.TryGetProperty("priorCmsSha256", out var pr) ? pr.EnumerateArray().Select(x => x.GetString()!).ToArray() : Array.Empty<string>();
        Assert.Equal(prior, done.PriorCmsSha256);
        // Өмнөх гарын үсгүүдийн revision = оролтын гинжийн тохиолдол бүрийн өөрийн sigRevSha256, баримтын дарааллаар
        // (Go complete.go PriorRevisionSHA256).
        var priorRev = PriorRevisions(c);
        Assert.Equal(priorRev, done.PriorRevisionSha256);

        // CA бүртгэл (Go pades.Registration): fileName state-ээр дамжина; өмнөх нь зөвхөн priorCmsSha256-аар (revision нь
        // PriorSignatures-д, JSON-д орохгүй — хоёуланг нь бүтнээр илгээвэл CA 400).
        Assert.Equal(EidPades.CleanFileName(Str(p, "fileName") ?? "") ?? "", done.FileName);
        Assert.Equal(Str(p, "claimedRole") ?? "", done.ClaimedRole);
        if (done.FileName != "" && (done.RevIndex > 1 || done.HasPage))
        {
            var obo = done.ClaimedRole != "" ? "NTRMN-1234567" : null;
            var reg = EidPades.Registration(done, new RegistrationOptions { SessionId = "s1", OnBehalfOf = obo });
            var json = JsonSerializer.Serialize(reg);
            Assert.DoesNotContain("priorRevisionSha256", json, StringComparison.Ordinal);
            Assert.DoesNotContain("PriorSignatures", json, StringComparison.Ordinal);
            Assert.Contains("\"medium\":\"phone\"", json, StringComparison.Ordinal);
            Assert.Equal(prior.Length > 0 ? prior : null, reg.PriorCmsSha256?.ToArray());
            Assert.Equal(priorRev, reg.PriorSignatures.Select(x => x.RevisionSha256).ToArray());
            Assert.Equal(done.RevIndex == 1 ? done.PageSha256 : null, reg.PageSha256);
            Assert.Equal("PNOMN-00000000000", reg.SignerEtsi);
            // APPEARANCE_SPEC.md §6.6: the drawn images' {kind, sha256}, signature then stamp; no field without images.
            var images = new List<PdfSignatureImage>();
            if (opts.Appearance?.SignatureImage is { } sigImg) images.Add(new PdfSignatureImage("signature", sigImg.Sha256));
            if (opts.Appearance?.StampImage is { } stampImg) images.Add(new PdfSignatureImage("stamp", stampImg.Sha256));
            Assert.Equal(images, done.Images);
            Assert.Equal(images.Count > 0 ? images : null, reg.Images?.ToList());
            Assert.Equal(images.Count > 0, json.Contains("\"images\":", StringComparison.Ordinal));
        }
    }

    /// <summary>expect.suggestion (Go pades.Suggestion JSON) ↔ PlacementSuggestion, field-for-field (numbers as JSON numbers).</summary>
    private static void AssertSuggestion(JsonElement want, PlacementSuggestion got)
    {
        Assert.Equal(want.GetProperty("page").GetInt32(), got.Page);
        Assert.Equal(want.GetProperty("x").GetDouble(), got.X);
        Assert.Equal(want.GetProperty("y").GetDouble(), got.Y);
        Assert.Equal(want.GetProperty("width").GetDouble(), got.Width);
        Assert.Equal(want.GetProperty("height").GetDouble(), got.Height);
        Assert.Equal(want.GetProperty("status").GetString(), JsonSerializer.Serialize(got.Status).Trim('"'));
        Assert.Equal(want.GetProperty("pageWidth").GetDouble(), got.PageWidth);
        Assert.Equal(want.GetProperty("pageHeight").GetDouble(), got.PageHeight);
        Assert.Equal(want.GetProperty("pageCount").GetInt32(), got.PageCount);
        var pages = want.GetProperty("pages").EnumerateArray()
            .Select(p => new PageSize { Width = p.GetProperty("width").GetDouble(), Height = p.GetProperty("height").GetDouble() }).ToArray();
        Assert.Equal(pages, got.Pages);
        // The public JSON shape is Go's: same property names, same values.
        using var mine = JsonDocument.Parse(JsonSerializer.Serialize(got));
        Assert.Equal(want.EnumerateObject().Select(p => p.Name), mine.RootElement.EnumerateObject().Select(p => p.Name));
    }

    private static string[] PriorRevisions(JsonElement c)
    {
        var inputRef = c.GetProperty("input").GetString()!;
        if (!inputRef.StartsWith("case:", StringComparison.Ordinal)) return Array.Empty<string>();
        var prev = Case(inputRef[5..]);
        return PriorRevisions(prev).Append(Str(prev.GetProperty("expect"), "sigRevSha256")!).ToArray();
    }

    [Fact]
    public void ManifestHasVisibleCases()
    {
        var cases = Manifest.GetProperty("cases").EnumerateArray().ToList();
        Assert.True(cases.Count >= 17, "golden case цөөн");
        Assert.True(cases.Count(c => c.GetProperty("prepare").TryGetProperty("appearance", out _)) >= 5, "харагдах golden case цөөн");
        // golden v7 (PLACEMENT_SPEC.md §6a/§6b): exact cases and a suggestion on every visible case.
        Assert.True(cases.Count(c => c.GetProperty("prepare").TryGetProperty("appearance", out var a) && a.TryGetProperty("exact", out _)) >= 5,
            "exact golden case цөөн");
        Assert.All(cases.Where(c => c.GetProperty("prepare").TryGetProperty("appearance", out _)), c =>
            Assert.True(c.GetProperty("expect").TryGetProperty("suggestion", out _) || c.GetProperty("expect").TryGetProperty("suggestionError", out _),
                c.GetProperty("name").GetString()));
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    internal static void AssertSameBytes(byte[] want, byte[] got, string what)
    {
        if (want.AsSpan().SequenceEqual(got)) return;
        int i = 0;
        while (i < want.Length && i < got.Length && want[i] == got[i]) i++;
        static string Ctx(byte[] x, int i)
        {
            int s = Math.Max(0, i - 100), n = Math.Min(240, x.Length - s);
            var sb = new StringBuilder();
            foreach (var b in x.AsSpan(s, n)) sb.Append(b is >= 0x20 and < 0x7f ? ((char)b).ToString() : $"\\x{b:X2}");
            return sb.ToString();
        }
        Assert.Fail($"{what}: output differs at byte {i} (want {want.Length}, got {got.Length})\nwant: {Ctx(want, i)}\ngot:  {Ctx(got, i)}");
    }

    private sealed class FixedTime : TimeProvider
    {
        private readonly DateTimeOffset _t;

        public FixedTime(DateTimeOffset t) => _t = t;

        public override DateTimeOffset GetUtcNow() => _t.ToUniversalTime();
    }

    /// <summary>manifest.http: "METHOD URL hex(SHA-256(body))[0:16]" → http/*.der.</summary>
    private sealed class Replay : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(ct);
            var key = request.Method.Method + " " + request.RequestUri + " " + Hex(SHA256.HashData(body))[..16];
            if (!Manifest.GetProperty("http").TryGetProperty(key, out var file))
                return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("no fixture: " + key) };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Fixtures.Read(file.GetString()!.Split('/'))) };
        }
    }
}
