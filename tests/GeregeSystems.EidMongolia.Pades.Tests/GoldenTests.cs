using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>testdata/pades-client — Go цөмөөс (tools/genvectors) үүсгэсэн vector; DLL-ээр байт бүрээр ижил гарах ёстой.</summary>
internal static class Golden
{
    public static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "testdata", "pades-client");

    public static byte[] Read(string rel) => File.ReadAllBytes(Path.Combine(Dir, rel));

    public static byte[] SignerCert() => Read("pki/leaf.der");

    public static byte[] Root() => Read("pki/root.der");

    public static JsonElement Vectors()
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Dir, "vectors.json")));
        return doc.RootElement.Clone();
    }

    public static IEnumerable<object[]> Names(string section) =>
        Vectors().GetProperty(section).EnumerateArray().Select(v => new object[] { v.GetProperty("name").GetString()! });

    public static JsonElement Vector(string section, string name) =>
        Vectors().GetProperty(section).EnumerateArray().Single(v => v.GetProperty("name").GetString() == name);

    public static string? Str(JsonElement v, string key) =>
        v.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    public static PrepareOptions Options(JsonElement v) => new()
    {
        SignerCert = SignerCert(),
        Chain = new[] { Root() },
        SignerName = Str(v, "signerName"),
        Reason = Str(v, "reason"),
        ClaimedRole = Str(v, "claimedRole"),
        SigningTime = DateTimeOffset.Parse(Str(v, "signingTime")!, System.Globalization.CultureInfo.InvariantCulture),
        DocId = Str(v, "docId"),
        VerifyPage = v.GetProperty("verifyPage").GetBoolean(),
        FileName = Str(v, "fileName"),
        Lang = Str(v, "lang"),
    };

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}

public class GoldenTests
{
    public static IEnumerable<object[]> PrepareNames() => Golden.Names("prepare");

    public static IEnumerable<object[]> VerifyNames() => Golden.Names("verify");

    [Theory]
    [MemberData(nameof(PrepareNames))]
    public void PrepareMatchesGoCore(string name)
    {
        var v = Golden.Vector("prepare", name);
        var p = EidPades.Prepare(Golden.Read(Golden.Str(v, "input")!), Golden.Options(v));

        Assert.Equal(Golden.Str(v, "dtbs"), Golden.Hex(p.Dtbs));
        Assert.Equal(Golden.Str(v, "digest"), Golden.Hex(p.Digest));
        Assert.Equal(Golden.Str(v, "docId"), p.DocId);
        Assert.Equal(Golden.Str(v, "stateSha256"), Golden.Hex(SHA256.HashData(p.State)));
    }

    [Theory]
    [MemberData(nameof(VerifyNames))]
    public void VerifyMatchesGoCore(string name)
    {
        var v = Golden.Vector("verify", name);
        var rootPem = File.ReadAllText(Path.Combine(Golden.Dir, "pki", "desktop-root.pem"));
        var report = EidPades.Verify(Golden.Read(Golden.Str(v, "input")!), new VerifyOptions
        {
            Roots = new[] { System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(rootPem).RawData },
            Time = DateTimeOffset.Parse(Golden.Str(v, "time")!, System.Globalization.CultureInfo.InvariantCulture),
        });

        var expected = JsonNode.Parse(v.GetProperty("report").GetRawText());
        Assert.True(JsonNode.DeepEquals(expected, JsonNode.Parse(report.Json)),
            $"report differs:\nexpected {expected!.ToJsonString()}\nactual   {report.Json}");
        Assert.Equal(v.GetProperty("report").GetProperty("indication").GetString(), report.Indication);
    }

    [Fact]
    public async Task CompleteRejectsWrongSignature()
    {
        var v = Golden.Vector("prepare", "quartz-plain");
        var p = EidPades.Prepare(Golden.Read(Golden.Str(v, "input")!), Golden.Options(v));
        var ex = await Assert.ThrowsAsync<EidPadesException>(() => EidPades.CompleteAsync(p.State, new byte[64]));
        Assert.Equal(EidPadesErrorCode.SignatureInvalid, ex.Code);
    }

    /// <summary>Зөв r||s гарын үсэг DLL-ийн шалгалтыг давж, дараагийн алхам (TSA) руу хүрнэ — хүрэх боломжгүй TSA → TSA_UNAVAILABLE.</summary>
    [Theory]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public async Task CompleteAcceptsSignatureThenNeedsTsa(DSASignatureFormat format)
    {
        var v = Golden.Vector("prepare", "objstm-role");
        var p = EidPades.Prepare(Golden.Read(Golden.Str(v, "input")!), Golden.Options(v));

        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(Path.Combine(Golden.Dir, "pki", "leaf.key")));
        var sig = key.SignHash(p.Dtbs, format);

        var ex = await Assert.ThrowsAsync<EidPadesException>(() =>
            EidPades.CompleteAsync(p.State, sig, new CompleteOptions { TsaUrl = "http://127.0.0.1:9/" }));
        Assert.Equal(EidPadesErrorCode.TsaUnavailable, ex.Code);
    }

    [Fact]
    public void InvalidDocIdIsRejectedByCore()
    {
        var v = Golden.Vector("prepare", "quartz-plain");
        var ex = Assert.Throws<EidPadesException>(() =>
            EidPades.Prepare(Golden.Read(Golden.Str(v, "input")!), Golden.Options(v) with { DocId = "NOT-A-UUID" }));
        Assert.Equal(EidPadesErrorCode.RequestInvalid, ex.Code);
    }

    [Fact]
    public void ProfileVersion()
    {
        Assert.Equal(Golden.Vectors().GetProperty("profile").GetString(), EidPades.Version());
    }
}
