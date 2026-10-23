using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// Go TestAppearanceImageInput (APPEARANCE_SPEC.md §6.1, §6.3, §6.6): image input checks (REQUEST_INVALID before the PDF is
/// parsed — SuggestPlacement too), the default sizes and the registration <c>images</c>. The images are the golden v10 ones.
/// </summary>
public class AppearanceImageTests
{
    private static readonly JsonElement Manifest = LoadManifest();

    private static JsonElement LoadManifest()
    {
        using var d = JsonDocument.Parse(Fixtures.Read("manifest.json"));
        return d.RootElement.Clone();
    }

    private static PdfImage GoldenImage(string kind)
    {
        var c = Manifest.GetProperty("cases").EnumerateArray().Single(x => x.GetProperty("name").GetString() == "img-signature-stamp");
        return JsonSerializer.Deserialize<PdfImage>(c.GetProperty("prepare").GetProperty("appearance").GetProperty(kind).GetRawText())!;
    }

    private static PdfImage Sig() => GoldenImage("signatureImage");

    private static PdfImage Stamp() => GoldenImage("stampImage");

    private static byte[] Zlib(byte[] raw)
    {
        var m = new MemoryStream();
        using (var z = new ZLibStream(m, CompressionLevel.Optimal, leaveOpen: true)) z.Write(raw);
        return m.ToArray();
    }

    public static IEnumerable<object[]> BadImages()
    {
        var s = Sig();
        yield return new object[] { "sha256 том үсэг", s with { Sha256 = s.Sha256.ToUpperInvariant() } };
        yield return new object[] { "sha256 богино", s with { Sha256 = s.Sha256[..63] } };
        yield return new object[] { "өнгө 256", s with { Color = new[] { 18, 256, 110 } } };
        yield return new object[] { "өнгө сөрөг", s with { Color = new[] { -1, 32, 110 } } };
        yield return new object[] { "өнгө 2 утга", s with { Color = new[] { 18, 32 } } };
        yield return new object[] { "өргөн 1601", s with { Width = 1601 } };
        yield return new object[] { "өндөр 0", s with { Height = 0 } };
        yield return new object[] { "alpha хоосон", s with { Alpha = Array.Empty<byte>() } };
        yield return new object[] { "alpha zlib биш", s with { Alpha = "not zlib"u8.ToArray() } };
        yield return new object[] { "alpha илүү байт", s with { Height = s.Height - 1 } };
        yield return new object[] { "alpha дутуу байт", s with { Alpha = Zlib(new byte[s.Width * s.Height - 1]) } };
        yield return new object[] { "alpha ард хог", s with { Alpha = s.Alpha.Append((byte)0).ToArray() } };
        yield return new object[] { "alpha > 300 KiB", s with { Alpha = new byte[(300 << 10) + 1] } };
    }

    [Theory]
    [MemberData(nameof(BadImages))]
    public void RejectsBadImage(string name, PdfImage im)
    {
        var doc = Fixtures.Read("input", "quartz-pdf13.pdf");
        var e = Assert.Throws<EidPadesException>(() => EidPades.SuggestPlacement(doc, new Appearance { X = 36, Y = 36, SignatureImage = im }));
        Assert.True(e.RawCode == "REQUEST_INVALID", name);
    }

    [Fact]
    public void DefaultSizes()
    {
        var doc = Fixtures.Read("input", "quartz-pdf13.pdf");
        var cases = new (Appearance A, double W, double H)[]
        {
            (new Appearance { X = 36, Y = 36 }, 220, 64),
            (new Appearance { X = 36, Y = 36, SignatureImage = Sig() }, 220, 110),
            (new Appearance { X = 36, Y = 36, StampImage = Stamp() }, 240, 147.5),
            (new Appearance { X = 36, Y = 36, SignatureImage = Sig(), StampImage = Stamp() }, 240, 147.5),
            (new Appearance { X = 36, Y = 36, Width = 300, Height = 180, StampImage = Stamp() }, 300, 180),
        };
        foreach (var (a, w, h) in cases)
        {
            var s = EidPades.SuggestPlacement(doc, a);
            Assert.Equal((w, h), (s.Width, s.Height));
        }
    }

    [Fact]
    public void RegistrationImages()
    {
        var sig = Sig();
        var stamp = Stamp();
        var cert = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Fixtures.Golden, "pki", "citizen.pem"))).RawData;
        var c = new Completed
        {
            SignerCert = cert,
            DocId = "d",
            RevIndex = 2,
            FileName = "a.pdf",
            ClaimedRole = "x",
            Images = new[] { new PdfSignatureImage(PdfSignatureImage.KindSignature, sig.Sha256), new PdfSignatureImage(PdfSignatureImage.KindStamp, stamp.Sha256) },
        };
        var json = JsonSerializer.Serialize(EidPades.Registration(c, new RegistrationOptions { OnBehalfOf = "NTRMN-1234567" }));
        Assert.Contains("\"images\":[{\"kind\":\"signature\",\"sha256\":\"" + sig.Sha256 + "\"},{\"kind\":\"stamp\",\"sha256\":\"" + stamp.Sha256 + "\"}]",
            json, StringComparison.Ordinal);
        json = JsonSerializer.Serialize(EidPades.Registration(new Completed { SignerCert = cert, DocId = "d", RevIndex = 2, FileName = "a.pdf" }));
        Assert.DoesNotContain("\"images\"", json, StringComparison.Ordinal);
    }
}
