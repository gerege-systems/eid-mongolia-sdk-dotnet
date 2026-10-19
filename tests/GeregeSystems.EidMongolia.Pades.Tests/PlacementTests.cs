using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using GeregeSystems.EidMongolia.Pades.Pdf;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// PLACEMENT_SPEC.md §8: the occupancy scanner and candidate search against the Go vectors
/// (testdata/golden/placement/vectors.json) box-for-box, the trial order, and robustness on malformed content/streams.
/// </summary>
public class PlacementTests
{
    private static readonly JsonElement Vectors = LoadVectors();

    private static JsonElement LoadVectors()
    {
        using var d = JsonDocument.Parse(Fixtures.Read("placement", "vectors.json"));
        return d.RootElement.Clone();
    }

    public static IEnumerable<object[]> VectorNames() => Vectors.EnumerateArray().Select(v => new object[] { v.GetProperty("name").GetString()! });

    [Fact]
    public void VectorCount() => Assert.Equal(21, Vectors.GetArrayLength());

    [Theory]
    [MemberData(nameof(VectorNames))]
    public void MatchesGoVector(string name)
    {
        var v = Vectors.EnumerateArray().Single(x => x.GetProperty("name").GetString() == name);
        var exp = v.GetProperty("expect");
        var inc = Incremental.Open(Fixtures.Read(v.GetProperty("input").GetString()!.Split('/')));
        var (page, ok) = SignatureAppearance.NthPage(inc.Root.Key("Pages"), v.GetProperty("page").GetInt32());
        Assert.True(ok);
        var (box, rot) = SignatureAppearance.PageGeometry(page);
        Assert.Equal(Longs(exp.GetProperty("box")), box);
        Assert.Equal(exp.GetProperty("rotate").GetInt32(), rot);

        var req = v.GetProperty("request").EnumerateArray().Select(x => SignatureAppearance.Round100(x.GetDouble())).ToArray();
        var occ = Occupancy.Scan(page, box);
        var boxes = exp.GetProperty("boxes");
        if (boxes.ValueKind == JsonValueKind.Null)
        {
            Assert.Null(occ);
        }
        else
        {
            Assert.NotNull(occ);
            var want = boxes.EnumerateArray().Select(Longs).ToList();
            Assert.Equal(want.Count, occ!.Count);
            for (int i = 0; i < want.Count; i++) Assert.True(want[i].SequenceEqual(occ[i]), $"{name}: box {i}: want [{string.Join(' ', want[i])}] got [{string.Join(' ', occ[i])}]");
        }

        var placed = StampPlacement.Choose(page, box, rot, req[0], req[1], req[2], req[3]);
        Assert.Equal(exp.GetProperty("status").GetString(), Status(placed.Status));
        Assert.Equal(exp.GetProperty("x").GetInt64(), placed.X);
        Assert.Equal(exp.GetProperty("y").GetInt64(), placed.Y);
    }

    /// <summary>Go TestPlacementCandidates — the trial order on A4 with the portal's default request.</summary>
    [Fact]
    public void CandidateOrder()
    {
        var c = StampPlacement.Candidates(59528, 84189, 34000, 3600, 22000, 6400);
        Assert.Equal((34000L, 3600L), c[0]);
        Assert.Equal((3528L, 3600L), c[1]);
        Assert.Equal((34000L, 4800L), c[2]);
        long n = (84189 - 3600 - 3600 - 6400) / 1200;
        Assert.Equal(2 + 2 * n, c.Count);
        Assert.Equal((3528L, 4800L), c[(int)(2 + n)]);
        // A centred request: the mirrored column equals the requested one.
        var centred = StampPlacement.Candidates(1000, 3000, 400, 0, 200, 100);
        Assert.Equal(3, centred.Count);
        Assert.Equal((400L, 1200L), centred[1]);
    }

    [Fact]
    public void StatusJsonIsLowercase()
    {
        var json = JsonSerializer.Serialize(new Placement { Page = 2, X = 340, Y = 60, Width = 220, Height = 64, Status = PlacementStatus.Moved });
        Assert.Equal("{\"page\":2,\"x\":340,\"y\":60,\"width\":220,\"height\":64,\"status\":\"moved\"}", json);
        Assert.Equal(PlacementStatus.Unscanned, JsonSerializer.Deserialize<Placement>("{\"status\":\"unscanned\"}")!.Status);
    }

    // ── Content tokens, numbers ──

    [Theory]
    [InlineData("5.", 0, 0, 500, 500)]
    [InlineData(".5", 0, 0, 50, 50)]
    [InlineData("-.5", -50, -50, 0, 0)]
    [InlineData("+5", 0, 0, 500, 500)]
    public void NumberGrammar(string n, long x0, long y0, long x1, long y1)
    {
        var occ = Scan(L($"0 0 {n} {n} re f"));
        Assert.NotNull(occ);
        Assert.Equal(new[] { x0, y0, x1, y1 }, Assert.Single(occ!));
    }

    [Theory]
    [InlineData("1e5 0 0 5 5 re f")] // 1e5 is a keyword: re gets 4 numbers after it is cleared
    [InlineData("--5 0 0 5 5 re f")]
    [InlineData("1.2.3 0 0 5 5 re f")]
    public void MalformedNumbersAreKeywords(string content)
    {
        var occ = Scan(L(content));
        Assert.Equal(new[] { 0L, 0, 500, 500 }, Assert.Single(occ!));
    }

    // ── Robustness: never throws, never exceeds limits ──

    [Fact]
    public void ArbitraryContentNeverThrows()
    {
        var rnd = new Random(20261019);
        var seeds = new[]
        {
            "BT /F1 12 Tf (abc) Tj ET q 1 0 0 1 0 0 cm 0 0 10 10 re f Q BI /W 1 ID x EI",
            "q 1 0 0 1 10 10 cm /X Do Q [(a) -250 (b)] TJ 0 0 m 10 10 l 20 0 30 10 40 0 c h S",
            "<</A [1 2 [3 (x\\) <4142> /N#41]]>> BDC (unbalanced ( string \\777 \\\n) EMC ] >> } { ) Tj",
        };
        for (int iter = 0; iter < 3000; iter++)
        {
            byte[] content;
            var seed = Encoding.Latin1.GetBytes(seeds[iter % seeds.Length]);
            switch (iter % 3)
            {
                case 0: // random bytes
                    content = new byte[rnd.Next(0, 400)];
                    rnd.NextBytes(content);
                    break;
                case 1: // mutated seed
                    content = (byte[])seed.Clone();
                    for (int m = rnd.Next(1, 8); m > 0; m--) content[rnd.Next(content.Length)] = (byte)rnd.Next(256);
                    break;
                default: // truncated seed
                    content = seed[..rnd.Next(seed.Length)];
                    break;
            }
            var occ = Scan(content); // must not throw
            if (occ is not null) StampPlacement.Place(new long[] { 0, 0, 61200, 79200 }, 0, 34000, 3600, 22000, 6400, occ);
        }
    }

    [Fact]
    public void LimitsMakeThePageUnscannable()
    {
        Assert.Null(Scan(L(string.Concat(Enumerable.Repeat("q ", 65))))); // q depth 64
        Assert.NotNull(Scan(L(string.Concat(Enumerable.Repeat("q ", 64)))));
        Assert.Null(Scan(L(new string('[', 33) + " 1 ] Tj"))); // nesting 32
        Assert.Null(Scan(L(string.Concat(Enumerable.Repeat("n ", 100_001))))); // operators
        Assert.Null(Scan(L(string.Concat(Enumerable.Repeat("1 ", 65_537)) + "n"))); // operands
        Assert.Null(Scan(L("/X Do"))); // the form XObject runs itself: depth 8
        var big = "1" + new string('0', 31); // 1e31, the longest numeric token (32 bytes)
        Assert.Null(Scan(L(string.Concat(Enumerable.Repeat($"{big} 0 0 {big} 0 0 cm ", 10))))); // non-finite CTM
        Assert.NotNull(Scan(L(string.Concat(Enumerable.Repeat($"{big} 0 0 {big} 0 0 cm ", 9)))));
    }

    [Fact]
    public void EofInsideAnArrayEndsTheContent()
    {
        Assert.Empty(Scan(L("0 0 5 5 re [ 1 2 f"))!);
        Assert.Single(Scan(L("0 0 5 5 re f [ 1 2"))!);
    }

    // ── Flate (§3.1): header, Adler-32, truncation, trailing bytes ──

    private const string Square = "0 0 5 5 re f";

    private static byte[] Zlib(string s)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.SmallestSize, leaveOpen: true)) z.Write(L(s));
        return ms.ToArray();
    }

    [Fact]
    public void FlateValid() => Assert.Single(ScanStream(Zlib(Square), "/Filter /FlateDecode")!);

    [Fact]
    public void FlateArrayWithNullParms() => Assert.Single(ScanStream(Zlib(Square), "/Filter [/FlateDecode] /DecodeParms [null]")!);

    [Fact]
    public void FlateTrailingBytesIgnored() => Assert.Single(ScanStream(Zlib(Square).Concat(L("\r\n\0junk")).ToArray(), "/Filter /FlateDecode")!);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(8)]
    public void FlateTruncatedIsUnscannable(int cut)
    {
        var z = Zlib(Square);
        Assert.Null(ScanStream(z[..^cut], "/Filter /FlateDecode"));
    }

    [Fact]
    public void FlateBadChecksumIsUnscannable()
    {
        var z = Zlib(Square);
        z[^1] ^= 1;
        Assert.Null(ScanStream(z, "/Filter /FlateDecode"));
    }

    [Theory]
    [InlineData(new byte[] { 0x78, 0x9d })] // (CMF·256 + FLG) mod 31 ≠ 0
    [InlineData(new byte[] { 0x79, 0x9c })] // CM ≠ 8
    [InlineData(new byte[] { 0x88, 0x98 })] // CINFO > 7
    public void FlateBadHeaderIsUnscannable(byte[] header)
    {
        var z = Zlib(Square);
        z[0] = header[0];
        z[1] = header[1];
        Assert.Null(ScanStream(z, "/Filter /FlateDecode"));
    }

    [Fact]
    public void FlatePresetDictionaryIsUnscannable()
    {
        var z = Zlib(Square);
        // FDICT with a non-empty dictionary id: Go ErrDictionary.
        var fd = new byte[] { 0x78, 0xbb, 0, 0, 0, 2 }.Concat(z[2..]).ToArray();
        Assert.Equal(0, (fd[0] * 256 + fd[1]) % 31);
        Assert.Null(ScanStream(fd, "/Filter /FlateDecode"));
    }

    [Theory]
    [InlineData("/Filter /LZWDecode")]
    [InlineData("/Filter /FlateDecode /DecodeParms << /Predictor 12 >>")]
    [InlineData("/Filter [/FlateDecode /FlateDecode]")]
    [InlineData("/Filter [/FlateDecode] /DecodeParms [<< >>]")]
    public void UnsupportedFilterIsUnscannable(string dict) => Assert.Null(ScanStream(Zlib(Square), dict));

    [Fact]
    public void FlateGarbageNeverThrows()
    {
        var rnd = new Random(7);
        var z = Zlib(string.Concat(Enumerable.Repeat("BT /F1 12 Tf 72 700 Td (Hello) Tj ET 0 0 5 5 re f ", 40)));
        for (int i = 0; i < 2000; i++)
        {
            var b = (byte[])z.Clone();
            for (int m = rnd.Next(1, 6); m > 0; m--) b[rnd.Next(2, b.Length)] = (byte)rnd.Next(256);
            ScanStream(b, "/Filter /FlateDecode");
        }
    }

    /// <summary>The strict decoder agrees with ZLibStream on every valid stream (stored, fixed, dynamic blocks).</summary>
    [Fact]
    public void ZlibStrictMatchesZLibStream()
    {
        var rnd = new Random(3);
        foreach (var level in new[] { CompressionLevel.NoCompression, CompressionLevel.Fastest, CompressionLevel.Optimal, CompressionLevel.SmallestSize })
        {
            foreach (var size in new[] { 0, 1, 100, 70_000, 300_000 })
            {
                var src = new byte[size];
                for (int i = 0; i < size; i++) src[i] = (byte)(i % 97 < 50 ? i * 7 % 251 : rnd.Next(256));
                var ms = new MemoryStream();
                using (var z = new ZLibStream(ms, level, leaveOpen: true)) z.Write(src);
                Assert.Equal(src, ZlibStrict.Decode(ms.ToArray(), 1 << 22));
                if (size > 0) Assert.Null(ZlibStrict.Decode(ms.ToArray(), size - 1)); // decoded-size budget
            }
        }
    }

    // ── Helpers ──

    private static byte[] L(string s) => Encoding.Latin1.GetBytes(s);

    private static long[] Longs(JsonElement e) => e.EnumerateArray().Select(x => x.GetInt64()).ToArray();

    private static string Status(PlacementStatus s) => JsonSerializer.Serialize(s).Trim('"');

    /// <summary>Letter page whose content is <paramref name="content"/>; /X is a form that runs the same content.</summary>
    private static List<long[]>? Scan(byte[] content) => ScanStream(content, "");

    private static List<long[]>? ScanStream(byte[] data, string filter)
    {
        var doc = Pdf(
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /X 5 0 R >> >> /Contents 4 0 R >>",
            Stream(filter, data),
            Stream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X 5 0 R >> >> " + filter, data));
        var inc = Incremental.Open(doc);
        var (page, ok) = SignatureAppearance.NthPage(inc.Root.Key("Pages"), 1);
        Assert.True(ok);
        return Occupancy.Scan(page, new long[] { 0, 0, 61200, 79200 });
    }

    private static byte[] Stream(string dict, byte[] data) =>
        L($"<< {dict} /Length {data.Length} >>\nstream\n").Concat(data).Concat(L("\nendstream")).ToArray();

    /// <summary>Go fxPDF — a minimal classic-xref PDF: objs[0] is object 1 (the Catalog).</summary>
    private static byte[] Pdf(params object[] objs)
    {
        var b = new MemoryStream();
        void W(string s) => b.Write(L(s));
        W("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
        var offs = new long[objs.Length];
        for (int i = 0; i < objs.Length; i++)
        {
            offs[i] = b.Length;
            W($"{i + 1} 0 obj\n");
            if (objs[i] is byte[] raw) b.Write(raw);
            else W((string)objs[i]);
            W("\nendobj\n");
        }
        long x = b.Length;
        W($"xref\n0 {objs.Length + 1}\n0000000000 65535 f \n");
        foreach (var o in offs) W($"{o:D10} 00000 n \n");
        W($"trailer\n<< /Size {objs.Length + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n");
        return b.ToArray();
    }
}
