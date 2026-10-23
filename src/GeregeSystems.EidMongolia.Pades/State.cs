using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>
/// Prepare → Complete төлөв — Go reference state.go-ийн формат: "EIDPADES1" ‖ uint32 BE толгойн урт ‖ JSON толгой ‖ prepared
/// PDF. JSON түлхүүр Go-тэй ижил тул SDK хооронд солилцож болно.
/// </summary>
internal sealed class PrepState
{
    private static readonly byte[] Magic = "EIDPADES1"u8.ToArray();

    public string DocId { get; set; } = "";
    public byte[] SignerCert { get; set; } = Array.Empty<byte>();
    public List<byte[]> Chain { get; set; } = new();
    public byte[] SignedAttrs { get; set; } = Array.Empty<byte>();
    public long[] ByteRange { get; set; } = new long[4];
    public int RevIndex { get; set; }
    public string InSha256 { get; set; } = "";
    public bool HasPage { get; set; }
    public string PageSha256 { get; set; } = "";
    public string ClaimedRole { get; set; } = "";
    public string FileName { get; set; } = "";
    public List<PdfSignatureImage> Images { get; set; } = new();
    public string PreparedSha256 { get; set; } = "";
    public byte[] Pdf { get; set; } = Array.Empty<byte>();

    public byte[] Encode()
    {
        var head = new MemoryStream();
        using (var w = new Utf8JsonWriter(head))
        {
            w.WriteStartObject();
            w.WriteString("docId", DocId);
            w.WriteBase64String("signerCert", SignerCert);
            w.WriteStartArray("chain");
            foreach (var c in Chain) w.WriteBase64StringValue(c);
            w.WriteEndArray();
            w.WriteBase64String("signedAttrs", SignedAttrs);
            w.WriteStartArray("byteRange");
            foreach (var x in ByteRange) w.WriteNumberValue(x);
            w.WriteEndArray();
            w.WriteNumber("revIndex", RevIndex);
            w.WriteString("inSha256", InSha256);
            w.WriteBoolean("hasPage", HasPage);
            if (PageSha256 != "") w.WriteString("pageSha256", PageSha256);
            if (ClaimedRole != "") w.WriteString("claimedRole", ClaimedRole);
            if (FileName != "") w.WriteString("fileName", FileName);
            if (Images.Count > 0)
            {
                w.WriteStartArray("images");
                foreach (var im in Images)
                {
                    w.WriteStartObject();
                    w.WriteString("kind", im.Kind);
                    w.WriteString("sha256", im.Sha256);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
            }
            w.WriteString("preparedSha256", PreparedSha256);
            w.WriteEndObject();
        }
        var h = head.ToArray();
        var outBytes = new byte[Magic.Length + 4 + h.Length + Pdf.Length];
        Magic.CopyTo(outBytes, 0);
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(Magic.Length), (uint)h.Length);
        h.CopyTo(outBytes, Magic.Length + 4);
        Pdf.CopyTo(outBytes, Magic.Length + 4 + h.Length);
        return outBytes;
    }

    public static PrepState Decode(byte[] b)
    {
        if (b.Length < Magic.Length + 4 || !b.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw new FormatException("state header not recognised");
        uint n = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(Magic.Length));
        if (n > (uint)(b.Length - Magic.Length - 4)) throw new FormatException("state truncated");
        var s = new PrepState();
        using (var doc = JsonDocument.Parse(b.AsMemory(Magic.Length + 4, (int)n)))
        {
            var r = doc.RootElement;
            s.DocId = Str(r, "docId");
            s.SignerCert = Bytes(r, "signerCert");
            if (r.TryGetProperty("chain", out var ch) && ch.ValueKind == JsonValueKind.Array)
                foreach (var e in ch.EnumerateArray()) s.Chain.Add(e.GetBytesFromBase64());
            s.SignedAttrs = Bytes(r, "signedAttrs");
            if (r.TryGetProperty("byteRange", out var br) && br.ValueKind == JsonValueKind.Array && br.GetArrayLength() == 4)
            {
                int i = 0;
                foreach (var e in br.EnumerateArray()) s.ByteRange[i++] = e.GetInt64();
            }
            s.RevIndex = r.TryGetProperty("revIndex", out var ri) ? ri.GetInt32() : 0;
            s.InSha256 = Str(r, "inSha256");
            s.HasPage = r.TryGetProperty("hasPage", out var hp) && hp.ValueKind == JsonValueKind.True;
            s.PageSha256 = Str(r, "pageSha256");
            s.ClaimedRole = Str(r, "claimedRole");
            s.FileName = Str(r, "fileName");
            if (r.TryGetProperty("images", out var ims) && ims.ValueKind == JsonValueKind.Array)
                foreach (var e in ims.EnumerateArray())
                    s.Images.Add(new PdfSignatureImage(Str(e, "kind"), Str(e, "sha256")));
            s.PreparedSha256 = Str(r, "preparedSha256");
        }
        s.Pdf = b.AsSpan(Magic.Length + 4 + (int)n).ToArray();
        if (Hex(SHA256.HashData(s.Pdf)) != s.PreparedSha256) throw new FormatException("prepared PDF hash mismatch");
        if (s.SignedAttrs.Length == 0 || s.SignerCert.Length == 0 || s.Pdf.Length == 0 || s.RevIndex < 1) throw new FormatException("state incomplete");
        return s;
    }

    private static string Str(JsonElement r, string k) =>
        r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static byte[] Bytes(JsonElement r, string k) =>
        r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetBytesFromBase64() : Array.Empty<byte>();

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    internal static string Utf8(byte[] b) => Encoding.UTF8.GetString(b);
}
