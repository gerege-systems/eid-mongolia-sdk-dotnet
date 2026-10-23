using System;
using System.Collections.Generic;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>
/// Strict zlib (RFC 1950 + RFC 1951) decoder for the occupancy scanner (PLACEMENT_SPEC.md §3.1) — the semantics of Go's
/// <c>compress/zlib</c> reader: CM = 8, CINFO ≤ 7, <c>(CMF·256 + FLG) mod 31 = 0</c>, a preset dictionary only with the
/// empty-dictionary id 1 (Go reads it and compares with adler32(nil)), raw deflate up to the final block, then the
/// Adler-32 of the output must match; bytes after the checksum are ignored. Any header/Huffman/distance error,
/// truncation or checksum mismatch → <c>null</c>.
/// <para>
/// <see cref="System.IO.Compression.ZLibStream"/> is not used here on purpose: on .NET 8 it returns a truncated stream
/// (missing data or missing Adler-32 bytes) as a short read without an error, and it reads past the end of the zlib
/// stream, so neither truncation nor the checksum position can be detected — Go rejects both (unscannable).
/// </para>
/// </summary>
internal static class ZlibStrict
{
    private const int MaxBits = 15;

    private static readonly int[] LenBase = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    private static readonly int[] LenExtra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    private static readonly int[] DistBase = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    private static readonly int[] DistExtra = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    private static readonly int[] CodeOrder = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

    private static readonly Huffman FixedLit = FixedLiteral();
    private static readonly Huffman FixedDist = Build(Fill(32, 5))!; // 30, 31 are decoded and rejected (Go)

    private sealed class DecodeException : Exception
    {
    }

    /// <summary>The decoded bytes, or <c>null</c> when the stream is invalid or decodes to more than <paramref name="maxOut"/> bytes.</summary>
    public static byte[]? Decode(ReadOnlySpan<byte> src, int maxOut) => Decode(src, maxOut, out _);

    /// <summary>
    /// <see cref="Decode(ReadOnlySpan{byte}, int)"/> that also reports how many input bytes the stream used (header, deflate
    /// data, Adler-32) — callers that must reject trailing bytes (APPEARANCE_SPEC.md §6.1) compare it with the input length.
    /// </summary>
    public static byte[]? Decode(ReadOnlySpan<byte> src, int maxOut, out int used)
    {
        used = 0;
        try
        {
            return DecodeCore(src, maxOut, out used);
        }
        catch (DecodeException)
        {
            return null;
        }
    }

    private static byte[] DecodeCore(ReadOnlySpan<byte> src, int maxOut, out int used)
    {
        if (src.Length < 2) throw new DecodeException();
        int cmf = src[0], flg = src[1];
        if ((cmf & 0x0f) != 8 || cmf >> 4 > 7 || (cmf << 8 | flg) % 31 != 0) throw new DecodeException();
        var br = new BitReader(src, 2);
        if ((flg & 0x20) != 0 && br.ReadUInt32BE() != 1) throw new DecodeException(); // Go: dictionary id must be adler32(nil)
        var output = new List<byte>(Math.Min(maxOut, 1 << 16));
        bool final;
        do
        {
            final = br.Bits(1) == 1;
            switch (br.Bits(2))
            {
                case 0:
                    Stored(ref br, output, maxOut);
                    break;
                case 1:
                    Codes(ref br, output, maxOut, FixedLit, FixedDist);
                    break;
                case 2:
                    var (lit, dist) = Dynamic(ref br);
                    Codes(ref br, output, maxOut, lit, dist);
                    break;
                default:
                    throw new DecodeException();
            }
        } while (!final);
        br.AlignToByte();
        uint want = br.ReadUInt32BE();
        var outBytes = output.ToArray();
        if (Adler32(outBytes) != want) throw new DecodeException();
        used = br.Pos;
        return outBytes;
    }

    private static uint Adler32(byte[] b)
    {
        const uint mod = 65521;
        uint a = 1, s = 0;
        foreach (var x in b)
        {
            a = (a + x) % mod;
            s = (s + a) % mod;
        }
        return s << 16 | a;
    }

    private static void Stored(ref BitReader br, List<byte> output, int maxOut)
    {
        br.AlignToByte();
        int n = br.Byte() | br.Byte() << 8;
        int nn = br.Byte() | br.Byte() << 8;
        if ((ushort)nn != (ushort)~n) throw new DecodeException();
        if (output.Count + n > maxOut) throw new DecodeException();
        for (int i = 0; i < n; i++) output.Add(br.Byte());
    }

    private static void Codes(ref BitReader br, List<byte> output, int maxOut, Huffman lit, Huffman dist)
    {
        while (true)
        {
            int sym = br.Decode(lit);
            if (sym < 256)
            {
                if (output.Count >= maxOut) throw new DecodeException();
                output.Add((byte)sym);
                continue;
            }
            if (sym == 256) return;
            sym -= 257;
            if (sym >= 29) throw new DecodeException(); // 286, 287 (fixed table only)
            int len = LenBase[sym] + br.Bits(LenExtra[sym]);
            int ds = br.Decode(dist);
            if (ds >= 30) throw new DecodeException();
            int d = DistBase[ds] + br.Bits(DistExtra[ds]);
            if (d > output.Count) throw new DecodeException(); // Go: distance beyond the history written so far
            if (output.Count + len > maxOut) throw new DecodeException();
            int from = output.Count - d;
            for (int i = 0; i < len; i++) output.Add(output[from + i]);
        }
    }

    private static (Huffman Lit, Huffman Dist) Dynamic(ref BitReader br)
    {
        int nlit = br.Bits(5) + 257;
        if (nlit > 286) throw new DecodeException();
        int ndist = br.Bits(5) + 1;
        if (ndist > 30) throw new DecodeException();
        int nclen = br.Bits(4) + 4;
        var codeLens = new int[19];
        for (int i = 0; i < nclen; i++) codeLens[CodeOrder[i]] = br.Bits(3);
        var clh = Build(codeLens) ?? throw new DecodeException();
        var lens = new int[nlit + ndist];
        for (int i = 0; i < lens.Length;)
        {
            int x = br.Decode(clh);
            if (x < 16)
            {
                lens[i++] = x;
                continue;
            }
            int rep, val = 0;
            switch (x)
            {
                case 16:
                    if (i == 0) throw new DecodeException();
                    val = lens[i - 1];
                    rep = 3 + br.Bits(2);
                    break;
                case 17:
                    rep = 3 + br.Bits(3);
                    break;
                default:
                    rep = 11 + br.Bits(7);
                    break;
            }
            if (i + rep > lens.Length) throw new DecodeException();
            for (int j = 0; j < rep; j++) lens[i++] = val;
        }
        var lit = Build(lens.AsSpan(0, nlit)) ?? throw new DecodeException();
        var dist = Build(lens.AsSpan(nlit, ndist)) ?? throw new DecodeException();
        return (lit, dist);
    }

    private static int[] Fill(int n, int len)
    {
        var a = new int[n];
        Array.Fill(a, len);
        return a;
    }

    private static Huffman FixedLiteral()
    {
        var l = new int[288];
        for (int i = 0; i < 144; i++) l[i] = 8;
        for (int i = 144; i < 256; i++) l[i] = 9;
        for (int i = 256; i < 280; i++) l[i] = 7;
        for (int i = 280; i < 288; i++) l[i] = 8;
        return Build(l)!;
    }

    /// <summary>Canonical Huffman code (RFC 1951 §3.2.2). Go huffmanDecoder.init: over-subscribed or incomplete → null,
    /// except an empty code and the degenerate single code of length 1 (an unused code then fails at decode).</summary>
    private static Huffman? Build(ReadOnlySpan<int> lengths)
    {
        var count = new int[MaxBits + 1];
        int min = 0, max = 0;
        foreach (var n in lengths)
        {
            if (n == 0) continue;
            if (min == 0 || n < min) min = n;
            if (n > max) max = n;
            count[n]++;
        }
        var h = new Huffman(count, new int[lengths.Length]);
        if (max == 0) return h;
        int code = 0;
        for (int i = min; i <= max; i++) code = (code << 1) + count[i];
        if (code != 1 << max && !(code == 1 && max == 1)) return null;
        var offs = new int[MaxBits + 2];
        for (int i = 1; i <= MaxBits; i++) offs[i + 1] = offs[i] + count[i];
        for (int s = 0; s < lengths.Length; s++)
            if (lengths[s] != 0) h.Symbol[offs[lengths[s]]++] = s;
        return h;
    }

    private sealed record Huffman(int[] Count, int[] Symbol);

    private ref struct BitReader
    {
        private readonly ReadOnlySpan<byte> _b;
        private int _pos;
        private int _bitBuf;
        private int _bitCnt;

        public BitReader(ReadOnlySpan<byte> b, int pos)
        {
            _b = b;
            _pos = pos;
            _bitBuf = 0;
            _bitCnt = 0;
        }

        public int Bits(int need)
        {
            long v = _bitBuf;
            while (_bitCnt < need)
            {
                if (_pos >= _b.Length) throw new DecodeException(); // truncated
                v |= (long)_b[_pos++] << _bitCnt;
                _bitCnt += 8;
            }
            _bitBuf = (int)(v >> need);
            _bitCnt -= need;
            return (int)(v & ((1L << need) - 1));
        }

        public int Pos => _pos;

        public void AlignToByte()
        {
            _bitBuf = 0;
            _bitCnt = 0;
        }

        public byte Byte()
        {
            if (_pos >= _b.Length) throw new DecodeException();
            return _b[_pos++];
        }

        public uint ReadUInt32BE()
        {
            uint v = 0;
            for (int i = 0; i < 4; i++) v = v << 8 | Byte();
            return v;
        }

        /// <summary>One symbol, bit by bit (codes are packed MSB-first of the code, LSB-first in the stream).</summary>
        public int Decode(Huffman h)
        {
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= MaxBits; len++)
            {
                code |= Bits(1);
                int count = h.Count[len];
                if (code - count < first) return h.Symbol[index + (code - first)];
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            throw new DecodeException(); // unassigned code (incomplete degenerate / empty table)
        }
    }
}
