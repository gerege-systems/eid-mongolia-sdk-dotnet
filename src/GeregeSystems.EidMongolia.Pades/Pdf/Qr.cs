using System;
using System.Collections.Generic;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>PAGE_SPEC.md §7 QR: byte mode, ECC M, хувилбар 1–6, маск ТОГТМОЛ 0 — Go reference internal/qr-тэй ижил матриц.</summary>
internal static class Qr
{
    private sealed record Version(int EcPerBlock, int Blocks, int DataPerBlock, int[] Align);

    private static readonly Version[] Versions =
    {
        new(0, 0, 0, Array.Empty<int>()),
        new(10, 1, 16, Array.Empty<int>()),
        new(16, 1, 28, new[] { 6, 18 }),
        new(26, 1, 44, new[] { 6, 22 }),
        new(18, 2, 32, new[] { 6, 26 }),
        new(24, 2, 43, new[] { 6, 30 }),
        new(16, 4, 27, new[] { 6, 34 }),
    };

    private const int Mask = 0;

    /// <summary>[row][col], true = хар. Quiet zone орохгүй.</summary>
    public static bool[][] Encode(byte[] data)
    {
        int ver = 0;
        for (int v = 1; v <= 6; v++)
        {
            if (4 + 8 + 8 * data.Length <= Versions[v].Blocks * Versions[v].DataPerBlock * 8)
            {
                ver = v;
                break;
            }
        }
        if (ver == 0) throw new ArgumentException("qr: data too long (≤ 106 bytes)");
        var vi = Versions[ver];
        int total = vi.Blocks * vi.DataPerBlock;
        var bits = new List<bool>();
        void Put(int v, int n)
        {
            for (int i = n - 1; i >= 0; i--) bits.Add((v >> i & 1) == 1);
        }
        Put(0b0100, 4);
        Put(data.Length, 8);
        foreach (var b in data) Put(b, 8);
        Put(0, Math.Min(4, total * 8 - bits.Count));
        while (bits.Count % 8 != 0) bits.Add(false);
        var cw = new List<byte>(total);
        for (int i = 0; i < bits.Count; i += 8)
        {
            byte b = 0;
            for (int j = 0; j < 8; j++)
                if (bits[i + j]) b |= (byte)(1 << (7 - j));
            cw.Add(b);
        }
        for (int i = 0; cw.Count < total; i++) cw.Add(i % 2 == 0 ? (byte)0xEC : (byte)0x11);

        var gen = RsGenerator(vi.EcPerBlock);
        var dataBlocks = new byte[vi.Blocks][];
        var ecBlocks = new byte[vi.Blocks][];
        for (int b = 0; b < vi.Blocks; b++)
        {
            dataBlocks[b] = cw.GetRange(b * vi.DataPerBlock, vi.DataPerBlock).ToArray();
            ecBlocks[b] = RsRemainder(dataBlocks[b], gen);
        }
        var final = new List<byte>();
        for (int i = 0; i < vi.DataPerBlock; i++)
            for (int b = 0; b < vi.Blocks; b++) final.Add(dataBlocks[b][i]);
        for (int i = 0; i < vi.EcPerBlock; i++)
            for (int b = 0; b < vi.Blocks; b++) final.Add(ecBlocks[b][i]);
        return Place(ver, vi, final);
    }

    private static bool[][] Place(int ver, Version vi, List<byte> final)
    {
        int n = 17 + 4 * ver;
        var m = new bool[n][];
        var fn = new bool[n][];
        for (int i = 0; i < n; i++)
        {
            m[i] = new bool[n];
            fn[i] = new bool[n];
        }
        void Set(int r, int c, bool dark)
        {
            m[r][c] = dark;
            fn[r][c] = true;
        }
        void Finder(int r0, int c0)
        {
            for (int r = -1; r <= 7; r++)
            {
                for (int c = -1; c <= 7; c++)
                {
                    int rr = r0 + r, cc = c0 + c;
                    if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue;
                    bool dark = r >= 0 && r <= 6 && c >= 0 && c <= 6 &&
                                (r == 0 || r == 6 || c == 0 || c == 6 || r >= 2 && r <= 4 && c >= 2 && c <= 4);
                    Set(rr, cc, dark);
                }
            }
        }
        Finder(0, 0);
        Finder(0, n - 7);
        Finder(n - 7, 0);
        for (int i = 8; i < n - 8; i++)
        {
            Set(6, i, i % 2 == 0);
            Set(i, 6, i % 2 == 0);
        }
        foreach (var r in vi.Align)
        {
            foreach (var c in vi.Align)
            {
                if (r < 9 && c < 9 || r < 9 && c > n - 9 || r > n - 9 && c < 9) continue;
                for (int dr = -2; dr <= 2; dr++)
                    for (int dc = -2; dc <= 2; dc++)
                        Set(r + dr, c + dc, Math.Max(Math.Abs(dr), Math.Abs(dc)) != 1);
            }
        }
        int f = FormatBits(0b00 << 3 | Mask);
        bool Fb(int i) => (f >> i & 1) == 1;
        for (int i = 0; i <= 5; i++) Set(i, 8, Fb(i));
        Set(7, 8, Fb(6));
        Set(8, 8, Fb(7));
        Set(8, 7, Fb(8));
        for (int i = 9; i < 15; i++) Set(8, 14 - i, Fb(i));
        for (int i = 0; i < 8; i++) Set(8, n - 1 - i, Fb(i));
        for (int i = 8; i < 15; i++) Set(n - 15 + i, 8, Fb(i));
        Set(n - 8, 8, true);

        int bit = 0;
        bool up = true;
        for (int col = n - 1; col > 0; col -= 2)
        {
            if (col == 6) col--;
            for (int k = 0; k < n; k++)
            {
                int r = up ? n - 1 - k : k;
                foreach (var c in new[] { col, col - 1 })
                {
                    if (fn[r][c]) continue;
                    bool dark = false;
                    if (bit < final.Count * 8) dark = (final[bit / 8] >> (7 - bit % 8) & 1) == 1;
                    bit++;
                    if ((r + c) % 2 == 0) dark = !dark;
                    m[r][c] = dark;
                }
            }
            up = !up;
        }
        return m;
    }

    private static int FormatBits(int data)
    {
        const int g = 0x537;
        int v = data << 10;
        for (int i = 14; i >= 10; i--)
            if ((v >> i & 1) == 1) v ^= g << (i - 10);
        return (data << 10 | v) ^ 0x5412;
    }

    private static readonly byte[] GfExp = new byte[512];
    private static readonly byte[] GfLog = new byte[256];

#pragma warning disable CA1810 // static ctor: GF хүснэгт нэг удаа
    static Qr()
    {
        int x = 1;
        for (int i = 0; i < 255; i++)
        {
            GfExp[i] = (byte)x;
            GfLog[x] = (byte)i;
            x <<= 1;
            if ((x & 0x100) != 0) x ^= 0x11D;
        }
        for (int i = 255; i < 512; i++) GfExp[i] = GfExp[i - 255];
    }
#pragma warning restore CA1810

    private static byte GfMul(byte a, byte b) => a == 0 || b == 0 ? (byte)0 : GfExp[GfLog[a] + GfLog[b]];

    private static byte[] RsGenerator(int n)
    {
        var g = new byte[] { 1 };
        for (int i = 0; i < n; i++)
        {
            var next = new byte[g.Length + 1];
            for (int j = 0; j < g.Length; j++)
            {
                next[j] ^= g[j];
                next[j + 1] ^= GfMul(g[j], GfExp[i]);
            }
            g = next;
        }
        return g[1..];
    }

    private static byte[] RsRemainder(byte[] data, byte[] gen)
    {
        var rem = new byte[gen.Length];
        foreach (var d in data)
        {
            byte f = (byte)(d ^ rem[0]);
            Array.Copy(rem, 1, rem, 0, rem.Length - 1);
            rem[^1] = 0;
            for (int i = 0; i < gen.Length; i++) rem[i] ^= GfMul(gen[i], f);
        }
        return rem;
    }
}
