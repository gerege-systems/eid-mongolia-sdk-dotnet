using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Numerics;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

/// <summary>DER-ийг байт түвшинд угсрах жижиг туслах (Go cryptobyte-ийн адил: SET OF-ийг автоматаар эрэмбэлэхгүй).</summary>
internal static class Der
{
    public const byte Sequence = 0x30;
    public const byte Set = 0x31;

    public static byte[] Tlv(byte tag, params byte[][] content)
    {
        int len = 0;
        foreach (var c in content) len += c.Length;
        var ms = new MemoryStream(len + 6);
        ms.WriteByte(tag);
        WriteLength(ms, len);
        foreach (var c in content) ms.Write(c);
        return ms.ToArray();
    }

    public static byte[] Tlv(byte tag, IEnumerable<byte[]> content) => Tlv(tag, new List<byte[]>(content).ToArray());

    private static void WriteLength(Stream s, int len)
    {
        if (len < 0x80)
        {
            s.WriteByte((byte)len);
            return;
        }
        int n = 0;
        for (int v = len; v > 0; v >>= 8) n++;
        s.WriteByte((byte)(0x80 | n));
        for (int i = n - 1; i >= 0; i--) s.WriteByte((byte)(len >> (8 * i)));
    }

    public static byte[] Seq(params byte[][] content) => Tlv(Sequence, content);

    public static byte[] SetOf(params byte[][] content) => Tlv(Set, content);

    public static byte[] Oid(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        return w.Encode();
    }

    public static byte[] OctetString(ReadOnlySpan<byte> b)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteOctetString(b);
        return w.Encode();
    }

    public static byte[] Integer(BigInteger v)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteInteger(v);
        return w.Encode();
    }

    public static byte[] Integer(long v)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteInteger(v);
        return w.Encode();
    }

    public static byte[] Utf8String(string s)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteCharacterString(UniversalTagNumber.UTF8String, s);
        return w.Encode();
    }

    public static readonly byte[] Null = { 0x05, 0x00 };

    public static readonly byte[] True = { 0x01, 0x01, 0xff };

    /// <summary>AlgorithmIdentifier; nullParams — RSA PKCS#1 ба TSA/OCSP-ийн hash алгоритмд NULL параметр.</summary>
    public static byte[] AlgId(string oid, bool nullParams) => nullParams ? Seq(Oid(oid), Null) : Seq(Oid(oid));

    /// <summary>Go bytes.Compare — лексикограф, богино нь угтвар бол бага.</summary>
    public static int Compare(byte[] a, byte[] b) => a.AsSpan().SequenceCompareTo(b);
}
