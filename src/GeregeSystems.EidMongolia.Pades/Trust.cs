using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using GeregeSystems.EidMongolia.Pades.Crypto;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>Шигтгэсэн нийтийн eID PKI гинж (01 root; 02–05 завсрын; 04/05 иргэн/байгууллагын олгогч).</summary>
internal static class Trust
{
    private static readonly Lazy<X509Certificate2[]> Chain = new(() => new[]
    {
        Load("01-mongolian-national-root-ca"),
        Load("02-mongolian-national-issuing-ca-mddc"),
        Load("03-gerege-issuing-ca"),
        Load("04-eid-mongolia-issuing-ca"),
        Load("05-eid-mongolia-org-issuing-ca"),
    });

    public static X509Certificate2 NationalRoot => Chain.Value[0];

    public static IReadOnlyList<X509Certificate2> Intermediates => Chain.Value[1..];

    public static IReadOnlyList<X509Certificate2> Issuers => new[] { Chain.Value[3], Chain.Value[4] };

    private static X509Certificate2 Load(string name)
    {
        using var s = typeof(Trust).Assembly.GetManifestResourceStream("eid." + name + ".pem")
                      ?? throw new InvalidOperationException("missing embedded certificate " + name);
        using var r = new StreamReader(s);
        return X509Certificate2.CreateFromPem(r.ReadToEnd());
    }

    public static List<X509Certificate2> ParseAll(IReadOnlyList<byte[]> ders)
    {
        var o = new List<X509Certificate2>(ders.Count);
        foreach (var d in ders) o.Add(X509Util.Parse(d));
        return o;
    }

    /// <summary>Өгсөн гинж эсвэл шигтгэсэн завсрын CA-аас signer-ийн олгогчоор root хүртэл (root-гүй).</summary>
    public static List<X509Certificate2> SignerChain(X509Certificate2 signer, IReadOnlyList<byte[]>? ders)
    {
        if (ders is { Count: > 0 }) return ParseAll(ders);
        var pool = Intermediates;
        var chain = new List<X509Certificate2>();
        var cur = signer;
        for (int k = 0; k <= pool.Count; k++)
        {
            X509Certificate2? next = null;
            foreach (var c in pool)
            {
                if (c.SubjectName.RawData.AsSpan().SequenceEqual(cur.IssuerName.RawData) && X509Util.CheckSignatureFrom(cur, c))
                {
                    next = c;
                    break;
                }
            }
            if (next is null) break;
            chain.Add(next);
            cur = next;
        }
        if (chain.Count == 0) throw new FormatException("signer issuer is not in the embedded eID chain — pass Chain");
        return chain;
    }
}
