using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>Нэг гарын үсгийн LTV өгөгдөл (DER). Contents — /Contents (тэг дүүргэлттэй) → VRI түлхүүр.</summary>
internal sealed class DssData
{
    public List<byte[]> Certs { get; } = new();
    public List<byte[]> Ocsps { get; } = new();
    public List<byte[]> Crls { get; } = new();
    public byte[] Contents { get; set; } = Array.Empty<byte>();
}

/// <summary>Go reference core/dss.go — /DSS revision (гарын үсэггүй): хуучин DSS-ийг хадгалж шинийг нэмнэ, stream шахалтгүй.</summary>
internal static class Dss
{
    private const int MaxDssStream = 4 << 20;

    public static byte[] Append(byte[] signed, DssData d)
    {
        if (d.Certs.Count + d.Ocsps.Count + d.Crls.Count == 0) throw new InvalidOperationException("pades: empty DSS");
        var inc = Incremental.Open(signed);
        var root = inc.Root;
        var old = root.Key("DSS");
        if (!old.IsNull && old.Kind != PdfKind.Dict) throw new PdfFormatException("pades: /DSS is not a dictionary");

        var known = new Dictionary<string, string>(StringComparer.Ordinal);
        var lists = new Dictionary<string, List<string>>(StringComparer.Ordinal)
        {
            ["Certs"] = new(),
            ["OCSPs"] = new(),
            ["CRLs"] = new(),
        };
        foreach (var key in new[] { "Certs", "OCSPs", "CRLs" })
        {
            var arr = old.Key(key);
            var ap = arr.Ptr;
            for (int i = 0; i < arr.Len; i++)
            {
                var e = arr.Index(i);
                var refStr = Serializer.SerializeToString(e, ap.Id);
                lists[key].Add(refStr);
                if (e.Kind == PdfKind.Stream)
                {
                    var data = e.StreamBytes();
                    if (data.Length > MaxDssStream) data = data.AsSpan(0, MaxDssStream).ToArray();
                    known[Convert.ToHexString(SHA256.HashData(data))] = refStr;
                }
            }
        }

        var vriEntry = new[] { new List<string>(), new List<string>(), new List<string>() };
        void Add(int slot, string key, List<byte[]> items)
        {
            foreach (var der in items)
            {
                var sum = Convert.ToHexString(SHA256.HashData(der));
                if (!known.TryGetValue(sum, out var refStr))
                {
                    var s = new MemoryStream();
                    s.Ascii(string.Create(CultureInfo.InvariantCulture, $"<< /Length {der.Length} >>\nstream\n"));
                    s.Write(der);
                    s.Ascii("\nendstream");
                    var (id, _) = inc.AddObject(s.ToArray());
                    refStr = id.ToString(CultureInfo.InvariantCulture) + " 0 R";
                    known[sum] = refStr;
                    lists[key].Add(refStr);
                }
                if (!vriEntry[slot].Contains(refStr)) vriEntry[slot].Add(refStr);
            }
        }
        Add(0, "Certs", d.Certs);
        Add(1, "OCSPs", d.Ocsps);
        Add(2, "CRLs", d.Crls);

        var dss = new MemoryStream();
        dss.Ascii("<<");
        foreach (var key in new[] { "Certs", "OCSPs", "CRLs" })
            if (lists[key].Count > 0) dss.Ascii(" /" + key + " [" + string.Join(" ", lists[key]) + "]");
        var vri = old.Key("VRI");
        if (d.Contents.Length > 0 || vri.Kind == PdfKind.Dict)
        {
            dss.Ascii(" /VRI <<");
            var vp = vri.Ptr;
            string newKey = "";
            if (d.Contents.Length > 0) newKey = Convert.ToHexString(SHA1.HashData(d.Contents)); // VRI: ISO 32000-2 §12.8.4.4
            foreach (var key in vri.Keys())
            {
                if (key == newKey) continue;
                dss.Ascii(" /" + Serializer.EscapeName(key) + " ");
                Serializer.Serialize(dss, vri.Key(key), vp.Id, 0);
            }
            if (newKey != "")
            {
                dss.Ascii(" /" + newKey + " <<");
                var names = new[] { "Cert", "OCSP", "CRL" };
                for (int i = 0; i < 3; i++)
                    if (vriEntry[i].Count > 0) dss.Ascii(" /" + names[i] + " [" + string.Join(" ", vriEntry[i]) + "]");
                dss.Ascii(" >>");
            }
            dss.Ascii(" >>");
        }
        dss.Ascii(" >>");
        var (dssId, _) = inc.AddObject(dss.ToArray());

        var cat = new MemoryStream();
        cat.Ascii("<<\n  /Type /Catalog\n");
        inc.CatalogCopy(cat, "DSS");
        cat.Ascii(string.Create(CultureInfo.InvariantCulture, $"  /DSS {dssId} 0 R\n>>"));
        var (catId, _) = inc.AddObject(cat.ToArray());
        return inc.Finish(catId);
    }
}
