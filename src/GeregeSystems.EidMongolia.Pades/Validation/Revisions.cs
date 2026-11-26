using System;
using System.Collections.Generic;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Validation;

// Гарын үсгийн ДАРАА нэмэгдсэн revision-ийн шинжилгээ — TS SDK src/pades/validate/revisions.ts (Go SDK
// pades/internal/validate/revisions.go — CA-ийн нийтийн шалгагчийн код)-ийн 1:1 порт. Гарын үсгийн мужийн төгсгөл хүртэлх
// баримт (суурь) ба бүтэн файлыг ЗАДАЛСАН объектын графаар харьцуулж, ялгаа бүр зөвшөөрөгдсөн жагсаалтад багтвал л «зөвхөн
// гарын үсгээр өргөтгөгдсөн» гэж үзнэ; бусад бүх зүйл (задарч чадаагүйг оруулаад) — modified_after_signing (fail closed).
// Prod нь зөвхөн "own" profile (манай PAdES бичигчийн яг хэлбэр).

/// <summary>Extract-ийн шалгасан гарын үсгийн харагдах дүрслэлд хэрэгтэй өгөгдөл.</summary>
internal sealed class SigMeta
{
    /// <summary>ByteRange-ийн төгсгөлөөр эрэмбэлсэн дараалал (1-ээс).</summary>
    public int RevIndex;

    /// <summary>signer-attributes-v2-ийн ганц claimedRole ("" — байхгүй).</summary>
    public string Role = "";

    /// <summary>claimedRole 0 эсвэл яг 1.</summary>
    public bool RoleOk;

    /// <summary>Гарын үсэг зурагчийн гэрчилгээ e-Seal (APPEARANCE_SPEC.md §6.1).</summary>
    public bool Seal;
}

/// <summary>Гарын үсгийн мужийн дараах revision-уудын дүгнэлт.</summary>
internal readonly record struct LaterChanges(bool SignaturesOnly, int Signatures, bool Visible)
{
    public static readonly LaterChanges Nothing = new(false, 0, false);
}

internal enum ClassifyMode
{
    Broad = 0,
    Own = 1,
    DssOnly = 2,
}

/// <summary>Нэг баримтын бүх гарын үсэгт хуваалцах төлөв: харагдац (эхний N байт) ба алхмын дүнгийн кэш.</summary>
internal sealed class Revisions
{
    private readonly Dictionary<int, PdfView?> _views = new();
    private readonly Dictionary<(int, int, int), LaterChanges?> _steps = new();

    public Revisions(byte[] doc, Dictionary<int, long[]> known, bool ownProfile, System.Threading.CancellationToken ct = default)
    {
        Budget = new PdfBudget { Ct = ct };
        Doc = doc;
        Known = known;
        OwnProfile = ownProfile;
    }

    public byte[] Doc { get; }

    /// <summary>Extract-ийн задалж, криптографаар шалгасан гарын үсгүүд: объектын дугаар → ByteRange.</summary>
    public Dictionary<int, long[]> Known { get; }
    public bool OwnProfile { get; }
    public PdfBudget Budget { get; }
    public Dictionary<int, SigMeta> Sigs { get; set; } = new();
    public string DocId { get; set; } = "";

    public PdfView? View(int n)
    {
        if (_views.TryGetValue(n, out var hit)) return hit;
        PdfView? v;
        try
        {
            v = PdfView.Open(Doc, n, Budget);
        }
        catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
        {
            v = null;
        }
        _views[n] = v;
        return v;
    }

    /// <summary>end (ByteRange-ийн төгсгөл)-ээс хойшхи өөрчлөлтийг ангилна. Алдаа бүр «зөвшөөрөгдөөгүй».</summary>
    public LaterChanges Later(long end)
    {
        try
        {
            return LaterCore(end);
        }
        catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
        {
            return LaterChanges.Nothing;
        }
    }

    private LaterChanges LaterCore(long endL)
    {
        int n = Doc.Length;
        if (endL <= 0 || endL >= n) return LaterChanges.Nothing;
        int end = (int)endL;
        var fin = View(n);
        var bas = View(end);
        if (fin is null || bas is null) return LaterChanges.Nothing;
        int k = fin.Sections.Count - bas.Sections.Count;
        if (k < 1) return LaterChanges.Nothing;
        var ends = new List<int> { end };
        for (int i = k - 1; i >= 0; i--)
        {
            var s = fin.Sections[i];
            var p = fin.Parser(s.End);
            var at = p.Startxref();
            int e = p.Pos;
            if (i == 0) e = n;
            if (at is not { } atv || atv != s.Off || e <= ends[ends.Count - 1]) return LaterChanges.Nothing;
            ends.Add(e);
        }
        bool signaturesOnly = true;
        int signatures = 0;
        bool visible = false;
        int sigSteps = 0;
        for (int i = 1; i < ends.Count; i++)
        {
            Budget.Ct.ThrowIfCancellationRequested();
            bool hasSig = HasSig(ends[i - 1], ends[i]);
            if (hasSig) sigSteps++;
            var st = Classify(ends[i - 1], ends[i], true, StepMode(hasSig));
            if (st is not { } stv) return LaterChanges.Nothing;
            signatures += stv.Signatures;
            visible = visible || stv.Visible;
        }
        if (k > 1)
        {
            var mode = ClassifyMode.Broad;
            if (sigSteps == k) mode = StepMode(true);
            else if (sigSteps == 0) mode = StepMode(false);
            var cum = Classify(ends[0], n, false, mode);
            if (cum is not { } cv || cv.Signatures != signatures) return LaterChanges.Nothing;
            visible = visible || cv.Visible;
        }
        return new LaterChanges(signaturesOnly, signatures, visible);
    }

    private ClassifyMode StepMode(bool hasSig)
    {
        if (!hasSig) return ClassifyMode.DssOnly;
        return OwnProfile ? ClassifyMode.Own : ClassifyMode.Broad;
    }

    private bool HasSig(int from, int to)
    {
        var bas = View(from);
        var fin = View(to);
        if (bas is null || fin is null) return true;
        foreach (var num in Known.Keys)
            if (P.InUse(P.Ent(fin.Xref, num)) && !P.InUse(P.Ent(bas.Xref, num))) return true;
        return false;
    }

    private LaterChanges? Classify(int from, int to, bool strict, ClassifyMode mode)
    {
        var key = (from, to, (int)mode * 2 + (strict ? 1 : 0));
        if (_steps.TryGetValue(key, out var hit)) return hit;
        LaterChanges? res = null;
        var bas = View(from);
        var fin = View(to);
        if (bas is not null && fin is not null)
        {
            var c = new Classifier(bas, fin, strict, Known)
            {
                Sigs = Sigs,
                DocId = DocId,
                Own = mode == ClassifyMode.Own,
                DssOnly = mode == ClassifyMode.DssOnly,
                OwnProfile = OwnProfile,
            };
            bool ok = true;
            try
            {
                c.Run();
            }
            catch (PdfObjException)
            {
                // Go: алдаа (errNotSignatureOnly, errPDFSyntax, errPDFLimit) → nil. Бусад exception = Go panic → Later()-ийн
                // recover (кэшлэгдэхгүй).
                ok = false;
            }
            if (ok) res = new LaterChanges(true, c.SigDicts.Count, c.Visible);
        }
        _steps[key] = res;
        return res;
    }
}

internal sealed class Classifier
{
    private static readonly string[] SigFieldKeys = { "Type", "Subtype", "FT", "T", "TU", "V", "Rect", "P", "F", "Ff", "M", "AP" };
    private static readonly string[] SigDictKeys =
    {
        "Type", "Filter", "SubFilter", "Contents", "ByteRange", "Cert", "M", "Name", "Location", "Reason", "ContactInfo", "Reference", "Prop_Build",
        "Prop_AuthTime", "Prop_AuthType", "Changes", "R", "V", "TransformMethod", "TransformParams",
    };
    private static readonly string[] OwnFieldKeys = { "Type", "Subtype", "Rect", "P", "F", "FT", "T", "V" };
    private static readonly string[] OwnSigDictKeys =
    {
        "Type", "Filter", "SubFilter", "Prop_Build", "ByteRange", "Contents", "TransformMethod", "TransformParams", "Name", "Location", "Reason", "ContactInfo", "M",
    };
    private static readonly string[] PadesSigDictKeys = { "Type", "Filter", "SubFilter", "ByteRange", "Contents", "M", "Name", "Reason" };
    private static readonly string[] LtvRoles = { "catalog", "dss", "vri", "vrient", "ltvarr", "ltv", "info", "metadata" };

    /// <summary>Sig dict-ийн чөлөөт бичвэрийн дээд урт, байт (Go ownTextLimit).</summary>
    public const int OwnTextLimit = 256;

    public Classifier(PdfView bas, PdfView fin, bool strict, Dictionary<int, long[]> known)
    {
        Base = bas;
        Fin = fin;
        Strict = strict;
        Known = known;
        End = bas.Len;
    }

    public PdfView Base { get; }
    public PdfView Fin { get; }
    public bool Strict { get; }
    public Dictionary<int, long[]> Known { get; }
    public int End { get; }
    public bool Own { get; init; }
    public bool DssOnly { get; init; }
    public bool OwnProfile { get; init; }
    public Dictionary<int, SigMeta> Sigs { get; init; } = new();
    public string DocId { get; init; } = "";

    private bool _ltvWork, _infoWork, _sigWork;
    private readonly HashSet<int> _rewritten = new();
    private readonly HashSet<int> _ownRewrite = new();
    private int _root;
    public readonly HashSet<int> Changed = new();
    public readonly HashSet<int> IsNew = new();
    private readonly HashSet<int> _allowed = new();
    private readonly HashSet<int> _exclusive = new();
    private readonly HashSet<int> _infra = new();
    private readonly HashSet<int> _xrefSelf = new();
    private readonly Dictionary<(int, int), int> _edges = new();
    public readonly HashSet<int> SigDicts = new();
    private readonly HashSet<int> _widgets = new();
    private readonly Dictionary<int, string> _role = new();
    private readonly HashSet<int> _seen = new();
    public readonly HashSet<int> Pages = new();
    private readonly Dictionary<int, int> _widgetP = new();
    private readonly Dictionary<int, int> _widgetPage = new();
    private readonly Dictionary<int, int> _annotsOf = new();
    private readonly HashSet<string> _fieldNames = new(StringComparer.Ordinal);
    public bool Visible;
    private readonly HashSet<int> _ownVis = new();

    public static PdfObjException NotSignatureOnly() => new("validate: change after the signature is not on the allowed list");

    public void Edge(int a, int b)
    {
        _edges.TryGetValue((a, b), out var n);
        _edges[(a, b)] = n + 1;
    }

    private void Claim(int num, string role)
    {
        if (_role.TryGetValue(num, out var r) && r != role) throw NotSignatureOnly();
        _role[num] = role;
    }

    private string? RoleOf(int n) => _role.TryGetValue(n, out var r) ? r : null;

    public void Run()
    {
        Structure();
        Diff();
        var refs = Fin.Graph();
        var reach = new HashSet<int>();
        var queue = new Stack<int>();
        P.Refs(Fin.Trailer, r => queue.Push(r.Num));
        while (queue.Count > 0)
        {
            int n = queue.Pop();
            if (reach.Contains(n) || !P.InUse(P.Ent(Fin.Xref, n))) continue;
            reach.Add(n);
            if (refs.TryGetValue(n, out var tos))
                foreach (var t in tos) queue.Push(t);
        }
        foreach (var n in IsNew)
            if (Strict || reach.Contains(n)) _exclusive.Add(n);
        bool dangling = false;
        void MarkNew(PRef r) => dangling = dangling || IsNew.Contains(r.Num);
        P.Refs(Base.Trailer, MarkNew);
        foreach (var kv in Fin.Xref)
        {
            int num = kv.Key;
            if (!P.InUse(kv.Value) || IsNew.Contains(num)) continue;
            if (Changed.Contains(num))
            {
                P.Refs(Base.Get(num), MarkNew);
            }
            else if (refs.TryGetValue(num, out var tos))
            {
                foreach (var to in tos) dangling = dangling || IsNew.Contains(to);
            }
        }
        if (dangling) throw NotSignatureOnly();
        Catalog();
        var pages = new List<int>(Pages);
        pages.Sort();
        foreach (var p in pages) Page(p);
        foreach (var n in _ownRewrite)
        {
            var r = RoleOf(n);
            if (!Changed.Contains(n) || !_allowed.Contains(n) || (r != "page" && r != "annots")) throw NotSignatureOnly();
        }
        foreach (var kv in _widgetP)
        {
            int w = kv.Key, p = kv.Value;
            bool placed = _widgetPage.TryGetValue(w, out var at);
            if ((p != 0 && (!Pages.Contains(p) || (placed && at != p))) || (_ownVis.Contains(w) && (!placed || at != p))) throw NotSignatureOnly();
        }
        if (DssOnly) Info();
        foreach (var n in Changed)
        {
            if (!_allowed.Contains(n) && !_infra.Contains(n) && (Strict || reach.Contains(n))) throw NotSignatureOnly();
            var r = RoleOf(n);
            if (Own && !IsNew.Contains(n) && !(_allowed.Contains(n) && (r == "page" || r == "annots"))) throw NotSignatureOnly();
        }
        if (DssOnly) DssOnlyRules();
        if (Own)
        {
            if (!IsNew.Contains(_root) || SigDicts.Count != _widgets.Count || SigDicts.Count == 0 || (Strict && SigDicts.Count != 1) ||
                (Visible && _ownVis.Count == 0))
                throw NotSignatureOnly();
            foreach (var n in IsNew)
            {
                var r = RoleOf(n) ?? "";
                if (Strict && !_xrefSelf.Contains(n) && r != "sig" && r != "field" && r != "catalog" && (r != "ap" || _ownVis.Count == 0))
                    throw NotSignatureOnly();
            }
        }
        foreach (var kv in refs)
        {
            int from = kv.Key;
            if ((!Strict && !reach.Contains(from)) || _infra.Contains(from)) continue;
            var count = new Dictionary<int, int>();
            foreach (var to in kv.Value)
            {
                if (!_exclusive.Contains(to)) continue;
                count.TryGetValue(to, out var c0);
                count[to] = c0 + 1;
            }
            foreach (var c in count)
            {
                _edges.TryGetValue((from, c.Key), out var have);
                if (have != c.Value) throw NotSignatureOnly();
            }
        }
        bool bad = false;
        foreach (var kv in Fin.Trailer)
            if (kv.Key != "Root") P.Refs(kv.Value, r => bad = bad || _exclusive.Contains(r.Num));
        if (bad || (SigDicts.Count == 0 && _sigWork)) throw NotSignatureOnly();
    }

    /// <summary>xref гинж, trailer, мужийн дараах байтуудын бүрэн хамралт.</summary>
    private void Structure()
    {
        var fs = Fin.Sections;
        var bs = Base.Sections;
        int k = fs.Count - bs.Count;
        if (k < 1 || (Strict && k != 1)) throw NotSignatureOnly();
        for (int i = 0; i < bs.Count; i++)
            if (fs[k + i].Off != bs[i].Off) throw NotSignatureOnly();
        var lin = Fin.Parser(0);
        lin.Skip();
        bool linearized = false;
        try
        {
            var o = lin.Indirect(null);
            linearized = o.Val is Dictionary<string, object?> ld && P.Get(ld, "Linearized") is not null && P.IfaceEq(P.Get(ld, "L"), (long)Fin.Len);
        }
        catch (Exception e) when (e is not OperationCanceledException and not OutOfMemoryException)
        {
            // Go: задрахгүй бол алгасна
        }
        if (linearized) throw NotSignatureOnly();
        var spans = new List<(int S, int E)>();
        for (int si = 0; si < k; si++)
        {
            var s = fs[si];
            bool infoOmitted = Own && P.IsName(P.Get(s.Trailer, "Type"), "XRef") && P.Get(s.Trailer, "Info") is null;
            if (s.Off < End || !TrailerCompatible(Base.Trailer, s.Trailer, infoOmitted)) throw NotSignatureOnly();
            var p = Fin.Parser(s.End);
            var at = p.Startxref();
            if (at is not { } atv || atv != s.Off) throw NotSignatureOnly();
            spans.Add((s.Start, p.Pos));
            var keys = new List<string> { "Size", "Root", "Info", "ID", "Prev" };
            if (Fin.ByteAt(s.Start) == 'x')
            {
                for (int i = s.Start; i < s.End; i++)
                {
                    int c = Fin.ByteAt(i);
                    if (c == 0 || c == '%') throw NotSignatureOnly();
                }
            }
            else
            {
                keys.AddRange(new[] { "Type", "W", "Index", "Length", "Filter", "DecodeParms" });
                var sp = Fin.Parser(s.Start);
                sp.Strict = true;
                sp.Indirect(null);
            }
            if (!OnlyKeys(s.Trailer, keys.ToArray())) throw NotSignatureOnly();
            var packed = new Dictionary<long, int>();
            foreach (var kv in s.Ents)
            {
                int num = kv.Key;
                var e = kv.Value;
                if (Own && e.Kind != P.EntUse) throw NotSignatureOnly();
                if (Own && P.InUse(P.Ent(Base.Xref, num))) _ownRewrite.Add(num);
                if (DssOnly && OwnProfile && P.InUse(e) && P.InUse(P.Ent(Base.Xref, num))) _rewritten.Add(num);
                if (e.Kind == P.EntUse)
                {
                    int c = Fin.ByteAt(e.Off);
                    if (e.Off < End || e.Off >= Fin.Len || c < '0' || c > '9') throw NotSignatureOnly();
                    if (e.Off == s.Start)
                    {
                        _infra.Add(num);
                        _xrefSelf.Add(num);
                        continue;
                    }
                    var p2 = Fin.Parser((int)e.Off);
                    p2.Strict = true;
                    var o = p2.Indirect(Fin.LengthOf);
                    if (o.Num != num || o.Gen != e.Gen) throw NotSignatureOnly();
                    spans.Add(((int)e.Off, p2.Pos));
                }
                else if (e.Kind == P.EntComp)
                {
                    var st = P.Ent(Fin.Xref, e.Off);
                    if (st.Kind != P.EntUse || st.Off < End) throw NotSignatureOnly();
                    if (Own) throw NotSignatureOnly();
                    packed.TryGetValue(e.Off, out var pc);
                    packed[e.Off] = pc + 1;
                }
            }
            foreach (var kv in packed)
            {
                if (!Strict) continue;
                var st = Fin.ObjStmAt(kv.Key);
                if (kv.Key > int.MaxValue || !s.Ents.ContainsKey((int)kv.Key) || st.Nums.Count != kv.Value) throw NotSignatureOnly();
                foreach (var off in st.Offs)
                {
                    var sp = new PdfParser(st.Data, st.Data.Length, (int)Math.Min((long)st.First + off, st.Data.Length), Fin.Budget, true);
                    sp.Value(0);
                }
                _infra.Add((int)kv.Key);
            }
        }
        spans.Sort((a, b) => a.S.CompareTo(b.S));
        int cur = End;
        foreach (var sp in spans)
        {
            if (sp.S < cur || !P.AllGapSpace(Fin.B.AsSpan(cur, sp.S - cur))) throw NotSignatureOnly();
            cur = sp.E;
        }
        if (!P.AllGapSpace(Fin.B.AsSpan(cur, Fin.Len - cur))) throw NotSignatureOnly();
    }

    /// <summary>Суурь ба эцсийн xref-ийг харьцуулж Changed/IsNew-г бөглөнө.</summary>
    private void Diff()
    {
        foreach (var kv in Base.Xref)
        {
            var be = kv.Value;
            if (!P.InUse(be)) continue;
            if (be.Kind == P.EntUse && be.Off >= End) throw NotSignatureOnly();
            if (!P.InUse(P.Ent(Fin.Xref, kv.Key))) throw NotSignatureOnly();
        }
        foreach (var kv in Fin.Xref)
        {
            int num = kv.Key;
            var fe = kv.Value;
            if (!P.InUse(fe)) continue;
            var be = P.Ent(Base.Xref, num);
            if (!P.InUse(be))
            {
                IsNew.Add(num);
                Changed.Add(num);
                continue;
            }
            if (be == fe && (be.Kind == P.EntUse || P.Ent(Base.Xref, be.Off) == P.Ent(Fin.Xref, fe.Off))) continue;
            var bo = Base.Get(num);
            var fo = Fin.Get(num);
            bool unpack = be.Kind == P.EntComp && fe.Kind == P.EntUse && fe.Gen == 0 && (Own || (!Strict && OwnProfile && !DssOnly));
            if ((be.Kind != fe.Kind || be.Gen != fe.Gen) && !unpack) throw NotSignatureOnly();
            if (unpack && P.PdfEqual(bo, fo)) throw NotSignatureOnly();
            if (!P.PdfEqual(bo, fo)) Changed.Add(num);
        }
    }

    /// <summary>Эцсийн талын утга fv-г задална; ref бол заасан объект нь шинэ эсвэл суурьт ЯГ энэ байрлалд байсан.</summary>
    private (object? Val, int Num) Container(object? bv, object? fv, int owner, string role)
    {
        if (fv is not PRef r) return (fv, owner);
        if (!IsNew.Contains(r.Num) && !P.IfaceEq(bv, fv)) throw NotSignatureOnly();
        Claim(r.Num, role);
        var val = Fin.Deref(r);
        Edge(owner, r.Num);
        if (Changed.Contains(r.Num)) _allowed.Add(r.Num);
        return (val, r.Num);
    }

    private Dictionary<string, object?>? BaseDict(object? v)
    {
        var o = Base.Resolve(v);
        if (o is null) return null;
        if (o is not Dictionary<string, object?> d) throw NotSignatureOnly();
        return d;
    }

    private List<object?>? BaseArr(object? v)
    {
        var o = Base.Resolve(v);
        if (o is null) return null;
        if (o is not List<object?> a) throw NotSignatureOnly();
        return a;
    }

    private static bool SameExcept(Dictionary<string, object?>? a, Dictionary<string, object?>? b, params string[] keys)
    {
        foreach (var d in new[] { a, b })
        {
            if (d is null) continue;
            foreach (var k in d.Keys)
                if (Array.IndexOf(keys, k) < 0 && !P.PdfEqual(P.Get(a, k), P.Get(b, k))) return false;
        }
        return true;
    }

    internal static bool OnlyKeys(Dictionary<string, object?>? d, params string[] keys)
    {
        if (d is null) return true;
        foreach (var k in d.Keys)
            if (Array.IndexOf(keys, k) < 0) return false;
        return true;
    }

    private static List<string> SortedKeys(Dictionary<string, object?>? d)
    {
        var l = d is null ? new List<string>() : new List<string>(d.Keys);
        l.Sort(string.CompareOrdinal);
        return l;
    }

    /// <summary>«M.m» (1.0 … 2.9) → M*10+m.</summary>
    private static int? PdfVersion(string s)
    {
        if (s.Length != 3 || s[1] != '.' || (s[0] != '1' && s[0] != '2') || s[2] < '0' || s[2] > '9') return null;
        return (s[0] - '0') * 10 + (s[2] - '0');
    }

    private static bool TrailerCompatible(Dictionary<string, object?> bas, Dictionary<string, object?> later, bool infoOmitted)
    {
        if (!infoOmitted && !P.PdfEqual(P.Get(later, "Info"), P.Get(bas, "Info"))) return false;
        if (P.Get(bas, "ID") is List<object?> bid && bid.Count == 2 && later.ContainsKey("ID"))
        {
            if (P.Get(later, "ID") is not List<object?> a || a.Count != 2 || !P.PdfEqual(a[0], bid[0])) return false;
        }
        long bs = P.Get(bas, "Size") is long bsv ? bsv : 0;
        return P.Get(later, "Size") is long ls && ls >= bs;
    }

    private void Catalog()
    {
        var fr = P.Get(Fin.Trailer, "Root");
        var br = P.Get(Base.Trailer, "Root");
        if (fr is not PRef frr || br is not PRef brr || (frr.Num != brr.Num && !IsNew.Contains(frr.Num))) throw NotSignatureOnly();
        var fc0 = Fin.Deref(frr);
        var bc0 = Base.Deref(brr);
        var except = new List<string> { "AcroForm", "DSS", "Perms", "Version" };
        if (DssOnly) except.AddRange(new[] { "Extensions", "Metadata" });
        if (fc0 is not Dictionary<string, object?> fc || bc0 is not Dictionary<string, object?> bc || !SameExcept(bc, fc, except.ToArray())) throw NotSignatureOnly();
        if (Own)
        {
            if (!SameExcept(bc, fc, "AcroForm", "Version") ||
                (!P.PdfEqual(P.Get(bc, "Version"), P.Get(fc, "Version")) && (P.Get(bc, "Version") is not null || !P.IfaceEq(P.Get(fc, "Version"), new PName("1.5")))))
                throw NotSignatureOnly();
        }
        _root = frr.Num;
        _allowed.Add(frr.Num);
        Claim(frr.Num, "catalog");
        PageTree(P.Get(fc, "Pages"));
        if (!P.PdfEqual(P.Get(bc, "Version"), P.Get(fc, "Version")))
        {
            var fvn = P.Get(fc, "Version");
            var nv = PdfVersion(fvn is PName fn ? fn.V : "");
            var bb = Base;
            var head = new StringBuilder();
            for (int i = Math.Min(bb.Len, 5); i < Math.Min(bb.Len, 8); i++) head.Append((char)bb.B[i]);
            int? floor = PdfVersion(head.ToString());
            bool ok2 = floor is not null;
            if (bc.ContainsKey("Version"))
            {
                var bn = P.Get(bc, "Version");
                var bv = PdfVersion(bn is PName bnn ? bnn.V : "");
                ok2 = ok2 && bv is not null;
                floor = Math.Max(floor ?? 0, bv ?? 0);
            }
            var pfx = new StringBuilder();
            for (int i = 0; i < Math.Min(5, bb.Len); i++) pfx.Append((char)bb.B[i]);
            if (nv is not { } nvv || !ok2 || pfx.ToString() != "%PDF-" || nvv < (floor ?? 0)) throw NotSignatureOnly();
            if (DssOnly) _infoWork = true;
            else _sigWork = true;
        }
        if (DssOnly)
        {
            Extensions(P.Get(bc, "Extensions"), P.Get(fc, "Extensions"));
            Metadata(P.Get(bc, "Metadata"), P.Get(fc, "Metadata"));
        }
        AcroForm(P.Get(bc, "AcroForm"), P.Get(fc, "AcroForm"));
        if (!P.PdfEqual(P.Get(bc, "Perms"), P.Get(fc, "Perms")))
        {
            _sigWork = true;
            var bpd = BaseDict(P.Get(bc, "Perms"));
            var (pv, pn) = Container(P.Get(bc, "Perms"), P.Get(fc, "Perms"), _root, "perms");
            if (pv is not Dictionary<string, object?> pvd || !OnlyKeys(pvd, "DocMDP", "UR", "UR3")) throw NotSignatureOnly();
            foreach (var key in SortedKeys(pvd))
            {
                var r = P.Get(pvd, key);
                if (r is not PRef rr || (!SigDicts.Contains(rr.Num) && (Changed.Contains(rr.Num) || !P.IfaceEq(P.Get(bpd, key), rr)))) throw NotSignatureOnly();
                Edge(pn, rr.Num);
            }
        }
        Dss(P.Get(bc, "DSS"), P.Get(fc, "DSS"));
    }

    private void PageTree(object? root)
    {
        var stack = new Stack<object?>();
        stack.Push(root);
        var visited = new HashSet<int>();
        while (stack.Count > 0)
        {
            var r = stack.Pop();
            if (r is not PRef rr || visited.Contains(rr.Num)) throw NotSignatureOnly();
            visited.Add(rr.Num);
            var o = Fin.Deref(rr);
            var d = o as Dictionary<string, object?>;
            var t = P.Get(d, "Type");
            if (P.IfaceEq(t, new PName("Page")))
            {
                Pages.Add(rr.Num);
            }
            else if (P.IfaceEq(t, new PName("Pages")))
            {
                if (Fin.Resolve(P.Get(d, "Kids")) is not List<object?> kids) throw NotSignatureOnly();
                foreach (var kid in kids) stack.Push(kid);
            }
            else
            {
                throw NotSignatureOnly();
            }
        }
    }

    private void Page(int p)
    {
        var fo = Fin.Get(p);
        if (fo is not Dictionary<string, object?> fd || IsNew.Contains(p)) throw NotSignatureOnly();
        var bd = fd;
        if (Changed.Contains(p))
        {
            if (Base.Get(p) is not Dictionary<string, object?> bo || !SameExcept(bo, fd, "Annots")) throw NotSignatureOnly();
            bd = bo;
            Claim(p, "page");
            _sigWork = true;
            _allowed.Add(p);
        }
        var ar = P.Get(fd, "Annots");
        if (!Changed.Contains(p) && !(ar is PRef arr && Changed.Contains(arr.Num))) return;
        if (ar is null)
        {
            if (P.Get(bd, "Annots") is not null) throw NotSignatureOnly();
            return;
        }
        var ba = BaseArr(P.Get(bd, "Annots")) ?? new List<object?>();
        var (v, anum) = Container(P.Get(bd, "Annots"), ar, p, "annots");
        if (v is not List<object?> fa) throw NotSignatureOnly();
        if (anum != p)
        {
            if (_annotsOf.ContainsKey(anum)) throw NotSignatureOnly();
            _annotsOf[anum] = p;
            if (Changed.Contains(anum))
            {
                _sigWork = true;
                _exclusive.Add(anum);
            }
        }
        if (fa.Count < ba.Count) throw NotSignatureOnly();
        for (int i = 0; i < fa.Count; i++)
        {
            var e = fa[i];
            if (i < ba.Count)
            {
                if (!P.PdfEqual(ba[i], e)) throw NotSignatureOnly();
                continue;
            }
            if (e is not PRef er || !_widgets.Contains(er.Num) || _widgetPage.ContainsKey(er.Num)) throw NotSignatureOnly();
            _widgetPage[er.Num] = p;
            Edge(anum, er.Num);
        }
    }

    private void AcroForm(object? bv, object? fv)
    {
        if (fv is null)
        {
            if (bv is not null) throw NotSignatureOnly();
            return;
        }
        var bd = BaseDict(bv);
        var (v, num) = Container(bv, fv, _root, "acroform");
        if (v is not Dictionary<string, object?> fd || !SameExcept(bd, fd, "Fields", "SigFlags")) throw NotSignatureOnly();
        if (!P.PdfEqual(P.Get(bd, "SigFlags"), P.Get(fd, "SigFlags")))
        {
            var nf = P.Get(fd, "SigFlags");
            var ofv = P.Get(bd, "SigFlags");
            bool was = ofv is long;
            long of = ofv is long ol ? ol : 0;
            if (nf is not long nfl || (nfl != 1 && nfl != 3) || (ofv is not null && !was) || nfl < of) throw NotSignatureOnly();
        }
        if (!P.PdfEqual(P.Get(bd, "SigFlags"), P.Get(fd, "SigFlags")) || bd is null) _sigWork = true;
        if (Own)
        {
            if (fv is not Dictionary<string, object?> || P.Get(fd, "Fields") is not List<object?> || !P.IfaceEq(P.Get(fd, "SigFlags"), 3L)) throw NotSignatureOnly();
        }
        var bf = BaseArr(P.Get(bd, "Fields")) ?? new List<object?>();
        if (Own)
        {
            foreach (var e in bf)
            {
                var o = Base.Resolve(e);
                if (o is not Dictionary<string, object?> od || e is not PRef) throw NotSignatureOnly();
                if (P.Get(od, "T") is PStr t) _fieldNames.Add(OwnText.PdfTextString(t));
            }
        }
        var (fv2, fnum) = Container(P.Get(bd, "Fields"), P.Get(fd, "Fields"), num, "fields");
        if ((fv2 is not null && fv2 is not List<object?>) || (fv2 is List<object?> fl0 ? fl0.Count : 0) < bf.Count) throw NotSignatureOnly();
        var ff = fv2 as List<object?> ?? new List<object?>();
        for (int i = 0; i < ff.Count; i++)
        {
            var e = ff[i];
            if (i < bf.Count)
            {
                if (!P.PdfEqual(bf[i], e)) throw NotSignatureOnly();
                if (e is PRef er && Changed.Contains(er.Num))
                {
                    if (Own) throw NotSignatureOnly();
                    FilledField(er.Num);
                }
            }
            else if (e is not PRef nr)
            {
                throw NotSignatureOnly();
            }
            else
            {
                NewField(nr, fnum);
            }
        }
    }

    private void NewField(PRef r, int owner)
    {
        if (!IsNew.Contains(r.Num) || _widgets.Contains(r.Num)) throw NotSignatureOnly();
        if (Fin.Deref(r) is not Dictionary<string, object?> d || !OnlyKeys(d, SigFieldKeys) || !P.IfaceEq(P.Get(d, "FT"), new PName("Sig"))) throw NotSignatureOnly();
        if (d.ContainsKey("Type") && !P.IfaceEq(P.Get(d, "Type"), new PName("Annot"))) throw NotSignatureOnly();
        if (d.ContainsKey("Subtype") && !P.IfaceEq(P.Get(d, "Subtype"), new PName("Widget"))) throw NotSignatureOnly();
        foreach (var k in new[] { "T", "TU", "M" })
            if (d.ContainsKey(k) && P.Get(d, k) is not PStr) throw NotSignatureOnly();
        foreach (var k in new[] { "F", "Ff" })
            if (d.ContainsKey(k) && P.Get(d, k) is not long) throw NotSignatureOnly();
        if (Own)
        {
            if (d.ContainsKey("AP"))
            {
                OwnAppearance.OwnVisible(this, d, r.Num);
                _ownVis.Add(r.Num);
            }
            else if (!OnlyKeys(d, OwnFieldKeys) || !P.IfaceEq(P.Get(d, "Type"), new PName("Annot")) || !P.IfaceEq(P.Get(d, "Subtype"), new PName("Widget")) ||
                     !P.PdfEqual(P.Get(d, "Rect"), new List<object?> { 0L, 0L, 0L, 0L }) || !P.IfaceEq(P.Get(d, "F"), 132L))
            {
                throw NotSignatureOnly();
            }
            var name = OwnText.Text(P.Get(d, "T"), 32);
            if (name is null || !OwnFieldName(name) || !P.IfaceEq(P.Get(d, "T"), new PStr(name)) || _fieldNames.Contains(name)) throw NotSignatureOnly();
            _fieldNames.Add(name);
        }
        _widgetP[r.Num] = 0;
        if (d.ContainsKey("P"))
        {
            if (P.Get(d, "P") is not PRef pr) throw NotSignatureOnly();
            _widgetP[r.Num] = pr.Num;
        }
        Claim(r.Num, "field");
        _sigWork = true;
        _widgets.Add(r.Num);
        _allowed.Add(r.Num);
        Edge(owner, r.Num);
        SigValue(P.Get(d, "V"), r.Num);
        Appearance(null, d, r.Num);
    }

    /// <summary>«Signature N», N = 1…9999 (тэргүүн тэггүй).</summary>
    private static bool OwnFieldName(string s)
    {
        if (!s.StartsWith("Signature ", StringComparison.Ordinal)) return false;
        var n = s.Substring("Signature ".Length);
        if (n.Length < 1 || n.Length > 4 || n[0] == '0') return false;
        foreach (var c in n)
            if (c < '0' || c > '9') return false;
        return true;
    }

    private void FilledField(int num)
    {
        var bd0 = Base.Get(num);
        var fd0 = Fin.Get(num);
        if (bd0 is not Dictionary<string, object?> bd || fd0 is not Dictionary<string, object?> fd || !P.IfaceEq(P.Get(bd, "FT"), new PName("Sig")) ||
            P.Get(bd, "V") is not null || P.Get(bd, "Kids") is not null || !SameExcept(bd, fd, "V", "AP", "M"))
            throw NotSignatureOnly();
        if (bd.ContainsKey("Type") && !P.IfaceEq(P.Get(bd, "Type"), new PName("Annot"))) throw NotSignatureOnly();
        if (bd.ContainsKey("Subtype") && !P.IfaceEq(P.Get(bd, "Subtype"), new PName("Widget"))) throw NotSignatureOnly();
        if (fd.ContainsKey("M") && P.Get(fd, "M") is not PStr) throw NotSignatureOnly();
        Claim(num, "field");
        _sigWork = true;
        _allowed.Add(num);
        SigValue(P.Get(fd, "V"), num);
        Appearance(bd, fd, num);
    }

    private void SigValue(object? v, int owner)
    {
        if (v is not PRef r || !IsNew.Contains(r.Num) || SigDicts.Contains(r.Num)) throw NotSignatureOnly();
        Claim(r.Num, "sig");
        if (Fin.Deref(r) is not Dictionary<string, object?> d || !OnlyKeys(d, SigDictKeys)) throw NotSignatureOnly();
        if (Own && (!OnlyKeys(d, OwnSigDictKeys) || !P.IfaceEq(P.Get(d, "Type"), new PName("Sig")))) throw NotSignatureOnly();
        if (Own)
        {
            if (P.IfaceEq(P.Get(d, "SubFilter"), new PName("ETSI.CAdES.detached")) &&
                (!OnlyKeys(d, PadesSigDictKeys) || !P.IfaceEq(P.Get(d, "Filter"), new PName("Adobe.PPKLite")) || P.Get(d, "M") is null))
                throw NotSignatureOnly();
            foreach (var k in new[] { "Name", "Location", "Reason", "ContactInfo", "M" })
            {
                if (!d.ContainsKey(k)) continue;
                var text = OwnText.Text(P.Get(d, k), OwnTextLimit);
                if (text is null || (k == "M" && !OwnText.OwnDate(text))) throw NotSignatureOnly();
            }
        }
        if (d.ContainsKey("Type") && !P.IfaceEq(P.Get(d, "Type"), new PName("Sig"))) throw NotSignatureOnly();
        if (P.Get(d, "ByteRange") is not List<object?> br || P.Get(d, "Contents") is not PStr || br.Count != 4) throw NotSignatureOnly();
        var n = new long[4];
        for (int i = 0; i < 4; i++)
        {
            if (br[i] is not long x) throw NotSignatureOnly();
            n[i] = x;
        }
        if (n[0] != 0 || n[1] <= 0 || n[2] <= n[1] || n[3] < 0 || (Int128)n[2] + n[3] <= End) throw NotSignatureOnly();
        if (!Known.TryGetValue(r.Num, out var kb) || kb.Length != 4) throw NotSignatureOnly();
        for (int i = 0; i < 4; i++)
            if (kb[i] != n[i]) throw NotSignatureOnly();
        bool bad = false;
        foreach (var kv in d)
        {
            if (kv.Key != "Reference")
            {
                P.Refs(kv.Value, _ => bad = true);
                continue;
            }
            bad = bad || kv.Value is not List<object?>;
            foreach (var row in kv.Value as List<object?> ?? new List<object?>())
            {
                if (row is not Dictionary<string, object?> rd || !OnlyKeys(rd, "Type", "TransformMethod", "TransformParams", "DigestMethod", "Data"))
                {
                    bad = true;
                    continue;
                }
                foreach (var rkv in rd)
                {
                    if (rkv.Key != "Data")
                    {
                        P.Refs(rkv.Value, _ => bad = true);
                    }
                    else if (rkv.Value is PRef dr && dr.Num == _root)
                    {
                        Edge(r.Num, _root);
                    }
                    else if (rkv.Value is PRef dr2 && P.IfaceEq(dr2, P.Get(Base.Trailer, "Root")))
                    {
                        // суурийн Catalog
                    }
                    else
                    {
                        bad = true;
                    }
                }
            }
        }
        if (bad) throw NotSignatureOnly();
        SigDicts.Add(r.Num);
        _allowed.Add(r.Num);
        Edge(owner, r.Num);
    }

    private void Appearance(Dictionary<string, object?>? bas, Dictionary<string, object?> d, int widget)
    {
        if (d.ContainsKey("Rect"))
        {
            if (P.Get(d, "Rect") is not List<object?> a || a.Count != 4) throw NotSignatureOnly();
            var f = new double[4];
            for (int i = 0; i < 4; i++)
            {
                if (a[i] is long l) f[i] = l;
                else if (a[i] is PReal pr) f[i] = pr.V;
                else throw NotSignatureOnly();
            }
            if (f[0] != f[2] && f[1] != f[3]) Visible = true;
        }
        if (!d.ContainsKey("AP")) return;
        var ap = P.Get(d, "AP");
        Visible = true;
        if (P.PdfEqual(P.Get(bas, "AP"), ap)) return;
        if (ap is not Dictionary<string, object?> apd || !OnlyKeys(apd, "N", "R", "D")) throw NotSignatureOnly();
        var queue = new Stack<int>();
        foreach (var key in SortedKeys(apd))
        {
            if (P.Get(apd, key) is not PRef r || !IsNew.Contains(r.Num)) throw NotSignatureOnly();
            if (Fin.Deref(r) is not PStream) throw NotSignatureOnly();
            Edge(widget, r.Num);
            queue.Push(r.Num);
        }
        while (queue.Count > 0)
        {
            int n = queue.Pop();
            if (!Changed.Contains(n)) continue;
            if (!IsNew.Contains(n) || _infra.Contains(n)) throw NotSignatureOnly();
            Claim(n, "ap");
            if (_seen.Contains(n)) continue;
            _seen.Add(n);
            _allowed.Add(n);
            P.Refs(Fin.Get(n), t =>
            {
                Edge(n, t.Num);
                queue.Push(t.Num);
            });
        }
    }

    private (object? Val, int Num) DssNode(object? bv, object? fv, int owner, string role)
    {
        var (v, num) = Container(bv, fv, owner, role);
        if (num != owner && Changed.Contains(num))
        {
            _exclusive.Add(num);
            _ltvWork = true;
        }
        return (v, num);
    }

    private HashSet<int> BaseLtvStreams(Dictionary<string, object?>? bd)
    {
        var o = new HashSet<int>();
        void Add(Dictionary<string, object?>? d, params string[] keys)
        {
            foreach (var k in keys)
                foreach (var e in BaseArr(P.Get(d, k)) ?? new List<object?>())
                    if (e is PRef r) o.Add(r.Num);
        }
        Add(bd, "Certs", "OCSPs", "CRLs");
        var vri = BaseDict(P.Get(bd, "VRI"));
        if (vri is not null)
        {
            foreach (var e in vri.Values)
            {
                var ed = BaseDict(e);
                Add(ed, "Cert", "OCSP", "CRL");
                if (P.Get(ed, "TS") is PRef ts) o.Add(ts.Num);
            }
        }
        return o;
    }

    private void Dss(object? bv, object? fv)
    {
        if (fv is null)
        {
            if (bv is not null) throw NotSignatureOnly();
            return;
        }
        var bd = BaseDict(bv);
        var old = BaseLtvStreams(bd);
        var (v, num) = DssNode(bv, fv, _root, "dss");
        if (v is not Dictionary<string, object?> fd || !OnlyKeys(fd, "Type", "VRI", "Certs", "OCSPs", "CRLs")) throw NotSignatureOnly();
        foreach (var k in new[] { "Certs", "OCSPs", "CRLs" }) LtvArray(P.Get(bd, k), P.Get(fd, k), num, old);
        if (P.Get(fd, "VRI") is null) return;
        var bvri = BaseDict(P.Get(bd, "VRI"));
        var (vv, vnum) = DssNode(P.Get(bd, "VRI"), P.Get(fd, "VRI"), num, "vri");
        if (vv is not Dictionary<string, object?> fvri) throw NotSignatureOnly();
        foreach (var key in SortedKeys(fvri))
        {
            var bed = BaseDict(P.Get(bvri, key));
            var (ev, enumv) = DssNode(P.Get(bvri, key), P.Get(fvri, key), vnum, "vrient");
            if (ev is not Dictionary<string, object?> fed || !OnlyKeys(fed, "Type", "Cert", "OCSP", "CRL", "TU", "TS")) throw NotSignatureOnly();
            foreach (var k in new[] { "Cert", "OCSP", "CRL" }) LtvArray(P.Get(bed, k), P.Get(fed, k), enumv, old);
            if (P.Get(fed, "TU") is not null && P.Get(fed, "TU") is not PStr) throw NotSignatureOnly();
            if (fed.ContainsKey("TS")) LtvStream(P.Get(fed, "TS"), enumv, old);
        }
    }

    private void LtvArray(object? bv, object? fv, int owner, HashSet<int> old)
    {
        if (fv is null) return;
        var (v, num) = DssNode(bv, fv, owner, "ltvarr");
        if (v is not List<object?> a) throw NotSignatureOnly();
        if (num != owner)
        {
            if (_seen.Contains(num)) return;
            _seen.Add(num);
        }
        foreach (var e in a) LtvStream(e, num, old);
    }

    private void LtvStream(object? v, int owner, HashSet<int> old)
    {
        if (v is not PRef r) throw NotSignatureOnly();
        Claim(r.Num, "ltv");
        Edge(owner, r.Num);
        if (!IsNew.Contains(r.Num))
        {
            if (Changed.Contains(r.Num) || !old.Contains(r.Num)) throw NotSignatureOnly();
            return;
        }
        if (Fin.Deref(r) is not PStream s || !OnlyKeys(s.Dict, "Length", "Filter", "DecodeParms")) throw NotSignatureOnly();
        bool ok = true;
        P.Refs(s.Dict, _ => ok = false);
        if (!ok) throw NotSignatureOnly();
        _allowed.Add(r.Num);
        _ltvWork = true;
    }

    private void DssOnlyRules()
    {
        if (SigDicts.Count > 0 || _widgets.Count > 0 || _sigWork || Visible || ((_infoWork || OwnProfile) && !_ltvWork)) throw NotSignatureOnly();
        foreach (var n in Changed)
        {
            if (_infra.Contains(n) || (!Strict && !_allowed.Contains(n))) continue;
            if (Array.IndexOf(LtvRoles, RoleOf(n) ?? "") < 0) throw NotSignatureOnly();
        }
        foreach (var n in _rewritten)
        {
            if (!Changed.Contains(n) || !_allowed.Contains(n) || Array.IndexOf(LtvRoles, RoleOf(n) ?? "") < 0) throw NotSignatureOnly();
        }
    }

    private void Extensions(object? bv, object? fv)
    {
        if (P.PdfEqual(bv, fv)) return;
        if (fv is not Dictionary<string, object?> fd) throw NotSignatureOnly();
        static bool Dev(object? x)
        {
            if (x is not Dictionary<string, object?> xd || !OnlyKeys(xd, "Type", "BaseVersion", "ExtensionLevel", "ExtensionRevision", "URL")) return false;
            if (P.Get(xd, "BaseVersion") is not PName) return false;
            if (P.Get(xd, "ExtensionLevel") is not long) return false;
            foreach (var k in new[] { "ExtensionRevision", "URL" })
                if (xd.ContainsKey(k) && P.Get(xd, k) is not PStr) return false;
            if (xd.ContainsKey("Type") && !P.IfaceEq(P.Get(xd, "Type"), new PName("DeveloperExtensions"))) return false;
            return true;
        }
        foreach (var kv in fd)
        {
            if (kv.Key == "Type")
            {
                if (!P.IfaceEq(kv.Value, new PName("Extensions"))) throw NotSignatureOnly();
                continue;
            }
            if (kv.Value is List<object?> a)
            {
                foreach (var e in a)
                    if (!Dev(e)) throw NotSignatureOnly();
            }
            else if (!Dev(kv.Value))
            {
                throw NotSignatureOnly();
            }
        }
        _infoWork = true;
    }

    private void Metadata(object? bv, object? fv)
    {
        if (P.PdfEqual(bv, fv) && (fv is not PRef fr0 || !Changed.Contains(fr0.Num))) return;
        if (fv is not PRef) throw NotSignatureOnly();
        var (v, num) = Container(bv, fv, _root, "metadata");
        if (v is not PStream s || !OnlyKeys(s.Dict, "Type", "Subtype", "Length", "Filter", "DecodeParms") || !P.IfaceEq(P.Get(s.Dict, "Type"), new PName("Metadata")) ||
            !P.IfaceEq(P.Get(s.Dict, "Subtype"), new PName("XML")))
            throw NotSignatureOnly();
        bool bad = false;
        P.Refs(s.Dict, _ => bad = true);
        if (bad) throw NotSignatureOnly();
        if (IsNew.Contains(num)) _exclusive.Add(num);
        _infoWork = true;
    }

    private void Info()
    {
        if (P.Get(Fin.Trailer, "Info") is not PRef r || !Changed.Contains(r.Num) || IsNew.Contains(r.Num)) return;
        if (Fin.Get(r.Num) is not Dictionary<string, object?> d) throw NotSignatureOnly();
        foreach (var v in d.Values)
            if (v is not PStr && v is not PName) throw NotSignatureOnly();
        Claim(r.Num, "info");
        _allowed.Add(r.Num);
        _infoWork = true;
    }
}

/// <summary>PDF бичвэрийн мөрийн туслахууд (TS goUTF8 / pdfTextString / ownText / ownDate).</summary>
internal static class OwnText
{
    private static readonly string[] Forbidden = { " obj", "endobj", "stream", "xref", "trailer", "startxref", "%%EOF" };

    /// <summary>Go string(utf16.Decode(units)) — хос бус surrogate → U+FFFD.</summary>
    private static string DecodeUtf16(List<int> units)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < units.Count; i++)
        {
            int u = units[i];
            if (u >= 0xd800 && u < 0xdc00 && i + 1 < units.Count && units[i + 1] >= 0xdc00 && units[i + 1] < 0xe000)
            {
                sb.Append(char.ConvertFromUtf32(0x10000 + ((u - 0xd800) << 10) + (units[i + 1] - 0xdc00)));
                i++;
            }
            else if (u >= 0xd800 && u < 0xe000)
            {
                sb.Append('�');
            }
            else
            {
                sb.Append((char)u);
            }
        }
        return sb.ToString();
    }

    /// <summary>Go-ийн UTF-8 руны давталт (latin1 мөр = түүхий байт; буруу байт бүр нэг U+FFFD).</summary>
    public static string GoUtf8(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        for (int i = 0; i < raw.Length;)
        {
            int c = raw[i];
            if (c < 0x80)
            {
                sb.Append(raw[i]);
                i++;
                continue;
            }
            int n = 0, cp = 0, lo = 0x80, hi = 0xbf;
            if (c >= 0xc2 && c <= 0xdf)
            {
                n = 1;
                cp = c & 0x1f;
            }
            else if (c >= 0xe0 && c <= 0xef)
            {
                n = 2;
                cp = c & 0x0f;
                if (c == 0xe0) lo = 0xa0;
                if (c == 0xed) hi = 0x9f;
            }
            else if (c >= 0xf0 && c <= 0xf4)
            {
                n = 3;
                cp = c & 0x07;
                if (c == 0xf0) lo = 0x90;
                if (c == 0xf4) hi = 0x8f;
            }
            bool ok = n > 0 && i + n < raw.Length;
            if (ok)
            {
                for (int k = 1; k <= n; k++)
                {
                    int x = raw[i + k];
                    int l = k == 1 ? lo : 0x80;
                    int h = k == 1 ? hi : 0xbf;
                    if (x < l || x > h)
                    {
                        ok = false;
                        break;
                    }
                    cp = (cp << 6) | (x & 0x3f);
                }
            }
            if (!ok)
            {
                sb.Append('�');
                i++;
                continue;
            }
            sb.Append(char.ConvertFromUtf32(cp));
            i += n + 1;
        }
        return sb.ToString();
    }

    /// <summary>PDF text string: BOM-той (FE FF) бол UTF-16BE, эс бөгөөс түүхий байт (Go string — UTF-8 гэж уншина).</summary>
    public static string PdfTextString(PStr s)
    {
        var raw = s.V;
        if (!raw.StartsWith("þÿ", StringComparison.Ordinal)) return GoUtf8(raw);
        var units = new List<int>();
        for (int i = 2; i + 1 < raw.Length; i += 2) units.Add((raw[i] << 8) | raw[i + 1]);
        return DecodeUtf16(units);
    }

    /// <summary>v нь PAdES бичигчийн бичдэг хэлбэртэй бичвэр мөн эсэх; тайлсан бичвэрийг буцаана.</summary>
    public static string? Text(object? v, int limit)
    {
        if (v is not PStr s || s.V.Length > limit) return null;
        var raw = s.V;
        bool utf16be = raw.StartsWith("þÿ", StringComparison.Ordinal);
        if (utf16be && raw.Length % 2 != 0) return null;
        var text = PdfTextString(s);
        for (int i = 0; i < text.Length; i++)
        {
            int r = char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? char.ConvertToUtf32(text[i], text[++i]) : text[i];
            if (r < 0x20 || r == 0x7f || (!utf16be && r > 0x7e)) return null;
        }
        foreach (var bad in Forbidden)
            if (raw.Contains(bad, StringComparison.Ordinal) || text.Contains(bad, StringComparison.Ordinal)) return null;
        return text;
    }

    /// <summary>«D:YYYYMMDDHHmmSS±HH'mm'».</summary>
    public static bool OwnDate(string s)
    {
        if (s.Length != 23 || !s.StartsWith("D:", StringComparison.Ordinal) || (s[16] != '+' && s[16] != '-') || s[19] != '\'' || s[22] != '\'') return false;
        var d = s.Substring(2, 14) + s.Substring(17, 2) + s.Substring(20, 2);
        foreach (var c in d)
            if (c < '0' || c > '9') return false;
        return true;
    }
}
