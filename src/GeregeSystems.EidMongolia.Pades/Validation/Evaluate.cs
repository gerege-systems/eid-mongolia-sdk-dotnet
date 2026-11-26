using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;

namespace GeregeSystems.EidMongolia.Pades.Validation;

/// <summary>Цуцлалтын эх сурвалжийн хариу (TS CertStatus): eID олгогчийн гаргасан гэрчилгээний төлөв.</summary>
internal readonly record struct CertStatusResult(bool Issued, bool Revoked, GoTime? RevokedAt);

/// <summary>
/// cert — шалгах гэрчилгээ, issuer — гинжийн (гарын үсгээр баталгаажсан) олгогч: нотолгоо энэ хосынх байх ёстой. at — шалгах
/// цаг (цагийн тэмдгийн цаг эсвэл одоо): «good» нотолгоо at-д шинэлэг (FreshAt).
/// </summary>
internal interface IStatusSource
{
    Task<CertStatusResult> CertStatusAsync(ValCert cert, ValCert issuer, GoTime at, CancellationToken ct);
}

/// <summary>
/// Итгэлийн шийдвэр — TS SDK src/pades/validate/evaluate.ts (CA server/internal/validate/{validate.go,ltv.go}, Go SDK
/// pades/{trust.go,validatepdf.go})-ийн порт. Гинжийг Go crypto/x509 Verify-ийн зан төлөвөөр (эх нэрийн/түлхүүрийн ID-ийн
/// эрэмбэ, SHA-1 татгалзах, хугацаа, EKU) өөрөө бүтээнэ — X509Chain биш (платформ бүрд ижил, AIA татахгүй). Нэмэлт fail-closed
/// дүрэм (core-ийн path builder-тэй ижил, owner-ийн шийдвэр): name constraints-тэй CA-г татгалзана (SDK үнэлдэггүй), гинжийн
/// урт хязгаартай, RSA &lt; 2048 бит түлхүүрээр гарын үсэг таарахгүй (<see cref="ValCert.MinRsaBits"/>).
/// </summary>
internal sealed class Evaluator
{
    public const string ProblemIntegrity = "integrity_failed";
    public const string ProblemMalformed = "malformed_signature";
    public const string ProblemWeakAlgorithm = "weak_algorithm";
    public const string ProblemUntrusted = "untrusted_chain";
    public const string ProblemKeyUsage = "wrong_key_usage";
    public const string ProblemRevoked = "revoked";
    public const string ProblemRevokedAfter = "revoked_after_signing";
    public const string ProblemRevocationUnknown = "revocation_unavailable";
    public const string ProblemExpired = "expired";
    public const string ProblemNotYetValid = "not_yet_valid";
    public const string ProblemModifiedAfter = "modified_after_signing";
    public const string ProblemTimestampInvalid = "timestamp_invalid";

    private const int MaxChainLength = 10;
    private const int MaxChainAttempts = 100;

    private static readonly HashSet<string> HandledCritical = new(StringComparer.Ordinal)
    {
        "2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.17", "2.5.29.30", "2.5.29.32", "2.5.29.31", "2.5.29.35", "2.5.29.14", "2.5.29.36", "2.5.29.54", "2.5.29.33",
    };

    private readonly List<ValCert> _roots;
    private readonly List<ValCert> _intermediates;
    private readonly List<ValCert> _issuers;
    private readonly IStatusSource? _status;
    private readonly GoTime _now;

    public Evaluator(List<ValCert> roots, List<ValCert> intermediates, List<ValCert> issuers, IStatusSource? status, GoTime now)
    {
        _roots = roots;
        _intermediates = intermediates;
        _issuers = issuers;
        _status = status;
        _now = now;
    }

    // ── гинж (Go crypto/x509 Verify) ──

    private static byte[] KeyId(ValCert c, string oid)
    {
        if (c.Extension(oid) is not { } v) return Array.Empty<byte>();
        try
        {
            var n = Asn1.ParseOne(v);
            if (oid == "2.5.29.14") return n.Tag == Asn1.OctetString ? n.Value.ToArray() : Array.Empty<byte>();
            foreach (var x in Asn1.Children(n))
                if (x.Tag == 0x80) return x.Value.ToArray();
            return Array.Empty<byte>();
        }
        catch (Asn1Exception)
        {
            return Array.Empty<byte>();
        }
    }

    /// <summary>basicConstraints pathLenConstraint (-1 — байхгүй).</summary>
    private static long MaxPathLen(ValCert c)
    {
        if (c.Extension(ValCert.OidBasicConstraints) is not { } v) return -1;
        try
        {
            foreach (var x in Asn1.Children(Asn1.ParseOne(v)))
            {
                if (x.Tag != Asn1.Integer) continue;
                var i = Asn1.IntValue(x.Value.Span);
                return i > long.MaxValue ? long.MaxValue : i < long.MinValue ? long.MinValue : (long)i;
            }
            return -1;
        }
        catch (Asn1Exception)
        {
            return -1;
        }
    }

    private static bool ValidAt(ValCert c, GoTime at) => !GoTime.Before(at, c.NotBeforeGo) && !GoTime.After(at, c.NotAfterGo);

    private static bool UnhandledCritical(ValCert c)
    {
        foreach (var e in c.Extensions)
            if (e.Critical && !HandledCritical.Contains(e.Oid)) return true;
        return false;
    }

    private sealed class CertPool
    {
        private readonly List<ValCert> _list = new();

        public void Add(ValCert c)
        {
            if (!Contains(c)) _list.Add(c);
        }

        public bool Contains(ValCert c)
        {
            foreach (var x in _list)
                if (x.Raw.AsSpan().SequenceEqual(c.Raw)) return true;
            return false;
        }

        /// <summary>Go findPotentialParents: AKID=SKID → нэг нь алга → зөрсөн.</summary>
        public List<ValCert> Parents(ValCert c)
        {
            var akid = KeyId(c, "2.5.29.35");
            var m = new List<ValCert>();
            var one = new List<ValCert>();
            var mis = new List<ValCert>();
            foreach (var p in _list)
            {
                if (!p.RawSubject.AsSpan().SequenceEqual(c.RawIssuer)) continue;
                var skid = KeyId(p, "2.5.29.14");
                if (skid.AsSpan().SequenceEqual(akid)) m.Add(p);
                else if ((skid.Length == 0 && akid.Length > 0) || (skid.Length > 0 && akid.Length == 0)) one.Add(p);
                else mis.Add(p);
            }
            m.AddRange(one);
            m.AddRange(mis);
            return m;
        }
    }

    private sealed class Budget
    {
        public int N;
    }

    private static List<List<ValCert>> BuildChains(List<ValCert> chain, CertPool roots, CertPool inter, GoTime at, Budget budget)
    {
        var c = chain[chain.Count - 1];
        var o = new List<List<ValCert>>();
        void Consider(ValCert cand, bool root)
        {
            foreach (var x in chain)
                if (x.RawSubject.AsSpan().SequenceEqual(cand.RawSubject) && x.Spki.AsSpan().SequenceEqual(cand.Spki)) return;
            if (++budget.N > MaxChainAttempts) return;
            if (!c.CheckSignatureFrom(cand)) return;
            if (UnhandledCritical(cand) || !ValidAt(cand, at)) return;
            // core path builder-ийн fail-closed дүрэм: name constraints-ийг SDK үнэлдэггүй тул ийм CA-г хүлээн авахгүй.
            if (cand.Extension(ValCert.OidNameConstraints) is not null) return;
            if (!root && (!cand.BasicConstraintsValid || !cand.IsCa)) return;
            long mpl = MaxPathLen(cand);
            if (cand.BasicConstraintsValid && mpl >= 0 && chain.Count - 1 > mpl) return;
            if (root)
            {
                o.Add(new List<ValCert>(chain) { cand });
            }
            else if (chain.Count < MaxChainLength)
            {
                o.AddRange(BuildChains(new List<ValCert>(chain) { cand }, roots, inter, at, budget));
            }
        }
        foreach (var r in roots.Parents(c)) Consider(r, true);
        foreach (var p in inter.Parents(c)) Consider(p, false);
        return o;
    }

    /// <summary>Go checkChainForKeyUsage.</summary>
    private static bool ChainAllows(List<ValCert> chain, string eku)
    {
        for (int i = chain.Count - 1; i >= 0; i--)
        {
            var c = chain[i];
            if (c.ExtKeyUsage.Count == 0) continue;
            if (c.ExtKeyUsage.Contains(ValCert.OidKpAny)) continue;
            if (!c.ExtKeyUsage.Contains(eku)) return false;
        }
        return true;
    }

    private CertPool Pool(List<ValCert> extra)
    {
        var p = new CertPool();
        foreach (var c in extra) p.Add(c);
        foreach (var c in _intermediates) p.Add(c);
        return p;
    }

    /// <summary>verifyAt — leaf-ийг итгэлийн тулгуур хүртэл яг at цагт (eku "" — ExtKeyUsageAny).</summary>
    private List<ValCert>? VerifyAt(ValCert leaf, List<ValCert> extra, GoTime at, string eku)
    {
        if (_roots.Count == 0) return null;
        if (UnhandledCritical(leaf) || !ValidAt(leaf, at)) return null;
        var roots = new CertPool();
        foreach (var r in _roots) roots.Add(r);
        if (roots.Contains(leaf)) return new List<ValCert> { leaf };
        var chains = BuildChains(new List<ValCert> { leaf }, roots, Pool(extra), at, new Budget());
        if (eku == "") return chains.Count > 0 ? chains[0] : null;
        foreach (var ch in chains)
            if (ChainAllows(ch, eku)) return ch;
        return null;
    }

    private List<ValCert>? VerifyChain(ValCert leaf, List<ValCert> extra, GoTime at)
    {
        var ch = VerifyAt(leaf, extra, at, "");
        if (ch is not null) return ch;
        var nb = leaf.NotBeforeGo;
        var na = leaf.NotAfterGo;
        if (GoTime.After(at, na) || GoTime.Before(at, nb))
        {
            // Math.trunc((notAfter − notBefore) / 2) мс
            long half = (leaf.NotAfter.UnixMs - leaf.NotBefore.UnixMs) / 2;
            return VerifyAt(leaf, extra, nb.AddMs(half), "");
        }
        return null;
    }

    private bool IsIssuer(ValCert c)
    {
        foreach (var i in _issuers)
            if (c.RawSubject.AsSpan().SequenceEqual(i.RawSubject) && c.Spki.AsSpan().SequenceEqual(i.Spki)) return true;
        return false;
    }

    private async Task<(CertInfo Info, GoTime? RevokedAt)> CertInfoAsync(ValCert c, List<ValCert>? chain, GoTime at, CancellationToken ct)
    {
        var info = new CertInfo
        {
            CommonName = GoFmt.CommonName(c.RawSubject),
            Subject = GoFmt.NameString(c.RawSubject),
            Issuer = GoFmt.NameString(c.RawIssuer),
            Serial = GoFmt.HexSerial(c.Serial),
            NotBefore = c.NotBeforeGo.Format(),
            NotAfter = c.NotAfterGo.Format(),
            Usage = UsageOf(c),
            IssuedByEid = false,
            Revocation = new CertRevocation { Status = "unknown" },
        };
        if (chain is null || chain.Count < 2 || !IsIssuer(chain[1])) return (info, null);
        info.IssuedByEid = true;
        if (_status is null) return (info, null);
        CertStatusResult st;
        try
        {
            st = await _status.CertStatusAsync(c, chain[1], at, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return (info, null);
        }
        if (!st.Issued) return (info, null);
        if (st.Revoked)
        {
            info.Revocation = new CertRevocation { Status = "revoked", RevokedAt = st.RevokedAt!.Value.Format() };
            return (info, st.RevokedAt);
        }
        info.Revocation = new CertRevocation { Status = "good" };
        return (info, null);
    }

    private (TimestampInfo Info, List<ValCert>? Chain, bool Ok) EvaluateTimestamp(RawTimestamp r)
    {
        var info = new TimestampInfo { Time = r.Time.Format(), Serial = r.Serial, Tsa = "", Trusted = false };
        ValCert tsa;
        try
        {
            tsa = ValCert.Parse(r.TsaCert ?? Array.Empty<byte>());
        }
        catch (ValCertException)
        {
            return (info, null, false);
        }
        info.Tsa = GoFmt.CommonName(tsa.RawSubject);
        if (!r.Matches || r.WeakDigest || r.Time.IsZero || !tsa.IsTsaSigningCert()) return (info, null, false);
        var chain = VerifyAt(tsa, ParseCerts(r.Certs), r.Time, ValCert.OidKpTimeStamping);
        info.Trusted = chain is not null;
        return (info, chain, info.Trusted);
    }

    public async Task<SignatureReport> EvaluateSignatureAsync(RawSignature r, CancellationToken ct)
    {
        var s = new SignatureReport
        {
            Indication = "valid",
            SignerName = "",
            SignerNameSource = "unverified",
            CoversWholeDocument = r.CoversWhole,
            Visible = r.Visible,
            KeyMedium = "unknown",
        };
        if (r.SignerName != "") s.ClaimedName = r.SignerName;
        if (r.Reason != "") s.Reason = r.Reason;
        if (r.Location != "") s.Location = r.Location;
        if (r.ClaimedTime is { } ctm) s.ClaimedTime = ctm.Format();
        if (r.ClaimedRoles.Count > 0) s.ClaimedRoles = r.ClaimedRoles;
        if (!r.CoversWhole && r.LaterSignaturesOnly)
        {
            s.ExtendedBySignaturesOnly = true;
            s.LaterSignatures = r.LaterSignatures;
            s.VisibleLaterSignature = r.LaterVisible;
        }
        SignatureReport Fail(string p)
        {
            s.ProblemList.Add(p);
            s.Indication = "invalid";
            return s;
        }
        if (r.Malformed) return Fail(ProblemMalformed);
        ValCert leaf;
        try
        {
            leaf = ValCert.Parse(r.Leaf ?? Array.Empty<byte>());
        }
        catch (ValCertException)
        {
            return Fail(ProblemMalformed);
        }
        s.SignerName = DisplayName(leaf);
        s.SignerNameSource = "certificate";
        var civil = CivilId(leaf);
        if (civil != "") s.CivilId = civil;
        if (!r.Integrity) return Fail(ProblemIntegrity);
        if (r.WeakDigest) return Fail(ProblemWeakAlgorithm);
        bool cades = r.SubFilter == "ETSI.CAdES.detached";
        if (cades && r.SigningCertV2 != "match") return Fail(ProblemMalformed);

        var at = _now;
        GoTime? signingTime = null;
        List<ValCert>? tsChain = null;
        if (r.Timestamp is not null)
        {
            var ts = EvaluateTimestamp(r.Timestamp);
            tsChain = ts.Chain;
            s.Timestamp = ts.Info;
            if (ts.Ok)
            {
                signingTime = r.Timestamp.Time;
                s.SigningTime = r.Timestamp.Time.Format();
                at = r.Timestamp.Time;
            }
            else
            {
                s.ProblemList.Add(ProblemTimestampInvalid);
            }
        }

        var chain = VerifyChain(leaf, ParseCerts(r.Certs), at);
        bool trusted = chain is not null;
        s.ChainTrusted = trusted;
        if (chain is not null)
        {
            foreach (var c in chain) s.ChainList.Add(GoFmt.CommonName(c.RawSubject));
        }
        else
        {
            s.ChainList.Add(GoFmt.CommonName(leaf.RawSubject));
        }
        var (info, revokedAt) = await CertInfoAsync(leaf, chain, at, ct).ConfigureAwait(false);
        s.Certificate = info;
        if (!trusted) s.ProblemList.Add(ProblemUntrusted);
        if (info.Usage is not ("sign" or "seal" or "document_signer")) s.ProblemList.Add(ProblemKeyUsage);
        if (GoTime.After(at, leaf.NotAfterGo)) s.ProblemList.Add(ProblemExpired);
        else if (GoTime.Before(at, leaf.NotBeforeGo)) s.ProblemList.Add(ProblemNotYetValid);
        if (info.Revocation.Status == "revoked")
        {
            if (signingTime is { } st && revokedAt is { } ra && GoTime.After(ra, st)) s.ProblemList.Add(ProblemRevokedAfter);
            else s.ProblemList.Add(ProblemRevoked);
        }
        else if (info.Revocation.Status == "unknown" && trusted)
        {
            s.ProblemList.Add(ProblemRevocationUnknown);
        }
        if (trusted && info.IssuedByEid && info.Usage == "document_signer" && !s.ProblemList.Contains(ProblemRevoked))
        {
            s.SignerName = r.SignerName;
            s.SignerNameSource = "platform_attested";
        }
        if (cades && r.SigningTimeAttr && info.IssuedByEid) s.ProblemList.Add(ProblemMalformed);
        if (!r.CoversWhole && !r.LaterSignaturesOnly) s.ProblemList.Add(ProblemModifiedAfter);
        if (chain is not null) s.Ltv = LtvCoverage(r.Dss, at, _now, new[] { chain, tsChain ?? new List<ValCert>() });
        if (cades)
        {
            s.SignatureLevel = signingTime is not null && s.Ltv is { Complete: true } ? "PAdES-BASELINE-LT"
                : signingTime is not null ? "PAdES-BASELINE-T" : "PAdES-BASELINE-B";
        }
        s.Indication = Indication(s.ProblemList);
        return s;
    }

    public static string Indication(List<string> problems)
    {
        var o = "valid";
        foreach (var p in problems)
        {
            switch (p)
            {
                case ProblemIntegrity:
                case ProblemMalformed:
                case ProblemWeakAlgorithm:
                case ProblemUntrusted:
                case ProblemKeyUsage:
                case ProblemRevoked:
                case ProblemExpired:
                case ProblemNotYetValid:
                    return "invalid";
                case ProblemRevokedAfter:
                    break;
                default:
                    o = "indeterminate";
                    break;
            }
        }
        return o;
    }

    public static List<ValCert> ParseCerts(List<byte[]> ders)
    {
        var o = new List<ValCert>();
        foreach (var d in ders)
        {
            try
            {
                o.Add(ValCert.Parse(d));
            }
            catch (ValCertException)
            {
                // алгасна
            }
        }
        return o;
    }

    /// <summary>eidcrypto.SubjectDisplayName.</summary>
    private static string DisplayName(ValCert c)
    {
        var (given, surname) = GoFmt.SubjectNames(c.RawSubject);
        var n = GoTrim(given + " " + surname);
        return n != "" ? n : GoFmt.CommonName(c.RawSubject);
    }

    /// <summary>JS String.prototype.trim (Unicode WhiteSpace + LineTerminator).</summary>
    private static string GoTrim(string s)
    {
        static bool Ws(char c) => char.IsWhiteSpace(c) || c == '﻿';
        int a = 0, b = s.Length;
        while (a < b && Ws(s[a])) a++;
        while (b > a && Ws(s[b - 1])) b--;
        return s.Substring(a, b - a);
    }

    private static string CivilId(ValCert c)
    {
        var sn = GoFmt.SubjectSerialNumber(c.RawSubject);
        return sn.StartsWith("PNOMN-", StringComparison.Ordinal) ? sn.Substring(6) : "";
    }

    private const string EkuDocumentSigning = "1.3.6.1.5.5.7.3.36";

    private static readonly HashSet<string> GoKnownEku = new(StringComparer.Ordinal)
    {
        "2.5.29.37.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6",
        "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9", "1.3.6.1.4.1.311.10.3.3", "2.16.840.1.113730.4.1", "1.3.6.1.4.1.311.2.1.22",
        "1.3.6.1.4.1.311.61.1.1",
    };

    /// <summary>CA usageOf: KU/EKU-аар профайл.</summary>
    private static string UsageOf(ValCert c)
    {
        var known = new List<string>();
        foreach (var e in c.ExtKeyUsage)
            if (GoKnownEku.Contains(e)) known.Add(e);
        foreach (var e in known)
        {
            if (e == ValCert.OidKpTimeStamping) return "timestamp";
            if (e == ValCert.OidKpOcspSigning) return "other";
        }
        if (c.IsCa) return "other";
        if (c.ExtKeyUsage.Contains(EkuDocumentSigning)) return "document_signer";
        bool cc = (c.KeyUsage & (1 << 1)) != 0;
        bool ds = (c.KeyUsage & 1) != 0;
        if (cc && !ds && known.Count == 0) return "seal";
        if (cc) return "sign";
        if (ds && known.Contains("1.3.6.1.5.5.7.3.2")) return "auth";
        return "other";
    }

    // ── LTV (ltv.go) ──

    private const string OidOcspNoCheck = "1.3.6.1.5.5.7.48.1.5";

    /// <summary>
    /// Go ltvCoverage — гинжийн (leaf → root) ба TSA гинжийн root-оос бусад гэрчилгээ бүрд DSS-д олгогчийн (эсвэл delegated
    /// nocheck responder-ийн) зурсан, CertID таарсан, good, at-д шинэлэг OCSP эсвэл олгогчийн, шинэлэг, тэр гэрчилгээг агуулаагүй
    /// CRL. now — шалгагчийн одоо (ирээдүйн thisUpdate-ийг татгалзана).
    /// </summary>
    private static LtvInfo LtvCoverage(RawDss? dss, GoTime at, GoTime now, List<ValCert>[] chains)
    {
        var o = new LtvInfo();
        var crls = new List<ValCrl>();
        foreach (var der in dss?.Crls ?? new List<byte[]>())
            if (ValRevocation.ParseCrl(der) is { } c) crls.Add(c);
        var seen = new List<byte[]>();
        foreach (var chain in chains)
        {
            for (int i = 0; i + 1 < chain.Count; i++)
            {
                var cert = chain[i];
                var issuer = chain[i + 1];
                bool dup = false;
                foreach (var x in seen)
                {
                    if (x.AsSpan().SequenceEqual(cert.Raw))
                    {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;
                seen.Add(cert.Raw);
                if (!Covered(cert, issuer, at, now, dss?.Ocsps ?? new List<byte[]>(), crls)) o.MissingList.Add(GoFmt.CommonName(cert.RawSubject));
            }
        }
        o.Complete = o.MissingList.Count == 0 && seen.Count > 0;
        return o;
    }

    private static bool Covered(ValCert cert, ValCert issuer, GoTime at, GoTime now, List<byte[]> ocsps, List<ValCrl> crls)
    {
        foreach (var der in ocsps)
        {
            ValOcspResp resp;
            try
            {
                resp = ValRevocation.ParseOcsp(der, cert.SerialValue, issuer);
            }
            catch (Exception e) when (ValRevocation.IsParse(e))
            {
                continue;
            }
            if (resp.Status != "good" || !ValRevocation.OcspCertIdMatches(der, cert, issuer)) continue;
            if (resp.Certificate is { } rc && !rc.Raw.AsSpan().SequenceEqual(issuer.Raw) && rc.Extension(OidOcspNoCheck) is null) continue;
            if (ValRevocation.OcspFreshAt(resp, at, now)) return true;
        }
        foreach (var crl in crls)
        {
            if (!ValRevocation.CrlFor(crl, cert, issuer) || !ValRevocation.FreshAt(crl.ThisUpdate, crl.NextUpdate, at, now)) continue;
            if (ValRevocation.CrlListed(crl, cert) is not null) continue;
            return true;
        }
        return false;
    }

    // ── түвшин (eid.CertificateLevelOf, RAW_DIGEST_SIGNATURE) ──

    private const string OidQcStatements = "1.3.6.1.5.5.7.1.3";
    private const string OidQcCompliance = "0.4.0.1862.1.1";
    private const string OidQcSscd = "0.4.0.1862.1.4";

    /// <summary>qcStatements-д QcCompliance → QUALIFIED (+ QcSSCD → QSCD), бусад → ADVANCED; гэмтсэн бол null.</summary>
    public static string? SignLevelOf(ValCert c)
    {
        if (c.Extension(OidQcStatements) is not { } v) return "ADVANCED";
        try
        {
            var seq = Asn1.ParseOne(v);
            if (seq.Tag != Asn1.Sequence) return null;
            bool compliance = false, sscd = false;
            foreach (var st in Asn1.Children(seq))
            {
                if (st.Tag != Asn1.Sequence) return null;
                var id = Asn1.ReadNode(st.Value, 0);
                if (id.Tag != Asn1.Oid) return null;
                var o = Asn1.OidString(id);
                compliance |= o == OidQcCompliance;
                sscd |= o == OidQcSscd;
            }
            return !compliance ? "ADVANCED" : sscd ? "QSCD" : "QUALIFIED";
        }
        catch (Asn1Exception)
        {
            return null;
        }
    }
}

/// <summary>
/// Go dssStatus: баримтын DSS-ийн OCSP/CRL-ээс. Нотолгоо нь ЭНЭ гэрчилгээ + түүний гинжийн олгогчийнх байх ёстой. Цуцалсан
/// нотолгоо аль нэг нь байвал revoked (хамгийн эрт цаг — «good»-ийг давна); үгүй бол at-д шинэлэг good нотолгоо байвал good;
/// эс бөгөөс issued=false (unknown).
/// </summary>
internal sealed class DssStatus : IStatusSource
{
    private readonly RawDss? _dss;
    private readonly GoTime _now;

    public DssStatus(RawDss? dss, GoTime now)
    {
        _dss = dss;
        _now = now;
    }

    /// <summary>Go ocspFor — der нь cert-ийн хариу, олгогч эсвэл түүний OCSPSigning responder зурсан.</summary>
    internal static ValOcspResp? OcspFor(byte[] der, ValCert cert, ValCert issuer)
    {
        ValOcspResp resp;
        try
        {
            resp = ValRevocation.ParseOcspFrom(der, cert.SerialValue, issuer);
        }
        catch (Exception e) when (ValRevocation.IsParse(e))
        {
            return null;
        }
        if (resp.Serial != cert.SerialValue || !ValRevocation.OcspCertIdMatches(der, cert, issuer) || !ValRevocation.ResponderOk(resp, issuer)) return null;
        return resp;
    }

    public Task<CertStatusResult> CertStatusAsync(ValCert cert, ValCert issuer, GoTime at, CancellationToken ct)
    {
        GoTime? revoked = null;
        void MarkRevoked(GoTime t)
        {
            if (revoked is not { } r || GoTime.Before(t, r)) revoked = t;
        }
        bool good = false;
        foreach (var der in _dss?.Ocsps ?? new List<byte[]>())
        {
            ct.ThrowIfCancellationRequested();
            var resp = OcspFor(der, cert, issuer);
            if (resp is null) continue;
            if (resp.Status == "revoked") MarkRevoked(GoTime.FromPrecise(resp.RevokedAt!.Value));
            else if (resp.Status == "good") good = good || ValRevocation.OcspFreshAt(resp, at, _now);
        }
        foreach (var der in _dss?.Crls ?? new List<byte[]>())
        {
            ct.ThrowIfCancellationRequested();
            var crl = ValRevocation.ParseCrl(der);
            if (crl is null || !ValRevocation.CrlFor(crl, cert, issuer)) continue;
            if (ValRevocation.CrlListed(crl, cert) is { } t) MarkRevoked(t);
            else good = good || ValRevocation.FreshAt(crl.ThisUpdate, crl.NextUpdate, at, _now);
        }
        if (revoked is not null) return Task.FromResult(new CertStatusResult(true, true, revoked));
        if (good) return Task.FromResult(new CertStatusResult(true, false, null));
        return Task.FromResult(new CertStatusResult(false, false, null));
    }
}

/// <summary>
/// Go onlineStatus: AIA OCSP, эс бөгөөс CDP CRL (одоогийн төлөв, now-д шинэлэг); хариугүй бол fallback (DSS). Онлайн «good»
/// байсан ч fallback-д олгогчийн гарын үсэгтэй цуцалсан нотолгоо байвал revoked (цуцлалт буцахгүй).
/// </summary>
internal sealed class OnlineStatus : IStatusSource
{
    private const int OnlineOcspMax = 16 << 10;

    private readonly Fetcher _f;
    private readonly IStatusSource? _fallback;
    private readonly GoTime _now;
    private readonly Dictionary<string, CertStatusResult> _cache = new(StringComparer.Ordinal);

    public OnlineStatus(Fetcher f, IStatusSource? fallback, GoTime now)
    {
        _f = f;
        _fallback = fallback;
        _now = now;
    }

    public async Task<CertStatusResult> CertStatusAsync(ValCert cert, ValCert issuer, GoTime at, CancellationToken ct)
    {
        var key = Asn1.Hex(cert.Raw) + ":" + Asn1.Hex(issuer.Raw);
        if (_cache.TryGetValue(key, out var hit)) return hit;
        var st = await OcspAsync(cert, issuer, ct).ConfigureAwait(false) ?? await CrlAsync(cert, issuer, ct).ConfigureAwait(false);
        if (_fallback is not null && (st is null || !st.Value.Revoked))
        {
            var fst = await _fallback.CertStatusAsync(cert, issuer, at, ct).ConfigureAwait(false);
            if (st is null || fst.Revoked) st = fst;
        }
        var res = st ?? new CertStatusResult(false, false, null);
        _cache[key] = res;
        return res;
    }

    /// <summary>Нэг URL-ийн алдаа (сүлжээ, timeout, HTTP) — дараагийн URL руу; дуудагчийн цуцлалт биш.</summary>
    private static bool Soft(Exception e, CancellationToken ct) => !(e is OperationCanceledException && ct.IsCancellationRequested);

    private async Task<CertStatusResult?> OcspAsync(ValCert cert, ValCert issuer, CancellationToken ct)
    {
        byte[] req;
        try
        {
            req = ValRevocation.OcspRequest(cert, issuer);
        }
        catch (Exception e) when (ValRevocation.IsParse(e))
        {
            return null;
        }
        foreach (var u in cert.OcspServers)
        {
            byte[] der;
            try
            {
                der = await _f.DoAsync(HttpMethod.Post, u, "application/ocsp-request", req, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (Soft(e, ct))
            {
                continue;
            }
            if (der.Length > OnlineOcspMax) continue;
            var resp = DssStatus.OcspFor(der, cert, issuer);
            if (resp is null) continue;
            var rc = resp.Certificate;
            if (rc is not null && !ValCert.SameCertKey(rc, issuer) && !(!GoTime.Before(_now, rc.NotBeforeGo) && !GoTime.After(_now, rc.NotAfterGo))) continue;
            if (resp.Status == "revoked") return new CertStatusResult(true, true, GoTime.FromPrecise(resp.RevokedAt!.Value));
            if (!ValRevocation.OcspFreshAt(resp, _now, _now)) continue;
            if (resp.Status == "good") return new CertStatusResult(true, false, null);
            return new CertStatusResult(false, false, null);
        }
        return null;
    }

    private async Task<CertStatusResult?> CrlAsync(ValCert cert, ValCert issuer, CancellationToken ct)
    {
        foreach (var u in cert.CrlDps)
        {
            ValCrl? crl;
            try
            {
                crl = ValRevocation.ParseCrl(await _f.DoAsync(HttpMethod.Get, u, "", null, ct).ConfigureAwait(false));
            }
            catch (Exception e) when (Soft(e, ct))
            {
                continue;
            }
            if (crl is null || !ValRevocation.CrlFor(crl, cert, issuer)) continue;
            if (ValRevocation.CrlListed(crl, cert) is { } t) return new CertStatusResult(true, true, t);
            if (ValRevocation.FreshAt(crl.ThisUpdate, crl.NextUpdate, _now, _now)) return new CertStatusResult(true, false, null);
        }
        return null;
    }
}
