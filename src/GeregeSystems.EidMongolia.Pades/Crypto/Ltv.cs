using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

internal class LtvException : Exception
{
    public LtvException(string message) : base(message) { }
}

/// <summary>OCSP thisUpdate нь timestamp-аас хожуу биш (дахин оролдоно).</summary>
internal sealed class NotFreshException : LtvException
{
    public NotFreshException(string message) : base(message) { }
}

/// <summary>DSS (B-LT) цуглуулалт — Go reference ltv.go: гэрчилгээ бүрийн AIA OCSP (SHA-1 CertID) ба CDP CRL, fail-closed.</summary>
internal static class Ltv
{
    private static readonly TimeSpan OcspAfterTs = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan OcspWaitMax = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan OcspRetry = TimeSpan.FromSeconds(1);

    public static async Task<DssData> CollectWithWaitAsync(Fetcher f, Func<DateTimeOffset> now, Func<TimeSpan, CancellationToken, Task> sleep,
        DateTimeOffset genTime, IReadOnlyList<X509Certificate2> roots, CancellationToken ct, params IReadOnlyList<X509Certificate2>[] chains)
    {
        var waited = TimeSpan.Zero;
        var truncated = new DateTimeOffset(genTime.Ticks - genTime.Ticks % TimeSpan.TicksPerSecond, genTime.Offset);
        var d = truncated + OcspAfterTs - now();
        if (d > OcspWaitMax) d = OcspWaitMax;
        while (true)
        {
            if (d > TimeSpan.Zero)
            {
                await sleep(d, ct).ConfigureAwait(false);
                waited += d;
            }
            try
            {
                return await CollectAsync(f, now(), genTime, roots, ct, chains).ConfigureAwait(false);
            }
            catch (NotFreshException) when (waited + OcspRetry <= OcspWaitMax)
            {
                d = OcspRetry;
            }
        }
    }

    public static async Task<DssData> CollectAsync(Fetcher f, DateTimeOffset now, DateTimeOffset after, IReadOnlyList<X509Certificate2> roots,
        CancellationToken ct, params IReadOnlyList<X509Certificate2>[] chains)
    {
        var d = new DssData();
        void AddCert(X509Certificate2 c)
        {
            foreach (var b in d.Certs)
                if (b.AsSpan().SequenceEqual(c.RawData)) return;
            d.Certs.Add(c.RawData);
        }
        static void Add(List<byte[]> list, byte[] der)
        {
            foreach (var b in list)
                if (b.AsSpan().SequenceEqual(der)) return;
            list.Add(der);
        }
        var pool = new List<X509Certificate2>();
        foreach (var ch in chains) pool.AddRange(ch);
        X509Certificate2? IssuerOf(X509Certificate2 c)
        {
            var cands = new List<X509Certificate2>(pool);
            cands.AddRange(roots);
            foreach (var cand in cands)
                if (cand.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData) && X509Util.CheckSignatureFrom(c, cand)) return cand;
            return null;
        }
        bool IsRoot(X509Certificate2 c)
        {
            foreach (var r in roots)
                if (X509Util.Equal(r, c)) return true;
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ch in chains)
        {
            for (int i = 0; i < ch.Count; i++)
            {
                var c = ch[i];
                var key = Convert.ToBase64String(c.RawData);
                if (seen.Contains(key) || IsRoot(c)) continue;
                seen.Add(key);
                AddCert(c);
                var issuer = IssuerOf(c) ?? throw new LtvException("LTV incomplete: issuer of " + c.Subject + " not found");
                bool ok = false;
                NotFreshException? freshErr = null;
                DateTimeOffset? fresh = i == 0 ? after : null;
                var ocspUrls = X509Util.OcspServers(c);
                foreach (var u in ocspUrls)
                {
                    try
                    {
                        var (der, resp) = await FetchOcspAsync(f, u, c, issuer, now, fresh, ct).ConfigureAwait(false);
                        Add(d.Ocsps, der);
                        if (resp.Certificate is not null && !X509Util.Equal(resp.Certificate, issuer)) AddCert(resp.Certificate);
                        ok = true;
                        break;
                    }
                    catch (NotFreshException e)
                    {
                        freshErr = e;
                    }
                    catch (Exception e) when (Soft(e, ct))
                    {
                    }
                }
                foreach (var u in X509Util.CrlDistributionPoints(c))
                {
                    byte[] der;
                    try
                    {
                        der = await f.DoAsync(HttpMethod.Get, u, null, null, ct).ConfigureAwait(false);
                    }
                    catch (Exception e) when (Soft(e, ct))
                    {
                        continue;
                    }
                    if (CrlCovers(der, c, issuer, now))
                    {
                        Add(d.Crls, der);
                        ok = true;
                    }
                }
                if (!ok)
                {
                    if (freshErr is not null) throw new NotFreshException(freshErr.Message + ": " + c.Subject);
                    throw new LtvException("LTV incomplete: no valid OCSP/CRL for " + c.Subject);
                }
                if (i == 0 && freshErr is not null && ocspUrls.Count > 0 && !HasFreshOcsp(d.Ocsps, c, issuer, after))
                    throw new NotFreshException(freshErr.Message + ": " + c.Subject);
            }
        }
        return d;
    }

    /// <summary>Нэг URL-ийн алдаа (сүлжээ, задлалт, timeout) — дараагийн URL руу; дуудагчийн цуцлалт биш.</summary>
    private static bool Soft(Exception e, CancellationToken ct) =>
        e is HttpRequestException or FormatException or System.Formats.Asn1.AsnContentException
            or System.Security.Cryptography.CryptographicException or LtvException ||
        e is OperationCanceledException && !ct.IsCancellationRequested;

    private static bool HasFreshOcsp(List<byte[]> list, X509Certificate2 c, X509Certificate2 issuer, DateTimeOffset after)
    {
        foreach (var der in list)
        {
            try
            {
                if (Ocsp.ParseForCert(der, c, issuer).ThisUpdate > after) return true;
            }
            catch (Exception e) when (e is FormatException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
            {
            }
        }
        return false;
    }

    private static async Task<(byte[] Der, OcspResponse Resp)> FetchOcspAsync(Fetcher f, string url, X509Certificate2 c, X509Certificate2 issuer,
        DateTimeOffset now, DateTimeOffset? after, CancellationToken ct)
    {
        var req = Ocsp.CreateRequest(c, issuer);
        var der = await f.DoAsync(HttpMethod.Post, url, "application/ocsp-request", req, ct).ConfigureAwait(false);
        var resp = Ocsp.ParseForCert(der, c, issuer);
        if (!Ocsp.ResponderOk(resp, issuer)) throw new LtvException("OCSP responder EKU is not OCSPSigning");
        if (resp.Status != OcspStatus.Good || resp.NextUpdate is { } nu && nu < now)
            throw new LtvException("OCSP " + c.Subject + ": status " + resp.Status);
        if (after is { } a && !(resp.ThisUpdate > a)) throw new NotFreshException("OCSP thisUpdate is not after the timestamp");
        return (der, resp);
    }

    private static bool CrlCovers(byte[] der, X509Certificate2 c, X509Certificate2 issuer, DateTimeOffset now)
    {
        Crl crl;
        try
        {
            crl = Crl.Parse(der);
        }
        catch (Exception e) when (e is FormatException or System.Formats.Asn1.AsnContentException)
        {
            return false;
        }
        if (!crl.RawIssuer.AsSpan().SequenceEqual(c.IssuerName.RawData) || !X509Util.CheckCrlSignatureFrom(der, issuer)) return false;
        if (crl.NextUpdate is not { } nu || nu < now) return false;
        var serial = Cms.Serial(c);
        foreach (var s in crl.Revoked)
            if (s == serial) return false;
        return true;
    }
}
