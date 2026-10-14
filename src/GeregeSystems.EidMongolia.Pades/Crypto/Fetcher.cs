using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Pades.Crypto;

/// <summary>TSA/OCSP/CRL HTTP — зөвхөн http/https, 10 с timeout, redirect дагахгүй, 200 биш эсвэл 4 MiB-аас их бол алдаа; GET кэштэй.</summary>
internal sealed class Fetcher : IDisposable
{
    private const int MaxResponse = 4 << 20;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly HttpClient _client;
    private readonly bool _owns;
    private readonly Dictionary<string, byte[]> _cache = new(StringComparer.Ordinal);

    public Fetcher(HttpClient? client)
    {
        if (client is not null)
        {
            _client = client;
            return;
        }
        _client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = Timeout };
        _owns = true;
    }

    /// <summary>Үндэсний CRL-ийн eID https толин хуулбар (WIRE.md §3) — тогтмол, өөр URL буулгахгүй.</summary>
    private static readonly Dictionary<string, string> CrlMirror = new(StringComparer.Ordinal)
    {
        ["http://esign.gov.mn/MNICA-2022.crl"] = "https://crl.eidmongolia.mn/MNICA-2022.crl",
        ["http://esign.gov.mn/MNRCA-2021.crl"] = "https://crl.eidmongolia.mn/MNRCA-2021.crl",
    };

    public async Task<byte[]> DoAsync(HttpMethod method, string raw, string? contentType, byte[]? body, CancellationToken ct)
    {
        if (CrlMirror.TryGetValue(raw, out var mirrored)) raw = mirrored;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new HttpRequestException("unsupported URL: " + raw);
        var key = uri.ToString();
        if (method == HttpMethod.Get && _cache.TryGetValue(key, out var hit)) return hit;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        using var req = new HttpRequestMessage(method, uri);
        if (body is not null)
        {
            req.Content = new ByteArrayContent(body);
            if (contentType is not null) req.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        }
        using var resp = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        await using var s = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
        var buf = new byte[81920];
        using var ms = new System.IO.MemoryStream();
        int n;
        while ((n = await s.ReadAsync(buf, cts.Token).ConfigureAwait(false)) > 0)
        {
            ms.Write(buf, 0, n);
            if (ms.Length > MaxResponse) break;
        }
        if (resp.StatusCode != HttpStatusCode.OK || ms.Length > MaxResponse)
            throw new HttpRequestException($"{key}: HTTP {(int)resp.StatusCode}");
        var outBytes = ms.ToArray();
        if (method == HttpMethod.Get) _cache[key] = outBytes;
        return outBytes;
    }

    public void Dispose()
    {
        if (_owns) _client.Dispose();
    }
}
