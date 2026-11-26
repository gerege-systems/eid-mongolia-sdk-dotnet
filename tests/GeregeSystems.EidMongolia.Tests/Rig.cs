using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Нэг бичигдсэн хүсэлт.</summary>
internal sealed record Recorded(string Method, string PathAndQuery, string? Body, HttpRequestMessage Request)
{
    /// <summary>URL-ийн escaped зам (query-гүй).</summary>
    public string Path => PathAndQuery.Split('?')[0];

    public JsonElement Json()
    {
        using var d = JsonDocument.Parse(Body ?? "null");
        return d.RootElement.Clone();
    }

    /// <summary>Биеийн дээд түвшний түлхүүрүүд (эрэмбэлсэн, ","-ээр).</summary>
    public string Keys() => string.Join(",", Json().EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal));
}

/// <summary>Сүлжээгүй fake handler: хүсэлт бүрийг бичиж, <c>respond</c>-оор хариулна.</summary>
internal sealed class Recorder : HttpMessageHandler
{
    private readonly Func<Recorded, HttpResponseMessage> _respond;

    public Recorder(Func<Recorded, HttpResponseMessage> respond) => _respond = respond;

    public List<Recorded> Requests { get; } = new();

    public Recorded Last => Requests[^1];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        var rec = new Recorded(request.Method.Method, request.RequestUri!.PathAndQuery, body, request);
        lock (Requests)
        {
            Requests.Add(rec);
        }
        return _respond(rec);
    }
}

/// <summary>Гараар удирддаг цаг (зөвхөн GetUtcNow; таймер нь системийнх).</summary>
internal sealed class ManualClock : TimeProvider
{
    public ManualClock(DateTimeOffset now) => Now = now;

    public DateTimeOffset Now { get; set; }

    public override DateTimeOffset GetUtcNow() => Now;
}

internal static class Rig
{
    /// <summary>Go client_test.go-ийн <c>creds</c>.</summary>
    public static readonly EidCredentials Creds = new("rp-uuid", "Гэрээний систем", "rp_sk_secret123");

    /// <summary>Тогтмол rpChallenge (auth хүсэлтийн биеийг яг тулгахад).</summary>
    public const string Challenge = "Zml4ZWQtcnAtY2hhbGxlbmdlLWZvci13aXJlLXRlc3Rz";

    public static readonly DateTimeOffset T0 = new(2026, 11, 26, 4, 0, 0, TimeSpan.Zero);

    public static HttpResponseMessage Json(int status, string body, string? retryAfter = null)
    {
        var r = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (retryAfter is not null)
        {
            r.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }
        return r;
    }

    public static (EidClient Client, Recorder Http, ManualClock Clock) Create(Func<Recorded, HttpResponseMessage> respond,
        EidCredentials? creds = null, string? challenge = Challenge, TimeSpan? signTtl = null)
    {
        var rec = new Recorder(respond);
        var clock = new ManualClock(T0);
        var c = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp.example.mn",
            Credentials = creds ?? Creds,
            TimeProvider = clock,
            SignSessionTtl = signTtl,
        }, new HttpClient(rec));
        if (challenge is not null)
        {
            c.NewChallenge = () => challenge;
        }
        return (c, rec, clock);
    }

    public static (EidClient Client, Recorder Http, ManualClock Clock) Create(int status, string body) =>
        Create(_ => Json(status, body));
}

/// <summary>JSON-ийг утгаар нь (түлхүүрийн дараалал үл хамааран) тулгана.</summary>
internal static class JsonAssert
{
    public static void Equivalent(string expected, JsonElement actual, string because = "")
    {
        using var d = JsonDocument.Parse(expected);
        var diff = Diff(d.RootElement, actual, "$");
        Assert.True(diff is null, because + " " + diff + "\nwant " + expected + "\n got " + actual.GetRawText());
    }

    public static string? Diff(JsonElement want, JsonElement got, string path)
    {
        if (want.ValueKind != got.ValueKind)
        {
            return path + ": төрөл " + want.ValueKind + " ≠ " + got.ValueKind;
        }
        switch (want.ValueKind)
        {
            case JsonValueKind.Object:
                var wk = want.EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).ToList();
                var gk = got.EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).ToList();
                if (!wk.SequenceEqual(gk))
                {
                    return path + ": түлхүүр [" + string.Join(",", wk) + "] ≠ [" + string.Join(",", gk) + "]";
                }
                foreach (var p in want.EnumerateObject())
                {
                    if (Diff(p.Value, got.GetProperty(p.Name), path + "." + p.Name) is { } e)
                    {
                        return e;
                    }
                }
                return null;
            case JsonValueKind.Array:
                if (want.GetArrayLength() != got.GetArrayLength())
                {
                    return path + ": урт " + want.GetArrayLength() + " ≠ " + got.GetArrayLength();
                }
                for (var i = 0; i < want.GetArrayLength(); i++)
                {
                    if (Diff(want[i], got[i], path + "[" + i + "]") is { } e)
                    {
                        return e;
                    }
                }
                return null;
            case JsonValueKind.String:
                return want.GetString() == got.GetString() ? null : path + ": \"" + want.GetString() + "\" ≠ \"" + got.GetString() + "\"";
            case JsonValueKind.Number:
                return want.GetDecimal() == got.GetDecimal() ? null : path + ": " + want.GetRawText() + " ≠ " + got.GetRawText();
            default:
                return null;
        }
    }
}
