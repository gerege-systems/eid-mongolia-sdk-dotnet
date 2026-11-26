using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>
/// <c>testdata/conformance/eidlogin/scenarios.json</c> (eidlogin/1) — <see cref="EidLoginHandler"/>-ийг Go
/// <c>eidlogin/conformance_test.go</c>-ийн harness-аар ажиллуулна. Формат ба matcher: corpus README §eidlogin.
/// </summary>
public class LoginConformanceTests
{
    private const string File = "eidlogin/scenarios.json";
    private const int ScenarioCount = 24;

    public static IEnumerable<object[]> ScenarioNames() =>
        Corpus.Json(File).GetProperty("scenarios").EnumerateArray().Select(s => new object[] { s.GetProperty("name").GetString()! });

    [Fact]
    public void CorpusPresentAndComplete()
    {
        Assert.True(System.IO.File.Exists(Path.Combine(Corpus.Dir, File)), File + " алга");
        var f = Corpus.Json(File);
        Assert.Equal("eidlogin/1", f.GetProperty("version").GetString());
        var names = f.GetProperty("scenarios").EnumerateArray().Select(s => s.GetProperty("name").GetString()!).ToList();
        Assert.Equal(ScenarioCount, names.Count);
        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task Scenario(string name)
    {
        var f = Corpus.Json(File);
        var sc = f.GetProperty("scenarios").EnumerateArray().Single(s => s.GetProperty("name").GetString() == name);
        var cfg = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var p in f.GetProperty("config").EnumerateObject())
        {
            cfg[p.Name] = p.Value.Clone();
        }
        if (sc.TryGetProperty("config", out var over))
        {
            foreach (var p in over.EnumerateObject())
            {
                cfg[p.Name] = p.Value.Clone();
            }
        }
        string Cs(string k) => cfg.TryGetValue(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
        double Cn(string k) => cfg.TryGetValue(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;
        bool Cb(string k, bool want) => cfg.TryGetValue(k, out var v) && v.ValueKind == (want ? JsonValueKind.True : JsonValueKind.False);

        var upstream = new RuleUpstream();
        if (sc.TryGetProperty("upstream", out var su))
        {
            upstream.Prepend(su);
        }
        upstream.Append(f.GetProperty("upstream"));
        using var client = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp-api.conformance.test",
            Credentials = new EidCredentials(Cs("rpUUID"), Cs("rpName"), Cs("apiSecret")),
        }, new HttpClient(upstream));

        var events = new List<EidLoginEvent>();
        var keys = new List<string>();
        var o = new EidLoginOptions
        {
            Client = client,
            OnSuccess = (_, _, _) => Task.FromResult<EidLoginSuccess?>(new EidLoginSuccess { Redirect = "/dashboard" }),
            CallbackUrl = Cs("callbackUrl"),
            SuccessRedirect = Cs("successRedirect"),
            FailureRedirect = Cs("failureRedirect"),
            Ttl = TimeSpan.FromSeconds(Cn("ttlSeconds")),
            Poll = TimeSpan.FromMilliseconds(Cn("pollMs")),
            PushFloor = TimeSpan.FromMilliseconds(Cn("pushFloorMs")),
            DisablePushFloor = Cn("pushFloorMs") == 0,
            CookieName = Cs("cookieName"),
            DisableRevocation = Cs("revocation") == "disabled",
            DisableDecoy = Cb("decoy", false),
            ClientIp = EidLoginClientIp.RemoteAddress,
            // Бодит цаг, гэхдээ хүлээлт (decoy poll) шууд дуусна (Go: h.sleep = no-op).
            TimeProvider = new SystemNowInstantTimers(),
            OnEvent = (ev, _) =>
            {
                events.Add(ev);
                return Task.CompletedTask;
            },
        };
        if (Cb("recordRateLimitKeys", true))
        {
            o.RateLimit = (k, _) =>
            {
                keys.Add(k);
                return new ValueTask<bool>(true);
            };
        }
        var h = new EidLoginHandler(o);
        var cookieName = Cs("cookieName");

        // Танихгүй түлхүүр = harness-ийн хоцрогдол: шинэ corpus түлхүүр хоосон (vacuous) PASS болохоос сэргийлж FAIL.
        AssertKnownKeys(name, "scenario", sc, "name", "comment", "config", "upstream", "steps", "events", "rateLimitKeys");
        var steps = sc.GetProperty("steps").EnumerateArray().ToList();
        var results = new StepResult[steps.Count];
        for (var i = 0; i < steps.Count; i++)
        {
            var st = steps[i];
            AssertKnownKeys(name, "алхам " + i, st, "comment", "request", "expect", "upstream", "repeat");
            AssertKnownKeys(name, "алхам " + i + " request", st.GetProperty("request"), "method", "path", "headers", "json", "text", "cookieFrom", "ip");
            var ex = st.GetProperty("expect");
            AssertKnownKeys(name, "алхам " + i + " expect", ex, "status", "json", "jsonKeys", "sameKeysAs", "location", "headers", "setCookie", "noSetCookie");
            if (ex.TryGetProperty("setCookie", out var exc))
            {
                AssertKnownKeys(name, "алхам " + i + " expect.setCookie", exc, "value", "attributes", "cleared");
            }
            if (st.TryGetProperty("upstream", out var stu))
            {
                upstream.Prepend(stu);
            }
            var n = st.TryGetProperty("repeat", out var rep) ? Math.Max(rep.GetInt32(), 1) : 1;
            for (var r = 0; r < n; r++)
            {
                var rq = st.GetProperty("request");
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? body = null;
                if (rq.TryGetProperty("json", out var j))
                {
                    body = j.GetRawText();
                    headers["Content-Type"] = "application/json";
                }
                else if (rq.TryGetProperty("text", out var t))
                {
                    body = t.GetString();
                }
                if (rq.TryGetProperty("headers", out var hs))
                {
                    foreach (var p in hs.EnumerateObject())
                    {
                        headers[p.Name] = p.Value.GetString()!;
                    }
                }
                if (rq.TryGetProperty("cookieFrom", out var cf))
                {
                    // Эх алхам cookie тавиагүй бол cookie-гүй хүсэлт илгээж хоосон PASS хийхгүй — FAIL.
                    var from = cf.GetInt32();
                    Assert.True(from >= 0 && from < i && results[from]?.Cookie is { } ck && ck.TryGetValue("", out _),
                        name + ": алхам " + i + ": cookieFrom " + from + " — тэр алхам " + cookieName + " cookie тавиагүй");
                    headers["Cookie"] = cookieName + "=" + results[from].Cookie![""];
                }
                var res = await h.HandleAsync(new EidLoginRequest
                {
                    Method = rq.GetProperty("method").GetString()!,
                    Url = "https://rp.conformance.test" + rq.GetProperty("path").GetString(),
                    Headers = headers,
                    Body = body,
                    RemoteIp = Corpus.Opt(rq, "ip"),
                });
                var sr = new StepResult(res);
                if ((res.Header("Content-Type") ?? "").StartsWith("application/json", StringComparison.Ordinal))
                {
                    sr.Json = JsonNode.Parse(res.Body) as JsonObject;
                }
                foreach (var c in res.HeaderValues("Set-Cookie"))
                {
                    if (c.StartsWith(cookieName + "=", StringComparison.Ordinal))
                    {
                        sr.Cookie = ParseCookie(c);
                    }
                }
                results[i] = sr;
                var err = CheckStep(st.GetProperty("expect"), sr, results);
                Assert.True(err is null, name + ": алхам " + i + ": " + err + " (status " + res.Status + ", body " + res.Body + ", Set-Cookie " +
                    string.Join(" | ", res.HeaderValues("Set-Cookie")) + ")");
            }
        }
        if (sc.TryGetProperty("events", out var wantEvents))
        {
            var we = wantEvents.EnumerateArray().ToList();
            Assert.True(we.Count == events.Count, name + ": events " + events.Count + " ≠ " + we.Count + ": " +
                string.Join(", ", events.Select(e => e.Kind)));
            for (var i = 0; i < we.Count; i++)
            {
                var want = we[i];
                var got = events[i];
                Assert.True(want.GetProperty("kind").GetString() == got.Kind, name + ": event " + i + ": " + got.Kind);
                if (want.TryGetProperty("sessionId", out var ws))
                {
                    var gs = string.IsNullOrEmpty(got.SessionId) ? null : JsonValue.Create(got.SessionId);
                    var e = Match(ws, gs, results);
                    Assert.True(e is null, name + ": event " + i + " sessionId: " + e);
                }
                if (want.TryGetProperty("meta", out var wm))
                {
                    var e = Match(wm, JsonSerializer.SerializeToNode(got.Meta), results);
                    Assert.True(e is null, name + ": event " + i + " meta: " + e + " (" + JsonSerializer.Serialize(got.Meta) + ")");
                }
            }
        }
        if (sc.TryGetProperty("rateLimitKeys", out var wantKeys))
        {
            Assert.Equal(wantKeys.EnumerateArray().Select(k => k.GetString()!).ToList(), keys);
        }
    }

    // ---- harness ----

    private static void AssertKnownKeys(string scenario, string where, JsonElement o, params string[] known)
    {
        Assert.True(o.ValueKind == JsonValueKind.Object, scenario + ": " + where + " объект биш");
        var unknown = o.EnumerateObject().Select(p => p.Name).Where(k => Array.IndexOf(known, k) < 0).ToList();
        Assert.True(unknown.Count == 0, scenario + ": " + where + ": harness танихгүй түлхүүр [" + string.Join(",", unknown) +
            "] — harness-ийг corpus README-тэй тааруул");
    }

    private sealed class StepResult
    {
        public StepResult(EidLoginResponse raw) => Raw = raw;

        public EidLoginResponse Raw { get; }

        public JsonObject? Json { get; set; }

        /// <summary>Cookie: "" түлхүүр = утга, бусад = attribute (жижиг үсгээр; флаг = "true").</summary>
        public Dictionary<string, string>? Cookie { get; set; }
    }

    private static Dictionary<string, string> ParseCookie(string setCookie)
    {
        var o = new Dictionary<string, string>(StringComparer.Ordinal);
        var parts = setCookie.Split(';');
        for (var i = 0; i < parts.Length; i++)
        {
            var p = parts[i].Trim();
            var eq = p.IndexOf('=');
            var k = eq >= 0 ? p[..eq] : p;
            var v = eq >= 0 ? p[(eq + 1)..] : "true";
            if (i == 0)
            {
                o[""] = v;
                continue;
            }
            o[k.ToLowerInvariant()] = v;
        }
        return o;
    }

    private static List<string> SortedKeys(JsonObject? o) =>
        (o ?? new JsonObject()).Select(p => p.Key).OrderBy(x => x, StringComparer.Ordinal).ToList();

    private static string? CheckStep(JsonElement e, StepResult res, StepResult[] all)
    {
        if (e.TryGetProperty("status", out var s) && s.GetInt32() != res.Raw.Status)
        {
            return "status " + res.Raw.Status + " ≠ " + s.GetInt32();
        }
        if (e.TryGetProperty("jsonKeys", out var ks))
        {
            var want = ks.EnumerateArray().Select(k => k.GetString()!).OrderBy(x => x, StringComparer.Ordinal).ToList();
            if (!want.SequenceEqual(SortedKeys(res.Json)))
            {
                return "json keys [" + string.Join(",", SortedKeys(res.Json)) + "] ≠ [" + string.Join(",", want) + "]";
            }
        }
        if (e.TryGetProperty("sameKeysAs", out var same) && !SortedKeys(res.Json).SequenceEqual(SortedKeys(all[same.GetInt32()].Json)))
        {
            return "json keys ≠ алхам " + same.GetInt32() + "-ийнх";
        }
        if (e.TryGetProperty("json", out var j) && Match(j, res.Json, all) is { } je)
        {
            return "json: " + je;
        }
        if (e.TryGetProperty("location", out var l) && Match(l, Value(res.Raw.Header("Location")), all) is { } le)
        {
            return "location: " + le;
        }
        if (e.TryGetProperty("headers", out var hs))
        {
            foreach (var p in hs.EnumerateObject())
            {
                if (res.Raw.Header(p.Name) != p.Value.GetString())
                {
                    return "header " + p.Name + " '" + res.Raw.Header(p.Name) + "' ≠ '" + p.Value.GetString() + "'";
                }
            }
        }
        if (e.TryGetProperty("noSetCookie", out var nsc) && nsc.ValueKind == JsonValueKind.True && res.Cookie is not null)
        {
            return "Set-Cookie байх ёсгүй";
        }
        if (e.TryGetProperty("setCookie", out var sc))
        {
            if (res.Cookie is null)
            {
                return "Set-Cookie алга";
            }
            if (sc.TryGetProperty("cleared", out var cl) && cl.ValueKind == JsonValueKind.True &&
                (res.Cookie.GetValueOrDefault("") != "" || res.Cookie.GetValueOrDefault("max-age") != "0"))
            {
                return "cookie цэвэрлэгдээгүй";
            }
            if (sc.TryGetProperty("value", out var v) && Match(v, Value(res.Cookie.GetValueOrDefault("")), all) is { } ve)
            {
                return "cookie value: " + ve;
            }
            if (sc.TryGetProperty("attributes", out var attrs))
            {
                foreach (var a in attrs.EnumerateObject())
                {
                    var has = res.Cookie.TryGetValue(a.Name.ToLowerInvariant(), out var got);
                    if (a.Value.ValueKind == JsonValueKind.True)
                    {
                        if (!has)
                        {
                            return "cookie " + a.Name + " алга";
                        }
                        continue;
                    }
                    if (Match(a.Value, has ? Value(got) : null, all) is { } ae)
                    {
                        return "cookie " + a.Name + ": " + ae;
                    }
                }
            }
        }
        return null;
    }

    private static JsonNode? Value(string? s) => s is null ? null : JsonValue.Create(s);

    /// <summary>README §eidlogin matcher-ууд: $re, $range, $sameAs, объект (subset), null, утга.</summary>
    private static string? Match(JsonElement want, JsonNode? got, StepResult[] all)
    {
        if (want.ValueKind == JsonValueKind.Object)
        {
            if (want.TryGetProperty("$re", out var re))
            {
                var s = Str(got);
                return Regex.IsMatch(s, re.GetString()!, RegexOptions.CultureInvariant) ? null : "'" + s + "' ≁ /" + re.GetString() + "/";
            }
            if (want.TryGetProperty("$range", out var rg))
            {
                if (got is JsonValue gv && gv.TryGetValue<double>(out var d) && d >= rg[0].GetDouble() && d <= rg[1].GetDouble())
                {
                    return null;
                }
                return got?.ToJsonString() + " ∉ " + rg.GetRawText();
            }
            if (want.TryGetProperty("$sameAs", out var sa))
            {
                var parts = sa.GetString()!.Split('.', 3);
                var src = all[int.Parse(parts[0], CultureInfo.InvariantCulture)].Json?[parts[2]];
                return Str(src) == Str(got) ? null : Str(got) + " ≠ " + sa.GetString() + " (" + Str(src) + ")";
            }
            if (got is not JsonObject go)
            {
                return "объект хүлээсэн: " + got?.ToJsonString();
            }
            foreach (var p in want.EnumerateObject())
            {
                if (Match(p.Value, go[p.Name], all) is { } e)
                {
                    return p.Name + ": " + e;
                }
            }
            return null;
        }
        if (want.ValueKind == JsonValueKind.Null)
        {
            return got is null ? null : "null хүлээсэн: " + got.ToJsonString();
        }
        if (got is not JsonValue v)
        {
            return "утга хүлээсэн (" + want.GetRawText() + "): " + got?.ToJsonString();
        }
        switch (want.ValueKind)
        {
            case JsonValueKind.Number:
                return v.TryGetValue<double>(out var n) && n == want.GetDouble() ? null : v.ToJsonString() + " ≠ " + want.GetRawText();
            case JsonValueKind.True:
            case JsonValueKind.False:
                return v.TryGetValue<bool>(out var b) && b == (want.ValueKind == JsonValueKind.True) ? null : v.ToJsonString() + " ≠ " + want.GetRawText();
            default:
                return v.TryGetValue<string>(out var s2) && s2 == want.GetString() ? null : v.ToJsonString() + " ≠ " + want.GetRawText();
        }
    }

    /// <summary>Мөрийн хэлбэр (Go <c>confStr</c>): тоо → бүхэл, null → "".</summary>
    private static string Str(JsonNode? n)
    {
        if (n is not JsonValue v)
        {
            return n is null ? "" : n.ToJsonString();
        }
        if (v.TryGetValue<string>(out var s))
        {
            return s;
        }
        if (v.TryGetValue<bool>(out var b))
        {
            return b ? "true" : "false";
        }
        if (v.TryGetValue<double>(out var d))
        {
            return ((long)d).ToString(CultureInfo.InvariantCulture);
        }
        return v.ToJsonString();
    }

    /// <summary>
    /// Fake RP-API (README §eidlogin upstream): эхний таарсан дүрэм (method + path яг / pathPrefix; query үл хамаарна),
    /// <c>expiresAtInSeconds</c> → expiresAt = бодит одоо + N с; таараагүй → 404.
    /// </summary>
    private sealed class RuleUpstream : HttpMessageHandler
    {
        private readonly List<JsonElement> _rules = new();

        public void Prepend(JsonElement rules)
        {
            lock (_rules)
            {
                _rules.InsertRange(0, rules.EnumerateArray().Select(r => r.Clone()));
            }
        }

        public void Append(JsonElement rules)
        {
            lock (_rules)
            {
                _rules.AddRange(rules.EnumerateArray().Select(r => r.Clone()));
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            List<JsonElement> rules;
            lock (_rules)
            {
                rules = _rules.ToList();
            }
            foreach (var ru in rules)
            {
                var path0 = Corpus.Str(ru, "path");
                var prefix = Corpus.Str(ru, "pathPrefix");
                if (Corpus.Str(ru, "method") != request.Method.Method || (path0.Length > 0 && path0 != path) ||
                    (prefix.Length > 0 && !path.StartsWith(prefix, StringComparison.Ordinal)))
                {
                    continue;
                }
                var ct0 = Corpus.Str(ru, "contentType");
                string body;
                if (ru.TryGetProperty("bodyText", out var bt))
                {
                    body = bt.GetString()!;
                }
                else if (ru.TryGetProperty("expiresAtInSeconds", out var ex) && ex.GetInt32() > 0)
                {
                    var o = JsonNode.Parse(ru.GetProperty("body").GetRawText())!.AsObject();
                    o["expiresAt"] = DateTimeOffset.UtcNow.AddSeconds(ex.GetInt32()).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
                    body = o.ToJsonString();
                }
                else
                {
                    body = ru.GetProperty("body").GetRawText();
                }
                var res = new HttpResponseMessage((HttpStatusCode)ru.GetProperty("status").GetInt32())
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)),
                };
                res.Content.Headers.TryAddWithoutValidation("Content-Type", ct0.Length > 0 ? ct0 : "application/json");
                return Task.FromResult(res);
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                Content = new StringContent("{\"error\":\"not found\"}", Encoding.UTF8, "application/json"),
            });
        }
    }
}

/// <summary>Бодит одоо, гэхдээ timer бүр шууд дуусна (Task.Delay хүлээхгүй).</summary>
internal sealed class SystemNowInstantTimers : TimeProvider
{
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        _ = Task.Run(() => callback(state));
        return new Noop();
    }

    private sealed class Noop : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
