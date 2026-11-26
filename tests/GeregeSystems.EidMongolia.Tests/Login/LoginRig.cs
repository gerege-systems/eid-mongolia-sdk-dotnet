using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Login;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

// Login backend-ийн тестийн хэрэгсэл — зөвхөн нийтийн API (AspNetCore тестэд link-ээр дахин хэрэглэнэ).

/// <summary>
/// Удирддаг цаг: GetUtcNow = <see cref="Now"/>; timer бүр (Task.Delay) хүлээх хугацаагаа <see cref="Sleeps"/>-д бичээд
/// шууд дуусна — push floor / decoy poll-ыг бодитоор унтахгүй хэмжинэ.
/// </summary>
internal sealed class FakeTime : TimeProvider
{
    private readonly List<TimeSpan> _sleeps = new();

    public FakeTime(DateTimeOffset now) => Now = now;

    public DateTimeOffset Now { get; set; }

    public List<TimeSpan> Sleeps
    {
        get
        {
            lock (_sleeps)
            {
                return _sleeps.ToList();
            }
        }
    }

    public void ClearSleeps()
    {
        lock (_sleeps)
        {
            _sleeps.Clear();
        }
    }

    public override DateTimeOffset GetUtcNow() => Now;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        lock (_sleeps)
        {
            _sleeps.Add(dueTime);
        }
        _ = Task.Run(() => callback(state));
        return new Fired();
    }

    private sealed class Fired : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>
/// RP-API-г дуурайна (Go eidlogin_test.go <c>fakeEID</c>): start хүсэлтийг хадгалж, COMPLETE үед БОДИТ ACSP_V2 гарын
/// үсэг (тестийн RSA түлхүүрээр, RSA-PSS SHA-512) буцаана — validator (AllowUntrusted) гарын үсэг, flowType, verifier-ийг
/// жинхэнээр шалгана.
/// </summary>
internal sealed class FakeEid : HttpMessageHandler
{
    public const string Sid = "0b5e6a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c";
    public const string Etsi = "PNOMN-111949212017";

    private readonly object _mu = new();
    private readonly RSA _key;
    private JsonObject? _req;
    private string _path = "";
    private string _end = "";
    private string _flow = "";
    private string _verifier = "";
    private bool _tamper;
    private string _refuse = "";
    private bool _polledOther;
    private int _ttlAuth;
    private TimeSpan _exp;

    public FakeEid()
    {
        _key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var dn = new X500DistinguishedNameBuilder();
        dn.AddCountryOrRegion("MN");
        dn.AddCommonName("DORJ BAT");
        dn.Add("2.5.4.5", Etsi, UniversalTagNumber.PrintableString);
        dn.Add("2.5.4.42", "BAT");
        dn.Add("2.5.4.4", "DORJ");
        var req = new CertificateRequest(dn.Build(), _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.4") }, false));
        using var cert = req.CreateSelfSigned(now.AddHours(-1), now.AddHours(1));
        CertDer = cert.RawData;
    }

    public byte[] CertDer { get; }

    /// <summary>Хүсэлт бүрийн өмнө (ж: цагийг урагшлуулах).</summary>
    public Action<HttpRequestMessage>? OnRequest { get; set; }

    public JsonObject? LastStart
    {
        get
        {
            lock (_mu)
            {
                return _req;
            }
        }
    }

    public string LastPath
    {
        get
        {
            lock (_mu)
            {
                return _path;
            }
        }
    }

    public bool PolledOther
    {
        get
        {
            lock (_mu)
            {
                return _polledOther;
            }
        }
    }

    /// <summary>end: "" = RUNNING, "OK" = гарын үсэгтэй COMPLETE, бусад = endResult.</summary>
    public void Set(string end, string flow, string verifier)
    {
        lock (_mu)
        {
            (_end, _flow, _verifier) = (end, flow, verifier);
        }
    }

    public void SetTamper(bool v)
    {
        lock (_mu)
        {
            _tamper = v;
        }
    }

    /// <summary>"" = бодит; "json400" = eID-ийн татгалзал; "proxy400" = JSON бус 4xx; "500"; "401"; "429".</summary>
    public void SetRefuse(string v)
    {
        lock (_mu)
        {
            _refuse = v;
        }
    }

    /// <summary>auth — discovery sessionTtl.auth (сек; 0 = талбар алга); exp — start хариуны expiresAt (Zero = алга).</summary>
    public void SetTtl(int auth, TimeSpan exp)
    {
        lock (_mu)
        {
            (_ttlAuth, _exp) = (auth, exp);
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        OnRequest?.Invoke(request);
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        var path = request.RequestUri!.AbsolutePath;
        lock (_mu)
        {
            JsonObject Exp(JsonObject o)
            {
                if (_exp > TimeSpan.Zero)
                {
                    o["expiresAt"] = (DateTimeOffset.UtcNow + _exp).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
                }
                return o;
            }
            if (path == "/.well-known/eid")
            {
                return _ttlAuth > 0
                    ? Json(200, new JsonObject { ["version"] = "v3", ["sessionTtl"] = new JsonObject { ["auth"] = _ttlAuth, ["sign"] = 600 } })
                    : Json(200, new JsonObject { ["version"] = "v3" });
            }
            if (path == "/authentication/device-link/anonymous")
            {
                _path = path;
                _req = JsonNode.Parse(body!)!.AsObject();
                return Json(200, Exp(new JsonObject
                {
                    ["sessionID"] = Sid,
                    ["sessionToken"] = "tok_ABC-123",
                    ["sessionSecret"] = Convert.ToBase64String(new byte[32]),
                    ["deviceLinkBase"] = "https://eid.example.test/dl",
                    ["vc"] = "12345",
                }));
            }
            if (path.StartsWith("/authentication/notification/etsi/", StringComparison.Ordinal))
            {
                _path = path;
                switch (_refuse)
                {
                    case "json400":
                        return Raw(400, "application/json", "{\"error\":\"хэрэглэгч олдсонгүй\"}");
                    case "proxy400":
                        return Raw(400, "text/html", "<html>400 The SSL certificate error</html>");
                    case "401":
                        return Raw(401, "application/json", "{\"error\":\"unauthorized\"}");
                    case "429":
                        return Raw(429, "application/json", "{\"error\":\"rate limited\"}");
                    case "500":
                        return Raw(500, "application/json", "{\"error\":\"дотоод алдаа\"}");
                }
                _req = JsonNode.Parse(body!)!.AsObject();
                return Json(200, Exp(new JsonObject { ["sessionID"] = Sid, ["vc"] = new JsonObject { ["type"] = "alphaNumeric4", ["value"] = "54321" } }));
            }
            if (path.StartsWith("/session/", StringComparison.Ordinal) && path != "/session/" + Sid)
            {
                _polledOther = true;
                return Raw(404, "application/json", "{\"error\":\"session олдсонгүй\"}");
            }
            if (path == "/session/" + Sid)
            {
                if (_end.Length == 0)
                {
                    return Json(200, new JsonObject { ["state"] = "RUNNING" });
                }
                if (_end != "OK")
                {
                    return Json(200, new JsonObject { ["state"] = "COMPLETE", ["result"] = new JsonObject { ["endResult"] = _end } });
                }
                return Json(200, Signed());
            }
            return Raw(404, "application/json", "{\"error\":\"not found\"}");
        }
    }

    private JsonObject Signed()
    {
        var req = _req!;
        var cb = _flow == "Web2App" ? (string?)req["initialCallbackUrl"] ?? "" : "";
        var sr = Convert.ToBase64String(Encoding.ASCII.GetBytes("server-random-0123456789"));
        var uc = EidCrypto.UserChallengeOf(_verifier);
        var payload = Acsp.BuildV2Payload(new AcspV2Params
        {
            ServerRandom = sr,
            RpChallenge = (string)req["signatureProtocolParameters"]!["rpChallenge"]!,
            UserChallenge = uc,
            RelyingPartyName = (string)req["relyingPartyName"]!,
            Interactions = (string)req["interactions"]!,
            InteractionTypeUsed = "displayTextAndPIN",
            InitialCallbackUrl = cb,
            FlowType = _flow,
        });
        if (_tamper)
        {
            payload = payload.Append((byte)'x').ToArray();
        }
        var sig = _key.SignData(payload, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        return new JsonObject
        {
            ["state"] = "COMPLETE",
            ["result"] = new JsonObject { ["endResult"] = "OK", ["documentNumber"] = "doc-1" },
            ["signature"] = new JsonObject
            {
                ["value"] = Convert.ToBase64String(sig),
                ["signatureAlgorithm"] = "rsassa-pss",
                ["serverRandom"] = sr,
                ["userChallenge"] = uc,
                ["flowType"] = _flow,
                ["initialCallbackUrl"] = cb,
                ["signatureAlgorithmParameters"] = new JsonObject { ["hashAlgorithm"] = "SHA-512" },
            },
            ["signatureProtocol"] = "ACSP_V2",
            ["cert"] = new JsonObject { ["value"] = Convert.ToBase64String(CertDer), ["certificateLevel"] = "QUALIFIED" },
            ["interactionTypeUsed"] = "displayTextAndPIN",
            ["person"] = new JsonObject { ["civilId"] = "111949212017", ["firstName"] = "Бат", ["lastName"] = "Дорж" },
        };
    }

    private static HttpResponseMessage Json(int status, JsonObject o) => Raw(status, "application/json", o.ToJsonString());

    private static HttpResponseMessage Raw(int status, string contentType, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, contentType) };
}

/// <summary>Handler-ийн хариу + задалсан JSON.</summary>
internal sealed record LoginResp(EidLoginResponse Raw, JsonObject? Body)
{
    public int Code => Raw.Status;

    public string? Str(string key) => Body?[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public long? Num(string key) => Body?[key] is JsonValue v && v.TryGetValue<long>(out var n) ? n : null;

    public string Keys() => string.Join(",", (Body ?? new JsonObject()).Select(p => p.Key).OrderBy(x => x, StringComparer.Ordinal));

    /// <summary>eid_login cookie-г ("eid_login=&lt;утга&gt;") — HttpOnly, Secure, SameSite=Lax байгааг шалгана.</summary>
    public string LoginCookie()
    {
        foreach (var c in Raw.HeaderValues("Set-Cookie"))
        {
            if (c.StartsWith("eid_login=", StringComparison.Ordinal) && !c.StartsWith("eid_login=;", StringComparison.Ordinal))
            {
                foreach (var attr in new[] { "HttpOnly", "Secure", "SameSite=Lax" })
                {
                    Assert.Contains("; " + attr, c);
                }
                return c.Split(';')[0];
            }
        }
        throw new Xunit.Sdk.XunitException("eid_login cookie алга: " + string.Join(" | ", Raw.HeaderValues("Set-Cookie")));
    }

    /// <summary>eid_login cookie-ийн Max-Age.</summary>
    public string MaxAge()
    {
        var c = Raw.HeaderValues("Set-Cookie").First(x => x.StartsWith("eid_login=", StringComparison.Ordinal));
        return c.Split(';').Select(p => p.Trim()).First(p => p.StartsWith("Max-Age=", StringComparison.Ordinal))["Max-Age=".Length..];
    }

    public bool ClearsCookie() => Raw.HeaderValues("Set-Cookie").Any(c => c.StartsWith("eid_login=;", StringComparison.Ordinal) && c.Contains("Max-Age=0"));
}

/// <summary>Go eidlogin_test.go <c>env</c>: fake RP-API + handler + удирддаг цаг + бичигдсэн identity/event/log.</summary>
internal sealed class LoginEnv
{
    public const string CallbackUrl = "https://bank.example.mn/auth/eid/callback";

    private LoginEnv(FakeEid fake, FakeTime time)
    {
        Fake = fake;
        Time = time;
    }

    public FakeEid Fake { get; }

    public FakeTime Time { get; }

    public EidClient Client { get; private set; } = null!;

    public EidLoginHandler H { get; private set; } = null!;

    public IEidLoginStore Store { get; private set; } = null!;

    public List<EidLoginIdentity> Ids { get; } = new();

    public List<EidLoginEvent> Events { get; } = new();

    public List<EidLoginLogEntry> Logs { get; } = new();

    public List<string> Kinds => Events.Select(e => e.Kind).ToList();

    public static LoginEnv Create(Action<EidLoginOptions>? mod = null)
    {
        var e = new LoginEnv(new FakeEid(), new FakeTime(DateTimeOffset.UtcNow));
        e.Client = new EidClient(new EidClientOptions
        {
            BaseUrl = "https://rp-api.example.test",
            Credentials = new EidCredentials("rp-1", "Демо банк", "rp_sk_test"),
            Trust = new TrustConfig { AllowUntrusted = true, AllowAnyIssuer = true },
        }, new HttpClient(e.Fake));
        var o = new EidLoginOptions
        {
            Client = e.Client,
            // Тестүүд «eid_login» нэрээр бичигдсэн (анхдагч нь rp-conformance/2-оос __Host-eid_login).
            CookieName = "eid_login",
            CallbackUrl = CallbackUrl,
            FailureRedirect = "/login",
            TimeProvider = e.Time,
            OnSuccess = (id, _, _) =>
            {
                lock (e.Ids)
                {
                    e.Ids.Add(id);
                }
                return Task.FromResult<EidLoginSuccess?>(new EidLoginSuccess
                {
                    Redirect = "/dashboard",
                    Data = new { user = id.Etsi },
                    Headers = new[] { new KeyValuePair<string, string>("Set-Cookie", "app_session=s1; Path=/; HttpOnly") },
                });
            },
            Log = l =>
            {
                lock (e.Logs)
                {
                    e.Logs.Add(l);
                }
            },
        };
        mod?.Invoke(o);
        var userEvent = o.OnEvent;
        o.OnEvent = async (ev, ct) =>
        {
            lock (e.Events)
            {
                e.Events.Add(ev);
            }
            if (userEvent is not null)
            {
                await userEvent(ev, ct);
            }
        };
        o.Store ??= new MemoryEidLoginStore(timeProvider: e.Time);
        e.Store = o.Store;
        e.H = new EidLoginHandler(o);
        return e;
    }

    public async Task<LoginResp> Do(string method, string target, string? body = null, IDictionary<string, string>? headers = null,
        string? ip = null)
    {
        var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (body is not null)
        {
            h["Content-Type"] = "application/json";
        }
        foreach (var (k, v) in headers ?? new Dictionary<string, string>())
        {
            h[k] = v;
        }
        var res = await H.HandleAsync(new EidLoginRequest { Method = method, Url = target, Headers = h, Body = body, RemoteIp = ip });
        JsonObject? json = null;
        if ((res.Header("Content-Type") ?? "").StartsWith("application/json", StringComparison.Ordinal))
        {
            json = JsonNode.Parse(res.Body)!.AsObject();
        }
        return new LoginResp(res, json);
    }

    public Task<LoginResp> Status(string cookie) =>
        Do("GET", "/auth/eid/status", headers: new Dictionary<string, string> { ["Cookie"] = cookie });

    public Task<LoginResp> StartQr() => Do("POST", "/auth/eid/start", "{\"mode\":\"qr\"}");

    public Task<LoginResp> StartPush(string idCode) => Do("POST", "/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"" + idCode + "\"}");
}
