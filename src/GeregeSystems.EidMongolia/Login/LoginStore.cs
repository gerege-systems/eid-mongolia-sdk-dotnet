using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Login;

/// <summary>
/// Нэвтрэлтийн төлөвийн сан (Go <c>Store</c>, TS <c>EidLoginStore</c>). Анхдагч <see cref="MemoryEidLoginStore"/> (нэг
/// процесс); олон instance бол Redis г.м. — <see cref="EidLoginTx"/>-ийг JSON-оор хадгалж болно.
/// </summary>
public interface IEidLoginStore
{
    /// <summary>Олдохгүй / хугацаа дууссан бол null.</summary>
    Task<EidLoginTx?> GetAsync(string sessionId, CancellationToken ct);

    /// <summary><paramref name="ttl"/>-тэй хадгална (байвал солино).</summary>
    Task SetAsync(EidLoginTx tx, TimeSpan ttl, CancellationToken ct);

    /// <summary>
    /// Устгана; байсан бол true. Амжилтыг (OnSuccess) нэг л удаа гаргахад ашиглана — АТОМАР байх ёстой (Redis <c>DEL</c>).
    /// </summary>
    Task<bool> DeleteAsync(string sessionId, CancellationToken ct);
}

/// <summary>Санах ойн сан дүүрсэн (хугацаа нь дуусаагүй дээд хэмжээний нэвтрэлт) — start 503 <c>busy</c>.</summary>
public sealed class EidLoginStoreFullException : EidException
{
    /// <summary>Шинэ алдаа.</summary>
    public EidLoginStoreFullException() : base("eidlogin: memory store дүүрсэн")
    {
    }
}

/// <summary>
/// Нэг процессын санах ойн сан (TTL-тэй; Go <c>NewMemoryStore</c>, TS <c>memoryLoginStore</c>). Дүүрвэл хугацаа
/// дууссаныг цэвэрлээд, хоосроогүй бол ШИНЭ нэвтрэлтийг <see cref="EidLoginStoreFullException"/>-оор татгалзана — эхэлсэн
/// нэвтрэлтүүдийг хэзээ ч шахаж гаргахгүй. Олон instance / serverless-д тохирохгүй. Thread-safe.
/// </summary>
public sealed class MemoryEidLoginStore : IEidLoginStore
{
    /// <summary>Анхдагч дээд хэмжээ (идэвхтэй нэвтрэлт).</summary>
    public const int DefaultMax = 10_000;

    private readonly Dictionary<string, (EidLoginTx Tx, DateTimeOffset Exp)> _m = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    /// <summary>Шинэ сан.</summary>
    /// <param name="max">Дээд хэмжээ (&gt; 0).</param>
    /// <param name="timeProvider">Цаг (тест); null = систем.</param>
    public MemoryEidLoginStore(int max = DefaultMax, TimeProvider? timeProvider = null)
    {
        if (max <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(max), "max > 0 байх ёстой");
        }
        Max = max;
        _clock = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Дээд хэмжээ.</summary>
    public int Max { get; }

    /// <summary>Одоо хадгалагдаж буй бичлэгийн тоо (хугацаа дууссан ч цэвэрлэгдээгүй бол орно).</summary>
    public int Count
    {
        get
        {
            lock (_m)
            {
                return _m.Count;
            }
        }
    }

    /// <inheritdoc/>
    public Task<EidLoginTx?> GetAsync(string sessionId, CancellationToken ct)
    {
        lock (_m)
        {
            if (!_m.TryGetValue(sessionId, out var e))
            {
                return Task.FromResult<EidLoginTx?>(null);
            }
            if (_clock.GetUtcNow() >= e.Exp)
            {
                _m.Remove(sessionId);
                return Task.FromResult<EidLoginTx?>(null);
            }
            return Task.FromResult<EidLoginTx?>(e.Tx);
        }
    }

    /// <inheritdoc/>
    public Task SetAsync(EidLoginTx tx, TimeSpan ttl, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tx);
        lock (_m)
        {
            var now = _clock.GetUtcNow();
            if (!_m.ContainsKey(tx.SessionId) && _m.Count >= Max)
            {
                foreach (var k in _m.Where(p => now >= p.Value.Exp).Select(p => p.Key).ToList())
                {
                    _m.Remove(k);
                }
                if (_m.Count >= Max)
                {
                    throw new EidLoginStoreFullException();
                }
            }
            _m[tx.SessionId] = (tx, now + ttl);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<bool> DeleteAsync(string sessionId, CancellationToken ct)
    {
        lock (_m)
        {
            return Task.FromResult(_m.Remove(sessionId));
        }
    }
}

/// <summary>
/// Нэг төрлийн хязгаар (Go <c>RateRule</c>, TS <c>EidLoginRateRule</c>). <see cref="Func"/> өгвөл түүгээр (Redis г.м.);
/// үгүй бол <see cref="Max"/> &gt; 0 үед санах ойн гулсах цонх (түлхүүр тус бүрд <see cref="Window"/>-д Max); Max ≤ 0 ба
/// Func null бол хязгааргүй.
/// </summary>
public sealed record EidLoginRateRule
{
    /// <summary>Цонхонд зөвшөөрөх тоо.</summary>
    public int Max { get; init; }

    /// <summary>Цонх (Max &gt; 0 үед &gt; 0).</summary>
    public TimeSpan Window { get; init; }

    /// <summary>Өөрийн хязгаарлагч: true — зөвшөөрөх, false — 429.</summary>
    public Func<string, CancellationToken, ValueTask<bool>>? Func { get; init; }

    /// <summary>Хязгааргүй (тухайн төрлийн анхдагчийг унтраана).</summary>
    public static EidLoginRateRule Unlimited { get; } = new();

    /// <summary>
    /// Анхдагч хязгаар (шинэ dictionary): start — нэг IP-ээс 60 секундэд 20 (ClientIp өгсөн үед); push — нэг дугаарт 60
    /// секундэд 3 (MFA fatigue). Go <c>DefaultRateLimit</c>, TS <c>defaultRateLimit</c>-тэй ижил.
    /// </summary>
    public static Dictionary<string, EidLoginRateRule> Defaults() => new(StringComparer.Ordinal)
    {
        ["start"] = new EidLoginRateRule { Max = 20, Window = TimeSpan.FromMinutes(1) },
        ["push"] = new EidLoginRateRule { Max = 3, Window = TimeSpan.FromMinutes(1) },
    };
}

/// <summary>
/// Санах ойн гулсах цонх (түлхүүр тус бүрд), дээд тал нь maxKeys түлхүүр (Go/TS <c>windowLimiter</c>). Дүүрвэл цонх нь
/// өнгөрсөн түлхүүрийг цэвэрлээд, хоосроогүй бол ШИНЭ түлхүүрийг татгалзана (fail-closed) — байгаа түлхүүрийн тоолуурыг
/// хэзээ ч арилгахгүй тул олон түлхүүрээр дүүргэж тухайн дугаарын хязгаарыг тойрох боломжгүй.
/// </summary>
internal sealed class WindowLimiter
{
    /// <summary>Анхдагч дээд түлхүүрийн тоо (төрөл тус бүрд).</summary>
    public const int DefaultMaxKeys = 10_000;

    private readonly int _limit;
    private readonly TimeSpan _window;
    private readonly int _maxKeys;
    private readonly TimeProvider _clock;
    private readonly Dictionary<string, List<DateTimeOffset>> _hits = new(StringComparer.Ordinal);

    public WindowLimiter(int limit, TimeSpan window, int maxKeys, TimeProvider clock)
    {
        _limit = limit;
        _window = window;
        _maxKeys = maxKeys;
        _clock = clock;
    }

    public bool Allow(string key)
    {
        lock (_hits)
        {
            var now = _clock.GetUtcNow();
            if (!_hits.ContainsKey(key) && _hits.Count >= _maxKeys)
            {
                foreach (var k in _hits.Where(p => p.Value.Count == 0 || now - p.Value[^1] >= _window).Select(p => p.Key).ToList())
                {
                    _hits.Remove(k);
                }
                if (_hits.Count >= _maxKeys)
                {
                    return false;
                }
            }
            var h = _hits.TryGetValue(key, out var prev) ? prev.Where(t => now - t < _window).ToList() : new List<DateTimeOffset>();
            if (h.Count >= _limit)
            {
                _hits[key] = h;
                return false;
            }
            h.Add(now);
            _hits[key] = h;
            return true;
        }
    }
}
