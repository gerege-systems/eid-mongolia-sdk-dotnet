using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// base64 хувилбарууд — Go <c>encoding/base64</c>-ийн Std / RawStd / URL / RawURL-тэй ижил дүрэм (net8-д
/// <c>Base64Url</c> алга тул гараар). <see cref="Convert.FromBase64String"/> whitespace зөвшөөрдөг тул тэмдэгтийг
/// урьдчилж шалгана.
/// </summary>
internal static class B64
{
    public static string Std(ReadOnlySpan<byte> b) => Convert.ToBase64String(b);

    public static string Std(string utf8) => Convert.ToBase64String(Encoding.UTF8.GetBytes(utf8));

    /// <summary>BASE64URL, padding-гүй (Go RawURLEncoding).</summary>
    public static string RawUrl(ReadOnlySpan<byte> b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Стандарт base64, padding-тэй (Go StdEncoding).</summary>
    public static bool TryDecodeStd(string s, out byte[] b) => TryDecode(s, url: false, padded: true, out b);

    /// <summary>Go-ийн Std, RawStd, URL, RawURL дарааллаар; эхний амжилттай, хоосон биш үр дүн.</summary>
    public static bool TryDecodeAny(string s, out byte[] b)
    {
        foreach (var (url, padded) in new[] { (false, true), (false, false), (true, true), (true, false) })
        {
            if (TryDecode(s, url, padded, out b) && b.Length > 0)
            {
                return true;
            }
        }
        b = Array.Empty<byte>();
        return false;
    }

    private static bool TryDecode(string s, bool url, bool padded, out byte[] b)
    {
        b = Array.Empty<byte>();
        var body = s.Length;
        if (padded)
        {
            if (s.Length % 4 != 0)
            {
                return false;
            }
            while (body > 0 && s.Length - body < 2 && s[body - 1] == '=')
            {
                body--;
            }
        }
        else if (s.Length % 4 == 1)
        {
            return false;
        }
        for (var i = 0; i < body; i++)
        {
            var c = s[i];
            var ok = c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' ||
                (url ? c is '-' or '_' : c is '+' or '/');
            if (!ok)
            {
                return false;
            }
        }
        if (padded && body % 4 == 1)
        {
            return false;
        }
        var std = s[..body];
        if (url)
        {
            std = std.Replace('-', '+').Replace('_', '/');
        }
        std += new string('=', (4 - std.Length % 4) % 4);
        try
        {
            b = Convert.FromBase64String(std);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>
/// JS <c>JSON.stringify</c>-тай БАЙТ-ИЖИЛ JSON бичигч (interactions-д). System.Text.Json нь non-ASCII-г relaxed encoder-оор
/// ч escape хийдэг тул энд хэрэглэхгүй. Дүрэм (ECMA-262 QuoteJSONString): <c>"</c> → <c>\"</c>, <c>\</c> → <c>\\</c>,
/// \b \f \n \r \t богино, бусад U+0000–U+001F ба ганц surrogate → <c>\uXXXX</c> (жижиг hex), бусад бүх тэмдэгт
/// (U+2028/U+2029, U+007F, кирилл, <c>&lt; &gt; &amp;</c>) түүхийгээр.
/// </summary>
internal static class JsJson
{
    public static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    continue;
                case '\\':
                    sb.Append("\\\\");
                    continue;
                case '\b':
                    sb.Append("\\b");
                    continue;
                case '\f':
                    sb.Append("\\f");
                    continue;
                case '\n':
                    sb.Append("\\n");
                    continue;
                case '\r':
                    sb.Append("\\r");
                    continue;
                case '\t':
                    sb.Append("\\t");
                    continue;
            }
            if (c < 0x20)
            {
                AppendU(sb, c);
            }
            else if (char.IsHighSurrogate(c))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    sb.Append(c).Append(s[i + 1]);
                    i++;
                }
                else
                {
                    AppendU(sb, c);
                }
            }
            else if (char.IsLowSurrogate(c))
            {
                AppendU(sb, c);
            }
            else
            {
                sb.Append(c);
            }
        }
        sb.Append('"');
    }

    private static void AppendU(StringBuilder sb, char c) =>
        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));

    /// <summary>
    /// <c>JSON.stringify(interactions)</c>: талбарын дараалал type, displayText60, displayText200; хоосон (null / "")
    /// текст талбар орхигдоно (Go <c>omitempty</c>-тэй ижил).
    /// </summary>
    public static string Interactions(IEnumerable<Interaction>? interactions)
    {
        var sb = new StringBuilder("[");
        var first = true;
        foreach (var it in interactions ?? Array.Empty<Interaction>())
        {
            ArgumentNullException.ThrowIfNull(it, nameof(interactions));
            if (!first)
            {
                sb.Append(',');
            }
            first = false;
            sb.Append("{\"type\":");
            WriteString(sb, it.Type ?? "");
            if (!string.IsNullOrEmpty(it.DisplayText60))
            {
                sb.Append(",\"displayText60\":");
                WriteString(sb, it.DisplayText60);
            }
            if (!string.IsNullOrEmpty(it.DisplayText200))
            {
                sb.Append(",\"displayText200\":");
                WriteString(sb, it.DisplayText200);
            }
            sb.Append('}');
        }
        return sb.Append(']').ToString();
    }
}
