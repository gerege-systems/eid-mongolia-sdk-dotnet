using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>
/// PDF token/объект уншигч — digitorus/pdf lex.go-ийн байт-түвшний хуулбар (санах ойн массив дээр). Файлын төгсгөлөөс
/// цааш уншвал алдаа (AllowEof = true үед л EOF токен).
/// </summary>
internal sealed class Lexer
{
    internal static readonly object Eof = new();

    private readonly byte[] _data;
    private readonly int _end;
    private int _pos;
    private bool _eof;
    private readonly List<object?> _unread = new();

    public bool AllowEof { get; set; }

    /// <summary>Одоо уншиж буй шууд бус объектын дугаар (stream-ийн Ptr-д).</summary>
    public ObjPtr CurrentObj { get; private set; }

    public Lexer(byte[] data, int start, int end)
    {
        _data = data;
        _pos = start;
        _end = end;
    }

    /// <summary>Дараагийн уншилтын байрлал (массивын индекс).</summary>
    public int Offset => _pos;

    public void SeekForward(int offset) => _pos = offset;

    private byte ReadByte()
    {
        if (_pos >= _end)
        {
            if (AllowEof)
            {
                _eof = true;
                return (byte)'\n';
            }
            throw new PdfFormatException("malformed PDF: unexpected end of data at offset " + _pos);
        }
        return _data[_pos++];
    }

    private void UnreadByte()
    {
        // Go: pos > 0 бол л буцаана; EOF дээр «\n» буцаасан бол байрлал өөрчлөгдөөгүй.
        if (_eof) return;
        if (_pos > 0) _pos--;
    }

    public void UnreadToken(object? t) => _unread.Add(t);

    public object? ReadToken()
    {
        if (_unread.Count > 0)
        {
            var t = _unread[^1];
            _unread.RemoveAt(_unread.Count - 1);
            return t;
        }

        byte c = ReadByte();
        while (true)
        {
            if (IsSpace(c))
            {
                if (_eof) return Eof;
                c = ReadByte();
            }
            else if (c == '%')
            {
                while (c != '\r' && c != '\n') c = ReadByte();
            }
            else
            {
                break;
            }
        }

        switch (c)
        {
            case (byte)'<':
                if (ReadByte() == '<') return new PdfKeyword("<<");
                UnreadByte();
                return ReadHexString();
            case (byte)'(':
                return ReadLiteralString();
            case (byte)'[':
            case (byte)']':
            case (byte)'{':
            case (byte)'}':
                return new PdfKeyword(((char)c).ToString());
            case (byte)'/':
                return ReadName();
            case (byte)'>':
                if (ReadByte() == '>') return new PdfKeyword(">>");
                UnreadByte();
                throw new PdfFormatException("unexpected delimiter '>'");
            default:
                if (IsDelim(c)) throw new PdfFormatException("unexpected delimiter " + (char)c);
                UnreadByte();
                return ReadKeyword();
        }
    }

    private PdfString ReadHexString()
    {
        var tmp = new StringBuilder();
        while (true)
        {
            byte c;
            do { c = ReadByte(); } while (IsSpace(c) && !_eof);
            if (_eof) throw new PdfFormatException("unterminated hex string");
            if (c == '>') break;
            byte c2;
            do { c2 = ReadByte(); } while (IsSpace(c2) && !_eof);
            if (_eof) throw new PdfFormatException("unterminated hex string");
            int x = Unhex(c) << 4 | Unhex(c2);
            if (Unhex(c) < 0 || Unhex(c2) < 0 || x < 0) throw new PdfFormatException("malformed hex string");
            tmp.Append((char)x);
        }
        return new PdfString(tmp.ToString());
    }

    private static int Unhex(byte b)
    {
        if (b >= '0' && b <= '9') return b - '0';
        if (b >= 'a' && b <= 'f') return b - 'a' + 10;
        if (b >= 'A' && b <= 'F') return b - 'A' + 10;
        return -1;
    }

    private PdfString ReadLiteralString()
    {
        var tmp = new StringBuilder();
        int depth = 1;
        while (true)
        {
            byte c = ReadByte();
            if (_eof) throw new PdfFormatException("unterminated string");
            switch (c)
            {
                case (byte)'(':
                    depth++;
                    tmp.Append('(');
                    break;
                case (byte)')':
                    if (--depth == 0) return new PdfString(tmp.ToString());
                    tmp.Append(')');
                    break;
                case (byte)'\\':
                    c = ReadByte();
                    switch (c)
                    {
                        case (byte)'n': tmp.Append('\n'); break;
                        case (byte)'r': tmp.Append('\r'); break;
                        case (byte)'b': tmp.Append('\b'); break;
                        case (byte)'t': tmp.Append('\t'); break;
                        case (byte)'f': tmp.Append('\f'); break;
                        case (byte)'(':
                        case (byte)')':
                        case (byte)'\\':
                            tmp.Append((char)c);
                            break;
                        case (byte)'\r':
                            if (ReadByte() != '\n') UnreadByte();
                            break;
                        case (byte)'\n':
                            break;
                        case >= (byte)'0' and <= (byte)'7':
                            {
                                int x = c - '0';
                                for (int i = 0; i < 2; i++)
                                {
                                    c = ReadByte();
                                    if (c < '0' || c > '7')
                                    {
                                        UnreadByte();
                                        break;
                                    }
                                    x = x * 8 + (c - '0');
                                }
                                if (x > 255) throw new PdfFormatException("invalid octal escape");
                                tmp.Append((char)x);
                                break;
                            }
                        default:
                            throw new PdfFormatException("invalid escape sequence");
                    }
                    break;
                default:
                    tmp.Append((char)c);
                    break;
            }
        }
    }

    private PdfName ReadName()
    {
        var tmp = new StringBuilder();
        while (true)
        {
            byte c = ReadByte();
            if (IsDelim(c) || IsSpace(c))
            {
                UnreadByte();
                break;
            }
            if (c == '#')
            {
                int hi = Unhex(ReadByte()), lo = Unhex(ReadByte());
                if (hi < 0 || lo < 0) throw new PdfFormatException("malformed name");
                tmp.Append((char)(hi << 4 | lo));
                continue;
            }
            tmp.Append((char)c);
        }
        return new PdfName(tmp.ToString());
    }

    private object ReadKeyword()
    {
        var tmp = new StringBuilder();
        while (true)
        {
            byte c = ReadByte();
            if (IsDelim(c) || IsSpace(c))
            {
                UnreadByte();
                break;
            }
            tmp.Append((char)c);
        }
        var s = tmp.ToString();
        if (s == "true") return true;
        if (s == "false") return false;
        if (IsInteger(s))
        {
            if (!long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var x))
                throw new PdfFormatException("invalid integer " + s);
            return x;
        }
        if (IsReal(s))
        {
            if (!double.TryParse(s, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var f))
                throw new PdfFormatException("invalid real " + s);
            return f;
        }
        return new PdfKeyword(s);
    }

    private static bool IsInteger(string s)
    {
        if (s.Length > 0 && (s[0] == '+' || s[0] == '-')) s = s[1..];
        if (s.Length == 0) return false;
        foreach (var c in s)
            if (c < '0' || c > '9') return false;
        return true;
    }

    private static bool IsReal(string s)
    {
        if (s.Length > 0 && (s[0] == '+' || s[0] == '-')) s = s[1..];
        if (s.Length == 0) return false;
        int ndot = 0;
        foreach (var c in s)
        {
            if (c == '.')
            {
                ndot++;
                continue;
            }
            if (c < '0' || c > '9') return false;
        }
        return ndot == 1;
    }

    public object? ReadObject()
    {
        var tok = ReadToken();
        if (tok is PdfKeyword kw)
        {
            switch (kw.Value)
            {
                case "null":
                    return null;
                case "endobj":
                    UnreadToken(tok);
                    return null;
                case "<<":
                    return ReadDict();
                case "[":
                    return ReadArray();
            }
            throw new PdfFormatException("unexpected keyword " + kw.Value + " parsing object");
        }

        if (tok is long t1 && t1 >= 0 && t1 <= uint.MaxValue)
        {
            var tok2 = ReadToken();
            if (tok2 is long t2 && t2 >= 0 && t2 <= ushort.MaxValue)
            {
                var tok3 = ReadToken();
                if (tok3 is PdfKeyword k3)
                {
                    if (k3.Value == "R") return new ObjPtr((uint)t1, (ushort)t2);
                    if (k3.Value == "obj")
                    {
                        var old = CurrentObj;
                        CurrentObj = new ObjPtr((uint)t1, (ushort)t2);
                        var obj = ReadObject();
                        if (obj is not PdfStream)
                        {
                            var tok4 = ReadToken();
                            if (tok4 is not PdfKeyword { Value: "endobj" })
                                throw new PdfFormatException("missing endobj after indirect object definition");
                        }
                        CurrentObj = old;
                        return new ObjDef(new ObjPtr((uint)t1, (ushort)t2), obj);
                    }
                }
                UnreadToken(tok3);
            }
            UnreadToken(tok2);
        }
        if (tok == Eof) throw new PdfFormatException("unexpected EOF parsing object");
        return tok;
    }

    private PdfArray ReadArray()
    {
        var x = new PdfArray();
        while (true)
        {
            var tok = ReadToken();
            if (tok is null || tok is PdfKeyword { Value: "]" }) break;
            if (tok == Eof) throw new PdfFormatException("unexpected EOF in array");
            // ReadObject un-reads endobj without consuming it: inside an array that would never advance.
            if (tok is PdfKeyword { Value: "endobj" }) throw new PdfFormatException("unterminated array");
            UnreadToken(tok);
            x.Add(ReadObject());
        }
        return x;
    }

    private object ReadDict()
    {
        var x = new PdfDict();
        while (true)
        {
            var tok = ReadToken();
            if (tok is null || tok is PdfKeyword { Value: ">>" }) break;
            if (tok is not PdfName n) throw new PdfFormatException("unexpected non-name key parsing dictionary");
            x[n.Value] = ReadObject();
        }

        var next = ReadToken();
        if (next is not PdfKeyword { Value: "stream" })
        {
            UnreadToken(next);
            return x;
        }
        switch (ReadByte())
        {
            case (byte)'\r':
                if (ReadByte() != '\n') UnreadByte();
                break;
            case (byte)'\n':
                break;
            default:
                throw new PdfFormatException("stream keyword not followed by newline");
        }
        return new PdfStream(x, CurrentObj, _pos);
    }

    internal static bool IsSpace(byte b) => b is 0 or (byte)'\t' or (byte)'\n' or (byte)'\f' or (byte)'\r' or (byte)' ';

    internal static bool IsDelim(byte b) =>
        b is (byte)'<' or (byte)'>' or (byte)'(' or (byte)')' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';
}
