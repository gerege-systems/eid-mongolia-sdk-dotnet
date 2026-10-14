using System;
using System.Collections.Generic;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

// PDF-ийн объектын загвар — Go reference-ийн задлагч (github.com/digitorus/pdf, rsc.io/pdf-ийн fork)-ийн семантикийг
// яг давтана: string/name нь түүхий байт (Latin-1 string-ээр — тэмдэгт бүр = нэг байт), dict-д null утгатай түлхүүр
// хадгалагдана, давхардсан түлхүүрийн сүүлийнх нь ялна, Keys() нь байтаар эрэмбэлэгдэнэ.

internal readonly record struct ObjPtr(uint Id, ushort Gen);

internal sealed record PdfName(string Value);

internal sealed record PdfKeyword(string Value);

internal sealed record PdfString(string Raw);

internal sealed class PdfDict : Dictionary<string, object?>
{
    public PdfDict() : base(StringComparer.Ordinal) { }
}

internal sealed class PdfArray : List<object?>
{
}

internal sealed record PdfStream(PdfDict Header, ObjPtr Ptr, long Offset);

internal sealed record ObjDef(ObjPtr Ptr, object? Obj);

/// <summary>Задлагчийн алдаа (Go-д panic/error) — API-ийн хил дээр PDF_INVALID болно.</summary>
internal sealed class PdfFormatException : Exception
{
    public PdfFormatException(string message, Exception? inner = null) : base(message, inner) { }
}

internal static class Latin1
{
    public static readonly Encoding Encoding = Encoding.Latin1;

    public static string FromBytes(ReadOnlySpan<byte> b) => Encoding.GetString(b);

    public static byte[] ToBytes(string s) => Encoding.GetBytes(s);
}
