using System;
using System.Formats.Asn1;
using System.Text;

namespace GeregeSystems.EidMongolia;

/// <summary>
/// Иргэний гэрчилгээний subject-ийн талбарууд (Go <c>eid.Subject</c>, RFC 5280 / ETSI EN 319 412-2). Гэрчилгээнд
/// байхгүй талбар "". Энэ нь зөвхөн задлалт — гэрчилгээнд итгэх эсэхийг <see cref="ResponseValidator"/> шийднэ:
/// баталгаажаагүй гэрчилгээний нэрэнд бүү итгэ (<see cref="VerifiedIdentity.Subject"/>-ийг ашигла).
/// </summary>
public sealed record CertSubject
{
    /// <summary>GIVENNAME (2.5.4.42), латин (ICAO, том үсэг). Давхардвал эхнийх.</summary>
    public string GivenName { get; init; } = "";

    /// <summary>SURNAME (2.5.4.4), эцэг/эхийн нэр, латин. Давхардвал эхнийх.</summary>
    public string Surname { get; init; } = "";

    /// <summary>CN (2.5.4.3). Давхардвал сүүлийнх (Go pkix.Name).</summary>
    public string CommonName { get; init; } = "";

    /// <summary>
    /// SERIALNUMBER (2.5.4.5): ETSI таних тэмдэг, ж: PNOMN-&lt;иргэний дугаар&gt; / NTRMN-&lt;бүртгэл&gt;. Давхардвал
    /// сүүлийнх (Go pkix.Name).
    /// </summary>
    public string SerialNumber { get; init; } = "";

    /// <summary>C (2.5.4.6), ж: MN. Давхардвал эхнийх.</summary>
    public string Country { get; init; } = "";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// DER Name (RDNSequence)-ээс талбаруудыг задална. Утгын төрөл ба тэмдэгт нь Go x509 parseName-ийн дүрэмтэй ижил
    /// (UTF8String, PrintableString, IA5String, NumericString, T61String, BMPString); бусад нь <see cref="FormatException"/>.
    /// </summary>
    internal static CertSubject FromName(byte[] rawName)
    {
        var top = new AsnReader(rawName, AsnEncodingRules.DER);
        var seq = top.ReadSequence();
        top.ThrowIfNotEmpty();
        string? given = null, surname = null, country = null;
        string cn = "", serial = "";
        while (seq.HasData)
        {
            var set = seq.ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                var atv = set.ReadSequence();
                var oid = atv.ReadObjectIdentifier();
                var tag = atv.PeekTag();
                var full = atv.ReadEncodedValue();
                atv.ThrowIfNotEmpty();
                if (!AsnDecoder.TryReadEncodedValue(full.Span, AsnEncodingRules.DER, out _, out var off, out var len, out _))
                {
                    throw new FormatException("x509: Name-ийн утга буруу");
                }
                var value = Decode(tag, full.Span.Slice(off, len));
                switch (oid)
                {
                    case "2.5.4.3":
                        cn = value;
                        break;
                    case "2.5.4.5":
                        serial = value;
                        break;
                    case "2.5.4.6":
                        country ??= value;
                        break;
                    case "2.5.4.42":
                        given ??= value;
                        break;
                    case "2.5.4.4":
                        surname ??= value;
                        break;
                }
            }
        }
        return new CertSubject
        {
            GivenName = given ?? "",
            Surname = surname ?? "",
            CommonName = cn,
            SerialNumber = serial,
            Country = country ?? "",
        };
    }

    /// <summary>
    /// DER Name-д SERIALNUMBER (2.5.4.5) эсвэл CN (2.5.4.3) нэгээс олон удаа байгаа эсэх (бүх RDN-ийн бүх atv; Name-ийг
    /// <see cref="FromName"/> аль хэдийн шалгасан).
    /// </summary>
    internal static bool HasDuplicateIdentity(byte[] rawName)
    {
        var top = new AsnReader(rawName, AsnEncodingRules.DER);
        var seq = top.ReadSequence();
        int serials = 0, cns = 0;
        while (seq.HasData)
        {
            var set = seq.ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                var atv = set.ReadSequence();
                switch (atv.ReadObjectIdentifier())
                {
                    case "2.5.4.3":
                        cns++;
                        break;
                    case "2.5.4.5":
                        serials++;
                        break;
                }
                atv.ReadEncodedValue();
            }
        }
        return serials > 1 || cns > 1;
    }

    /// <summary>Go x509 parseASN1String.</summary>
    private static string Decode(Asn1Tag tag, ReadOnlySpan<byte> v)
    {
        if (tag.TagClass != TagClass.Universal || tag.IsConstructed)
        {
            throw new FormatException("x509: Name-ийн утга мөр биш");
        }
        switch ((UniversalTagNumber)tag.TagValue)
        {
            case UniversalTagNumber.UTF8String:
                return StrictUtf8.GetString(v);
            case UniversalTagNumber.PrintableString:
                foreach (var b in v)
                {
                    if (!IsPrintable(b))
                    {
                        throw new FormatException("x509: PrintableString буруу");
                    }
                }
                return Encoding.Latin1.GetString(v);
            case UniversalTagNumber.IA5String:
                foreach (var b in v)
                {
                    if (b >= 0x80)
                    {
                        throw new FormatException("x509: IA5String буруу");
                    }
                }
                return Encoding.Latin1.GetString(v);
            case UniversalTagNumber.NumericString:
                foreach (var b in v)
                {
                    if (b is not ((>= (byte)'0' and <= (byte)'9') or (byte)' '))
                    {
                        throw new FormatException("x509: NumericString буруу");
                    }
                }
                return Encoding.Latin1.GetString(v);
            case UniversalTagNumber.T61String:
                return Encoding.Latin1.GetString(v);
            case UniversalTagNumber.BMPString:
                if (v.Length % 2 != 0)
                {
                    throw new FormatException("x509: BMPString урт сондгой");
                }
                if (v.Length >= 2 && v[^1] == 0 && v[^2] == 0)
                {
                    v = v[..^2];
                }
                return Encoding.BigEndianUnicode.GetString(v);
            default:
                throw new FormatException("x509: дэмжигдээгүй мөрийн төрөл " + tag.TagValue);
        }
    }

    /// <summary>Go x509 isPrintable (PrintableString + '*', '&amp;' нийцлийн үүднээс).</summary>
    private static bool IsPrintable(byte b) =>
        b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'0' and <= (byte)'9') or
            (>= (byte)'\'' and <= (byte)')') or (>= (byte)'+' and <= (byte)'/') or (byte)' ' or (byte)':' or (byte)'=' or
            (byte)'?' or (byte)'*' or (byte)'&';
}
