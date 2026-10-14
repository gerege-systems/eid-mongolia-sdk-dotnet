using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Pades.Crypto;
using GeregeSystems.EidMongolia.Pades.Pdf;

namespace GeregeSystems.EidMongolia.Pades;

/// <summary>
/// eID client-side PAdES (профайл <c>pades-client/1</c>). PDF клиентээс гарахгүй: <see cref="Prepare"/> → 32 байт DTBS-ийг
/// утас/токеноор зуруулах → <see cref="CompleteAsync"/> → PAdES-BASELINE-LT PDF. Go reference-тэй байт-ижил. Thread-safe.
/// </summary>
public static class EidPades
{
    /// <summary>PDF/CMS профайлын хувилбар.</summary>
    public const string ProfileVersion = "pades-client/1";

    /// <summary>Нийтийн RFC 3161 TSA.</summary>
    public const string DefaultTsaUrl = "https://tsa.timeserver.mn/";

    /// <summary>Prepare-ийн оролтын дээд хэмжээ (10 MiB − 256 KiB).</summary>
    public const int MaxInputBytes = MaxOutputBytes - (256 << 10);

    /// <summary>Гаралтын дээд хэмжээ (10 MiB).</summary>
    public const int MaxOutputBytes = 10 << 20;

    /// <summary>Нэг баримтын гарын үсгийн дээд тоо.</summary>
    public const int MaxSignatures = 16;

    internal const string PageVerifyUrl = "https://ca.eidmongolia.mn/verify/";
    private const string PageBrand = "eID Mongolia";
    private const string PageTrustUrl = "https://eidmongolia.mn/trust";
    private const string PageTsaName = "eID Mongolia TSA (tsa.timeserver.mn)";
    private const string PageProvider = "ca.eidmongolia.mn";
    private const int MaxFileName = 120;
    private static readonly TimeSpan SigningZone = TimeSpan.FromHours(8);
    private static readonly Regex UuidRe = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.CultureInvariant);

    internal static bool IsUuid(string s) => UuidRe.IsMatch(s);

    /// <summary>
    /// PDF-д гарын үсгийн revision (placeholder) бичиж, иргэний зурах DTBS-ийг буцаана. Сүлжээ ашиглахгүй.
    /// </summary>
    /// <exception cref="EidPadesException">PRECHECKS (PDF_INVALID, PDF_ENCRYPTED, PDF_LOCKED, …), SIGNER_INVALID, REQUEST_INVALID.</exception>
    public static PreparedDocument Prepare(byte[] pdf, PrepareOptions options)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        ArgumentNullException.ThrowIfNull(options);
        if (pdf.Length > MaxInputBytes) throw new EidPadesException("PDF_TOO_LARGE", "PDF is larger than 9.75 MiB");
        if (!pdf.AsSpan().StartsWith("%PDF-"u8)) throw new EidPadesException("PDF_INVALID", "not a PDF or damaged");

        X509Certificate2 cert;
        List<X509Certificate2> chain;
        try
        {
            cert = X509Util.Parse(options.SignerCert ?? Array.Empty<byte>());
        }
        catch (FormatException e)
        {
            throw new EidPadesException("SIGNER_INVALID", "signerCert could not be parsed", e);
        }
        if (!Cms.IsRsa(cert) && !Cms.IsEc(cert)) throw new EidPadesException("SIGNER_INVALID", "unsupported key type (RSA or ECDSA)");
        try
        {
            chain = Trust.SignerChain(cert, options.Chain);
        }
        catch (FormatException e)
        {
            throw new EidPadesException("SIGNER_INVALID", "issuer chain: " + e.Message, e);
        }
        if (!string.IsNullOrEmpty(options.DocId) && !IsUuid(options.DocId))
            throw new EidPadesException("REQUEST_INVALID", "docId must be a lowercase UUID");
        if (!string.IsNullOrEmpty(options.Lang) && options.Lang is not ("mn" or "en"))
            throw new EidPadesException("REQUEST_INVALID", "lang: mn | en");
        var now = (options.SigningTime ?? DateTimeOffset.UtcNow).ToOffset(SigningZone);

        var inHex = PrepState.Hex(SHA256.HashData(pdf));
        var issuers = new List<X509Certificate2>(Trust.Issuers) { chain[0] };
        var (newDoc, revIndex) = Prechecks.Run(pdf, issuers);
        var docId = options.DocId ?? "";
        byte[] baseBytes = pdf;
        string pageHex = "";
        bool hasPage = newDoc && options.VerifyPage;
        if (!newDoc)
        {
            var fromPage = Prechecks.DocIdFromPage(pdf);
            if (fromPage != "")
            {
                if (docId != "" && docId != fromPage) throw new EidPadesException("REQUEST_INVALID", "docId does not match the document page");
                docId = fromPage;
            }
        }
        if (newDoc && docId == "") docId = RandUuid();
        if (hasPage)
        {
            var fileName = CleanFileName(options.FileName ?? "") ?? throw new EidPadesException("REQUEST_INVALID", "fileName is required, ≤ 120 characters");
            try
            {
                baseBytes = VerifyPage.Append(pdf, new PageData(PageBrand, fileName, inHex, pdf.Length, docId, PageVerifyUrl + docId, PageTrustUrl,
                    IssuerCommonName(cert), PageTsaName, PageProvider, options.Lang ?? ""));
            }
            catch (Exception e) when (Prechecks.IsParseError(e))
            {
                throw new EidPadesException("PDF_INVALID", "could not add the verification page", e);
            }
            pageHex = PrepState.Hex(SHA256.HashData(baseBytes));
        }
        var name = options.SignerName;
        if (string.IsNullOrWhiteSpace(name) || GoText.TrimSpace(name) == "") name = SignerDisplayName(cert);
        PreparedRevision prep;
        try
        {
            prep = SignatureRevision.Prepare(baseBytes, now, name, options.Reason ?? "");
        }
        catch (Exception e) when (Prechecks.IsParseError(e))
        {
            throw new EidPadesException("PDF_INVALID", "could not write the signature revision", e);
        }
        if (prep.Pdf.Length + (256 << 10) > MaxOutputBytes) throw new EidPadesException("PDF_TOO_LARGE", "signed output would exceed 10 MiB");
        var attrs = Cms.SignedAttributes(prep.Digest, cert, options.ClaimedRole);
        var st = new PrepState
        {
            DocId = docId,
            SignerCert = cert.RawData,
            SignedAttrs = attrs,
            ByteRange = prep.ByteRange,
            RevIndex = revIndex,
            InSha256 = inHex,
            HasPage = hasPage,
            PageSha256 = pageHex,
            ClaimedRole = options.ClaimedRole ?? "",
            Pdf = prep.Pdf,
            PreparedSha256 = PrepState.Hex(SHA256.HashData(prep.Pdf)),
        };
        foreach (var c in chain) st.Chain.Add(c.RawData);
        return new PreparedDocument { Dtbs = Cms.Dtbs(attrs), Digest = prep.Digest, DocId = docId, State = st.Encode() };
    }

    /// <summary>
    /// Гарын үсгийг DTBS дээр шалгаад RFC 3161 timestamp → CMS → embed → OCSP/CRL (genTime-ийн дараа) → DSS revision.
    /// </summary>
    /// <param name="state"><see cref="PreparedDocument.State"/>.</param>
    /// <param name="signature">RSA PKCS#1 v1.5, ECDSA r‖s эсвэл DER — гэрчилгээний түлхүүрээр автоматаар.</param>
    /// <param name="options">TSA, итгэлийн тулгуур, HTTP, цаг; <c>null</c> = анхдагч.</param>
    /// <param name="cancellationToken">Сүлжээний хүсэлт ба хүлээлтийг тасална.</param>
    /// <exception cref="EidPadesException">STATE_INVALID, SIGNATURE_INVALID, TSA_UNAVAILABLE, LTV_UNAVAILABLE, PLACEHOLDER_OVERFLOW, …</exception>
    public static async Task<Completed> CompleteAsync(byte[] state, byte[] signature, CompleteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(signature);
        var o = options ?? new CompleteOptions();
        PrepState st;
        X509Certificate2 cert;
        List<X509Certificate2> chain;
        try
        {
            st = PrepState.Decode(state);
            cert = X509Util.Parse(st.SignerCert);
            chain = Trust.ParseAll(st.Chain);
        }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException)
        {
            throw new EidPadesException("STATE_INVALID", "state could not be decoded", e);
        }
        if (chain.Count == 0) throw new EidPadesException("STATE_INVALID", "state chain is empty");
        List<X509Certificate2> roots;
        try
        {
            roots = o.Roots is { Count: > 0 } ? Trust.ParseAll(o.Roots) : new List<X509Certificate2> { Trust.NationalRoot };
        }
        catch (FormatException e)
        {
            throw new EidPadesException("REQUEST_INVALID", "roots", e);
        }
        var time = o.TimeProvider ?? TimeProvider.System;
        DateTimeOffset Now() => time.GetUtcNow();
        var sleep = o.Sleep ?? ((d, ct) => Task.Delay(d, time, ct));
        var tsaUrl = string.IsNullOrEmpty(o.TsaUrl) ? DefaultTsaUrl : o.TsaUrl;

        var sig = CitizenSignature(cert, Cms.Dtbs(st.SignedAttrs), signature)
                  ?? throw new EidPadesException("SIGNATURE_INVALID", "signature does not match the DTBS");

        using var f = new Fetcher(o.HttpClient);
        TimestampResult ts;
        try
        {
            var nonce = o.NonceSource?.Invoke() ?? RandomNumberGenerator.GetBytes(8);
            ts = await Tsa.TimestampAsync(f, tsaUrl, sig, roots, chain, Now(), nonce, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or FormatException or AsnContentException or CryptographicException ||
                                  e is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new EidPadesException("TSA_UNAVAILABLE", "could not obtain a TSA timestamp: " + e.Message, e);
        }
        var cms = Cms.Assemble(st.SignedAttrs, cert, chain, sig, ts.RawToken);
        byte[] signed;
        try
        {
            signed = SignatureRevision.EmbedCms(st.Pdf, st.ByteRange, cms);
        }
        catch (InvalidOperationException e)
        {
            throw new EidPadesException("STATE_INVALID", "could not embed the CMS", e);
        }
        var citizenChain = new List<X509Certificate2> { cert };
        citizenChain.AddRange(chain);
        DssData dss;
        try
        {
            dss = await Ltv.CollectWithWaitAsync(f, Now, sleep, ts.Time, roots, cancellationToken, citizenChain, ts.Certificates).ConfigureAwait(false);
        }
        catch (LtvException e)
        {
            throw new EidPadesException("LTV_UNAVAILABLE", "could not collect complete OCSP/CRL data: " + e.Message, e);
        }
        byte[] outPdf;
        try
        {
            dss.Contents = SignatureRevision.SignatureContents(signed, st.ByteRange);
            outPdf = Dss.Append(signed, dss);
        }
        catch (Exception e) when (Prechecks.IsParseError(e))
        {
            throw new EidPadesException("SELF_VALIDATION_FAILED", "could not write the DSS revision", e);
        }
        if (outPdf.Length > MaxOutputBytes) throw new EidPadesException("PDF_TOO_LARGE", "output exceeds 10 MiB");

        var prior = SelfCheck(outPdf, st);
        return new Completed
        {
            Pdf = outPdf,
            DocId = st.DocId,
            Cms = cms,
            OutSha256 = PrepState.Hex(SHA256.HashData(outPdf)),
            InSha256 = st.InSha256,
            HasPage = st.HasPage,
            PageSha256 = st.PageSha256,
            SignerCert = cert.RawData,
            RevIndex = st.RevIndex,
            SigRevSha256 = PrepState.Hex(SHA256.HashData(signed)),
            PriorCmsSha256 = prior,
        };
    }

    /// <summary>
    /// Хөнгөн self-check (бүрэн validator-гүй): гаралтын гарын үсгийн тоо = revIndex, шинэ гарын үсэг криптограф хүчинтэй, /DSS
    /// бий. Өмнөх гарын үсгүүдийн CMS-ийн SHA-256-ийг (баримтын дарааллаар) буцаана.
    /// </summary>
    private static List<string> SelfCheck(byte[] outPdf, PrepState st)
    {
        try
        {
            var (sigs, _, hasDss) = Prechecks.Scan(outPdf);
            sigs.RemoveAll(s => s.Type != "" && s.Type != "Sig");
            if (sigs.Count != st.RevIndex || !hasDss) throw new FormatException("signature count / DSS");
            Prechecks.CheckSignature(outPdf, sigs[^1]);
            var prior = new List<string>();
            for (int i = 0; i < sigs.Count - 1; i++)
            {
                var der = Prechecks.FirstSequence(Latin1.ToBytes(sigs[i].ContentsRaw));
                if (der is not null) prior.Add(PrepState.Hex(SHA256.HashData(der)));
            }
            return prior;
        }
        catch (Exception e) when (Prechecks.IsParseError(e) || e is CryptographicException or AsnContentException)
        {
            throw new EidPadesException("SELF_VALIDATION_FAILED", "output failed the self-check: " + e.Message, e);
        }
    }

    /// <summary>DTBS дээрх гарын үсгийг шалгаж CMS-д бичих хэлбэрээр (RSA хэвээр, ECDSA DER) буцаана; таарахгүй бол null.</summary>
    private static byte[]? CitizenSignature(X509Certificate2 cert, byte[] dtbs, byte[] sig)
    {
        try
        {
            if (Cms.IsRsa(cert))
            {
                using var rsa = cert.GetRSAPublicKey()!;
                return rsa.VerifyHash(dtbs, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) ? sig : null;
            }
            if (Cms.IsEc(cert))
            {
                using var ec = cert.GetECDsaPublicKey()!;
                int n = (ec.KeySize + 7) / 8;
                if (sig.Length == 2 * n && ec.VerifyHash(dtbs, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                {
                    var r = new BigInteger(sig.AsSpan(0, n), isUnsigned: true, isBigEndian: true);
                    var s = new BigInteger(sig.AsSpan(n), isUnsigned: true, isBigEndian: true);
                    return Der.Seq(Der.Integer(r), Der.Integer(s));
                }
                return ec.VerifyHash(dtbs, sig, DSASignatureFormat.Rfc3279DerSequence) ? sig : null;
            }
        }
        catch (CryptographicException)
        {
        }
        return null;
    }

    private static string RandUuid()
    {
        var b = RandomNumberGenerator.GetBytes(16);
        b[6] = (byte)(b[6] & 0x0f | 0x40);
        b[8] = (byte)(b[8] & 0x3f | 0x80);
        var h = PrepState.Hex(b);
        return h[..8] + "-" + h[8..12] + "-" + h[12..16] + "-" + h[16..20] + "-" + h[20..];
    }

    /// <summary>CA-тай ижил: Cc/Cf/Zl/Zp (ба буруу UTF-16) хасаж NFC, trim; 1–120 тэмдэгт; эс бөгөөс null.</summary>
    internal static string? CleanFileName(string s)
    {
        var b = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsSurrogate(s[i]))
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    var cat = CharUnicodeInfo.GetUnicodeCategory(char.ConvertToUtf32(s[i], s[i + 1]));
                    if (!IsDropped(cat)) b.Append(s[i]).Append(s[i + 1]);
                    i++;
                }
                continue;
            }
            if (s[i] == '�' || IsDropped(CharUnicodeInfo.GetUnicodeCategory(s[i]))) continue;
            b.Append(s[i]);
        }
        var o = GoText.TrimSpace(b.ToString().Normalize(NormalizationForm.FormC));
        int runes = 0;
        foreach (var _ in o.EnumerateRunes()) runes++;
        return o == "" || runes > MaxFileName ? null : o;
    }

    private static bool IsDropped(System.Globalization.UnicodeCategory c) =>
        c is System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format
            or System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator;

    private static string IssuerCommonName(X509Certificate2 c) => LastAttr(c.IssuerName, "2.5.4.3");

    /// <summary>Гэрчилгээний GIVENNAME SURNAME (бичигдсэнээрээ); хоосон бол CN.</summary>
    internal static string SignerDisplayName(X509Certificate2 c)
    {
        var name = GoText.TrimSpace(LastAttr(c.SubjectName, "2.5.4.42") + " " + LastAttr(c.SubjectName, "2.5.4.4"));
        return name != "" ? name : LastAttr(c.SubjectName, "2.5.4.3");
    }

    private static string LastAttr(X500DistinguishedName dn, string oid)
    {
        string v = "";
        foreach (var rdn in dn.EnumerateRelativeDistinguishedNames(reversed: false))
        {
            if (rdn.HasMultipleElements) continue;
            if (rdn.GetSingleElementType().Value == oid) v = rdn.GetSingleElementValue() ?? "";
        }
        return v;
    }
}
