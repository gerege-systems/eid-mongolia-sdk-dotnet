using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using GeregeSystems.EidMongolia.Qr;
using Xunit;

namespace GeregeSystems.EidMongolia.Pades.Tests;

/// <summary>
/// «Миний QR» (гэрээ myqr-2026-10-26): тест дотор үүсгэсэн PKI (root → CA → навч, QcStatements) дээр §7-ийн
/// кейсүүд, stub RP-API-ийн client тест, CA-ийн testdata/myqr_vectors.json (байвал) vector runner.
/// </summary>
public class QrTests
{
    /// <summary>CA репогийн myqr_vectors.json-ийн SHA-256 — файлыг хуулахдаа энд тогтооно (хоосон = хараахан ирээгүй).</summary>
    private const string MYQR_VECTORS_SHA256 = "";

    private const string RpUuid = "6f1c2a9e-1b7d-4c2e-9a51-3d8e5b7c9f01";
    private const string Sid = "3f0d4a52-8e1b-4f6a-b0c7-2d9e1a5b7c33";
    private const string Nonce = "order-1042";
    private const string RpName = "Demo Bank";
    private const string Etsi = "PNOMN-000000000001";
    private const string Tok = "q9Xk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiM";

    private static readonly Lazy<Pki> P = new(() => new Pki());

    // ---------------------------------------------------------------- test PKI

    private sealed class Pki
    {
        public readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public readonly X509Certificate2 Root, Ca, Leaf, Auth, Revoked, Expired, OtherRoot, OtherCa, OtherLeaf;
        public readonly RSA LeafKey, AuthKey, RevokedKey, ExpiredKey, OtherLeafKey;

        public Pki()
        {
            var nb = Now.AddDays(-1);
            var na = Now.AddYears(1);
            var rootKey = RSA.Create(2048);
            Root = Issue(Dn("C=MN", "CN=MyQR Test Root"), rootKey, null, null, nb, na, 1, ca: true);
            var caKey = RSA.Create(2048);
            Ca = Issue(Dn("C=MN", "CN=MyQR Test Issuing CA"), caKey, Root, rootKey, nb, na, 2, ca: true);
            LeafKey = RSA.Create(2048);
            Leaf = Issue(Citizen(Etsi), LeafKey, Ca, caKey, nb, na, 0x10, ca: false, sign: true);
            AuthKey = RSA.Create(2048);
            Auth = Issue(Citizen(Etsi), AuthKey, Ca, caKey, nb, na, 0x11, ca: false, sign: false);
            RevokedKey = RSA.Create(2048);
            Revoked = Issue(Citizen(Etsi), RevokedKey, Ca, caKey, nb, na, 0x12, ca: false, sign: true);
            ExpiredKey = RSA.Create(2048);
            Expired = Issue(Citizen(Etsi), ExpiredKey, Ca, caKey, Now.AddDays(-30), Now.AddDays(-2), 0x13, ca: false, sign: true);
            var otherRootKey = RSA.Create(2048);
            OtherRoot = Issue(Dn("C=MN", "CN=Other Root"), otherRootKey, null, null, nb, na, 3, ca: true);
            var otherCaKey = RSA.Create(2048);
            OtherCa = Issue(Dn("C=MN", "CN=Other Issuing CA"), otherCaKey, OtherRoot, otherRootKey, nb, na, 4, ca: true);
            OtherLeafKey = RSA.Create(2048);
            OtherLeaf = Issue(Citizen(Etsi), OtherLeafKey, OtherCa, otherCaKey, nb, na, 0x14, ca: false, sign: true);
        }

        public string Ski(X509Certificate2 c) => c.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First().SubjectKeyIdentifier!.ToLowerInvariant();

        private static X500DistinguishedName Dn(params string[] rdns) => new(string.Join(", ", rdns));

        private static X500DistinguishedName Citizen(string serial)
        {
            var b = new X500DistinguishedNameBuilder();
            b.AddCountryOrRegion("MN");
            b.Add("2.5.4.4", "DORJ", UniversalTagNumber.UTF8String);
            b.Add("2.5.4.42", "BAT", UniversalTagNumber.UTF8String);
            b.Add("2.5.4.5", serial, UniversalTagNumber.PrintableString);
            b.AddCommonName("DORJ BAT");
            return b.Build();
        }

        private static byte[] QcStatements()
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("0.4.0.1862.1.1"); // QcCompliance
                }
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("0.4.0.1862.1.6"); // QcType
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier("0.4.0.1862.1.6.1"); // esign
                    }
                }
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("0.4.0.1862.1.7"); // QcCClegislation
                    using (w.PushSequence())
                    {
                        w.WriteCharacterString(UniversalTagNumber.PrintableString, "MN");
                    }
                }
            }
            return w.Encode();
        }

        private static X509Certificate2 Issue(X500DistinguishedName subject, RSA key, X509Certificate2? issuer, RSA? issuerKey,
            DateTimeOffset nb, DateTimeOffset na, byte serial, bool ca, bool sign = false)
        {
            var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var ski = new X509SubjectKeyIdentifierExtension(req.PublicKey, false);
            req.CertificateExtensions.Add(ski);
            if (ca)
            {
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            }
            else
            {
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(sign
                    ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation
                    : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                if (sign)
                {
                    req.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.3", QcStatements(), false));
                }
            }
            if (issuer is null)
            {
                return new X509Certificate2(req.CreateSelfSigned(nb, na).RawData);
            }
            var issuerSki = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First().SubjectKeyIdentifierBytes.Span;
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSki));
            var gen = X509SignatureGenerator.CreateForRSA(issuerKey!, RSASignaturePadding.Pkcs1);
            using var c = req.Create(issuer.SubjectName, gen, nb, na, new byte[] { 0x01, serial });
            return new X509Certificate2(c.RawData);
        }
    }

    // ---------------------------------------------------------------- JWS builder

    private static string B64U(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static readonly JsonSerializerOptions Raw = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private static string Header(X509Certificate2 leaf, X509Certificate2 inter) =>
        "{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + Convert.ToBase64String(leaf.RawData) + "\",\"" +
        Convert.ToBase64String(inter.RawData) + "\"]}";

    private static JsonObject Payload(long iat, string sid = Sid, string nonce = Nonce, string aud = RpUuid, JsonObject? data = null) => new()
    {
        ["iss"] = EidQr.DefaultIssuer,
        ["sub"] = Etsi,
        ["aud"] = aud,
        ["rp_name"] = RpName,
        ["sid"] = sid,
        ["nonce"] = nonce,
        ["iat"] = iat,
        ["exp"] = iat + 300,
        ["statement"] = "Та " + RpName + "-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна",
        ["data"] = data ?? new JsonObject
        {
            ["source"] = "citizenid",
            ["fields"] = new JsonObject { ["reg_no"] = "УБ90010112", ["given_name"] = "Бат", ["surname"] = "Дорж", ["birth_date"] = "1990-01-01" },
        },
    };

    /// <summary>Go encoding/json шиг &lt; &gt; &amp;-ийг escape хийсэн payload.</summary>
    private static string PayloadJson(JsonObject p) =>
        p.ToJsonString(Raw).Replace("<", "\\u003c", StringComparison.Ordinal).Replace(">", "\\u003e", StringComparison.Ordinal)
            .Replace("&", "\\u0026", StringComparison.Ordinal);

    private static string Sign(string header, string payloadJson, RSA key, RSASignaturePadding? pad = null)
    {
        var input = B64U(Encoding.UTF8.GetBytes(header)) + "." + B64U(Encoding.UTF8.GetBytes(payloadJson));
        return input + "." + B64U(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, pad ?? RSASignaturePadding.Pss));
    }

    private static string Jws(JsonObject? payload = null, X509Certificate2? leaf = null, RSA? key = null, X509Certificate2? inter = null) =>
        Sign(Header(leaf ?? P.Value.Leaf, inter ?? P.Value.Ca), PayloadJson(payload ?? Payload(P.Value.Now.ToUnixTimeSeconds() - 10)), key ?? P.Value.LeafKey);

    private static Func<X509Certificate2, X509Certificate2?, Task<string>> Stub(Dictionary<string, string> m) =>
        (leaf, _) => Task.FromResult(m.TryGetValue(EidQr.SerialHex(leaf), out var s) ? s : "unknown");

    private static QrTrust TrustWith(Dictionary<string, string>? rev = null, bool soft = false, string? ski = null) => new(
        Anchors: new[] { P.Value.Root },
        Intermediates: Array.Empty<X509Certificate2>(),
        AllowedIssuerSkis: new[] { ski ?? P.Value.Ski(P.Value.Ca) },
        Revocation: Stub(rev ?? GoodAll()),
        RevocationSoftFail: soft);

    private static Dictionary<string, string> GoodAll() => new()
    {
        [EidQr.SerialHex(P.Value.Leaf)] = "good",
        [EidQr.SerialHex(P.Value.Auth)] = "good",
        [EidQr.SerialHex(P.Value.Expired)] = "good",
        [EidQr.SerialHex(P.Value.OtherLeaf)] = "good",
        [EidQr.SerialHex(P.Value.Revoked)] = "revoked",
    };

    private static QrExpect Expect(DateTimeOffset? now = null, string rp = RpUuid, string sid = Sid, string nonce = Nonce) =>
        new(rp, sid, nonce, null, now ?? P.Value.Now);

    // ---------------------------------------------------------------- §7 кейсүүд

    private sealed record Case(string Name, Func<string> Jws, string? Error, Func<QrExpect>? Exp = null, Func<QrTrust>? Trust = null);

    private static IEnumerable<Case> Cases()
    {
        var p = P.Value;
        long iat = p.Now.ToUnixTimeSeconds() - 10;
        JsonObject Pl(Action<JsonObject> m)
        {
            var o = Payload(iat);
            m(o);
            return o;
        }
        JsonObject Data(Action<JsonObject> m) => Pl(o => m(o["data"]!.AsObject()));
        JsonObject Fields(Action<JsonObject> m) => Data(d => m(d["fields"]!.AsObject()));
        string Hdr(string h) => Sign(h, PayloadJson(Payload(iat)), p.LeafKey);
        var leafB64 = Convert.ToBase64String(p.Leaf.RawData);
        var caB64 = Convert.ToBase64String(p.Ca.RawData);

        yield return new("ok_basic", () => Jws(), null);
        yield return new("ok_unicode", () => Jws(Fields(f =>
        {
            f["note"] = "<b>Тест & 😀</b>";
            f["Өргөн"] = "Үүрийн";
        })), null);
        yield return new("ok_aud_uppercase_expect", () => Jws(), null, () => Expect(rp: RpUuid.ToUpperInvariant()));
        yield return new("ok_skew_edge", () => Jws(), null, () => Expect(DateTimeOffset.FromUnixTimeSeconds(iat + 300 + 59)));
        yield return new("ok_source_unknown", () => Jws(Data(d => d["source"] = "unknown")), null);
        yield return new("ok_photo_only", () => Jws(Data(d =>
        {
            d["fields"] = new JsonObject();
            d["photo"] = Convert.ToBase64String(Jpeg(64));
        })), null);
        yield return new("malformed_segments", () => "eyJhIjoxfQ.eyJiIjoyfQ", EidQrErrorCodes.JwsMalformed);
        yield return new("malformed_bad_char", () => Jws() + "=", EidQrErrorCodes.JwsMalformed);
        yield return new("header_extra_kid", () => Hdr("{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"kid\":\"k\",\"x5c\":[\"" + leafB64 + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("header_alg_rs256", () => Hdr("{\"alg\":\"RS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + leafB64 + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("header_alg_none", () => Hdr("{\"alg\":\"none\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + leafB64 + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("header_typ_jwt", () => Hdr("{\"alg\":\"PS256\",\"typ\":\"JWT\",\"x5c\":[\"" + leafB64 + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("header_duplicate_alg", () => Hdr("{\"alg\":\"PS256\",\"alg\":\"PS256\",\"x5c\":[\"" + leafB64 + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("x5c_single", () => Hdr("{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + leafB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("x5c_garbage", () => Hdr("{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + Convert.ToBase64String(new byte[] { 1, 2, 3 }) + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("x5c_base64url", () => Hdr("{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + B64U(p.Leaf.RawData) + "\",\"" + caB64 + "\"]}"), EidQrErrorCodes.HeaderInvalid);
        yield return new("chain_other_root", () => Jws(leaf: p.OtherLeaf, key: p.OtherLeafKey, inter: p.OtherCa), EidQrErrorCodes.ChainInvalid);
        yield return new("chain_x5c1_is_root_only", () => Jws(inter: p.OtherRoot), EidQrErrorCodes.ChainInvalid);
        yield return new("chain_issuer_not_allowed", () => Jws(), EidQrErrorCodes.ChainInvalid, null, () => TrustWith(ski: p.Ski(p.Root)));
        yield return new("leaf_auth_profile", () => Jws(leaf: p.Auth, key: p.AuthKey), EidQrErrorCodes.ChainInvalid);
        yield return new("leaf_expired", () => Jws(leaf: p.Expired, key: p.ExpiredKey), EidQrErrorCodes.ChainInvalid);
        yield return new("leaf_revoked", () => Jws(leaf: p.Revoked, key: p.RevokedKey), EidQrErrorCodes.CertRevoked);
        yield return new("revocation_unknown", () => Jws(), EidQrErrorCodes.RevocationUnknown, null, () => TrustWith(new Dictionary<string, string>()));
        yield return new("revocation_unknown_soft_fail", () => Jws(), null, null, () => TrustWith(new Dictionary<string, string>(), soft: true));
        yield return new("revocation_throws", () => Jws(), EidQrErrorCodes.RevocationUnknown, null,
            () => TrustWith() with { Revocation = (_, _) => throw new HttpRequestException("ocsp down") });
        yield return new("revocation_default_no_aia", () => Jws(), EidQrErrorCodes.RevocationUnknown, null, () => TrustWith() with { Revocation = null });
        yield return new("revocation_default_no_aia_soft", () => Jws(), null, null, () => TrustWith() with { Revocation = null, RevocationSoftFail = true });
        yield return new("bad_signature", () =>
        {
            var j = Jws();
            var i = j.LastIndexOf('.') + 5;
            return j[..i] + (j[i] == 'A' ? 'B' : 'A') + j[(i + 1)..];
        }, EidQrErrorCodes.SignatureInvalid);
        yield return new("signature_pkcs1v15", () => Sign(Header(p.Leaf, p.Ca), PayloadJson(Payload(iat)), p.LeafKey, RSASignaturePadding.Pkcs1), EidQrErrorCodes.SignatureInvalid);
        yield return new("payload_not_json", () => Sign(Header(p.Leaf, p.Ca), "not json", p.LeafKey), EidQrErrorCodes.JwsMalformed);
        yield return new("payload_array", () => Sign(Header(p.Leaf, p.Ca), "[1]", p.LeafKey), EidQrErrorCodes.JwsMalformed);
        yield return new("iss_wrong", () => Jws(Pl(o => o["iss"] = "https://evil.example")), EidQrErrorCodes.ClaimsInvalid);
        yield return new("sub_mismatch_cert", () => Jws(Pl(o => o["sub"] = "PNOMN-999999999999")), EidQrErrorCodes.ClaimsInvalid);
        yield return new("statement_wrong_rp", () => Jws(Pl(o => o["statement"] = "Та Other-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна")), EidQrErrorCodes.ClaimsInvalid);
        yield return new("iat_float", () => Jws(Pl(o => o["iat"] = iat + 0.5)), EidQrErrorCodes.ClaimsInvalid);
        yield return new("aud_mismatch", () => Jws(), EidQrErrorCodes.AudienceMismatch, () => Expect(rp: "00000000-0000-0000-0000-000000000000"));
        yield return new("sid_mismatch", () => Jws(), EidQrErrorCodes.SessionMismatch, () => Expect(sid: "other-sid"));
        yield return new("nonce_mismatch", () => Jws(), EidQrErrorCodes.NonceMismatch, () => Expect(nonce: "order-1043"));
        yield return new("exp_minus_iat_301", () => Jws(Pl(o => o["exp"] = iat + 301)), EidQrErrorCodes.ClaimsInvalid);
        yield return new("exp_equals_iat", () => Jws(Pl(o => o["exp"] = iat)), EidQrErrorCodes.ClaimsInvalid);
        yield return new("iat_future", () => Jws(Pl(o =>
        {
            o["iat"] = iat + 120;
            o["exp"] = iat + 420;
        })), EidQrErrorCodes.NotYetValid);
        yield return new("expired", () => Jws(), EidQrErrorCodes.Expired, () => Expect(DateTimeOffset.FromUnixTimeSeconds(iat + 300 + 61)));
        yield return new("data_value_number", () => Jws(Fields(f => f["age"] = 34)), EidQrErrorCodes.DataInvalid);
        yield return new("data_value_null", () => Jws(Fields(f => f["age"] = null)), EidQrErrorCodes.DataInvalid);
        yield return new("data_value_too_long", () => Jws(Fields(f => f["long"] = new string('я', 1025))), EidQrErrorCodes.DataInvalid);
        yield return new("data_value_max", () => Jws(Fields(f => f["long"] = new string('я', 1024))), null);
        yield return new("data_value_nul", () => Jws(Fields(f => f["x"] = "a\0b")), EidQrErrorCodes.DataInvalid);
        yield return new("data_key_too_long", () => Jws(Fields(f => f[new string('к', 65)] = "x")), EidQrErrorCodes.DataInvalid);
        yield return new("data_key_control", () => Jws(Fields(f => f["a\u0085"] = "x")), EidQrErrorCodes.DataInvalid);
        yield return new("data_too_many_fields", () => Jws(Fields(f =>
        {
            for (int i = 0; i < 125; i++) f["k" + i] = "v";
        })), EidQrErrorCodes.DataInvalid);
        yield return new("data_max_fields", () => Jws(Fields(f =>
        {
            for (int i = 0; i < 124; i++) f["k" + i] = "v";
        })), null);
        yield return new("data_empty_no_photo", () => Jws(Data(d => d["fields"] = new JsonObject())), EidQrErrorCodes.DataInvalid);
        yield return new("data_source_bad", () => Jws(Data(d => d["source"] = "DAN")), EidQrErrorCodes.DataInvalid);
        yield return new("photo_not_jpeg", () => Jws(Data(d => d["photo"] = Convert.ToBase64String(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0, 0 }))), EidQrErrorCodes.DataInvalid);
        yield return new("photo_too_large", () => Jws(Data(d => d["photo"] = Convert.ToBase64String(Jpeg(153601)))), EidQrErrorCodes.DataInvalid);
        yield return new("photo_unpadded", () => Jws(Data(d => d["photo"] = Convert.ToBase64String(Jpeg(10)).TrimEnd('='))), EidQrErrorCodes.DataInvalid);
        yield return new("data_extra_member", () => Jws(Data(d => d["extra"] = "x")), EidQrErrorCodes.DataInvalid);
        yield return new("data_missing", () => Jws(Pl(o => o.Remove("data"))), EidQrErrorCodes.DataInvalid);
    }

    private static byte[] Jpeg(int n)
    {
        var b = new byte[n];
        new Random(n).NextBytes(b);
        b[0] = 0xFF;
        b[1] = 0xD8;
        b[2] = 0xFF;
        return b;
    }

    [Fact]
    public async Task VerifyCases()
    {
        var failures = new List<string>();
        foreach (var c in Cases())
        {
            var jws = c.Jws();
            var exp = c.Exp?.Invoke() ?? Expect();
            var trust = c.Trust?.Invoke() ?? TrustWith();
            try
            {
                var r = await EidQr.VerifyAsync(jws, exp, trust);
                if (c.Error is not null) failures.Add(c.Name + ": want " + c.Error + ", got OK");
                else Assert.Equal(Etsi, r.Signer.Etsi);
            }
            catch (EidQrException e)
            {
                if (c.Error != e.Code) failures.Add(c.Name + ": want " + (c.Error ?? "OK") + ", got " + e.Code + " (" + e.Message + ")");
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public async Task VerifyResultMembers()
    {
        var p = P.Value;
        var photo = Jpeg(2048);
        var pl = Payload(p.Now.ToUnixTimeSeconds() - 10, data: new JsonObject
        {
            ["source"] = "citizenid",
            ["fields"] = new JsonObject { ["surname"] = "Дорж", ["given_name"] = "Бат", ["reg_no"] = "УБ90010112", ["note"] = "<a&b>" },
            ["photo"] = Convert.ToBase64String(photo),
        });
        var jws = Jws(pl);
        var r = await EidQr.VerifyAsync(jws, Expect(), TrustWith());

        Assert.Equal(jws, r.Jws);
        Assert.Equal(new[] { "surname", "given_name", "reg_no", "note" }, r.Data.Select(kv => kv.Key)); // payload-ийн дараалал
        Assert.Equal("<a&b>", r.Data.Single(kv => kv.Key == "note").Value);
        Assert.Equal("citizenid", r.Source);
        Assert.Equal(photo, r.Photo);
        Assert.Equal(Etsi, r.Signer.Etsi);
        Assert.Equal("BAT", r.Signer.GivenName);
        Assert.Equal("DORJ", r.Signer.Surname);
        Assert.Equal("DORJ BAT", r.Signer.CommonName);
        Assert.Equal(p.Leaf.RawData, r.Signer.Certificate.RawData);
        Assert.Equal(p.Now.ToUnixTimeSeconds() - 10, r.SignedAt.ToUnixTimeSeconds());
        Assert.Equal(RpName, r.Claims.GetProperty("rp_name").GetString());
        var input = jws[..jws.LastIndexOf('.')];
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(input))).ToLowerInvariant(), r.Sha256);
        Assert.Contains("\\u003ca\\u0026b\\u003e", Encoding.UTF8.GetString(EidQr.B64UrlOrNull(input.Split('.')[1])!), StringComparison.Ordinal);
    }

    [Fact]
    public void Parse()
    {
        Assert.Equal((Tok, "EIDMN-QR1:" + Tok), EidQr.Parse("EIDMN-QR1:" + Tok));
        Assert.Equal((Tok, "EIDMN-QR1:" + Tok), EidQr.Parse("  EIDMN-QR1:" + Tok + "\n"));
        foreach (var bad in new[] { null, "", Tok, "EIDMN-QR2:" + Tok, "EIDMN-QR1:" + Tok[..42], "EIDMN-QR1:" + Tok + "A", "eidmn-qr1:" + Tok, "EIDMN-QR1:" + Tok[..42] + "+" })
        {
            Assert.Equal(EidQrErrorCodes.FormatInvalid, Assert.Throws<EidQrException>(() => EidQr.Parse(bad)).Code);
        }
    }

    [Fact]
    public void CitizenIssuingCaSkiMatchesEmbedded04()
    {
        var ca04 = Trust.Issuers[0];
        Assert.Equal(EidQr.CitizenIssuingCaSki, ca04.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First().SubjectKeyIdentifier!.ToLowerInvariant());
    }

    [Fact]
    public async Task DefaultTrustRejectsTestPki()
    {
        // Анхдагч итгэл = үндэсний root + олгогч 04 — тест PKI итгэгдэхгүй.
        var e = await Assert.ThrowsAsync<EidQrException>(() => EidQr.VerifyAsync(Jws(), Expect()));
        Assert.Equal(EidQrErrorCodes.ChainInvalid, e.Code);
    }

    // ---------------------------------------------------------------- CA-ийн vector (байвал)

    [Fact]
    public async Task Vectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "testdata", "myqr_vectors.json");
        if (!File.Exists(path))
        {
            return; // CA репогийн файл хараахан хуулагдаагүй (гэрээ §7.1) — хуулахдаа MYQR_VECTORS_SHA256-г тогтоо.
        }
        var raw = File.ReadAllBytes(path);
        Assert.Equal(MYQR_VECTORS_SHA256, Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant());
        using var doc = JsonDocument.Parse(raw);
        var v = doc.RootElement;
        Assert.Equal("myqr-2026-10-26", v.GetProperty("contract").GetString());
        var issuer = v.GetProperty("issuer").GetString();
        var t = v.GetProperty("trust");
        var anchors = t.GetProperty("anchorsPem").EnumerateArray().Select(x => X509Certificate2.CreateFromPem(x.GetString())).ToArray();
        var inters = t.GetProperty("intermediatesPem").EnumerateArray().Select(x => X509Certificate2.CreateFromPem(x.GetString())).ToArray();
        var skis = t.GetProperty("allowedIssuerSkis").EnumerateArray().Select(x => x.GetString()!).ToArray();

        foreach (var c in v.GetProperty("parse").EnumerateArray())
        {
            var input = c.GetProperty("in").GetString();
            if (c.TryGetProperty("error", out var err))
            {
                Assert.Equal(err.GetString(), Assert.Throws<EidQrException>(() => EidQr.Parse(input)).Code);
            }
            else
            {
                var (token, qr) = EidQr.Parse(input);
                Assert.Equal(c.GetProperty("token").GetString(), token);
                if (c.TryGetProperty("qr", out var wq)) Assert.Equal(wq.GetString(), qr);
            }
        }

        var failures = new List<string>();
        foreach (var c in v.GetProperty("verify").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString();
            var e = c.GetProperty("expect");
            var exp = new QrExpect(e.GetProperty("rpUUID").GetString()!, e.GetProperty("sessionId").GetString()!, e.GetProperty("nonce").GetString()!,
                issuer, DateTimeOffset.FromUnixTimeSeconds(e.GetProperty("now").GetInt64()));
            var rev = new Dictionary<string, string>(StringComparer.Ordinal);
            if (c.TryGetProperty("revocation", out var rv))
            {
                foreach (var kv in rv.EnumerateObject()) rev[kv.Name.ToLowerInvariant()] = kv.Value.GetString()!;
            }
            var trust = new QrTrust(anchors, inters, skis, Stub(rev));
            try
            {
                var r = await EidQr.VerifyAsync(c.GetProperty("jws").GetString()!, exp, trust);
                if (c.TryGetProperty("error", out var err))
                {
                    failures.Add(name + ": want " + err.GetString() + ", got OK");
                    continue;
                }
                var want = c.GetProperty("result");
                var got = JsonNode.Parse(r.Claims.GetRawText())!.AsObject();
                foreach (var kv in want.GetProperty("claims").EnumerateObject())
                {
                    if (!JsonNode.DeepEquals(JsonNode.Parse(kv.Value.GetRawText()), got[kv.Name])) failures.Add(name + ": claims." + kv.Name);
                }
                if (!want.GetProperty("dataKeys").EnumerateArray().Select(x => x.GetString()).SequenceEqual(r.Data.Select(kv => kv.Key))) failures.Add(name + ": dataKeys");
                foreach (var kv in want.GetProperty("data").EnumerateObject())
                {
                    if (r.Data.FirstOrDefault(d => d.Key == kv.Name).Value != kv.Value.GetString()) failures.Add(name + ": data." + kv.Name);
                }
                if (want.GetProperty("source").GetString() != r.Source) failures.Add(name + ": source");
                var ps = want.GetProperty("photoSha256");
                var gotPs = r.Photo is null ? null : Convert.ToHexString(SHA256.HashData(r.Photo)).ToLowerInvariant();
                if ((ps.ValueKind == JsonValueKind.Null ? null : ps.GetString()) != gotPs) failures.Add(name + ": photoSha256");
                var sg = want.GetProperty("signer");
                if (sg.GetProperty("etsi").GetString() != r.Signer.Etsi) failures.Add(name + ": signer.etsi");
                if (sg.GetProperty("certSha256").GetString() != Convert.ToHexString(SHA256.HashData(r.Signer.Certificate.RawData)).ToLowerInvariant()) failures.Add(name + ": signer.certSha256");
                if (want.GetProperty("sha256").GetString() != r.Sha256) failures.Add(name + ": sha256");
            }
            catch (EidQrException ex)
            {
                var wantErr = c.TryGetProperty("error", out var err) ? err.GetString() : "OK";
                if (wantErr != ex.Code) failures.Add(name + ": want " + wantErr + ", got " + ex.Code + " (" + ex.Message + ")");
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    // ---------------------------------------------------------------- stub RP-API

    private sealed class Api : HttpMessageHandler
    {
        public int Hits;
        public JsonObject? StartBody;
        public string State = "OK";
        public Func<string, string>? MakeJws;

        private static HttpResponseMessage Json(HttpStatusCode s, JsonNode body) =>
            new(s) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

        private static HttpResponseMessage Error(int status, string code) =>
            Json((HttpStatusCode)status, new JsonObject { ["error"] = "x", ["code"] = code });

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            Hits++;
            Assert.Equal("Bearer rp_sk_secret", r.Headers.Authorization!.ToString());
            var path = r.RequestUri!.AbsolutePath;
            if (path == "/authentication/qr" && r.Method == HttpMethod.Post)
            {
                StartBody = JsonNode.Parse(await r.Content!.ReadAsStringAsync(ct))!.AsObject();
                var qr = StartBody["qr"]!.GetValue<string>();
                return qr[^1] switch
                {
                    'B' => Error(409, "NO_SIGNING_CERTIFICATE"),
                    'C' => Error(404, "QR_TOKEN_INVALID"),
                    'D' => Error(403, "PERMISSION_DENIED"),
                    _ => Json(HttpStatusCode.OK, new JsonObject { ["sessionID"] = Sid }),
                };
            }
            if (path == "/session/" + Sid)
            {
                Assert.Contains("timeoutMs=", r.RequestUri.Query, StringComparison.Ordinal);
                switch (State)
                {
                    case "RUNNING":
                        return Json(HttpStatusCode.OK, new JsonObject { ["state"] = "RUNNING" });
                    case "REFUSED":
                        return Json(HttpStatusCode.OK, new JsonObject { ["state"] = "COMPLETE", ["result"] = new JsonObject { ["endResult"] = "USER_REFUSED" } });
                    case "GONE":
                        return Error(410, "QR_PRESENTATION_GONE");
                    case "GONE_NOCODE":
                        return new HttpResponseMessage(HttpStatusCode.Gone);
                    case "DENIED":
                        return Error(403, "PERMISSION_DENIED");
                }
                var nonce = StartBody!["nonce"]!.GetValue<string>();
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["state"] = "COMPLETE",
                    ["result"] = new JsonObject { ["endResult"] = "OK" },
                    ["signatureProtocol"] = "RAW_DIGEST_SIGNATURE",
                    ["interactionTypeUsed"] = "displayTextAndPIN",
                    ["presentation"] = new JsonObject { ["jws"] = MakeJws!(nonce) },
                });
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private static (Api, EidQrClient) Client()
    {
        var api = new Api
        {
            MakeJws = nonce => Jws(Payload(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1, nonce: nonce)),
        };
        // Бодит цагаар шалгана (client-ийн Now тохируулгагүй) — PKI нь өнөөдрөөс ±.
        var c = new EidQrClient(new EidQrOptions
        {
            BaseUrl = "https://rp.test",
            RpUuid = RpUuid,
            RpName = "Касс 3",
            ApiSecret = "rp_sk_secret",
            HttpClient = new HttpClient(api),
        }, TrustWith());
        return (api, c);
    }

    [Fact]
    public async Task StartBadQrIsLocal()
    {
        var (api, c) = Client();
        foreach (var bad in new[] { Tok, "EIDMN-QR2:" + Tok, "x" })
        {
            var e = await Assert.ThrowsAsync<EidQrException>(() => c.StartAsync(new QrStartRequest(bad)));
            Assert.Equal(EidQrErrorCodes.FormatInvalid, e.Code);
            Assert.Null(e.HttpStatus);
        }
        Assert.Equal(0, api.Hits);
    }

    [Fact]
    public async Task StartBodyAndAutoNonce()
    {
        var (api, c) = Client();
        var s = await c.StartAsync(new QrStartRequest("  EIDMN-QR1:" + Tok + "\n"));
        Assert.Equal(Sid, s.SessionId);
        Assert.Equal(22, s.Nonce.Length);
        Assert.Matches("^[A-Za-z0-9_-]{22}$", s.Nonce);
        var b = api.StartBody!;
        Assert.Equal(new[] { "qr", "relyingPartyUUID", "relyingPartyName", "nonce" }, b.Select(kv => kv.Key));
        Assert.Equal("EIDMN-QR1:" + Tok, b["qr"]!.GetValue<string>());
        Assert.Equal(RpUuid, b["relyingPartyUUID"]!.GetValue<string>());
        Assert.Equal("Касс 3", b["relyingPartyName"]!.GetValue<string>());
        Assert.Equal(s.Nonce, b["nonce"]!.GetValue<string>());

        var s2 = await c.StartAsync(new QrStartRequest("EIDMN-QR1:" + Tok, "order-1042-abcdefgh", "Касс 7"));
        Assert.Equal("order-1042-abcdefgh", s2.Nonce);
        Assert.Equal("order-1042-abcdefgh", api.StartBody!["nonce"]!.GetValue<string>());
        Assert.Equal("Касс 7", api.StartBody!["relyingPartyName"]!.GetValue<string>());
        Assert.NotEqual(EidQrClient.NewNonce(), EidQrClient.NewNonce());
    }

    [Theory]
    [InlineData('B', 409, "NO_SIGNING_CERTIFICATE")]
    [InlineData('C', 404, "QR_TOKEN_INVALID")]
    [InlineData('D', 403, "PERMISSION_DENIED")]
    public async Task StartServerCodesPassThrough(char last, int status, string code)
    {
        var (_, c) = Client();
        var e = await Assert.ThrowsAsync<EidQrException>(() => c.StartAsync(new QrStartRequest("EIDMN-QR1:" + Tok[..42] + last)));
        Assert.Equal(code, e.Code);
        Assert.Equal(status, e.HttpStatus);
    }

    [Fact]
    public async Task ResultCheckFlow()
    {
        var (api, c) = Client();
        var s = await c.StartAsync(new QrStartRequest("EIDMN-QR1:" + Tok));

        api.State = "RUNNING";
        Assert.False((await c.CheckAsync(s)).Complete);
        Assert.Equal(EidQrErrorCodes.Pending, (await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(s, TimeSpan.FromMilliseconds(1)))).Code);

        api.State = "OK";
        var chk = await c.CheckAsync(s, TimeSpan.FromSeconds(5));
        Assert.True(chk.Complete);
        Assert.Equal("Бат", chk.Result!.Data.Single(kv => kv.Key == "given_name").Value);
        var r = await c.ResultAsync(s);
        Assert.Equal(Etsi, r.Signer.Etsi);
        Assert.Equal(s.Nonce, r.Claims.GetProperty("nonce").GetString());
        var again = await c.VerifyAsync(r.Jws, s);
        Assert.Equal(r.Sha256, again.Sha256);
        Assert.Equal(EidQrErrorCodes.NonceMismatch, (await Assert.ThrowsAsync<EidQrException>(() => c.VerifyAsync(r.Jws, s with { Nonce = "x" }))).Code);
    }

    [Theory]
    [InlineData("REFUSED", "SESSION_FAILED", null)]
    [InlineData("GONE", "QR_PRESENTATION_GONE", 410)]
    [InlineData("GONE_NOCODE", "QR_PRESENTATION_GONE", 410)]
    [InlineData("DENIED", "PERMISSION_DENIED", 403)]
    public async Task ResultErrors(string state, string code, int? status)
    {
        var (api, c) = Client();
        var s = await c.StartAsync(new QrStartRequest("EIDMN-QR1:" + Tok));
        api.State = state;
        var e = await Assert.ThrowsAsync<EidQrException>(() => c.ResultAsync(s));
        Assert.Equal(code, e.Code);
        Assert.Equal(status, e.HttpStatus);
        if (state == "REFUSED") Assert.Equal("USER_REFUSED", e.EndResult);
        Assert.Equal(code, (await Assert.ThrowsAsync<EidQrException>(() => c.CheckAsync(s))).Code);
    }

    [Fact]
    public void SessionRoundTripsAsJson()
    {
        var s = new QrSession(Sid, Nonce);
        Assert.Equal(s, JsonSerializer.Deserialize<QrSession>(JsonSerializer.Serialize(s)));
    }
}
