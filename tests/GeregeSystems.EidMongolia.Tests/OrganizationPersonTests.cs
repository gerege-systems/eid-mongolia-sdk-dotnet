using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace GeregeSystems.EidMongolia.Tests;

/// <summary>Go client_test.go TestOrganization, x509_gaps_test.go TestRepresentationsRaw, seal_grant_test.go
/// TestOrganization_SealGrants, portal_gaps_test.go TestPersonService, share_test.go TestPersonCertificate*-ийн порт.</summary>
public class OrganizationPersonTests
{
    // Go client_test.go TestOrganization + x509_gaps_test.go TestRepresentationsRaw.
    [Fact]
    public async Task Representations()
    {
        var (c, h, _) = Rig.Create(200, "{\"personEtsi\":\"PNOMN-12345678\",\"representations\":[{\"orgEtsi\":\"NTRMN-6235972\",\"orgRegister\":\"6235972\"," +
            "\"orgName\":\"Гэрэгэ Системс ХХК\",\"role\":\"ceo\",\"rightType\":\"ADMIN\",\"source\":\"REGISTRY\",\"validFrom\":\"2026-10-01T00:00:00Z\"}],\"future\":{\"x\":1}}");
        var r = await c.Organization.GetRepresentationsAsync("PNOMN-12345678");
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/organization/representations/etsi/PNOMN-12345678", h.Last.Path);
        Assert.Equal("ADMIN", Assert.Single(r.Representations).RightType);
        Assert.Equal("{\"x\":1}", r.Raw!.Value.GetProperty("future").GetRawText());

        (c, _, _) = Rig.Create(200, "{\"representations\":null}");
        r = await c.Organization.GetRepresentationsAsync("PNOMN-1");
        Assert.Equal("PNOMN-1", r.PersonEtsi);
        Assert.Empty(r.Representations);
    }

    // Go seal_grant_test.go TestOrganization_SealGrants.
    [Fact]
    public async Task SealGrants()
    {
        var body = "{\"personEtsi\":\"PNOMN-12345678\",\"organizations\":[{\"orgEtsi\":\"NTRMN-6235972\",\"orgName\":\"Гэрэгэ Системс ХХК\",\"orgStatus\":\"ACTIVE\",\"grants\":[" +
            "{\"grantId\":\"g1\",\"rpName\":\"eidmongolia.mn\",\"rpDomain\":\"eidmongolia.mn\",\"status\":\"APPROVED\",\"createdAt\":\"2026-11-20T05:00:00Z\"," +
            "\"decidedAt\":\"2026-11-20T05:01:00Z\",\"approverName\":\"Бат\",\"sealCount\":12,\"sealCount30d\":3,\"lastSealedAt\":\"2026-11-20T07:00:00Z\"}," +
            "{\"grantId\":\"g2\",\"rpName\":\"Банк\",\"status\":\"PENDING\",\"createdAt\":\"2026-11-20T05:00:00Z\",\"expiresAt\":\"2026-11-20T05:07:00Z\"," +
            "\"sealCount\":0,\"sealCount30d\":0,\"lastSealedAt\":null}," +
            "{\"grantId\":\"g3\",\"rpName\":\"Даатгал\",\"status\":\"APPROVED\",\"createdAt\":\"2026-11-20T05:00:00Z\"}]}," +
            "{\"orgEtsi\":\"NTRMN-1\",\"orgName\":\"Б\",\"orgStatus\":\"SUSPENDED\",\"grants\":null}],\"future\":1}";
        var (c, h, _) = Rig.Create(200, body);
        var r = await c.Organization.SealGrantsAsync("PNOMN-12345678");
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/organization/seal-grants/etsi/PNOMN-12345678", h.Last.Path);
        Assert.Equal("PNOMN-12345678", r.PersonEtsi);
        Assert.Equal(2, r.Organizations.Count);
        Assert.NotNull(r.Raw);
        var o = r.Organizations[0];
        Assert.Equal("Гэрэгэ Системс ХХК", o.OrgName);
        Assert.Equal("ACTIVE", o.OrgStatus);
        Assert.Equal(3, o.Grants.Count);
        var (g1, g2, g3) = (o.Grants[0], o.Grants[1], o.Grants[2]);
        Assert.Equal(SealGrantStatuses.Approved, g1.Status);
        Assert.Equal("eidmongolia.mn", g1.RpDomain);
        Assert.Equal("Бат", g1.ApproverName);
        Assert.NotNull(g1.DecidedAt);
        Assert.Equal(12, g1.SealCount);
        Assert.Equal(3, g1.SealCount30d);
        Assert.NotNull(g1.LastSealedAt);
        Assert.Equal(SealGrantStatuses.Pending, g2.Status);
        Assert.NotNull(g2.ExpiresAt);
        Assert.Equal(0, g2.SealCount);
        Assert.Null(g2.LastSealedAt);
        // Статистик боломжгүй — талбаргүй → null (0 биш).
        Assert.Null(g3.SealCount);
        Assert.Null(g3.SealCount30d);
        Assert.Null(g3.LastSealedAt);
        Assert.NotNull(r.Organizations[1].Grants);
        Assert.Empty(r.Organizations[1].Grants);

        (c, _, _) = Rig.Create(200, "{\"personEtsi\":\"PNOMN-12345678\",\"organizations\":null}");
        Assert.Empty((await c.Organization.SealGrantsAsync("PNOMN-12345678")).Organizations);
        (c, _, _) = Rig.Create(403, "{\"error\":\"PKI_READ эрхгүй\",\"code\":\"PERMISSION_DENIED\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c.Organization.SealGrantsAsync("PNOMN-12345678"));
    }

    // Go portal_gaps_test.go TestPersonService.
    [Fact]
    public async Task PersonService()
    {
        var (c, h, _) = Rig.Create(r => r.Path switch
        {
            var p when p.StartsWith("/certificates/", StringComparison.Ordinal) => Rig.Json(200,
                "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"valid\":1,\"total\":1},\"certificates\":[{\"documentNumber\":\"d\",\"type\":\"AUTH\"," +
                "\"keyMedium\":\"TOKEN\",\"serialNumber\":\"ab\",\"certificateLevel\":\"ADVANCED\",\"status\":\"VALID\",\"notBefore\":\"2026-10-12T16:36:35+08:00\"," +
                "\"notAfter\":\"2027-10-12T16:36:35+08:00\",\"issuerDn\":\"CN=x\",\"organization\":{\"etsi\":\"NTRMN-6235972\",\"name\":\"Гэрэгэ\"}}]}"),
            var p when p.StartsWith("/devices/", StringComparison.Ordinal) => Rig.Json(200,
                "{\"personEtsi\":\"PNOMN-1\",\"devices\":[{\"documentNumber\":\"d\",\"platform\":\"APNS\",\"enrolledAt\":\"2026-10-01T00:00:00Z\",\"active\":true}]," +
                "\"activeCount\":1,\"total\":1}"),
            var p when p.StartsWith("/rp/activity/", StringComparison.Ordinal) => Rig.Json(200,
                "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"authentication\":2,\"signature\":1},\"sessions\":[{\"id\":\"9\",\"kind\":\"AUTH\"," +
                "\"flow\":\"AUTHENTICATION\",\"outcome\":\"OK\",\"timestamp\":\"2026-10-01T00:00:00Z\"}],\"total\":3,\"limit\":5,\"offset\":10}"),
            var p when p.StartsWith("/person/summary/", StringComparison.Ordinal) => Rig.Json(200,
                "{\"personEtsi\":\"PNOMN-1\",\"firstName\":\"Бат\",\"lastName\":\"Дорж\",\"nationality\":\"MNG\",\"certificates\":{\"valid\":2}," +
                "\"activity\":{\"authentication\":42},\"devicesActive\":1,\"devicesTotal\":2,\"representationCount\":1}"),
            var p when p.StartsWith("/person/children/", StringComparison.Ordinal) => Rig.Json(200,
                "{\"children\":[{\"etsi\":\"PNOMN-2\",\"regNo\":\"УБ\",\"name\":\"Дорж Сүх\",\"registered\":false}]}"),
            _ => Rig.Json(404, "{}"),
        });
        var certs = await c.Person.CertificatesAsync("PNOMN-1");
        Assert.Equal(1, certs.Counts.Valid);
        Assert.Equal("NTRMN-6235972", certs.Certificates[0].Organization!.Etsi);
        Assert.Equal(2027, certs.Certificates[0].NotAfter.Year);
        Assert.NotNull(certs.Raw);
        Assert.Equal("GET", h.Last.Method);
        Assert.Equal("/certificates/etsi/PNOMN-1", h.Last.Path);

        var dev = await c.Person.DevicesAsync("PNOMN-1");
        Assert.Equal(1, dev.ActiveCount);
        Assert.Equal("APNS", dev.Devices[0].Platform);
        Assert.Equal("/devices/etsi/PNOMN-1", h.Last.Path);

        var act = await c.Person.ActivityAsync("PNOMN-1", new ActivityQuery { Flow = "AUTHENTICATION", Limit = 5, Offset = 10 });
        Assert.Equal(2, act.Counts.Authentication);
        Assert.Equal("AUTH", act.Sessions[0].Kind);
        Assert.Equal(10, act.Offset);
        Assert.Equal("/rp/activity/etsi/PNOMN-1?flow=AUTHENTICATION&limit=5&offset=10", h.Last.PathAndQuery);
        await c.Person.ActivityAsync("PNOMN-1");
        Assert.Equal("/rp/activity/etsi/PNOMN-1", h.Last.PathAndQuery);
        await c.Person.ActivityAsync("PNOMN-1", new ActivityQuery());
        Assert.Equal("/rp/activity/etsi/PNOMN-1", h.Last.PathAndQuery);

        var sum = await c.Person.SummaryAsync("PNOMN-1");
        Assert.Equal("Дорж", sum.LastName);
        Assert.Equal("MNG", sum.Nationality);
        Assert.Equal(42, sum.Activity.Authentication);
        Assert.Equal(1, sum.RepresentationCount);
        Assert.Equal("/person/summary/etsi/PNOMN-1", h.Last.Path);

        var ch = await c.Person.ChildrenAsync("PNOMN-1");
        Assert.Equal("Дорж Сүх", Assert.Single(ch.Children).Name);
        Assert.Equal("/person/children/etsi/PNOMN-1", h.Last.Path);

        (c, _, _) = Rig.Create(403, "{\"error\":\"RP-д PKI_READ эрх алга\"}");
        await Assert.ThrowsAsync<EidForbiddenException>(() => c.Person.SummaryAsync("PNOMN-1"));
    }

    // Go share_test.go TestPersonCertificateRevocationFields + TestPersonCertificateTokenSerial.
    [Fact]
    public async Task PersonCertificateRevocationAndTokenSerial()
    {
        var (c, _, _) = Rig.Create(200, "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"revoked\":1,\"suspended\":1,\"total\":2},\"certificates\":[" +
            "{\"type\":\"SIGN\",\"status\":\"REVOKED\",\"issuedAt\":\"2026-01-02T03:04:05+08:00\",\"revokedAt\":\"2026-02-01T00:00:00+08:00\",\"revocationReason\":\"keyCompromise\"}," +
            "{\"type\":\"SIGN\",\"status\":\"SUSPENDED\",\"issuedAt\":\"2025-01-02T03:04:05+08:00\",\"revocationReason\":\"superseded\"}]}");
        var pc = await c.Person.CertificatesAsync("PNOMN-1");
        var (a, b) = (pc.Certificates[0], pc.Certificates[1]);
        Assert.Equal(2026, a.IssuedAt!.Value.Year);
        Assert.Equal(2, a.RevokedAt!.Value.Month);
        Assert.Equal("keyCompromise", a.RevocationReason);
        Assert.Null(b.RevokedAt);
        Assert.Equal("superseded", b.RevocationReason);
        Assert.NotNull(b.IssuedAt);

        (c, _, _) = Rig.Create(200, "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"valid\":2,\"total\":2},\"certificates\":[" +
            "{\"type\":\"AUTH\",\"keyMedium\":\"TOKEN\",\"status\":\"VALID\",\"tokenSerial\":\"EP2003-0042A1\",\"organization\":{\"etsi\":\"NTRMN-1\",\"name\":\"Тест ХХК\"}}," +
            "{\"type\":\"SIGN\",\"keyMedium\":\"MOBILE\",\"status\":\"VALID\"}]}");
        pc = await c.Person.CertificatesAsync("PNOMN-1");
        Assert.Equal("EP2003-0042A1", pc.Certificates[0].TokenSerial);
        Assert.Null(pc.Certificates[1].TokenSerial);
    }

    [Fact]
    public async Task EmptyBodyGivesEmptyRecords()
    {
        var (c, _, _) = Rig.Create(200, "");
        var s = await c.Person.SummaryAsync("PNOMN-1");
        Assert.Null(s.Raw);
        Assert.Empty((await c.Person.ChildrenAsync("PNOMN-1")).Children);
        (c, _, _) = Rig.Create(200, "{}");
        Assert.Equal(JsonValueKind.Object, (await c.Person.SummaryAsync("PNOMN-1")).Raw!.Value.ValueKind);
    }
}
