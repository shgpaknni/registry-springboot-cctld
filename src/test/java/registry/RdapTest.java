package registry;

import org.junit.jupiter.api.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class RdapTest {
    Registry reg;
    RdapServer rdap;
    AtomicLong nanos = new AtomicLong();
    HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void start() throws Exception {
        reg = new Registry(Db.inMemory(), Config.defaults("xx").withPbkdf2Iterations(1000), new TestClock());
        reg.createRegistrar("reg1", "Registrar One", "correct-horse-battery", "fp1", 100_000, 0);
        reg.createContact("reg1", "con1", "Asha Rao", "Example Org", "asha@example.org", "+91.8000000000", "IN");
        reg.createDomain("reg1", "alpha.xx", 1, "con1", List.of("ns1.example.net", "ns2.example.net"), "auth-secret-1");
        rdap = new RdapServer(reg, new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), new RateLimiter(5, 1, nanos::get));
    }

    @AfterEach
    void stop() { rdap.close(); }

    HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + rdap.port() + path)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void registeredDomainIsPublishedWithoutPersonalData() throws Exception {
        var r = get("/rdap/domain/ALPHA.xx");
        assertEquals(200, r.statusCode());
        assertEquals("application/rdap+json", r.headers().firstValue("Content-Type").orElse(""));
        String b = r.body();
        assertTrue(b.contains("\"ldhName\":\"alpha.xx\""), b);
        assertTrue(b.contains("\"ns1.example.net\""), b);
        assertTrue(b.contains("\"Registrar One\""), b);
        assertTrue(b.contains("REDACTED FOR PRIVACY"), b);
        for (String secret : List.of("asha", "Asha", "Example Org", "+91", "@")) assertFalse(b.contains(secret), "leaked " + secret);
    }

    @Test
    void statusFollowsLifecycle() throws Exception {
        reg.setServerHold("compliance", "alpha.xx", true);
        assertTrue(get("/rdap/domain/alpha.xx").body().contains("server hold"));
        TestClock clock = (TestClock) reg.clock();
        clock.advance(java.time.Duration.ofDays(400));
        reg.runLifecycle();
        assertTrue(get("/rdap/domain/alpha.xx").body().contains("auto renew period"));
    }

    @Test
    void errorsFollowRdapConventions() throws Exception {
        var nf = get("/rdap/domain/missing.xx");
        assertEquals(404, nf.statusCode());
        assertTrue(nf.body().contains("\"errorCode\":404"));
        assertEquals(404, get("/rdap/domain/example.com").statusCode());      // not authoritative
        assertEquals(400, get("/rdap/domain/-bad.xx").statusCode());          // malformed
        assertEquals(404, get("/rdap/nameserver/ns1.example.net").statusCode());
        assertEquals(200, get("/rdap/help").statusCode());
    }

    @Test
    void nameserverAndRegistrarEntityLookupsReturnRdapObjects() throws Exception {
        reg.createHost("reg1", "ns1.example.net", List.of("192.0.2.53"), List.of("2001:db8::53"));

        var ns = get("/rdap/nameserver/ns1.example.net");
        assertEquals(200, ns.statusCode());
        assertTrue(ns.body().contains("\"objectClassName\":\"nameserver\""), ns.body());
        assertTrue(ns.body().contains("\"192.0.2.53\""), ns.body());
        assertTrue(ns.body().contains("\"2001:db8::53\""), ns.body());

        var entity = get("/rdap/entity/reg1");
        assertEquals(200, entity.statusCode());
        assertTrue(entity.body().contains("\"objectClassName\":\"entity\""), entity.body());
        assertTrue(entity.body().contains("\"handle\":\"reg1\""), entity.body());
        assertTrue(entity.body().contains("Registrar One"), entity.body());
    }

    @Test
    void unsupportedRdapQueryTypesReturn501() throws Exception {
        assertEquals(501, get("/rdap/domains?registrant=con1").statusCode());
        assertEquals(501, get("/rdap/nameservers?unsupported=value").statusCode());
        assertEquals(501, get("/rdap/entities?unsupported=value").statusCode());
    }

    @Test
    void domainSearchByNameserverIpv4ReturnsMatchingDomains() throws Exception {
        reg.createHost("reg1", "ns1.example.net", List.of("192.0.2.53"), List.of());

        var response = get("/rdap/domains?nsIp=192.0.2.53");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"domainSearchResults\":[{"), response.body());
        assertTrue(response.body().contains("\"ldhName\":\"alpha.xx\""), response.body());
    }

    @Test
    void domainSearchByNameserverIpv6MatchesEquivalentPresentation() throws Exception {
        reg.createHost("reg1", "ns1.example.net", List.of(), List.of("2001:db8::53"));

        var response = get("/rdap/domains?nsIp=2001:0db8:0:0:0:0:0:53");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"ldhName\":\"alpha.xx\""), response.body());
    }

    @Test
    void domainSearchByNameserverIpRejectsMalformedAddress() throws Exception {
        var response = get("/rdap/domains?nsIp=999.999.999.999");
        assertEquals(400, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"errorCode\":400"), response.body());
    }

    @Test
    void domainSearchByNameserverNameReturnsDomainsUsingThatHost() throws Exception {
        reg.createHost("reg1", "ns1.example.net", List.of("192.0.2.53"), List.of());
        reg.createDomain("reg1", "byhost.xx", 1, "con1",
                List.of("ns1.example.net", "ns2.example.net"), "auth-secret-2");

        var response = get("/rdap/domains?nsLdhName=ns1.example*.net");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"domainSearchResults\":[{"), response.body());
        assertTrue(response.body().contains("\"ldhName\":\"byhost.xx\""), response.body());
    }

    @Test
    void domainSearchSupportsExactAndPartialNames() throws Exception {
        var r = get("/rdap/domains?name=alpha*.xx");
        assertEquals(200, r.statusCode(), r.body());
        assertTrue(r.body().contains("\"domainSearchResults\":[{"), r.body());
        assertTrue(r.body().contains("\"ldhName\":\"alpha.xx\""), r.body());

        var exact = get("/rdap/domains?name=alpha.xx");
        assertEquals(200, exact.statusCode(), exact.body());
        assertTrue(exact.body().contains("alpha.xx"), exact.body());
    }

    @Test
    void nameserverSearchReturnsPublicNameserverObjects() throws Exception {
        reg.createHost("reg1", "ns1.example.net", List.of("192.0.2.53"), List.of("2001:db8::53"));
        var r = get("/rdap/nameservers?name=ns1.example*.net");
        assertEquals(200, r.statusCode(), r.body());
        assertTrue(r.body().contains("\"nameserverSearchResults\":[{"), r.body());
        assertTrue(r.body().contains("\"ldhName\":\"ns1.example.net\""), r.body());
        assertTrue(r.body().contains("192.0.2.53"), r.body());
    }

    @Test
    void nameserverSearchByIpv4ReturnsMatchingNameserver() throws Exception {
        reg.createHost("reg1", "ns-ipv4.example.net", List.of("192.0.2.53"), List.of());

        var response = get("/rdap/nameservers?ip=192.0.2.53");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"nameserverSearchResults\":[{"), response.body());
        assertTrue(response.body().contains("\"ldhName\":\"ns-ipv4.example.net\""), response.body());
        assertTrue(response.body().contains("\"v4\":[\"192.0.2.53\"]"), response.body());
    }

    @Test
    void nameserverSearchByIpv6MatchesEquivalentPresentation() throws Exception {
        reg.createHost("reg1", "ns-ipv6.example.net", List.of(), List.of("2001:db8::53"));

        var response = get("/rdap/nameservers?ip=2001:0db8:0:0:0:0:0:53");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"ldhName\":\"ns-ipv6.example.net\""), response.body());
        assertTrue(response.body().contains("\"v6\":[\"2001:db8::53\"]"), response.body());
    }

    @Test
    void nameserverSearchByIpRejectsMalformedAddress() throws Exception {
        var response = get("/rdap/nameservers?ip=999.999.999.999");
        assertEquals(400, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"errorCode\":400"), response.body());
    }

    @Test
    void nameserverSearchByIpReturnsEmptyResultsForUnknownAddress() throws Exception {
        var response = get("/rdap/nameservers?ip=192.0.2.254");
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.body().contains("\"nameserverSearchResults\":[]"), response.body());
    }

    @Test
    void registrarEntitySearchSupportsHandleAndName() throws Exception {
        var handle = get("/rdap/entities?handle=reg*");
        assertEquals(200, handle.statusCode(), handle.body());
        assertTrue(handle.body().contains("\"entitySearchResults\":[{"), handle.body());
        assertTrue(handle.body().contains("\"handle\":\"reg1\""), handle.body());

        var name = get("/rdap/entities?fn=Registrar%20O*");
        assertEquals(200, name.statusCode(), name.body());
        assertTrue(name.body().contains("Registrar One"), name.body());
    }

    @Test
    void rdapSearchRejectsMultipleAsterisksAndMultipleSelectors() throws Exception {
        assertEquals(400, get("/rdap/domains?name=a*b*.xx").statusCode());
        assertEquals(400, get("/rdap/domains?name=alpha.xx&name=beta.xx").statusCode());
    }


    @Test
    void rdapSearchCountAndCursorPagingWork() throws Exception {
        for (int i = 0; i < 27; i++) {
            String name = String.format(java.util.Locale.ROOT, "page%02d.xx", i);
            reg.createDomain("reg1", name, 1, "con1", List.of("ns1.example.net", "ns2.example.net"), "auth-secret-" + i);

        }
        var first = get("/rdap/domains?name=page*.xx&count=true");
        assertEquals(200, first.statusCode(), first.body());
        assertTrue(first.body().contains("\"totalCount\":27"), first.body());
        assertTrue(first.body().contains("\"pageSize\":25"), first.body());
        assertTrue(first.body().contains("\"pageNumber\":1"), first.body());
        assertTrue(first.body().contains("\"paging\""), first.body());
        int href = first.body().indexOf("\"href\":\"");
        assertTrue(href >= 0, first.body());
        int start = href + "\"href\":\"".length();
        int end = first.body().indexOf('"', start);
        String next = first.body().substring(start, end);
        var second = get(next);
        assertEquals(200, second.statusCode(), second.body());
        assertTrue(second.body().contains("\"pageNumber\":2"), second.body());
        assertTrue(second.body().contains("page25.xx"), second.body());
        assertTrue(second.body().contains("page26.xx"), second.body());
    }

    @Test
    void rdapSearchSupportsSortingAndRejectsInvalidPagingParameters() throws Exception {
        reg.createDomain("reg1", "beta.xx", 1, "con1", List.of("ns1.example.net", "ns2.example.net"), "auth-secret-beta");

        var descending = get("/rdap/domains?name=*.xx&sort=name:d");
        assertEquals(200, descending.statusCode(), descending.body());
        assertTrue(descending.body().contains("\"currentSort\":\"name:d\""), descending.body());
        assertTrue(descending.body().indexOf("beta.xx") < descending.body().indexOf("alpha.xx"), descending.body());
        assertEquals(400, get("/rdap/domains?name=alpha.xx&count=maybe").statusCode());
        assertEquals(400, get("/rdap/domains?name=alpha.xx&sort=unknown").statusCode());
        assertEquals(400, get("/rdap/domains?name=alpha.xx&cursor=not-a-valid-cursor").statusCode());
    }

    @Test
    void rateLimitReturns429ThenRecovers() throws Exception {
        for (int i = 0; i < 5; i++) assertEquals(200, get("/rdap/domain/alpha.xx").statusCode());
        var limited = get("/rdap/domain/alpha.xx");
        assertEquals(429, limited.statusCode());
        assertEquals("1", limited.headers().firstValue("Retry-After").orElse(""));
        nanos.addAndGet(2_000_000_000L);                                      // two seconds later
        assertEquals(200, get("/rdap/domain/alpha.xx").statusCode());
    }

    @Test
    void zoneFileReflectsOutbox(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        ZoneWriter zw = new ZoneWriter(reg, dir.resolve("zone.txt"));
        assertTrue(zw.runOnce());
        String z = Files.readString(dir.resolve("zone.txt"));
        assertTrue(z.contains("alpha IN NS ns1.example.net."), z);
        assertFalse(zw.runOnce());                                            // nothing pending now
        reg.deleteDomain("reg1", "alpha.xx");
        assertTrue(zw.runOnce());
        assertFalse(Files.readString(dir.resolve("zone.txt")).contains("alpha"));
    }
}
