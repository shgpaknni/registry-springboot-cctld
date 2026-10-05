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
