package registry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegistryTest {
    static final List<String> NS = List.of("ns1.example.net", "ns2.example.net");
    TestClock clock;
    Db db;
    Registry reg;

    @BeforeEach
    void setUp() {
        clock = new TestClock();
        db = Db.inMemory();
        reg = new Registry(db, Config.defaults("xx").withPbkdf2Iterations(1000), clock);
        reg.createRegistrar("reg1", "Registrar One", "correct-horse-battery", "fp1", 100_000, 0);
        reg.createRegistrar("reg2", "Registrar Two", "another-long-password", "fp2", 100_000, 0);
        reg.createContact("reg1", "con1", "Asha Rao", "Example Org", "asha@example.org", "+91.8000000000", "IN");
        reg.createContact("reg2", "con2", "Ravi Kumar", null, "ravi@example.org", null, "IN");
    }

    int code(Runnable r) {
        return assertThrows(RegistryException.class, r::run).code;
    }

    Registry.DomainView create(String name, int years) {
        return reg.createDomain("reg1", name, years, "con1", NS, "auth-secret-1");
    }

    @Test
    void createChargesLedgerAndSetsExpiry() {
        var v = create("alpha.xx", 2);
        assertEquals("ACTIVE", v.state());
        assertEquals(100_000 - 2_000, reg.balance("reg1"));
        assertEquals(clock.instant().atZone(ZoneOffset.UTC).plusYears(2).toEpochSecond(), v.expires());
        assertEquals(NS, v.ns());
    }

    @Test
    void duplicateIsRejectedAndNotCharged() {
        create("alpha.xx", 1);
        assertEquals(2302, code(() -> create("ALPHA.xx.", 1)));
        assertEquals(99_000, reg.balance("reg1"));
    }

    @Test
    void policyAndSyntaxRules() {
        assertEquals(2306, code(() -> create("nic.xx", 1)));              // reserved
        assertEquals(2005, code(() -> create("-bad.xx", 1)));            // leading hyphen
        assertEquals(2005, code(() -> create("ab--cd.xx", 1)));          // hyphens at 3-4
        assertEquals(2005, code(() -> create("under_score.xx", 1)));
        assertEquals(2306, code(() -> create("other.com", 1)));          // wrong zone
        assertEquals(2306, code(() -> create("a.b.xx", 1)));             // third level
        assertEquals(2004, code(() -> create("ok.xx", 11)));             // term
        assertEquals(2005, code(() -> create("xn--zzzzzzzzzzzz.xx", 1))); // not valid punycode
        assertTrue(reg.check("xn--mnchen-3ya.xx").available());          // valid IDN (munchen with umlaut)
        assertFalse(reg.check("nic.xx").available());
        assertEquals(0, reg.ledgerCount("reg1"));
    }

    @Test
    void nameServerRules() {
        assertEquals(2004, code(() -> reg.createDomain("reg1", "one.xx", 1, "con1", List.of("ns1.example.net"), "auth-secret-1")));
        assertEquals(2306, code(() -> reg.createDomain("reg1", "two.xx", 1, "con1", List.of("ns1.two.xx", "ns2.example.net"), "auth-secret-1")));
        assertEquals(2005, code(() -> reg.createDomain("reg1", "three.xx", 1, "con1", List.of("bad host", "ns2.example.net"), "auth-secret-1")));
        assertEquals(2201, code(() -> reg.createDomain("reg1", "four.xx", 1, "con2", NS, "auth-secret-1"))); // other registrar's contact
        assertEquals(2303, code(() -> reg.createDomain("reg1", "five.xx", 1, "nope", NS, "auth-secret-1")));
    }

    @Test
    void insufficientFundsIsAtomic() {
        reg.createRegistrar("poor", "Poor", "poor-registrar-pass", "fp3", 500, 0);
        reg.createContact("poor", "conp", "P", null, "p@example.org", null, "IN");
        assertEquals(2104, code(() -> reg.createDomain("poor", "broke.xx", 1, "conp", NS, "auth-secret-1")));
        assertTrue(reg.check("broke.xx").available());
        assertEquals(500, reg.balance("poor"));
        assertEquals(0, reg.ledgerCount("poor"));
        assertTrue(reg.verifyAuditChain());
    }

    @Test
    void creditLimitAllowsOverdraft() {
        reg.createRegistrar("credit", "Credit", "credit-registrar-pass", "fp4", 0, 3_000);
        reg.createContact("credit", "conc", "C", null, "c@example.org", null, "IN");
        reg.createDomain("credit", "one.xx", 3, "conc", NS, "auth-secret-1");
        assertEquals(-3_000, reg.balance("credit"));
        assertEquals(2104, code(() -> reg.createDomain("credit", "two.xx", 1, "conc", NS, "auth-secret-1")));
    }

    @Test
    void suspendedRegistrarCannotWriteButRegistryKeepsData() {
        create("alpha.xx", 1);
        reg.setRegistrarStatus("reg1", "SUSPENDED");
        assertEquals(2201, code(() -> create("beta.xx", 1)));
        assertEquals(2201, code(() -> reg.deleteDomain("reg1", "alpha.xx")));
        assertTrue(reg.find("alpha.xx").isPresent());
    }

    @Test
    void renewRules() {
        var v = create("alpha.xx", 1);
        LocalDate exp = java.time.Instant.ofEpochSecond(v.expires()).atZone(ZoneOffset.UTC).toLocalDate();
        assertEquals(2306, code(() -> reg.renewDomain("reg1", "alpha.xx", exp.plusDays(1), 1)));   // wrong current expiry
        assertEquals(2201, code(() -> reg.renewDomain("reg2", "alpha.xx", exp, 1)));               // not sponsor
        assertEquals(2306, code(() -> reg.renewDomain("reg1", "alpha.xx", exp, 10)));              // exceeds 10 years total
        var r = reg.renewDomain("reg1", "alpha.xx", exp, 2);
        assertEquals(java.time.Instant.ofEpochSecond(v.expires()).atZone(ZoneOffset.UTC).plusYears(2).toEpochSecond(), r.expires());
        assertEquals(100_000 - 1_000 - 2_000, reg.balance("reg1"));
    }

    @Test
    void deleteInAddGraceRefundsAndPurges() {
        create("alpha.xx", 2);
        assertEquals(Registry.DeleteOutcome.PURGED, reg.deleteDomain("reg1", "alpha.xx"));
        assertEquals(100_000, reg.balance("reg1"));
        assertTrue(reg.find("alpha.xx").isEmpty());
        assertTrue(reg.check("alpha.xx").available());
    }

    @Test
    void deleteAfterAddGraceGoesToRedemptionAndCanBeRestored() {
        create("alpha.xx", 2);
        clock.advance(Duration.ofDays(6));
        assertTrue(reg.zoneEntries().containsKey("alpha.xx"));
        assertEquals(Registry.DeleteOutcome.REDEMPTION, reg.deleteDomain("reg1", "alpha.xx"));
        assertEquals("REDEMPTION", reg.find("alpha.xx").get().state());
        assertFalse(reg.zoneEntries().containsKey("alpha.xx"));
        assertEquals(98_000, reg.balance("reg1"));                                 // no refund
        assertEquals(2201, code(() -> reg.restoreDomain("reg2", "alpha.xx")));
        reg.restoreDomain("reg1", "alpha.xx");
        assertEquals("ACTIVE", reg.find("alpha.xx").get().state());
        assertEquals(98_000 - 4_000, reg.balance("reg1"));
        assertTrue(reg.zoneEntries().containsKey("alpha.xx"));
    }

    @Test
    void lifecycleAdvancesStepByStep() {
        create("alpha.xx", 1);
        reg.runLifecycle();
        assertEquals("ACTIVE", reg.find("alpha.xx").get().state());

        clock.advance(Duration.ofDays(366));
        assertEquals(1, reg.runLifecycle());
        assertEquals("AUTORENEW_GRACE", reg.find("alpha.xx").get().state());
        assertTrue(reg.zoneEntries().containsKey("alpha.xx"));                    // still resolving in grace

        clock.advance(Duration.ofDays(45));
        reg.runLifecycle();
        assertEquals("REDEMPTION", reg.find("alpha.xx").get().state());
        assertFalse(reg.zoneEntries().containsKey("alpha.xx"));

        clock.advance(Duration.ofDays(30));
        reg.runLifecycle();
        assertEquals("PENDING_DELETE", reg.find("alpha.xx").get().state());

        clock.advance(Duration.ofDays(5));
        reg.runLifecycle();
        assertTrue(reg.find("alpha.xx").isEmpty());
    }

    @Test
    void lifecycleCatchesUpAfterLongOutage() {
        create("alpha.xx", 1);
        clock.advance(Duration.ofDays(365 + 45 + 30 + 5 + 2));
        assertEquals(4, reg.runLifecycle());
        assertTrue(reg.find("alpha.xx").isEmpty());
    }

    @Test
    void renewInGraceReturnsToActive() {
        var v = create("alpha.xx", 1);
        clock.advance(Duration.ofDays(370));
        reg.runLifecycle();
        LocalDate exp = java.time.Instant.ofEpochSecond(v.expires()).atZone(ZoneOffset.UTC).toLocalDate();
        assertEquals("ACTIVE", reg.renewDomain("reg1", "alpha.xx", exp, 1).state());
    }

    @Test
    void serverHoldRemovesFromZone() {
        create("alpha.xx", 1);
        reg.setServerHold("compliance", "alpha.xx", true);
        assertFalse(reg.zoneEntries().containsKey("alpha.xx"));
        reg.setServerHold("compliance", "alpha.xx", false);
        assertTrue(reg.zoneEntries().containsKey("alpha.xx"));
    }

    @Test
    void sponsorIsolation() {
        create("alpha.xx", 1);
        assertEquals(2201, code(() -> reg.domainInfo("reg2", "alpha.xx")));
        assertEquals(2201, code(() -> reg.deleteDomain("reg2", "alpha.xx")));
        assertEquals(2303, code(() -> reg.domainInfo("reg1", "missing.xx")));
    }

    @Test
    void authenticationNeedsPasswordAndPinnedCertificate() {
        assertTrue(reg.authenticate("reg1", "correct-horse-battery", "FP1"));
        assertFalse(reg.authenticate("reg1", "wrong-password-here", "fp1"));
        assertFalse(reg.authenticate("reg1", "correct-horse-battery", "fp2"));
        assertFalse(reg.authenticate("ghost", "whatever-password", "fp1"));
        reg.setRegistrarStatus("reg1", "TERMINATED");
        assertFalse(reg.authenticate("reg1", "correct-horse-battery", "fp1"));
    }

    @Test
    void auditChainDetectsTampering() throws Exception {
        create("alpha.xx", 1);
        create("beta.xx", 1);
        clock.advance(Duration.ofDays(6));
        reg.deleteDomain("reg1", "beta.xx");
        assertTrue(reg.verifyAuditChain());
        try (Connection c = db.open()) {
            c.createStatement().executeUpdate("UPDATE audit SET detail='forged' WHERE id=(SELECT MIN(id) FROM audit WHERE act='DOMAIN_CREATE')");
            c.commit();
        }
        assertFalse(reg.verifyAuditChain());
    }
}
