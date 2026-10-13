package registry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class ZoneWriterTest {
    @TempDir Path tempDir;
    Registry reg;

    @BeforeEach
    void setup() {
        reg = new Registry(Db.inMemory(),
                Config.defaults("xx").withPbkdf2Iterations(1000), new TestClock());
        reg.createRegistrar("reg1", "Registrar One",
                "correct-horse-battery", "fp1", 100_000, 0);
        reg.createContact("reg1", "con1", "Asha Rao", null,
                "asha@example.org", null, "IN");
        reg.createDomain("reg1", "alpha.xx", 1, "con1",
                List.of("ns1.example.net", "ns2.example.net"), "auth-secret-1");
        reg.secDnsCreate("reg1", "alpha.xx",
                List.of(new Registry.DsData(12345, 13, 2, "aabbccddeeff0011")),
                List.of());
    }

    private ZoneWriter writer(Path file, DnssecZoneSigner signer) {
        return new ZoneWriter(reg, file, signer,
                List.of("ns1.example.net.", "ns2.example.net."),
                "ns1.example.net.", "hostmaster.example.net.",
                3600, 600, 1_209_600, 300);
    }

    @Test
    void writesSoaApexNameserversDelegationAndChildDs() throws Exception {
        Path file = tempDir.resolve("zone.db");
        writer(file, null).write();
        String zone = Files.readString(file, StandardCharsets.UTF_8);

        assertTrue(zone.contains("$ORIGIN xx."));
        assertTrue(zone.contains("@ IN SOA ns1.example.net. hostmaster.example.net. ("));
        assertTrue(zone.contains("@ IN NS ns1.example.net."));
        assertTrue(zone.contains("@ IN NS ns2.example.net."));
        assertTrue(zone.contains("alpha IN NS ns1.example.net."));
        assertTrue(zone.contains("alpha IN DS 12345 13 2 AABBCCDDEEFF0011"));
        assertFalse(zone.contains("RRSIG")); // This test intentionally uses unsigned mode.
    }

    @Test
    void incrementsSoaSerialWhenRegeneratingSameSecond() throws Exception {
        Path file = tempDir.resolve("zone.db");
        ZoneWriter writer = writer(file, null);

        writer.write();
        long first = serial(Files.readString(file));
        writer.write();
        long second = serial(Files.readString(file));

        assertEquals((first + 1) & 0xffff_ffffL, second);
    }

    @Test
    void failedSigningPreservesLastPublishedZoneAndDoesNotAcknowledgeOutbox() throws Exception {
        Path file = tempDir.resolve("zone.db");
        Files.writeString(file, "LAST_GOOD_SIGNED_ZONE");
        Path keys = tempDir.resolve("keys");
        Files.createDirectories(keys);
        Files.writeString(keys.resolve("Kxx.+013+12345.key"), "dummy public key");
        Files.writeString(keys.resolve("Kxx.+013+12345.private"), "dummy private key");

        List<List<String>> commands = new ArrayList<>();
        DnssecZoneSigner signer = new DnssecZoneSigner(
                "fake-signzone", "fake-verify", keys, "xx.",
                Duration.ofSeconds(1),
                (command, timeout, log) -> {
                    commands.add(command);
                    if (command.get(0).equals("fake-signzone")) {
                        Path output = Path.of(command.get(command.indexOf("-f") + 1));
                        Files.writeString(output, "$ORIGIN xx.\n@ IN SOA ns1.example.net. hostmaster.example.net. ( 1 3600 600 1209600 300 )\n");
                    }
                });

        long pendingBefore = reg.pendingOutboxMax();
        assertThrows(IOException.class, () -> writer(file, signer).runOnce());

        assertEquals("LAST_GOOD_SIGNED_ZONE", Files.readString(file));
        assertEquals(pendingBefore, reg.pendingOutboxMax());
        assertEquals(1, commands.size()); // Verification is not attempted on structurally unsigned output.
    }

    private static long serial(String zone) {
        Matcher m = Pattern.compile(
                "(?is)\\bSOA\\s+\\S+\\s+\\S+\\s+\\(?\\s*(\\d{1,10})").matcher(zone);
        assertTrue(m.find(), "SOA serial not found");
        return Long.parseUnsignedLong(m.group(1));
    }
}
