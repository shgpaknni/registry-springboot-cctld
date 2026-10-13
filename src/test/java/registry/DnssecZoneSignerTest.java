package registry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnssecZoneSignerTest {
    @TempDir Path tempDir;

    private static final String SIGNED_ZONE = """
            $ORIGIN xx.
            $TTL 3600
            @ IN SOA ns1.example.net. hostmaster.example.net. ( 1 3600 600 1209600 300 )
            @ IN NS ns1.example.net.
            @ IN NS ns2.example.net.
            @ IN DNSKEY 257 3 13 AAAAAAAAAAAAAAAAAAAA
            @ IN RRSIG SOA 13 1 3600 20300101000000 20200101000000 12345 xx. AAAAAA
            @ IN NSEC ns1.example.net. NS SOA RRSIG NSEC DNSKEY
            @ IN RRSIG NSEC 13 1 3600 20300101000000 20200101000000 12345 xx. AAAAAA
            """;

    private Path keyDirectory() throws IOException {
        Path dir = tempDir.resolve("keys");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("Kxx.+013+12345.key"), "dummy public key");
        Files.writeString(dir.resolve("Kxx.+013+12345.private"), "dummy private key");
        return dir;
    }

    @Test
    void signsAndVerifiesOutputBeforeAcceptingIt() throws Exception {
        Path keys = keyDirectory();
        Path unsigned = tempDir.resolve("unsigned.db");
        Path signed = tempDir.resolve("signed.db");
        Files.writeString(unsigned, "$ORIGIN xx.\n@ IN SOA ns1.example.net. hostmaster.example.net. ( 1 3600 600 1209600 300 )\n");

        List<List<String>> calls = new ArrayList<>();
        DnssecZoneSigner signer = new DnssecZoneSigner(
                "fake-signzone", "fake-verify", keys, "xx.",
                Duration.ofSeconds(1),
                (command, timeout, log) -> {
                    calls.add(command);
                    if (command.get(0).equals("fake-signzone")) {
                        Path output = Path.of(command.get(command.indexOf("-f") + 1));
                        Files.writeString(output, SIGNED_ZONE);
                    }
                });

        signer.sign(unsigned, signed);

        String result = Files.readString(signed);
        assertTrue(result.contains(" DNSKEY "));
        assertTrue(result.contains(" RRSIG "));
        assertTrue(result.contains(" NSEC "));
        assertEquals(2, calls.size());
        assertEquals("fake-signzone", calls.get(0).get(0));
        assertTrue(calls.get(0).contains("-o"));
        assertTrue(calls.get(0).contains("xx."));
        assertTrue(calls.get(0).contains(keys.resolve("Kxx.+013+12345.key").toAbsolutePath().toString()));
        assertEquals(List.of("fake-verify", "-o", "xx.", signed.toAbsolutePath().toString()), calls.get(1));
    }

    @Test
    void rejectsSignerOutputWithoutDnssecRecordsAndDoesNotRunVerifier() throws Exception {
        Path keys = keyDirectory();
        Path unsigned = tempDir.resolve("unsigned.db");
        Path signed = tempDir.resolve("signed.db");
        Files.writeString(unsigned, "$ORIGIN xx.\n");

        List<List<String>> calls = new ArrayList<>();
        DnssecZoneSigner signer = new DnssecZoneSigner(
                "fake-signzone", "fake-verify", keys, "xx.",
                Duration.ofSeconds(1),
                (command, timeout, log) -> {
                    calls.add(command);
                    if (command.get(0).equals("fake-signzone")) {
                        Path output = Path.of(command.get(command.indexOf("-f") + 1));
                        Files.writeString(output, "$ORIGIN xx.\n@ IN SOA ns1.example.net. hostmaster.example.net. ( 1 3600 600 1209600 300 )\n");
                    }
                });

        IOException error = assertThrows(IOException.class, () -> signer.sign(unsigned, signed));
        assertTrue(error.getMessage().contains("DNSKEY"));
        assertEquals(1, calls.size());
        assertFalse(Files.exists(signed));
    }

    @Test
    void refusesToSignWithoutAKeyPair() throws Exception {
        Path keys = tempDir.resolve("empty-keys");
        Files.createDirectories(keys);
        Path unsigned = tempDir.resolve("unsigned.db");
        Path signed = tempDir.resolve("signed.db");
        Files.writeString(unsigned, "$ORIGIN xx.\n");

        DnssecZoneSigner signer = new DnssecZoneSigner(
                "fake-signzone", "fake-verify", keys, "xx.",
                Duration.ofSeconds(1),
                (command, timeout, log) -> fail("Command must not run without keys"));

        IOException error = assertThrows(IOException.class, () -> signer.sign(unsigned, signed));
        assertTrue(error.getMessage().contains("No matching BIND"));
    }
}
