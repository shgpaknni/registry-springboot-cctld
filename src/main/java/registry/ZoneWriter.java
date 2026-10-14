package registry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates the authoritative master zone. When DNSSEC is enabled, the generated
 * file is signed and verified before it atomically replaces the published zone.
 */
public final class ZoneWriter {
    private static final long UINT32_MASK = 0xffff_ffffL;
    private static final long SERIAL_HALF_RANGE = 0x8000_0000L;

    private final Registry reg;
    private final Path file;
    private final DnssecZoneSigner signer;
    private final List<String> apexNameServers;
    private final String soaMname;
    private final String soaRname;
    private final long soaRefresh;
    private final long soaRetry;
    private final long soaExpire;
    private final long soaMinimum;

    /** Backwards-compatible constructor for the prototype's unsigned/test configuration. */
    public ZoneWriter(Registry reg, Path file) {
        this(reg, file, null, defaultNameServers(reg), null, null,
                3600, 600, 1_209_600, 300);
    }

    public ZoneWriter(
            Registry reg,
            Path file,
            DnssecZoneSigner signer,
            List<String> apexNameServers,
            String soaMname,
            String soaRname,
            long soaRefresh,
            long soaRetry,
            long soaExpire,
            long soaMinimum) {

        this.reg = Objects.requireNonNull(reg, "registry");
        this.file = Objects.requireNonNull(file, "zone file").toAbsolutePath().normalize();
        this.signer = signer;

        if (apexNameServers == null || apexNameServers.isEmpty()) {
            throw new IllegalArgumentException("At least one apex nameserver is required");
        }
        this.apexNameServers = apexNameServers.stream()
                .map(ZoneWriter::fqdn)
                .distinct()
                .toList();

        if (this.apexNameServers.isEmpty()) {
            throw new IllegalArgumentException("At least one apex nameserver is required");
        }

        String origin = fqdn(reg.config().zone());
        this.soaMname = soaMname == null || soaMname.isBlank()
                ? this.apexNameServers.get(0) : fqdn(soaMname);
        this.soaRname = soaRname == null || soaRname.isBlank()
                ? fqdn("hostmaster." + origin) : fqdn(soaRname);

        if (soaRefresh <= 0 || soaRetry <= 0 || soaExpire <= 0 || soaMinimum <= 0) {
            throw new IllegalArgumentException("SOA timers must be positive");
        }
        this.soaRefresh = soaRefresh;
        this.soaRetry = soaRetry;
        this.soaExpire = soaExpire;
        this.soaMinimum = soaMinimum;
    }

    private static List<String> defaultNameServers(Registry reg) {
        String origin = fqdn(reg.config().zone());
        return List.of("ns1." + origin, "ns2." + origin);
    }

    static String fqdn(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("DNS name is required");
        }
        String value = name.trim();
        if (value.chars().anyMatch(Character::isWhitespace) || value.contains("..")) {
            throw new IllegalArgumentException("Invalid DNS name: " + name);
        }
        while (value.endsWith(".") && !value.isEmpty()) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Invalid DNS name: " + name);
        }
        return value.toLowerCase(Locale.ROOT) + ".";
    }

    /** Publish only when there are queued changes; failed signing leaves the outbox pending. */
    public boolean runOnce() throws IOException {
        long max = reg.pendingOutboxMax();
        if (max == 0) return false;
        write();
        reg.markOutboxPublished(max);
        return true;
    }

    public synchronized void write() throws IOException {
        Path parent = file.getParent();
        Files.createDirectories(parent);

        Path unsigned = parent.resolve(file.getFileName() + ".unsigned.tmp");
        Path signed = parent.resolve(file.getFileName() + ".signed.tmp");

        try {
            Files.writeString(unsigned, renderZone(nextSerial()), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            Path candidate = unsigned;
            if (signer != null) {
                signer.sign(unsigned, signed);
                candidate = signed;
            }

            try {
                Files.move(candidate, file,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(candidate, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(unsigned);
            Files.deleteIfExists(signed);
        }
    }

    private String renderZone(long serial) {
        String origin = fqdn(reg.config().zone());
        StringBuilder sb = new StringBuilder();
        sb.append("; generated ")
                .append(Instant.now(reg.clock()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS))
                .append('\n');
        sb.append("$ORIGIN ").append(origin).append('\n');
        sb.append("$TTL 3600\n");
        sb.append("@ IN SOA ").append(soaMname).append(' ').append(soaRname).append(" (\n")
                .append("  ").append(serial).append(" ; serial\n")
                .append("  ").append(soaRefresh).append(" ; refresh\n")
                .append("  ").append(soaRetry).append(" ; retry\n")
                .append("  ").append(soaExpire).append(" ; expire\n")
                .append("  ").append(soaMinimum).append(" ; negative-cache TTL\n")
                .append(")\n");

        for (String ns : apexNameServers) {
            sb.append("@ IN NS ").append(ns).append('\n');
        }

        for (Map.Entry<String, List<String>> entry : reg.zoneEntries().entrySet()) {
            String label = Names.label(entry.getKey(), reg.config());
            for (String ns : entry.getValue()) {
                sb.append(label).append(" IN NS ").append(fqdn(ns)).append('\n');
            }
        }

        // Publish A/AAAA records for in-zone host objects; these are the glue records for delegations.
        for (Map.Entry<String, Registry.HostAddresses> entry : reg.zoneHostAddresses().entrySet()) {
            String owner = relativeName(entry.getKey(), reg.config().zone());
            Registry.HostAddresses addresses = entry.getValue();
            for (String address : addresses.ipv4()) {
                sb.append(owner).append(" IN A ").append(address).append('\n');
            }
            for (String address : addresses.ipv6()) {
                sb.append(owner).append(" IN AAAA ").append(address).append('\n');
            }
        }

        // Child DS RRsets are authoritative on the parent side of each delegation.
        for (Map.Entry<String, List<Registry.DsData>> entry : reg.zoneDsEntries().entrySet()) {
            String label = Names.label(entry.getKey(), reg.config());
            for (Registry.DsData ds : entry.getValue()) {
                sb.append(label).append(" IN DS ")
                        .append(ds.keyTag()).append(' ')
                        .append(ds.alg()).append(' ')
                        .append(ds.digestType()).append(' ')
                        .append(ds.digest().toUpperCase(Locale.ROOT))
                        .append('\n');
            }
        }
        return sb.toString();
    }

    private static String relativeName(String host, String zone) {
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        String suffix = "." + zone.toLowerCase(Locale.ROOT);
        if (!normalizedHost.endsWith(suffix)) {
            throw new IllegalArgumentException("Glue host is outside configured zone: " + host);
        }
        return normalizedHost.substring(0, normalizedHost.length() - suffix.length());
    }

    /** 32-bit SOA serial using RFC 1982 serial arithmetic relative to the currently published file. */
    private long nextSerial() throws IOException {
        long candidate = Instant.now(reg.clock()).getEpochSecond() & UINT32_MASK;
        if (!Files.isRegularFile(file)) return candidate;

        String old = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = Pattern.compile(
                "(?is)\\bSOA\\s+\\S+\\s+\\S+\\s+\\(?\\s*(\\d{1,10})")
                .matcher(old);
        if (!m.find()) return candidate;

        long previous;
        try {
            previous = Long.parseUnsignedLong(m.group(1)) & UINT32_MASK;
        } catch (NumberFormatException e) {
            return candidate;
        }

        long difference = (candidate - previous) & UINT32_MASK;
        if (difference == 0 || difference >= SERIAL_HALF_RANGE) {
            candidate = (previous + 1) & UINT32_MASK;
        }
        return candidate;
    }
}
