package registry;

import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Writes the zone delegation file and drains the outbox (ADR-005). Prototype uses full regeneration;
 * production sends incremental RFC 2136 updates to the Knot hidden primary and reconciles nightly (ADR-006).
 */
public final class ZoneWriter {
    private final Registry reg;
    private final Path file;

    public ZoneWriter(Registry reg, Path file) {
        this.reg = reg;
        this.file = file;
    }

    /** Publishes if there are pending outbox events. Returns true if a new zone file was written. */
    public boolean runOnce() throws IOException {
        long max = reg.pendingOutboxMax();
        if (max == 0) return false;
        write();
        reg.markOutboxPublished(max);
        return true;
    }

    public void write() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("; generated ").append(Instant.now(reg.clock()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS)).append('\n');
        sb.append("; SOA, apex NS and DNSSEC records are added by the signer\n");
        sb.append("$ORIGIN ").append(reg.config().zone()).append(".\n$TTL 3600\n");
        for (Map.Entry<String, List<String>> e : reg.zoneEntries().entrySet()) {
            String label = Names.label(e.getKey(), reg.config());
            for (String ns : e.getValue()) sb.append(label).append(" IN NS ").append(ns).append(".\n");
        }
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, sb.toString());
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
