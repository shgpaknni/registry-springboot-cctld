package registry;

import java.time.Duration;
import java.util.Set;

/** Registry policy. Fees are in minor currency units (currency/tax are open questions, OQ-3). */
public record Config(String zone, long createFeePerYear, long renewFeePerYear, long restoreFee,
                     Duration addGrace, Duration autoRenewGrace, Duration redemption, Duration pendingDelete,
                     int maxYears, Set<String> reserved, int maxSessionsPerRegistrar, int idleSeconds,
                     int pbkdf2Iterations) {
    public static Config defaults(String zone) {
        return new Config(zone, 1000, 1000, 4000,
                Duration.ofDays(5), Duration.ofDays(45), Duration.ofDays(30), Duration.ofDays(5),
                10, Set.of("nic", "whois", "www", "registry", "rdap"), 10, 300, 60_000);
    }

    public Config withPbkdf2Iterations(int n) {
        return new Config(zone, createFeePerYear, renewFeePerYear, restoreFee, addGrace, autoRenewGrace,
                redemption, pendingDelete, maxYears, reserved, maxSessionsPerRegistrar, idleSeconds, n);
    }

    public Config withMaxSessions(int n) {
        return new Config(zone, createFeePerYear, renewFeePerYear, restoreFee, addGrace, autoRenewGrace,
                redemption, pendingDelete, maxYears, reserved, n, idleSeconds, pbkdf2Iterations);
    }
}
