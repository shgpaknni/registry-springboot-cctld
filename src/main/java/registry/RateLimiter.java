package registry;

import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** Per-key token bucket (FR-031). Prototype: unbounded key map; production uses HAProxy stick tables (ADR-010). */
public final class RateLimiter {
    private static final class Bucket {
        double tokens;
        long last;
    }

    private final double capacity;
    private final double perNano;
    private final LongSupplier nanos;
    private final Map<String, Bucket> buckets = new HashMap<>();

    public RateLimiter(int burst, double perSecond, LongSupplier nanos) {
        this.capacity = burst;
        this.perNano = perSecond / 1_000_000_000.0;
        this.nanos = nanos;
    }

    public synchronized boolean tryAcquire(String key) {
        long n = nanos.getAsLong();
        Bucket b = buckets.get(key);
        if (b == null) {
            b = new Bucket();
            b.tokens = capacity;
            b.last = n;
            buckets.put(key, b);
        }
        b.tokens = Math.min(capacity, b.tokens + (n - b.last) * perNano);
        b.last = n;
        if (b.tokens >= 1) {
            b.tokens -= 1;
            return true;
        }
        return false;
    }
}
