package registry;

import java.time.*;

final class TestClock extends Clock {
    private Instant now = Instant.parse("2026-10-05T00:00:00Z");

    @Override public ZoneId getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(ZoneId zone) { return this; }
    @Override public Instant instant() { return now; }
    void advance(Duration d) { now = now.plus(d); }
}
