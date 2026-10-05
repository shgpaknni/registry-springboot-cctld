package registry;

import org.springframework.scheduling.annotation.Scheduled;

/**
 * Spring-managed replacement for the prototype's ScheduledExecutorService.
 * Zone publication is frequent; lifecycle transitions run hourly.
 */
public final class RegistryScheduler {
    private final Registry registry;
    private final ZoneWriter zoneWriter;

    public RegistryScheduler(Registry registry, ZoneWriter zoneWriter) {
        this.registry = registry;
        this.zoneWriter = zoneWriter;
    }

    @Scheduled(initialDelay = 1000, fixedDelay = 5000)
    public void publishZone() {
        try {
            zoneWriter.runOnce();
        } catch (Exception e) {
            System.err.println("zone publish failed: " + e);
        }
    }

    @Scheduled(initialDelay = 1000, fixedDelay = 3600000)
    public void runLifecycle() {
        try {
            registry.runLifecycle();
        } catch (Exception e) {
            System.err.println("lifecycle failed: " + e);
        }
    }
}
