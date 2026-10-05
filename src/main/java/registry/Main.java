package registry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.CertificateFactory;
import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Starts the prototype.
 *   java registry.Main --create-registrar ID NAME PASSWORD CLIENT_CERT.crt BALANCE
 *   java registry.Main            (serves EPP + RDAP, configured by environment variables)
 */
public final class Main {
    private static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? d : v;
    }

    public static void main(String[] a) throws Exception {
        Config cfg = Config.defaults(env("REGISTRY_ZONE", "xx"));
        Db db = Db.file(env("REGISTRY_DB", "./data/registry"));
        Registry reg = new Registry(db, cfg, Clock.systemUTC());

        if (a.length == 6 && a[0].equals("--create-registrar")) {
            try (var in = Files.newInputStream(Path.of(a[4]))) {
                var cert = CertificateFactory.getInstance("X.509").generateCertificate(in);
                reg.createRegistrar(a[1], a[2], a[3], Tls.fingerprint(cert), Long.parseLong(a[5]), 0);
            }
            System.out.println("Registrar " + a[1] + " created.");
            return;
        }

        char[] pass = env("TLS_PASS", "changeit").toCharArray();
        var ctx = Tls.context(Path.of(env("TLS_KEYSTORE", "certs/server.p12")), pass, Path.of(env("TLS_TRUSTSTORE", "certs/server-trust.p12")), pass);
        var epp = new EppServer(reg, ctx, Integer.parseInt(env("EPP_PORT", "7700")));
        var rdap = new RdapServer(reg, new InetSocketAddress(InetAddress.getByName(env("RDAP_BIND", "127.0.0.1")), Integer.parseInt(env("RDAP_PORT", "8080"))),
                new RateLimiter(20, 10, System::nanoTime));
        var zone = new ZoneWriter(reg, Path.of(env("ZONE_FILE", "./data/zone.txt")));
        Files.createDirectories(Path.of(env("ZONE_FILE", "./data/zone.txt")).toAbsolutePath().getParent());

        var sched = Executors.newScheduledThreadPool(1);
        sched.scheduleWithFixedDelay(() -> {
            try { zone.runOnce(); } catch (Exception e) { System.err.println("zone publish failed: " + e); }
        }, 1, 5, TimeUnit.SECONDS);
        sched.scheduleWithFixedDelay(() -> {
            try { reg.runLifecycle(); } catch (Exception e) { System.err.println("lifecycle failed: " + e); }
        }, 1, 3600, TimeUnit.SECONDS);
        System.out.println("EPP on " + epp.port() + ", RDAP on " + rdap.port() + ", zone ." + cfg.zone());
    }
}
