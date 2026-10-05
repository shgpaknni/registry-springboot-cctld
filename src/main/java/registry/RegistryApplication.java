package registry;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

import javax.net.ssl.SSLContext;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;

@SpringBootApplication
@EnableScheduling
public class RegistryApplication {

    public static void main(String[] args) {
        SpringApplication.run(RegistryApplication.class, args);
    }

    @Bean
    Clock registryClock() {
        return Clock.systemUTC();
    }

    @Bean
    Config registryConfig(
            @Value("${registry.zone:xx}") String zone,
            @Value("${registry.fees.create-per-year:1000}") long createFee,
            @Value("${registry.fees.renew-per-year:1000}") long renewFee,
            @Value("${registry.fees.restore:4000}") long restoreFee,
            @Value("${registry.max-years:10}") int maxYears,
            @Value("${registry.max-sessions-per-registrar:10}") int maxSessions,
            @Value("${registry.idle-seconds:300}") int idleSeconds,
            @Value("${registry.pbkdf2-iterations:60000}") int iterations) {
        return new Config(
                zone, createFee, renewFee, restoreFee,
                java.time.Duration.ofDays(5),
                java.time.Duration.ofDays(45),
                java.time.Duration.ofDays(30),
                java.time.Duration.ofDays(5),
                maxYears,
                java.util.Set.of("nic", "whois", "www", "registry", "rdap"),
                maxSessions, idleSeconds, iterations);
    }

    @Bean
    Db registryDb(@Value("${registry.db:./data/registry}") String path) {
        return Db.file(path);
    }

    @Bean
    Registry registry(Db db, Config config, Clock clock) {
        return new Registry(db, config, clock);
    }

    @Bean(destroyMethod = "close")
    EppServer eppServer(
            Registry registry,
            @Value("${registry.tls.keystore:certs/server.p12}") String keyStore,
            @Value("${registry.tls.keystore-password:changeit}") String keyPass,
            @Value("${registry.tls.truststore:certs/server-trust.p12}") String trustStore,
            @Value("${registry.tls.truststore-password:changeit}") String trustPass,
            @Value("${registry.epp.port:7700}") int port) throws Exception {
        SSLContext ctx = Tls.context(Path.of(keyStore), keyPass.toCharArray(),
                Path.of(trustStore), trustPass.toCharArray());
        return new EppServer(registry, ctx, port);
    }

    @Bean(destroyMethod = "close")
    RdapServer rdapServer(
            Registry registry,
            @Value("${registry.rdap.bind:127.0.0.1}") String bind,
            @Value("${registry.rdap.port:8080}") int port,
            @Value("${registry.rdap.rate-limit-burst:20}") int burst,
            @Value("${registry.rdap.rate-limit-per-second:10}") double rate) throws Exception {
        return new RdapServer(registry,
                new InetSocketAddress(InetAddress.getByName(bind), port),
                new RateLimiter(burst, rate, System::nanoTime));
    }

    @Bean
    ZoneWriter zoneWriter(
            Registry registry,
            @Value("${registry.zone-file:./data/zone.txt}") String zoneFile) throws Exception {
        Path file = Path.of(zoneFile);
        Files.createDirectories(file.toAbsolutePath().getParent());
        return new ZoneWriter(registry, file);
    }

    @Bean
    RegistryScheduler registryScheduler(Registry registry, ZoneWriter zoneWriter) {
        return new RegistryScheduler(registry, zoneWriter);
    }

    @Bean
    CommandLineRunner startupSummary(EppServer epp, RdapServer rdap, Config config) {
        return args -> System.out.printf(
                "ccTLD registry started: zone=.%s, EPP=%d, RDAP=%d%n",
                config.zone(), epp.port(), rdap.port());
    }
}
