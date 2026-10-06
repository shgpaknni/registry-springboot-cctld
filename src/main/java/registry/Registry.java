package registry;

import java.sql.Statement;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * Registry core: domain lifecycle, billing, audit and outbox. Every mutating command runs in ONE
 * database transaction (ADR-002). Prototype limitation: a process-wide write lock serialises writes
 * so the audit hash chain stays linear; production would use a different chaining strategy.
 */
public final class Registry {
    public record DomainView(String name, String sponsor, String registrant, String state, boolean serverHold,
                             long created, long expires, List<String> ns) {}

    public record Availability(String name, boolean available, String reason) {}

    public enum DeleteOutcome { PURGED, REDEMPTION }

    private record Row(String name, String sponsor, String registrant, String state, long created, long expires,
                       long since, boolean hold) {}

    @FunctionalInterface
    private interface Body<T> { T run(Connection c) throws Exception; }

    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern ID = Pattern.compile("^[A-Za-z0-9_-]{3,32}$");

    /*
     * RFC 5732 host/address validation.
     *
     * IPv4:
     *     four decimal octets, each 0-255
     *
     * IPv6:
     *     validated using java.net.InetAddress
     */
    private static final Pattern IPV4 =
            Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}$");

    private static final SecureRandom RNG = new SecureRandom();

    private final Db db;
    private final Config cfg;
    private final Clock clock;
    private final ReentrantLock writeLock = new ReentrantLock();
    private final String dummyHash;

    public Registry(Db db, Config cfg, Clock clock) {
        this.db = db;
        this.cfg = cfg;
        this.clock = clock;
        this.dummyHash = Pw.hash("dummy-password", cfg.pbkdf2Iterations());
    }

    public Config config() { return cfg; }

    public Clock clock() { return clock; }

    private long now() { return clock.instant().getEpochSecond(); }

    // ---------------------------------------------------------------- plumbing

    private <T> T tx(Body<T> body) {
        writeLock.lock();
        try (Connection c = db.open()) {
            try {
                T r = body.run(c);
                c.commit();
                return r;
            } catch (RegistryException e) {
                c.rollback();
                throw e;
            } catch (Exception e) {
                c.rollback();
                throw new RegistryException(2400, "Command failed", e);
            }
        } catch (SQLException e) {
            throw new RegistryException(2400, "Command failed", e);
        } finally {
            writeLock.unlock();
        }
    }

    private <T> T read(Body<T> body) {
        try (Connection c = db.open()) {
            try {
                return body.run(c);
            } finally {
                c.rollback();
            }
        } catch (RegistryException e) {
            throw e;
        } catch (Exception e) {
            throw new RegistryException(2400, "Command failed", e);
        }
    }

    private static List<Object[]> rows(Connection c, String sql, Object... args) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            try (ResultSet rs = ps.executeQuery()) {
                int n = rs.getMetaData().getColumnCount();
                List<Object[]> out = new ArrayList<>();
                while (rs.next()) {
                    Object[] r = new Object[n];
                    for (int i = 0; i < n; i++) r[i] = rs.getObject(i + 1);
                    out.add(r);
                }
                return out;
            }
        }
    }

    private static int update(Connection c, String sql, Object... args) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            return ps.executeUpdate();
        }
    }

    private static long num(Object o) { return ((Number) o).longValue(); }

    private static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long addYears(long epoch, int years) {
        return ZonedDateTime.ofInstant(Instant.ofEpochSecond(epoch), ZoneOffset.UTC).plusYears(years).toEpochSecond();
    }

    // ---------------------------------------------------------------- audit, outbox, billing

    private static final String GENESIS = "0".repeat(64);

    private void audit(Connection c, String actor, String act, String obj, String detail) throws SQLException {
        String d = detail.length() > 500 ? detail.substring(0, 500) : detail;
        List<Object[]> last = rows(c, "SELECT h FROM audit ORDER BY id DESC LIMIT 1");
        String prev = last.isEmpty() ? GENESIS : (String) last.get(0)[0];
        long ts = now();
        String h = sha256(prev + "|" + ts + "|" + actor + "|" + act + "|" + obj + "|" + d);
        update(c, "INSERT INTO audit(ts,actor,act,obj,detail,prev_h,h) VALUES(?,?,?,?,?,?,?)", ts, actor, act, obj, d, prev, h);
    }

    /** Recomputes the whole audit hash chain; false means a row was altered or removed (NFR-017). */
    public boolean verifyAuditChain() {
        return read(c -> {
            String prev = GENESIS;
            for (Object[] r : rows(c, "SELECT ts,actor,act,obj,detail,prev_h,h FROM audit ORDER BY id")) {
                String expect = sha256(prev + "|" + num(r[0]) + "|" + r[1] + "|" + r[2] + "|" + r[3] + "|" + r[4]);
                if (!prev.equals(r[5]) || !expect.equals(r[6])) return false;
                prev = (String) r[6];
            }
            return true;
        });
    }

    private void outbox(Connection c, String kind, String domain) throws SQLException {
        update(c, "INSERT INTO outbox(kind,domain_name,ts,published) VALUES(?,?,?,FALSE)", kind, domain, now());
    }

    public long pendingOutboxMax() {
        return read(c -> {
            Object o = rows(c, "SELECT MAX(id) FROM outbox WHERE published = FALSE").get(0)[0];
            return o == null ? 0L : num(o);
        });
    }

    public void markOutboxPublished(long upToId) {
        tx(c -> update(c, "UPDATE outbox SET published = TRUE WHERE id <= ?", upToId));
    }

    /** Atomic balance check plus debit in one statement; the ledger row is written in the same transaction (FR-032, FR-033). */
    private void charge(Connection c, String registrar, long amount, String kind, String domain) throws SQLException {
        int n = update(c, "UPDATE registrar SET balance = balance - ? WHERE id = ? AND status = 'ACTIVE' AND balance - ? >= -credit_limit",
                amount, registrar, amount);
        if (n == 0) throw new RegistryException(2104, "Billing failure: insufficient funds");
        update(c, "INSERT INTO ledger(registrar,domain_name,kind,amount,ts) VALUES(?,?,?,?,?)", registrar, domain, kind, -amount, now());
    }

    private void refund(Connection c, String registrar, long amount, String domain) throws SQLException {
        update(c, "UPDATE registrar SET balance = balance + ? WHERE id = ?", amount, registrar);
        update(c, "INSERT INTO ledger(registrar,domain_name,kind,amount,ts) VALUES(?,?,'REFUND',?,?)", registrar, domain, amount, now());
    }

    public long balance(String registrar) {
        return read(c -> num(rows(c, "SELECT balance FROM registrar WHERE id=?", registrar).get(0)[0]));
    }

    public int ledgerCount(String registrar) {
        return read(c -> (int) num(rows(c, "SELECT COUNT(*) FROM ledger WHERE registrar=?", registrar).get(0)[0]));
    }

    // ---------------------------------------------------------------- registrar administration

    public void createRegistrar(String id, String name, String password, String certFingerprint, long balance, long creditLimit) {
        if (!ID.matcher(id).matches()) throw new RegistryException(2005, "Invalid registrar id");
        if (password.length() < 12) throw new RegistryException(2005, "Password must be at least 12 characters");
        String hash = Pw.hash(password, cfg.pbkdf2Iterations());
        tx(c -> {
            if (!rows(c, "SELECT 1 FROM registrar WHERE id=?", id).isEmpty()) throw new RegistryException(2302, "Registrar exists");
            update(c, "INSERT INTO registrar(id,name,pw_hash,cert_fp,status,balance,credit_limit) VALUES(?,?,?,?, 'ACTIVE',?,?)",
                    id, name, hash, certFingerprint.toLowerCase(Locale.ROOT), balance, creditLimit);
            audit(c, "admin", "REGISTRAR_CREATE", id, name);
            return null;
        });
    }

    public void setRegistrarStatus(String id, String status) {
        if (!Set.of("ACTIVE", "SUSPENDED", "TERMINATED").contains(status)) throw new RegistryException(2005, "Bad status");
        tx(c -> {
            if (update(c, "UPDATE registrar SET status=? WHERE id=?", status, id) == 0) throw new RegistryException(2303, "No such registrar");
            audit(c, "admin", "REGISTRAR_STATUS", id, status);
            return null;
        });
    }

    public void topUp(String id, long amount) {
        if (amount <= 0) throw new RegistryException(2005, "Amount must be positive");
        tx(c -> {
            update(c, "UPDATE registrar SET balance = balance + ? WHERE id=?", amount, id);
            update(c, "INSERT INTO ledger(registrar,domain_name,kind,amount,ts) VALUES(?,NULL,'DEPOSIT',?,?)", id, amount, now());
            audit(c, "admin", "DEPOSIT", id, String.valueOf(amount));
            return null;
        });
    }

    /** Password plus pinned client-certificate check. Unknown ids cost the same time as wrong passwords. */
    public boolean authenticate(String id, String password, String certFingerprint) {
        return read(c -> {
            List<Object[]> r = rows(c, "SELECT pw_hash,cert_fp,status FROM registrar WHERE id=?", id);
            boolean pwOk = Pw.verify(password, r.isEmpty() ? dummyHash : (String) r.get(0)[0]);
            if (r.isEmpty()) return false;
            Object[] x = r.get(0);
            return pwOk && certFingerprint != null && certFingerprint.equalsIgnoreCase((String) x[1])
                    && !"TERMINATED".equals(x[2]);
        });
    }

    public String registrarName(String id) {
        return read(c -> {
            List<Object[]> r = rows(c, "SELECT name FROM registrar WHERE id=?", id);
            return r.isEmpty() ? id : (String) r.get(0)[0];
        });
    }

    private void requireActive(Connection c, String registrar) throws SQLException {
        List<Object[]> r = rows(c, "SELECT status FROM registrar WHERE id=?", registrar);
        if (r.isEmpty() || !"ACTIVE".equals(r.get(0)[0])) throw new RegistryException(2201, "Authorization error: registrar not active");
    }

    // ---------------------------------------------------------------- contacts

    public void createContact(String registrar, String id, String name, String org, String email, String phone, String country) {
        if (!ID.matcher(String.valueOf(id)).matches()) throw new RegistryException(2005, "Invalid contact id");
        if (name == null || name.isBlank()) throw new RegistryException(2003, "Missing contact name");
        if (email == null || !EMAIL.matcher(email).matches()) throw new RegistryException(2005, "Invalid email");
        if (country == null || !country.matches("[A-Z]{2}")) throw new RegistryException(2005, "Invalid country code");
        tx(c -> {
            requireActive(c, registrar);
            if (!rows(c, "SELECT 1 FROM contact WHERE id=?", id).isEmpty()) throw new RegistryException(2302, "Contact exists");
            update(c, "INSERT INTO contact(id,sponsor,name,org,email,phone,country,created) VALUES(?,?,?,?,?,?,?,?)",
                    id, registrar, name, org, email, phone, country, now());
            audit(c, registrar, "CONTACT_CREATE", id, "");
            return null;
        });
    }

    // ---------------------------------------------------------------- RFC 5732 HOST OBJECTS

    /**
     * RFC 5732 host object check.
     */
    public List<HostAvailability> checkHosts(
            String registrar,
            List<String> rawNames) {

        requireRegistrarActive(registrar);

        if (rawNames == null || rawNames.isEmpty()) {
            throw new RegistryException(
                    2003,
                    "Required parameter missing: host name"
            );
        }

        if (rawNames.size() > 50) {
            throw new RegistryException(
                    2004,
                    "At most 50 hosts per check"
            );
        }

        return read(c -> {
            List<HostAvailability> result = new ArrayList<>();

            for (String raw : rawNames) {
                String name = Names.host(raw);

                boolean exists = !rows(
                        c,
                        "SELECT 1 FROM hosts WHERE name=?",
                        name
                ).isEmpty();

                result.add(
                        new HostAvailability(
                                name,
                                !exists,
                                exists ? "In use" : null
                        )
                );
            }

            return result;
        });
    }

    public record HostAvailability(
            String name,
            boolean available,
            String reason
    ) {}

    /**
     * RFC 5732 host:create.
     */
    public void createHost(
            String registrar,
            String rawName,
            List<String> ipv4,
            List<String> ipv6) {

        tx(c -> {

            requireActive(c, registrar);

            String name = Names.host(rawName);

            validateHostAddresses(ipv4, ipv6);

            /*
             * RFC 5732:
             * Only host objects that are subordinate to the
             * sponsoring registrar's zone need glue addresses.
             *
             * For our ccTLD implementation, an in-zone host must
             * carry at least one IP address.
             */
            boolean inZone =
                    name.equals(cfg.zone())
                    || name.endsWith("." + cfg.zone());

            if (inZone &&
                    (ipv4 == null || ipv4.isEmpty()) &&
                    (ipv6 == null || ipv6.isEmpty())) {

                throw new RegistryException(
                        2003,
                        "In-bailiwick host requires at least one address"
                );
            }

            if (!rows(
                    c,
                    "SELECT 1 FROM hosts WHERE name=?",
                    name
            ).isEmpty()) {

                throw new RegistryException(
                        2302,
                        "Host object exists"
                );
            }

            long now = now();

            update(
                    c,
                    """
                    INSERT INTO hosts(
                        name,
                        registrar_id,
                        created,
                        updated
                    )
                    VALUES(?,?,?,?)
                    """,
                    name,
                    registrar,
                    now,
                    now
            );

            insertHostAddresses(c, name, ipv4, 4);
            insertHostAddresses(c, name, ipv6, 6);

            audit(
                    c,
                    registrar,
                    "HOST_CREATE",
                    name,
                    "ipv4=" + String.valueOf(ipv4)
                            + ",ipv6="
                            + String.valueOf(ipv6)
            );

            return null;
        });
    }

    /**
     * RFC 5732 host:info.
     */
    public Host hostInfo(
            String registrar,
            String rawName) {

        return read(c -> {

            requireActive(c, registrar);

            String name = Names.host(rawName);

            List<Object[]> hostRows = rows(
                    c,
                    """
                    SELECT name, registrar_id
                    FROM hosts
                    WHERE name=?
                    """,
                    name
            );

            if (hostRows.isEmpty()) {
                throw new RegistryException(
                        2303,
                        "Host object does not exist"
                );
            }

            String sponsor =
                    (String) hostRows.get(0)[1];

            if (!registrar.equals(sponsor)) {
                throw new RegistryException(
                        2201,
                        "Authorization error: not the sponsoring registrar"
                );
            }

            List<String> ipv4 =
                    hostAddresses(c, name, 4);

            List<String> ipv6 =
                    hostAddresses(c, name, 6);

            return new Host(
                    name,
                    sponsor,
                    ipv4,
                    ipv6
            );
        });
    }

    /**
     * RFC 5732 host:update.
     *
     * The complete address set is supplied after applying
     * the requested add/remove operations.
     */
    public void updateHost(
            String registrar,
            String rawName,
            List<String> addIpv4,
            List<String> removeIpv4,
            List<String> addIpv6,
            List<String> removeIpv6) {

        tx(c -> {

            requireActive(c, registrar);

            String name = Names.host(rawName);

            List<Object[]> hostRows = rows(
                    c,
                    """
                    SELECT registrar_id
                    FROM hosts
                    WHERE name=?
                    """,
                    name
            );

            if (hostRows.isEmpty()) {
                throw new RegistryException(
                        2303,
                        "Host object does not exist"
                );
            }

            if (!registrar.equals(hostRows.get(0)[0])) {
                throw new RegistryException(
                        2201,
                        "Authorization error: not the sponsoring registrar"
                );
            }

            validateHostAddresses(addIpv4, addIpv6);
            validateHostAddresses(removeIpv4, removeIpv6);

            Set<String> ipv4 =
                    new TreeSet<>(hostAddresses(c, name, 4));

            Set<String> ipv6 =
                    new TreeSet<>(hostAddresses(c, name, 6));

            if (addIpv4 != null) {
                ipv4.addAll(addIpv4);
            }

            if (removeIpv4 != null) {
                ipv4.removeAll(removeIpv4);
            }

            if (addIpv6 != null) {
                ipv6.addAll(addIpv6);
            }

            if (removeIpv6 != null) {
                ipv6.removeAll(removeIpv6);
            }

            boolean inZone =
                    name.equals(cfg.zone())
                    || name.endsWith("." + cfg.zone());

            if (inZone && ipv4.isEmpty() && ipv6.isEmpty()) {
                throw new RegistryException(
                        2306,
                        "In-bailiwick host requires at least one address"
                );
            }

            update(
                    c,
                    """
                    DELETE FROM host_addresses
                    WHERE host_name=?
                    """,
                    name
            );

            insertHostAddresses(
                    c,
                    name,
                    new ArrayList<>(ipv4),
                    4
            );

            insertHostAddresses(
                    c,
                    name,
                    new ArrayList<>(ipv6),
                    6
            );

            update(
                    c,
                    """
                    UPDATE hosts
                    SET updated=?
                    WHERE name=?
                    """,
                    now(),
                    name
            );

            audit(
                    c,
                    registrar,
                    "HOST_UPDATE",
                    name,
                    "addresses updated"
            );

            return null;
        });
    }

    /**
     * RFC 5732 host:delete.
     *
     * A host referenced by a domain delegation cannot be deleted.
     */
    public void deleteHost(
            String registrar,
            String rawName) {

        tx(c -> {

            requireActive(c, registrar);

            String name = Names.host(rawName);

            List<Object[]> hostRows = rows(
                    c,
                    """
                    SELECT registrar_id
                    FROM hosts
                    WHERE name=?
                    """,
                    name
            );

            if (hostRows.isEmpty()) {
                throw new RegistryException(
                        2303,
                        "Host object does not exist"
                );
            }

            if (!registrar.equals(hostRows.get(0)[0])) {
                throw new RegistryException(
                        2201,
                        "Authorization error: not the sponsoring registrar"
                );
            }

            List<Object[]> references = rows(
                    c,
                    """
                    SELECT domain_name
                    FROM domain_ns
                    WHERE ns=?
                    LIMIT 1
                    """,
                    name
            );

            if (!references.isEmpty()) {
                throw new RegistryException(
                        2304,
                        "Host object is still referenced by a domain"
                );
            }

            update(
                    c,
                    "DELETE FROM hosts WHERE name=?",
                    name
            );

            audit(
                    c,
                    registrar,
                    "HOST_DELETE",
                    name,
                    ""
            );

            return null;
        });
    }

    /**
     * Checks that all supplied addresses are valid IPv4/IPv6
     * literals and that the lists don't contain duplicates.
     */
    private static void validateHostAddresses(
            List<String> ipv4,
            List<String> ipv6) {

        if (ipv4 != null) {
            Set<String> unique = new HashSet<>();

            for (String address : ipv4) {

                if (address == null ||
                        !isIpv4(address) ||
                        !unique.add(address)) {

                    throw new RegistryException(
                            2005,
                            "Invalid IPv4 address: "
                                    + address
                    );
                }
            }
        }

        if (ipv6 != null) {
            Set<String> unique = new HashSet<>();

            for (String address : ipv6) {

                if (address == null ||
                        !isIpv6(address) ||
                        !unique.add(address)) {

                    throw new RegistryException(
                            2005,
                            "Invalid IPv6 address: "
                                    + address
                    );
                }
            }
        }
    }

    private static boolean isIpv4(String address) {

        if (!IPV4.matcher(address).matches()) {
            return false;
        }

        String[] parts = address.split("\\.");

        for (String part : parts) {
            try {
                int n = Integer.parseInt(part);

                if (n < 0 || n > 255) {
                    return false;
                }

            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private static boolean isIpv6(String address) {

        try {
            java.net.InetAddress parsed =
                    java.net.InetAddress.getByName(address);

            return parsed instanceof java.net.Inet6Address;

        } catch (Exception e) {
            return false;
        }
    }

    private static void insertHostAddresses(
            Connection c,
            String hostName,
            List<String> addresses,
            int version)
            throws SQLException {

        if (addresses == null) {
            return;
        }

        for (String address : addresses) {

            update(
                    c,
                    """
                    INSERT INTO host_addresses(
                        host_name,
                        address,
                        ip_version
                    )
                    VALUES(?,?,?)
                    """,
                    hostName,
                    address,
                    version
            );
        }
    }

    private static List<String> hostAddresses(
            Connection c,
            String hostName,
            int version)
            throws SQLException {

        List<String> result = new ArrayList<>();

        for (Object[] row : rows(
                c,
                """
                SELECT address
                FROM host_addresses
                WHERE host_name=?
                  AND ip_version=?
                ORDER BY address
                """,
                hostName,
                version)) {

            result.add((String) row[0]);
        }

        return result;
    }

    private void requireRegistrarActive(
            String registrar) {

        read(c -> {
            requireActive(c, registrar);
            return null;
        });
    }

    // ---------------------------------------------------------------- RFC 5733 contact commands

    public record ContactView(
            String id,
            String sponsor,
            String name,
            String org,
            String email,
            String phone,
            String country,
            long created
    ) {}

    public record ContactAvailability(String id, boolean available, String reason) {}

    public List<ContactAvailability> checkContacts(String registrar, List<String> ids) {
        return read(c -> {
            requireActive(c, registrar);
            List<ContactAvailability> out = new ArrayList<>();

            for (String id : ids) {
                if (!ID.matcher(String.valueOf(id)).matches()) {
                    out.add(new ContactAvailability(String.valueOf(id), false, "Invalid contact id"));
                    continue;
                }

                boolean exists = !rows(c,
                        "SELECT 1 FROM contact WHERE id=?",
                        id).isEmpty();

                out.add(new ContactAvailability(
                        id,
                        !exists,
                        exists ? "Contact exists" : null
                ));
            }

            return out;
        });
    }

    public ContactView contactInfo(String registrar, String id) {
        if (!ID.matcher(String.valueOf(id)).matches())
            throw new RegistryException(2005, "Invalid contact id");

        return read(c -> {
            requireActive(c, registrar);

            List<Object[]> r = rows(c,
                    "SELECT id,sponsor,name,org,email,phone,country,created " +
                    "FROM contact WHERE id=?",
                    id);

            if (r.isEmpty())
                throw new RegistryException(2303, "Contact does not exist");

            Object[] x = r.get(0);

            if (!registrar.equals(x[1]))
                throw new RegistryException(2201,
                        "Authorization error: not the sponsoring registrar");

            return new ContactView(
                    (String) x[0],
                    (String) x[1],
                    (String) x[2],
                    (String) x[3],
                    (String) x[4],
                    (String) x[5],
                    (String) x[6],
                    num(x[7])
            );
        });
    }

    public ContactView updateContact(
            String registrar,
            String id,
            String name,
            String org,
            String email,
            String phone,
            String country
    ) {
        if (!ID.matcher(String.valueOf(id)).matches())
            throw new RegistryException(2005, "Invalid contact id");

        if (name != null && name.isBlank())
            throw new RegistryException(2003, "Contact name cannot be empty");

        if (email != null && !EMAIL.matcher(email).matches())
            throw new RegistryException(2005, "Invalid email");

        if (country != null && !country.matches("[A-Z]{2}"))
            throw new RegistryException(2005, "Invalid country code");

        return tx(c -> {
            requireActive(c, registrar);

            List<Object[]> r = rows(c,
                    "SELECT id,sponsor,name,org,email,phone,country,created " +
                    "FROM contact WHERE id=?",
                    id);

            if (r.isEmpty())
                throw new RegistryException(2303, "Contact does not exist");

            Object[] old = r.get(0);

            if (!registrar.equals(old[1]))
                throw new RegistryException(2201,
                        "Authorization error: not the sponsoring registrar");

            String nName = name != null ? name : (String) old[2];
            String nOrg = org != null ? org : (String) old[3];
            String nEmail = email != null ? email : (String) old[4];
            String nPhone = phone != null ? phone : (String) old[5];
            String nCountry = country != null ? country : (String) old[6];

            update(c,
                    "UPDATE contact SET name=?,org=?,email=?,phone=?,country=? WHERE id=?",
                    nName, nOrg, nEmail, nPhone, nCountry, id);

            audit(c, registrar, "CONTACT_UPDATE", id,
                    "contact data updated");

            return new ContactView(
                    id,
                    registrar,
                    nName,
                    nOrg,
                    nEmail,
                    nPhone,
                    nCountry,
                    num(old[7])
            );
        });
    }

    public void deleteContact(String registrar, String id) {
        if (!ID.matcher(String.valueOf(id)).matches())
            throw new RegistryException(2005, "Invalid contact id");

        tx(c -> {
            requireActive(c, registrar);

            List<Object[]> r = rows(c,
                    "SELECT sponsor FROM contact WHERE id=?",
                    id);

            if (r.isEmpty())
                throw new RegistryException(2303, "Contact does not exist");

            if (!registrar.equals(r.get(0)[0]))
                throw new RegistryException(2201,
                        "Authorization error: not the sponsoring registrar");

            boolean used = !rows(c,
                    "SELECT 1 FROM domains WHERE registrant=?",
                    id).isEmpty();

            if (used)
                throw new RegistryException(2306,
                        "Contact is referenced by a domain");

            update(c,
                    "DELETE FROM contact WHERE id=?",
                    id);

            audit(c, registrar, "CONTACT_DELETE", id, "");

            return null;
        });
    }

    // ---------------------------------------------------------------- domain commands

    public Availability check(String raw) {
        String n;
        try {
            n = Names.check(raw, cfg);
        } catch (RegistryException e) {
            return new Availability(String.valueOf(raw), false, e.getMessage());
        }
        boolean taken = read(c -> !rows(c, "SELECT 1 FROM domains WHERE name=?", n).isEmpty());
        return new Availability(n, !taken, taken ? "In use" : null);
    }

    public DomainView createDomain(String registrar, String rawName, int years, String registrant, List<String> rawNs, String authInfo) {
        return tx(c -> {
            requireActive(c, registrar);
            String name = Names.check(rawName, cfg);
            if (years < 1 || years > cfg.maxYears()) throw new RegistryException(2004, "Period out of range");
            if (authInfo == null || authInfo.length() < 8) throw new RegistryException(2003, "AuthInfo of at least 8 characters required");
            Set<String> ns = new TreeSet<>();
            for (String h : rawNs) ns.add(Names.host(h));
            if (ns.size() < 2 || ns.size() > 13) throw new RegistryException(2004, "2 to 13 distinct name servers required");
            for (String h : ns) {

                boolean inBailiwick =
                        h.equals(cfg.zone())
                        || h.endsWith("." + cfg.zone());

                if (inBailiwick) {

                    /*
                     * RFC 5732:
                     * An in-bailiwick nameserver must have a
                     * corresponding host object.
                     */
                    if (rows(
                            c,
                            "SELECT 1 FROM hosts WHERE name=?",
                            h
                    ).isEmpty()) {

                        throw new RegistryException(
                                2306,
                                "In-bailiwick name server requires a host object"
                        );
                    }
                }
            }
            if (!rows(c, "SELECT 1 FROM domains WHERE name=?", name).isEmpty()) throw new RegistryException(2302, "Object exists");
            List<Object[]> ct = rows(c, "SELECT sponsor FROM contact WHERE id=?", registrant);
            if (ct.isEmpty()) throw new RegistryException(2303, "Registrant contact does not exist");
            if (!registrar.equals(ct.get(0)[0])) throw new RegistryException(2201, "Contact belongs to another registrar");

            charge(c, registrar, years * cfg.createFeePerYear(), "CREATE", name);
            long now = now();
            update(c, "INSERT INTO domains(name,sponsor,registrant,state,created,expires,state_since,authinfo_hash,server_hold) VALUES(?,?,?, 'ACTIVE',?,?,?,?,FALSE)",
                    name, registrar, registrant, now, addYears(now, years), now, Pw.hash(authInfo, cfg.pbkdf2Iterations()));
            for (String h : ns) update(c, "INSERT INTO domain_ns(domain_name,ns) VALUES(?,?)", name, h);
            audit(c, registrar, "DOMAIN_CREATE", name, years + "y");
            outbox(c, "ZONE_CHANGE", name);
            return view(c, fetch(c, name));
        });
    }

    public DomainView renewDomain(String registrar, String rawName, java.time.LocalDate curExpDate, int years) {
        return tx(c -> {
            requireActive(c, registrar);
            String name = Names.parse(rawName, cfg);
            Row r = owned(c, registrar, name);
            if (!r.state().equals("ACTIVE") && !r.state().equals("AUTORENEW_GRACE"))
                throw new RegistryException(2304, "Object status prohibits operation");
            if (!Instant.ofEpochSecond(r.expires()).atZone(ZoneOffset.UTC).toLocalDate().equals(curExpDate))
                throw new RegistryException(2306, "Current expiry date does not match");
            if (years < 1 || years > cfg.maxYears()) throw new RegistryException(2004, "Period out of range");
            long newExp = addYears(r.expires(), years);
            if (newExp > addYears(now(), cfg.maxYears())) throw new RegistryException(2306, "Total term would exceed " + cfg.maxYears() + " years");
            charge(c, registrar, years * cfg.renewFeePerYear(), "RENEW", name);
            update(c, "UPDATE domains SET expires=?, state='ACTIVE', state_since=? WHERE name=?", newExp, now(), name);
            audit(c, registrar, "DOMAIN_RENEW", name, years + "y");
            outbox(c, "ZONE_CHANGE", name);
            return view(c, fetch(c, name));
        });
    }

    public DeleteOutcome deleteDomain(String registrar, String rawName) {
        return tx(c -> {
            requireActive(c, registrar);
            String name = Names.parse(rawName, cfg);
            Row r = owned(c, registrar, name);
            if (!r.state().equals("ACTIVE") && !r.state().equals("AUTORENEW_GRACE"))
                throw new RegistryException(2304, "Object status prohibits operation");
            long now = now();
            if (r.state().equals("ACTIVE") && now - r.created() <= cfg.addGrace().toSeconds()) {
                List<Object[]> fee = rows(c, "SELECT -amount FROM ledger WHERE registrar=? AND domain_name=? AND kind='CREATE' ORDER BY id DESC LIMIT 1", registrar, name);
                if (!fee.isEmpty()) refund(c, registrar, num(fee.get(0)[0]), name);
                update(c, "DELETE FROM domains WHERE name=?", name);
                audit(c, registrar, "DOMAIN_DELETE", name, "add-grace purge, fee refunded");
                outbox(c, "ZONE_CHANGE", name);
                return DeleteOutcome.PURGED;
            }
            update(c, "UPDATE domains SET state='REDEMPTION', state_since=? WHERE name=?", now, name);
            audit(c, registrar, "DOMAIN_DELETE", name, "-> REDEMPTION");
            outbox(c, "ZONE_CHANGE", name);
            return DeleteOutcome.REDEMPTION;
        });
    }


    /**
     * RFC 5731 domain:update.
     *
     * Supports:
     * - adding/removing name servers
     * - changing registrant
     *
     * Status add/removal is deliberately handled separately because
     * registry server statuses are not stored in the current schema.
     */
    public DomainView updateDomain(
            String registrar,
            String rawName,
            String newRegistrant,
            List<String> addNs,
            List<String> removeNs
    ) {
        return tx(c -> {
            requireActive(c, registrar);

            String name = Names.parse(rawName, cfg);
            Row r = owned(c, registrar, name);

            if (!r.state().equals("ACTIVE") &&
                !r.state().equals("AUTORENEW_GRACE")) {
                throw new RegistryException(
                        2304,
                        "Object status prohibits operation"
                );
            }

            // Load current name servers directly from domain_ns.
            // Row does not contain an ns() field.
            Set<String> current = new TreeSet<>();

            for (Object[] x : rows(
                    c,
                    "SELECT ns FROM domain_ns WHERE domain_name=?",
                    name
            )) {
                current.add((String) x[0]);
            }

            Set<String> add = new TreeSet<>();

            if (addNs != null) {
                for (String h : addNs) {
                    if (h == null || h.isBlank()) {
                        throw new RegistryException(
                                2003,
                                "Invalid host name"
                        );
                    }

                    add.add(Names.host(h));
                }
            }

            Set<String> remove = new TreeSet<>();

            if (removeNs != null) {
                for (String h : removeNs) {
                    if (h == null || h.isBlank()) {
                        throw new RegistryException(
                                2003,
                                "Invalid host name"
                        );
                    }

                    remove.add(Names.host(h));
                }
            }

            // The same nameserver cannot appear in both add and remove.
            Set<String> overlap = new TreeSet<>(add);
            overlap.retainAll(remove);

            if (!overlap.isEmpty()) {
                throw new RegistryException(
                        2004,
                        "The same name server cannot be added and removed"
                );
            }

            // In-bailiwick nameservers must have host objects.
            for (String h : add) {
                if (h.endsWith("." + cfg.zone()) ||
                    h.equals(cfg.zone())) {

                    if (rows(
                            c,
                            "SELECT 1 FROM hosts WHERE name=?",
                            h
                    ).isEmpty()) {
                        throw new RegistryException(
                                2306,
                                "In-bailiwick host object does not exist: " + h
                        );
                    }
                }
            }

            Set<String> resulting = new TreeSet<>(current);
            resulting.removeAll(remove);
            resulting.addAll(add);

            // Registry policy: maintain 2-13 nameservers.
            if (resulting.size() < 2 || resulting.size() > 13) {
                throw new RegistryException(
                        2306,
                        "Domain must have 2 to 13 name servers"
                );
            }

            // Remove nameservers.
            for (String h : remove) {
                update(
                        c,
                        "DELETE FROM domain_ns WHERE domain_name=? AND ns=?",
                        name,
                        h
                );
            }

            // Add nameservers.
            for (String h : add) {
                if (!current.contains(h)) {
                    update(
                            c,
                            "INSERT INTO domain_ns(domain_name,ns) VALUES(?,?)",
                            name,
                            h
                    );
                }
            }

            String registrant = r.registrant();

            // Change registrant.
            if (newRegistrant != null) {

                List<Object[]> contact = rows(
                        c,
                        "SELECT sponsor FROM contact WHERE id=?",
                        newRegistrant
                );

                if (contact.isEmpty()) {
                    throw new RegistryException(
                            2303,
                            "Registrant contact does not exist"
                    );
                }

                if (!registrar.equals(contact.get(0)[0])) {
                    throw new RegistryException(
                            2201,
                            "Registrant belongs to another registrar"
                    );
                }

                registrant = newRegistrant;

                update(
                        c,
                        "UPDATE domains SET registrant=? WHERE name=?",
                        registrant,
                        name
                );
            }

            audit(
                    c,
                    registrar,
                    "DOMAIN_UPDATE",
                    name,
                    "registrant=" + registrant +
                    ";addNS=" + add +
                    ";removeNS=" + remove
            );

            if (!add.isEmpty() || !remove.isEmpty()) {
                outbox(c, "ZONE_CHANGE", name);
            }

            return view(c, fetch(c, name));
        });
    }

    public DomainView restoreDomain(String registrar, String rawName) {
        return tx(c -> {
            requireActive(c, registrar);
            String name = Names.parse(rawName, cfg);
            Row r = owned(c, registrar, name);
            if (!r.state().equals("REDEMPTION")) throw new RegistryException(2304, "Object is not in redemption");
            charge(c, registrar, cfg.restoreFee(), "RESTORE", name);
            long now = now();
            long exp = r.expires();
            if (exp <= now) {
                charge(c, registrar, cfg.renewFeePerYear(), "RENEW", name);
                exp = addYears(now, 1);
            }
            update(c, "UPDATE domains SET state='ACTIVE', state_since=?, expires=? WHERE name=?", now, exp, name);
            audit(c, registrar, "DOMAIN_RESTORE", name, "");
            outbox(c, "ZONE_CHANGE", name);
            return view(c, fetch(c, name));
        });
    }

    /** Sponsor-only view (EPP info). */
    public DomainView domainInfo(String registrar, String rawName) {
        return read(c -> view(c, owned(c, registrar, Names.parse(rawName, cfg))));
    }

    /** Public view (RDAP). */
    public Optional<DomainView> find(String rawName) {
        String name = Names.parse(rawName, cfg);
        return read(c -> {
            Row r = fetch(c, name);
            return r == null ? Optional.<DomainView>empty() : Optional.of(view(c, r));
        });
    }

    private Row owned(Connection c, String registrar, String name) throws SQLException {
        Row r = fetch(c, name);
        if (r == null) throw new RegistryException(2303, "Object does not exist");
        if (!r.sponsor().equals(registrar)) throw new RegistryException(2201, "Authorization error: not the sponsoring registrar");
        return r;
    }

    private Row fetch(Connection c, String name) throws SQLException {
        List<Object[]> l = rows(c, "SELECT sponsor,registrant,state,created,expires,state_since,server_hold FROM domains WHERE name=?", name);
        if (l.isEmpty()) return null;
        Object[] x = l.get(0);
        return new Row(name, (String) x[0], (String) x[1], (String) x[2], num(x[3]), num(x[4]), num(x[5]), (Boolean) x[6]);
    }

    private DomainView view(Connection c, Row r) throws SQLException {
        List<String> ns = new ArrayList<>();
        for (Object[] x : rows(c, "SELECT ns FROM domain_ns WHERE domain_name=? ORDER BY ns", r.name())) ns.add((String) x[0]);
        return new DomainView(r.name(), r.sponsor(), r.registrant(), r.state(), r.hold(), r.created(), r.expires(), ns);
    }

    // ---------------------------------------------------------------- lifecycle and zone

    /** Moves domains through grace, redemption and pending-delete as time passes (FR-013, FR-015). Returns transitions made. */
    public int runLifecycle() {
        return tx(c -> {
            long grace = cfg.autoRenewGrace().toSeconds(), red = cfg.redemption().toSeconds(), pd = cfg.pendingDelete().toSeconds();
            int total = 0;
            for (int pass = 0; pass < 8; pass++) {
                long now = now();
                List<Object[]> due = rows(c, "SELECT name,state,expires,state_since FROM domains WHERE "
                        + "(state='ACTIVE' AND expires<=?) OR (state='AUTORENEW_GRACE' AND expires+?<=?) "
                        + "OR (state='REDEMPTION' AND state_since+?<=?) OR (state='PENDING_DELETE' AND state_since+?<=?)",
                        now, grace, now, red, now, pd, now);
                if (due.isEmpty()) break;
                for (Object[] x : due) {
                    String name = (String) x[0], st = (String) x[1];
                    long exp = num(x[2]), since = num(x[3]);
                    switch (st) {
                        case "ACTIVE" -> {
                            update(c, "UPDATE domains SET state='AUTORENEW_GRACE', state_since=? WHERE name=?", exp, name);
                            audit(c, "system", "LIFECYCLE", name, "ACTIVE -> AUTORENEW_GRACE");
                        }
                        case "AUTORENEW_GRACE" -> {
                            update(c, "UPDATE domains SET state='REDEMPTION', state_since=? WHERE name=?", exp + grace, name);
                            audit(c, "system", "LIFECYCLE", name, "AUTORENEW_GRACE -> REDEMPTION");
                            outbox(c, "ZONE_CHANGE", name);
                        }
                        case "REDEMPTION" -> {
                            update(c, "UPDATE domains SET state='PENDING_DELETE', state_since=? WHERE name=?", since + red, name);
                            audit(c, "system", "LIFECYCLE", name, "REDEMPTION -> PENDING_DELETE");
                        }
                        default -> {
                            update(c, "DELETE FROM domains WHERE name=?", name);
                            audit(c, "system", "LIFECYCLE", name, "PURGED");
                        }
                    }
                    total++;
                }
            }
            return total;
        });
    }

    /** Domains that belong in the published zone: ACTIVE or AUTORENEW_GRACE, not on serverHold (FR-017). */
    public SortedMap<String, List<String>> zoneEntries() {
        return read(c -> {
            SortedMap<String, List<String>> m = new TreeMap<>();
            for (Object[] x : rows(c, "SELECT d.name, n.ns FROM domains d JOIN domain_ns n ON n.domain_name = d.name "
                    + "WHERE d.state IN ('ACTIVE','AUTORENEW_GRACE') AND d.server_hold = FALSE ORDER BY d.name, n.ns")) {
                m.computeIfAbsent((String) x[0], k -> new ArrayList<>()).add((String) x[1]);
            }
            return m;
        });
    }

    /** Administrative hold: removes the domain from the zone without changing its lifecycle (FR-016, FR-017). */
    public void setServerHold(String actor, String rawName, boolean hold) {
        tx(c -> {
            String name = Names.parse(rawName, cfg);
            if (update(c, "UPDATE domains SET server_hold=? WHERE name=?", hold, name) == 0) throw new RegistryException(2303, "Object does not exist");
            audit(c, actor, "SERVER_HOLD", name, String.valueOf(hold));
            outbox(c, "ZONE_CHANGE", name);
            return null;
        });
    }

    public static String randomAuthInfo() {
        byte[] b = new byte[12];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }


    // ================================================================
    // RFC 5730 EPP Message Queue
    // ================================================================

    public long queueMessage(String registrar, String message) {
        if (registrar == null || registrar.isBlank())
            throw new RegistryException(2003, "Registrar required");

        if (message == null || message.isBlank())
            throw new RegistryException(2003, "Message required");

        if (message.length() > 2000)
            throw new RegistryException(2004, "Message too long");

        try (Connection c = db.open();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO epp_message(registrar,qdate,message) VALUES(?,?,?)",
                     Statement.RETURN_GENERATED_KEYS)) {

            ps.setString(1, registrar);
            ps.setLong(2, Instant.now(clock).getEpochSecond());
            ps.setString(3, message);
            ps.executeUpdate();

            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (!rs.next())
                    throw new RegistryException(2400, "Unable to queue EPP message");

                long id = rs.getLong(1);
                c.commit();
                return id;
            }

        } catch (SQLException e) {
            throw new RegistryException(2400, "Unable to queue EPP message");
        }
    }

    public record PollMessage(
            long id,
            long qdate,
            String message,
            long count
    ) {}

    public Optional<PollMessage> pollMessage(String registrar) {
        try (Connection c = db.open()) {

            long count;

            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT COUNT(*) FROM epp_message WHERE registrar=?")) {

                ps.setString(1, registrar);

                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    count = rs.getLong(1);
                }
            }

            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT id,qdate,message " +
                    "FROM epp_message " +
                    "WHERE registrar=? " +
                    "ORDER BY id " +
                    "LIMIT 1")) {

                ps.setString(1, registrar);

                try (ResultSet rs = ps.executeQuery()) {

                    if (!rs.next()) {
                        c.commit();
                        return Optional.empty();
                    }

                    PollMessage result = new PollMessage(
                            rs.getLong("id"),
                            rs.getLong("qdate"),
                            rs.getString("message"),
                            count
                    );

                    c.commit();
                    return Optional.of(result);
                }
            }

        } catch (SQLException e) {
            throw new RegistryException(
                    2400,
                    "Unable to read EPP message queue"
            );
        }
    }

    public void acknowledgeMessage(String registrar, long id) {
        try (Connection c = db.open();
             PreparedStatement ps = c.prepareStatement(
                     "DELETE FROM epp_message " +
                     "WHERE registrar=? AND id=?")) {

            ps.setString(1, registrar);
            ps.setLong(2, id);

            if (ps.executeUpdate() == 0) {
                c.rollback();
                throw new RegistryException(
                        2303,
                        "Message does not exist"
                );
            }

            c.commit();

        } catch (SQLException e) {
            throw new RegistryException(
                    2400,
                    "Unable to acknowledge EPP message"
            );
        }
    }
}
