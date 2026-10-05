package registry;

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
                if (h.endsWith("." + cfg.zone()) || h.equals(cfg.zone()))
                    throw new RegistryException(2306, "In-bailiwick name servers need host objects (not in this prototype)");
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
}
