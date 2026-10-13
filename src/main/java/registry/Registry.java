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

    /** Public, privacy-safe nameserver representation for RDAP (RFC 9082/9083). */
    public record RdapHostView(String name, String sponsor, List<String> ipv4, List<String> ipv6,
                               long created, long updated, boolean linked) {
        public RdapHostView {
            ipv4 = List.copyOf(ipv4);
            ipv6 = List.copyOf(ipv6);
        }
    }

    /** Public RDAP registrar entity. Contact data is deliberately not included in this search subset. */
    public record RdapEntityView(String handle, String name) {}

    public record RestoreReport(
            String preData,
            String postData,
            long delTime,
            long resTime,
            String resReason,
            List<String> statements,
            String other
    ) {}

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
    // RFC 3915: registry-defined period for receiving restore report.
    private static final long RESTORE_REPORT_WINDOW_SECONDS = 24L * 60L * 60L;
    private static final Pattern IPV4 =
            Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}$");

    private final Db db;
    private final Config cfg;
    private final Clock clock;
    private final ReentrantLock writeLock = new ReentrantLock();
    private static final java.security.SecureRandom RNG = new java.security.SecureRandom();

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
                e.printStackTrace();
                throw new RegistryException(2400, "Command failed: " + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new RegistryException(2400, "Command failed: " + e.getMessage(), e);
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
            throw new RegistryException(2400, "Command failed: " + e.getMessage(), e);
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
    public String registrarStatus(String id) {
        return read(c -> {
            List<Object[]> r = rows(c, "SELECT status FROM registrar WHERE id=?", id);
            if (r.isEmpty()) return null;
            return (String) r.get(0)[0];
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

    // ---------------------------------------------------------------- RFC 5733 contacts

    public record ContactAvailability(String id, boolean available, String reason) {}

    public record ContactView(
            String id, String roid, String sponsor, String crId, String upId,
            long created, Long updated,
            String intName, String intOrg, List<String> intStreet, String intCity, String intSp, String intPc, String intCc,
            String locName, String locOrg, List<String> locStreet, String locCity, String locSp, String locPc, String locCc,
            String phone, String fax, String email, List<String> statuses,
            Boolean discloseFlag, List<String> disclose
    ) {}

    public record ContactTransferView(
            String id, String status, String requester, String sponsor, long requested, long expires
    ) {}

    private static final Set<String> CONTACT_STATUSES = Set.of(
            "clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"
    );

    private static final Set<String> DISCLOSE_VALUES = Set.of(
            "name:int", "name:loc", "org:int", "org:loc", "addr:int", "addr:loc", "voice", "fax", "email"
    );

    public boolean verifyContactAuth(String registrar,String id,String authInfo){ return read(c->{List<Object[]>r=rows(c,"SELECT sponsor,authinfo_hash FROM contact c JOIN contact_details d ON d.contact_id=c.id WHERE c.id=?",id);if(r.isEmpty()||!registrar.equals(r.get(0)[0]))return false;return authInfo!=null&&Pw.verify(authInfo,(String)r.get(0)[1]);}); }

    public List<ContactAvailability> checkContacts(String registrar, List<String> ids) {
        return read(c -> {
            requireActive(c, registrar);
            List<ContactAvailability> out = new ArrayList<>();
            for (String id : ids) {
                boolean valid = ID.matcher(String.valueOf(id)).matches();
                boolean exists = valid && !rows(c, "SELECT 1 FROM contact WHERE id=?", id).isEmpty();
                out.add(new ContactAvailability(id, !exists, exists ? "In use" : null));
            }
            return out;
        });
    }

    public void createContact(String registrar, String id, String name, String org, String email, String phone, String country) {
        // Compatibility wrapper for existing callers/tests.
        createContactRich(
                registrar, id,
                name, org, null, List.of("1 Main"), "Bengaluru", null, null, country,
                null, null, null, List.of(), null, null, null, country,
                phone, null, email, "contact-secret-1", null, List.of()
        );
    }

    public void createContactRich(
            String registrar, String id,
            String intName, String intOrg, String intStreet1, List<String> intStreets,
            String intCity, String intSp, String intPc, String intCc,
            String locName, String locOrg, String locStreet1, List<String> locStreets,
            String locCity, String locSp, String locPc, String locCc,
            String phone, String fax, String email, String authInfo,
            Boolean discloseFlag, List<String> disclose
    ) {
        if (!ID.matcher(String.valueOf(id)).matches()) throw new RegistryException(2005, "Invalid contact id");
        if (email == null || !EMAIL.matcher(email).matches()) throw new RegistryException(2005, "Invalid email");
        if (authInfo != null && authInfo.length() < 8) throw new RegistryException(2003, "Contact AuthInfo of at least 8 characters required");
        validatePostal(intName, intCity, intCc, intStreets, intSp, intPc);
        validatePostal(locName, locCity, locCc, locStreets, locSp, locPc);
        if ((intName == null || intName.isBlank()) && (locName == null || locName.isBlank()))
            throw new RegistryException(2003, "At least one postalInfo is required");
        validateDisclosure(discloseFlag, disclose);
        tx(c -> {
            requireActive(c, registrar);
            if (!rows(c, "SELECT 1 FROM contact WHERE id=?", id).isEmpty()) throw new RegistryException(2302, "Contact exists");
            long now=now();
            update(c,"INSERT INTO contact(id,sponsor,name,org,email,phone,country,created) VALUES(?,?,?,?,?,?,?,?)",
                    id,registrar,first(intName,locName),first(intOrg,locOrg),email,phone,first(intCc,locCc),now);
            update(c,"INSERT INTO contact_details(contact_id,roid,authinfo_hash,cr_id,created,updated,int_name,int_org,int_street1,int_street2,int_street3,int_city,int_sp,int_pc,int_cc,loc_name,loc_org,loc_street1,loc_street2,loc_street3,loc_city,loc_sp,loc_pc,loc_cc,fax,disclose_flag,disclose) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    id, id.toUpperCase(Locale.ROOT)+"-REP", Pw.hash(authInfo == null ? "contact-internal-" + id : authInfo,cfg.pbkdf2Iterations()), registrar, now, null,
                    intName,intOrg,street(intStreets,0),street(intStreets,1),street(intStreets,2),intCity,intSp,intPc,intCc,
                    locName,locOrg,street(locStreets,0),street(locStreets,1),street(locStreets,2),locCity,locSp,locPc,locCc,
                    fax,discloseFlag,joinCsv(disclose));
            audit(c,registrar,"CONTACT_CREATE",id,"");
            return null;
        });
    }

    public ContactView contactInfo(String registrar, String id) {
        return read(c -> {
            List<Object[]> r=rows(c,"SELECT c.id,c.sponsor,c.email,c.phone,c.created,d.roid,d.cr_id,d.up_id,d.updated,d.int_name,d.int_org,d.int_street1,d.int_street2,d.int_street3,d.int_city,d.int_sp,d.int_pc,d.int_cc,d.loc_name,d.loc_org,d.loc_street1,d.loc_street2,d.loc_street3,d.loc_city,d.loc_sp,d.loc_pc,d.loc_cc,d.fax,d.disclose_flag,d.disclose FROM contact c JOIN contact_details d ON d.contact_id=c.id WHERE c.id=?",id);
            if(r.isEmpty()) throw new RegistryException(2303,"Object does not exist");
            Object[] x=r.get(0); String sponsor=(String)x[1];
            boolean owner=registrar.equals(sponsor);
            List<String> statuses=new ArrayList<>();
            for(Object[] q:rows(c,"SELECT status FROM contact_status WHERE contact_id=? ORDER BY status",id)) statuses.add((String)q[0]);
            boolean linked=!rows(c,"SELECT 1 FROM domains WHERE registrant=? LIMIT 1",id).isEmpty();
            if(linked) statuses.add("linked");
            if(statuses.isEmpty()) statuses.add("ok");
            return new ContactView(id,(String)x[5],sponsor,(String)x[6],(String)x[7],num(x[4]),x[8]==null?null:num(x[8]),
                    (String)x[9],(String)x[10],streets((String)x[11],(String)x[12],(String)x[13]),(String)x[14],(String)x[15],(String)x[16],(String)x[17],
                    (String)x[18],(String)x[19],streets((String)x[20],(String)x[21],(String)x[22]),(String)x[23],(String)x[24],(String)x[25],(String)x[26],
                    (String)x[3],(String)x[27],(String)x[2],statuses,(Boolean)x[28],splitCsv((String)x[29]));
        });
    }

    public void updateContact(
            String registrar, String id,
            String intName, String intOrg, List<String> intStreets, String intCity, String intSp, String intPc, String intCc,
            String locName, String locOrg, List<String> locStreets, String locCity, String locSp, String locPc, String locCc,
            String phone, String fax, String email, String authInfo,
            List<String> addStatus, List<String> remStatus,
            Boolean discloseFlag, List<String> disclose
    ) {
        if (addStatus.isEmpty() && remStatus.isEmpty() && intName==null && intOrg==null && intStreets==null && intCity==null && intSp==null && intPc==null && intCc==null && locName==null && locOrg==null && locStreets==null && locCity==null && locSp==null && locPc==null && locCc==null && phone==null && fax==null && email==null && authInfo==null && discloseFlag==null)
            throw new RegistryException(2003,"At least one add, rem, or chg element is required");
        validateDisclosure(discloseFlag,disclose);
        tx(c -> {
            requireActive(c,registrar);
            List<Object[]> owner=rows(c,"SELECT sponsor FROM contact WHERE id=?",id);
            if(owner.isEmpty()) throw new RegistryException(2303,"Object does not exist");
            if(!registrar.equals(owner.get(0)[0])) throw new RegistryException(2201,"Authorization error");
            List<Object[]> st=rows(c,"SELECT status FROM contact_status WHERE contact_id=?",id);
            Set<String> cur=new TreeSet<>(); for(Object[] q:st) cur.add((String)q[0]);
            for(String v:addStatus){if(!CONTACT_STATUSES.contains(v)) throw new RegistryException(2004,"Invalid contact status"); if(!cur.add(v)) throw new RegistryException(2304,"Status already present");}
            for(String v:remStatus){if(!CONTACT_STATUSES.contains(v)) throw new RegistryException(2004,"Invalid contact status"); if(!cur.remove(v)) throw new RegistryException(2304,"Status not present");}
            update(c,"DELETE FROM contact_status WHERE contact_id=?",id);
            for(String v:cur) update(c,"INSERT INTO contact_status(contact_id,status) VALUES(?,?)",id,v);
            if(!rows(c,"SELECT 1 FROM contact_details WHERE contact_id=?",id).isEmpty()){
                List<Object[]> old=rows(c,"SELECT int_name,int_org,int_street1,int_street2,int_street3,int_city,int_sp,int_pc,int_cc,loc_name,loc_org,loc_street1,loc_street2,loc_street3,loc_city,loc_sp,loc_pc,loc_cc,c.phone,fax,email,disclose_flag,disclose FROM contact_details d JOIN contact c ON c.id=d.contact_id WHERE d.contact_id=?",id);
                Object[] o=old.get(0);
                String nInt=intName!=null?intName:(String)o[0], oInt=intOrg!=null?intOrg:(String)o[1], nLoc=locName!=null?locName:(String)o[9], oLoc=locOrg!=null?locOrg:(String)o[10];
                String ph=phone!=null?phone:(String)o[18], fx=fax!=null?fax:(String)o[19], em=email!=null?email:(String)o[20];
                if(em!=null&&!EMAIL.matcher(em).matches()) throw new RegistryException(2005,"Invalid email");
                update(c,"UPDATE contact SET name=?,org=?,email=?,phone=?,country=? WHERE id=?",first(nInt,nLoc),first(oInt,oLoc),em,ph,first((String)o[8],(String)o[17]),id);
                update(c,"UPDATE contact_details SET int_name=?,int_org=?,int_street1=?,int_street2=?,int_street3=?,int_city=?,int_sp=?,int_pc=?,int_cc=?,loc_name=?,loc_org=?,loc_street1=?,loc_street2=?,loc_street3=?,loc_city=?,loc_sp=?,loc_pc=?,loc_cc=?,fax=?,disclose_flag=?,disclose=?,up_id=?,updated=?,authinfo_hash=? WHERE contact_id=?",
                        nInt,oInt,streetValue(intStreets,0,(String)o[2]),streetValue(intStreets,1,(String)o[3]),streetValue(intStreets,2,(String)o[4]),intCity!=null?intCity:(String)o[5],intSp!=null?intSp:(String)o[6],intPc!=null?intPc:(String)o[7],intCc!=null?intCc:(String)o[8],
                        nLoc,oLoc,streetValue(locStreets,0,(String)o[11]),streetValue(locStreets,1,(String)o[12]),streetValue(locStreets,2,(String)o[13]),locCity!=null?locCity:(String)o[14],locSp!=null?locSp:(String)o[15],locPc!=null?locPc:(String)o[16],locCc!=null?locCc:(String)o[17],fx,discloseFlag!=null?discloseFlag:o[21],discloseFlag!=null?joinCsv(disclose):o[22],registrar,now(),authInfo!=null?Pw.hash(authInfo == null ? "contact-internal-" + id : authInfo,cfg.pbkdf2Iterations()):contactAuthHash(c,id),id);
            }
            audit(c,registrar,"CONTACT_UPDATE",id,""); return null;
        });
    }

    public void deleteContact(String registrar,String id){
        tx(c->{requireActive(c,registrar); List<Object[]> r=rows(c,"SELECT sponsor FROM contact WHERE id=?",id); if(r.isEmpty()) throw new RegistryException(2303,"Object does not exist"); if(!registrar.equals(r.get(0)[0])) throw new RegistryException(2201,"Authorization error"); if(!rows(c,"SELECT 1 FROM domains WHERE registrant=? LIMIT 1",id).isEmpty()) throw new RegistryException(2305,"Object association exists"); update(c,"DELETE FROM contact WHERE id=?",id); audit(c,registrar,"CONTACT_DELETE",id,""); return null;});
    }

    public ContactTransferView transferContact(String registrar,String id,String op,String authInfo){
        return tx(c->{requireActive(c,registrar); List<Object[]> r=rows(c,"SELECT sponsor FROM contact WHERE id=?",id); if(r.isEmpty()) throw new RegistryException(2303,"Object does not exist"); String sponsor=(String)r.get(0)[0]; long now=now();
            List<Object[]> p=rows(c,"SELECT requester,sponsor,requested,expires,status FROM contact_transfer WHERE contact_id=?",id);
            if(!p.isEmpty() && num(p.get(0)[3])<=now){update(c,"DELETE FROM contact_transfer WHERE contact_id=?",id);p=List.of();}
            switch(op){
                case "request" -> {if(registrar.equals(sponsor)) throw new RegistryException(2306,"Already sponsoring client"); if(!p.isEmpty()) throw new RegistryException(2302,"Transfer pending"); if(authInfo==null||!verifyContactAuth(c,id,authInfo)) throw new RegistryException(2202,"Invalid authorization information"); long exp=now+5L*86400; update(c,"INSERT INTO contact_transfer(contact_id,requester,sponsor,requested,expires,status) VALUES(?,?,?,?,?,'pending')",id,registrar,sponsor,now,exp); return new ContactTransferView(id,"pending",registrar,sponsor,now,exp);}
                case "query" -> {if(p.isEmpty()) throw new RegistryException(2303,"No transfer history"); Object[]x=p.get(0); if(!registrar.equals(x[0])&&!registrar.equals(x[1])) throw new RegistryException(2201,"Authorization error"); return new ContactTransferView(id,(String)x[4],(String)x[0],(String)x[1],num(x[2]),num(x[3]));}
                case "cancel" -> {if(p.isEmpty()) throw new RegistryException(2303,"No pending transfer"); if(!registrar.equals(p.get(0)[0])) throw new RegistryException(2201,"Authorization error"); update(c,"DELETE FROM contact_transfer WHERE contact_id=?",id); return new ContactTransferView(id,"cancelled",(String)p.get(0)[0],(String)p.get(0)[1],num(p.get(0)[2]),num(p.get(0)[3]));}
                case "approve" -> {if(p.isEmpty()) throw new RegistryException(2303,"No pending transfer"); if(!registrar.equals(sponsor)) throw new RegistryException(2201,"Authorization error"); update(c,"UPDATE contact SET sponsor=? WHERE id=?",p.get(0)[0],id); update(c,"DELETE FROM contact_transfer WHERE contact_id=?",id); return new ContactTransferView(id,"approved",(String)p.get(0)[0],sponsor,num(p.get(0)[2]),num(p.get(0)[3]));}
                case "reject" -> {if(p.isEmpty()) throw new RegistryException(2303,"No pending transfer"); if(!registrar.equals(sponsor)) throw new RegistryException(2201,"Authorization error"); update(c,"DELETE FROM contact_transfer WHERE contact_id=?",id); return new ContactTransferView(id,"rejected",(String)p.get(0)[0],sponsor,num(p.get(0)[2]),num(p.get(0)[3]));}
                default -> throw new RegistryException(2004,"Invalid contact transfer operation");
            }
        });
    }

    private boolean verifyContactAuth(Connection c,String id,String auth) throws SQLException {List<Object[]>r=rows(c,"SELECT authinfo_hash FROM contact_details WHERE contact_id=?",id); return !r.isEmpty()&&Pw.verify(auth,(String)r.get(0)[0]);}

    private String contactAuthHash(Connection c,String id) throws SQLException { List<Object[]> r=rows(c,"SELECT authinfo_hash FROM contact_details WHERE contact_id=?",id); return r.isEmpty()?Pw.hash("contact-secret-1",cfg.pbkdf2Iterations()):(String)r.get(0)[0]; }

    private static void validatePostal(String name,String city,String cc,List<String> streets,String sp,String pc){
        if(name==null||name.isBlank()) return;
        if(city==null||city.isBlank()) throw new RegistryException(2003,"Postal city is required");
        if(cc==null||!cc.matches("[A-Z]{2}")) throw new RegistryException(2005,"Invalid country code");
        if(streets!=null&&streets.size()>3) throw new RegistryException(2004,"At most 3 street elements are allowed");
    }
    private static void validateDisclosure(Boolean flag,List<String> vals){if(flag==null)return;if(vals==null||vals.isEmpty())throw new RegistryException(2308,"Disclosure requires at least one element");for(String v:vals)if(!DISCLOSE_VALUES.contains(v))throw new RegistryException(2004,"Invalid disclosure element");}
    private static String first(String a,String b){return a!=null&&!a.isBlank()?a:b;}
    private static String street(List<String>s,int i){return s!=null&&i<s.size()?s.get(i):null;}
    private static String streetValue(List<String>s,int i,String old){return s==null?old:street(s,i);}
    private static List<String> streets(String a,String b,String c){List<String> r=new ArrayList<>(); if(a!=null&&!a.isBlank())r.add(a); if(b!=null&&!b.isBlank())r.add(b); if(c!=null&&!c.isBlank())r.add(c); return r;}
    private static String joinCsv(List<String>x){return x==null?null:String.join(",",x);}
    private static List<String> splitCsv(String x){return x==null||x.isBlank()?new ArrayList<>():new ArrayList<>(Arrays.asList(x.split(",")));}

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



    // ================================================================
    // RFC 5731 DOMAIN TRANSFER
    // ================================================================

    public record DsData(
            int keyTag,
            int alg,
            int digestType,
            String digest
    ) {}

    public record DnsKeyData(
            int flags,
            int protocol,
            int alg,
            String publicKey
    ) {}

    public record SecDnsView(
            List<DsData> dsData,
            List<DnsKeyData> keyData
    ) {}

    public record TransferView(
            String name,
            String status,
            String requester,
            String sponsor,
            long requested,
            long expires
    ) {}

    private static final long TRANSFER_PERIOD_SECONDS = 5L * 24L * 60L * 60L;

    /**
     * RFC 5731 transfer command.
     *
     * query    - either sponsor or requester may inspect a pending transfer
     * request   - a non-sponsoring registrar requests transfer using AuthInfo
     * cancel    - requesting registrar cancels its request
     * approve   - sponsoring registrar approves the request
     * reject   - sponsoring registrar rejects the request
     */
    public TransferView transferDomain(
            String registrar,
            String rawName,
            String op,
            String authInfo
    ) {
        return tx(c -> {
            requireActive(c, registrar);

            String name = Names.parse(rawName, cfg);
            Row domain = fetch(c, name);

            if (domain == null)
                throw new RegistryException(2303, "Object does not exist");

            List<Object[]> pending = rows(
                    c,
                    "SELECT requester,current_sponsor,requested,expires " +
                    "FROM domain_transfer WHERE domain_name=?",
                    name
            );

            long now = now();

            // Expired pending transfer requests are discarded.
            if (!pending.isEmpty() && num(pending.get(0)[3]) <= now) {
                update(c,
                        "DELETE FROM domain_transfer WHERE domain_name=?",
                        name);
                pending = List.of();
            }

            switch (op) {
                case "request" -> {
                    if (registrar.equals(domain.sponsor()))
                        throw new RegistryException(
                                2306,
                                "Sponsoring registrar cannot request transfer"
                        );

                    if (!pending.isEmpty())
                        throw new RegistryException(
                                2306,
                                "Transfer already pending"
                        );

                    if (authInfo == null || authInfo.isBlank())
                        throw new RegistryException(
                                2003,
                                "Transfer AuthInfo is required"
                        );

                    List<Object[]> hash = rows(
                            c,
                            "SELECT authinfo_hash FROM domains WHERE name=?",
                            name
                    );

                    if (hash.isEmpty() ||
                        !Pw.verify(authInfo, (String) hash.get(0)[0])) {
                        throw new RegistryException(
                                2200,
                                "Authorization error"
                        );
                    }

                    if (!domain.state().equals("ACTIVE") &&
                        !domain.state().equals("AUTORENEW_GRACE")) {
                        throw new RegistryException(
                                2304,
                                "Object status prohibits transfer"
                        );
                    }

                    long expires = now + TRANSFER_PERIOD_SECONDS;

                    update(
                            c,
                            "INSERT INTO domain_transfer(" +
                            "domain_name,requester,current_sponsor,requested,expires" +
                            ") VALUES(?,?,?,?,?)",
                            name,
                            registrar,
                            domain.sponsor(),
                            now,
                            expires
                    );

                    audit(
                            c,
                            registrar,
                            "DOMAIN_TRANSFER_REQUEST",
                            name,
                            "requester=" + registrar
                    );

                    return new TransferView(
                            name,
                            "pending",
                            registrar,
                            domain.sponsor(),
                            now,
                            expires
                    );
                }

                case "query" -> {
                    if (pending.isEmpty())
                        throw new RegistryException(
                                2303,
                                "No pending transfer"
                        );

                    Object[] x = pending.get(0);
                    String requester = (String) x[0];
                    String sponsor = (String) x[1];

                    if (!registrar.equals(requester) &&
                        !registrar.equals(sponsor)) {
                        throw new RegistryException(
                                2201,
                                "Authorization error"
                        );
                    }

                    return new TransferView(
                            name,
                            "pending",
                            requester,
                            sponsor,
                            num(x[2]),
                            num(x[3])
                    );
                }

                case "cancel" -> {
                    if (pending.isEmpty())
                        throw new RegistryException(
                                2303,
                                "No pending transfer"
                        );

                    Object[] x = pending.get(0);
                    String requester = (String) x[0];

                    if (!registrar.equals(requester))
                        throw new RegistryException(
                                2201,
                                "Only the requesting registrar may cancel"
                        );

                    update(
                            c,
                            "DELETE FROM domain_transfer WHERE domain_name=?",
                            name
                    );

                    audit(
                            c,
                            registrar,
                            "DOMAIN_TRANSFER_CANCEL",
                            name,
                            ""
                    );

                    return new TransferView(
                            name,
                            "cancelled",
                            requester,
                            domain.sponsor(),
                            num(x[2]),
                            num(x[3])
                    );
                }

                case "approve" -> {
                    if (pending.isEmpty())
                        throw new RegistryException(
                                2303,
                                "No pending transfer"
                        );

                    Object[] x = pending.get(0);
                    String requester = (String) x[0];
                    String sponsor = (String) x[1];

                    if (!registrar.equals(sponsor))
                        throw new RegistryException(
                                2201,
                                "Only the sponsoring registrar may approve"
                        );

                    update(
                            c,
                            "UPDATE domains SET sponsor=? WHERE name=?",
                            requester,
                            name
                    );

                    update(
                            c,
                            "DELETE FROM domain_transfer WHERE domain_name=?",
                            name
                    );

                    audit(
                            c,
                            registrar,
                            "DOMAIN_TRANSFER_APPROVE",
                            name,
                            sponsor + " -> " + requester
                    );

                    outbox(c, "ZONE_CHANGE", name);

                    return new TransferView(
                            name,
                            "serverApproved",
                            requester,
                            requester,
                            num(x[2]),
                            num(x[3])
                    );
                }

                case "reject" -> {
                    if (pending.isEmpty())
                        throw new RegistryException(
                                2303,
                                "No pending transfer"
                        );

                    Object[] x = pending.get(0);
                    String requester = (String) x[0];
                    String sponsor = (String) x[1];

                    if (!registrar.equals(sponsor))
                        throw new RegistryException(
                                2201,
                                "Only the sponsoring registrar may reject"
                        );

                    update(
                            c,
                            "DELETE FROM domain_transfer WHERE domain_name=?",
                            name
                    );

                    audit(
                            c,
                            registrar,
                            "DOMAIN_TRANSFER_REJECT",
                            name,
                            ""
                    );

                    return new TransferView(
                            name,
                            "clientRejected",
                            requester,
                            sponsor,
                            num(x[2]),
                            num(x[3])
                    );
                }

                default -> throw new RegistryException(
                        2003,
                        "Invalid transfer operation"
                );
            }
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



    public void restoreDomain(
            String registrar,
            String rawName,
            String op,
            RestoreReport report
    ) {

        tx(c -> {

            requireActive(c, registrar);

            String name =
                    Names.parse(rawName, cfg);

            Row r = owned(c, registrar, name);

            long now = now();

            // ------------------------------------------------
            // RFC 3915 restore request
            // REDEMPTION -> PENDING_RESTORE
            // ------------------------------------------------

            if ("request".equals(op)) {

                if (!"REDEMPTION".equals(r.state())) {

                    throw new RegistryException(
                            2304,
                            "Object is not in redemption"
                    );
                }

                update(
                        c,
                        "UPDATE domains "
                                + "SET state='PENDING_RESTORE', "
                                + "state_since=? "
                                + "WHERE name=?",
                        now,
                        name
                );

                audit(
                        c,
                        registrar,
                        "DOMAIN_RESTORE_REQUEST",
                        name,
                        ""
                );

                outbox(
                        c,
                        "ZONE_CHANGE",
                        name
                );

                return null;
            }


            // ------------------------------------------------
            // RFC 3915 restore report
            // PENDING_RESTORE -> ACTIVE
            // ------------------------------------------------

            if ("report".equals(op)) {

                if (!"PENDING_RESTORE".equals(r.state())) {

                    throw new RegistryException(
                            2304,
                            "Object is not pending restore"
                    );
                }

                if (report == null) {

                    throw new RegistryException(
                            2003,
                            "Invalid RGP restore report"
                    );
                }

                if (report.preData() == null
                        || report.preData().isBlank()
                        || report.postData() == null
                        || report.postData().isBlank()
                        || report.resReason() == null
                        || report.resReason().isBlank()
                        || report.statements() == null
                        || report.statements().size() != 2) {

                    throw new RegistryException(
                            2003,
                            "Invalid RGP restore report"
                    );
                }

                if (report.delTime() <= 0
                        || report.resTime() <= 0) {

                    throw new RegistryException(
                            2005,
                            "Invalid date-time value"
                    );
                }

                charge(c, registrar, 4000, "RESTORE", name);
                update(
                        c,
                        "UPDATE domains "
                                + "SET state='ACTIVE', "
                                + "state_since=? "
                                + "WHERE name=?",
                        now,
                        name
                );

                audit(
                        c,
                        registrar,
                        "DOMAIN_RESTORE_REPORT",
                        name,
                        ""
                );

                outbox(
                        c,
                        "ZONE_CHANGE",
                        name
                );

                return null;
            }


            throw new RegistryException(
                    2003,
                    "Invalid RGP restore operation"
            );
        });
    }



    /** Sponsor-only view (EPP info). */
    public DomainView domainInfo(String registrar, String rawName) {
        return read(c -> view(c, owned(c, registrar, Names.parse(rawName, cfg))));
    }

    /** Public view (RDAP). */
    /** Public RDAP nameserver lookup. Does not require registrar authentication and exposes no credentials. */
    public Optional<RdapHostView> findHost(String rawName) {
        String name = Names.host(rawName);
        return read(c -> {
            List<Object[]> r = rows(c,
                    "SELECT registrar_id, created, updated FROM hosts WHERE name=?", name);
            if (r.isEmpty()) return Optional.empty();
            Object[] x = r.get(0);
            String sponsor = (String) x[0];
            List<String> ipv4 = hostAddresses(c, name, 4);
            List<String> ipv6 = hostAddresses(c, name, 6);
            boolean linked = !rows(c,
                    "SELECT 1 FROM domain_ns WHERE ns=? LIMIT 1", name).isEmpty();
            return Optional.of(new RdapHostView(name, sponsor, ipv4, ipv6,
                    num(x[1]), num(x[2]), linked));
        });
    }

    /**
     * RFC 9082 domain-name search. Supports the name selector and at most one asterisk.
     * Search results are bounded to protect the registry from expensive wide queries.
     */
    public List<DomainView> searchDomainsByName(String rawPattern) {
        String pattern = domainSearchPattern(rawPattern);
        String like = rdapSqlLikePattern(pattern);
        return read(c -> {
            List<DomainView> out = new ArrayList<>();
            for (Object[] x : rows(c, """
                    SELECT name,sponsor,registrant,state,created,expires,state_since,server_hold
                    FROM domains WHERE name LIKE ? ESCAPE '!'
                    ORDER BY name LIMIT 100
                    """, like)) {
                Row row = new Row((String) x[0], (String) x[1], (String) x[2], (String) x[3],
                        num(x[4]), num(x[5]), num(x[6]), (Boolean) x[7]);
                out.add(view(c, row));
            }
            return List.copyOf(out);
        });
    }

    /** RFC 9082 nameserver-name search, with a hard maximum of 100 results. */
    public List<RdapHostView> searchHostsByName(String rawPattern) {
        String pattern = hostSearchPattern(rawPattern);
        String like = rdapSqlLikePattern(pattern);
        return read(c -> {
            List<RdapHostView> out = new ArrayList<>();
            for (Object[] x : rows(c, """
                    SELECT name,registrar_id,created,updated
                    FROM hosts WHERE name LIKE ? ESCAPE '!'
                    ORDER BY name LIMIT 100
                    """, like)) {
                String name = (String) x[0];
                String sponsor = (String) x[1];
                List<String> ipv4 = hostAddresses(c, name, 4);
                List<String> ipv6 = hostAddresses(c, name, 6);
                boolean linked = !rows(c, "SELECT 1 FROM domain_ns WHERE ns=? LIMIT 1", name).isEmpty();
                out.add(new RdapHostView(name, sponsor, ipv4, ipv6,
                        num(x[2]), num(x[3]), linked));
            }
            return List.copyOf(out);
        });
    }

    /** RFC 9082 registrar-entity search by handle. Contact entities are outside this supported subset. */
    public List<RdapEntityView> searchRegistrarsByHandle(String rawPattern) {
        String pattern = entityHandleSearchPattern(rawPattern);
        String like = rdapSqlLikePattern(pattern);
        return read(c -> {
            List<RdapEntityView> out = new ArrayList<>();
            for (Object[] x : rows(c, """
                    SELECT id,name FROM registrar WHERE id LIKE ? ESCAPE '!'
                    ORDER BY id LIMIT 100
                    """, like)) {
                out.add(new RdapEntityView((String) x[0], (String) x[1]));
            }
            return List.copyOf(out);
        });
    }

    /** RFC 9082 registrar-entity search by fn; contact entities are not searched by this prototype. */
    public List<RdapEntityView> searchRegistrarsByName(String rawPattern) {
        String pattern = entityNameSearchPattern(rawPattern);
        String like = rdapSqlLikePattern(pattern);
        return read(c -> {
            List<RdapEntityView> out = new ArrayList<>();
            for (Object[] x : rows(c, """
                    SELECT id,name FROM registrar WHERE LOWER(name) LIKE ? ESCAPE '!'
                    ORDER BY id LIMIT 100
                    """, like)) {
                out.add(new RdapEntityView((String) x[0], (String) x[1]));
            }
            return List.copyOf(out);
        });
    }

    private String domainSearchPattern(String raw) {
        String pattern = Names.normalize(raw);
        if (pattern.indexOf('*') != pattern.lastIndexOf('*'))
            throw new RegistryException(2005, "RDAP search patterns allow at most one asterisk");
        String candidate = pattern.replace("*", "x");
        if (!candidate.endsWith("." + cfg.zone()))
            throw new RegistryException(2306, "Domain search pattern is outside this registry zone");
        Names.parse(candidate, cfg);
        return pattern;
    }

    private static String hostSearchPattern(String raw) {
        String pattern = Names.normalize(raw);
        if (pattern.indexOf('*') != pattern.lastIndexOf('*'))
            throw new RegistryException(2005, "RDAP search patterns allow at most one asterisk");
        Names.host(pattern.replace("*", "x"));
        return pattern;
    }

    private static String entityHandleSearchPattern(String raw) {
        if (raw == null || raw.isBlank())
            throw new RegistryException(2005, "Registrar handle search pattern is required");
        // Preserve case for handles; lookup semantics are provider-defined.
        String pattern = raw.trim();
        if (pattern.length() > 32 || pattern.chars().anyMatch(Character::isISOControl)
                || pattern.indexOf('*') != pattern.lastIndexOf('*'))
            throw new RegistryException(2005, "Malformed registrar handle search pattern");
        String candidate = pattern.replace("*", "x");
        if (!ID.matcher(candidate).matches())
            throw new RegistryException(2005, "Malformed registrar handle search pattern");
        return pattern;
    }

    private static String entityNameSearchPattern(String raw) {
        return normalizeEntitySearchPattern(raw);
    }

    private static String normalizeEntitySearchPattern(String raw) {
        if (raw == null || raw.isBlank())
            throw new RegistryException(2005, "RDAP search pattern is required");
        String pattern = java.text.Normalizer.normalize(raw.trim(), java.text.Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
        if (pattern.length() > 128 || pattern.chars().anyMatch(Character::isISOControl)
                || pattern.indexOf('*') != pattern.lastIndexOf('*'))
            throw new RegistryException(2005, "Malformed RDAP entity search pattern");
        return pattern;
    }

    /** Escapes SQL LIKE metacharacters; only the RFC-defined asterisk is a search wildcard. */
    private static String rdapSqlLikePattern(String pattern) {
        return pattern.replace("!", "!!")
                .replace("%", "!%")
                .replace("_", "!_")
                .replace("*", "%");
    }

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
            long grace = cfg.autoRenewGrace().toSeconds();
            long red = cfg.redemption().toSeconds();
            long pd = cfg.pendingDelete().toSeconds();

            int total = 0;

            for (int pass = 0; pass < 8; pass++) {
                long now = now();

                List<Object[]> due = rows(
                        c,
                        "SELECT name,state,expires,state_since FROM domains WHERE "
                                + "(state='ACTIVE' AND expires<=?) "
                                + "OR (state='AUTORENEW_GRACE' AND expires+?<=?) "
                                + "OR (state='REDEMPTION' AND state_since+?<=?) "
                                + "OR (state='PENDING_DELETE' AND state_since+?<=?) "
                                + "OR (state='PENDING_RESTORE' AND state_since+?<=?)",
                        now,
                        grace,
                        now,
                        red,
                        now,
                        pd,
                        now,
                        RESTORE_REPORT_WINDOW_SECONDS,
                        now
                );

                if (due.isEmpty()) {
                    break;
                }

                for (Object[] x : due) {
                    String name = (String) x[0];
                    String st = (String) x[1];
                    long exp = num(x[2]);
                    long since = num(x[3]);

                    switch (st) {
                        case "ACTIVE" -> {
                            update(
                                    c,
                                    "UPDATE domains SET state='AUTORENEW_GRACE', state_since=? WHERE name=?",
                                    exp,
                                    name
                            );
                            audit(
                                    c,
                                    "system",
                                    "LIFECYCLE",
                                    name,
                                    "ACTIVE -> AUTORENEW_GRACE"
                            );
                        }

                        case "AUTORENEW_GRACE" -> {
                            update(
                                    c,
                                    "UPDATE domains SET state='REDEMPTION', state_since=? WHERE name=?",
                                    exp + grace,
                                    name
                            );
                            audit(
                                    c,
                                    "system",
                                    "LIFECYCLE",
                                    name,
                                    "AUTORENEW_GRACE -> REDEMPTION"
                            );
                            outbox(c, "ZONE_CHANGE", name);
                        }

                        case "REDEMPTION" -> {
                            update(
                                    c,
                                    "UPDATE domains SET state='PENDING_DELETE', state_since=? WHERE name=?",
                                    since + red,
                                    name
                            );
                            audit(
                                    c,
                                    "system",
                                    "LIFECYCLE",
                                    name,
                                    "REDEMPTION -> PENDING_DELETE"
                            );
                        }

                        case "PENDING_RESTORE" -> {
                            update(
                                    c,
                                    "UPDATE domains SET state='REDEMPTION', state_since=? WHERE name=?",
                                    now,
                                    name
                            );
                            audit(
                                    c,
                                    "system",
                                    "LIFECYCLE",
                                    name,
                                    "PENDING_RESTORE -> REDEMPTION"
                            );
                        }

                        case "PENDING_DELETE" -> {
                            update(
                                    c,
                                    "DELETE FROM domains WHERE name=?",
                                    name
                            );
                            audit(
                                    c,
                                    "system",
                                    "LIFECYCLE",
                                    name,
                                    "PURGED"
                            );
                        }

                        default -> {
                            // Defensive: the query should only return states handled above.
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


    /** DS records that belong in the parent zone: active delegations not on serverHold. */
    public SortedMap<String, List<DsData>> zoneDsEntries() {
        return read(c -> {
            SortedMap<String, List<DsData>> result = new TreeMap<>();
            for (Object[] x : rows(c, """
                    SELECT d.name, ds.key_tag, ds.alg, ds.digest_type, ds.digest
                    FROM domains d
                    JOIN domain_ds ds ON ds.domain_name = d.name
                    WHERE d.state IN ('ACTIVE','AUTORENEW_GRACE')
                      AND d.server_hold = FALSE
                    ORDER BY d.name, ds.key_tag, ds.alg, ds.digest_type
                    """)) {
                String name = (String) x[0];
                result.computeIfAbsent(name, k -> new ArrayList<>())
                        .add(new DsData(
                                ((Number) x[1]).intValue(),
                                ((Number) x[2]).intValue(),
                                ((Number) x[3]).intValue(),
                                (String) x[4]));
            }
            return result;
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
    /* ============================================================
       RFC 5910 - EPP DNSSEC Mapping
       ============================================================ */

    public SecDnsView secDnsInfo(String registrar, String name) {
        return tx(c -> {
            requireActive(c, registrar);

            List<Object[]> d = rows(c, """
                    SELECT key_tag, alg, digest_type, digest
                    FROM domain_ds
                    WHERE domain_name=?
                    ORDER BY key_tag, alg, digest_type
                    """, name);

            List<Object[]> k = rows(c, """
                    SELECT flags, protocol, alg, public_key
                    FROM domain_dnskey
                    WHERE domain_name=?
                    ORDER BY flags, protocol, alg, public_key
                    """, name);

            List<DsData> ds = new ArrayList<>();
            for (Object[] x : d) {
                ds.add(new DsData(
                        ((Number)x[0]).intValue(),
                        ((Number)x[1]).intValue(),
                        ((Number)x[2]).intValue(),
                        (String)x[3]
                ));
            }

            List<DnsKeyData> keys = new ArrayList<>();
            for (Object[] x : k) {
                keys.add(new DnsKeyData(
                        ((Number)x[0]).intValue(),
                        ((Number)x[1]).intValue(),
                        ((Number)x[2]).intValue(),
                        (String)x[3]
                ));
            }

            return new SecDnsView(ds, keys);
        });
    }

    public void secDnsCreate(
            String registrar,
            String name,
            List<DsData> ds,
            List<DnsKeyData> keys) {

        tx(c -> {
            requireActive(c, registrar);

            List<Object[]> domain =
                    rows(c, "SELECT sponsor FROM domains WHERE name=?", name);

            if (domain.isEmpty())
                throw new RegistryException(2303, "Object does not exist");

            if (!registrar.equals(domain.get(0)[0]))
                throw new RegistryException(2201, "Authorization error");

            validateSecDns(ds, keys);

            update(c, "DELETE FROM domain_ds WHERE domain_name=?", name);
            update(c, "DELETE FROM domain_dnskey WHERE domain_name=?", name);

            insertSecDns(c, name, ds, keys);

            audit(c, registrar, "SECDNS_CREATE", name,
                    "ds=" + ds.size() + ",keys=" + keys.size());

            outbox(c, "SECDNS", name);

            return null;
        });
    }

    public void secDnsUpdate(
            String registrar,
            String name,
            List<DsData> addDs,
            List<DsData> remDs,
            List<DnsKeyData> addKeys,
            List<DnsKeyData> remKeys,
            boolean removeAll) {

        tx(c -> {
            requireActive(c, registrar);

            List<Object[]> domain =
                    rows(c, "SELECT sponsor FROM domains WHERE name=?", name);

            if (domain.isEmpty())
                throw new RegistryException(2303, "Object does not exist");

            if (!registrar.equals(domain.get(0)[0]))
                throw new RegistryException(2201, "Authorization error");

            validateSecDns(addDs, addKeys);
            validateSecDns(remDs, remKeys);

            if (removeAll) {
                update(c, "DELETE FROM domain_ds WHERE domain_name=?", name);
                update(c, "DELETE FROM domain_dnskey WHERE domain_name=?", name);
            }

            for (DsData x : remDs) {
                update(c, """
                        DELETE FROM domain_ds
                        WHERE domain_name=?
                          AND key_tag=?
                          AND alg=?
                          AND digest_type=?
                          AND digest=?
                        """,
                        name,
                        x.keyTag(),
                        x.alg(),
                        x.digestType(),
                        x.digest());
            }

            for (DnsKeyData x : remKeys) {
                update(c, """
                        DELETE FROM domain_dnskey
                        WHERE domain_name=?
                          AND flags=?
                          AND protocol=?
                          AND alg=?
                          AND public_key=?
                        """,
                        name,
                        x.flags(),
                        x.protocol(),
                        x.alg(),
                        x.publicKey());
            }

            insertSecDns(c, name, addDs, addKeys);

            audit(c, registrar, "SECDNS_UPDATE", name,
                    "addDs=" + addDs.size()
                            + ",remDs=" + remDs.size()
                            + ",addKeys=" + addKeys.size()
                            + ",remKeys=" + remKeys.size()
                            + ",all=" + removeAll);

            outbox(c, "SECDNS", name);

            return null;
        });
    }

    private void insertSecDns(
            Connection c,
            String name,
            List<DsData> ds,
            List<DnsKeyData> keys) throws SQLException {

        for (DsData x : ds) {
            update(c, """
                    INSERT INTO domain_ds
                        (domain_name,key_tag,alg,digest_type,digest)
                    VALUES (?,?,?,?,?)
                    """,
                    name,
                    x.keyTag(),
                    x.alg(),
                    x.digestType(),
                    x.digest());
        }

        for (DnsKeyData x : keys) {
            update(c, """
                    INSERT INTO domain_dnskey
                        (domain_name,flags,protocol,alg,public_key)
                    VALUES (?,?,?,?,?)
                    """,
                    name,
                    x.flags(),
                    x.protocol(),
                    x.alg(),
                    x.publicKey());
        }
    }

    private void validateSecDns(
            List<DsData> ds,
            List<DnsKeyData> keys) {

        if (ds == null || keys == null)
            throw new RegistryException(2001, "Missing DNSSEC data");

        for (DsData x : ds) {
            if (x.keyTag() < 0 || x.keyTag() > 65535)
                throw new RegistryException(2001, "Invalid DS keyTag");

            if (x.alg() < 0 || x.alg() > 255)
                throw new RegistryException(2001, "Invalid DS alg");

            if (x.digestType() < 0 || x.digestType() > 255)
                throw new RegistryException(2001, "Invalid DS digest type");

            if (x.digest() == null || x.digest().isBlank()
                    || !x.digest().matches("[0-9A-Fa-f]+")) {
                throw new RegistryException(2001, "Invalid DS digest");
            }
        }

        for (DnsKeyData x : keys) {
            if (x.flags() < 0 || x.flags() > 65535)
                throw new RegistryException(2001, "Invalid DNSKEY flags");

            if (x.protocol() != 3)
                throw new RegistryException(2001, "DNSKEY protocol must be 3");

            if (x.alg() < 0 || x.alg() > 255)
                throw new RegistryException(2001, "Invalid DNSKEY alg");

            if (x.publicKey() == null || x.publicKey().isBlank())
                throw new RegistryException(2001, "Invalid DNSKEY public key");
        }
    }

}





