package registry;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * EPP server (RFC 5730/5734): TLS with mandatory client certificate, 4-byte length framing,
 * login pinned to a registered certificate, and hardened XML parsing (no DTDs, SEC-008).
 * Implements hello, login, logout, domain check/create/info/renew/delete, contact create, and RGP restore.
 */
public final class EppServer implements AutoCloseable {
    static final String NS_EPP = "urn:ietf:params:xml:ns:epp-1.0";
    static final String NS_DOMAIN = "urn:ietf:params:xml:ns:domain-1.0";
    static final String NS_CONTACT = "urn:ietf:params:xml:ns:contact-1.0";
    static final String NS_RGP = "urn:ietf:params:xml:ns:rgp-1.0";
    private static final int MAX_FRAME = 1_048_576;

    private final Registry reg;
    private final SSLServerSocket server;
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private final Map<String, AtomicInteger> sessions = new ConcurrentHashMap<>();
    private volatile boolean closed;

    private static final class Session {
        String certFp;
        String registrar;
        boolean close;
        int failures;
    }

    public EppServer(Registry reg, SSLContext ctx, int port) throws IOException {
        this.reg = reg;
        this.server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
        server.setNeedClientAuth(true);
        server.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        pool.submit(this::acceptLoop);
    }

    public int port() { return server.getLocalPort(); }

    private void acceptLoop() {
        while (!closed) {
            try {
                Socket s = server.accept();
                pool.submit(() -> handle(s));
            } catch (IOException e) {
                if (closed) return;
            }
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        server.close();
        pool.shutdownNow();
    }

    private void handle(Socket sock) {
        Session st = new Session();
        try (sock) {
            sock.setSoTimeout(reg.config().idleSeconds() * 1000);
            SSLSocket ssl = (SSLSocket) sock;
            ssl.startHandshake();
            st.certFp = Tls.fingerprint(ssl.getSession().getPeerCertificates()[0]);
            DataInputStream in = new DataInputStream(new BufferedInputStream(ssl.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(ssl.getOutputStream()));
            writeFrame(out, greeting());
            while (!st.close) {
                byte[] req = readFrame(in);
                if (req == null) break;
                writeFrame(out, dispatch(st, req));
            }
        } catch (IOException e) {
            // handshake failure, idle timeout or client went away: just drop the connection
        } finally {
            if (st.registrar != null) sessions.get(st.registrar).decrementAndGet();
        }
    }

    static byte[] readFrame(DataInputStream in) throws IOException {
        int len;
        try {
            len = in.readInt();
        } catch (EOFException e) {
            return null;
        }
        if (len < 4 || len > MAX_FRAME + 4) throw new IOException("bad frame length");
        byte[] b = new byte[len - 4];
        in.readFully(b);
        return b;
    }

    static void writeFrame(DataOutputStream out, String xml) throws IOException {
        byte[] b = xml.getBytes(StandardCharsets.UTF_8);
        out.writeInt(b.length + 4);
        out.write(b);
        out.flush();
    }

    // ------------------------------------------------------------------ XML helpers

    static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        var builder = f.newDocumentBuilder();
        builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
            @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
        });
        return builder.parse(new ByteArrayInputStream(xml));
    }

    private static List<Element> kids(Element e) {
        List<Element> out = new ArrayList<>();
        for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element k) out.add(k);
        }
        return out;
    }

    private static Element kid(Element e, String local) {
        for (Element k : kids(e)) if (local.equals(k.getLocalName())) return k;
        return null;
    }

    private static String text(Element e, String local) {
        Element k = kid(e, local);
        return k == null ? null : k.getTextContent().trim();
    }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    static String response(int code, String msg, String body, String clTRID) {
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><epp xmlns=\"" + NS_EPP
                + "\"><response><result code=\"" + code + "\"><msg>" + esc(msg) + "</msg></result>");
        if (body != null) sb.append(body);
        sb.append("<trID>");
        if (clTRID != null) sb.append("<clTRID>").append(esc(clTRID)).append("</clTRID>");
        sb.append("<svTRID>").append(UUID.randomUUID()).append("</svTRID></trID></response></epp>");
        return sb.toString();
    }

    private String greeting() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><epp xmlns=\"" + NS_EPP + "\"><greeting>"
                + "<svID>ccTLD registry prototype</svID><svDate>" + Instant.now(reg.clock()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + "</svDate>"
                + "<svcMenu><version>1.0</version><lang>en</lang><objURI>" + NS_DOMAIN + "</objURI><objURI>" + NS_CONTACT + "</objURI>"
                + "<svcExtension><extURI>" + NS_RGP + "</extURI></svcExtension></svcMenu>"
                + "<dcp><access><all/></access><statement><purpose><admin/><prov/></purpose><recipient><ours/><public/></recipient>"
                + "<retention><stated/></retention></statement></dcp></greeting></epp>";
    }

    // ------------------------------------------------------------------ dispatch

    private String dispatch(Session st, byte[] xml) {
        Document doc;
        try {
            doc = parse(xml);
        } catch (Exception e) {
            return response(2001, "Command syntax error", null, null);
        }
        Element root = doc.getDocumentElement();
        if (!"epp".equals(root.getLocalName()) || !NS_EPP.equals(root.getNamespaceURI()) || kids(root).size() != 1)
            return response(2001, "Command syntax error", null, null);
        Element top = kids(root).get(0);
        if ("hello".equals(top.getLocalName())) return greeting();
        if (!"command".equals(top.getLocalName())) return response(2001, "Command syntax error", null, null);

        String cl = text(top, "clTRID");
        Element cmd = null;
        for (Element k : kids(top)) {
            if (!"clTRID".equals(k.getLocalName()) && !"extension".equals(k.getLocalName())) { cmd = k; break; }
        }
        if (cmd == null) return response(2001, "Command syntax error", null, cl);
        try {
            return execute(st, cmd, kid(top, "extension"), cl);
        } catch (RegistryException e) {
            if (e.code >= 2500) st.close = true;
            return response(e.code, e.getMessage(), null, cl);
        } catch (RuntimeException e) {
            return response(2400, "Command failed", null, cl);
        }
    }

    private String execute(Session st, Element cmd, Element ext, String cl) {
        String name = cmd.getLocalName();
        if (name.equals("login")) return login(st, cmd, cl);
        if (name.equals("logout")) {
            st.close = true;
            return response(1500, "Command completed successfully; ending session", null, cl);
        }
        if (!Set.of("check", "create", "info", "renew", "delete", "update").contains(name))
            throw new RegistryException(2101, "Unimplemented command");
        if (st.registrar == null) throw new RegistryException(2002, "Command use error: login required");
        List<Element> k = kids(cmd);
        if (k.isEmpty()) throw new RegistryException(2001, "Command syntax error");
        Element obj = k.get(0);
        if (NS_DOMAIN.equals(obj.getNamespaceURI())) {
            switch (name) {
                case "check": return domainCheck(obj, cl);
                case "create": return domainCreate(st, obj, cl);
                case "info": return domainInfo(st, obj, cl);
                case "renew": return domainRenew(st, obj, cl);
                case "delete": return domainDelete(st, obj, cl);
                case "update": return domainRestore(st, obj, ext, cl);
                default: break;
            }
        } else if (NS_CONTACT.equals(obj.getNamespaceURI()) && name.equals("create")) {
            return contactCreate(st, obj, cl);
        }
        throw new RegistryException(2101, "Unimplemented command");
    }

    private String login(Session st, Element cmd, String cl) {
        String id = text(cmd, "clID"), pw = text(cmd, "pw");
        if (st.registrar != null) throw new RegistryException(2002, "Command use error: already logged in");
        if (id == null || pw == null) throw new RegistryException(2001, "Command syntax error");
        if (!reg.authenticate(id, pw, st.certFp)) {
            if (++st.failures >= 3) st.close = true;
            throw new RegistryException(2200, "Authentication error");
        }
        AtomicInteger n = sessions.computeIfAbsent(id, x -> new AtomicInteger());
        if (n.incrementAndGet() > reg.config().maxSessionsPerRegistrar()) {
            n.decrementAndGet();
            throw new RegistryException(2500, "Command failed; server closing connection: session limit reached");
        }
        st.registrar = id;
        return response(1000, "Command completed successfully", null, cl);
    }

    private static int period(Element obj) {
        Element p = kid(obj, "period");
        if (p == null) return 1;
        if (!"y".equals(p.getAttribute("unit"))) throw new RegistryException(2004, "Only year periods are supported");
        try {
            return Integer.parseInt(p.getTextContent().trim());
        } catch (NumberFormatException e) {
            throw new RegistryException(2005, "Invalid period");
        }
    }

    private static String need(Element obj, String local) {
        String v = text(obj, local);
        if (v == null || v.isEmpty()) throw new RegistryException(2003, "Required parameter missing: " + local);
        return v;
    }


    private String domainCheck(Element obj, String cl) {
        StringBuilder sb = new StringBuilder("<resData><domain:chkData xmlns:domain=\"" + NS_DOMAIN + "\">");
        int count = 0;
        for (Element n : kids(obj)) {
            if (!"name".equals(n.getLocalName())) continue;
            if (++count > 50) throw new RegistryException(2004, "At most 50 names per check");
            Registry.Availability a = reg.check(n.getTextContent());
            sb.append("<domain:cd><domain:name avail=\"").append(a.available() ? 1 : 0).append("\">").append(esc(a.name())).append("</domain:name>");
            if (!a.available()) sb.append("<domain:reason>").append(esc(a.reason())).append("</domain:reason>");
            sb.append("</domain:cd>");
        }
        if (count == 0) throw new RegistryException(2003, "Required parameter missing: name");
        return response(1000, "Command completed successfully", sb.append("</domain:chkData></resData>").toString(), cl);
    }

    private String domainCreate(Session st, Element obj, String cl) {
        List<String> ns = new ArrayList<>();
        Element nsEl = kid(obj, "ns");
        if (nsEl != null) {
            for (Element h : kids(nsEl)) {
                if (h.getLocalName().equals("hostName") || h.getLocalName().equals("hostObj")) ns.add(h.getTextContent());
            }
        }
        Element ai = kid(obj, "authInfo");
        Registry.DomainView v = reg.createDomain(st.registrar, need(obj, "name"), period(obj), need(obj, "registrant"), ns,
                ai == null ? null : text(ai, "pw"));
        String body = "<resData><domain:creData xmlns:domain=\"" + NS_DOMAIN + "\"><domain:name>" + esc(v.name()) + "</domain:name>"
                + "<domain:crDate>" + date(v.created()) + "</domain:crDate><domain:exDate>" + date(v.expires()) + "</domain:exDate></domain:creData></resData>";
        return response(1000, "Command completed successfully", body, cl);
    }

    private String domainInfo(Session st, Element obj, String cl) {
        Registry.DomainView v = reg.domainInfo(st.registrar, need(obj, "name"));
        StringBuilder sb = new StringBuilder("<resData><domain:infData xmlns:domain=\"" + NS_DOMAIN + "\"><domain:name>")
                .append(esc(v.name())).append("</domain:name><domain:status s=\"").append(v.state().equals("PENDING_DELETE") || v.state().equals("REDEMPTION") ? "pendingDelete" : v.serverHold() ? "serverHold" : "ok")
                .append("\"/><domain:registrant>").append(esc(v.registrant())).append("</domain:registrant><domain:ns>");
        for (String h : v.ns()) sb.append("<domain:hostName>").append(esc(h)).append("</domain:hostName>");
        sb.append("</domain:ns><domain:clID>").append(esc(v.sponsor())).append("</domain:clID><domain:crDate>").append(date(v.created()))
                .append("</domain:crDate><domain:exDate>").append(date(v.expires())).append("</domain:exDate></domain:infData></resData>");
        String rgp = switch (v.state()) {
            case "AUTORENEW_GRACE" -> "autoRenewPeriod";
            case "REDEMPTION" -> "redemptionPeriod";
            case "PENDING_DELETE" -> "pendingDelete";
            default -> null;
        };
        if (rgp != null) sb.append("<extension><rgp:infData xmlns:rgp=\"" + NS_RGP + "\"><rgp:rgpStatus s=\"").append(rgp).append("\"/></rgp:infData></extension>");
        return response(1000, "Command completed successfully", sb.toString(), cl);
    }

    private String domainRenew(Session st, Element obj, String cl) {
        String cur = need(obj, "curExpDate");
        LocalDate d;
        try {
            d = LocalDate.parse(cur.substring(0, Math.min(10, cur.length())));
        } catch (RuntimeException e) {
            throw new RegistryException(2005, "Invalid curExpDate");
        }
        Registry.DomainView v = reg.renewDomain(st.registrar, need(obj, "name"), d, period(obj));
        String body = "<resData><domain:renData xmlns:domain=\"" + NS_DOMAIN + "\"><domain:name>" + esc(v.name()) + "</domain:name><domain:exDate>"
                + date(v.expires()) + "</domain:exDate></domain:renData></resData>";
        return response(1000, "Command completed successfully", body, cl);
    }

    private String domainDelete(Session st, Element obj, String cl) {
        return reg.deleteDomain(st.registrar, need(obj, "name")) == Registry.DeleteOutcome.PURGED
                ? response(1000, "Command completed successfully", null, cl)
                : response(1001, "Command completed successfully; action pending", null, cl);
    }

    private String domainRestore(Session st, Element obj, Element ext, String cl) {
        Element upd = ext == null ? null : kid(ext, "update");
        Element restore = upd == null ? null : kid(upd, "restore");
        if (restore == null || !"request".equals(restore.getAttribute("op")))
            throw new RegistryException(2101, "Unimplemented command: only RGP restore is supported for update");
        reg.restoreDomain(st.registrar, need(obj, "name"));
        return response(1000, "Command completed successfully", null, cl);
    }

    private String contactCreate(Session st, Element obj, String cl) {
        Element pi = kid(obj, "postalInfo");
        if (pi == null) throw new RegistryException(2003, "Required parameter missing: postalInfo");
        Element addr = kid(pi, "addr");
        reg.createContact(st.registrar, need(obj, "id"), text(pi, "name"), text(pi, "org"), text(obj, "email"), text(obj, "voice"),
                addr == null ? null : text(addr, "cc"));
        String body = "<resData><contact:creData xmlns:contact=\"" + NS_CONTACT + "\"><contact:id>" + esc(text(obj, "id")) + "</contact:id><contact:crDate>"
                + Instant.now(reg.clock()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + "</contact:crDate></contact:creData></resData>";
        return response(1000, "Command completed successfully", body, cl);
    }

    private static String date(long epoch) { return Instant.ofEpochSecond(epoch).toString(); }
}
