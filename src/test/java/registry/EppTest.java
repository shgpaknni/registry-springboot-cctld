package registry;

import org.junit.jupiter.api.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class EppTest {
    static final Path CERTS = Path.of(System.getProperty("certs", "certs"));
    static final char[] PW = "changeit".toCharArray();
    static final String PASS1 = "correct-horse-battery", PASS2 = "another-long-password";

    Registry reg;
    EppServer server;

    static SSLContext clientCtx(String name) throws Exception {
        return Tls.context(CERTS.resolve(name + ".p12"), PW, CERTS.resolve("client-trust.p12"), PW);
    }

    static String fp(String alias) throws Exception {
        return Tls.fingerprint(Tls.load(CERTS.resolve(alias + ".p12"), PW).getCertificate(alias));
    }

    @BeforeEach
    void start() throws Exception {
        startWith(Config.defaults("xx").withPbkdf2Iterations(1000));
    }

    void startWith(Config cfg) throws Exception {
        reg = new Registry(Db.inMemory(), cfg, new TestClock());
        reg.createRegistrar("reg1", "Registrar One", PASS1, fp("reg1"), 100_000, 0);
        reg.createRegistrar("reg2", "Registrar Two", PASS2, fp("reg2"), 100_000, 0);
        SSLContext server = Tls.context(CERTS.resolve("server.p12"), PW, CERTS.resolve("server-trust.p12"), PW);
        this.server = new EppServer(reg, server, 0);
    }

    @AfterEach
    void stop() throws Exception { server.close(); }

    /** Minimal EPP client: RFC 5734 framing over TLS. */
    static final class Client implements AutoCloseable {
        final SSLSocket s;
        final DataInputStream in;
        final DataOutputStream out;
        int n;

        Client(SSLContext ctx, int port) throws IOException {
            s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", port);
            s.setSoTimeout(10_000);
            in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
            out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
        }

        String read() throws IOException {
            int len = in.readInt();
            byte[] b = new byte[len - 4];
            in.readFully(b);
            return new String(b, StandardCharsets.UTF_8);
        }

        String sendRaw(String xml) throws IOException {
            byte[] b = xml.getBytes(StandardCharsets.UTF_8);
            out.writeInt(b.length + 4);
            out.write(b);
            out.flush();
            return read();
        }

        String cmd(String inner) throws IOException {
            return sendRaw("<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command>" + inner
                    + "<clTRID>T-" + (++n) + "</clTRID></command></epp>");
        }

        String login(String id, String pw) throws IOException {
            return cmd("<login><clID>" + id + "</clID><pw>" + pw + "</pw><options><version>1.0</version><lang>en</lang></options><svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI><objURI>urn:ietf:params:xml:ns:host-1.0</objURI><objURI>urn:ietf:params:xml:ns:contact-1.0</objURI><svcExtension><extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI></svcExtension></svcs></login>");
        }

        @Override public void close() throws IOException { s.close(); }
    }

    static int code(String xml) {
        Matcher m = Pattern.compile("result code=\"(\\d+)\"").matcher(xml);
        assertTrue(m.find(), xml);
        return Integer.parseInt(m.group(1));
    }

    static String between(String xml, String open, String close) {
        int a = xml.indexOf(open), b = xml.indexOf(close, a);
        assertTrue(a >= 0 && b > a, "missing " + open + " in " + xml);
        return xml.substring(a + open.length(), b);
    }

    static final String CONTACT = "<create><contact:create xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>con1</contact:id>"
            + "<contact:postalInfo type=\"int\"><contact:name>Asha Rao</contact:name><contact:org>Example</contact:org>"
            + "<contact:addr><contact:street>1 Main</contact:street><contact:city>Bengaluru</contact:city><contact:cc>IN</contact:cc></contact:addr>"
            + "</contact:postalInfo><contact:voice>+91.8000000000</contact:voice><contact:email>asha@example.org</contact:email></contact:create></create>";

    static String createDomain(String name, int years) {
        return "<create><domain:create xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>" + name
                + "</domain:name><domain:period unit=\"y\">" + years + "</domain:period><domain:ns><domain:hostName>ns1.example.net</domain:hostName>"
                + "<domain:hostName>ns2.example.net</domain:hostName></domain:ns><domain:registrant>con1</domain:registrant>"
                + "<domain:authInfo><domain:pw>auth-secret-1</domain:pw></domain:authInfo></domain:create></create>";
    }

    static String dom(String verb, String name) {
        return "<" + verb + "><domain:" + verb + " xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>" + name
                + "</domain:name></domain:" + verb + "></" + verb + ">";
    }

    @Test
    void fullRegistrarSession() throws Exception {
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            assertTrue(c.read().contains("<greeting>"));
            assertEquals(1000, code(c.login("reg1", PASS1)));
            assertEquals(1000, code(c.cmd(CONTACT)));

            String chk = c.cmd("<check><domain:check xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>alpha.xx</domain:name>"
                    + "<domain:name>nic.xx</domain:name></domain:check></check>");
            assertTrue(chk.contains("avail=\"1\">alpha.xx"), chk);
            assertTrue(chk.contains("avail=\"0\">nic.xx"), chk);

            String cr = c.cmd(createDomain("alpha.xx", 2));
            assertEquals(1000, code(cr), cr);
            assertTrue(cr.contains("<clTRID>T-"), cr);
            assertEquals(98_000, reg.balance("reg1"));
            assertEquals(2302, code(c.cmd(createDomain("alpha.xx", 1))));

            String info = c.cmd(dom("info", "alpha.xx"));
            assertEquals(1000, code(info));
            assertTrue(info.contains("<domain:hostName>ns1.example.net</domain:hostName>"));
            String exDate = between(info, "<domain:exDate>", "</domain:exDate>");

            String ren = "<renew><domain:renew xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>alpha.xx</domain:name>"
                    + "<domain:curExpDate>" + exDate.substring(0, 10) + "</domain:curExpDate><domain:period unit=\"y\">1</domain:period></domain:renew></renew>";
            assertEquals(1000, code(c.cmd(ren)));
            assertEquals(97_000, reg.balance("reg1"));

            assertEquals(1000, code(c.cmd(dom("delete", "alpha.xx"))));      // inside add grace: purged and refunded
            assertEquals(2303, code(c.cmd(dom("info", "alpha.xx"))));
            assertEquals(1500, code(c.cmd("<logout/>")));
        }
    }

    @Test
    void rgpRestoreOverEpp() throws Exception {
        TestClock clock = (TestClock) reg.clock();
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            c.read();
            c.login("reg1", PASS1);
            c.cmd(CONTACT);
            c.cmd(createDomain("alpha.xx", 1));
            clock.advance(java.time.Duration.ofDays(10));
            assertEquals(1001, code(c.cmd(dom("delete", "alpha.xx"))));
            assertTrue(c.cmd(dom("info", "alpha.xx")).contains("redemptionPeriod"));
            String restore = "<update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>alpha.xx</domain:name></domain:update></update>"
                    + "<extension><rgp:update xmlns:rgp=\"urn:ietf:params:xml:ns:rgp-1.0\"><rgp:restore op=\"request\"/></rgp:update></extension>";
            assertEquals(1000, code(c.cmd(restore)));
            assertEquals("ACTIVE", reg.find("alpha.xx").get().state());
        }
    }

    @Test
    void authenticationFailuresAndOrdering() throws Exception {
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            c.read();
            assertEquals(2002, code(c.cmd(dom("info", "alpha.xx"))));        // before login
            assertEquals(2200, code(c.login("reg1", "wrong-password-here")));
            assertEquals(2200, code(c.login("reg2", PASS2)));                // reg1's certificate is not pinned to reg2
            assertEquals(2200, code(c.login("ghost", PASS1)));               // third failure closes the session
            assertThrows(IOException.class, () -> { c.cmd("<logout/>"); c.read(); });
        }
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            c.read();
            assertEquals(1000, code(c.login("reg1", PASS1)));
            assertEquals(2002, code(c.login("reg1", PASS1)));                // already logged in
        }
    }

    @Test
    void unknownCertificateIsRejectedAtTlsLevel() {
        assertThrows(IOException.class, () -> {
            try (Client c = new Client(clientCtx("rogue"), server.port())) {
                c.read();                                                    // greeting never arrives
            }
        });
    }

    @Test
    void xmlExternalEntitiesAndDoctypesAreRefused() throws Exception {
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            c.read();
            String xxe = "<?xml version=\"1.0\"?><!DOCTYPE epp [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                    + "<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><login><clID>&x;</clID><pw>x</pw></login></command></epp>";
            String r = c.sendRaw(xxe);
            assertEquals(2001, code(r));
            assertFalse(r.contains("root:"), r);
            assertEquals(2001, code(c.sendRaw("<not-xml")));
            assertEquals(1000, code(c.login("reg1", PASS1)));                // session still usable
        }
    }

    @Test
    void helloAndUnknownCommands() throws Exception {
        try (Client c = new Client(clientCtx("reg1"), server.port())) {
            c.read();
            assertTrue(c.sendRaw("<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><hello/></epp>").contains("<greeting>"));
            c.login("reg1", PASS1);
            assertEquals(1300, code(c.cmd("<poll op=\"req\"/>")));
        }
    }

    @Test
    void sessionLimitIsEnforced() throws Exception {
        server.close();
        startWith(Config.defaults("xx").withPbkdf2Iterations(1000).withMaxSessions(1));
        try (Client a = new Client(clientCtx("reg1"), server.port()); Client b = new Client(clientCtx("reg1"), server.port())) {
            a.read();
            b.read();
            assertEquals(1000, code(a.login("reg1", PASS1)));
            assertEquals(2500, code(b.login("reg1", PASS1)));
        }
    }
}
