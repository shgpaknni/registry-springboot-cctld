import registry.Tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class LiveRegister {

    static final char[] PASS = "changeit".toCharArray();

    static String send(DataInputStream in, DataOutputStream out, String xml)
            throws IOException {

        byte[] data = xml.getBytes(StandardCharsets.UTF_8);

        out.writeInt(data.length + 4);
        out.write(data);
        out.flush();

        int len = in.readInt();
        byte[] response = new byte[len - 4];
        in.readFully(response);

        return new String(response, StandardCharsets.UTF_8);
    }

    static String command(DataInputStream in, DataOutputStream out,
                          String command, int trid) throws IOException {

        return send(in, out,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                        "<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\">" +
                        "<command>" +
                        command +
                        "<clTRID>LIVE-" + trid + "</clTRID>" +
                        "</command>" +
                        "</epp>");
    }

    static void show(String title, String response) {
        System.out.println("\n========== " + title + " ==========");
        System.out.println(response);
    }

    public static void main(String[] args) throws Exception {

        Path certs = Path.of("certs");

        SSLContext ctx = Tls.context(
                certs.resolve("reg1.p12"),
                PASS,
                certs.resolve("client-trust.p12"),
                PASS
        );

        try (SSLSocket socket =
                     (SSLSocket) ctx.getSocketFactory()
                             .createSocket("localhost", 7700)) {

            socket.setSoTimeout(10000);

            DataInputStream in =
                    new DataInputStream(
                            new BufferedInputStream(socket.getInputStream()));

            DataOutputStream out =
                    new DataOutputStream(
                            new BufferedOutputStream(socket.getOutputStream()));

            // 1. Greeting
            String greeting = read(in);

            show("EPP GREETING", greeting);

            // 2. Login
            String login = command(
                    in,
                    out,
                    "<login>" +
                            "<clID>reg1</clID>" +
                            "<pw>correct-horse-battery</pw>" +
                            "</login>",
                    1
            );

            show("LOGIN", login);

            // 3. Create contact
            String contact = command(
                    in,
                    out,
                    "<create>" +
                            "<contact:create xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\">" +
                            "<contact:id>livecon</contact:id>" +
                            "<contact:postalInfo type=\"int\">" +
                            "<contact:name>Live Test User</contact:name>" +
                            "<contact:org>Example</contact:org>" +
                            "<contact:addr>" +
                            "<contact:street>1 Main</contact:street>" +
                            "<contact:city>Bengaluru</contact:city>" +
                            "<contact:cc>IN</contact:cc>" +
                            "</contact:addr>" +
                            "</contact:postalInfo>" +
                            "<contact:voice>+91.8000000000</contact:voice>" +
                            "<contact:email>live@example.org</contact:email>" +
                            "</contact:create>" +
                            "</create>",
                    2
            );

            show("CONTACT CREATE", contact);

            // 4. Check domain availability
            String check = command(
                    in,
                    out,
                    "<check>" +
                            "<domain:check xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\">" +
                            "<domain:name>something.xx</domain:name>" +
                            "</domain:check>" +
                            "</check>",
                    3
            );

            show("DOMAIN CHECK", check);

            // 5. REAL DOMAIN REGISTRATION
            String create = command(
                    in,
                    out,
                    "<create>" +
                            "<domain:create xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\">" +
                            "<domain:name>something.xx</domain:name>" +
                            "<domain:period unit=\"y\">1</domain:period>" +
                            "<domain:ns>" +
                            "<domain:hostName>ns1.example.net</domain:hostName>" +
                            "<domain:hostName>ns2.example.net</domain:hostName>" +
                            "</domain:ns>" +
                            "<domain:registrant>livecon</domain:registrant>" +
                            "<domain:authInfo>" +
                            "<domain:pw>live-secret-123</domain:pw>" +
                            "</domain:authInfo>" +
                            "</domain:create>" +
                            "</create>",
                    4
            );

            show("REAL DOMAIN REGISTRATION", create);

            // 6. Verify through EPP info
            String info = command(
                    in,
                    out,
                    "<info>" +
                            "<domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\">" +
                            "<domain:name>something.xx</domain:name>" +
                            "</domain:info>" +
                            "</info>",
                    5
            );

            show("DOMAIN INFO", info);

            // 7. Logout
            String logout = command(
                    in,
                    out,
                    "<logout/>",
                    6
            );

            show("LOGOUT", logout);
        }
    }

    static String read(DataInputStream in) throws IOException {

        int len = in.readInt();

        byte[] data = new byte[len - 4];

        in.readFully(data);

        return new String(data, StandardCharsets.UTF_8);
    }
}