package registry;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;

/**
 * Read-only RDAP (RFC 9082/9083 subset). Plain HTTP on purpose: TLS terminates at HAProxy (ADR-010).
 * Registrant data is always redacted (FR-030).
 */
public final class RdapServer implements AutoCloseable {
    private final Registry reg;
    private final RateLimiter limiter;
    private final HttpServer http;

    public RdapServer(Registry reg, InetSocketAddress addr, RateLimiter limiter) throws IOException {
        this.reg = reg;
        this.limiter = limiter;
        this.http = HttpServer.create(addr, 0);
        http.createContext("/rdap/", this::handle);
        http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        http.start();
    }

    public int port() { return http.getAddress().getPort(); }

    @Override
    public void close() { http.stop(0); }

    private void handle(HttpExchange ex) throws IOException {
        try {
            if (!"GET".equals(ex.getRequestMethod()) && !"HEAD".equals(ex.getRequestMethod())) {
                send(ex, 405, error(405, "Method Not Allowed", "Only GET is supported."));
                return;
            }
            if (!limiter.tryAcquire(ex.getRemoteAddress().getAddress().getHostAddress())) {
                ex.getResponseHeaders().add("Retry-After", "1");
                send(ex, 429, error(429, "Too Many Requests", "Rate limit exceeded."));
                return;
            }
            String path = ex.getRequestURI().getRawPath();
            if (path.equals("/rdap/help")) {
                send(ex, 200, "{\"rdapConformance\":[\"rdap_level_0\"],\"notices\":[{\"title\":\"Help\",\"description\":[\"Query /rdap/domain/{name}.\"]}]}");
            } else if (path.startsWith("/rdap/domain/")) {
                domain(ex, path.substring("/rdap/domain/".length()));
            } else {
                send(ex, 404, error(404, "Not Found", "Unknown RDAP path."));
            }
        } catch (RuntimeException e) {
            send(ex, 500, error(500, "Internal Error", "Please try again later."));
        } finally {
            ex.close();
        }
    }

    private void domain(HttpExchange ex, String raw) throws IOException {
        Optional<Registry.DomainView> v;
        try {
            v = reg.find(raw);
        } catch (RegistryException e) {
            if (e.code == 2005) send(ex, 400, error(400, "Bad Request", "Malformed domain name."));
            else send(ex, 404, error(404, "Not Found", "This server is not authoritative for that name."));
            return;
        }
        if (v.isEmpty()) {
            send(ex, 404, error(404, "Not Found", "Domain not registered."));
            return;
        }
        send(ex, 200, render(v.get()));
    }

    private String render(Registry.DomainView d) {
        List<String> status = new ArrayList<>();
        switch (d.state()) {
            case "ACTIVE" -> status.add("active");
            case "AUTORENEW_GRACE" -> status.add("auto renew period");
            case "REDEMPTION" -> status.add("redemption period");
            default -> status.add("pending delete");
        }
        if (d.serverHold()) status.add("server hold");
        StringBuilder sb = new StringBuilder("{\"rdapConformance\":[\"rdap_level_0\"],\"objectClassName\":\"domain\",\"ldhName\":")
                .append(q(d.name())).append(",\"status\":[");
        for (int i = 0; i < status.size(); i++) sb.append(i > 0 ? "," : "").append(q(status.get(i)));
        sb.append("],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":").append(q(Instant.ofEpochSecond(d.created()).toString()))
                .append("},{\"eventAction\":\"expiration\",\"eventDate\":").append(q(Instant.ofEpochSecond(d.expires()).toString())).append("}],\"nameservers\":[");
        for (int i = 0; i < d.ns().size(); i++)
            sb.append(i > 0 ? "," : "").append("{\"objectClassName\":\"nameserver\",\"ldhName\":").append(q(d.ns().get(i))).append("}");
        sb.append("],\"entities\":[{\"objectClassName\":\"entity\",\"handle\":").append(q(d.sponsor()))
                .append(",\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",")
                .append(q(reg.registrarName(d.sponsor()))).append("]]]},")
                .append("{\"objectClassName\":\"entity\",\"roles\":[\"registrant\"],\"remarks\":[{\"title\":\"REDACTED FOR PRIVACY\",")
                .append("\"description\":[\"Registrant contact data is not published.\"]}]}],")
                .append("\"notices\":[{\"title\":\"Terms\",\"description\":[\"Prototype data. Not for production use.\"]}]}");
        return sb.toString();
    }

    private static String error(int code, String title, String description) {
        return "{\"rdapConformance\":[\"rdap_level_0\"],\"errorCode\":" + code + ",\"title\":" + q(title) + ",\"description\":[" + q(description) + "]}";
    }

    static String q(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    private void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/rdap+json");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        boolean head = "HEAD".equals(ex.getRequestMethod());
        ex.sendResponseHeaders(code, head ? -1 : b.length);
        if (!head) try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
}
