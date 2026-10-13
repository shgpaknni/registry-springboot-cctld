package registry;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
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
                ex.getResponseHeaders().set("Allow", "GET, HEAD");
                send(ex, 405, error(405, "Method Not Allowed", "Only GET and HEAD are supported."));
                return;
            }
            if (!limiter.tryAcquire(ex.getRemoteAddress().getAddress().getHostAddress())) {
                ex.getResponseHeaders().add("Retry-After", "1");
                send(ex, 429, error(429, "Too Many Requests", "Rate limit exceeded."));
                return;
            }
            String path = ex.getRequestURI().getPath();
            if (path.equals("/rdap/help")) {
                send(ex, 200, "{\"rdapConformance\":[\"rdap_level_0\"],\"notices\":[{\"title\":\"Help\",\"description\":[\"Supported lookups: /rdap/domain/{name}, /rdap/nameserver/{name}, and /rdap/entity/{registrar-handle}. Unsupported query types return 501.\"]}]}");
            } else if (path.startsWith("/rdap/domain/")) {
                domain(ex, path.substring("/rdap/domain/".length()));
            } else if (path.startsWith("/rdap/nameserver/")) {
                nameserver(ex, path.substring("/rdap/nameserver/".length()));
            } else if (path.startsWith("/rdap/entity/")) {
                entity(ex, path.substring("/rdap/entity/".length()));
            } else if (path.equals("/rdap/domains")) {
                domainSearch(ex);
            } else if (path.equals("/rdap/nameservers")) {
                nameserverSearch(ex);
            } else if (path.equals("/rdap/entities")) {
                entitySearch(ex);
            } else if (path.startsWith("/rdap/ip/") || path.startsWith("/rdap/autnum/")) {
                send(ex, 501, error(501, "Not Implemented", "This RDAP query type is not supported by this registry."));
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

    private record SearchParameter(String name, String value) {}

    /** RFC 9082 defines one selector per search query. */
    private SearchParameter searchParameter(HttpExchange ex) {
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null || raw.isBlank() || raw.indexOf('&') >= 0)
            throw new RegistryException(2005, "Exactly one RDAP search parameter is required");
        int equals = raw.indexOf('=');
        if (equals <= 0 || equals == raw.length() - 1 || raw.indexOf('=', equals + 1) >= 0)
            throw new RegistryException(2005, "Malformed RDAP search parameter");
        try {
            String name = URLDecoder.decode(raw.substring(0, equals), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(raw.substring(equals + 1), StandardCharsets.UTF_8);
            if (name.isBlank() || value.isBlank())
                throw new RegistryException(2005, "RDAP search parameter and value are required");
            return new SearchParameter(name, value);
        } catch (IllegalArgumentException e) {
            throw new RegistryException(2005, "Invalid percent-encoding in RDAP search query");
        }
    }

    private void domainSearch(HttpExchange ex) throws IOException {
        final SearchParameter p;
        try {
            p = searchParameter(ex);
        } catch (RegistryException e) {
            send(ex, 400, error(400, "Bad Request", e.getMessage()));
            return;
        }
        if (!"name".equals(p.name())) {
            send(ex, 501, error(501, "Not Implemented", "Supported domain search selector: name."));
            return;
        }
        try {
            List<Registry.DomainView> found = reg.searchDomainsByName(p.value());
            StringBuilder body = new StringBuilder("{\"rdapConformance\":[\"rdap_level_0\"],\"domainSearchResults\":[");
            for (int i = 0; i < found.size(); i++) {
                if (i > 0) body.append(',');
                body.append(withoutConformance(render(found.get(i))));
            }
            send(ex, 200, body.append("]}").toString());
        } catch (RegistryException e) {
            sendSearchFailure(ex, e);
        }
    }

    private void nameserverSearch(HttpExchange ex) throws IOException {
        final SearchParameter p;
        try {
            p = searchParameter(ex);
        } catch (RegistryException e) {
            send(ex, 400, error(400, "Bad Request", e.getMessage()));
            return;
        }
        if (!"name".equals(p.name())) {
            send(ex, 501, error(501, "Not Implemented", "Supported nameserver search selector: name."));
            return;
        }
        try {
            List<Registry.RdapHostView> found = reg.searchHostsByName(p.value());
            StringBuilder body = new StringBuilder("{\"rdapConformance\":[\"rdap_level_0\"],\"nameserverSearchResults\":[");
            for (int i = 0; i < found.size(); i++) {
                if (i > 0) body.append(',');
                body.append(withoutConformance(renderNameserver(found.get(i))));
            }
            send(ex, 200, body.append("]}").toString());
        } catch (RegistryException e) {
            sendSearchFailure(ex, e);
        }
    }

    private void entitySearch(HttpExchange ex) throws IOException {
        final SearchParameter p;
        try {
            p = searchParameter(ex);
        } catch (RegistryException e) {
            send(ex, 400, error(400, "Bad Request", e.getMessage()));
            return;
        }
        if (!"handle".equals(p.name()) && !"fn".equals(p.name())) {
            send(ex, 501, error(501, "Not Implemented", "Supported registrar entity search selectors: handle and fn."));
            return;
        }
        try {
            List<Registry.RdapEntityView> found = "handle".equals(p.name())
                    ? reg.searchRegistrarsByHandle(p.value())
                    : reg.searchRegistrarsByName(p.value());
            StringBuilder body = new StringBuilder("{\"rdapConformance\":[\"rdap_level_0\"],\"entitySearchResults\":[");
            for (int i = 0; i < found.size(); i++) {
                if (i > 0) body.append(',');
                Registry.RdapEntityView entity = found.get(i);
                body.append(registrarEntity(entity.handle(), entity.name()));
            }
            send(ex, 200, body.append("]}").toString());
        } catch (RegistryException e) {
            sendSearchFailure(ex, e);
        }
    }

    private void sendSearchFailure(HttpExchange ex, RegistryException e) throws IOException {
        if (e.code == 2005 || e.code == 2306) {
            send(ex, 400, error(400, "Bad Request", e.getMessage()));
        } else {
            send(ex, 500, error(500, "Internal Error", "Unable to process RDAP search."));
        }
    }

    private static String withoutConformance(String json) {
        String prefix = "{\"rdapConformance\":[\"rdap_level_0\"],";
        if (!json.startsWith(prefix)) throw new IllegalArgumentException("Unexpected RDAP object serialization");
        return "{" + json.substring(prefix.length());
    }

    private void nameserver(HttpExchange ex, String raw) throws IOException {
        try {
            Optional<Registry.RdapHostView> v = reg.findHost(raw);
            if (v.isEmpty()) {
                send(ex, 404, error(404, "Not Found", "Nameserver not registered."));
                return;
            }
            send(ex, 200, renderNameserver(v.get()));
        } catch (RegistryException e) {
            if (e.code == 2005) send(ex, 400, error(400, "Bad Request", "Malformed nameserver name."));
            else send(ex, 404, error(404, "Not Found", "Nameserver not found."));
        }
    }

    private void entity(HttpExchange ex, String rawHandle) throws IOException {
        String handle = rawHandle == null ? "" : rawHandle.trim();
        String status = reg.registrarStatus(handle);
        if (handle.isBlank() || status == null) {
            send(ex, 404, error(404, "Not Found", "Registrar entity not found."));
            return;
        }
        String entity = registrarEntity(handle, reg.registrarName(handle));
        send(ex, 200, "{\"rdapConformance\":[\"rdap_level_0\"]," + entity.substring(1));
    }

    private String renderNameserver(Registry.RdapHostView h) {
        StringBuilder sb = new StringBuilder("{\"rdapConformance\":[\"rdap_level_0\"],\"objectClassName\":\"nameserver\",\"ldhName\":")
                .append(q(h.name()));
        if (!h.ipv4().isEmpty() || !h.ipv6().isEmpty()) {
            sb.append(",\"ipAddresses\":{\"v4\":[");
            for (int i = 0; i < h.ipv4().size(); i++)
                sb.append(i == 0 ? "" : ",").append(q(h.ipv4().get(i)));
            sb.append("],\"v6\":[");
            for (int i = 0; i < h.ipv6().size(); i++)
                sb.append(i == 0 ? "" : ",").append(q(h.ipv6().get(i)));
            sb.append("]}");
        }
        sb.append(",\"events\":[{\"eventAction\":\"registration\",\"eventDate\":")
                .append(q(Instant.ofEpochSecond(h.created()).toString()))
                .append("},{\"eventAction\":\"last changed\",\"eventDate\":")
                .append(q(Instant.ofEpochSecond(h.updated()).toString())).append("}]")
                .append(",\"entities\":[")
                .append(registrarEntity(h.sponsor(), reg.registrarName(h.sponsor())))
                .append("]}");
        return sb.toString();
    }

    private static String registrarEntity(String handle, String name) {
        return "{\"objectClassName\":\"entity\",\"handle\":" + q(handle)
                + ",\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\","
                + q(name) + "]]]}";
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
