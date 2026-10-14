package registry;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
                send(ex, 200, "{\"rdapConformance\":[\"rdap_level_0\"],\"notices\":[{\"title\":\"Help\",\"description\":[\"Lookups: /rdap/domain/{name}, /rdap/nameserver/{name}, /rdap/entity/{registrar-handle}. Searches: /rdap/domains?name={pattern}, /rdap/nameservers?name={pattern}, /rdap/entities?handle={pattern} or fn={pattern}. Search queries support count, sort, and cursor on a bounded subset. Unsupported query types return 501.\"]}]}");
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

    private static final int SEARCH_PAGE_SIZE = 25;
    private static final int SEARCH_RESULT_CAP = 100;
    private record SearchRequest(String selector, String value, boolean count, String sort,
                                 String sortProperty, boolean descending, int offset) {}

    /** Parse RFC 9082 selectors plus RFC 8977 count/sort/cursor parameters. */
    private SearchRequest searchRequest(HttpExchange ex, String defaultSort) {
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null || raw.isBlank()) throw new RegistryException(2005, "An RDAP search selector is required");
        Map<String, String> params = new LinkedHashMap<>();
        try {
            for (String component : raw.split("&", -1)) {
                int equals = component.indexOf('=');
                if (equals <= 0) throw new RegistryException(2005, "Malformed RDAP search parameter");
                String name = URLDecoder.decode(component.substring(0, equals), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(component.substring(equals + 1), StandardCharsets.UTF_8);
                if (name.isBlank() || value.isBlank() || params.putIfAbsent(name, value) != null)
                    throw new RegistryException(2005, "Empty or duplicate RDAP search parameter");
            }
        } catch (IllegalArgumentException e) {
            throw new RegistryException(2005, "Invalid percent-encoding in RDAP search query");
        }
        boolean count = false;
        if (params.containsKey("count")) {
            count = switch (params.remove("count").toLowerCase(java.util.Locale.ROOT)) {
                case "true", "yes", "1" -> true;
                case "false", "no", "0" -> false;
                default -> throw new RegistryException(2005, "Invalid RDAP count value");
            };
        }
        String sort = params.remove("sort");
        if (sort == null) sort = defaultSort;
        Matcher sortMatch = Pattern.compile("^([A-Za-z][A-Za-z0-9_]*)(?::([ad]))?$").matcher(sort);
        if (!sortMatch.matches()) throw new RegistryException(2005, "Malformed or unsupported RDAP sort parameter");
        String sortProperty = sortMatch.group(1);
        boolean descending = "d".equals(sortMatch.group(2));
        String cursor = params.remove("cursor");
        if (params.size() != 1) throw new RegistryException(2005, "Exactly one RDAP search selector is required");
        Map.Entry<String, String> selector = params.entrySet().iterator().next();
        int offset = 0;
        if (cursor != null) {
            try {
                String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
                Matcher cursorMatch = Pattern.compile("^offset=(\\d+),limit=(\\d+)$").matcher(decoded);
                if (!cursorMatch.matches()) throw new IllegalArgumentException();
                offset = Integer.parseInt(cursorMatch.group(1));
                int limit = Integer.parseInt(cursorMatch.group(2));
                if (limit != SEARCH_PAGE_SIZE || offset < 0 || offset > SEARCH_RESULT_CAP - SEARCH_PAGE_SIZE
                        || offset % SEARCH_PAGE_SIZE != 0) throw new IllegalArgumentException();
            } catch (IllegalArgumentException e) {
                throw new RegistryException(2005, "Invalid RDAP cursor");
            }
        }
        return new SearchRequest(selector.getKey(), selector.getValue(), count, sort, sortProperty, descending, offset);
    }

    private void domainSearch(HttpExchange ex) throws IOException {
        final SearchRequest p;
        try { p = searchRequest(ex, "name"); }
        catch (RegistryException e) { send(ex, 400, error(400, "Bad Request", e.getMessage())); return; }
        boolean byNameserver = "nsLdhName".equals(p.selector());
        if (!"name".equals(p.selector()) && !byNameserver) {
            send(ex, 501, error(501, "Not Implemented", "Supported domain search selectors: name, nsLdhName.")); return;
        }
        if (byNameserver && (!"name".equals(p.sortProperty()) || p.descending())) {
            send(ex, 400, error(400, "Bad Request", "Domain-by-nameserver search supports only ascending name ordering.")); return;
        }
        try {
            Registry.RdapSearchPage<Registry.DomainView> result = byNameserver
                    ? reg.searchDomainsByNameserverPage(p.value())
                    : reg.searchDomainsByNamePage(p.value(), p.sortProperty(), p.descending());
            List<Registry.DomainView> page = slice(result.results(), p.offset());
            List<String> objects = new ArrayList<>();
            for (Registry.DomainView d : page) objects.add(withoutConformance(render(d)));
            sendSearchResponse(ex, p, "domainSearchResults", objects, result.totalCount(), "domains");
        } catch (RegistryException e) { sendSearchFailure(ex, e); }
    }

    private void nameserverSearch(HttpExchange ex) throws IOException {
        final SearchRequest p;
        try { p = searchRequest(ex, "name"); }
        catch (RegistryException e) { send(ex, 400, error(400, "Bad Request", e.getMessage())); return; }
        if (!"name".equals(p.selector())) {
            send(ex, 501, error(501, "Not Implemented", "Supported nameserver search selector: name.")); return;
        }
        try {
            Registry.RdapSearchPage<Registry.RdapHostView> result = reg.searchHostsByNamePage(p.value(), p.sortProperty(), p.descending());
            List<Registry.RdapHostView> page = slice(result.results(), p.offset());
            List<String> objects = new ArrayList<>();
            for (Registry.RdapHostView h : page) objects.add(withoutConformance(renderNameserver(h)));
            sendSearchResponse(ex, p, "nameserverSearchResults", objects, result.totalCount(), "nameservers");
        } catch (RegistryException e) { sendSearchFailure(ex, e); }
    }

    private void entitySearch(HttpExchange ex) throws IOException {
        final SearchRequest p;
        try { p = searchRequest(ex, "handle"); }
        catch (RegistryException e) { send(ex, 400, error(400, "Bad Request", e.getMessage())); return; }
        if (!"handle".equals(p.selector()) && !"fn".equals(p.selector())) {
            send(ex, 501, error(501, "Not Implemented", "Supported registrar entity search selectors: handle and fn.")); return;
        }
        try {
            Registry.RdapSearchPage<Registry.RdapEntityView> result = "handle".equals(p.selector())
                    ? reg.searchRegistrarsByHandlePage(p.value(), p.sortProperty(), p.descending())
                    : reg.searchRegistrarsByNamePage(p.value(), p.sortProperty(), p.descending());
            List<Registry.RdapEntityView> page = slice(result.results(), p.offset());
            List<String> objects = new ArrayList<>();
            for (Registry.RdapEntityView entity : page) objects.add(registrarEntity(entity.handle(), entity.name()));
            sendSearchResponse(ex, p, "entitySearchResults", objects, result.totalCount(), "entities");
        } catch (RegistryException e) { sendSearchFailure(ex, e); }
    }

    private static <T> List<T> slice(List<T> results, int offset) {
        if (offset >= results.size()) return List.of();
        return results.subList(offset, Math.min(offset + SEARCH_PAGE_SIZE, results.size()));
    }

    private void sendSearchResponse(HttpExchange ex, SearchRequest p, String resultsKey, List<String> objects,
                                    long total, String objectType) throws IOException {
        boolean paging = p.count() || total > SEARCH_PAGE_SIZE;
        String conformance = paging
                ? "[\"rdap_level_0\",\"sorting\",\"paging\"]"
                : "[\"rdap_level_0\",\"sorting\"]";
        StringBuilder body = new StringBuilder("{\"rdapConformance\":").append(conformance)
                .append(",\"sorting_metadata\":").append(sortingMetadata(p.sort(), objectType));
        if (paging) {
            body.append(",\"paging_metadata\":{");
            boolean comma = false;
            if (p.count()) { body.append("\"totalCount\":").append(total); comma = true; }
            if (total > SEARCH_PAGE_SIZE) {
                if (comma) body.append(',');
                body.append("\"pageSize\":").append(SEARCH_PAGE_SIZE)
                        .append(",\"pageNumber\":").append((p.offset() / SEARCH_PAGE_SIZE) + 1);
                int nextOffset = p.offset() + objects.size();
                if (nextOffset < Math.min(total, SEARCH_RESULT_CAP)) {
                    body.append(",\"links\":[{\"value\":").append(q(ex.getRequestURI().toString()))
                            .append(",\"rel\":\"next\",\"href\":")
                            .append(q(nextPageUri(ex, nextOffset))).append(",\"title\":\"Result Pagination Link\",\"type\":\"application/rdap+json\"}]");
                }
            }
            body.append('}');
        }
        if (total > SEARCH_RESULT_CAP) {
            body.append(",\"notices\":[{\"title\":\"Search query limits\",\"description\":[\"Search results are limited to the first 100 objects for this query.\"]}]");
        }
        body.append(",\"").append(resultsKey).append("\":[");
        for (int i = 0; i < objects.size(); i++) { if (i > 0) body.append(','); body.append(objects.get(i)); }
        send(ex, 200, body.append("]}").toString());
    }

    private static String sortingMetadata(String currentSort, String objectType) {
        String[][] entries = switch (objectType) {
            case "domains" -> new String[][] {
                    {"name", "$.domainSearchResults[*].[unicodeName,ldhName]", "true"},
                    {"registrationDate", "$.domainSearchResults[*].events[?(@.eventAction==\"registration\")].eventDate", "false"},
                    {"expirationDate", "$.domainSearchResults[*].events[?(@.eventAction==\"expiration\")].eventDate", "false"}
            };
            case "nameservers" -> new String[][] {
                    {"name", "$.nameserverSearchResults[*].[unicodeName,ldhName]", "true"},
                    {"registrationDate", "$.nameserverSearchResults[*].events[?(@.eventAction==\"registration\")].eventDate", "false"},
                    {"lastChangedDate", "$.nameserverSearchResults[*].events[?(@.eventAction==\"last changed\")].eventDate", "false"}
            };
            default -> new String[][] {
                    {"handle", "$.entitySearchResults[*].handle", "true"},
                    {"fn", "$.entitySearchResults[*].vcardArray[1][?(@[0]==\"fn\")][3]", "false"}
            };
        };
        StringBuilder json = new StringBuilder("{\"currentSort\":").append(q(currentSort)).append(",\"availableSorts\":[");
        for (int i = 0; i < entries.length; i++) {
            if (i > 0) json.append(',');
            json.append("{\"property\":").append(q(entries[i][0]))
                    .append(",\"jsonPath\":").append(q(entries[i][1]))
                    .append(",\"default\":").append(entries[i][2]).append('}');
        }
        return json.append("]}").toString();
    }

    private static String nextPageUri(HttpExchange ex, int nextOffset) {
        String rawQuery = ex.getRequestURI().getRawQuery();
        List<String> parts = new ArrayList<>();
        if (rawQuery != null) {
            for (String part : rawQuery.split("&")) {
                int equals = part.indexOf('=');
                String name = equals < 0 ? part : part.substring(0, equals);
                if (!"cursor".equals(name)) parts.add(part);
            }
        }
        String cursor = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("offset=" + nextOffset + ",limit=" + SEARCH_PAGE_SIZE).getBytes(StandardCharsets.UTF_8));
        parts.add("cursor=" + cursor);
        return ex.getRequestURI().getRawPath() + "?" + String.join("&", parts);
    }

    private void sendSearchFailure(HttpExchange ex, RegistryException e) throws IOException {
        if (e.code == 2005 || e.code == 2306) send(ex, 400, error(400, "Bad Request", e.getMessage()));
        else send(ex, 500, error(500, "Internal Error", "Unable to process RDAP search."));
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
