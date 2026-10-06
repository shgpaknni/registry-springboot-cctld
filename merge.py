from pathlib import Path

ROOT = Path("src/main/java/registry")
REGISTRY = ROOT / "Registry.java"
EPP = ROOT / "EppServer.java"


# ============================================================
# Registry.java — RFC 5731 domain:update
# ============================================================

s = REGISTRY.read_text(encoding="utf-8")

start_marker = "    public DomainView updateDomain("
end_marker = "    public DomainView restoreDomain(String registrar, String rawName) {"

if start_marker in s:
    print("Registry.java: existing domain:update found — replacing it")

    start = s.index(start_marker)
    end = s.index(end_marker, start)

    method = r'''    public DomainView updateDomain(
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

'''

    s = s[:start] + method + s[end:]

else:
    print("Registry.java: domain:update not found — inserting")

    if end_marker not in s:
        raise SystemExit(
            "Registry.java: restoreDomain insertion point not found"
        )

    method = r'''    public DomainView updateDomain(
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

            Set<String> overlap = new TreeSet<>(add);
            overlap.retainAll(remove);

            if (!overlap.isEmpty()) {
                throw new RegistryException(
                        2004,
                        "The same name server cannot be added and removed"
                );
            }

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

            if (resulting.size() < 2 || resulting.size() > 13) {
                throw new RegistryException(
                        2306,
                        "Domain must have 2 to 13 name servers"
                );
            }

            for (String h : remove) {
                update(
                        c,
                        "DELETE FROM domain_ns WHERE domain_name=? AND ns=?",
                        name,
                        h
                );
            }

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

'''

    s = s.replace(end_marker, method + end_marker, 1)

REGISTRY.write_text(s, encoding="utf-8")

print("Registry.java: RFC 5731 domain:update ready")


# ============================================================
# EppServer.java — RFC 5731 domain:update
# ============================================================

s = EPP.read_text(encoding="utf-8")

# Fix dispatch.
old_dispatch = 'case "update": return domainRestore(st, obj, ext, cl);'
new_dispatch = 'case "update": return domainUpdate(st, obj, ext, cl);'

if old_dispatch in s:
    s = s.replace(old_dispatch, new_dispatch, 1)
    print("EppServer.java: domain update dispatch fixed")

elif new_dispatch in s:
    print("EppServer.java: domain update dispatch already fixed")

else:
    raise SystemExit(
        "EppServer.java: domain update dispatch not found"
    )


# Replace existing domainUpdate() if present.
if "private String domainUpdate(" in s:

    start_marker = "    private String domainUpdate("
    end_marker = "    private String domainRestore(Session st, Element obj, Element ext, String cl) {"

    start = s.index(start_marker)
    end = s.index(end_marker, start)

    print("EppServer.java: existing domainUpdate found — replacing")

    method = r'''    private String domainUpdate(
            Session st,
            Element obj,
            Element ext,
            String cl
    ) {
        /*
         * RFC 5731 domain:update.
         *
         * Supports:
         *   domain:add/ns
         *   domain:rem/ns
         *   domain:chg/registrant
         *
         * RGP restore remains handled separately.
         */

        Element rgpUpdate =
                ext == null ? null : kid(ext, "update");

        Element restore =
                rgpUpdate == null ? null : kid(rgpUpdate, "restore");

        if (restore != null) {
            return domainRestore(st, obj, ext, cl);
        }

        List<String> addNs = new ArrayList<>();
        List<String> removeNs = new ArrayList<>();

        Element add = kid(obj, "add");
        Element rem = kid(obj, "rem");

        if (add != null) {
            Element ns = kid(add, "ns");

            if (ns != null) {
                for (Element h : kids(ns)) {
                    if ("hostObj".equals(h.getLocalName()) ||
                        "hostName".equals(h.getLocalName())) {

                        String value = h.getTextContent().trim();

                        if (!value.isEmpty()) {
                            addNs.add(value);
                        }
                    }
                }
            }
        }

        if (rem != null) {
            Element ns = kid(rem, "ns");

            if (ns != null) {
                for (Element h : kids(ns)) {
                    if ("hostObj".equals(h.getLocalName()) ||
                        "hostName".equals(h.getLocalName())) {

                        String value = h.getTextContent().trim();

                        if (!value.isEmpty()) {
                            removeNs.add(value);
                        }
                    }
                }
            }
        }

        String registrant = null;

        Element chg = kid(obj, "chg");

        if (chg != null) {
            registrant = text(chg, "registrant");
        }

        if (addNs.isEmpty() &&
            removeNs.isEmpty() &&
            registrant == null) {

            throw new RegistryException(
                    2003,
                    "Domain update contains no changes"
            );
        }

        reg.updateDomain(
                st.registrar,
                need(obj, "name"),
                registrant,
                addNs,
                removeNs
        );

        return response(
                1000,
                "Command completed successfully",
                null,
                cl
        );
    }

'''

    s = s[:start] + method + s[end:]

else:

    marker = "    private String domainRestore(Session st, Element obj, Element ext, String cl) {"

    if marker not in s:
        raise SystemExit(
            "EppServer.java: domainRestore method not found"
        )

    method = r'''    private String domainUpdate(
            Session st,
            Element obj,
            Element ext,
            String cl
    ) {
        /*
         * RFC 5731 domain:update.
         *
         * Supports:
         *   domain:add/ns
         *   domain:rem/ns
         *   domain:chg/registrant
         *
         * RGP restore remains handled separately.
         */

        Element rgpUpdate =
                ext == null ? null : kid(ext, "update");

        Element restore =
                rgpUpdate == null ? null : kid(rgpUpdate, "restore");

        if (restore != null) {
            return domainRestore(st, obj, ext, cl);
        }

        List<String> addNs = new ArrayList<>();
        List<String> removeNs = new ArrayList<>();

        Element add = kid(obj, "add");
        Element rem = kid(obj, "rem");

        if (add != null) {
            Element ns = kid(add, "ns");

            if (ns != null) {
                for (Element h : kids(ns)) {
                    if ("hostObj".equals(h.getLocalName()) ||
                        "hostName".equals(h.getLocalName())) {

                        String value = h.getTextContent().trim();

                        if (!value.isEmpty()) {
                            addNs.add(value);
                        }
                    }
                }
            }
        }

        if (rem != null) {
            Element ns = kid(rem, "ns");

            if (ns != null) {
                for (Element h : kids(ns)) {
                    if ("hostObj".equals(h.getLocalName()) ||
                        "hostName".equals(h.getLocalName())) {

                        String value = h.getTextContent().trim();

                        if (!value.isEmpty()) {
                            removeNs.add(value);
                        }
                    }
                }
            }
        }

        String registrant = null;

        Element chg = kid(obj, "chg");

        if (chg != null) {
            registrant = text(chg, "registrant");
        }

        if (addNs.isEmpty() &&
            removeNs.isEmpty() &&
            registrant == null) {

            throw new RegistryException(
                    2003,
                    "Domain update contains no changes"
            );
        }

        reg.updateDomain(
                st.registrar,
                need(obj, "name"),
                registrant,
                addNs,
                removeNs
        );

        return response(
                1000,
                "Command completed successfully",
                null,
                cl
        );
    }

'''

    s = s.replace(marker, method + marker, 1)

    print("EppServer.java: RFC 5731 domainUpdate added")


EPP.write_text(s, encoding="utf-8")

print()
print("========================================")
print("RFC 5731 domain:update integration DONE")
print("========================================")
print()
print(r"Run: .\mvnw.cmd test")