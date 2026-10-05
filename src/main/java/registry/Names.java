package registry;

import java.net.IDN;
import java.util.Locale;
import java.util.regex.Pattern;

/** Domain and host name validation (FR-011, DR-011). */
final class Names {
    private static final Pattern LABEL = Pattern.compile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");

    private Names() {}

    static String normalize(String s) {
        if (s == null) throw new RegistryException(2005, "Missing name");
        String n = s.trim().toLowerCase(Locale.ROOT);
        return n.endsWith(".") ? n.substring(0, n.length() - 1) : n;
    }

    /** Syntax and zone membership only. Returns the normalized name. */
    static String parse(String raw, Config cfg) {
        String n = normalize(raw);
        if (n.length() > 253) throw new RegistryException(2005, "Name too long");
        String suffix = "." + cfg.zone();
        if (!n.endsWith(suffix)) throw new RegistryException(2306, "Name is not in zone ." + cfg.zone());
        String label = n.substring(0, n.length() - suffix.length());
        if (label.contains(".")) throw new RegistryException(2306, "Only second-level names are supported");
        checkLabel(label);
        return n;
    }

    /** Syntax, zone and reserved-name policy. */
    static String check(String raw, Config cfg) {
        String n = parse(raw, cfg);
        if (cfg.reserved().contains(label(n, cfg))) throw new RegistryException(2306, "Reserved name");
        return n;
    }

    static String label(String n, Config cfg) {
        return n.substring(0, n.length() - cfg.zone().length() - 1);
    }

    static void checkLabel(String label) {
        if (!LABEL.matcher(label).matches()) throw new RegistryException(2005, "Invalid label syntax");
        if (label.startsWith("xn--")) {
            try {
                String u = IDN.toUnicode(label);
                if (u.equals(label) || !IDN.toASCII(u).equals(label)) throw new RegistryException(2005, "Invalid IDN label");
            } catch (IllegalArgumentException e) {
                throw new RegistryException(2005, "Invalid IDN label");
            }
        } else if (label.length() >= 4 && label.startsWith("--", 2)) {
            throw new RegistryException(2005, "Hyphens in positions 3 and 4 are reserved");
        }
    }

    static String host(String raw) {
        String n = normalize(raw);
        String[] parts = n.split("\\.", -1);
        if (n.length() > 253 || parts.length < 2) throw new RegistryException(2005, "Invalid host name");
        for (String p : parts) {
            if (!LABEL.matcher(p).matches()) throw new RegistryException(2005, "Invalid host name");
        }
        return n;
    }
}
