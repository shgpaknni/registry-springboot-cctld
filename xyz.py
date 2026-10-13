from pathlib import Path
import re
import shutil

ROOT = Path(r"C:\Users\DNS\Downloads\cctld-registry-springboot")

EPP = ROOT / "src" / "main" / "java" / "registry" / "EppServer.java"
REG = ROOT / "src" / "main" / "java" / "registry" / "Registry.java"


def backup(path):
    backup = path.with_suffix(path.suffix + ".before-rgp-fix")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"Backup: {backup}")


def replace_method(src, method_name, replacement):
    """
    Replace a Java method using brace balancing.
    Does not depend on the method's exact formatting.
    """
    m = re.search(
        rf"(?m)^[ \t]*(?:public|private|protected)[^\n]*\b{re.escape(method_name)}\s*\(",
        src
    )

    if not m:
        raise RuntimeError(f"Could not find {method_name}()")

    start = m.start()

    brace = src.find("{", m.end())
    if brace < 0:
        raise RuntimeError(f"Could not find opening brace for {method_name}()")

    depth = 0
    end = None

    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1

            if depth == 0:
                end = i + 1
                break

    if end is None:
        raise RuntimeError(f"Could not find closing brace for {method_name}()")

    return src[:start] + replacement.rstrip() + "\n" + src[end:]


# ============================================================
# EppServer.java
# ============================================================

backup(EPP)

epp = EPP.read_text(encoding="utf-8")


# ------------------------------------------------------------
# Replace domainRestore()
# ------------------------------------------------------------

domain_restore = r'''
    private String domainRestore(Session st, Element obj, Element ext, String cl) {
        if (ext == null) {
            throw new RegistryException(
                    2003,
                    "RGP restore extension required"
            );
        }

        Element rgpUpdate = null;

        for (Element e : kids(ext)) {
            if ("update".equals(e.getLocalName())
                    && NS_RGP.equals(e.getNamespaceURI())) {
                rgpUpdate = e;
                break;
            }
        }

        if (rgpUpdate == null) {
            throw new RegistryException(
                    2003,
                    "RGP update extension required"
            );
        }

        Element restore = kid(rgpUpdate, "restore");

        if (restore == null) {
            throw new RegistryException(
                    2003,
                    "RGP restore element required"
            );
        }

        String op = restore.getAttribute("op");

        String name = need(obj, "name");

        if ("request".equals(op)) {

            reg.restoreDomain(
                    st.registrar,
                    name,
                    "request",
                    null
            );

            return response(
                    1001,
                    "Command completed successfully; action pending",
                    null,
                    cl
            );
        }

        if ("report".equals(op)) {

            Registry.RestoreReport report =
                    parseRgpReport(restore);

            reg.restoreDomain(
                    st.registrar,
                    name,
                    "report",
                    report
            );

            return response(
                    1000,
                    "Command completed successfully",
                    null,
                    cl
            );
        }

        throw new RegistryException(
                2003,
                "Invalid RGP restore operation"
        );
    }
'''

epp = replace_method(epp, "domainRestore", domain_restore)


# ------------------------------------------------------------
# Add parseRgpReport()
# ------------------------------------------------------------

# IMPORTANT:
# Check for the actual method declaration, not merely the call.
if not re.search(
        r"(?m)^\s*(?:private|public|protected)\s+"
        r"(?:static\s+)?Registry\.RestoreReport\s+parseRgpReport\s*\(",
        epp):

    parse_method = r'''
    private static Registry.RestoreReport parseRgpReport(Element report) {

        String preData =
                text(report, "preData");

        String postData =
                text(report, "postData");

        String delTime =
                text(report, "delTime");

        String resTime =
                text(report, "resTime");

        String resReason =
                text(report, "resReason");

        String other =
                text(report, "other");

        List<String> statements =
                new ArrayList<>();

        for (Element e : kids(report)) {
            if ("statement".equals(e.getLocalName())) {
                String value =
                        e.getTextContent().trim();

                if (!value.isEmpty()) {
                    statements.add(value);
                }
            }
        }

        /*
         * RFC 3915 restore reports require:
         *   preData
         *   postData
         *   delTime
         *   resTime
         *   resReason
         *   exactly two statements
         */
        if (preData == null || preData.isBlank()
                || postData == null || postData.isBlank()
                || delTime == null || delTime.isBlank()
                || resTime == null || resTime.isBlank()
                || resReason == null || resReason.isBlank()
                || statements.size() != 2) {

            throw new RegistryException(
                    2003,
                    "Invalid RGP restore report"
            );
        }

        long delEpoch;
        long resEpoch;

        try {
            delEpoch =
                    Instant.parse(delTime).getEpochSecond();

            resEpoch =
                    Instant.parse(resTime).getEpochSecond();

        } catch (DateTimeParseException e) {

            throw new RegistryException(
                    2005,
                    "Invalid date-time value"
            );
        }

        return new Registry.RestoreReport(
                preData,
                postData,
                delEpoch,
                resEpoch,
                resReason,
                statements,
                other
        );
    }
'''

    # Put it immediately before hostCreate().
    marker = re.search(
        r"(?m)^[ \t]*private String hostCreate\s*\(",
        epp
    )

    if not marker:
        raise RuntimeError(
            "Could not find hostCreate() insertion point"
        )

    epp = (
        epp[:marker.start()]
        + parse_method.rstrip()
        + "\n\n"
        + epp[marker.start():]
    )

    print("Added parseRgpReport()")

else:
    print("parseRgpReport() already exists")


EPP.write_text(epp, encoding="utf-8")

print("EppServer.java fixed")


# ============================================================
# Registry.java
# ============================================================

backup(REG)

reg = REG.read_text(encoding="utf-8")


# ------------------------------------------------------------
# Replace restoreDomain()
# ------------------------------------------------------------

restore_domain = r'''
    public void restoreDomain(
            String registrar,
            String rawName,
            String op,
            RestoreReport report
    ) {

        return tx(c -> {

            requireActive(c, registrar);

            String name =
                    Names.parse(rawName, cfg);

            Row r =
                    fetch(c, name);

            if (r == null) {
                throw new RegistryException(
                        2303,
                        "Object does not exist"
                );
            }

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
'''

reg = replace_method(
    reg,
    "restoreDomain",
    restore_domain
)

REG.write_text(reg, encoding="utf-8")

print("Registry.java fixed")


# ============================================================
# FINAL CHECKS
# ============================================================

epp_check = EPP.read_text(encoding="utf-8")
reg_check = REG.read_text(encoding="utf-8")

checks = {
    "EPP domainRestore": re.search(
        r"\bprivate String domainRestore\s*\(",
        epp
    ),
    "EPP parseRgpReport": re.search(
        r"\bparseRgpReport\s*\(",
        epp
    ),
    "Registry restoreDomain": re.search(
        r"\bpublic void restoreDomain\s*\(",
        reg_check
    ),
    "Registry RestoreReport": re.search(
        r"\brecord RestoreReport\s*\(",
        reg_check
    ),
    "Lifecycle restore timeout": "PENDING_RESTORE" in reg_check,
}

print()
print("=" * 60)
print("RGP PATCH COMPLETE")
print("=" * 60)

for name, ok in checks.items():
    print(f"{name:35} {'OK' if ok else 'MISSING'}")

print()
print("Now run:")
print(r".\mvnw.cmd clean test")