# ccTLD Registry Prototype — Spring Boot

This version wraps the existing registry domain logic in Spring Boot.

## What remains unchanged

- `Registry` — domain lifecycle, billing, audit chain, contacts and registrar logic
- `Db` — H2/JDBC persistence
- `EppServer` — EPP over TLS/mTLS on port 7700
- `RdapServer` — RDAP read-only endpoint on port 8080
- `ZoneWriter` — zone-file publication
- Existing tests and protocol implementation

Spring Boot now owns application startup, configuration, lifecycle and shutdown.

## Requirements

- Java 21+
- Maven 3.9+

## Run

```bash
mvn spring-boot:run
```

or:

```bash
mvn clean package
java -jar target/cctld-registry-0.0.1-SNAPSHOT.jar
```

## Configuration

Edit `src/main/resources/application.yml`, or override properties from the command line:

```bash
java -jar target/cctld-registry-0.0.1-SNAPSHOT.jar   --registry.zone=in   --registry.db=./data/registry   --registry.epp.port=7700   --registry.rdap.port=8080
```

TLS keystore/truststore and passwords are also externalized under `registry.tls.*`.

## DNSSEC zone signing (RFC 4033, RFC 4034, RFC 4035)

`ZoneWriter` emits the SOA, apex NS, child NS delegations, and child DS records stored through the EPP DNSSEC mapping. When `registry.dnssec.enabled` is `true`, the publisher invokes BIND `dnssec-signzone` with explicit key pairs, checks for DNSKEY/RRSIG/NSEC-or-NSEC3 records, and runs `dnssec-verify`. Only a verified result replaces the published zone file. If signing or verification fails, the previous file remains in place and the outbox is not marked published.

DNSSEC signing is **disabled by default** until the deployment has real key material and authoritative nameserver/SOA settings. Install BIND utilities so `dnssec-keygen`, `dnssec-signzone`, and `dnssec-verify` are available on `PATH`. Example commands for the prototype zone `xx`:

```powershell
New-Item -ItemType Directory -Force .\data\dnssec-keys | Out-Null
dnssec-keygen -K .\data\dnssec-keys -a ECDSAP256SHA256 -f KSK -n ZONE xx
dnssec-keygen -K .\data\dnssec-keys -a ECDSAP256SHA256 -n ZONE xx
```

Keep the generated private keys out of Git; `data/` is ignored. Configure `registry.dnssec.enabled: true`, the real apex nameservers, SOA values, and key directory before enabling signing. Replace `xx` in the key-generation commands with the configured zone name. For an actual TLD, successful local signing is only one part of deployment: the parent/root delegation must separately publish the DS for the TLD's DNSKEY.

## Health

Spring Boot Actuator exposes:

```text
GET http://localhost:8081/actuator/health
```

The RDAP service supports exact domain, nameserver, and registrar-entity lookups plus a bounded subset of RFC 9082 search queries. Registrant details are redacted. Search queries accept one selector and at most one `*` wildcard; search results are capped at 100 objects.

```text
GET  /rdap/help
GET  /rdap/domain/{name}
HEAD /rdap/domain/{name}
GET  /rdap/nameserver/{name}
HEAD /rdap/nameserver/{name}
GET  /rdap/entity/{registrar-handle}
HEAD /rdap/entity/{registrar-handle}
GET  /rdap/domains?name={pattern}
GET  /rdap/nameservers?name={pattern}
GET  /rdap/entities?handle={pattern}
GET  /rdap/entities?fn={pattern}
```

Domain search supports `name`; nameserver search supports `name`; registrar entity search supports `handle` and `fn`. Other selectors (including nameserver-IP and domain-by-nameserver searches) and unsupported query classes return HTTP 501. Malformed search patterns return HTTP 400. Search results expose only registrar entity data; contact entity search is not implemented.

EPP remains a separate TLS protocol listener because EPP is not HTTP.

## Architecture

```text
                    Spring Boot
                         |
          +--------------+--------------+
          |              |              |
       Registry          |         Lifecycle
          |              |          Scheduler
        Db/H2            |
          |         Protocol adapters
          |          /            \
          |       EPP/mTLS       RDAP
          |       :7700          :8080
          |
      ZoneWriter
          |
    data/zone.txt
```

The original `Main.java` is retained only as legacy/reference code; `RegistryApplication` is now the application entry point.
