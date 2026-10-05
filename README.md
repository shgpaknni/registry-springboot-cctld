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

## Health

Spring Boot Actuator exposes:

```text
GET http://localhost:8081/actuator/health
```

The existing RDAP service continues to serve:

```text
GET /rdap/help
GET /rdap/domain/{name}
```

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
