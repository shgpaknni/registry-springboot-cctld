#!/bin/bash
# Generates DEVELOPMENT-ONLY certificates: a server cert, two registrar client certs, and a rogue cert.
# Production uses certificates from the internal CA (Vault PKI, ADR-013).
set -euo pipefail
OUT="${1:-certs}"; PASS=changeit
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"
gen() { # alias, dn, extra args
  keytool -genkeypair -alias "$1" -keyalg RSA -keysize 2048 -dname "$2" -validity 825 -storetype PKCS12 \
    -keystore "$1.p12" -storepass $PASS -keypass $PASS "${@:3}" >/dev/null 2>&1
  keytool -exportcert -alias "$1" -keystore "$1.p12" -storepass $PASS -file "$1.crt" >/dev/null 2>&1
}
gen server "CN=localhost" -ext san=dns:localhost,ip:127.0.0.1
gen reg1 "CN=registrar-one"
gen reg2 "CN=registrar-two"
gen rogue "CN=rogue"
imp() { keytool -importcert -noprompt -alias "$2" -file "$2.crt" -keystore "$1" -storetype PKCS12 -storepass $PASS >/dev/null 2>&1; }
imp server-trust.p12 reg1; imp server-trust.p12 reg2      # server trusts registrar certs only
imp client-trust.p12 server                               # clients trust the server cert
echo "certificates written to $(pwd)"
