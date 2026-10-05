#!/bin/bash
# Compiles and runs all tests. Needs: JDK 21, H2 and JUnit 5 jars (paths below match Ubuntu's apt packages).
set -euo pipefail
cd "$(dirname "$0")/.."
J=/usr/share/java
LIBS="$J/h2.jar"
TESTLIBS="$J/junit-jupiter-api.jar:$J/junit-jupiter-engine.jar:$J/junit-jupiter-params.jar:$J/junit-platform-commons.jar:$J/junit-platform-engine.jar:$J/junit-platform-launcher.jar:$J/junit-platform-console.jar:$J/junit-platform-reporting.jar:$J/opentest4j.jar:$J/apiguardian-api.jar"
[ -d certs ] || scripts/gen-certs.sh certs
rm -rf out && mkdir -p out/main out/test
javac -Xlint:all -d out/main $(find src/main -name '*.java')
javac -Xlint:-options -cp "out/main:$LIBS:$TESTLIBS" -d out/test $(find src/test -name '*.java')
java -Dcerts=certs -cp "out/main:out/test:$LIBS:$TESTLIBS" org.junit.platform.console.ConsoleLauncher execute --scan-classpath out/test --details=tree --disable-banner 2>&1
