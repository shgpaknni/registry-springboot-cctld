package registry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * RFC 4033/4034/4035 zone-signing adapter for BIND.
 * Private key material remains in the configured key directory and is never logged.
 */
public final class DnssecZoneSigner {
    @FunctionalInterface
    interface CommandRunner {
        void run(List<String> command, Duration timeout, Path logFile) throws IOException;
    }

    private final String signerCommand;
    private final String verifierCommand;
    private final Path keyDirectory;
    private final String origin;
    private final Duration timeout;
    private final CommandRunner runner;

    public DnssecZoneSigner(
            String signerCommand,
            String verifierCommand,
            Path keyDirectory,
            String origin) {
        this(signerCommand, verifierCommand, keyDirectory, origin,
                Duration.ofMinutes(2), null);
    }

    DnssecZoneSigner(
            String signerCommand,
            String verifierCommand,
            Path keyDirectory,
            String origin,
            Duration timeout,
            CommandRunner runner) {
        if (signerCommand == null || signerCommand.isBlank()
                || verifierCommand == null || verifierCommand.isBlank()) {
            throw new IllegalArgumentException("BIND signer and verifier commands are required");
        }
        this.signerCommand = signerCommand;
        this.verifierCommand = verifierCommand;
        this.keyDirectory = Objects.requireNonNull(keyDirectory).toAbsolutePath().normalize();
        this.origin = ZoneWriter.fqdn(origin);
        this.timeout = Objects.requireNonNull(timeout);
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("DNSSEC command timeout must be positive");
        }
        this.runner = runner == null ? this::runProcess : runner;
    }

    /**
     * Writes signedZone only after BIND signing, structural checks, and dnssec-verify succeed.
     * Caller is responsible for atomically publishing that verified result.
     */
    public void sign(Path unsignedZone, Path signedZone) throws IOException {
        Path input = unsignedZone.toAbsolutePath().normalize();
        Path output = signedZone.toAbsolutePath().normalize();
        if (!Files.isRegularFile(input)) {
            throw new IOException("Unsigned zone file does not exist: " + input);
        }
        if (input.equals(output)) {
            throw new IOException("Unsigned and signed zone paths must differ");
        }

        List<Path> keys = publicKeyFilesWithPrivateCounterparts();
        Files.createDirectories(output.getParent());
        Files.deleteIfExists(output);

        Path signLog = output.resolveSibling(output.getFileName() + ".sign.log");
        Path verifyLog = output.resolveSibling(output.getFileName() + ".verify.log");
        boolean verified = false;

        try {
            List<String> signArgs = new ArrayList<>();
            signArgs.add(signerCommand);
            signArgs.add("-o");
            signArgs.add(origin);
            signArgs.add("-f");
            signArgs.add(output.toString());
            signArgs.add(input.toString());
            for (Path key : keys) signArgs.add(key.toString());

            runner.run(List.copyOf(signArgs), timeout, signLog);

            if (!Files.isRegularFile(output) || Files.size(output) == 0) {
                throw new IOException("BIND signer did not produce a signed zone file");
            }
            requireDnssecRecords(output);

            runner.run(List.of(
                    verifierCommand,
                    "-o", origin,
                    output.toString()), timeout, verifyLog);

            verified = true;
        } finally {
            Files.deleteIfExists(signLog);
            Files.deleteIfExists(verifyLog);
            if (!verified) Files.deleteIfExists(output);
        }
    }

    private List<Path> publicKeyFilesWithPrivateCounterparts() throws IOException {
        if (!Files.isDirectory(keyDirectory)) {
            throw new IOException("DNSSEC key directory does not exist: " + keyDirectory);
        }

        List<Path> keys = new ArrayList<>();
        try (Stream<Path> files = Files.list(keyDirectory)) {
            for (Path privateKey : files
                    .filter(p -> p.getFileName().toString().startsWith("K")
                            && p.getFileName().toString().endsWith(".private"))
                    .toList()) {
                String name = privateKey.getFileName().toString();
                String base = name.substring(0, name.length() - ".private".length());
                Path publicKey = keyDirectory.resolve(base + ".key");
                if (Files.isRegularFile(publicKey)) keys.add(publicKey.toAbsolutePath().normalize());
            }
        }

        keys.sort(Comparator.comparing(Path::toString));
        if (keys.isEmpty()) {
            throw new IOException("No matching BIND .key/.private key pairs found in " + keyDirectory);
        }
        return List.copyOf(keys);
    }

    private static void requireDnssecRecords(Path file) throws IOException {
        boolean dnskey = false;
        boolean rrsig = false;
        boolean nsec = false;

        try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                String record = line.split(";", 2)[0].trim();
                if (record.isEmpty()) continue;
                for (String token : record.split("\\s+")) {
                    if (token.equalsIgnoreCase("DNSKEY")) dnskey = true;
                    if (token.equalsIgnoreCase("RRSIG")) rrsig = true;
                    if (token.equalsIgnoreCase("NSEC") || token.equalsIgnoreCase("NSEC3")) nsec = true;
                }
            }
        }

        if (!dnskey || !rrsig || !nsec) {
            throw new IOException("Signer output lacks required DNSKEY, RRSIG, or NSEC/NSEC3 records");
        }
    }

    private void runProcess(List<String> command, Duration wait, Path logFile) throws IOException {
        Files.createDirectories(logFile.toAbsolutePath().getParent());
        Process process = new ProcessBuilder(command)
                .directory(keyDirectory.toFile())
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile())
                .start();

        try {
            boolean finished = process.waitFor(wait.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IOException("Timed out running " + command.get(0)
                        + " after " + wait);
            }
            if (process.exitValue() != 0) {
                String output = Files.isRegularFile(logFile)
                        ? Files.readString(logFile, StandardCharsets.UTF_8) : "";
                if (output.length() > 8000) output = output.substring(output.length() - 8000);
                throw new IOException(command.get(0) + " exited with code "
                        + process.exitValue() + (output.isBlank() ? "" : ":\n" + output));
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while running " + command.get(0), e);
        }
    }
}
