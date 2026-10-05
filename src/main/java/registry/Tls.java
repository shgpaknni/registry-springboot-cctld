package registry;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.HexFormat;

/** TLS helpers: builds contexts from PKCS12 stores and fingerprints certificates for registrar pinning. */
public final class Tls {
    private Tls() {}

    public static SSLContext context(Path keyStore, char[] keyPass, Path trustStore, char[] trustPass)
            throws GeneralSecurityException, IOException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(load(keyStore, keyPass), keyPass);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(load(trustStore, trustPass));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    public static KeyStore load(Path file, char[] pass) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, pass);
        }
        return ks;
    }

    public static String fingerprint(Certificate cert) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
