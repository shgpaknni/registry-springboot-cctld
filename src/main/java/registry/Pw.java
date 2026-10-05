package registry;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Salted PBKDF2 hashing for registrar passwords and domain AuthInfo (SEC-003, DR-013). */
final class Pw {
    private static final SecureRandom RNG = new SecureRandom();

    private Pw() {}

    static String hash(String secret, int iterations) {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        return iterations + ":" + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(derive(secret, salt, iterations));
    }

    static boolean verify(String secret, String stored) {
        try {
            String[] p = stored.split(":");
            byte[] expected = Base64.getDecoder().decode(p[2]);
            byte[] actual = derive(secret, Base64.getDecoder().decode(p[1]), Integer.parseInt(p[0]));
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static byte[] derive(String secret, byte[] salt, int iterations) {
        try {
            var spec = new PBEKeySpec(secret.toCharArray(), salt, iterations, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
