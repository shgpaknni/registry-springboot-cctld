package registry;

/** A failure carrying the EPP result code (RFC 5730 section 3) to return to the client. */
@SuppressWarnings("serial")
public class RegistryException extends RuntimeException {
    public final int code;

    public RegistryException(int code, String message) {
        super(message);
        this.code = code;
    }

    public RegistryException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }
}
