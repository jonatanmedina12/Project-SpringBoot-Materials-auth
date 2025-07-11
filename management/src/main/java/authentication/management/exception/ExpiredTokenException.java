package authentication.management.exception;

/**
        * Excepción lanzada cuando un token ha expirado
 */
public class ExpiredTokenException extends RuntimeException {

    public ExpiredTokenException(String message) {
        super(message);
    }

    public ExpiredTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public ExpiredTokenException() {
        super("El token JWT ha expirado");
    }
}