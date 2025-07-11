package authentication.management.exception;

/**
 * Excepción lanzada cuando un token JWT es inválido
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}