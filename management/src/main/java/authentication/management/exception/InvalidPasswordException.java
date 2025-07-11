package authentication.management.exception;

/**
 * Excepción lanzada cuando una contraseña no cumple los criterios de seguridad
 */
public class InvalidPasswordException extends RuntimeException {

    public InvalidPasswordException(String message) {
        super(message);
    }

    public InvalidPasswordException(String message, Throwable cause) {
        super(message, cause);
    }
}