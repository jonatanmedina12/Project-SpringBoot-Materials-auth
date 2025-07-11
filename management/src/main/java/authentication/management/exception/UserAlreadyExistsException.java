package authentication.management.exception;

/**
 * Excepción lanzada cuando se intenta crear un usuario que ya existe
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }

    public UserAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserAlreadyExistsException(String username, String email) {
        super("Usuario ya existe con username: " + username + " o email: " + email);
    }
}