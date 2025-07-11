package authentication.management.exception;

/**
 * Excepción lanzada cuando no se encuentra un usuario
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserNotFoundException(Long id) {
        super("Usuario con ID " + id + " no encontrado");
    }

    public UserNotFoundException(String usernameOrEmail, boolean isEmail) {
        super("Usuario no encontrado con " + (isEmail ? "email" : "username") + ": " + usernameOrEmail);
    }
}