package authentication.management.exception;

/**
 * Excepción lanzada cuando un usuario no tiene suficientes privilegios
 */
public class InsufficientPrivilegesException extends RuntimeException {

    public InsufficientPrivilegesException(String message) {
        super(message);
    }

    public InsufficientPrivilegesException(String message, Throwable cause) {
        super(message, cause);
    }

    public InsufficientPrivilegesException(String username, String requiredPermission) {
        super("El usuario '" + username + "' no tiene el permiso requerido: " + requiredPermission);
    }
}