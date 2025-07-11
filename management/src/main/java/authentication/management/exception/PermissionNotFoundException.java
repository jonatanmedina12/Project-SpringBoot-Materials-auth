package authentication.management.exception;

/**
 * Excepción lanzada cuando no se encuentra un permiso
 */
public class PermissionNotFoundException extends RuntimeException {



    public PermissionNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public PermissionNotFoundException(String permissionName) {
        super("Permiso '" + permissionName + "' no encontrado en el sistema");
    }
}