package authentication.management.exception;

/**
 * Excepción lanzada cuando una cuenta está bloqueada
 */
public class AccountLockedException extends RuntimeException {



    public AccountLockedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccountLockedException(String username) {
        super("La cuenta del usuario '" + username + "' está bloqueada debido a múltiples intentos fallidos de login");
    }
}