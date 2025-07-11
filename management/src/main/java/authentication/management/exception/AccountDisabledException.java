package authentication.management.exception;

/**
 * Excepción lanzada cuando una cuenta está deshabilitada
 */
public class AccountDisabledException extends RuntimeException {



    public AccountDisabledException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccountDisabledException(String username) {
        super("La cuenta del usuario '" + username + "' está deshabilitada");
    }
}
