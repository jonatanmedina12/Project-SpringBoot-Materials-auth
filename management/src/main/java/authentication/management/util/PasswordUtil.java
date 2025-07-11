package authentication.management.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Utilidad para manejo de contraseñas
 */
@Component
public class PasswordUtil {

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
    private static final SecureRandom secureRandom = new SecureRandom();

    // Patrones de validación
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile(".*[@$!%*?&].*");

    /**
     * Encripta una contraseña usando BCrypt
     */
    public String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    /**
     * Verifica si una contraseña coincide con su hash
     */
    public boolean matches(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Valida que una contraseña cumpla con los criterios de seguridad
     */
    public boolean isValidPassword(String password) {
        if (password == null || password.length() < 8 || password.length() > 100) {
            return false;
        }

        return UPPERCASE_PATTERN.matcher(password).matches() &&
                LOWERCASE_PATTERN.matcher(password).matches() &&
                DIGIT_PATTERN.matcher(password).matches() &&
                SPECIAL_CHAR_PATTERN.matcher(password).matches();
    }

    /**
     * Genera una contraseña temporal aleatoria
     */
    public String generateTemporaryPassword(int length) {
        if (length < 8) length = 8;
        if (length > 50) length = 50;

        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String specialChars = "@$!%*?&";
        String allChars = uppercase + lowercase + digits + specialChars;

        StringBuilder password = new StringBuilder();

        // Asegurar al menos un carácter de cada tipo
        password.append(uppercase.charAt(secureRandom.nextInt(uppercase.length())));
        password.append(lowercase.charAt(secureRandom.nextInt(lowercase.length())));
        password.append(digits.charAt(secureRandom.nextInt(digits.length())));
        password.append(specialChars.charAt(secureRandom.nextInt(specialChars.length())));

        // Completar el resto de la longitud
        for (int i = 4; i < length; i++) {
            password.append(allChars.charAt(secureRandom.nextInt(allChars.length())));
        }

        // Mezclar los caracteres
        return shuffleString(password.toString());
    }

    /**
     * Mezcla los caracteres de una cadena
     */
    private String shuffleString(String input) {
        char[] characters = input.toCharArray();
        for (int i = 0; i < characters.length; i++) {
            int randomIndex = secureRandom.nextInt(characters.length);
            char temp = characters[i];
            characters[i] = characters[randomIndex];
            characters[randomIndex] = temp;
        }
        return new String(characters);
    }

    /**
     * Obtiene un mensaje descriptivo de los errores de validación de contraseña
     */
    public String getPasswordValidationMessage(String password) {
        Map<Predicate<String>, String> validationRules = Map.of(
                Objects::isNull, "La contraseña es requerida",
                p -> p != null && p.length() < 8, "La contraseña debe tener al menos 8 caracteres",
                p -> p != null && p.length() > 100, "La contraseña no puede tener más de 100 caracteres",
                p -> p != null && !UPPERCASE_PATTERN.matcher(p).matches(), "La contraseña debe contener al menos una letra mayúscula",
                p -> p != null && !LOWERCASE_PATTERN.matcher(p).matches(), "La contraseña debe contener al menos una letra minúscula",
                p -> p != null && !DIGIT_PATTERN.matcher(p).matches(), "La contraseña debe contener al menos un número",
                p -> p != null && !SPECIAL_CHAR_PATTERN.matcher(p).matches(), "La contraseña debe contener al menos un carácter especial (@$!%*?&)"
        );

        return validationRules.entrySet().stream()
                .filter(entry -> entry.getKey().test(password))
                .findFirst()
                .map(Map.Entry::getValue)
                .orElse(null);
    }

}
