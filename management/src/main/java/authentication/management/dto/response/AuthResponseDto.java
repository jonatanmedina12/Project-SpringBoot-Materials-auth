package authentication.management.dto.response;

/**
 * DTO de respuesta completa para autenticación
 */
public class AuthResponseDto {

    private UserResponseDto user;
    private JwtResponseDto tokens;

    public AuthResponseDto() {}

    public AuthResponseDto(UserResponseDto user, JwtResponseDto tokens) {
        this.user = user;
        this.tokens = tokens;
    }

    // Getters y Setters
    public UserResponseDto getUser() {
        return user;
    }

    public void setUser(UserResponseDto user) {
        this.user = user;
    }

    public JwtResponseDto getTokens() {
        return tokens;
    }

    public void setTokens(JwtResponseDto tokens) {
        this.tokens = tokens;
    }
}