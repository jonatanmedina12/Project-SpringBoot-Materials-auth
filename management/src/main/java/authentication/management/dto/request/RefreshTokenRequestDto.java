package authentication.management.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO para solicitudes de refresh token
 */
public class RefreshTokenRequestDto {

    @NotBlank(message = "El refresh token es requerido")
    private String refreshToken;

    public RefreshTokenRequestDto() {}

    public RefreshTokenRequestDto(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // Getters y Setters
    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}