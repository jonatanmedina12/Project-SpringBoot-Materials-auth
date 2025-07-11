package authentication.management.service;

import authentication.management.dto.request.LoginRequestDto;
import authentication.management.dto.request.RefreshTokenRequestDto;
import authentication.management.dto.request.RegisterRequestDto;
import authentication.management.dto.response.AuthResponseDto;
import authentication.management.dto.response.JwtResponseDto;
import authentication.management.dto.response.UserResponseDto;

import java.util.Optional;

/**
 * Interface para el servicio de autenticación
 */
public interface IAuthService {

    /**
     * Autentica un usuario y genera tokens
     *
     * @param loginRequest datos de login
     * @return respuesta de autenticación con tokens
     */
    AuthResponseDto login(LoginRequestDto loginRequest);

    /**
     * Registra un nuevo usuario
     *
     * @param registerRequest datos de registro
     * @return respuesta de autenticación con tokens
     */
    AuthResponseDto register(RegisterRequestDto registerRequest);

    /**
     * Renueva un access token usando un refresh token
     *
     * @param refreshRequest datos del refresh token
     * @return nuevos tokens JWT
     */
    JwtResponseDto refreshToken(RefreshTokenRequestDto refreshRequest);

    /**
     * Cierra sesión revocando los tokens del usuario
     *
     * @param username nombre del usuario
     * @param refreshToken token a revocar (opcional)
     */
    void logout(String username, String refreshToken);

    /**
     * Valida un token JWT
     *
     * @param token el token a validar
     * @param username el nombre de usuario esperado
     * @return true si el token es válido
     */
    boolean validateToken(String token, String username);

    /**
     * Obtiene información del usuario desde un token
     *
     * @param token el token JWT
     * @return información del usuario si el token es válido
     */
    Optional<UserResponseDto> getUserFromToken(String token);


}