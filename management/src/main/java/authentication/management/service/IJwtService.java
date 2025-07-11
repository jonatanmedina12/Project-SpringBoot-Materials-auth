package authentication.management.service;


import authentication.management.dto.response.JwtResponseDto;
import authentication.management.entity.User;
import io.jsonwebtoken.Claims;

import java.util.Map;

/**
 * Interface para el servicio de gestión de JWT
 */
public interface IJwtService {

    /**
     * Genera tokens para un usuario
     *
     * @param user el usuario
     * @return tokens JWT generados
     */
    JwtResponseDto generateTokensForUser(User user);

    /**
     * Renueva un access token
     *
     * @param refreshToken el refresh token
     * @param user el usuario
     * @return nuevos tokens JWT
     */
    JwtResponseDto renewAccessToken(String refreshToken, User user);

    /**
     * Valida un token
     *
     * @param token el token a validar
     * @param username el username esperado
     * @return true si es válido
     */
    boolean validateToken(String token, String username);

    /**
     * Extrae el username de un token
     *
     * @param token el token JWT
     * @return el username
     */
    String getUsernameFromToken(String token);

    /**
     * Extrae todos los claims de un token
     *
     * @param token el token JWT
     * @return los claims
     */
    Claims extractAllClaims(String token);

    /**
     * Genera un access token
     *
     * @param claims claims adicionales
     * @param username nombre de usuario
     * @return el token generado
     */
    String generateAccessToken(Map<String, Object> claims, String username);

    /**
     * Genera un refresh token
     *
     * @param username nombre de usuario
     * @return el token generado
     */
    String generateRefreshToken(String username);

    /**
     * Verifica si un token ha expirado
     *
     * @param token el token a verificar
     * @return true si ha expirado
     */
    boolean isTokenExpired(String token);
}