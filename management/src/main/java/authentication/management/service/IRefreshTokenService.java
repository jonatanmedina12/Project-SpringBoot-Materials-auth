package authentication.management.service;

import authentication.management.entity.RefreshToken;
import authentication.management.entity.User;

import java.util.List;

/**
 * Interface para el servicio de gestión de refresh tokens
 */
public interface IRefreshTokenService {

    /**
     * Crea un nuevo refresh token para un usuario
     *
     * @param user el usuario
     * @param tokenValue valor del token (opcional)
     * @return el refresh token creado
     */
    RefreshToken createRefreshToken(User user, String tokenValue);

    /**
     * Valida un refresh token
     *
     * @param token el token a validar
     * @return el refresh token si es válido
     */
    RefreshToken validateRefreshToken(String token);

    /**
     * Marca un token como usado
     *
     * @param token el token a marcar
     */
    void markTokenAsUsed(String token);

    /**
     * Revoca un refresh token específico
     *
     * @param token el token a revocar
     */
    void revokeRefreshToken(String token);

    /**
     * Revoca todos los refresh tokens de un usuario
     *
     * @param userId ID del usuario
     */
    void revokeAllUserTokens(Long userId);

    /**
     * Obtiene tokens válidos de un usuario
     *
     * @param userId ID del usuario
     * @return lista de tokens válidos
     */
    List<RefreshToken> getValidUserTokens(Long userId);

    /**
     * Verifica si un token específico es válido
     *
     * @param token el token a verificar
     * @return true si el token es válido
     */
    boolean isTokenValid(String token);

    /**
     * Limpia tokens expirados
     */
    void cleanupExpiredTokens();
}