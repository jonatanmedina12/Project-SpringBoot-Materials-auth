package authentication.management.service;

import authentication.management.dto.response.JwtResponseDto;
import authentication.management.entity.Permission;
import authentication.management.entity.Role;
import authentication.management.entity.User;
import authentication.management.util.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Servicio para generación y manejo de tokens JWT
 */
@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final JwtTokenUtil jwtTokenUtil;

    public JwtService(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    /**
     * Genera tokens JWT completos para un usuario
     */
    public JwtResponseDto generateTokensForUser(User user) {
        logger.info("Generando tokens JWT para usuario: {}", user.getUsername());

        try {
            // Extraer roles y permisos
            String[] roles = user.getRoles().stream()
                    .map(role -> role.getName())
                    .toArray(String[]::new);

            String[] permissions = user.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())
                    .map(permission -> permission.getName())
                    .distinct()
                    .toArray(String[]::new);

            // Generar claims adicionales
            Map<String, Object> extraClaims = jwtTokenUtil.generateExtraClaims(
                    user.getEmail(),
                    user.getFullName(),
                    roles,
                    permissions
            );

            // Generar tokens
            String accessToken = jwtTokenUtil.generateToken(user.getUsername(), extraClaims);
            String refreshToken = jwtTokenUtil.generateRefreshToken(user.getUsername());

            // Calcular expiración
            Long expiresIn = jwtTokenUtil.getJwtExpirationInSeconds();
            LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(expiresIn);

            logger.info("Tokens JWT generados exitosamente para usuario: {}", user.getUsername());

            return new JwtResponseDto(accessToken, refreshToken, expiresIn, expiresAt);

        } catch (Exception e) {
            logger.error("Error al generar tokens JWT para usuario {}: {}", user.getUsername(), e.getMessage(), e);
            throw new RuntimeException("Error al generar tokens JWT", e);
        }
    }

    /**
     * Valida un token JWT
     */
    public boolean validateToken(String token, String username) {
        try {
            return jwtTokenUtil.validateToken(token, username);
        } catch (Exception e) {
            logger.error("Error al validar token JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extrae el username de un token
     */
    public String getUsernameFromToken(String token) {
        try {
            return jwtTokenUtil.getUsernameFromToken(token);
        } catch (Exception e) {
            logger.error("Error al extraer username del token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Verifica si un token ha expirado
     */
    public boolean isTokenExpired(String token) {
        try {
            return jwtTokenUtil.isTokenExpired(token);
        } catch (Exception e) {
            logger.error("Error al verificar expiración del token: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Obtiene el tiempo restante de un token en segundos
     */
    public Long getTokenRemainingTime(String token) {
        try {
            return jwtTokenUtil.getExpirationTimeInSeconds(token);
        } catch (Exception e) {
            logger.error("Error al obtener tiempo restante del token: {}", e.getMessage());
            return 0L;
        }
    }

    /**
     * Renueva un access token usando un refresh token válido
     */
    public JwtResponseDto renewAccessToken(String refreshToken, User user) {
        logger.info("Renovando access token para usuario: {}", user.getUsername());

        try {
            // Validar refresh token
            if (!jwtTokenUtil.validateToken(refreshToken, user.getUsername())) {
                throw new IllegalArgumentException("Refresh token inválido o expirado");
            }

            // Generar nuevo access token
            String[] roles = user.getRoles().stream()
                    .map(Role::getName)
                    .toArray(String[]::new);

            String[] permissions = user.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())
                    .map(Permission::getName)
                    .distinct()
                    .toArray(String[]::new);

            Map<String, Object> extraClaims = jwtTokenUtil.generateExtraClaims(
                    user.getEmail(),
                    user.getFullName(),
                    roles,
                    permissions
            );

            String newAccessToken = jwtTokenUtil.generateToken(user.getUsername(), extraClaims);
            Long expiresIn = jwtTokenUtil.getJwtExpirationInSeconds();
            LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(expiresIn);

            logger.info("Access token renovado exitosamente para usuario: {}", user.getUsername());

            return new JwtResponseDto(newAccessToken, refreshToken, expiresIn, expiresAt);

        } catch (Exception e) {
            logger.error("Error al renovar access token para usuario {}: {}", user.getUsername(), e.getMessage(), e);
            throw new RuntimeException("Error al renovar access token", e);
        }
    }

    /**
     * Extrae el token del header Authorization
     */
    public String extractTokenFromAuthHeader(String authHeader) {
        return jwtTokenUtil.extractTokenFromAuthHeader(authHeader);
    }
}