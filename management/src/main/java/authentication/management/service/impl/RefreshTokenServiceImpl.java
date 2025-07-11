package authentication.management.service.impl;

import authentication.management.entity.RefreshToken;
import authentication.management.entity.User;
import authentication.management.exception.InvalidTokenException;
import authentication.management.repository.command.RefreshCommandTokenRepository;
import authentication.management.repository.query.RefreshQueryTokenRepository;
import authentication.management.service.IRefreshTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Servicio para gestión de refresh tokens
 */
@Service
@Transactional
public class RefreshTokenServiceImpl implements IRefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenServiceImpl.class);

    @Value("${app.jwt.refresh-expiration:2592000}")
    private Long refreshTokenExpirationSeconds;

    private final RefreshQueryTokenRepository refreshTokenRepository;
    private final RefreshCommandTokenRepository refreshCommandTokenRepository;

    public RefreshTokenServiceImpl(RefreshQueryTokenRepository refreshTokenRepository, RefreshCommandTokenRepository refreshCommandTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshCommandTokenRepository = refreshCommandTokenRepository;
    }

    /**
     * Crea un nuevo refresh token para un usuario
     */
    public RefreshToken createRefreshToken(User user, String tokenValue) {
        logger.debug("Creando refresh token para usuario: {}", user.getUsername());

        try {
            // Generar token único si no se proporciona
            String token = (tokenValue != null) ? tokenValue : generateUniqueToken();

            // Calcular fecha de expiración
            LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTokenExpirationSeconds);

            // Crear y guardar refresh token
            RefreshToken refreshToken = new RefreshToken(token, expiresAt, user);
            RefreshToken savedToken = refreshTokenRepository.save(refreshToken);

            logger.debug("Refresh token creado exitosamente para usuario: {}", user.getUsername());
            return savedToken;

        } catch (Exception e) {
            logger.error("Error al crear refresh token para usuario: {}", user.getUsername(), e);
            throw new RuntimeException("Error al crear refresh token", e);
        }
    }

    /**
     * Valida un refresh token
     */
    @Transactional(readOnly = true)
    public RefreshToken validateRefreshToken(String token) {
        logger.debug("Validando refresh token");

        try {
            RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                    .orElseThrow(() -> new InvalidTokenException("Refresh token no encontrado"));

            if (!refreshToken.isValid()) {
                logger.warn("Refresh token inválido: usado={}, revocado={}, expirado={}",
                        refreshToken.getUsed(), refreshToken.getRevoked(), refreshToken.isExpired());
                throw new InvalidTokenException("Refresh token inválido o expirado");
            }

            logger.debug("Refresh token validado exitosamente");
            return refreshToken;

        } catch (InvalidTokenException e) {
            logger.warn("Validación de refresh token fallida: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error al validar refresh token", e);
            throw new InvalidTokenException("Error interno al validar refresh token");
        }
    }

    /**
     * Marca un token como usado
     */
    public void markTokenAsUsed(String token) {
        logger.debug("Marcando token como usado");

        try {
            refreshCommandTokenRepository.markTokenAsUsed(token);
            logger.debug("Token marcado como usado exitosamente");
        } catch (Exception e) {
            logger.error("Error al marcar token como usado", e);
            throw new RuntimeException("Error al marcar token como usado", e);
        }
    }

    /**
     * Revoca un refresh token específico
     */
    public void revokeRefreshToken(String token) {
        logger.debug("Revocando refresh token");

        try {
            refreshCommandTokenRepository.revokeToken(token);
            logger.debug("Refresh token revocado exitosamente");
        } catch (Exception e) {
            logger.error("Error al revocar refresh token", e);
            throw new RuntimeException("Error al revocar refresh token", e);
        }
    }

    /**
     * Revoca todos los refresh tokens de un usuario
     */
    public void revokeAllUserTokens(Long userId) {
        logger.debug("Revocando todos los tokens del usuario: {}", userId);

        try {
            refreshCommandTokenRepository.revokeAllUserTokens(userId);
            logger.debug("Todos los tokens del usuario revocados exitosamente");
        } catch (Exception e) {
            logger.error("Error al revocar todos los tokens del usuario: {}", userId, e);
            throw new RuntimeException("Error al revocar tokens del usuario", e);
        }
    }

    /**
     * Obtiene tokens válidos de un usuario
     */
    @Transactional(readOnly = true)
    public List<RefreshToken> getValidUserTokens(Long userId) {
        try {
            return refreshTokenRepository.findValidTokensByUserId(userId, LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Error al obtener tokens válidos del usuario: {}", userId, e);
            return List.of();
        }
    }

    /**
     * Verifica si un token específico es válido
     */
    @Transactional(readOnly = true)
    public boolean isTokenValid(String token) {
        try {
            return refreshTokenRepository.existsValidToken(token, LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Error al verificar validez del token", e);
            return false;
        }
    }

    /**
     * Limpia tokens expirados (scheduled task)
     */
    @Scheduled(fixedRate = 3600000) // Cada hora
    public void cleanupExpiredTokens() {
        logger.info("Iniciando limpieza de tokens expirados");

        try {
            LocalDateTime now = LocalDateTime.now();

            // Eliminar tokens expirados
            refreshCommandTokenRepository.deleteExpiredTokens(now);

            // Eliminar tokens usados o revocados más antiguos de 30 días
            LocalDateTime cutoffDate = now.minusDays(30);
            refreshCommandTokenRepository.deleteOldUsedOrRevokedTokens(cutoffDate);

            logger.info("Limpieza de tokens completada exitosamente");
        } catch (Exception e) {
            logger.error("Error durante la limpieza de tokens", e);
        }
    }

    /**
     * Genera un token único
     */
    private String generateUniqueToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
