package authentication.management.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Utilidad para manejo de tokens JWT
 */
@Component
public class JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration:86400}")
    private Long jwtExpirationInSeconds;

    @Value("${app.jwt.refresh-expiration:2592000}")
    private Long refreshExpirationInSeconds;

    /**
     * Obtiene la clave secreta para firmar tokens
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * Genera un token JWT para un usuario
     */
    public String generateToken(String username, Map<String, Object> extraClaims) {
        return createToken(extraClaims, username, jwtExpirationInSeconds);
    }

    /**
     * Genera un token JWT básico para un usuario
     */
    public String generateToken(String username) {
        return generateToken(username, new HashMap<>());
    }

    /**
     * Genera un refresh token
     */
    public String generateRefreshToken(String username) {
        return createToken(new HashMap<>(), username, refreshExpirationInSeconds);
    }


    /**
     * Crea un token JWT con claims personalizados
     */
    private String createToken(Map<String, Object> claims, String subject, Long expirationSeconds) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationSeconds * 1000);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extrae el username del token
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración del token
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extrae un claim específico del token
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los claims del token
     */

    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("Error al parsear token JWT: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Verifica si el token ha expirado
     */
    public Boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (JwtException e) {
            logger.warn("Token JWT inválido o expirado: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Valida un token JWT
     */
    public Boolean validateToken(String token, String username) {
        try {
            final String tokenUsername = getUsernameFromToken(token);
            return (username.equals(tokenUsername) && !isTokenExpired(token));
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("Error al validar token JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Valida un token JWT sin verificar username
     */
    public Boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("Error al validar token JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene la fecha de expiración como LocalDateTime
     */
    public LocalDateTime getExpirationAsLocalDateTime(String token) {
        Date expirationDate = getExpirationDateFromToken(token);
        return expirationDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    }

    /**
     * Obtiene el tiempo restante de expiración en segundos
     */
    public Long getExpirationTimeInSeconds(String token) {
        Date expirationDate = getExpirationDateFromToken(token);
        Date now = new Date();
        return (expirationDate.getTime() - now.getTime()) / 1000;
    }

    /**
     * Extrae el token del header Authorization
     */
    public String extractTokenFromAuthHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Genera claims adicionales para el token
     */
    public Map<String, Object> generateExtraClaims(String email, String fullName, String[] roles, String[] permissions) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("fullName", fullName);
        claims.put("roles", roles);
        claims.put("permissions", permissions);
        return claims;
    }

    // Getters para configuración
    public Long getJwtExpirationInSeconds() {
        return jwtExpirationInSeconds;
    }

    public Long getRefreshExpirationInSeconds() {
        return refreshExpirationInSeconds;
    }
}