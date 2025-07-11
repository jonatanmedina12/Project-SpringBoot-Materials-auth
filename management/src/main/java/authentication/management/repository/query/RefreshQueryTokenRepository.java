package authentication.management.repository.query;

import authentication.management.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repositorio para la entidad RefreshToken
 */
@Repository
public interface RefreshQueryTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Busca un refresh token por su valor
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Busca refresh tokens válidos para un usuario
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId AND rt.used = false AND rt.revoked = false AND rt.expiresAt > :now ORDER BY rt.createdAt DESC")
    List<RefreshToken> findValidTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    /**
     * Busca todos los refresh tokens de un usuario
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId ORDER BY rt.createdAt DESC")
    List<RefreshToken> findByUserId(@Param("userId") Long userId);

    /**
     * Busca refresh tokens expirados
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.expiresAt < :now AND rt.used = false AND rt.revoked = false")
    List<RefreshToken> findExpiredTokens(@Param("now") LocalDateTime now);


    /**
     * Cuenta tokens válidos por usuario
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user.id = :userId AND rt.used = false AND rt.revoked = false AND rt.expiresAt > :now")
    Long countValidTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    /**
     * Verifica si existe un token válido específico
     */
    @Query("SELECT COUNT(rt) > 0 FROM RefreshToken rt WHERE rt.token = :token AND rt.used = false AND rt.revoked = false AND rt.expiresAt > :now")
    boolean existsValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    /**
     * Busca el último token válido de un usuario
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId AND rt.used = false AND rt.revoked = false AND rt.expiresAt > :now ORDER BY rt.createdAt DESC LIMIT 1")
    Optional<RefreshToken> findLatestValidTokenByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);
}