package authentication.management.repository.command;

import authentication.management.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

/**
 * Repositorio para la entidad RefreshToken
 */
@Repository
public interface RefreshCommandTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Marca un token como usado
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.used = true WHERE rt.token = :token")
    void markTokenAsUsed(@Param("token") String token);

    /**
     * Revoca un token específico
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.token = :token")
    void revokeToken(@Param("token") String token);

    /**
     * Revoca todos los tokens de un usuario
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user.id = :userId AND rt.revoked = false")
    void revokeAllUserTokens(@Param("userId") Long userId);

    /**
     * Elimina tokens expirados
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Elimina tokens usados o revocados antiguos
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE (rt.used = true OR rt.revoked = true) AND rt.createdAt < :cutoffDate")
    void deleteOldUsedOrRevokedTokens(@Param("cutoffDate") LocalDateTime cutoffDate);
}
