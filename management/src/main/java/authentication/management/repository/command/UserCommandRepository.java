package authentication.management.repository.command;

import authentication.management.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

/**
 * Repositorio para la entidad User
 */
@Repository
public interface UserCommandRepository extends JpaRepository<User, Long> {
    /**
     * Actualiza el último login de un usuario
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") Long userId, @Param("lastLogin") LocalDateTime lastLogin);

    /**
     * Incrementa los intentos de login fallidos
     */
    @Modifying
    @Query("UPDATE User u SET u.loginAttempts = u.loginAttempts + 1 WHERE u.id = :userId")
    void incrementLoginAttempts(@Param("userId") Long userId);

    /**
     * Resetea los intentos de login fallidos
     */
    @Modifying
    @Query("UPDATE User u SET u.loginAttempts = 0 WHERE u.id = :userId")
    void resetLoginAttempts(@Param("userId") Long userId);

    /**
     * Bloquea una cuenta de usuario
     */
    @Modifying
    @Query("UPDATE User u SET u.accountLocked = true WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") Long userId);

    /**
     * Desbloquea una cuenta de usuario
     */
    @Modifying
    @Query("UPDATE User u SET u.accountLocked = false, u.loginAttempts = 0 WHERE u.id = :userId")
    void unlockUserAccount(@Param("userId") Long userId);
}
