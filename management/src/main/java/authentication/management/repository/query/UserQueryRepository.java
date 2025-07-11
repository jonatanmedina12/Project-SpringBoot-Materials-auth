package authentication.management.repository.query;

import authentication.management.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repositorio para la entidad User
 */
@Repository
public interface  UserQueryRepository extends JpaRepository<User, Long> {
    /**
     * Busca un usuario por username
     */
    Optional<User> findByUsername(String username);

    /**
     * Busca un usuario por email
     */
    Optional<User> findByEmail(String email);

    /**
     * Busca un usuario por username o email
     */
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);

    /**
     * Verifica si existe un usuario con el username especificado
     */
    boolean existsByUsername(String username);

    /**
     * Verifica si existe un usuario con el email especificado
     */
    boolean existsByEmail(String email);

    /**
     * Verifica si existe un usuario con username o email (excluyendo un ID específico)
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE (u.username = :username OR u.email = :email) AND (:id IS NULL OR u.id != :id)")
    boolean existsByUsernameOrEmailAndIdNot(@Param("username") String username,
                                            @Param("email") String email,
                                            @Param("id") Long id);

    /**
     * Busca usuarios activos
     */
    @Query("SELECT u FROM User u WHERE u.active = true ORDER BY u.createdAt DESC")
    List<User> findActiveUsers();

    /**
     * Busca usuarios por rol
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName ORDER BY u.username ASC")
    List<User> findUsersByRole(@Param("roleName") String roleName);

    /**
     * Busca usuarios con cuentas bloqueadas
     */
    @Query("SELECT u FROM User u WHERE u.accountLocked = true ORDER BY u.username ASC")
    List<User> findLockedUsers();

    /**
     * Busca usuarios sin verificar email
     */
    @Query("SELECT u FROM User u WHERE u.emailVerified = false AND u.active = true ORDER BY u.createdAt DESC")
    List<User> findUnverifiedUsers();

    /**
     * Busca usuarios creados en un rango de fechas
     */
    @Query("SELECT u FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate ORDER BY u.createdAt DESC")
    List<User> findUsersByCreationDateBetween(@Param("startDate") LocalDateTime startDate,
                                              @Param("endDate") LocalDateTime endDate);



    /**
     * Busca usuarios por nombre o apellido (búsqueda parcial)
     */
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
            "ORDER BY u.username ASC")
    List<User> searchUsers(@Param("searchTerm") String searchTerm);

    /**
     * Cuenta usuarios activos
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.active = true")
    Long countActiveUsers();

    /**
     * Cuenta usuarios por rol
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Long countUsersByRole(@Param("roleName") String roleName);

}
