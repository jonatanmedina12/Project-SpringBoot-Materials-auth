package authentication.management.repository.query;

import authentication.management.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Repositorio para la entidad Role
 */
@Repository
public interface RoleQueryRepository extends JpaRepository<Role, Long> {

    /**
     * Busca un rol por nombre
     */
    Optional<Role> findByName(String name);

    /**
     * Verifica si existe un rol con el nombre especificado
     */
    boolean existsByName(String name);

    /**
     * Busca roles activos
     */
    @Query("SELECT r FROM Role r WHERE r.active = true ORDER BY r.name ASC")
    List<Role> findActiveRoles();

    /**
     * Busca roles por nombre que contenga el texto especificado
     */
    @Query("SELECT r FROM Role r WHERE LOWER(r.name) LIKE LOWER(CONCAT('%', :name, '%')) ORDER BY r.name ASC")
    List<Role> findByNameContainingIgnoreCase(@Param("name") String name);

    /**
     * Busca múltiples roles por sus nombres
     */
    @Query("SELECT r FROM Role r WHERE r.name IN :names")
    Set<Role> findByNameIn(@Param("names") Set<String> names);

    /**
     * Busca roles que tengan un permiso específico
     */
    @Query("SELECT r FROM Role r JOIN r.permissions p WHERE p.name = :permissionName ORDER BY r.name ASC")
    List<Role> findRolesByPermission(@Param("permissionName") String permissionName);

    /**
     * Busca roles por usuario
     */
    @Query("SELECT r FROM Role r JOIN r.users u WHERE u.id = :userId ORDER BY r.name ASC")
    List<Role> findRolesByUserId(@Param("userId") Long userId);

    /**
     * Cuenta roles activos
     */
    @Query("SELECT COUNT(r) FROM Role r WHERE r.active = true")
    Long countActiveRoles();

    /**
     * Obtiene roles por defecto para nuevos usuarios
     */
    @Query("SELECT r FROM Role r WHERE r.name = 'USER' AND r.active = true")
    Optional<Role> findDefaultRole();
}
