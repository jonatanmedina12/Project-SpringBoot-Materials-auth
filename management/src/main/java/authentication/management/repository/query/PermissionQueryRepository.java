package authentication.management.repository.query;

import authentication.management.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Repositorio para la entidad Permission
 */
@Repository
public interface PermissionQueryRepository extends JpaRepository<Permission, Long> {
    /**
     * Busca un permiso por nombre
     */
    Optional<Permission> findByName(String name);

    /**
     * Verifica si existe un permiso con el nombre especificado
     */
    boolean existsByName(String name);

    /**
     * Busca permisos por nombre que contenga el texto especificado
     */
    @Query("SELECT p FROM Permission p WHERE LOWER(p.name) LIKE LOWER(CONCAT('%', :name, '%')) ORDER BY p.name ASC")
    List<Permission> findByNameContainingIgnoreCase(@Param("name") String name);

    /**
     * Busca múltiples permisos por sus nombres
     */
    @Query("SELECT p FROM Permission p WHERE p.name IN :names")
    Set<Permission> findByNameIn(@Param("names") Set<String> names);

    /**
     * Busca permisos asignados a un rol específico
     */
    @Query("SELECT p FROM Permission p JOIN p.roles r WHERE r.id = :roleId ORDER BY p.name ASC")
    List<Permission> findPermissionsByRoleId(@Param("roleId") Long roleId);

    /**
     * Busca permisos de un usuario específico (a través de sus roles)
     */
    @Query("SELECT DISTINCT p FROM Permission p JOIN p.roles r JOIN r.users u WHERE u.id = :userId ORDER BY p.name ASC")
    List<Permission> findPermissionsByUserId(@Param("userId") Long userId);

    /**
     * Obtiene todos los permisos ordenados por nombre
     */
    @Query("SELECT p FROM Permission p ORDER BY p.name ASC")
    List<Permission> findAllOrderByName();
}
