package authentication.management.service;

import authentication.management.dto.request.ChangePasswordRequestDto;
import authentication.management.dto.response.UserResponseDto;
import authentication.management.entity.User;

import java.util.List;
import java.util.Optional;

/**
 * Interface para el servicio de gestión de usuarios
 */
public interface IUserService {

    /**
     * Obtiene todos los usuarios
     *
     * @return lista de usuarios
     */
    List<UserResponseDto> getAllUsers();

    /**
     * Obtiene usuarios activos
     *
     * @return lista de usuarios activos
     */
    List<UserResponseDto> getActiveUsers();

    /**
     * Busca un usuario por ID
     *
     * @param id ID del usuario
     * @return el usuario si existe
     */
    Optional<UserResponseDto> getUserById(Long id);

    /**
     * Busca un usuario por username
     *
     * @param username nombre de usuario
     * @return el usuario si existe
     */
    Optional<UserResponseDto> getUserByUsername(String username);

    /**
     * Busca usuarios por término de búsqueda
     *
     * @param searchTerm término de búsqueda
     * @return lista de usuarios encontrados
     */
    List<UserResponseDto> searchUsers(String searchTerm);

    /**
     * Actualiza la información de un usuario
     *
     * @param id ID del usuario
     * @param firstName nombre
     * @param lastName apellido
     * @param email correo electrónico
     * @return usuario actualizado
     */
    UserResponseDto updateUser(Long id, String firstName, String lastName, String email);

    /**
     * Cambia la contraseña de un usuario
     *
     * @param userId ID del usuario
     * @param changePasswordRequest datos de cambio de contraseña
     */
    void changePassword(Long userId, ChangePasswordRequestDto changePasswordRequest);

    /**
     * Activa o desactiva un usuario
     *
     * @param id ID del usuario
     * @return usuario actualizado
     */
    UserResponseDto toggleUserStatus(Long id);

    /**
     * Desbloquea una cuenta de usuario
     *
     * @param id ID del usuario
     * @return usuario desbloqueado
     */
    UserResponseDto unlockUser(Long id);

    /**
     * Convierte una entidad User a UserResponseDto
     *
     * @param user entidad usuario
     * @return DTO del usuario
     */
    UserResponseDto convertToResponseDto(User user);

    /**
     * Obtiene estadísticas de usuarios
     *
     * @return estadísticas de usuarios
     */
    UserStatistics getUserStatistics();

    /**
     * Clase para estadísticas de usuarios
     */
    class UserStatistics {
        private final Long totalUsers;
        private final Long activeUsers;
        private final Long adminUsers;
        private final Long regularUsers;

        public UserStatistics(Long totalUsers, Long activeUsers, Long adminUsers, Long regularUsers) {
            this.totalUsers = totalUsers;
            this.activeUsers = activeUsers;
            this.adminUsers = adminUsers;
            this.regularUsers = regularUsers;
        }

        public Long getTotalUsers() { return totalUsers; }
        public Long getActiveUsers() { return activeUsers; }
        public Long getAdminUsers() { return adminUsers; }
        public Long getRegularUsers() { return regularUsers; }
    }
}
