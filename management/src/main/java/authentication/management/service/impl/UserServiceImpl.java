package authentication.management.service.impl;


import authentication.management.dto.request.ChangePasswordRequestDto;
import authentication.management.dto.response.UserResponseDto;
import authentication.management.entity.Permission;
import authentication.management.entity.Role;
import authentication.management.entity.User;
import authentication.management.exception.UserAlreadyExistsException;
import authentication.management.repository.query.UserQueryRepository;
import authentication.management.service.IUserService;
import authentication.management.util.PasswordUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Servicio para gestión de usuarios
 */
@Service
@Transactional
public class UserServiceImpl implements IUserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserQueryRepository userRepository;
    private final PasswordUtil passwordUtil;

    public UserServiceImpl(UserQueryRepository userRepository, PasswordUtil passwordUtil) {
        this.userRepository = userRepository;
        this.passwordUtil = passwordUtil;
    }

    /**
     * Obtiene todos los usuarios
     */
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        logger.info("Obteniendo todos los usuarios");

        try {
            List<User> users = userRepository.findAll();
            return users.stream()
                    .map(this::convertToResponseDto)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error al obtener todos los usuarios", e);
            throw new RuntimeException("Error al obtener usuarios", e);
        }
    }

    /**
     * Obtiene usuarios activos
     */
    @Transactional(readOnly = true)
    public List<UserResponseDto> getActiveUsers() {
        logger.info("Obteniendo usuarios activos");

        try {
            List<User> users = userRepository.findActiveUsers();
            return users.stream()
                    .map(this::convertToResponseDto)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error al obtener usuarios activos", e);
            throw new RuntimeException("Error al obtener usuarios activos", e);
        }
    }

    /**
     * Busca un usuario por ID
     */
    @Transactional(readOnly = true)
    public Optional<UserResponseDto> getUserById(Long id) {
        logger.debug("Buscando usuario por ID: {}", id);

        try {
            Optional<User> userOpt = userRepository.findById(id);
            return userOpt.map(this::convertToResponseDto);
        } catch (Exception e) {
            logger.error("Error al buscar usuario por ID: {}", id, e);
            return Optional.empty();
        }
    }

    /**
     * Busca un usuario por username
     */
    @Transactional(readOnly = true)
    public Optional<UserResponseDto> getUserByUsername(String username) {
        logger.debug("Buscando usuario por username: {}", username);

        try {
            Optional<User> userOpt = userRepository.findByUsername(username);
            return userOpt.map(this::convertToResponseDto);
        } catch (Exception e) {
            logger.error("Error al buscar usuario por username: {}", username, e);
            return Optional.empty();
        }
    }

    /**
     * Busca usuarios por término de búsqueda
     */
    @Transactional(readOnly = true)
    public List<UserResponseDto> searchUsers(String searchTerm) {
        logger.info("Buscando usuarios con término: {}", searchTerm);

        try {
            List<User> users = userRepository.searchUsers(searchTerm);
            return users.stream()
                    .map(this::convertToResponseDto)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error al buscar usuarios con término: {}", searchTerm, e);
            throw new RuntimeException("Error al buscar usuarios", e);
        }
    }

    /**
     * Actualiza la información de un usuario
     */
    public UserResponseDto updateUser(Long id, String firstName, String lastName, String email) {
        logger.info("Actualizando usuario con ID: {}", id);

        try {
            User user = userRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            // Verificar si el email ya existe para otro usuario
            if (!user.getEmail().equals(email) && userRepository.existsByEmail(email)) {
                throw new UserAlreadyExistsException("El email ya está en uso por otro usuario");
            }

            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEmail(email);

            User updatedUser = userRepository.save(user);
            logger.info("Usuario actualizado exitosamente: {}", updatedUser.getUsername());

            return convertToResponseDto(updatedUser);

        } catch (UserAlreadyExistsException | IllegalArgumentException e) {
            logger.warn("Error al actualizar usuario: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error al actualizar usuario con ID: {}", id, e);
            throw new RuntimeException("Error al actualizar usuario", e);
        }
    }

    /**
     * Cambia la contraseña de un usuario
     */
    public void changePassword(Long userId, ChangePasswordRequestDto changePasswordRequest) {
        logger.info("Cambiando contraseña para usuario ID: {}", userId);

        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            // Verificar contraseña actual
            if (!passwordUtil.matches(changePasswordRequest.getCurrentPassword(), user.getPassword())) {
                throw new IllegalArgumentException("La contraseña actual es incorrecta");
            }

            // Verificar que las nuevas contraseñas coincidan
            if (!changePasswordRequest.isPasswordsMatch()) {
                throw new IllegalArgumentException("Las nuevas contraseñas no coinciden");
            }

            // Validar nueva contraseña
            String validationMessage = passwordUtil.getPasswordValidationMessage(changePasswordRequest.getNewPassword());
            if (validationMessage != null) {
                throw new IllegalArgumentException(validationMessage);
            }

            // Cambiar contraseña
            user.setPassword(passwordUtil.encodePassword(changePasswordRequest.getNewPassword()));
            userRepository.save(user);

            logger.info("Contraseña cambiada exitosamente para usuario: {}", user.getUsername());

        } catch (IllegalArgumentException e) {
            logger.warn("Error al cambiar contraseña: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error al cambiar contraseña para usuario ID: {}", userId, e);
            throw new RuntimeException("Error al cambiar contraseña", e);
        }
    }

    /**
     * Activa o desactiva un usuario
     */
    public UserResponseDto toggleUserStatus(Long id) {
        logger.info("Cambiando estado de usuario ID: {}", id);

        try {
            User user = userRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            user.setActive(!user.getActive());
            User updatedUser = userRepository.save(user);

            logger.info("Estado de usuario cambiado. Usuario: {}, Activo: {}",
                    updatedUser.getUsername(), updatedUser.getActive());

            return convertToResponseDto(updatedUser);

        } catch (IllegalArgumentException e) {
            logger.warn("Error al cambiar estado de usuario: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error al cambiar estado de usuario ID: {}", id, e);
            throw new RuntimeException("Error al cambiar estado de usuario", e);
        }
    }

    /**
     * Desbloquea una cuenta de usuario
     */
    public UserResponseDto unlockUser(Long id) {
        logger.info("Desbloqueando usuario ID: {}", id);

        try {
            User user = userRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            user.unlockAccount();
            User updatedUser = userRepository.save(user);

            logger.info("Usuario desbloqueado exitosamente: {}", updatedUser.getUsername());

            return convertToResponseDto(updatedUser);

        } catch (IllegalArgumentException e) {
            logger.warn("Error al desbloquear usuario: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error al desbloquear usuario ID: {}", id, e);
            throw new RuntimeException("Error al desbloquear usuario", e);
        }
    }

    /**
     * Convierte una entidad User a UserResponseDto
     */
    public UserResponseDto convertToResponseDto(User user) {
        UserResponseDto dto = new UserResponseDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setFullName(user.getFullName());
        dto.setActive(user.getActive());
        dto.setEmailVerified(user.getEmailVerified());
        dto.setAccountLocked(user.getAccountLocked());
        dto.setLastLogin(user.getLastLogin());
        dto.setCreatedAt(user.getCreatedAt());

        // Extraer nombres de roles
        Set<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        dto.setRoles(roleNames);

        // Extraer nombres de permisos
        Set<String> permissionNames = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toSet());
        dto.setPermissions(permissionNames);

        return dto;
    }

    /**
     * Obtiene estadísticas de usuarios
     */
    @Transactional(readOnly = true)
    public UserStatistics getUserStatistics() {
        logger.info("Obteniendo estadísticas de usuarios");

        try {
            Long totalUsers = userRepository.count();
            Long activeUsers = userRepository.countActiveUsers();
            Long adminUsers = userRepository.countUsersByRole("ADMIN");
            Long regularUsers = userRepository.countUsersByRole("USER");

            return new UserStatistics(totalUsers, activeUsers, adminUsers, regularUsers);

        } catch (Exception e) {
            logger.error("Error al obtener estadísticas de usuarios", e);
            throw new RuntimeException("Error al obtener estadísticas", e);
        }
    }


}