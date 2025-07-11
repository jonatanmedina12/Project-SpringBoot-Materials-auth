package authentication.management.controller;


import authentication.management.dto.request.ChangePasswordRequestDto;
import authentication.management.dto.request.UpdateProfileRequestDto;
import authentication.management.dto.response.ApiResponseDto;
import authentication.management.dto.response.UserResponseDto;
import authentication.management.service.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * Controlador REST para gestión de usuarios (solo administradores)
 */
@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "http://localhost:4200")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Usuarios", description = "Operaciones de gestión de usuarios (solo administradores)")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final IUserService userService;

    public UserController(IUserService userService) {
        this.userService = userService;
    }

    /**
     * Obtiene todos los usuarios
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Obtener todos los usuarios",
            description = "Retorna la lista completa de usuarios del sistema")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios obtenida exitosamente"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado"),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    public ResponseEntity<ApiResponseDto<List<UserResponseDto>>> getAllUsers() {
        logger.info("Solicitud para obtener todos los usuarios");

        try {
            List<UserResponseDto> users = userService.getAllUsers();

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.success(
                    users,
                    "Usuarios obtenidos exitosamente. Total: " + users.size()
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error al obtener todos los usuarios", e);

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.error(
                    "Error interno al obtener usuarios"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Obtiene usuarios activos
     */
    @GetMapping("/active")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Obtener usuarios activos",
            description = "Retorna solo los usuarios activos del sistema")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuarios activos obtenidos exitosamente"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<List<UserResponseDto>>> getActiveUsers() {
        logger.info("Solicitud para obtener usuarios activos");

        try {
            List<UserResponseDto> users = userService.getActiveUsers();

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.success(
                    users,
                    "Usuarios activos obtenidos exitosamente. Total: " + users.size()
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error al obtener usuarios activos", e);

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.error(
                    "Error interno al obtener usuarios activos"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Busca un usuario por ID
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Buscar usuario por ID",
            description = "Retorna un usuario específico basado en su ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> getUserById(
            @Parameter(description = "ID del usuario", example = "1")
            @PathVariable Long id) {

        logger.info("Solicitud para obtener usuario con ID: {}", id);

        try {
            Optional<UserResponseDto> userOpt = userService.getUserById(id);

            if (userOpt.isPresent()) {
                ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                        userOpt.get(),
                        "Usuario encontrado"
                );

                return ResponseEntity.ok(response);
            } else {
                ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(
                        "Usuario con ID " + id + " no encontrado"
                );

                return ResponseEntity.status(404).body(response);
            }

        } catch (Exception e) {
            logger.error("Error al buscar usuario con ID: {}", id, e);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(
                    "Error interno al buscar usuario"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Busca usuarios por término de búsqueda
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Buscar usuarios",
            description = "Busca usuarios por nombre, apellido, username o email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Búsqueda realizada exitosamente"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<List<UserResponseDto>>> searchUsers(
            @Parameter(description = "Término de búsqueda")
            @RequestParam String searchTerm) {

        logger.info("Solicitud de búsqueda de usuarios con término: {}", searchTerm);

        try {
            List<UserResponseDto> users = userService.searchUsers(searchTerm);

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.success(
                    users,
                    "Búsqueda completada. Se encontraron " + users.size() + " usuarios"
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error al buscar usuarios con término: {}", searchTerm, e);

            ApiResponseDto<List<UserResponseDto>> response = ApiResponseDto.error(
                    "Error interno al buscar usuarios"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Cambia el estado activo/inactivo de un usuario
     */
    @PutMapping("/{id}/toggle-status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Cambiar estado de usuario",
            description = "Activa o desactiva un usuario")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Estado cambiado exitosamente"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> toggleUserStatus(
            @Parameter(description = "ID del usuario", example = "1")
            @PathVariable Long id) {

        logger.info("Solicitud para cambiar estado de usuario ID: {}", id);

        try {
            UserResponseDto user = userService.toggleUserStatus(id);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                    user,
                    "Estado del usuario cambiado exitosamente"
            );

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            logger.warn("Usuario no encontrado para ID: {}", id);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(e.getMessage());
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            logger.error("Error al cambiar estado de usuario ID: {}", id, e);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(
                    "Error interno al cambiar estado del usuario"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Desbloquea una cuenta de usuario
     */
    @PutMapping("/{id}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Desbloquear usuario",
            description = "Desbloquea una cuenta de usuario bloqueada")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario desbloqueado exitosamente"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> unlockUser(
            @Parameter(description = "ID del usuario", example = "1")
            @PathVariable Long id) {

        logger.info("Solicitud para desbloquear usuario ID: {}", id);

        try {
            UserResponseDto user = userService.unlockUser(id);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                    user,
                    "Usuario desbloqueado exitosamente"
            );

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            logger.warn("Usuario no encontrado para ID: {}", id);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(e.getMessage());
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            logger.error("Error al desbloquear usuario ID: {}", id, e);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error(
                    "Error interno al desbloquear usuario"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Obtiene estadísticas de usuarios
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Estadísticas de usuarios",
            description = "Obtiene estadísticas generales de usuarios del sistema")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Estadísticas obtenidas exitosamente"),
            @ApiResponse(responseCode = "403", description = "Acceso denegado")
    })
    public ResponseEntity<ApiResponseDto<IUserService.UserStatistics>> getUserStatistics() {
        logger.info("Solicitud de estadísticas de usuarios");

        try {
            IUserService.UserStatistics statistics = userService.getUserStatistics();

            ApiResponseDto<IUserService.UserStatistics> response = ApiResponseDto.success(
                    statistics,
                    "Estadísticas de usuarios obtenidas exitosamente"
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error al obtener estadísticas de usuarios", e);

            ApiResponseDto<IUserService.UserStatistics> response = ApiResponseDto.error(
                    "Error interno al obtener estadísticas"
            );

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Endpoint para cambiar contraseña del usuario autenticado
     */
    @PutMapping("/change-password")
    @Operation(summary = "Cambiar contraseña",
            description = "Permite al usuario autenticado cambiar su contraseña")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Contraseña cambiada exitosamente"),
            @ApiResponse(responseCode = "400", description = "Datos inválidos o contraseña actual incorrecta"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<ApiResponseDto<String>> changePassword(
            @Parameter(description = "Datos para cambio de contraseña")
            @Valid @RequestBody ChangePasswordRequestDto changePasswordRequest) {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String username = authentication.getName();

                // Obtener usuario actual
                Optional<UserResponseDto> userOpt = userService.getUserByUsername(username);
                if (userOpt.isPresent()) {
                    userService.changePassword(userOpt.get().getId(), changePasswordRequest);

                    ApiResponseDto<String> response = ApiResponseDto.success(
                            "OK",
                            "Contraseña cambiada exitosamente"
                    );

                    return ResponseEntity.ok(response);
                }
            }

            ApiResponseDto<String> response = ApiResponseDto.error("Usuario no autenticado");
            return ResponseEntity.status(401).body(response);

        } catch (IllegalArgumentException e) {
            logger.warn("Error al cambiar contraseña: {}", e.getMessage());
            ApiResponseDto<String> response = ApiResponseDto.error(e.getMessage());
            return ResponseEntity.badRequest().body(response);

        } catch (Exception e) {
            logger.error("Error interno al cambiar contraseña", e);
            ApiResponseDto<String> response = ApiResponseDto.error("Error interno del servidor");
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Endpoint para actualizar perfil del usuario autenticado
     */
    @PutMapping("/profile")
    @Operation(summary = "Actualizar perfil",
            description = "Permite al usuario autenticado actualizar su información personal")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Perfil actualizado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Datos inválidos"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> updateProfile(
            @Parameter(description = "Datos del perfil a actualizar")
            @Valid @RequestBody UpdateProfileRequestDto updateProfileRequest) {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String username = authentication.getName();

                // Obtener usuario actual
                Optional<UserResponseDto> userOpt = userService.getUserByUsername(username);
                if (userOpt.isPresent()) {
                    UserResponseDto updatedUser = userService.updateUser(
                            userOpt.get().getId(),
                            updateProfileRequest.getFirstName(),
                            updateProfileRequest.getLastName(),
                            updateProfileRequest.getEmail()
                    );

                    ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                            updatedUser,
                            "Perfil actualizado exitosamente"
                    );

                    return ResponseEntity.ok(response);
                }
            }

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Usuario no autenticado");
            return ResponseEntity.status(401).body(response);

        } catch (Exception e) {
            logger.error("Error al actualizar perfil", e);
            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Error interno del servidor");
            return ResponseEntity.status(500).body(response);
        }
    }
}