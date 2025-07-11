package authentication.management.controller;

import authentication.management.dto.request.*;
import authentication.management.dto.response.ApiResponseDto;
import authentication.management.dto.response.AuthResponseDto;
import authentication.management.dto.response.JwtResponseDto;
import authentication.management.dto.response.UserResponseDto;
import authentication.management.service.IAuthService;
import authentication.management.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

/**
 * Controlador REST para autenticación
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
@Tag(name = "Autenticación", description = "Operaciones de autenticación y autorización")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final IAuthService authService;
    private final JwtService jwtService;

    public AuthController(IAuthService authService, JwtService jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }

    /**
     * Endpoint para login de usuarios
     */
    @SecurityRequirement(name = "") //  ignora seguridad
    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión",
            description = "Autentica un usuario y devuelve tokens JWT")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso"),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas"),
            @ApiResponse(responseCode = "423", description = "Cuenta bloqueada"),
            @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos")
    })
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> login(
            @Parameter(description = "Credenciales de login")
            @Valid @RequestBody LoginRequestDto loginRequest) {

        logger.info("Solicitud de login para: {}", loginRequest.getUsernameOrEmail());

        try {
            AuthResponseDto authResponse = authService.login(loginRequest);

            ApiResponseDto<AuthResponseDto> response = ApiResponseDto.success(
                    authResponse,
                    "Autenticación exitosa"
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error en login para: {}", loginRequest.getUsernameOrEmail(), e);

            ApiResponseDto<AuthResponseDto> response = ApiResponseDto.error(e.getMessage());

            // Determinar código de estado basado en el tipo de excepción
            if (e.getMessage().contains("bloqueada")) {
                return ResponseEntity.status(423).body(response);
            } else if (e.getMessage().contains("inválidas") || e.getMessage().contains("inactiva")) {
                return ResponseEntity.status(401).body(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
    }

    /**
     * Endpoint para registro de nuevos usuarios
     */
    @SecurityRequirement(name = "")
    @PostMapping("/register")
    @Operation(summary = "Registrar usuario",
            description = "Registra un nuevo usuario en el sistema")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente"),
            @ApiResponse(responseCode = "409", description = "Usuario o email ya existe"),
            @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos")
    })
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> register(
            @Parameter(description = "Datos de registro del usuario")
            @Valid @RequestBody RegisterRequestDto registerRequest) {

        logger.info("Solicitud de registro para username: {} y email: {}",
                registerRequest.getUsername(), registerRequest.getEmail());

        try {
            AuthResponseDto authResponse = authService.register(registerRequest);

            ApiResponseDto<AuthResponseDto> response = ApiResponseDto.success(
                    authResponse,
                    "Usuario registrado y autenticado exitosamente"
            );

            return ResponseEntity.status(201).body(response);

        } catch (Exception e) {
            logger.error("Error en registro para username: {}", registerRequest.getUsername(), e);

            ApiResponseDto<AuthResponseDto> response = ApiResponseDto.error(e.getMessage());

            if (e.getMessage().contains("ya está") || e.getMessage().contains("ya existe")) {
                return ResponseEntity.status(409).body(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
    }

    /**
     * Endpoint para renovar tokens JWT
     */
    @PostMapping("/refresh-token")
    @Operation(summary = "Renovar token",
            description = "Renueva un access token usando un refresh token válido")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token renovado exitosamente"),
            @ApiResponse(responseCode = "401", description = "Refresh token inválido o expirado"),
            @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos")
    })
    public ResponseEntity<ApiResponseDto<JwtResponseDto>> refreshToken(
            @Parameter(description = "Refresh token para renovación")
            @Valid @RequestBody RefreshTokenRequestDto refreshRequest) {

        logger.info("Solicitud de renovación de token");

        try {
            JwtResponseDto tokens = authService.refreshToken(refreshRequest);

            ApiResponseDto<JwtResponseDto> response = ApiResponseDto.success(
                    tokens,
                    "Token renovado exitosamente"
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error en renovación de token", e);

            ApiResponseDto<JwtResponseDto> response = ApiResponseDto.error(e.getMessage());

            if (e.getMessage().contains("inválido") || e.getMessage().contains("expirado")) {
                return ResponseEntity.status(401).body(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
    }

    /**
     * Endpoint para logout
     */
    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión",
            description = "Revoca los tokens del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logout exitoso"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<ApiResponseDto<String>> logout(
            @Parameter(description = "Refresh token (opcional)", required = false)
            @RequestParam(required = false) String refreshToken,
            HttpServletRequest request) {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String username = authentication.getName();
                logger.info("Solicitud de logout para usuario: {}", username);

                authService.logout(username, refreshToken);

                ApiResponseDto<String> response = ApiResponseDto.success(
                        "OK",
                        "Sesión cerrada exitosamente"
                );

                return ResponseEntity.ok(response);
            } else {
                ApiResponseDto<String> response = ApiResponseDto.error("Usuario no autenticado");
                return ResponseEntity.status(401).body(response);
            }

        } catch (Exception e) {
            logger.error("Error durante logout", e);

            // No fallar el logout, solo logear el error
            ApiResponseDto<String> response = ApiResponseDto.success(
                    "OK",
                    "Sesión cerrada (con errores internos)"
            );

            return ResponseEntity.ok(response);
        }
    }

    /**
     * Endpoint para validar token
     */
    @GetMapping("/validate")
    @Operation(summary = "Validar token",
            description = "Valida si un token JWT es válido y devuelve información del usuario")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token válido"),
            @ApiResponse(responseCode = "401", description = "Token inválido o expirado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> validateToken(HttpServletRequest request) {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String username = authentication.getName();

                // Extraer token del header
                String authHeader = request.getHeader("Authorization");
                String token = jwtService.extractTokenFromAuthHeader(authHeader);

                if (token != null) {
                    Optional<UserResponseDto> userOpt = authService.getUserFromToken(token);

                    if (userOpt.isPresent()) {
                        ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                                userOpt.get(),
                                "Token válido"
                        );

                        return ResponseEntity.ok(response);
                    }
                }
            }

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Token inválido");
            return ResponseEntity.status(401).body(response);

        } catch (Exception e) {
            logger.error("Error al validar token", e);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Error interno al validar token");
            return ResponseEntity.status(401).body(response);
        }
    }

    /**
     * Endpoint para obtener información del usuario autenticado
     */
    @GetMapping("/me")
    @Operation(summary = "Información del usuario",
            description = "Obtiene la información del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Información obtenida exitosamente"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<ApiResponseDto<UserResponseDto>> getCurrentUser(HttpServletRequest request) {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String authHeader = request.getHeader("Authorization");
                String token = jwtService.extractTokenFromAuthHeader(authHeader);

                if (token != null) {
                    Optional<UserResponseDto> userOpt = authService.getUserFromToken(token);

                    if (userOpt.isPresent()) {
                        ApiResponseDto<UserResponseDto> response = ApiResponseDto.success(
                                userOpt.get(),
                                "Información del usuario obtenida exitosamente"
                        );

                        return ResponseEntity.ok(response);
                    }
                }
            }

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Usuario no autenticado");
            return ResponseEntity.status(401).body(response);

        } catch (Exception e) {
            logger.error("Error al obtener información del usuario", e);

            ApiResponseDto<UserResponseDto> response = ApiResponseDto.error("Error interno");
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Health check del servicio de autenticación
     */
    @GetMapping("/health")
    @Operation(summary = "Verificar estado del servicio",
            description = "Endpoint de verificación de salud del servicio de autenticación")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Servicio funcionando correctamente")
    })
    public ResponseEntity<ApiResponseDto<String>> healthCheck() {
        logger.debug("Health check del servicio de autenticación");

        ApiResponseDto<String> response = ApiResponseDto.success(
                "OK",
                "Servicio de autenticación funcionando correctamente"
        );

        return ResponseEntity.ok(response);
    }

}