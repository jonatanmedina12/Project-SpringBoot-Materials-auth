package authentication.management.service.impl;

import authentication.management.dto.request.LoginRequestDto;
import authentication.management.dto.request.RefreshTokenRequestDto;
import authentication.management.dto.request.RegisterRequestDto;
import authentication.management.dto.response.AuthResponseDto;
import authentication.management.dto.response.JwtResponseDto;
import authentication.management.dto.response.UserResponseDto;
import authentication.management.entity.RefreshToken;
import authentication.management.entity.Role;
import authentication.management.entity.User;
import authentication.management.exception.AuthenticationException;
import authentication.management.exception.InvalidTokenException;
import authentication.management.exception.UserAlreadyExistsException;
import authentication.management.repository.command.UserCommandRepository;
import authentication.management.repository.query.RoleQueryRepository;
import authentication.management.repository.query.UserQueryRepository;
import authentication.management.service.IAuthService;
import authentication.management.service.IRefreshTokenService;
import authentication.management.service.IUserService;
import authentication.management.service.JwtService;
import authentication.management.util.PasswordUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

/**
 * Servicio principal de autenticación
 */
@Service
@Transactional
public class AuthServiceImpl implements IAuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Value("${app.security.max-login-attempts:5}")
    private int maxLoginAttempts;

    private final UserQueryRepository userRepository;
    private final UserCommandRepository userCommandRepository;
    private final RoleQueryRepository roleRepository;
    private final JwtService jwtService;
    private final IRefreshTokenService refreshTokenService;
    private final IUserService userService;
    private final PasswordUtil passwordUtil;


    public AuthServiceImpl(UserQueryRepository userRepository, UserCommandRepository userCommandRepository, RoleQueryRepository roleRepository,
                           JwtService jwtService, IRefreshTokenService refreshTokenService, IUserService userService,
                           PasswordUtil passwordUtil) {
        this.userRepository = userRepository;
        this.userCommandRepository = userCommandRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
        this.passwordUtil = passwordUtil;
    }

    /**
     * Autentica un usuario y genera tokens
     */
    public AuthResponseDto login(LoginRequestDto loginRequest) {
        logger.info("Intento de login para: {}", loginRequest.getUsernameOrEmail());

        try {
            // Buscar usuario por username o email
            User user = userRepository.findByUsernameOrEmail(loginRequest.getUsernameOrEmail())
                    .orElseThrow(() -> new AuthenticationException("Credenciales inválidas"));

            // Verificar si la cuenta está bloqueada
            if (user.getAccountLocked()) {
                logger.warn("Intento de login en cuenta bloqueada: {}", user.getUsername());
                throw new AuthenticationException("La cuenta está bloqueada. Contacte al administrador.");
            }

            // Verificar si la cuenta está activa
            if (!user.getActive()) {
                logger.warn("Intento de login en cuenta inactiva: {}", user.getUsername());
                throw new AuthenticationException("La cuenta está inactiva");
            }
            logger.info("Password sin codificar recibido: {}", loginRequest.getPassword());
            logger.info("Password codificado en DB: {}", user.getPassword());
            logger.info("¿Coinciden?: {}", passwordUtil.matches(loginRequest.getPassword(), user.getPassword()));
            // Verificar contraseña
            if (!passwordUtil.matches(loginRequest.getPassword(), user.getPassword())) {
                handleFailedLogin(user);
                throw new AuthenticationException("Credenciales inválidas");
            }

            // Login exitoso
            handleSuccessfulLogin(user);

            // Generar tokens
            JwtResponseDto tokens = jwtService.generateTokensForUser(user);

            // Guardar refresh token si está habilitado "Remember Me"
            if (loginRequest.isRememberMe()) {
                refreshTokenService.createRefreshToken(user, tokens.getRefreshToken());
            }

            // Preparar respuesta
            UserResponseDto userResponse = userService.convertToResponseDto(user);
            AuthResponseDto authResponse = new AuthResponseDto(userResponse, tokens);

            logger.info("Login exitoso para usuario: {}", user.getUsername());
            return authResponse;

        } catch (AuthenticationException e) {
            logger.warn("Fallo de autenticación para: {} - {}", loginRequest.getUsernameOrEmail(), e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error durante el login para: {}", loginRequest.getUsernameOrEmail(), e);
            throw new AuthenticationException("Error interno durante la autenticación");
        }
    }

    /**
     * Registra un nuevo usuario
     */
    public AuthResponseDto register(RegisterRequestDto registerRequest) {
        logger.info("Intento de registro para username: {} y email: {}",
                registerRequest.getUsername(), registerRequest.getEmail());

        try {
            // Verificar si el usuario ya existe
            if (userRepository.existsByUsername(registerRequest.getUsername())) {
                throw new UserAlreadyExistsException("El nombre de usuario ya está en uso");
            }

            if (userRepository.existsByEmail(registerRequest.getEmail())) {
                throw new UserAlreadyExistsException("El email ya está registrado");
            }

            // Validar contraseña
            String passwordValidationMessage = passwordUtil.getPasswordValidationMessage(registerRequest.getPassword());
            if (passwordValidationMessage != null) {
                throw new IllegalArgumentException(passwordValidationMessage);
            }

            // Crear nuevo usuario
            User newUser = new User();
            newUser.setUsername(registerRequest.getUsername());
            newUser.setEmail(registerRequest.getEmail());
            newUser.setPassword(passwordUtil.encodePassword(registerRequest.getPassword()));
            newUser.setFirstName(registerRequest.getFirstName());
            newUser.setLastName(registerRequest.getLastName());

            // Asignar rol por defecto
            Optional<Role> defaultRole = roleRepository.findDefaultRole();
            if (defaultRole.isPresent()) {
                newUser.setRoles(Set.of(defaultRole.get()));
            } else {
                // Si no hay rol por defecto, buscar rol USER
                Role userRole = roleRepository.findByName("USER")
                        .orElseThrow(() -> new RuntimeException("Rol USER no encontrado en el sistema"));
                newUser.setRoles(Set.of(userRole));
            }

            // Guardar usuario
            User savedUser = userCommandRepository.save(newUser);

            // Generar tokens
            JwtResponseDto tokens = jwtService.generateTokensForUser(savedUser);

            // Crear refresh token
            refreshTokenService.createRefreshToken(savedUser, tokens.getRefreshToken());

            // Preparar respuesta
            UserResponseDto userResponse = userService.convertToResponseDto(savedUser);
            AuthResponseDto authResponse = new AuthResponseDto(userResponse, tokens);

            logger.info("Usuario registrado exitosamente: {}", savedUser.getUsername());
            return authResponse;

        } catch (UserAlreadyExistsException | IllegalArgumentException e) {
            logger.warn("Error en registro: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error durante el registro para username: {}", registerRequest.getUsername(), e);
            throw new RuntimeException("Error interno durante el registro");
        }
    }

    /**
     * Renueva un access token usando un refresh token
     */
    public JwtResponseDto refreshToken(RefreshTokenRequestDto refreshRequest) {
        logger.info("Solicitud de renovación de token");

        try {
            // Validar y obtener refresh token
            RefreshToken refreshToken = refreshTokenService.validateRefreshToken(refreshRequest.getRefreshToken());

            // Obtener usuario asociado
            User user = refreshToken.getUser();

            // Verificar que el usuario siga activo
            if (!user.getActive() || user.getAccountLocked()) {
                refreshTokenService.revokeRefreshToken(refreshRequest.getRefreshToken());
                throw new AuthenticationException("Usuario inactivo o bloqueado");
            }

            // Generar nuevo access token
            JwtResponseDto newTokens = jwtService.renewAccessToken(refreshRequest.getRefreshToken(), user);

            // Marcar el refresh token como usado
            refreshTokenService.markTokenAsUsed(refreshRequest.getRefreshToken());

            logger.info("Token renovado exitosamente para usuario: {}", user.getUsername());
            return newTokens;

        } catch (InvalidTokenException | AuthenticationException e) {
            logger.warn("Error en renovación de token: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error durante la renovación de token", e);
            throw new InvalidTokenException("Error interno durante la renovación del token");
        }
    }

    /**
     * Cierra sesión revocando los tokens del usuario
     */
    public void logout(String username, String refreshToken) {
        logger.info("Logout para usuario: {}", username);

        try {
            Optional<User> userOpt = userRepository.findByUsername(username);
            if (userOpt.isPresent()) {
                User user = userOpt.get();

                // Revocar refresh token específico si se proporciona
                if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                    refreshTokenService.revokeRefreshToken(refreshToken);
                } else {
                    // Revocar todos los tokens del usuario
                    refreshTokenService.revokeAllUserTokens(user.getId());
                }

                logger.info("Logout exitoso para usuario: {}", username);
            }
        } catch (Exception e) {
            logger.error("Error durante logout para usuario: {}", username, e);
            // No lanzar excepción en logout para no afectar la experiencia del usuario
        }
    }

    /**
     * Maneja un login fallido
     */
    private void handleFailedLogin(User user) {
        user.incrementLoginAttempts();

        if (user.getLoginAttempts() >= maxLoginAttempts) {
            user.lockAccount();
            logger.warn("Cuenta bloqueada por exceso de intentos fallidos: {}", user.getUsername());
        }

        userRepository.save(user);
    }

    /**
     * Maneja un login exitoso
     */
    private void handleSuccessfulLogin(User user) {
        user.resetLoginAttempts();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);
    }

    /**
     * Valida un token JWT
     */
    @Transactional(readOnly = true)
    public boolean validateToken(String token, String username) {
        try {
            return jwtService.validateToken(token, username);
        } catch (Exception e) {
            logger.error("Error al validar token para usuario: {}", username, e);
            return false;
        }
    }

    /**
     * Obtiene información del usuario desde un token
     */
    @Transactional(readOnly = true)
    public Optional<UserResponseDto> getUserFromToken(String token) {
        try {
            String username = jwtService.getUsernameFromToken(token);
            if (username != null) {
                Optional<User> userOpt = userRepository.findByUsername(username);
                if (userOpt.isPresent()) {
                    return Optional.of(userService.convertToResponseDto(userOpt.get()));
                }
            }
        } catch (Exception e) {
            logger.error("Error al obtener usuario desde token", e);
        }

        return Optional.empty();
    }

}
