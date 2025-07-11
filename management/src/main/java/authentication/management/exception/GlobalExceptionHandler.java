package authentication.management.exception;

import authentication.management.dto.response.ApiResponseDto;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.management.relation.RoleNotFoundException;
import java.nio.file.AccessDeniedException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Controlador global para manejo de excepciones en el servicio de autenticación
 * Captura todas las excepciones no manejadas y devuelve respuestas estandarizadas
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ===== EXCEPCIONES DE AUTENTICACIÓN =====

    /**
     * Maneja excepciones de autenticación personalizadas
     */
    @ExceptionHandler(authentication.management.exception.AuthenticationException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleCustomAuthenticationException(
            authentication.management.exception.AuthenticationException ex, HttpServletRequest request) {

        logger.warn("Error de autenticación personalizada: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "AUTHENTICATION_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }



    /**
     * Maneja excepciones de credenciales incorrectas
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleBadCredentials(
            BadCredentialsException ex, HttpServletRequest request) {

        logger.warn("Credenciales incorrectas: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Usuario o contraseña incorrectos",
                "BAD_CREDENTIALS",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // ===== EXCEPCIONES DE USUARIOS =====

    /**
     * Maneja excepciones de usuario ya existente
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleUserAlreadyExists(
            UserAlreadyExistsException ex, HttpServletRequest request) {

        logger.warn("Usuario ya existe: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "USER_ALREADY_EXISTS",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    /**
     * Maneja excepciones de usuario no encontrado
     */
    @ExceptionHandler({UserNotFoundException.class, UsernameNotFoundException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleUserNotFound(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Usuario no encontrado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Usuario no encontrado",
                "USER_NOT_FOUND",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    // ===== EXCEPCIONES DE TOKENS JWT =====

    /**
     * Maneja excepciones de token inválido
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleInvalidToken(
            InvalidTokenException ex, HttpServletRequest request) {

        logger.warn("Token inválido: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "INVALID_TOKEN",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Maneja excepciones de token expirado
     */
    @ExceptionHandler({ExpiredTokenException.class, ExpiredJwtException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleExpiredToken(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Token expirado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "El token ha expirado",
                "EXPIRED_TOKEN",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Maneja excepciones de JWT malformado
     */
    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleMalformedJwt(
            MalformedJwtException ex, HttpServletRequest request) {

        logger.warn("JWT malformado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Token JWT malformado",
                "MALFORMED_JWT",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Maneja excepciones generales de JWT
     */
    @ExceptionHandler({JwtException.class, SecurityException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleJwtException(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Error de JWT: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Error en el token de autenticación",
                "JWT_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // ===== EXCEPCIONES DE CUENTAS =====

    /**
     * Maneja excepciones de cuenta bloqueada
     */
    @ExceptionHandler({AccountLockedException.class, LockedException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleAccountLocked(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Cuenta bloqueada: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Cuenta bloqueada por múltiples intentos fallidos. Contacte al administrador.",
                "ACCOUNT_LOCKED",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.LOCKED);
    }

    /**
     * Maneja excepciones de cuenta deshabilitada
     */
    @ExceptionHandler({AccountDisabledException.class, DisabledException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleAccountDisabled(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Cuenta deshabilitada: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "La cuenta está deshabilitada. Contacte al administrador.",
                "ACCOUNT_DISABLED",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // ===== EXCEPCIONES DE AUTORIZACIÓN =====

    /**
     * Maneja excepciones de acceso denegado
     */
    @ExceptionHandler({InsufficientPrivilegesException.class, AccessDeniedException.class})
    public ResponseEntity<ApiResponseDto<Object>> handleAccessDenied(
            RuntimeException ex, HttpServletRequest request) {

        logger.warn("Acceso denegado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "No tiene permisos suficientes para realizar esta operación",
                "ACCESS_DENIED",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // ===== EXCEPCIONES DE ROLES Y PERMISOS =====

    /**
     * Maneja excepciones de rol no encontrado
     */
    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleRoleNotFound(
            RoleNotFoundException ex, HttpServletRequest request) {

        logger.error("Rol no encontrado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "ROLE_NOT_FOUND",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    /**
     * Maneja excepciones de permiso no encontrado
     */
    @ExceptionHandler(PermissionNotFoundException.class)
    public ResponseEntity<ApiResponseDto<Object>> handlePermissionNotFound(
            PermissionNotFoundException ex, HttpServletRequest request) {

        logger.error("Permiso no encontrado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "PERMISSION_NOT_FOUND",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    // ===== EXCEPCIONES DE VALIDACIÓN =====

    /**
     * Maneja errores de validación de Bean Validation (@Valid)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        logger.warn("Errores de validación en campos - URI: {}", request.getRequestURI());

        Map<String, String> fieldErrors = new HashMap<>();
        BindingResult bindingResult = ex.getBindingResult();

        for (FieldError fieldError : bindingResult.getFieldErrors()) {
            fieldErrors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        Map<String, Object> errorData = new HashMap<>();
        errorData.put("message", "Errores de validación en los campos");
        errorData.put("fieldErrors", fieldErrors);
        errorData.put("errorCode", "VALIDATION_ERROR");
        errorData.put("path", request.getRequestURI());
        errorData.put("timestamp", LocalDateTime.now());

        ApiResponseDto<Object> response = new ApiResponseDto<>(
                errorData,
                "Datos inválidos en la solicitud",
                false
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja violaciones de constraint de validación
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleConstraintViolation(
            ConstraintViolationException ex, HttpServletRequest request) {

        logger.warn("Violaciones de constraint - URI: {}", request.getRequestURI());

        Map<String, String> errors = new HashMap<>();
        Set<ConstraintViolation<?>> violations = ex.getConstraintViolations();

        for (ConstraintViolation<?> violation : violations) {
            String fieldName = violation.getPropertyPath().toString();
            String message = violation.getMessage();
            errors.put(fieldName, message);
        }

        Map<String, Object> errorData = new HashMap<>();
        errorData.put("message", "Violaciones de restricciones de validación");
        errorData.put("constraintErrors", errors);
        errorData.put("errorCode", "CONSTRAINT_VIOLATION");
        errorData.put("path", request.getRequestURI());
        errorData.put("timestamp", LocalDateTime.now());

        ApiResponseDto<Object> response = new ApiResponseDto<>(
                errorData,
                "Datos no válidos según las restricciones",
                false
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja excepciones de contraseña inválida
     */
    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleInvalidPassword(
            InvalidPasswordException ex, HttpServletRequest request) {

        logger.warn("Contraseña inválida: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "INVALID_PASSWORD",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ===== EXCEPCIONES DE ARGUMENTOS =====

    /**
     * Maneja argumentos ilegales
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {

        logger.warn("Argumento ilegal: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                ex.getMessage(),
                "ILLEGAL_ARGUMENT",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja excepciones de tipo de argumento incorrecto
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {

        logger.warn("Tipo de argumento incorrecto: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        String message = String.format("El parámetro '%s' debe ser de tipo %s",
                ex.getName(),
                ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "desconocido");

        ApiResponseDto<Object> response = createErrorResponse(
                message,
                "TYPE_MISMATCH",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja parámetros requeridos faltantes
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleMissingParameter(
            MissingServletRequestParameterException ex, HttpServletRequest request) {

        logger.warn("Parámetro requerido faltante: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        String message = String.format("El parámetro requerido '%s' no está presente", ex.getParameterName());

        ApiResponseDto<Object> response = createErrorResponse(
                message,
                "MISSING_PARAMETER",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ===== EXCEPCIONES DE HTTP =====

    /**
     * Maneja métodos HTTP no soportados
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {

        logger.warn("Método HTTP no soportado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        String message = String.format("El método %s no está soportado para esta URL. Métodos soportados: %s",
                ex.getMethod(),
                String.join(", ", ex.getSupportedMethods()));

        ApiResponseDto<Object> response = createErrorResponse(
                message,
                "METHOD_NOT_SUPPORTED",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.METHOD_NOT_ALLOWED);
    }

    /**
     * Maneja tipos de media no soportados
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex, HttpServletRequest request) {

        logger.warn("Tipo de media no soportado: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Tipo de contenido no soportado. Use application/json",
                "MEDIA_TYPE_NOT_SUPPORTED",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    /**
     * Maneja mensaje HTTP no legible
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex, HttpServletRequest request) {

        logger.warn("Mensaje HTTP no legible: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        String message = "JSON malformado o no válido";

        // Detectar tipo específico de error JSON
        if (ex.getCause() instanceof InvalidFormatException) {
            InvalidFormatException ife = (InvalidFormatException) ex.getCause();
            message = String.format("Valor inválido para el campo '%s': %s",
                    ife.getPath().get(0).getFieldName(),
                    ife.getValue());
        } else if (ex.getCause() instanceof JsonMappingException) {
            message = "Error en el mapeo del JSON. Verifique la estructura de los datos";
        }

        ApiResponseDto<Object> response = createErrorResponse(
                message,
                "JSON_PARSE_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja cuando no se encuentra un handler para la URL
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleNoHandlerFound(
            NoHandlerFoundException ex, HttpServletRequest request) {

        logger.warn("Endpoint no encontrado: {} {} - URI: {}", ex.getHttpMethod(), ex.getRequestURL(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                String.format("Endpoint no encontrado: %s %s", ex.getHttpMethod(), ex.getRequestURL()),
                "ENDPOINT_NOT_FOUND",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    // ===== EXCEPCIONES DE BASE DE DATOS =====

    /**
     * Maneja violaciones de restricciones de integridad
     */
    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleDataIntegrityViolation(
            org.springframework.dao.DataIntegrityViolationException ex, HttpServletRequest request) {

        logger.error("Violación de integridad de datos: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        String message = "Error de integridad de datos. ";
        String errorCode = "DATA_INTEGRITY_VIOLATION";

        if (ex.getMessage() != null) {
            String exceptionMessage = ex.getMessage().toLowerCase();
            if (exceptionMessage.contains("unique") || exceptionMessage.contains("duplicate")) {
                message += "Ya existe un registro con estos datos únicos.";
                errorCode = "DUPLICATE_ENTRY";
            } else if (exceptionMessage.contains("foreign key") || exceptionMessage.contains("constraint")) {
                message += "No se puede completar la operación debido a dependencias de datos.";
                errorCode = "FOREIGN_KEY_VIOLATION";
            } else {
                message += "Verifique que los datos cumplan con las restricciones del sistema.";
            }
        }

        ApiResponseDto<Object> response = createErrorResponse(
                message,
                errorCode,
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    /**
     * Maneja excepciones de acceso a datos
     */
    @ExceptionHandler(org.springframework.dao.DataAccessException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleDataAccessException(
            org.springframework.dao.DataAccessException ex, HttpServletRequest request) {

        logger.error("Error de acceso a datos: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Error al acceder a la base de datos. Intente nuevamente más tarde.",
                "DATABASE_ACCESS_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ===== EXCEPCIONES GENERALES =====

    /**
     * Maneja excepciones de estado ilegal
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleIllegalState(
            IllegalStateException ex, HttpServletRequest request) {

        logger.error("Estado ilegal: {} - URI: {}", ex.getMessage(), request.getRequestURI());

        ApiResponseDto<Object> response = createErrorResponse(
                "Error interno: Estado inválido del sistema",
                "ILLEGAL_STATE",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Maneja excepciones genéricas de runtime
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleRuntimeException(
            RuntimeException ex, HttpServletRequest request) {

        logger.error("Error de runtime: {} - URI: {}", ex.getMessage(), request.getRequestURI(), ex);

        ApiResponseDto<Object> response = createErrorResponse(
                "Ha ocurrido un error interno. Intente nuevamente más tarde.",
                "RUNTIME_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Maneja todas las demás excepciones no capturadas
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto<Object>> handleGenericException(
            Exception ex, HttpServletRequest request) {

        logger.error("Error no manejado: {} - URI: {}", ex.getMessage(), request.getRequestURI(), ex);

        ApiResponseDto<Object> response = createErrorResponse(
                "Ha ocurrido un error inesperado. Contacte al administrador del sistema.",
                "UNEXPECTED_ERROR",
                request.getRequestURI()
        );

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ===== MÉTODOS HELPER =====

    /**
     * Crea una respuesta de error estandarizada
     */
    private ApiResponseDto<Object> createErrorResponse(String message, String errorCode, String path) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("errorCode", errorCode);
        errorDetails.put("path", path);
        errorDetails.put("timestamp", LocalDateTime.now());

        ApiResponseDto<Object> response = ApiResponseDto.error(message);
        response.setData(errorDetails);

        return response;
    }

    /**
     * Crea una respuesta de error con detalles adicionales
     */
    private ApiResponseDto<Object> createDetailedErrorResponse(String message, String errorCode,
                                                               String path, Map<String, Object> additionalDetails) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("errorCode", errorCode);
        errorDetails.put("path", path);
        errorDetails.put("timestamp", LocalDateTime.now());

        if (additionalDetails != null) {
            errorDetails.putAll(additionalDetails);
        }

        ApiResponseDto<Object> response = ApiResponseDto.error(message);
        response.setData(errorDetails);

        return response;
    }
}