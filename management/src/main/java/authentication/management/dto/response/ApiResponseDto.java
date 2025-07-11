package authentication.management.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;

/**
 * DTO genérico para respuestas de la API de autenticación
 */
public class ApiResponseDto<T> {

    private T data;
    private String message;
    private boolean success;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;

    public ApiResponseDto() {
        this.timestamp = LocalDateTime.now();
    }

    public ApiResponseDto(T data, String message, boolean success) {
        this();
        this.data = data;
        this.message = message;
        this.success = success;
    }

    // Métodos estáticos de conveniencia
    public static <T> ApiResponseDto<T> success(T data, String message) {
        return new ApiResponseDto<>(data, message, true);
    }

    public static <T> ApiResponseDto<T> success(T data) {
        return success(data, "Operación exitosa");
    }

    public static <T> ApiResponseDto<T> error(String message) {
        return new ApiResponseDto<>(null, message, false);
    }

    // Getters y Setters
    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}