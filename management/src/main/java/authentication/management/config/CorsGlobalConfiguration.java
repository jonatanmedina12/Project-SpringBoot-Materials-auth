package authentication.management.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

/**
 * Configuración global de CORS para la aplicación
 * Permite requests desde el frontend Angular y otros orígenes autorizados
 */
@Configuration
public class CorsGlobalConfiguration {

    /**
     * Configuración principal de CORS
     * Se inyecta en SecurityConfig para uso con Spring Security
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // ✅ Orígenes permitidos - usar patterns para mayor flexibilidad
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:4200",     // Angular desarrollo
                "http://localhost:3000",     // React desarrollo (si aplica)
                "https://tu-dominio.com"     // Producción (actualizar cuando sea necesario)
        ));

        // ✅ Métodos HTTP permitidos
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
        ));

        // ✅ Headers permitidos - incluir todos los necesarios para JWT
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-Requested-With",
                "Cache-Control",
                "Pragma"
        ));

        // ✅ Headers expuestos al cliente
        configuration.setExposedHeaders(Arrays.asList(
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Authorization",
                "Content-Type"
        ));

        // ✅ Permitir credenciales (cookies, Authorization headers)
        configuration.setAllowCredentials(true);

        // ✅ Tiempo de cache para preflight requests (1 hora)
        configuration.setMaxAge(3600L);

        // Aplicar configuración a todas las rutas
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * Configuración específica para desarrollo
     * Más permisiva para facilitar el desarrollo local
     */
    @Bean
    public CorsConfiguration developmentCorsConfiguration() {
        CorsConfiguration config = new CorsConfiguration();

        // Solo para desarrollo - permite cualquier origen
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        return config;
    }
}