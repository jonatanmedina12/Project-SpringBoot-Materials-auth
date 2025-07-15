# Etapa de construcción
FROM maven:3.9.6-eclipse-temurin-21 AS build

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos de configuración Maven
COPY pom.xml .
COPY src ./src

# Construir aplicación (saltando tests para acelerar build)
RUN mvn clean package -DskipTests

# Etapa de producción
FROM eclipse-temurin:21-jre-alpine AS runtime

# Instalar curl para health checks
RUN apk add --no-cache curl

# Crear usuario no privilegiado para seguridad
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# Establecer directorio de trabajo
WORKDIR /app

# Copiar JAR desde etapa de build
COPY --from=build /app/target/authentication-management.jar app.jar

# Cambiar propietario de archivos
RUN chown -R appuser:appgroup /app

# Cambiar a usuario no privilegiado
USER appuser

# Exponer puerto (Railway asigna PORT automáticamente)
EXPOSE $PORT

# Health check para monitoreo
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/actuator/health || exit 1

# Comando de inicio optimizado para contenedores
ENTRYPOINT ["java", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Dspring.profiles.active=prod", \
    "-Dserver.port=${PORT:-8080}", \
    "-jar", \
    "app.jar"]