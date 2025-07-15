# Etapa de construcción
FROM maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app
COPY management/pom.xml .
COPY management/src ./src

# Compilar sin tests para producción
RUN mvn clean package -DskipTests -Dmaven.test.skip=true

# Etapa de producción
FROM eclipse-temurin:21-jre-alpine

# Instalar dependencias necesarias
RUN apk add --no-cache curl tzdata && \
    cp /usr/share/zoneinfo/America/Bogota /etc/localtime && \
    echo "America/Bogota" > /etc/timezone

# Crear usuario no privilegiado
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

# Copiar JAR compilado
COPY --from=build /app/target/authentication-management.jar app.jar
RUN chown -R appuser:appgroup /app

USER appuser

# Exponer puerto
EXPOSE $PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/actuator/health || exit 1

# Punto de entrada con configuración optimizada
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+ExitOnOutOfMemoryError", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-Dspring.profiles.active=prod", \
    "-Dserver.port=${PORT:-8080}", \
    "-jar", \
    "app.jar"]