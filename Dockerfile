# Etapa de construcción
FROM maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app

COPY management/pom.xml .
COPY management/src ./src

RUN mvn clean package -DskipTests

# Etapa de producción
FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache curl

RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

COPY --from=build /app/target/authentication-management.jar app.jar

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE $PORT

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/actuator/health || exit 1

ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Dspring.profiles.active=prod", \
    "-Dserver.port=${PORT:-8080}", \
    "-jar", \
    "app.jar"]