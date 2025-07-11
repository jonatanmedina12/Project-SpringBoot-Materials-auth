# 🔐 Authentication Management Backend

Microservicio de autenticación y autorización desarrollado con **Spring Boot 3.4.5**, **Spring Security** y **JWT** para el sistema de gestión de materiales. Proporciona una solución completa de autenticación con roles y permisos granulares.

## 🚀 Características Principales

### ✨ Tecnologías Utilizadas
- **Spring Boot 3.4.5**: Framework principal
- **Spring Security 6**: Autenticación y autorización
- **JWT (JSON Web Tokens)**: Autenticación stateless
- **JJWT 0.12.3**: Librería JWT moderna y segura
- **PostgreSQL**: Base de datos principal
- **Java 21**: Versión LTS más reciente
- **BCrypt**: Encriptación de contraseñas

### 🔐 Funcionalidades de Seguridad

#### 🎯 **Autenticación**
- ✅ **Login/Register**: Registro e inicio de sesión seguros
- ✅ **JWT Access Tokens**: Tokens de acceso con expiración configurable
- ✅ **Refresh Tokens**: Renovación automática de tokens
- ✅ **Password Security**: Validación robusta de contraseñas
- ✅ **Account Locking**: Bloqueo automático por intentos fallidos
- ✅ **Session Management**: Gestión de sesiones stateless

#### 👥 **Autorización**
- ✅ **Role-Based Access Control (RBAC)**: Control basado en roles
- ✅ **Permission System**: Sistema granular de permisos
- ✅ **User Roles**: ADMIN, MANAGER, USER, READONLY
- ✅ **Method Security**: Seguridad a nivel de método
- ✅ **Endpoint Protection**: Protección automática de endpoints

#### 🛡️ **Seguridad Avanzada**
- ✅ **Password Encoding**: BCrypt con salt rounds configurables
- ✅ **Token Validation**: Validación exhaustiva de tokens
- ✅ **CORS Configuration**: Configuración de Cross-Origin
- ✅ **Security Headers**: Headers de seguridad automáticos
- ✅ **Rate Limiting**: Límite de intentos de login

## 📊 **Endpoints de la API**

### 🔓 Autenticación (`/api/auth`)
```http
POST   /api/auth/login              # Iniciar sesión
POST   /api/auth/register           # Registrar usuario
POST   /api/auth/refresh-token      # Renovar token
POST   /api/auth/logout             # Cerrar sesión
GET    /api/auth/validate           # Validar token
GET    /api/auth/me                 # Información del usuario
GET    /api/auth/health             # Health check
```

### 👥 Gestión de Usuarios (`/api/users`) - Solo ADMIN
```http
GET    /api/users                   # Obtener todos los usuarios
GET    /api/users/active            # Obtener usuarios activos
GET    /api/users/{id}              # Obtener usuario por ID
GET    /api/users/search            # Buscar usuarios
PUT    /api/users/{id}/toggle-status # Activar/desactivar usuario
PUT    /api/users/{id}/unlock       # Desbloquear cuenta
GET    /api/users/statistics        # Estadísticas de usuarios
```

## 🛠️ Instalación y Configuración

### Prerrequisitos
- Java 21+
- Maven 3.8+
- PostgreSQL 12+

### 1. Configurar la base de datos
```sql
-- Crear base de datos
CREATE DATABASE auth_management;
CREATE DATABASE auth_management_dev;
CREATE DATABASE auth_management_test;

-- Crear usuario (opcional)
CREATE USER auth_admin WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_management TO auth_admin;
```

### 2. Configurar variables de entorno
```bash
# Desarrollo
export JWT_SECRET=mySecretKey123456789012345678901234567890123456789012345678901234567890
export DATABASE_URL=jdbc:postgresql://localhost:5432/auth_management
export DATABASE_USERNAME=postgres
export DATABASE_PASSWORD=your_password

# Producción (adicionales)
export JWT_SECRET_PROD=your_super_secure_production_secret_key_here
export JWT_EXPIRATION_PROD=86400
export JWT_REFRESH_EXPIRATION_PROD=2592000
```

### 3. Compilar y ejecutar
```bash
# Desarrollo
mvn spring-boot:run

# Con perfil específico
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Compilar JAR
mvn clean package
java -jar target/authentication-management-backend.jar
```

La aplicación estará disponible en `http://localhost:8081`

## 🔑 **Configuración JWT**

### Variables de Configuración
```yaml
app:
  jwt:
    secret: "tu_clave_secreta_muy_larga_y_segura"
    expiration: 86400        # 24 horas (segundos)
    refresh-expiration: 2592000  # 30 días (segundos)
  
  security:
    max-login-attempts: 5    # Intentos antes de bloqueo
```

### Estructura del Token JWT
```json
{
  "sub": "username",
  "email": "user@example.com",
  "fullName": "Usuario Completo",
  "roles": ["USER", "ADMIN"],
  "permissions": ["READ_MATERIALS", "WRITE_MATERIALS"],
  "iat": 1640995200,
  "exp": 1641081600
}
```

## 📚 Documentación de la API

### Swagger UI
- **Swagger UI**: `http://localhost:8081/swagger-ui.html`
- **OpenAPI JSON**: `http://localhost:8081/v3/api-docs`

### Ejemplos de Uso

#### Registro de Usuario
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "nuevousuario",
  "email": "usuario@ejemplo.com",
  "password": "Password123!",
  "confirmPassword": "Password123!",
  "firstName": "Nuevo",
  "lastName": "Usuario"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "usernameOrEmail": "admin",
  "password": "Admin123!",
  "rememberMe": true
}
```

#### Uso del Token
```http
GET /api/auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Respuesta Estándar
```json
{
  "data": {
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@ejemplo.com",
      "roles": ["ADMIN"],
      "permissions": ["READ_USERS", "WRITE_USERS"]
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
      "tokenType": "Bearer",
      "expiresIn": 86400,
      "expiresAt": "2024-01-16T10:30:00"
    }
  },
  "message": "Autenticación exitosa",
  "success": true,
  "timestamp": "2024-01-15T10:30:00"
}
```

## 👥 **Sistema de Roles y Permisos**

### Roles Predefinidos
- **ADMIN**: Acceso completo al sistema
- **MANAGER**: Gestión de materiales y reportes
- **USER**: Acceso básico a materiales
- **READONLY**: Solo lectura

### Permisos Disponibles
- `READ_USERS`, `WRITE_USERS`, `DELETE_USERS`
- `READ_MATERIALS`, `WRITE_MATERIALS`, `DELETE_MATERIALS`
- `READ_REPORTS`, `ADMIN_PANEL`

### Usuarios por Defecto
```
Username: admin
Password: Admin123!
Roles: ADMIN

Username: user  
Password: User123!
Roles: USER
```

## 🔒 **Configuración de Seguridad**

### Endpoints Públicos
- `/api/auth/login`
- `/api/auth/register`
- `/api/auth/refresh-token`
- `/api/auth/health`
- `/swagger-ui/**`
- `/actuator/health`

### Endpoints Protegidos
- `/api/auth/me` - Requiere autenticación
- `/api/users/**` - Requiere rol ADMIN
- `/api/roles/**` - Requiere rol ADMIN

### Configuración CORS
```java
// Orígenes permitidos
"http://localhost:4200"  // Angular development
"http://localhost:3000"  // React development
```

## 🧪 Testing

### Ejecutar Tests
```bash
# Todos los tests
mvn test

# Tests específicos
mvn test -Dtest=AuthControllerTest
mvn test -Dtest=JwtServiceTest

# Tests de integración
mvn integration-test
```

### Tests Implementados
- **Unit Tests**: Servicios, utilidades, mappers
- **Integration Tests**: Controllers con Spring Security
- **Security Tests**: Autenticación y autorización

## 📈 Monitoreo y Métricas

### Spring Boot Actuator
- `/actuator/health` - Estado de la aplicación
- `/actuator/info` - Información del servicio
- `/actuator/metrics` - Métricas de rendimiento

### Logs
```bash
# Ubicación de logs
logs/auth-management.log

# Niveles configurables por environment
DEBUG: Desarrollo
INFO: Producción
```

## 🐳 Docker

### Dockerfile
```dockerfile
FROM openjdk:21-jdk-slim
COPY target/authentication-management-backend.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/app.jar"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  auth-service:
    build: .
    ports:
      - "8081:8081"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - DATABASE_URL=jdbc:postgresql://db:5432/auth_management
    depends_on:
      - db
  
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_management
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
```

## 🔧 Integración con Material Management

### Comunicación entre Microservicios
```java
// En material-management-backend
@Component
public class AuthServiceClient {
    
    @Value("${auth.service.url:http://localhost:8081}")
    private String authServiceUrl;
    
    public boolean validateToken(String token) {
        // HTTP call to auth service validation endpoint
        return restTemplate.postForObject(
            authServiceUrl + "/api/auth/validate", 
            token, 
            Boolean.class
        );
    }
}
```

### Headers de Autenticación
```http
# En todas las requests al material service
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🚀 Despliegue

### Variables de Entorno para Producción
```bash
SPRING_PROFILES_ACTIVE=prod
DATABASE_URL=jdbc:postgresql://host:5432/auth_management_prod
DATABASE_USERNAME=prod_user
DATABASE_PASSWORD=secure_password
JWT_SECRET_PROD=your_super_secure_production_secret
SERVER_PORT=8081
```

### Build para Producción
```bash
mvn clean package -Pprod
java -jar target/authentication-management-backend.jar --spring.profiles.active=prod
```
