
-- Insertar permisos
INSERT INTO permissions (name, description) VALUES
('READ_USERS', 'Leer información de usuarios'),
('WRITE_USERS', 'Crear y editar usuarios'),
('DELETE_USERS', 'Eliminar usuarios'),
('READ_MATERIALS', 'Leer información de materiales'),
('WRITE_MATERIALS', 'Crear y editar materiales'),
('DELETE_MATERIALS', 'Eliminar materiales'),
('READ_REPORTS', 'Acceso a reportes'),
('ADMIN_PANEL', 'Acceso al panel de administración')
ON CONFLICT (name) DO NOTHING;

-- Insertar roles
INSERT INTO roles (name, description, active, created_at) VALUES
('ADMIN', 'Administrador del sistema con acceso completo', true, NOW()),
('USER', 'Usuario estándar con permisos básicos', true, NOW()),
('MANAGER', 'Gestor con permisos intermedios', true, NOW()),
('READONLY', 'Usuario de solo lectura', true, NOW())
ON CONFLICT (name) DO NOTHING;

-- Asignar permisos a roles
-- Rol ADMIN (todos los permisos)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'ADMIN'
ON CONFLICT DO NOTHING;

-- Rol MANAGER (permisos de lectura y escritura, sin eliminación de usuarios)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'MANAGER'
AND p.name IN ('READ_USERS', 'READ_MATERIALS', 'WRITE_MATERIALS', 'READ_REPORTS')
ON CONFLICT DO NOTHING;

-- Rol USER (permisos básicos)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'USER'
AND p.name IN ('READ_MATERIALS', 'WRITE_MATERIALS')
ON CONFLICT DO NOTHING;

-- Rol READONLY (solo lectura)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'READONLY'
AND p.name IN ('READ_USERS', 'READ_MATERIALS', 'READ_REPORTS')
ON CONFLICT DO NOTHING;

-- Insertar usuario administrador por defecto
-- Contraseña: Admin123!
INSERT INTO users (username, email, password, first_name, last_name, active, email_verified, account_locked, login_attempts, created_at, password_changed_at) VALUES
('admin', 'admin@materialmanagement.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQjqd8BEHXOOhd9OVVnVnpj4G', 'Admin', 'Sistema', true, true, false, 0, NOW(), NOW())
ON CONFLICT (username) DO NOTHING;

-- Insertar usuario estándar por defecto
-- Contraseña: User123!
INSERT INTO users (username, email, password, first_name, last_name, active, email_verified, account_locked, login_attempts, created_at, password_changed_at) VALUES
('user', 'user@materialmanagement.com', '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', 'Usuario', 'Estándar', true, true, false, 0, NOW(), NOW())
ON CONFLICT (username) DO NOTHING;

-- Asignar rol ADMIN al usuario admin
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ADMIN'
ON CONFLICT DO NOTHING;

-- Asignar rol USER al usuario user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'user' AND r.name = 'USER'
ON CONFLICT DO NOTHING;