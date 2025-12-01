/*
=============================================================================
   BASE DE DATOS: HYPERNOVA
   PROYECTO:     Sistema de Estación Terrena CanSat
   FECHA:        Noviembre 2025
=============================================================================
*/

-- 1. REINICIALIZACIÓN DE LA BASE DE DATOS
-- --------------------------------------------------------------------------
DROP DATABASE IF EXISTS Hypernova;
CREATE DATABASE Hypernova CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE Hypernova;

/*
=============================================================================
   SECCIÓN 1: CREACIÓN DE TABLAS (DDL)
=============================================================================
*/

-- TABLA: USUARIOS
-- Integra autenticación local y OAuth
CREATE TABLE Usuarios (
    ID_Usuario      INT PRIMARY KEY AUTO_INCREMENT,
    Nombre          VARCHAR(100) NOT NULL,
    Password        VARCHAR(255) NOT NULL,
    Rol             ENUM('admin', 'invitado', 'mantenimiento') NOT NULL,
    Email           VARCHAR(200) UNIQUE,
    Oauth_Provider  VARCHAR(50) NULL,
    Oauth_Sub       VARCHAR(255) UNIQUE
);

-- TABLA: VEHÍCULO CANSAT
CREATE TABLE Vehiculo_CanSat (
    ID_Vehiculo     INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Vehiculo VARCHAR(100) NOT NULL,
    Categoria       VARCHAR(100),
    Estado          ENUM('operativo', 'requiere revision') NOT NULL DEFAULT 'operativo'
);

-- TABLA: MISIÓN
CREATE TABLE Mision (
    ID_Mision       INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Mision   VARCHAR(100) NOT NULL,
    Fecha           DATE,
    Lugar           VARCHAR(100),
    FK_ID_Vehiculo  INT,
    FK_ID_Usuario   INT,
    
    FOREIGN KEY (FK_ID_Vehiculo) REFERENCES Vehiculo_CanSat(ID_Vehiculo) 
        ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Usuario) REFERENCES Usuarios(ID_Usuario) 
        ON DELETE SET NULL ON UPDATE CASCADE
);

-- TABLA: SESIÓN (Historial de accesos)
CREATE TABLE Sesion (
    ID_Sesion           INT PRIMARY KEY AUTO_INCREMENT,
    Fecha_Hora_Inicio   DATETIME NOT NULL,
    Fecha_Hora_Fin      DATETIME,
    FK_ID_Usuario       INT,
    
    FOREIGN KEY (FK_ID_Usuario) REFERENCES Usuarios(ID_Usuario)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- TABLA: TRAMA CANSAT (Datos de telemetría)
CREATE TABLE Trama_CanSat (
    ID_Trama        INT PRIMARY KEY AUTO_INCREMENT,
    Trama           VARCHAR(500),
    Fecha_Hora      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FK_ID_Mision    INT,
    FK_ID_Usuario   INT,
    
    FOREIGN KEY (FK_ID_Mision) REFERENCES Mision(ID_Mision)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Usuario) REFERENCES Usuarios(ID_Usuario)
        ON DELETE SET NULL ON UPDATE CASCADE
);

-- TABLA: REPORTE DE MANTENIMIENTO
CREATE TABLE Reporte_Mantenimiento (
    ID_Reporte          INT PRIMARY KEY AUTO_INCREMENT,
    Comentarios         TEXT NOT NULL,
    Fecha_Hora_Reporte  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FK_ID_Vehiculo      INT NOT NULL,
    FK_ID_Usuario       INT NOT NULL,
    
    FOREIGN KEY (FK_ID_Vehiculo) REFERENCES Vehiculo_CanSat(ID_Vehiculo)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Usuario) REFERENCES Usuarios(ID_Usuario)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- TABLA: FLASK SESSIONS
-- Necesaria para el manejo de sesiones del lado del servidor en Python/Flask
CREATE TABLE flask_sessions (
    id          INT NOT NULL AUTO_INCREMENT,
    session_id  VARCHAR(255) NULL,
    data        BLOB NULL,
    expiry      DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE (session_id)
);

-- TABLA: BITÁCORA (AUDITORÍA)
CREATE TABLE Bitacora_DB (
    ID_Log              INT PRIMARY KEY AUTO_INCREMENT,
    Tabla_Afectada      VARCHAR(50),
    Accion              VARCHAR(20), -- INSERT, UPDATE, DELETE
    Detalle             TEXT,        -- Descripción del cambio
    Fecha               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Usuario_Responsable VARCHAR(100) DEFAULT 'Sistema' 
);

/*
=============================================================================
   SECCIÓN 2: TRIGGERS (LÓGICA AUTOMÁTICA)
=============================================================================
*/

DELIMITER //

-- 2.1 Trigger: Nuevo Vehículo
CREATE TRIGGER trg_vehiculo_insert AFTER INSERT ON Vehiculo_CanSat
FOR EACH ROW
BEGIN
    INSERT INTO Bitacora_DB (Tabla_Afectada, Accion, Detalle)
    VALUES ('Vehiculo', 'INSERT', CONCAT('Nuevo vehículo: ', NEW.Nombre_Vehiculo, ' (', NEW.Categoria, ')'));
END //

-- 2.2 Trigger: Cambio de Estado en Vehículo
CREATE TRIGGER trg_vehiculo_update AFTER UPDATE ON Vehiculo_CanSat
FOR EACH ROW
BEGIN
    INSERT INTO Bitacora_DB (Tabla_Afectada, Accion, Detalle)
    VALUES ('Vehiculo', 'UPDATE', CONCAT('Vehículo ', OLD.Nombre_Vehiculo, ': Estado cambió de ', OLD.Estado, ' a ', NEW.Estado));
END //

-- 2.3 Trigger: Eliminación de Vehículo
CREATE TRIGGER trg_vehiculo_delete BEFORE DELETE ON Vehiculo_CanSat
FOR EACH ROW
BEGIN
    INSERT INTO Bitacora_DB (Tabla_Afectada, Accion, Detalle)
    VALUES ('Vehiculo', 'DELETE', CONCAT('Se eliminó vehículo: ', OLD.Nombre_Vehiculo));
END //

-- 2.4 Trigger: Nueva Misión
CREATE TRIGGER trg_mision_insert AFTER INSERT ON Mision
FOR EACH ROW
BEGIN
    INSERT INTO Bitacora_DB (Tabla_Afectada, Accion, Detalle)
    VALUES ('Mision', 'INSERT', CONCAT('Nueva misión: ', NEW.Nombre_Mision, ' en ', NEW.Lugar));
END //

-- 2.5 Trigger: Modificación de Usuario
CREATE TRIGGER trg_usuario_update AFTER UPDATE ON Usuarios
FOR EACH ROW
BEGIN
    INSERT INTO Bitacora_DB (Tabla_Afectada, Accion, Detalle)
    VALUES ('Usuarios', 'UPDATE', CONCAT('Usuario ID ', OLD.ID_Usuario, ' modificado. Rol: ', NEW.Rol));
END //

DELIMITER ;

/*
=============================================================================
   SECCIÓN 3: DATOS DE EJEMPLO (SEEDING)
=============================================================================
*/

-- Usuarios
INSERT INTO Usuarios (Nombre, Password, Rol, Email) VALUES
('Marco',   'Marco.123', 'admin', 'marcogluna.ipn@gmail.com'),
('Luis',    'Mant.123',  'mantenimiento', NULL),
('Valeria', 'Val.1234',  'invitado', NULL);

-- Vehículos
INSERT INTO Vehiculo_CanSat (Nombre_Vehiculo, Categoria, Estado) VALUES
('CanSat-X', 'Exploración', 'operativo'),
('CanSat-Y', 'Meteorología', 'requiere revision');

-- Misiones
INSERT INTO Mision (Nombre_Mision, Fecha, Lugar, FK_ID_Vehiculo, FK_ID_Usuario) VALUES
('Mision Solar',     '2025-11-10', 'Desierto', 1, 1),
('Mision Climática', '2025-11-15', 'Bosque',   2, 1);

-- Tramas (Datos simulados)
INSERT INTO Trama_CanSat (Trama, FK_ID_Mision, FK_ID_Usuario) VALUES
('TEMP:22;ALT:300;', 1, 2),
('TEMP:25;ALT:320;', 2, 2);

-- Reportes
INSERT INTO Reporte_Mantenimiento (Comentarios, FK_ID_Vehiculo, FK_ID_Usuario) VALUES
('Se cambió la antena.',         1, 3),
('Se calibró el sensor térmico.', 2, 3);

/*
=============================================================================
   SECCIÓN 4: CONSULTAS DE VERIFICACIÓN
=============================================================================
*/
SELECT 'Usuarios' AS Tabla, COUNT(*) AS Total FROM Usuarios
UNION
SELECT 'Vehiculos', COUNT(*) FROM Vehiculo_CanSat
UNION
SELECT 'Misiones', COUNT(*) FROM Mision;

SELECT * FROM Bitacora_DB ORDER BY Fecha DESC;