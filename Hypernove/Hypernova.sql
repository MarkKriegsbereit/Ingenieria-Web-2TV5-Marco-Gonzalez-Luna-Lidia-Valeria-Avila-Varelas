create database Hypernova;
use Hypernova;

CREATE TABLE Administrador (
    ID_Administrador INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Administrador VARCHAR(100) NOT NULL,
    Password VARCHAR(255) NOT NULL
);

select * from Administrador;

CREATE TABLE Vehiculo_CanSat (
    ID_Vehiculo INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Vehiculo VARCHAR(100) NOT NULL,
    Categoria VARCHAR(100),
    Estado ENUM('operativo', 'requiere revision') NOT NULL DEFAULT 'operativo'
);

CREATE TABLE Mision (
    ID_Mision INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Mision VARCHAR(100) NOT NULL,
    Fecha DATE,
    Lugar VARCHAR(100),
    FK_ID_Vehiculo INT,
    FK_ID_Administrador INT,
    FOREIGN KEY (FK_ID_Vehiculo) REFERENCES Vehiculo_CanSat(ID_Vehiculo) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Administrador) REFERENCES Administrador(ID_Administrador) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE Sesion (
    ID_Sesion INT PRIMARY KEY AUTO_INCREMENT,
    Fecha_Hora_Inicio DATETIME NOT NULL,
    Fecha_Hora_Fin DATETIME,
    FK_ID_Administrador INT,
    FOREIGN KEY (FK_ID_Administrador) REFERENCES Administrador(ID_Administrador) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Invitado (
    ID_Invitado INT PRIMARY KEY AUTO_INCREMENT,
    Nombre_Invitado VARCHAR(100) NOT NULL,
    Password VARCHAR(255) NOT NULL
);

CREATE TABLE Trama_CanSat (
    ID_Trama INT PRIMARY KEY AUTO_INCREMENT,
    Trama VARCHAR(500),
    Fecha_Hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FK_ID_Mision INT,
    -- Se asume una relación con Invitado según el diagrama, aunque es poco común.
    FK_ID_Invitado INT,
    FOREIGN KEY (FK_ID_Mision) REFERENCES Mision(ID_Mision) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Invitado) REFERENCES Invitado(ID_Invitado) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE Personal_Mantenimiento (
    ID_Personal INT PRIMARY KEY AUTO_INCREMENT,
    Nombre VARCHAR(100) NOT NULL,
    Password VARCHAR(255) NOT NULL
);

CREATE TABLE Reporte_Mantenimiento (
    ID_Reporte INT PRIMARY KEY AUTO_INCREMENT,
    Comentarios TEXT NOT NULL,
    Fecha_Hora_Reporte DATETIME DEFAULT CURRENT_TIMESTAMP,
    FK_ID_Vehiculo INT NOT NULL,
    FK_ID_Personal INT NOT NULL,
    FOREIGN KEY (FK_ID_Vehiculo) REFERENCES Vehiculo_CanSat(ID_Vehiculo) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (FK_ID_Personal) REFERENCES Personal_Mantenimiento(ID_Personal) ON DELETE CASCADE ON UPDATE CASCADE
    
);

INSERT INTO Administrador (Nombre_Administrador, Password) VALUES ('Valeria', '1234');

select * from Administrador;
SELECT COUNT(*) FROM Administrador;

