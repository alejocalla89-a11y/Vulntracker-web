import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_FILE = os.path.join(os.path.dirname(__file__), 'vulntracker.db')

def init_database():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # 1. Tabla de Usuarios con correo electrónico y soporte multitenant
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        nombre_completo TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('Administrador', 'Técnico', 'Desarrollador'))
    );
    """)

    # 2. Tabla de Activos Tecnológicos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        ip TEXT NOT NULL,
        tipo TEXT NOT NULL,
        sistema_operativo TEXT NOT NULL,
        criticidad TEXT NOT NULL CHECK(criticidad IN ('Baja', 'Media', 'Alta', 'Crítica')),
        ubicacion TEXT NOT NULL,
        estado TEXT NOT NULL DEFAULT 'Operativo' CHECK(estado IN ('Operativo', 'Mantenimiento', 'Fuera de Línea'))
    );
    """)

    # 3. Tabla de Vulnerabilidades
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilidades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        titulo TEXT NOT NULL,
        descripcion TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        severidad TEXT NOT NULL CHECK(severidad IN ('Baja', 'Media', 'Alta', 'Crítica')),
        solucion_sugerida TEXT NOT NULL
    );
    """)

    # 4. Tabla de Auditorías / Escaneos de Proyectos (Aislados por usuario / usuario_id)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auditorias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre_proyecto TEXT NOT NULL,
        nombre_archivo TEXT NOT NULL,
        fecha_escaneo DATETIME NOT NULL,
        archivos_analizados INTEGER NOT NULL,
        total_hallazgos INTEGER NOT NULL,
        criticas INTEGER NOT NULL,
        altas INTEGER NOT NULL,
        medias INTEGER NOT NULL,
        bajas INTEGER NOT NULL,
        indice_riesgo INTEGER NOT NULL,
        usuario_id INTEGER NOT NULL,
        activo_id INTEGER,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        FOREIGN KEY(activo_id) REFERENCES activos(id) ON DELETE SET NULL
    );
    """)

    # 5. Tabla de Hallazgos Específicos de cada Auditoría
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auditoria_hallazgos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        auditoria_id INTEGER NOT NULL,
        tipo TEXT NOT NULL,
        archivo TEXT NOT NULL,
        linea INTEGER,
        codigo_fragmento TEXT,
        cve_id TEXT NOT NULL,
        titulo TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        severidad TEXT NOT NULL,
        descripcion TEXT NOT NULL,
        solucion TEXT NOT NULL,
        FOREIGN KEY(auditoria_id) REFERENCES auditorias(id) ON DELETE CASCADE
    );
    """)

    # 6. Tabla de Parches y Tareas de Remediación
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS parches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        activo_id INTEGER NOT NULL,
        vulnerabilidad_id INTEGER NOT NULL,
        asignado_a INTEGER,
        estado TEXT NOT NULL DEFAULT 'Pendiente' CHECK(estado IN ('Pendiente', 'En Proceso', 'Remediado', 'Mitigado')),
        fecha_deteccion DATE NOT NULL,
        fecha_limite DATE NOT NULL,
        fecha_remediacion DATE,
        notas_remediacion TEXT,
        FOREIGN KEY(activo_id) REFERENCES activos(id) ON DELETE CASCADE,
        FOREIGN KEY(vulnerabilidad_id) REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
        FOREIGN KEY(asignado_a) REFERENCES usuarios(id)
    );
    """)

    # Cuentas de usuario iniciales (Administrador, Técnico, y Desarrolladores independientes Pablo y José)
    admin_hash = generate_password_hash('admin123')
    tecnico_hash = generate_password_hash('tecnico123')
    pablo_hash = generate_password_hash('pablo123')
    jose_hash = generate_password_hash('jose123')

    cursor.executemany("""
    INSERT INTO usuarios (username, email, password_hash, nombre_completo, rol)
    VALUES (?, ?, ?, ?, ?)
    """, [
        ('admin', 'admin@vulntracker.sec', admin_hash, 'Administrador Global', 'Administrador'),
        ('tecnico', 'tecnico@vulntracker.sec', tecnico_hash, 'Soporte Técnico SecOps', 'Técnico'),
        ('pablo', 'pablo@empresa.com', pablo_hash, 'Pablo Desarrollador', 'Desarrollador'),
        ('jose', 'jose@empresa.com', jose_hash, 'José Desarrollador', 'Desarrollador')
    ])

    # Servidores de infraestructura base
    activos_data = [
        ('SRV-WEB-PROD-01', '192.168.10.15', 'Servidor Web', 'Ubuntu Server 22.04 LTS', 'Crítica', 'Centro de Cómputo Principal'),
        ('SRV-APP-INT-01', '192.168.10.20', 'Servidor de Aplicaciones', 'Debian 12 Bookworm', 'Alta', 'Centro de Cómputo Principal')
    ]
    cursor.executemany("""
    INSERT INTO activos (nombre, ip, tipo, sistema_operativo, criticidad, ubicacion)
    VALUES (?, ?, ?, ?, ?, ?)
    """, activos_data)

    conn.commit()
    conn.close()
    print("Base de datos 'vulntracker.db' v6 inicializada con soporte de email y multitenancy.")

if __name__ == '__main__':
    init_database()
