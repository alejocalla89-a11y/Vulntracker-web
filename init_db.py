import sqlite3
import os
import re
from werkzeug.security import generate_password_hash

DATABASE_URL = os.environ.get('DATABASE_URL')
DB_FILE = os.path.join(os.path.dirname(__file__), 'vulntracker.db')

def get_init_db():
    url = os.environ.get('DATABASE_URL')
    if url:
        import psycopg2
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(url)
        return conn, True
    else:
        conn = sqlite3.connect(DB_FILE)
        return conn, False

def convert_sql(sql, is_pg):
    if not is_pg:
        return sql
    s = sql.replace('?', '%s')
    s = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', s, flags=re.IGNORECASE)
    s = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)', 
               r'INSERT INTO \1 (\2) VALUES (\3) ON CONFLICT DO NOTHING', s, flags=re.IGNORECASE)
    return s

def init_database():
    try:
        conn, is_pg = get_init_db()
        cursor = conn.cursor()

        sql_usuarios = """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            nombre_completo TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('Administrador', 'Técnico', 'Desarrollador'))
        );
        """
        cursor.execute(convert_sql(sql_usuarios, is_pg))

        sql_activos = """
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
        """
        cursor.execute(convert_sql(sql_activos, is_pg))

        sql_vulns = """
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            severidad TEXT NOT NULL CHECK(severidad IN ('Baja', 'Media', 'Alta', 'Crítica')),
            solucion_sugerida TEXT NOT NULL
        );
        """
        cursor.execute(convert_sql(sql_vulns, is_pg))

        sql_auditorias = """
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
        """
        cursor.execute(convert_sql(sql_auditorias, is_pg))

        sql_hallazgos = """
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
        """
        cursor.execute(convert_sql(sql_hallazgos, is_pg))

        sql_parches = """
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
        """
        cursor.execute(convert_sql(sql_parches, is_pg))

        admin_hash = generate_password_hash('admin123')
        tecnico_hash = generate_password_hash('tecnico123')
        pablo_hash = generate_password_hash('pablo123')
        jose_hash = generate_password_hash('jose123')

        sql_ins_user = """
        INSERT INTO usuarios (username, email, password_hash, nombre_completo, rol)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING;
        """ if is_pg else """
        INSERT OR IGNORE INTO usuarios (username, email, password_hash, nombre_completo, rol)
        VALUES (?, ?, ?, ?, ?);
        """

        for u in [
            ('admin', 'admin@vulntracker.sec', admin_hash, 'Administrador Global', 'Administrador'),
            ('tecnico', 'tecnico@vulntracker.sec', tecnico_hash, 'Soporte Técnico SecOps', 'Técnico'),
            ('pablo', 'pablo@empresa.com', pablo_hash, 'Pablo Desarrollador', 'Desarrollador'),
            ('jose', 'jose@empresa.com', jose_hash, 'José Desarrollador', 'Desarrollador')
        ]:
            try:
                cursor.execute(convert_sql(sql_ins_user, is_pg), u)
            except Exception:
                if is_pg:
                    conn.rollback()

        sql_ins_activos = """
        INSERT INTO activos (nombre, ip, tipo, sistema_operativo, criticidad, ubicacion)
        VALUES (?, ?, ?, ?, ?, ?);
        """
        try:
            cursor.execute("SELECT COUNT(*) FROM activos")
            cnt = cursor.fetchone()[0]
            if cnt == 0:
                for a in [
                    ('SRV-WEB-PROD-01', '192.168.10.15', 'Servidor Web', 'Ubuntu Server 22.04 LTS', 'Crítica', 'Centro de Cómputo Principal'),
                    ('SRV-APP-INT-01', '192.168.10.20', 'Servidor de Aplicaciones', 'Debian 12 Bookworm', 'Alta', 'Centro de Cómputo Principal')
                ]:
                    cursor.execute(convert_sql(sql_ins_activos, is_pg), a)
        except Exception:
            if is_pg:
                conn.rollback()

        conn.commit()
        conn.close()
        print("Base de datos inicializada exitosamente.")
    except Exception as e:
        print(f"Advertencia inicializando BD: {e}")

if __name__ == '__main__':
    init_database()
