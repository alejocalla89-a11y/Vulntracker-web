import sqlite3
import os
import json
import zipfile
import re
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from security_scanner import scan_uploaded_content

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vulntracker_segura_key_academica_v6')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'vulntracker.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB límite

DATABASE_URL = os.environ.get('DATABASE_URL')

class DBWrapper:
    def __init__(self, conn, is_pg):
        self.conn = conn
        self.is_pg = is_pg

    def _convert_sql(self, sql):
        if not self.is_pg:
            return sql
        s = sql.replace('?', '%s')
        s = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', s, flags=re.IGNORECASE)
        s = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)', 
                   r'INSERT INTO \1 (\2) VALUES (\3) ON CONFLICT DO NOTHING', s, flags=re.IGNORECASE)
        return s

    def execute(self, sql, params=()):
        if self.is_pg:
            import psycopg2.extras
            cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            converted_sql = self._convert_sql(sql)
            cursor.execute(converted_sql, params)
            return cursor
        else:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            return cursor

    def commit(self):
        self.conn.commit()

    def cursor(self):
        if self.is_pg:
            import psycopg2.extras
            return self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        else:
            return self.conn.cursor()

    def close(self):
        self.conn.close()

def get_db():
    if 'db' not in g:
        if DATABASE_URL:
            import psycopg2
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url)
            g.db = DBWrapper(conn, is_pg=True)
        else:
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            g.db = DBWrapper(conn, is_pg=False)
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

try:
    from init_db import init_database
    init_database()
except Exception as e:
    print(f"Error inicializando la BD: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicie sesión para acceder al sistema.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        login_input = request.form['username'].strip().lower()
        password = request.form['password'].strip()
        
        db = get_db()
        user = db.execute('''
            SELECT * FROM usuarios 
            WHERE LOWER(username) = ? OR LOWER(email) = ?
        ''', (login_input, login_input)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['nombre'] = user['nombre_completo']
            session['rol'] = user['rol']
            flash(f'Bienvenido al sistema, {user["nombre_completo"]}', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas. Verifique su usuario/correo y contraseña.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo'].strip()
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip().lower()
        password = request.form['password'].strip()
        rol = request.form.get('rol', 'Desarrollador').strip()
        
        if rol not in ['Administrador', 'Técnico', 'Desarrollador']:
            rol = 'Desarrollador'
            
        db = get_db()
        user_exist = db.execute('SELECT id FROM usuarios WHERE LOWER(username) = ? OR LOWER(email) = ?', (username, email)).fetchone()
        
        if user_exist:
            flash('El nombre de usuario o correo electrónico ya se encuentra registrado.', 'danger')
            return render_template('register.html')
            
        password_hash = generate_password_hash(password)
        db.execute('''
            INSERT INTO usuarios (username, email, password_hash, nombre_completo, rol)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, nombre_completo, rol))
        db.commit()
        
        flash('Registro de cuenta exitoso. Ya puede iniciar sesión con sus credenciales.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión finalizada exitosamente.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    is_admin = (session.get('rol') == 'Administrador')
    user_id = session.get('user_id')
    
    total_activos = db.execute('SELECT COUNT(*) FROM activos').fetchone()[0]
    total_vulns = db.execute('SELECT COUNT(*) FROM vulnerabilidades').fetchone()[0]
    
    if is_admin:
        parches_pendientes = db.execute("SELECT COUNT(*) FROM parches WHERE estado IN ('Pendiente', 'En Proceso')").fetchone()[0]
        parches_remediados = db.execute("SELECT COUNT(*) FROM parches WHERE estado IN ('Remediado', 'Mitigado')").fetchone()[0]
        vulns_criticas = db.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE severidad = 'Crítica'").fetchone()[0]
        total_auditorias = db.execute("SELECT COUNT(*) FROM auditorias").fetchone()[0]

        criticas_cnt = db.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE severidad = 'Crítica'").fetchone()[0]
        altas_cnt = db.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE severidad = 'Alta'").fetchone()[0]
        medias_cnt = db.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE severidad = 'Media'").fetchone()[0]
        bajas_cnt = db.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE severidad = 'Baja'").fetchone()[0]

        query_riesgo = """
            SELECT COALESCE(SUM(v.cvss_score), 0)
            FROM parches p
            JOIN vulnerabilidades v ON p.vulnerabilidad_id = v.id
            WHERE p.estado IN ('Pendiente', 'En Proceso')
        """
        suma_riesgo = db.execute(query_riesgo).fetchone()[0]
        
        query_recientes = """
            SELECT p.id, a.nombre AS activo, a.ip, v.cve_id, v.severidad, v.cvss_score, 
                   p.estado, p.fecha_limite, u.nombre_completo AS asignado
            FROM parches p
            JOIN activos a ON p.activo_id = a.id
            JOIN vulnerabilidades v ON p.vulnerabilidad_id = v.id
            LEFT JOIN usuarios u ON p.asignado_a = u.id
            ORDER BY p.id DESC LIMIT 5
        """
        recientes = db.execute(query_recientes).fetchall()

        auditorias_recientes = db.execute("""
            SELECT a.id, a.nombre_proyecto, a.nombre_archivo, a.fecha_escaneo, 
                   a.archivos_analizados, a.total_hallazgos, a.indice_riesgo, a.criticas, a.altas,
                   act.nombre AS activo_nombre, u.nombre_completo AS auditor
            FROM auditorias a
            LEFT JOIN activos act ON a.activo_id = act.id
            LEFT JOIN usuarios u ON a.usuario_id = u.id
            ORDER BY a.id DESC LIMIT 5
        """).fetchall()
    else:
        parches_pendientes = db.execute("SELECT COUNT(*) FROM parches WHERE asignado_a = ? AND estado IN ('Pendiente', 'En Proceso')", (user_id,)).fetchone()[0]
        parches_remediados = db.execute("SELECT COUNT(*) FROM parches WHERE asignado_a = ? AND estado IN ('Remediado', 'Mitigado')", (user_id,)).fetchone()[0]
        total_auditorias = db.execute("SELECT COUNT(*) FROM auditorias WHERE usuario_id = ?", (user_id,)).fetchone()[0]

        vulns_criticas = db.execute("""
            SELECT COUNT(*) FROM auditoria_hallazgos ah
            JOIN auditorias a ON ah.auditoria_id = a.id
            WHERE a.usuario_id = ? AND ah.severidad = 'Crítica'
        """, (user_id,)).fetchone()[0]

        criticas_cnt = vulns_criticas
        altas_cnt = db.execute("""
            SELECT COUNT(*) FROM auditoria_hallazgos ah
            JOIN auditorias a ON ah.auditoria_id = a.id
            WHERE a.usuario_id = ? AND ah.severidad = 'Alta'
        """, (user_id,)).fetchone()[0]
        medias_cnt = db.execute("""
            SELECT COUNT(*) FROM auditoria_hallazgos ah
            JOIN auditorias a ON ah.auditoria_id = a.id
            WHERE a.usuario_id = ? AND ah.severidad = 'Media'
        """, (user_id,)).fetchone()[0]
        bajas_cnt = db.execute("""
            SELECT COUNT(*) FROM auditoria_hallazgos ah
            JOIN auditorias a ON ah.auditoria_id = a.id
            WHERE a.usuario_id = ? AND ah.severidad = 'Baja'
        """, (user_id,)).fetchone()[0]

        query_riesgo = """
            SELECT COALESCE(SUM(indice_riesgo), 0) FROM auditorias WHERE usuario_id = ?
        """
        suma_riesgo = db.execute(query_riesgo, (user_id,)).fetchone()[0]

        query_recientes = """
            SELECT p.id, a.nombre AS activo, a.ip, v.cve_id, v.severidad, v.cvss_score, 
                   p.estado, p.fecha_limite, u.nombre_completo AS asignado
            FROM parches p
            JOIN activos a ON p.activo_id = a.id
            JOIN vulnerabilidades v ON p.vulnerabilidad_id = v.id
            LEFT JOIN usuarios u ON p.asignado_a = u.id
            WHERE p.asignado_a = ?
            ORDER BY p.id DESC LIMIT 5
        """
        recientes = db.execute(query_recientes, (user_id,)).fetchall()

        auditorias_recientes = db.execute("""
            SELECT a.id, a.nombre_proyecto, a.nombre_archivo, a.fecha_escaneo, 
                   a.archivos_analizados, a.total_hallazgos, a.indice_riesgo, a.criticas, a.altas,
                   act.nombre AS activo_nombre, u.nombre_completo AS auditor
            FROM auditorias a
            LEFT JOIN activos act ON a.activo_id = act.id
            LEFT JOIN usuarios u ON a.usuario_id = u.id
            WHERE a.usuario_id = ?
            ORDER BY a.id DESC LIMIT 5
        """, (user_id,)).fetchall()

    indice_riesgo = min(100, int((suma_riesgo / 35.0) * 100)) if suma_riesgo > 0 else 0

    return render_template('dashboard.html',
                           total_activos=total_activos,
                           total_vulns=total_vulns,
                           parches_pendientes=parches_pendientes,
                           parches_remediados=parches_remediados,
                           vulns_criticas=vulns_criticas,
                           total_auditorias=total_auditorias,
                           indice_riesgo=indice_riesgo,
                           recientes=recientes,
                           auditorias_recientes=auditorias_recientes,
                           criticas_cnt=criticas_cnt,
                           altas_cnt=altas_cnt,
                           medias_cnt=medias_cnt,
                           bajas_cnt=bajas_cnt,
                           is_admin=is_admin)

@app.route('/auditorias')
@login_required
def auditorias():
    db = get_db()
    is_admin = (session.get('rol') == 'Administrador')
    user_id = session.get('user_id')
    
    if is_admin:
        auditorias_list = db.execute("""
            SELECT a.*, act.nombre AS activo_nombre, u.nombre_completo AS auditor, u.email AS auditor_email
            FROM auditorias a
            LEFT JOIN activos act ON a.activo_id = act.id
            LEFT JOIN usuarios u ON a.usuario_id = u.id
            ORDER BY a.id DESC
        """).fetchall()
    else:
        auditorias_list = db.execute("""
            SELECT a.*, act.nombre AS activo_nombre, u.nombre_completo AS auditor, u.email AS auditor_email
            FROM auditorias a
            LEFT JOIN activos act ON a.activo_id = act.id
            LEFT JOIN usuarios u ON a.usuario_id = u.id
            WHERE a.usuario_id = ?
            ORDER BY a.id DESC
        """, (user_id,)).fetchall()
        
    activos_list = db.execute("SELECT id, nombre, ip FROM activos").fetchall()
    return render_template('auditorias.html', auditorias=auditorias_list, activos=activos_list, is_admin=is_admin)

@app.route('/auditorias/escanear', methods=['POST'])
@login_required
def escanear_proyecto():
    if 'archivo_proyecto' not in request.files:
        flash('No se seleccionó ningún archivo para escanear.', 'danger')
        return redirect(url_for('auditorias'))
    
    file = request.files['archivo_proyecto']
    if file.filename == '':
        flash('Nombre de archivo vacío.', 'danger')
        return redirect(url_for('auditorias'))
    
    nombre_proyecto = request.form.get('nombre_proyecto', '').strip() or 'Proyecto de Software'
    activo_id_raw = request.form.get('activo_id')
    activo_id = int(activo_id_raw) if activo_id_raw and activo_id_raw.isdigit() else None
    
    orig_name = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    saved_filename = f"{timestamp}_{orig_name}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
    file.save(file_path)
    
    resultado = scan_uploaded_content(file_path, orig_name)
    
    db = get_db()
    
    if db.is_pg:
        cursor = db.execute("""
            INSERT INTO auditorias (
                nombre_proyecto, nombre_archivo, fecha_escaneo, archivos_analizados,
                total_hallazgos, criticas, altas, medias, bajas, indice_riesgo, usuario_id, activo_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
        """, (
            nombre_proyecto, orig_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            resultado['archivos_analizados'], resultado['total_hallazgos'],
            resultado['criticas'], resultado['altas'], resultado['medias'], resultado['bajas'],
            resultado['riesgo_estimado'], session['user_id'], activo_id
        ))
        auditoria_id = cursor.fetchone()[0]
    else:
        cursor = db.execute("""
            INSERT INTO auditorias (
                nombre_proyecto, nombre_archivo, fecha_escaneo, archivos_analizados,
                total_hallazgos, criticas, altas, medias, bajas, indice_riesgo, usuario_id, activo_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            nombre_proyecto, orig_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            resultado['archivos_analizados'], resultado['total_hallazgos'],
            resultado['criticas'], resultado['altas'], resultado['medias'], resultado['bajas'],
            resultado['riesgo_estimado'], session['user_id'], activo_id
        ))
        auditoria_id = cursor.lastrowid

    for h in resultado['hallazgos']:
        db.execute("""
            INSERT INTO auditoria_hallazgos (
                auditoria_id, tipo, archivo, linea, codigo_fragmento, cve_id,
                titulo, cvss_score, severidad, descripcion, solucion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            auditoria_id, h['tipo'], h['archivo'], h['linea'], h['codigo_fragmento'],
            h['cve_id'], h['titulo'], h['cvss_score'], h['severidad'], h['descripcion'], h['solucion']
        ))
        
        db.execute("""
            INSERT OR IGNORE INTO vulnerabilidades (cve_id, titulo, descripcion, cvss_score, severidad, solucion_sugerida)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (h['cve_id'], h['titulo'], h['descripcion'], h['cvss_score'], h['severidad'], h['solucion']))
        
        if activo_id:
            vuln_row = db.execute("SELECT id FROM vulnerabilidades WHERE cve_id = ?", (h['cve_id'],)).fetchone()
            if vuln_row:
                vuln_db_id = vuln_row[0]
                existe_parche = db.execute("""
                    SELECT id FROM parches 
                    WHERE activo_id = ? AND vulnerabilidad_id = ? AND estado IN ('Pendiente', 'En Proceso')
                """, (activo_id, vuln_db_id)).fetchone()
                if not existe_parche:
                    fecha_det = datetime.now().strftime('%Y-%m-%d')
                    fecha_lim = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
                    db.execute("""
                        INSERT INTO parches (activo_id, vulnerabilidad_id, asignado_a, estado, fecha_deteccion, fecha_limite, notas_remediacion)
                        VALUES (?, ?, ?, 'Pendiente', ?, ?, ?)
                    """, (activo_id, vuln_db_id, session['user_id'], fecha_det, fecha_lim, f"Detectado en proyecto '{nombre_proyecto}' de {session.get('nombre')}"))

    db.commit()
    flash(f'Análisis completado para {session.get("nombre")}: {resultado["total_hallazgos"]} hallazgos identificados. Índice de Riesgo: {resultado["riesgo_estimado"]}%', 'success')
    return redirect(url_for('auditoria_detalle', auditoria_id=auditoria_id))

@app.route('/auditorias/<int:auditoria_id>')
@login_required
def auditoria_detalle(auditoria_id):
    db = get_db()
    is_admin = (session.get('rol') == 'Administrador')
    user_id = session.get('user_id')
    
    auditoria = db.execute("""
        SELECT a.*, act.nombre AS activo_nombre, act.ip AS activo_ip, u.nombre_completo AS auditor, u.email AS auditor_email
        FROM auditorias a
        LEFT JOIN activos act ON a.activo_id = act.id
        LEFT JOIN usuarios u ON a.usuario_id = u.id
        WHERE a.id = ?
    """, (auditoria_id,)).fetchone()
    
    if not auditoria:
        flash('Auditoría no encontrada.', 'danger')
        return redirect(url_for('auditorias'))
        
    if not is_admin and auditoria['usuario_id'] != user_id:
        flash('Acceso restringido: No tiene permisos para consultar proyectos de otros usuarios.', 'warning')
        return redirect(url_for('auditorias'))
        
    hallazgos = db.execute("""
        SELECT * FROM auditoria_hallazgos
        WHERE auditoria_id = ?
        ORDER BY cvss_score DESC
    """, (auditoria_id,)).fetchall()
    
    return render_template('auditoria_detalle.html', auditoria=auditoria, hallazgos=hallazgos)

@app.route('/activos', methods=['GET', 'POST'])
@login_required
def activos():
    db = get_db()
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        ip = request.form['ip'].strip()
        tipo = request.form['tipo'].strip()
        so = request.form['sistema_operativo'].strip()
        criticidad = request.form['criticidad'].strip()
        ubicacion = request.form['ubicacion'].strip()
        
        db.execute("""
            INSERT INTO activos (nombre, ip, tipo, sistema_operativo, criticidad, ubicacion)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nombre, ip, tipo, so, criticidad, ubicacion))
        db.commit()
        flash('Activo tecnológico registrado exitosamente.', 'success')
        return redirect(url_for('activos'))
        
    activos_list = db.execute('SELECT * FROM activos ORDER BY id DESC').fetchall()
    return render_template('activos.html', activos=activos_list)

@app.route('/activos/eliminar/<int:activo_id>', methods=['POST'])
@login_required
def eliminar_activo(activo_id):
    db = get_db()
    db.execute('DELETE FROM activos WHERE id = ?', (activo_id,))
    db.commit()
    flash('Activo eliminado del inventario.', 'info')
    return redirect(url_for('activos'))

@app.route('/vulnerabilidades', methods=['GET', 'POST'])
@login_required
def vulnerabilidades():
    db = get_db()
    if request.method == 'POST':
        cve_id = request.form['cve_id'].strip().upper()
        titulo = request.form['titulo'].strip()
        descripcion = request.form['descripcion'].strip()
        cvss_score = float(request.form['cvss_score'])
        solucion = request.form['solucion_sugerida'].strip()
        
        if cvss_score >= 9.0:
            severidad = 'Crítica'
        elif cvss_score >= 7.0:
            severidad = 'Alta'
        elif cvss_score >= 4.0:
            severidad = 'Media'
        else:
            severidad = 'Baja'
            
        try:
            db.execute("""
                INSERT INTO vulnerabilidades (cve_id, titulo, descripcion, cvss_score, severidad, solucion_sugerida)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cve_id, titulo, descripcion, cvss_score, severidad, solucion))
            db.commit()
            flash(f'Vulnerabilidad {cve_id} registrada con severidad {severidad}.', 'success')
        except Exception as e:
            flash(f'No se pudo registrar {cve_id} (posiblemente duplicada).', 'danger')
            
        return redirect(url_for('vulnerabilidades'))
        
    vulns_list = db.execute('SELECT * FROM vulnerabilidades ORDER BY cvss_score DESC').fetchall()
    return render_template('vulnerabilidades.html', vulnerabilidades=vulns_list)

@app.route('/parches', methods=['GET', 'POST'])
@login_required
def parches():
    db = get_db()
    is_admin = (session.get('rol') == 'Administrador')
    user_id = session.get('user_id')

    if request.method == 'POST':
        activo_id = int(request.form['activo_id'])
        vuln_id = int(request.form['vulnerabilidad_id'])
        asignado_a = int(request.form['asignado_a'])
        fecha_limite = request.form['fecha_limite']
        notas = request.form.get('notas_remediacion', '')
        fecha_deteccion = datetime.now().strftime('%Y-%m-%d')
        
        db.execute("""
            INSERT INTO parches (activo_id, vulnerabilidad_id, asignado_a, estado, fecha_deteccion, fecha_limite, notas_remediacion)
            VALUES (?, ?, ?, 'Pendiente', ?, ?, ?)
        """, (activo_id, vuln_id, asignado_a, fecha_deteccion, fecha_limite, notas))
        db.commit()
        flash('Tarea de remediación asignada exitosamente.', 'success')
        return redirect(url_for('parches'))
        
    query_admin = """
        SELECT p.id, a.nombre AS activo_nombre, a.ip AS activo_ip, a.criticidad AS activo_criticidad,
               v.cve_id, v.titulo AS vuln_titulo, v.cvss_score, v.severidad, v.solucion_sugerida,
               p.estado, p.fecha_deteccion, p.fecha_limite, p.fecha_remediacion, p.notas_remediacion,
               u.nombre_completo AS asignado_nombre
        FROM parches p
        JOIN activos a ON p.activo_id = a.id
        JOIN vulnerabilidades v ON p.vulnerabilidad_id = v.id
        LEFT JOIN usuarios u ON p.asignado_a = u.id
        ORDER BY 
            CASE p.estado 
                WHEN 'Pendiente' THEN 1 
                WHEN 'En Proceso' THEN 2 
                WHEN 'Remediado' THEN 3 
                ELSE 4 
            END, v.cvss_score DESC
    """
    
    query_user = """
        SELECT p.id, a.nombre AS activo_nombre, a.ip AS activo_ip, a.criticidad AS activo_criticidad,
               v.cve_id, v.titulo AS vuln_titulo, v.cvss_score, v.severidad, v.solucion_sugerida,
               p.estado, p.fecha_deteccion, p.fecha_limite, p.fecha_remediacion, p.notas_remediacion,
               u.nombre_completo AS asignado_nombre
        FROM parches p
        JOIN activos a ON p.activo_id = a.id
        JOIN vulnerabilidades v ON p.vulnerabilidad_id = v.id
        LEFT JOIN usuarios u ON p.asignado_a = u.id
        WHERE p.asignado_a = ?
        ORDER BY 
            CASE p.estado 
                WHEN 'Pendiente' THEN 1 
                WHEN 'En Proceso' THEN 2 
                WHEN 'Remediado' THEN 3 
                ELSE 4 
            END, v.cvss_score DESC
    """
    
    parches_list = db.execute(query_admin if is_admin else query_user, () if is_admin else (user_id,)).fetchall()
    activos_list = db.execute('SELECT id, nombre, ip FROM activos').fetchall()
    vulns_list = db.execute('SELECT id, cve_id, titulo, cvss_score FROM vulnerabilidades').fetchall()
    usuarios_list = db.execute('SELECT id, nombre_completo, email, rol FROM usuarios').fetchall()
    
    return render_template('parches.html',
                           parches=parches_list,
                           activos=activos_list,
                           vulnerabilidades=vulns_list,
                           usuarios=usuarios_list,
                           is_admin=is_admin)

@app.route('/parches/actualizar_estado/<int:parche_id>', methods=['POST'])
@login_required
def actualizar_estado_parche(parche_id):
    db = get_db()
    nuevo_estado = request.form['estado']
    notas = request.form.get('notas_remediacion', '')
    
    fecha_remediacion = datetime.now().strftime('%Y-%m-%d') if nuevo_estado in ['Remediado', 'Mitigado'] else None
    
    db.execute("""
        UPDATE parches
        SET estado = ?, notas_remediacion = ?, fecha_remediacion = ?
        WHERE id = ?
    """, (nuevo_estado, notas, fecha_remediacion, parche_id))
    db.commit()
    flash(f'Estado del parche #{parche_id} actualizado a {nuevo_estado}.', 'success')
    return redirect(url_for('parches'))



@app.route('/usuarios')
@login_required
def usuarios():
    if session.get('rol') != 'Administrador':
        flash('Acceso denegado: El módulo de gestión de usuarios es exclusivo para el Administrador.', 'warning')
        return redirect(url_for('dashboard'))
        
    db = get_db()
    usuarios_list = db.execute('SELECT id, username, email, nombre_completo, rol FROM usuarios ORDER BY id ASC').fetchall()
    return render_template('usuarios.html', usuarios=usuarios_list)

@app.route('/usuarios/cambiar_rol/<int:user_id>', methods=['POST'])
@login_required
def cambiar_rol_usuario(user_id):
    if session.get('rol') != 'Administrador':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('dashboard'))
        
    nuevo_rol = request.form.get('rol', '').strip()
    if nuevo_rol in ['Administrador', 'Técnico', 'Desarrollador']:
        db = get_db()
        db.execute('UPDATE usuarios SET rol = ? WHERE id = ?', (nuevo_rol, user_id))
        db.commit()
        flash(f'Rol del usuario #{user_id} actualizado a {nuevo_rol}.', 'success')
    return redirect(url_for('usuarios'))

@app.route('/usuarios/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password_usuario(user_id):
    if session.get('rol') != 'Administrador':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('dashboard'))
        
    nueva_clave = request.form.get('nueva_password', '').strip()
    if nueva_clave:
        password_hash = generate_password_hash(nueva_clave)
        db = get_db()
        db.execute('UPDATE usuarios SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        db.commit()
        flash(f'Contraseña restablecida exitosamente para el usuario #{user_id}.', 'success')
    else:
        flash('La nueva contraseña no puede estar vacía.', 'warning')
    return redirect(url_for('usuarios'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
