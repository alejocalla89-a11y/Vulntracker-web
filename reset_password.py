import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_FILE = os.path.join(os.path.dirname(__file__), 'vulntracker.db')

def reset():
    if not os.path.exists(DB_FILE):
        print("La base de datos no existe.")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    admin_h = generate_password_hash('admin123')
    tecnico_h = generate_password_hash('tecnico123')
    c.execute("UPDATE usuarios SET password_hash = ? WHERE username = 'admin'", (admin_h,))
    c.execute("UPDATE usuarios SET password_hash = ? WHERE username = 'tecnico'", (tecnico_h,))
    conn.commit()
    conn.close()
    print("Contraseñas restauradas con éxito: admin/admin123, tecnico/tecnico123")

if __name__ == '__main__':
    reset()
