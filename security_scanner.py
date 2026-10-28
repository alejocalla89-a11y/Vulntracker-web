import re
import os
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime

# ==============================================================================
# BASE DE DATOS DE SEGURIDAD SCA (COMPOSICIÓN DE SOFTWARE Y DEPENDENCIAS 2025/2026)
# ==============================================================================
KNOWN_DEPENDENCIES_VULNS = {
    # --- DEPENDENCIAS PYTHON ---
    'flask': [
        {'min_ver': '0.0', 'max_ver': '2.2.4', 'cve': 'CVE-2023-30861', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Fuga de cookies de sesión con encabezados Vary ausentes',
         'sol': 'Actualizar Flask a la versión >= 2.2.5 o >= 2.3.2'},
        {'min_ver': '0.0', 'max_ver': '0.12.2', 'cve': 'CVE-2018-1000656', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Denegación de servicio por decodificación JSON no controlada',
         'sol': 'Actualizar Flask a versiones modernas >= 2.0'}
    ],
    'requests': [
        {'min_ver': '0.0', 'max_ver': '2.31.0', 'cve': 'CVE-2023-32681', 'cvss': 6.1, 'sev': 'Media',
         'title': 'Fuga de credenciales Proxy-Authorization en redirecciones',
         'sol': 'Actualizar Requests a la versión >= 2.32.0'}
    ],
    'urllib3': [
        {'min_ver': '0.0', 'max_ver': '1.26.17', 'cve': 'CVE-2023-43804', 'cvss': 8.1, 'sev': 'Alta',
         'title': 'Filtración de cabecera Cookie en redirecciones de origen cruzado',
         'sol': 'Actualizar urllib3 a >= 1.26.18 o >= 2.0.7'},
        {'min_ver': '0.0', 'max_ver': '1.26.18', 'cve': 'CVE-2023-45803', 'cvss': 7.1, 'sev': 'Alta',
         'title': 'Desbordamiento o fuga de datos en canalización HTTP Request',
         'sol': 'Actualizar urllib3 a >= 1.26.19 o >= 2.0.8'}
    ],
    'werkzeug': [
        {'min_ver': '0.0', 'max_ver': '3.0.1', 'cve': 'CVE-2024-34069', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Agotamiento de recursos y DoS en parseo de datos multipart',
         'sol': 'Actualizar Werkzeug a >= 3.0.3'},
        {'min_ver': '0.0', 'max_ver': '2.2.2', 'cve': 'CVE-2023-25577', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Denegación de servicio mediante alta concurrencia de archivos adjuntos',
         'sol': 'Actualizar Werkzeug a >= 2.2.3'}
    ],
    'django': [
        {'min_ver': '0.0', 'max_ver': '4.2.11', 'cve': 'CVE-2024-27351', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Agotamiento de CPU por expresión regular en django.utils.text.Truncator',
         'sol': 'Actualizar Django a >= 4.2.12 o >= 5.0.4'}
    ],
    'pyyaml': [
        {'min_ver': '0.0', 'max_ver': '5.3.1', 'cve': 'CVE-2020-14343', 'cvss': 9.8, 'sev': 'Crítica',
         'title': 'Ejecución remota de código (RCE) por deserialización YAML insegura',
         'sol': 'Actualizar PyYAML a >= 5.4 y utilizar yaml.safe_load()'}
    ],
    'pillow': [
        {'min_ver': '0.0', 'max_ver': '10.2.0', 'cve': 'CVE-2024-28219', 'cvss': 8.8, 'sev': 'Alta',
         'title': 'Desbordamiento de búfer en procesamiento de perfiles ICC de imágenes',
         'sol': 'Actualizar Pillow a la versión >= 10.3.0'}
    ],
    'jinja2': [
        {'min_ver': '0.0', 'max_ver': '3.1.2', 'cve': 'CVE-2024-22195', 'cvss': 6.1, 'sev': 'Media',
         'title': 'Inyección de HTML/XSS en filtro xmlattr',
         'sol': 'Actualizar Jinja2 a >= 3.1.3'}
    ],

    # --- DEPENDENCIAS NODE.JS / NPM ---
    'express': [
        {'min_ver': '0.0', 'max_ver': '4.19.1', 'cve': 'CVE-2024-29041', 'cvss': 6.5, 'sev': 'Media',
         'title': 'Manejo deficiente de redirecciones abiertas en rutas URL',
         'sol': 'Actualizar express a la versión >= 4.19.2'}
    ],
    'lodash': [
        {'min_ver': '0.0', 'max_ver': '4.17.20', 'cve': 'CVE-2021-23337', 'cvss': 7.2, 'sev': 'Alta',
         'title': 'Contaminación de prototipo (Prototype Pollution) en utilidades de objetos',
         'sol': 'Actualizar lodash a >= 4.17.21'}
    ],
    'axios': [
        {'min_ver': '0.0', 'max_ver': '1.7.3', 'cve': 'CVE-2024-39338', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Inyección de SSRF mediante manipulación de rutas absolutas',
         'sol': 'Actualizar axios a la versión >= 1.7.4'}
    ],
    'jsonwebtoken': [
        {'min_ver': '0.0', 'max_ver': '8.5.1', 'cve': 'CVE-2022-23529', 'cvss': 9.8, 'sev': 'Crítica',
         'title': 'Ejecución remota de código en verificación de firmas JWT',
         'sol': 'Actualizar jsonwebtoken a >= 9.0.0'}
    ],

    # --- DEPENDENCIAS .NET / C# (CS) ---
    'newtonsoft.json': [
        {'min_ver': '0.0', 'max_ver': '12.0.3', 'cve': 'CVE-2021-24112', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'Agotamiento de pila y DoS por anidamiento excesivo en JSON',
         'sol': 'Actualizar Newtonsoft.Json en el paquete NuGet a >= 13.0.1'}
    ],
    'log4net': [
        {'min_ver': '0.0', 'max_ver': '2.0.9', 'cve': 'CVE-2018-1285', 'cvss': 8.8, 'sev': 'Alta',
         'title': 'Inyección de Entidades Externas XML (XXE) en parser de configuración',
         'sol': 'Actualizar log4net en el archivo .csproj a >= 2.0.10'}
    ],
    'system.text.encodings.web': [
        {'min_ver': '0.0', 'max_ver': '4.5.0', 'cve': 'CVE-2021-26701', 'cvss': 8.1, 'sev': 'Alta',
         'title': 'Corrupción de memoria y posible RCE en decodificador web .NET Core',
         'sol': 'Actualizar System.Text.Encodings.Web a >= 4.5.1 o >= 5.0.1'}
    ],
    'restsharp': [
        {'min_ver': '0.0', 'max_ver': '106.11.6', 'cve': 'CVE-2021-27293', 'cvss': 7.5, 'sev': 'Alta',
         'title': 'ReDoS (Denegación de servicio por expresión regular) en cliente HTTP',
         'sol': 'Actualizar RestSharp a >= 106.11.7'}
    ],
    'system.data.sqlclient': [
        {'min_ver': '0.0', 'max_ver': '4.8.5', 'cve': 'CVE-2024-21319', 'cvss': 8.8, 'sev': 'Alta',
         'title': 'Ejecución remota de código en controlador de base de datos SQL Server',
         'sol': 'Actualizar System.Data.SqlClient a la versión >= 4.8.6 o migrar a Microsoft.Data.SqlClient'}
    ]
}

# ==============================================================================
# REGLAS DE ANÁLISIS ESTÁTICO DE CÓDIGO (SAST MULTILENGUAJE - C#, PYTHON, JS, PHP, JAVA)
# ==============================================================================
SAST_RULES = [
    # 1. C# (.CS) SPECIFIC RULES
    {
        'id': 'SAST-CS-SQLI',
        'language': 'C#',
        'title': 'Inyección SQL en C# (.NET) por interpolación o concatenación',
        'cve': 'CWE-89',
        'cvss': 9.6,
        'sev': 'Crítica',
        'patterns': [
            r'SqlCommand\s*\(.*?\$"',
            r'SqlCommand\s*\(.*?\+',
            r'FromSqlRaw\s*\(\s*\$"',
            r'FromSqlRaw\s*\(\s*".*?\+',
            r'ExecuteSqlRawAsync\s*\(\s*\$"',
            r'ExecuteQuery\s*\(.*?\+'
        ],
        'desc': 'Se detectó construcción dinámica de consultas SQL en C# mediante interpolación de cadenas ($"...") o concatenación con el operador (+). Esto permite inyección de comandos SQL.',
        'sol': 'Utilizar parámetros SqlParam o interpolación parametrizada segura en EF Core: FromSqlInterpolated($"SELECT ... WHERE id = {id}").'
    },
    {
        'id': 'SAST-CS-CMD-INJECTION',
        'language': 'C#',
        'title': 'Ejecución insegura de procesos del sistema en C# (Process.Start)',
        'cve': 'CWE-78',
        'cvss': 9.8,
        'sev': 'Crítica',
        'patterns': [
            r'Process\.Start\s*\(\s*["\'](cmd|powershell|bash|sh)["\']',
            r'Process\.Start\s*\(\s*\$"',
            r'FileName\s*=\s*["\'](cmd\.exe|powershell\.exe|bash)["\']'
        ],
        'desc': 'Invocación de consolas de comandos del sistema operativo (cmd.exe, powershell) pasando argumentos dinámicos en C#. Riesgo de Remote Code Execution (RCE).',
        'sol': 'Evitar ejecutar intérpretes de consola. Invocar directamente el ejecutable deseado y pasar parámetros en la propiedad ArgumentList sin concatenar.'
    },
    {
        'id': 'SAST-CS-INSECURE-DESER',
        'language': 'C#',
        'title': 'Deserialización insegura en C# (BinaryFormatter / TypeNameHandling)',
        'cve': 'CWE-502',
        'cvss': 9.8,
        'sev': 'Crítica',
        'patterns': [
            r'BinaryFormatter\s*\(',
            r'\.Deserialize\s*\(',
            r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto)'
        ],
        'desc': 'El uso de BinaryFormatter o TypeNameHandling.All en Newtonsoft.Json en C# permite la instanciación de objetos arbitrarios y ejecución remota de código.',
        'sol': 'Remplazar BinaryFormatter por System.Text.Json o JsonSerializer sin polimorfismo sin restricciones.'
    },
    {
        'id': 'SAST-CS-WEAK-CRYPTO',
        'language': 'C#',
        'title': 'Uso de algoritmos o modos criptográficos obsoletos en C#',
        'cve': 'CWE-327',
        'cvss': 7.4,
        'sev': 'Alta',
        'patterns': [
            r'MD5\.Create\s*\(',
            r'SHA1\.Create\s*\(',
            r'TripleDESCryptoServiceProvider',
            r'CipherMode\.ECB'
        ],
        'desc': 'Empleo de algoritmos vulnerables (MD5, SHA1, TripleDES) o el modo de cifrado ECB en C# que revela patrones en los datos cifrados.',
        'sol': 'Utilizar cifrado simétrico AES-GCM (AES con modo autenticado) y algoritmos de hash SHA256 o SHA512.'
    },
    {
        'id': 'SAST-CS-XXE',
        'language': 'C#',
        'title': 'Vulnerabilidad XXE en procesamiento XML en C#',
        'cve': 'CWE-611',
        'cvss': 8.2,
        'sev': 'Alta',
        'patterns': [
            r'DtdProcessing\s*=\s*DtdProcessing\.Parse',
            r'XmlResolver\s*=\s*new\s+XmlUrlResolver'
        ],
        'desc': 'Configuración de lectura XML en .NET que permite la resolución de entidades externas (XXE), con riesgo de lectura no autorizada de archivos del servidor.',
        'sol': 'Establecer DtdProcessing = DtdProcessing.Prohibit o Ignore y asignar XmlResolver = null.'
    },
    {
        'id': 'SAST-CS-JWT-WEAK-KEY',
        'language': 'C#',
        'title': 'Clave de firma JWT fija o débil en C# / ASP.NET Core',
        'cve': 'CWE-347',
        'cvss': 8.1,
        'sev': 'Alta',
        'patterns': [
            r'SymmetricSecurityKey\s*\(\s*Encoding\..*?GetBytes\s*\(\s*["\'].*?["\']\s*\)'
        ],
        'desc': 'Definición de claves simétricas de tokens JWT quemadas en el código fuente de C#.',
        'sol': 'Cargar la clave secreta desde variables de entorno seguras o Azure Key Vault / AWS Secrets Manager.'
    },

    # 2. MODERN 2025/2026 AI & CLOUD API KEY LEAKS (TODOS LOS LENGUAJES)
    {
        'id': 'SAST-AI-API-KEY-LEAK',
        'language': 'Global',
        'title': 'Filtración de Claves de API de IA y Servicios Cloud (2025/2026)',
        'cve': 'CWE-798',
        'cvss': 9.1,
        'sev': 'Crítica',
        'patterns': [
            r'sk-proj-[a-zA-Z0-9_\-]{20,}',               # OpenAI API Keys
            r'sk-ant-api03-[a-zA-Z0-9_\-]{20,}',          # Anthropic Claude Keys
            r'AIzaSy[a-zA-Z0-9_\-]{33}',                  # Google Gemini / Cloud API Key
            r'AKIA[0-9A-Z]{16}',                           # AWS Access Key ID
            r'ghp_[a-zA-Z0-9]{36}',                        # GitHub Personal Access Token
            r'sq0atp-[0-9a-zA-Z\-_]{22}'                  # Square Access Token
        ],
        'desc': 'Se detectó una clave de acceso real para servicios de Inteligencia Artificial (OpenAI, Anthropic, Gemini) o infraestructura cloud (AWS, GitHub).',
        'sol': 'Revocar inmediatamente la API key comprometida y migrarla a un gestor de secretos (Secrets Manager / .env).'
    },

    # 3. REGLAS MULTILENGUAJE GENERICAS (PYTHON, JS, PHP, SQL)
    {
        'id': 'SAST-SQL-INJ',
        'language': 'Python/JS/PHP',
        'title': 'Posible Inyección SQL por concatenación de cadenas',
        'cve': 'CWE-89',
        'cvss': 9.4,
        'sev': 'Crítica',
        'patterns': [
            r'execute\s*\(\s*["\'].*?%s',
            r'execute\s*\(\s*f["\'].*?\{',
            r'execute\s*\(\s*["\'].*?\+\s*\w+',
            r'cursor\.execute\s*\(\s*["\'].*?SELECT.*?WHERE.*?["\']\s*\+',
            r'mysqli_query\s*\(\s*\$.*?\.'
        ],
        'desc': 'Construcción dinámica de sentencias SQL mediante concatenación directa de variables no sanitizadas.',
        'sol': 'Utilizar consultas preparadas parametrizadas (?) o el ORM nativo del framework.'
    },
    {
        'id': 'SAST-HARDCODED-SECRET',
        'language': 'Global',
        'title': 'Credenciales o Claves Secretas en Código Fuente',
        'cve': 'CWE-798',
        'cvss': 8.9,
        'sev': 'Alta',
        'patterns': [
            r'(?i)(password|secret_key|api_key|token|auth_token)\s*=\s*["\'][a-zA-Z0-9_\-\.\@\#\$]{6,}["\']'
        ],
        'desc': 'Valores de autenticación o secretos codificados directamente en el archivo.',
        'sol': 'Almacenar contraseñas y claves en variables de entorno (.env).'
    },
    {
        'id': 'SAST-DEBUG-ENABLED',
        'language': 'Python/JS',
        'title': 'Modo Depuración (Debug Mode) habilitado en Producción',
        'cve': 'CWE-489',
        'cvss': 7.2,
        'sev': 'Media',
        'patterns': [
            r'app\.run\s*\(.*?debug\s*=\s*True',
            r'DEBUG\s*=\s*True',
            r'const\s+DEBUG\s*=\s*true'
        ],
        'desc': 'El modo debug activo expone consolas interactiva y trazas completas de error.',
        'sol': 'Deshabilitar el parámetro debug en entornos de producción.'
    },
    {
        'id': 'SAST-CMD-INJECTION',
        'language': 'Python/JS/PHP',
        'title': 'Ejecución insegura de comandos del sistema operativo',
        'cve': 'CWE-78',
        'cvss': 9.8,
        'sev': 'Crítica',
        'patterns': [
            r'os\.system\s*\(',
            r'subprocess\.Popen\s*\(.*?shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
            r'child_process\.exec\s*\('
        ],
        'desc': 'Invocación de funciones de ejecución shell dinámicas con posible entrada de usuario.',
        'sol': 'Evitar utilizar el intérprete de shell y utilizar APIs seguras de manejo de argumentos en lista.'
    },
    {
        'id': 'SAST-CORS-PERMISSIVE',
        'language': 'Global',
        'title': 'Configuración de CORS Excesivamente Permisiva (Access-Control-Allow-Origin: *)',
        'cve': 'CWE-942',
        'cvss': 7.2,
        'sev': 'Media',
        'patterns': [
            r'Access-Control-Allow-Origin.*?\*',
            r'AllowAnyOrigin\s*\(',
            r'cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']'
        ],
        'desc': 'La política CORS permite solicitudes de cualquier dominio web externo, facilitando ataques de Robo de Datos Cross-Domain.',
        'sol': 'Restringir los orígenes permitidos explícitamente a los dominios de confianza.'
    },
    {
        'id': 'SAST-XSS-UNSANITIZED',
        'language': 'JS/PHP/C#',
        'title': 'Inyección de Script en Sitio Cruzado (XSS) en renderizado',
        'cve': 'CWE-79',
        'cvss': 7.5,
        'sev': 'Alta',
        'patterns': [
            r'dangerouslySetInnerHTML',
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'@Html\.Raw\s*\('
        ],
        'desc': 'Inserción directa de contenido HTML/JavaScript dinámico en el DOM del navegador sin escapar ni sanitizar.',
        'sol': 'Utilizar bind de texto seguro (textContent, {{ var }}) o escapar caracteres HTML especiales.'
    }
]

def parse_version_tuple(ver_str):
    try:
        parts = re.findall(r'\d+', ver_str)
        return tuple(map(int, parts))
    except Exception:
        return (0, 0, 0)

def version_in_range(ver_str, min_ver, max_ver):
    v = parse_version_tuple(ver_str)
    min_v = parse_version_tuple(min_ver)
    max_v = parse_version_tuple(max_ver)
    return min_v <= v <= max_v

def analyze_csproj_or_packages_config(content, filename):
    """
    SCA Parser para proyectos C# (.NET) analizando .csproj y packages.config XML
    """
    findings = []
    lines = content.splitlines()
    
    # Intentar parseo XML directo para .csproj
    try:
        root = ET.fromstring(content)
        # Buscar <PackageReference Include="X" Version="Y" />
        for elem in root.iter():
            if elem.tag.endswith('PackageReference'):
                pkg_name = elem.attrib.get('Include', '').lower()
                pkg_ver = elem.attrib.get('Version', '')
                if not pkg_ver:
                    # A veces la versión está en un elemento hijo <Version>1.0.0</Version>
                    ver_child = elem.find('Version')
                    if ver_child is not None and ver_child.text:
                        pkg_ver = ver_child.text
                
                if pkg_name in KNOWN_DEPENDENCIES_VULNS and pkg_ver:
                    for rule in KNOWN_DEPENDENCIES_VULNS[pkg_name]:
                        if version_in_range(pkg_ver, rule['min_ver'], rule['max_ver']):
                            findings.append({
                                'tipo': 'SCA (Dependencia .NET)',
                                'archivo': filename,
                                'linea': 1,
                                'codigo_fragmento': f'<PackageReference Include="{pkg_name}" Version="{pkg_ver}" />',
                                'cve_id': rule['cve'],
                                'titulo': f"{rule['title']} ({pkg_name} {pkg_ver})",
                                'cvss_score': rule['cvss'],
                                'severidad': rule['sev'],
                                'descripcion': f"El paquete NuGet '{pkg_name}' v'{pkg_ver}' presenta vulnerabilidades de seguridad catalogadas.",
                                'solucion': rule['sol']
                            })
    except Exception:
        # Fallback por regex si el XML está fragmentado o no es válido
        for line_num, line in enumerate(lines, 1):
            match = re.search(r'PackageReference\s+Include=["\']([a-zA-Z0-9_\-\.]+)["\']\s+Version=["\']([0-9\.]+)["\']', line, re.IGNORECASE)
            if not match:
                match = re.search(r'package\s+id=["\']([a-zA-Z0-9_\-\.]+)["\']\s+version=["\']([0-9\.]+)["\']', line, re.IGNORECASE)
            
            if match:
                pkg_name = match.group(1).lower()
                pkg_ver = match.group(2)
                if pkg_name in KNOWN_DEPENDENCIES_VULNS:
                    for rule in KNOWN_DEPENDENCIES_VULNS[pkg_name]:
                        if version_in_range(pkg_ver, rule['min_ver'], rule['max_ver']):
                            findings.append({
                                'tipo': 'SCA (Dependencia .NET)',
                                'archivo': filename,
                                'linea': line_num,
                                'codigo_fragmento': line.strip(),
                                'cve_id': rule['cve'],
                                'titulo': f"{rule['title']} ({pkg_name} {pkg_ver})",
                                'cvss_score': rule['cvss'],
                                'severidad': rule['sev'],
                                'descripcion': f"El paquete NuGet '{pkg_name}' versión '{pkg_ver}' está marcado con vulnerabilidades conocidas.",
                                'solucion': rule['sol']
                            })
    return findings

def analyze_dependencies_file(content, filename):
    findings = []
    name_lower = filename.lower()
    lines = content.splitlines()

    if name_lower.endswith('.csproj') or 'packages.config' in name_lower:
        return analyze_csproj_or_packages_config(content, filename)
    
    if 'requirements' in name_lower or name_lower.endswith('.txt'):
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|<=|~=)\s*([0-9\.]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_ver = match.group(2)
                if pkg_name in KNOWN_DEPENDENCIES_VULNS:
                    for rule in KNOWN_DEPENDENCIES_VULNS[pkg_name]:
                        if version_in_range(pkg_ver, rule['min_ver'], rule['max_ver']):
                            findings.append({
                                'tipo': 'SCA (Dependencia)',
                                'archivo': filename,
                                'linea': line_num,
                                'codigo_fragmento': line,
                                'cve_id': rule['cve'],
                                'titulo': f"{rule['title']} ({pkg_name} {pkg_ver})",
                                'cvss_score': rule['cvss'],
                                'severidad': rule['sev'],
                                'descripcion': f"La dependencia Python '{pkg_name}' v'{pkg_ver}' contiene fallos de seguridad catalogados.",
                                'solucion': rule['sol']
                            })
                            
    elif 'package.json' in name_lower:
        for line_num, line in enumerate(lines, 1):
            match = re.search(r'["\']([a-zA-Z0-9_\-\.\@\/]+)["\']\s*:\s*["\'][\^~]?([0-9\.]+)["\']', line)
            if match:
                pkg_name = match.group(1).lower().split('/')[-1]
                pkg_ver = match.group(2)
                if pkg_name in KNOWN_DEPENDENCIES_VULNS:
                    for rule in KNOWN_DEPENDENCIES_VULNS[pkg_name]:
                        if version_in_range(pkg_ver, rule['min_ver'], rule['max_ver']):
                            findings.append({
                                'tipo': 'SCA (Dependencia NPM)',
                                'archivo': filename,
                                'linea': line_num,
                                'codigo_fragmento': line.strip(),
                                'cve_id': rule['cve'],
                                'titulo': f"{rule['title']} ({pkg_name} {pkg_ver})",
                                'cvss_score': rule['cvss'],
                                'severidad': rule['sev'],
                                'descripcion': f"El paquete Node.js '{pkg_name}' versión '{pkg_ver}' presenta riesgos de seguridad.",
                                'solucion': rule['sol']
                            })
    return findings

def analyze_code_file(content, filename):
    findings = []
    lines = content.splitlines()
    ext = os.path.splitext(filename)[1].lower()

    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        # Ignorar comentarios según lenguaje
        if line_clean.startswith('#') or line_clean.startswith('//') or line_clean.startswith('/*') or line_clean.startswith('*'):
            continue
            
        for rule in SAST_RULES:
            # Filtrar o aplicar regla según la extensión del archivo
            if ext in ('.cs', '.csproj') and rule['language'] not in ('C#', 'Global'):
                continue
            if ext in ('.py',) and rule['language'] not in ('Python', 'Python/JS', 'Python/JS/PHP', 'Global'):
                continue

            for pat in rule['patterns']:
                if re.search(pat, line):
                    findings.append({
                        'tipo': f"SAST ({rule['language']})",
                        'archivo': filename,
                        'linea': line_num,
                        'codigo_fragmento': line_clean[:120],
                        'cve_id': rule['cve'],
                        'titulo': f"{rule['title']} (Línea {line_num})",
                        'cvss_score': rule['cvss'],
                        'severidad': rule['sev'],
                        'descripcion': rule['desc'],
                        'solucion': rule['sol']
                    })
                    break # Evitar duplicar el mismo hallazgo en la misma línea
    return findings

def scan_uploaded_content(file_path, original_filename):
    """
    Analiza un archivo individual (.cs, .py, .js, .txt, .json, .csproj) o un archivo .zip completo
    soporta C# (.NET Core / C# Framework), Python, Node.js, PHP, Java, SQL y manifiestos de paquetes.
    """
    findings = []
    archivos_analizados = 0

    valid_extensions = (
        '.cs', '.csproj', '.py', '.js', '.jsx', '.ts', '.tsx', 
        '.php', '.java', '.go', '.sql', '.txt', '.json', '.xml', '.config'
    )

    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as z:
            for entry in z.namelist():
                if '__pycache__' in entry or '.git' in entry or 'node_modules' in entry or 'bin/' in entry or 'obj/' in entry or entry.endswith('/'):
                    continue
                name_lower = entry.lower()
                if name_lower.endswith(valid_extensions) or 'requirements' in name_lower or 'packages.config' in name_lower:
                    archivos_analizados += 1
                    try:
                        with z.open(entry) as f:
                            raw = f.read().decode('utf-8', errors='ignore')
                            if 'requirements' in name_lower or 'package.json' in name_lower or name_lower.endswith('.csproj') or 'packages.config' in name_lower:
                                findings.extend(analyze_dependencies_file(raw, entry))
                            
                            if name_lower.endswith(('.cs', '.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.go', '.sql')):
                                findings.extend(analyze_code_file(raw, entry))
                    except Exception:
                        pass
    else:
        # Archivo plano individual subido
        archivos_analizados = 1
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
            name_lower = original_filename.lower()
            if 'requirements' in name_lower or 'package.json' in name_lower or name_lower.endswith('.csproj') or 'packages.config' in name_lower or name_lower.endswith('.txt'):
                findings.extend(analyze_dependencies_file(raw, original_filename))
            
            if name_lower.endswith(('.cs', '.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.go', '.sql')):
                findings.extend(analyze_code_file(raw, original_filename))

    # Estadísticas
    total_hallazgos = len(findings)
    criticas = sum(1 for h in findings if h['severidad'] == 'Crítica')
    altas = sum(1 for h in findings if h['severidad'] == 'Alta')
    medias = sum(1 for h in findings if h['severidad'] == 'Media')
    bajas = sum(1 for h in findings if h['severidad'] == 'Baja')

    # Índice de riesgo estandarizado
    score_sum = sum(h['cvss_score'] for h in findings)
    riesgo_estimado = min(100, int((score_sum / 25.0) * 100)) if score_sum > 0 else 0

    return {
        'archivos_analizados': archivos_analizados,
        'total_hallazgos': total_hallazgos,
        'criticas': criticas,
        'altas': altas,
        'medias': medias,
        'bajas': bajas,
        'riesgo_estimado': riesgo_estimado,
        'hallazgos': findings
    }
