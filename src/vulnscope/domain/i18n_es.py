"""Spanish texts for server-generated content. English is the source language (see rules.py / playbooks.py)."""

LANGS = ("en", "es")


def norm_lang(value) -> str:
    return value if value in LANGS else "en"


SEVERITY_ES = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja"}

RULE_TEXT_ES = {
    "SEC001": ("Clave de acceso de AWS en el código", "Revoca esta clave en IAM de inmediato, crea una nueva y cárgala desde variables de entorno o un gestor de secretos. Reescribe el historial de git si se subió."),
    "SEC002": ("Clave privada incrustada en el código", "Trata la clave como comprometida: rótala, elimínala del historial del repositorio y móntala desde un gestor de secretos al desplegar."),
    "SEC003": ("Contraseña, token o secreto escrito en el código", "Lee los secretos desde variables de entorno o un gestor de secretos y falla al arrancar si faltan. Rota el valor expuesto."),
    "SEC004": ("Token de proveedor conocido (GitHub / Slack)", "Revoca el token en el proveedor, emite uno nuevo con los mínimos privilegios y guárdalo en un gestor de secretos."),
    "SEC005": ("Credenciales por defecto escritas en el código", "Nunca incluyas cuentas por defecto. Crea los usuarios al desplegar y guarda solo hashes con sal (p. ej. werkzeug.security.generate_password_hash)."),
    "INJ001": ("Consulta SQL construida con formato de texto (Python)", "Usa consultas parametrizadas: pasa los valores como argumento aparte para que el controlador los escape."),
    "INJ002": ("Consulta SQL construida por concatenación (JS/TS)", "Usa marcadores ($1, ?) y pasa los valores en el arreglo de parámetros."),
    "INJ003": ("SQL construido con datos de la petición (PHP)", "Usa sentencias preparadas de PDO con parámetros enlazados."),
    "INJ004": ("Ejecución de comandos del sistema con shell", "Evita el shell. Pasa una lista de argumentos a subprocess.run y valida todo valor controlado por el usuario contra una lista permitida."),
    "INJ005": ("Comando del sistema armado con texto dinámico (Node.js)", "Usa execFile/spawn con un arreglo de argumentos y nunca insertes datos del usuario en la cadena del comando."),
    "INJ006": ("Path traversal: acceso a archivos guiado por la petición", "Resuelve la ruta y verifica que quede dentro de un directorio base permitido; prefiere identificadores opacos a nombres de archivo."),
    "INJ007": ("SSRF: URL tomada de la petición", "Valida el destino contra una lista de hosts permitidos y bloquea rangos privados y link-local antes de conectar."),
    "EXE001": ("Evaluación dinámica de código (eval/exec)", "Elimina eval/exec. Interpreta datos con json.loads / ast.literal_eval o despacha mediante un diccionario de funciones permitidas."),
    "EXE002": ("Deserialización insegura (pickle / marshal / yaml.load)", "Nunca deserialices bytes no confiables con pickle/marshal. Usa JSON o yaml.safe_load."),
    "EXE003": ("Riesgo de inyección de plantillas (SSTI)", "Renderiza archivos de plantilla fijos y pasa los datos del usuario como variables; nunca construyas el código de la plantilla con entrada del usuario."),
    "EXE004": ("unserialize de PHP sobre datos de la petición", "Usa json_decode en lugar de unserialize para entrada no confiable."),
    "CFG001": ("Modo debug activado", "Desactiva el modo debug fuera del desarrollo local: contrólalo con una variable de entorno desactivada por defecto. El depurador de Werkzeug permite ejecución remota de código."),
    "CFG002": ("Verificación de certificados TLS desactivada", "Mantén la verificación activa y confía en el paquete de CA correcto en lugar de desactivar controles."),
    "CFG003": ("CORS demasiado permisivo", "Permite solo los orígenes específicos que necesitan acceso."),
    "CFG004": ("Firma JWT sin verificar / algoritmo 'none'", "Verifica siempre las firmas y fija explícitamente los algoritmos aceptados (p. ej. algorithms=[\"HS256\"])."),
    "CFG005": ("Protección CSRF desactivada", "Mantén la protección CSRF en endpoints con cookies, o usa tokens en cabeceras."),
    "CFG006": ("Servicio enlazado a todas las interfaces", "Enlaza a 127.0.0.1 salvo que el servicio deba ser accesible desde fuera, y coloca un proxy inverso delante."),
    "CRY001": ("Algoritmo de hash débil (MD5 / SHA-1)", "Usa SHA-256 o superior para integridad y un hash de contraseñas (bcrypt, scrypt, argon2) para credenciales."),
    "CRY002": ("Cifrado débil o modo ECB", "Usa AES-GCM o ChaCha20-Poly1305 de una librería reconocida."),
    "CRY003": ("Valor aleatorio predecible usado como secreto", "Usa el módulo secrets (Python) o crypto.randomBytes / crypto.getRandomValues (JS)."),
    "WEB001": ("Punto de XSS en el DOM (innerHTML / document.write)", "Asigna con textContent, o sanitiza con una librería reconocida como DOMPurify antes de insertar HTML."),
    "WEB002": ("Autoescape de plantillas omitido", "Quita |safe / Markup() para datos controlados por el usuario y deja que el motor de plantillas los escape."),
    "WEB003": ("URL HTTP sin cifrar", "Usa https:// para todo endpoint externo."),
    "INF001": ("Regla de red abierta a todo Internet", "Restringe la entrada al CIDR más pequeño posible (VPN, balanceador o rango de la oficina) y expone solo los puertos necesarios."),
    "INF002": ("Almacenamiento en la nube público / principal comodín", "Bloquea el acceso público del bucket y concede acceso solo a principales con nombre."),
    "INF003": ("El contenedor corre como root", "Crea un usuario sin privilegios en la imagen y elimina capabilities."),
    "INF004": ("Etiqueta de imagen sin fijar (:latest)", "Fija las imágenes base a una versión o digest específico."),
    "INF005": ("Permisos de escritura para todos (chmod 777)", "Concede los permisos mínimos (p. ej. 750 / 640)."),
    "FIL001": ("Archivo de entorno incluido en el proyecto", "Quita los archivos .env del repositorio, agrégalos a .gitignore y entrega un .env.example con valores de ejemplo."),
    "FIL002": ("Archivo de clave privada incluido en el proyecto", "Elimina la clave, rótala y móntala en tiempo de ejecución desde un gestor de secretos."),
    "FIL003": ("Archivo de base de datos incluido en el proyecto", "No subas bases de datos: pueden contener datos de usuarios. Genéralas al desplegar o con scripts de carga."),
    "FIL004": ("Entorno virtual / carpeta de dependencias incluida", "Excluye entornos virtuales y dependencias del repositorio (.gitignore) e instálalas desde requirements.txt."),
}

PLAYBOOK_ES = {
    "Preventive monitoring and a periodic patch audit.": "Monitoreo preventivo y auditoría periódica de parches.",
    "Intermediate perimeter restriction and a scheduled fix (within 30 days).": "Restricción perimetral intermedia y corrección programada (dentro de 30 días).",
    "Apply urgent patches in the next maintenance window and restrict access meanwhile.": "Aplica parches urgentes en la próxima ventana de mantenimiento y restringe el acceso mientras tanto.",
    "IMMEDIATE ISOLATION of the resource. Emergency mitigation is active.": "AISLAMIENTO INMEDIATO del recurso. Mitigación de emergencia activa.",
    "Manual analysis by the security team.": "Análisis manual por el equipo de seguridad.",
    "List pending security updates": "Listar actualizaciones de seguridad pendientes",
    "Scan container images on push (AWS ECR)": "Escanear imágenes de contenedor al subirlas (AWS ECR)",
    "Rate-limit the service port (example: 8080)": "Limitar la tasa del puerto del servicio (ejemplo: 8080)",
    "Enable a managed WAF rule group in front of the app (AWS WAF)": "Habilitar un grupo de reglas WAF administrado frente a la app (AWS WAF)",
    "Upgrade only the affected package": "Actualizar solo el paquete afectado",
    "Restrict the resource to the corporate VPN range (AWS Security Group)": "Restringir el recurso al rango de la VPN corporativa (AWS Security Group)",
    "Stop the affected service to halt exploitation": "Detener el servicio afectado para frenar la explotación",
    "Quarantine the instance with an isolated Security Group (AWS)": "Poner la instancia en cuarentena con un Security Group aislado (AWS)",
    "Rotate the exposed credential (AWS IAM example)": "Rotar la credencial expuesta (ejemplo con AWS IAM)",
    "Purge the secret from git history": "Eliminar el secreto del historial de git",
    "Block common injection payloads at the edge (AWS WAF managed rules)": "Bloquear payloads comunes de inyección en el borde (reglas administradas de AWS WAF)",
    "Run the app with a least-privilege database user": "Ejecutar la app con un usuario de base de datos de mínimo privilegio",
    "Run the container read-only, non-root, without extra capabilities": "Ejecutar el contenedor en solo lectura, sin root y sin capabilities extra",
    "Add baseline security headers at the reverse proxy": "Agregar cabeceras de seguridad básicas en el proxy inverso",
    "Configure manual alerts in the cloud console": "Configurar alertas manuales en la consola cloud",
    "No automated script is available for this severity.": "No hay un script automatizado para esta severidad.",
}
STATE_ES = {"cerrada": "cerrada", "mitigada": "mitigada"}
