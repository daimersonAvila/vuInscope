# VulnScope

**Registro y analizador de vulnerabilidades.**
Sube un proyecto comprimido y VulnScope te muestra **dónde están los errores, qué tan probable es un ataque y cómo solucionarlo**.

Evolución del proyecto del Grupo 4 — *Cloud Computing para el desarrollo de software*.

---

## Tabla de contenido

- [Funcionalidades](#funcionalidades)
- [Inicio rápido](#inicio-rápido)
- [Arquitectura hexagonal](#arquitectura-hexagonal)
- [Idioma y modos de color](#idioma-y-modos-de-color)
- [Despliegue en producción](#despliegue-en-producción)
- [Seguridad implementada](#seguridad-implementada)
- [Limitaciones](#limitaciones)
- [Cambios respecto al proyecto original](#cambios-respecto-al-proyecto-original)

---

## Funcionalidades

| Funcionalidad | Dónde está |
|---|---|
| Landing que explica el proyecto + botón "Launch console" | `/` → `/app` |
| Carga de proyectos comprimidos (`.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`) **o de un solo archivo de código** (`main.c`, `app.py`…) | `adapters/outbound/archive_reader.py` |
| Detección de vulnerabilidades (50 reglas, con archivo y línea), incluidas 13 reglas de **C/C++** (`gets`, `strcpy`, `sprintf`, `printf(var)`, `system`…) | `domain/rules.py`, `domain/scanner.py` |
| **Revisión de código con IA**: el modelo lee los archivos y reporta vulnerabilidades por su cuenta (cualquier lenguaje), validando su salida | `application/ai_review.py` |
| Cómo solucionarlo (fix + ejemplo por hallazgo) + asistente de IA | `application/use_cases.py` (`AIAdvisor`) |
| IA con API pública, sin clave (Pollinations.AI, configurable) | `adapters/outbound/ai_http.py` |
| Cadenas de Markov: riesgo de ataque y ciclo de vida | `domain/markov.py`, `domain/risk.py`, `LifecycleService` |
| Playbooks de mitigación (simulación) | `domain/playbooks.py` |
| Bloqueo de duplicados exactos al crear (HTTP 409 + aviso) | `RegistryService`, índice `UNIQUE` en SQLite |
| Frontend en inglés por defecto + selector **EN / ES** | `static/js/i18n.js`, `/api/rule-text?lang=es` |
| 6 modos de color (Auto, Light, Dark, High contrast, Ocean, Sand) | Barra superior · `static/css/site.css` |
| CSP estricta, sin scripts inline | `adapters/inbound/http/app.py` |

---

## Inicio rápido

```bash
# 1. Instalar dependencias
pip install -r requirements.txt -r requirements-dev.txt

# 2. Iniciar la app
python wsgi.py
```

Abre <http://127.0.0.1:5000>. En desarrollo las credenciales son `admin` / `demo123`.

Comandos opcionales:

```bash
python scripts/seed.py     # cargar datos de ejemplo
python -m pytest           # ejecutar las 54 pruebas
```

---

## Arquitectura hexagonal

```
domain/         Reglas puras (modelos, scanner, Markov, playbooks, redacción)
                — sin Flask ni SQL
application/    Puertos (ports.py) y casos de uso (use_cases.py)
adapters/
  inbound/http  Flask: rutas, cabeceras de seguridad, rate limit
  outbound/     SQLite, lector seguro de archivos, cliente IA, JWT/hash
bootstrap.py    Único lugar donde se conectan adaptadores con puertos
```

Cambiar SQLite por Postgres, o Pollinations por otro proveedor de IA, solo requiere **escribir un adaptador nuevo**: el dominio no se toca.

---

## Idioma y modos de color

El selector **EN | ES** y el menú de color están en la barra superior de la landing y de la consola. La elección se guarda en el navegador (`localStorage`).

El idioma cambia los textos de la interfaz, los nombres y soluciones de cada regla, los playbooks y la respuesta de la IA (se le pide en español).

**Para añadir un idioma:**

1. Agrega las claves en `ES` dentro de `static/js/i18n.js`.
2. Agrega el texto de las reglas en `domain/i18n_es.py`.

---

## Despliegue en producción

1. Copia la configuración y complétala:

   ```bash
   cp .env.example .env
   python scripts/hash_password.py   # genera ADMIN_PASSWORD_HASH
   ```

   | Variable | Descripción |
   |---|---|
   | `APP_ENV` | Usa `production` para activar las validaciones estrictas |
   | `SECRET_KEY` | Clave para firmar los JWT |
   | `ADMIN_PASSWORD_HASH` | Hash de la contraseña del administrador |
   | `ALLOWED_HOSTS` | Hosts permitidos |
   | `TRUSTED_PROXIES` | Usa `1` si hay un proxy inverso delante |
   | `AI_URL` / `AI_MODEL` | Endpoint y modelo del proveedor de IA |

   > Con `APP_ENV=production` la app **no arranca** si falta `SECRET_KEY`, `ADMIN_PASSWORD_HASH` o `ALLOWED_HOSTS`.

2. Levanta el contenedor (sin root, sistema de archivos de solo lectura, sin capabilities):

   ```bash
   docker compose up -d --build
   ```

3. Coloca un proxy inverso con TLS delante (Caddy, Nginx o ALB).

---

## Seguridad implementada

**Cabeceras y navegador**
- CSP estricta sin inline (`script-src 'self'`), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP.
- Salida de la IA mostrada solo con `textContent`.

**Autenticación y acceso**
- JWT HS256 con `exp`/`iss`/`iat`; contraseñas guardadas solo como hash salado.
- Rate limit por endpoint y bloqueo de cuenta tras 5 fallos.
- Validación de `Host`.

**Archivos subidos**
- Límites de tamaño, número de entradas y descompresión (protección contra zip-slip, symlinks y zip/tar bombs).
- Detección de formato por *magic bytes*.
- El contenido subido nunca se ejecuta ni se escribe a disco.

**Datos y IA**
- Secretos enmascarados antes de mostrarse o enviarse a la IA.
- Mitigación de *prompt injection* (el código se marca como dato no confiable).
- SQL parametrizado.
- Errores genéricos hacia el cliente (detalles solo en logs).

---

## Limitaciones

- **IA pública:** la llamada real a `text.pollinations.ai` no pudo probarse en el entorno de desarrollo por falta de salida a Internet. Se probó con un proveedor simulado y con el *fallback* local. Verifica el endpoint y modelo vigentes y ajusta `AI_URL` / `AI_MODEL`. Si el servicio falla, la app responde con guía integrada y no se rompe.
- **Privacidad:** el código enviado a un servicio público sale de tu control. La revisión con IA envía el código fuente (con los secretos ya enmascarados) y solo ocurre si marcas la casilla *Analizar el código con IA*. Para código privado déjala desactivada o usa `AI_ENABLED=0`.
- **Revisión con IA:** revisa como máximo 10 fragmentos (~12 000 caracteres c/u) por análisis, prioriza los archivos con hallazgos previos y tiene un presupuesto de 50 s. Si el servicio no responde, la interfaz lo indica ("la IA no respondió, solo se ejecutaron las reglas integradas") en vez de mostrar ceros sin explicación. Los hallazgos de la IA se validan (línea real, severidad y CWE permitidos), pero pueden ser falsos positivos.
- **Escalado:** el rate limit y el bloqueo de cuenta viven en memoria (1 worker). Con varios workers o instancias usa Redis o el limitador del proxy.
- **Usuarios:** hay un único administrador definido por configuración. SQLite es suficiente para un grupo pequeño.
- **Análisis estático:** se basa en patrones, puede dar falsos positivos o negativos y no sustituye una auditoría.

---

## Cambios respecto al proyecto original

**Corregido (versión actual)**
- Analizar un proyecto/archivo `.c` daba todo en cero: el escáner no tenía ninguna regla para C/C++ y la IA solo "explicaba" hallazgos ya existentes (con 0 hallazgos ni siquiera se llamaba). Ahora hay reglas de C/C++ y una revisión real del código con IA; además se aceptan `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx` y archivos sueltos.
- Los comentarios en C ya no ocultan código real (`*p = x;`, `--i;`, `#define …`).
- Timeout de gunicorn subido a 120 s por la revisión con IA.

**Corregido (versión inicial)**
- `SECRET_KEY` y contraseña en texto plano.
- `debug=True`.
- Respuesta 401 del login con clave `token`.
- `puntaje_cvss = NaN` aceptado.
- Markov que devolvía valores enormes si "cerrada" era inalcanzable.
- `.db` y `.venv` dentro del repositorio.

**Compatibilidad de la API**
- Se conservan rutas y campos (`/login`, `/api/vulnerabilidades`, `titulo`, `cve_codigo`…).
- El identificador acepta también `CWE-NNN`.
- El playbook ahora devuelve `{strategy, steps[]}` en inglés.

**Duplicados**
- Un duplicado "exacto" tiene mismos título, identificador, severidad, estado y puntaje (tras quitar espacios en los extremos).
- También se bloquea al **editar** un registro hasta igualar otro.

---

## Autores

Grupo 4 — Cloud Computing para el desarrollo de software.
