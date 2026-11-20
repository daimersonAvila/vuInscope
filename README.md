# VulnScope

**Registro y analizador de vulnerabilidades.**
Sube un proyecto comprimido y VulnScope te muestra **dónde están los errores, qué tan probable es un ataque, si el proyecto aprueba el Quality Gate y cómo solucionarlo**. El resultado se puede descargar como reporte en PDF.

Evolución del proyecto del Grupo 4 — *Cloud Computing para el desarrollo de software*.

---

## Tabla de contenido

- [Funcionalidades](#funcionalidades)
- [Lenguajes y archivos analizados](#lenguajes-y-archivos-analizados)
- [Quality Gate](#quality-gate)
- [Reporte en PDF](#reporte-en-pdf)
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
| Carga de proyectos comprimidos (`.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`) **o de un solo archivo de código** (`main.c`, `App.java`, `app.py`…) | `adapters/outbound/archive_reader.py` |
| Detección de vulnerabilidades (59 reglas, con archivo y línea), incluidas 13 reglas de **C/C++** y 9 de **Java** | `domain/rules.py`, `domain/scanner.py` |
| **Quality Gate**: veredicto Aprobado / Aprobado con advertencias / Reprobado según la severidad de los hallazgos | `domain/gate.py` |
| **Reporte en PDF** con encabezado, resumen, tabla de hallazgos y tarjetas por severidad | Botón "Descargar reporte (PDF)" · `static/css/site.css` (sección 12) |
| Reporte en JSON | Botón "Descargar reporte (JSON)" |
| **Revisión de código con IA**: el modelo lee los archivos y reporta vulnerabilidades por su cuenta (cualquier lenguaje), validando su salida | `application/ai_review.py` |
| Cómo solucionarlo (fix + ejemplo por hallazgo) + asistente de IA | `application/use_cases.py` (`AIAdvisor`) |
| IA con API pública, sin clave (Pollinations.AI, configurable) | `adapters/outbound/ai_http.py` |
| Cadena de Markov: riesgo de la ruta de ataque (puntaje 0–100 y ruta más probable) | `domain/markov.py`, `domain/risk.py` |
| Playbooks de mitigación (simulación) | `domain/playbooks.py` |
| Bloqueo de duplicados exactos al crear (HTTP 409 + aviso) | `RegistryService`, índice `UNIQUE` en SQLite |
| Frontend en inglés por defecto + selector **EN / ES** | `static/js/i18n.js`, `/api/rule-text?lang=es` |
| 6 modos de color (Auto, Light, Dark, High contrast, Ocean, Sand) | Barra superior · `static/css/site.css` |
| CSP estricta, sin scripts inline | `adapters/inbound/http/app.py` |

---

## Lenguajes y archivos analizados

| Nivel de cobertura | Qué detecta | Lenguajes / archivos |
|---|---|---|
| **Reglas específicas** | Inyección SQL y de comandos, deserialización insegura, XXE, uso de funciones peligrosas, etc. | Python · JavaScript / TypeScript · PHP · **Java** (también Kotlin y Scala) · C / C++ |
| **Reglas generales** | Secretos escritos en el código, hashes y cifrados débiles, TLS desactivado, CORS abierto, URLs `http://` | Todo lo anterior, más Go, Ruby, Rust y C# |
| **Infraestructura y configuración** | Configuraciones riesgosas de nube y contenedores, secretos en archivos de configuración | Terraform, Dockerfile, YAML, JSON, scripts de shell, `.env`, `.properties`, `.toml` |
| **Plantillas** | Puntos de XSS | HTML y plantillas Jinja |
| **Nombres de archivo** | Llaves privadas, `.env` y bases de datos incluidas en el proyecto | Cualquier archivo |
| **Revisión con IA (opcional)** | Vulnerabilidades en código que las reglas no cubren | Cualquier lenguaje |

Las carpetas de dependencias (`node_modules`, `.venv`, `.git`, etc.) se omiten.

---

## Quality Gate

Después de cada análisis, la consola muestra un banner con el veredicto del proyecto según el número de hallazgos por severidad:

| Veredicto | Condición |
|---|---|
| **Reprobado** | Algún hallazgo **crítico**, o **más de 2** altos |
| **Aprobado con advertencias** | Algún hallazgo **alto**, o **más de 5** medios |
| **Aprobado** | Ninguna de las condiciones anteriores |

El banner indica qué condición se superó (por ejemplo, "4 alta (límite 2)").

**Para cambiar los límites:** edita `FAIL_LIMITS` y `WARN_LIMITS` en `src/vulnscope/domain/gate.py`. El texto explicativo del banner está en `templates/app.html` y su traducción en `static/js/i18n.js`.

> El Quality Gate usa solo el conteo por severidad. Un proyecto "Aprobado" no está garantizado como seguro: el análisis es estático y puede tener falsos negativos.

---

## Reporte en PDF

El botón **Descargar reporte (PDF)** abre el diálogo de impresión del navegador con un diseño preparado para papel. Para guardarlo, elige **Destino: Guardar como PDF**.

El informe incluye:

1. **Encabezado:** logo, título, nombre del archivo analizado y fecha.
2. **Página 1:** veredicto del Quality Gate, puntaje de riesgo, conteo por severidad y ruta de ataque.
3. **Página 2:** tabla resumen de hallazgos (severidad, hallazgo y ubicación).
4. **Páginas siguientes:** cada hallazgo con su código, la línea marcada y cómo solucionarlo.
5. **Pie de página:** número de página (en navegadores recientes).

El PDF siempre se imprime con colores claros sobre papel blanco, sin importar el modo de color elegido. El diseño está en la sección `12. IMPRESIÓN / PDF` de `static/css/site.css` (bloque `@media print`) y la acción del botón en `static/js/app.js`.

---

## Inicio rápido

```bash
# 1. Crear y activar un entorno virtual
python3 -m venv .venv
source .venv/bin/activate          # en fish: source .venv/bin/activate.fish
                                   # en Windows: .venv\Scripts\Activate.ps1

# 2. Instalar dependencias
pip install -r requirements.txt -r requirements-dev.txt

# 3. Iniciar la app
python wsgi.py
```

Abre <http://127.0.0.1:5000>. En desarrollo las credenciales son `admin` / `demo123`.

Comandos opcionales:

```bash
python scripts/seed.py     # cargar datos de ejemplo
python -m pytest           # ejecutar las pruebas
```

---

## Arquitectura hexagonal

```
domain/         Reglas puras (modelos, scanner, Quality Gate, Markov, playbooks,
                redacción) — sin Flask ni SQL
application/    Puertos (ports.py), casos de uso (use_cases.py) y revisión con IA
                (ai_review.py)
adapters/
  inbound/http  Flask: rutas, cabeceras de seguridad, rate limit
  outbound/     SQLite, lector seguro de archivos, cliente IA, JWT/hash
bootstrap.py    Único lugar donde se conectan adaptadores con puertos
```

Cambiar SQLite por Postgres, o Pollinations por otro proveedor de IA, solo requiere **escribir un adaptador nuevo**: el dominio no se toca.

---

## Idioma y modos de color

El selector **EN | ES** y el menú de color están en la barra superior de la landing y de la consola. La elección se guarda en el navegador (`localStorage`).

El idioma cambia los textos de la interfaz, los nombres y soluciones de cada regla, los playbooks, el Quality Gate, el encabezado del PDF y la respuesta de la IA (se le pide en español).

**Para añadir un idioma:**

1. Agrega las claves en `ES` dentro de `static/js/i18n.js`.
2. Agrega el texto de las reglas en `domain/i18n_es.py`.

**Al agregar una regla nueva** en `domain/rules.py`, agrega también su traducción en `RULE_TEXT_ES` (`domain/i18n_es.py`). Sin ella, el endpoint `/api/rule-text?lang=es` falla.

> La página principal muestra el total de reglas calculado automáticamente. Su traducción al español en `i18n.js` incluye ese número (`"59 checks cover…"`), así que si el total cambia hay que actualizarlo ahí también.

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
   > El archivo `.env` **nunca** se sube al repositorio: créalo directamente en el servidor.

2. Levanta el contenedor (sin root, sistema de archivos de solo lectura, sin capabilities):

   ```bash
   docker compose up -d --build
   ```

3. Coloca un proxy inverso con TLS delante (Caddy, Nginx o ALB).

**Caché de archivos estáticos:** `SEND_FILE_MAX_AGE_DEFAULT` en `adapters/inbound/http/app.py` controla cuánto guarda el navegador `app.js`, `site.css` e `i18n.js` (3600 s en producción). Durante el desarrollo, bájalo a `0` o usa *Disable cache* en las herramientas del navegador para ver los cambios al instante.

---

## Seguridad implementada

**Cabeceras y navegador**
- CSP estricta sin inline (`script-src 'self'`), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP.
- Salida de la IA y datos del análisis mostrados solo con `textContent`.

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
- **Revisión con IA:** revisa como máximo 10 fragmentos (~12 000 caracteres c/u) por análisis, prioriza los archivos con hallazgos previos y tiene un presupuesto de 50 s. Si el servicio no responde, la interfaz lo indica en vez de mostrar ceros sin explicación. Los hallazgos de la IA se validan (línea real, severidad y CWE permitidos), pero pueden ser falsos positivos.
- **Quality Gate:** los límites son fijos en el código (`domain/gate.py`) y no se configuran desde la interfaz. Un veredicto "Aprobado" no prueba que el código sea seguro.
- **Reporte en PDF:** se genera con la impresión del navegador, así que su aspecto depende de este. Chrome y Edge recientes dan el mejor resultado (el número de página en el pie requiere Chrome 131 o superior). Incluye como máximo los primeros 300 hallazgos y respeta el filtro de severidad activo.
- **Cobertura de lenguajes:** las reglas específicas cubren Python, JavaScript/TypeScript, PHP, Java y C/C++. En otros lenguajes solo aplican las reglas generales; para ellos conviene usar la revisión con IA.
- **Escalado:** el rate limit y el bloqueo de cuenta viven en memoria (1 worker). Con varios workers o instancias usa Redis o el limitador del proxy.
- **Usuarios:** hay un único administrador definido por configuración. SQLite es suficiente para un grupo pequeño.
- **Análisis estático:** se basa en patrones, puede dar falsos positivos o negativos y no sustituye una auditoría.

---

## Cambios respecto al proyecto original

**Nuevo en la versión actual**
- **Quality Gate** con veredicto Aprobado / Aprobado con advertencias / Reprobado (`domain/gate.py`).
- **9 reglas de Java** (`JAV001`–`JAV009`): SQL concatenado, comandos del sistema, deserialización, números aleatorios predecibles, TLS desactivado, XXE, `printStackTrace`, `catch` demasiado amplio y contraseña en la URL de JDBC.
- **Reporte en PDF** con diseño propio para impresión.
- Se **retiró el pronóstico de ciclo de vida** (cadena de Markov sobre el historial de estados). La cadena de Markov se conserva para el riesgo de la ruta de ataque.

**Corregido (versión anterior)**
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
- La respuesta de `/api/scan` incluye ahora el campo `gate`.

**Duplicados**
- Un duplicado "exacto" tiene mismos título, identificador, severidad, estado y puntaje (tras quitar espacios en los extremos).
- También se bloquea al **editar** un registro hasta igualar otro.

---

## Autores

Grupo 4 — Cloud Computing para el desarrollo de software: Daimerson Avila, Juan Bonilla, Sofia Siza, Sebastian Cetina.