/* Language (EN/ES) + color-mode preferences. Loaded in <head> so the theme applies before first paint.
   Translations are keyed by the English source text. Nothing is inserted as HTML. */
(() => {
  'use strict';
  const THEMES = ['auto', 'light', 'dark', 'contrast', 'ocean', 'sand'];
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };
  let lang = store.get('vs_lang') === 'es' ? 'es' : 'en';
  let theme = THEMES.includes(store.get('vs_theme')) ? store.get('vs_theme') : 'auto';
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.lang = lang;

  const ES = {
    "37 checks cover hard-coded secrets, SQL and command injection, unsafe deserialisation, weak cryptography, XSS sinks, debug flags and risky cloud or container settings. Every finding points to a file and line.": "37 controles cubren secretos escritos en el código, inyección SQL y de comandos, deserialización insegura, criptografía débil, puntos de XSS, banderas de debug y configuraciones riesgosas de nube o contenedores. Cada hallazgo señala un archivo y una línea.",
    "A Markov chain learns how vulnerabilities move between statuses from the registry history and predicts what happens next.": "Una cadena de Markov aprende cómo cambian de estado las vulnerabilidades a partir del historial del registro y predice qué sigue.",
    "A Markov chain turns your findings into an attack path — from first contact to full compromise — and gives a 0–100 risk score with the most probable route highlighted.": "Una cadena de Markov convierte tus hallazgos en una ruta de ataque —del primer contacto al compromiso total— y da un puntaje de riesgo de 0 a 100 con la ruta más probable resaltada.",
    "AI features send a few redacted lines around each finding to a public AI service. Secrets are masked first. Leave this off for private code.": "Las funciones de IA envían unas pocas líneas enmascaradas alrededor de cada hallazgo a un servicio público de IA. Los secretos se ocultan antes. Déjalo desactivado para código privado.",
    "Accepts .zip, .tar, .tar.gz, .tar.bz2 and .tar.xz up to 25 MB. No account needed to scan.": "Acepta .zip, .tar, .tar.gz, .tar.bz2 y .tar.xz de hasta 25 MB. No necesitas cuenta para escanear.",
    "Actions": "Acciones",
    "Add all to registry": "Agregar todo al registro",
    "Add an AI remediation plan after the scan": "Agregar un plan de remediación con IA después del escaneo",
    "Analyze project": "Analizar proyecto",
    "Anyone who types <code>' OR '1'='1</code> as a name can read the whole table. Pass the value as a parameter so the driver escapes it.": "Cualquiera que escriba <code>' OR '1'='1</code> como nombre puede leer toda la tabla. Pasa el valor como parámetro para que el controlador lo escape.",
    "Archives are processed in memory and discarded after the response. When you ask the AI for help, only a few redacted lines around a finding are sent to a public AI service, and only after you click. Do not upload code you are not allowed to share with third parties.": "Los archivos se procesan en memoria y se descartan tras la respuesta. Cuando pides ayuda a la IA, solo se envían unas pocas líneas enmascaradas alrededor de un hallazgo a un servicio público de IA, y únicamente después de que hagas clic. No subas código que no puedas compartir con terceros.",
    "Attack-path risk": "Riesgo de la ruta de ataque",
    "Auto": "Automático",
    "Built to be exposed to the internet": "Diseñado para estar expuesto a internet",
    "CVE-2024-12345 or CWE-89": "CVE-2024-12345 o CWE-89",
    "CVSS": "CVSS",
    "CVSS score (0–10)": "Puntaje CVSS (0–10)",
    "Cancel": "Cancelar",
    "Check a project now": "Revisa un proyecto ahora",
    "Close": "Cerrar",
    "Closed": "Cerrada",
    "Color mode": "Modo de color",
    "Console sections": "Secciones de la consola",
    "Create record": "Crear registro",
    "Critical": "Crítica",
    "Dark": "Oscuro",
    "Download report (JSON)": "Descargar reporte (JSON)",
    "Drop a compressed project. It is unpacked in memory with limits against zip bombs and path tricks; dependency folders like <code>node_modules</code> and <code>.venv</code> are skipped.": "Suelta un proyecto comprimido. Se descomprime en memoria con límites contra zip bombs y trucos de rutas; las carpetas de dependencias como <code>node_modules</code> y <code>.venv</code> se omiten.",
    "Each finding carries a fix and a corrected example. Ask the AI assistant for a tailored explanation of any finding, written for the exact lines in your code.": "Cada hallazgo trae una solución y un ejemplo corregido. Pide al asistente de IA una explicación a medida de cualquier hallazgo, escrita para las líneas exactas de tu código.",
    "Everyone can read the log. Signing in is required to add, change or delete records. An identical record cannot be created twice.": "Cualquiera puede leer el registro. Para agregar, cambiar o borrar registros hay que iniciar sesión. Un registro idéntico no se puede crear dos veces.",
    "Filter by file or rule": "Filtrar por archivo o regla",
    "Filter findings": "Filtrar hallazgos",
    "Findings": "Hallazgos",
    "Findings are weighted by severity and fed into the attack-path chain to compute risk and the likeliest route to compromise.": "Los hallazgos se ponderan por severidad y alimentan la cadena de la ruta de ataque para calcular el riesgo y la ruta más probable al compromiso.",
    "Fix": "Corregir",
    "Generic error messages; details stay in server logs": "Mensajes de error genéricos; los detalles quedan en los logs del servidor",
    "Get AI remediation plan": "Obtener plan de remediación con IA",
    "HSTS, frame, referrer, MIME-sniffing and permissions headers on every response": "Cabeceras HSTS, de frames, referrer, MIME-sniffing y permisos en cada respuesta",
    "High": "Alta",
    "High contrast": "Alto contraste",
    "How a scan works": "Cómo funciona un escaneo",
    "How it works": "Cómo funciona",
    "How likely an attack is": "Qué tan probable es un ataque",
    "How to solve it": "Cómo solucionarlo",
    "Identifier": "Identificador",
    "In review": "En revisión",
    "Language": "Idioma",
    "Launch console": "Abrir consola",
    "Lifecycle forecast": "Pronóstico de ciclo de vida",
    "Light": "Claro",
    "Low": "Baja",
    "Medium": "Media",
    "Mitigated": "Mitigada",
    "Mitigation playbooks with ready-to-review commands for AWS, Linux and Kubernetes. They are simulation only: VulnScope never executes anything.": "Playbooks de mitigación con comandos listos para revisar en AWS, Linux y Kubernetes. Son solo simulación: VulnScope nunca ejecuta nada.",
    "Model": "Modelar",
    "Most likely route to compromise": "Ruta más probable al compromiso",
    "Needed to change the registry. Scanning and AI help stay open.": "Necesario para modificar el registro. El escaneo y la ayuda de IA siguen abiertos.",
    "Ocean": "Océano",
    "One scan, five answers": "Un escaneo, cinco respuestas",
    "Open": "Abierta",
    "Parameterised SQL and a unique constraint behind the duplicate guard": "SQL parametrizado y una restricción única detrás del bloqueo de duplicados",
    "Password": "Contraseña",
    "Primary": "Principal",
    "Rate limits on every endpoint and a lockout after repeated failed logins": "Límites de tasa en cada endpoint y bloqueo tras varios inicios de sesión fallidos",
    "Register findings in the vulnerability log. A second Markov chain learns from your status changes and forecasts how many steps remain until each one is closed. Exact duplicates are refused with a clear notice.": "Registra los hallazgos en el log de vulnerabilidades. Una segunda cadena de Markov aprende de tus cambios de estado y pronostica cuántos pasos faltan para cerrar cada una. Los duplicados exactos se rechazan con un aviso claro.",
    "Registry": "Registro",
    "Remediation plan": "Plan de remediación",
    "Rules read each text file line by line. Secrets are masked the moment they are found, so they never appear in results or reach the AI.": "Las reglas leen cada archivo de texto línea por línea. Los secretos se enmascaran al encontrarlos, así que nunca aparecen en los resultados ni llegan a la IA.",
    "Run simulation": "Ejecutar simulación",
    "SQL injection": "Inyección SQL",
    "Sand": "Arena",
    "Scan": "Escanear",
    "Scan a project": "Escanear un proyecto",
    "Security": "Seguridad",
    "See how a scan works": "Ver cómo funciona un escaneo",
    "Severity": "Severidad",
    "Show the transition matrix behind this estimate": "Mostrar la matriz de transición detrás de esta estimación",
    "Sign in": "Iniciar sesión",
    "Sign out": "Cerrar sesión",
    "Signed, expiring tokens; passwords stored only as salted hashes": "Tokens firmados y con expiración; contraseñas guardadas solo como hashes con sal",
    "Simulate a vulnerability": "Simular una vulnerabilidad",
    "Simulation only — review before running anything. Identifiers are placeholders.": "Solo simulación: revisa antes de ejecutar cualquier cosa. Los identificadores son marcadores de ejemplo.",
    "Start from": "Empezar desde",
    "Status": "Estado",
    "Strict Content-Security-Policy with no inline scripts or styles": "Content-Security-Policy estricta, sin scripts ni estilos en línea",
    "The registry is empty. Create a record above or scan a project and add its findings.": "El registro está vacío. Crea un registro arriba o escanea un proyecto y agrega sus hallazgos.",
    "Title": "Título",
    "Upload": "Subir",
    "Upload a compressed project and get findings with file and line, a risk estimate and fixes. The archive is read in memory and never executed.": "Sube un proyecto comprimido y obtén hallazgos con archivo y línea, una estimación de riesgo y soluciones. El archivo se lee en memoria y nunca se ejecuta.",
    "Upload a project archive. VulnScope shows where it is vulnerable, how likely an attacker is to get through, and how to fix each problem.": "Sube un proyecto comprimido. VulnScope muestra dónde es vulnerable, qué tan probable es que un atacante entre y cómo arreglar cada problema.",
    "Upload size, entry-count and decompression limits": "Límites de tamaño de subida, número de entradas y descompresión",
    "Upload your project.<br>See where it breaks and how to fix it.": "Sube tu proyecto.<br>Mira dónde falla y cómo arreglarlo.",
    "Username": "Usuario",
    "VulnScope console": "Consola de VulnScope",
    "VulnScope reads a zipped codebase, marks every insecure line, estimates how an attacker would chain those flaws together, and explains each fix in plain English. Nothing you upload is ever run.": "VulnScope lee un código comprimido, marca cada línea insegura, estima cómo encadenaría un atacante esas fallas y explica cada solución en lenguaje claro. Nada de lo que subes se ejecuta jamás.",
    "VulnScope — find the flaw, see the fix": "VulnScope — encuentra la falla, mira la solución",
    "VulnScope — vulnerability registry and analyzer. Cloud Computing for Software Development, Group 4: Daimerson Avila, Juan Bonilla, Sofia Siza, Sebastian Cetina.": "VulnScope — registro y analizador de vulnerabilidades. Cloud Computing para el desarrollo de software, Grupo 4: Daimerson Avila, Juan Bonilla, Sofia Siza, Sebastian Cetina.",
    "Vulnerability registry": "Registro de vulnerabilidades",
    "What it does": "Qué hace",
    "What to do in the cloud": "Qué hacer en la nube",
    "Where it is in its lifecycle": "En qué punto de su ciclo de vida está",
    "Where the errors are": "Dónde están los errores",
    "Work through the list by severity, ask the AI for help, copy a playbook, or add everything to the registry in one click.": "Recorre la lista por severidad, pide ayuda a la IA, copia un playbook o agrega todo al registro con un clic.",
    "Your code stays yours": "Tu código sigue siendo tuyo",
    "Sign in to continue.": "Inicia sesión para continuar.",
    "Cannot reach the server. Check your connection.": "No se pudo conectar con el servidor. Revisa tu conexión.",
    "Signed out.": "Sesión cerrada.",
    "Signed in.": "Sesión iniciada.",
    "Signed in as {user}": "Sesión de {user}",
    "Too many attempts. Wait a few minutes and try again.": "Demasiados intentos. Espera unos minutos e inténtalo de nuevo.",
    "Wrong username or password.": "Usuario o contraseña incorrectos.",
    "Mitigation playbook": "Playbook de mitigación",
    "Drop a project archive here, or choose a file": "Suelta aquí un proyecto comprimido o elige un archivo",
    "{size} MB — ready to analyze": "{size} MB — listo para analizar",
    ".zip, .tar, .tar.gz, .tar.bz2 or .tar.xz — up to 25 MB": ".zip, .tar, .tar.gz, .tar.bz2 o .tar.xz — hasta 25 MB",
    "That file is {size} MB. The limit is {max} MB.": "Ese archivo pesa {size} MB. El límite es {max} MB.",
    "Unpacking and scanning…": "Descomprimiendo y escaneando…",
    "Low risk": "Riesgo bajo",
    "Moderate risk": "Riesgo moderado",
    "High risk": "Riesgo alto",
    "Critical risk": "Riesgo crítico",
    "Risk score {n} out of 100": "Puntaje de riesgo {n} de 100",
    "No findings, so the model sees no route to compromise.": "Sin hallazgos, el modelo no ve ninguna ruta al compromiso.",
    "Probability that an attacker who reaches the app ends up with a compromise, given the weaknesses found.": "Probabilidad de que un atacante que llega a la app logre un compromiso, dadas las debilidades encontradas.",
    "{a} of {b} files read": "{a} de {b} archivos leídos",
    "skipped folders: {list}": "carpetas omitidas: {list}",
    "{n} files over 1 MB skipped": "{n} archivos de más de 1 MB omitidos",
    "{n} unsafe entries ignored": "{n} entradas inseguras ignoradas",
    "archive truncated at the entry limit": "archivo truncado por el límite de entradas",
    "Attacker reaches the app": "El atacante llega a la app",
    "Input injection": "Inyección de entrada",
    "Credential theft": "Robo de credenciales",
    "Code execution": "Ejecución de código",
    "Data exposure / misconfiguration": "Exposición de datos / mala configuración",
    "System compromised": "Sistema comprometido",
    "Attack contained": "Ataque contenido",
    "No route found": "No se encontró ruta",
    "All": "Todas",
    "From \\ to": "De \\ a",
    "({n} of {m})": "({n} de {m})",
    "No findings match this filter.": "Ningún hallazgo coincide con este filtro.",
    "No issues found by the built-in rules. This does not prove the code is safe.": "Las reglas integradas no encontraron problemas. Eso no prueba que el código sea seguro.",
    "Showing the first 300 of {n}. Narrow the filter to see the rest.": "Mostrando los primeros 300 de {n}. Acota el filtro para ver el resto.",
    "How to fix": "Cómo solucionarlo",
    "Explain with AI": "Explicar con IA",
    "Cloud playbook": "Playbook de nube",
    "Add to registry": "Agregar al registro",
    "Asking…": "Consultando…",
    "Explanation": "Explicación",
    "Built-in guidance": "Guía integrada",
    "AI: {engine}": "IA: {engine}",
    "The public AI service did not answer, so this is the built-in guidance.": "El servicio público de IA no respondió, así que esta es la guía integrada.",
    "Asking the AI for a remediation plan…": "Pidiendo un plan de remediación a la IA…",
    "The public AI service is unavailable right now, so built-in guidance is shown.": "El servicio público de IA no está disponible ahora, así que se muestra la guía integrada.",
    "Nothing added: an identical record is already in the registry.": "No se agregó nada: ya existe un registro idéntico en el registro.",
    "Nothing added: {n} identical records are already in the registry.": "No se agregó nada: ya existen {n} registros idénticos.",
    "Added {n} to the registry.": "Se agregaron {n} al registro.",
    "Skipped 1 identical duplicate.": "Se omitió 1 duplicado idéntico.",
    "Skipped {n} identical duplicates.": "Se omitieron {n} duplicados idénticos.",
    "Status of record {id}": "Estado del registro {id}",
    "Playbook": "Playbook",
    "Delete": "Eliminar",
    "Existing record: #{id}.": "Registro existente: #{id}.",
    "Delete record #{id}?": "¿Eliminar el registro #{id}?",
    "Status updated.": "Estado actualizado.",
    "Record deleted.": "Registro eliminado.",
    "Record created.": "Registro creado.",
    "Duplicate blocked: an identical record already exists.": "Duplicado bloqueado: ya existe un registro idéntico.",
    "Learned entirely from your registry history.": "Aprendido por completo del historial de tu registro.",
    "Learned from your registry history, blended with a built-in prior because there are few observed transitions.": "Aprendido del historial de tu registro y combinado con una referencia integrada porque hay pocas transiciones observadas.",
    "Built-in prior only: the registry has no status history yet.": "Solo la referencia integrada: el registro aún no tiene historial de estados.",
    "Transitions observed: {n}.": "Transiciones observadas: {n}.",
    "From {state}": "Desde {state}",
    "Never closes": "Nunca se cierra",
    "{n} steps": "{n} pasos",
    "to reach Closed. Most likely next: {next}.": "para llegar a Cerrada. Lo más probable a continuación: {next}.",
    "Not found": "No encontrado",
    "Method not allowed": "Método no permitido",
    "Internal server error": "Error interno del servidor",
    "Invalid credentials": "Credenciales inválidas",
    "Invalid token": "Token inválido",
    "Token expired": "Token expirado",
    "Use 'Authorization: Bearer <token>'": "Usa 'Authorization: Bearer <token>'",
    "Too many requests. Slow down and retry shortly.": "Demasiadas solicitudes. Ve más despacio e inténtalo en un momento.",
    "An identical vulnerability is already registered, so it was not created.": "Ya existe una vulnerabilidad idéntica registrada, por eso no se creó.",
    "Vulnerability not found": "Vulnerabilidad no encontrada",
    "The scanner is busy. Try again in a few seconds.": "El escáner está ocupado. Inténtalo de nuevo en unos segundos.",
    "Unsupported archive format. Upload a .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz file.": "Formato no compatible. Sube un archivo .zip, .tar, .tar.gz, .tar.bz2 o .tar.xz.",
    "The file is not a valid zip archive.": "El archivo no es un zip válido.",
    "The file is not a valid tar archive.": "El archivo no es un tar válido.",
    "The uploaded file is empty.": "El archivo subido está vacío.",
    "The archive contains no readable files.": "El archivo comprimido no contiene archivos legibles.",
    "Attach a project archive in the 'archive' field.": "Adjunta un proyecto comprimido en el campo 'archive'.",
    "File too large. Maximum upload is 25 MB.": "Archivo demasiado grande. El máximo es 25 MB.",
    "Archive expands to more than the allowed size (possible decompression bomb).": "El archivo se expande por encima del tamaño permitido (posible bomba de descompresión).",
    "Archive contents exceed the allowed size.": "El contenido del archivo excede el tamaño permitido.",
    "titulo must be a non-empty string": "El título no puede estar vacío",
    "cve_codigo must be a non-empty string": "El identificador no puede estar vacío",
    "titulo must be at most 200 characters": "El título admite como máximo 200 caracteres",
    "cve_codigo must look like CVE-YYYY-NNNN (e.g. CVE-2024-12345) or CWE-NNN": "El identificador debe verse como CVE-AAAA-NNNN (p. ej. CVE-2024-12345) o CWE-NNN",
    "puntaje_cvss must be a number between 0 and 10": "El puntaje CVSS debe ser un número entre 0 y 10",
    "Send a JSON object": "Envía un objeto JSON",
  };

  const listeners = [];
  function t(key, vars) {
    let out = (lang === 'es' && ES[key]) || key;
    if (vars) out = out.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? vars[k] : `{${k}}`));
    return out;
  }
  function serialize(el) {
    let out = '';
    el.childNodes.forEach((n) => {
      if (n.nodeType === 3) out += n.nodeValue;
      else if (n.nodeName === 'BR') out += '<br>';
      else if (n.nodeName === 'CODE') out += `<code>${n.textContent}</code>`;
      else out += n.textContent;
    });
    return out.replace(/\s+/g, ' ').trim();
  }
  function setRich(el, text) {
    el.replaceChildren();
    text.split(/(<br>|<code>.*?<\/code>)/).forEach((part) => {
      if (!part) return;
      if (part === '<br>') el.append(document.createElement('br'));
      else if (part.startsWith('<code>')) { const c = document.createElement('code'); c.textContent = part.slice(6, -7); el.append(c); }
      else el.append(document.createTextNode(part));
    });
  }
  let titleEn, descEn;
  function translatePage() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      if (el._en === undefined) el._en = serialize(el);
      setRich(el, t(el._en));
    });
    document.querySelectorAll('[data-i18n-attr]').forEach((el) => {
      el._enAttr = el._enAttr || {};
      el.getAttribute('data-i18n-attr').split(/\s+/).forEach((a) => {
        if (el._enAttr[a] === undefined) el._enAttr[a] = el.getAttribute(a) || '';
        el.setAttribute(a, t(el._enAttr[a]));
      });
    });
    if (titleEn === undefined) titleEn = document.title;
    document.title = t(titleEn);
    const meta = document.querySelector('meta[name="description"]');
    if (meta) { if (descEn === undefined) descEn = meta.content; meta.content = t(descEn); }
  }
  function syncControls() {
    document.querySelectorAll('[data-lang]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
    const sel = document.getElementById('theme-select');
    if (sel) sel.value = theme;
  }
  function setLang(l) {
    lang = l === 'es' ? 'es' : 'en';
    store.set('vs_lang', lang); root.lang = lang;
    translatePage(); syncControls(); listeners.forEach((cb) => cb(lang));
  }
  function setTheme(name) {
    theme = THEMES.includes(name) ? name : 'auto';
    store.set('vs_theme', theme); root.dataset.theme = theme;
  }
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-lang]').forEach((b) => b.addEventListener('click', () => setLang(b.dataset.lang)));
    const sel = document.getElementById('theme-select');
    if (sel) sel.addEventListener('change', () => setTheme(sel.value));
    translatePage(); syncControls();
  });
  window.VS = { t, onLang: (cb) => listeners.push(cb), get lang() { return lang; } };
})();
