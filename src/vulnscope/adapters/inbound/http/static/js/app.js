/* VulnScope console. Every dynamic string is inserted with textContent / text nodes (never innerHTML). */
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const h = (tag, attrs = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  };
  const t = (k, v) => VS.t(k, v);
  const SEV_LABEL = { baja: 'Low', media: 'Medium', alta: 'High', critica: 'Critical', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
  const SEV_CLASS = { baja: 'low', media: 'medium', alta: 'high', critica: 'critical', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
  const ST_LABEL = { abierta: 'Open', en_revision: 'In review', mitigada: 'Mitigated', cerrada: 'Closed' };
  const MAX_MB = 25;
  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage unavailable */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* storage unavailable */ } },
  };
  const pill = (sev) => h('span', { class: `pill pill-${SEV_CLASS[sev] || 'low'}` }, t(SEV_LABEL[sev] || sev));

  // ------------------------------------------------------------------ API
  class ApiError extends Error { constructor(status, body) { super((body && body.error) || `Request failed (${status})`); this.status = status; this.body = body || {}; } }
  const session = { token: store.get('vs_token'), user: store.get('vs_user'), exp: Number(store.get('vs_exp') || 0) };
  const loggedIn = () => !!session.token && Date.now() < session.exp;

  async function api(path, { method = 'GET', json, form, auth = false } = {}) {
    const headers = {};
    if (auth) {
      if (!loggedIn()) throw new ApiError(401, { error: 'Sign in to continue.' });
      headers.Authorization = `Bearer ${session.token}`;
    }
    let body;
    if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
    if (form) body = form;
    let res;
    try { res = await fetch(path, { method, headers, body, credentials: 'omit' }); }
    catch { throw new ApiError(0, { error: 'Cannot reach the server. Check your connection.' }); }
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      if (res.status === 401 && auth) logout(false);
      throw new ApiError(res.status, data);
    }
    return data;
  }

  // ------------------------------------------------------------------ UI helpers
  let noticeTimer;
  function notice(msg, isError = false) {
    const n = $('#notice');
    n.textContent = t(msg); n.classList.toggle('is-error', isError); n.hidden = false;
    clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { n.hidden = true; }, 7000);
  }
  const busy = (text) => { $('#busy').hidden = !text; if (text) $('#busy-text').textContent = t(text); };

  function updateSession() {
    const on = loggedIn();
    $('#btn-login').hidden = on; $('#btn-logout').hidden = !on;
    $('#who').hidden = !on; $('#who').textContent = on ? t('Signed in as {user}', { user: session.user }) : '';
    if (!$('#view-registry').hidden) loadRegistry();
  }
  function logout(announce = true) {
    session.token = session.user = null; session.exp = 0;
    ['vs_token', 'vs_user', 'vs_exp'].forEach(store.del);
    updateSession();
    if (announce) notice('Signed out.');
  }

  // Sign-in dialog; resolves true when signed in.
  const dlgLogin = $('#dlg-login');
  function requireLogin() {
    if (loggedIn()) return Promise.resolve(true);
    return new Promise((resolve) => {
      $('#login-error').hidden = true;
      $('#login-form').reset();
      dlgLogin._resolve = resolve;
      dlgLogin.showModal();
      $('#login-form [name=username]').focus();
    });
  }
  const closeLogin = (ok) => { if (dlgLogin.open) dlgLogin.close(); if (dlgLogin._resolve) { dlgLogin._resolve(ok); dlgLogin._resolve = null; } };
  $('#login-cancel').addEventListener('click', () => closeLogin(false));
  dlgLogin.addEventListener('cancel', () => closeLogin(false));
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const err = $('#login-error');
    try {
      const r = await api('/login', { method: 'POST', json: { username: f.get('username'), clave: f.get('clave') } });
      session.token = r.token; session.user = String(f.get('username')); session.exp = Date.now() + r.expires_in * 1000 - 5000;
      store.set('vs_token', session.token); store.set('vs_user', session.user); store.set('vs_exp', String(session.exp));
      updateSession(); closeLogin(true); notice('Signed in.');
    } catch (ex) {
      err.textContent = t(ex.status === 429 ? 'Too many attempts. Wait a few minutes and try again.' : 'Wrong username or password.');
      err.hidden = false;
    }
  });
  $('#btn-login').addEventListener('click', requireLogin);
  $('#btn-logout').addEventListener('click', () => logout());

  // Playbook dialog
  const dlgPb = $('#dlg-playbook');
  $('#pb-close').addEventListener('click', () => dlgPb.close());
  function showPlaybook(pb) {
    const mt = pb.metadata && pb.metadata.rule_id ? ruleText({ rule_id: pb.metadata.rule_id, title: pb.metadata.title }).title : (pb.metadata && pb.metadata.title);
    $('#pb-title').textContent = t('Mitigation playbook') + (mt ? `: ${mt}` : '');
    $('#pb-strategy').textContent = pb.strategy;
    const box = $('#pb-steps'); box.replaceChildren();
    (pb.steps || []).forEach((s) => box.append(h('div', { class: 'pbstep' }, h('h4', {}, s.label), h('pre', {}, h('code', {}, s.code)))));
    dlgPb.showModal();
  }

  // ------------------------------------------------------------------ localised rule text
  const ruleCache = {};
  const ruleText = (f) => (VS.lang === 'es' && ruleCache.es && ruleCache.es[f.rule_id]) || { title: f.title, fix: f.fix };
  async function loadRuleText() {
    if (VS.lang !== 'es' || ruleCache.es) return;
    try { ruleCache.es = await api('/api/rule-text?lang=es'); } catch { /* fall back to English */ }
  }

  // ------------------------------------------------------------------ tabs
  const views = ['scan', 'registry', 'lifecycle'];
  function showView(name) {
    views.forEach((v) => {
      $(`#view-${v}`).hidden = v !== name;
      $(`#tab-${v}`).setAttribute('aria-selected', String(v === name));
    });
    if (name === 'registry') loadRegistry();
    if (name === 'lifecycle') loadLifecycle();
  }
  document.querySelectorAll('.tabs [data-view]').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

  // ------------------------------------------------------------------ scan
  let file = null, scan = null, sevFilter = 'all';
  const fileInput = $('#file'), drop = $('#drop');
  function renderDrop() {
    $('#drop-title').textContent = file ? file.name : t('Drop a project archive here, or choose a file');
    $('#drop-sub').textContent = file ? t('{size} MB — ready to analyze', { size: (file.size / 1048576).toFixed(2) })
      : t('.zip, .tar, .tar.gz, .tar.bz2 or .tar.xz — up to 25 MB');
  }
  function pick(f) {
    if (!f) return;
    if (f.size > MAX_MB * 1024 * 1024) { notice(t('That file is {size} MB. The limit is {max} MB.', { size: (f.size / 1048576).toFixed(1), max: MAX_MB }), true); return; }
    file = f; renderDrop();
    $('#btn-scan').disabled = false;
  }
  fileInput.addEventListener('change', () => pick(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => pick(e.dataTransfer.files[0]));

  $('#scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!file) return;
    const fd = new FormData(); fd.append('archive', file, file.name);
    $('#btn-scan').disabled = true; $('#results').hidden = true; busy('Unpacking and scanning…');
    try {
      scan = await api('/api/scan', { method: 'POST', form: fd });
      await loadRuleText();
      renderResults();
      if ($('#use-ai').checked && scan.findings.length) getPlan();
    } catch (ex) {
      notice(ex.message, true);
    } finally { busy(''); $('#btn-scan').disabled = false; }
  });

  function renderResults(fresh = true) {
    const { findings, stats, risk } = scan;
    $('#results').hidden = false;
    $('#risk-score').textContent = risk.score;
    const lvl = $('#risk-level'); lvl.textContent = t(`${risk.level[0].toUpperCase()}${risk.level.slice(1)} risk`);
    lvl.className = `pill pill-${risk.level}`;
    $('#risk-bar').style.width = `${Math.min(100, risk.score)}%`;
    $('#risk-meter').setAttribute('aria-label', t('Risk score {n} out of 100', { n: risk.score }));
    $('#risk-explain').textContent = risk.score === 0
      ? t('No findings, so the model sees no route to compromise.')
      : t('Probability that an attacker who reaches the app ends up with a compromise, given the weaknesses found.');
    const counts = $('#counts'); counts.replaceChildren();
    ['critical', 'high', 'medium', 'low'].forEach((s) => counts.append(h('div', { class: `count ${s}` }, h('b', {}, stats.by_severity[s]), t(SEV_LABEL[s]))));
    const bits = [t('{a} of {b} files read', { a: stats.files_scanned, b: stats.files_total })];
    if (stats.ignored_dirs.length) bits.push(t('skipped folders: {list}', { list: stats.ignored_dirs.join(', ') }));
    if (stats.skipped_large) bits.push(t('{n} files over 1 MB skipped', { n: stats.skipped_large }));
    if (stats.skipped_unsafe) bits.push(t('{n} unsafe entries ignored', { n: stats.skipped_unsafe }));
    if (stats.truncated) bits.push(t('archive truncated at the entry limit'));
    counts.append(h('p', { class: 'stat' }, bits.join(' · ')));

    const path = $('#path'); path.replaceChildren();
    if (risk.path_labels.length) risk.path_labels.forEach((l, i) => path.append(h('li', { class: i === risk.path_labels.length - 1 ? 'end' : '' }, t(l))));
    else path.append(h('li', {}, t('No route found')));
    renderMatrix($('#risk-matrix'), risk.states.map((s) => t(s.label)), risk.matrix);

    if (fresh) { $('#ai-plan').hidden = true; sevFilter = 'all'; $('#text-filter').value = ''; }
    const chips = $('#sev-filter'); chips.replaceChildren();
    ['all', 'critical', 'high', 'medium', 'low'].forEach((s) => chips.append(h('button', {
      class: 'chip', type: 'button', 'aria-pressed': String(s === sevFilter), 'data-sev': s,
      onclick: () => { sevFilter = s; chips.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-pressed', String(c.dataset.sev === s))); renderFindings(); },
    }, s === 'all' ? t('All') : t(SEV_LABEL[s]))));
    renderFindings();
    if (fresh) $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderMatrix(table, labels, m) {
    table.replaceChildren();
    table.append(h('thead', {}, h('tr', {}, h('th', {}, t('From \\ to')), labels.map((l) => h('th', {}, l)))));
    const tb = h('tbody');
    m.forEach((row, i) => tb.append(h('tr', {}, h('th', { scope: 'row' }, labels[i]), row.map((v) => {
      const td = h('td', { class: v > 0 ? 'hot' : '' }, v === 0 ? '–' : `${(v * 100).toFixed(1)}%`);
      td.style.setProperty('--p', String(Math.min(1, v * 1.4)));
      return td;
    }))));
    table.append(tb);
  }

  function renderFindings() {
    const q = $('#text-filter').value.trim().toLowerCase();
    const list = scan.findings.filter((f) => (sevFilter === 'all' || f.severity === sevFilter)
      && (!q || `${f.path} ${f.rule_id} ${ruleText(f).title} ${f.cwe}`.toLowerCase().includes(q)));
    $('#findings-count').textContent = t('({n} of {m})', { n: list.length, m: scan.findings.length });
    const ul = $('#findings'); ul.replaceChildren();
    if (!list.length) ul.append(h('li', { class: 'muted' }, t(scan.findings.length ? 'No findings match this filter.' : 'No issues found by the built-in rules. This does not prove the code is safe.')));
    list.slice(0, 300).forEach((f) => ul.append(findingItem(f)));
    if (list.length > 300) ul.append(h('li', { class: 'muted' }, t('Showing the first 300 of {n}. Narrow the filter to see the rest.', { n: list.length })));
  }
  $('#text-filter').addEventListener('input', () => scan && renderFindings());

  function findingItem(f) {
    const aiOut = h('div', { class: 'aibox', hidden: true });
    const rt = ruleText(f);
    const where = f.line ? `${f.path}:${f.line}` : f.path;
    const code = f.context.length ? h('pre', { class: 'listing', tabindex: '0' }, h('code', {}, f.context.map((c) =>
      h('span', { class: c.hit ? 'hit' : '' }, h('span', { class: 'ln' }, c.n), h('span', { class: 'src' }, c.text + '\n'))))) : null;
    const body = h('div', { class: 'finding-body' },
      code,
      h('div', { class: 'howfix' }, h('h4', {}, t('How to fix')), h('p', {}, rt.fix), f.example ? h('pre', {}, h('code', {}, f.example)) : null),
      h('div', { class: 'row' },
        h('button', { class: 'btn btn-small', type: 'button', onclick: (e) => explain(f, aiOut, e.currentTarget) }, t('Explain with AI')),
        h('button', { class: 'btn btn-small btn-ghost', type: 'button', onclick: () => openRulePlaybook(f) }, t('Cloud playbook')),
        h('button', { class: 'btn btn-small btn-ghost', type: 'button', onclick: () => register([f]) }, t('Add to registry'))),
      aiOut);
    return h('li', {}, h('details', { class: 'finding' },
      h('summary', {}, pill(f.severity), h('span', { class: 'ftitle' }, `${rt.title} `, h('span', { class: 'cwe' }, f.cwe)), h('span', { class: 'floc' }, where)), body));
  }

  async function explain(f, out, btn) {
    btn.disabled = true; btn.textContent = t('Asking…');
    try {
      const r = await api('/api/ai/explain', { method: 'POST', json: { lang: VS.lang, finding: { rule_id: f.rule_id, path: f.path, line: f.line, context: f.context } } });
      out.replaceChildren(h('div', { class: 'aibox-head' }, h('h2', {}, t('Explanation')), h('span', { class: 'pill' }, r.fallback ? t('Built-in guidance') : t('AI: {engine}', { engine: r.engine }))),
        r.fallback ? h('p', { class: 'fine' }, t('The public AI service did not answer, so this is the built-in guidance.')) : null,
        h('pre', { class: 'prose' }, r.text));
      out.hidden = false;
    } catch (ex) { notice(ex.message, true); }
    finally { btn.disabled = false; btn.textContent = t('Explain with AI'); }
  }

  async function openRulePlaybook(f) {
    try { showPlaybook(await api('/api/playbook', { method: 'POST', json: { rule_id: f.rule_id, lang: VS.lang } })); }
    catch (ex) { notice(ex.message, true); }
  }

  async function getPlan() {
    if (!scan) return;
    busy('Asking the AI for a remediation plan…');
    try {
      const r = await api('/api/ai/summary', { method: 'POST', json: {
        lang: VS.lang, by_severity: scan.stats.by_severity, risk_score: scan.risk.score,
        top: scan.findings.slice(0, 15).map((f) => ({ rule_id: f.rule_id, path: f.path, line: f.line })) } });
      $('#ai-plan-text').textContent = r.text;
      $('#ai-plan-engine').textContent = r.fallback ? t('Built-in guidance') : t('AI: {engine}', { engine: r.engine });
      $('#ai-plan').hidden = false;
      if (r.fallback) notice('The public AI service is unavailable right now, so built-in guidance is shown.');
    } catch (ex) { notice(ex.message, true); }
    finally { busy(''); }
  }
  $('#btn-ai-plan').addEventListener('click', getPlan);

  async function register(items) {
    if (!(await requireLogin())) return;
    try {
      const r = await api('/api/vulnerabilidades/bulk', { method: 'POST', auth: true,
        json: { findings: items.map((f) => ({ rule_id: f.rule_id, path: f.path, line: f.line })) } });
      if (r.created === 0 && r.duplicates > 0) notice(t(r.duplicates === 1 ? 'Nothing added: an identical record is already in the registry.' : 'Nothing added: {n} identical records are already in the registry.', { n: r.duplicates }), true);
      else notice(t('Added {n} to the registry.', { n: r.created }) + (r.duplicates ? ' ' + t(r.duplicates === 1 ? 'Skipped 1 identical duplicate.' : 'Skipped {n} identical duplicates.', { n: r.duplicates }) : ''));
    } catch (ex) { notice(ex.message, true); }
  }
  $('#btn-register-all').addEventListener('click', () => scan && register(scan.findings));

  $('#btn-export').addEventListener('click', () => {
    if (!scan) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' }));
    const a = h('a', { href: url, download: 'vulnscope-report.json' });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  // ------------------------------------------------------------------ registry
  async function loadRegistry() {
    let rows;
    try { rows = await api('/api/vulnerabilidades'); } catch (ex) { notice(ex.message, true); return; }
    const tb = $('#registry-table tbody'); tb.replaceChildren();
    $('#registry-empty').hidden = rows.length > 0;
    rows.forEach((v) => {
      const status = loggedIn()
        ? h('select', { 'aria-label': t('Status of record {id}', { id: v.id }), onchange: (e) => changeStatus(v, e.target.value, e.target) },
          Object.entries(ST_LABEL).map(([val, label]) => h('option', { value: val, selected: val === v.estado }, t(label))))
        : t(ST_LABEL[v.estado] || v.estado);
      tb.append(h('tr', {}, h('td', {}, v.id), h('td', {}, v.titulo), h('td', { class: 'cwe' }, v.cve_codigo),
        h('td', {}, pill(v.severidad)), h('td', {}, status), h('td', {}, v.puntaje_cvss.toFixed(1)),
        h('td', {}, h('div', { class: 'row' },
          h('button', { class: 'btn btn-small btn-ghost', type: 'button', onclick: () => registryPlaybook(v.id) }, t('Playbook')),
          h('button', { class: 'btn btn-small btn-ghost', type: 'button', onclick: () => remove(v) }, t('Delete'))))));
    });
  }
  const dup = $('#dup-warning');
  function showDup(ex) {
    dup.textContent = `${t(ex.message)} ${t('Existing record: #{id}.', { id: ex.body.existing_id })}`; dup.hidden = false;
    notice('Duplicate blocked: an identical record already exists.', true);
  }
  async function changeStatus(v, estado, sel) {
    try {
      await api(`/api/vulnerabilidades/${v.id}`, { method: 'PUT', auth: true, json: { ...v, estado } });
      notice('Status updated.'); loadRegistry();
    } catch (ex) { if (ex.status === 409) showDup(ex); else notice(ex.message, true); sel.value = v.estado; }
  }
  async function remove(v) {
    if (!(await requireLogin())) return;
    if (!confirm(t('Delete record #{id}?', { id: v.id }))) return;
    try { await api(`/api/vulnerabilidades/${v.id}`, { method: 'DELETE', auth: true }); notice('Record deleted.'); loadRegistry(); }
    catch (ex) { notice(ex.message, true); }
  }
  async function registryPlaybook(id) {
    if (!(await requireLogin())) return;
    try { showPlaybook(await api(`/api/vulnerabilidades/${id}/playbook?lang=${VS.lang}`, { auth: true })); } catch (ex) { notice(ex.message, true); }
  }
  $('#vuln-form').addEventListener('submit', async (e) => {
    e.preventDefault(); dup.hidden = true;
    if (!e.target.reportValidity()) return;
    if (!(await requireLogin())) return;
    const f = new FormData(e.target);
    const body = { titulo: f.get('titulo'), cve_codigo: String(f.get('cve_codigo')).trim().toUpperCase(), severidad: f.get('severidad'),
      estado: f.get('estado'), puntaje_cvss: parseFloat(f.get('puntaje_cvss')) };
    try {
      await api('/api/vulnerabilidades', { method: 'POST', auth: true, json: body });
      notice('Record created.'); e.target.reset(); loadRegistry();
    } catch (ex) { if (ex.status === 409) showDup(ex); else notice(ex.message, true); }
  });

  // ------------------------------------------------------------------ lifecycle
  async function loadLifecycle() {
    try {
      const d = await api('/api/markov/lifecycle');
      const src = { history: 'Learned entirely from your registry history.', 'history+prior': 'Learned from your registry history, blended with a built-in prior because there are few observed transitions.', prior: 'Built-in prior only: the registry has no status history yet.' }[d.data_source];
      $('#lc-source').textContent = `${t(src)} ${t('Transitions observed: {n}.', { n: d.transitions_observed })}`;
      renderMatrix($('#lc-matrix'), d.states.map((s) => t(ST_LABEL[s])), d.matrix);
      const cards = $('#lc-cards'); cards.replaceChildren();
      d.states.filter((s) => s !== 'cerrada').forEach((s) => {
        const steps = d.expected_steps_to_closed[s];
        cards.append(h('div', { class: 'lc-card' }, h('span', { class: 'muted' }, t('From {state}', { state: t(ST_LABEL[s]) })),
          h('b', {}, steps === null ? t('Never closes') : t('{n} steps', { n: steps })),
          h('span', {}, t('to reach Closed. Most likely next: {next}.', { next: t(ST_LABEL[d.next_most_likely[s]]) }))));
      });
      renderSim(d.simulation);
    } catch (ex) { notice(ex.message, true); }
  }
  function renderSim(seq) {
    const ol = $('#lc-sim'); ol.replaceChildren();
    seq.forEach((s, i) => ol.append(h('li', { class: i === seq.length - 1 && s === 'cerrada' ? 'end' : '' }, t(ST_LABEL[s]))));
  }
  $('#btn-sim').addEventListener('click', async () => {
    try { renderSim((await api(`/api/markov/lifecycle?from=${encodeURIComponent($('#lc-from').value)}`)).simulation); }
    catch (ex) { notice(ex.message, true); }
  });

  VS.onLang(async () => {
    renderDrop(); updateSession();
    if (scan) { await loadRuleText(); renderResults(false); }
    if (!$('#view-lifecycle').hidden) loadLifecycle();
  });
  renderDrop();
  updateSession();
  if (VS.lang === 'es') loadRuleText();
  if (location.hash === '#registry') showView('registry');
})();
