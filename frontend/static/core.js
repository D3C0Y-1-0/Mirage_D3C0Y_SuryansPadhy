// Platform core: API client, shared state, router, shell, small UI helpers.
// Pages live in pages-*.js and get (root, ctx). Nothing here computes risk: every number comes from the backend.
import { fmt, tmin } from './charts.js';

// ---------- API ----------
const memo = new Map();
export async function api(path, body, { method } = {}) {
  const res = await fetch(path, body === undefined && !method ? {} : {
    method: method || 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) });
  if (res.status === 401 && !path.startsWith('/api/auth/')) { location.href = '/login?next=' + encodeURIComponent('/app' + location.hash); throw new Error('Sign in required'); }
  let data = null; try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) {                          // FastAPI validation errors arrive as a list: make them readable
    const d = data?.detail;
    throw new Error(!d ? `Request failed (${res.status})` : typeof d === 'string' ? d : Array.isArray(d) ? d.map(x => `${(x.loc || []).filter(k => k !== 'body' && k !== 'query').join(' ')}: ${x.msg}`).join('; ') : JSON.stringify(d));
  }
  return data;
}
export function get(path) {             // cached GET (the dataset does not change while the server runs)
  if (!memo.has(path)) memo.set(path, api(path).catch(e => { memo.delete(path); throw e; }));
  return memo.get(path);
}

// ---------- shared state: the current simulated scenario ----------
const KEY = 'cascade.scenario';
const listeners = new Set();
export const store = {
  get scenario() { try { return JSON.parse(sessionStorage.getItem(KEY)); } catch { return null; } },
  set scenario(v) { try { v ? sessionStorage.setItem(KEY, JSON.stringify(v)) : sessionStorage.removeItem(KEY); } catch { /* private mode */ } listeners.forEach(f => f(v)); },
  on(f) { listeners.add(f); return () => listeners.delete(f); },
  time: 0,             // replay clock shared by Simulation, Incidents, Timeline
};
export async function runScenario(request, title) {
  const result = await api('/api/multi', request);
  store.scenario = { request, result, title: title || 'Custom scenario', ranAt: Date.now() };
  return result;
}

// ---------- helpers ----------
export const h = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export { fmt, tmin };
export const pm = v => `${fmt(v)} people-min`;
export const pct = (a, b) => a ? Math.round(100 * (a - b) / a) : 0;
export function toast(text) { const t = document.getElementById('toast'); t.textContent = text; t.style.display = 'block'; clearTimeout(toast.h); toast.h = setTimeout(() => t.style.display = 'none', 3800); }
export const loading = (root, text = 'Loading') => root.innerHTML = `<div class="skel" aria-busy="true" aria-label="${h(text)}"><i style="height:64px;width:min(560px,80%)"></i><div class="r"><i style="height:110px"></i><i style="height:110px"></i><i style="height:110px"></i><i style="height:110px"></i></div><div class="r" style="grid-template-columns:2fr 1fr"><i style="height:300px"></i><i style="height:300px"></i></div><span class="sr-only" style="position:absolute;left:-9999px">${h(text)}</span></div>`;
export const errorBox = (root, e) => root.innerHTML = `<div class="err">Could not load this: ${h(e.message || e)}. Is the backend running?</div>`;
export const ATK = ['A', 'B', 'C', 'D'];
export const atkColor = id => ({ A: '#E5559F', B: '#2A8FD6', C: '#9A74F0', D: '#2BA58A' }[id] || '#8E9DE0');
export const atkBadge = id => `<span class="atk ${h(id)}" aria-label="Attacker ${h(id)}">${h(id)}</span>`;

// sortable table: cols [{key, label, num, render(row), sort(row)}]
export function table(host, rows, cols, { onRow, sortKey, desc = true, selected, empty = 'Nothing matches these filters.' } = {}) {
  let sk = sortKey, sd = desc;
  function draw() {
    const col = cols.find(c => c.key === sk);
    const val = r => col ? (col.sort ? col.sort(r) : r[col.key]) : 0;
    const sorted = col ? [...rows].sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * (sd ? -1 : 1); }) : rows;
    host.innerHTML = `<div class="tablewrap"><table class="t"><thead><tr>${cols.map(c => `<th class="${c.num ? 'n' : ''}" scope="col" aria-sort="${c.key === sk ? (sd ? 'descending' : 'ascending') : 'none'}">${c.nosort ? h(c.label) : `<button data-k="${c.key}">${h(c.label)}${c.key === sk ? `<span class="ar">${sd ? '↓' : '↑'}</span>` : ''}</button>`}</th>`).join('')}</tr></thead>
      <tbody>${sorted.length ? sorted.map((r, i) => `<tr class="${onRow ? 'click' : ''} ${selected && selected(r) ? 'sel' : ''}" data-i="${rows.indexOf(r)}" ${onRow ? 'tabindex="0"' : ''}>${cols.map(c => `<td class="${c.num ? 'n' : ''}">${c.render ? c.render(r) : h(r[c.key])}</td>`).join('')}</tr>`).join('')
        : `<tr><td colspan="${cols.length}" class="mute" style="text-align:center;padding:28px">${h(empty)}</td></tr>`}</tbody></table></div>`;
    host.querySelectorAll('th button').forEach(b => b.onclick = () => { if (sk === b.dataset.k) sd = !sd; else { sk = b.dataset.k; sd = true; } draw(); });
    if (onRow) host.querySelectorAll('tbody tr[data-i]').forEach(tr => {
      const go = () => onRow(rows[+tr.dataset.i]);
      tr.onclick = go; tr.onkeydown = e => { if (e.key === 'Enter') go(); };
    });
  }
  draw();
  return { redraw: (r) => { if (r) rows = r; draw(); } };
}

// drawer
const drawer = () => document.getElementById('drawer');
export function openDrawer(html, onClose) {
  const d = drawer(); d.innerHTML = `<button class="btn small x" id="drawerClose">Close</button>` + html;
  d.classList.add('open'); document.getElementById('scrim').classList.add('on');
  d.querySelector('#drawerClose').onclick = closeDrawer; d.focus({ preventScroll: true });
  openDrawer.onClose = onClose;
  return d;
}
export function closeDrawer() { drawer().classList.remove('open'); document.getElementById('scrim').classList.remove('on'); openDrawer.onClose?.(); openDrawer.onClose = null; }

// ---------- the 3D twin: the ORIGINAL frontend/index.html, embedded once and kept alive ----------
let twinFrame = null;
export function twin() {
  if (!twinFrame) {
    const host = document.getElementById('twinhost');
    host.innerHTML = '<iframe class="twinframe" src="/twin" title="Cascade 3D digital twin" allow="fullscreen"></iframe>';
    twinFrame = host.querySelector('iframe');
  }
  return twinFrame;
}
export function withTwin(fn) {             // run fn(window.cascade inside the twin) once it is ready
  location.hash = '#/twin';
  const f = twin();
  const tryNow = (n = 0) => { const c = f.contentWindow?.cascade; if (c && f.contentWindow.cascade.S?.graph) fn(c); else if (n < 80) setTimeout(() => tryNow(n + 1), 150); else toast('The twin did not finish loading.'); };
  tryNow();
}

// ---------- navigation ----------
const I = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  twin: '<path d="M12 3 3 8l9 5 9-5z"/><path d="m3 13 9 5 9-5"/><path d="m3 17.5 9 4.5 9-4.5" opacity=".5"/>',
  inventory: '<rect x="4" y="3" width="16" height="6" rx="1.5"/><rect x="4" y="15" width="16" height="6" rx="1.5"/><path d="M8 6h.01M8 18h.01"/>',
  services: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7.5 8 11 16M16.5 8 13 16"/>',
  vulns: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="M12 8v5M12 16h.01"/>',
  simulate: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  incidents: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
  timeline: '<path d="M3 12h18"/><circle cx="7" cy="12" r="2"/><circle cx="14" cy="12" r="2"/><path d="M7 5v3M14 16v3M19 5v14"/>',
  risk: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  graphs: '<path d="M3 20h18"/><path d="m4 16 5-6 4 3 7-8"/>',
  ml: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  optimizer: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  response: '<path d="M9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  project: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v5h1"/>',
  architecture: '<rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="9" y="15" width="6" height="6" rx="1"/><path d="M6 9v3h12V9M12 12v3"/>',
  water: '<path d="M12 3s6 7 6 11a6 6 0 0 1-12 0c0-4 6-11 6-11z"/><path d="M8 14h2l1.5-3 2 5 1.5-2h1"/>',
  live: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19 5a10 10 0 0 1 0 14M5 19A10 10 0 0 1 5 5"/>',
  recovery: '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><path d="M12 8v4l3 2"/>',
  assumptions: '<path d="M4 4h16v16H4z"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  evaluation: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  electricity: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
  novel: '<path d="M12 2 2 7l10 5 10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/><circle cx="18" cy="5" r="3" fill="currentColor" stroke="none"/>',
  failsafe: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="M12 8v4l2.5 2"/>',
  paths: '<circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="19" r="2"/><path d="M7 6h10M6 8l5 9M18 8l-5 9"/>',
  drill: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l3 2M9 2h6"/>',
  exposure: '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/>',
  report: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M14 3v5h5"/>',
  compliance: '<path d="M9 11l2 2 4-4"/><path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>',
  security: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
};
export const ROUTES = [
  ['Command centre', [['overview', 'Overview', 'ops']]],
  ['Infrastructure', [['twin', 'Digital twin', null], ['inventory', 'Asset inventory', 'ops'], ['services', 'Services and dependencies', 'ops'], ['vulns', 'Vulnerability intelligence', 'ops']]],
  ['Monitoring', [['live', 'Live attack testbed', 'live'], ['water', 'Water anomaly monitoring', 'water'], ['electricity', 'Electricity attack screening', 'elec'], ['novel', 'Unknown-attack response', 'water']]],
  ['Threat simulation', [['simulate', 'Attack simulation', 'sim'], ['paths', 'Attack paths', 'plus'], ['incidents', 'Active incidents', 'sim'], ['timeline', 'Attack timeline', 'sim'], ['drill', 'Drill mode', 'plus']]],
  ['Risk intelligence', [['risk', 'Risk register', 'ops'], ['exposure', 'Exposure and roadmap', 'plus'], ['graphs', 'Graphs and analytics', 'intel'], ['ml', 'ML insights', 'intel'], ['evaluation', 'Model evaluation', 'elec']]],
  ['Defence', [['optimizer', 'Fix optimiser', 'intel'], ['response', 'Containment and response', 'sim'], ['failsafe', 'Failsafe and operator', 'water'], ['recovery', 'Recovery', 'recover']]],
  ['Governance', [['report', 'Incident report', 'plus'], ['compliance', 'Compliance mapping', 'plus'], ['assumptions', 'Assumptions register', 'recover'], ['project', 'Project information', 'gov'], ['architecture', 'Architecture and methodology', 'gov'], ['security', 'Security and 2FA', 'gov']]],
];
const LABEL = Object.fromEntries(ROUTES.flatMap(([, items]) => items.map(([k, l]) => [k, l])));
const MODULE = Object.fromEntries(ROUTES.flatMap(([, items]) => items.map(([k, , m]) => [k, m])));

function renderNav() {
  let closed = {}; try { closed = JSON.parse(localStorage.getItem('cascade.nav') || '{}'); } catch { /* ignore */ }
  document.getElementById('nav').innerHTML = ROUTES.map(([g, items]) => `<div class="grp ${closed[g] ? 'closed' : ''}" data-g="${h(g)}">
    <button aria-expanded="${!closed[g]}">${h(g)}<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m3 4.5 3 3 3-3"/></svg></button>
    <ul>${items.map(([k, l]) => `<li><a href="#/${k}" data-r="${k}" title="${h(l)}"><svg viewBox="0 0 24 24" aria-hidden="true">${I[k]}</svg>${h(l)}${k === 'incidents' ? '<span class="badge" id="incBadge" hidden></span>' : ''}</a></li>`).join('')}</ul></div>`).join('');
  document.querySelectorAll('.grp > button').forEach(b => b.onclick = () => {
    const g = b.parentElement; g.classList.toggle('closed'); b.setAttribute('aria-expanded', !g.classList.contains('closed'));
    closed[g.dataset.g] = g.classList.contains('closed'); try { localStorage.setItem('cascade.nav', JSON.stringify(closed)); } catch { /* ignore */ }
  });
}

const modules = {};
async function route() {
  const key = (location.hash.replace(/^#\/?/, '').split('?')[0]) || 'overview';
  const k = LABEL[key] ? key : 'overview';
  document.querySelectorAll('#nav a').forEach(a => { const on = a.dataset.r === k; a.classList.toggle('on', on); on ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'); const g = a.closest('.grp'); if (on && g.classList.contains('closed')) g.classList.remove('closed'); });
  document.getElementById('title').textContent = LABEL[k];
  document.title = `${LABEL[k]}: Cascade`;
  closeDrawer();
  document.getElementById('side').classList.remove('open');
  const page = document.getElementById('page'), th = document.getElementById('twinhost');
  if (route.cleanup) { try { route.cleanup(); } catch { /* ignore */ } route.cleanup = null; }
  if (k === 'twin') {
    page.style.display = 'none'; th.classList.add('on'); twin(); document.getElementById('main').scrollTop = 0;
    if (!th.querySelector('.twinnote')) th.insertAdjacentHTML('beforeend', '<div class="twinnote">The original 3D twin, unchanged. It also runs on its own at /twin.</div>');
    return;
  }
  th.classList.remove('on'); page.style.display = '';
  page.className = 'page'; page.innerHTML = ''; void page.offsetWidth; page.classList.add('enter');
  document.getElementById('main').scrollTop = 0;
  let box = null;
  try {
    const m = modules[MODULE[k]] ||= await import(`./pages-${MODULE[k]}.js`);
    // each visit renders into its own box: if the user leaves before a slow page finishes, that page's late
    // writes land in a detached box instead of on top of the next page (was: "Cannot set properties of null")
    box = document.createElement('div'); box.className = 'pagebox'; page.replaceChildren(box);
    const ctx = { onLeave: f => route.cleanup = f };
    await m[k](box, ctx);
  } catch (e) { console.error(e); if (!box || box.isConnected) errorBox(box || page, e); }   // a page the user already left stays quiet
}

// ---------- top bar ----------
function refreshPills() {
  const sc = store.scenario, sim = document.getElementById('simPill'), ev = document.getElementById('evPill');
  const badge = document.getElementById('incBadge');
  if (sc) {
    const active = sc.result.attackers.filter(a => a.status === 'active').length;
    sim.classList.add('live'); sim.querySelector('span:last-child').innerHTML = `<b>${h(sc.title)}</b>, ${sc.result.attackers.length} attacker${sc.result.attackers.length === 1 ? '' : 's'}`;
    ev.querySelector('b').textContent = sc.result.events.length;
    if (badge) { badge.hidden = !active; badge.textContent = active; }
  } else {
    sim.classList.remove('live'); sim.querySelector('span:last-child').textContent = 'No simulation';
    ev.querySelector('b').textContent = 0; if (badge) badge.hidden = true;
  }
}
// live testbed: a small poll so every page shows a live alarm (the Live page itself streams)
let liveSeen = null;
async function pollLive() {
  try {
    const s = await api('/api/live/status');   // live: never the cached get()
    const p = document.getElementById('livePill'); if (!p) return;
    const inc = s.running && s.incident;
    p.hidden = !inc;
    if (inc) {
      const st = inc.state;
      p.className = 'pill keep livepill ' + (st === 'awaiting_operator' ? 'alarm' : st === 'isolated' ? 'iso' : 'ok');
      p.querySelector('span:last-child').innerHTML = st === 'awaiting_operator' ? `<b>LIVE ALARM</b> ${h(s.asset)}` : st === 'isolated' ? `Live: ${h(s.asset)} isolated` : st === 'recovered' ? 'Live: recovered' : 'Live: dismissed';
      if (liveSeen !== inc.id && st === 'awaiting_operator') { liveSeen = inc.id; if (!location.hash.startsWith('#/live')) toast(`LIVE alarm on ${s.asset_name}: ${inc.first || 'unauthorised command'}. Open the Live page.`); }
    }
  } catch { /* backend restarting */ }
}
setInterval(pollLive, 2500); pollLive();
async function refreshTop() {
  try {
    const d = await get('/api/dataset');
    const p = document.getElementById('dataPill'); p.classList.add('ok');
    p.querySelector('span:last-child').innerHTML = `<b>${h(d.folder)}</b>, ${d.assets} systems, simulated`;
  } catch { /* shown on pages */ }
  try {
    const s = await api('/api/auth/status');
    const p = document.getElementById('secPill');
    p.classList.toggle('ok', s.totp_enabled); p.classList.toggle('warnp', !s.totp_enabled);
    p.querySelector('span:last-child').textContent = !s.accounts_exist ? 'Security: not set up' : s.totp_enabled ? '2FA on' : '2FA off';
    document.getElementById('userBtn').textContent = s.user || 'Account';
    document.getElementById('signOut').hidden = !s.user;
    const sl = document.querySelector('#userMenu a[href="#/security"]');
    if (sl) sl.textContent = !s.accounts_exist ? 'Turn on sign-in and 2FA' : s.totp_enabled ? 'Security and 2FA (on)' : 'Security: turn on 2FA';
    const who = document.getElementById('whoLine');
    if (who) who.textContent = !s.accounts_exist ? 'Open access: anyone who can reach this server can use it.' : s.user ? `Signed in as ${s.user}` : '';
  } catch { /* ignore */ }
}
export { refreshTop };

// ---------- KPI numbers count up when a page renders them ----------
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
function tick(el) {
  if (el.dataset.ticked) return; el.dataset.ticked = '1';
  const raw = el.childNodes[0]?.nodeType === 3 ? el.childNodes[0].textContent.trim() : el.textContent.trim();
  const m = raw.match(/^([\d.,]+)([kM%]?)$/); if (!m || reduceMotion) return;
  const target = parseFloat(m[1].replace(/,/g, '')), dec = (m[1].split('.')[1] || '').length, comma = m[1].includes(',');
  const node = el.childNodes[0]?.nodeType === 3 ? el.childNodes[0] : el; const t0 = performance.now();
  const step = t => { const k = Math.min(1, (t - t0) / 900), v = target * (1 - Math.pow(1 - k, 3));
    const s = comma ? Math.round(v).toLocaleString() : v.toFixed(dec); node.textContent = s + m[2]; if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
new MutationObserver(() => document.querySelectorAll('#page .kpi .v').forEach(tick)).observe(document.getElementById('page'), { childList: true, subtree: true });

// ---------- theme ----------
const SUN = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON = '<svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('cascade.theme', t); } catch { /* private mode */ }
  const b = document.getElementById('themeBtn'); b.innerHTML = t === 'light' ? MOON : SUN; b.title = t === 'light' ? 'Switch to dark' : 'Switch to light';
}
setTheme(document.documentElement.dataset.theme || 'light');
document.getElementById('themeBtn').onclick = () => { setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'); toast(`${document.documentElement.dataset.theme === 'light' ? 'Light' : 'Dark'} theme`); };

// ---------- command palette (Ctrl+K): pages, systems, actions ----------
const pal = document.getElementById('palette'), palIn = document.getElementById('palIn'), palList = document.getElementById('palList');
let palItems = [], palSel = 0;
async function palBuild() {
  const items = ROUTES.flatMap(([g, list]) => list.map(([k, l]) => ({ label: l, sub: g, run: () => { location.hash = '#/' + k; } })));
  items.push({ label: 'Switch light or dark theme', sub: 'Action', run: () => document.getElementById('themeBtn').click() });
  items.push({ label: 'Run "two attackers at once"', sub: 'Action', run: () => { location.hash = '#/simulate'; } });
  items.push({ label: 'Open the project site', sub: 'Action', run: () => { location.href = '/'; } });
  try {
    const inv = await get('/api/assets');
    inv.assets.forEach(a => items.push({ label: a.name, sub: `System, ${a.sector || a.zone_name}`, run: async () => { (await import('./pages-ops.js')).assetDrawer(a.id); } }));
  } catch { /* signed out or loading */ }
  return items;
}
function palDraw() {
  const q = palIn.value.toLowerCase().trim();
  const shown = palItems.filter(i => !q || (i.label + ' ' + i.sub).toLowerCase().includes(q)).slice(0, 40);
  palSel = Math.min(palSel, Math.max(0, shown.length - 1));
  palList.innerHTML = shown.map((i, n) => `<li role="option" data-n="${n}" class="${n === palSel ? 'on' : ''}" aria-selected="${n === palSel}">${h(i.label)}<span>${h(i.sub)}</span></li>`).join('') || '<li>No match</li>';
  palList.querySelectorAll('li[data-n]').forEach(li => { li.onclick = () => palRun(shown[+li.dataset.n]); li.onmousemove = () => { palSel = +li.dataset.n; palList.querySelectorAll('li').forEach(x => x.classList.toggle('on', x === li)); }; });
  palDraw.shown = shown;
}
function palRun(item) { palClose(); item?.run(); }
async function palOpen() { pal.classList.add('on'); palIn.value = ''; palSel = 0; palItems = await palBuild(); palDraw(); palIn.focus(); }
function palClose() { pal.classList.remove('on'); }
palIn.oninput = () => { palSel = 0; palDraw(); };
palIn.onkeydown = e => {
  if (e.key === 'ArrowDown') { palSel++; palDraw(); e.preventDefault(); }
  else if (e.key === 'ArrowUp') { palSel = Math.max(0, palSel - 1); palDraw(); e.preventDefault(); }
  else if (e.key === 'Enter') palRun(palDraw.shown?.[palSel]);
  else if (e.key === 'Escape') palClose();
};
pal.onclick = e => { if (e.target === pal) palClose(); };
document.getElementById('paletteBtn').onclick = palOpen;
addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.classList.contains('on') ? palClose() : palOpen(); } });

// ---------- boot ----------
renderNav();
store.on(refreshPills); refreshPills(); refreshTop();
addEventListener('hashchange', route);
route();
document.getElementById('scrim').onclick = () => { closeDrawer(); document.getElementById('side').classList.remove('open'); };
addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
const mt = document.getElementById('menuToggle');
mt.onclick = () => { const s = document.getElementById('side'); s.classList.toggle('open'); mt.setAttribute('aria-expanded', s.classList.contains('open')); document.getElementById('scrim').classList.toggle('on', s.classList.contains('open')); };
const um = document.getElementById('userMenu'), ub = document.getElementById('userBtn');
ub.onclick = e => { e.stopPropagation(); um.classList.toggle('open'); ub.setAttribute('aria-expanded', um.classList.contains('open')); };
addEventListener('click', () => um.classList.remove('open'));
document.getElementById('signOut').onclick = async () => { await api('/api/auth/logout', {}); location.href = '/login'; };
