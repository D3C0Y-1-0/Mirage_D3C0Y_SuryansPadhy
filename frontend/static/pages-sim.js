// Attack simulation (multi-attacker), Active incidents, Attack timeline, Containment and response.
// The backend (multi.py) does all the simulating; these pages configure it and replay its answer.
import { api, get, h, fmt, tmin, pm, pct, table, store, runScenario, toast, loading, errorBox, atkBadge, atkColor, ATK, withTwin, openDrawer, closeDrawer } from './core.js';
import { bars, grouped, lines, COLORS as C } from './charts.js';
import { netmap } from './netmap.js';
import { assetDrawer } from './pages-ops.js';

const PROFILES = [['0.5', 'Opportunistic (0.5×)'], ['1', 'Organised crew (1×)'], ['2', 'State-backed (2×)']];
const HORIZON = 360;
const hashParams = () => new URLSearchParams(location.hash.split('?')[1] || '');

// every way in of an attacker (one attacker can hold several)
export const entriesOf = a => (a.entries && a.entries.length ? a.entries : [{ asset: a.entry, start: a.start || 0 }]);

// state of the replay at minute t, for the map. Everything comes from the backend result:
// a node fills when t >= its compromise time; the edge parent -> child grows between the parent's and the child's time.
export function mapState(res, t, names) {
  const st = {}, paths = [];
  const n = res.attackers.length, idx = Object.fromEntries(res.attackers.map((a, i) => [a.id, i]));
  for (const a of res.attackers) {
    const col = atkColor(a.id), off = n > 1 ? (idx[a.id] - (n - 1) / 2) * 4 : 0;
    for (const [node, tt] of Object.entries(a.compromised)) {
      const from = a.parents[node];
      if (from) {
        const t0 = a.compromised[from];
        if (t >= t0) paths.push({ src: from, dst: node, color: col, offset: off, frac: tt > t0 ? (t - t0) / (tt - t0) : 1 });
      }
      if (tt > t) continue;
      const first = res.combined.first_by[node];
      const s = st[node] ||= { label: true, priority: 2 };
      if (first.attacker === a.id) { s.fill = col; s.labelColor = '#FFFFFF'; s.tip = `Attacker ${a.id} at ${tmin(tt)}` + (s.tip ? '; ' + s.tip : ''); }
      else { s.ring2 = col; s.tip = (s.tip ? s.tip + '; ' : '') + `also attacker ${a.id} at ${tmin(tt)} (contested)`; }
    }
    for (const e of entriesOf(a)) {
      if (e.start > t) st[e.asset] = { ...(st[e.asset] || {}), ring: col, ringDash: true, label: true, priority: 3, tip: `Attacker ${a.id} comes in here at ${tmin(e.start)}` };
      else if (!a.compromised[e.asset]) st[e.asset] = { ...(st[e.asset] || {}), ring: col, label: true, priority: 3, tip: `Attacker ${a.id} was stopped at this way in` };
    }
  }
  for (const w of res.maintenance || []) {
    const end = w.start + 60 * w.hours;
    if (t >= w.start && t < end) st[w.asset] = { ...(st[w.asset] || {}), stroke: C.warn, ring: C.warn, ringDash: true, label: true, priority: 3, tip: 'offline for patching' };
  }
  return { st, paths };
}

// ======================================= ATTACK SIMULATION =======================================
export async function simulate(root, ctx) {
  loading(root, 'Loading the simulator');
  let g, presets, fixList, inv;
  try {
    [g, presets, inv] = await Promise.all([get('/api/graph'), get('/api/multi/presets'), get('/api/assets')]);
    presets = presets.presets;
  } catch (e) { return errorBox(root, e); }
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  const entries = g.assets.filter(a => a.is_entry).sort((a, b) => b.entry_prob - a.entry_prob);
  const inside = g.assets.filter(a => !a.is_entry);
  const sc = store.scenario;
  const p = hashParams();
  const norm = a => { const e = entriesOf(a); return { speed: 1, contain_at: null, adaptive: false, active: true, ...a, entry: e[0].asset, start: e[0].start, more: e.slice(1).map(x => ({ ...x })), entries: e.length > 1 ? e.map(x => ({ ...x })) : [] }; };
  const sync = a => { a.entries = a.more?.length ? [{ asset: a.entry, start: +a.start || 0 }, ...a.more] : []; };
  let req = sc?.request ? structuredClone(sc.request) : { attackers: [{ id: 'A', entry: p.get('entry') || entries[0]?.id, start: 0, speed: 1, contain_at: null, adaptive: false, active: true }], fixes: [], maintenance: [], detection: true, speed: 1 };
  if (p.get('entry') && sc) req = { attackers: [{ id: 'A', entry: p.get('entry'), start: 0, speed: 1, contain_at: null, adaptive: false, active: true }], fixes: [], maintenance: [], detection: true, speed: 1 };
  req.attackers = req.attackers.map(norm);
  if (p.get('fixes')) { req.fixes = p.get('fixes').split(',').filter(Boolean); req.attackers.forEach(a => a.adaptive = p.get('adaptive') === '1' || a.adaptive); }
  let title = p.get('entry') ? `Attack from ${names[p.get('entry')]}` : sc?.title || 'Custom scenario', activePreset = sc && !p.get('entry') ? sc.presetKey : null;
  let res = sc && !p.get('entry') && !p.get('fixes') ? sc.result : null;
  let t = res ? Math.min(store.time || HORIZON, HORIZON) : 0, playing = false, raf = 0, last = 0, speed = 12;
  const entryOptions = sel => `<optgroup label="Ways in from outside">${entries.map(a => `<option value="${a.id}" ${a.id === sel ? 'selected' : ''}>${h(a.name)}</option>`).join('')}</optgroup>
    <optgroup label="Already inside (insider or compromised device)">${inside.map(a => `<option value="${a.id}" ${a.id === sel ? 'selected' : ''}>${h(a.name)}</option>`).join('')}</optgroup>`;

  root.innerHTML = `
    <div class="head"><div><h2>Attack simulation</h2><p class="lede">Configure one or more attackers, each with its own way in, start time and speed, and run them through the same city at the same time. The backend keeps every attacker's own path and history; alarms and isolation are shared, as they would be in a real control room.</p></div></div>
    <div class="banner"><span><b>Defensive simulation only.</b> Abstract model of how intrusions spread across the modelled city. No real system is scanned, contacted or attacked, and no exploit code exists in this project.</span></div>
    <div class="sheet" style="margin-bottom:16px"><h3>Attacker profiles</h3><p class="sub">Illustrative patterns described in MITRE ATT&CK for ICS, not attribution to any group. Each picks the matching way in from this city and an attacker speed.</p><div class="presets" id="profiles"></div></div>
    <div class="sheet" style="margin-bottom:16px"><h3>Ready-made situations</h3><p class="sub">Built from the loaded dataset by the backend, so the pairs are real ones from this city.</p><div class="presets" id="presets"></div></div>
    <div class="sheet" style="margin-bottom:16px">
      <div class="row" style="justify-content:space-between"><h3>Scenario</h3><div class="row">
        <button class="btn small" id="addAtk">Add attacker</button><button class="btn small" id="addMaint">Add maintenance window</button>
        <button class="btn small" id="reset">Reset</button><button class="btn primary" id="run">Run simulation</button></div></div>
      <div class="atkrow head"><span></span><span>Way in</span><span>Starts at (min)</span><span>Attacker type</span><span>Contain at (min)</span><span>Adaptive</span><span>Active</span><span></span></div>
      <div id="atkRows"></div>
      <div id="maintRows"></div>
      <div class="row" style="margin-top:14px;gap:16px">
        <label class="chk"><input type="checkbox" id="det" ${req.detection ? 'checked' : ''}> Detection and isolation on</label>
        <label class="fl" style="width:200px" title="Failsafe island mode: at this minute internet and vendor access are cut and the operator is paged. Blank = off.">Failsafe island mode at (min)<input class="f" type="number" min="0" max="360" step="5" id="island" placeholder="off" value="${req.island_at ?? ''}"></label>
        <label class="fl" style="flex:1;min-width:260px">Defences applied before the attack (what-if fixes)<select class="f" id="fixPick"><option value="">Loading fixes…</option></select></label>
      </div>
      <div class="chips" id="fixChips" style="margin-top:8px"></div>
    </div>
    <div id="results"></div>`;
  const $ = s => root.querySelector(s);

  const PROFS = [
    { k: 'edge', title: 'Edge-device intrusion', text: 'Exploits an internet-facing VPN or gateway (ATT&CK ICS T0822 External Remote Services, T0866 Exploitation of Remote Services). Fast, skilled.', types: ['vpn_gateway', 'telecom_gateway', 'web_server'], speed: 2 },
    { k: 'vendor', title: 'Supply-chain access', text: 'Comes in through a vendor\'s remote access (T0862 Supply Chain Compromise, T0859 Valid Accounts). Patient.', vendor: true, speed: 1 },
    { k: 'exposed', title: 'Exposed field device', text: 'Finds an internet-accessible controller or camera (T0883 Internet Accessible Device). Opportunistic.', types: ['rtu', 'camera', 'iot_gateway', 'plc', 'medical_iot'], speed: 0.5 },
    { k: 'insider', title: 'Insider or infected laptop', text: 'Already inside on a workstation (T0859 Valid Accounts, T0886 Remote Services). No internet link needed.', types: ['workstation'], inside: true, speed: 1 },
  ];
  const pickFor = pf => {
    const pool = g.assets.filter(a => pf.vendor ? a.is_entry && inv.assets.find(x => x.id === a.id)?.vendor_access : pf.inside ? pf.types.includes(a.type) : a.is_entry && pf.types.includes(a.type));
    return pool.sort((a, b) => b.risk - a.risk)[0];
  };
  $('#profiles').innerHTML = PROFS.map(pf => { const a = pickFor(pf); return `<button class="preset" data-p="${pf.k}" ${a ? '' : 'disabled'}><b>${h(pf.title)}</b><span>${h(pf.text)}${a ? ` Here: ${h(a.name)}.` : ' No matching system in this city.'}</span></button>`; }).join('');
  $('#profiles').querySelectorAll('[data-p]').forEach(b => b.onclick = () => {
    const pf = PROFS.find(x => x.k === b.dataset.p), a = pickFor(pf); if (!a) return;
    req = { attackers: [{ id: 'A', entry: a.id, start: 0, speed: pf.speed, contain_at: null, adaptive: false, active: true }], fixes: [], maintenance: [], detection: true, speed: 1 };
    title = `Profile: ${pf.title}`; activePreset = null; drawConfig(); run();
  });
  $('#presets').innerHTML = presets.map(pr => `<button class="preset ${pr.key === activePreset ? 'on' : ''}" data-k="${pr.key}"><b>${pr.key}. ${h(pr.title)}</b><span>${h(pr.text)}</span></button>`).join('');
  $('#presets').querySelectorAll('.preset').forEach(b => b.onclick = () => {
    const pr = presets.find(x => x.key === b.dataset.k);
    req = { attackers: pr.attackers.map(a => norm({ start: 0, ...a })), fixes: [...pr.fixes], maintenance: pr.maintenance.map(w => ({ ...w })), detection: true, speed: 1, island_at: pr.island_at ?? null, c2: true };
    title = `${pr.key}. ${pr.title}`; activePreset = pr.key;
    $('#presets').querySelectorAll('.preset').forEach(x => x.classList.toggle('on', x === b));
    drawConfig(); run();
  });

  function drawConfig() {
    if ($('#island')) $('#island').value = req.island_at ?? '';
    $('#atkRows').innerHTML = req.attackers.map((a, i) => `<div class="atkrow" data-i="${i}">${atkBadge(a.id)}
      <select class="f" data-f="entry" aria-label="Way in for attacker ${a.id}">${entryOptions(a.entry)}</select>
      <input class="f" type="number" min="0" max="360" step="5" data-f="start" value="${a.start}" aria-label="Start minute">
      <select class="f" data-f="speed" aria-label="Attacker type">${PROFILES.map(([v, l]) => `<option value="${v}" ${+v === +a.speed ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <input class="f" type="number" min="0" max="360" step="5" data-f="contain_at" value="${a.contain_at ?? ''}" placeholder="never" aria-label="Contain at minute">
      <label class="chk" title="Re-picks the way in that does the most harm against the current defences"><input type="checkbox" data-f="adaptive" ${a.adaptive ? 'checked' : ''}> adapts</label>
      <label class="chk"><input type="checkbox" data-f="active" ${a.active !== false ? 'checked' : ''}> on</label>
      <button class="btn small" data-del="${i}" aria-label="Remove attacker ${a.id}" ${req.attackers.length < 2 && !req.maintenance.length ? 'disabled' : ''}>×</button></div>
      ${(a.more || []).map((e, k) => `<div class="atkrow sub" data-i="${i}" data-k="${k}"><span class="faint" aria-hidden="true">↳</span>
        <select class="f" data-g="asset" aria-label="Another way in for attacker ${a.id}">${entryOptions(e.asset)}</select>
        <input class="f" type="number" min="0" max="360" step="5" data-g="start" value="${e.start}" aria-label="Minute this way in opens">
        <span class="faint" style="font-size:12px;grid-column:span 4">Same attacker ${a.id}, another way in</span>
        <button class="btn small" data-delk="${k}" aria-label="Remove this way in">×</button></div>`).join('')}
      <div class="atkrow sub"><span></span><button class="linkbtn" data-more="${i}" style="justify-self:start;grid-column:span 3">+ another way in for attacker ${a.id}</button></div>`).join('');
    $('#maintRows').innerHTML = req.maintenance.map((w, i) => `<div class="atkrow" data-m="${i}"><span class="tag warn" title="Maintenance">M</span>
      <select class="f" data-f="asset" aria-label="System being patched">${inv.assets.filter(a => a.cve_count).sort((a, b) => a.patchable_without_downtime - b.patchable_without_downtime).map(a => `<option value="${a.id}" ${a.id === w.asset ? 'selected' : ''}>${h(a.name)}${a.patchable_without_downtime ? '' : ` (${a.downtime_hours_to_patch} h down)`}</option>`).join('')}</select>
      <input class="f" type="number" min="0" max="360" step="5" data-f="start" value="${w.start}" aria-label="Maintenance start minute">
      <label class="fl" style="grid-column:span 1">hours<input class="f" type="number" min="0.5" max="48" step="0.5" data-f="hours" value="${w.hours}" aria-label="Hours offline"></label>
      <span class="faint" style="font-size:12px;grid-column:span 3">Offline while patched; patched afterwards</span>
      <button class="btn small" data-delm="${i}" aria-label="Remove maintenance window">×</button></div>`).join('');
    $('#atkRows').querySelectorAll('.atkrow').forEach(row => row.querySelectorAll('[data-f]').forEach(inp => inp.onchange = () => {
      const a = req.attackers[+row.dataset.i], f = inp.dataset.f;
      a[f] = inp.type === 'checkbox' ? inp.checked : f === 'entry' ? inp.value : inp.value === '' ? null : +inp.value; sync(a); activePreset = null; title = 'Custom scenario';
    }));
    $('#atkRows').querySelectorAll('.atkrow.sub[data-k]').forEach(row => row.querySelectorAll('[data-g]').forEach(inp => inp.onchange = () => {
      const a = req.attackers[+row.dataset.i], e = a.more[+row.dataset.k];
      e[inp.dataset.g] = inp.dataset.g === 'asset' ? inp.value : +inp.value || 0; sync(a); activePreset = null; title = 'Custom scenario';
    }));
    $('#atkRows').querySelectorAll('[data-delk]').forEach(b => b.onclick = () => { const a = req.attackers[+b.closest('.atkrow').dataset.i]; a.more.splice(+b.dataset.delk, 1); sync(a); drawConfig(); });
    $('#atkRows').querySelectorAll('[data-more]').forEach(b => b.onclick = () => {
      const a = req.attackers[+b.dataset.more], used = new Set([a.entry, ...(a.more || []).map(e => e.asset)]);
      if ((a.more || []).length >= 3) return toast('Up to four ways in per attacker.');
      (a.more ||= []).push({ asset: (entries.find(e => !used.has(e.id)) || entries[0]).id, start: 0 }); sync(a); title = 'Custom scenario'; activePreset = null; drawConfig();
    });
    $('#maintRows').querySelectorAll('.atkrow').forEach(row => row.querySelectorAll('[data-f]').forEach(inp => inp.onchange = () => {
      const w = req.maintenance[+row.dataset.m]; w[inp.dataset.f] = inp.dataset.f === 'asset' ? inp.value : +inp.value; title = 'Custom scenario';
    }));
    $('#atkRows').querySelectorAll('[data-del]').forEach(b => b.onclick = () => { req.attackers.splice(+b.dataset.del, 1); req.attackers.forEach((a, i) => a.id = ATK[i]); drawConfig(); });
    $('#maintRows').querySelectorAll('[data-delm]').forEach(b => b.onclick = () => { req.maintenance.splice(+b.dataset.delm, 1); drawConfig(); });
    drawFixChips();
  }
  function drawFixChips() {
    const label = id => fixList?.find(f => f.id === id)?.fix || id;
    $('#fixChips').innerHTML = req.fixes.map(f => `<span class="tag white">${h(label(f))} <button class="linkbtn" data-rm="${h(f)}" aria-label="Remove fix">remove</button></span>`).join('') || '<span class="faint" style="font-size:12px">No defences changed. The city as it is in the dataset.</span>';
    $('#fixChips').querySelectorAll('[data-rm]').forEach(b => b.onclick = () => { req.fixes = req.fixes.filter(x => x !== b.dataset.rm); drawFixChips(); });
  }
  get('/api/fixes').then(fx => {
    fixList = fx.fixes;
    const groups = {}; fixList.forEach(f => (groups[f.type] ||= []).push(f));
    $('#fixPick').innerHTML = '<option value="">Add a fix…</option>' + Object.entries(groups).map(([k, list]) => `<optgroup label="${h(k.replace('_', ' '))}">${list.map(f => `<option value="${h(f.id)}">${h(f.fix)}</option>`).join('')}</optgroup>`).join('');
    $('#fixPick').onchange = e => { if (e.target.value && !req.fixes.includes(e.target.value)) req.fixes.push(e.target.value); e.target.value = ''; title = 'Custom scenario'; drawFixChips(); };
    drawFixChips();
  }).catch(() => { $('#fixPick').innerHTML = '<option>Fix list still computing, try again shortly</option>'; });
  $('#addAtk').onclick = () => { if (req.attackers.length >= 4) return toast('Up to four attackers.'); const used = new Set(req.attackers.map(a => a.entry)); req.attackers.push(norm({ id: ATK[req.attackers.length], entry: (entries.find(e => !used.has(e.id)) || entries[0]).id, start: 15 })); title = 'Custom scenario'; drawConfig(); };
  $('#addMaint').onclick = () => { if (req.maintenance.length >= 2) return toast('Up to two maintenance windows.'); const a = inv.assets.find(x => x.cve_count && !x.patchable_without_downtime) || inv.assets.find(x => x.cve_count); req.maintenance.push({ asset: a.id, start: 20, hours: a.downtime_hours_to_patch || 1, patch: true }); drawConfig(); };
  $('#reset').onclick = () => { req = { attackers: [norm({ id: 'A', entry: entries[0].id, start: 0 })], fixes: [], maintenance: [], detection: true, speed: 1, island_at: null }; title = 'Custom scenario'; activePreset = null; $('#det').checked = true; $('#island').value = ''; drawConfig(); toast('Scenario reset'); };
  $('#det').onchange = e => req.detection = e.target.checked;
  $('#island').onchange = e => { req.island_at = e.target.value === '' ? null : Math.max(0, Math.min(360, +e.target.value)); title = 'Custom scenario'; activePreset = null; };
  $('#run').onclick = () => run();
  drawConfig();

  async function run() {
    stop();
    const r = $('#results'); r.innerHTML = '<div class="loading"><span class="spin"></span>Simulating</div>';
    const btn = $('#run'); btn.disabled = true; btn.textContent = 'Running…';
    try {
      req.attackers.forEach(sync);
      res = await runScenario(req, title);
      const s = store.scenario; s.presetKey = activePreset; store.scenario = s;
      t = 0; drawResults();
      $('#results').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
      play();
    } catch (e) { r.innerHTML = `<div class="err">${h(e.message)}</div>`; }
    finally { btn.disabled = false; btn.textContent = 'Run simulation'; }
  }

  let map;
  function drawResults() {
    const r = $('#results');
    if (!res) { r.innerHTML = '<div class="chart-empty">Pick a ready-made situation or configure attackers, then run the simulation.</div>'; return; }
    const cb = res.combined, multi = res.attackers.length > 1;
    const pinned = getPinned();
    r.innerHTML = `
      <div class="grid g12">
        <div class="sheet">
          <div class="clockbig" id="clock">T+00:00</div>
          <p class="mute" id="clockSub" style="margin-top:4px"></p>
          <div class="player" style="margin-top:14px">
            <button class="iconbtn" id="play" aria-label="Play or pause the replay"><svg viewBox="0 0 16 16"><path d="M4 2l10 6-10 6z"/></svg></button>
            <input type="range" id="scrub" min="0" max="${HORIZON}" step="1" value="0" aria-label="Replay time">
          </div>
          <div class="row" style="margin-top:8px"><div class="seg" id="spd"><button data-s="4">1×</button><button data-s="12" class="on">3×</button><button data-s="40">10×</button></div>
            <span class="faint" style="font-size:12px">Space plays and pauses</span></div>
          <h4 style="font:700 19px var(--display);margin:20px 0 8px">Attackers</h4>
          <div id="atkCards"></div>
          <div class="row" style="margin-top:16px">
            <button class="btn small" id="pin">Save for comparison</button>
            <button class="btn small" id="toTwin" title="Opens the 3D twin and replays this exact scenario: every attacker in its own colour, staggered starts, containment, maintenance and failsafe">Replay in 3D twin</button>
            <button class="btn small" id="clear">Clear results</button>
          </div>
        </div>
        <div class="chart-card"><div class="row" style="justify-content:space-between"><h3>Who got where</h3><div class="chart-legend" style="margin:0">${res.attackers.map(a => `<span><i style="background:${atkColor(a.id)}"></i>Attacker ${a.id}</span>`).join('')}</div></div>
          <div class="chart-legend maplegend" style="margin:6px 0 4px"><span><i class="lg dot"></i>Not reached</span><span><i class="lg fill"></i>Compromised (colour = first attacker)</span><span><i class="lg ring"></i>Outer ring = second attacker also got there</span><span><i class="lg dash"></i>Dashed ring = way in not open yet</span><span><i class="lg flight"></i>Line growing = attack in flight</span>${res.maintenance?.length ? '<span><i class="lg maint"></i>Amber = offline for patching</span>' : ''}</div>
          <div id="map"></div></div>
      </div>
      <div class="kpis" style="margin-top:16px">
        <div class="kpi"><div class="v pink">${fmt(cb.harm)}</div><div class="l">Combined harm</div><div class="s">people × minutes in 6 hours</div></div>
        <div class="kpi"><div class="v ${cb.first_failure_min < HORIZON ? 'pink' : ''}">${tmin(cb.first_failure_min)}</div><div class="l">First service lost</div><div class="s">${cb.services.filter(s => s.population > 0).length} service${cb.services.length === 1 ? '' : 's'} lost in the window</div></div>
        <div class="kpi"><div class="v">${cb.assets_lost}<span class="mute" style="font-size:20px"> / ${g.assets.length}</span></div><div class="l">Systems compromised</div><div class="s">${cb.contested.length} contested by more than one attacker</div></div>
        <div class="kpi"><div class="v">${res.detected_at == null ? '–' : tmin(res.detected_at)}</div><div class="l">First detected</div><div class="s">${res.request.detection ? 'shared alarms isolate a zone 15 min later' : 'detection switched off'}</div></div>
      </div>
      <div class="grid g2" style="margin-top:16px">
        <div class="sheet"><h3>Services lost, and who caused it</h3><p class="sub">The cause is the compromise (or maintenance outage) whose loss broke the service rule.</p><div id="svcLost"></div></div>
        <div class="chart-card"><h3>${multi ? 'Together against each alone' : 'Harm over time'}</h3><p class="sub">${multi ? 'Harm if each attacker had acted alone, against the combined run. Together can be less than the sum (both hit the same service) or more (each half-breaks a service the other finishes).' : 'People without an essential service, minute by minute.'}</p><div id="soloChart"></div></div>
      </div>
      <div class="grid g2" style="margin-top:16px">
        <div class="sheet"><h3>Contested systems</h3><p class="sub">Reached by more than one attacker. The first one owns it; both records are kept.</p><div id="contested"></div></div>
        <div class="sheet"><h3>Event log</h3><p class="sub">Greyed events are still in the future at the replay time. <a href="#/timeline">Open the timeline</a></p><div class="evlog" id="evlog"></div></div>
      </div>
      <div class="sheet" style="margin-top:16px"><div class="row" style="justify-content:space-between"><h3>Compare scenarios</h3>${pinned.length ? '<button class="linkbtn" id="unpin">Clear saved</button>' : ''}</div>
        <p class="sub">Save runs to compare single against multi-attacker, before against after a fix, or with and without maintenance.</p><div id="cmp"></div></div>`;
    map = netmap(r.querySelector('#map'), g, { height: innerWidth < 700 ? 360 : 520, onClick: a => assetDrawer(a.id) });
    evCount = -1;
    r.querySelector('#atkCards').innerHTML = res.attackers.map(a => `<div style="display:grid;grid-template-columns:26px minmax(0,1fr) auto;gap:10px;padding:10px 0;border-bottom:1px solid var(--line)">
      ${atkBadge(a.id)}<div>${entriesOf(a).map((e, k) => `<b style="font-weight:600">${h(names[e.asset])}</b>${k ? ` <span class="faint" style="font-size:12px">from ${tmin(e.start)}</span>` : ''}`).join('<br>')}${a.adapted_from ? `<br><span class="tag warn">adapted from ${h(names[a.adapted_from])}</span>` : ''}
      <br><span class="faint" style="font-size:12px">starts ${tmin(a.start)}, ${PROFILES.find(p => +p[0] === +a.speed)?.[1] || a.speed + '×'}${a.contain_at != null ? `, contained ${tmin(a.contain_at)}${a.contained_by === 'failsafe' ? ' by the failsafe' : ''}` : ''}</span></div>
      <div style="text-align:right"><span class="tag ${a.status === 'active' ? 'pink' : 'white'}">${a.status}</span><br><span class="faint" style="font-size:12px">${a.reached} reached, ${a.owned} first</span></div></div>`).join('');
    table(r.querySelector('#svcLost'), cb.services, [
      { key: 'service', label: 'Service' }, { key: 'population', label: 'People', num: true, render: x => x.population.toLocaleString() },
      { key: 'fail_at', label: 'Lost', num: true, render: x => `<span class="pinkt">${tmin(x.fail_at)}</span>${x.restored_at != null ? `<br><span class="faint">back ${tmin(x.restored_at)}</span>` : ''}` },
      { key: 'cause', label: 'Cause', render: x => x.cause === 'maintenance' ? '<span class="tag warn">maintenance</span>' : x.cause ? `${atkBadge(x.cause)} <span class="faint">${h(names[x.cause_asset] || '')}</span>` : '–' },
    ], { sortKey: 'fail_at', desc: false, empty: 'No service lost within 6 hours.' });
    if (multi && res.solo) {
      bars(r.querySelector('#soloChart'), [...res.attackers.map(a => ({ label: `Attacker ${a.id} alone`, value: res.solo[a.id].harm, color: atkColor(a.id) })),
        { label: 'Sum of the solos', value: res.attackers.reduce((s, a) => s + res.solo[a.id].harm, 0), color: C.series[0] },
        { label: 'All together', value: cb.harm, color: '#FFFFFF' }], { horizontal: true, labelWidth: 140 });
    } else {
      const pts = []; let lost = 0;
      [...cb.services].sort((a, b) => a.fail_at - b.fail_at).forEach(s => { lost += s.population; pts.push([s.fail_at, lost]); });
      lines(r.querySelector('#soloChart'), [{ label: 'People without a service', color: C.pink, points: pts }], { yLabel: 'people' });
    }
    r.querySelector('#contested').innerHTML = cb.contested.length ? cb.contested.map(c => `<div class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)">
      <span>${h(c.name)}</span><span class="row">${Object.entries(c.times).map(([id, tt]) => `${atkBadge(id)}<span class="num ${id === c.winner ? '' : 'faint'}">${tmin(tt)}</span>`).join(' ')}</span></div>`).join('') : '<p class="mute">No system was reached by more than one attacker.</p>';
    drawCompare();
    r.querySelector('#play').onclick = () => playing ? stop() : play();
    r.querySelector('#scrub').oninput = e => { stop(); t = +e.target.value; frame(); };
    r.querySelectorAll('#spd button').forEach(b => { b.classList.toggle('on', +b.dataset.s === speed); b.onclick = () => { speed = +b.dataset.s; r.querySelectorAll('#spd button').forEach(x => x.classList.toggle('on', x === b)); }; });
    r.querySelector('#pin').onclick = () => { const p = getPinned(); p.push(summary()); setPinned(p.slice(-4)); drawCompare(); toast('Saved. Run another scenario to compare.'); };
    r.querySelector('#unpin')?.addEventListener('click', () => { setPinned([]); drawCompare(); });
    r.querySelector('#clear').onclick = () => { stop(); store.scenario = null; res = null; drawResults(); toast('Results cleared'); };
    r.querySelector('#toTwin').onclick = () => { const sc = store.scenario; withTwin(c => c.playScenario(sc.request, sc.title)); };
    frame();
  }
  function summary() {
    return { title, harm: res.combined.harm, first: res.combined.first_failure_min, lost: res.combined.assets_lost, contested: res.combined.contested.length,
      attackers: res.attackers.map(a => `${a.id}: ${names[a.entry]}${a.start ? ` at ${tmin(a.start)}` : ''}`).join('; '), fixes: res.request.fixes.length, maint: res.maintenance?.length || 0 };
  }
  function getPinned() { try { return JSON.parse(sessionStorage.getItem('cascade.compare') || '[]'); } catch { return []; } }
  function setPinned(v) { try { sessionStorage.setItem('cascade.compare', JSON.stringify(v)); } catch { /* ignore */ } }
  function drawCompare() {
    const rows = [...getPinned(), { ...summary(), current: true }];
    table($('#cmp'), rows, [
      { key: 'title', label: 'Scenario', render: x => `${h(x.title)}${x.current ? ' <span class="tag white">current</span>' : ''}<br><span class="faint" style="font-size:12px">${h(x.attackers)}</span>` },
      { key: 'fixes', label: 'Fixes', num: true }, { key: 'maint', label: 'Maint.', num: true },
      { key: 'harm', label: 'Harm', num: true, render: x => fmt(x.harm) }, { key: 'first', label: 'First loss', num: true, render: x => tmin(x.first) },
      { key: 'lost', label: 'Systems lost', num: true }, { key: 'contested', label: 'Contested', num: true }], { sortKey: null });
  }
  let evCount = -1;
  function frame() {
    if (!res || !map) return;
    store.time = t;
    const { st, paths } = mapState(res, t, names);
    map.update(st, paths);
    const lost = res.combined.services.filter(s => s.fail_at <= t && (s.restored_at == null || s.restored_at > t));
    const clock = $('#clock'); if (!clock) return;
    clock.textContent = tmin(t).replace('none in 6 h', 'T+06:00'); clock.classList.toggle('lost', lost.length > 0);
    $('#clockSub').innerHTML = lost.length ? `<span class="pinkt">${lost.map(s => h(s.service)).join(', ')} lost</span>` : 'All services running';
    $('#scrub').value = t;
    const past = res.events.filter(e => e.t <= t).length;          // rebuild the log only when an event crosses the clock
    if (past !== evCount) {
      evCount = past;
      $('#evlog').innerHTML = res.events.map((e, i) => `<div class="${e.t > t ? 'future' : ''} ${i === past - 1 ? 'now' : ''}"><span class="t">${tmin(e.t)}</span>${e.attacker && e.attacker.length === 1 ? atkBadge(e.attacker) : '<span></span>'}<span class="${e.kind === 'service_down' ? 'pinkt' : e.kind === 'maintenance' || e.kind === 'failsafe' ? 'warnt' : ''}">${h(e.text)}</span></div>`).join('');
    }
  }
  function play() {
    if (!res) return;
    if (t >= HORIZON) t = 0;
    playing = true; last = performance.now();
    const btn = $('#play'); if (btn) btn.innerHTML = '<svg viewBox="0 0 16 16"><path d="M3 2h4v12H3zM9 2h4v12H9z"/></svg>';
    const step = now => { if (!playing) return; t = Math.min(HORIZON, t + (now - last) / 1000 * speed); last = now; frame(); if (t >= HORIZON) return stop(); raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
  }
  function stop() { playing = false; cancelAnimationFrame(raf); const btn = $('#play'); if (btn) btn.innerHTML = '<svg viewBox="0 0 16 16"><path d="M4 2l10 6-10 6z"/></svg>'; }
  const key = e => { if (e.code === 'Space' && !/INPUT|SELECT|TEXTAREA|BUTTON/.test(document.activeElement.tagName)) { e.preventDefault(); playing ? stop() : play(); } };
  addEventListener('keydown', key);
  ctx.onLeave(() => { stop(); removeEventListener('keydown', key); });
  if (p.get('compare') && req.fixes.length) {     // e.g. from Attack paths: the same attack without, then with, the fix
    (async () => {
      const fx = [...req.fixes], label = fx.map(f => fixList?.find(x => x.id === f)?.fix || f).join(', ');
      req.fixes = []; title = `Before: attack from ${names[req.attackers[0].entry]}`; drawFixChips(); await run();
      if (!res) return;
      const pinned = getPinned(); pinned.push(summary()); setPinned(pinned.slice(-4));
      req.fixes = fx; title = `After: ${label}`; drawFixChips(); await run();
      toast('Compared: the same attack without and with the fix. See "Compare scenarios" below.');
    })();
  } else if (p.get('entry') || p.get('fixes')) run(); else drawResults();
}

// ======================================= ACTIVE INCIDENTS =======================================
export async function incidents(root) {
  const sc = store.scenario;
  if (!sc) { root.innerHTML = noScenario('Active incidents'); return; }
  loading(root, 'Loading incidents');
  try {
    const g = await get('/api/graph');
    const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
    const res = sc.result, t = store.time ?? HORIZON;
    const applied = sc.applied || [];
    root.innerHTML = `
      <div class="head"><div><h2>Active incidents</h2><p class="lede">Each simulated attacker in "${h(sc.title)}" is one incident. State shown at the replay time <b class="num">${tmin(t)}</b>; change it on the Attack simulation or Timeline page.</p></div>
        <div class="row"><a class="btn" href="#/simulate">Back to the simulation</a></div></div>
      <div class="banner"><span><b>Applied to the simulation</b> means the scenario was re-run with that change. <b>Recommended</b> actions are advice only and change nothing.</span></div>
      ${applied.length ? `<div class="sheet" style="margin-bottom:16px"><h3>Applied so far</h3>${applied.map(a => `<p class="note" style="margin-top:6px">${h(a)}</p>`).join('')}</div>` : ''}
      <div class="grid g2" id="inc"></div>`;
    root.querySelector('#inc').innerHTML = res.attackers.map(a => {
      const sofar = Object.entries(a.compromised).filter(([, tt]) => tt <= t);
      const next = Object.entries(a.compromised).filter(([, tt]) => tt > t).sort((x, y) => x[1] - y[1])[0];
      const svc = res.combined.services.filter(s => s.cause === a.id);
      const ents = entriesOf(a), waiting = ents.filter(e => e.start > t);
      const state = a.status === 'blocked by failsafe' ? 'Blocked by the failsafe' : a.active === false ? 'Blocked before it started'
        : a.start > t ? `Not started yet (comes in at ${tmin(a.start)})` : a.contain_at != null && a.contain_at <= t ? `Contained at ${tmin(a.contain_at)}${a.contained_by === 'failsafe' ? ' (failsafe)' : ''}`
        : !Object.keys(a.compromised).length ? 'Blocked' : next ? 'Spreading' : 'Stopped (no further reach)';
      const done = /Blocked|Contained/.test(state);
      const det = res.detected_at != null && res.detected_at <= t ? `${Math.round(t - res.detected_at)} min since first detection` : 'Not detected yet';
      return `<div class="sheet" data-a="${a.id}">
        <div class="row" style="justify-content:space-between">${atkBadge(a.id)}<h3 style="flex:1;font-size:24px">Incident ${a.id}: ${h(names[a.entry])}${ents.length > 1 ? ` <span class="faint" style="font-size:15px">+${ents.length - 1} more way${ents.length > 2 ? 's' : ''} in</span>` : ''}</h3><span class="tag ${state === 'Spreading' ? 'pink' : 'white'}" data-state>${h(state)}</span></div>
        <dl class="kv" style="margin-top:12px">
          <dt>Way${ents.length > 1 ? 's' : ''} in</dt><dd>${ents.map(e => `${h(names[e.asset])}${ents.length > 1 || e.start ? ` <span class="faint">from ${tmin(e.start)}${e.start > t ? ', not open yet' : ''}</span>` : ''}`).join('<br>')}${a.adapted_from ? ` <span class="tag warn">adapted from ${h(names[a.adapted_from])}</span>` : ''}</dd>
          <dt>Started</dt><dd>${tmin(a.start)}</dd><dt>Detection</dt><dd>${det}</dd>
          <dt>Systems compromised</dt><dd>${sofar.length} so far${sofar.length ? `: ${sofar.slice(-4).map(([id]) => h(names[id])).join(', ')}${sofar.length > 4 ? '…' : ''}` : ''}</dd>
          <dt>Next target</dt><dd>${next ? `${h(names[next[0]])} at ${tmin(next[1])}` : 'none'}</dd>
          <dt>Services it caused lost</dt><dd>${svc.length ? svc.map(s => `${h(s.service)} <span class="faint">${tmin(s.fail_at)}</span>`).join('<br>') : 'none'}</dd>
        </dl>
        <h4 style="font:700 18px var(--display);margin:16px 0 8px">Apply to the simulation</h4>
        <div class="row">
          <button class="btn small primary" data-act="contain" ${a.start > t || done ? 'disabled' : ''} title="${a.start > t ? 'It has not started yet at this replay time' : done ? 'Already stopped' : ''}">Contain now (${tmin(t)})</button>
          ${next && !done ? `<button class="btn small" data-act="monitor" data-target="${next[0]}">Monitor next target</button>` : ''}
          <button class="btn small" data-act="block" ${a.status === 'blocked by failsafe' ? 'disabled' : ''}>Block before it starts</button>
        </div>
        <h4 style="font:700 18px var(--display);margin:16px 0 8px">Recommended (advice only)</h4>
        <div data-rec class="mute" style="font-size:13px"><span class="spin"></span> Loading plan</div></div>`;
    }).join('');
    for (const a of res.attackers) {
      const card = root.querySelector(`[data-a="${a.id}"]`);
      if (a.status === 'blocked by failsafe') { card.querySelector('[data-rec]').textContent = 'Nothing to do: the failsafe refused this way in.'; }
      else api('/api/containment', { entry_points: entriesOf(a).map(e => e.asset), fixes: sc.request.fixes }).then(plan => {
        const items = plan.items.filter(i => i.kind === 'asset' && i.deadline + a.start >= t).slice(0, 3);
        card.querySelector('[data-rec]').innerHTML = items.length ? items.map(i => `<p style="margin:6px 0"><b class="num">by ${tmin(i.deadline + a.start)}</b> ${h(i.action)}</p>`).join('') + '<a href="#/response">Full response plan</a>' : 'Every deadline has passed at this replay time.';
      }).catch(() => card.querySelector('[data-rec]').textContent = 'Plan unavailable.');
      card.querySelectorAll('[data-act]').forEach(b => b.onclick = async () => {
        const req = structuredClone(sc.request), at = req.attackers.find(x => x.id === a.id);
        let note;
        if (b.dataset.act === 'contain') { at.contain_at = Math.round(t); note = `Attacker ${a.id} contained at ${tmin(t)}`; }
        if (b.dataset.act === 'block') { at.active = false; note = `Attacker ${a.id} blocked before it started (removed from the run)`; }
        if (!at) return toast('This attacker is no longer in the scenario. Re-run it from the Attack simulation page.');
        if (b.dataset.act === 'monitor') { const f = `monitor:${b.dataset.target}`; if (!req.fixes.includes(f)) req.fixes.push(f); note = `Monitoring added on ${names[b.dataset.target]}`; }
        if (!req.attackers.some(x => x.active !== false)) return toast('At least one attacker must stay in the run. Clear the scenario instead.');
        b.disabled = true; b.innerHTML = '<span class="spin"></span>';
        try {
          const before = sc.result.combined.harm;
          const r2 = await api('/api/multi', req);
          // blocked attackers stay listed (greyed) so the incident does not silently disappear
          for (const x of req.attackers.filter(x => x.active === false && !r2.attackers.some(y => y.id === x.id)))
            r2.attackers.push({ ...x, entries: entriesOf(x), compromised: {}, parents: {}, path: [], reached: 0, owned: 0, status: 'blocked', last_t: null });
          r2.attackers.sort((p, q) => p.id.localeCompare(q.id));
          store.scenario = { ...sc, request: req, result: r2, presetKey: null, title: sc.title.endsWith('(modified)') ? sc.title : `${sc.title} (modified)`, applied: [...applied, `${note}. Harm ${fmt(before)} → ${fmt(r2.combined.harm)} people-min.`] };
          toast(`${note}. Harm ${fmt(before)} → ${fmt(r2.combined.harm)}.`);
          incidents(root);
        } catch (e) { toast(e.message); b.disabled = false; }
      });
    }
  } catch (e) { errorBox(root, e); }
}
const noScenario = (name) => `<div class="head"><div><h2>${name}</h2><p class="lede">Nothing is running. Incidents come from the simulated scenario you run on the Attack simulation page.</p></div></div>
  <div class="chart-empty">No simulated scenario yet. <a href="#/simulate">Run one</a>, for example "B. Staggered attacks".</div>`;

// ======================================= ATTACK TIMELINE =======================================
export async function timeline(root, ctx) {
  const sc = store.scenario;
  if (!sc) { root.innerHTML = noScenario('Attack timeline'); return; }
  const res = sc.result, X = v => `${Math.max(0, Math.min(100, v / HORIZON * 100))}%`;
  const NOW = v => `calc(var(--nm) + (100% - var(--nm)) * ${Math.max(0, Math.min(1, v / HORIZON)).toFixed(4)})`;   // same x as the lanes' tracks
  let g; try { g = await get('/api/graph'); } catch (e) { return errorBox(root, e); }
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  let t = Math.min(HORIZON, store.time ?? HORIZON);
  const laneName = (html, title) => `<span class="nm" title="${h(title)}">${html}</span>`;
  const fsT = res.failsafe?.at;
  root.innerHTML = `
    <div class="head"><div><h2>Attack timeline</h2><p class="lede">"${h(sc.title)}" over the 6-hour window. One lane per attacker (each tick is a system compromised), one for defence, one per service lost.</p></div>
      <div class="row"><a class="btn" href="#/simulate">Back to the simulation</a></div></div>
    <div class="sheet tl">
      <div class="axis">${[0, 60, 120, 180, 240, 300, 360].map((v, i, all) => `<span class="${i === 0 ? 'first' : i === all.length - 1 ? 'last' : ''}" style="left:${X(v)}">${tmin(v).replace('none in 6 h', 'T+06:00')}</span>`).join('')}</div>
      <div class="lanes">
      ${res.attackers.map(a => { const ents = entriesOf(a), nm = ents.map(e => names[e.asset]).join(' + ');
        return `<div class="lane" data-lane="${a.id}">${laneName(`${atkBadge(a.id)}<span class="tx">${h(nm)}</span>`, `Attacker ${a.id}: ${nm}${a.status === 'blocked by failsafe' ? ' (blocked by the failsafe)' : ''}`)}<div class="tr">
        ${a.status === 'blocked by failsafe' || a.status === 'blocked' ? `<span class="note" style="left:${X(a.start)}">${a.status === 'blocked' ? 'blocked before it started' : 'refused by the failsafe'}</span>` :
          `<span class="span" style="left:${X(a.start)};width:${X((a.contain_at ?? a.last_t ?? a.start) - a.start)};background:${atkColor(a.id)};opacity:.22"></span>`}
        ${ents.filter(e => e.start > 0).map(e => `<span class="mk start" style="left:${X(e.start)};border-color:${atkColor(a.id)}" title="${h(names[e.asset])} opens at ${tmin(e.start)}"></span>`).join('')}
        ${(a.path || []).map(p => `<span class="tick" title="${h(p.name)} at ${tmin(p.t)}${p.first ? '' : ' (another attacker got there first)'}" style="left:${X(p.t)};background:${p.first ? atkColor(a.id) : 'transparent'};border:1px solid ${atkColor(a.id)}"></span>`).join('')}
        ${a.contain_at != null && a.status !== 'blocked by failsafe' ? `<span class="mk stop" style="left:${X(a.contain_at)}" title="contained at ${tmin(a.contain_at)}${a.contained_by === 'failsafe' ? ' by the failsafe' : ''}"></span>` : ''}</div></div>`; }).join('')}
      <div class="lane">${laneName('Defence', 'Detection, isolation, maintenance and failsafe')}<div class="tr">
        ${res.detected_at != null ? `<span class="tick" style="left:${X(res.detected_at)};background:var(--white)" title="Detected ${tmin(res.detected_at)}"></span>` : ''}
        ${res.isolations.filter(i => i.at <= HORIZON).map(i => `<span class="tick" style="left:${X(i.at)};background:var(--soft)" title="${i.zone ? 'Zone ' + h(i.zone) : 'Network'} isolated ${tmin(i.at)}"></span>`).join('')}
        ${(res.maintenance || []).map(w => `<span class="span" style="left:${X(w.start)};width:${X(w.hours * 60)};background:var(--warn);opacity:.5" title="${h(names[w.asset])} offline for patching, ${tmin(w.start)} to ${tmin(w.start + 60 * w.hours)}"></span>`).join('')}
        ${fsT != null ? `<span class="tick fs" style="left:${X(fsT)}" title="Failsafe: internet and vendor access cut at ${tmin(fsT)}"></span>` : ''}</div></div>
      ${res.combined.services.map(s => `<div class="lane">${laneName(`<span class="tx">${h(s.service)}</span>`, `${s.service}: lost ${tmin(s.fail_at)}${s.cause ? ` (${s.cause === 'maintenance' ? 'maintenance' : s.cause === 'failsafe' ? 'failsafe' : 'attacker ' + s.cause})` : ''}`)}<div class="tr">
        ${s.backup_from != null ? `<span class="span" style="left:${X(s.backup_from)};width:${X(s.fail_at - s.backup_from)};background:var(--warn);opacity:.28" title="on backup from ${tmin(s.backup_from)}"></span>` : ''}
        <span class="span" style="left:${X(s.fail_at)};width:${X((s.restored_at ?? HORIZON) - s.fail_at)};background:var(--pink-deep)" title="lost ${tmin(s.fail_at)}${s.restored_at != null ? `, back ${tmin(s.restored_at)}` : ''}"></span></div></div>`).join('')}
      <div class="tnow" id="tnow" style="left:${NOW(t)}" aria-hidden="true"></div>
      </div>
      <div class="lane" style="border:0">${laneName('Replay time', 'Shared with the Attack simulation and Active incidents pages')}<div class="tr"><input type="range" id="tScrub" min="0" max="${HORIZON}" step="1" value="${Math.round(t)}" aria-label="Replay time" style="width:100%"></div></div>
      <p class="faint" style="font-size:12px;margin-top:10px">Filled tick = this attacker got there first; outlined = it arrived after another attacker. Coloured dashed line = a later way in opens; white bar = contained. White = detected; blue-white = isolation; amber = maintenance or a service on backup; pink bars = service lost. The dashed vertical line is the replay time (<span class="num" id="tLbl">${tmin(t).replace('none in 6 h', 'T+06:00')}</span>), shared with the simulation page.</p>
    </div>
    <div class="filters" style="margin-top:16px"><select class="f" id="who" aria-label="Filter events"><option value="">All events</option>${res.attackers.map(a => `<option value="${a.id}">Attacker ${a.id}</option>`).join('')}<option value="svc">Services only</option><option value="def">Defence only</option></select>
      <label class="chk"><input type="checkbox" id="past"> Only what has happened by the replay time</label></div>
    <div id="evt"></div>`;
  const DEF = ['detected', 'isolated', 'maintenance', 'maintenance_end', 'attacker_contained', 'failsafe', 'attacker_joins'];
  const draw = () => {
    const w = root.querySelector('#who').value, past = root.querySelector('#past').checked;
    const rows = res.events.filter(e => (!past || e.t <= t) && (!w || (w === 'svc' ? e.kind.startsWith('service') : w === 'def' ? DEF.includes(e.kind) : e.attacker === w)));
    table(root.querySelector('#evt'), rows, [
      { key: 't', label: 'Time', num: true, render: e => `<span class="${e.t > t ? 'faint' : ''}">${tmin(e.t)}</span>`, sort: e => -e.t },
      { key: 'attacker', label: 'Attacker', render: e => e.attacker && e.attacker.length === 1 ? atkBadge(e.attacker) : '–' },
      { key: 'kind', label: 'Kind', render: e => h(e.kind.replace(/_/g, ' ')) },
      { key: 'text', label: 'Event', render: e => `<span class="${e.kind === 'service_down' ? 'pinkt' : e.t > t ? 'faint' : ''}">${h(e.text)}</span>` }], { sortKey: 't', empty: 'No events match this filter.' });
  };
  root.querySelector('#who').onchange = draw; root.querySelector('#past').onchange = draw;
  root.querySelector('#tScrub').oninput = e => {
    t = +e.target.value; store.time = t;
    root.querySelector('#tnow').style.left = NOW(t); root.querySelector('#tLbl').textContent = tmin(t).replace('none in 6 h', 'T+06:00');
    if (root.querySelector('#past').checked) draw();
  };
  draw();
}

// ================================== CONTAINMENT AND RESPONSE ==================================
export async function response(root) {
  loading(root, 'Loading the response plan');
  try {
    const g = await get('/api/graph');
    const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
    const entries = g.assets.filter(a => a.is_entry).sort((a, b) => b.entry_prob - a.entry_prob);
    const sc = store.scenario;
    const sources = sc ? sc.result.attackers.map(a => ({ key: a.id, entry: a.entry, start: a.start, label: `Attacker ${a.id}: ${names[a.entry]}` })) : [];
    root.innerHTML = `
      <div class="head"><div><h2>Containment and response</h2><p class="lede">If this attack starts now, what must be done and by when. Each deadline is the minute the attacker arrives minus how long the action takes. Deadlines before the first alarm are ones you would miss without better monitoring.</p></div></div>
      <div class="filters"><label class="fl">Attack to respond to<select class="f" id="src" style="min-width:300px">
        ${sources.map(s => `<option value="atk:${s.key}">${h(s.label)} (current scenario)</option>`).join('')}
        ${entries.map(a => `<option value="entry:${a.id}">From ${h(a.name)}</option>`).join('')}</select></label></div>
      <div id="plan"></div>`;
    const drawPlan = async () => {
      const v = root.querySelector('#src').value, [kind, id] = v.split(':');
      const src = kind === 'atk' ? sources.find(s => s.key === id) : { entry: id, start: 0 };
      const out = root.querySelector('#plan'); out.innerHTML = '<div class="loading"><span class="spin"></span>Working out deadlines</div>';
      const plan = await api('/api/containment', { entry_points: [src.entry], fixes: kind === 'atk' ? sc.request.fixes : [] });
      const off = src.start || 0;
      const firstAsset = plan.items.find(i => i.kind === 'asset' && i.deadline > 0);
      out.innerHTML = `
        <div class="kpis" style="margin-bottom:16px">
          <div class="kpi"><div class="v">${plan.items.length}</div><div class="l">Actions</div><div class="s">systems to isolate, services to fail over</div></div>
          <div class="kpi"><div class="v">${plan.detected_at == null ? '–' : tmin(plan.detected_at + off)}</div><div class="l">First alarm</div><div class="s">when defenders would find out</div></div>
          <div class="kpi"><div class="v pink">${plan.deadlines_before_detection}</div><div class="l">Deadlines before the alarm</div><div class="s">missed unless monitoring improves</div></div>
          <div class="kpi"><div class="v">${firstAsset ? tmin(firstAsset.deadline + off) : '–'}</div><div class="l">First real deadline</div><div class="s">${firstAsset ? h(firstAsset.target_name) : ''}</div></div>
        </div>
        <div class="grid g21">
          <div class="sheet"><h3>Recommended actions</h3><p class="sub">Advice only. Nothing here changes the simulation until you apply it.</p>
            <ul class="steps">${plan.items.map(i => `<li class="${i.before_detection ? 'missed' : ''}"><span class="dl">${tmin(i.deadline + off)}</span>
              <div><b style="font-weight:600">${h(i.action)}</b><p>${h(i.why)}</p></div>
              <span class="tag ${i.before_detection ? 'pink' : 'white'}">${i.before_detection ? 'before the alarm' : 'after the alarm'}</span></li>`).join('')}</ul></div>
          <div class="sheet"><h3>Test it in the simulation</h3><p class="sub">Apply a containment to ${kind === 'atk' ? `attacker ${h(id)} in the current scenario` : 'this attack'} and re-run.</p>
            <div class="row" style="flex-direction:column;align-items:stretch">
              ${plan.detected_at != null ? `<button class="btn wrap" data-c="${Math.round(plan.detected_at + off + 15)}">Contain at the first alarm + 15 min (${tmin(plan.detected_at + off + 15)})</button>` : ''}
              ${firstAsset ? `<button class="btn wrap" data-c="${Math.round(firstAsset.deadline + off)}">Contain at the first deadline (${tmin(firstAsset.deadline + off)})</button>` : ''}
              <button class="btn wrap" data-m="1">Monitor the entry point instead</button>
            </div><div id="testOut" style="margin-top:14px"></div></div>
        </div>`;
      out.querySelectorAll('[data-c],[data-m]').forEach(b => b.onclick = async () => {
        const base = kind === 'atk' ? structuredClone(sc.request) : { attackers: [{ id: 'A', entry: src.entry, start: 0, speed: 1, contain_at: null, adaptive: false, active: true }], fixes: [], maintenance: [], detection: true, speed: 1 };
        const target = base.attackers.find(a => a.id === (kind === 'atk' ? id : 'A'));
        const tested = structuredClone(base);
        if (b.dataset.c) tested.attackers.find(a => a.id === target.id).contain_at = +b.dataset.c;
        else if (!tested.fixes.includes(`monitor:${src.entry}`)) tested.fixes.push(`monitor:${src.entry}`);
        const o = out.querySelector('#testOut'); o.innerHTML = '<span class="spin"></span> Re-running';
        try {
          const [r0, r1] = await Promise.all([api('/api/multi', base), api('/api/multi', tested)]);
          o.innerHTML = `<p class="note"><b>Applied in a test run.</b> Harm ${fmt(r0.combined.harm)} → ${fmt(r1.combined.harm)} people-min (−${pct(r0.combined.harm, r1.combined.harm)}%). First loss ${tmin(r0.combined.first_failure_min)} → ${tmin(r1.combined.first_failure_min)}.</p>
            <button class="btn small primary" style="margin-top:10px" id="keep">Make this the current scenario</button>`;
          o.querySelector('#keep').onclick = () => { store.scenario = { request: tested, result: r1, title: (sc?.title || `Attack from ${names[src.entry]}`) + ' + containment', ranAt: Date.now(), applied: [...(sc?.applied || []), b.textContent.trim()] }; toast('Saved as the current scenario.'); };
        } catch (e) { o.innerHTML = `<div class="err">${h(e.message)}</div>`; }
      });
    };
    root.querySelector('#src').onchange = drawPlan; drawPlan();
  } catch (e) { errorBox(root, e); }
}
