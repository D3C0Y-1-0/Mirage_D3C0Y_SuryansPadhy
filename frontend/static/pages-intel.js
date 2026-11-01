// Graphs and analytics, ML insights, Fix optimiser.
import { api, get, h, fmt, tmin, pm, pct, table, store, loading, errorBox, toast, atkColor, atkBadge, withTwin } from './core.js';
import { bars, scatter, lines, grouped, empty, COLORS as C } from './charts.js';
import { netmap } from './netmap.js';
import { assetDrawer } from './pages-ops.js';

const sgn = v => v > 0 ? `−${v}%` : v < 0 ? `+${-v}%` : 'no change in';
const card = (id, title, sub, span = '') => `<div class="chart-card" ${span}><h3>${title}</h3><p class="sub">${sub}</p><div id="${id}"><div class="loading"><span class="spin"></span>Loading</div></div></div>`;

// ======================================= GRAPHS =======================================
export async function graphs(root) {
  const sc = store.scenario;
  root.innerHTML = `
    <div class="head"><div><h2>Graphs and analytics</h2><p class="lede">Every chart is computed by the backend from the loaded dataset or from a simulation it ran. Hover for values; each chart can be downloaded as data or image.</p></div>
      <div class="filters" style="margin:0"><label class="fl">Sector filter (system charts)<select class="f" id="gSector"><option value="">All sectors</option></select></label></div></div>
    <h3 style="font-size:24px;margin:8px 0 12px">Risk</h3>
    <div class="grid g2">
      ${card('c1', '1. Risk distribution', 'Number of systems in each risk band.')}
      ${card('c2', '2. Criticality against risk', 'Each dot is a system. Top-right = critical and at risk. White = a way in from outside.')}
      ${card('c3', '3. Severity (CVSS) against likelihood (EPSS)', 'Each dot is a CVE; amber = on CISA KEV.')}
      ${card('c4', '4. Vulnerabilities by zone', 'CVE count and known-exploited count per network zone.')}
      ${card('c5', '5. High-risk systems by sector', 'Systems with risk 15+ against all systems, per sector.')}
      ${card('c8', '8. Expected against worst-case harm, per way in', 'Likelihood-weighted harm (P × harm) against the harm if that way in is used. Same unit.')}
    </div>
    <h3 style="font-size:24px;margin:28px 0 12px">Attack</h3>
    <div class="grid g2">
      ${card('c6', '6. Attack propagation over time', 'Systems compromised in the worst single attack, with and without detection.')}
      ${card('c7', '7. Service disruption over time', 'People without an essential service in the worst single attack.')}
      ${card('c12', '12. Attacker-specific progression', sc ? `Systems reached per attacker in "${h(sc.title)}".` : 'Run a multi-attacker scenario to fill this chart.')}
      ${card('c14', '14. Attack-path choke points', 'Links that the most ways in use to reach systems behind a service.')}
    </div>
    <div class="grid" style="margin-top:16px">${card('c13', '13. Infrastructure dependency graph', 'Same layout as the 3D twin. Solid = attack paths; dashed = dependencies. Highlighted = choke-point links and the most central systems (betweenness on attack paths).')}</div>
    <h3 style="font-size:24px;margin:28px 0 12px">Defence</h3>
    <div class="grid g2">
      ${card('c10', '10. Risk reduction per fix (top 12)', 'Expected-harm reduction from each single fix, re-simulated against every way in.')}
      ${card('c11', '11. Fix cost against risk reduction', 'Staff hours against expected-harm reduction. Top-left is the cheap, effective corner.')}
      ${card('c9', '9. Before and after the optimiser\'s bundle', 'Default budget: 3 fixes, 2 maintenance windows, adaptive attacker.')}
      ${card('c15', 'Sensitivity: does the fix order survive ±30%?', 'Each estimate moved 30% down and up; did the top fix stay the top fix?')}
    </div>
    <p class="faint" style="margin-top:16px;font-size:12px">Not shown: P50/P90 impact bands. The model is deterministic for a given set of assumptions; the sensitivity chart above is the honest stand-in for uncertainty.</p>`;
  const $ = s => root.querySelector(s);
  const safe = async (id, fn) => { try { await fn($(id)); } catch (e) { empty($(id), `Could not load: ${h(e.message)}`); } };
  const inv = await get('/api/assets').catch(() => null);
  if (inv) $('#gSector').innerHTML += [...new Set(inv.assets.map(a => a.sector).filter(Boolean))].sort().map(s => `<option>${h(s)}</option>`).join('');
  const sysCharts = () => {
    const sec = $('#gSector').value, A = inv.assets.filter(a => !sec || a.sector === sec);
    const bands = [['Low (<5)', 0, 5], ['Medium (5-15)', 5, 15], ['High (15-30)', 15, 30], ['Very high (30+)', 30, 1e9]];
    safe('#c1', el => bars(el, bands.map(([l, lo, hi]) => ({ label: l, value: A.filter(a => a.risk >= lo && a.risk < hi).length, color: lo >= 15 ? '#FFFFFF' : C.series[0] })), { fmtv: v => v.toFixed(0), yLabel: 'systems' }));
    safe('#c2', el => scatter(el, A.map(a => ({ x: a.criticality + (a.id.charCodeAt(a.id.length - 1) % 5 - 2) * .06, y: a.risk, label: a.name, color: a.is_entry ? '#FFFFFF' : C.series[0], a })),
      { xMin: 0, xMax: 5, xLabel: 'criticality (1-5)', yLabel: 'risk', fmtx: v => v.toFixed(0), onClick: p => assetDrawer(p.a.id),
        legendItems: [{ label: 'Way in from outside', color: '#FFFFFF' }, { label: 'Internal', color: C.series[0] }], tipFmt: p => `<b>${h(p.label)}</b><br>criticality ${p.a.criticality}, risk ${p.a.risk}` }));
  };
  if (inv) { sysCharts(); $('#gSector').onchange = sysCharts; }
  safe('#c3', async el => { const { vulns } = await get('/api/vulns'); scatter(el, vulns.map(v => ({ x: v.cvss, y: v.epss ?? 0, label: v.cve_id, color: v.kev ? C.warn : C.series[0] })), { xMin: 0, xMax: 10, yMax: 1, xLabel: 'CVSS', yLabel: 'EPSS', fmtx: x => x.toFixed(0), fmty: y => y.toFixed(1), legendItems: [{ label: 'On KEV', color: C.warn }, { label: 'Not on KEV', color: C.series[0] }] }); });
  const an = await get('/api/analytics').catch(() => null);
  if (an) {
    safe('#c4', el => grouped(el, an.by_zone.map(z => z.name), [{ name: 'CVEs', color: C.series[0], values: an.by_zone.map(z => z.cves) }, { name: 'Known exploited', color: C.warn, values: an.by_zone.map(z => z.kev) }], { fmtv: v => v.toFixed(0) }));
    safe('#c5', el => grouped(el, an.by_sector.map(z => z.name), [{ name: 'All systems', color: C.series[0], values: an.by_sector.map(z => z.assets) }, { name: 'High risk', color: '#FFFFFF', values: an.by_sector.map(z => z.high) }], { fmtv: v => v.toFixed(0) }));
    safe('#c8', el => grouped(el, an.per_entry.map(e => e.name), [{ name: 'Expected (P × harm)', color: C.series[0], values: an.per_entry.map(e => e.prob * e.harm) }, { name: 'If this way in is used', color: '#FFFFFF', values: an.per_entry.map(e => e.harm) }]));
    safe('#c14', el => bars(el, an.choke_points.slice(0, 8).map(c => ({ label: `${c.src_name} → ${c.dst_name}`, value: c.entries, c })), { horizontal: true, labelWidth: 230, fmtv: v => v.toFixed(0), tipFmt: d => `<b>${h(d.label)}</b><br>used by: ${d.c.entry_names.map(h).join(', ')}` }));
  }
  safe('#c6', async el => {
    const g = await get('/api/graph'), ov = await get('/api/overview');
    const on = await api('/api/simulate', { entry_points: [ov.worst_entry] });
    const free = await api('/api/multi', { attackers: [{ id: 'A', entry: ov.worst_entry }], detection: false });
    const cum = obj => Object.values(obj).sort((a, b) => a - b).map((t, i) => [t, i + 1]).filter(p => p[0] <= 360);
    lines(el, [{ label: 'Detection on', color: C.pink, points: cum(on.compromised) }, { label: 'Nobody stops it', color: C.series[0], dash: true, points: cum(free.combined.first_by ? Object.fromEntries(Object.entries(free.combined.first_by).map(([k, v]) => [k, v.t])) : {}) }],
      { yLabel: 'systems', markers: on.detected_at != null && on.detected_at < 360 ? [{ t: on.detected_at, label: 'detected' }] : [], fmty: v => v.toFixed(0) });
    {   // say what the two lines mean, from the numbers (they can be identical, and that is a finding, not a glitch)
      const nOn = Object.keys(on.compromised).length, nFree = Object.keys(free.combined.first_by || {}).length;
      const lastOn = Math.max(...Object.values(on.compromised)), cfg = await get('/api/config').catch(() => ({}));
      const resp = cfg.RESPONSE_DELAY_MIN ?? 15;
      const msg = on.detected_at == null || on.detected_at >= 360 ? `Nothing detects this attack within 6 hours, so both lines are the same: ${nOn} systems.`
        : nOn < nFree ? `Detection at ${tmin(on.detected_at)} plus a ${resp}-minute response stops the spread at ${nOn} systems instead of ${nFree}.`
        : on.detected_at + resp > lastOn ? `Both lines are the same: detection at ${tmin(on.detected_at)} plus a ${resp}-minute response comes after the attacker's last new system (${tmin(lastOn)}). Faster detection is what would change this line.`
        : `Both lines are the same: detection fires at ${tmin(on.detected_at)}, but isolation (${resp} minutes later) only cuts off the zone where it fired, and the attacker keeps moving through other zones until ${tmin(lastOn)}. Monitoring in those zones is what would change this line.`;
      el.insertAdjacentHTML('beforeend', `<p class="faint" style="margin-top:8px;font-size:13px">${h(msg)}</p>`);
    }
    const pts = []; let lost = 0;
    Object.entries(on.failures).filter(([, t]) => t < 360).sort((a, b) => a[1] - b[1]).forEach(([n, t]) => { lost += g.services.find(s => s.name === n)?.population || 0; pts.push([t, lost]); });
    lines($('#c7'), [{ label: 'People without a service', color: C.pink, points: pts }], { yLabel: 'people' });
  });
  safe('#c12', async el => {
    if (!sc) return empty(el, 'No scenario yet. Run one on the Attack simulation page.');
    lines(el, sc.result.attackers.map(a => ({ label: `Attacker ${a.id}`, color: atkColor(a.id), points: Object.values(a.compromised).sort((x, y) => x - y).map((t, i) => [t, i + 1]).filter(p => p[0] <= 360) })), { yLabel: 'systems reached', fmty: v => v.toFixed(0) });
  });
  safe('#c13', async el => {
    const g = await get('/api/graph');
    const m = netmap(el, g, { height: 480, onClick: a => assetDrawer(a.id) });
    if (!an) return m.update();
    const st = {}; an.central_assets.slice(0, 5).forEach(c => st[c.id] = { fill: '#FFFFFF', label: true, labelColor: '#FFFFFF', tip: `betweenness ${c.betweenness}` });
    m.update(st, an.choke_points.slice(0, 6).map(c => ({ src: c.src, dst: c.dst, color: C.series[0], width: 1.5 + c.entries })));
  });
  safe('#c10', async el => {
    const fx = await get('/api/fixes');
    const top = [...fx.fixes].sort((a, b) => b.risk_reduction_pct - a.risk_reduction_pct).slice(0, 12);
    bars(el, top.map(f => ({ label: f.fix, value: f.risk_reduction_pct, color: f.risk_reduction_pct < 0 ? C.warn : C.series[0], f })), { horizontal: true, labelWidth: 240, fmtv: v => v.toFixed(0) + '%', tipFmt: d => `<b>${h(d.label)}</b><br>−${d.f.risk_reduction_pct}% likely harm, −${d.f.worst_case_reduction_pct}% worst case<br>+${d.f.minutes_bought} min bought, ${d.f.staff_hours} staff h` });
    const pts = fx.fixes.filter(f => f.risk_reduction_pct > 0);
    scatter($('#c11'), pts.map(f => ({ x: f.staff_hours + ((f.id.length % 7) - 3) * .05, y: f.risk_reduction_pct, label: f.fix, color: f.needs_window ? C.warn : C.series[0] })),
      { xMin: 0, xMax: 5, xLabel: 'staff hours', yLabel: '% likely harm removed', fmtx: v => v.toFixed(0), fmty: v => v.toFixed(0) + '%', legendItems: [{ label: 'Needs a maintenance window', color: C.warn }, { label: 'No window needed', color: C.series[0] }] });
  });
  safe('#c9', async el => {
    const o = await api('/api/optimize', { max_fixes: 3, windows: 2, simultaneous: 1 });
    grouped(el, ['Worst case', 'Likely harm, all ways in', 'Patch outage'], [{ name: 'Before', color: C.series[0], values: [o.before.worst_harm, o.before.expected_harm, 0] }, { name: 'After the bundle', color: '#FFFFFF', values: [o.best.worst_harm, o.best.expected_harm, o.best.patch_outage_harm] }]);
  });
  safe('#c15', async el => {
    el.innerHTML = '<div class="loading"><span class="spin"></span>The sensitivity test runs once, about a minute after start-up</div>';
    const s = await get('/api/sensitivity');
    el.innerHTML = `<p class="note ${s.top1_stable === s.total ? '' : 'warn'}">Top fix unchanged in <b>${s.top1_stable} of ${s.total}</b> runs; top three unchanged in ${s.top3_stable} of ${s.total}. Baseline top fix: ${h(s.base_top3[0])}.</p><div style="max-height:250px;overflow:auto;margin-top:10px" id="sensT"></div>`;
    table(el.querySelector('#sensT'), s.runs, [
      { key: 'label', label: 'Assumption moved' }, { key: 'change_pct', label: 'Change', num: true, render: r => `${r.change_pct > 0 ? '+' : ''}${r.change_pct}%` },
      { key: 'same_top1', label: 'Same top fix', render: r => r.same_top1 ? 'yes' : `<span class="pinkt">no: ${h(r.top3[0])}</span>`, sort: r => +r.same_top1 },
      { key: 'same_top3', label: 'Same top three', render: r => r.same_top3 ? 'yes' : '<span class="warn">order changed</span>', sort: r => +r.same_top3 }], { sortKey: 'same_top1', desc: false });
  });
}

// ======================================= ML INSIGHTS =======================================
export async function ml(root) {
  loading(root, 'Loading model status');
  try {
    const [m, w, sec] = await Promise.all([get('/api/ml'), get('/api/water/summary').catch(() => ({ available: false })), get('/api/ml/sectors').catch(() => null)]);
    const mc = w.available ? w.model_card : null, t = mc?.held_out_test_attacks_4_7_evaluated_once;
    root.innerHTML = `
      <div class="head"><div><h2>ML insights</h2><p class="lede">Two different questions, answered by two different sources. We did not train our own CVE exploitation model: FIRST's EPSS already does that job, trained on far more data than a hackathon could. Our machine learning answers a different question.</p></div></div>
      ${sec ? `<div class="sheet" style="margin-bottom:16px"><h3>Sector models: what was tested, what was approved</h3><p class="sub">${h(sec.note)}</p>
        <div class="tablewrap"><table class="t sectors"><thead><tr><th>Sector</th><th>Decision</th><th>Data</th><th>Held-out result</th></tr></thead><tbody>
        ${sec.sectors.map(s => `<tr><td><b>${h(s.sector)}</b>${s.page ? `<br><a href="${s.page}">open</a>` : ''}</td><td><span class="tag ${s.decision === 'approved' ? 'white' : s.decision === 'no_go' ? 'warn' : ''}">${h(s.label)}</span></td><td style="font-size:12px">${h(s.dataset)}<br><span class="faint">${h(s.model)}</span></td><td style="font-size:12px">${h(s.held_out)}<br><span class="faint">${h(s.allowed_wording)}</span></td></tr>`).join('')}
        </tbody></table></div>
        <p class="note" style="margin-top:10px"><a href="#/evaluation">See every criterion and score</a>. Two of six sectors passed their pre-declared gates. The other four are reported as negative results instead of being shipped: a detector that raises a false alarm on 1 in 14 normal flows, or misses its own pre-set recall target, does not go on an operator's screen.</p></div>` : ''}
      <div class="grid g2">
        <div class="sheet"><h3>"Will this CVE be exploited?"</h3><p class="sub">Answered by external intelligence, not by our ML.</p>
          <dl class="kv"><dt>Source</dt><dd>FIRST EPSS (30-day exploitation estimate) and CISA KEV (confirmed exploited)</dd>
          <dt>Rule</dt><dd>On KEV → 0.9; otherwise EPSS; otherwise 0.05</dd>
          <dt>Feeds</dt><dd>The vulnerability score V of each system, which sets how fast the simulated attacker gets in</dd>
          <dt>CVEs</dt><dd>${m.total}: ${m.sources['CISA KEV (0.9)']} via KEV, ${m.sources.EPSS} via EPSS, ${m.sources['default 0.05']} default</dd></dl></div>
        <div class="sheet"><h3>"Is the water plant behaving abnormally?"</h3><p class="sub">Answered by our ML: SENTINEL water anomaly detector, by Suryans Padhy.</p>
          ${mc ? `<dl class="kv"><dt>Model</dt><dd>Model C ${h(mc.version)}: predictive residual, scikit-learn HistGradientBoostingRegressor</dd>
          <dt>Learns</dt><dd>Normal operation only (${h(mc.training_data)})</dd>
          <dt>Held-out test</dt><dd>${h(t.attacks_detected)} documented attacks detected, ${t.false_alarms_per_7d_strict} false alarms per 7 days, precision ${t.precision}, recall ${t.recall}, PR-AUC ${t.pr_auc} (evaluated once)</dd>
          <dt>Used as</dt><dd>Advisory evidence in a separate water monitoring view. Never changes CVSS, EPSS or KEV; never marks a device compromised or a service lost.</dd></dl>
          <a class="btn primary" href="#/water" style="margin-top:14px">Open water anomaly monitoring</a>` : '<p class="note warn">Water package not installed.</p>'}</div>
      </div>
      ${mc ? `<div class="grid g2" style="margin-top:16px">
        <div class="chart-card"><h3>Held-out test: hours to detect each attack</h3><p class="sub">BATADAL attacks 4-7, scored once by the model owner. Lower is faster; 0 h means flagged within the attack's first hour.</p><div id="mlLat"></div></div>
        <div class="sheet"><h3>Limitations (from the model card)</h3><ul style="margin:0;padding-left:18px;color:var(--mute);font-size:13px">${mc.limitations.map(x => `<li style="margin:4px 0">${h(x)}</li>`).join('')}</ul></div></div>` : ''}
      <div class="grid g2" style="margin-top:16px">
        <div class="chart-card"><h3>Where each CVE's probability comes from</h3><p class="sub">Count of CVEs by source.</p><div id="mlSrc"></div></div>
        <div class="chart-card"><h3>Probability in use against EPSS</h3><p class="sub">KEV CVEs sit at 0.9; the rest on the diagonal.</p><div id="mlScatter"></div></div>
      </div>
      <div class="sheet" style="margin-top:16px"><h3>Per-CVE probability</h3><p class="sub">The value the risk engine uses for every CVE, and why.</p><div id="mlTable"></div></div>`;
    if (mc) bars(root.querySelector('#mlLat'), Object.entries(t.latency_h_new_episode).map(([k, v]) => ({ label: `Attack ${k}`, value: v })), { fmtv: v => `${v} h`, yLabel: 'hours' });
    const src = Object.entries(m.sources).filter(([k]) => k !== 'ML model');
    bars(root.querySelector('#mlSrc'), src.map(([k, v]) => ({ label: k, value: v })), { horizontal: true, labelWidth: 130, fmtv: v => v.toFixed(0) });
    scatter(root.querySelector('#mlScatter'), m.rows.map(r => ({ x: r.epss ?? 0, y: r.used, label: r.cve_id, color: r.kev ? C.warn : C.series[0] })),
      { xMin: 0, xMax: 1, yMax: 1, xLabel: 'EPSS', yLabel: 'probability used', fmtx: v => v.toFixed(1), fmty: v => v.toFixed(1), legendItems: [{ label: 'KEV (0.9)', color: C.warn }, { label: 'EPSS', color: C.series[0] }] });
    table(root.querySelector('#mlTable'), m.rows, [
      { key: 'cve_id', label: 'CVE' }, { key: 'cvss', label: 'CVSS', num: true }, { key: 'epss', label: 'EPSS', num: true, render: r => r.epss == null ? '–' : r.epss.toFixed(3) },
      { key: 'kev', label: 'KEV', render: r => r.kev ? '<span class="tag warn">yes</span>' : 'no', sort: r => +r.kev },
      { key: 'used', label: 'Used', num: true, render: r => r.used.toFixed(3) }, { key: 'source', label: 'Source' }], { sortKey: 'used' });
  } catch (e) { errorBox(root, e); }
}

// ======================================= FIX OPTIMISER =======================================
export async function optimizer(root) {
  root.innerHTML = `
    <div class="head"><div><h2>Fix optimiser</h2><p class="lede">Finds the best combination of fixes for your budget. Every candidate bundle is applied to a copy of the city and the attack is re-run; the attacker then re-picks the way in that does the most harm against the new defences.</p></div></div>
    <div class="sheet" style="margin-bottom:16px"><h3>Budget</h3>
      <div class="row" style="gap:18px;align-items:flex-end">
        <label class="fl">Fixes at most<input class="f" type="number" id="oN" min="1" max="6" value="3"></label>
        <label class="fl">Maintenance windows<input class="f" type="number" id="oW" min="0" max="10" value="2"></label>
        <label class="fl">Staff hours (blank = no limit)<input class="f" type="number" id="oS" min="1" max="100" placeholder="no limit" style="width:140px"></label>
        <label class="fl">Simultaneous ways in<select class="f" id="oK"><option value="1">1 attacker</option><option value="2">2 at once</option><option value="3">3 at once</option></select></label>
        <label class="fl">Attacker type<select class="f" id="oV"><option value="0.5">Opportunistic</option><option value="1" selected>Organised crew</option><option value="2">State-backed</option></select></label>
        <button class="btn primary" id="oRun">Find the best bundle</button>
      </div>
      <p class="faint" style="margin-top:10px;font-size:12px">Patches that need downtime use a maintenance window if one is left. Without one, the patch's own outage (people × minutes) is added to the cost. OT systems are never patched live in this model.</p></div>
    <div id="oOut"></div>
    <div class="sheet" style="margin-top:16px"><h3>Every single fix, ranked</h3><p class="sub">Each fix tested alone against every way in. Net benefit = harm removed minus harm from the patch outage itself.</p>
      <div class="filters"><select class="f" id="fType"><option value="">All fix types</option><option value="patch">Patch</option><option value="harden">Harden</option><option value="monitor">Monitor</option><option value="segment">Segment</option><option value="restrict_exposure">Remove exposure</option></select></div>
      <div id="fTable"><div class="loading"><span class="spin"></span>Loading</div></div></div>`;
  const $ = s => root.querySelector(s);
  const g = await get('/api/graph');
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  let fx;
  try {
    fx = await get('/api/fixes');
    const t = table($('#fTable'), fx.fixes, [
      { key: 'fix', label: 'Fix' }, { key: 'type', label: 'Type', render: r => h(r.type.replace('_', ' ')) },
      { key: 'risk_reduction_pct', label: 'Likely harm', num: true, render: r => `${r.risk_reduction_pct > 0 ? '−' : r.risk_reduction_pct < 0 ? '+' : ''}${Math.abs(r.risk_reduction_pct)}%` },
      { key: 'worst_case_reduction_pct', label: 'Worst case', num: true, render: r => `${r.worst_case_reduction_pct > 0 ? '−' : ''}${Math.abs(r.worst_case_reduction_pct)}%` },
      { key: 'minutes_bought', label: 'Time bought', num: true, render: r => r.minutes_bought ? `+${r.minutes_bought} min` : '–' },
      { key: 'staff_hours', label: 'Staff h', num: true },
      { key: 'net_benefit', label: 'Net benefit', num: true, render: r => fmt(r.net_benefit) },
      { key: 'note', label: 'Note', nosort: true, render: r => `<span class="faint" style="font-size:12px">${h(r.note)}${r.needs_window ? (r.note ? '; ' : '') + 'needs a window' : ''}</span>` }], { sortKey: 'net_benefit' });
    $('#fType').onchange = e => t.redraw(fx.fixes.filter(f => !e.target.value || f.type === e.target.value));
  } catch (e) { $('#fTable').innerHTML = `<div class="err">${h(e.message)}</div>`; }
  const run = async () => {
    const out = $('#oOut');
    const body = { max_fixes: +$('#oN').value, windows: +$('#oW').value, staff_budget: $('#oS').value ? +$('#oS').value : null, simultaneous: +$('#oK').value, speed: +$('#oV').value };
    out.innerHTML = `<div class="loading"><span class="spin"></span>Searching bundles${body.max_fixes > 3 || body.simultaneous > 1 ? ' (larger budgets take up to a minute)' : ''}</div>`;
    try {
      const o = await api('/api/optimize', body);
      const b = o.before, a = o.best;
      const why = id => fx?.fixes.find(f => f.id === id);
      out.innerHTML = `
        <div class="kpis">
          <div class="kpi"><div class="v">${pct(b.worst_harm, a.worst_harm)}%</div><div class="l">Worst case removed</div><div class="s">${fmt(b.worst_harm)} → ${fmt(a.worst_harm)} people-min</div></div>
          <div class="kpi"><div class="v">${pct(b.expected_harm, a.expected_harm)}%</div><div class="l">Likely harm removed</div><div class="s">${fmt(b.expected_harm)} → ${fmt(a.expected_harm)}</div></div>
          <div class="kpi"><div class="v">${a.earliest_failure_min >= 360 ? 'All 6 h' : `+${Math.round(a.earliest_failure_min - b.earliest_failure_min)} min`}</div><div class="l">Time bought</div><div class="s">first loss ${tmin(b.earliest_failure_min)} → ${tmin(a.earliest_failure_min)}</div></div>
          <div class="kpi"><div class="v">${a.staff_hours} h</div><div class="l">Staff time</div><div class="s">${a.windows_used} window${a.windows_used === 1 ? '' : 's'} used, patch outage ${fmt(a.patch_outage_harm)}</div></div>
        </div>
        <div class="grid g2" style="margin-top:16px">
          <div class="sheet"><h3>Recommended bundle</h3><p class="sub">Why each one: its effect when tested alone. Together they can do more, because closing one way in matters only once the others are closed too.</p>
            ${a.fixes.length ? a.fixes.map((id, i) => { const w = why(id); return `<div style="padding:10px 0;border-bottom:1px solid var(--line)"><b style="font-weight:600">${i + 1}. ${h(a.labels[i])}</b>
              <p class="mute" style="font-size:13px">${w ? `Alone: ${sgn(w.risk_reduction_pct)} likely harm, ${sgn(w.worst_case_reduction_pct)} worst case, ${w.staff_hours} staff h${w.needs_window ? ', needs a maintenance window' : ''}.` : ''}</p></div>`; }).join('') : '<p class="mute">Doing nothing is already the best option within this budget.</p>'}
            <p class="note" style="margin-top:12px">Attacker's best way in: before, ${b.attacker_entry.map(e => h(names[e])).join(' + ') || 'none'}; after, <b>${a.attacker_entry.map(e => h(names[e])).join(' + ') || 'none'}</b>.</p>
            <div class="row" style="margin-top:12px"><button class="btn small primary" id="oSim">Test against an adaptive attacker</button><button class="btn small" id="oTwin">Apply in the 3D twin</button></div></div>
          <div class="chart-card"><h3>Before and after</h3><p class="sub">Same unit, people × minutes over 6 hours.</p><div id="oChart"></div></div>
        </div>
        <div class="sheet" style="margin-top:16px"><h3>Runners-up</h3><div id="oRun2"></div></div>`;
      grouped(out.querySelector('#oChart'), ['Worst case', 'Likely harm', 'Patch outage'], [{ name: 'Before', color: C.series[0], values: [b.worst_harm, b.expected_harm, 0] }, { name: 'After', color: '#FFFFFF', values: [a.worst_harm, a.expected_harm, a.patch_outage_harm] }]);
      table(out.querySelector('#oRun2'), o.runners_up, [
        { key: 'labels', label: 'Bundle', render: r => r.labels.map(h).join('<br>') || 'nothing' },
        { key: 'worst_harm', label: 'Worst case', num: true, render: r => fmt(r.worst_harm) }, { key: 'expected_harm', label: 'Likely harm', num: true, render: r => fmt(r.expected_harm) },
        { key: 'earliest_failure_min', label: 'First loss', num: true, render: r => tmin(r.earliest_failure_min) }, { key: 'staff_hours', label: 'Staff h', num: true }], { sortKey: null });
      out.querySelector('#oSim').onclick = () => { location.hash = `#/simulate?entry=${b.attacker_entry[0]}&fixes=${a.fixes.join(',')}&adaptive=1`; };
      out.querySelector('#oTwin').onclick = () => withTwin(c => { a.fixes.forEach(f => { if (!c.S.applied.has(f)) c.toggleFix(f); }); });
    } catch (e) { out.innerHTML = `<div class="err">${h(e.message)}</div>`; }
  };
  $('#oRun').onclick = run; run();
}
