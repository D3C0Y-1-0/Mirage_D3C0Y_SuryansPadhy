// Exposure and roadmap, Attack paths, Drill mode, Incident report, Compliance mapping.
import { api, get, h, fmt, tmin, pct, table, store, loading, errorBox, toast, atkBadge, atkColor, withTwin } from './core.js';
import { bars, curves, COLORS as C, empty } from './charts.js';
import { netmap } from './netmap.js';
import { assetDrawer } from './pages-ops.js';

const ls = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
             set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } } };
const inr = v => '₹' + (v >= 1e7 ? (v / 1e7).toFixed(2) + ' crore' : v >= 1e5 ? (v / 1e5).toFixed(2) + ' lakh' : Math.round(v).toLocaleString('en-IN'));

// ======================================= EXPOSURE AND ROADMAP =======================================
export async function exposure(root) {
  loading(root, 'Loading exposure');
  let ex, rm;
  const cfg = ls.get('cascade.roadmap', { staff: 8, every: 2, rateStaff: 1500, ratePm: 2 });
  try { [ex, rm] = await Promise.all([get('/api/insights/exposure'), api(`/api/insights/roadmap?staff=${Math.max(1, Math.min(80, +cfg.staff || 8))}&window_weeks=${Math.max(1, Math.min(8, +cfg.every || 2))}`)]); }
  catch (e) { return errorBox(root, e); }
  root.innerHTML = `
    <div class="head"><div><h2>Exposure and roadmap</h2><p class="lede">One number for the whole city, a 13-week plan that respects your staff hours and maintenance windows, and how sure we can be, given that every timing in the model is an estimate.</p></div></div>
    <div class="grid g12">
      <div class="sheet"><h3>City exposure score</h3><p class="sub">${h(ex.formula)}.</p>
        <div class="expo"><svg viewBox="0 0 200 120" id="exGauge" aria-hidden="true"></svg><div class="expov num">${ex.score}</div><div class="faint" style="text-align:center;font-size:12px">out of 100 (lower is better)</div></div>
        <dl class="kv" style="margin-top:10px"><dt>Worst-case harm</dt><dd>${fmt(ex.worst_harm)} people-min (${ex.worst_share}% of the ceiling)</dd><dt>Likely harm, all ways in</dt><dd>${fmt(ex.expected_harm)} (${ex.expected_share}%). A sum over every way in, so it can exceed the worst single attack</dd><dt>Ceiling</dt><dd>${fmt(ex.ceiling)}: every service lost for 6 hours</dd></dl></div>
      <div class="chart-card"><h3>Burn-down: exposure over the plan</h3><p class="sub">The five-fix plan (chosen by simulated harm), scheduled week by week. Each point re-runs every way in.</p><div id="exBurn"></div></div>
    </div>
    <div class="grid g21" style="margin-top:16px">
      <div class="sheet"><div class="row" style="justify-content:space-between"><h3>30/60/90-day roadmap</h3>
        <div class="row"><label class="fl">Staff hours per week<input class="f" type="number" id="rStaff" min="1" max="80" value="${cfg.staff}"></label><label class="fl">Maintenance window every (weeks)<input class="f" type="number" id="rEvery" min="1" max="8" value="${cfg.every}"></label><button class="btn small primary" id="rGo">Re-plan</button></div></div>
        <div id="rTable" style="margin-top:12px"></div>
        ${rm.unscheduled.length ? `<p class="note warn" style="margin-top:10px">${rm.unscheduled.length} fix(es) do not fit in 13 weeks with this budget.</p>` : ''}</div>
      <div class="sheet"><h3>Cost in rupees</h3><p class="sub">Both rates are assumptions you can change. They are kept in this browser only.</p>
        <div class="row" style="align-items:flex-end"><label class="fl">₹ per staff hour<input class="f" type="number" id="cStaff" min="0" value="${cfg.rateStaff}" style="width:110px"></label>
          <label class="fl">₹ per person-minute of lost service<input class="f" type="number" id="cPm" min="0" step="0.5" value="${cfg.ratePm}" style="width:110px"></label></div>
        <div id="cOut" style="margin-top:14px"></div></div>
    </div>
    <div class="chart-card" style="margin-top:16px"><h3>How sure are we? P10, P50 and P90</h3><p class="sub" id="mcSub">Every assumption (crossing speeds, firewall and segmentation effects, detection and response times, attacker speed) drawn at random within ±30%, all at once, 200 times.</p><div id="mcOut"><div class="loading"><span class="spin"></span>Running 600 simulations once on the server (about 10 s)</div></div></div>`;
  const $ = s => root.querySelector(s);
  // gauge
  const a = Math.min(1, ex.score / 100), R = 80, cx = 100, cy = 105;
  const pt = (k, r) => [cx + r * Math.cos(Math.PI * (1 - k)), cy - r * Math.sin(Math.PI * (1 - k))];
  $('#exGauge').innerHTML = `<path d="M${pt(0, R).join(',')} A${R},${R} 0 0 1 ${pt(1, R).join(',')}" stroke="var(--line)" stroke-width="14" fill="none" stroke-linecap="round"/>
    <path d="M${pt(0, R).join(',')} A${R},${R} 0 0 1 ${pt(a, R).join(',')}" stroke="${ex.score >= 40 ? 'var(--pink)' : ex.score >= 15 ? 'var(--warn)' : 'var(--soft)'}" stroke-width="14" fill="none" stroke-linecap="round"/>`;
  const draw = r => {
    curves($('#exBurn'), r.points.map(p => `wk ${p.week}`), [
      { name: 'Exposure score', color: '#FFFFFF', bold: true, values: r.points.map(p => p.score) }], { fmty: v => v.toFixed(0), xLabel: 'week', xPos: r.points.map(p => p.week) });
    table($('#rTable'), r.plan, [
      { key: 'week', label: 'Week', num: true }, { key: 'label', label: 'Fix' },
      { key: 'hours', label: 'Staff h', num: true }, { key: 'needs_window', label: 'Window', render: x => x.needs_window ? '<span class="tag warn">maintenance window</span>' : 'live' },
      { key: 'phase', label: 'Phase', render: x => x.week <= 4 ? '30 days' : x.week <= 9 ? '60 days' : '90 days', sort: x => x.week }], { sortKey: 'week', desc: false, empty: 'Nothing to schedule.' });
    cost(r);
  };
  const cost = r => {
    const rs = +$('#cStaff').value || 0, rp = +$('#cPm').value || 0;
    ls.set('cascade.roadmap', { staff: +$('#rStaff').value, every: +$('#rEvery').value, rateStaff: rs, ratePm: rp });
    const hours = r.plan.reduce((s, p) => s + p.hours, 0), first = r.points[0], last = r.points[r.points.length - 1];
    const avW = first.worst - last.worst, avE = first.expected - last.expected;
    $('#cOut').innerHTML = `<dl class="kv"><dt>Staff cost of the plan</dt><dd>${hours} h × ₹${rs.toLocaleString('en-IN')} = <b>${inr(hours * rs)}</b></dd>
      <dt>Worst-case harm avoided</dt><dd>${fmt(avW)} people-min ≈ <b>${inr(avW * rp)}</b></dd><dt>Likely harm avoided</dt><dd>${fmt(avE)} people-min ≈ <b>${inr(avE * rp)}</b></dd>
      <dt>Cost per person-minute saved</dt><dd>${avE > 0 ? '₹' + (hours * rs / avE).toFixed(4) : '–'} (likely harm)</dd></dl>
      <p class="faint" style="font-size:12px;margin-top:8px">Illustrative. The rupee value of an outage minute is a policy choice, not a measurement; patch-window costs and equipment are not included.</p>`;
  };
  draw(rm);
  $('#rGo').onclick = async () => { try { rm = await api(`/api/insights/roadmap?staff=${+$('#rStaff').value}&window_weeks=${+$('#rEvery').value}`); draw(rm); toast('Roadmap re-planned'); } catch (e) { toast(e.message); } };
  $('#cStaff').oninput = $('#cPm').oninput = () => cost(rm);
  // Monte Carlo
  try {
    const mc = await get('/api/insights/montecarlo');
    const R2 = mc.results, names = Object.keys(R2);
    const W = Math.max(400, $('#mcOut').clientWidth), rowH = 54, Ht = names.length * rowH * 2 + 40;
    const max = Math.max(...names.flatMap(n => [R2[n].worst.max, R2[n].expected.max, R2[n].worst.p90, R2[n].expected.p90])) * 1.02 || 1, x0 = 230, x1 = W - 200, X = v => x0 + v / max * (x1 - x0);   // values get their own column on the right
    let y = 20, svg = '';
    for (const n of names) for (const m of ['worst', 'expected']) {
      const r = R2[n][m];
      svg += `<text x="${x0 - 12}" y="${y + 18}" text-anchor="end" fill="#A9B4DA" font-size="12">${h(n)}${m === 'worst' ? ', worst case' : ', likely'}</text>
        <line x1="${X(r.min)}" x2="${X(r.max)}" y1="${y + 14}" y2="${y + 14}" stroke="rgba(169,180,218,.35)" stroke-width="2"/>
        <rect x="${X(r.p10)}" y="${y + 6}" width="${Math.max(3, X(r.p90) - X(r.p10))}" height="16" rx="6" fill="${m === 'worst' ? 'rgba(255,111,181,.45)' : 'rgba(142,157,224,.5)'}"/>
        <circle cx="${X(r.p50)}" cy="${y + 14}" r="6" fill="#FFFFFF" stroke="#12225E" stroke-width="2"/>
        <text x="${W - 8}" y="${y + 18}" fill="#FFFFFF" font-size="12" text-anchor="end"><tspan fill="#A9B4DA">P10 </tspan>${fmt(r.p10)}<tspan fill="#A9B4DA">  P50 </tspan>${fmt(r.p50)}<tspan fill="#A9B4DA">  P90 </tspan>${fmt(r.p90)}</text>`;
      y += rowH;
    }
    $('#mcOut').innerHTML = `<div class="chart-legend"><span><i style="background:rgba(255,111,181,.6)"></i>Worst case, P10-P90</span><span><i style="background:rgba(142,157,224,.7)"></i>Likely harm, P10-P90</span><span><i style="background:#fff;height:8px;width:8px;border-radius:50%"></i>P50</span><span><i style="background:rgba(169,180,218,.5)"></i>Min-max</span></div>
      <svg viewBox="0 0 ${W} ${y + 10}" width="100%" height="${y + 10}">${svg}</svg>
      <p class="note" style="margin-top:8px">${names.filter(n => R2[n].beats_no_fix_share != null).map(n => `${h(n)} beats doing nothing on worst case in ${Math.round(100 * R2[n].beats_no_fix_share)}% of the runs.`).join(' ')} ${h(mc.note)}</p>`;
  } catch (e) { empty($('#mcOut'), `Uncertainty run unavailable: ${h(e.message)}`); }
}

// ======================================= ATTACK PATHS =======================================
export async function paths(root) {
  loading(root, 'Finding attack paths');
  let ap, g, ov;
  try { [ap, g, ov] = await Promise.all([get('/api/insights/paths'), get('/api/graph'), get('/api/overview')]); } catch (e) { return errorBox(root, e); }
  const J = ap.crown_jewels.filter(j => j.paths.length);
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  let sel = J[0], pi = 0;
  root.innerHTML = `
    <div class="head"><div><h2>Attack paths</h2><p class="lede">Crown jewels are the systems essential services depend on. For each one: the fastest routes from any way in, using the same crossing times as the simulation, and the links that many routes share.</p></div></div>
    <div class="grid g12">
      <div class="sheet"><h3>Crown jewels</h3><p class="sub">Sorted by how fast the quickest route reaches them.</p><div id="jList" class="jlist"></div></div>
      <div class="chart-card"><div class="row" style="justify-content:space-between"><h3 id="pTitle"></h3><div class="row"><button class="btn small" id="pPlay">Replay this route</button><button class="btn small" id="pTwin">This way in, 3D twin</button><a class="btn small primary" id="pSim">Simulate it</a></div></div>
        <p class="sub" id="pSub"></p><div id="pPaths"></div><div id="pMap"></div></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>Choke points</h3><p class="sub">Links that the most of these ${ap.paths_counted} routes cross. Segmenting one slows every route through it six times over (model assumption) and pushes the attacker elsewhere. Test it before you believe it.</p><div id="cTable"></div></div>`;
  const $ = s => root.querySelector(s);
  const map = netmap($('#pMap'), g, { height: 420, onClick: a => assetDrawer(a.id) });
  let raf = 0;
  // the selected route, exactly: every hop in order, numbered, with arrows; t = minutes along the route (Infinity = all)
  const drawRoute = (p, t = Infinity) => {
    const st = {}, cum = [0]; (p.hop_minutes || []).forEach(m => cum.push(cum[cum.length - 1] + m));
    p.nodes.forEach((n, k) => { const reached = t >= (cum[k] ?? 0); st[n] = { fill: !reached ? undefined : k === 0 ? '#FF6FB5' : k === p.nodes.length - 1 ? '#FFFFFF' : '#8E9DE0', label: true, labelColor: '#FFFFFF', priority: 3, tip: `hop ${k}: ${tmin(cum[k] ?? 0)}` }; });
    map.update(st, p.nodes.slice(1).map((n, k) => ({ src: p.nodes[k], dst: n, color: '#FF6FB5', width: 3, step: k + 1,
      frac: !p.hop_minutes || t === Infinity ? 1 : Math.max(0, Math.min(1, (t - cum[k]) / Math.max(.01, p.hop_minutes[k]))) })));
  };
  const replay = () => {                         // animate the route on its own clock: 1 s per 10 simulated minutes, at least 3 s
    cancelAnimationFrame(raf);
    const p = sel.paths[pi], dur = Math.max(3000, p.minutes * 100), t0 = performance.now();
    const btn = $('#pPlay'); btn.textContent = 'Replaying…'; btn.disabled = true;
    const step = now => { const k = Math.min(1, (now - t0) / dur); drawRoute(p, k * p.minutes); if (k < 1) raf = requestAnimationFrame(step); else { btn.textContent = 'Replay this route'; btn.disabled = false; } };
    raf = requestAnimationFrame(step);
  };
  const drawSel = () => {
    cancelAnimationFrame(raf); const pb = $('#pPlay'); if (pb) { pb.textContent = 'Replay this route'; pb.disabled = false; }
    $('#jList').innerHTML = J.map((j, i) => `<button class="jitem ${j === sel ? 'on' : ''}" data-i="${i}"><b>${h(j.name)}</b><span>${h(j.services.join(', '))}</span><em class="num">${tmin(j.paths[0].minutes)}</em></button>`).join('');
    $('#jList').querySelectorAll('.jitem').forEach(b => b.onclick = () => { sel = J[+b.dataset.i]; pi = 0; drawSel(); });
    $('#pTitle').textContent = sel.name;
    $('#pSub').textContent = `Keeps ${sel.services.join(', ')} running. ${sel.paths.length} fastest routes shown; click one to draw it.`;
    $('#pPaths').innerHTML = sel.paths.map((p, i) => `<button class="pitem ${i === pi ? 'on' : ''}" data-i="${i}" aria-pressed="${i === pi}"><span class="num">${tmin(p.minutes)}</span>${p.names.map((n, k) => `<sup>${k}</sup>${h(n)}`).join(' <i>→</i> ')}</button>`).join('');
    $('#pPaths').querySelectorAll('.pitem').forEach(b => b.onclick = () => { pi = +b.dataset.i; drawSel(); });
    const p = sel.paths[pi];
    drawRoute(p);
    $('#pSim').href = `#/simulate?entry=${p.entry}`;
  };
  $('#pPlay').onclick = replay;
  $('#pTwin').onclick = () => withTwin(c => c.setEntries([sel.paths[pi].entry]));
  // a choke point is tested from a way in whose route actually crosses it, before and after segmenting
  const entryVia = c => { for (const j of J) for (const p of j.paths) for (let k = 1; k < p.nodes.length; k++) if (p.nodes[k - 1] === c.src && p.nodes[k] === c.dst) return p.entry; return ov.worst_entry; };
  drawSel();
  table($('#cTable'), ap.choke_points, [
    { key: 'src_name', label: 'Link', render: c => `${h(c.src_name)} → ${h(c.dst_name)}` },
    { key: 'paths', label: 'Routes through it', num: true, render: c => `<span class="bar" style="width:${Math.round(80 * c.paths / c.of)}px"></span>${c.paths} of ${c.of}` },
    { key: 'fix', label: 'Test', nosort: true, render: c => c.segmented ? '<span class="faint">already segmented</span>' : c.fix ? `<a class="btn small" href="#/simulate?entry=${entryVia(c)}&fixes=${encodeURIComponent(c.fix)}&compare=1" title="Runs the attack from ${h(names[entryVia(c)] || '')} without and then with this link segmented">Segment it and simulate</a>` : '–' }], { sortKey: 'paths' });
}

// ======================================= DRILL MODE =======================================
export async function drill(root, ctx) {
  let presets;
  try { presets = (await get('/api/multi/presets')).presets; } catch (e) { return errorBox(root, e); }
  const board = ls.get('cascade.drill', []);
  root.innerHTML = `
    <div class="head"><div><h2>Drill mode</h2><p class="lede">Training for the people in the control room. A surprise attack plays out; nothing is shown until the first alarm. Then you choose, against the clock. Your score is how much of the avoidable harm you avoided.</p></div></div>
    <div class="grid g21">
      <div class="sheet" id="dStage"><div class="drillstart"><h3>Ready?</h3><p class="mute" style="margin:8px 0 16px">One simulated minute passes every quarter second. You will not know where the attacker came in until an alarm fires.</p>
        <button class="btn primary" id="dGo">Start a surprise drill</button></div></div>
      <div class="sheet"><h3>Your best drills</h3><p class="sub">Kept in this browser.</p><div id="dBoard"></div></div>
    </div>`;
  const $ = s => root.querySelector(s);
  const drawBoard = () => table($('#dBoard'), ls.get('cascade.drill', []).slice(0, 8), [
    { key: 'score', label: 'Score', num: true, render: x => `${x.score}%` }, { key: 'delay', label: 'Decided after alarm', num: true, render: x => x.delay == null ? 'no decision' : `${x.delay} min` },
    { key: 'title', label: 'Scenario', render: x => `${h(x.title)}<br><span class="faint">${h(x.when || '')}</span>` }], { sortKey: null, empty: 'No drills yet. Start one on the left.' });
  drawBoard();
  let raf = 0, timer = 0;
  ctx.onLeave(() => { cancelAnimationFrame(raf); clearInterval(timer); });
  $('#dGo').onclick = async () => {
    const pr = presets[Math.floor(Math.random() * presets.length)];
    const req = { attackers: pr.attackers.map(a => ({ speed: 1, start: 0, contain_at: null, adaptive: false, active: true, ...a })), fixes: [...pr.fixes], maintenance: pr.maintenance, detection: true, speed: 1 };
    $('#dStage').innerHTML = '<div class="loading"><span class="spin"></span>Preparing a surprise</div>';
    let base;
    try { base = await api('/api/multi', req); } catch (e) { $('#dStage').innerHTML = `<div class="err">${h(e.message)}</div>`; return; }
    const det = base.detected_at;
    let t = 0, decided = null;
    $('#dStage').innerHTML = `<div class="row" style="justify-content:space-between"><div class="clockbig num" id="dClock">T+00:00</div><span class="tag" id="dState">Quiet. Nothing detected.</span></div>
      <div class="evlog" id="dLog" style="margin-top:12px;max-height:220px"></div><div id="dAct" style="margin-top:14px"></div>`;
    const visible = () => base.events.filter(e => e.t <= t && (det != null && t >= det ? true : ['service_down', 'detected', 'isolated', 'maintenance', 'maintenance_end'].includes(e.kind)));
    const step = () => {
      t = Math.min(360, t + 1);
      $('#dClock').textContent = tmin(t).replace('none in 6 h', 'T+06:00');
      $('#dLog').innerHTML = visible().slice(-12).reverse().map(e => `<div><span class="t">${tmin(e.t)}</span>${e.attacker && e.attacker.length === 1 && det != null && t >= det ? atkBadge(e.attacker) : '<span></span>'}<span class="${e.kind === 'service_down' ? 'pinkt' : ''}">${h(e.text)}</span></div>`).join('');
      if (det != null && t >= det && !decided && !$('#dAct').dataset.on) offer();
      if (t >= 360 || decided) { clearInterval(timer); if (!decided) finish(null); }
    };
    const offer = () => {
      $('#dAct').dataset.on = '1'; $('#dState').className = 'tag pink'; $('#dState').textContent = 'ALARM. Decide now.';
      $('#dAct').innerHTML = `<p class="note pinkn"><b>Alarm at ${tmin(det)}.</b> Every minute you wait, the attack keeps moving. Choose one:</p>
        <div class="row" style="margin-top:10px"><button class="btn primary" data-a="island">Cut internet and vendor access now</button><button class="btn" data-a="evict">Evict the detected attacker(s) now</button><button class="btn" data-a="wait">Wait and watch</button></div>`;
      $('#dAct').querySelectorAll('[data-a]').forEach(b => b.onclick = () => { decided = { action: b.dataset.a, at: t }; clearInterval(timer); finish(decided); });
    };
    timer = setInterval(step, 250);
    const finish = async d => {
      $('#dAct').innerHTML = '<div class="loading"><span class="spin"></span>Scoring against the best possible response</div>';
      const withAction = (a, at) => { const r = structuredClone(req);
        if (a === 'island') r.island_at = at;
        if (a === 'evict') r.attackers.forEach(x => { if (x.start <= at) x.contain_at = at; });
        return r; };
      try {
        const T0 = det ?? 360;
        const [mine, bestI, bestE] = await Promise.all([
          d && d.action !== 'wait' ? api('/api/multi', withAction(d.action, d.at)) : Promise.resolve(base),
          api('/api/multi', withAction('island', T0)), api('/api/multi', withAction('evict', T0))]);
        const best = Math.min(bestI.combined.harm, bestE.combined.harm), none = base.combined.harm;
        const avoidable = none - best > 1;
        const score = avoidable ? Math.max(0, Math.min(100, Math.round(100 * (none - mine.combined.harm) / (none - best)))) : null;
        const delay = d ? Math.round(d.at - T0) : null;
        const rec = { score, delay, title: pr.title, when: new Date().toLocaleString() };
        if (avoidable) { const b = ls.get('cascade.drill', []); b.push(rec); b.sort((x, y) => y.score - x.score || (x.delay ?? 999) - (y.delay ?? 999)); ls.set('cascade.drill', b.slice(0, 20)); }
        api('/api/ops/log', { context: `Drill: ${pr.title}`, action: d ? { island: 'Cut internet and vendor access', evict: 'Evict detected attackers', wait: 'Wait and watch' }[d.action] : 'No decision', decision: 'note', reason: `score ${avoidable ? score + '%' : 'n/a'}, decided ${delay ?? '-'} min after alarm`, sim_time: d ? tmin(d.at) : null }).catch(() => {});
        $('#dAct').innerHTML = `<div class="kpis"><div class="kpi"><div class="v">${avoidable ? score + '%' : 'n/a'}</div><div class="l">${avoidable ? 'of avoidable harm avoided' : 'nothing was avoidable after the alarm'}</div><div class="s">best possible: ${fmt(best)} people-min</div></div>
          <div class="kpi"><div class="v">${delay == null ? '–' : delay + ' min'}</div><div class="l">decision time after alarm</div><div class="s">alarm at ${tmin(T0)}</div></div>
          <div class="kpi"><div class="v pink">${fmt(mine.combined.harm)}</div><div class="l">harm with your choice</div><div class="s">doing nothing: ${fmt(none)}</div></div>
          <div class="kpi"><div class="v" style="font-size:22px">${h(pr.title)}</div><div class="l">the scenario</div><div class="s">${base.attackers.map(a => `Attacker ${a.id}`).join(', ')}</div></div></div>
          <p class="note" style="margin-top:10px">${avoidable ? '' : 'In this scenario the damage was already locked in before anyone could notice (a service had already lost a system it needs and was running on backup). Only earlier detection, from monitoring, would help; this drill is not scored. '}The best response here was to ${bestI.combined.harm <= bestE.combined.harm ? 'cut internet and vendor access' : 'evict the detected attackers'} at the moment of the alarm. ${d?.action === 'island' ? 'Island mode assumes outside attackers need a live internet link; insiders are not stopped by it.' : ''}</p>
          <button class="btn primary" style="margin-top:12px" id="dAgain">Another drill</button>`;
        $('#dAgain').onclick = () => drill(root, ctx);
        drawBoard();
      } catch (e) { $('#dAct').innerHTML = `<div class="err">${h(e.message)}</div>`; }
    };
  };
}

// ======================================= INCIDENT REPORT =======================================
export async function report(root) {
  const sc = store.scenario;
  let cfg, audit, verify, ds;
  try { [cfg, audit, verify, ds] = await Promise.all([get('/api/config'), api('/api/ops/log'), api('/api/ops/verify'), get('/api/dataset')]); } catch (e) { return errorBox(root, e); }
  const g = await get('/api/graph'); const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  const res = sc?.result;
  root.innerHTML = `
    <div class="head noprint"><div><h2>Incident report</h2><p class="lede">A printable record of the current simulated scenario, the decisions taken and the assumptions behind the numbers.</p></div>
      <div class="row"><button class="btn primary" id="print">Print or save as PDF</button></div></div>
    ${!res ? '<div class="chart-empty">No scenario yet. Run one on Attack simulation, then come back.</div>' : `
    <article class="report">
      <header><div><b>Cascade incident report</b><span>Simulated exercise. Not a real incident.</span></div><div class="faint">${new Date().toLocaleString()}<br>Dataset ${h(ds.folder)}, ${ds.assets} systems</div></header>
      <h3>${h(sc.title)}</h3>
      <div class="kpis" style="margin:12px 0"><div class="kpi"><div class="v">${fmt(res.combined.harm)}</div><div class="l">Harm, people × minutes</div></div>
        <div class="kpi"><div class="v">${tmin(res.combined.first_failure_min)}</div><div class="l">First service lost</div></div>
        <div class="kpi"><div class="v">${res.combined.assets_lost}</div><div class="l">Systems compromised</div></div>
        <div class="kpi"><div class="v">${res.detected_at == null ? '–' : tmin(res.detected_at)}</div><div class="l">First detected</div></div></div>
      <h4>Attackers</h4><ul>${res.attackers.map(a => `<li>Attacker ${h(a.id)}: entered through ${h(names[a.entry])} at ${tmin(a.start)}; ${a.reached} systems reached; status ${h(a.status)}${a.adapted_from ? `; switched from ${h(names[a.adapted_from])}` : ''}.</li>`).join('')}</ul>
      <h4>Services lost</h4><ul>${res.combined.services.map(s => `<li>${h(s.service)} (${s.population.toLocaleString()} people): lost at ${tmin(s.fail_at)}${s.restored_at != null ? `, restored ${tmin(s.restored_at)}` : ''}; cause ${s.cause === 'maintenance' ? 'maintenance downtime' : s.cause === 'failsafe' ? 'failsafe cut-off' : `attacker ${h(s.cause)} via ${h(names[s.cause_asset] || '')}`}.</li>`).join('') || '<li>None within 6 hours.</li>'}</ul>
      <h4>Defences in place</h4><p>${res.request.fixes.length ? res.request.fixes.map(h).join(', ') : 'None beyond the dataset.'}${res.failsafe ? ` Failsafe island mode at ${tmin(res.failsafe.at)}.` : ''}</p>
      <h4>Actions applied during the exercise</h4><ul>${(sc.applied || []).map(a => `<li>${h(a)}</li>`).join('') || '<li>None.</li>'}</ul>
      <h4>Timeline</h4><table class="t"><tbody>${res.events.slice(0, 60).map(e => `<tr><td class="n">${tmin(e.t)}</td><td>${e.attacker && e.attacker.length === 1 ? 'Attacker ' + h(e.attacker) : ''}</td><td>${h(e.attacker && e.attacker.length === 1 ? e.text.replace(/^Attacker [A-D]: /, '') : e.text)}</td></tr>`).join('')}</tbody></table>
      <h4>Operator decisions (audit trail)</h4><p class="${verify.ok ? '' : 'pinkt'}">${verify.ok ? `Audit chain verified: ${verify.entries} entries, unbroken. Head hash ${h((verify.head || '').slice(0, 16))}…` : `Audit chain check failed at entry ${verify.broken_at}: ${h(verify.reason)}.`}</p>
      <table class="t"><tbody>${audit.rows.slice(0, 30).map(r => `<tr><td>${h(r.at)}</td><td>${h(r.decision)}</td><td>${h(r.action)}${r.reason ? ' (' + h(r.reason) + ')' : ''}</td><td class="faint" style="font:11px var(--mono)">${h((r.hash || '').slice(0, 12))}</td></tr>`).join('') || '<tr><td>No decisions logged.</td></tr>'}</tbody></table>
      <h4>Assumptions</h4><p class="faint">Crossing time = base minutes ÷ (speed × (${cfg.MIN_EXPLOIT_FACTOR} + V)), × (1 + ${cfg.FIREWALL_FACTOR} × firewall level), × ${cfg.SEGMENT_FACTOR} if segmented. Detection ${cfg.TTD_MONITORED_MIN} min if monitored, ${cfg.TTD_UNMONITORED_MIN} min otherwise; isolation ${cfg.RESPONSE_DELAY_MIN} min later. Harm window ${cfg.HORIZON_MIN / 60} h. Infrastructure simulated; CVE, KEV and EPSS data real. Under India's CERT-In directions (2022), a real incident of this kind would have to be reported within 6 hours of noticing it.</p>
    </article>`}`;
  root.querySelector('#print').onclick = () => window.print();
}

// ======================================= COMPLIANCE MAPPING =======================================
export async function compliance(root) {
  loading(root, 'Loading the mapping');
  let c;
  try { c = await get('/api/insights/compliance'); } catch (e) { return errorBox(root, e); }
  const cols = [{ key: 'label', label: 'Fix' },
    { key: 'nist_800_53', label: 'NIST SP 800-53 (used by SP 800-82r3)', render: r => r.nist_800_53.map(h).join('<br>') },
    { key: 'iec_62443', label: 'IEC 62443', render: r => r.iec_62443.map(h).join('<br>') },
    { key: 'india', label: 'India', render: r => r.india.map(h).join('<br>') },
    { key: 'mitre_ics', label: 'MITRE ATT&CK for ICS: mitigations', render: r => (r.mitre_ics || []).map(h).join('<br>') },
    { key: 'mitre_techniques', label: 'Techniques it counters', render: r => (r.mitre_techniques || []).map(h).join('<br>') }];
  root.innerHTML = `
    <div class="head"><div><h2>Compliance mapping</h2><p class="lede">Which control families each recommended fix relates to, so a plan can be discussed in the language auditors use.</p></div></div>
    <p class="note warn" style="margin-bottom:16px">${h(c.note)}</p>
    <div class="sheet"><h3>The optimiser's bundle</h3><div id="c1"></div></div>
    <div class="sheet" style="margin-top:16px"><h3>The five-fix plan</h3><div id="c2"></div></div>
    <div class="sheet" style="margin-top:16px"><h3>By fix type</h3><div id="c3"></div></div>`;
  table(root.querySelector('#c1'), c.optimiser_bundle, cols, { sortKey: null });
  table(root.querySelector('#c2'), c.plan, cols, { sortKey: null });
  table(root.querySelector('#c3'), Object.entries(c.mapping).map(([k, v]) => ({ label: k.replace('_', ' '), ...v })), cols, { sortKey: null });
}
