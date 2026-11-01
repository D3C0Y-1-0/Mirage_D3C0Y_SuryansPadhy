// Water anomaly monitoring (SENTINEL Model C historical replay + rule layer) and Failsafe and operator.
import { api, get, h, fmt, tmin, pct, table, store, loading, errorBox, toast, atkBadge, withTwin } from './core.js';
import { bars, grouped, COLORS as C, empty } from './charts.js';
import { netmap } from './netmap.js';

const LEVEL = {
  normal: { label: 'Normal', text: 'Both layers within their normal range.', color: '#FFFFFF' },
  watch: { label: 'Watch', text: 'One layer above its threshold for one hour. No alert yet (needs 2 hours).', color: '#8E9DE0' },
  advisory: { label: 'Advisory', text: 'One layer alerting. Operator notified to investigate. No automatic action.', color: '#F2B84B' },
  alarm: { label: 'Alarm', text: 'Both layers alerting, a high ML deviation, or a tank outside its safe range. Operator paged; protective actions proposed.', color: '#F2B84B' },
};
const ZONES = [ // C-Town schematic: hydraulic zones and the stations without a tank, laid out left to right roughly as in the network
  ['zone_T1', 'T1', 'PU1, PU2', 0, 0], ['zone_T2', 'T2', 'V2', 1, 0], ['zone_T3', 'T3', 'PU4, PU5', 2, 0], ['zone_T4', 'T4', 'PU6, PU7', 3, 0],
  ['zone_T5', 'T5', 'PU8', 0, 1], ['zone_T6', 'T6', 'no control', 1, 1], ['zone_T7', 'T7', 'PU10, PU11', 2, 1], ['station_PU9', 'PU9', 'station', 3, 1], ['station_PU3', 'PU3', 'station', 3, 2],
];
const sev = s => s === 'high' ? 'tag warn' : s === 'medium' ? 'tag white' : 'tag';
const ts = s => String(s).replace('T', ' ').slice(0, 16);

// ======================================= WATER MONITORING =======================================
export async function water(root, ctx) {
  loading(root, 'Loading water monitoring');
  let S, H, ev, policy;
  try {
    S = await get('/api/water/summary');
    if (!S.available) { root.innerHTML = '<div class="chart-empty">The water anomaly package is not installed. Put the SENTINEL integration files in <code class="c">ml_water/</code>.</div>'; return; }
    [H, ev, policy] = await Promise.all([get('/api/water/hourly'), get('/api/water/events'), get('/api/failsafe/policy')]);
  } catch (e) { return errorBox(root, e); }
  const mc = S.model_card, R = S.rules.evaluation, M = S.ml_same_period;
  const N = H.t.length;
  const demoStart = H.t.indexOf('2016-12-05 19:00'), demoEnd = H.t.indexOf('2016-12-10 16:00');
  let i = demoStart >= 0 ? demoStart : 0, playing = false, timer = 0, showRef = false, decision = null, pausedForAlarm = new Set();

  root.innerHTML = `
    <div class="head"><div><h2>Water anomaly monitoring</h2><p class="lede">Early warning for the water sector: does the plant behave the way it normally does? Two independent layers compare every hour with normal operation, so they can flag an attack that is in no vulnerability database and was never seen in training.</p></div>
      <div class="row"><button class="btn" id="wTwin">Show water assets in the 3D twin</button></div></div>
    <div class="histbanner"><b>Historical replay.</b> ${h(S.banner.replace(/^HISTORICAL REPLAY of /, ''))} ${h(S.disclaimer)}</div>
    <div class="kpis" style="margin-top:16px">
      <div class="kpi"><div class="v">${S.events}</div><div class="l">ML alert episodes</div><div class="s">${S.by_severity.high} high, ${S.by_severity.medium} medium, ${S.by_severity.low} low deviation</div></div>
      <div class="kpi"><div class="v">${S.rules.episodes}</div><div class="l">Rule-layer episodes</div><div class="s">safety envelope, no ML</div></div>
      <div class="kpi"><div class="v">${S.mapped_events}<span class="mute" style="font-size:20px"> / ${S.events}</span></div><div class="l">Events on a city asset</div><div class="s">the rest are shown by C-Town zone</div></div>
      <div class="kpi"><div class="v">${S.hours.toLocaleString()}</div><div class="l">Hours replayed</div><div class="s">2016-07-04 to 2016-12-25, hourly</div></div>
    </div>

    <div class="grid g12" style="margin-top:16px">
      <div class="sheet"><h3>Operator console</h3><p class="sub">Replay one hour at a time. The replay stops at every new alarm and waits for a human decision.</p>
        <div class="statusbox" id="lvl"></div>
        <div class="player" style="margin-top:14px"><button class="iconbtn" id="wPlay" aria-label="Play or pause"><svg viewBox="0 0 16 16"><path d="M4 2l10 6-10 6z"/></svg></button>
          <input type="range" id="wScrub" min="0" max="${N - 1}" value="${i}" aria-label="Replay hour"></div>
        <div class="row" style="margin-top:8px;justify-content:space-between"><span class="num" id="wTime" style="font:700 22px var(--display)"></span>
          <div class="seg"><button data-j="demo" class="on">Attack 6 window</button><button data-j="all">Whole period</button></div></div>
        <div id="decide" style="margin-top:14px"></div>
      </div>
      <div class="sheet"><div class="row" style="justify-content:space-between"><h3>What the two layers see this hour</h3><span class="faint" style="font-size:12px">ML threshold = 50 on the display scale</span></div>
        <div class="grid g2" style="margin-top:8px">
          <div><h4 class="h4">Layer 1: ML (Model C ${h(mc.version)})</h4><div id="mlNow"></div></div>
          <div><h4 class="h4">Layer 2: safety envelope (rules)</h4><div id="ruleNow"></div></div>
        </div>
        <h4 class="h4" style="margin-top:14px">Where: C-Town hydraulic zones</h4>
        <div id="zones"></div>
        <p class="faint" style="font-size:12px;margin-top:6px">Only T1 (→ WA04 tank RTU) and pumps PU1/PU2 (→ WA01 pumping PLC) have a city asset. Everything else stays at zone level; no asset link is invented. Telemetry reaches the city through WA02 (telecontrol SCADA) and WA03 (HMI). The location can be downstream of the tampered part.</p>
      </div>
    </div>

    <div class="chart-card" style="margin-top:16px"><div class="row" style="justify-content:space-between"><h3>Anomaly score over the whole replay</h3>
      <label class="chk"><input type="checkbox" id="wRef"> Show documented attack windows (reference only)</label></div>
      <p class="sub">Model C's hourly score on a 0-100 scale (50 = alert threshold). Bands below: ML episodes and rule-layer episodes. Click to jump the console there.</p>
      <div id="wTimeline"></div></div>

    <div class="grid g2" style="margin-top:16px">
      <div class="sheet dk"><h3>Observed against expected</h3><p class="sub">The top signal this hour: what the sensor said, what Model C expected from the previous hours and the pump/valve settings, and the normal range the rule layer learned.</p>
        <div class="filters"><select class="f" id="wSig" aria-label="Signal"></select><span class="faint" style="font-size:12px" id="wSigNote"></span></div><div id="wSigChart"></div></div>
      <div class="sheet"><h3>An attack nobody has seen before</h3>
        <p class="mute" style="font-size:13px;margin-bottom:10px">Vulnerability feeds (NVD, KEV, EPSS) only know published weaknesses. A new attack has no CVE. Both layers here learn <b>normal</b> behaviour instead of attack signatures, so anything that pushes the plant outside normal is flagged, known or not.</p>
        <div class="tablewrap"><table class="t"><thead><tr><th></th><th>ML (Model C)</th><th>Rules (envelope)</th></tr></thead><tbody>
          <tr><td>How it decides</td><td>Predicts each level and pressure; a large miss is unusual</td><td>Hard limits, pump/flow consistency, rate of change, frozen sensors</td></tr>
          <tr><td>Learned from</td><td>Dataset03, normal only</td><td>Dataset04, ${h(S.reference_period[0].slice(0, 10))} to ${h(S.reference_period[1].slice(0, 10))} (no documented attack)</td></tr>
          <tr><td>Attacks flagged after ${h(S.reference_period[1].slice(0, 10))}</td><td>${h(M.attacks_detected)}</td><td>${h(R.attacks_detected)}</td></tr>
          <tr><td>Hours to first flag</td><td class="num">${Object.values(M.latency_h).join(', ')}</td><td class="num">${Object.values(R.latency_h).join(', ')}</td></tr>
          <tr><td>False-alarm episodes per 7 days</td><td class="num">${M.false_alarms_per_7d}</td><td class="num">${R.false_alarms_per_7d}</td></tr>
        </tbody></table></div>
        <p class="note" style="margin-top:10px">ML is fast (0-3 h) but raises about one false alarm a week. Rules are slow (5-102 h) but raised none here. Together: the ML gives early warning, the rules confirm, and only both, or a large deviation, page the operator.</p>
        <p class="faint" style="font-size:12px;margin-top:8px">Scored once against the official BATADAL attack table, which neither layer sees. Attacks 1-3 were the ML's validation set, so its numbers there are not fully independent. One simulated network, seven attacks: not evidence for a real utility.</p></div>
    </div>

    <div class="sheet" style="margin-top:16px"><h3>Alert episodes</h3><p class="sub">ML episodes as delivered by the model owner, and rule-layer episodes. "Reference" = overlaps a documented BATADAL attack; the detectors never see this.</p>
      <div class="filters"><div class="seg" id="evSrc"><button class="on" data-s="ml">ML episodes (${ev.events.length})</button><button data-s="rules">Rule episodes (${ev.rule_episodes.length})</button></div></div><div id="evT"></div></div>

    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><div class="row" style="justify-content:space-between"><h3>Operator decisions (audit trail)</h3><button class="btn small" id="verify">Verify chain</button></div><p class="sub">Every acknowledgement, approval, dismissal and automatic failsafe, with who and when. Each entry carries the SHA-256 of the one before, so an edited or deleted entry is detected. Stored in <code class="c">.cascade/audit.jsonl</code>.</p><div id="vOut"></div><div id="audit"></div></div>
      <div class="sheet"><h3>Model card</h3><dl class="kv">
        <dt>Model</dt><dd>${h(mc.name)}</dd><dt>Owner</dt><dd>Suryans Padhy (SENTINEL)</dd><dt>Trained on</dt><dd>${h(mc.training_data)}</dd>
        <dt>Inputs</dt><dd>${h(mc.inputs)}</dd><dt>Held-out test</dt><dd>${h(mc.held_out_test_attacks_4_7_evaluated_once.attacks_detected)} attacks, precision ${mc.held_out_test_attacks_4_7_evaluated_once.precision}, recall ${mc.held_out_test_attacks_4_7_evaluated_once.recall}, ${mc.held_out_test_attacks_4_7_evaluated_once.false_alarms_per_7d_strict} false alarms / 7 days</dd>
        <dt>Not for</dt><dd>${mc.not_intended_for.map(h).join('; ')}</dd><dt>Limitations</dt><dd>${mc.limitations.map(h).join('. ')}.</dd></dl></div>
    </div>`;
  const $ = s => root.querySelector(s);

  // ---- big timeline ----
  const drawTimeline = () => {
    const host = $('#wTimeline'), W = Math.max(600, host.clientWidth), Ht = 190, top = 10, plotH = 120, x0 = 44, x1 = W - 10;
    const X = k => x0 + k / (N - 1) * (x1 - x0), Y = v => top + plotH - v / 100 * plotH;
    const idx = Object.fromEntries(H.t.map((t, k) => [t, k]));
    let d = ''; H.score.forEach((v, k) => { d += `${k ? 'L' : 'M'}${X(k).toFixed(1)},${Y(v).toFixed(1)}`; });
    const band = (a, b, y, col, title) => `<rect x="${X(a)}" y="${y}" width="${Math.max(2, X(b) - X(a))}" height="10" rx="2" fill="${col}"><title>${h(title)}</title></rect>`;
    const mlB = ev.events.map(e => band(idx[ts(e.timestamp_start)] ?? 0, idx[ts(e.timestamp_last_alert)] ?? 0, top + plotH + 14, e.severity === 'high' ? '#F2B84B' : '#8E9DE0', `${e.event_id}, ${e.severity}`)).join('');
    const ruB = ev.rule_episodes.map(e => band(idx[ts(e.start)] ?? 0, idx[ts(e.end)] ?? 0, top + plotH + 30, '#FFFFFF', `${e.id}: ${e.rules.join(', ')}`)).join('');
    const ref = showRef ? S.attack_windows.map(w => { const a = idx[w.start] ?? H.t.findIndex(t => t >= w.start), b = idx[w.end] ?? H.t.findIndex(t => t >= w.end); return `<rect x="${X(a)}" y="${top}" width="${X(b) - X(a)}" height="${plotH}" fill="rgba(242,184,75,.10)" stroke="rgba(242,184,75,.5)" stroke-dasharray="3 3"><title>Reference: BATADAL attack ${w.id}</title></rect><text x="${X(a) + 3}" y="${top + 11}" fill="#F2B84B" font-size="10">A${w.id}</text>`; }).join('') : '';
    const months = []; H.t.forEach((t, k) => { if (t.endsWith('-01 00:00')) months.push(`<text x="${X(k)}" y="${Ht - 4}" fill="#6F7DB5" font-size="11" text-anchor="middle">${t.slice(0, 7)}</text>`); });
    host.innerHTML = `<svg viewBox="0 0 ${W} ${Ht}" width="100%" height="${Ht}" style="display:block;cursor:pointer" id="tlSvg">
      ${[0, 50, 100].map(v => `<line x1="${x0}" x2="${x1}" y1="${Y(v)}" y2="${Y(v)}" stroke="${v === 50 ? 'rgba(255,255,255,.45)' : 'rgba(43,61,134,.55)'}" stroke-dasharray="${v === 50 ? '4 4' : ''}"/><text x="${x0 - 6}" y="${Y(v) + 4}" text-anchor="end" fill="#6F7DB5" font-size="11">${v}</text>`).join('')}
      ${ref}<path d="${d}" fill="none" stroke="#8E9DE0" stroke-width="1.2"/>
      <text x="${x0}" y="${top + plotH + 12}" fill="#6F7DB5" font-size="10"></text>${mlB}${ruB}
      <text x="4" y="${top + plotH + 23}" fill="#6F7DB5" font-size="10">ML</text><text x="4" y="${top + plotH + 39}" fill="#6F7DB5" font-size="10">Rules</text>
      ${months.join('')}<line id="tlCur" y1="${top}" y2="${top + plotH + 40}" stroke="#FFFFFF" stroke-width="1.5"/></svg>`;
    const svg = $('#tlSvg');
    svg.onclick = e => { const b = svg.getBoundingClientRect(), px = (e.clientX - b.left) * W / b.width; i = Math.round(Math.max(0, Math.min(N - 1, (px - x0) / (x1 - x0) * (N - 1)))); stop(); showHour(); };
    drawTimeline.X = X;
  };
  drawTimeline();
  $('#wRef').onchange = e => { showRef = e.target.checked; drawTimeline(); showHour(); };

  // ---- console ----
  const zoneHot = () => { const z = new Map(); for (const s of H.top[i] || []) if (s.z >= H.threshold) z.set(s.zone, Math.max(z.get(s.zone) || 0, s.z)); for (const r of H.rules[i] || []) { const m = S.mapping.find(x => x.signal_id === r.signal); if (m) z.set(m.hydraulic_zone, Math.max(z.get(m.hydraulic_zone) || 0, 10)); } return z; };
  function showHour() {
    const lv = H.level[i], L = LEVEL[lv];
    $('#wTime').textContent = H.t[i];
    $('#wScrub').value = i;
    $('#lvl').innerHTML = `<div class="lvl ${lv}"><span class="dot"></span><b>${L.label}</b></div><p class="mute" style="font-size:13px;margin-top:6px">${L.text}</p>`;
    $('#mlNow').innerHTML = `<div class="gauge"><span style="width:${H.score[i]}%;background:${H.score[i] >= 50 ? '#F2B84B' : '#8E9DE0'}"></span><i style="left:50%"></i></div>
      <p style="margin-top:6px"><b class="num" style="font:800 30px var(--display)">${H.score[i].toFixed(0)}</b><span class="mute"> / 100 ${H.alert[i] ? `<span class="${sev(H.severity[i])}">alert, ${h(H.severity[i])}</span>` : H.score[i] >= 50 ? '<span class="tag">above threshold, 1st hour</span>' : ''}</span></p>
      ${(H.top[i] || []).slice(0, 3).map(s => `<p style="font-size:12px;margin-top:4px"><b>${h(s.signal)}</b> <span class="mute">${s.observed} seen, ${s.predicted} expected (|z| ${s.z.toFixed(1)}), ${h(s.zone.replace('_', ' '))}${s.assets.length ? `, city asset ${s.assets.map(h).join(', ')}` : ''}</span></p>`).join('')}`;
    const rh = H.rules[i] || [];
    $('#ruleNow').innerHTML = rh.length ? `<p><span class="tag ${H.rule_alert[i] ? 'warn' : ''}">${H.rule_alert[i] ? 'alert (2 h)' : 'outside envelope, 1st hour'}</span></p>` + rh.map(r => `<p style="font-size:12px;margin-top:4px"><b>${h(r.rule)}</b> <span class="mute">${h(r.detail)}</span></p>`).join('') : '<p class="mute" style="font-size:13px">All rules inside the normal envelope.</p>';
    const hot = zoneHot();
    $('#zones').innerHTML = `<div class="zgrid">${ZONES.map(([id, nm, sub, gx, gy]) => { const z = hot.get(id) ? (hot.get(id) >= 10 * H.threshold ? 20 : 5) : 0; const mapped = id === 'zone_T1'; return `<div class="zone ${z ? (z >= 10 ? 'hot' : 'warm') : ''}" style="grid-column:${gx + 1};grid-row:${gy + 1}"><b>${nm}</b><span>${sub}</span>${mapped ? '<em>WA04, WA01</em>' : ''}</div>`; }).join('')}</div>`;
    const cur = $('#tlCur'); if (cur && drawTimeline.X) { cur.setAttribute('x1', drawTimeline.X(i)); cur.setAttribute('x2', drawTimeline.X(i)); }
    // signal list follows the top signal unless the user picked one
    if (!$('#wSig').dataset.user) { const top = (H.top[i] || [])[0]; if (top && $('#wSig').value !== top.signal) { $('#wSig').value = top.signal; drawSignal(); } }
    // human in the loop: stop at the first hour of each new alarm
    const newAlarm = lv === 'alarm' && H.level[i - 1] !== 'alarm';
    if (newAlarm && playing && !pausedForAlarm.has(i)) { pausedForAlarm.add(i); stop(); askOperator(); }
    else if (!decision) $('#decide').innerHTML = lv === 'alarm' ? '<p class="note warn">Alarm continuing. A decision was already taken for this episode, or press play to continue.</p>' : '';
  }

  // operator decision with a countdown to the automatic failsafe (1 s on screen = 1 min)
  function askOperator() {
    let left = policy.operator_ack_min;
    const ctxText = `Water alarm at ${H.t[i]} (replay)`;
    decision = { at: H.t[i] };
    const render = () => {
      $('#decide').innerHTML = `<div class="decide"><div class="row" style="justify-content:space-between"><b style="font:700 22px var(--display)">Operator decision required</b><span class="count num">${left} min</span></div>
        <p class="mute" style="font-size:13px;margin:6px 0 10px">${policy.auto ? `If nobody responds in ${policy.operator_ack_min} minutes, the failsafe cuts remote access to water control and keeps the pumps on local level control.` : 'Automatic failsafe is off; the alarm waits for a human.'} 1 second here = 1 minute.</p>
        <input class="f" id="dReason" placeholder="Note or reason (required to dismiss)" style="width:100%;margin-bottom:8px" aria-label="Reason">
        <div class="row"><button class="btn small primary" data-d="approved">Approve protective actions</button><button class="btn small" data-d="acknowledged">Acknowledge, investigate first</button><button class="btn small" data-d="dismissed">Dismiss as false alarm</button></div>
        <p style="margin:10px 0 0"><a href="#/novel?hour=${encodeURIComponent(H.t[i])}">What if this is an attacker? Simulate the consequence →</a></p>
        <ul class="mute" style="font-size:12px;margin:10px 0 0;padding-left:18px"><li>Cut internet and vendor remote access to the water control network (WA02, WA03, WA04 cellular link)</li><li>Hold pumps PU1/PU2 on local tank-level control at the station</li><li>Call the on-call water engineer to read the T1 gauge by hand</li></ul></div>`;
      $('#decide').querySelectorAll('[data-d]').forEach(b => b.onclick = async () => {
        let reason = '';
        reason = ($('#dReason')?.value || '').trim();
        if (b.dataset.d === 'dismissed' && !reason) return toast('Write why it is a false alarm first; it goes into the audit trail.');
        clearInterval(timer); await log(b.dataset.d, b.dataset.d === 'approved' ? 'Cut remote access; pumps to local control; engineer called' : b.dataset.d === 'acknowledged' ? 'Investigating before acting' : 'No action', reason, ctxText);
        $('#decide').innerHTML = `<p class="note">${{ approved: 'Protective actions approved', acknowledged: 'Acknowledged. Investigating; protective actions on hold', dismissed: 'Dismissed as a false alarm' }[b.dataset.d]} by the operator at ${H.t[i]}, ${policy.operator_ack_min - left} min after the alarm. Press play to continue.</p>`;
        decision = null;
      });
    };
    render();
    clearInterval(timer);
    timer = setInterval(async () => {
      left--; const c = $('#decide .count'); if (c) c.textContent = `${left} min`;
      if (left <= 0) {
        clearInterval(timer); decision = null;
        if (policy.auto) { await log('auto_failsafe', 'Cut remote access; pumps to local control; engineer paged again', `No operator response in ${policy.operator_ack_min} min`, ctxText);
          $('#decide').innerHTML = `<p class="note warn"><b>Failsafe acted on its own</b> at ${H.t[i]} + ${policy.operator_ack_min} min: remote access cut, pumps on local control, on-call engineer paged again. A human still has to confirm before remote access is restored.</p>`; }
      }
    }, 1000);
  }
  async function log(decisionKind, action, reason, context) {
    try { await api('/api/ops/log', { context, action, decision: decisionKind, reason, sim_time: H.t[i] }); } catch (e) { toast(e.message); }
    drawAudit();
  }
  async function drawAudit() {
    const r = await api('/api/ops/log');
    table($('#audit'), r.rows, [{ key: 'at', label: 'Logged' }, { key: 'sim_time', label: 'Replay time' }, { key: 'decision', label: 'Decision', render: x => `<span class="tag ${x.decision === 'auto_failsafe' ? 'warn' : 'white'}">${h(x.decision.replace('_', ' '))}</span>` },
      { key: 'action', label: 'Action', render: x => `${h(x.action)}${x.reason ? `<br><span class="faint">${h(x.reason)}</span>` : ''}` }, { key: 'by', label: 'By' }], { sortKey: null, empty: 'No decisions yet. Play the replay until it stops at an alarm.' });
  }
  drawAudit();
  $('#verify').onclick = async () => { const v = await api('/api/ops/verify'); $('#vOut').innerHTML = `<p class="note ${v.ok ? '' : 'pinkn'}" style="margin-bottom:10px">${v.ok ? `Chain intact: ${v.entries} entries verified.` : `Chain broken at entry ${v.broken_at}: ${h(v.reason)}.`}</p>`; };

  // signal chart
  const sigs = [...new Set(S.mapping.map(m => m.signal_id))];
  $('#wSig').innerHTML = sigs.map(s => `<option>${h(s)}</option>`).join('');
  $('#wSig').onchange = () => { $('#wSig').dataset.user = '1'; drawSignal(); };
  async function drawSignal() {
    const sig = $('#wSig').value, a = Math.max(0, i - 48), b = Math.min(N - 1, i + 24);
    const m = S.mapping.find(x => x.signal_id === sig);
    $('#wSigNote').textContent = m ? `${m.kind.replace(/_/g, ' ')}, ${m.unit}, ${m.hydraulic_zone.replace('_', ' ')}${m.mapped_city_asset_ids ? `, city asset ${m.mapped_city_asset_ids}` : ', no city asset'}` : '';
    try {
      const s = await api(`/api/water/signal/${encodeURIComponent(sig)}?start=${encodeURIComponent(H.t[a])}&end=${encodeURIComponent(H.t[b])}`);
      sigChart($('#wSigChart'), s, H.t[i]);
    } catch (e) { empty($('#wSigChart'), e.message); }
  }

  // events table
  const drawEvents = src => {
    if (src === 'ml') table($('#evT'), ev.events, [
      { key: 'timestamp_start', label: 'Start', render: e => ts(e.timestamp_start) }, { key: 'alert_duration_h', label: 'Hours', num: true },
      { key: 'severity', label: 'Deviation', render: e => `<span class="${sev(e.severity)}">${e.severity}</span>`, sort: e => ({ low: 1, medium: 2, high: 3 })[e.severity] },
      { key: 'hydraulic_zones', label: 'Zones', render: e => e.hydraulic_zones.map(z => h(z.replace('_', ' '))).join(', ') },
      { key: 'mapping_status', label: 'City asset', render: e => e.mapped_city_asset_ids.length ? e.mapped_city_asset_ids.map(h).join(', ') : '<span class="faint">zone level only</span>' },
      { key: 'documented_attack_overlap', label: 'Reference', render: e => e.documented_attack_overlap ? `<span class="tag">attack ${e.documented_attack_overlap}</span>` : '<span class="faint">none</span>', sort: e => e.documented_attack_overlap || 0 }],
      { sortKey: null, onRow: e => { i = Math.max(0, H.t.indexOf(ts(e.timestamp_start))); stop(); showHour(); root.querySelector('#lvl').scrollIntoView({ behavior: 'smooth', block: 'center' }); } });
    else table($('#evT'), ev.rule_episodes, [
      { key: 'start', label: 'Start', render: e => ts(e.start) }, { key: 'hours', label: 'Alert hours', num: true },
      { key: 'rules', label: 'Rules', render: e => e.rules.map(h).join(', ') }, { key: 'signals', label: 'Signals', render: e => e.signals.map(h).join(', ') }],
      { sortKey: null, onRow: e => { i = Math.max(0, H.t.indexOf(ts(e.start))); stop(); showHour(); } });
  };
  $('#evSrc').querySelectorAll('button').forEach(b => b.onclick = () => { $('#evSrc').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); drawEvents(b.dataset.s); });
  drawEvents('ml');

  // playback
  let range = 'demo';
  root.querySelectorAll('[data-j]').forEach(b => b.onclick = () => { range = b.dataset.j; root.querySelectorAll('[data-j]').forEach(x => x.classList.toggle('on', x === b)); if (range === 'demo') i = demoStart; stop(); showHour(); });
  let raf = 0, lastStep = 0;
  function play() { playing = true; $('#wPlay').innerHTML = '<svg viewBox="0 0 16 16"><path d="M3 2h4v12H3zM9 2h4v12H9z"/></svg>'; lastStep = 0;
    const tick = now => { if (!playing) return; if (now - lastStep > (range === 'demo' ? 260 : 25)) { lastStep = now; const end = range === 'demo' ? demoEnd : N - 1; if (i >= end) return stop(); i++; showHour(); } raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick); }
  function stop() { playing = false; cancelAnimationFrame(raf); const b = $('#wPlay'); if (b) b.innerHTML = '<svg viewBox="0 0 16 16"><path d="M4 2l10 6-10 6z"/></svg>'; }
  $('#wPlay').onclick = () => playing ? stop() : play();
  $('#wScrub').oninput = e => { stop(); i = +e.target.value; showHour(); };
  $('#wTwin').onclick = () => withTwin(c => c.waterView?.(true));
  ctx.onLeave(() => { stop(); clearInterval(timer); });
  showHour(); drawSignal();
}

function sigChart(host, s, nowT) {
  const W = Math.max(320, host.clientWidth), Ht = 220, x0 = 46, x1 = W - 10, y0 = 190, y1 = 10;
  const vals = [...s.observed, ...(s.predicted || []).filter(v => v != null), ...(s.limits ? [s.limits.low, s.limits.high] : [])];
  let lo = Math.min(...vals), hi = Math.max(...vals); if (hi === lo) hi = lo + 1; const pad = (hi - lo) * .08; lo -= pad; hi += pad;
  const X = k => x0 + k / Math.max(1, s.t.length - 1) * (x1 - x0), Y = v => y0 - (v - lo) / (hi - lo) * (y0 - y1);
  const path = arr => arr.map((v, k) => v == null ? '' : `${k && arr[k - 1] != null ? 'L' : 'M'}${X(k).toFixed(1)},${Y(v).toFixed(1)}`).join('');
  const k = s.t.indexOf(nowT);
  host.innerHTML = `<div class="chart-legend"><span><i style="background:#FFFFFF"></i>Observed</span>${s.predicted ? '<span><i style="background:#8E9DE0"></i>Expected by Model C</span>' : ''}${s.limits ? '<span><i style="background:#F2B84B"></i>Normal range (rules)</span>' : ''}</div>
    <svg viewBox="0 0 ${W} ${Ht}" width="100%" height="${Ht}">
    ${[lo + pad, (lo + hi) / 2, hi - pad].map(v => `<line x1="${x0}" x2="${x1}" y1="${Y(v)}" y2="${Y(v)}" stroke="rgba(43,61,134,.55)"/><text x="${x0 - 6}" y="${Y(v) + 4}" text-anchor="end" fill="#6F7DB5" font-size="11">${v.toFixed(1)}</text>`).join('')}
    ${s.limits ? `<line x1="${x0}" x2="${x1}" y1="${Y(s.limits.low)}" y2="${Y(s.limits.low)}" stroke="#F2B84B" stroke-dasharray="4 4"/><line x1="${x0}" x2="${x1}" y1="${Y(s.limits.high)}" y2="${Y(s.limits.high)}" stroke="#F2B84B" stroke-dasharray="4 4"/>` : ''}
    ${s.predicted ? `<path d="${path(s.predicted)}" fill="none" stroke="#8E9DE0" stroke-width="2" stroke-dasharray="5 3"/>` : ''}
    <path d="${path(s.observed)}" fill="none" stroke="#FFFFFF" stroke-width="2"/>
    ${k >= 0 ? `<line x1="${X(k)}" x2="${X(k)}" y1="${y1}" y2="${y0}" stroke="#F2B84B" stroke-width="1.5"/>` : ''}
    <text x="${x0}" y="${Ht - 6}" fill="#6F7DB5" font-size="11">${h(s.t[0])}</text><text x="${x1}" y="${Ht - 6}" fill="#6F7DB5" font-size="11" text-anchor="end">${h(s.t[s.t.length - 1])}</text></svg>`;
}

// ======================================= FAILSAFE AND OPERATOR =======================================
export async function failsafe(root) {
  loading(root, 'Loading the failsafe');
  let policy, g;
  try { [policy, g] = await Promise.all([get('/api/failsafe/policy'), get('/api/graph')]); } catch (e) { return errorBox(root, e); }
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  const sc = store.scenario;
  root.innerHTML = `
    <div class="head"><div><h2>Failsafe and human intervention</h2><p class="lede">What happens when an alarm fires and nobody is sure yet. The platform proposes; a human decides; and if nobody answers in time, a failsafe puts the city in a safe state on its own. Every step is logged.</p></div></div>
    <div class="ladder">
      <div><b>1. Watch</b><span>One layer above threshold for an hour. Logged, nobody disturbed.</span></div>
      <div><b>2. Advisory</b><span>One layer alerting. On-call operator notified to investigate. No automatic action.</span></div>
      <div><b>3. Alarm</b><span>Both layers, a large deviation, or a cyber alarm in the simulation. Operator paged, protective actions proposed and waiting for approval.</span></div>
      <div class="w"><b>4. Failsafe</b><span>No answer in ${policy.operator_ack_min} min: cut internet and vendor access ("island mode"), field equipment to local control, page again.</span></div>
      <div><b>5. Recovery</b><span>Only a human can restore remote access, after checking the cause. Logged.</span></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>Test the failsafe on an attack</h3><p class="sub">Island mode at a chosen minute, run on the backend against ${sc ? `the current scenario "${h(sc.title)}"` : 'the worst single attack'}. Compares no failsafe, an operator who answers quickly, and nobody answering (the failsafe acts alone).</p>
      <div class="row" style="gap:18px;align-items:flex-end">
        <label class="fl">Operator answers after (min)<input class="f" type="number" id="fOp" min="0" max="120" value="5"></label>
        <label class="fl">Failsafe waits (min)<input class="f" type="number" id="fAck" min="1" max="120" value="${policy.operator_ack_min}"></label>
        <label class="chk" title="If an outside attacker keeps working without the internet (for example, it planted an automatic payload), cutting the link does not stop it"><input type="checkbox" id="fC2" ${policy.c2 ? 'checked' : ''}> Outside attackers need a live internet link</label>
        <button class="btn primary" id="fRun">Run the comparison</button></div>
      <div id="fOut" style="margin-top:16px"></div></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>What island mode costs</h3><p class="sub">A failsafe is not free. That is why a human approves it first when someone is there.</p><div id="fCost"></div></div>
      <div class="sheet"><h3>Unknown attacks</h3><p class="mute" style="font-size:13px">An attack with no CVE and no signature is still caught when it changes behaviour: the attack simulation raises an alarm when a monitored system is reached; the water layers compare every hour with normal operation. Either alarm starts the same ladder. What a novel attack cannot bypass is the human checkpoint and the failsafe timer.</p>
        <p class="note warn" style="margin-top:10px">Limit: an attacker who stays inside normal behaviour and avoids monitored systems is not detected by any of this. More monitoring (Fix optimiser) shrinks that space.</p></div>
    </div>`;
  const $ = s => root.querySelector(s);
  const run = async () => {
    const out = $('#fOut'); out.innerHTML = '<div class="loading"><span class="spin"></span>Running four simulations</div>';
    try {
      let req = sc ? structuredClone(sc.request) : null;
      if (!req) { const ov = await get('/api/overview'); req = { attackers: [{ id: 'A', entry: ov.worst_entry, start: 0 }], fixes: [], maintenance: [], detection: true, speed: 1 }; }
      const base = await api('/api/multi', { ...req, island_at: null });
      const det = base.detected_at;
      if (det == null || det > 360) { out.innerHTML = '<p class="note warn">This attack is never detected within 6 hours, so nothing triggers the ladder. Add monitoring first (Fix optimiser).</p>'; return; }
      const c2 = $('#fC2').checked, op = +$('#fOp').value, ack = +$('#fAck').value;
      const at = m => Math.min(360, det + m);
      const [fast, auto, late] = await Promise.all([
        api('/api/multi', { ...req, island_at: at(op), c2 }), api('/api/multi', { ...req, island_at: at(ack), c2 }), api('/api/multi', { ...req, island_at: at(Math.max(ack, 60)), c2 })]);
      const rows = [['No failsafe', base, null], [`Operator approves after ${op} min`, fast, at(op)], [`Nobody answers: failsafe after ${ack} min`, auto, at(ack)], [`Failsafe switched off, manual cut after ${Math.max(ack, 60)} min`, late, at(Math.max(ack, 60))]];
      out.innerHTML = `<p class="mute" style="font-size:13px;margin-bottom:10px">First alarm at <b class="num">${tmin(det)}</b>.</p>
        <div class="grid g12"><div class="chart-card"><h3>Harm</h3><p class="sub">People × minutes of lost service in 6 hours.</p><div id="fChart"></div></div>
        <div id="fTable"></div></div>`;
      const short = ['No failsafe', `Operator, ${op} min`, `Failsafe, ${ack} min`, `Manual cut, ${Math.max(ack, 60)} min`];   // full wording in the table beside
      bars($('#fChart'), rows.map(([l, r], k) => ({ label: short[k], value: r.combined.harm, color: k === 0 ? C.pink : k === 2 ? C.warn : '#FFFFFF' })), { horizontal: true, labelWidth: 170, tipFmt: d => `<b>${h(rows[short.indexOf(d.label)][0])}</b><br>${fmt(d.value)} people-min` });
      table($('#fTable'), rows.map(([l, r, t]) => ({ l, r, t })), [
        { key: 'l', label: 'Response' }, { key: 't', label: 'Cut at', num: true, render: x => x.t == null ? '–' : tmin(x.t) },
        { key: 'harm', label: 'Harm', num: true, render: x => fmt(x.r.combined.harm), sort: x => x.r.combined.harm },
        { key: 'lost', label: 'Systems lost', num: true, render: x => x.r.combined.assets_lost },
        { key: 'att', label: 'Attackers', render: x => x.r.attackers.map(a => `${atkBadge(a.id)} <span class="faint" style="font-size:12px">${h(a.status)}</span>`).join('<br>') }], { sortKey: null });
      const fs = auto.failsafe;
      $('#fCost').innerHTML = `<dl class="kv"><dt>Unreachable (counted as down)</dt><dd>${fs.lost_assets.map(a => h(names[a])).join(', ') || 'none'}</dd>
        <dt>Services lost to the failsafe itself</dt><dd>${auto.combined.services.filter(s => s.cause === 'failsafe').map(s => h(s.service)).join(', ') || 'none in this city'}</dd>
        <dt>Lose remote access, keep running locally</dt><dd>${fs.remote_only_cut.map(a => h(names[a])).join(', ')}</dd>
        <dt>Not stopped by island mode</dt><dd>Attackers who started inside (insiders, an infected laptop already on the network). ${auto.attackers.filter(a => a.status === 'active').map(a => `Attacker ${h(a.id)} is still active here.`).join(' ')}</dd></dl>
        <p class="faint" style="font-size:12px;margin-top:8px">${h(fs.note)} Assumption: ${c2 ? 'outside attackers stop when their internet link is cut' : 'outside attackers keep going without the internet, so the cut only blocks new ones'}.</p>`;
    } catch (e) { out.innerHTML = `<div class="err">${h(e.message)}</div>`; }
  };
  $('#fRun').onclick = run; run();
}


// ================================= UNKNOWN-ATTACK RESPONSE =================================
// One pipeline for an attack nobody has seen before: learn normal -> deviation -> alarm -> "what if it is an
// attacker?" (simulated consequence) -> isolate -> a human decides, with a failsafe timer if nobody does.
export async function novel(root, ctx) {
  loading(root, 'Loading the unknown-attack pipeline');
  let S, H, policy, g;
  try {
    S = await get('/api/water/summary');
    if (!S.available) { root.innerHTML = '<div class="chart-empty">This pipeline runs on the water anomaly package, which is not installed (<code class="c">ml_water/</code>).</div>'; return; }
    [H, policy, g] = await Promise.all([get('/api/water/hourly'), get('/api/failsafe/policy'), get('/api/graph')]);
  } catch (e) { return errorBox(root, e); }
  const names = Object.fromEntries(g.assets.map(a => [a.id, a.name]));
  // the first hour of every alarm episode
  const starts = H.level.map((l, k) => l === 'alarm' && H.level[k - 1] !== 'alarm' ? k : -1).filter(k => k >= 0);
  const qp = new URLSearchParams(location.hash.split('?')[1] || '');
  let hour = qp.get('hour') || H.t[starts.find(k => H.t[k] >= '2016-12-05') ?? starts[0]], asset = qp.get('asset') || '', pick = 'operator', res = null, timer = 0;
  root.innerHTML = `
    <div class="head"><div><h2>Unknown-attack response</h2><p class="lede">A new attack has no CVE and no signature, so a vulnerability feed cannot see it. Cascade still catches it when the infrastructure stops behaving normally, then asks the question that matters: <b>if this is an attacker, what does it break next, and what does each response save?</b> The decision stays with a human; a failsafe timer covers the case where nobody answers.</p></div>
      <div class="row"><a class="btn" href="#/water">Water console</a></div></div>
    <div class="histbanner"><b>Historical replay plus simulation.</b> The alarm is real model output on BATADAL (2016, simulated C-Town). The consequence is a simulation on the modelled city. Neither is live telemetry.</div>
    <ol class="pipe5" id="pipe">
      ${['Learn normal', 'Deviation', 'Alarm', 'What if it is an attacker?', 'Isolate and decide'].map((t, k) => `<li data-k="${k}"><span class="n">${k + 1}</span><b>${t}</b><em></em></li>`).join('')}
    </ol>
    <div class="row" style="margin:14px 0;gap:12px"><label class="fl" style="min-width:260px">Alarm (first hour of each episode)<select class="f" id="nHour">${starts.map(k => `<option value="${h(H.t[k])}" ${H.t[k] === hour ? 'selected' : ''}>${h(H.t[k])}${H.t[k] >= '2016-12-05' && H.t[k] <= '2016-12-10 16:00' ? ' (attack 6 window)' : ''}</option>`).join('')}</select></label>
      <label class="fl" style="min-width:260px">Suspected foothold<select class="f" id="nAsset"><option value="">Loading…</option></select></label></div>
    <div class="grid g2">
      <div class="sheet"><h3>1-3. Normal, deviation, alarm</h3><div id="nAlarm"></div></div>
      <div class="chart-card"><h3>4. If it is an attacker: where it goes</h3><p class="sub" id="nMapSub"></p><div id="nMap"></div></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>5. What each response saves</h3><p class="sub" id="nNote"></p><div id="nOpts"></div></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>Human decision</h3><div id="nDecide"></div></div>
      <div class="sheet"><h3>Take it further</h3><div class="row" style="flex-wrap:wrap;gap:8px"><a class="btn small" id="nSim">Open in Attack simulation</a><button class="btn small" id="nTwin">Replay in 3D twin</button><a class="btn small" href="#/failsafe">Failsafe settings</a></div>
        <p class="faint" style="font-size:12px;margin-top:10px">The same pipeline takes any anomaly source. Electricity, transport and IoT models can feed it the same way once they deliver hourly scores with a threshold and held-out test results.</p></div>
    </div>`;
  const $ = q => root.querySelector(q);
  const map = netmap($('#nMap'), g, { height: 360 });
  const stage = (k, txt, state) => { const li = $(`#pipe [data-k="${k}"]`); li.querySelector('em').textContent = txt; li.className = state || ''; };
  async function load() {
    clearInterval(timer);
    $('#nOpts').innerHTML = '<div class="loading"><span class="spin"></span>Simulating every response</div>';
    try { res = await api(`/api/novel/whatif?hour=${encodeURIComponent(hour)}${asset ? `&asset=${asset}` : ''}`); }
    catch (e) { $('#nOpts').innerHTML = `<div class="err">${h(e.message)}</div>`; return; }
    asset = res.asset || '';
    const a = res.alarm;
    stage(0, `ML trained on normal data only; rules learned ${S.reference_period[0].slice(0, 10)} to ${S.reference_period[1].slice(0, 10)}`, 'done');
    stage(1, a.signals.length ? `${a.signals[0].signal}: ${a.signals[0].observed} seen, ${a.signals[0].expected} expected` : 'rules outside the envelope', 'done');
    stage(2, `${a.level}, score ${a.score.toFixed(0)} / 100 (alert at 50)`, a.level === 'alarm' ? 'alarm' : 'done');
    stage(3, res.asset ? `foothold assumed at ${names[res.asset]}` : 'no foothold to test', res.asset ? 'done' : '');
    stage(4, 'waiting for the operator', 'wait');
    $('#nAlarm').innerHTML = `<dl class="kv"><dt>Hour</dt><dd class="num">${h(a.hour)}</dd><dt>Level</dt><dd><span class="tag ${a.level === 'alarm' ? 'warn' : ''}">${h(a.level)}</span> ML ${a.ml_alert ? 'alert' : 'no alert'}, rules ${a.rule_alert ? 'alert' : 'no alert'}</dd></dl>
      <h4 class="h4" style="margin-top:12px">Against normal</h4>
      ${a.signals.map(s => { const k = Math.min(1, s.z / 40); return `<div class="devrow"><b>${h(s.signal)}</b><span class="mute">${h(s.zone.replace('_', ' '))}</span><div class="dbar"><i style="left:${Math.min(100, 8.78587 / 40 * 100)}%" title="threshold"></i><span style="width:${(k * 100).toFixed(0)}%"></span></div><span class="num">|z| ${s.z.toFixed(1)}</span></div>`; }).join('') || '<p class="mute">No ML signal above threshold this hour.</p>'}
      ${a.rules.map(r => `<p style="font-size:12px;margin-top:6px"><b>${h(r.rule)}</b> <span class="mute">${h(r.detail)}</span></p>`).join('')}
      <p class="faint" style="font-size:12px;margin-top:8px">Bar = how far the signal is from what normal operation predicts; the tick is the alarm threshold (|z| 8.79). No signature or CVE is involved.</p>`;
    const sel = $('#nAsset');
    sel.innerHTML = `<optgroup label="From this alarm">${res.candidates.map(c => `<option value="${c.asset}" ${c.asset === asset ? 'selected' : ''}>${h(c.name)}</option>`).join('')}</optgroup>
      <optgroup label="Any other system (what-if)">${g.assets.filter(x => !res.candidates.some(c => c.asset === x.id)).map(x => `<option value="${x.id}" ${x.id === asset ? 'selected' : ''}>${h(x.name)}</option>`).join('')}</optgroup>`;
    $('#nNote').textContent = res.note || '';
    $('#nSim').href = res.asset ? `#/simulate?entry=${res.asset}` : '#/simulate';
    drawOpts(); decide();
  }
  function drawOpts() {
    if (!res?.options?.length) { $('#nOpts').innerHTML = `<p class="mute">${h(res?.note || 'Nothing to simulate.')}</p>`; map.update({}, []); return; }
    const base = res.options[0], maxH = Math.max(1, ...res.options.map(o => o.harm));
    $('#nOpts').innerHTML = `<div class="opts">${res.options.map(o => `<button class="opt ${o.key === pick ? 'on' : ''}" data-k="${o.key}" aria-pressed="${o.key === pick}">
      <b>${h(o.title)}</b><span class="mute">${h(o.text)}</span>
      <div class="hbar"><span style="width:${(100 * o.harm / maxH).toFixed(1)}%"></span></div>
      <span class="num">${fmt(o.harm)} people-min · ${o.assets_lost} system${o.assets_lost === 1 ? '' : 's'} reached · first loss ${tmin(o.first_failure_min)}</span>
      ${o.key !== 'no_action' ? `<em class="${o.assets_lost < base.assets_lost || o.harm < base.harm ? 'good' : ''}">${o.harm < base.harm ? `saves ${fmt(base.harm - o.harm)} people-min` : o.assets_lost < base.assets_lost ? `stops the spread: ${base.assets_lost - o.assets_lost} fewer system${base.assets_lost - o.assets_lost === 1 ? '' : 's'} reached` : 'no difference for this foothold'}</em>` : ''}</button>`).join('')}</div>
      ${res.options.every(o => o.harm === base.harm) && base.harm > 0 ? `<p class="note" style="margin-top:10px">Harm is the same for every response here: the suspected foothold is itself part of ${h(base.services.map(s => s.service).join(', '))}, so that service is already at risk the moment the system is taken over. What the response changes is how far the attacker gets beyond it.</p>` : ''}`;
    $('#nOpts').querySelectorAll('.opt').forEach(b => b.onclick = () => { pick = b.dataset.k; drawOpts(); });
    const o = res.options.find(x => x.key === pick), st = {};
    for (const [id, t] of Object.entries(o.compromised)) st[id] = { fill: '#FF6FB5', label: true, labelColor: '#fff', priority: 3, tip: `reached ${tmin(t)}` };
    st[res.asset] = { ...(st[res.asset] || {}), ring: '#F2B84B', label: true, priority: 4, tip: 'suspected foothold (the anomaly)' };
    map.update(st, Object.entries(o.parents).filter(([, p]) => p).map(([c, p]) => ({ src: p, dst: c, color: '#FF6FB5' })));
    $('#nMapSub').textContent = `${o.title}: ${o.assets_lost} system${o.assets_lost === 1 ? '' : 's'} reached. Amber ring = the suspected foothold.`;
  }
  function decide() {
    if (!res?.asset) { $('#nDecide').innerHTML = '<p class="mute">No alarm to decide on.</p>'; return; }
    let left = policy.operator_ack_min;
    const ctxText = `Unknown-attack alarm ${hour}, suspected foothold ${names[res.asset]}`;
    const render = () => {
      $('#nDecide').innerHTML = `<div class="decide"><div class="row" style="justify-content:space-between"><b style="font:700 20px var(--display)">Operator decision required</b><span class="count num">${left} min</span></div>
        <p class="mute" style="font-size:13px;margin:6px 0 10px">${policy.auto ? `If nobody answers in ${policy.operator_ack_min} minutes the failsafe goes to island mode on its own.` : 'Automatic failsafe is off; the alarm waits for a human.'} 1 second here = 1 minute.</p>
        <input class="f" id="nReason" placeholder="Note or reason (required to dismiss)" style="width:100%;margin-bottom:8px" aria-label="Reason">
        <div class="row"><button class="btn small primary" data-d="approved">Isolate ${h(names[res.asset])}</button><button class="btn small" data-d="acknowledged">Investigate first</button><button class="btn small" data-d="dismissed">Dismiss as false alarm</button></div></div>`;
      $('#nDecide').querySelectorAll('[data-d]').forEach(b => b.onclick = async () => {
        const reason = ($('#nReason')?.value || '').trim();
        if (b.dataset.d === 'dismissed' && !reason) return toast('Write why it is a false alarm first; it goes into the audit trail.');
        clearInterval(timer);
        try { await api('/api/ops/log', { context: ctxText, action: b.dataset.d === 'approved' ? `Isolate ${names[res.asset]}` : b.dataset.d === 'acknowledged' ? 'Investigating before acting' : 'No action', decision: b.dataset.d, reason, sim_time: hour }); } catch (e) { toast(e.message); }
        stage(4, { approved: 'isolated by the operator', acknowledged: 'operator investigating', dismissed: 'dismissed by the operator' }[b.dataset.d], b.dataset.d === 'dismissed' ? '' : 'done');
        if (b.dataset.d === 'approved') { pick = 'operator'; drawOpts(); }
        $('#nDecide').innerHTML = `<p class="note">Logged to the audit trail (hash-chained). ${b.dataset.d === 'approved' ? 'The map now shows the operator response.' : ''}</p>`;
        toast('Decision logged');
      });
    };
    render();
    timer = setInterval(async () => {
      left--; const c = $('#nDecide .count'); if (c) c.textContent = `${left} min`;
      if (left <= 0) {
        clearInterval(timer);
        if (policy.auto) {
          try { await api('/api/ops/log', { context: ctxText, action: 'Island mode: internet and vendor access cut', decision: 'auto_failsafe', reason: `No operator response in ${policy.operator_ack_min} min`, sim_time: hour }); } catch { /* shown elsewhere */ }
          stage(4, 'failsafe acted on its own', 'alarm'); pick = 'failsafe'; drawOpts();
          $('#nDecide').innerHTML = '<p class="note warn"><b>Failsafe acted on its own:</b> island mode, operator paged again. A human must confirm before remote access is restored.</p>';
        }
      }
    }, 1000);
  }
  $('#nHour').onchange = e => { hour = e.target.value; asset = ''; load(); };
  $('#nAsset').onchange = e => { asset = e.target.value; load(); };
  $('#nTwin').onclick = () => { const o = res?.options.find(x => x.key === pick); if (!res?.asset) return; const contain = { operator: 15, both: (policy.operator_ack_min || 15) + 15 }[pick];
    withTwin(c => c.playScenario({ attackers: [{ id: 'A', entry: res.asset, start: 0, contain_at: contain ?? null }], island_at: ['failsafe', 'both'].includes(pick) ? policy.operator_ack_min : null, fixes: [] }, `Unknown attack at ${names[res.asset]}: ${o.title}`)); };
  ctx.onLeave(() => clearInterval(timer));
  load();
}
