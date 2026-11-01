// Live attack testbed: real Modbus/TCP traffic to an emulated controller, detected and answered as it happens.
// The page streams /api/live/stream (server-sent events, twice a second). Nothing here is animated for effect:
// every number is the controller's current register value or a request the backend actually received.
import { api, get, h, tmin, toast, withTwin } from './core.js';

const STAGES = [
  ['learn', 'Normal behaviour', 'Learned from the HMI\'s own traffic for 30 s'],
  ['rules', 'Threshold', 'Every request checked against what is normal'],
  ['alarm', 'Alarm', 'Raised the moment a rule fires'],
  ['isolate', 'Isolate', 'Unknown masters refused'],
  ['human', 'Failsafe or human', 'Operator decides; failsafe acts if nobody answers'],
  ['recover', 'Recover', 'Known-good settings restored'],
];
const sevTag = s => s === 'alarm' ? '<span class="tag pink">alarm</span>' : '<span class="tag">notice</span>';

export async function live(root, ctx) {
  let st = null, showHmi = false, es = null, spread = null, lastInc = null;
  try { st = await api('/api/live/state'); } catch (e) { root.innerHTML = `<div class="err">Could not reach the live testbed: ${h(e.message)}</div>`; return; }
  if (!st.running) {
    const cloud = /public deployments/.test(st.error || '');
    root.innerHTML = `<div class="head"><div><h2>Live attack testbed</h2><p class="lede">A real Modbus/TCP attack against an emulated controller, detected, isolated and recovered as it happens.</p></div></div>`
      + (cloud ? `<div class="histbanner live"><b>Runs on a local install only.</b> For safety the live testbed is switched off on this public deployment: nobody on the internet can start, see or control an attack here. Run Cascade on your own laptop (<code class="c">run_master.bat</code>) to use it.</div>`
        : `<div class="err">The emulated controller is not running: ${h(st.error || 'unknown reason')}. Start Cascade without <code class="c">CASCADE_LIVE=0</code>, and make sure port 5020 is free.</div>`);
    return;
  }
  spread = await get('/api/live/spread').catch(() => null);
  const cmd = st.host === '127.0.0.1' ? 'python tools\\live\\attack.py' : `python tools\\live\\attack.py --host <this laptop's IP>`;
  root.innerHTML = `
    <div class="head"><div><h2>Live attack testbed</h2><p class="lede">A real attack, detected and answered as it happens. An attacker script sends real Modbus/TCP commands to a controller; Cascade inspects every request, raises the alarm, isolates the attacker and restores the controller.</p></div></div>
    <div class="histbanner live"><b>LIVE traffic, emulated device.</b> The controller is a small Python program on this laptop (Modbus/TCP ${h(st.host)}:${st.port}) standing in for <b>${h(st.asset_name)}</b>. The packets, the detection and the isolation are real; the tank is a toy model, and what happens beyond the controller is the usual simulation.</div>
    <div class="lv-grid">
      <div class="sheet lv-tank"><h3>Controller: tank and pump</h3><div id="lvTank"></div></div>
      <div class="sheet"><h3>Response</h3><div id="lvResp"></div><h3 style="margin-top:18px">Detection pipeline</h3><ol class="lv-pipe" id="lvPipe"></ol></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>Alerts</h3><p class="sub">Each rule names the MITRE ATT&CK for ICS technique it caught and the mitigation that would have stopped it.</p><div id="lvAlerts"></div></div>
    <div class="sheet" style="margin-top:16px"><div class="lv-pkhead"><h3>Modbus requests, as received</h3><label class="chk"><input type="checkbox" id="lvHmi"> Show the HMI's routine reads</label></div><div id="lvPk"></div></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>If nobody stops it (simulated)</h3><div id="lvSpread"></div></div>
      <div class="sheet"><h3>Run the attack yourself</h3>
        <p class="sub">Open a second terminal in the project folder and run:</p>
        <pre class="lv-cmd"><code id="lvCmd">${h(cmd)}</code><button class="btn small" id="lvCopy">Copy</button></pre>
        <p class="sub">Steps: map the controller, switch off its alarm, raise the high setpoint above the tank, force the pump on. Use <code class="c">recon</code> alone to see only the early-warning notices. Attack from a second laptop with <code class="c">--host</code> (start Cascade with <code class="c">CASCADE_LIVE_HOST=0.0.0.0</code>).</p>
        <label class="chk" style="margin-top:8px"><input type="checkbox" id="lvSis"> Independent safety trip (SIS) at 490 cm: not reachable over Modbus, as in a real plant</label>
      </div>
    </div>`;
  root.querySelector('#lvCopy').onclick = () => { navigator.clipboard?.writeText(root.querySelector('#lvCmd').textContent).then(() => toast('Copied'), () => toast('Copy failed: select the text')); };
  root.querySelector('#lvHmi').onchange = e => { showHmi = e.target.checked; if (showHmi) api('/api/live/state?all_packets=true').then(s => { st = s; draw(); }); };
  root.querySelector('#lvSis').onchange = async e => { try { st = await api('/api/live/sis', { on: e.target.checked }); draw(); } catch (err) { toast(err.message); } };
  const act = async (path, body) => { try { st = await api(path, body || {}); draw(); } catch (err) { toast(err.message); } };

  function tank(p) {
    const H = 260, W = 220, top = 20, bot = top + H, k = H / p.tank_cm, y = v => bot - Math.min(p.tank_cm + 5, v) * k;
    const water = p.overflowing ? 'var(--pink)' : p.level_cm >= p.high_alarm_cm ? 'var(--warn)' : '#6FA8FF';
    const used = [];      // labels never overlap: each one moves down until it has 13 px of room
    const line = (v, lbl, dash, col) => { let ly = y(v) + 4; for (let k = 0; k < 6 && used.some(u => Math.abs(u - ly) < 13); k++) ly += 13; used.push(ly);
      return `<line x1="40" x2="150" y1="${y(v)}" y2="${y(v)}" stroke="${col}" stroke-dasharray="${dash}"/><text x="156" y="${ly}" font-size="11" fill="${col}">${lbl}</text>`; };
    return `<svg viewBox="0 0 ${W + 60} ${H + 40}" width="100%" style="max-width:300px" role="img" aria-label="Tank level ${p.level_cm} cm">
      <rect x="40" y="${top}" width="110" height="${H}" rx="6" fill="none" stroke="var(--mute)" stroke-width="2"/>
      <rect x="42" y="${y(p.level_cm)}" width="106" height="${Math.max(0, bot - y(p.level_cm) - 2)}" rx="4" fill="${water}" opacity=".85"/>
      ${line(p.high_sp, `high setpoint ${p.high_sp}`, '5 4', p.high_sp > p.tank_cm ? 'var(--pink)' : 'var(--white)')}
      ${line(p.low_sp, `low setpoint ${p.low_sp}`, '5 4', 'var(--mute)')}
      ${line(p.high_alarm_cm, 'alarm 450', '2 3', 'var(--warn)')}
      ${p.sis_on ? line(p.sis_trip_cm, 'SIS trip 490', '1 3', 'var(--mute)') : ''}
      <text x="95" y="${H + 38}" text-anchor="middle" font-size="13" fill="var(--white)" font-weight="700">${p.level_cm.toFixed(0)} cm</text>
    </svg>
    <div class="lv-chips">
      <span class="tag ${p.pump ? 'pink' : ''}">pump ${p.pump ? 'ON' : 'off'}</span>
      <span class="tag ${p.manual ? 'pink' : ''}">${p.manual ? 'MANUAL mode' : 'auto mode'}</span>
      <span class="tag ${p.alarm_enable ? '' : 'pink'}">alarm ${p.alarm_enable ? 'enabled' : 'DISABLED'}</span>
      ${p.high_alarm ? '<span class="tag warn">HIGH LEVEL</span>' : ''}
      ${p.sis_tripped ? '<span class="tag warn">SIS tripped: pump forced off</span>' : ''}
      ${p.overflowing || p.spilled_s ? `<span class="tag pink">overflowing ${p.spilled_s.toFixed(0)} s</span>` : ''}
    </div>`;
  }

  const put = (sel, html) => { const el = root.querySelector(sel); if (el && el._html !== html) { el.innerHTML = html; el._html = html; return true; } return false; };

  function stage(s) {
    const inc = s.incident;
    if (!s.baseline.learned) return 'learn';
    if (!inc) return 'rules';
    if (inc.state === 'awaiting_operator') return 'human';
    if (inc.state === 'isolated') return 'isolate';
    if (inc.state === 'recovered') return 'recover';
    return 'rules';
  }

  function draw() {
    const s = st, p = s.process, inc = s.incident;
    put('#lvTank', tank(p));
    root.querySelector('#lvSis').checked = p.sis_on;
    const cur = stage(s), order = STAGES.map(x => x[0]);
    const doneUpTo = inc ? (inc.state === 'awaiting_operator' ? 2 : inc.state === 'isolated' ? 4 : inc.state === 'recovered' ? 5 : 1) : s.baseline.learned ? 1 : -1;
    put('#lvPipe', STAGES.map(([k, t, d], i) => `<li class="${k === cur ? 'on' : i <= doneUpTo ? 'done' : ''}"><b>${t}</b><span>${k === 'learn' && !s.baseline.learned ? `learning: ${Math.round(100 * s.baseline.progress)}%` : d}</span></li>`).join(''));
    let r;
    if (!s.baseline.learned) r = `<p class="lv-state">Learning normal behaviour from the HMI (${Math.round(100 * s.baseline.progress)}% of ${s.baseline.seconds} s). Rules switch on after this.</p>`;
    else if (!inc) r = `<p class="lv-state ok">Normal. Watching every request.</p><p class="sub">Normal behaviour learned: the HMI writes ${s.baseline.writes.map(h).join(', ') || 'nothing'}${Object.entries(s.baseline.range).map(([a, [lo, hi]]) => `; register ${a} stays within ${lo}-${hi}`).join('')}. Anything else raises an alert.</p>`;
    else if (inc.state === 'awaiting_operator') r = `<p class="lv-state alarm">ALARM at ${h(inc.opened_at)} from ${h(inc.src)}</p>
      <div class="lv-count"><b id="lvSec"></b> s until the failsafe isolates the controller on its own</div>
      <div class="lv-btns"><button class="btn primary" id="lvIso">Isolate now</button><button class="btn" id="lvDis">Dismiss as false alarm</button></div>`;
    else if (inc.state === 'isolated') r = `<p class="lv-state iso">Isolated by ${inc.decided_by === 'failsafe' ? '<b>the failsafe</b> (nobody answered in time)' : `<b>${h(inc.decided_by)}</b>`} at T+${Math.round(inc.decided_t)} s. Unknown masters are refused.</p>
      <p class="sub">The attacker is cut off, but the settings they wrote are still in the controller${p.manual || p.high_sp > p.tank_cm || !p.alarm_enable ? ': the tank is still at risk' : ''}. Recovery puts them back.</p>
      <div class="lv-btns"><button class="btn primary" id="lvRes">Restore known-good configuration</button></div>`;
    else if (inc.state === 'recovered') r = `<p class="lv-state ok">Recovered at T+${Math.round(inc.recovered_t)} s. Setpoints, alarm and auto mode restored; isolation still on.</p><div class="lv-btns"><button class="btn" id="lvClose">Close incident and reset the demo</button></div>`;
    else r = `<p class="lv-state">Dismissed by ${h(inc.decided_by)}. The alerts stay on record.</p><div class="lv-btns"><button class="btn" id="lvClose">Close incident</button></div>`;
    if (put('#lvResp', r)) {         // buttons are only rebuilt when the state changes, so a click is never lost
      root.querySelector('#lvIso')?.addEventListener('click', () => act('/api/live/decide', { decision: 'isolate' }));
      root.querySelector('#lvDis')?.addEventListener('click', () => act('/api/live/decide', { decision: 'dismiss' }));
      root.querySelector('#lvRes')?.addEventListener('click', () => act('/api/live/restore'));
      root.querySelector('#lvClose')?.addEventListener('click', () => act('/api/live/close'));
    }
    const sec = root.querySelector('#lvSec'); if (sec && inc) sec.textContent = Math.ceil(inc.seconds_left ?? 0);
    const al = s.alerts.slice().reverse();
    put('#lvAlerts', al.length ? `<div class="tablewrap"><table class="t"><thead><tr><th>Time</th><th>Level</th><th>What</th><th>ATT&CK for ICS</th><th>Would be stopped by</th><th>Source</th></tr></thead><tbody>${al.map(a => `<tr><td class="n">${h(a.at)}</td><td>${sevTag(a.severity)}</td><td>${h(a.text)}<div class="faint" style="font-size:12px">${h(a.detail)}</div></td><td>${h(a.technique)}</td><td>${h(a.mitigation)}</td><td>${h(a.src)}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="chart-empty">No alerts. Run the attack script to see them appear here.</div>');
    const pk = s.packets.filter(x => showHmi || !(x.master === 'HMI' && ![5, 6, 15, 16].includes(x.fc))).slice().reverse().slice(0, 40);
    put('#lvPk', pk.length ? `<div class="tablewrap lv-pk"><table class="t"><thead><tr><th>Time</th><th>From</th><th>Master</th><th>Request</th><th>Address</th><th>Value</th><th>Result</th></tr></thead><tbody>${pk.map(x => `<tr class="${x.alerts.length ? 'hot' : ''}"><td class="n">${h(x.at)}</td><td>${h(x.src)}</td><td>${x.master === 'HMI' ? 'HMI' : '<span class="tag pink">unknown</span>'}</td><td>${h(x.fname)}</td><td class="n">${x.addr ?? ''}</td><td>${x.value == null ? '' : h(Array.isArray(x.value) ? x.value.join(', ') : x.value)}</td><td>${/refused/.test(x.result) ? `<span class="tag">${h(x.result)}</span>` : h(x.result)}${x.alerts.length ? ` <span class="tag pink">${x.alerts.length} alert${x.alerts.length > 1 ? 's' : ''}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="chart-empty">No requests yet other than the HMI\'s routine polling.</div>');
    if (inc && lastInc !== inc.id) { lastInc = inc.id; }
  }

  function drawSpread() {
    const el = root.querySelector('#lvSpread');
    if (!spread) { el.innerHTML = '<div class="chart-empty">Simulation unavailable.</div>'; return; }
    const sv = Object.entries(spread.failures).sort((a, b) => a[1] - b[1]);
    el.innerHTML = `<p class="sub">${h(spread.note)}</p>
      <dl class="kv"><dt>Systems the attacker reaches from here</dt><dd>${Object.keys(spread.compromised).length}: ${Object.values(spread.names).map(h).join(', ')}</dd>
      ${sv.map(([n, t]) => `<dt>${h(n)}</dt><dd class="pinkt">lost at ${tmin(t)}</dd>`).join('') || '<dt>Essential services</dt><dd>none lost in 6 hours</dd>'}</dl>
      <button class="btn" id="lvTwin" style="margin-top:12px">Show this in the 3D twin</button>`;
    el.querySelector('#lvTwin').onclick = () => withTwin(c => c.playScenario({ attackers: [{ id: 'A', speed: 1, contain_at: null, adaptive: false, entries: [{ asset: spread.asset, start: 0 }] }], maintenance: [], island_at: null, detection: true }, `LIVE foothold: ${st.asset_name} (spread simulated)`));
  }

  draw(); drawSpread();
  // stream: half-second snapshots; reconnects on its own if the server restarts
  try {
    es = new EventSource('/api/live/stream');
    es.onmessage = ev => { try { const s = JSON.parse(ev.data); if (showHmi) { st = { ...s, packets: st.packets.concat(s.packets.filter(p => !st.packets.some(q => q.t === p.t && q.src === p.src))).slice(-120) }; } else st = s; draw(); } catch { /* ignore one bad frame */ } };
  } catch { /* EventSource unsupported: fall back to polling */ }
  const poll = setInterval(() => { if (!es || es.readyState === 2) api('/api/live/state').then(s => { st = s; draw(); }).catch(() => {}); }, 2000);
  ctx?.onLeave?.(() => { es?.close(); clearInterval(poll); });
}
