// Project information, Architecture and methodology, Security and 2FA.
import { api, get, h, fmt, loading, errorBox, toast, refreshTop } from './core.js';

const SITE = window.CASCADE_SITE;
const gh = () => window.cascadeGithubReady() ? `<a class="btn primary" href="${h(SITE.github)}" target="_blank" rel="noopener">View on GitHub</a>`
  : `<button class="btn" disabled title="Set the link in frontend/static/site-config.js">GitHub link not set yet</button>`;

// ======================================= PROJECT =======================================
export async function project(root) {
  loading(root, 'Loading');
  try {
    const [cfg, ds, ml] = await Promise.all([get('/api/config'), get('/api/dataset'), get('/api/ml')]);
    root.innerHTML = `
      <div class="head"><div><h2>${h(SITE.project)}: ${h(SITE.title)}</h2><p class="lede">${h(SITE.problem)}. A time-aware cyber digital twin with predictive risk analysis and budget-constrained defence optimisation.</p></div><div class="row">${gh()}</div></div>
      <div class="grid g21">
        <div class="sheet prose">
          <h3 style="margin-top:0">About the project</h3>
          <p>Critical infrastructure now runs on connected IT, IoT, cloud and OT. Vulnerability scanners rank bugs by severity, but severity does not say which hospital loses power, how many people lose water, or how long defenders have. PS03 asks for AI-based prediction of cyber risk to critical infrastructure; this platform answers it by simulating how an attack would spread through a modelled city over time and measuring the result in lost essential services.</p>
          <h3>Methodology</h3>
          <p><b>Infrastructure modelling.</b> Systems, network and vendor links, dependencies and essential services from four CSV files (the data contract). Only network and vendor links are attack paths; dependency and physical links carry consequences, not attackers.</p>
          <p><b>Asset profiling.</b> Each system has a type, zone, criticality (1-5), exposure (0-1), internet and vendor access flags, software and version, CVEs, configuration weaknesses, monitoring and patch downtime.</p>
          <p><b>Vulnerability assessment.</b> Per CVE: CVSS from NVD, CISA KEV and FIRST EPSS (EPSS is the exploitation prediction; we did not train our own). Per system: V = 1 − Π(1 − p × CVSS/10) + 0.05 per weakness.</p>
          <p><b>Risk scoring.</b> A display score = 100 × likelihood × impact, where impact mixes criticality with the share of the population whose service this system alone takes down.</p>
          <p><b>Attack propagation.</b> Crossing a link takes base minutes ÷ (attacker speed × (${cfg.MIN_EXPLOIT_FACTOR} + V of the target)), × (1 + ${cfg.FIREWALL_FACTOR} × firewall level), × ${cfg.SEGMENT_FACTOR} if segmented. Earliest arrival by shortest path; several attackers keep separate histories.</p>
          <p><b>Detection assumptions.</b> A monitored system raises the alarm ${cfg.TTD_MONITORED_MIN} min after compromise; its zone is isolated ${cfg.RESPONSE_DELAY_MIN} min later. Otherwise someone notices after ${cfg.TTD_UNMONITORED_MIN} min and the whole network is isolated.</p>
          <p><b>Service impact.</b> A service fails when its rule (for example <code class="c">A05 AND (A06 OR A07)</code>) turns false and its backup buffer runs out. Harm = people × minutes of outage within ${cfg.HORIZON_MIN / 60} hours. Expected harm weights each way in by exposure × V.</p>
          <p><b>Water anomaly monitoring.</b> SENTINEL Model C (trained on normal C-Town operation) flags hours where tank levels or pressures disagree with what the pumps and valves imply; an independent rule layer checks hard limits, pump/flow consistency, rate of change and frozen sensors. Either can trigger the operator ladder; only a human or the failsafe timer acts.</p>
          <p><b>Fix optimisation.</b> Each fix (patch, harden, monitor, segment, remove exposure) edits a copy of the data and the simulation re-runs. Bundles are searched under fix count, maintenance windows and staff hours; the attacker re-picks its best way in after every bundle; OT patch downtime counts as harm unless a window is used.</p>
          <h3>Dataset and sources</h3>
          <p>Loaded now: <b>${h(ds.folder)}</b>, ${ds.assets} systems, ${ds.links} links, ${ds.services} services. The SENTINEL master city was assembled by Suryans Padhy from NIST SP 800-82r3 architecture patterns, MITRE ATT&CK for ICS asset classes, real CPE-matched products and their CVEs from NVD, CISA's Known Exploited Vulnerabilities catalogue and FIRST EPSS scores. The infrastructure itself is simulated.</p>
          <h3>Assumptions and limitations</h3>
          <ul>
            <li>The infrastructure is simulated. No real operator's network is used, scanned or attacked.</li>
            <li>Attack propagation times are model assumptions (base minutes per link, the factors above), not measurements.</li>
            <li>Detection times are assumed: ${cfg.TTD_MONITORED_MIN} min with monitoring, ${cfg.TTD_UNMONITORED_MIN} min without.</li>
            <li>EPSS estimates exploitation activity across the internet; it is not proof that a given system will be compromised.</li>
            <li>The water anomaly ML is shown on historical BATADAL data (one simulated network, seven attacks); its alerts are advisory and never mark a system compromised.</li>
            <li>Service-impact estimates depend on the population figures, backup buffers and service rules in services.csv.</li>
            <li>Every estimate can be moved ±30% on the Graphs page (sensitivity) to see whether the fix order holds.</li>
          </ul>
        </div>
        <div>
          <div class="sheet"><h3>Team</h3>${SITE.team.map(p => `<div style="padding:12px 0;border-bottom:1px solid var(--line)"><b style="font:700 24px var(--display)">${h(p.name)}</b><p class="mute" style="font-size:13px;margin-top:4px">${h(p.role)}</p></div>`).join('')}
            <div class="row" style="margin-top:14px">${gh()}</div>
            <p class="faint" style="font-size:12px;margin-top:10px">The GitHub link and team details live in one file: <code class="c">frontend/static/site-config.js</code>.</p></div>
          <div class="sheet" style="margin-top:16px"><h3>Assumptions in use</h3><p class="sub">Live from <code class="c">backend/config.py</code>.</p>
            <dl class="kv">${Object.entries(cfg).filter(([, v]) => typeof v !== 'object').map(([k, v]) => `<dt style="font:12px var(--mono)">${h(k)}</dt><dd>${h(v)}</dd>`).join('')}</dl></div>
        </div>
      </div>`;
  } catch (e) { errorBox(root, e); }
}

// ======================================= ARCHITECTURE =======================================
export async function architecture(root) {
  root.innerHTML = `
    <div class="head"><div><h2>Architecture and methodology</h2><p class="lede">What actually runs, as found in the repository. One Python process serves the API, the 3D twin and this platform; everything works offline.</p></div></div>
    <div class="sheet"><h3>Data flow</h3><p class="sub">Each box is a real module. Arrows are function calls, not services.</p>
      <div class="diagram" style="margin-top:12px">
        <div class="box"><b>Asset and vulnerability data</b><span>assets, links, services, vulns CSVs; optional asset_metadata</span><code>data_master/</code></div>
        <div class="box"><b>Infrastructure graph</b><span>validation, compiled model (cached)</span><code>load_graph.py, simulate.compile_model</code></div>
        <div class="box"><b>Risk engine</b><span>V per system, display risk score</span><code>risk.py</code></div>
        <div class="box"><b>Attack simulation</b><span>single engine (fast) and multi-attacker engine (attributed), tested equal</span><code>simulate.py, multi.py</code></div>
        <div class="box"><b>Service impact</b><span>service rules, buffers, people × minutes</span><code>harm.py</code></div>
        <div class="box"><b>ML and analytics</b><span>water anomaly ML (Model C, historical replay) + rule layer; choke points, centrality</span><code>water.py, ml_water/, api.analytics</code></div>
        <div class="box"><b>Fix optimiser</b><span>fix ranking, bundles, adaptive attacker, sensitivity</span><code>fixes.py, optimize.py, sensitivity.py</code></div>
        <div class="box"><b>Dashboard and twin</b><span>FastAPI; Three.js twin; this platform</span><code>api.py, frontend/</code></div>
      </div></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>Technology stack</h3><dl class="kv">
        <dt>Backend</dt><dd>Python 3.10+, FastAPI, Uvicorn, Pydantic</dd>
        <dt>Modelling</dt><dd>pandas, NetworkX (graph, betweenness), heapq Dijkstra</dd>
        <dt>3D twin</dt><dd>Three.js 0.160 (vendored), bloom post-processing, procedural textures</dd>
        <dt>Platform</dt><dd>Plain JavaScript modules, hand-written SVG charts, no build step</dd>
        <dt>Security</dt><dd>Python standard library: PBKDF2, HMAC-SHA256, TOTP (RFC 6238)</dd>
        <dt>Testing</dt><dd>Rule tests per module, run on three datasets; Playwright browser checks</dd>
        <dt>ML (Suryans Padhy)</dt><dd>scikit-learn HistGradientBoostingRegressor (Model C, frozen); the platform reads its exported replay and events, it does not re-run the model</dd></dl></div>
      <div class="sheet"><h3>API endpoints</h3><div id="eps"></div></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>Two simulation engines, one model</h3><p class="mute" style="max-width:80ch">
      <code class="c">simulate.simulate_full</code> is a multi-source shortest path: fast enough for the optimiser to call it thousands of times, but it forgets which attacker reached each system.
      <code class="c">multi.simulate_multi</code> keeps one state per attacker (entry, start time, speed, path, containment) and a shared defence state (alarms and isolation), and supports maintenance windows.
      Both read the same compiled model and constants. <code class="c">test_multi.py</code> checks that one attacker, and two attackers starting together, give exactly the old engine's systems, times and harm on every dataset.</p></div>`;
  const eps = [
    ['GET', '/api/graph', 'Systems, links, services, layout'], ['GET', '/api/overview', 'Expected and worst-case harm, first failure'],
    ['POST', '/api/simulate', 'One combined attack (used by the twin)'], ['POST', '/api/multi', 'Multi-attacker run with attribution'],
    ['GET', '/api/multi/presets', 'Scenarios A-H built from the dataset'], ['GET', '/api/fixes', 'Every single fix, ranked'],
    ['POST', '/api/optimize', 'Best bundle for a budget'], ['GET', '/api/asset/{id}', 'Why a system is at risk'],
    ['POST', '/api/containment', 'Response plan with deadlines'], ['GET', '/api/sensitivity', '±30% on every assumption'],
    ['GET', '/api/assets', 'Inventory'], ['GET', '/api/vulns', 'Vulnerability intelligence'], ['GET', '/api/risk_register', 'Risk register'],
    ['GET', '/api/baseline', 'CVSS-only against Cascade'], ['GET', '/api/analytics', 'Choke points, centrality, per-zone and per-sector'],
    ['GET', '/api/ml', 'ML status and per-CVE probability source'], ['POST', '/api/validate', 'Check replacement CSVs'],
    ['POST', '/api/auth/*', 'Account, password, 2FA'],
  ];
  root.querySelector('#eps').innerHTML = `<div class="tablewrap"><table class="t"><tbody>${eps.map(([m, p, d]) => `<tr><td><span class="tag">${m}</span></td><td style="font:12px var(--mono)">${h(p)}</td><td class="mute">${h(d)}</td></tr>`).join('')}</tbody></table></div>`;
}

// ======================================= SECURITY & 2FA =======================================
export async function security(root) {
  loading(root, 'Loading account security');
  let s;
  try { s = await api('/api/auth/status'); } catch (e) { return errorBox(root, e); }
  const intro = `<div class="head"><div><h2>Security and two-factor authentication</h2><p class="lede">Sign-in uses a password plus a 6-digit code from an authenticator app (TOTP). The backend verifies every code; nothing here is decided in the browser.</p></div></div>`;
  const how = `<div class="sheet" style="margin-top:16px"><h3>How it is protected</h3><dl class="kv">
    <dt>Passwords</dt><dd>PBKDF2-HMAC-SHA256, 310,000 rounds, random salt. The password itself is never stored.</dd>
    <dt>2FA secret</dt><dd>Encrypted at rest (HMAC-SHA256 keystream with an authentication tag). The key lives apart from the data, in <code class="c">CASCADE_SECRET</code> or <code class="c">.cascade/secret.key</code>.</dd>
    <dt>Codes</dt><dd>RFC 6238, 30-second steps, one step of clock drift allowed, a used code cannot be replayed.</dd>
    <dt>Recovery codes</dt><dd>8 codes, stored only as hashes, each works once.</dd>
    <dt>Brute force</dt><dd>5 wrong attempts lock the account for 5 minutes.</dd>
    <dt>Session</dt><dd>Signed cookie, HttpOnly, SameSite=Strict, 8 hours. Password alone gives a half session that can only enter a code.</dd>
    <dt>Storage</dt><dd><code class="c">.cascade/</code> at the project root, excluded from git.</dd>
    <dt>Reset</dt><dd><code class="c">python backend/auth.py --reset</code> removes accounts (not data).</dd></dl></div>`;
  if (!s.accounts_exist) {
    root.innerHTML = intro + `<div class="grid g2"><div class="sheet"><h3>Set up the administrator account</h3>
      <p class="sub">The platform is open until the first account exists (so a fresh copy still demos). Once you create it, the platform and its API require sign-in. Only one account can be created this way.</p>
      <form id="setup" class="grid" style="gap:10px;max-width:360px">
        <label class="fl">Username<input class="f" name="u" autocomplete="username" required minlength="3"></label>
        <label class="fl">Password (10+ characters)<input class="f" name="p" type="password" autocomplete="new-password" required minlength="10"></label>
        <label class="fl">Repeat password<input class="f" name="p2" type="password" autocomplete="new-password" required></label>
        <button class="btn primary">Create account</button><p class="err" id="sErr" hidden></p></form></div>
      <div class="sheet"><h3>Status</h3><p class="note warn">Not set up. Anyone who can reach this server can use the platform. The server listens on this computer only (127.0.0.1) by default.</p></div></div>` + how;
    root.querySelector('#setup').onsubmit = async e => {
      e.preventDefault(); const f = new FormData(e.target), err = root.querySelector('#sErr');
      if (f.get('p') !== f.get('p2')) { err.hidden = false; err.textContent = 'The passwords do not match.'; return; }
      try { await api('/api/auth/setup', { username: f.get('u'), password: f.get('p') }); toast('Account created. Now turn on 2FA.'); refreshTop(); security(root); }
      catch (x) { err.hidden = false; err.textContent = x.message; }
    };
    return;
  }
  if (!s.user) { root.innerHTML = intro + `<div class="sheet"><p>Sign in to manage security.</p><a class="btn primary" href="/login?next=/app%23/security" style="margin-top:12px">Sign in</a></div>`; return; }
  root.innerHTML = intro + `<div class="grid g2"><div class="sheet" id="tf"></div>
    <div class="sheet"><h3>Account</h3><dl class="kv"><dt>Signed in as</dt><dd>${h(s.user)}</dd><dt>Two-factor</dt><dd>${s.totp_enabled ? 'On' : '<span class="pinkt">Off</span>'}</dd>
      <dt>Recovery codes left</dt><dd>${s.totp_enabled ? s.recovery_left : '–'}</dd><dt>Access gate</dt><dd>${s.gate ? 'On: sign-in required' : 'Off (CASCADE_AUTH=off)'}</dd></dl>
      <button class="btn" id="out" style="margin-top:14px">Sign out</button></div></div>` + how;
  root.querySelector('#out').onclick = async () => { await api('/api/auth/logout', {}); location.href = '/login'; };
  const tf = root.querySelector('#tf');
  if (s.totp_enabled) {
    tf.innerHTML = `<h3>Two-factor is on</h3><p class="sub">Every sign-in asks for a code from your authenticator app. To turn it off, confirm with your password and a current code.</p>
      <form id="dis" class="grid" style="gap:10px;max-width:340px"><label class="fl">Password<input class="f" name="p" type="password" autocomplete="current-password" required></label>
      <label class="fl">6-digit code or a recovery code<input class="f" name="c" inputmode="numeric" autocomplete="one-time-code" required></label>
      <button class="btn">Turn off 2FA</button><p class="err" id="dErr" hidden></p></form>`;
    tf.querySelector('#dis').onsubmit = async e => {
      e.preventDefault(); const f = new FormData(e.target);
      try { await api('/api/auth/2fa/disable', { password: f.get('p'), code: f.get('c') }); toast('2FA turned off.'); refreshTop(); security(root); }
      catch (x) { const er = tf.querySelector('#dErr'); er.hidden = false; er.textContent = x.message; }
    };
    return;
  }
  tf.innerHTML = `<h3>Turn on two-factor</h3><p class="sub">You need an authenticator app such as Google Authenticator, Microsoft Authenticator or Aegis.</p><button class="btn primary" id="start">Start set-up</button>`;
  tf.querySelector('#start').onclick = async () => {
    try {
      const r = await api('/api/auth/2fa/start', {});
      let qrHtml = '';
      try { const q = window.qrcode(0, 'M'); q.addData(r.uri); q.make(); qrHtml = q.createSvgTag({ cellSize: 5, margin: 0, scalable: false }); } catch { qrHtml = '<p class="mute">QR code unavailable; type the key instead.</p>'; }
      tf.innerHTML = `<h3>Scan this in your app</h3><div class="row" style="align-items:flex-start;gap:20px;margin-top:10px"><div class="qr">${qrHtml}</div>
        <div style="flex:1;min-width:200px"><p class="sub">Can't scan? Enter this key by hand (time-based, 6 digits, 30 s):</p><p style="font:15px var(--mono);word-break:break-all">${h(r.secret.match(/.{1,4}/g).join(' '))}</p></div></div>
        <form id="conf" class="row" style="margin-top:16px"><input class="f" name="c" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code" required pattern="[0-9 ]{6,7}" style="width:140px"><button class="btn primary">Confirm</button></form><p class="err" id="cErr" hidden style="margin-top:10px"></p>`;
      tf.querySelector('#conf').onsubmit = async e => {
        e.preventDefault();
        try {
          const c = await api('/api/auth/2fa/confirm', { code: new FormData(e.target).get('c') });
          tf.innerHTML = `<h3>2FA is on. Save these recovery codes</h3><p class="sub">Each one works once if you lose your phone. They are shown only now.</p>
            <div class="codes">${c.recovery_codes.map(x => `<span>${h(x)}</span>`).join('')}</div>
            <div class="row" style="margin-top:12px"><button class="btn small" id="dl">Download as text</button><button class="btn small primary" id="done">I have saved them</button></div>`;
          tf.querySelector('#dl').onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([`Cascade recovery codes for ${s.user}\n\n${c.recovery_codes.join('\n')}\n`], { type: 'text/plain' })); a.download = 'cascade-recovery-codes.txt'; a.click(); };
          tf.querySelector('#done').onclick = () => { refreshTop(); security(root); };
        } catch (x) { const er = tf.querySelector('#cErr'); er.hidden = false; er.textContent = x.message; }
      };
    } catch (x) { toast(x.message); }
  };
}
