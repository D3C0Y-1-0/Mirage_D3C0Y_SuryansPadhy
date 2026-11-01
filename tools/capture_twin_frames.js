// Capture the 5 frames used by the landing page's "Scroll into the city" section, straight from the 3D twin,
// plus the on-screen position of every hotspot (projected from the twin's own 3D positions, not hand-placed).
// Usage (server running on :8000 with the dataset you want):  node tools/capture_twin_frames.js
// Writes frontend/static/img/twin-step-{0..4}.jpg and frontend/static/img/twin-frames.json
const { chromium } = require('playwright');
const fs = require('fs'), path = require('path');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
const OUT = path.join(__dirname, '..', 'frontend', 'static', 'img');
const W = 1600, H = 900;

(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const p = await b.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 1, reducedMotion: 'reduce' });
  const errs = []; p.on('pageerror', e => errs.push(e.message));
  const L = await (await fetch(`${BASE}/api/public/landing`)).json();
  const protect = await (await fetch(`${BASE}/api/public/attack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entry: L.worst_entry, protect: true }) })).json();
  await p.goto(`${BASE}/twin`);
  await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 120000 });
  await p.waitForTimeout(3500);
  // quiet chrome that would date the frame (banner, menus); keep clock, rail and panel: the callouts point at them
  await p.addStyleTag({ content: '#banner, #ctx, .ticker .rate { visibility: hidden !important; }' });

  const setT = T => p.evaluate(T => { const s = document.querySelector('#scrub'); window.cascade.S.T = T; s.value = T; s.dispatchEvent(new Event('input')); }, T);
  const settle = (ms = 1400) => p.waitForTimeout(ms);
  // screen position of a building (its roof) / of a DOM element, normalised to 0..1 of the frame
  const at = id => p.evaluate(id => {
    const c = window.cascade, n = c.nodes[id], v = n.group.position.clone(); v.y = n.top * .75;
    v.project(c.camera); const r = document.querySelector('#stage canvas').getBoundingClientRect();
    return [(r.left + (v.x + 1) / 2 * r.width) / innerWidth, (r.top + (1 - v.y) / 2 * r.height) / innerHeight];
  }, id);
  // DOM hotspots point at the element's right edge, so a callout placed beside it never covers it
  const elAt = sel => p.evaluate(sel => { const e = document.querySelector(sel); if (!e) return null; const r = e.getBoundingClientRect(); const w = [...e.querySelectorAll('*')].reduce((m, c) => Math.max(m, c.getBoundingClientRect().right), r.left); return [(Math.min(r.right, w) + 6) / innerWidth, (r.top + r.height / 2) / innerHeight]; }, sel);
  const shot = async i => { const f = `twin-step-${i}.jpg`; await p.screenshot({ path: path.join(OUT, f), type: 'jpeg', quality: 78 }); return f; };

  const frames = [];
  const worst = L.worst_entry;
  // 0: the city before the attack
  await p.evaluate(() => window.cascade.setEntries([], false)); await setT(0); await settle(1800);
  const centre = await p.evaluate(() => { const c = window.cascade, v = c.sceneFit.center.clone(); v.project(c.camera); const r = document.querySelector('#stage canvas').getBoundingClientRect(); return [(r.left + (v.x + 1) / 2 * r.width) / innerWidth, (r.top + (1 - v.y) / 2 * r.height) / innerHeight]; });
  frames.push({ step: 0, T: 0, src: await shot(0), hot: centre, key: 'city' });
  // 1: the entry beam, T+00:00
  await p.evaluate(w => window.cascade.setEntries([w], false), worst);
  await p.waitForFunction(() => window.cascade.S.sim, null, { timeout: 30000 });
  await setT(0); await settle(1800);
  frames.push({ step: 1, T: 0, src: await shot(1), hot: await at(worst), key: worst });
  // 2: spread around T+00:20 (hotspot = the last building reached by then)
  const sim = await p.evaluate(() => ({ c: window.cascade.S.sim.compromised, f: window.cascade.S.sim.failures }));
  const T2 = 20, reached = Object.entries(sim.c).filter(([, t]) => t <= T2).sort((a, b) => b[1] - a[1]);
  const spreadId = (reached[0] || [worst])[0];
  await setT(T2); await settle();
  frames.push({ step: 2, T: T2, src: await shot(2), hot: await at(spreadId), key: spreadId });
  // 3: first service lost: the clock turns pink
  const T3 = Math.min(...Object.values(sim.f), 360);
  await setT(T3 + .2); await settle();
  frames.push({ step: 3, T: T3, src: await shot(3), hot: await elAt('#clock'), key: 'clock', rail: await elAt('#rail .service.lost') });
  // 4: same moment with the optimiser's bundle applied
  await p.evaluate(([w, f]) => window.cascade.setScenario({ attackers: [{ id: 'A', entry: w }], fixes: f }, false), [worst, protect.fixes]);
  await p.waitForFunction(() => window.cascade.S.sim, null, { timeout: 30000 });
  await setT(T3 + .2); await settle(1800);
  const domed = protect.fixes.map(f => f.split(':')).filter(([k]) => k !== 'segment').map(([, id]) => id);
  const protId = domed[0] || worst;
  frames.push({ step: 4, T: T3, src: await shot(4), hot: await at(protId), key: protId, entry: await at(worst), fixes: protect.fix_labels });
  // the X-ray zooms into the real way in (its position in frame 4)
  const meta = { generated: new Date().toISOString(), dataset_worst_entry: worst, width: W, height: H, first_service_lost_min: T3, frames, xray: await at(worst) };
  fs.writeFileSync(path.join(OUT, 'twin-frames.json'), JSON.stringify(meta, null, 1));
  console.log(JSON.stringify(meta, null, 1));
  if (errs.length) console.error('page errors:', errs);
  await b.close();
})();
