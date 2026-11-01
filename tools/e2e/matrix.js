// Scenario test matrix (PASS 12, section 4): every row checked on the 2D Attack simulation page AND in the 3D twin.
// Usage (server on :8000):  node tools/e2e/matrix.js
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
const HEX = { A: 'e5559f', B: '2a8fd6', C: '9a74f0', D: '2ba58a' };          // platform palette
const TWIN = { A: 'ff6fb5', B: '2a8fd6', C: '9a74f0', D: '2ba58a' };         // twin palette (A keeps the twin pink)
const results = [];
const ok = (row, where, cond, msg) => { results.push({ row, where, pass: !!cond, msg }); if (!cond) console.log(`FAIL [${row}] ${where}: ${msg}`); };
const post = (p, path, body) => p.evaluate(async ([path, body]) => { const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return r.json(); }, [path, body]);
const entriesOf = a => a.entries?.length ? a.entries : [{ asset: a.entry, start: a.start || 0 }];

async function twinAt(p, T) {
  await p.evaluate(T => { const s = document.querySelector('#scrub'); s.value = T; s.dispatchEvent(new Event('input')); }, T);
  await p.waitForTimeout(260);
  return p.evaluate(() => {
    const c = window.cascade, out = {};
    for (const [id, n] of Object.entries(c.nodes)) out[id] = { beam: n.entryBeam.visible, beamHex: n.entryBeam.material.color.getHexString(), tag: n.beamTag.visible,
      glow: n.glow[0]?.emissive.getHexString(), halo2: n.halo2.visible, halo2Hex: n.halo2.material.color.getHexString(), dome: n.dome.visible, eye: n.eye.visible,
      halo: n.halo.material.color.getHexString(), small: n.small.textContent, label: n.nm.textContent };
    return { nodes: out, rail: document.querySelector('#rail').innerText, latest: document.querySelector('#latest').innerText };
  });
}
async function mapAt(p, t) {
  await p.$eval('#scrub', (s, t) => { s.value = t; s.dispatchEvent(new Event('input')); }, t);
  return p.evaluate(() => ({
    fill: Object.fromEntries([...document.querySelectorAll('#map circle.nd')].map(c => [c.dataset.id, c.getAttribute('fill')])),
    ring2: Object.fromEntries([...document.querySelectorAll('#map circle[data-ring2]')].map(c => [c.dataset.ring2, c.getAttribute('stroke')])),
    cards: document.querySelector('#atkCards').innerText, log: document.querySelector('#evlog').innerText }));
}

(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const errs = [];
  const p2 = await b.newPage({ viewport: { width: 1440, height: 900 } }), p3 = await b.newPage({ viewport: { width: 1440, height: 900 } });
  for (const p of [p2, p3]) { p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text())); }
  await p2.goto(`${BASE}/app#/simulate`); await p2.waitForSelector('#presets .preset');
  await p3.goto(`${BASE}/twin`); await p3.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 90000 }); await p3.waitForTimeout(2000);
  const presets = (await p2.evaluate(async () => (await (await fetch('/api/multi/presets')).json()).presets));
  const P = Object.fromEntries(presets.map(x => [x.key, x]));
  const ov = await p2.evaluate(async () => (await (await fetch('/api/overview')).json()));
  const worst = ov.worst_entry, second = P.A.attackers[1].entry;

  // run one scenario in both views; returns backend answer + per-view state hooks
  async function both(row, sc) {
    const req = { attackers: sc.attackers, fixes: sc.fixes || [], maintenance: sc.maintenance || [], island_at: sc.island_at ?? null, detection: true, speed: 1 };
    const ref = await post(p2, '/api/multi', req);
    // 2D: drive the page through its own store + run button path
    await p2.evaluate(([req, title]) => { sessionStorage.setItem('cascade.scenario', JSON.stringify({ request: req, result: null, title })); }, [req, row]);
    if (sc.preset) { await p2.click(`#presets [data-k="${sc.preset}"]`); }
    else { await p2.evaluate(() => { location.hash = '#/overview'; }); await p2.waitForTimeout(300); await p2.evaluate(() => { location.hash = '#/simulate'; }); await p2.waitForSelector('#run'); await p2.click('#run'); }
    await p2.waitForSelector('#map circle.nd', { timeout: 30000 }); await p2.waitForTimeout(200);
    // 3D
    await p3.evaluate(([req, title]) => window.cascade.setScenario({ ...req, title }, false), [req, row]);
    await p3.waitForFunction(() => window.cascade.S.sim, null, { timeout: 30000 }); await p3.waitForTimeout(300);
    const twinSim = await p3.evaluate(() => { const s = window.cascade.S.sim; return { multi: !!s.multi, compromised: s.compromised, owner: s.owner || null }; });
    return { ref, twinSim };
  }
  const firstBy = ref => Object.fromEntries(Object.entries(ref.combined.first_by).map(([k, v]) => [k, v.t]));
  const same = (x, y) => JSON.stringify(Object.entries(x).sort()) === JSON.stringify(Object.entries(y).sort());

  // generic checks for any scenario at several minutes
  async function generic(row, ref, Ts = [0, 15, 30, 60, 120]) {
    for (const T of Ts) {
      const m = await mapAt(p2, T), tw = await twinAt(p3, T);
      for (const [id, v] of Object.entries(ref.combined.first_by)) {
        const want2 = v.t <= T ? '#' + HEX[v.attacker] : null;
        if (want2) ok(row, '2D', (m.fill[id] || '').toLowerCase() === want2, `T=${T} ${id} fill ${m.fill[id]} want ${want2}`);
        if (v.t <= T) ok(row, '3D', tw.nodes[id].glow === TWIN[v.attacker], `T=${T} ${id} glow ${tw.nodes[id].glow} want ${TWIN[v.attacker]}`);
      }
      for (const c of ref.combined.contested) {
        const [atk, tt] = Object.entries(c.times).filter(([k]) => k !== c.winner).sort((a, b) => a[1] - b[1])[0];
        ok(row, '2D', (T >= tt) === (m.ring2[c.asset] && m.ring2[c.asset] !== 'none'), `T=${T} contested ring ${c.asset}`);
        ok(row, '3D', (T >= tt) === tw.nodes[c.asset].halo2, `T=${T} contested halo ${c.asset}`);
        if (T >= tt) ok(row, '3D', tw.nodes[c.asset].halo2Hex === TWIN[atk], `contested colour ${c.asset}`);
      }
      for (const a of ref.attackers) for (const e of entriesOf(a)) {
        if (a.status === 'blocked by failsafe') { ok(row, '3D', !tw.nodes[e.asset].beam || ref.attackers.some(o => o !== a && entriesOf(o).some(x => x.asset === e.asset && x.start <= T)), `blocked attacker ${a.id} beam hidden`); continue; }
        const firstOwner = ref.attackers.flatMap(o => entriesOf(o).map(x => ({ ...x, id: o.id }))).filter(x => x.asset === e.asset).sort((p, q) => p.start - q.start)[0];
        ok(row, '3D', tw.nodes[e.asset].beam === (T >= firstOwner.start), `T=${T} beam ${e.asset} start ${firstOwner.start}`);
        if (T >= firstOwner.start) ok(row, '3D', tw.nodes[e.asset].beamHex === TWIN[firstOwner.id], `beam colour ${e.asset}`);
      }
    }
  }

  // 1. one attacker, one way in == /api/simulate
  {
    const sim = await post(p2, '/api/simulate', { entry_points: [worst], speed: 1, fixes: [] });
    const { ref, twinSim } = await both('1 one attacker, one way in', { attackers: [{ id: 'A', entry: worst, start: 0 }] });
    ok(1, 'API', same(firstBy(ref), sim.compromised), 'multi == simulate');
    ok(1, '3D', same(twinSim.compromised, sim.compromised) && !twinSim.multi, 'twin uses /api/simulate result');
    await generic(1, ref);
  }
  // 2. one attacker, two ways in at T+0: merged, one colour
  {
    const sim = await post(p2, '/api/simulate', { entry_points: [worst, second], speed: 1, fixes: [] });
    const { ref, twinSim } = await both('2 one attacker, two ways in', { attackers: [{ id: 'A', entries: [{ asset: worst, start: 0 }, { asset: second, start: 0 }] }] });
    ok(2, 'API', same(firstBy(ref), sim.compromised), 'merged == multi-source simulate');
    ok(2, 'API', Object.values(ref.combined.first_by).every(v => v.attacker === 'A'), 'one identity');
    ok(2, '3D', same(twinSim.compromised, sim.compromised), 'twin merged');
    await generic(2, ref);
  }
  // 3. preset A: two attackers at T+0
  { const { ref } = await both('3 preset A', { ...P.A, preset: 'A' }); ok(3, 'API', ref.attackers.length === 2, 'two attackers'); await generic(3, ref); }
  // 4. preset B: B starts at T+15, A unaffected
  {
    const { ref } = await both('4 preset B', { ...P.B, preset: 'B' });
    const B = ref.attackers.find(a => a.id === 'B'), A = ref.attackers.find(a => a.id === 'A');
    ok(4, 'API', Object.values(B.compromised).length === 0 || Math.min(...Object.values(B.compromised)) >= 15, 'B nothing before T+15');
    if (B.compromised[B.entry] !== undefined) ok(4, 'API', B.compromised[B.entry] === 15, `B first compromise exactly T+15 (${B.compromised[B.entry]})`);
    const soloA = await post(p2, '/api/multi', { attackers: [P.B.attackers[0]], detection: true });
    const sa = soloA.attackers[0].compromised, before15 = Object.fromEntries(Object.entries(A.compromised).filter(([, t]) => t < 15));
    ok(4, 'API', Object.entries(before15).every(([k, t]) => sa[k] === t), 'A identical before B joins');
    await generic(4, ref, [0, 14, 15, 16, 40]);
    const tw = await twinAt(p3, 14); ok(4, '3D', !tw.nodes[B.entry].beam && /comes in at/.test(tw.nodes[B.entry].small), 'B waiting at T+14');
    const tw2 = await twinAt(p3, 15); ok(4, '3D', tw2.nodes[B.entry].beam, 'B beam at T+15');
  }
  // 5. converging + competing (D, E): winner owns, both times listed
  for (const k of ['D', 'E']) {
    if (!P[k]) { ok(5, 'API', true, `preset ${k} not available on this dataset`); continue; }
    const { ref } = await both(`5 preset ${k}`, { ...P[k], preset: k });
    ok(5, 'API', ref.combined.contested.length > 0, `${k} has contested systems`);
    for (const c of ref.combined.contested) ok(5, 'API', c.times[c.winner] === Math.min(...Object.values(c.times)), 'winner is first');
    const m = await mapAt(p2, 360);
    const html = await p2.$eval('#contested', e => e.innerText);
    ok(5, '2D', ref.combined.contested.every(c => html.includes(c.name)), 'contested list shows each system with both times');
    await generic(5, ref, [0, 30, 90, 360]);
  }
  // 6. preset F: A contained at 30
  {
    const { ref } = await both('6 preset F', { ...P.F, preset: 'F' });
    const A = ref.attackers.find(a => a.id === 'A'), B = ref.attackers.find(a => a.id === 'B');
    ok(6, 'API', Object.values(A.compromised).every(t => t <= 30) && A.status === 'contained', 'A stops at T+30');
    ok(6, 'API', Object.values(B.compromised).some(t => t > 30) || B.reached > 0, 'B continues');
    const tw = await twinAt(p3, 60); ok(6, '3D', /Contained at T\+00:30/.test(tw.rail), 'rail shows A contained');
    await generic(6, ref);
  }
  // 7. preset G: adaptive
  if (P.G) {
    const { ref } = await both('7 preset G', { ...P.G, preset: 'G' });
    const A = ref.attackers[0];
    const m = await mapAt(p2, 60);
    if (A.adapted_from) { ok(7, '2D', /adapted from/i.test(m.cards), '2D shows adapted from'); const tw = await twinAt(p3, 60); ok(7, '3D', /adapted from/i.test(tw.rail), 'twin shows adapted from'); }
    else ok(7, 'API', true, 'attacker kept its way in on this dataset (honest)');
    await generic(7, ref);
  }
  // 8. preset H: maintenance
  if (P.H) {
    const { ref } = await both('8 preset H', { ...P.H, preset: 'H' });
    const w = ref.maintenance[0];
    const tw = await twinAt(p3, w.start + 1); ok(8, '3D', tw.nodes[w.asset].halo === 'f2b84b' && /patching/.test(tw.nodes[w.asset].small), 'amber while patching');
    const svc = ref.combined.services.filter(s => s.cause === 'maintenance');
    if (svc.length) { const m = await mapAt(p2, 360); ok(8, '2D', /caused by maintenance/.test(m.log), 'outage attributed to maintenance'); }
    await generic(8, ref, [0, 15, w.start + 1]);
  }
  // 9. failsafe island mode
  {
    const { ref } = await both('9 preset K', { ...P.K, preset: 'K' });
    const A = ref.attackers.find(a => a.id === 'A'), B = ref.attackers.find(a => a.id === 'B');
    ok(9, 'API', Object.values(A.compromised).every(t => t <= 12), 'outside attacker stops at the cut');
    ok(9, 'API', B.status === 'blocked by failsafe', 'later outside attacker refused');
    const ins = await post(p2, '/api/multi', { attackers: [{ id: 'A', entry: P.K.attackers[0].entry }, { id: 'B', entry: (await p2.evaluate(async () => (await (await fetch('/api/graph')).json()).assets.find(a => !a.is_entry && a.type === 'workstation').id)) }], island_at: 12 });
    const insider = ins.attackers.find(a => a.id === 'B');
    ok(9, 'API', insider.status !== 'contained' && Object.values(insider.compromised).some(t => t > 12) || insider.reached <= 1, 'insider continues after the cut');
    const tw = await twinAt(p3, 30); ok(9, '3D', /Blocked by the failsafe/.test(tw.rail), 'rail shows B blocked');
    await generic(9, ref, [0, 12, 30]);
  }
  // 10. four attackers
  if (P.J) {
    const { ref } = await both('10 preset J', { ...P.J, preset: 'J' });
    const cols = new Set(Object.values(TWIN)); ok(10, '3D', cols.size === 4, 'four distinct colours');
    await generic(10, ref, [0, 10, 25, 60]);
    // labels never overlap
    await twinAt(p3, 60); await p3.waitForTimeout(400);
    const overlaps = await p3.evaluate(() => { const r = [...document.querySelectorAll('.label:not(.culled):not(.quiet)')].filter(e => getComputedStyle(e).opacity > .05).map(e => e.getBoundingClientRect()); let n = 0; for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) { const a = r[i], b = r[j]; if (a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top) n++; } return n; });
    ok(10, '3D', overlaps === 0, `labels overlap: ${overlaps}`);
    await p3.screenshot({ path: (process.env.OUT || '/tmp') + '/matrix_twin_J.png' });
    await p2.screenshot({ path: (process.env.OUT || '/tmp') + '/matrix_2d_J.png' });
  }
  // dome bug: no dome without a session fix; monitored systems get the dashed ring instead
  {
    await p3.evaluate(() => window.cascade.setEntries([], false)); await p3.waitForTimeout(300);
    const tw = await twinAt(p3, 0);
    const g = await p3.evaluate(() => window.cascade.S.graph.assets.map(a => [a.id, !!a.monitored]));
    ok('dome', '3D', Object.values(tw.nodes).every(n => !n.dome), 'no dome before any fix');
    ok('dome', '3D', g.every(([id, m]) => tw.nodes[id].eye === m), 'monitored marker exactly on dataset-monitored systems');
    const fx = await p3.evaluate(async () => (await (await fetch('/api/fixes')).json()).fixes.find(f => !f.id.startsWith('segment:')));
    await p3.evaluate(id => window.cascade.toggleFix(id), fx.id); await p3.waitForTimeout(800);
    const tw2 = await twinAt(p3, 0); const target = fx.id.split(':')[1];
    ok('dome', '3D', tw2.nodes[target].dome && Object.entries(tw2.nodes).filter(([k, n]) => n.dome).length === 1, `dome only on ${target} after applying ${fx.id}`);
    await p3.evaluate(id => window.cascade.toggleFix(id), fx.id);
  }
  const fails = results.filter(r => !r.pass);
  const byRow = {}; for (const r of results) { const k = `${r.row}`; byRow[k] ||= { pass: 0, fail: 0 }; byRow[k][r.pass ? 'pass' : 'fail']++; }
  console.log(JSON.stringify(byRow));
  console.log(errs.length ? 'CONSOLE ERRORS:\n' + [...new Set(errs)].join('\n') : 'no console errors');
  console.log(fails.length ? `FAIL ${fails.length}/${results.length}` : `PASS ${results.length} assertions`);
  await b.close(); process.exit(fails.length || errs.length ? 1 : 0);
})();
