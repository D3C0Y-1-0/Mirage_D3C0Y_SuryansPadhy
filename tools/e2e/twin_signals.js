// Junction signals: cars obey the cycle and queue, the lights follow the junction-signal controller's simulated state,
// the message sign changes only when its controller is reached, and nothing errors.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000', OUT = process.env.OUT || '/tmp';
(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } }); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
  await p.goto(BASE + '/twin', { waitUntil: 'domcontentloaded', timeout: 120000 }); await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 120000 }); await p.waitForTimeout(3000);
  const info = await p.evaluate(() => { const e = window.cascade.env; return { j: e.junctions.length, heads: e.sigHeads.length, cars: e.carPaths.length, sigAsset: Object.keys(window.cascade.nodes).find(k => window.cascade.nodes[k].sig), vms: Object.keys(window.cascade.nodes).find(k => window.cascade.nodes[k].vms) }; });
  console.log('setup', JSON.stringify(info));
  if (info.j < 20 || info.heads !== info.j * 4) bad('junction setup ' + JSON.stringify(info));
  // nobody runs a red light: sample twice a second for 8 s; a car on a red approach must never be between its stop line and the junction centre unless it was already there
  const viol = await p.evaluate(async () => {
    const { env, sigPhase } = window.cascade; let v = 0, stopped = 0, samples = 0;
    const prev = new Map(env.carPaths.map(c => [c, c.u]));
    for (let k = 0; k < 16; k++) {
      await new Promise(r => setTimeout(r, 500));
      const t = (performance.now() - env.t0) / 1000;
      for (const c of env.carPaths) {
        const u0 = prev.get(c), u1 = c.u; prev.set(c, u1);
        if (Math.abs(u1 - u0) > .5) continue;              // wrapped around
        for (const x of c.cross) {
          const stop = x.u - c.dir * c.stopU, before = (stop - u0) * c.dir, after = (stop - u1) * c.dir;
          if (before > 1e-3 && after < -1e-3 && sigPhase(t, x.off, c.axis) === 0 && sigPhase(t - .5, x.off, c.axis) === 0) v++;   // crossed the line while red throughout
          if (Math.abs(after) < 1e-3) stopped++;
        }
        samples++;
      }
    }
    return { v, stopped, samples };
  });
  console.log('red-light check', JSON.stringify(viol));
  if (viol.v) bad('cars crossed a red stop line: ' + viol.v);
  if (!viol.stopped) bad('no car ever waited at a stop line');
  const mode0 = await p.evaluate(() => window.cascade.env.sigMode);
  if (mode0 !== 'normal') bad('signals not normal before any attack: ' + mode0);
  // close-up of a junction (normal)
  await p.evaluate(() => { const c = window.cascade, j = c.env.junctions.find(j => Math.abs(j.X) < 80 && Math.abs(j.Z) < 80) || c.env.junctions[0]; c.camera.position.set(j.X + 14, 9, j.Z + 14); window.__j = j; });
  await p.evaluate(() => { const c = window.cascade; /* orbit controls target */ });
  await p.waitForTimeout(300);
  if (info.sigAsset) {
    await p.evaluate(id => { const g = window.cascade.S.graph, l = g.links.find(l => l.dst === id && l.src !== id) || g.links.find(l => l.src === id); window.cascade.setEntries([l.dst === id ? l.src : l.dst], false); }, info.sigAsset);
    await p.waitForFunction(() => window.cascade.S.sim, null, { timeout: 60000 });
    const t2 = await p.evaluate(id => window.cascade.S.sim.compromised[id], info.sigAsset);
    await p.evaluate(t => { const s = document.querySelector('#scrub'); s.value = Math.max(0, t - 1); s.dispatchEvent(new Event('input', { bubbles: true })); }, t2); await p.waitForTimeout(600);
    const before = await p.evaluate(() => window.cascade.env.sigMode);
    await p.evaluate(t => { const s = document.querySelector('#scrub'); s.value = t + 1; s.dispatchEvent(new Event('input', { bubbles: true })); }, t2); await p.waitForTimeout(600);
    const after = await p.evaluate(() => window.cascade.env.sigMode);
    console.log(`signals around ${info.sigAsset} at T=${t2}: before=${before} after=${after}`);
    if (before !== 'normal' || after !== 'attack') bad('signal mode does not follow the controller');
    if (info.vms) {
      const vt = await p.evaluate(id => window.cascade.S.sim.compromised[id], info.vms);
      const vmsBad = await p.evaluate(id => { const n = window.cascade.nodes[id]; return n.vms.face.map === n.vms.bad; }, info.vms);
      const shouldBe = vt !== undefined && vt <= t2 + 1;
      if (vmsBad !== shouldBe) bad(`message sign state ${vmsBad} but reached-at ${vt}`); else console.log('message sign ok:', vmsBad ? 'reached' : 'normal');
    }
    const legend = await p.evaluate(() => document.querySelector('#rail')?.textContent || '');
    if (!/scenery, not data/.test(legend)) bad('legend does not explain the signals');
    await p.screenshot({ path: OUT + '/twin_signals_attack.png' });
    await p.evaluate(() => window.cascade.setEntries([], false)); await p.waitForTimeout(600);
    if (await p.evaluate(() => window.cascade.env.sigMode) !== 'normal') bad('signals did not return to normal after clearing');
  }
  if (errs.length) bad('console errors: ' + errs.slice(0, 3).join(' | '));
  console.log(fails ? `twin_signals: ${fails} FAIL` : 'twin_signals: all ok');
  await b.close(); process.exit(fails ? 1 : 0);
})();
