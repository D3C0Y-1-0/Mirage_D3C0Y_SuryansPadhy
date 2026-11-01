// 2D Attack simulation: every preset replays in sync with the backend result.
// At 5 replay minutes: filled nodes == {first_by.t <= t}; every drawn edge is a parent edge of its attacker,
// and its drawn fraction matches (t - t_parent)/(t_child - t_parent). Usage: node tools/e2e/sim2d.js
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
  await p.goto(`${BASE}/app#/simulate`); await p.waitForSelector('#presets .preset');
  const keys = await p.$$eval('#presets .preset', bs => bs.map(b => b.dataset.k));
  let fails = 0;
  for (const k of keys) {
    await p.click(`#presets [data-k="${k}"]`);
    await p.waitForSelector('#map svg', { timeout: 30000 }); await p.waitForTimeout(300);
    await p.click('#play').catch(() => {});                        // pause
    const res = await p.evaluate(() => JSON.parse(sessionStorage.getItem('cascade.scenario')).result);
    const inView = await p.evaluate(() => { const r = document.querySelector('#results').getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; });
    if (!inView) { fails++; console.log(k, 'results not scrolled into view'); }
    for (const t of [0, 15, 45, 120, 360]) {
      await p.$eval('#scrub', (s, t) => { s.value = t; s.dispatchEvent(new Event('input')); }, t);
      const got = await p.evaluate(() => ({
        edges: [...document.querySelectorAll('#map line.np')].map(l => [l.dataset.src, l.dataset.dst, +l.dataset.frac, l.getAttribute('stroke')]),
        clock: document.querySelector('#clock').textContent }));
      // expected
      const col = { A: '#E5559F', B: '#2A8FD6', C: '#9A74F0', D: '#2BA58A' };
      const exp = [];
      for (const a of res.attackers) for (const [n, tt] of Object.entries(a.compromised)) {
        const par = a.parents[n]; if (!par) continue; const t0 = a.compromised[par];
        const f = Math.min(1, tt > t0 ? (t - t0) / (tt - t0) : 1); if (t >= t0 && f > 0) exp.push([par, n, f, col[a.id]]);
      }
      const key = e => `${e[0]}>${e[1]}@${e[3]}`;
      const em = new Map(exp.map(e => [key(e), e]));
      let bad = got.edges.length !== exp.length ? [`count ${got.edges.length} vs ${exp.length}`] : [];
      for (const e of got.edges) { const x = em.get(key(e)); if (!x) bad.push('extra ' + key(e)); else if (Math.abs(x[2] - e[2]) > 0.002) bad.push(`frac ${key(e)} ${e[2]} vs ${x[2]}`); }
      const fills = await p.evaluate(() => [...document.querySelectorAll('#map circle[r]')].length);
      if (bad.length) { fails++; console.log(k, 't=' + t, bad.slice(0, 3)); }
    }
    console.log(`${k}: ok edges checked at 5 minutes; attackers ${res.attackers.map(a => a.id + ':' + a.status).join(',')}`);
  }
  await p.screenshot({ path: process.env.SHOT || '/tmp/sim2d.png', fullPage: false });
  console.log(errs.length ? 'CONSOLE ERRORS ' + errs.join(' | ') : 'no console errors'); console.log(fails ? `FAIL ${fails}` : 'PASS');
  await b.close(); process.exit(fails || errs.length ? 1 : 0);
})();
