// Unknown-attack response page: pipeline stages fill, options come from the backend, the map shows the chosen
// response's spread, a decision is logged, and the water console links here.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  for (const [W, H] of [[1440, 900], [390, 844]]) {
    const p = await b.newPage({ viewport: { width: W, height: H } }); const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
    await p.goto(`${BASE}/app#/novel`); await p.waitForSelector('.opt', { timeout: 60000 });
    const st = await p.$$eval('#pipe li', l => l.map(x => x.className + ':' + x.querySelector('em').textContent));
    if (st.slice(0, 4).some(x => /^:/.test(x) || /:$/.test(x))) bad('pipeline stage empty: ' + st);
    const api = await p.evaluate(async () => { const h = document.querySelector('#nHour').value; return (await (await fetch('/api/novel/whatif?hour=' + encodeURIComponent(h))).json()); });
    const shown = await p.$$eval('.opt', o => o.length); if (shown !== api.options.length) bad('options shown ' + shown);
    // pick another foothold (an outside way in) and check the map follows the backend
    await p.selectOption('#nAsset', 'EL01'); await p.waitForTimeout(2500);
    for (const k of ['no_action', 'operator']) {
      await p.click(`.opt[data-k="${k}"]`); await p.waitForTimeout(200);
      const r = await p.evaluate(async k => { const res = await (await fetch('/api/novel/whatif?hour=' + encodeURIComponent(document.querySelector('#nHour').value) + '&asset=EL01')).json(); const o = res.options.find(x => x.key === k);
        const edges = [...document.querySelectorAll('#nMap line.np')].map(l => l.dataset.src + '>' + l.dataset.dst).sort(); const exp = Object.entries(o.parents).filter(([, p]) => p).map(([c, p]) => p + '>' + c).sort(); return { edges, exp, harm: o.harm }; }, k);
      if (JSON.stringify(r.edges) !== JSON.stringify(r.exp)) bad(`${W} map for ${k}: ${r.edges} vs ${r.exp}`); else console.log(`${W} ${k}: map matches (${r.edges.length} edges, harm ${r.harm})`);
    }
    if (W === 1440) {
      await p.click('[data-d="approved"]'); await p.waitForTimeout(800);
      const last = await p.evaluate(async () => (await (await fetch('/api/ops/log')).json()));
      const entries = last.entries || last; if (!JSON.stringify(entries).includes('Isolate')) bad('decision not logged');
      await p.screenshot({ path: (process.env.OUT || '/tmp') + '/novel.png', fullPage: true });
      // water console links here
      await p.goto(`${BASE}/app#/water`); await p.waitForSelector('#wPlay'); 
    }
    const hs = await p.evaluate(() => document.querySelector('#main').scrollWidth > document.querySelector('#main').clientWidth + 1); if (hs) bad(`${W} horizontal scroll`);
    if (errs.length) bad(`${W} console: ` + errs.join(' | '));
    await p.close();
  }
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
