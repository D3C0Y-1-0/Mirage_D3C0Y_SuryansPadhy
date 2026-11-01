// Section 5: Attack paths (route highlight exact, replay, choke point compare), Active incidents (state + actions refresh),
// Attack timeline (ticks on the axis, marker shared, filters, truncation), scenario state across pages and reloads.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  const errs = [];
  for (const [W, H] of [[1440, 900], [1024, 768], [390, 844]]) {
    const p = await b.newPage({ viewport: { width: W, height: H } });
    p.on('pageerror', e => errs.push(`${W}: ${e.message}`)); p.on('console', m => m.type() === 'error' && errs.push(`${W}: ${m.text()}`));
    // ---- attack paths
    await p.goto(`${BASE}/app#/paths`); await p.waitForSelector('#pMap svg', { timeout: 30000 }); await p.waitForTimeout(300);
    const pi = await p.$$eval('#pPaths .pitem', b => b.length);
    for (let i = 0; i < Math.min(pi, 3); i++) {
      await p.click(`#pPaths .pitem[data-i="${i}"]`); await p.waitForTimeout(100);
      const r = await p.evaluate(i => ({ edges: [...document.querySelectorAll('#pMap line.np')].map(l => [l.dataset.src, l.dataset.dst]),
        steps: [...document.querySelectorAll('#pMap text')].filter(t => /^\d+$/.test(t.textContent)).map(t => +t.textContent) }), i);
      const route = await p.evaluate(async i => { const ap = await (await fetch('/api/insights/paths')).json(); const j = ap.crown_jewels.filter(j => j.paths.length)[0]; return j.paths[i].nodes; }, i);
      const exp = route.slice(1).map((n, k) => [route[k], n]);
      if (JSON.stringify(r.edges) !== JSON.stringify(exp)) bad(`${W} paths route ${i}: drawn ${JSON.stringify(r.edges)} != ${JSON.stringify(exp)}`);
      if (JSON.stringify(r.steps) !== JSON.stringify(exp.map((_, k) => k + 1))) bad(`${W} paths route ${i}: hop numbers ${r.steps}`);
    }
    // labels on the map do not overlap
    const ov = await p.evaluate(() => { const r = [...document.querySelectorAll('#pMap text.nlabel')].filter(t => t.getAttribute('visibility') !== 'hidden').map(t => t.getBoundingClientRect()); let n = 0; for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) { const a = r[i], c = r[j]; if (a.left < c.right - 1 && a.right > c.left + 1 && a.top < c.bottom - 1 && a.bottom > c.top + 1) n++; } return n; });
    if (ov) bad(`${W} paths: ${ov} overlapping labels`);
    // replay animates (in-flight fractions < 1 part-way)
    await p.click('#pPlay'); await p.waitForTimeout(700);
    const mid = await p.$$eval('#pMap line.np', ls => ls.map(l => +l.dataset.frac));
    if (!(mid.length === 0 || mid.some(f => f < 1))) bad(`${W} replay not animating ${mid}`);
    if (W === 1440) {
      // choke point: opens the simulation with that fix, runs before and after
      const href = await p.$eval('#cTable a.btn', a => a.getAttribute('href'));
      await p.click('#cTable a.btn');
      await p.waitForFunction(() => document.querySelectorAll('#cmp tbody tr').length >= 2 && /After/.test(document.querySelector('#cmp').innerText), null, { timeout: 60000 });
      const sc = await p.evaluate(() => JSON.parse(sessionStorage.getItem('cascade.scenario')));
      const fx = decodeURIComponent(href.match(/fixes=([^&]+)/)[1]);
      if (!sc.request.fixes.includes(fx)) bad('choke point fix not applied: ' + fx);
      console.log('choke point:', href, '-> harm', sc.result.combined.harm);
    }
    // ---- staggered scenario for incidents + timeline
    await p.goto(`${BASE}/app#/simulate`); await p.waitForSelector('#presets .preset');
    await p.click('#presets [data-k="B"]'); await p.waitForSelector('#map circle.nd', { timeout: 30000 });
    await p.$eval('#scrub', s => { s.value = 10; s.dispatchEvent(new Event('input')); });
    await p.evaluate(() => { location.hash = '#/incidents'; }); await p.waitForSelector('[data-a="B"]');
    const stB = await p.$eval('[data-a="B"] [data-state]', e => e.textContent);
    if (!/Not started yet/.test(stB)) bad(`${W} incident B at T+10 should be waiting: ${stB}`);
    const disabled = await p.$eval('[data-a="B"] [data-act="contain"]', b => b.disabled);
    if (!disabled) bad('contain enabled before start');
    // contain A now -> re-run, refresh, no stale data
    await p.evaluate(() => { const s = JSON.parse(sessionStorage.getItem('cascade.scenario')); window.__h0 = s.result.combined.harm; });
    await p.click('[data-a="A"] [data-act="contain"]');
    await p.waitForFunction(() => /Contained at/.test(document.querySelector('[data-a="A"] [data-state]')?.textContent || ''), null, { timeout: 30000 });
    const after = await p.evaluate(() => { const s = JSON.parse(sessionStorage.getItem('cascade.scenario')); return { ca: s.result.attackers.find(a => a.id === 'A').contain_at, title: s.title, applied: s.applied?.length }; });
    if (after.ca !== 10) bad(`contain_at ${after.ca}`);
    // block B -> stays listed as blocked
    await p.click('[data-a="B"] [data-act="block"]');
    await p.waitForFunction(() => /Blocked before/.test(document.querySelector('[data-a="B"] [data-state]')?.textContent || ''), null, { timeout: 30000 });
    // ---- timeline: same scenario, marker at the shared time, ticks on the axis
    await p.evaluate(() => { location.hash = '#/timeline'; }); await p.waitForSelector('#tnow');
    const tl = await p.evaluate(() => {
      const axis = [...document.querySelectorAll('.axis span')].map(s => s.getBoundingClientRect());
      const tr = document.querySelector('.lane .tr').getBoundingClientRect(), now = document.querySelector('#tnow').getBoundingClientRect();
      const x0 = axis[0].left, x6 = axis[axis.length - 1].right;
      const trunc = [...document.querySelectorAll('.lane .nm .tx')].every(t => t.scrollWidth <= t.clientWidth + 1 || getComputedStyle(t).textOverflow === 'ellipsis');
      const titled = [...document.querySelectorAll('.lane .nm')].every(n => n.title);
      return { x0, x6, tr0: tr.left, tr1: tr.right, now: now.left, exp: tr.left + tr.width * (10 / 360), trunc, titled, hs: document.documentElement.scrollWidth > innerWidth || document.querySelector('#main').scrollWidth > document.querySelector('#main').clientWidth };
    });
    if (Math.abs(tl.x0 - tl.tr0) > 2 || Math.abs(tl.x6 - tl.tr1) > 2) bad(`${W} axis ${tl.x0}-${tl.x6} vs track ${tl.tr0}-${tl.tr1}`);
    if (Math.abs(tl.now - tl.exp) > 2) bad(`${W} replay marker at ${tl.now}, expected ${tl.exp}`);
    if (!tl.trunc || !tl.titled) bad(`${W} lane names not truncated with tooltip`);
    if (tl.hs) bad(`${W} timeline horizontal scroll`);
    // filters
    for (const v of ['A', 'B', 'svc', 'def', '']) {
      await p.selectOption('#who', v); const n = await p.$$eval('#evt tbody tr', r => r.length);
      const exp = await p.evaluate(v => { const s = JSON.parse(sessionStorage.getItem('cascade.scenario')); const DEF = ['detected', 'isolated', 'maintenance', 'maintenance_end', 'attacker_contained', 'failsafe', 'attacker_joins']; return s.result.events.filter(e => !v || (v === 'svc' ? e.kind.startsWith('service') : v === 'def' ? DEF.includes(e.kind) : e.attacker === v)).length; }, v);
      if (n !== Math.max(exp, exp ? exp : 1) && !(exp === 0 && n === 1)) bad(`${W} filter ${v}: ${n} rows vs ${exp}`);
    }
    // ---- state persists across pages and a reload
    const before = await p.evaluate(() => sessionStorage.getItem('cascade.scenario'));
    await p.reload(); await p.waitForSelector('#tnow');
    await p.evaluate(() => { location.hash = '#/simulate'; }); await p.waitForSelector('#map circle.nd', { timeout: 30000 });
    const after2 = await p.evaluate(() => sessionStorage.getItem('cascade.scenario'));
    if (before !== after2) bad(`${W} scenario changed across reload/pages`);
    const shownTitle = await p.evaluate(() => document.querySelector('.top')?.innerText || '');
    if (W >= 768 && !/modified/.test(shownTitle)) bad(`${W} top bar does not show the modified scenario`);
    if (W === 1440) await p.screenshot({ path: (process.env.OUT || '/tmp') + '/timeline.png', fullPage: false });
    console.log(`${W}px section 5 checks done`);
    await p.close();
  }
  if (errs.length) bad('console: ' + [...new Set(errs)].join(' | '));
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
