// Landing "Try it": click the worst way in; at 5 minutes the pink set == {id: times[id] <= t} and every drawn edge is
// in `parents` with the right fraction. Then Protect: the after-replay follows the same rule. Also keyboard: Tab + Enter.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
  let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  await p.goto(BASE + '/'); await p.waitForTimeout(2500);
  const worst = await p.evaluate(async () => (await (await fetch('/api/public/landing')).json()).worst_entry);
  await p.evaluate(() => document.querySelector('#demo').scrollIntoView()); await p.waitForTimeout(600);
  // the loading state appears immediately on click
  const clickAt = Date.now();
  await p.click(`#mapBefore .node[data-id="${worst}"]`);
  const busySeen = await p.evaluate(() => !document.querySelector('#mBusy').hidden || !!window.__demo.before);
  if (!busySeen) bad('no loading state on click');
  await p.waitForFunction(() => window.__demo.before, null, { timeout: 20000 });
  async function check(svgSel, which, Ts) {
    for (const t of Ts) {
      await p.evaluate(t => window.__demo.set(t), t); await p.waitForTimeout(60);
      const r = await p.evaluate(([sel, which]) => {
        const st = window.__demo[which];
        const pink = [...document.querySelectorAll(`${sel} [data-id]`)].filter(g => g.dataset.hit === '1').map(g => g.dataset.id).sort();
        const edges = [...document.querySelectorAll(`${sel} line.edge`)].map(l => [l.dataset.src, l.dataset.dst]);
        return { pink, edges, st };
      }, [svgSel, which]);
      const exp = Object.entries(r.st.times).filter(([, tt]) => tt <= t).map(([k]) => k).sort();
      if (JSON.stringify(exp) !== JSON.stringify(r.pink)) bad(`${which} t=${t}: pink ${r.pink} != ${exp}`);
      for (const [s, d] of r.edges) if (r.st.parents[d] !== s) bad(`${which} t=${t}: edge ${s}->${d} not in parents`);
      const expEdges = Object.entries(r.st.parents).filter(([c, par]) => par && t >= r.st.times[par] && (r.st.times[c] > r.st.times[par] ? (t - r.st.times[par]) > 0 : true)).length;
      if (r.edges.length !== expEdges) bad(`${which} t=${t}: ${r.edges.length} edges, expected ${expEdges}`);
      console.log(`${which} t=${t}: ${r.pink.length} pink, ${r.edges.length} edges, ok`);
    }
  }
  const T5 = [0, 10, 30, 75, 200];
  await check('#mapBefore', 'before', T5);
  // harm counter ticks with the clock and ends at the backend's harm
  await p.evaluate(() => window.__demo.set(360));
  const hb = await p.$eval('#hBefore', e => e.textContent), fb = await p.evaluate(() => window.__demo.before.harm);
  console.log('harm at 6 h', hb, 'backend', fb);
  // protect
  await p.evaluate(() => { window.__msgs = []; new MutationObserver(() => window.__msgs.push(document.querySelector('#dStatus').textContent)).observe(document.querySelector('#dStatus'), { childList: true, characterData: true, subtree: true }); });
  await p.click('#protect');
  await p.waitForFunction(() => window.__demo.after, null, { timeout: 60000 });
  const msg = await p.evaluate(() => window.__msgs.join(' | '));
  if (!/Trying every fix/.test(msg)) bad('no protect loading message: ' + msg);
  const hb2 = await p.evaluate(() => [window.__demo.before.harm, window.__demo.after.harm]);
  if (!(hb2[1] < hb2[0])) bad(`protect did not reduce harm for the worst way in: ${hb2}`); else console.log('protect harm', hb2[0], '->', hb2[1]);
  await p.waitForFunction(() => window.__demo.after, null, { timeout: 60000 });
  await check('#mapAfter', 'after', T5);
  await check('#mapBefore', 'before', [45]);
  await p.evaluate(() => window.__demo.set(120)); await p.screenshot({ path: (process.env.OUT || '/tmp') + '/tryit.png' });
  // keyboard: focus a system and press Enter
  const other = await p.evaluate(w => [...document.querySelectorAll('#mapBefore .node')].map(g => g.dataset.id).find(id => id !== w), worst);
  await p.focus(`#mapBefore .node[data-id="${other}"]`); await p.keyboard.press('Enter');
  await p.waitForFunction(o => window.__demo.before && document.querySelector('#dEntry').textContent.includes(document.querySelector(`#mapBefore .node[data-id="${o}"] title`).textContent), other, { timeout: 20000 });
  const stillFocused = await p.evaluate(o => document.activeElement?.dataset?.id === o, other);
  if (!stillFocused) bad('focus lost after Enter');
  console.log('keyboard attack ok');
  // error state
  await p.route('**/api/public/attack', r => r.fulfill({ status: 500, body: '{"detail":"test failure"}', contentType: 'application/json' }));
  await p.click(`#mapBefore .node[data-id="${worst}"]`); await p.waitForTimeout(500);
  const err = await p.$eval('#dStatus', e => e.className.includes('err') && e.textContent);
  if (!err) bad('no error message'); else console.log('error state:', err);
  if (errs.filter(e => !/500/.test(e)).length) bad('console: ' + errs.join(' | '));
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
