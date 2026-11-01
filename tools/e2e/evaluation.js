// Model evaluation page: six model cards; every approved model fails no criterion; every rejected one shows a failed
// criterion; the IoT demo shows integrity OK and its test numbers equal results.json.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  for (const [W, H] of [[1440, 900], [390, 844]]) {
    const p = await b.newPage({ viewport: { width: W, height: H } }); const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
    await p.goto(`${BASE}/app#/evaluation`); await p.waitForSelector('#iotBars svg', { timeout: 30000 }); await p.waitForTimeout(2500);
    const cards = await p.$$eval('.evcard', cs => cs.map(c => ({ cls: c.className, fails: c.querySelectorAll('.gp.no').length, name: c.querySelector('h3').textContent })));
    if (cards.length !== 6) bad('cards ' + cards.length);
    for (const c of cards) { if (/approved/.test(c.cls) && c.fails) bad(c.name + ' approved with a failed criterion'); if (/no_go/.test(c.cls) && !c.fails) bad(c.name + ' rejected without a failed criterion'); }
    const r = await p.evaluate(async () => (await (await fetch('/api/ml/evaluation')).json()).iot_demo.results.test_once.candidate.attack_recall);
    const shown = await p.$eval('#iot .kpi .v', e => e.textContent); if (shown !== r.toFixed(3)) bad(`IoT recall shown ${shown} vs ${r}`);
    const integ = await p.$eval('#iot', e => /declaration unchanged/.test(e.textContent) && /results locked/.test(e.textContent)); if (!integ) bad('integrity line');
    const hs = await p.evaluate(() => document.querySelector('#main').scrollWidth > document.querySelector('#main').clientWidth + 1); if (hs) bad(`${W} horizontal scroll`);
    if (W === 1440) await p.screenshot({ path: (process.env.OUT || '/tmp') + '/evaluation.png', fullPage: false });
    if (errs.length) bad(`${W} console: ${errs.join(' | ')}`);
    console.log(`${W}px checked: ${cards.map(c => c.name + (c.fails ? `(${c.fails} failed)` : '')).join(', ')}`); await p.close();
  }
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
