// Electricity screening page: KPIs equal the model card, the table follows the filters, block click filters,
// the sample drawer shows the warning and the evidence; the ML page lists all six sectors.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  for (const [W, H] of [[1440, 900], [390, 844]]) {
    const p = await b.newPage({ viewport: { width: W, height: H } }); const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
    await p.goto(`${BASE}/app#/electricity`); await p.waitForSelector('#eTable table', { timeout: 30000 });
    const mc = await p.evaluate(async () => (await (await fetch('/api/electricity/summary')).json()).model_card);
    await p.waitForTimeout(2500); const kp = await p.$$eval('.kpi .v', v => v.map(x => x.textContent));   // KPIs count up on arrival
    if (kp[0] !== (100 * mc.held_out_test_data13_15_evaluated_once.attack_precision).toFixed(1) + '%') bad('precision KPI ' + kp[0]);
    if (kp[1] !== (100 * mc.held_out_test_data13_15_evaluated_once.attack_recall).toFixed(1) + '%') bad('recall KPI ' + kp[1]);
    const warn = await p.$eval('#main', m => /never means the grid is safe/.test(m.innerText)); if (!warn) bad('coverage warning missing');
    await p.selectOption('#eOut', 'attack_missed'); await p.waitForTimeout(600);
    const tags = await p.$$eval('#eTable tbody tr td:last-child', t => t.map(x => x.textContent.trim()));
    if (!tags.length || tags.some(t => t !== 'Attack missed')) bad('outcome filter ' + tags.slice(0, 3));
    await p.click('.eblock[data-i="1"]'); await p.waitForTimeout(700);
    const cnt = await p.$eval('#eCount', e => e.textContent); if (!/block 2/.test(cnt)) bad('block filter ' + cnt);
    await p.click('#eTable tbody tr'); await p.waitForSelector('.drawer.open .evrow', { timeout: 5000 });
    const dr = await p.$eval('.drawer.open', d => d.innerText); if (!/does not mean the grid is safe|investigate/.test(dr) || !/never means/.test(dr)) bad('drawer wording');
    await p.keyboard.press('Escape');
    await p.evaluate(() => { location.hash = '#/ml'; }); await p.waitForTimeout(2500);
    await p.waitForFunction(() => /Transportation/.test(document.querySelector('#main').textContent), null, { timeout: 15000 }).catch(() => {});
    const sec = await p.$eval('#main', m => ['Water', 'Electricity', 'IoT', 'Healthcare', 'Telecom', 'Transportation'].every(s => m.textContent.includes(s)) && /NO-GO/.test(m.textContent));
    if (!sec) bad('sector table');
    const hs = await p.evaluate(() => document.querySelector('#main').scrollWidth > document.querySelector('#main').clientWidth + 1); if (hs) bad(`${W} horizontal scroll`);
    if (W === 1440) { await p.evaluate(() => { location.hash = '#/electricity'; }); await p.waitForSelector('#eTable table', { state: 'attached', timeout: 30000 }); await p.waitForTimeout(800); await p.screenshot({ path: (process.env.OUT || '/tmp') + '/electricity.png', fullPage: false }); }
    if (errs.length) bad(`${W} console: ${errs.join(' | ')}`);
    console.log(`${W}px checked`); await p.close();
  }
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
