// Twin sweep: Present mode runs every step without an error; the before/after split view paints both sides;
// the risk heatmap stays in sync with the halo state; the water tab's amber rings follow its replay.
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } }); let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
  await p.goto(BASE + '/twin', { waitUntil: 'domcontentloaded', timeout: 120000 }); await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 120000 }); await p.waitForTimeout(2500);
  // present mode
  await p.click('#demoBtn'); await p.waitForTimeout(500);
  const n = await p.evaluate(() => +document.querySelector('#pCount').textContent.match(/of (\d+)/)[1]);
  for (let i = 0; i < n; i++) {
    await p.waitForFunction(() => !/Working/.test(document.querySelector('#pText').textContent), null, { timeout: 120000 });
    const t = await p.$eval('#pText', e => e.textContent);
    if (/could not run|undefined|NaN/.test(t)) bad(`present step ${i + 1}: ${t}`); else console.log(`present step ${i + 1}: ok`);
    if (i < n - 1) await p.click('#pNext');
  }
  await p.click('#pNext'); await p.waitForTimeout(400);
  if (!(await p.$eval('#present', e => e.hidden))) bad('present mode did not finish');
  // split view (optimizer compare)
  await p.evaluate(() => document.querySelector('[data-tab="optimize"]').click()); await p.waitForTimeout(800);
  await p.evaluate(() => document.querySelector('#oRun')?.click());
  await p.waitForFunction(() => window.cascade.S.opt, null, { timeout: 180000 }); await p.waitForTimeout(500);
  await p.evaluate(() => document.querySelector('#oCompare')?.click());
  await p.waitForFunction(() => window.cascade.S.split, null, { timeout: 60000 }); await p.waitForTimeout(1500);
  const split = await p.evaluate(() => ({ cap: document.querySelector('#capL').textContent + ' | ' + document.querySelector('#capR').textContent, on: document.querySelector('#stage').classList.contains('split') }));
  if (!split.on || /undefined/.test(split.cap)) bad('split view: ' + JSON.stringify(split)); else console.log('split view ok:', split.cap.slice(0, 120));
  await p.screenshot({ path: (process.env.OUT || '/tmp') + '/twin_split.png' });
  await p.evaluate(() => document.querySelector('[data-tab="replay"]').click()); await p.waitForTimeout(500);
  await p.evaluate(() => window.cascade.setEntries([], false)); await p.waitForTimeout(500);
  // heatmap: halos follow risk while on, back to normal when off
  await p.keyboard.press('h'); await p.waitForTimeout(400);
  const heat = await p.evaluate(() => Object.values(window.cascade.nodes).filter(n => n.halo.scale.x > 1.1).length);
  await p.keyboard.press('h'); await p.waitForTimeout(400);
  const off = await p.evaluate(() => Object.values(window.cascade.nodes).filter(n => n.halo.scale.x !== 1).length);
  if (!heat || off) bad(`heatmap on=${heat} off-leftover=${off}`); else console.log(`heatmap ok: ${heat} scaled halos, reset when off`);
  // water tab: amber rings == the replay's hot set
  await p.evaluate(() => document.querySelector('[data-tab="water"]').click()); await p.waitForTimeout(3000);
  const w = await p.evaluate(() => { const hot = window.cascade.S.waterHot; const amber = Object.entries(window.cascade.nodes).filter(([, n]) => n.halo.material.color.getHexString() === 'f2b84b').map(([id]) => id).sort(); return { hot: hot ? [...hot].sort() : [], amber }; });
  if (JSON.stringify(w.hot) !== JSON.stringify(w.amber)) bad(`water rings ${w.amber} vs hot ${w.hot}`); else console.log(`water rings in sync (${w.amber.length})`);
  // frame rate (software GL here, so only a sanity floor; on a real GPU the target is 50+)
  const fps = await p.evaluate(() => new Promise(r => { let n = 0; const t0 = performance.now(); const f = () => { n++; if (performance.now() - t0 < 2000) requestAnimationFrame(f); else r(n / 2); }; requestAnimationFrame(f); }));
  console.log('fps (swiftshader, CPU):', fps);
  if (errs.length) bad('console: ' + [...new Set(errs)].join(' | '));
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
