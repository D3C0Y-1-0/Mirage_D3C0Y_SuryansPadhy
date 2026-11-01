// Click every button and link on every route (landing, the 22 platform pages, the twin tabs). After each click:
// no console error, no failed call (5xx anywhere; 4xx outside the sign-in endpoints), no "undefined"/"NaN"/empty text.
// Usage (server on :8000):  node tools/e2e/click_all.js [routes]
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
const ONLY = process.env.ONLY || 'landing,app,twin';
const ROUTES = (process.argv[2] || 'overview,inventory,services,vulns,live,water,electricity,novel,evaluation,recovery,assumptions,simulate,paths,incidents,timeline,drill,risk,exposure,graphs,ml,optimizer,response,failsafe,report,compliance,project,architecture,security').split(',');
const SKIP = /print|sign out|log out|disable|delete|remove two|download|export|copy/i;
(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await ctx.newPage();
  const issues = []; let where = '', c = 0;
  p.on('pageerror', e => issues.push(`${where}: page error ${e.message}`));
  p.on('console', m => { if (m.type() === 'error' && !/Failed to load resource: the server responded with a status of 4\d\d/.test(m.text())) issues.push(`${where}: console ${m.text().slice(0, 160)}`); });
  p.on('response', r => { const u = r.url(); if (!u.startsWith(BASE)) return; const s = r.status();
    if (s >= 500 || (s >= 400 && !u.includes('/api/auth/') && s !== 401)) issues.push(`${where}: ${s} ${r.request().method()} ${u.replace(BASE, '')}`); });
  p.on('dialog', d => d.dismiss());
  const textCheck = async () => { let t; try { t = await p.evaluate(() => document.body.innerText); } catch { await p.waitForTimeout(1500); return; } const m = t.match(/\b(undefined|NaN|\[object Object\])\b/); if (m) issues.push(`${where}: text shows "${m[1]}" near "${t.slice(Math.max(0, m.index - 40), m.index + 20).replace(/\s+/g, ' ')}"`); };
  async function clickAll(scope, reset, max = 45) {
    const n = await p.evaluate(sel => document.querySelectorAll(sel).length, scope);
    let clicked = 0;
    for (let i = 0; i < n && clicked < max; i++) {
      const info = await p.evaluate(([sel, i]) => {
        const el = document.querySelectorAll(sel)[i]; if (!el) return null;
        const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
        const vis = r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && !el.disabled && !el.closest('[hidden]');
        const href = el.getAttribute('href') || '';
        return { vis, txt: (el.innerText || el.getAttribute('aria-label') || el.title || '').trim().slice(0, 50), href, ext: /^https?:|^mailto:/.test(href) || el.target === '_blank', empty: !(el.innerText || el.getAttribute('aria-label') || el.title || el.querySelector('svg,img')) };
      }, [scope, i]);
      if (!info || !info.vis || info.ext || SKIP.test(info.txt)) continue;
      if (info.empty) issues.push(`${where}: control #${i} has no text or label`);
      where = `${where.split(' » ')[0]} » "${info.txt}"`;
      try { await p.evaluate(([sel, i]) => document.querySelectorAll(sel)[i].click(), [scope, i]); } catch (e) { continue; }
      clicked++;
      await p.waitForTimeout(info.href.startsWith('#/') || info.href.startsWith('/') ? 900 : 450);
      await textCheck();
      await reset();
    }
    return clicked;
  }
  // landing
  if (ONLY.includes('landing')) {
  where = '/'; await p.goto(BASE + '/'); await p.waitForTimeout(2500);
  c = await clickAll('main a, main button, section a, section button, header a, header button, footer a', async () => { if (!p.url().replace(/#.*/, '').endsWith(':8000/')) { await p.goto(BASE + '/'); await p.waitForTimeout(1500); } }, 60);
  console.log(`/ : ${c} clicks`); }
  let c2;
  // platform
  if (ONLY.includes('app')) {
  await p.goto(`${BASE}/app#/simulate`); await p.waitForSelector('#presets .preset'); await p.click('#presets [data-k="B"]'); await p.waitForTimeout(3000);
  for (const r of ROUTES) {
    where = `#/${r}`;
    const go = async () => { await p.evaluate(r => { location.hash = '#/' + r; }, r); await p.waitForTimeout(r === 'graphs' ? 6000 : 1800); };
    await p.goto(`${BASE}/app#/${r}`); await p.waitForTimeout(r === 'graphs' ? 8000 : 2500);
    await textCheck();
    c = await clickAll('#main button, #main a, #main [role=button], #main select', async () => { if (!p.url().includes(`#/${r}`)) await go(); else if (await p.evaluate(() => !!document.querySelector('.drawer.open'))) await p.keyboard.press('Escape'); });
    console.log(`#/${r}: ${c} clicks`);
  } }
  // twin tabs
  if (ONLY.includes('twin')) {
  where = '/twin'; await p.goto(BASE + '/twin', { waitUntil: 'domcontentloaded', timeout: 120000 }); await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 90000 }); await p.waitForTimeout(2500);
  for (const tab of ['replay', 'fixes', 'optimize', 'respond', 'water']) {
    where = `/twin ${tab}`;
    await p.evaluate(t => document.querySelector(`[data-tab="${t}"]`)?.click(), tab); await p.waitForTimeout(tab === 'fixes' ? 5000 : 2000);
    c = await clickAll('#panel button, #panel a', async () => {
      if (!p.url().includes('/twin')) { await p.goto(BASE + '/twin', { waitUntil: 'domcontentloaded', timeout: 120000 }); await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 90000 }); await p.waitForTimeout(1500); }
      await p.evaluate(t => { if (window.cascade.S.tab !== t) document.querySelector(`[data-tab="${t}"]`)?.click(); }, tab); }, 25);
    await textCheck();
    console.log(`/twin ${tab}: ${c} clicks`);
  } }
  const u = [...new Set(issues)];
  console.log(u.length ? 'ISSUES:\n' + u.join('\n') : 'no issues'); console.log(u.length ? `FAIL ${u.length}` : 'PASS');
  await b.close(); process.exit(u.length ? 1 : 0);
})();
