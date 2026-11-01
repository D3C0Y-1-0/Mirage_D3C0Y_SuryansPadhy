// Both themes, every platform page: console errors, failed calls, "undefined"/"NaN", and text that is
// (nearly) invisible against its own background (contrast < 2.2). Usage: node tools/e2e/themes.js
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
const ROUTES = (process.env.ROUTES || 'overview,inventory,services,vulns,water,simulate,paths,incidents,timeline,drill,risk,exposure,graphs,ml,optimizer,response,failsafe,report,compliance,project,architecture,security').split(',');
const CONTRAST = () => {
  const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const v = m[1].split(',').map(Number); return { r: v[0], g: v[1], b: v[2], a: v[3] ?? 1 }; };
  const lum = ({ r, g, b }) => { const f = x => { x /= 255; return x <= .03928 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4; }; return .2126 * f(r) + .7152 * f(g) + .0722 * f(b); };
  const bgOf = el => { let stack = []; for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.backgroundImage !== 'none' && !cs.backgroundImage.includes('url')) return null; const c = parse(cs.backgroundColor); if (c && c.a > 0) { stack.push(c); if (c.a >= .95) break; } } let out = { r: 255, g: 255, b: 255 }; if (!stack.length) return out; out = stack.pop(); while (stack.length) { const c = stack.pop(); out = { r: c.r * c.a + out.r * (1 - c.a), g: c.g * c.a + out.g * (1 - c.a), b: c.b * c.a + out.b * (1 - c.a) }; } return out; };
  const bad = [];
  for (const el of document.querySelectorAll('#main *, .top *')) {
    if (el.closest('svg, canvas, .twinhost, [aria-hidden="true"], option')) continue;
    if (![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (!r.width || cs.visibility === 'hidden' || +cs.opacity < .3) continue;
    const fg = parse(cs.color), bg = bgOf(el); if (!fg || !bg) continue;
    const L1 = lum(fg), L2 = lum(bg), k = (Math.max(L1, L2) + .05) / (Math.min(L1, L2) + .05);
    if (k < 2.2) bad.push(`${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]} "${el.textContent.trim().slice(0, 30)}" ${k.toFixed(2)}`);
  }
  return [...new Set(bad)].slice(0, 6);
};
(async () => {
  const b = await chromium.launch(); const issues = [];
  for (const theme of ['light', 'dark']) {
    const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } });
    await ctx.addInitScript(t => { try { localStorage.setItem('cascade.theme', t); } catch {} }, theme);
    const p = await ctx.newPage(); let where = '';
    p.on('pageerror', e => issues.push(`${theme} ${where}: ${e.message}`));
    p.on('console', m => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) issues.push(`${theme} ${where}: ${m.text().slice(0, 150)}`); });
    p.on('response', r => { if (r.status() >= 500) issues.push(`${theme} ${where}: ${r.status()} ${r.url()}`); });
    await p.goto(`${BASE}/app#/simulate`); await p.waitForSelector('#presets .preset'); await p.click('#presets [data-k="D"]'); await p.waitForTimeout(2500);
    for (const r of ROUTES) {
      where = r; await p.evaluate(r => { location.hash = '#/' + r; }, r); await p.waitForTimeout(r === 'graphs' ? 8000 : 2600);
      const t = await p.evaluate(() => document.querySelector('#main').innerText);
      const m = t.match(/\b(undefined|NaN|null|\[object Object\])\b/); if (m) issues.push(`${theme} ${r}: shows "${m[1]}" near "${t.slice(Math.max(0, m.index - 40), m.index + 15).replace(/\s+/g, ' ')}"`);
      for (const c of await p.evaluate(CONTRAST)) issues.push(`${theme} ${r}: low contrast ${c}`);
    }
    await ctx.close();
  }
  const u = [...new Set(issues)]; console.log(u.join('\n') || 'no issues'); console.log(u.length ? `FAIL ${u.length}` : 'PASS'); await b.close();
})();
