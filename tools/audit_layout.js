// Layout audit: every route at 5 widths. Reports horizontal page scroll, clipped text (not intentional ellipsis),
// text under 11px, and console errors.  Usage (server running on :8000):
//   node tools/audit_layout.js [widths=1440,1280,1024,768,390] [--twin]
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
const widths = (process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '1440,1280,1024,768,390').split(',').map(Number);
const withTwin = process.argv.includes('--twin');
const ROUTES = (process.env.ROUTES || 'overview,inventory,services,vulns,water,electricity,novel,evaluation,simulate,paths,incidents,timeline,drill,risk,exposure,graphs,ml,optimizer,response,failsafe,report,compliance,project,architecture,security').split(',');

const CHECK = () => {
  const out = [];
  const vis = el => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && +cs.opacity > 0.05; };
  const path = el => { const p = []; let e = el; while (e && e.nodeType === 1 && p.length < 4) { p.unshift(e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (e.className && typeof e.className === 'string' ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.') : '')); e = e.parentElement; } return p.join(' > '); };
  const scroller = document.getElementById('main') || document.documentElement;
  if (document.documentElement.scrollWidth > innerWidth + 1) out.push({ kind: 'page-hscroll', detail: `${document.documentElement.scrollWidth} > ${innerWidth}` });
  if (scroller !== document.documentElement && scroller.scrollWidth > scroller.clientWidth + 1) out.push({ kind: 'main-hscroll', detail: `${scroller.scrollWidth} > ${scroller.clientWidth}` });
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('svg, canvas, .chart-tip, .ticker, .marq, .twinhost, script, style, [aria-hidden="true"], .sr-only, .sr, select, option, input, textarea')) continue;
    if (!vis(el)) continue;
    const cs = getComputedStyle(el);
    const ownText = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (ownText && parseFloat(cs.fontSize) < 11) out.push({ kind: 'small-text', where: path(el), detail: `${cs.fontSize}: "${el.textContent.trim().slice(0, 40)}"` });
    const clips = ['hidden', 'clip'].includes(cs.overflowX) || ['hidden', 'clip'].includes(cs.overflow);
    if (ownText && clips && cs.textOverflow !== 'ellipsis' && el.scrollWidth > el.clientWidth + 2) out.push({ kind: 'clipped-text', where: path(el), detail: `"${el.textContent.trim().slice(0, 50)}" ${el.scrollWidth}>${el.clientWidth}` });
    if (ownText && !clips && cs.whiteSpace === 'nowrap' && el.parentElement) {
      const pr = el.parentElement.getBoundingClientRect(), r = el.getBoundingClientRect(), pcs = getComputedStyle(el.parentElement);
      if (r.right > pr.right + 2 && ['hidden', 'clip'].includes(pcs.overflowX)) out.push({ kind: 'overflowing-nowrap', where: path(el), detail: `"${el.textContent.trim().slice(0, 40)}"` });
    }
  }
  return out;
};

(async () => {
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const report = [];
  for (const w of widths) {
    const h = w < 500 ? 844 : w < 900 ? 1024 : 900;
    const p = await b.newPage({ viewport: { width: w, height: h } });
    const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
    const log = (route, items) => { for (const it of items) report.push({ w, route, ...it }); };
    await p.goto(`${BASE}/`); await p.waitForTimeout(2500);
    for (const y of [0, .2, .45, .7, .95]) { await p.evaluate(f => window.scrollTo(0, document.documentElement.scrollHeight * f), y); await p.waitForTimeout(700); log(`/ @${y}`, await p.evaluate(CHECK)); }
    await p.goto(`${BASE}/app#/overview`); await p.waitForTimeout(2500);
    for (const r of ROUTES) {
      await p.evaluate(r => { location.hash = '#/' + r; }, r); await p.waitForTimeout(r === 'graphs' ? 9000 : r === 'water' ? 4000 : 2600);
      log(`/app#/${r}`, await p.evaluate(CHECK));
    }
    if (withTwin && [1440, 1024, 390].includes(w)) {
      await p.goto(`${BASE}/twin`); await p.waitForTimeout(9000);
      for (const tab of ['replay', 'fixes', 'optimize', 'respond', 'water']) {
        await p.evaluate(t => document.querySelector(`[data-tab="${t}"]`)?.click(), tab); await p.waitForTimeout(tab === 'fixes' ? 6000 : 2500);
        log(`/twin ${tab}`, await p.evaluate(CHECK));
      }
    }
    for (const e of errs) report.push({ w, route: '(console)', kind: 'console-error', detail: e.slice(0, 200) });
    await p.close();
  }
  const seen = new Set();
  const uniq = report.filter(r => { const k = `${r.w}|${r.kind}|${r.where || ''}|${r.detail}`; if (seen.has(k)) return false; seen.add(k); return true; });
  console.log(JSON.stringify(uniq, null, 1));
  console.error(`${uniq.length} issues`);
  await b.close();
})();
