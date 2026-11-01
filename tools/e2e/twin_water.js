// Twin water tab: amber rings (mapped signal) and faint amber rings (systems that carry the signal) equal the replay's sets.
const { chromium } = require('playwright');
(async () => { const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] }); const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
const errs = []; p.on('pageerror', e => errs.push(e.message));
await p.goto('http://localhost:8000/twin', { waitUntil: 'domcontentloaded', timeout: 120000 }); await p.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 120000 }); await p.waitForTimeout(2000);
await p.evaluate(() => document.querySelector('[data-tab="water"]').click()); await p.waitForSelector('#wScrub', { timeout: 30000 });
const idx = await p.evaluate(() => { const H = window.cascade.S.w.H; const out = []; for (let i = 0; i < H.t.length; i++) if ((H.top[i] || []).some(s => s.z >= H.threshold) || (H.rules[i] || []).length) out.push(i); return out; });
console.log('hours with anomalies:', idx.length);
let bad = 0;
const ring = await p.evaluate(() => { const S = window.cascade.S, H = S.w.H, out = []; const mp = Object.fromEntries(S.w.sum.mapping.map(m => [m.signal_id, m.mapped_city_asset_ids])); for (let i = 0; i < H.t.length; i++) if ((H.top[i] || []).some(s => s.z >= H.threshold && s.assets.length) || (H.rules[i] || []).some(r => mp[r.signal])) out.push(i); return { out, n: H.t.length, from: H.t[0], to: H.t[H.t.length - 1] }; });
console.log('twin replay', ring.n, 'hours', ring.from, '->', ring.to, '; hours that should show rings:', ring.out.length, ring.out.slice(0, 8));
for (const i of [...idx.slice(0, 3), 0]) {
  await p.$eval('#wScrub', (s, i) => { s.value = i; s.dispatchEvent(new Event('input')); }, i); await p.waitForTimeout(300);
  const r = await p.evaluate(() => { const S = window.cascade.S; const hot = [...(S.waterHot || []), ...(S.waterSeen || [])].sort(); const amber = Object.entries(window.cascade.nodes).filter(([, n]) => n.halo.material.color.getHexString() === 'f2b84b').map(([id]) => id).sort(); return { hot, amber }; });
  const same = JSON.stringify(r.hot) === JSON.stringify(r.amber); if (!same) bad++;
  console.log('hour', i, same ? 'in sync' : 'MISMATCH', r.hot.length, r.amber.length);
}
console.log(errs.join('|') || 'no errors', bad ? 'FAIL' : 'PASS'); await b.close(); })();
