// Landing "Scroll into the city": at 10 scroll positions the visible frame equals the active step, the connector ends
// within 12 px of the hotspot, and no callout overlaps another or the nav.  Usage: node tools/e2e/landing_zoom.js
const { chromium } = require('playwright');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000';
(async () => {
  const b = await chromium.launch(); let fails = 0;
  for (const [w, h] of [[1440, 900], [1024, 768], [390, 844]]) {
    const p = await b.newPage({ viewport: { width: w, height: h } });
    const errs = []; p.on('pageerror', e => errs.push(e.message));
    await p.goto(BASE + '/'); await p.waitForTimeout(2000); await p.evaluate(async () => { window.__zf = await (await fetch('/static/img/twin-frames.json')).json(); });
    const box = await p.$eval('#city', s => ({ top: s.getBoundingClientRect().top + scrollY, h: s.offsetHeight }));
    for (const f of [.2, .27, .35, .42, .5, .57, .64, .7, .78, .84]) {
      await p.evaluate(y => { window.scrollTo(0, y); window.dispatchEvent(new Event('scroll')); }, box.top + (box.h - h) * f);
      await p.waitForTimeout(650);
      const r = await p.evaluate(() => {
        const z = window.__zoom.state, vis = [...document.querySelectorAll('#pan .frame')].map(f => +getComputedStyle(f).opacity);
        const shown = vis.indexOf(Math.max(...vis));
        const line = document.querySelector('#zLine'), on = line.classList.contains('on');
        const st = document.querySelector('#stick').getBoundingClientRect();
        const end = [+line.getAttribute('x2') + st.left, +line.getAttribute('y2') + st.top];
        // independent check: where the hotspot really is = the frame image's on-screen box (after every transform)
        // times the hotspot's position in the captured frame (twin-frames.json)
        const ZF = window.__zf, k = z.step, img = document.querySelector('#pan .frame').getBoundingClientRect();
        const hn = k < 0 || !ZF ? null : k === 0 ? [.5, .5] : k >= 5 ? ZF.xray : ZF.frames[k].hot;
        const hot = hn && [img.left + hn[0] * img.width, img.top + hn[1] * img.height];
        const cs = [...document.querySelectorAll('.callout.on')].map(c => c.getBoundingClientRect());
        const nav = document.querySelector('#nav').getBoundingClientRect();
        const ov = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
        return { step: z.step, frame: z.frame, shown, on, dist: hot ? Math.hypot(end[0] - hot[0], end[1] - hot[1]) : null, ncall: cs.length,
          navOverlap: cs.some(c => ov(c, nav)) && innerWidth >= 640, callOverlap: cs.length > 1 };
      });
      const expFrame = Math.min(4, r.step < 0 ? 0 : r.step);
      const bad = [];
      if (r.shown !== expFrame) bad.push(`frame ${r.shown} != step ${r.step}`);
      if (w >= 640 && r.step >= 0 && r.step < 5 && r.on && r.dist > 12) bad.push(`connector ${r.dist.toFixed(1)}px from hotspot`);
      if (r.navOverlap) bad.push('callout over nav'); if (r.callOverlap) bad.push('two callouts');
      if (bad.length) { fails++; console.log(`${w}px @${f}: ${bad.join(', ')}`); }
      else console.log(`${w}px @${f}: step ${r.step}, frame ${r.shown}, connector ${r.on ? r.dist.toFixed(1) + 'px' : 'n/a'}`);
      if (w === 1440 && [.27, .5, .64, .78].includes(f)) await p.screenshot({ path: `${process.env.OUT || '/tmp'}/zoom_${f}.png` });
    }
    if (errs.length) { fails++; console.log('errors', errs); }
    await p.close();
  }
  // reduced motion: static stack, five frames with captions
  const p = await b.newPage({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
  await p.goto(BASE + '/'); await p.waitForTimeout(2500);
  const n = await p.$$eval('#zStack figure', f => f.length), stickHidden = await p.$eval('#stick', s => getComputedStyle(s).display === 'none');
  if (n !== 5 || !stickHidden) { fails++; console.log('reduced motion stack', n, stickHidden); } else console.log('reduced motion: 5 stacked frames, pinned stage off');
  console.log(fails ? `FAIL ${fails}` : 'PASS'); await b.close(); process.exit(fails ? 1 : 0);
})();
