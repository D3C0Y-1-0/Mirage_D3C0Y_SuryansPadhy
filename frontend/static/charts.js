// Small SVG chart kit for the platform. No dependencies, works offline.
// Every chart: title + subtitle outside (in the page), recessive grid, 2px lines, rounded bar ends,
// hover tooltip, legend for 2+ series, and export (CSV of the data, SVG of the picture).
const NS = 'http://www.w3.org/2000/svg';
const C = {
  ink: '#FFFFFF', mute: '#A9B4DA', faint: '#6F7DB5', grid: 'rgba(43,61,134,.55)', surface: '#12225E',
  series: ['#8E9DE0', '#FFFFFF'],                       // single-measure charts: soft blue-white, highlight white
  atk: { A: '#E5559F', B: '#2A8FD6', C: '#9A74F0', D: '#2BA58A' },
  pink: '#FF6FB5', warn: '#F2B84B',
};
export { C as COLORS };

const el = (tag, attrs = {}, parent) => {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
};
export const fmt = (v, d = 0) => v == null || Number.isNaN(v) ? '–' : Math.abs(v) >= 1e6 ? (v / 1e6).toFixed(1) + 'M'
  : Math.abs(v) >= 1e4 ? (v / 1e3).toFixed(0) + 'k' : Math.abs(v) >= 1e3 ? (v / 1e3).toFixed(1) + 'k' : (+v).toFixed(d);
export const tmin = m => { if (m == null) return '–'; if (m >= 360) return 'none in 6 h'; m = Math.round(m); return `T+${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`; };   // round first: never T+00:60

// time axis in minutes: whole hours (every 2 h when the plot is narrow), never 100-minute steps
function timeTicks(xMax, width) {
  const step = xMax <= 30 ? 5 : xMax <= 120 ? 15 : xMax <= 720 ? (width < 380 ? 120 : 60) : 240;
  const out = []; for (let v = 0; v <= xMax + 1e-9; v += step) out.push(v); return out;
}
function niceTicks(lo, hi, n = 5, minStep = 0) {
  if (hi === lo) hi = lo + 1;
  const span = hi - lo, step0 = Math.max(span / n, minStep), mag = 10 ** Math.floor(Math.log10(step0));
  const step = Math.max(minStep, [1, 2, 5, 10].map(m => m * mag).find(s => s >= step0));   // no 2.5 steps: 0.25 printed with one decimal read as 0.3
  if (minStep && hi < lo + step) hi = lo + step;
  const out = []; for (let v = Math.ceil(lo / step) * step; v <= hi + 1e-9; v += step) out.push(+v.toFixed(10));
  while (!out.length || out[out.length - 1] < hi - 1e-9) out.push(+((out.length ? out[out.length - 1] : lo) + step).toFixed(10));   // the top tick always covers the data
  return out;
}

// shared tooltip
let tip;
function tooltip() {
  if (!tip) { tip = document.createElement('div'); tip.className = 'chart-tip'; tip.setAttribute('role', 'status'); document.body.appendChild(tip); }
  return tip;
}
function showTip(evt, html) {
  const t = tooltip(); t.innerHTML = html; t.style.display = 'block';
  const r = t.getBoundingClientRect(); let x = evt.clientX + 14, y = evt.clientY + 14;
  if (x + r.width > innerWidth - 8) x = evt.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = evt.clientY - r.height - 14;
  t.style.left = x + 'px'; t.style.top = y + 'px';
}
const hideTip = () => { if (tip) tip.style.display = 'none'; };

function frame(host, { height = 260, left = 52, bottom = 34, top = 12, right = 16 } = {}) {
  host.innerHTML = '';
  const W = Math.max(280, host.clientWidth || 560), H = height;
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', height: H, role: 'img', class: 'chart' }, host);
  return { svg, W, H, x0: left, x1: W - right, y0: H - bottom, y1: top };
}

function axisY(f, ticks, y, fmtv = fmt, label) {
  const stp = ticks.length > 1 ? ticks[1] - ticks[0] : 1;
  if (fmtv === fmt && stp < 1) fmtv = v => v.toFixed(stp < .1 ? 2 : 1);
  for (const v of ticks) {
    const yy = y(v);
    el('line', { x1: f.x0, x2: f.x1, y1: yy, y2: yy, stroke: C.grid, 'stroke-width': 1 }, f.svg);
    el('text', { x: f.x0 - 8, y: yy + 4, 'text-anchor': 'end', fill: C.faint, 'font-size': 11 }, f.svg).textContent = fmtv(v);
  }
  if (label) el('text', { x: 4, y: f.y1 + 2, fill: C.faint, 'font-size': 11, 'dominant-baseline': 'hanging' }, f.svg).textContent = '';
}
function axisLabels(f, xl, yl) {
  if (xl) el('text', { x: f.x1, y: f.H - 4, 'text-anchor': 'end', fill: C.faint, 'font-size': 11 }, f.svg).textContent = xl;
  if (yl) { const t = el('text', { x: 12, y: f.y1, fill: C.faint, 'font-size': 11, transform: `rotate(-90 12 ${f.y1})`, 'text-anchor': 'end' }, f.svg); t.textContent = yl; }
}

function legend(host, items) {
  if (items.length < 2) return;
  const lg = document.createElement('div'); lg.className = 'chart-legend';
  lg.innerHTML = items.map(i => `<span><i style="background:${i.color}${i.dash ? ';background:repeating-linear-gradient(90deg,' + i.color + ' 0 4px,transparent 4px 7px)' : ''}"></i>${i.label}</span>`).join('');
  host.prepend(lg);
}

// ---------- vertical or horizontal bar chart ----------
// axis label in up to two lines (word wrap), ellipsis only if it still does not fit; full text on hover
function axisLabel(t, label, slot, lines = 2) {
  const max = Math.max(5, Math.floor(slot / 6.3)), words = String(label).split(/\s+/), out = [''];
  for (const w of words) { const cur = out[out.length - 1]; if ((cur + ' ' + w).trim().length <= max) out[out.length - 1] = (cur + ' ' + w).trim(); else if (out.length < lines) out.push(w); else { out[out.length - 1] = (cur + ' ' + w).trim(); break; } }
  out.forEach((ln, k) => { if (ln.length > max) out[k] = ln.slice(0, max - 1) + '…'; });
  if (out.join(' ').replace('…', '').length < String(label).length && !out[out.length - 1].endsWith('…')) out[out.length - 1] = out[out.length - 1].slice(0, max - 1) + '…';
  t.textContent = '';
  const x = t.getAttribute('x');
  out.forEach((ln, k) => { const sp = document.createElementNS('http://www.w3.org/2000/svg', 'tspan'); sp.setAttribute('x', x); if (k) sp.setAttribute('dy', '13'); sp.textContent = ln; t.appendChild(sp); });
  const ti = document.createElementNS('http://www.w3.org/2000/svg', 'title'); ti.textContent = label; t.appendChild(ti);
}

export function bars(host, data, { horizontal = false, height, xLabel, yLabel, fmtv = fmt, color, max, tipFmt, onClick, labelWidth = 170 } = {}) {
  if (!data.length) return empty(host);
  if (horizontal) {
    const h = height || Math.max(120, data.length * 30 + 40);
    const f = frame(host, { height: h, left: Math.min(labelWidth, (host.clientWidth || 560) * .42), bottom: 28, right: 52 });
    const lo = Math.min(0, ...data.map(d => d.value));
    const hTicks = niceTicks(lo, max ?? (Math.max(...data.map(d => d.value), 0) * 1.05 || 1), 4, data.every(d => Number.isInteger(d.value)) ? 1 : 0);
    const hi = max ?? hTicks[hTicks.length - 1];             // the scale ends on the last tick, so every tick sits inside the plot
    const x = v => f.x0 + (v - lo) / (hi - lo) * (f.x1 - f.x0);
    for (const v of hTicks.filter(v => v <= hi + 1e-9)) {
      el('line', { x1: x(v), x2: x(v), y1: f.y1, y2: f.y0, stroke: C.grid }, f.svg);
      el('text', { x: x(v), y: f.y0 + 16, 'text-anchor': 'middle', fill: C.faint, 'font-size': 11 }, f.svg).textContent = fmtv(v);
    }
    const bh = Math.min(18, (f.y0 - f.y1) / data.length - 8);
    data.forEach((d, i) => {
      const cy = f.y1 + (i + .5) * (f.y0 - f.y1) / data.length;
      const t = el('text', { x: f.x0 - 8, y: cy + 4, 'text-anchor': 'end', fill: C.mute, 'font-size': 12 }, f.svg);
      const mc = Math.floor((f.x0 - 12) / 6.4); t.textContent = d.label.length > mc ? d.label.slice(0, mc - 1) + '…' : d.label;
      // measured, not guessed: wide letters (M, W, &) can still push a label past the left edge
      for (let n = t.textContent.length - 1; n > 3 && t.getComputedTextLength?.() > f.x0 - 10; n--) t.textContent = d.label.slice(0, n - 1) + '…';
      if (t.textContent !== d.label) el('title', {}, t).textContent = d.label;
      const w = Math.abs(x(d.value) - x(0));
      const r = el('rect', { x: Math.min(x(0), x(d.value)), y: cy - bh / 2, width: Math.max(1, w), height: bh, rx: 4, fill: d.color || color || C.series[0] }, f.svg);
      el('text', { x: x(Math.max(0, d.value)) + 6, y: cy + 4, fill: C.ink, 'font-size': 11 }, f.svg).textContent = fmtv(d.value);
      const hit = el('rect', { x: f.x0 - labelWidth, y: cy - (f.y0 - f.y1) / data.length / 2, width: f.x1 - f.x0 + labelWidth, height: (f.y0 - f.y1) / data.length, fill: 'transparent', style: onClick ? 'cursor:pointer' : '' }, f.svg);
      hit.addEventListener('mousemove', e => { r.setAttribute('opacity', .8); showTip(e, tipFmt ? tipFmt(d) : `<b>${d.label}</b><br>${fmtv(d.value)}`); });
      hit.addEventListener('mouseleave', () => { r.removeAttribute('opacity'); hideTip(); });
      if (onClick) hit.addEventListener('click', () => onClick(d));
    });
    axisLabels(f, xLabel);
    attachExport(host, f.svg, data.map(d => ({ label: d.label, value: d.value })));
    return f;
  }
  const f = frame(host, { height: height || 240, bottom: 46 });
  const hi = max ?? (Math.max(...data.map(d => d.value), 0) * 1.08 || 1);
  const ticks = niceTicks(0, hi, 4, data.every(d => Number.isInteger(d.value)) ? 1 : 0), top = ticks[ticks.length - 1];
  const y = v => f.y0 - v / top * (f.y0 - f.y1);
  axisY(f, ticks, y, fmtv);
  const slot = (f.x1 - f.x0) / data.length, bw = Math.min(46, slot - 6);
  data.forEach((d, i) => {
    const cx = f.x0 + (i + .5) * slot, yy = y(d.value), hgt = f.y0 - yy;
    const p = hgt > 4 ? `M${cx - bw / 2},${f.y0} V${yy + 4} q0,-4 4,-4 H${cx + bw / 2 - 4} q4,0 4,4 V${f.y0} Z` : `M${cx - bw / 2},${f.y0} h${bw} v${-Math.max(hgt, 1)} h${-bw} Z`;
    const r = el('path', { d: p, fill: d.color || color || C.series[0] }, f.svg);
    if (data.length <= 8) el('text', { x: cx, y: yy - 5, 'text-anchor': 'middle', fill: C.ink, 'font-size': 11 }, f.svg).textContent = fmtv(d.value);   // the value, so a zero is visibly a zero
    const lab = el('text', { x: cx, y: f.y0 + 15, 'text-anchor': 'middle', fill: C.mute, 'font-size': 11 }, f.svg);
    axisLabel(lab, d.label, slot, d.sub ? 1 : 2);
    if (d.sub) el('text', { x: cx, y: f.y0 + 29, 'text-anchor': 'middle', fill: C.faint, 'font-size': 10 }, f.svg).textContent = d.sub;
    const hit = el('rect', { x: cx - slot / 2, y: f.y1, width: slot, height: f.y0 - f.y1, fill: 'transparent' }, f.svg);
    hit.addEventListener('mousemove', e => { r.setAttribute('opacity', .8); showTip(e, tipFmt ? tipFmt(d) : `<b>${d.label}</b><br>${fmtv(d.value)}`); });
    hit.addEventListener('mouseleave', () => { r.removeAttribute('opacity'); hideTip(); });
    if (onClick) { hit.style.cursor = 'pointer'; hit.addEventListener('click', () => onClick(d)); }
  });
  axisLabels(f, xLabel, yLabel);
  attachExport(host, f.svg, data.map(d => ({ label: d.label, value: d.value })));
  return f;
}

// ---------- grouped bars (2-3 measures per category, one axis, same unit) ----------
export function grouped(host, cats, series, { height = 250, fmtv = fmt, yLabel } = {}) {
  if (!cats.length) return empty(host);
  const f = frame(host, { height, bottom: 46 });
  const hi = Math.max(...series.flatMap(s => s.values), 0) * 1.08 || 1;
  const ticks = niceTicks(0, hi, 4, series.every(s => s.values.every(Number.isInteger)) ? 1 : 0), top = ticks[ticks.length - 1];
  const y = v => f.y0 - v / top * (f.y0 - f.y1);
  axisY(f, ticks, y, fmtv);
  const slot = (f.x1 - f.x0) / cats.length, gw = Math.min(28, (slot - 10) / series.length);
  cats.forEach((c, i) => {
    const cx = f.x0 + (i + .5) * slot, x0 = cx - gw * series.length / 2;
    series.forEach((s, k) => {
      const v = s.values[i], yy = y(v), h = f.y0 - yy;
      const p = h > 4 ? `M${x0 + k * gw + 1},${f.y0} V${yy + 3} q0,-3 3,-3 H${x0 + (k + 1) * gw - 4} q3,0 3,3 V${f.y0} Z` : `M${x0 + k * gw + 1},${f.y0} h${gw - 2} v${-Math.max(1, h)} h${-(gw - 2)} Z`;
      el('path', { d: p, fill: s.color }, f.svg);
    });
    const lab = el('text', { x: cx, y: f.y0 + 15, 'text-anchor': 'middle', fill: C.mute, 'font-size': 11 }, f.svg);
    axisLabel(lab, c, slot, 2);
    const hit = el('rect', { x: cx - slot / 2, y: f.y1, width: slot, height: f.y0 - f.y1, fill: 'transparent' }, f.svg);
    hit.addEventListener('mousemove', e => showTip(e, `<b>${c}</b>` + series.map(s => `<br><i class="sw" style="background:${s.color}"></i>${s.name}: ${fmtv(s.values[i])}`).join('')));
    hit.addEventListener('mouseleave', hideTip);
  });
  axisLabels(f, null, yLabel);
  legend(host, series.map(s => ({ label: s.name, color: s.color })));
  attachExport(host, f.svg, cats.map((c, i) => Object.fromEntries([['category', c], ...series.map(s => [s.name, s.values[i]])])));
  return f;
}

// ---------- scatter ----------
export function scatter(host, pts, { height = 280, xLabel, yLabel, xMax, yMax, xMin = 0, yMin = 0, fmtx = fmt, fmty = fmt, tipFmt, legendItems, onClick } = {}) {
  if (!pts.length) return empty(host);
  const f = frame(host, { height, bottom: 40 });
  const xs = niceTicks(xMin, xMax ?? (Math.max(...pts.map(p => p.x)) * 1.05 || 1), 5), ys = niceTicks(yMin, yMax ?? (Math.max(...pts.map(p => p.y)) * 1.08 || 1), 4);
  const xa = xs[0], xb = xs[xs.length - 1], ya = ys[0], yb = ys[ys.length - 1];
  const x = v => f.x0 + (v - xa) / (xb - xa) * (f.x1 - f.x0), y = v => f.y0 - (v - ya) / (yb - ya) * (f.y0 - f.y1);
  axisY(f, ys, y, fmty);
  for (const v of xs) el('text', { x: x(v), y: f.y0 + 16, 'text-anchor': 'middle', fill: C.faint, 'font-size': 11 }, f.svg).textContent = fmtx(v);
  for (const p of pts) {
    const c = el('circle', { cx: x(p.x), cy: y(p.y), r: p.r || 5, fill: p.color || C.series[0], stroke: C.surface, 'stroke-width': 2 }, f.svg);
    if (p.label && p.showLabel) el('text', { x: x(p.x) + 8, y: y(p.y) - 6, fill: C.mute, 'font-size': 11 }, f.svg).textContent = p.label;
    const hit = el('circle', { cx: x(p.x), cy: y(p.y), r: 11, fill: 'transparent', style: onClick ? 'cursor:pointer' : '' }, f.svg);
    hit.addEventListener('mousemove', e => { c.setAttribute('r', (p.r || 5) + 2); showTip(e, tipFmt ? tipFmt(p) : `<b>${p.label || ''}</b><br>${fmtx(p.x)}, ${fmty(p.y)}`); });
    hit.addEventListener('mouseleave', () => { c.setAttribute('r', p.r || 5); hideTip(); });
    if (onClick) hit.addEventListener('click', () => onClick(p));
  }
  axisLabels(f, xLabel, yLabel);
  if (legendItems) legend(host, legendItems);
  attachExport(host, f.svg, pts.map(p => ({ label: p.label, x: p.x, y: p.y })));
  return f;
}

// ---------- line / step chart over time (minutes) ----------
export function lines(host, series, { height = 250, xMax = 360, yLabel, xLabel = 'minutes from start', fmty = fmt, step = true, markers = [], yMax } = {}) {
  if (!series.length || !series.some(s => s.points.length)) return empty(host);
  const f = frame(host, { height, bottom: 36 });
  const hi = yMax ?? (Math.max(...series.flatMap(s => s.points.map(p => p[1])), 0) * 1.08 || 1);
  const ys = niceTicks(0, hi, 4, series.every(s => s.points.every(p => Number.isInteger(p[1]))) ? 1 : 0), top = ys[ys.length - 1];
  const x = v => f.x0 + Math.min(v, xMax) / xMax * (f.x1 - f.x0), y = v => f.y0 - v / top * (f.y0 - f.y1);
  axisY(f, ys, y, fmty);
  for (const v of timeTicks(xMax, f.x1 - f.x0)) el('text', { x: Math.min(x(v), f.W - 23), y: f.y0 + 16, 'text-anchor': 'middle', fill: C.faint, 'font-size': 11 }, f.svg).textContent = tmin(v).replace('none in 6 h', 'T+06:00');
  for (const m of markers) {
    el('line', { x1: x(m.t), x2: x(m.t), y1: f.y1, y2: f.y0, stroke: m.color || C.mute, 'stroke-dasharray': '3 4' }, f.svg);
    el('text', { x: x(m.t) + 4, y: f.y1 + 10, fill: m.color || C.mute, 'font-size': 11 }, f.svg).textContent = m.label;
  }
  const endLabels = [];
  for (const s of series) {
    if (!s.points.length) continue;
    let d = '', prev = null;
    const pts = [...s.points].sort((a, b) => a[0] - b[0]);
    for (const [t, v] of pts) {
      if (prev === null) d += `M${x(0)},${y(step ? 0 : v)}` + (step ? ` H${x(t)} V${y(v)}` : ` L${x(t)},${y(v)}`);
      else d += step ? ` H${x(t)} V${y(v)}` : ` L${x(t)},${y(v)}`;
      prev = v;
    }
    d += ` H${x(xMax)}`;
    el('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-dasharray': s.dash ? '5 4' : null, 'stroke-linejoin': 'round' }, f.svg);
    const last = pts[pts.length - 1];
    if (series.length <= 4 && s.label) endLabels.push({ text: s.label, x: x(last[0]), y: y(last[1]) - 6, color: s.color });
  }
  // end-of-line labels: inside the plot, right-aligned when near the edge, never on top of each other
  endLabels.sort((a, b) => a.y - b.y);
  const usedY = [];
  for (const L of endLabels) {
    let ly = Math.max(f.y1 + 11, Math.min(f.y0 - 4, L.y));
    for (let k = 0; k < 8 && usedY.some(u => Math.abs(u - ly) < 13); k++) ly = ly - 13 >= f.y1 + 11 && k < 4 ? ly - 13 : Math.max(...usedY) + 13;   // stack upwards, off the line
    usedY.push(ly);
    const nearEdge = L.x + 6 + L.text.length * 6 > f.x1;
    el('text', { x: nearEdge ? f.x1 - 2 : L.x + 6, y: ly, fill: C.mute, 'font-size': 11, 'text-anchor': nearEdge ? 'end' : 'start' }, f.svg).textContent = L.text;
  }
  // crosshair
  const cross = el('line', { y1: f.y1, y2: f.y0, stroke: C.mute, 'stroke-width': 1, visibility: 'hidden' }, f.svg);
  const hit = el('rect', { x: f.x0, y: f.y1, width: f.x1 - f.x0, height: f.y0 - f.y1, fill: 'transparent' }, f.svg);
  hit.addEventListener('mousemove', e => {
    const box = f.svg.getBoundingClientRect(), px = (e.clientX - box.left) * f.W / box.width;
    const t = Math.max(0, Math.min(xMax, (px - f.x0) / (f.x1 - f.x0) * xMax));
    cross.setAttribute('x1', x(t)); cross.setAttribute('x2', x(t)); cross.setAttribute('visibility', 'visible');
    const val = s => { let v = 0; for (const [tt, vv] of [...s.points].sort((a, b) => a[0] - b[0])) { if (tt <= t) v = vv; } return v; };
    showTip(e, `<b>${tmin(t)}</b>` + series.map(s => `<br><i class="sw" style="background:${s.color}"></i>${s.label}: ${fmty(val(s))}`).join(''));
  });
  hit.addEventListener('mouseleave', () => { cross.setAttribute('visibility', 'hidden'); hideTip(); });
  axisLabels(f, xLabel, yLabel);
  legend(host, series.map(s => ({ label: s.label, color: s.color, dash: s.dash })));
  attachExport(host, f.svg, series.flatMap(s => s.points.map(([t, v]) => ({ series: s.label, minute: t, value: v }))));
  return f;
}

// line chart with categorical x (number of fixes) - used for the baseline comparison
export function curves(host, xs, series, { height = 260, fmty = fmt, xLabel, yLabel, xPos } = {}) {
  const f = frame(host, { height, bottom: 36 });
  const hi = Math.max(...series.flatMap(s => s.values), 0) * 1.08 || 1;
  const ys = niceTicks(0, hi, 4), top = ys[ys.length - 1];
  // xPos: real positions (e.g. week numbers) so uneven gaps are drawn uneven; otherwise evenly spaced categories
  const pos = xPos || xs.map((_, i) => i), p0 = pos[0], p1 = pos[pos.length - 1];
  const x = i => f.x0 + 10 + (pos[i] - p0) / ((p1 - p0) || 1) * (f.x1 - f.x0 - 20), y = v => f.y0 - v / top * (f.y0 - f.y1);
  axisY(f, ys, y, fmty);
  xs.forEach((v, i) => el('text', { x: x(i), y: f.y0 + 16, 'text-anchor': 'middle', fill: C.faint, 'font-size': 11 }, f.svg).textContent = v);
  for (const s of series) {
    el('path', { d: s.values.map((v, i) => `${i ? 'L' : 'M'}${x(i)},${y(v)}`).join(' '), fill: 'none', stroke: s.color, 'stroke-width': s.bold ? 3 : 2, 'stroke-dasharray': s.dash ? '5 4' : null }, f.svg);
    s.values.forEach((v, i) => el('circle', { cx: x(i), cy: y(v), r: 4, fill: s.color, stroke: C.surface, 'stroke-width': 2 }, f.svg));
  }
  xs.forEach((v, i) => {
    const hit = el('rect', { x: x(i) - 20, y: f.y1, width: 40, height: f.y0 - f.y1, fill: 'transparent' }, f.svg);
    hit.addEventListener('mousemove', e => showTip(e, `<b>${xLabel || ''} ${v}</b>` + series.map(s => `<br><i class="sw" style="background:${s.color}"></i>${s.name}: ${fmty(s.values[i])}${s.notes?.[i] ? ` <span class="mute">(${s.notes[i]})</span>` : ''}`).join('')));
    hit.addEventListener('mouseleave', hideTip);
  });
  axisLabels(f, xLabel, yLabel);
  legend(host, series.map(s => ({ label: s.name, color: s.color, dash: s.dash })));
  attachExport(host, f.svg, xs.map((v, i) => Object.fromEntries([['x', v], ...series.map(s => [s.name, s.values[i]])])));
  return f;
}

export function empty(host, text = 'No data for this chart yet.') {
  host.innerHTML = `<div class="chart-empty">${text}</div>`;
}

// export buttons: a small row under the chart
function attachExport(host, svg, rows) {
  const card = host.closest('.chart-card');
  if (!card) return;
  let bar = card.querySelector('.chart-export');
  if (!bar) { bar = document.createElement('div'); bar.className = 'chart-export'; card.appendChild(bar); }
  const name = (card.querySelector('h3')?.textContent || 'chart').toLowerCase().replace(/[^a-z0-9]+/g, '-');
  bar.innerHTML = '<button class="linkbtn" data-x="csv">Download data (CSV)</button><button class="linkbtn" data-x="svg">Download image (SVG)</button>';
  bar.querySelector('[data-x=csv]').onclick = () => {
    const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
    const csv = [cols.join(','), ...rows.map(r => cols.map(c => JSON.stringify(r[c] ?? '')).join(','))].join('\n');
    download(new Blob([csv], { type: 'text/csv' }), name + '.csv');
  };
  bar.querySelector('[data-x=svg]').onclick = () => {
    const clone = svg.cloneNode(true); clone.setAttribute('xmlns', NS); clone.setAttribute('style', 'background:#12225E;font-family:sans-serif');
    download(new Blob([clone.outerHTML], { type: 'image/svg+xml' }), name + '.svg');
  };
}
export function download(blob, name) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
