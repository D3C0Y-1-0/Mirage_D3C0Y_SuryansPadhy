// 2D network map of the modelled city: the same layout the 3D twin uses (x, z from /api/graph).
// Used by Services, Attack simulation, Response and Graphs. Recolours in place (cheap enough to animate).
import { COLORS as C } from './charts.js';
const NS = 'http://www.w3.org/2000/svg';
const el = (tag, attrs = {}, parent) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v); if (parent) parent.appendChild(n); return n; };

export function netmap(host, graph, opts = {}) {
  const { height = 420, onClick, showDeps = true, labels = 'smart' } = opts;
  host.innerHTML = '';
  host.classList.add('netmap');
  const W = Math.max(320, host.clientWidth || 640), H = height, pad = 34;
  const xs = graph.assets.map(a => a.x), zs = graph.assets.map(a => a.z);
  const minX = Math.min(...xs), maxX = Math.max(...xs), minZ = Math.min(...zs), maxZ = Math.max(...zs);
  const s = Math.min((W - 2 * pad) / ((maxX - minX) || 1), (H - 2 * pad) / ((maxZ - minZ) || 1));
  const P = a => [W / 2 + (a.x - (minX + maxX) / 2) * s, H / 2 + (a.z - (minZ + maxZ) / 2) * s];
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', height: H, role: 'img', 'aria-label': 'Network map of the modelled city' }, host);
  const byId = Object.fromEntries(graph.assets.map(a => [a.id, a]));

  // sector pads (from asset_metadata), or zone groups
  const groupKey = a => a.sector || a.zone;
  const groups = {};
  for (const a of graph.assets) (groups[groupKey(a)] ||= []).push(a);
  const gLayer = el('g', {}, svg), groupBoxes = [];
  for (const [name, list] of Object.entries(groups)) {
    const ps = list.map(P), x0 = Math.min(...ps.map(p => p[0])) - 18, x1 = Math.max(...ps.map(p => p[0])) + 18;
    const y0 = Math.min(...ps.map(p => p[1])) - 18, y1 = Math.max(...ps.map(p => p[1])) + 18;
    el('rect', { x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 10, fill: 'rgba(26,44,114,.35)', stroke: 'rgba(43,61,134,.9)' }, gLayer);
    el('text', { x: x0 + 8, y: y1 - 7, fill: C.faint, 'font-size': 11, 'font-weight': 600 }, gLayer).textContent = name;
    groupBoxes.push({ x0: x0 + 6, x1: x0 + 10 + name.length * 6.2, y0: y1 - 19, y1: y1 - 3 });
  }
  const linkLayer = el('g', {}, svg), pathLayer = el('g', {}, svg), nodeLayer = el('g', {}, svg), labelLayer = el('g', {}, svg);
  const linkEls = [];
  for (const l of graph.links) {
    if (!l.attack_path && !showDeps) continue;
    const [x1, y1] = P(byId[l.src]), [x2, y2] = P(byId[l.dst]);
    const ln = el('line', { x1, y1, x2, y2, stroke: l.attack_path ? 'rgba(169,180,218,.38)' : 'rgba(169,180,218,.22)', 'stroke-width': 1, 'stroke-dasharray': l.attack_path ? null : '3 4' }, linkLayer);
    linkEls.push({ l, ln });
  }
  const nodes = {};
  for (const a of graph.assets) {
    const [x, y] = P(a), r = 4 + a.criticality * 1.3;
    const halo = el('circle', { cx: x, cy: y, r: r + 6, fill: 'none', stroke: 'none', 'stroke-width': 2 }, nodeLayer);
    const halo2 = el('circle', { cx: x, cy: y, r: r + 10, fill: 'none', stroke: 'none', 'stroke-width': 2.5, 'data-ring2': a.id }, nodeLayer);
    const c = el('circle', { cx: x, cy: y, r, fill: C.surface, stroke: '#FFFFFF', 'stroke-width': 1.5, 'data-id': a.id, class: 'nd' }, nodeLayer);
    const t = el('text', { x, y: y - r - 6, 'text-anchor': 'middle', fill: C.mute, 'font-size': 11, class: 'nlabel' }, labelLayer);
    t.textContent = a.name.length > 26 ? a.name.slice(0, 25) + '…' : a.name;
    const hit = el('circle', { cx: x, cy: y, r: r + 8, fill: 'transparent', tabindex: 0, role: 'button', 'aria-label': a.name, style: 'cursor:pointer' }, nodeLayer);
    nodes[a.id] = { a, c, halo, halo2, t, x, y, r };
    hit.addEventListener('mousemove', e => tipFor(e, a));
    hit.addEventListener('mouseleave', () => tipHide());
    if (onClick) { hit.addEventListener('click', () => onClick(a)); hit.addEventListener('keydown', e => { if (e.key === 'Enter') onClick(a); }); }
  }
  let lastState = {};
  function tipFor(e, a) {
    const st = lastState[a.id] || {};
    const tip = document.querySelector('.chart-tip') || Object.assign(document.body.appendChild(document.createElement('div')), { className: 'chart-tip' });
    tip.innerHTML = `<b>${a.name}</b><br>${a.type.replace(/_/g, ' ')}, ${a.sector || a.zone}<br>criticality ${a.criticality}, risk ${a.risk}` + (st.tip ? `<br>${st.tip}` : '');
    tip.style.display = 'block'; tip.style.left = (e.clientX + 14) + 'px'; tip.style.top = (e.clientY + 14) + 'px';
  }
  function tipHide() { const t = document.querySelector('.chart-tip'); if (t) t.style.display = 'none'; }

  // state: { [assetId]: {fill, stroke, ring, ring2, label(bool), priority, tip} }
  // paths: [{src, dst, color, width, offset, frac (0..1, partial edge drawn from src), arrow, step (hop number)}]
  // Labels are placed above, then below, then hidden if they would overlap a higher-priority label.
  function update(state = {}, paths = []) {
    lastState = state;
    const want = [];
    for (const [id, n] of Object.entries(nodes)) {
      const st = state[id] || {};
      n.c.setAttribute('fill', st.fill || C.surface);
      n.c.setAttribute('stroke', st.stroke || '#FFFFFF');
      n.halo.setAttribute('stroke', st.ring || 'none');
      n.halo.setAttribute('stroke-dasharray', st.ringDash ? '3 3' : '');
      n.halo2.setAttribute('stroke', st.ring2 || 'none');
      const show = labels === 'all' || st.label || (labels === 'smart' && graph.assets.length <= 14);
      n.t.setAttribute('fill', st.labelColor || C.mute);
      if (show) want.push([st.priority ?? (st.label ? 1 : 0), n]); else n.t.setAttribute('visibility', 'hidden');
    }
    // greedy label placement, highest priority first
    want.sort((p, q) => q[0] - p[0] || q[1].a.criticality - p[1].a.criticality);
    const boxes = [...groupBoxes, ...Object.values(nodes).map(n => ({ x0: n.x - n.r, x1: n.x + n.r, y0: n.y - n.r, y1: n.y + n.r }))];
    const hit = b => boxes.some(o => b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0);
    for (const [, n] of want) {
      const w = n.t.textContent.length * 6.1 + 4, placed = [[n.y - n.r - 6, 'above'], [n.y + n.r + 15, 'below']].find(([y]) => {
        const b = { x0: n.x - w / 2, x1: n.x + w / 2, y0: y - 11, y1: y + 2 };
        if (b.x0 < 0 || b.x1 > W || b.y0 < 0 || b.y1 > H || hit(b)) return false;
        boxes.push(b); return true;
      });
      if (placed) { n.t.setAttribute('y', placed[0]); n.t.setAttribute('visibility', 'visible'); }
      else n.t.setAttribute('visibility', 'hidden');
    }
    pathLayer.innerHTML = '';
    for (const p of paths) {
      const a = nodes[p.src], b = nodes[p.dst];
      if (!a || !b) continue;
      const f = Math.max(0, Math.min(1, p.frac ?? 1));
      if (f <= 0) continue;
      const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, off = p.offset || 0;
      const ox = -dy / len * off, oy = dx / len * off;
      const ex = a.x + dx * f + ox, ey = a.y + dy * f + oy;
      el('line', { x1: a.x + ox, y1: a.y + oy, x2: ex, y2: ey, stroke: p.color, 'stroke-width': p.width || 2.5, 'stroke-linecap': 'round', opacity: p.opacity ?? 1, 'data-src': p.src, 'data-dst': p.dst, 'data-frac': f.toFixed(3), class: 'np' }, pathLayer);
      if (f < 1) el('circle', { cx: ex, cy: ey, r: 3.5, fill: p.color }, pathLayer);           // the attack in flight
      if (p.arrow !== false && f >= 1) {   // small arrowhead near the target
        const k = Math.max(0, 1 - (b.r + 5) / len), ax = a.x + dx * k + ox, ay = a.y + dy * k + oy, ang = Math.atan2(dy, dx);
        el('path', { d: `M${ax},${ay} l${-8 * Math.cos(ang - .45)},${-8 * Math.sin(ang - .45)} M${ax},${ay} l${-8 * Math.cos(ang + .45)},${-8 * Math.sin(ang + .45)}`, stroke: p.color, 'stroke-width': 2, fill: 'none', 'stroke-linecap': 'round' }, pathLayer);
      }
      if (p.step != null) {   // hop number at the midpoint
        const mx = a.x + dx * .5 + ox, my = a.y + dy * .5 + oy;
        el('circle', { cx: mx, cy: my, r: 8, fill: p.color }, pathLayer);
        const tt = el('text', { x: mx, y: my + 3.5, 'text-anchor': 'middle', 'font-size': 10, 'font-weight': 700, fill: '#0B1020' }, pathLayer);
        tt.textContent = p.step;
      }
    }
  }
  update();
  return { update, nodes, svg };
}
