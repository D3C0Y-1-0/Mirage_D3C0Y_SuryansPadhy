// Recovery (after containment) and the assumptions register.
// Everything is computed by the backend (/api/recovery, /api/assumptions); this page only draws it.
import { get, h, fmt, table, loading, errorBox } from './core.js';
import { COLORS as C } from './charts.js';

const kpi = (v, l, s, cls = '') => `<div class="kpi"><div class="v ${cls}">${v}</div><div class="l">${l}</div><div class="s">${s}</div></div>`;
// recovery runs past the 6-hour window, so times are never capped here (the shared tmin() is); hours can pass 24
const tt = m => { m = Math.round(m); return `T+${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`; };   // hours can pass 24 (T+29:15)
const hrs = m => m == null ? 'never' : tt(m);
const ph = v => v == null ? 'n/a' : v >= 1e6 ? `${(v / 1e6).toFixed(2)}M` : v >= 1e3 ? `${Math.round(v / 1e3)}k` : String(v);
const CREW = ['#8E9DE0', '#FFFFFF', '#C9B8FF', '#7FD1C1', '#F2B84B', '#FF9FCB', '#9FD4FF', '#D8E0FF'];

export async function recovery(root) {
  loading(root, 'Planning the recovery');
  let an, first;
  try { [an, first] = await Promise.all([get('/api/analytics'), get('/api/recovery')]); } catch (e) { return errorBox(root, e); }
  const entries = an.per_entry.slice().sort((a, b) => b.harm - a.harm);
  const st = { entry: first.entry, crews: 2, backups: true };
  root.innerHTML = `
    <div class="head"><div><h2>Recovery</h2><p class="lede">The rest of the site stops at the 6-hour window and assumes a lost service stays lost. This page covers what comes after: once the attacker is cut off, which systems are restored first, by how many crews, and when each essential service is back.</p></div></div>
    <p class="note warn" style="margin-bottom:16px"><b>Planning model on simulated infrastructure.</b> Restore times are stated assumptions (listed at the bottom and on the Assumptions page), not measurements from a real utility.</p>
    <div class="sheet" style="margin-bottom:16px"><div class="rcv-ctl">
      <label>Attack <select id="rEntry">${entries.map(e => `<option value="${h(e.id)}" ${e.id === st.entry ? 'selected' : ''}>${h(e.name)}${e.id === first.entry ? ' (worst case)' : ''}</option>`).join('')}</select></label>
      <label>Crews <select id="rCrews">${[1, 2, 3, 4, 6].map(c => `<option ${c === 2 ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
      <label class="chk"><input type="checkbox" id="rBack" checked> Tested offline backups exist</label>
    </div></div>
    <div id="rBody"></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>What if we had more crews, or no backups?</h3><p class="sub">Same attack. Last service back, every system back, and total people × hours without a service (including after the 6-hour window).</p><div id="rGrid"></div></div>
      <div class="sheet"><h3>Restore time per kind of system</h3><p class="sub" id="rBasis"></p><div id="rTimes"></div></div>
    </div>`;
  const draw = async () => {
    const body = root.querySelector('#rBody');
    body.innerHTML = '<div class="loading"><span class="spin"></span>Scheduling crews</div>';
    let r, base;
    try {
      [r, base] = await Promise.all([get(`/api/recovery?entry=${encodeURIComponent(st.entry)}&crews=${st.crews}&backups=${st.backups}`), get(`/api/recovery?entry=${encodeURIComponent(st.entry)}`)]);
    } catch (e) { return errorBox(body, e); }
    const cutoff = Math.max(...r.jobs.map(j => j.ready_at), 0);
    const lastSvc = r.services.filter(s => s.restored_at != null).sort((a, b) => b.restored_at - a.restored_at)[0];
    let finding = '';
    if (lastSvc) {
      const blockers = r.jobs.filter(j => j.helps.includes(lastSvc.name));
      const rdy = Math.max(...blockers.map(j => j.ready_at), 0), byNet = blockers.some(j => j.ready_by === 'network' && j.ready_at === rdy);
      const waitShare = (rdy - lastSvc.failed_at) / Math.max(1, lastSvc.restored_at - lastSvc.failed_at);
      finding = `${lastSvc.name} is the last service back, at ${tt(lastSvc.restored_at)}. Cleaning the systems it needs could not start before ${tt(rdy)}, when the attacker was cut off from them`
        + (byNet ? ': nothing on that path is monitored, so it waited for the network-wide isolation' : '')
        + (waitShare > .4 ? `. ${Math.round(100 * waitShare)}% of this outage is waiting for containment, not repair, so earlier detection shortens recovery more than more crews do.` : '.');
    }
    body.innerHTML = `
      <div class="kpis">
        ${kpi(tt(cutoff), 'Attacker cut off from every system', `detected ${hrs(r.detected_at)}`)}
        ${kpi(hrs(r.last_service_back_at), 'Last essential service back', r.services.length ? `${r.services.length} service${r.services.length === 1 ? '' : 's'} were lost` : 'no service was lost', 'pink')}
        ${kpi(hrs(r.all_restored_at), 'Every system restored', `${r.systems_hit} systems, ${r.crews} crew${r.crews === 1 ? '' : 's'}`)}
        ${kpi(ph(r.people_hours), 'People × hours without a service', `${ph(r.people_hours_after_window)} of it after the 6-hour window`)}
      </div>
      ${r.never_contained.length ? `<p class="note warn" style="margin-top:12px">Never cut off in the model (no detection reached them): ${r.never_contained.map(h).join(', ')}.</p>` : ''}
      ${finding ? `<p class="note" style="margin-top:12px">${h(finding)}</p>` : ''}
      <div class="chart-card" style="margin-top:16px"><h3>Restoration schedule</h3><p class="sub">Each row is a compromised system. Thin pink: attacker still there. Dotted: cut off, waiting for a crew. Bar: a crew restoring it. Lines: when each service comes back.</p><div id="rGantt"></div></div>
      <div class="sheet" style="margin-top:16px"><h3>Essential services</h3><div id="rSvc"></div></div>`;
    gantt(body.querySelector('#rGantt'), r);
    table(body.querySelector('#rSvc'), r.services, [
      { key: 'name', label: 'Service' }, { key: 'population', label: 'People', num: true, render: s => fmt(s.population) },
      { key: 'failed_at', label: 'Lost at', num: true, render: s => tt(s.failed_at) },
      { key: 'restored_at', label: 'Back at', num: true, render: s => hrs(s.restored_at) },
      { key: 'outage_hours', label: 'Outage', num: true, render: s => s.outage_hours == null ? 'not restored' : `${s.outage_hours} h` },
      { key: 'people_hours', label: 'People × hours', num: true, render: s => ph(s.people_hours) }], { sortKey: 'failed_at', desc: false, empty: 'No essential service was lost in this attack.' });
    table(root.querySelector('#rGrid'), base.grid, [
      { key: 'crews', label: 'Crews', num: true }, { key: 'backups', label: 'Backups', render: g => g.backups ? 'tested' : '<span class="tag warn">none</span>' },
      { key: 'last_service_back_at', label: 'Last service back', num: true, render: g => hrs(g.last_service_back_at) },
      { key: 'all_restored_at', label: 'All systems back', num: true, render: g => hrs(g.all_restored_at) },
      { key: 'people_hours', label: 'People × hours', num: true, render: g => ph(g.people_hours) }], { sortKey: null });
    root.querySelector('#rBasis').textContent = base.basis + ` Without a tested backup: ×${base.no_backup_factor}. ATT&CK for ICS mitigations for this stage: ${base.attack_mitigations.map(m => `${m.id} ${m.name}`).join(', ')}.`;
    const used = new Set(r.jobs.map(j => j.type));
    table(root.querySelector('#rTimes'), Object.entries(base.restore_hours).filter(([t]) => used.has(t)).map(([t, v]) => ({ t, v })).concat([{ t: 'anything else', v: base.default_hours }]), [
      { key: 't', label: 'Kind of system (in this attack)', render: x => h(x.t.replace(/_/g, ' ')) }, { key: 'v', label: 'Hours with backup', num: true }], { sortKey: null });
  };
  root.querySelector('#rEntry').onchange = e => { st.entry = e.target.value; draw(); };
  root.querySelector('#rCrews').onchange = e => { st.crews = +e.target.value; draw(); };
  root.querySelector('#rBack').onchange = e => { st.backups = e.target.checked; draw(); };
  draw();
}

function gantt(host, r) {
  if (!r.jobs.length) { host.innerHTML = '<div class="chart-empty">Nothing to restore.</div>'; return; }
  const W = Math.max(320, host.clientWidth || 640), narrow = W < 560, left = narrow ? 110 : 210, right = 14, rowH = 26, top = 24;
  const H = top + r.jobs.length * rowH + 34;
  const tMax = Math.max(...r.jobs.map(j => j.end), 360) * 1.02;
  const x = t => left + t / tMax * (W - left - right);
  const step = tMax / 60 > 24 ? 360 : tMax / 60 > 12 ? 180 : 120;
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Restoration schedule">`;
  for (let t = 0; t <= tMax; t += step) s += `<line x1="${x(t)}" x2="${x(t)}" y1="${top - 6}" y2="${H - 30}" stroke="${C.grid}"/><text x="${Math.min(x(t), W - 24)}" y="${H - 14}" text-anchor="middle" fill="${C.faint}" font-size="11">${tt(t)}</text>`;
  s += `<line x1="${x(360)}" x2="${x(360)}" y1="${top - 10}" y2="${H - 30}" stroke="${C.mute}" stroke-dasharray="2 3"/><text x="${x(360) + 4}" y="${top - 12}" fill="${C.mute}" font-size="10">end of the 6-hour window</text>`;
  r.jobs.slice().sort((a, b) => a.compromised_at - b.compromised_at).forEach((j, i) => {
    const y = top + i * rowH + rowH / 2, mc = narrow ? 15 : 30;
    const nm = j.name.length > mc ? j.name.slice(0, mc - 1) + '…' : j.name;
    s += `<text x="${left - 8}" y="${y + 4}" text-anchor="end" fill="${C.mute}" font-size="12"><title>${h(j.name)}</title>${h(nm)}</text>`;
    s += `<line x1="${x(j.compromised_at)}" x2="${x(j.ready_at)}" y1="${y}" y2="${y}" stroke="${C.pink}" stroke-width="2"/>`;
    if (j.start > j.ready_at) s += `<line x1="${x(j.ready_at)}" x2="${x(j.start)}" y1="${y}" y2="${y}" stroke="${C.mute}" stroke-width="1.5" stroke-dasharray="2 3"/>`;
    s += `<rect x="${x(j.start)}" y="${y - 8}" width="${Math.max(2, x(j.end) - x(j.start))}" height="16" rx="4" fill="${CREW[(j.crew - 1) % CREW.length]}"><title>${h(j.name)}: crew ${j.crew}, ${tt(j.start)} to ${tt(j.end)} (${j.hours} h)${j.helps.length ? '. Needed by ' + j.helps.join(', ') : ''}</title></rect>`;
    if (!narrow && x(j.end) - x(j.start) > 52) s += `<text x="${x(j.start) + 6}" y="${y + 4}" fill="#0B1020" font-size="10" font-weight="700">crew ${j.crew}</text>`;
  });
  r.services.filter(v => v.restored_at != null).forEach((v, i) => {
    s += `<line x1="${x(v.restored_at)}" x2="${x(v.restored_at)}" y1="${top - 6}" y2="${H - 30}" stroke="${C.series[0]}" stroke-width="1.5"><title>${h(v.name)} back at ${tt(v.restored_at)}</title></line>`;
  });
  host.innerHTML = s + '</svg>';
  const back = r.services.filter(v => v.restored_at != null);
  if (back.length) host.insertAdjacentHTML('beforeend', `<p class="faint" style="font-size:12px;margin-top:6px">Service lines: ${back.map(v => `${h(v.name)} ${tt(v.restored_at)}`).join(' · ')}</p>`);
}

export async function assumptions(root) {
  loading(root, 'Loading the assumptions');
  let a;
  try { a = await get('/api/assumptions'); } catch (e) { return errorBox(root, e); }
  const val = v => typeof v === 'object' ? Object.entries(v).map(([k, x]) => `${h(k.replace(/_/g, ' '))} ${h(x)}`).join(', ') : h(v);
  root.innerHTML = `
    <div class="head"><div><h2>Assumptions register</h2><p class="lede">Every number the model uses, what it means, where it comes from and how it was tested. If a judge asks "where does that number come from?", the answer is on this page.</p></div></div>
    <p class="note warn" style="margin-bottom:16px">${h(a.note)}</p>
    <div class="sheet"><div id="aTable"></div></div>`;
  table(root.querySelector('#aTable'), a.rows, [
    { key: 'name', label: 'Assumption', render: r => `<code class="c">${h(r.name)}</code>` },
    { key: 'value', label: 'Value', render: r => `<span class="wrapv">${val(r.value)}</span>` },
    { key: 'meaning', label: 'What it means' }, { key: 'basis', label: 'Basis (honest)' }, { key: 'tested', label: 'How it was tested' }], { sortKey: null });
}
