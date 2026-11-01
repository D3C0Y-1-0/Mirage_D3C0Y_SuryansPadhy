// Overview, Asset inventory, Services and dependencies, Vulnerability intelligence, Risk register.
import { api, get, h, fmt, tmin, pm, pct, table, openDrawer, closeDrawer, loading, errorBox, store, withTwin, toast, atkBadge, atkColor } from './core.js';
import { bars, scatter, curves, grouped, COLORS as C, empty } from './charts.js';
import { netmap } from './netmap.js';

const riskBand = r => r >= 30 ? 'Very high' : r >= 15 ? 'High' : r >= 5 ? 'Medium' : 'Low';
const yesno = b => b ? 'Yes' : 'No';
const ruleText = r => h(r).replace(/\b(AND|OR|NOT)\b/g, '<b>$1</b>');

// ======================================= OVERVIEW =======================================
export async function overview(root) {
  loading(root, 'Loading the command centre');
  try {
    const [g, inv, ov, an] = await Promise.all([get('/api/graph'), get('/api/assets'), get('/api/overview'), get('/api/analytics')]);
    const A = inv.assets, sc = store.scenario;
    const crit = A.filter(a => a.criticality >= 4).length, high = A.filter(a => a.risk >= 15).length;
    const cves = new Set(A.flatMap(a => a.cves)).size, kev = A.reduce((s, a) => s + a.kev_count, 0);
    const active = sc ? sc.result.attackers.filter(a => a.status === 'active').length : 0;
    const totalRisk = Math.round(A.reduce((s, a) => s + a.risk, 0) / A.length);
    const worst = await api('/api/simulate', { entry_points: [ov.worst_entry] });
    const name = id => g.assets.find(a => a.id === id)?.name || id;
    root.innerHTML = `
      <div class="head"><div><h2>Command centre</h2><p class="lede">The state of the modelled city right now, and what the worst simulated attack would do to it. Simulated data, no live telemetry.</p></div>
        <div class="row"><a class="btn primary" href="#/twin">Open the digital twin</a><a class="btn" href="#/simulate">Run an attack simulation</a></div></div>
      <div class="kpis">
        ${kpi(A.length, 'Systems modelled', `${g.links.length} connections, ${g.services.length} services`)}
        ${kpi(crit, 'Critical systems', 'criticality 4 or 5 of 5')}
        ${kpi(high, 'High-risk systems', 'risk score 15 or more')}
        ${kpi(cves, 'Known vulnerabilities', `${kev} on CISA's exploited list`)}
        ${kpi(active, 'Simulated incidents', sc ? `in "${h(sc.title)}"` : 'none running', active ? 'pink' : '')}
        ${kpi(totalRisk, 'Average risk score', 'mean of per-system scores, 0-100')}
        ${kpi(fmt(ov.expected_harm), 'Likely harm, all ways in', 'people × min; every way in, weighted by likelihood, so it can exceed one worst attack')}
        ${kpi(tmin(ov.first_failure_min), 'First service failure', `worst case via ${h(name(ov.worst_entry))}`, 'pink')}
      </div>
      <div class="grid g21" style="margin-top:16px">
        <div class="chart-card"><h3>Highest-risk systems</h3><p class="sub">Risk combines how breakable a system is, how exposed it is and what it takes down. Click a bar to open the system.</p><div id="ovTop"></div></div>
        <div class="chart-card"><h3>Security posture</h3><p class="sub">Counts from the inventory. A system can appear in several rows.</p><div id="ovPosture"></div></div>
      </div>
      <div class="grid g2" style="margin-top:16px">
        <div class="sheet"><h3>Ways in, ranked by harm</h3><p class="sub">Each entry point simulated on its own. Harm in people × minutes over 6 hours.</p><div id="ovEntries"></div></div>
        <div class="sheet"><h3>Services under the worst attack</h3><p class="sub">From ${h(name(ov.worst_entry))}, with detection and isolation switched on.</p><div id="ovSvc"></div></div>
      </div>
      <div class="grid g2" style="margin-top:16px">
        <div class="sheet"><h3>Choke points</h3><p class="sub">Attack-path links used by the most entry points on their way to systems behind a service. Segmenting or monitoring these helps many attacks at once.</p><div id="ovChoke"></div></div>
        <div class="sheet"><h3>${sc ? 'Latest simulated events' : 'Worst-case attack, first events'}</h3><p class="sub">${sc ? `From "${h(sc.title)}". <a href="#/timeline">Full timeline</a>` : 'Run a scenario in Attack simulation to see your own.'}</p><div class="evlog" id="ovEv"></div></div>
      </div>`;
    const top = [...A].sort((a, b) => b.risk - a.risk).slice(0, 8);
    bars(root.querySelector('#ovTop'), top.map(a => ({ label: a.name, value: a.risk, id: a.id, color: a.is_entry ? C.series[1] : C.series[0] })),
      { horizontal: true, fmtv: v => v.toFixed(0), onClick: d => assetDrawer(d.id), tipFmt: d => `<b>${h(d.label)}</b><br>risk ${d.value}${A.find(a => a.id === d.id).is_entry ? '<br>a way in from outside' : ''}` });
    const posture = [['Internet-facing', A.filter(a => a.internet_facing).length], ['Vendor access', A.filter(a => a.vendor_access).length],
      ['Not monitored', A.filter(a => !a.monitored).length], ['Weak configuration', A.filter(a => a.config_flags.length).length],
      ['Known-exploited CVE', A.filter(a => a.kev_count).length], ['Needs downtime to patch', A.filter(a => a.cve_count && !a.patchable_without_downtime).length]];
    bars(root.querySelector('#ovPosture'), posture.map(([l, v]) => ({ label: l, value: v })), { horizontal: true, labelWidth: 150, fmtv: v => v.toFixed(0), max: A.length });
    table(root.querySelector('#ovEntries'), an.per_entry, [
      { key: 'name', label: 'Way in' }, { key: 'prob', label: 'Likelihood', num: true, render: r => `${Math.round(r.prob * 100)}%` },
      { key: 'harm', label: 'Harm', num: true, render: r => fmt(r.harm) }, { key: 'first_failure_min', label: 'First loss', num: true, render: r => tmin(r.first_failure_min), sort: r => -r.first_failure_min }],
      { sortKey: 'harm', onRow: r => { location.hash = `#/simulate?entry=${r.id}`; } });
    const sv = g.services.map(s => ({ ...s, fail: worst.failures[s.name] }));
    table(root.querySelector('#ovSvc'), sv, [
      { key: 'name', label: 'Service' }, { key: 'population', label: 'People', num: true, render: r => r.population.toLocaleString() },
      { key: 'fail', label: 'Lost at', num: true, render: r => r.fail != null && r.fail < 360 ? `<span class="pinkt">${tmin(r.fail)}</span>` : 'not lost', sort: r => -(r.fail ?? 999) }], { sortKey: 'fail' });
    root.querySelector('#ovChoke').innerHTML = an.choke_points.slice(0, 6).map(c => `<div class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)">
      <span>${h(c.src_name)} → ${h(c.dst_name)}</span><span class="tag white">${c.entries} way${c.entries > 1 ? 's' : ''} in</span></div>`).join('') || '<p class="mute">No shared links.</p>';
    const evs = sc ? sc.result.events.slice(-10).reverse() : worst.events.slice(0, 10);
    root.querySelector('#ovEv').innerHTML = evs.map(e => `<div><span class="t">${tmin(e.t)}</span>${e.attacker && e.attacker.length === 1 ? atkBadge(e.attacker) : '<span></span>'}<span class="${e.kind === 'service_down' ? 'pinkt' : ''}">${h(e.text)}</span></div>`).join('');
  } catch (e) { errorBox(root, e); }
}
const kpi = (v, l, s, cls = '') => `<div class="kpi"><div class="v ${cls}">${v}</div><div class="l">${l}</div><div class="s">${s}</div></div>`;

// ================================ ASSET DRAWER (shared) ================================
export async function assetDrawer(id) {
  const d = openDrawer('<div class="loading"><span class="spin"></span>Loading system</div>');
  try {
    const [a, inv] = await Promise.all([api(`/api/asset/${encodeURIComponent(id)}`), get('/api/assets')]);
    const row = inv.assets.find(x => x.id === id);
    d.innerHTML = `<button class="btn small x" id="drawerClose">Close</button>
      <h3>${h(a.name)}</h3>
      <p class="mute" style="margin-top:6px">${h(row.sector || row.zone_name)}, ${h(a.type.replace(/_/g, ' '))}${row.role ? `. ${h(row.role)}` : ''}</p>
      <div class="row" style="margin-top:14px">
        ${row.is_entry ? '<button class="btn small primary" id="dAttack">Simulate an attack from here</button>' : ''}
        <button class="btn small" id="dTwin">Show in the 3D twin</button>
      </div>
      <h4>Blast radius</h4><div id="dBlast"><button class="btn small" id="dBlastBtn">If this system is taken over, what follows?</button></div>
      <h4>Why it is at risk</h4><p class="note ${a.score.risk >= 15 ? 'pinkn' : ''}">${h(a.summary)}</p>
      <dl class="kv" style="margin-top:12px">
        <dt>Risk score</dt><dd>${a.score.risk} (${riskBand(a.score.risk)}). V ${a.score.V}, likelihood ${a.score.L}, impact ${a.score.impact}</dd>
        <dt>Criticality</dt><dd>${a.criticality} of 5</dd>
        <dt>Exposure</dt><dd>${a.exposure}${row.internet_facing ? ', internet-facing' : ''}${row.vendor_access ? ', vendor access' : ''}${row.is_entry ? `. Entry likelihood ${Math.round(row.entry_prob * 100)}%` : ''}</dd>
        <dt>Software</dt><dd>${h(a.software)} ${h(a.version)}${row.version_source ? `<br><span class="faint">${h(row.version_source)}</span>` : ''}</dd>
        ${row.mitre_asset_class ? `<dt>MITRE ICS asset class</dt><dd>${h(row.mitre_asset_class)}</dd>` : ''}
        ${row.layer ? `<dt>Network layer</dt><dd>${h(row.layer)}</dd>` : ''}
        <dt>Monitoring</dt><dd>${a.monitored ? 'Monitored: alarm 10 min after compromise' : 'Not monitored: noticed after about 4 hours'}</dd>
        <dt>Configuration</dt><dd>${a.config_flags.length ? a.config_flags.map(f => `<span class="tag warn">${h(f.replace(/_/g, ' '))}</span>`).join(' ') : 'No known weakness'}</dd>
        <dt>Patching</dt><dd>${a.patchable_without_downtime ? 'Can be patched live' : `Needs ${a.downtime_hours_to_patch} h downtime (maintenance window)`}${a.patch_outage_harm ? `<br><span class="pinkt">Patching without a window costs ${pm(a.patch_outage_harm)}</span>` : ''}</dd>
        <dt>Takes down alone</dt><dd>${a.breaks_alone.length ? a.breaks_alone.map(h).join(', ') : 'Nothing on its own'}</dd>
        <dt>Part of</dt><dd>${a.part_of.length ? a.part_of.map(h).join(', ') : 'No service rule'}</dd>
        <dt>Connected to</dt><dd>${a.neighbours.map(n => h(inv.assets.find(x => x.id === n)?.name || n)).join(', ') || 'None'}</dd>
      </dl>
      <h4>Vulnerabilities (${a.cves.length})</h4>
      ${a.cves.length ? `<div class="tablewrap"><table class="t"><thead><tr><th>CVE</th><th class="n">CVSS</th><th class="n">EPSS</th><th>KEV</th><th>Patch</th></tr></thead><tbody>
        ${a.cves.map(c => `<tr><td>${h(c.id)}${c.ics ? ' <span class="tag">ICS</span>' : ''}</td><td class="n">${c.cvss}</td><td class="n">${c.epss.toFixed(3)}</td><td>${c.kev ? '<span class="tag warn">Exploited</span>' : 'No'}</td><td>${c.patch_available ? 'Available' : 'None yet'}</td></tr>`).join('')}</tbody></table></div>` : '<p class="mute">No known CVEs. It can still be a way in through weak credentials or phishing.</p>'}
      <h4>Fixes for this system</h4>
      ${a.fixes.length ? a.fixes.map(f => `<div class="row" style="justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--line)"><span>${h(f.label)}</span><span class="tag">${h(f.type.replace('_', ' '))}</span></div>`).join('') + '<p class="faint" style="margin-top:8px;font-size:12px">See Fix optimiser for how much each one removes.</p>' : '<p class="mute">Nothing left to fix here.</p>'}`;
    d.querySelector('#drawerClose').onclick = closeDrawer;
    d.querySelector('#dAttack')?.addEventListener('click', () => { closeDrawer(); location.hash = `#/simulate?entry=${id}`; });
    d.querySelector('#dTwin').onclick = () => { closeDrawer(); withTwin(c => c.openCard(id)); };
    d.querySelector('#dBlastBtn').onclick = async () => {
      const out = d.querySelector('#dBlast'); out.innerHTML = '<span class="spin"></span> Simulating';
      try {
        const [free, det] = await Promise.all([api('/api/multi', { attackers: [{ id: 'A', entry: id }], detection: false }), api('/api/multi', { attackers: [{ id: 'A', entry: id }], detection: true })]);
        const reach = Object.entries(free.combined.first_by).filter(([x]) => x !== id).sort((p, q) => p[1].t - q[1].t);
        out.innerHTML = `<p class="note pinkn">With nobody stopping it: <b>${reach.length}</b> more systems within 6 h, ${free.combined.services.length} service${free.combined.services.length === 1 ? '' : 's'} lost, ${fmt(free.combined.harm)} people-min.
          With today's detection: ${det.combined.assets_lost - 1} more systems, ${fmt(det.combined.harm)} people-min.</p>
          <p class="mute" style="font-size:12px;margin-top:6px">Next to fall: ${reach.slice(0, 5).map(([x, v]) => `${h(inv.assets.find(a => a.id === x)?.name || x)} <span class="faint">${tmin(v.t)}</span>`).join(', ') || 'nothing (no onward attack path)'}${reach.length > 5 ? '…' : ''}</p>
          ${free.combined.services.length ? `<p class="mute" style="font-size:12px">Services: ${free.combined.services.map(s => `${h(s.service)} <span class="faint">${tmin(s.fail_at)}</span>`).join(', ')}</p>` : ''}`;
      } catch (e) { out.innerHTML = `<div class="err">${h(e.message)}</div>`; }
    };
  } catch (e) { d.innerHTML = `<button class="btn small x" onclick="document.getElementById('drawer').classList.remove('open')">Close</button><div class="err" style="margin-top:48px">${h(e.message)}</div>`; }
}

// ======================================= INVENTORY =======================================
export async function inventory(root) {
  loading(root, 'Loading the inventory');
  try {
    const inv = await get('/api/assets');
    const A = inv.assets;
    const opts = (vals) => [...new Set(vals)].filter(Boolean).sort().map(v => `<option>${h(v)}</option>`).join('');
    root.innerHTML = `
      <div class="head"><div><h2>Asset inventory</h2><p class="lede">${A.length} systems from <code class="c">assets.csv</code>, joined with their vulnerabilities, risk and the services they keep running. Click a row for the full record.</p></div>
        <div class="row"><button class="btn" id="exportInv">Download CSV</button></div></div>
      <div class="filters">
        <input class="f" id="q" placeholder="Search name, software, CVE" style="width:240px" aria-label="Search">
        <select class="f" id="fSector" aria-label="Sector"><option value="">All sectors</option>${opts(A.map(a => a.sector))}</select>
        <select class="f" id="fZone" aria-label="Zone"><option value="">All zones</option>${opts(A.map(a => a.zone_name))}</select>
        <select class="f" id="fType" aria-label="Type"><option value="">All types</option>${opts(A.map(a => a.type.replace(/_/g, ' ')))}</select>
        <select class="f" id="fCrit" aria-label="Criticality"><option value="">Any criticality</option><option value="5">5 only</option><option value="4">4 and up</option><option value="3">3 and up</option></select>
        <select class="f" id="fExp" aria-label="Exposure"><option value="">Any exposure</option><option value="internet">Internet-facing</option><option value="vendor">Vendor access</option><option value="internal">Internal only</option></select>
        <select class="f" id="fRisk" aria-label="Risk"><option value="">Any risk</option><option value="30">Very high (30+)</option><option value="15">High and up (15+)</option><option value="5">Medium and up (5+)</option></select>
        <span class="mute" id="count"></span>
      </div>
      <div id="invTable"></div>
      <div class="grid g2" style="margin-top:24px">
        <div class="sheet"><h3>Check a dataset</h3><p class="sub">Validate replacement CSVs against the data contract before you switch to them. Files you do not pick are taken from the live dataset, so you can check one file at a time. Nothing is replaced.</p>
          <div class="row"><input type="file" id="valFiles" accept=".csv" multiple class="f" style="padding-top:6px;height:40px"><button class="btn primary" id="valBtn">Check files</button></div>
          <div id="valOut" style="margin-top:12px"></div></div>
        <div class="sheet"><h3>Editing records</h3><p class="sub">The inventory is read from the dataset folder (CSV files owned by the data contract). To change a system, edit its CSV row and restart the server, or set <code class="c">CASCADE_DATA</code> to another folder.</p>
          <p class="note">What-if changes (patch, harden, monitor, segment, remove exposure) are applied to a copy in Fix optimiser and Attack simulation, never to the files. That way every result can be reproduced from the same data.</p></div>
      </div>`;
    const cols = [
      { key: 'name', label: 'System', render: r => `<b style="font-weight:600">${h(r.name)}</b><br><span class="faint">${h(r.id)}, ${h(r.type.replace(/_/g, ' '))}</span>` },
      { key: 'sector', label: 'Sector / zone', render: r => `${h(r.sector || '–')}<br><span class="faint">${h(r.zone_name)}</span>` },
      { key: 'software', label: 'Software and version', render: r => `${h(r.software)}<br><span class="faint">${h(r.version)}</span>` },
      { key: 'criticality', label: 'Crit.', num: true },
      { key: 'exposure', label: 'Exposure', num: true, render: r => `${r.exposure}${r.internet_facing ? '<br><span class="tag">internet</span>' : ''}${r.vendor_access ? '<br><span class="tag">vendor</span>' : ''}` },
      { key: 'cve_count', label: 'CVEs', num: true, render: r => `${r.cve_count}${r.kev_count ? `<br><span class="tag warn">${r.kev_count} KEV</span>` : ''}` },
      { key: 'monitored', label: 'Monitored', render: r => r.monitored ? 'Yes' : '<span class="faint">No</span>', sort: r => +r.monitored },
      { key: 'patch', label: 'Patch', render: r => !r.cve_count ? '<span class="faint">–</span>' : `${r.patch_available ? 'Available' : 'None'}<br><span class="faint">${r.patchable_without_downtime ? 'live' : r.downtime_hours_to_patch + ' h down'}</span>`, sort: r => r.downtime_hours_to_patch },
      { key: 'risk', label: 'Risk', num: true, render: r => `<span class="bar" style="width:${Math.max(3, Math.min(60, r.risk * 2))}px;background:${r.risk >= 15 ? 'var(--white)' : 'var(--soft)'}"></span>${r.risk}` },
    ];
    const t = table(root.querySelector('#invTable'), A, cols, { sortKey: 'risk', onRow: r => assetDrawer(r.id) });
    const $ = s => root.querySelector(s);
    const apply = () => {
      const q = $('#q').value.toLowerCase(), sec = $('#fSector').value, z = $('#fZone').value, ty = $('#fType').value, cr = +$('#fCrit').value, ex = $('#fExp').value, rk = +$('#fRisk').value;
      const rows = A.filter(a => (!q || [a.name, a.software, a.id, ...a.cves].join(' ').toLowerCase().includes(q)) && (!sec || a.sector === sec) && (!z || a.zone_name === z)
        && (!ty || a.type.replace(/_/g, ' ') === ty) && (!cr || (cr === 5 ? a.criticality === 5 : a.criticality >= cr))
        && (!ex || (ex === 'internet' ? a.internet_facing : ex === 'vendor' ? a.vendor_access : !a.internet_facing && !a.vendor_access)) && (!rk || a.risk >= rk));
      t.redraw(rows); $('#count').textContent = `${rows.length} of ${A.length}`;
    };
    root.querySelectorAll('.filters input, .filters select').forEach(e => e.addEventListener('input', apply)); apply();
    $('#exportInv').onclick = () => {
      const cols = ['id', 'name', 'type', 'sector', 'zone', 'criticality', 'exposure', 'internet_facing', 'vendor_access', 'software', 'version', 'cve_count', 'kev_count', 'monitored', 'risk'];
      const csv = [cols.join(','), ...A.map(a => cols.map(c => JSON.stringify(a[c] ?? '')).join(','))].join('\n');
      const l = document.createElement('a'); l.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); l.download = 'cascade-inventory.csv'; l.click();
    };
    $('#valBtn').onclick = async () => {
      const files = [...$('#valFiles').files];
      if (!files.length) return toast('Pick one or more of assets.csv, links.csv, services.csv, vulns.csv first.');
      const out = $('#valOut'); out.innerHTML = '<span class="spin"></span> Checking';
      try {
        const payload = {}; for (const f of files) payload[f.name] = await f.text();
        const r = await api('/api/validate', { files: payload });
        out.innerHTML = `<p class="note ${r.ok ? '' : 'pinkn'}"><b>${r.ok ? 'Valid.' : 'Problems found.'}</b> Checked ${r.checked.map(h).join(', ')}. Rows: ${Object.entries(r.rows).map(([k, v]) => `${h(k)} ${v}`).join(', ')}.</p>
          ${r.errors.map(e => `<p class="note pinkn" style="margin-top:6px">${h(e)}</p>`).join('')}${r.warnings.map(e => `<p class="note warn" style="margin-top:6px">${h(e)}</p>`).join('')}<p class="faint" style="margin-top:8px;font-size:12px">${h(r.note)}</p>`;
      } catch (e) { out.innerHTML = `<div class="err">${h(e.message)}</div>`; }
    };
  } catch (e) { errorBox(root, e); }
}

// ================================== SERVICES & DEPENDENCIES ==================================
export async function services(root) {
  loading(root, 'Loading services');
  try {
    const [g, inv, ov] = await Promise.all([get('/api/graph'), get('/api/assets'), get('/api/overview')]);
    const worst = await api('/api/simulate', { entry_points: [ov.worst_entry] });
    const byId = Object.fromEntries(inv.assets.map(a => [a.id, a]));
    root.innerHTML = `
      <div class="head"><div><h2>Services and dependencies</h2><p class="lede">An essential service runs while its rule is true. When the attacker takes enough systems to make it false, the backup buffer starts; when the buffer runs out, the service is lost.</p></div></div>
      <div class="chart-card"><h3>Dependency map</h3><p class="sub">Solid lines are network or vendor links an attacker can cross. Dashed lines are dependencies (power, data) it cannot travel along. Highlighted: the systems behind the selected service.</p>
        <div class="row" style="margin-bottom:8px" id="svcPick"></div><div id="svcMap"></div></div>
      <div id="svcTable" style="margin-top:16px"></div>`;
    const ids = g.assets.map(a => a.id);
    const used = s => [...new Set((s.rule.match(/[A-Za-z0-9_]+/g) || []).filter(t => ids.includes(t)))];
    const map = netmap(root.querySelector('#svcMap'), g, { height: 440, onClick: a => assetDrawer(a.id) });
    const pick = root.querySelector('#svcPick');
    pick.innerHTML = `<div class="seg" role="group" aria-label="Service">${g.services.map((s, i) => `<button data-i="${i}" class="${i ? '' : 'on'}">${h(s.name)}</button>`).join('')}</div>`;
    const show = i => {
      const s = g.services[i], u = used(s);
      pick.querySelectorAll('button').forEach(b => b.classList.toggle('on', +b.dataset.i === i));
      const st = {}; for (const id of u) st[id] = { fill: '#FFFFFF', label: true, labelColor: '#FFFFFF', tip: `needed by ${s.name}` };
      for (const [id, t] of Object.entries(worst.compromised)) if (u.includes(id) && t < 360) st[id] = { ...st[id], ring: C.pink, tip: `needed by ${s.name}; reached at ${tmin(t)} in the worst attack` };
      map.update(st);
    };
    pick.querySelectorAll('button').forEach(b => b.onclick = () => show(+b.dataset.i)); show(0);
    const rows = g.services.map(s => ({ ...s, used: used(s), fail: worst.failures[s.name] }));
    table(root.querySelector('#svcTable'), rows, [
      { key: 'name', label: 'Service', render: r => `<b style="font-weight:600">${h(r.name)}</b><br><span class="faint">${h(r.id)}</span>` },
      { key: 'population', label: 'People', num: true, render: r => r.population.toLocaleString() },
      { key: 'rule', label: 'Runs while', render: r => `<span style="font-size:12px">${ruleText(r.rule)}</span><br><span class="faint">${r.used.map(id => h(byId[id]?.name || id)).join(', ')}</span>` },
      { key: 'buffer_min', label: 'Backup', num: true, render: r => `${r.buffer_min} min` },
      { key: 'fail', label: 'Worst attack', num: true, render: r => r.fail != null && r.fail < 360 ? `<span class="pinkt">lost ${tmin(r.fail)}</span>` : 'not lost', sort: r => -(r.fail ?? 999) },
      { key: 'risk', label: 'Riskiest system behind it', render: r => { const m = r.used.map(id => byId[id]).filter(Boolean).sort((a, b) => b.risk - a.risk)[0]; return m ? `${h(m.name)} <span class="faint">(${m.risk})</span>` : '–'; }, sort: r => Math.max(0, ...r.used.map(id => byId[id]?.risk || 0)) },
    ], { sortKey: 'population' });
  } catch (e) { errorBox(root, e); }
}

// ================================ VULNERABILITY INTELLIGENCE ================================
export async function vulns(root) {
  loading(root, 'Loading vulnerabilities');
  try {
    const { vulns: V } = await get('/api/vulns');
    root.innerHTML = `
      <div class="head"><div><h2>Vulnerability intelligence</h2><p class="lede">${V.length} CVEs from NVD, with CISA KEV and FIRST EPSS. Four different questions, kept apart:</p></div></div>
      <div class="kpis" style="margin-bottom:16px">
        ${kpi('CVSS', 'Severity', 'How bad the bug is in general, 0-10. Same score in a lab and a hospital.')}
        ${kpi('EPSS · KEV', 'Likelihood of exploitation', 'EPSS: chance of exploitation attempts seen in the next 30 days, across the internet. KEV: confirmed exploited.')}
        ${kpi('Risk', 'Infrastructure risk', 'The system the CVE sits on: exposure, criticality, what it takes down.')}
        ${kpi('Harm', 'Operational consequence', 'People × minutes of lost service in the simulation. See Risk register and Fix optimiser.')}
      </div>
      <p class="note warn" style="margin-bottom:16px">EPSS is not the probability that a particular system here will be compromised. It is a population-level estimate of exploitation activity, used as one input to how fast an attacker gets in.</p>
      <div class="grid g12" style="margin-bottom:16px">
        <div class="chart-card"><h3>Where the probability comes from</h3><p class="sub">Per CVE: 0.9 if on CISA KEV, else FIRST EPSS, else 0.05. (Our ML is a water anomaly detector, not a CVE model.)</p><div id="vSrc"></div></div>
        <div class="chart-card"><h3>Severity against likelihood</h3><p class="sub">Each dot is a CVE. High CVSS with low EPSS is common: severe but rarely exploited. Amber dots are on CISA's KEV list.</p><div id="vScatter"></div></div>
      </div>
      <div class="filters">
        <input class="f" id="vq" placeholder="Search CVE, vendor, product, system" style="width:260px" aria-label="Search">
        <label class="chk"><input type="checkbox" id="vKev"> Known exploited (KEV)</label>
        <label class="chk"><input type="checkbox" id="vIcs"> ICS/OT products</label>
        <label class="chk"><input type="checkbox" id="vPatch"> Patch available</label>
        <select class="f" id="vCvss" aria-label="Minimum CVSS"><option value="0">Any CVSS</option><option value="9">9.0+ critical</option><option value="7">7.0+ high</option></select>
        <span class="mute" id="vCount"></span>
      </div>
      <div id="vTable"></div>`;
    const src = {}; V.forEach(v => src[v.prob_source] = (src[v.prob_source] || 0) + 1);
    bars(root.querySelector('#vSrc'), Object.entries(src).map(([k, v]) => ({ label: k, value: v })), { horizontal: true, labelWidth: 130, fmtv: v => v.toFixed(0) });
    scatter(root.querySelector('#vScatter'), V.map(v => ({ x: v.cvss, y: v.epss ?? 0, label: v.cve_id, color: v.kev ? C.warn : C.series[0], v })),
      { xMin: 0, xMax: 10, yMax: 1, xLabel: 'CVSS severity', yLabel: 'EPSS', fmtx: x => x.toFixed(0), fmty: y => y.toFixed(1),
        legendItems: [{ label: 'On CISA KEV', color: C.warn }, { label: 'Not on KEV', color: C.series[0] }],
        tipFmt: p => `<b>${h(p.label)}</b><br>CVSS ${p.x}, EPSS ${p.y.toFixed(3)}${p.v.kev ? '<br>on CISA KEV' : ''}<br>${p.v.assets.map(a => h(a.name)).join(', ')}` });
    const t = table(root.querySelector('#vTable'), V, [
      { key: 'cve_id', label: 'CVE', render: r => `<b style="font-weight:600">${h(r.cve_id)}</b>${r.ics ? ' <span class="tag">ICS</span>' : ''}<br><span class="faint">${h(r.cwe)}</span>` },
      { key: 'product', label: 'Product', render: r => `${h(r.vendor)}<br><span class="faint">${h(r.product)}</span>` },
      { key: 'cvss', label: 'CVSS', num: true },
      { key: 'epss', label: 'EPSS', num: true, render: r => r.epss == null ? '–' : r.epss.toFixed(3) },
      { key: 'kev', label: 'KEV', render: r => r.kev ? '<span class="tag warn">Exploited</span>' : 'No', sort: r => +r.kev },
      { key: 'exploit_prob_used', label: 'Prob. used', num: true, render: r => `${r.exploit_prob_used.toFixed(2)}<br><span class="faint">${h(r.prob_source)}</span>` },
      { key: 'assets', label: 'On system', render: r => r.assets.map(a => `${h(a.name)} <span class="faint">crit ${a.criticality}</span>`).join('<br>') || '–', sort: r => r.max_asset_criticality },
      { key: 'patch_available', label: 'Patch', render: r => r.patch_available ? h(r.patch_type || 'patch') : '<span class="faint">none</span>', sort: r => +r.patch_available },
      { key: 'max_asset_risk', label: 'System risk', num: true },
    ], { sortKey: 'max_asset_risk' });
    const $ = s => root.querySelector(s);
    const apply = () => {
      const q = $('#vq').value.toLowerCase(), min = +$('#vCvss').value;
      const rows = V.filter(v => (!q || [v.cve_id, v.vendor, v.product, ...v.assets.map(a => a.name)].join(' ').toLowerCase().includes(q))
        && (!$('#vKev').checked || v.kev) && (!$('#vIcs').checked || v.ics) && (!$('#vPatch').checked || v.patch_available) && v.cvss >= min);
      t.redraw(rows); $('#vCount').textContent = `${rows.length} of ${V.length}`;
    };
    root.querySelectorAll('.filters input, .filters select').forEach(e => e.addEventListener('input', apply)); apply();
  } catch (e) { errorBox(root, e); }
}

// ======================================= RISK REGISTER =======================================
export async function risk(root) {
  loading(root, 'Loading the risk register');
  try {
    const reg = await get('/api/risk_register');
    root.innerHTML = `
      <div class="head"><div><h2>Risk register</h2><p class="lede">Every system ranked by consequence-aware risk, with the factors behind it and the single best fix that touches it. The CVSS rank column shows where a severity-only list would have put it.</p></div></div>
      <div id="rTable"></div>
      <div class="chart-card" style="margin-top:16px"><h3>Does the ranking matter? CVSS-only against Cascade</h3>
        <p class="sub">Five fix-ordering strategies, five fixes each. After every fix the backend re-runs every way in. Lower is better. Worst-case harm = what an attacker who picks the best way in can do.</p>
        <div class="seg" id="bMode" style="margin-bottom:10px"><button class="on" data-m="worst">Worst-case harm</button><button data-m="expected">Likely harm, all ways in</button></div>
        <div id="bChart"><div class="loading"><span class="spin"></span>Running 25 re-simulations (about 10 s the first time)</div></div><div id="bTake" style="margin-top:12px"></div></div>`;
    if (!reg.fix_ranking_ready) root.querySelector('.lede').insertAdjacentHTML('afterend', '<p class="note warn" style="margin-top:8px">Fix ranking is still being computed in the background; reload in a minute for the recommended-action column.</p>');
    table(root.querySelector('#rTable'), reg.rows, [
      { key: 'risk_rank', label: '#', num: true, sort: r => -r.risk_rank },
      { key: 'name', label: 'System', render: r => `<b style="font-weight:600">${h(r.name)}</b><br><span class="faint">${h(r.sector || r.zone_name)}${r.is_entry ? ', way in' : ''}</span>` },
      { key: 'risk', label: 'Risk', num: true, render: r => `<span class="bar" style="width:${Math.max(3, Math.min(60, r.risk * 2))}px;background:${r.risk >= 15 ? 'var(--white)' : 'var(--soft)'}"></span>${r.risk}` },
      { key: 'cvss_rank', label: 'CVSS rank', num: true, sort: r => -r.cvss_rank, render: r => `${r.cvss_rank}${Math.abs(r.cvss_rank - r.risk_rank) >= 5 ? ` <span class="tag ${r.cvss_rank > r.risk_rank ? 'pink' : ''}">${r.cvss_rank > r.risk_rank ? 'under-rated' : 'over-rated'}</span>` : ''}` },
      { key: 'criticality', label: 'Crit.', num: true },
      { key: 'cve_count', label: 'CVEs / KEV', num: true, render: r => `${r.cve_count} / ${r.kev_count}` },
      { key: 'max_epss', label: 'Max EPSS', num: true, render: r => r.max_epss.toFixed(2) },
      { key: 'harm_if_entry', label: 'Harm if way in', num: true, render: r => r.harm_if_entry == null ? '<span class="faint">not a way in</span>' : fmt(r.harm_if_entry), sort: r => r.harm_if_entry ?? -1 },
      { key: 'factors', label: 'Main factors', nosort: true, render: r => `<span style="font-size:12px">${r.factors.map(h).join('; ') || '–'}</span>${r.water_advisory ? `<br><span class="wbadge" title="Advisory evidence from the water anomaly ML. It raises investigation priority only; it does not change the risk score.">Water anomaly: ${h(r.water_advisory.text)}</span>` : ''}` },
      { key: 'recommended', label: 'Best fix touching it', render: r => r.recommended ? `${h(r.recommended.label)}<br><span class="faint">−${r.recommended.risk_reduction_pct}% likely harm, ${r.recommended.staff_hours} h</span>` : '<span class="faint">–</span>', sort: r => r.recommended?.risk_reduction_pct ?? -1 },
    ], { sortKey: 'risk', onRow: r => assetDrawer(r.id) });
    const b = await get('/api/baseline');
    const colors = { cvss: '#A9B4DA', epss: '#6F7DB5', kev_cvss: '#C28420', cascade_patch: '#8E9DE0', cascade: '#FFFFFF' };
    const draw = mode => {
      curves(root.querySelector('#bChart'), [0, 1, 2, 3, 4, 5].slice(0, b.k_max + 1), b.strategies.map(s => ({
        name: s.name, color: colors[s.key], bold: s.key === 'cascade', dash: ['cvss', 'epss', 'kev_cvss'].includes(s.key),
        values: s.points.map(p => p[mode]), notes: s.points.map(p => p.label || '') })), { xLabel: 'fixes applied', yLabel: 'people × minutes' });
    };
    draw('worst');
    root.querySelectorAll('#bMode button').forEach(x => x.onclick = () => { root.querySelectorAll('#bMode button').forEach(y => y.classList.toggle('on', y === x)); draw(x.dataset.m); });
    const by = Object.fromEntries(b.strategies.map(s => [s.key, s.points]));
    const base = by.cvss[0].worst, last = k => by[k][by[k].length - 1];
    root.querySelector('#bTake').innerHTML = `<p class="note">After ${b.k_max} fixes the worst case is ${fmt(last('cvss').worst)} with CVSS-only (−${pct(base, last('cvss').worst)}%),
      ${fmt(last('epss').worst)} with EPSS-only (−${pct(base, last('epss').worst)}%), ${fmt(last('cascade_patch').worst)} with Cascade patches only (−${pct(base, last('cascade_patch').worst)}%)
      and ${fmt(last('cascade').worst)} with Cascade using any fix (−${pct(base, last('cascade').worst)}%). CVSS-only's first pick was "${h(by.cvss[1].label)}".</p>
      <p class="faint" style="margin-top:8px;font-size:12px">${h(b.note)} Patch-only Cascade is not always ahead of EPSS: most of the gain comes from being allowed to monitor, segment or remove exposure, which a CVSS list cannot express.</p>`;
  } catch (e) { errorBox(root, e); }
}
