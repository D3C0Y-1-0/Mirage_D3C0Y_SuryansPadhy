// Electricity attack screening (SENTINEL module 11): a SAMPLE EXPLORER of benchmark data, not a live feed.
// Every number comes from ml_electricity/ via /api/electricity/*. UI rules from the model owner:
// show the coverage warning wherever results appear; a flag means "investigate"; no flag never means safe.
import { api, get, h, fmt, table, loading, errorBox, toast, openDrawer } from './core.js';
import { bars } from './charts.js';

const LBL = { normal_operation: 'Normal operation', natural_disturbance: 'Natural disturbance', cyberattack: 'Cyberattack' };
const OUT = { attack_flagged: ['Attack flagged', 'pink'], attack_missed: ['Attack missed', 'warn'], false_attack_flag: ['False attack flag', 'warn'], correct: ['Correct', 'white'], non_attack_confusion: ['Normal vs natural mix-up', ''] };
const pctf = v => `${(100 * v).toFixed(1)}%`;

export async function electricity(root) {
  loading(root, 'Loading electricity screening');
  let S;
  try { S = await get('/api/electricity/summary'); } catch (e) { return errorBox(root, e); }
  if (!S.available) { root.innerHTML = '<div class="chart-empty">The electricity screening package is not installed. Put the integration files in <code class="c">ml_electricity/</code>.</div>'; return; }
  const mc = S.model_card, ho = mc.held_out_test_data13_15_evaluated_once, va = mc.validation_data10_12, B = S.explorer.blocks;
  let f = { file: '', label: '', outcome: '', offset: 0 };
  root.innerHTML = `
    <div class="head"><div><h2>Electricity attack screening</h2><p class="lede">A second machine-learning sector. A frozen model sorts one power-system measurement into normal operation, natural disturbance or cyberattack. It is tuned to be <b>right when it flags</b>, at the cost of missing many attacks, so it raises investigation priority and never gives an all-clear.</p></div></div>
    <div class="histbanner"><b>Benchmark samples, not telemetry.</b> ${h(S.banner.replace(/^BENCHMARK SAMPLES from /, 'From '))}</div>
    <div class="note warn" style="margin-top:10px"><b>About 40% coverage.</b> ${h(S.warning)}</div>
    <div class="kpis" style="margin-top:16px">
      <div class="kpi"><div class="v">${pctf(ho.attack_precision)}</div><div class="l">Attack precision</div><div class="s">held-out data13-15, evaluated once</div></div>
      <div class="kpi"><div class="v warn">${pctf(ho.attack_recall)}</div><div class="l">Attack recall (coverage)</div><div class="s">most attacks are not flagged</div></div>
      <div class="kpi"><div class="v">${pctf(ho.natural_disturbance_called_attack_rate)}</div><div class="l">Natural disturbance flagged as attack</div><div class="s">${pctf(ho.normal_operation_called_attack_rate)} for normal operation</div></div>
      <div class="kpi"><div class="v">${ho.n.toLocaleString()}</div><div class="l">Held-out samples</div><div class="s">${Object.entries(ho.class_counts).map(([k, v]) => `${v.toLocaleString()} ${k === 'NoEvents' ? 'normal' : k.toLowerCase()}`).join(', ')}</div></div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="chart-card"><h3>Validation outcomes</h3><p class="sub">Validation files data10-12: what the model said for each benchmark label. (The held-out files were scored once by the model owner; only their totals are published.)</p><div id="eConf"></div></div>
      <div class="sheet"><h3>How it decides</h3><dl class="kv">
        <dt>Model</dt><dd>${h(mc.model.type.split('.').pop())}, ${mc.model.n_estimators} trees, min leaf ${mc.model.min_samples_leaf}; load-invariant ratios built from ${mc.features.required_raw_columns} raw measurements (so a change in grid load alone does not look like an attack)</dd>
        <dt>Rule</dt><dd>Cyberattack if P(cyberattack) ≥ <b>${mc.attack_threshold}</b>, otherwise the larger of normal and natural</dd>
        <dt>Threshold set on</dt><dd>${h(mc.tau_source)}</dd>
        <dt>Data</dt><dd>${h(mc.source.dataset)}: ${h(mc.source.nature)}</dd>
        <dt>Version</dt><dd><code class="c">${h(mc.model_version)}</code></dd></dl>
        <p class="faint" style="font-size:12px;margin-top:8px">${h(S.explanation_note)}</p></div>
    </div>
    <div class="sheet" style="margin-top:16px"><h3>Label blocks in the validation files</h3><p class="sub">${h(S.explorer.notice)} Click a block to list its samples.</p><div id="eBlocks" class="eblocks"></div></div>
    <div class="sheet" style="margin-top:16px"><div class="row" style="justify-content:space-between"><h3>Samples</h3><span class="faint" id="eCount" style="font-size:12px"></span></div>
      <div class="filters" style="margin:8px 0">
        <select class="f" id="eFile" aria-label="Source file"><option value="">All files</option>${[...new Set(B.map(b => b.source_file))].map(x => `<option>${h(x)}</option>`).join('')}</select>
        <select class="f" id="eLabel" aria-label="Benchmark label"><option value="">Any benchmark label</option>${Object.entries(LBL).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
        <select class="f" id="eOut" aria-label="Outcome"><option value="">Any outcome</option>${Object.entries(OUT).map(([k, [v]]) => `<option value="${k}">${v}</option>`).join('')}</select>
        <button class="btn small" id="eClear">Clear filters</button></div>
      <div id="eTable"></div><div class="row" style="margin-top:10px;gap:8px"><button class="btn small" id="ePrev">Previous</button><button class="btn small" id="eNext">Next</button></div></div>
    <div class="grid g2" style="margin-top:16px">
      <div class="sheet"><h3>Link to the city (illustrative)</h3><p class="note">${h(S.mapping.disclaimer)}</p>
        ${S.mapping.benchmark_components.map(c => `<p style="font-size:13px;margin-top:8px"><b>${h(c.benchmark)}</b> <span class="mute">≈ ${h(c.sentinel_name)} (${h(c.sentinel_asset)}): ${h(c.basis)}</span></p>`).join('')}
        <p class="faint" style="font-size:12px;margin-top:8px">The output never changes CVSS, EPSS, KEV or the simulated attack. At most it raises investigation priority for EL04-EL06.</p></div>
      <div class="sheet"><h3>Limitations</h3><ul style="margin:0;padding-left:18px;color:var(--mute);font-size:13px">${(mc.limitations || []).map(x => `<li style="margin:4px 0">${h(x)}</li>`).join('')}</ul>
        <p class="faint" style="font-size:12px;margin-top:8px">Source: ${h(mc.source.authors)}. ${h(mc.source.citation_hint)}.</p></div>
    </div>`;
  const $ = q => root.querySelector(q);
  // validation confusion matrix as grouped percentages
  const cm = va.confusion_rows_true_cols_pred, names = ['Normal', 'Natural', 'Attack'];
  $('#eConf').innerHTML = `<div class="tablewrap"><table class="t cm"><thead><tr><th>Benchmark label ↓ / model said →</th>${names.map(n => `<th class="n">${n}</th>`).join('')}</tr></thead><tbody>${cm.matrix.map((row, i) => { const tot = row.reduce((a, b) => a + b, 0); return `<tr><td>${names[i]} <span class="faint">(${tot.toLocaleString()})</span></td>${row.map((v, j) => `<td class="n ${i === j ? 'diag' : j === 2 && i !== 2 ? 'fa' : i === 2 && j !== 2 ? 'miss' : ''}">${v.toLocaleString()}<br><span class="faint">${pctf(v / tot)}</span></td>`).join('')}</tr>`; }).join('')}</tbody></table></div>
    <p class="faint" style="font-size:12px;margin-top:8px">Diagonal = agrees with the benchmark. Amber column = flagged as attack when it was not. Pink row = attacks the model did not flag.</p>`;
  // blocks
  $('#eBlocks').innerHTML = B.map((b, i) => `<button class="eblock ${b.benchmark_label}" data-i="${i}" title="${h(b.source_file)}, rows ${b.row_range[0]}-${b.row_range[1]}"><b>${h(b.source_file.replace('.csv', ''))} · block ${b.label_block}</b><span>${LBL[b.benchmark_label]}, ${b.rows.toLocaleString()} rows</span>
    <i class="ebar"><s style="width:${(100 * b.attack_flag_rate).toFixed(1)}%"></s></i><em>${pctf(b.attack_flag_rate)} flagged · mean P(attack) ${b.mean_p_cyberattack.toFixed(2)}</em></button>`).join('');
  $('#eBlocks').querySelectorAll('.eblock').forEach(b => b.onclick = () => { const x = B[+b.dataset.i]; f = { file: x.source_file, label: '', outcome: '', block: x.label_block, offset: 0 }; sync(); load(); $('#eTable').scrollIntoView({ behavior: 'smooth', block: 'center' }); });
  const sync = () => { $('#eFile').value = f.file || ''; $('#eLabel').value = f.label || ''; $('#eOut').value = f.outcome || ''; };
  async function load() {
    $('#eTable').innerHTML = '<div class="loading"><span class="spin"></span>Loading samples</div>';
    const q = new URLSearchParams({ offset: f.offset, limit: 25 }); if (f.file) q.set('file', f.file); if (f.label) q.set('label', f.label); if (f.outcome) q.set('outcome', f.outcome); if (f.block) q.set('block', f.block);
    let r; try { r = await api(`/api/electricity/samples?${q}`); } catch (e) { $('#eTable').innerHTML = `<div class="err">${h(e.message)}</div>`; return; }
    $('#eCount').textContent = r.total ? `${(f.offset + 1).toLocaleString()}-${Math.min(r.total, f.offset + 25).toLocaleString()} of ${r.total.toLocaleString()}${f.block ? ` (block ${f.block})` : ''}` : '';
    table($('#eTable'), r.rows, [
      { key: 'file', label: 'Sample', render: x => `${h(x.file)} <span class="faint">row ${x.row}</span>` },
      { key: 'label', label: 'Benchmark label', render: x => LBL[x.label] },
      { key: 'pred', label: 'Model said', render: x => `${LBL[x.pred]}${x.flag ? ' <span class="tag pink">investigate</span>' : ''}` },
      { key: 'p', label: 'P(attack)', num: true, render: x => `<span class="bar" style="width:${Math.max(3, 50 * x.p[2])}px;background:${x.flag ? 'var(--pink)' : 'var(--soft)'}"></span>${x.p[2].toFixed(2)}`, sort: x => x.p[2] },
      { key: 'outcome', label: 'Against the benchmark', render: x => `<span class="tag ${OUT[x.outcome][1]}">${OUT[x.outcome][0]}</span>` }],
      { sortKey: null, empty: 'No sample matches these filters.', onRow: x => detail(x) });
    $('#ePrev').disabled = f.offset === 0; $('#eNext').disabled = f.offset + 25 >= r.total;
  }
  function detail(x) {
    const mx = Math.max(...x.ev.map(e => Math.abs(e[1])), .01);
    openDrawer(`<h2 style="font-size:24px">${h(x.file)}, row ${x.row}</h2><p class="mute">Benchmark sample, block ${x.block}. No timestamp.</p>
      <div class="note warn" style="margin-top:10px">${h(S.warning)}</div>
      <h4 class="h4" style="margin-top:14px">Probabilities</h4><div id="dProb"></div>
      <p style="margin-top:6px;font-size:13px">Model said <b>${LBL[x.pred]}</b>${x.flag ? ': <b class="pinkt">likely cyber-physical attack signature, investigate</b>' : '. No flag: this does <b>not</b> mean the grid is safe.'} Benchmark label: ${LBL[x.label]}.</p>
      <h4 class="h4" style="margin-top:14px">What drove this score (top 3)</h4>
      ${x.ev.map(([n, v]) => `<div class="evrow"><code class="c">${h(n)}</code><i><s style="width:${(50 * Math.abs(v) / mx).toFixed(0)}%;${v >= 0 ? 'left:50%;background:var(--pink)' : 'right:50%;background:var(--soft)'}"></s></i><span class="num">${v >= 0 ? '+' : ''}${v.toFixed(3)}</span></div>`).join('')}
      <p class="faint" style="font-size:12px;margin-top:8px">${h(S.explanation_note)} Pink pushes toward attack, blue away from it. R1-R4 are benchmark relays, illustrative stand-ins for EL06; this is not a measurement from the city.</p>`);
    bars(document.querySelector('#dProb'), [{ label: 'Normal operation', value: x.p[0] }, { label: 'Natural disturbance', value: x.p[1] }, { label: 'Cyberattack', value: x.p[2], color: x.flag ? '#FF6FB5' : undefined }], { horizontal: true, max: 1, labelWidth: 150, fmtv: v => v.toFixed(2) });
  }
  $('#eFile').onchange = e => { f.file = e.target.value; f.block = null; f.offset = 0; load(); };
  $('#eLabel').onchange = e => { f.label = e.target.value; f.offset = 0; load(); };
  $('#eOut').onchange = e => { f.outcome = e.target.value; f.offset = 0; load(); };
  $('#eClear').onclick = () => { f = { file: '', label: '', outcome: '', offset: 0 }; sync(); load(); toast('Filters cleared'); };
  $('#ePrev').onclick = () => { f.offset = Math.max(0, f.offset - 25); load(); };
  $('#eNext').onclick = () => { f.offset += 25; load(); };
  load();
}

// ======================================= MODEL EVALUATION =======================================
// For all six sector models: the criteria fixed before training, against what each model actually scored.
export async function evaluation(root) {
  loading(root, 'Loading model evaluations');
  let E;
  try { E = await get('/api/ml/evaluation'); } catch (e) { return errorBox(root, e); }
  const DEC = { approved: ['Approved', 'white'], no_go: ['Rejected', 'warn'], demo_only: ['Demonstration only', ''] };
  const tick = p => p === true ? '<span class="gp ok" aria-label="met">✓</span>' : p === false ? '<span class="gp no" aria-label="not met">✗</span>' : '<span class="gp na" aria-label="reported">–</span>';
  const n = E.models.length, ok = E.models.filter(m => m.decision === 'approved').length;
  root.innerHTML = `
    <div class="head"><div><h2>Model evaluation</h2><p class="lede">Six sector models were built. For each, the pass criteria were written down <b>before</b> training, and the final test on held-back data was run once by a locked script, or not at all if the model already failed on validation. ${ok} of ${n} passed and are in the platform. The rest are shown here with the exact reason, instead of being shipped.</p></div></div>
    <div class="note">${h(E.note)}</div>
    <div class="evgrid" id="evg"></div>
    ${E.iot_demo ? '<div class="sheet" id="iot" style="margin-top:16px"></div>' : ''}`;
  root.querySelector('#evg').innerHTML = E.models.map(m => `<div class="sheet evcard ${m.decision}">
      <div class="row" style="justify-content:space-between;align-items:flex-start"><h3>${h(m.sector)}</h3><span class="tag ${DEC[m.decision][1]}">${DEC[m.decision][0]}</span></div>
      <p class="mute" style="font-size:13px;margin:4px 0 10px">${h(m.stage)}. ${h(m.model)}.</p>
      ${m.gates.length ? `<table class="t gates"><thead><tr><th></th><th>Criterion</th><th>Needed</th><th>Got</th></tr></thead><tbody>${m.gates.map(g => `<tr class="${g.pass === false ? 'bad' : ''}"><td>${tick(g.pass)}</td><td>${h(g.name)}</td><td class="num">${h(g.need)}</td><td class="num"><b>${h(g.got)}</b></td></tr>`).join('')}</tbody></table>` : ''}
      <p style="font-size:13px;margin-top:10px">${h(m.why)}</p>
      <p class="faint" style="font-size:12px;margin-top:8px">Data: ${h(m.data)}. Final test: ${h(m.final_test)}.</p></div>`).join('');
  if (E.iot_demo) {
    const d = E.iot_demo, r = d.results, c = r.candidate, b = r.baseline, t = r.test_once, sh = r.shortcut_rule_number_eq_100_on_validation;
    const G = { G1: 'Benign false positives <= 5% (validation)', G2: 'Beats the baseline on recall (validation and every fold)', G3: 'Session-confound check', G4: 'Recall holds on traffic never seen in training (within 0.10)', G5: 'Fold stability (macro-F1 within 0.10)' };
    root.querySelector('#iot').innerHTML = `<div class="row" style="justify-content:space-between"><h3>IoT demonstration benchmark</h3><span class="tag">Demonstration only</span></div>
      <div class="note warn" style="margin-top:8px"><b>${h(r.label)}</b> ${h(r.verdict)}</div>
      <div class="grid g2" style="margin-top:12px">
        <div><h4 class="h4">What was declared first</h4><dl class="kv">
          <dt>Data</dt><dd>CICIoT2023 curated derivative: train / validation / the test half that excludes validation. Hashes checked before running.</dd>
          <dt>Removed features</dt><dd>${h(d.declaration.excluded_features.capture_artefact.concat(d.declaration.excluded_features.window_dependent_aggregates).join(', '))}: ${h(d.declaration.excluded_features.reason)}</dd>
          <dt>Training rows</dt><dd>${r.train.rows.toLocaleString()} → ${r.train.after_dedup.toLocaleString()} after removing ${r.train.duplicates_removed.toLocaleString()} exact duplicates → ${r.train.subsample.toLocaleString()} sampled</dd>
          <dt>Threshold</dt><dd>set inside training only, for at most 5% benign false positives</dd>
          <dt>Integrity</dt><dd>${d.declaration_matches ? 'declaration unchanged since the run' : '<b class="warnt">declaration changed after the run</b>'}; ${d.lock_matches ? 'results locked (run once)' : '<b class="warnt">results do not match the lock</b>'}</dd></dl>
          <p class="faint" style="font-size:12px;margin-top:8px">${h(r.run_note || '')}</p></div>
        <div><h4 class="h4">Gates</h4><table class="t gates"><tbody>${Object.entries(r.gates).map(([k, v]) => `<tr class="${v ? '' : 'bad'}"><td>${tick(v)}</td><td>${k}: ${G[k]}</td></tr>`).join('')}</tbody></table>
          <p style="font-size:13px;margin-top:8px">G3 cannot be checked on this data at all, so the protocol is unmet whatever the scores. G4 failed: on validation traffic the model had never seen, recall dropped from ${c.validation.attack_recall.toFixed(3)} to ${c.validation_unseen_vectors.attack_recall.toFixed(3)}.</p></div>
      </div>
      <div class="kpis" style="margin-top:14px">
        <div class="kpi"><div class="v">${t.candidate.attack_recall.toFixed(3)}</div><div class="l">Attack recall, test (once)</div><div class="s">at ${(100 * t.candidate.benign_fpr).toFixed(1)}% benign false positives</div></div>
        <div class="kpi"><div class="v warn">${t.candidate_unseen_vectors.attack_recall.toFixed(3)}</div><div class="l">On test rows never seen in training</div><div class="s">${(100 * t.unseen_vector_share).toFixed(0)}% of the test rows</div></div>
        <div class="kpi"><div class="v">${t.baseline.attack_recall.toFixed(3)}</div><div class="l">Baseline (logistic regression)</div><div class="s">same false-positive budget</div></div>
        <div class="kpi"><div class="v">${sh.attack_recall.toFixed(3)}</div><div class="l">The shortcut we removed</div><div class="s">"Number = 100" alone, 0 false positives: why it had to go</div></div>
      </div>
      <div class="chart-card" style="margin-top:14px"><h3>Flag rate by traffic type (test, once)</h3><p class="sub">Floods are near 100%, which is the easy part and partly still the capture setup. Reconnaissance, brute force and web attacks are the hard part: about half are missed.</p><div id="iotBars"></div></div>`;
    const pc = t.candidate_flag_rate_by_class;
    bars(root.querySelector('#iotBars'), Object.entries(pc).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: +(100 * v).toFixed(1), color: k === 'Benign' ? '#F2B84B' : undefined })), { horizontal: true, max: 100, labelWidth: 120, fmtv: v => `${v}%` });
  }
}
