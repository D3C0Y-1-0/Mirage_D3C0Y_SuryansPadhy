// Live testbed end to end: the real attack script (separate process, real Modbus/TCP) against the running server.
// Checks: notices then alarm appear on the Live page; the site-wide pill and the twin react; the operator isolates;
// the attacker's connection is refused; recovery restores the controller; the failsafe acts if nobody answers.
const { chromium } = require('playwright');
const { spawn } = require('child_process');
const path = require('path');
const BASE = process.env.CASCADE_URL || 'http://localhost:8000', OUT = process.env.OUT || '/tmp';
const PY = process.env.PYTHON || 'python3', ATTACK = path.join(__dirname, '..', 'live', 'attack.py');
const attack = (args = []) => { const p = spawn(PY, [ATTACK, '--pause', '0.4', ...args]); let out = ''; p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d); return { p, out: () => out }; };
const state = () => fetch(BASE + '/api/live/state').then(r => r.json());
(async () => {
  let fails = 0; const bad = m => { fails++; console.log('FAIL', m); };
  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => m.type() === 'error' && errs.push(m.text()));
  await fetch(BASE + '/api/live/close', { method: 'POST' });
  let s = await state();
  if (!s.running) { console.log('FAIL testbed not running:', s.error); process.exit(1); }
  for (let i = 0; i < 70 && !s.baseline.learned; i++) { await new Promise(r => setTimeout(r, 1000)); s = await state(); }
  if (!s.baseline.learned) bad('baseline never learned');
  await p.goto(BASE + '/app#/live', { waitUntil: 'networkidle' }); await p.waitForTimeout(1500);
  if (!/Normal\. Watching every request/.test(await p.textContent('#lvResp'))) bad('not in normal state before the attack');
  // 1. recon only: notices, no incident
  let a = attack(['recon']); await new Promise(r => setTimeout(r, 2500)); a.p.kill();
  s = await state();
  const notices = s.alerts.filter(x => x.severity === 'notice').map(x => x.rule);
  if (!notices.includes('new_master') || !notices.includes('scan') || s.incident) bad(`recon: ${JSON.stringify(notices)} incident=${!!s.incident}`); else console.log('recon -> notices only:', notices.join(', '));
  // 2. full attack: alarm, pill, page
  a = attack(); await p.waitForFunction(() => /ALARM/.test(document.querySelector('#lvResp')?.textContent || ''), null, { timeout: 15000 }).catch(() => bad('no alarm on the page'));
  for (let i = 0; i < 20; i++) { s = await state(); if (s.alerts.some(x => x.rule === 'out_of_range') && s.alerts.filter(x => x.rule === 'unseen_point').length >= 3) break; await new Promise(r => setTimeout(r, 300)); }   // all four steps sent
  const rules = [...new Set(s.alerts.map(x => x.rule))];
  for (const r of ['unknown_write', 'alarm_off', 'out_of_range', 'unseen_point']) if (!rules.includes(r)) bad('missing alert ' + r);
  console.log('alerts:', rules.join(', '), '| techniques:', [...new Set(s.alerts.map(x => x.technique.split(' ')[0]))].join(' '));
  await p.waitForFunction(() => !document.querySelector('#livePill').hidden && /LIVE ALARM/.test(document.querySelector('#livePill').textContent), null, { timeout: 6000 }).catch(() => bad('top-bar pill did not show the alarm'));
  const sec = await p.textContent('#lvSec'); if (!(+sec > 0)) bad('no countdown: ' + sec);
  await p.screenshot({ path: OUT + '/live_alarm.png', fullPage: false });
  // 3. operator isolates
  await p.click('#lvIso'); await p.waitForTimeout(1500);
  s = await state();
  if (s.incident.state !== 'isolated' || s.incident.decided_by === 'failsafe') bad('isolate by operator: ' + JSON.stringify(s.incident));
  await new Promise(r => setTimeout(r, 1500));
  if (!/closed the connection|stopped/.test(a.out())) bad('attacker was not disconnected: ' + a.out().slice(-200)); else console.log('attacker disconnected:', a.out().trim().split('\n').pop());
  a.p.kill();
  const again = attack(['silence']); await new Promise(r => setTimeout(r, 2000)); again.p.kill();
  s = await state();
  if (!s.packets.some(x => /refused/.test(x.result))) bad('a new attacker connection was not refused while isolated'); else console.log('new attacker connection refused while isolated');
  if (s.process.alarm_enable) bad('expected alarm still disabled before recovery');
  // 4. recover
  await p.click('#lvRes'); await p.waitForTimeout(1200);
  s = await state();
  if (s.process.high_sp !== 420 || s.process.manual || !s.process.alarm_enable || s.incident.state !== 'recovered') bad('recovery: ' + JSON.stringify(s.process)); else console.log('recovered: setpoint 420, auto mode, alarm on');
  await p.click('#lvClose'); await p.waitForTimeout(1200);
  // twin reacts to a new alarm (separate page, polls on its own): open it first, then attack
  const tw = await b.newPage({ viewport: { width: 1280, height: 800 } });
  await tw.goto(BASE + '/twin', { waitUntil: 'domcontentloaded' }); await tw.waitForFunction(() => window.cascade?.S?.graph, null, { timeout: 120000 });
  a = attack(['setpoint']);
  await tw.waitForFunction(id => window.cascade.S.entries.includes(id) && /LIVE ALARM/.test(document.querySelector('#banner').textContent), s.asset, { timeout: 15000 }).then(() => console.log('twin: way in =', s.asset, '+ LIVE banner')).catch(() => bad('twin did not react to the live alarm'));
  await tw.screenshot({ path: OUT + '/live_twin.png' });
  // 5. failsafe when nobody answers (the attack above is still the open incident)
  await new Promise(r => setTimeout(r, 1000));
  s = await state(); if (!s.incident) bad('no incident for setpoint attack');
  const wait = s.ack_s + 4; await new Promise(r => setTimeout(r, wait * 1000));
  s = await state(); a.p.kill();
  if (s.incident?.state !== 'isolated' || s.incident.decided_by !== 'failsafe') bad('failsafe did not act: ' + JSON.stringify(s.incident)); else console.log(`failsafe isolated after ${s.ack_s} s with no answer`);
  const audit = await fetch(BASE + '/api/ops/verify').then(r => r.json()).catch(() => null);
  if (audit && audit.ok === false) bad('audit chain broken'); else console.log('audit chain:', audit ? JSON.stringify(audit).slice(0, 80) : 'n/a');
  await fetch(BASE + '/api/live/close', { method: 'POST' });
  if (errs.length) bad('console errors: ' + errs.slice(0, 3).join(' | '));
  console.log(fails ? `live_attack: ${fails} FAIL` : 'live_attack: PASS');
  await b.close(); process.exit(fails ? 1 : 0);
})();
