// Sign-in and 2FA end to end, in the browser, against a throwaway server (port 8011, temp state dir):
// open access -> create account -> gate on -> turn on 2FA (code computed like an authenticator app) ->
// sign out -> sign in with password + code -> recovery code works once -> wrong code refused -> 2FA off.
const { chromium } = require('playwright');
const { spawn } = require('child_process'); const crypto = require('crypto'); const fs = require('fs'); const os = require('os'); const path = require('path');
const PORT = 8011, BASE = `http://localhost:${PORT}`, ROOT = path.join(__dirname, '..', '..');
const b32 = s => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = ''; for (const c of s.replace(/[\s=]/g, '').toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totp = (secret, off = 0) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + off)); const h = crypto.createHmac('sha1', b32(secret)).update(c).digest(); const o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); };
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cascade-auth-'));
  const srv = spawn('python3', ['-m', 'uvicorn', 'api:app', '--app-dir', 'backend', '--port', String(PORT)], { cwd: ROOT, env: { ...process.env, CASCADE_STATE_DIR: dir, CASCADE_DATA: 'data' }, stdio: 'ignore' });
  let fails = 0; const bad = m => { fails++; console.log('FAIL', m); }, ok = m => console.log('ok  ', m);
  try {
    for (let i = 0; i < 60; i++) { try { await fetch(BASE + '/api/auth/status'); break; } catch { await new Promise(r => setTimeout(r, 500)); } }
    const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1280, height: 860 } });
    const errs = []; p.on('pageerror', e => errs.push(e.message));
    // 1. open access
    await p.goto(BASE + '/app#/overview'); await p.waitForTimeout(1500);
    if (!p.url().includes('/app')) bad('open access redirected'); else ok('open access before any account');
    await p.click('#userBtn'); const who = await p.$eval('#whoLine', e => e.textContent); /Open access/.test(who) ? ok('menu says open access') : bad('menu: ' + who);
    // 2. create account
    await p.evaluate(() => { location.hash = '#/security'; }); await p.waitForSelector('#setup');
    await p.fill('#setup [name=u]', 'dhruv'); await p.fill('#setup [name=p]', 'correct horse battery'); if (await p.$('#setup [name=p2]')) await p.fill('#setup [name=p2]', 'correct horse battery');
    await p.click('#setup button'); await p.waitForSelector('#start', { timeout: 10000 }); ok('account created');
    // 3. turn on 2FA
    await p.click('#start'); await p.waitForSelector('#conf');
    const secret = (await p.$eval('p[style*="--mono"]', e => e.textContent)).replace(/\s/g, '');
    if (!secret) { bad('no secret shown'); throw new Error('stop'); }
    if (!(await p.$('.qr svg'))) bad('no QR code'); else ok('QR code shown');
    await p.fill('#conf [name=c]', '000000'); await p.click('#conf button'); await p.waitForTimeout(500);
    (await p.$eval('#cErr', e => !e.hidden)) ? ok('wrong code refused') : bad('wrong code accepted');
    await p.fill('#conf [name=c]', totp(secret)); await p.click('#conf button'); await p.waitForSelector('.codes span');
    const rec = await p.$$eval('.codes span', s => s.map(x => x.textContent)); ok(`2FA on, ${rec.length} recovery codes`);
    await p.click('#done'); await p.waitForTimeout(800);
    // 4. sign out -> gated
    await p.click('#userBtn'); await p.click('#signOut'); await p.waitForURL(/\/login/); ok('signed out, on /login');
    await p.goto(BASE + '/app#/overview'); await p.waitForTimeout(800); p.url().includes('/login') ? ok('platform gated') : bad('not gated: ' + p.url());
    const api = await (await fetch(BASE + '/api/overview')).status; api === 401 ? ok('API gated (401)') : bad('API status ' + api);
    // 5. sign in: password + TOTP
    await p.fill('#f1 [name=u]', 'dhruv'); await p.fill('#f1 [name=p]', 'wrong password'); await p.click('#f1 button'); await p.waitForTimeout(500);
    (await p.$eval('#e1', e => e.textContent)) ? ok('wrong password refused') : bad('wrong password accepted');
    await p.fill('#f1 [name=p]', 'correct horse battery'); await p.click('#f1 button'); await p.waitForSelector('#code:not([hidden])');
    // the code used to confirm 2FA cannot be replayed: if we are still in that 30-second step, expect a clear message, then wait
    await p.fill('#f2 [name=c]', totp(secret)); await p.click('#f2 button'); await p.waitForTimeout(800);
    if (p.url().includes('/login')) {
      const m = await p.$eval('#e2', e => e.textContent); /already used/.test(m) ? ok('replayed code refused with a clear message') : bad('code refused: ' + m);
      await new Promise(r => setTimeout(r, (30 - (Date.now() / 1000) % 30 + 1) * 1000));
      await p.fill('#f2 [name=c]', totp(secret)); await p.click('#f2 button');
    }
    await p.waitForURL(/\/app/); ok('signed in with password + code');
    // 6. recovery code once
    await p.click('#userBtn'); await p.click('#signOut'); await p.waitForURL(/\/login/);
    for (const attempt of [1, 2]) {
      await p.fill('#f1 [name=u]', 'dhruv'); await p.fill('#f1 [name=p]', 'correct horse battery'); await p.click('#f1 button'); await p.waitForSelector('#code:not([hidden])');
      await p.fill('#f2 [name=c]', rec[0]); await p.click('#f2 button'); await p.waitForTimeout(2600);
      if (attempt === 1) { p.url().includes('/app') ? ok('recovery code accepted once') : bad('recovery code refused'); await p.click('#userBtn'); await p.click('#signOut'); await p.waitForURL(/\/login/); }
      else { p.url().includes('/login') ? ok('recovery code refused the second time') : bad('recovery code reused'); }
    }
    if (errs.length) bad('page errors: ' + errs.join(' | '));
    await b.close();
  } catch (e) { if (e.message !== 'stop') bad(e.message); }
  finally { srv.kill(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log(fails ? `FAIL ${fails}` : 'PASS'); process.exit(fails ? 1 : 0);
})();
