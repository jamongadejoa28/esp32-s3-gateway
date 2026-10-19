// Small pure helpers: SHA-256 fallback, IPv4/CIDR validation, password policy hints, router parsing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { sha256Sync, sha256Hex } from '../src/sha256.js';
import { isIp, ipNum, isMask, prefixOf, parseCidr, overlaps, sameSubnet, AP_NET, AP_MASK } from '../src/ip4.js';
import { policyState, policyOk } from '../src/password.js';

test('sha256 fallback matches node:crypto (FIPS 180-4 vectors and boundary lengths)', async () => {
  const ref = (b) => createHash('sha256').update(b).digest('hex');
  assert.equal(sha256Sync(new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Sync(new TextEncoder().encode('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for (const n of [1, 55, 56, 63, 64, 65, 119, 120, 1000, 65537]) {
    const b = randomBytes(n);
    assert.equal(sha256Sync(new Uint8Array(b)), ref(b), `len ${n}`);
  }
  const big = randomBytes(3 * 1024 * 1024);
  const t0 = Date.now();
  assert.equal(sha256Sync(new Uint8Array(big)), ref(big));
  assert.ok(Date.now() - t0 < 5000, '3 MB in reasonable time');
  const ab = new Uint8Array(randomBytes(777)).buffer;
  assert.equal(await sha256Hex(ab), ref(Buffer.from(ab)));
});

test('IPv4 helpers', () => {
  assert.ok(isIp('192.168.10.150'));
  assert.ok(!isIp('192.168.10.256'));
  assert.ok(!isIp('1.2.3'));
  assert.equal(ipNum('10.0.0.1'), 0x0a000001);
  assert.equal(ipNum('x'), null);
  assert.ok(isMask('255.255.255.0'));
  assert.ok(isMask('255.255.255.255'));
  assert.ok(!isMask('255.0.255.0'));
  assert.ok(!isMask('0.0.0.0'));
  assert.equal(prefixOf('255.255.240.0'), 20);
  assert.deepEqual(parseCidr('10.0.0.0/8'), { net: 0x0a000000, bits: 8 });
  assert.deepEqual(parseCidr('192.168.10.20'), { net: ipNum('192.168.10.20'), bits: 32 });
  assert.equal(parseCidr('10.0.0.1/8'), null, 'host bits must be zero');
  assert.equal(parseCidr('10.0.0.0/33'), null);
  assert.equal(parseCidr('nope'), null);
  assert.ok(overlaps('192.168.150.20', '255.255.255.0', AP_NET, AP_MASK));
  assert.ok(overlaps('192.168.0.1', '255.255.0.0', AP_NET, AP_MASK), 'a /16 containing the AP subnet overlaps');
  assert.ok(!overlaps('192.168.10.150', '255.255.255.0', AP_NET, AP_MASK));
  assert.ok(sameSubnet('192.168.10.150', '192.168.10.1', '255.255.255.0'));
  assert.ok(!sameSubnet('192.168.10.150', '192.168.11.1', '255.255.255.0'));
});

test('password policy hints mirror API.md §4.1', () => {
  assert.ok(policyOk('Plant-Room#2026', 'admin', 'mestio150!'));
  const s = policyState('short', 'admin');
  assert.equal(s.min_length, false);
  assert.equal(policyState('abcdefghij', 'x').classes, false);
  assert.equal(policyState('abcdefghiJ1', 'x').classes, true);
  assert.equal(policyState('Operator1!x', 'operator1!x').not_username, false);
  assert.equal(policyState('Same-Pass#1', 'u', 'Same-Pass#1').not_previous, false);
  assert.equal(policyState(`Ab1-${'가'.repeat(21)}`, 'u').max_length, false, '64 bytes, not characters');
  assert.equal(policyState('Ab1-\u0001xxxxxx', 'u').charset, false);
});

test('router hash parsing', async () => {
  const { parseHash } = await import('../src/router.js');
  assert.deepEqual(parseHash('#/settings/network'), { view: 'settings', args: ['network'] });
  assert.deepEqual(parseHash('#/alarms/history'), { view: 'alarms', args: ['history'] });
  // a malformed %-escape must not throw inside the hashchange handler
  assert.deepEqual(parseHash('#/settings/%E0'), { view: 'settings', args: ['%E0'] });
  assert.deepEqual(parseHash('#/%E0%A4%A'), { view: 'dashboard', args: [] });
  assert.deepEqual(parseHash(''), { view: 'dashboard', args: [] });
  assert.deepEqual(parseHash('#/nope/x'), { view: 'dashboard', args: [] });
});

test('ws: a silent socket is dropped and a reconnect is scheduled without waiting for onclose', async () => {
  const { LiveSocket } = await import('../src/ws.js');
  const statuses = [];
  const ls = new LiveSocket({ status: (s) => statuses.push(s), message() {}, opened() {}, failed() {} });
  let closed = 0;
  const fake = { readyState: 1, close() { closed++; this.readyState = 2; }, onclose: () => { throw new Error('must be detached'); }, onmessage: () => {}, send() {} };
  ls.ws = fake;
  ls.stopped = false;
  ls.lastRx = Date.now() - 31000;
  ls.tick();
  try {
    assert.equal(closed, 1);
    assert.equal(ls.ws, null);
    assert.equal(fake.onclose, null, 'handlers detached: a late close event cannot schedule twice');
    assert.deepEqual(statuses, ['reconnecting']);
    assert.ok(ls.timer, 'reconnect timer armed');
    assert.equal(ls.attempt, 1);
  } finally {
    clearTimeout(ls.timer);
  }
});

test('settings: every config section code resolves to a label in both languages', async () => {
  const { default: ko } = await import('../src/i18n/ko.js');
  const { default: en } = await import('../src/i18n/en.js');
  // set_system.js maps sections like this (SECTIONS order = cfg_section_t; 0x7f = secrets)
  const src = (await import('node:fs')).readFileSync(new URL('../src/views/set_system.js', import.meta.url), 'utf8');
  const sections = JSON.parse(/const SECTIONS = (\[[^\]]+\]);/.exec(src)[1].replace(/'/g, '"'));
  const cfgh = (await import('node:fs')).readFileSync(new URL('../../components/store/include/store/config.h', import.meta.url), 'utf8');
  const cnames = [...cfgh.matchAll(/CFG_SEC_([A-Z]+) = (\d+),/g)].sort((a, b) => a[2] - b[2]).map((m) => m[1].toLowerCase());
  assert.deepEqual(sections, cnames, 'SECTIONS follows cfg_section_t');
  assert.match(cfgh, /CFG_SEC_SECRETS = 0x7F/);
  assert.match(src, /CFG_SEC_SECRETS = 0x7f/);
  const { sectionLabel, logDetail } = await import('../src/views/set_system.js');
  const { setLang } = await import('../src/i18n/index.js');
  for (const l of ['ko', 'en']) {
    setLang(l);
    const dict = l === 'ko' ? ko : en;
    for (const s of [...sections, 'secrets']) {
      const label = sectionLabel(s);
      assert.ok(!/^(set|sl)\./.test(label), `${l}: ${s} -> ${label}`);
      assert.ok(Object.values(dict).includes(label));
    }
    assert.equal(logDetail({ type: 'config_change', code: 6, extra: 4 }), `${sectionLabel('security')} · rev 4`);
    assert.equal(logDetail({ type: 'config_change', code: 0x7f, extra: 5 }), `${sectionLabel('secrets')} · rev 5`);
    assert.notEqual(sectionLabel('secrets'), sectionLabel('general'));
    // account actions show the account named by their user_target record (eventlog.h AUD_USER_TARGET)
    const { t } = await import('../src/i18n/index.js');
    assert.equal(logDetail({ type: 'user_add', value: 2, extra: 0 }, 'op1'), `${t('log.target', { u: 'op1' })} · ${t('role.operator')}`);
    assert.equal(logDetail({ type: 'user_del', value: 0, extra: 0 }, 'op1'), t('log.target', { u: 'op1' }));
    assert.equal(logDetail({ type: 'password', value: 0, extra: 1 }, 'op1'), `${t('log.target', { u: 'op1' })} · ${t('log.pw_reset')}`);
    assert.equal(logDetail({ type: 'password', value: 0, extra: 0 }), t('log.pw_self'));
    assert.equal(logDetail({ type: 'user_target', code: 39, value: 0, extra: 17 }), `${t('log.t.user_del')} · #17`);
  }
  const evh = (await import('node:fs')).readFileSync(new URL('../../components/store/include/store/eventlog.h', import.meta.url), 'utf8');
  for (const [ty, n] of Object.entries({ password: 36, user_add: 37, user_mod: 38, user_del: 39 })) {
    assert.match(evh, new RegExp(`= ${n},\\s*/\\* "${ty}"`), `${ty} is ${n} in eventlog.h`);
  }
  setLang('ko');
});

test('native DOM insertion calls never receive a possibly-null argument (would render "null")', async () => {
  // Element.append/replaceChildren/... stringify null; only dom.js h()/replace() skip it. Scan every
  // such call in web/src and reject a top-level argument that can evaluate to null/undefined.
  const { readFileSync, readdirSync } = await import('node:fs');
  const { join } = await import('node:path');
  const root = new URL('../src/', import.meta.url).pathname;
  const files = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.js') && files.push(join(d, e.name))); };
  walk(root);
  const bad = [];
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/\.(append|prepend|replaceChildren|before|after|replaceWith)\(/g)) {
      let i = m.index + m[0].length;
      let depth = 0;
      let arg = '';
      const args = [];
      for (; i < src.length; i++) {
        const c = src[i];
        if ('([{'.includes(c)) depth++;
        else if (')]}'.includes(c)) { if (depth === 0) break; depth--; }
        if (c === ',' && depth === 0) { args.push(arg); arg = ''; } else arg += c;
      }
      args.push(arg);
      // only the depth-0 text of each argument matters (nested h(...) props may use null freely)
      const top = (a) => { let d = 0; let s = ''; for (const c of a) { if ('([{'.includes(c)) d++; else if (')]}'.includes(c)) d--; else if (d === 0) s += c; } return s; };
      for (const a of args) if (/\b(null|undefined)\b/.test(top(a))) bad.push(`${f.slice(root.length)}: .${m[1]}(${a.trim().slice(0, 60)})`);
    }
  }
  assert.deepEqual(bad, []);
});
