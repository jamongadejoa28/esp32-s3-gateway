// Contract test: the mock server against docs/api/*.schema.json and the behaviour of docs/API.md
// (auth, must_change, CSRF/Origin/Host checks, merge semantics, writes, alarms, comm loss, users,
// firmware, backup, logs, history, WebSocket frames). Also checks every API.md example.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import http from 'node:http';
import WebSocket from 'ws';
import { ROOT, schemas, valid, startMock, Client, sleep, until } from './helpers.mjs';

const ADMIN_PW = 'Plant-Room#2026';
let srv;
let A; // admin client

before(async () => {
  srv = await startMock(['--dev', '--seed', '42', '--no-comm-loss', '--no-faults']);
  A = new Client(srv.base);
});
after(async () => { if (srv) await srv.stop(); });

const hook = (path, body) => fetch(`${srv.base}/__mock/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

function wsOpen(client, { origin = srv.base, host } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { Origin: origin };
    if (client.cookie) headers.Cookie = client.cookie;
    if (host) headers.Host = host;
    const ws = new WebSocket(`ws://127.0.0.1:${srv.port}/ws`, { headers });
    const msgs = [];
    const waiters = [];
    ws.on('message', (d) => {
      const m = JSON.parse(d.toString());
      valid('ws-server', m);
      msgs.push(m);
      for (const w of [...waiters]) if (w.pred(m)) { waiters.splice(waiters.indexOf(w), 1); w.res(m); }
    });
    ws.on('open', () => resolve({
      ws, msgs,
      send: (o) => { valid('ws-client', o); ws.send(JSON.stringify(o)); },
      next: (pred, ms = 8000) => new Promise((res, rej) => {
        const hit = msgs.find(pred);
        if (hit) { msgs.splice(msgs.indexOf(hit), 1); res(hit); return; }
        const w = { pred, res: (m) => { msgs.splice(msgs.indexOf(m), 1); clearTimeout(w.tm); res(m); } };
        w.tm = setTimeout(() => { waiters.splice(waiters.indexOf(w), 1); rej(new Error('ws: timeout waiting for frame')); }, ms);
        waiters.push(w);
      }),
      closed: () => new Promise((res) => { if (ws.readyState === 3) res(ws.closeCode); else ws.on('close', (c) => res(c)); }),
    }));
    ws.on('unexpected-response', (req, res) => reject(Object.assign(new Error(`ws refused ${res.statusCode}`), { status: res.statusCode })));
    ws.on('error', (e) => { if (!e.status) reject(e); });
  });
}

test('every API.md example validates against its schema', () => {
  const md = readFileSync(join(ROOT, 'docs', 'API.md'), 'utf8');
  const re = /<!-- schema: ([\w.-]+) -->\s*```json\n([\s\S]*?)```/g;
  let n = 0;
  for (let m; (m = re.exec(md));) { valid(m[1], JSON.parse(m[2])); n++; }
  assert.ok(n >= 70, `found ${n} examples`);
});

test('the vendored validator rejects violations', () => {
  assert.ok(schemas.validate('session.response', { user: 'admin' }).length > 0);
  assert.ok(schemas.validate('auth-login.request', { user: 'a', pass: 'b', x: 1 }).some((e) => e.keyword === 'additionalProperties'));
  assert.ok(schemas.validate('alarms-ack.request', { keys: ['9:x'] }).length > 0);
  assert.ok(schemas.validate('ws-server', { t: 'snap', dev: 0 }).length > 0);
  assert.ok(schemas.validate('history.response', { t0: null, t0_age_ms: 0, dt: 2, n: 0, ch: { temp: [], hum: [], cur: [], st: [], sh: [] } }).length > 0);
});

test('unauthenticated surface, headers, host check', async () => {
  const s = await A.get('/session');
  assert.equal(s.status, 401);
  valid('empty', s.json);
  for (const [k, v] of [['content-security-policy', /default-src 'self'.*frame-ancestors 'none'/], ['x-content-type-options', /nosniff/], ['referrer-policy', /no-referrer/], ['x-frame-options', /DENY/], ['cache-control', /no-store/]]) {
    assert.match(s.headers.get(k) || '', v, k);
  }
  assert.equal(s.headers.get('server'), null);
  assert.equal(s.headers.get('access-control-allow-origin'), null);
  await A.expect('GET', '/devices', 401);
  await A.expect('GET', '/system/info', 401);
  await A.expect('GET', '/no/such/route', 404);
  // fetch() cannot override Host: use node:http (DNS rebinding check, API.md §1.1)
  const mis = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: srv.port, path: '/api/v1/session', headers: { Host: 'evil.example' } }, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(d) }));
    }).on('error', reject);
  });
  assert.equal(mis.status, 421);
  valid('error', mis.json);
  assert.equal(mis.json.error, 'misdirected');
  const idx = await A.get('//');
  assert.equal(idx.status, 200);
  assert.match(idx.text, /<svg class="sprite"/);
  const ver = readFileSync(join(ROOT, 'version.txt'), 'utf8').trim();
  assert.doesNotMatch(idx.text, /MEX150|ESP32|mestio_gw|Waveshare|<title>[^<]*\d/, 'no product/model/version on the public page');
  assert.ok(!idx.text.includes(`>${ver}<`) && !idx.text.includes(`"${ver}"`), 'firmware version not on the public page');
  const fav = await A.get('//favicon.svg');
  assert.equal(fav.status, 200);
  assert.doesNotMatch(fav.text, /<title>|<desc>|registered/);
  assert.equal((await A.get('//src/../../tools/mock_server.mjs')).status, 404);
});

test('login, forced password change, CSRF and Origin', async () => {
  const bad = await A.login('admin', 'wrong-password');
  assert.equal(bad.status, 401);
  valid('error', bad.json);
  assert.equal(bad.json.error, 'bad_credentials');
  valid('auth-login.request', { user: 'admin', pass: 'mestio150!' });
  const ok = await A.login('admin', 'mestio150!');
  assert.equal(ok.status, 200);
  valid('auth-login.response', ok.json);
  assert.equal(ok.json.must_change, true);
  assert.match(ok.headers.get('set-cookie'), /gw_sid=[A-Za-z0-9_-]{22}; Path=\/; HttpOnly; SameSite=Strict/);
  const blocked = await A.expect('GET', '/devices', 403);
  assert.equal(blocked.json.error, 'password_change_required');
  await assert.rejects(wsOpen(A), (e) => e.status === 403);
  const s = await A.expect('GET', '/session', 200, 'session.response');
  assert.equal(s.json.must_change, true);
  // CSRF + Origin on mutating routes
  const noCsrf = await A.req('POST', '/auth/password', { body: { current: 'mestio150!', new: ADMIN_PW }, csrf: false });
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.json.error, 'csrf');
  const evil = await A.req('POST', '/auth/password', { body: { current: 'mestio150!', new: ADMIN_PW }, headers: { Origin: 'http://evil.example' } });
  assert.equal(evil.status, 403);
  assert.equal(evil.json.error, 'origin');
  const weak = await A.expect('POST', '/auth/password', 422, null, { body: { current: 'mestio150!', new: 'short' } });
  assert.equal(weak.json.error, 'policy');
  assert.ok(weak.json.rules.includes('min_length'));
  const dflt = await A.expect('POST', '/auth/password', 422, null, { body: { current: 'mestio150!', new: 'mestio150!' } });
  assert.ok(dflt.json.rules.includes('not_default'));
  const wrong = await A.expect('POST', '/auth/password', 422, null, { body: { current: 'nope-nope-1', new: ADMIN_PW } });
  assert.equal(wrong.json.error, 'wrong_password');
  assert.equal(wrong.json.field, 'current');
  valid('auth-password.request', { current: 'mestio150!', new: ADMIN_PW });
  await A.expect('POST', '/auth/password', 204, null, { body: { current: 'mestio150!', new: ADMIN_PW } });
  const s2 = await A.expect('GET', '/session', 200, 'session.response');
  assert.equal(s2.json.must_change, false);
});

test('request body handling: content type, JSON, size, unknown members', async () => {
  const ct = await A.req('PUT', '/config/general', { body: '{"site":"x"}', type: 'text/plain' });
  assert.equal(ct.status, 400);
  assert.equal(ct.json.error, 'bad_request');
  const js = await A.req('PUT', '/config/general', { body: '{"site":', type: 'application/json' });
  assert.equal(js.status, 400);
  assert.equal(js.json.error, 'invalid_json');
  const big = await A.req('PUT', '/config/general', { body: JSON.stringify({ site: 'x'.repeat(9000) }) });
  assert.equal(big.status, 413);
  valid('error', big.json);
  const unk = await A.expect('PUT', '/config/general', 422, null, { body: { bogus: 1 } });
  assert.equal(unk.json.code, 'unknown_field');
  const nobody = await A.req('POST', '/system/reboot', { body: '{}' });
  assert.equal(nobody.status, 413);
});

test('meta, system, devices, live', async () => {
  const m = await A.expect('GET', '/meta/registers', 200, 'meta-registers.response');
  const etag = m.headers.get('etag');
  assert.match(etag, /^"[0-9a-f]{8}"$/);
  assert.equal((await A.req('GET', '/meta/registers', { headers: { 'If-None-Match': etag } })).status, 304);
  const set = m.json.regs.find((r) => r.addr === 40012);
  assert.deepEqual([set.min, set.max, set.scale], [5, 50, 10]);
  assert.equal(m.json.regs.find((r) => r.addr === 40027).disabled, 24.9);
  await A.expect('GET', '/meta/alarms', 200, 'meta-alarms.response');
  await A.expect('GET', '/system/info', 200, 'system-info.response');
  await A.expect('GET', '/system/network', 200, 'system-network.response');
  await A.expect('GET', '/devices', 200, 'devices.response');
  const live = await until(async () => { const r = await A.get('/devices/0/live'); return r.json.fresh && r; });
  valid('device-live.response', live.json);
  assert.ok(live.json.derived && typeof live.json.derived.temp === 'number');
  await A.expect('GET', '/devices/7/live', 404);
  await A.expect('GET', '/devices/0/stats', 200, 'device-stats.response');
});

test('history for every span, absolute ranges and CSV', async () => {
  for (const [span, dt] of [[900, 1], [3600, 5], [86400, 60], [604800, 600], [2592000, 1800]]) {
    const r = await A.expect('GET', `/devices/0/history?span=${span}&res=1&stages=1`, 200, 'history.response');
    assert.equal(r.json.dt, dt, `span ${span}`);
    assert.ok(r.json.n <= 1500 && r.json.n > 0);
    assert.equal(r.json.ch.temp.length, r.json.n);
    assert.ok(r.json.stages.cool.length === r.json.n);
    if (dt >= 60) assert.ok(r.json.min && r.json.max);
    assert.ok(r.json.ch.temp.filter((v) => v !== null).length > r.json.n * 0.5, 'mostly data');
  }
  const now = Date.now();
  const abs = await A.expect('GET', `/devices/0/history?from=${now - 7200000}&to=${now}&res=60`, 200, 'history.response');
  assert.equal(abs.json.dt, 60);
  await A.expect('GET', '/devices/0/history', 400);
  await A.expect('GET', '/devices/0/history?span=99999999', 400);
  // absolute windows before the 30-day retention are refused (t0_age_ms would break its schema)
  const old = await A.expect('GET', '/devices/0/history?from=1&to=2', 400);
  assert.equal(old.json.error, 'bad_request');
  const edge = await A.expect('GET', `/devices/0/history?from=${now - 29 * 86400000}&to=${now - 28 * 86400000}&res=60`, 200, 'history.response');
  assert.ok(edge.json.t0_age_ms <= 2678400000);
  // malformed %-escapes in path parameters are 400 bad_request, never 500
  for (const [m, pth] of [['GET', '/devices/%E0/live'], ['DELETE', '/users/%E0%A4%A'], ['GET', '/devices/%E0/history?span=900']]) {
    const r = await A.expect(m, pth, 400);
    assert.equal(r.json.error, 'bad_request', `${m} ${pth}`);
  }
  const csv = await A.get('/devices/0/history.csv?span=900&res=1');
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-type'), /text\/csv/);
  assert.match(csv.headers.get('content-disposition'), /attachment; filename="mestio-d0-/);
  assert.equal(csv.buf.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.match(csv.text, /^﻿time,temp,hum,current,set_temp,set_hum\r\n\d{4}-/);
  const csv2 = await A.get('/devices/0/history.csv?span=86400&res=60');
  assert.match(csv2.text, /temp_min,temp_max,hum_min,hum_max,current_min,current_max\r\n/);
});

test('configuration sections: GET, PUT merge, validation', async () => {
  for (const s of ['general', 'network', 'modbus', 'alarms', 'snmp', 'time', 'security', 'notify']) {
    await A.expect('GET', `/config/${s}`, 200, `config-${s}.response`);
  }
  await A.expect('GET', '/config/rules', 200, 'config-rules');
  const put = async (s, body, schema = `config-${s}.response`) => {
    valid(`config-${s}.request`, body);
    return (await A.expect('PUT', `/config/${s}`, 200, schema, { body })).json;
  };
  const g = await put('general', { site: '서버실 B' });
  assert.equal(g.site, '서버실 B');
  assert.equal(g.lang, 'ko', 'merge keeps absent members');
  const mb = await put('modbus', { poll_ms: 1000, devices: [{ id: 0, name: 'MEX150', slave: 1, enabled: true }, { id: 1, name: 'MEX150 #2', slave: 2, enabled: false }] });
  assert.equal(mb.devices.length, 2);
  const dup = await A.expect('PUT', '/config/modbus', 422, null, { body: { devices: [{ id: 0, slave: 1, enabled: true, name: 'a' }, { id: 1, slave: 1, enabled: true, name: 'b' }] } });
  assert.equal(dup.json.code, 'duplicate');
  await put('alarms', { debounce_raise: 2, sev_override: { high_hum: 2 } });
  const cleared = await put('alarms', { sev_override: {} });
  assert.deepEqual(cleared.sev_override, {});
  const badId = await A.expect('PUT', '/config/alarms', 422, null, { body: { sev_override: { rule_1: 3 } } });
  assert.equal(badId.json.code, 'unknown_field');
  const rules = [{ id: 1, name: 'Room too warm', enabled: true, dev: 0, src: 'temp', op: '>', thr: 28, hyst: 1, delay_s: 60, sev: 2 }];
  valid('config-rules', rules);
  const rr = await A.expect('PUT', '/config/rules', 200, 'config-rules', { body: rules });
  assert.equal(rr.json.length, 1);
  await put('time', { ntp: { enabled: false }, tz: 'KST-9' });
  await put('security', { idle_min: 30 });
  const lock = await A.expect('PUT', '/config/security', 422, null, { body: { ip_allow: ['10.0.0.0/8'] } });
  assert.equal(lock.json.code, 'lockout');
  await put('security', { idle_min: 15, ip_allow: [] });
  await put('notify', { syslog: { enabled: true, host: '192.168.10.20' } });
  // SNMP: v2c needs a read community; secrets are write-only
  const need = await A.expect('PUT', '/config/snmp', 422, null, { body: { v2c: true } });
  assert.equal(need.json.field, 'ro');
  const snmpReq = { enabled: true, v2c: true, ro: 'nms-read-1', v3: { users: [{ name: 'gwmonitor', access: 'ro', enabled: true, auth_pass: 'monitor-pass-1', priv_pass: 'monitor-priv-1' }, { name: 'gwadmin', access: 'rw', enabled: false }] }, traps: [{ host: '192.168.10.20', port: 162, version: 'v2c', inform: true, enabled: true, community: 'nms-trap' }] };
  const sn = await put('snmp', snmpReq);
  assert.equal(sn.ro_set, true);
  assert.equal(sn.v3.users[0].keys_set, true);
  assert.equal(sn.traps[0].community_set, true);
  assert.ok(!JSON.stringify(sn).includes('nms-read-1') && !JSON.stringify(sn).includes('monitor-pass-1'));
  // trap list replaced: same host:port keeps its community, a new one gets the default
  const sn2 = await put('snmp', { traps: [{ host: '192.168.10.20', port: 162 }, { host: '192.168.10.21' }] });
  assert.deepEqual(sn2.traps.map((x) => x.community_set), [true, false]);
  const tt = await A.expect('POST', '/snmp/test-trap', 200, 'snmp-test-trap.response');
  assert.equal(tt.json.sent.length, 2);
  const mib = await A.get('/snmp/mib');
  assert.equal(mib.status, 200);
  assert.match(mib.text, /MESTIO-GW-MIB DEFINITIONS ::= BEGIN/);
  // the real generated module (tools/gen_mib.py), not a placeholder: tables and notifications
  assert.match(mib.text, /^mexStatusTable OBJECT-TYPE/m);
  assert.match(mib.text, /^gwAlarmRaised NOTIFICATION-TYPE/m);
  await put('snmp', { enabled: false });
  await A.expect('POST', '/snmp/test-trap', 409);
  valid('time-set.request', { epoch_ms: Date.now() });
  await A.expect('POST', '/time', 204, null, { body: { epoch_ms: Date.now() } });
  await A.expect('POST', '/time', 422, null, { body: { epoch_ms: 1000 } });
});

test('network change is provisional and needs confirmation', async () => {
  const body = { eth: { mode: 'static', ip: '192.168.10.150', mask: '255.255.255.0', gw: '192.168.10.1' }, ap: { psk: 'new-ap-secret-42' } };
  valid('config-network.request', body);
  const overlap = await A.expect('PUT', '/config/network', 422, null, { body: { eth: { mode: 'static', ip: '192.168.150.20', mask: '255.255.255.0', gw: '192.168.150.1' } } });
  assert.equal(overlap.json.code, 'overlap');
  await A.expect('POST', '/config/network/confirm', 409);
  await A.expect('PUT', '/config/network', 202, 'network-apply.response', { body });
  const pend = await A.expect('GET', '/config/network', 200, 'config-network.response');
  assert.equal(pend.json.provisional.state, 'apply_pending');
  await A.expect('PUT', '/config/network', 423, null, { body });
  await until(async () => (await A.get('/config/network')).json.provisional?.state === 'await_confirm', 6000);
  await A.expect('POST', '/config/network/confirm', 204);
  const done = await A.expect('GET', '/config/network', 200, 'config-network.response');
  assert.equal(done.json.provisional, null);
});

test('register writes: applied/pending, rejections, run/stop, commands', async () => {
  valid('register-write.request', { value: 23.5 });
  let r = await A.req('PUT', '/devices/0/registers/40012', { body: { value: 23.5 } });
  assert.ok([200, 202].includes(r.status), r.text);
  valid('write-result.response', r.json);
  const cmd = await A.expect('GET', `/devices/0/commands/${r.json.cmd}`, 200, 'command.response');
  assert.equal(cmd.json.requested, 235);
  const reject = async (addr, body, reason) => {
    const x = await A.req('PUT', `/devices/0/registers/${addr}`, { body });
    assert.equal(x.status, 409, x.text);
    // 409 rejected bodies follow write-result.response (API.md §4.4); error.schema lacks `addr`
    // (contract issue recorded in DECISIONS.md), so only the write-result schema is checked here.
    valid('write-result.response', x.json);
    assert.equal(x.json.error, 'rejected');
    assert.equal(x.json.reason, reason);
  };
  await reject(40021, { value: 1.0 }, 'running_interlock');
  await reject(40036, { value: 20 }, 'readonly');
  await reject(40012, { value: 23.45 }, 'range');
  await reject(40012, { value: 99 }, 'range');
  await reject(40005, { raw: 2561 }, 'range');
  const unk = await A.expect('PUT', '/devices/0/registers/40099', 404, null, { body: { value: 1 } });
  assert.equal(unk.json.code, 'unknown_register');
  valid('device-run.request', { run: false });
  r = await A.req('POST', '/devices/0/run', { body: { run: false } });
  assert.ok([200, 202].includes(r.status), r.text);
  valid('write-result.response', r.json);
  await until(async () => ((await A.get('/devices/0/live')).json.regs['40005'] & 1) === 0);
  r = await A.req('PUT', '/devices/0/registers/40027', { body: { raw: 249 } }); // disabled sentinel while stopped
  assert.ok([200, 202].includes(r.status), r.text);
  r = await A.req('POST', '/devices/0/run', { body: { run: true } });
  assert.ok([200, 202].includes(r.status));
  await A.expect('GET', '/devices/0/commands/999999', 404);
});

test('alarms: raise, ack, history, CSV', async () => {
  await hook('fault', { dev: 0, coil: 23, on: true });
  const act = await until(async () => { const x = await A.get('/alarms/active'); return x.json.find((a) => a.key === '0:leak') && x; });
  valid('alarms-active.response', act.json);
  assert.equal(act.json[0].sev, 3, 'critical first');
  valid('alarms-ack.request', { keys: ['0:leak'] });
  await A.expect('POST', '/alarms/ack', 204, null, { body: { keys: ['0:leak'] } });
  const acked = (await A.get('/alarms/active')).json.find((a) => a.key === '0:leak');
  assert.equal(acked.acked, true);
  assert.equal(acked.ack_by, 'admin');
  await A.expect('POST', '/alarms/ack', 204, null, { body: { all: true } });
  await A.expect('POST', '/alarms/ack', 422, null, { body: { keys: ['bad key'] } });
  await hook('fault', { dev: 0, coil: 23, on: false });
  await until(async () => !(await A.get('/alarms/active')).json.some((a) => a.key === '0:leak'));
  const h1 = await A.expect('GET', '/alarms/history?limit=3', 200, 'alarms-history.response');
  assert.equal(h1.json.items.length, 3);
  assert.equal(h1.json.items[0].type, 'clear');
  const h2 = await A.expect('GET', `/alarms/history?limit=3&before=${h1.json.next}`, 200, 'alarms-history.response');
  assert.ok(h2.json.items[0].seq < h1.json.items[2].seq);
  await A.expect('GET', '/alarms/history?sev=3&dev=0', 200, 'alarms-history.response');
  const csv = await A.get('/alarms/history.csv');
  assert.match(csv.text, /^﻿seq,time,dev,id,code,type,sev,value,user\r\n/);
});

test('communication loss: offline, comm_lost alarm, writes rejected', async () => {
  await hook('comm', { dev: 0, online: false });
  await until(async () => (await A.get('/devices')).json[0].online === false);
  const live = await A.expect('GET', '/devices/0/live', 200, 'device-live.response');
  assert.equal(live.json.fresh, false);
  assert.ok((await A.get('/alarms/active')).json.some((a) => a.key === '0:comm_lost'));
  const w = await A.req('PUT', '/devices/0/registers/40012', { body: { value: 23 } });
  assert.equal(w.status, 409);
  assert.equal(w.json.reason, 'offline');
  await hook('comm', { dev: 0, online: true });
  await until(async () => (await A.get('/devices')).json[0].online === true);
  await until(async () => !(await A.get('/alarms/active')).json.some((a) => a.key === '0:comm_lost'));
  await A.expect('POST', '/devices/0/stats/reset', 204);
});

test('users: create, roles, limits, self-protection', async () => {
  const create = { name: 'operator1', role: 'operator', password: 'Temp-Start#2026', must_change: false };
  valid('user-create.request', create);
  await A.expect('POST', '/users', 201, 'user.response', { body: create });
  await A.expect('POST', '/users', 409, null, { body: create });
  await A.expect('POST', '/users', 422, null, { body: { name: 'weak', role: 'viewer', password: 'abc' } });
  await A.expect('GET', '/users', 200, 'users.response');
  const op = new Client(srv.base);
  assert.equal((await op.login('operator1', 'Temp-Start#2026')).status, 200);
  await op.expect('PUT', '/config/general', 403, null, { body: { site: 'x' } });
  await op.expect('GET', '/config/snmp', 403);
  await op.expect('GET', '/alarms/active', 200, 'alarms-active.response');
  valid('user-update.request', { role: 'viewer' });
  await A.expect('PUT', '/users/operator1', 200, 'user.response', { body: { role: 'viewer' } });
  await op.expect('GET', '/devices', 401); // role change revoked the session
  const self = await A.expect('DELETE', '/users/admin', 409);
  assert.equal(self.json.error, 'self');
  await A.expect('PUT', '/users/admin', 409, null, { body: { role: 'viewer' } });
  await A.expect('POST', '/users', 201, 'user.response', { body: { name: 'viewer2', role: 'viewer', password: 'Temp-Start#2026' } });
  await A.expect('POST', '/users', 201, 'user.response', { body: { name: 'viewer3', role: 'viewer', password: 'Temp-Start#2026' } });
  const lim = await A.expect('POST', '/users', 409, null, { body: { name: 'viewer4', role: 'viewer', password: 'Temp-Start#2026' } });
  assert.equal(lim.json.error, 'limit');
  for (const u of ['operator1', 'viewer2', 'viewer3']) await A.expect('DELETE', `/users/${u}`, 204);
  await A.expect('DELETE', '/users/nobody', 404);
});

test('backup/restore, logs, firmware info, core dump', async () => {
  const ex = await A.expect('GET', '/system/config/export', 200, 'config-bundle');
  assert.match(ex.headers.get('content-disposition'), /mestio-gw-config-/);
  assert.ok(!JSON.stringify(ex.json).match(/nms-read-1|psk"|password/));
  const bundle = ex.json;
  bundle.general.site = 'Restored site';
  const im = await A.expect('POST', '/system/config/import', 200, 'config-import.response', { body: bundle });
  assert.deepEqual(im.json.changed, ['general']);
  const newer = await A.expect('POST', '/system/config/import', 422, null, { body: { ...bundle, schema: 2 } });
  assert.equal(newer.json.code, 'unsupported_schema');
  for (const kind of ['audit', 'system']) {
    const l = await A.expect('GET', `/system/logs?kind=${kind}&limit=5`, 200, 'logs.response');
    assert.equal(l.json.items.length, 5);
    if (l.json.next !== null) await A.expect('GET', `/system/logs?kind=${kind}&limit=5&before=${l.json.next}`, 200, 'logs.response');
  }
  const audit = (await A.get('/system/logs?kind=audit&limit=200')).json.items;
  assert.ok(audit.some((x) => x.type === 'reg_write' && x.code === 40012));
  assert.ok(audit.some((x) => x.type === 'config_change'));
  await A.expect('GET', '/system/firmware', 200, 'firmware.response');
  await A.expect('GET', '/system/coredump', 404);
});

test('WebSocket: hello, subscription, snap deltas, ping, write, alarm, size limit', async () => {
  await assert.rejects(wsOpen(new Client(srv.base)), (e) => e.status === 401);
  await assert.rejects(wsOpen(A, { origin: 'http://evil.example' }), (e) => e.status === 403);
  await assert.rejects(wsOpen(A, { host: 'evil.example' }), (e) => e.status === 421);
  const c = await wsOpen(A);
  const hello = await c.next((m) => m.t === 'hello');
  assert.deepEqual(hello.devs, [0]);
  await sleep(1300);
  assert.ok(!c.msgs.some((m) => m.t === 'snap'), 'nothing but hello before sub');
  c.send({ t: 'sub', topics: ['snap', 'alarm', 'comm', 'write', 'sys'] });
  const full = await c.next((m) => m.t === 'snap');
  assert.equal(full.full, true);
  assert.ok('40036' in full.r && full.c !== undefined);
  const delta = await c.next((m) => m.t === 'snap');
  assert.equal(delta.full, false);
  assert.ok(Object.keys(delta.r).length < Object.keys(full.r).length);
  await c.next((m) => m.t === 'comm');
  c.send({ t: 'ping' });
  await c.next((m) => m.t === 'pong');
  await A.req('PUT', '/devices/0/registers/40013', { body: { value: 50 } });
  const wr = await c.next((m) => m.t === 'write' && m.addr === 40013);
  assert.equal(wr.by, 'admin');
  await hook('fault', { dev: 0, coil: 30, on: true });
  const al = await c.next((m) => m.t === 'alarm' && m.id === 'fire' && m.type === 'raise');
  assert.equal(al.sev, 3);
  await hook('fault', { dev: 0, coil: 30, on: false });
  await c.next((m) => m.t === 'alarm' && m.id === 'fire' && m.type === 'clear');
  await c.next((m) => m.t === 'sys', 12000);
  c.ws.send('x'.repeat(300));
  assert.equal(await c.closed(), 1009);
});

test('WebSocket: bye on logout and on session expiry; 5th client refused', async () => {
  const B = new Client(srv.base);
  await B.login('admin', ADMIN_PW);
  const socks = [];
  for (let i = 0; i < 4; i++) socks.push(await wsOpen(B));
  await assert.rejects(wsOpen(B), (e) => e.status === 503);
  await B.expect('POST', '/auth/logout', 204);
  for (const s of socks) {
    const bye = await s.next((m) => m.t === 'bye');
    assert.equal(bye.reason, 'logout');
  }
  const Cc = new Client(srv.base);
  await Cc.login('admin', ADMIN_PW);
  const w = await wsOpen(Cc);
  await hook('expire');
  const bye = await w.next((m) => m.t === 'bye');
  assert.equal(bye.reason, 'session_expired');
  await Cc.expect('GET', '/devices', 401);
});

test('rate limiting of logins (separate instance)', async () => {
  const s2 = await startMock(['--seed', '7', '--no-comm-loss', '--no-faults']);
  try {
    const c = new Client(s2.base);
    for (let i = 0; i < 4; i++) assert.equal((await c.login('admin', `wrong-${i}`)).status, 401);
    const lockedNow = await c.login('admin', 'wrong-4');
    assert.equal(lockedNow.status, 429, 'the failure that triggers the lock answers 429');
    valid('error', lockedNow.json);
    const r = await c.login('admin', 'mestio150!');
    assert.equal(r.status, 429, 'locked even with the right password');
    valid('error', r.json);
    assert.ok(r.json.retry_after > 0 && r.json.retry_after <= 300);
  } finally { await s2.stop(); }
});

test('firmware upload: hash mismatch, invalid image, success → reboot', async () => {
  A.cookie = null;
  await A.login('admin', ADMIN_PW);
  const junk = Buffer.alloc(1024, 7);
  const sha = (b) => createHash('sha256').update(b).digest('hex');
  const mm = await A.req('POST', '/system/firmware', { raw: junk, headers: { 'X-Firmware-SHA256': '0'.repeat(64) } });
  assert.equal(mm.status, 422);
  assert.equal(mm.json.error, 'hash_mismatch');
  const inv = await A.req('POST', '/system/firmware', { raw: junk, headers: { 'X-Firmware-SHA256': sha(junk) } });
  assert.equal(inv.status, 422);
  assert.equal(inv.json.error, 'image_invalid');
  const noHdr = await A.req('POST', '/system/firmware', { raw: junk });
  assert.equal(noHdr.status, 400);
  // minimal ESP app image: magic 0xE9, esp_app_desc_t at 32 (magic, version @+16, project @+48)
  const img = Buffer.alloc(4096);
  img[0] = 0xe9;
  img.writeUInt32LE(0xabcd5432, 32);
  img.write('9.9.9', 48, 'latin1');
  img.write('mestio_gw', 80, 'latin1');
  const ok = await A.req('POST', '/system/firmware', { raw: img, headers: { 'X-Firmware-SHA256': sha(img) } });
  assert.equal(ok.status, 200, ok.text);
  valid('firmware-upload.response', ok.json);
  assert.equal(ok.json.version, '9.9.9');
  await sleep(2500);
  await assert.rejects(fetch(`${srv.base}/api/v1/session`)); // rebooting: unreachable
  await sleep(6000);
  const after = await A.get('/session');
  assert.equal(after.status, 401, 'sessions do not survive a reboot');
  await A.login('admin', ADMIN_PW);
  const fw = await A.expect('GET', '/system/firmware', 200, 'firmware.response');
  assert.equal(fw.json.running.state, 'pending_verify');
  assert.equal(fw.json.running.version, '9.9.9');
});
