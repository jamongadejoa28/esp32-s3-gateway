import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startMock, Client, until } from './helpers.mjs';
let srv, admin;
before(async () => {
  srv = await startMock(['--ready', '--devices', '2', '--no-comm-loss', '--no-faults']);
  admin = new Client(srv.base);
  assert.equal((await admin.login('admin', 'Mestio-Admin#2026')).status, 200);
});
after(async () => { if (srv) await srv.stop(); });
const hook = (path, body) => fetch(`${srv.base}/__mock/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
test('alarm deletion is per-event/device/range, preserves active equipment alarms and non-alarm logs, and is audited', async () => {
  await hook('fault', { dev: 0, coil: 23, on: true });
  await until(async () => (await admin.get('/alarms/active')).json.some((a) => a.key === '0:leak'));
  const history = await admin.expect('GET', '/alarms/history', 200, 'alarms-history.response');
  assert.ok(history.json.items.length);
  const event = history.json.items.find((a) => a.id === 'leak' && a.dev === 0 && a.type === 'raise');
  assert.ok(event);
  const body = { mode: 'one', seq: event.seq, dev: 0 };
  const removed = await admin.expect('DELETE', '/alarms/history', 200, 'alarms-history-delete.response', { body });
  assert.equal(removed.json.deleted, 1);
  assert.equal((await admin.req('DELETE', '/alarms/history', { body })).json.deleted, 0, 'idempotent');
  assert.ok((await admin.get('/alarms/active')).json.some((a) => a.key === '0:leak'), 'deleting its raise event does not clear the current alarm');
  const all = await admin.expect('DELETE', '/alarms/history', 200, 'alarms-history-delete.response', { body: { mode: 'all', dev: 0 } });
  assert.ok(all.json.deleted >= 0);
  assert.ok((await admin.get('/system/logs?kind=system')).json.items.some((x) => x.type === 'boot'), 'system events survive');
  assert.ok((await admin.get('/system/logs?kind=audit')).json.items.some((x) => x.type === 'history_delete'), 'deletion audit survives');
  for (const body of [{}, { mode: 'one' }, { mode: 'all', seq: 1 }, { mode: 'range', from: 5, to: 1 }, { mode: 'all', dev: 9 }]) {
    await admin.expect('DELETE', '/alarms/history', 422, null, { body });
  }
  await hook('fault', { dev: 0, coil: 23, on: false });
  await until(async () => !(await admin.get('/alarms/active')).json.some((a) => a.key === '0:leak'));
  assert.ok((await admin.get('/alarms/history')).json.items.some((a) => a.id === 'leak' && a.type === 'clear'), 'device recovery creates a new clear event after deletion');
});
test('measurement deletion targets one device and keeps polling/registration and other devices intact', async () => {
  const other = (await admin.get('/devices/1/history?span=3600&res=1')).json.ch.temp.filter((n) => n !== null).length;
  assert.ok(other > 100);
  await admin.expect('DELETE', '/devices/0/history', 204);
  const cleared = await admin.expect('GET', '/devices/0/history?span=3600&res=1', 200, 'history.response');
  assert.ok(cleared.json.ch.temp.filter((n) => n !== null).length < 3);
  assert.ok((await admin.get('/devices/1/history?span=3600&res=1')).json.ch.temp.filter((n) => n !== null).length >= other);
  assert.equal((await admin.get('/devices')).json.length, 2);
});
test('destructive history APIs require admin and CSRF; display flags persist independently from serial settings', async () => {
  for (const role of ['viewer', 'operator']) {
    await admin.expect('POST', '/users', 201, 'user.response', { body: { name: role, role, password: 'Temp-Start#2026', must_change: false } });
    const c = new Client(srv.base);
    assert.equal((await c.login(role, 'Temp-Start#2026')).status, 200);
    await c.expect('DELETE', '/devices/0/history', 403);
    await c.expect('DELETE', '/alarms/history', 403, null, { body: { mode: 'all' } });
    await c.post('/auth/logout');
  }
  await admin.expect('DELETE', '/alarms/history', 403, null, { body: { mode: 'all' }, csrf: false });
  const old = (await admin.get('/config/modbus')).json;
  const devices = old.devices.map((d) => ({ ...d, display_mask: d.id === 0 ? 1 : 0x3fffff }));
  await admin.expect('PUT', '/config/modbus', 200, 'config-modbus.response', { body: { devices } });
  const after = (await admin.put('/config/modbus', { poll_ms: 2000 })).json;
  assert.deepEqual(after.devices, devices, 'port/timing edit preserves channel display flags');
  assert.deepEqual(after.port, old.port);
  assert.equal((await admin.get('/devices')).json[0].display_mask, 1);
});
