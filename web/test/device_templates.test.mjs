import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readDeviceTemplates } from '../../tools/device_templates.mjs';
import { channelRaw, deviceStatus, deviceValues, templateFor } from '../src/device_templates.js';
import { state, updateDevices, resetData } from '../src/store.js';
import { startMock, Client, valid } from './helpers.mjs';

const templates = readDeviceTemplates();
const dev = { id: 0, name: 'Unit', slave: 1, enabled: true, template_id: 'mex150' };
const lv = { known: true, on: true, seq: 1, rx: 1000, coils: 0, regs: { 40036: -55, 40037: 480, 40005: 0x0c01 } };

test('IA MEX150 template preserves the 22 channel IDs, flags, addresses and signed scaling', () => {
  valid('device-templates.response', templates);
  const tpl = templateFor(dev, templates);
  assert.equal(tpl.name, 'MST.MEX-150');
  assert.deepEqual(tpl.channels.map((c) => c.id), Array.from({ length: 22 }, (_, i) => i));
  assert.deepEqual(tpl.channels.filter((c) => c.access === 'disabled').map((c) => c.id), [3, 7, 8, 9, 10, 11, 12, 13]);
  assert.deepEqual(tpl.channels.filter((c) => c.access === 'conf_only').map((c) => c.id), [20, 21]);
  assert.deepEqual(tpl.channels.filter((c) => c.access === 'rw_conf').map((c) => c.addr), [40012, 40014, 40015, 40013, 40016, 40017]);
  assert.equal(channelRaw(tpl.channels[0], lv), -5.5);
  assert.equal(channelRaw(tpl.channels[5], lv), 1, 'delay byte is not part of the power value');
  assert.equal(channelRaw(tpl.channels[7], lv), null);
  assert.equal(channelRaw(tpl.channels[20], lv), null);
  assert.equal(templateFor({ ...dev, template_id: 'other' }, templates), undefined);
  assert.equal(templateFor({ ...dev, template_id: undefined }, templates), tpl, 'legacy device');
});

test('cards mask disabled, unknown, offline and stale data, including initial COMM failure and REST freshness', () => {
  assert.equal(deviceStatus(dev, lv, 1001, 1000), 'online');
  assert.equal(deviceValues(dev, lv, 1001, 1000).temp, -5.5);
  for (const [device, live, now, comm, status] of [
    [{ ...dev, enabled: false }, lv, 1001, null, 'disabled'],
    [dev, null, 1001, null, 'waiting'],
    [dev, null, 1001, { online: false }, 'offline'],
    [dev, { ...lv, on: false }, 1001, null, 'offline'],
    [dev, lv, 5001, null, 'stale'],
    [dev, { ...lv, fresh: false }, 1001, null, 'stale'],
    [dev, { ...lv, ready: false }, 1001, { online: true }, 'waiting'],
  ]) {
    assert.equal(deviceStatus(device, live, now, 1000, comm), status);
    assert.equal(deviceValues(device, live, now, 1000, comm), null);
  }
  assert.equal(deviceStatus(dev, lv, 14000, 10000), 'online', 'long poll uses the firmware freshness window');
});

test('reusing a device ID invalidates the old live values, history and communication state', () => {
  resetData();
  state.devices = [dev];
  for (const map of [state.live, state.series, state.comm]) map.set(0, { old: true });
  updateDevices([{ ...dev, name: 'Renamed' }]);
  assert.equal(state.live.has(0), true, 'renaming does not discard measurements');
  updateDevices([{ ...dev, slave: 2 }]);
  for (const map of [state.live, state.series, state.comm]) assert.equal(map.has(0), false);
  state.devices = [];
  resetData();
});

let server, admin;
before(async () => {
  server = await startMock(['--ready', '--no-comm-loss', '--no-faults']);
  admin = new Client(server.base);
  assert.equal((await admin.login('admin', 'Mestio-Admin#2026')).status, 200);
});
after(async () => { if (server) await server.stop(); });

test('template API, selection persistence, legacy merge and unknown-model rejection', async () => {
  const meta = await admin.expect('GET', '/meta/device-templates', 200, 'device-templates.response');
  assert.deepEqual(meta.json, templates);
  assert.equal((await admin.get('/meta/device-templates', { headers: { 'If-None-Match': meta.headers.get('etag') } })).status, 304);
  const saved = await admin.expect('PUT', '/config/modbus', 200, 'config-modbus.response', { body: { devices: [dev, { ...dev, id: 1, slave: 2, name: 'Second' }] } });
  assert.equal(saved.json.devices[1].template_id, 'mex150');
  const list = await admin.expect('GET', '/devices', 200, 'devices.response');
  assert.equal(list.json.length, 2);
  assert.equal(list.json[1].template_id, 'mex150');
  const legacy = await admin.expect('PUT', '/config/modbus', 200, 'config-modbus.response', { body: { devices: [{ id: 0 }, { id: 1, name: 'Legacy' }] } });
  assert.equal(legacy.json.devices[1].slave, 2);
  assert.equal(legacy.json.devices[1].template_id, 'mex150');
  for (const template_id of ['other', '']) {
    const r = await admin.expect('PUT', '/config/modbus', 422, null, { body: { devices: [{ ...dev, template_id }] } });
    assert.match(r.json.field, /template_id/);
  }
  assert.equal((await admin.get('/devices')).json.length, 2, 'invalid template must not alter configuration');
});

test('viewer/operator can inspect shared devices and templates, but only admin can register', async () => {
  for (const role of ['viewer', 'operator']) {
    await admin.expect('POST', '/users', 201, 'user.response', { body: { name: role, role, password: 'Temp-Start#2026', must_change: false } });
    const client = new Client(server.base);
    assert.equal((await client.login(role, 'Temp-Start#2026')).status, 200);
    await client.expect('GET', '/meta/device-templates', 200, 'device-templates.response');
    await client.expect('GET', '/devices', 200, 'devices.response');
    await client.expect('PUT', '/config/modbus', 403, null, { body: { devices: [dev] } });
    await client.post('/auth/logout');
  }
});
