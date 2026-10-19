// Live model tests: WS snap delta merge, derived values, alarm list maintenance, live series buffer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applySnap, derive, fromRest, stageBits, equipment, applyAlarm, sortAlarms, alarmSummary, emptyLive } from '../src/live.js';
import { DevSeries, historyArrays, stageTotals, S_TEMP, S_ST } from '../src/series.js';
import { backoffDelay } from '../src/ws.js';
import { valid } from './helpers.mjs';

const C = (...n) => n.reduce((a, x) => a | (1 << (x - 1)), 0) >>> 0;
const FULL = { t: 'snap', dev: 0, seq: 10, ts: 1000, on: true, full: true, r: { 40005: 1, 40011: 42, 40012: 230, 40013: 500, 40014: 10, 40015: 10, 40016: 50, 40017: 50, 40027: 300, 40028: 49, 40029: 599, 40030: 99, 40036: 235, 40037: 480, 40004: 0 }, c: C(1, 2, 12) };

test('snap: full frame replaces, delta frames merge only listed registers', () => {
  valid('ws-server', FULL);
  const a = applySnap(undefined, FULL, 1);
  assert.equal(a.applied, true);
  assert.equal(a.state.regs['40036'], 235);
  assert.equal(a.state.coils, C(1, 2, 12));
  const delta = { t: 'snap', dev: 0, seq: 11, ts: 2000, on: true, full: false, r: { 40036: 236 } };
  valid('ws-server', delta);
  const b = applySnap(a.state, delta, 2);
  assert.deepEqual(b.changed, ['40036']);
  assert.equal(b.coilsChanged, false);
  assert.equal(b.state.regs['40012'], 230, 'unlisted registers are kept');
  assert.equal(b.state.coils, a.state.coils, 'coils kept when c is absent');
  const c = applySnap(b.state, { ...delta, seq: 12, r: {}, c: C(1) }, 3);
  assert.equal(c.coilsChanged, true);
  assert.equal(a.state.regs['40036'], 235, 'previous state is not mutated');
  // a full frame drops registers no longer reported (e.g. slow group invalid after reconfigure)
  const d = applySnap(c.state, { ...FULL, seq: 13, r: { 40036: 240 } }, 4);
  assert.deepEqual(Object.keys(d.state.regs), ['40036']);
  assert.ok(d.changed.includes('40012'));
});

test('snap: stale frames are ignored; seq wrap and restarts are accepted', () => {
  const a = applySnap(undefined, FULL, 1).state;
  assert.equal(applySnap(a, { ...FULL, full: false, seq: 9, r: { 40036: 1 } }, 2).applied, false);
  assert.equal(applySnap(a, { ...FULL, full: false, seq: 10, r: { 40036: 1 } }, 2).applied, false);
  const restarted = { ...a, seq: 4294967290 };
  assert.equal(applySnap(restarted, { ...FULL, full: false, seq: 3, r: {} }, 2).applied, true);
  assert.equal(applySnap(a, { ...FULL, seq: 2 }, 2).applied, true, 'full frames always apply');
});

test('derive: scaled values, stages, mode, delays, disabled limits', () => {
  const st = applySnap(undefined, { ...FULL, r: { ...FULL.r, 40005: (12 << 8) | 1, 40004: 1 }, c: C(1, 2, 3, 4, 8, 12, 15, 16) }, 0).state;
  const d = derive(st);
  assert.equal(d.temp, 23.5);
  assert.equal(d.hum, 48);
  assert.equal(d.current, 4.2);
  assert.equal(d.setTemp, 23);
  assert.equal(d.hiTemp, 30);
  assert.equal(d.loTemp, null, '4.9 = disabled');
  assert.equal(d.hiHum, null);
  assert.equal(d.running, true);
  assert.equal(d.delay, 12);
  assert.equal(d.runDelay, true);
  assert.deepEqual(d.stages, { blower: 1, cool: 3, heat: 1, hum: 1, dehum: 1 });
  assert.deepEqual(d.mode, ['cool', 'dehum']);
  assert.equal(derive(emptyLive()), null);
  const rest = fromRest({ seq: 1, ts: null, online: true, regs: { 40036: -50 }, coils: 0, derived: { temp: -5 } }, 5);
  assert.equal(derive(rest).temp, -5);
  assert.equal(derive(rest).setTemp, null);
});

test('stage bits and equipment matrix', () => {
  assert.equal(stageBits(C(1)), 1);
  assert.equal(stageBits(C(16)), 2, 'cool3');
  assert.equal(stageBits(C(7)), 4);
  assert.equal(stageBits(C(9)), 8);
  assert.equal(stageBits(C(15)), 16);
  const eq = equipment(C(1, 3, 20));
  assert.deepEqual(eq.find((e) => e.key === 'blower'), { key: 'blower', on: true, fault: false });
  assert.deepEqual(eq.find((e) => e.key === 'cool2'), { key: 'cool2', on: true, fault: false });
  assert.ok(eq.filter((e) => e.key.startsWith('heat')).every((e) => e.fault && !e.on));
});

test('alarm list: raise, ack, clear, ordering, summary', () => {
  const raise = (id, sev, ts, seq) => ({ t: 'alarm', dev: 0, key: `0:${id}`, id, code: 100 + seq, type: 'raise', sev, ts, seq, value: 1 });
  let l = applyAlarm([], raise('drain_fault', 1, 100, 1));
  l = applyAlarm(l, raise('leak', 3, 200, 2));
  l = applyAlarm(l, raise('blower_fault', 2, 50, 3));
  for (const m of l) valid('alarms-active.response', [m]);
  assert.deepEqual(l.map((a) => a.id), ['leak', 'blower_fault', 'drain_fault']);
  assert.deepEqual(alarmSummary(l), { total: 3, unacked: 3, maxSev: 3 });
  l = applyAlarm(l, { t: 'alarm', dev: 0, key: '0:leak', id: 'leak', code: 123, type: 'ack', sev: 3, ts: 300, seq: 4, value: 1, user: 'op' });
  const leak = l.find((a) => a.id === 'leak');
  assert.equal(leak.acked, true);
  assert.equal(leak.ack_by, 'op');
  assert.equal(leak.since, 200, 'ack keeps since');
  l = applyAlarm(l, { t: 'alarm', dev: 0, key: '0:drain_fault', id: 'drain_fault', code: 125, type: 'clear', sev: 1, ts: 400, seq: 5, value: 1 });
  assert.equal(l.length, 2);
  assert.equal(applyAlarm(l, { type: 'ack', key: '0:nothing' }).length, 2, 'ack of unknown key is ignored');
  assert.deepEqual(sortAlarms([{ sev: 1, since: 1 }, { sev: 1, since: null }]).map((a) => a.since), [null, 1]);
});

test('series: backfill places points on the client clock and merges pending live samples', () => {
  const s = new DevSeries(100);
  const h = { t0: null, t0_age_ms: 5000, dt: 1, n: 4, ch: { temp: [235, null, 236, 237], hum: [480, null, 481, 482], cur: [42, null, 41, 40], st: [230, null, 230, 230], sh: [500, null, 500, 500] }, stages: { blower: [1, null, 1, 1], cool: [1, null, 0, 1], heat: [0, null, 0, 0], hum: [0, null, 0, 0], dehum: [0, null, 0, 0] } };
  valid('history.response', h);
  s.beginBackfill();
  const live = applySnap(undefined, FULL, 0).state;
  assert.equal(s.add(100000, live), false, 'queued during backfill');
  s.backfill(h, 100000);
  const r = s.ring;
  assert.equal(r.length, 5);
  assert.equal(r.time(0), 95000);
  assert.equal(r.val(S_TEMP, 0), 23.5);
  assert.ok(Number.isNaN(r.val(S_TEMP, 1)), 'null -> gap');
  assert.equal(r.flag(0), 3, 'blower + cool');
  assert.equal(r.time(4), 100000, 'pending live sample appended after the backfill');
  assert.equal(r.val(S_ST, 4), 23);
  assert.equal(s.add(100200, live), false, 'samples closer than 500 ms are dropped');
  assert.equal(s.add(101000, { ...live, on: false }), true);
  assert.ok(Number.isNaN(r.val(S_TEMP, 5)), 'offline -> gap');
  s.beginBackfill();
  s.add(102000, live);
  s.abortBackfill();
  assert.equal(r.lastTime(), 102000);
});

test('historyArrays / stageTotals for trends', () => {
  const h = { t0: 1792371540000, t0_age_ms: 120500, dt: 60, n: 2, ch: { temp: [234, 235], hum: [479, 480], cur: [42, null], st: [230, 230], sh: [500, 500] }, min: { temp: [232, 233], hum: [476, 478], cur: [40, null] }, max: { temp: [236, 237], hum: [482, 483], cur: [44, null] }, stages: { blower: [60, 60], cool: [30, 15], heat: [0, 0], hum: [0, null], dehum: [0, 0] } };
  valid('history.response', h);
  const a = historyArrays(h, 0);
  assert.deepEqual(Array.from(a.t), [1792371540000, 1792371600000]);
  assert.ok(Math.abs(a.v[5][1] - 23.3) < 1e-5, 'temp min (Float32)');
  assert.ok(Math.abs(a.v[6][0] - 23.6) < 1e-5);
  assert.ok(Number.isNaN(a.v[2][1]));
  assert.equal(a.f[0], 3);
  const rel = historyArrays({ ...h, t0: null }, 1000000);
  assert.equal(rel.t[0], 1000000 - 120500);
  const tot = stageTotals(h);
  assert.deepEqual(tot.cool, { on: 45, duty: 45 / 120 });
  assert.deepEqual(tot.hum, { on: 0, duty: 0 });
  const fine = historyArrays({ t0: 0, t0_age_ms: 0, dt: 1, n: 1, ch: { temp: [200], hum: [300], cur: [10], st: [200], sh: [300] } }, 0);
  assert.equal(fine.v[5][0], 20, 'without min/max the envelope falls back to the value');
});

test('ws backoff: exponential, capped at 10 s, jittered ±20 %', () => {
  assert.equal(backoffDelay(0, () => 0.5), 500);
  assert.equal(backoffDelay(1, () => 0.5), 1000);
  assert.equal(backoffDelay(4, () => 0.5), 8000);
  assert.equal(backoffDelay(5, () => 0.5), 10000);
  assert.equal(backoffDelay(50, () => 0.5), 10000);
  assert.equal(backoffDelay(10, () => 1), 12000);
  assert.equal(backoffDelay(10, () => 0), 8000);
  for (let i = 0; i < 100; i++) {
    const d = backoffDelay(i % 12);
    assert.ok(d >= 400 && d <= 12000);
  }
});
