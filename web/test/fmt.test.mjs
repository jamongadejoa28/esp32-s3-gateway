// Formatting tests (web/src/fmt.js): numbers, scale ×10, disabled sentinels, enums, input parsing,
// durations, dates.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fmt from '../src/fmt.js';
import { setLang } from '../src/i18n/index.js';

afterEach(() => setLang('ko'));

const hiTemp = { key: 'hi_temp', addr: 40027, scale: 10, signed: false, access: 'rw', min: 25, max: 50, disabled: 24.9, unit: '°C', ko: '고온설정', en: 'High temperature limit' };
const offset = { key: 'temp_offset', addr: 40021, scale: 10, signed: true, access: 'rw', min: -10, max: 10, disabled: null, unit: '°C' };
const run = { key: 'run', addr: 40005, scale: 1, runbit: true, min: 0, max: 1, disabled: null, unit: '', enum: [{ value: 0, ko: '정지', en: 'Stop' }, { value: 1, ko: '운전', en: 'Run' }] };
const hours = { key: 'cyl_hours', addr: 40059, scale: 1, min: 1000, max: 20000, disabled: null, unit: 'h' };

test('num: fixed decimals, grouping, true minus, no negative zero', () => {
  setLang('en');
  assert.equal(fmt.num(23.456, 1), '23.5');
  assert.equal(fmt.num(12345, 0), '12,345');
  assert.equal(fmt.num(-3.2, 1), '−3.2');
  assert.equal(fmt.num(-0.04, 1), '0.0');
  assert.equal(fmt.num(null), '—');
  assert.equal(fmt.num(NaN, 1), '—');
});

test('signed deltas', () => {
  setLang('en');
  assert.equal(fmt.signed(0.56, 1), '+0.6');
  assert.equal(fmt.signed(-1.24, 1), '−1.2');
  assert.equal(fmt.signed(0.01, 1), '0.0');
  assert.equal(fmt.signed(undefined), '—');
});

test('register values: scale ×10, signed, disabled sentinel, enum', () => {
  assert.equal(fmt.regValue(hiTemp, 300), '30.0');
  assert.equal(fmt.regValue(hiTemp, 249), '사용 안 함');
  setLang('en');
  assert.equal(fmt.regValue(hiTemp, 249), 'Disabled');
  assert.equal(fmt.regText(hiTemp, 249), 'Disabled');
  assert.equal(fmt.regText(hiTemp, 315), '31.5 °C');
  assert.equal(fmt.regText(offset, -5), '−0.5 °C');
  assert.equal(fmt.regValue(run, 0x0a01), 'Run', 'run bit of the full 40005 word');
  assert.equal(fmt.regValue(run, 0), 'Stop');
  assert.equal(fmt.regText(hours, 5000), '5,000 h');
  assert.equal(fmt.regValue(hours, undefined), '—');
  assert.equal(fmt.isDisabled(hiTemp, 249), true);
  assert.equal(fmt.isDisabled(offset, 0), false);
});

test('parseRegInput: format, representability at scale, range or sentinel', () => {
  assert.deepEqual(fmt.parseRegInput(hiTemp, '30.5'), { ok: true, raw: 305, value: 30.5 });
  assert.deepEqual(fmt.parseRegInput(hiTemp, '30,5'), { ok: true, raw: 305, value: 30.5 });
  assert.equal(fmt.parseRegInput(hiTemp, '24.9').raw, 249, 'sentinel accepted');
  assert.equal(fmt.parseRegInput(hiTemp, '24.8').why, 'range');
  assert.equal(fmt.parseRegInput(hiTemp, '30.55').why, 'scale');
  assert.equal(fmt.parseRegInput(hiTemp, 'abc').why, 'format');
  assert.equal(fmt.parseRegInput(hiTemp, '').why, 'format');
  assert.equal(fmt.parseRegInput(offset, '−1.5').raw, -15);
  assert.equal(fmt.parseRegInput(offset, '-10.1').why, 'range');
  assert.equal(fmt.parseRegInput(hours, '1000.5').why, 'scale');
  assert.equal(fmt.parseRegInput(hours, '20000').raw, 20000);
});

test('rangeText', () => {
  setLang('en');
  assert.equal(fmt.rangeText(hiTemp), '25.0 – 50.0 °C');
  assert.equal(fmt.rangeText(hours), '1,000 – 20,000 h');
});

test('durations, ages and run hours in both languages', () => {
  setLang('en');
  assert.equal(fmt.duration(42), '42 s');
  assert.equal(fmt.duration(600), '10 min');
  assert.equal(fmt.duration(3 * 3600 + 5 * 60), '3 h 05 min');
  assert.equal(fmt.duration(50 * 3600), '2 d 2 h');
  assert.equal(fmt.age(1500), '2 s');
  setLang('ko');
  assert.equal(fmt.duration(42), '42초');
  assert.equal(fmt.duration(3 * 3600 + 5 * 60), '3시간 05분');
  assert.equal(fmt.hoursMin(3 * 3600 + 7 * 60 + 29), '3:07');
  assert.equal(fmt.hoursMin(null), '—');
});

test('dates and axis labels use local time, 24 h', () => {
  const ms = new Date(2026, 9, 19, 7, 3, 9).getTime();
  assert.equal(fmt.dateTime(ms), '2026-10-19 07:03:09');
  assert.equal(fmt.dateTime(ms, false), '2026-10-19 07:03');
  assert.equal(fmt.clock(ms), '07:03:09');
  assert.equal(fmt.tickLabel(ms, 'm'), '07:03');
  assert.equal(fmt.tickLabel(ms, 'd'), '10-19');
  assert.equal(fmt.tickLabel(new Date(2026, 9, 19).getTime(), 'm'), '10-19', 'midnight shows the date');
  assert.equal(fmt.dateTime(null), '—');
});

test('bytes, percent, UTF-8 length', () => {
  setLang('en');
  assert.equal(fmt.bytes(512), '512 B');
  assert.equal(fmt.bytes(98304), '96 KB');
  assert.equal(fmt.bytes(7340032), '7.0 MB');
  assert.equal(fmt.pct(0.256), '26%');
  assert.equal(fmt.utf8Len('B동 전산실'), 14);
});
