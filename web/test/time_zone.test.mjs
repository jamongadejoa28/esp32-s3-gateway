import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeZone, parseTimeZone, parseDisplayTime } from '../src/time_zone.js';
import { dateTime, clock, tickLabel, logTime } from '../src/fmt.js';
afterEach(() => setTimeZone(null));
test('the configured gateway zone is used instead of the browser zone for clocks, logs and axes', () => {
  setTimeZone('KST-9');
  const ms = Date.UTC(2026, 9, 20, 23, 2, 3);
  assert.equal(dateTime(ms), '2026-10-21 08:02:03');
  assert.equal(clock(ms), '08:02:03');
  assert.equal(tickLabel(ms, 'd'), '10-21');
  assert.equal(parseDisplayTime('2026-10-21T08:02:03'), ms);
  setTimeZone('IST-5:30');
  assert.equal(dateTime(ms), '2026-10-21 04:32:03');
  assert.equal(logTime(null), '시각 동기화 전');
});
test('US/EU and southern-hemisphere daylight-saving rules use the epoch-specific offset', () => {
  setTimeZone('EST5EDT,M3.2.0,M11.1.0');
  assert.equal(dateTime(Date.UTC(2026, 0, 15, 12)), '2026-01-15 07:00:00');
  assert.equal(dateTime(Date.UTC(2026, 6, 15, 12)), '2026-07-15 08:00:00');
  assert.equal(parseDisplayTime('2026-03-08T02:30:00'), null, 'DST skipped hour');
  setTimeZone('CET-1CEST,M3.5.0,M10.5.0/3');
  assert.equal(dateTime(Date.UTC(2026, 6, 15, 12)), '2026-07-15 14:00:00');
  setTimeZone('AEST-10AEDT,M10.1.0,M4.1.0/3');
  assert.equal(dateTime(Date.UTC(2026, 0, 15, 12)), '2026-01-15 23:00:00');
  assert.equal(dateTime(Date.UTC(2026, 6, 15, 12)), '2026-07-15 22:00:00');
});
test('invalid local calendar input is not silently normalized', () => {
  setTimeZone('KST-9');
  for (const text of ['', '2026-02-30T12:00', '2026-13-01T12:00', '2026-01-01T25:00']) assert.equal(parseDisplayTime(text), null);
  assert.equal(parseTimeZone('not-a-timezone'), null);
});
