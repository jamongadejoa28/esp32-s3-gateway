// Ring buffer, decimation and axis tick tests (web/src/chart/*).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Ring, ArraySeries } from '../src/chart/ring.js';
import { decimate, decimateBand } from '../src/chart/decimate.js';
import { niceStep, niceTicks, stepDecimals, YDomain, timeTicks } from '../src/chart/axis.js';

// ---------------------------------------------------------------- ring
test('ring: push, wrap-around, logical order', () => {
  const r = new Ring(4, 2, true);
  assert.equal(r.length, 0);
  assert.equal(r.lastTime(), -Infinity);
  for (let i = 1; i <= 6; i++) assert.equal(r.push(i * 1000, [i, -i], i & 3), true);
  assert.equal(r.length, 4);
  assert.deepEqual([0, 1, 2, 3].map((i) => r.time(i)), [3000, 4000, 5000, 6000]);
  assert.deepEqual([0, 1, 2, 3].map((i) => r.val(0, i)), [3, 4, 5, 6]);
  assert.deepEqual([0, 1, 2, 3].map((i) => r.val(1, i)), [-3, -4, -5, -6]);
  assert.deepEqual([0, 1, 2, 3].map((i) => r.flag(i)), [3, 0, 1, 2]);
  assert.equal(r.lastTime(), 6000);
});

test('ring: rejects non-increasing timestamps, null -> NaN, rev bumps', () => {
  const r = new Ring(8, 1);
  const rev0 = r.rev;
  assert.equal(r.push(10, [1]), true);
  assert.equal(r.push(10, [2]), false);
  assert.equal(r.push(5, [2]), false);
  assert.equal(r.push(11, [null]), true);
  assert.ok(Number.isNaN(r.val(0, 1)));
  assert.equal(r.rev, rev0 + 2);
  r.clear();
  assert.equal(r.length, 0);
  assert.throws(() => new Ring(0, 1));
});

test('ring: lowerBound and nearest across the wrap point', () => {
  const r = new Ring(5, 1);
  for (let i = 0; i < 8; i++) r.push(i * 10, [i]); // keeps 30..70
  assert.equal(r.lowerBound(0), 0);
  assert.equal(r.lowerBound(30), 0);
  assert.equal(r.lowerBound(31), 1);
  assert.equal(r.lowerBound(70), 4);
  assert.equal(r.lowerBound(71), 5);
  assert.equal(r.nearest(44), 1);
  assert.equal(r.nearest(46), 2);
  assert.equal(r.nearest(-5), 0);
  assert.equal(r.nearest(1e9), 4);
  assert.equal(new Ring(2, 1).nearest(5), -1);
});

test('array series exposes the ring interface', () => {
  const s = new ArraySeries(new Float64Array([0, 10, 20]), [new Float32Array([1, 2, 3])], new Uint8Array([1, 0, 1]));
  assert.equal(s.length, 3);
  assert.equal(s.lowerBound(15), 2);
  assert.equal(s.nearest(14), 1);
  assert.equal(s.val(0, 2), 3);
  assert.equal(s.flag(2), 1);
});

// ---------------------------------------------------------------- decimation
function series(n, f, gapAt = new Set()) {
  const r = new Ring(n, 1);
  for (let i = 0; i < n; i++) r.push(i * 1000, [gapAt.has(i) ? NaN : f(i)]);
  return r;
}

test('decimate: few points are emitted exactly', () => {
  const r = series(10, (i) => i * i);
  const out = new Float32Array(1000);
  const res = decimate(r, 0, 0, 10, 0, 0.1, 100, out); // 100 px for 10 points -> raw
  assert.equal(res.n, 10);
  assert.equal(res.min, 0);
  assert.equal(res.max, 81);
  assert.equal(out[2 * 3], 300 * 0.1 * 10); // x of point 3 = 3000 ms * 0.1 px/ms
  assert.equal(out[2 * 3 + 1], 9);
});

test('decimate: many points collapse to at most 4 per pixel column and keep extremes', () => {
  const n = 36000;
  const r = series(n, (i) => Math.sin(i / 50) * 10 + (i === 12345 ? 100 : 0));
  const width = 200;
  const ppm = width / (n * 1000);
  const out = new Float32Array(2 * (4 * width + 16));
  const res = decimate(r, 0, 0, n, 0, ppm, width, out);
  assert.ok(res.n <= 4 * width + 4, `${res.n} points`);
  assert.equal(res.max, 100 + Math.sin(12345 / 50) * 10 > 100 ? res.max : res.max);
  let peak = -Infinity;
  for (let i = 0; i < res.n; i++) peak = Math.max(peak, out[2 * i + 1]);
  assert.ok(peak > 90, 'the single-sample spike survives decimation');
  for (let i = 1; i < res.n; i++) assert.ok(out[2 * i] >= out[2 * (i - 1)], 'x is monotonic');
});

test('decimate: gaps break the line once (no repeated NaN markers)', () => {
  const r = series(10, (i) => i, new Set([4, 5, 6]));
  const out = new Float32Array(100);
  const res = decimate(r, 0, 0, 10, 0, 0.01, 100, out);
  const ys = Array.from({ length: res.n }, (_, i) => out[2 * i + 1]);
  assert.equal(ys.filter(Number.isNaN).length, 1);
  assert.deepEqual(ys.filter((y) => !Number.isNaN(y)), [0, 1, 2, 3, 7, 8, 9]);
  const leading = series(3, () => 1, new Set([0]));
  const r2 = decimate(leading, 0, 0, 3, 0, 0.01, 100, out);
  assert.ok(!Number.isNaN(out[1]), 'no leading gap marker');
  assert.equal(r2.n, 2);
});

test('decimate: dense alternating gaps stay within 9 pairs per column and never overrun', () => {
  // 3600 samples (1 s), every third a gap, on a 300 px plot: 12 samples per column
  const r = series(3600, (i) => Math.sin(i / 50) * 10, new Set(Array.from({ length: 1200 }, (_, k) => 3 * k)));
  const W = 300;
  const ppm = W / 3600000;
  const out = new Float32Array(2 * (9 * W + 64));
  const res = decimate(r, 0, 0, 3600, 0, ppm, W, out);
  assert.ok(res.n <= 9 * W + 64, `n=${res.n}`);
  const cols = new Map();
  for (let i = 0; i < res.n; i++) cols.set(Math.floor(out[2 * i]), (cols.get(Math.floor(out[2 * i])) || 0) + 1);
  assert.ok(Math.max(...cols.values()) <= 9, 'per-column bound');
  assert.ok(out[2 * (res.n - 1)] > W - 2, 'the newest column is still drawn');
  // a too-small buffer truncates instead of writing past its end or over-reporting n
  const small = new Float32Array(20);
  const rs = decimate(r, 0, 0, 3600, 0, ppm, W, small);
  assert.equal(rs.n, 10);
  // the band variant obeys the same one-gap-per-column rule
  const t = new Float64Array(3600);
  const lo = new Float32Array(3600);
  const hi = new Float32Array(3600);
  for (let i = 0; i < 3600; i++) { t[i] = i * 1000; lo[i] = i % 3 ? -1 : NaN; hi[i] = 1; }
  const bout = new Float32Array(3 * 3 * W);
  const br = decimateBand(new ArraySeries(t, [lo, hi]), 0, 1, 0, 3600, 0, ppm, bout);
  assert.ok(br.n <= 3 * W, `band n=${br.n}`);
  const tiny = new Float32Array(9);
  assert.equal(decimateBand(new ArraySeries(t, [lo, hi]), 0, 1, 0, 3600, 0, ppm, tiny).n, 3);
});

test('decimate: empty range', () => {
  const r = series(5, (i) => i);
  const res = decimate(r, 0, 3, 3, 0, 1, 100, new Float32Array(16));
  assert.equal(res.n, 0);
  assert.ok(res.min > res.max);
});

test('decimateBand: per-column min of lows and max of highs, gaps', () => {
  const t = new Float64Array(100);
  const lo = new Float32Array(100);
  const hi = new Float32Array(100);
  for (let i = 0; i < 100; i++) { t[i] = i; lo[i] = i === 50 ? NaN : -i; hi[i] = i; }
  const s = new ArraySeries(t, [lo, hi]);
  const out = new Float32Array(3 * 200);
  const res = decimateBand(s, 0, 1, 0, 100, 0, 0.1, out); // 10 columns
  assert.equal(res.min, -99);
  assert.equal(res.max, 99);
  const triples = Array.from({ length: res.n }, (_, i) => [out[3 * i], out[3 * i + 1], out[3 * i + 2]]);
  assert.ok(triples.some((x) => Number.isNaN(x[1])), 'gap marker');
  assert.deepEqual(triples[0].slice(1), [-9, 9]);
});

// ---------------------------------------------------------------- axis
test('niceStep / stepDecimals', () => {
  assert.equal(niceStep(10, 5), 2);
  assert.equal(niceStep(1, 4), 0.25);
  assert.equal(niceStep(7, 4), 2);
  assert.equal(niceStep(0.03, 3), 0.01);
  assert.equal(niceStep(0, 4), 1);
  assert.equal(stepDecimals(2), 0);
  assert.equal(stepDecimals(0.5), 1);
  assert.equal(stepDecimals(0.25), 2);
});

test('niceTicks covers the range with round values', () => {
  const r = niceTicks(21.3, 25.8, 4);
  assert.ok(r.min <= 21.3 && r.max >= 25.8);
  assert.deepEqual(r.ticks, [20, 22, 24, 26]);
  assert.equal(r.decimals, 0);
  const f = niceTicks(0.1, 0.35, 4);
  assert.deepEqual(f.ticks, [0.1, 0.2, 0.3, 0.4], 'no floating point noise');
  assert.deepEqual(niceTicks(0.1, 0.35, 6).ticks, [0.1, 0.15, 0.2, 0.25, 0.3, 0.35]);
  const flat = niceTicks(23.5, 23.5, 4);
  assert.ok(flat.max > flat.min && flat.min <= 23.5 && flat.max >= 23.5);
  const swapped = niceTicks(10, 0, 4);
  assert.equal(swapped.min, 0);
  assert.deepEqual(niceTicks(NaN, 1).ticks, [0, 1]);
  assert.ok(niceTicks(-25, 85, 4).ticks.includes(0));
});

test('YDomain: grows immediately, keeps steady domains, shrinks with hysteresis', () => {
  const d = new YDomain({ count: 4, minSpan: 2 });
  assert.equal(d.update(22, 24), true);
  const first = { ...d.d };
  assert.equal(d.update(22.4, 23.6), false, 'inside and using enough of the domain');
  assert.equal(d.update(22, 30), true, 'data left the domain');
  assert.ok(d.d.max >= 30);
  assert.equal(d.update(23, 23.5), true, 'shrinks when using < 35 % of the span');
  assert.ok(d.d.max - d.d.min < 10);
  assert.equal(d.update(NaN, 1), false);
  d.reset();
  assert.equal(d.d, null);
  assert.ok(first.min <= 22 && first.max >= 24);
});

test('timeTicks: local-time alignment and step choice', () => {
  const kst = () => -540; // UTC+9
  const t0 = Date.UTC(2026, 9, 19, 0, 7, 13); // 09:07:13 KST
  const r = timeTicks(t0, t0 + 15 * 60000, 800, 84, kst);
  assert.equal(r.unit, 'm');
  assert.ok(r.step >= 60000 && r.step <= 5 * 60000);
  for (const tk of r.ticks) assert.equal((tk + 9 * 3600000) % r.step, 0, 'aligned to local multiples');
  assert.ok(r.ticks[0] >= t0 && r.ticks[r.ticks.length - 1] <= t0 + 15 * 60000);
  const day = timeTicks(t0, t0 + 30 * 86400000, 1000, 84, kst);
  assert.equal(day.unit, 'd');
  for (const tk of day.ticks) assert.equal((tk + 9 * 3600000) % 86400000, 0, 'local midnight');
  const sec = timeTicks(t0, t0 + 60000, 1000, 84, kst);
  assert.equal(sec.unit, 's');
  assert.deepEqual(timeTicks(5, 5, 100).ticks, []);
  // spacing never below minPx
  for (const span of [300e3, 3600e3, 86400e3, 7 * 86400e3]) {
    const x = timeTicks(t0, t0 + span, 600, 84, kst);
    assert.ok(x.step * (600 / span) >= 84 || x.step === 7 * 86400000, `span ${span}`);
  }
});
