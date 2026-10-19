// Axis helpers: "nice" numeric ticks, a y-domain with hysteresis (the scale only moves when the data
// leaves it or shrinks well inside it, so live charts do not jitter), and local-time x ticks.

/** Nice step (1, 2, 2.5, 5 × 10^k) so that `range` is covered by about `target` intervals. */
export function niceStep(range, target) {
  if (!(range > 0) || !(target > 0)) return 1;
  const raw = range / target;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const f = raw / mag;
  const m = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
  return m * mag;
}

/** Decimals needed to print every multiple of `step` exactly (0..4). */
export function stepDecimals(step) {
  for (let d = 0; d < 4; d++) {
    if (Math.abs(Math.round(step * 10 ** d) - step * 10 ** d) < 1e-9) return d;
  }
  return 4;
}

/**
 * Nice ticks covering [min, max] with about `count` intervals.
 * @returns {{min: number, max: number, step: number, ticks: number[], decimals: number}}
 */
export function niceTicks(min, max, count = 4) {
  if (!Number.isFinite(min) || !Number.isFinite(max)) return { min: 0, max: 1, step: 1, ticks: [0, 1], decimals: 0 };
  if (max < min) [min, max] = [max, min];
  if (max - min < 1e-9) {
    const pad = Math.abs(min) > 1 ? Math.abs(min) * 0.01 : 0.5;
    min -= pad;
    max += pad;
  }
  const step = niceStep(max - min, count);
  const lo = Math.floor(min / step + 1e-9) * step;
  const hi = Math.ceil(max / step - 1e-9) * step;
  const decimals = stepDecimals(step);
  const ticks = [];
  for (let v = lo, k = 0; v <= hi + step * 1e-6 && k < 64; v = lo + step * ++k) ticks.push(+(Math.round(v / step) * step).toFixed(decimals));
  return { min: ticks[0] ?? lo, max: ticks[ticks.length - 1] ?? hi, step, ticks, decimals };
}

/**
 * Y domain with hysteresis. update() returns true when the domain changed.
 * The domain grows immediately when data leaves it, and shrinks only when the data span uses
 * less than `shrink` of it (default 35 %), so steady signals keep a stable grid.
 */
export class YDomain {
  constructor({ count = 4, minSpan = 1, shrink = 0.35 } = {}) {
    this.count = count;
    this.minSpan = minSpan;
    this.shrink = shrink;
    this.d = null;
  }

  update(lo, hi) {
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return false;
    if (hi - lo < this.minSpan) {
      const c = (lo + hi) / 2;
      lo = c - this.minSpan / 2;
      hi = c + this.minSpan / 2;
    }
    const d = this.d;
    if (d && lo >= d.min && hi <= d.max && (hi - lo) >= this.shrink * (d.max - d.min)) return false;
    const pad = (hi - lo) * 0.08;
    this.d = niceTicks(lo - pad, hi + pad, this.count);
    return !d || d.min !== this.d.min || d.max !== this.d.max;
  }

  reset() { this.d = null; }
}

const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;
export const TIME_STEPS = [S, 2 * S, 5 * S, 10 * S, 15 * S, 30 * S, M, 2 * M, 5 * M, 10 * M, 15 * M, 30 * M, H, 2 * H, 3 * H, 6 * H, 12 * H, D, 2 * D, 7 * D];

/**
 * Local-time ticks for [t0, t1] (ms) on a plot `width` px wide, labels at least `minPx` apart.
 * Steps below a day are aligned to local wall-clock multiples (e.g. :00, :15); day steps to local
 * midnight. `tzOffsetMin(t)` returns Date#getTimezoneOffset() for t (injectable for tests).
 * @returns {{step: number, ticks: number[], unit: 's'|'m'|'d'}}
 */
export function timeTicks(t0, t1, width, minPx = 84, tzOffsetMin = (t) => new Date(t).getTimezoneOffset()) {
  const span = t1 - t0;
  if (!(span > 0) || !(width > 0)) return { step: H, ticks: [], unit: 'm' };
  const pxPerMs = width / span;
  let step = TIME_STEPS[TIME_STEPS.length - 1];
  for (const s of TIME_STEPS) {
    if (s * pxPerMs >= minPx) { step = s; break; }
  }
  const ticks = [];
  const off = (t) => -tzOffsetMin(t) * M; // local = utc + off
  let first;
  if (step < D) {
    const lo = t0 + off(t0);
    first = Math.ceil(lo / step) * step - off(t0);
  } else {
    const local = t0 + off(t0);
    first = Math.ceil(local / D) * D - off(t0);
  }
  for (let t = first, k = 0; t <= t1 && k < 200; k++) {
    ticks.push(t);
    if (step < D) t += step;
    else {
      // walk whole local days so DST changes keep ticks on midnight
      const next = t + step;
      t = next + (off(t) - off(next));
    }
  }
  return { step, ticks, unit: step < M ? 's' : step < D ? 'm' : 'd' };
}
