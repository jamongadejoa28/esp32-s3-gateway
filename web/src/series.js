// Per-device live history buffer for the dashboard charts: one hour of 1 s samples (backfilled
// from GET /history?span=3600&res=1&stages=1 after WS hello) extended by every snap.
// Timestamps are on the CLIENT clock so the time window can be anchored to performance-based
// "now" without depending on the gateway wall clock (which may be invalid).
import { Ring } from './chart/ring.js';
import { stageBits, snapshotReady } from './live.js';

export const S_TEMP = 0;
export const S_HUM = 1;
export const S_CUR = 2;
export const S_ST = 3;
export const S_SH = 4;
export const CAP = 3600 + 600;

const STAGE_KEYS = ['blower', 'cool', 'heat', 'hum', 'dehum'];

export class DevSeries {
  constructor(cap = CAP) {
    this.ring = new Ring(cap, 5, true);
    this.pending = []; // samples received while a backfill is in flight
    this.backfilling = false;
  }

  beginBackfill() {
    this.backfilling = true;
    this.pending = [];
  }

  /**
   * Replace the buffer with a history response, then re-append live samples that arrived during
   * the request. Point i of the response is at clientNow − t0_age_ms + i·dt·1000 (API.md §4.6).
   */
  backfill(h, clientNow) {
    const r = this.ring;
    r.clear();
    const base = clientNow - h.t0_age_ms;
    const step = h.dt * 1000;
    const sc = (a, i) => (a && a[i] !== null && a[i] !== undefined ? a[i] / 10 : NaN);
    for (let i = 0; i < h.n; i++) {
      let flags = 0;
      if (h.stages) {
        STAGE_KEYS.forEach((k, b) => {
          const v = h.stages[k] ? h.stages[k][i] : null;
          if (v) flags |= 1 << b;
        });
      }
      r.push(base + i * step, [sc(h.ch.temp, i), sc(h.ch.hum, i), sc(h.ch.cur, i), sc(h.ch.st, i), sc(h.ch.sh, i)], flags);
    }
    this.backfilling = false;
    for (const p of this.pending) r.push(p.t, p.v, p.f);
    this.pending = [];
  }

  abortBackfill() {
    this.backfilling = false;
    for (const p of this.pending) this.ring.push(p.t, p.v, p.f);
    this.pending = [];
  }

  /**
   * Add a sample from live state at client time t. Offline -> gap (NaN values).
   * Samples closer than 500 ms to the previous one are dropped (snaps are ≤ 1 Hz).
   */
  add(t, st) {
    const r = st && st.regs;
    const ok = snapshotReady(st);
    const v = (a) => (ok && r[a] !== undefined ? r[a] / 10 : NaN);
    const sample = { t, v: [v('40036'), v('40037'), v('40011'), v('40012'), v('40013')], f: ok ? stageBits(st.coils) : 0 };
    if (this.backfilling) {
      this.pending.push(sample);
      if (this.pending.length > 600) this.pending.shift();
      return false;
    }
    if (t - this.ring.lastTime() < 500) return false;
    return this.ring.push(sample.t, sample.v, sample.f);
  }
}

/**
 * Convert a history response into arrays for the Trends charts.
 * @returns {{t: Float64Array, v: Float32Array[], f: Uint8Array, stages: object|null}} v order:
 *   temp, hum, cur, st, sh, tmin, tmax, hmin, hmax, cmin, cmax (NaN gaps).
 */
export function historyArrays(h, clientNow) {
  const n = h.n;
  const t = new Float64Array(n);
  const base = h.t0 !== null && h.t0 !== undefined ? null : clientNow - h.t0_age_ms;
  const keys = [['ch', 'temp'], ['ch', 'hum'], ['ch', 'cur'], ['ch', 'st'], ['ch', 'sh'],
    ['min', 'temp'], ['max', 'temp'], ['min', 'hum'], ['max', 'hum'], ['min', 'cur'], ['max', 'cur']];
  const v = keys.map(() => new Float32Array(n));
  const f = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    t[i] = (base === null ? h.t0 : base) + i * h.dt * 1000;
    keys.forEach(([g, k], s) => {
      const arr = h[g] ? h[g][k] : null;
      const x = arr ? arr[i] : (g === 'ch' ? null : h.ch[k] ? h.ch[k][i] : null);
      v[s][i] = x === null || x === undefined ? NaN : x / 10;
    });
    if (h.stages) {
      STAGE_KEYS.forEach((k, b) => { if (h.stages[k] && h.stages[k][i]) f[i] |= 1 << b; });
    }
  }
  return { t, v, f, stages: h.stages || null };
}

/** Stage run-time totals (seconds) and duty (0..1) from a history response with stages=1. */
export function stageTotals(h) {
  const out = {};
  for (const k of STAGE_KEYS) {
    const arr = h.stages ? h.stages[k] || [] : [];
    let on = 0;
    let known = 0;
    for (const x of arr) {
      if (x === null || x === undefined) continue;
      on += x;
      known += h.dt;
    }
    out[k] = { on, duty: known ? on / known : null };
  }
  return out;
}
