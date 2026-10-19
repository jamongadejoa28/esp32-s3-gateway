// Fixed-capacity time-series ring: Float64Array timestamps (ms) + one Float32Array per series
// (NaN = gap) + an optional Uint8Array of flag bits per sample. Logical index 0 is the oldest sample.
// Timestamps must be pushed in increasing order; out-of-order pushes are rejected so binary search
// stays valid.
export class Ring {
  /**
   * @param {number} cap capacity in samples
   * @param {number} nSeries number of value series
   * @param {boolean} [flags] keep a Uint8 flag byte per sample
   */
  constructor(cap, nSeries, flags = false) {
    if (!(cap > 0) || !(nSeries > 0)) throw new RangeError('Ring: cap and nSeries must be > 0');
    this.cap = cap;
    this.t = new Float64Array(cap);
    this.v = [];
    for (let s = 0; s < nSeries; s++) this.v.push(new Float32Array(cap));
    this.f = flags ? new Uint8Array(cap) : null;
    this.head = 0;
    this.len = 0;
    this.rev = 0; // bumps on every mutation (cheap "dirty" check for consumers)
  }

  get length() { return this.len; }

  /** Physical slot of logical index i (0 = oldest). */
  slot(i) {
    const p = this.head + i;
    return p >= this.cap ? p - this.cap : p;
  }

  time(i) { return this.t[this.slot(i)]; }

  val(s, i) { return this.v[s][this.slot(i)]; }

  flag(i) { return this.f ? this.f[this.slot(i)] : 0; }

  lastTime() { return this.len ? this.t[this.slot(this.len - 1)] : -Infinity; }

  /**
   * Append a sample. Returns false (and stores nothing) when t is not after the last timestamp.
   * @param {number} t timestamp ms
   * @param {ArrayLike<number>} vals one value per series (null/undefined -> NaN)
   * @param {number} [flags]
   */
  push(t, vals, flags = 0) {
    if (!(t > this.lastTime())) return false;
    let p;
    if (this.len < this.cap) {
      p = this.slot(this.len);
      this.len++;
    } else {
      p = this.head;
      this.head = this.head + 1 === this.cap ? 0 : this.head + 1;
    }
    this.t[p] = t;
    for (let s = 0; s < this.v.length; s++) {
      const x = vals[s];
      this.v[s][p] = x === null || x === undefined ? NaN : x;
    }
    if (this.f) this.f[p] = flags;
    this.rev++;
    return true;
  }

  clear() {
    this.head = 0;
    this.len = 0;
    this.rev++;
  }

  /** First logical index whose time is >= t (len if none). */
  lowerBound(t) {
    let lo = 0;
    let hi = this.len;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.time(mid) < t) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** Logical index of the sample nearest to t, or -1 when empty. */
  nearest(t) {
    if (!this.len) return -1;
    const i = this.lowerBound(t);
    if (i === 0) return 0;
    if (i >= this.len) return this.len - 1;
    return t - this.time(i - 1) <= this.time(i) - t ? i - 1 : i;
  }
}

/**
 * Read-only adapter with the Ring interface over plain arrays (history query results):
 * t = Float64Array of timestamps, v = array of Float32Array series, f = optional Uint8Array.
 */
export class ArraySeries {
  constructor(t, v, f = null) {
    this.t = t;
    this.v = v;
    this.f = f;
    this.len = t.length;
    this.rev = 1;
  }

  get length() { return this.len; }
  time(i) { return this.t[i]; }
  val(s, i) { return this.v[s][i]; }
  flag(i) { return this.f ? this.f[i] : 0; }
  lastTime() { return this.len ? this.t[this.len - 1] : -Infinity; }
  lowerBound(t) { return Ring.prototype.lowerBound.call(this, t); }
  nearest(t) { return Ring.prototype.nearest.call(this, t); }
}
