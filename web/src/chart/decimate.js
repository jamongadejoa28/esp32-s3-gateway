// Pixel-column decimation (M4: first/min/max/last per column) for line rendering.
// Input: any series exposing time(i)/val(s, i) (Ring, ArraySeries). Output: interleaved (x, y)
// pairs in a caller-owned Float32Array, x in CSS px relative to the plot's left edge, y = data
// value; a NaN y marks a gap (the renderer lifts the pen). When the visible point count is at most
// 2 × width the raw points are emitted unchanged, so slow series stay exact. A pixel column gets at
// most one gap marker: further gaps inside the same column are sub-pixel and are merged, which
// bounds the output at 9 pairs per column (≤ 4 before the gap, the marker, ≤ 4 after it).

/**
 * @param {object} src series source (time(i), val(s, i), length)
 * @param {number} s series index
 * @param {number} i0 first logical index (inclusive)
 * @param {number} i1 last logical index (exclusive)
 * @param {number} t0 time at x = 0 (ms)
 * @param {number} pxPerMs horizontal scale
 * @param {number} width plot width in px
 * @param {Float32Array} out output buffer (pairs); should hold >= 2 * (9 * width + 64) floats.
 *   Writes never go past its end: output is truncated there and `n` counts only what was written.
 * @returns {{n: number, min: number, max: number}} pair count and finite value range (min > max if none)
 */
export function decimate(src, s, i0, i1, t0, pxPerMs, width, out) {
  let n = 0;
  let min = Infinity;
  let max = -Infinity;
  const count = i1 - i0;
  if (count <= 0) return { n, min, max };
  const cap = out.length >> 1;
  const put = (x, y) => {
    if (n >= cap) return;
    out[2 * n] = x;
    out[2 * n + 1] = y;
    n++;
  };
  if (count <= 2 * width) {
    let gap = false;
    for (let i = i0; i < i1; i++) {
      const y = src.val(s, i);
      const x = (src.time(i) - t0) * pxPerMs;
      if (y !== y) { // NaN
        if (!gap && n) put(x, NaN);
        gap = true;
        continue;
      }
      gap = false;
      if (y < min) min = y;
      if (y > max) max = y;
      put(x, y);
    }
    return { n, min, max };
  }
  let col = NaN;
  let cx = 0;
  let first = 0;
  let last = 0;
  let cmin = 0;
  let cmax = 0;
  let has = false;
  let gap = false;
  let gapCol = NaN;
  const flush = () => {
    if (!has) return;
    put(cx, first);
    if (cmin !== first && cmin !== last) put(cx, cmin);
    if (cmax !== first && cmax !== last && cmax !== cmin) put(cx, cmax);
    if (last !== first) put(cx, last);
    has = false;
  };
  for (let i = i0; i < i1; i++) {
    const x = (src.time(i) - t0) * pxPerMs;
    const c = Math.floor(x);
    const y = src.val(s, i);
    if (c !== col) {
      flush();
      col = c;
      cx = c + 0.5;
    }
    if (y !== y) {
      if (gapCol === col) continue; // this column already has its gap: merge the rest
      gapCol = col;
      flush();
      if (!gap && n) put(cx, NaN);
      gap = true;
      continue;
    }
    gap = false;
    if (y < min) min = y;
    if (y > max) max = y;
    if (!has) {
      first = last = cmin = cmax = y;
      has = true;
    } else {
      last = y;
      if (y < cmin) cmin = y;
      if (y > cmax) cmax = y;
    }
  }
  flush();
  return { n, min, max };
}

/**
 * Envelope (min/max band) decimation: per pixel column the lowest `lo` and highest `hi`.
 * Output triples (x, lo, hi); NaN lo marks a gap. At most one gap marker per column, so at most 3
 * triples per column; writes never go past the end of `out`.
 * @returns {{n: number, min: number, max: number}}
 */
export function decimateBand(src, sLo, sHi, i0, i1, t0, pxPerMs, out) {
  const cap = Math.floor(out.length / 3);
  let gapCol = NaN;
  let n = 0;
  let min = Infinity;
  let max = -Infinity;
  let col = NaN;
  let lo = Infinity;
  let hi = -Infinity;
  let cx = 0;
  let gap = false;
  const flush = () => {
    if (lo <= hi && n < cap) {
      out[3 * n] = cx;
      out[3 * n + 1] = lo;
      out[3 * n + 2] = hi;
      n++;
    }
    lo = Infinity;
    hi = -Infinity;
  };
  for (let i = i0; i < i1; i++) {
    const x = (src.time(i) - t0) * pxPerMs;
    const c = Math.floor(x);
    const a = src.val(sLo, i);
    const b = src.val(sHi, i);
    if (c !== col) {
      flush();
      col = c;
      cx = x;
    }
    if (a !== a || b !== b) {
      if (gapCol === col) continue;
      gapCol = col;
      flush();
      if (!gap && n && n < cap) {
        out[3 * n] = cx;
        out[3 * n + 1] = NaN;
        out[3 * n + 2] = NaN;
        n++;
      }
      gap = true;
      continue;
    }
    gap = false;
    if (a < lo) lo = a;
    if (b > hi) hi = b;
    if (a < min) min = a;
    if (b > max) max = b;
  }
  flush();
  return { n, min, max };
}
