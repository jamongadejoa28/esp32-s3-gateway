// Canvas time-series chart (DESIGN.md §11): two canvases per chart — a static layer (horizontal
// grid + y labels, redrawn only on resize / y-domain / theme change) and a data layer redrawn by a
// shared scheduler only when dirty (new samples, hover, or the follow window moved by at least one
// device pixel), capped at 30 fps and paused while the page is hidden. Min/max per pixel column
// decimation keeps the cost independent of the sample count. A ChartGroup shares one crosshair
// time and one DOM tooltip across charts.
import { decimate, decimateBand } from './decimate.js';
import { YDomain, timeTicks } from './axis.js';

const PAD = { l: 52, r: 16, t: 10, b: 24 };
const FRAME_MS = 33;

// ---------------------------------------------------------------------------------------------
// Palette (CSS custom properties, re-read on theme change)
// ---------------------------------------------------------------------------------------------
let pal = null;
function palette() {
  if (pal) return pal;
  const cs = getComputedStyle(document.documentElement);
  const v = (n) => cs.getPropertyValue(n).trim();
  pal = {
    temp: v('--c-temp'), hum: v('--c-hum'), cur: v('--c-cur'), set: v('--c-set'), band: v('--c-band'),
    lane: v('--c-lane'), line: v('--line'), muted: v('--muted'), alarm: v('--alarm'), surface: v('--surface'),
    font: `11px ${v('--font') || 'sans-serif'}`,
  };
  return pal;
}

/** Call after a theme change: re-reads colours and repaints every chart. */
export function refreshPalette() {
  pal = null;
  for (const c of live) { c.gridDirty = true; c.dirty = true; }
  request();
}

/** Translucent version of a #rrggbb colour. */
function alpha(hex, a) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}

// ---------------------------------------------------------------------------------------------
// Shared scheduler
// ---------------------------------------------------------------------------------------------
const live = new Set();
let raf = 0;
let timer = 0;
let lastFrame = -1e9;

function request() {
  if (raf || document.hidden) return;
  clearTimeout(timer);
  timer = 0;
  const wait = FRAME_MS - (performance.now() - lastFrame);
  if (wait > 1) timer = setTimeout(() => { timer = 0; request(); }, wait);
  else raf = requestAnimationFrame(frame);
}

function frame(ts) {
  raf = 0;
  lastFrame = ts;
  const now = Date.now();
  let wait = Infinity;
  for (const c of live) {
    const w = c.frame(now);
    if (w < wait) wait = w;
  }
  for (const c of live) {
    const g = c.o.group;
    if (g && g.tipDirty) { g.tipDirty = false; g.updateTip(); }
  }
  if (wait <= FRAME_MS) request();
  else if (wait < Infinity) timer = setTimeout(() => { timer = 0; request(); }, wait);
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
      raf = 0;
      clearTimeout(timer);
      timer = 0;
    } else {
      for (const c of live) c.dirty = true;
      request();
    }
  });
}

// ---------------------------------------------------------------------------------------------
// Group: shared hover time + tooltip
// ---------------------------------------------------------------------------------------------
export class ChartGroup {
  /**
   * @param {HTMLElement} host positioned ancestor of every chart in the group (tooltip parent)
   * @param {(t: number) => string} timeLabel tooltip header
   */
  constructor(host, timeLabel) {
    this.host = host;
    this.timeLabel = timeLabel;
    this.charts = [];
    this.t = null;
    this.tip = document.createElement('div');
    this.tip.className = 'tt';
    this.tip.hidden = true;
    this.tip.setAttribute('aria-hidden', 'true');
    host.appendChild(this.tip);
    this.px = 0;
    this.py = 0;
    this.tipDirty = false;
  }

  add(c) { this.charts.push(c); }

  remove(c) { this.charts = this.charts.filter((x) => x !== c); }

  /** Set (or clear with null) the hovered time; px/py = pointer position in viewport coords. */
  hover(t, px, py) {
    this.t = t;
    if (px !== undefined) { this.px = px; this.py = py; }
    for (const c of this.charts) c.dirtyOverlay = true;
    // the tooltip DOM is rebuilt and measured once per frame (scheduler), not per pointer event
    this.tipDirty = true;
    request();
  }

  updateTip() {
    const tip = this.tip;
    if (this.t === null) { tip.hidden = true; return; }
    while (tip.firstChild) tip.removeChild(tip.firstChild);
    const head = document.createElement('div');
    head.className = 't';
    head.textContent = this.timeLabel(this.t);
    tip.appendChild(head);
    let rows = 0;
    for (const c of this.charts) {
      for (const r of c.tipRows(this.t)) {
        const row = document.createElement('div');
        row.className = 'r';
        const k = document.createElement('i');
        k.className = `key ${r.key}`;
        const b = document.createElement('b');
        b.textContent = r.value;
        const s = document.createElement('span');
        s.textContent = r.label;
        row.append(k, b, s);
        tip.appendChild(row);
        rows++;
      }
    }
    if (!rows) { tip.hidden = true; return; }
    tip.hidden = false;
    const hr = this.host.getBoundingClientRect();
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let x = this.px - hr.left + 14;
    if (x + tw > hr.width - 4) x = this.px - hr.left - tw - 14;
    let y = this.py - hr.top - th / 2;
    y = Math.max(0, Math.min(y, hr.height - th));
    tip.style.transform = `translate(${Math.round(Math.max(0, x))}px,${Math.round(y)}px)`;
  }

  destroy() {
    for (const c of [...this.charts]) c.destroy();
    this.tip.remove();
  }
}

// ---------------------------------------------------------------------------------------------
// Chart
// ---------------------------------------------------------------------------------------------
/**
 * opts:
 *  group        ChartGroup (optional)
 *  label        accessible name
 *  lines        [{s, color: 'temp'|'hum'|'cur', key: CSS key class, label: () => string}] — first is "main"
 *  setpoint     {s, label: () => string} dashed reference series
 *  band         () => [below, above] | null — deadband around the setpoint series (current deviations)
 *  limits       () => [lo|null, hi|null] — dotted alarm limit lines
 *  envelope     {lo, hi} series indices (min/max band in the main colour)
 *  lanes        [{bit, label: () => string}] — stage activity lanes instead of lines
 *  fmt          (v) => string value formatter for the tooltip
 *  unit         string appended in the tooltip
 *  minSpan      minimum y span
 *  marker       draw the end dot on the newest point (follow mode)
 */
export class TimeChart {
  constructor(host, opts) {
    this.host = host;
    this.o = opts;
    this.src = null;
    this.mode = 'follow';
    this.span = 15 * 60000;
    this.t0 = 0;
    this.t1 = 1;
    this.dirty = true;
    this.gridDirty = true;
    this.dirtyOverlay = false;
    this.lastRev = -1;
    this.lastNow = 0;
    this.W = 0;
    this.H = 0;
    this.dpr = 1;
    this.dom = new YDomain({ count: opts.lanes ? 1 : 4, minSpan: opts.minSpan || 1 });
    this.buf = new Float32Array(4096);
    this.bufs = [];
    this.gc = document.createElement('canvas');
    this.dc = document.createElement('canvas');
    this.gc.setAttribute('aria-hidden', 'true');
    this.dc.setAttribute('aria-hidden', 'true');
    this.xh = document.createElement('div');
    this.xh.className = 'xh';
    this.xh.hidden = true;
    this.xd = document.createElement('div');
    this.xd.className = `xd ${opts.lines && opts.lines[0] ? opts.lines[0].key : ''}`;
    this.xd.hidden = true;
    host.classList.add('tc');
    host.tabIndex = 0;
    host.setAttribute('role', 'img');
    host.setAttribute('aria-label', opts.label || '');
    host.append(this.gc, this.dc, this.xh, this.xd);
    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(host);
    this.bind();
    if (opts.group) opts.group.add(this);
    live.add(this);
    this.resize();
  }

  bind() {
    const toT = (clientX) => {
      const r = this.host.getBoundingClientRect();
      const x = clientX - r.left;
      const pw = this.W - PAD.l - PAD.r;
      if (x < PAD.l || x > this.W - PAD.r || pw <= 0) return null;
      return this.t0 + ((x - PAD.l) / pw) * (this.t1 - this.t0);
    };
    this.onMove = (e) => {
      const g = this.o.group;
      const t = toT(e.clientX);
      if (g) g.hover(t, e.clientX, e.clientY);
      else { this.hoverT = t; this.dirtyOverlay = true; request(); }
    };
    this.onLeave = () => {
      if (this.o.group) this.o.group.hover(null);
      else { this.hoverT = null; this.dirtyOverlay = true; request(); }
    };
    this.onKey = (e) => {
      const g = this.o.group;
      if (!g) return;
      const step = (this.t1 - this.t0) / 60;
      const r = this.host.getBoundingClientRect();
      let t = g.t ?? this.t1;
      if (e.key === 'ArrowLeft') t -= step;
      else if (e.key === 'ArrowRight') t += step;
      else if (e.key === 'Home') t = this.t0;
      else if (e.key === 'End') t = this.t1;
      else if (e.key === 'Escape') { g.hover(null); return; }
      else return;
      e.preventDefault();
      t = Math.max(this.t0, Math.min(this.t1, t));
      const pw = this.W - PAD.l - PAD.r;
      g.hover(t, r.left + PAD.l + ((t - this.t0) / (this.t1 - this.t0)) * pw, r.top + this.H / 2);
    };
    this.onBlur = () => { if (this.o.group) this.o.group.hover(null); };
    this.host.addEventListener('pointermove', this.onMove);
    this.host.addEventListener('pointerleave', this.onLeave);
    this.host.addEventListener('keydown', this.onKey);
    this.host.addEventListener('blur', this.onBlur);
  }

  /** Data source (Ring / ArraySeries). */
  setSource(src) {
    this.src = src;
    this.lastRev = -1;
    this.dirty = true;
    request();
  }

  /** Follow "now" with a window of `spanMs`. */
  follow(spanMs) {
    this.mode = 'follow';
    this.span = spanMs;
    this.dom.reset();
    this.gridDirty = true;
    this.dirty = true;
    request();
  }

  /** Fixed window [t0, t1]. */
  fixed(t0, t1) {
    this.mode = 'fixed';
    this.t0 = t0;
    this.t1 = t1;
    this.dom.reset();
    this.gridDirty = true;
    this.dirty = true;
    request();
  }

  /** Force a repaint (e.g. setpoint/limits changed). */
  invalidate() {
    this.dirty = true;
    request();
  }

  resize() {
    const W = this.host.clientWidth;
    const H = this.host.clientHeight;
    const dpr = Math.min(3, window.devicePixelRatio || 1);
    if (W === this.W && H === this.H && dpr === this.dpr) return;
    this.W = W;
    this.H = H;
    this.dpr = dpr;
    for (const c of [this.gc, this.dc]) {
      c.width = Math.max(1, Math.round(W * dpr));
      c.height = Math.max(1, Math.round(H * dpr));
    }
    // decimate() emits ≤ 9 pairs per pixel column (≤ 4 points, one gap marker, ≤ 4 points; + the
    // samples just outside the window on both sides); raw emission (≤ 2 × width points) fits too
    const need = 2 * (9 * W + 64);
    if (this.buf.length < need) this.buf = new Float32Array(need);
    this.gridDirty = true;
    this.dirty = true;
    request();
  }

  /** Scheduler hook: draw when needed; returns ms until the next frame is needed. */
  frame(now) {
    const pw = this.W - PAD.l - PAD.r;
    if (pw < 16 || this.H < PAD.t + PAD.b + 8 || !this.src) return Infinity;
    const msPerDevPx = this.mode === 'follow' ? this.span / Math.max(1, pw * this.dpr) : Infinity;
    if (this.src.rev !== this.lastRev) this.dirty = true;
    if (this.mode === 'follow' && now - this.lastNow >= msPerDevPx) this.dirty = true;
    if (this.dirty) {
      this.lastRev = this.src.rev;
      this.lastNow = now;
      if (this.mode === 'follow') {
        this.t1 = now;
        this.t0 = now - this.span;
      }
      this.draw();
      this.dirty = false;
      this.dirtyOverlay = true;
    }
    if (this.dirtyOverlay) {
      this.overlay();
      this.dirtyOverlay = false;
    }
    return this.mode === 'follow' ? Math.max(FRAME_MS, msPerDevPx - (now - this.lastNow)) : Infinity;
  }

  xOf(t) { return PAD.l + ((t - this.t0) / (this.t1 - this.t0)) * (this.W - PAD.l - PAD.r); }

  yOf(v) {
    const d = this.dom.d;
    return PAD.t + (1 - (v - d.min) / (d.max - d.min)) * (this.H - PAD.t - PAD.b);
  }

  crisp(v) {
    const d = this.dpr;
    return (Math.round(v * d) + 0.5) / d;
  }

  /** Index range covering the window plus one sample on each side (line continuity). */
  range() {
    const s = this.src;
    const i0 = Math.max(0, s.lowerBound(this.t0) - 1);
    const i1 = Math.min(s.length, s.lowerBound(this.t1) + 1);
    return [i0, i1];
  }

  draw() {
    const o = this.o;
    const p = palette();
    const ctx = this.dc.getContext('2d');
    const dpr = this.dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this.W, this.H);
    const pw = this.W - PAD.l - PAD.r;
    const ppm = pw / (this.t1 - this.t0);
    const [i0, i1] = this.range();
    const src = this.src;
    if (o.lanes) {
      this.drawLanes(ctx, p, i0, i1, ppm);
    } else {
      // 1. decimate every series into its buffer and collect the y range
      let lo = Infinity;
      let hi = -Infinity;
      const acc = (r) => { if (r.min < lo) lo = r.min; if (r.max > hi) hi = r.max; };
      const out = [];
      o.lines.forEach((ln, k) => {
        const b = this.bufs[k] && this.bufs[k].length >= this.buf.length ? this.bufs[k] : (this.bufs[k] = new Float32Array(this.buf.length));
        const r = decimate(src, ln.s, i0, i1, this.t0, ppm, pw, b);
        acc(r);
        out.push({ ln, b, n: r.n });
      });
      let sp = null;
      let band = null;
      if (o.setpoint) {
        const b = this.spBuf && this.spBuf.length >= this.buf.length ? this.spBuf : (this.spBuf = new Float32Array(this.buf.length));
        const r = decimate(src, o.setpoint.s, i0, i1, this.t0, ppm, pw, b);
        sp = { b, n: r.n };
        acc(r);
        band = o.band ? o.band() : null;
        if (band && r.max >= r.min) acc({ min: r.min - band[0], max: r.max + band[1] });
      }
      let env = null;
      if (o.envelope) {
        const b = this.envBuf && this.envBuf.length >= this.buf.length * 2 ? this.envBuf : (this.envBuf = new Float32Array(this.buf.length * 2));
        const r = decimateBand(src, o.envelope.lo, o.envelope.hi, i0, i1, this.t0, ppm, b);
        env = { b, n: r.n };
        acc(r);
      }
      if (lo > hi && !this.dom.d) { lo = 0; hi = 1; }
      if (this.dom.update(lo, hi)) this.gridDirty = true;
      if (!this.dom.d) this.dom.update(0, 1);
      // 2. static layer
      if (this.gridDirty) { this.drawGrid(p); this.gridDirty = false; }
      // 3. data layer, clipped to the plot
      ctx.save();
      ctx.beginPath();
      ctx.rect(PAD.l, PAD.t - 2, pw, this.H - PAD.t - PAD.b + 4);
      ctx.clip();
      const X = (x) => PAD.l + x;
      if (sp && band) {
        ctx.fillStyle = p.band;
        this.fillBand(ctx, sp.b, sp.n, X, (v) => v + band[1], (v) => v - band[0]);
      }
      if (env) {
        ctx.fillStyle = alpha(p[o.lines[0].color], 0.14);
        let start = -1;
        const b = env.b;
        const flushEnv = (from, to) => {
          if (to - from < 1) return;
          ctx.beginPath();
          ctx.moveTo(X(b[3 * from]), this.yOf(b[3 * from + 2]));
          for (let j = from + 1; j <= to; j++) ctx.lineTo(X(b[3 * j]), this.yOf(b[3 * j + 2]));
          for (let j = to; j >= from; j--) ctx.lineTo(X(b[3 * j]), this.yOf(b[3 * j + 1]));
          ctx.closePath();
          ctx.fill();
        };
        for (let j = 0; j < env.n; j++) {
          const gap = b[3 * j + 1] !== b[3 * j + 1];
          if (gap) { if (start >= 0) flushEnv(start, j - 1); start = -1; } else if (start < 0) start = j;
        }
        if (start >= 0) flushEnv(start, env.n - 1);
      }
      const lim = o.limits ? o.limits() : null;
      if (lim) {
        ctx.save();
        ctx.strokeStyle = p.alarm;
        ctx.lineWidth = 1.25;
        ctx.setLineDash([1.5, 3.5]);
        ctx.lineCap = 'round';
        for (const v of lim) {
          if (v === null || v === undefined || v < this.dom.d.min || v > this.dom.d.max) continue;
          const y = this.crisp(this.yOf(v));
          ctx.beginPath();
          ctx.moveTo(PAD.l, y);
          ctx.lineTo(PAD.l + pw, y);
          ctx.stroke();
        }
        ctx.restore();
      }
      if (sp) {
        ctx.save();
        ctx.strokeStyle = p.set;
        ctx.lineWidth = 1.25;
        ctx.setLineDash([5, 4]);
        this.strokeLine(ctx, sp.b, sp.n, X);
        ctx.restore();
      }
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      for (const { ln, b, n } of out) {
        ctx.strokeStyle = p[ln.color];
        ctx.lineWidth = ln.width || 2;
        this.strokeLine(ctx, b, n, X);
      }
      ctx.restore();
      // end marker on the newest finite point (follow mode)
      if (o.marker && out[0] && out[0].n) {
        const { b, n } = out[0];
        const y = b[2 * n - 1];
        const x = X(b[2 * n - 2]);
        if (y === y && x >= PAD.l && x <= PAD.l + pw + 0.5) {
          ctx.beginPath();
          ctx.arc(x, this.yOf(y), 4, 0, Math.PI * 2);
          ctx.fillStyle = p[o.lines[0].color];
          ctx.strokeStyle = p.surface;
          ctx.lineWidth = 2;
          ctx.fill();
          ctx.stroke();
        }
      }
      // limit labels at the right edge; a limit outside the y-domain (which is never stretched to
      // include it: that would flatten the deadband detail) gets an edge marker ▲/▼ + value instead
      if (lim && o.fmt) {
        ctx.font = p.font;
        ctx.textAlign = 'right';
        const xr = PAD.l + pw - 4;
        for (const v of lim) {
          if (v === null || v === undefined) continue;
          if (v >= this.dom.d.min && v <= this.dom.d.max) {
            ctx.fillStyle = p.muted;
            ctx.textBaseline = 'bottom';
            ctx.fillText(o.fmt(v), PAD.l + pw - 2, this.yOf(v) - 2);
            continue;
          }
          const up = v > this.dom.d.max;
          const txt = o.fmt(v);
          const w = ctx.measureText(txt).width;
          const yc = up ? PAD.t + 8 : this.H - PAD.b - 8;
          ctx.fillStyle = alpha(p.surface, 0.85);
          ctx.fillRect(xr - w - 16, yc - 8, w + 20, 16);
          ctx.fillStyle = p.muted;
          ctx.textBaseline = 'middle';
          ctx.fillText(txt, xr, yc);
          const xt = xr - w - 8;
          ctx.beginPath();
          ctx.moveTo(xt - 4, up ? yc + 3 : yc - 3);
          ctx.lineTo(xt + 4, up ? yc + 3 : yc - 3);
          ctx.lineTo(xt, up ? yc - 4 : yc + 4);
          ctx.closePath();
          ctx.fillStyle = p.alarm;
          ctx.fill();
        }
      }
    }
    this.drawXAxis(ctx, p, pw);
  }

  strokeLine(ctx, b, n, X) {
    ctx.beginPath();
    let pen = false;
    for (let j = 0; j < n; j++) {
      const y = b[2 * j + 1];
      if (y !== y) { pen = false; continue; }
      const px = X(b[2 * j]);
      const py = this.yOf(y);
      if (pen) ctx.lineTo(px, py);
      else { ctx.moveTo(px, py); pen = true; }
    }
    ctx.stroke();
  }

  fillBand(ctx, b, n, X, up, dn) {
    let start = -1;
    const flush = (from, to) => {
      if (to < from) return;
      ctx.beginPath();
      // step-wise band: setpoints are step functions
      ctx.moveTo(X(b[2 * from]), this.yOf(up(b[2 * from + 1])));
      for (let j = from + 1; j <= to; j++) {
        ctx.lineTo(X(b[2 * j]), this.yOf(up(b[2 * j - 1])));
        ctx.lineTo(X(b[2 * j]), this.yOf(up(b[2 * j + 1])));
      }
      ctx.lineTo(X(b[2 * to]), this.yOf(dn(b[2 * to + 1])));
      for (let j = to; j > from; j--) {
        ctx.lineTo(X(b[2 * j]), this.yOf(dn(b[2 * j + 1])));
        ctx.lineTo(X(b[2 * j]), this.yOf(dn(b[2 * j - 1])));
      }
      ctx.lineTo(X(b[2 * from]), this.yOf(dn(b[2 * from + 1])));
      ctx.closePath();
      ctx.fill();
    };
    for (let j = 0; j < n; j++) {
      const gap = b[2 * j + 1] !== b[2 * j + 1];
      if (gap) { if (start >= 0) flush(start, j - 1); start = -1; } else if (start < 0) start = j;
    }
    if (start >= 0) flush(start, n - 1);
  }

  drawGrid(p) {
    const ctx = this.gc.getContext('2d');
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.W, this.H);
    const d = this.dom.d;
    if (!d || this.o.lanes) return;
    const pw = this.W - PAD.l - PAD.r;
    ctx.strokeStyle = p.line;
    ctx.lineWidth = 1 / this.dpr;
    ctx.font = p.font;
    ctx.fillStyle = p.muted;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.beginPath();
    for (const v of d.ticks) {
      if (v < d.min - 1e-9 || v > d.max + 1e-9) continue;
      const y = this.crisp(this.yOf(v));
      ctx.moveTo(PAD.l, y);
      ctx.lineTo(PAD.l + pw, y);
    }
    ctx.stroke();
    for (const v of d.ticks) {
      if (v < d.min - 1e-9 || v > d.max + 1e-9) continue;
      const txt = (this.o.tick || ((x) => x.toFixed(d.decimals)))(v, d.decimals);
      ctx.fillText(txt, PAD.l - 8, this.yOf(v));
    }
  }

  drawXAxis(ctx, p, pw) {
    const tt = timeTicks(this.t0, this.t1, pw, 84);
    const label = this.o.timeTick;
    if (!label || this.o.noXAxis) return;
    ctx.font = p.font;
    ctx.fillStyle = p.muted;
    ctx.textBaseline = 'alphabetic';
    ctx.textAlign = 'center';
    ctx.strokeStyle = p.line;
    ctx.lineWidth = 1 / this.dpr;
    const yb = this.H - PAD.b;
    ctx.beginPath();
    ctx.moveTo(PAD.l, this.crisp(yb));
    ctx.lineTo(PAD.l + pw, this.crisp(yb));
    ctx.stroke();
    for (const t of tt.ticks) {
      const x = this.xOf(t);
      const s = label(t, tt.unit);
      const w = ctx.measureText(s).width;
      if (x - w / 2 < PAD.l - 4 || x + w / 2 > PAD.l + pw + PAD.r - 2) continue;
      ctx.beginPath();
      ctx.moveTo(this.crisp(x), yb);
      ctx.lineTo(this.crisp(x), yb + 4);
      ctx.stroke();
      ctx.fillText(s, x, this.H - 6);
    }
  }

  drawLanes(ctx, p, i0, i1, ppm) {
    const lanes = this.o.lanes;
    const pw = this.W - PAD.l - PAD.r;
    const pitch = 16; // > the 11 px label font plus leading, so lane labels never touch
    const top = Math.max(2, (this.H - lanes.length * pitch) / 2);
    if (this.gridDirty) {
      const g = this.gc.getContext('2d');
      g.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      g.clearRect(0, 0, this.W, this.H);
      g.font = p.font;
      g.fillStyle = p.muted;
      g.textAlign = 'right';
      g.textBaseline = 'middle';
      lanes.forEach((ln, k) => {
        const y = top + k * pitch + pitch / 2;
        g.fillText(ln.label(), PAD.l - 8, y);
        g.fillStyle = p.line;
        g.fillRect(PAD.l, Math.round(y), pw, 1 / this.dpr);
        g.fillStyle = p.muted;
      });
      this.gridDirty = false;
    }
    const src = this.src;
    ctx.fillStyle = p.lane;
    lanes.forEach((ln, k) => {
      const y = top + k * pitch + pitch / 2 - 2;
      let runX = -1;
      let prevX = 0;
      for (let i = i0; i < i1; i++) {
        const x = PAD.l + (src.time(i) - this.t0) * ppm;
        const on = (src.flag(i) >> ln.bit) & 1;
        if (on && runX < 0) runX = x;
        if (!on && runX >= 0) { this.lane(ctx, runX, x, y, pw); runX = -1; }
        prevX = x;
      }
      if (runX >= 0) this.lane(ctx, runX, Math.max(prevX, runX + 1), y, pw);
    });
  }

  lane(ctx, x0, x1, y, pw) {
    const a = Math.max(PAD.l, x0);
    const b = Math.min(PAD.l + pw, x1);
    if (b > a) ctx.fillRect(a, y, Math.max(1, b - a), 4);
  }

  /** Crosshair + hover dot (DOM, no canvas redraw). */
  overlay() {
    const g = this.o.group;
    const t = g ? g.t : this.hoverT;
    // `hidden` is written only when it changes (no style invalidation on idle redraws)
    const show = (el, on) => { if (el.hidden === on) el.hidden = !on; };
    if (t === null || t === undefined || t < this.t0 || t > this.t1 || !this.src || !this.W) {
      show(this.xh, false);
      show(this.xd, false);
      return;
    }
    const x = this.xOf(t);
    show(this.xh, true);
    this.xh.style.transform = `translateX(${Math.round(x)}px)`;
    if (this.o.lanes || !this.dom.d) { show(this.xd, false); return; }
    const i = this.src.nearest(t);
    const v = i >= 0 ? this.src.val(this.o.lines[0].s, i) : NaN;
    if (v !== v || Math.abs(this.src.time(i) - t) > (this.t1 - this.t0) / 50) { show(this.xd, false); return; }
    show(this.xd, true);
    this.xd.style.transform = `translate(${Math.round(this.xOf(this.src.time(i)))}px,${Math.round(this.yOf(v))}px)`;
    if (g && !g.tip.hidden) g.tipDirty = true;
  }

  /** Tooltip rows at time t (values lead, labels follow). */
  tipRows(t) {
    const src = this.src;
    if (!src || t < this.t0 || t > this.t1) return [];
    const i = src.nearest(t);
    if (i < 0 || Math.abs(src.time(i) - t) > (this.t1 - this.t0) / 50) return [];
    const o = this.o;
    const f = (v) => (v !== v ? '—' : `${o.fmt ? o.fmt(v) : v}${o.unit ? ` ${o.unit}` : ''}`);
    if (o.lanes) {
      const on = o.lanes.filter((ln) => (src.flag(i) >> ln.bit) & 1).map((ln) => ln.label());
      return on.length ? [{ key: 'k-lane', value: on.join(' · '), label: o.label || '' }] : [];
    }
    const rows = o.lines.map((ln) => ({ key: ln.key, value: f(src.val(ln.s, i)), label: ln.label() }));
    if (o.envelope) {
      const lo = src.val(o.envelope.lo, i);
      const hi = src.val(o.envelope.hi, i);
      if (lo === lo && hi === hi) rows.push({ key: 'k-env', value: `${o.fmt(lo)} – ${o.fmt(hi)}`, label: o.envelope.label() });
    }
    if (o.setpoint) rows.push({ key: 'k-set', value: f(src.val(o.setpoint.s, i)), label: o.setpoint.label() });
    return rows;
  }

  destroy() {
    live.delete(this);
    this.ro.disconnect();
    this.host.removeEventListener('pointermove', this.onMove);
    this.host.removeEventListener('pointerleave', this.onLeave);
    this.host.removeEventListener('keydown', this.onKey);
    this.host.removeEventListener('blur', this.onBlur);
    if (this.o.group) this.o.group.remove(this);
    this.gc.remove();
    this.dc.remove();
    this.xh.remove();
    this.xd.remove();
  }
}

/** Small sparkline (RTT): drawn on demand, no scheduler. */
export function sparkline(canvas, values, color = 'muted') {
  const p = palette();
  const dpr = Math.min(3, window.devicePixelRatio || 1);
  const W = canvas.clientWidth;
  const H = canvas.clientHeight;
  if (!W || !H) return;
  if (canvas.width !== Math.round(W * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const v = values.filter((x) => Number.isFinite(x));
  if (v.length < 2) return;
  let lo = Math.min(...v);
  let hi = Math.max(...v);
  if (hi - lo < 10) { const c = (hi + lo) / 2; lo = c - 5; hi = c + 5; }
  const x = (i) => 1 + (i / (values.length - 1)) * (W - 6);
  const y = (val) => 3 + (1 - (val - lo) / (hi - lo)) * (H - 6);
  ctx.strokeStyle = p.muted;
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  let pen = false;
  values.forEach((val, i) => {
    if (!Number.isFinite(val)) { pen = false; return; }
    if (pen) ctx.lineTo(x(i), y(val)); else { ctx.moveTo(x(i), y(val)); pen = true; }
  });
  ctx.stroke();
  const last = values[values.length - 1];
  if (Number.isFinite(last)) {
    ctx.beginPath();
    ctx.arc(x(values.length - 1), y(last), 3, 0, Math.PI * 2);
    ctx.fillStyle = p[color] || p.temp;
    ctx.fill();
  }
}
