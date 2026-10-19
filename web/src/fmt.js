// Formatting: Intl numbers/dates in the UI language, register value display (scale ×10, disabled
// sentinels, enum labels), durations and data age. Pure: no DOM access.
import { t, locale, name } from './i18n/index.js';

const nfCache = new Map();
function nf(dec) {
  const key = `${locale()}|${dec}`;
  let f = nfCache.get(key);
  if (!f) {
    f = new Intl.NumberFormat(locale(), { minimumFractionDigits: dec, maximumFractionDigits: dec, useGrouping: true });
    nfCache.set(key, f);
  }
  return f;
}

export const DASH = '—';
const MINUS = '−';

/** Number with fixed decimals; null/NaN -> "—". Negative values use a true minus sign. */
export function num(v, dec = 0) {
  if (v === null || v === undefined || Number.isNaN(v)) return DASH;
  const s = nf(dec).format(Math.abs(v) < 0.5 * 10 ** -dec ? 0 : v);
  return s.replace('-', MINUS);
}

/** Signed delta "+0.5" / "−0.3" / "0.0". */
export function signed(v, dec = 1) {
  if (v === null || v === undefined || Number.isNaN(v)) return DASH;
  const r = Math.round(v * 10 ** dec) / 10 ** dec;
  if (r === 0) return num(0, dec);
  return (r > 0 ? '+' : MINUS) + nf(dec).format(Math.abs(r));
}

/** Decimals shown for a register of the given scale. */
export const decimals = (scale) => (scale === 10 ? 1 : 0);

/** Scaled value of a raw register reading. */
export const scaled = (reg, raw) => (raw === null || raw === undefined ? null : raw / reg.scale);

/** True when raw equals the register's "function disabled" sentinel. */
export function isDisabled(reg, raw) {
  return reg.disabled !== null && reg.disabled !== undefined && raw !== null && raw !== undefined
    && Math.round(reg.disabled * reg.scale) === raw;
}

/**
 * Display text of a register reading (without unit): "—" when unknown, "사용 안 함 / Disabled" for
 * the disabled sentinel, the enum label when the register has one, else the scaled number.
 */
export function regValue(reg, raw) {
  if (raw === null || raw === undefined) return DASH;
  if (isDisabled(reg, raw)) return t('disabled');
  if (reg.enum) {
    const e = reg.enum.find((x) => x.value === (reg.runbit ? raw & 1 : raw));
    if (e) return name(e);
  }
  return num(raw / reg.scale, decimals(reg.scale));
}

/** Value with unit, unless disabled/enum/unknown. */
export function regText(reg, raw) {
  const v = regValue(reg, raw);
  if (raw === null || raw === undefined || isDisabled(reg, raw) || reg.enum || !reg.unit) return v;
  return `${v} ${reg.unit}`;
}

/**
 * Parse a user-entered decimal for a register. Accepts "23.5", "23,5", "−3".
 * @returns {{ok: true, raw: number, value: number} | {ok: false, why: 'format'|'scale'|'range'}}
 */
export function parseRegInput(reg, text) {
  const s = String(text).trim().replace(',', '.').replace(MINUS, '-');
  if (!/^-?\d+(\.\d+)?$/.test(s)) return { ok: false, why: 'format' };
  const value = Number(s);
  const x = value * reg.scale;
  const raw = Math.round(x);
  if (Math.abs(x - raw) > 1e-6) return { ok: false, why: 'scale' };
  const minR = Math.round(reg.min * reg.scale);
  const maxR = Math.round(reg.max * reg.scale);
  const dis = reg.disabled === null ? null : Math.round(reg.disabled * reg.scale);
  if ((raw < minR || raw > maxR) && raw !== dis) return { ok: false, why: 'range' };
  return { ok: true, raw, value };
}

/** Range hint "5.0 – 50.0 °C". */
export function rangeText(reg) {
  const d = decimals(reg.scale);
  return `${num(reg.min, d)} – ${num(reg.max, d)}${reg.unit ? ` ${reg.unit}` : ''}`;
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

/** "2026-10-19 14:03:22" in the browser's local time. */
export function dateTime(ms, withSec = true) {
  if (ms === null || ms === undefined) return DASH;
  const d = new Date(ms);
  const base = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return withSec ? `${base}:${pad(d.getSeconds())}` : base;
}

/** "14:03:22" / "14:03". */
export function clock(ms, withSec = true) {
  if (ms === null || ms === undefined) return DASH;
  const d = new Date(ms);
  return withSec ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Axis label for a tick at `ms` given the tick unit ('s' | 'm' | 'd'). */
export function tickLabel(ms, unit) {
  const d = new Date(ms);
  if (unit === 's') return clock(ms, true);
  if (unit === 'd') return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  if (d.getHours() === 0 && d.getMinutes() === 0) return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  return clock(ms, false);
}

/** Compact duration: "45 s", "12 min", "3 h 05 min", "2 d 4 h". */
export function duration(sec) {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return DASH;
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return t('u.s', { n: sec });
  const m = Math.floor(sec / 60);
  if (m < 60) return t('u.min', { n: m });
  const h = Math.floor(m / 60);
  if (h < 48) return t('u.h_min', { h, m: pad(m % 60) });
  return t('u.d_h', { d: Math.floor(h / 24), h: h % 24 });
}

/** Run hours "12:34" (h:mm) for stage run-time totals. */
export function hoursMin(sec) {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return DASH;
  const m = Math.round(sec / 60);
  return `${Math.floor(m / 60)}:${pad(m % 60)}`;
}

/** Data age "3 s" / "2 min"; ≥ 1 h shows the duration. */
export function age(ms) {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return DASH;
  return duration(Math.max(0, ms) / 1000);
}

export function bytes(n) {
  if (n === null || n === undefined) return DASH;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${num(n / 1024, n < 10240 ? 1 : 0)} KB`;
  return `${num(n / 1048576, 1)} MB`;
}

export function pct(v, dec = 0) {
  return v === null || v === undefined || Number.isNaN(v) ? DASH : `${num(v * 100, dec)}%`;
}

/** Byte length of a string in UTF-8 (limits are bytes, API.md §1). */
export const utf8Len = (s) => new TextEncoder().encode(s).length;
