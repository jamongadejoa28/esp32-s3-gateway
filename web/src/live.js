// Pure live-data model: merging WS "snap" deltas, deriving temperature/humidity/stages from
// registers and coils (same rules as the firmware's `derived`), and maintaining the active alarm
// list from WS "alarm" frames. No DOM, no I/O: unit-tested in web/test/live.test.mjs.

/** Empty per-device live state. */
export const emptyLive = () => ({ seq: 0, ts: null, on: false, regs: {}, coils: 0, known: false, rx: 0 });

/** State from GET /devices/{d}/live. */
export function fromRest(r, rxMs) {
  return { seq: r.seq, ts: r.ts, on: r.online, regs: { ...r.regs }, coils: r.coils >>> 0, known: !!r.derived, rx: rxMs };
}

/**
 * Apply a WS snap frame. full:true replaces every register; otherwise only the listed registers
 * change and `c` updates the coils when present. Frames older than the current seq are ignored
 * unless the seq wrapped (u32) or the device restarted (much smaller seq).
 * @returns {{state: object, changed: string[], coilsChanged: boolean, applied: boolean}}
 */
export function applySnap(cur, m, rxMs) {
  const s = cur || emptyLive();
  const older = s.known && m.seq <= s.seq && s.seq - m.seq < 1000 && !m.full;
  if (older) return { state: s, changed: [], coilsChanged: false, applied: false };
  const regs = m.full ? {} : { ...s.regs };
  const changed = [];
  for (const k of Object.keys(m.r || {})) {
    if (s.regs[k] !== m.r[k]) changed.push(k);
    regs[k] = m.r[k];
  }
  if (m.full) for (const k of Object.keys(s.regs)) if (!(k in regs)) changed.push(k);
  const coils = m.c === undefined ? s.coils : m.c >>> 0;
  const state = { seq: m.seq, ts: m.ts, on: m.on, regs, coils, known: s.known || !!m.full || Object.keys(regs).length > 0, rx: rxMs };
  return { state, changed, coilsChanged: coils !== s.coils, applied: true };
}

const bit = (coils, n) => (coils >>> (n - 1)) & 1;

/** Stage flag byte (same bit order as history `stages`): 1 blower, 2 cool, 4 heat, 8 hum, 16 dehum. */
export function stageBits(coils) {
  let b = 0;
  if (bit(coils, 1)) b |= 1;
  if (bit(coils, 2) || bit(coils, 3) || bit(coils, 16)) b |= 2;
  if (bit(coils, 4) || bit(coils, 5) || bit(coils, 6) || bit(coils, 7)) b |= 4;
  if (bit(coils, 8) || bit(coils, 9)) b |= 8;
  if (bit(coils, 15)) b |= 16;
  return b;
}

const rv = (regs, a) => {
  const v = regs[String(a)];
  return v === undefined ? null : v;
};

/**
 * Derived values (like REST `derived`), or null when nothing is known yet.
 * temp/hum/current are scaled; set*, dev* are scaled or null before the first read.
 */
export function derive(st) {
  if (!st || !st.known) return null;
  const r = st.regs;
  const c = st.coils;
  const sc = (a) => { const v = rv(r, a); return v === null ? null : v / 10; };
  const w = rv(r, 40005);
  const mode = [];
  if (bit(c, 12)) mode.push('cool');
  if (bit(c, 13)) mode.push('heat');
  if (bit(c, 14)) mode.push('hum');
  if (bit(c, 15)) mode.push('dehum');
  return {
    temp: sc(40036),
    hum: sc(40037),
    current: sc(40011),
    setTemp: sc(40012),
    setHum: sc(40013),
    coolDev: sc(40014),
    heatDev: sc(40015),
    humDev: sc(40016),
    dehumDev: sc(40017),
    hiTemp: rv(r, 40027) === null || rv(r, 40027) === 249 ? null : rv(r, 40027) / 10,
    loTemp: rv(r, 40028) === null || rv(r, 40028) === 49 ? null : rv(r, 40028) / 10,
    hiHum: rv(r, 40029) === null || rv(r, 40029) === 599 ? null : rv(r, 40029) / 10,
    loHum: rv(r, 40030) === null || rv(r, 40030) === 99 ? null : rv(r, 40030) / 10,
    running: w === null ? null : (w & 1) === 1,
    delay: w === null ? 0 : (w >> 8) & 0xff,
    runDelay: rv(r, 40004) === null ? false : (rv(r, 40004) & 1) === 1,
    stopDelay: rv(r, 40004) === null ? false : (rv(r, 40004) & 2) === 2,
    stages: {
      blower: bit(c, 1),
      cool: bit(c, 2) + bit(c, 3) + bit(c, 16),
      heat: bit(c, 4) + bit(c, 5) + bit(c, 6) + bit(c, 7),
      hum: bit(c, 8) + bit(c, 9),
      dehum: bit(c, 15),
    },
    mode,
  };
}

/** Equipment matrix rows: [key, run coil, fault coil]. */
export const EQUIPMENT = [
  ['blower', 1, 17], ['cool1', 2, 18], ['cool2', 3, 19], ['cool3', 16, 31],
  ['heat1', 4, 20], ['heat2', 5, 20], ['heat3', 6, 20], ['heat4', 7, 20],
  ['hum1', 8, 21], ['hum2', 9, 21], ['supply', 10, 24], ['drain', 11, 25],
];

/** {on, fault} for each EQUIPMENT row. */
export function equipment(coils) {
  return EQUIPMENT.map(([key, run, fault]) => ({ key, on: !!bit(coils, run), fault: !!bit(coils, fault) }));
}

/**
 * Apply a WS alarm frame to the active list (array of REST alarms-active items).
 * Returns a new array sorted by severity desc, then since asc.
 */
export function applyAlarm(list, m) {
  const out = list.filter((a) => a.key !== m.key);
  if (m.type === 'raise') {
    out.push({ key: m.key, dev: m.dev, id: m.id, code: m.code, sev: m.sev, since: m.ts, acked: false, ack_by: null, ack_ts: null, value: m.value });
  } else if (m.type === 'ack') {
    const prev = list.find((a) => a.key === m.key);
    if (prev) out.push({ ...prev, acked: true, ack_by: m.user ?? null, ack_ts: m.ts });
  }
  return sortAlarms(out);
}

export function sortAlarms(list) {
  return list.slice().sort((a, b) => b.sev - a.sev || (a.since ?? 0) - (b.since ?? 0));
}

/** {total, unacked, maxSev} summary of an active list (maxSev -1 when empty). */
export function alarmSummary(list) {
  let unacked = 0;
  let maxSev = -1;
  for (const a of list) {
    if (!a.acked) unacked++;
    if (a.sev > maxSev) maxSev = a.sev;
  }
  return { total: list.length, unacked, maxSev };
}

/**
 * Data age (ms since the last snap arrived) after which the UI calls live data stale: the
 * firmware's freshness window (REST `fresh`, SNMP mexStatusValid, write checks; API.md §4.4) —
 * 3 s, or poll_ms + 3 s when poll_ms > 3000 — plus 1 s for WS delivery, which the client-side age
 * includes but the gateway's does not.
 */
export const staleAfterMs = (pollMs) => (pollMs > 3000 ? pollMs + 3000 : 3000) + 1000;

/** SYS_INIT_FAULT_* bit names (components/sysmgr/include/sysmgr/sysmgr.h), bit i = 1 << i. */
export const INIT_FAULTS = ['fs', 'store', 'modbus', 'net', 'web', 'snmp', 'syslog', 'core'];

/** Names of the init-fault bits set in `bits` (unknown bits are reported as hex by the caller). */
export const initFaultNames = (bits) => INIT_FAULTS.filter((_, i) => (bits >>> i) & 1);

/** True when settings cannot persist (LittleFS mount or store init failed). */
export const storageFailed = (info) => !!(info && info.diag && (info.diag.init_faults & 0x03));
