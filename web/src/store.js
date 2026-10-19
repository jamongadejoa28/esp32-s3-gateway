// Application state + topic pub/sub. Views subscribe to topics and re-render only what changed.
//   topics: session, meta, devices, dev (selected device), live:<d>, series:<d>, comm:<d>,
//           alarms, sys, info, ws (connection status), write, clock (1 Hz), theme, auth (lost/expired)
import { emptyLive } from './live.js';
import { storage } from './dom.js';

export const state = {
  session: null, // {user, role, csrf, must_change, idle_s}
  meta: null, // /meta/registers
  regs: new Map(), // addr -> reg meta
  alarmMeta: new Map(), // id -> meta alarm
  devices: [],
  dev: 0,
  live: new Map(), // dev -> live state (live.js)
  series: new Map(), // dev -> DevSeries
  comm: new Map(), // dev -> {online, rtt, err, rtts: number[]}
  alarms: [],
  sys: null,
  info: null,
  ws: 'idle', // idle | connecting | open | reconnecting
  srvOffset: 0, // gateway wall clock − client clock (ms), when the gateway clock is valid
  srvValid: false,
  pollMs: 1000, // config/modbus poll_ms (freshness window)
};

const subs = new Map();

export function on(topic, fn) {
  let set = subs.get(topic);
  if (!set) subs.set(topic, (set = new Set()));
  set.add(fn);
  return () => set.delete(fn);
}

export function emit(topic, payload) {
  const set = subs.get(topic);
  if (!set) return;
  for (const fn of [...set]) {
    try { fn(payload); } catch (e) { console.error(e); }
  }
}

export function set(key, value) {
  state[key] = value;
  emit(key, value);
}

export const live = (d) => state.live.get(d) || emptyLive();

/** Role rank check: can('operator') is true for operator and admin. */
const RANK = { viewer: 1, operator: 2, admin: 3 };
export const can = (role) => !!state.session && RANK[state.session.role] >= RANK[role];

/** Gateway wall time "now" in ms (client clock + offset), or null while the gateway clock is invalid. */
export const srvNow = () => (state.srvValid ? Date.now() + state.srvOffset : null);

export function devName(d) {
  const x = state.devices.find((v) => v.id === d);
  return x ? x.name : `#${d}`;
}

export function resetData() {
  state.live.clear();
  state.series.clear();
  state.comm.clear();
  state.alarms = [];
  state.sys = null;
}

/** Select the device shown by dashboard/controller/trends (remembered per browser). */
export function selectDevice(d) {
  if (state.dev === d) return;
  storage.set('gw.dev', String(d));
  set('dev', d);
}

/** Enabled devices (for device pickers). */
export const enabledDevices = () => state.devices.filter((d) => d.enabled);
