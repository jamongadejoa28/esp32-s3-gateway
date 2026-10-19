#!/usr/bin/env node
// MESTIO gateway mock server: the complete REST + WebSocket contract of docs/API.md backed by a
// simulated MEX150 (thermal/humidity physics, deadband stage logic, delays, faults, comm loss,
// write latency and verify, interlocks), auth/session/CSRF/must_change/rate limiting, history for
// every span, logs and system endpoints. Serves the built UI (web/dist) or the unbundled sources
// (--dev), or forwards /api and /ws to a real gateway (--proxy http://192.168.10.150).
//
//   node tools/mock_server.mjs [--port 8080] [--host 127.0.0.1] [--dev] [--proxy URL]
//        [--seed N] [--devices 1..4] [--ready] [--time-invalid] [--no-comm-loss] [--no-faults]
//        [--coredump] [--quiet]
//
// --ready starts with admin's password already changed to "Mestio-Admin#2026" (UI development).
// Mock-only test hooks live under /__mock/* (loopback clients only); they are not part of the API.
import http from 'node:http';
import { networkInterfaces, tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join, dirname, normalize, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { SchemaSet, toValidationError } from '../web/test/jsonschema.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const API = '/api/v1';

// ------------------------------------------------------------------------------------------------
// CLI
// ------------------------------------------------------------------------------------------------
function parseArgs(argv) {
  const o = { port: 8080, host: '127.0.0.1', dev: false, proxy: null, seed: Date.now() >>> 0, devices: 1, ready: false,
    timeInvalid: false, commLoss: true, faults: true, coredump: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    switch (a) {
      case '--port': o.port = Number(val()); break;
      case '--host': o.host = val(); break;
      case '--dev': o.dev = true; break;
      case '--proxy': o.proxy = new URL(val()); break;
      case '--seed': o.seed = Number(val()) >>> 0; break;
      case '--devices': o.devices = Math.max(1, Math.min(4, Number(val()) | 0)); break;
      case '--ready': o.ready = true; break;
      case '--time-invalid': o.timeInvalid = true; break;
      case '--no-comm-loss': o.commLoss = false; break;
      case '--no-faults': o.faults = false; break;
      case '--coredump': o.coredump = true; break;
      case '--quiet': o.quiet = true; break;
      case '-h': case '--help':
        process.stdout.write('usage: node tools/mock_server.mjs [--port N] [--host H] [--dev] [--proxy URL] [--seed N] '
          + '[--devices N] [--ready] [--time-invalid] [--no-comm-loss] [--no-faults] [--coredump] [--quiet]\n');
        process.exit(0);
        break;
      default: throw new Error(`unknown option ${a}`);
    }
  }
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error('bad --port');
  return o;
}
const OPT = parseArgs(process.argv.slice(2));
const log = (...a) => { if (!OPT.quiet) console.log(new Date().toISOString().slice(11, 19), ...a); };

// Deterministic PRNG (mulberry32) so --seed reproduces a session.
let rngState = OPT.seed || 1;
function rnd() {
  rngState = (rngState + 0x6d2b79f5) >>> 0;
  let t = rngState;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const rint = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const gauss = () => (rnd() + rnd() + rnd() - 1.5) / 1.5;
const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);

// ------------------------------------------------------------------------------------------------
// Single sources: regmap.def and alarm_catalog.def
// ------------------------------------------------------------------------------------------------
function splitArgs(s) {
  const out = []; let cur = ''; let q = false;
  for (const ch of s) {
    if (ch === '"') { q = !q; continue; }
    if (ch === ',' && !q) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}
function parseDef(file) {
  const rows = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*([A-Z]+)\((.*)\)\s*$/.exec(line);
    if (m) rows.push({ kind: m[1], args: splitArgs(m[2]) });
  }
  return rows;
}
const GROUPS = ['status', 'control', 'setpoint', 'deviation', 'delay', 'calibration', 'limits', 'options', 'info', 'alarm'];
const REGS = []; const BITS = []; const COILS = []; const ENUMS = {};
for (const { kind, args } of parseDef(join(ROOT, 'components/mex150/regmap.def'))) {
  if (kind === 'REG') {
    const [key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en] = args;
    const f = flags.split('|');
    REGS.push({ key, addr: +addr, scale: +scale, signed: sign === 'S', access: access.toLowerCase(), min: +min, max: +max,
      disabled: disabled === 'NONE' ? null : +disabled, stopped_only: f.includes('STOPPED'), snmp_rw: f.includes('SNMP_RW'),
      runbit: f.includes('RUNBIT'), bits: f.includes('BITS'), group, unit, ko, en });
  } else if (kind === 'REGBIT') {
    const [key, addr, bit, ko, en] = args;
    BITS.push({ key, addr: +addr, lsb: +bit, width: 1, unit: '', ko, en });
  } else if (kind === 'FIELD') {
    const [key, addr, lsb, width, unit, ko, en] = args;
    BITS.push({ key, addr: +addr, lsb: +lsb, width: +width, unit, ko, en });
  } else if (kind === 'COIL') {
    const [key, n, group, ko, en] = args;
    COILS.push({ key, n: +n, group, ko, en });
  } else if (kind === 'ENUM') {
    const [reg, value, ko, en] = args;
    (ENUMS[reg] ||= []).push({ value: +value, ko, en });
  }
}
const REG_BY_ADDR = new Map(REGS.map((r) => [r.addr, r]));
const SLOW_ADDRS = new Set([40027, 40028, 40029, 40030, 40053, 40054, 40059]);
const SEV = { INFO: 0, MINOR: 1, MAJOR: 2, CRITICAL: 3 };
const CATALOG = parseDef(join(ROOT, 'components/alarm/alarm_catalog.def')).filter((r) => r.kind === 'ALM').map(({ args }) => {
  const [id, code, kind, addr, bit, sev, vreg, ko, en] = args;
  const source = kind === 'SRC_COIL' ? `coil:${addr}` : kind === 'SRC_BIT' ? `bit:${addr}.${bit}` : kind === 'SRC_COMM' ? 'comm' : `rule:${addr}`;
  return { id, code: +code, kind, addr: +addr, bit: +bit, sev: SEV[sev], vreg: +vreg, ko, en, source };
});
const ALM_BY_ID = new Map(CATALOG.map((a) => [a.id, a]));
const ALM_BY_CODE = new Map(CATALOG.map((a) => [a.code, a]));
if (!REGS.length || !COILS.length || !CATALOG.length) throw new Error('regmap.def / alarm_catalog.def not parsed');

const META_REGISTERS = {
  version: 1,
  groups: GROUPS,
  regs: REGS.map((r) => {
    const o = { key: r.key, addr: r.addr, scale: r.scale, signed: r.signed, access: r.access, min: r.min / r.scale, max: r.max / r.scale,
      disabled: r.disabled === null ? null : r.disabled / r.scale, stopped_only: r.stopped_only, snmp_rw: r.snmp_rw, runbit: r.runbit,
      bits: r.bits, group: r.group, unit: r.unit, ko: r.ko, en: r.en };
    if (ENUMS[r.key]) o.enum = ENUMS[r.key];
    return o;
  }),
  bits: BITS,
  coils: COILS,
};
const META_ETAG = `"${createHash('sha256').update(JSON.stringify(META_REGISTERS)).digest('hex').slice(0, 8)}"`;
const FW_VERSION = readFileSync(join(ROOT, 'version.txt'), 'utf8').trim();
const SCHEMAS = new SchemaSet(join(ROOT, 'docs/api'));

// ------------------------------------------------------------------------------------------------
// Clocks. "mono" is the mock's monotonic timeline (real time); the gateway's wall clock may be
// invalid (--time-invalid) or offset by POST /time.
// ------------------------------------------------------------------------------------------------
const BOOT_MS = Date.now();
const clock = { valid: !OPT.timeInvalid, offset: OPT.timeInvalid ? -86400000 * 400 : 0 };
const monoMs = () => Date.now();
const wallMs = () => (clock.valid ? monoMs() + clock.offset : null);
const toWall = (mono) => (clock.valid ? Math.round(mono + clock.offset) : null);
const uptimeS = () => Math.floor((monoMs() - BOOT_MS) / 1000);

// ------------------------------------------------------------------------------------------------
// Configuration (firmware defaults, DESIGN.md §5)
// ------------------------------------------------------------------------------------------------
const HOSTNAME = 'mestio-gw-3456';
const clone = (o) => structuredClone(o);
function defaultConfig() {
  const devices = [];
  for (let i = 0; i < OPT.devices; i++) devices.push({ id: i, name: i ? `MEX150 #${i + 1}` : 'MEX150', slave: i + 1, enabled: true });
  return {
    general: OPT.ready ? { site: 'B동 전산실', location: 'Seoul', contact: 'facility@example.com', lang: 'ko' } : { site: '', location: '', contact: '', lang: 'ko' },
    network: { eth: { mode: 'static', ip: '192.168.10.150', mask: '255.255.255.0', gw: '192.168.10.1', dns1: '192.168.10.1', dns2: '' },
      hostname: HOSTNAME, ap: { fallback: true, ssid: 'MESTIO-GW-3456', channel: 6, idle_min: 15, fallback_after_s: 120 } },
    modbus: { devices, port: { baud: 9600, parity: 'N', stop: 1 }, poll_ms: 1000, timeout_ms: 300, retries: 1, gap_ms: 5, offline_after: 3 },
    alarms: { debounce_raise: 2, debounce_clear: 3, sev_override: {}, rules: [
      { id: 1, name: 'Room too warm', enabled: true, dev: 0, src: 'temp', op: '>', thr: 27.0, hyst: 1.0, delay_s: 60, sev: 2 },
      { id: 2, name: 'Overcurrent', enabled: false, dev: 0, src: 'cur', op: '>', thr: 15.0, hyst: 0.5, delay_s: 5, sev: 3 },
    ] },
    snmp: { enabled: false, v1: false, v2c: false, auth_traps: false,
      v3: { enabled: true, users: [{ name: 'gwmonitor', access: 'ro', enabled: true }, { name: 'gwadmin', access: 'rw', enabled: true }] },
      traps: [], sys: { name: HOSTNAME, contact: '', location: '' } },
    time: { ntp: { enabled: false, servers: ['pool.ntp.org', 'time.google.com'], interval_min: 60 }, tz: 'KST-9' },
    security: { idle_min: 15, lockout: { max_fail: 5, lock_min: 5 }, ip_allow: [], services: { snmp: true, syslog: true } },
    notify: { syslog: { enabled: false, host: '', port: 514, facility: 16, min_sev: 5 } },
  };
}
let cfg = defaultConfig();
let cfgRev = 1;
const secrets = { ro: '', rw: '', v3: [{ auth: null, priv: null }, { auth: null, priv: null }], traps: [], apPsk: 'k7qm-4xtr-9wpe-2nhd' };
const SECTIONS = ['general', 'network', 'modbus', 'alarms', 'snmp', 'time', 'security', 'notify'];

function deepMerge(base, patch) {
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) return clone(patch);
  const out = base && typeof base === 'object' && !Array.isArray(base) ? clone(base) : {};
  for (const [k, v] of Object.entries(patch)) out[k] = deepMerge(out[k], v);
  return out;
}

// ------------------------------------------------------------------------------------------------
// Event log (system) and audit log
// ------------------------------------------------------------------------------------------------
const LOG_CAP = 4000;
const logs = { system: [], audit: [] };
const logSeq = { system: 0, audit: 0 };
function logAppend(kind, type, { dev = null, code = 0, sev = 0, value = 0, user = null, extra = 0, mono = monoMs() } = {}) {
  const rec = { seq: ++logSeq[kind], mono, type, dev, code, sev, value: clamp(Math.round(value), -32768, 32767), user, extra: extra >>> 0 };
  const list = logs[kind];
  list.push(rec);
  if (list.length > LOG_CAP) list.splice(0, list.length - LOG_CAP);
  return rec;
}
const audit = (type, user, o = {}) => logAppend('audit', type, { user, ...o });
// Account changes are a pair, as in components/auth/users.c audit_account(): the action (user =
// actor) then user_target (user = the account, code = the action's type number, extra = its seq).
const AUD_NUM = { password: 36, user_add: 37, user_mod: 38, user_del: 39 };
function auditAccount(type, by, target, o = {}) {
  const rec = audit(type, by, o);
  audit('user_target', target, { code: AUD_NUM[type], value: rec.value, extra: rec.seq });
}
const ip2u32 = (ip) => { const m = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || ''); return m ? ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0 : 0; };

// ------------------------------------------------------------------------------------------------
// MEX150 simulator
// ------------------------------------------------------------------------------------------------
const FAULT_COILS = [17, 18, 19, 20, 21, 22, 24, 25, 31];
const MIN_STAGE_S = 30;

class Mex {
  constructor(id) {
    this.id = id;
    this.T = 23.4 + gauss() * 0.3;
    this.H = 47 + gauss();
    this.cool = 0; this.heat = 0; this.hum = 0; this.dehum = false;
    this.stageChange = -1e9;
    this.running = true; this.delay = 0; this.delayKind = 0; // 1 run delay, 2 stop delay
    this.blower = true; this.supply = false; this.drain = false;
    this.faults = new Map(); // coil -> remaining seconds (Infinity = forced)
    this.contam = false;
    this.curA = 0;
    this.regs = new Map([[40002, 0], [40012, 230], [40013, 500], [40014, 10], [40015, 10], [40016, 50], [40017, 50],
      [40018, 5], [40019, 5], [40020, id + 1], [40021, -5], [40022, 0], [40027, 300], [40028, 150], [40029, 700], [40030, 99],
      [40053, 0], [40054, 0], [40059, 5000]]);
    this.t = 0; // simulated seconds
    this.updateDerivedRegs();
  }

  reg(addr) { return this.regs.get(addr) ?? 0; }

  /** Advance the plant by dt seconds at simulated time-of-day tod (s). */
  step(dt, tod) {
    this.t += dt;
    const set = this.reg(40012) / 10, setH = this.reg(40013) / 10;
    const coolDev = this.reg(40014) / 10, heatDev = this.reg(40015) / 10;
    const humDev = this.reg(40016) / 10, dehumDev = this.reg(40017) / 10;
    // Delays
    if (this.delay > 0) {
      this.delay = Math.max(0, this.delay - dt);
      if (this.delay === 0) { if (this.delayKind === 2) this.blower = false; this.delayKind = 0; }
    }
    const active = this.running && this.delayKind !== 1;
    // Fault timers
    for (const [c, left] of this.faults) {
      if (left === Infinity) continue;
      if (left - dt <= 0) this.faults.delete(c); else this.faults.set(c, left - dt);
    }
    const ok = (coil) => !this.faults.has(coil);
    // Deadband stage logic with minimum on/off time
    if (active && this.t - this.stageChange >= MIN_STAGE_S) {
      const maxCool = [18, 19, 31].filter(ok).length;
      const maxHeat = ok(20) ? 4 : 0;
      let cool = this.cool, heat = this.heat;
      if (this.T > set + coolDev * (cool + 1) && cool < maxCool) cool++;
      else if (cool > 0 && this.T < set + coolDev * (cool - 1)) cool--;
      if (this.T < set - heatDev * (heat + 1) && heat < maxHeat) heat++;
      else if (heat > 0 && this.T > set - heatDev * (heat - 1)) heat--;
      if (cool > 0) heat = 0;
      cool = Math.min(cool, maxCool);
      if (cool !== this.cool || heat !== this.heat) { this.cool = cool; this.heat = heat; this.stageChange = this.t; }
    }
    if (!active) { this.cool = 0; this.heat = 0; }
    // Humidity: humidifier / dehumidifier with options 40053 / 40054
    if (active && ok(21)) {
      const allowHum = !(this.reg(40053) === 1 && this.cool > 0);
      if (!allowHum) this.hum = 0;
      else if (this.H < setH - humDev - 2) this.hum = 2;
      else if (this.H < setH - humDev) this.hum = Math.max(this.hum, 1);
      else if (this.H > setH) this.hum = 0;
    } else this.hum = 0;
    if (active) {
      const allowDehum = !(this.reg(40054) === 1 && this.heat > 0);
      if (!allowDehum) this.dehum = false;
      else if (this.H > setH + dehumDev) this.dehum = true;
      else if (this.H < setH) this.dehum = false;
    } else this.dehum = false;
    if (this.dehum) this.hum = 0;
    if (this.running && this.delayKind === 1) this.blower = true;
    if (this.running && active) this.blower = ok(17);
    // Supply / drain valve cycles while humidifying
    const cyc = Math.floor(this.t) % 600;
    this.supply = this.hum > 0 && ok(24) && cyc % 50 < 10;
    this.drain = this.hum > 0 && ok(25) && cyc < 15;
    // Physics (°C/s, %/s)
    const load = 0.0105 + 0.0035 * Math.sin((2 * Math.PI * (tod - 50400)) / 86400 + Math.PI / 2);
    const coolPow = this.cool * 0.012 + (this.dehum ? 0.004 : 0);
    const dT = load - coolPow + this.heat * 0.0065 + (26 - this.T) * 0.0015 + gauss() * 0.002;
    this.T = clamp(this.T + dT * dt, -20, 80);
    const amb = 47 + 10 * Math.sin((2 * Math.PI * (tod - 32400)) / 86400);
    const dH = (amb - this.H) * 0.0006 + this.hum * 0.028 - (this.dehum ? 0.035 : 0) - this.cool * 0.003 + gauss() * 0.01;
    this.H = clamp(this.H + dH * dt, 5, 98);
    this.curA = this.blower ? 1.8 : 0;
    this.curA += this.cool * 3.2 + this.heat * 2.5 + this.hum * 1.6 + (this.dehum ? 3.2 : 0) + (this.blower ? gauss() * 0.08 : 0);
    this.curA = clamp(this.curA, 0, 99.9);
    this.updateDerivedRegs();
  }

  /** Recompute register words and coils from the plant state (what the MEX150 would report). */
  updateDerivedRegs() {
    const T = Math.round(this.T * 10), H = Math.round(this.H * 10);
    const hiT = this.reg(40027), loT = this.reg(40028), hiH = this.reg(40029), loH = this.reg(40030);
    const almHiT = hiT !== 249 && T > hiT, almLoT = loT !== 49 && T < loT;
    const almHiH = hiH !== 599 && H > hiH, almLoH = loH !== 99 && H < loH;
    let coils = 0;
    const set = (n, on) => { if (on) coils |= 1 << (n - 1); };
    const coolStages = Math.max(this.cool, this.dehum ? 1 : 0);
    set(1, this.blower); set(2, coolStages >= 1); set(3, coolStages >= 2); set(16, coolStages >= 3);
    for (let i = 0; i < 4; i++) set(4 + i, this.heat > i);
    set(8, this.hum >= 1); set(9, this.hum >= 2); set(10, this.supply); set(11, this.drain);
    set(12, this.cool > 0); set(13, this.heat > 0); set(14, this.hum > 0); set(15, this.dehum);
    for (const c of this.faults.keys()) set(c, true);
    set(26, almLoT); set(27, almHiT); set(28, almLoH); set(29, almHiH);
    if ((coils >>> 16) & 0x7fff) coils |= 1 << 31;
    this.coils = coils >>> 0;
    const has = (c) => (coils >>> (c - 1)) & 1;
    let ad1 = 0;
    [[17, 0], [18, 1], [19, 2], [20, 3], [21, 4], [30, 5], [23, 6], [24, 8], [25, 9]].forEach(([c, b]) => { if (has(c)) ad1 |= 1 << b; });
    if (this.contam) ad1 |= 1 << 7;
    let ad2 = 0;
    if (this.delayKind === 1) ad2 |= 1; if (this.delayKind === 2) ad2 |= 2;
    if (has(31)) ad2 |= 1 << 2; if (has(22)) ad2 |= 1 << 11;
    if (almHiT) ad2 |= 1 << 12; if (almLoT) ad2 |= 1 << 13; if (almHiH) ad2 |= 1 << 14; if (almLoH) ad2 |= 1 << 15;
    let cp = 0; for (let i = 0; i < coolStages; i++) cp |= 1 << (8 + i); if (this.dehum) cp |= 1 << 12;
    let hp = 0; for (let i = 0; i < this.heat; i++) hp |= 1 << (8 + i);
    let up = 0; if (this.hum >= 1) up |= 1 << 8; if (this.hum >= 2) up |= 1 << 9; if (this.supply) up |= 1 << 14; if (this.drain) up |= 1 << 15;
    const r = this.regs;
    r.set(40003, ad1); r.set(40004, ad2);
    r.set(40005, (this.running ? 1 : 0) | (Math.min(255, Math.ceil(this.delay)) << 8));
    r.set(40006, cp); r.set(40007, hp); r.set(40008, up);
    r.set(40011, clamp(Math.round(this.curA * 10), 0, 999));
    r.set(40036, clamp(T, -250, 850)); r.set(40037, clamp(H, 0, 990));
  }

  /** Apply a register write as the MEX150 would (raw = requested write value). */
  write(addr, raw) {
    if (addr === 40005) {
      const run = raw === 1;
      if (run && !this.running) { this.running = true; this.delay = this.reg(40018); this.delayKind = 1; this.blower = true; }
      else if (!run && this.running) { this.running = false; this.delay = this.reg(40019); this.delayKind = 2; this.cool = this.heat = this.hum = 0; this.dehum = false; }
    } else this.regs.set(addr, raw);
    this.updateDerivedRegs();
  }
}

// ------------------------------------------------------------------------------------------------
// History (per device): fast ring 1 s × 3600, slow ring 1 min × 30 days
// ------------------------------------------------------------------------------------------------
const NULL16 = -32768;
const FAST_N = 3600;
const SLOW_N = 30 * 1440 + 60;
const STAGE_KINDS = ['blower', 'cool', 'heat', 'hum', 'dehum'];
function stageBits(coils) {
  let b = 0;
  if (coils & 1) b |= 1;                       // blower
  if (coils & ((1 << 1) | (1 << 2) | (1 << 15))) b |= 2; // cool1/2/3
  if (coils & (0xf << 3)) b |= 4;             // heat1..4
  if (coils & (3 << 7)) b |= 8;               // hum1/2
  if (coils & (1 << 14)) b |= 16;             // dehumidifying
  return b;
}
class History {
  constructor() {
    this.f = { t: new Float64Array(FAST_N), temp: new Int16Array(FAST_N), hum: new Int16Array(FAST_N), cur: new Int16Array(FAST_N),
      st: new Int16Array(FAST_N), sh: new Int16Array(FAST_N), sb: new Uint8Array(FAST_N) };
    this.fHead = 0; this.fLen = 0;
    const F = () => new Int16Array(SLOW_N);
    this.s = { t: new Float64Array(SLOW_N), tmin: F(), tavg: F(), tmax: F(), hmin: F(), havg: F(), hmax: F(), cmin: F(), cavg: F(), cmax: F(),
      st: F(), sh: F(), on: STAGE_KINDS.map(() => new Uint16Array(SLOW_N)) };
    this.sHead = 0; this.sLen = 0;
    this.acc = null;
  }

  /** One 1 s sample at mono second ts (ms); v = null for a gap. */
  sampleFast(ts, v) {
    const i = (this.fHead + this.fLen) % FAST_N;
    if (this.fLen < FAST_N) this.fLen++; else this.fHead = (this.fHead + 1) % FAST_N;
    const f = this.f;
    f.t[i] = ts;
    if (v) { f.temp[i] = v.temp; f.hum[i] = v.hum; f.cur[i] = v.cur; f.st[i] = v.st; f.sh[i] = v.sh; f.sb[i] = stageBits(v.coils); }
    else { f.temp[i] = f.hum[i] = f.cur[i] = f.st[i] = f.sh[i] = NULL16; f.sb[i] = 0; }
    this.accumulate(ts, v, 1);
  }

  /** Feed the minute accumulator; w = seconds this sample represents. */
  accumulate(ts, v, w) {
    const minute = Math.floor(ts / 60000) * 60000;
    if (this.acc && this.acc.minute !== minute) this.closeMinute();
    if (!this.acc) this.acc = { minute, n: 0, sum: [0, 0, 0], min: [Infinity, Infinity, Infinity], max: [-Infinity, -Infinity, -Infinity], st: NULL16, sh: NULL16, on: [0, 0, 0, 0, 0] };
    if (!v) return;
    const a = this.acc;
    const vals = [v.temp, v.hum, v.cur];
    for (let k = 0; k < 3; k++) { a.sum[k] += vals[k] * w; a.min[k] = Math.min(a.min[k], vals[k]); a.max[k] = Math.max(a.max[k], vals[k]); }
    a.n += w; a.st = v.st; a.sh = v.sh;
    const b = stageBits(v.coils);
    for (let k = 0; k < 5; k++) if (b & (1 << k)) a.on[k] += w;
  }

  closeMinute() {
    const a = this.acc; this.acc = null;
    if (!a) return;
    const i = (this.sHead + this.sLen) % SLOW_N;
    if (this.sLen < SLOW_N) this.sLen++; else this.sHead = (this.sHead + 1) % SLOW_N;
    const s = this.s;
    s.t[i] = a.minute;
    if (a.n > 0) {
      s.tmin[i] = a.min[0]; s.tavg[i] = Math.round(a.sum[0] / a.n); s.tmax[i] = a.max[0];
      s.hmin[i] = a.min[1]; s.havg[i] = Math.round(a.sum[1] / a.n); s.hmax[i] = a.max[1];
      s.cmin[i] = a.min[2]; s.cavg[i] = Math.round(a.sum[2] / a.n); s.cmax[i] = a.max[2];
      s.st[i] = a.st; s.sh[i] = a.sh;
      for (let k = 0; k < 5; k++) s.on[k][i] = Math.min(60, Math.round(a.on[k]));
    } else {
      for (const key of ['tmin', 'tavg', 'tmax', 'hmin', 'havg', 'hmax', 'cmin', 'cavg', 'cmax', 'st', 'sh']) s[key][i] = NULL16;
      for (let k = 0; k < 5; k++) s.on[k][i] = 0xffff;
    }
  }

  /** Bucketed query over mono ms [a, b) (a aligned to dt). */
  query(a, dt, n, withStages) {
    const dtMs = dt * 1000;
    const ch = { temp: [], hum: [], cur: [], st: [], sh: [] };
    const mn = { temp: [], hum: [], cur: [] }, mx = { temp: [], hum: [], cur: [] };
    const stages = Object.fromEntries(STAGE_KINDS.map((k) => [k, []]));
    const fine = dt < 60;
    const buckets = Array.from({ length: n }, () => ({ c: 0, s: [0, 0, 0], mn: [Infinity, Infinity, Infinity], mx: [-Infinity, -Infinity, -Infinity], st: null, sh: null, on: [0, 0, 0, 0, 0] }));
    const put = (t, vals, mins, maxs, st, sh, on, w) => {
      const bi = Math.floor((t - a) / dtMs);
      if (bi < 0 || bi >= n) return;
      const B = buckets[bi];
      for (let k = 0; k < 3; k++) { B.s[k] += vals[k] * w; B.mn[k] = Math.min(B.mn[k], mins[k]); B.mx[k] = Math.max(B.mx[k], maxs[k]); }
      B.c += w; B.st = st; B.sh = sh;
      for (let k = 0; k < 5; k++) B.on[k] += on[k];
    };
    if (fine) {
      const f = this.f;
      for (let j = 0; j < this.fLen; j++) {
        const i = (this.fHead + j) % FAST_N;
        if (f.temp[i] === NULL16) continue;
        const v = [f.temp[i], f.hum[i], f.cur[i]];
        const sb = f.sb[i];
        put(f.t[i], v, v, v, f.st[i], f.sh[i], STAGE_KINDS.map((_, k) => ((sb >> k) & 1)), 1);
      }
    } else {
      const s = this.s;
      const hi = a + n * dtMs;
      for (let j = 0; j < this.sLen; j++) {
        const i = (this.sHead + j) % SLOW_N;
        const t = s.t[i];
        if (t < a || t >= hi || s.tavg[i] === NULL16) continue;
        put(t, [s.tavg[i], s.havg[i], s.cavg[i]], [s.tmin[i], s.hmin[i], s.cmin[i]], [s.tmax[i], s.hmax[i], s.cmax[i]], s.st[i], s.sh[i], s.on.map((o) => o[i]), 1);
      }
      const p = this.acc; // the minute in progress
      if (p && p.n > 0 && p.minute >= a && p.minute < hi) {
        put(p.minute, p.sum.map((x) => Math.round(x / p.n)), p.min, p.max, p.st, p.sh, p.on.map((x) => Math.min(60, Math.round(x))), 1);
      }
    }
    for (const B of buckets) {
      const has = B.c > 0;
      const keys = ['temp', 'hum', 'cur'];
      keys.forEach((k, idx) => {
        ch[k].push(has ? Math.round(B.s[idx] / B.c) : null);
        mn[k].push(has ? B.mn[idx] : null); mx[k].push(has ? B.mx[idx] : null);
      });
      ch.st.push(has ? B.st : null); ch.sh.push(has ? B.sh : null);
      STAGE_KINDS.forEach((k, idx) => stages[k].push(has ? Math.min(dt, B.on[idx]) : null));
    }
    const out = { ch };
    if (!fine) { out.min = mn; out.max = mx; }
    if (withStages) out.stages = stages;
    return out;
  }
}

// ------------------------------------------------------------------------------------------------
// Device runtime: simulator + comm + stats + snapshots + history
// ------------------------------------------------------------------------------------------------
const devs = new Map(); // id -> runtime
function tod(ms) { return ((ms / 1000) + 9 * 3600) % 86400; } // KST time-of-day drives the load cycle

function makeDevice(id) {
  const d = { id, sim: new Mex(id), hist: new History(), online: false, commKnown: false, failCycles: 0, seq: 0, snapMono: null,
    snapRegs: null, snapCoils: 0, slowValid: false, lastSlow: 0, commLossLeft: 0, forcedOffline: false,
    nextCommLoss: monoMs() + rint(15, 30) * 60000,
    stats: { tx: 0, rx_ok: 0, crc: 0, timeout: 0, exception: 0, malformed: 0, rtt_last: 0, rtt_sum: 0, rtt_n: 0, rtt_max: 0, online_since: null, offline_count: 0, cycles: 0 },
    rtts: [], writeQueue: 0, alarmCnt: new Map() };
  prefillHistory(d);
  devs.set(id, d);
  return d;
}

/** Simulate the last 30 days (10 s steps) and the last hour (1 s steps) so every span has data. */
function prefillHistory(d) {
  const now = monoMs();
  const start = Math.floor((now - 30 * 86400000) / 60000) * 60000;
  const sim = d.sim;
  const outages = [];
  for (let k = 0; k < 6; k++) { const s = start + rnd() * (now - 7200000 - start); outages.push([s, s + rint(3, 40) * 60000]); }
  const stopAt = start + rnd() * (now - 86400000 * 2 - start);
  const setChange = start + rnd() * (now - 86400000 * 5 - start);
  let t = start;
  for (; t < now - 3600000; t += 10000) {
    if (Math.abs(t - stopAt) < 5000) sim.write(40005, 0);
    if (Math.abs(t - (stopAt + 3 * 3600000)) < 5000) sim.write(40005, 1);
    if (Math.abs(t - setChange) < 5000) sim.regs.set(40012, 240);
    if (Math.abs(t - (setChange + 2 * 86400000)) < 5000) sim.regs.set(40012, 230);
    sim.step(10, tod(t));
    const off = outages.some(([a, b]) => t >= a && t < b);
    d.hist.accumulate(t, off ? null : sampleOf(sim), 10);
  }
  if (!sim.running) sim.write(40005, 1);
  for (t = Math.floor((now - 3600000) / 1000) * 1000; t < now; t += 1000) {
    sim.step(1, tod(t));
    d.hist.sampleFast(t, sampleOf(sim));
  }
  d.lastSample = t;
}
function sampleOf(sim) {
  return { temp: sim.reg(40036), hum: sim.reg(40037), cur: sim.reg(40011), st: sim.reg(40012), sh: sim.reg(40013), coils: sim.coils };
}

function enabledDevs() { return cfg.modbus.devices.filter((x) => x.enabled).map((x) => x.id).sort((a, b) => a - b); }
function devCfg(id) { return cfg.modbus.devices.find((x) => x.id === id); }
function syncDevices() {
  for (const dc of cfg.modbus.devices) if (!devs.has(dc.id)) makeDevice(dc.id);
  for (const id of [...devs.keys()]) if (!devCfg(id)) devs.delete(id);
  for (const d of devs.values()) {
    const en = devCfg(d.id)?.enabled;
    if (!en) {
      // Disabled devices produce no COMM and their alarms are cleared (alm_engine_set_enabled).
      d.online = false; d.commKnown = false; d.snapRegs = null; d.snapMono = null; d.failCycles = 0;
      for (const a of [...activeAlarms.values()]) if (a.dev === d.id) clearAlarm(a, 'disabled');
    }
  }
}

/** One poll cycle for device d (fast group; slow group every 10 s). */
function pollCycle(d) {
  const st = d.stats;
  const now = monoMs();
  const lossActive = d.forcedOffline || d.commLossLeft > 0;
  const blocks = 8 + (now - d.lastSlow >= 10000 || !d.slowValid ? 3 : 0);
  st.cycles++;
  if (lossActive) {
    st.tx += 1 + cfg.modbus.retries; st.timeout += 1 + cfg.modbus.retries;
    d.failCycles++;
    if ((d.online || !d.commKnown) && d.failCycles >= cfg.modbus.offline_after) setOnline(d, false);
    return;
  }
  st.tx += blocks;
  if (rnd() < 0.0015) { st.crc++; st.tx++; }
  st.rx_ok += blocks;
  const rtt = Math.round(36 + Math.abs(gauss()) * 10 + (rnd() < 0.02 ? rint(20, 80) : 0));
  st.rtt_last = rtt; st.rtt_sum += rtt; st.rtt_n++; st.rtt_max = Math.max(st.rtt_max, rtt);
  d.rtts.push(rtt); if (d.rtts.length > 120) d.rtts.shift();
  if (blocks > 8) { d.lastSlow = now; d.slowValid = true; }
  d.failCycles = 0;
  d.seq = (d.seq + 1) >>> 0;
  d.snapMono = now;
  d.snapRegs = new Map(d.sim.regs);
  d.snapCoils = d.sim.coils;
  if (!d.online) setOnline(d, true);
  alarmFeedSnapshot(d);
  broadcastSnap(d);
}

/** COMM decision: posted for the first decision after boot/reconfigure and every later change. */
function setOnline(d, on) {
  if (d.commKnown && d.online === on) return;
  const wasOnline = d.commKnown && d.online;
  d.commKnown = true;
  d.online = on;
  if (on) d.stats.online_since = wallMs();
  else { if (wasOnline) d.stats.offline_count++; d.stats.online_since = null; }
  logAppend('system', on ? 'comm_restored' : 'comm_lost', { dev: d.id, code: 301, sev: on ? 0 : 2 });
  if (!on) raiseAlarm(d.id, 'comm_lost', 1); else { const a = activeAlarms.get(`${d.id}:comm_lost`); if (a) clearAlarm(a); }
  broadcast('comm', commFrame(d));
}
// Firmware rule (API.md §4.4 Freshness): max(3 s, poll_ms + 3 s) when poll_ms > 3000.
const freshWindow = () => (cfg.modbus.poll_ms > 3000 ? cfg.modbus.poll_ms + 3000 : 3000);
const isFresh = (d) => d.online && d.snapMono !== null && monoMs() - d.snapMono < freshWindow();

// ------------------------------------------------------------------------------------------------
// Alarms
// ------------------------------------------------------------------------------------------------
const activeAlarms = new Map(); // key -> active record
const effSev = (id) => (cfg.alarms.sev_override[id] ?? ALM_BY_ID.get(id).sev);
function alarmValue(d, a) { return a.vreg ? (d.snapRegs?.get(a.vreg) ?? 1) : 1; }

function raiseAlarm(dev, id, value, sevOverride) {
  const key = `${dev}:${id}`;
  if (activeAlarms.has(key)) return;
  const cat = ALM_BY_ID.get(id);
  const sev = sevOverride ?? effSev(id);
  const rec = logAppend('system', 'alarm_raise', { dev, code: cat.code, sev, value });
  const a = { key, dev, id, code: cat.code, sev, since: toWall(rec.mono), acked: false, ack_by: null, ack_ts: null, value, mono: rec.mono };
  activeAlarms.set(key, a);
  broadcast('alarm', { t: 'alarm', dev, key, id, code: cat.code, type: 'raise', sev, ts: a.since, seq: rec.seq, value });
}
function clearAlarm(a) {
  activeAlarms.delete(a.key);
  const rec = logAppend('system', 'alarm_clear', { dev: a.dev, code: a.code, sev: a.sev, value: a.value });
  broadcast('alarm', { t: 'alarm', dev: a.dev, key: a.key, id: a.id, code: a.code, type: 'clear', sev: a.sev, ts: toWall(rec.mono), seq: rec.seq, value: a.value });
}
function ackAlarm(a, user) {
  if (a.acked) return;
  const rec = logAppend('system', 'alarm_ack', { dev: a.dev, code: a.code, sev: a.sev, value: a.value, user });
  a.acked = true; a.ack_by = user; a.ack_ts = toWall(rec.mono);
  broadcast('alarm', { t: 'alarm', dev: a.dev, key: a.key, id: a.id, code: a.code, type: 'ack', sev: a.sev, ts: a.ack_ts, seq: rec.seq, value: a.value, user });
}

/** Debounced device alarms (coils 17–31, 40003 bit 7); frozen while offline. */
function alarmFeedSnapshot(d) {
  const { debounce_raise: nr, debounce_clear: nc } = cfg.alarms;
  for (const cat of CATALOG) {
    let cond;
    if (cat.kind === 'SRC_COIL') cond = ((d.snapCoils >>> (cat.addr - 1)) & 1) === 1;
    else if (cat.kind === 'SRC_BIT') cond = ((d.snapRegs.get(cat.addr) >>> cat.bit) & 1) === 1;
    else continue;
    const key = `${d.id}:${cat.id}`;
    const active = activeAlarms.has(key);
    const c = d.alarmCnt.get(key) || 0;
    if (cond !== active) {
      const n = c + 1;
      if (n >= (cond ? nr : nc)) {
        d.alarmCnt.set(key, 0);
        if (cond) raiseAlarm(d.id, cat.id, alarmValue(d, cat)); else clearAlarm(activeAlarms.get(key));
      } else d.alarmCnt.set(key, n);
    } else if (c) d.alarmCnt.set(key, 0);
  }
}

/** User threshold rules on 1 Hz samples: hysteresis + on-delay. */
const ruleState = new Map(); // rule id -> {since}
const ruleAddr = (src) => (src === 'temp' ? 40036 : src === 'hum' ? 40037 : src === 'cur' ? 40011 : Number(src.slice(4)));
function ruleValue(d, src) {
  if (!d || !isFresh(d)) return null;
  const addr = ruleAddr(src);
  const r = REG_BY_ADDR.get(addr);
  if (!r || !d.snapRegs.has(addr)) return null;
  return d.snapRegs.get(addr) / r.scale;
}
function evalRules() {
  const ids = new Set();
  for (const rule of cfg.alarms.rules) {
    ids.add(rule.id);
    const key = `${rule.dev}:rule_${rule.id}`;
    const active = activeAlarms.get(key);
    const d = devs.get(rule.dev);
    if (!rule.enabled || !devCfg(rule.dev)?.enabled) { if (active) clearAlarm(active); ruleState.delete(rule.id); continue; }
    const v = ruleValue(d, rule.src);
    if (v === null) continue; // frozen while offline/stale
    const over = rule.op === '>' ? v > rule.thr : v < rule.thr;
    const clear = rule.op === '>' ? v <= rule.thr - rule.hyst : v >= rule.thr + rule.hyst;
    const st = ruleState.get(rule.id) || { since: null };
    if (!active) {
      if (over) { st.since ??= monoMs(); if (monoMs() - st.since >= rule.delay_s * 1000) { raiseAlarm(rule.dev, `rule_${rule.id}`, Math.round(v * REG_BY_ADDR.get(ruleAddr(rule.src)).scale), rule.sev); /* value = source raw (API.md §4.7) */ st.since = null; } }
      else st.since = null;
    } else if (clear) clearAlarm(active);
    ruleState.set(rule.id, st);
  }
  for (const a of [...activeAlarms.values()]) {
    if (a.id.startsWith('rule_') && !ids.has(Number(a.id.slice(5)))) clearAlarm(a);
  }
}

// ------------------------------------------------------------------------------------------------
// Writes (validation mirrors mex_check_write; queue depth 8; verify; command history 16)
// ------------------------------------------------------------------------------------------------
let cmdSeq = 0;
const commands = []; // last 16
function rememberCommand(c) { commands.push(c); if (commands.length > 16) commands.shift(); }
function wsWrite(dev, c, by) {
  const f = { t: 'write', dev, cmd: c.cmd, addr: c.addr, state: c.state, by };
  if (c.state !== 'rejected' && c.raw !== undefined) f.raw = c.raw;
  if (c.reason) f.reason = c.reason;
  broadcast('write', f);
}
const WSTATE = { pending: 0, applied: 1, rejected: 2, uncertain: 3 };
const REASON = { readonly: 2, range: 3, running_interlock: 4, offline: 5, busy: 6, no_ack: 7, verify_mismatch: 8, cancelled: 9 };
/** AUD_REG_WRITE: value = raw requested, extra = EVLOG_REG_WRITE_EXTRA(raw_before, state, reason). */
function auditWrite(dev, addr, before, requested, user, state, reason) {
  const rb = reason ? (reason.startsWith('exception:') ? 0x80 | Number(reason.slice(10)) : REASON[reason] || 0) : 0;
  audit('reg_write', user, { dev, code: addr, value: requested, extra: ((before & 0xffff) | (WSTATE[state] << 16) | (rb << 24)) >>> 0 });
}

/**
 * Validate and execute a write. Returns {status, body} per API.md §4.4.
 * @param {number|null} value scaled value (or null), @param {number|null} raw raw value (or null)
 */
async function doWrite(d, addr, value, raw, user) {
  const r = REG_BY_ADDR.get(addr);
  if (!r) return { status: 404, body: { error: 'not_found', message: 'unknown register', code: 'unknown_register' } };
  const before = d.snapRegs?.get(addr) ?? 0;
  const reject = (reason) => {
    const c = { cmd: 0, dev: d.id, addr, state: 'rejected', reason };
    wsWrite(d.id, c, user);
    auditWrite(d.id, addr, before, raw ?? 0, user, 'rejected', reason);
    return { status: 409, body: { error: 'rejected', state: 'rejected', cmd: 0, addr, reason } };
  };
  if (value !== null) {
    const x = value * r.scale;
    if (!Number.isFinite(x) || Math.abs(x - Math.round(x)) > 1e-6) return reject('range');
    raw = Math.round(x);
  }
  if (r.access !== 'rw') return reject('readonly');
  if (raw < r.min || raw > r.max) { if (r.disabled === null || raw !== r.disabled) return reject('range'); }
  if (!isFresh(d)) return reject('offline');
  if (r.stopped_only && d.sim.running) return reject('running_interlock');
  if (d.writeQueue >= 8) { auditWrite(d.id, addr, before, raw, user, 'rejected', 'busy'); return { status: 503, body: { error: 'busy', message: 'write queue full' } }; }
  const c = { cmd: ++cmdSeq, dev: d.id, addr, state: 'pending', raw: before, requested: raw, reason: null, mono: monoMs() };
  rememberCommand(c);
  d.writeQueue++;
  const latency = rnd() < 0.1 ? rint(1600, 2600) : rint(180, 900);
  const done = new Promise((resolve) => setTimeout(() => {
    d.writeQueue--;
    const roll = rnd();
    // Re-validate with the newest snapshot (interlock may have changed while queued).
    if (!isFresh(d)) { c.state = 'rejected'; c.reason = 'offline'; }
    else if (r.stopped_only && d.sim.running) { c.state = 'rejected'; c.reason = 'running_interlock'; }
    else if (roll < 0.015) { c.state = 'uncertain'; c.reason = 'no_ack'; }
    else {
      d.sim.write(addr, raw);
      d.snapRegs?.set(addr, d.sim.reg(addr));
      c.state = 'applied'; c.raw = d.sim.reg(addr);
    }
    c.mono = monoMs();
    wsWrite(d.id, c, user);
    auditWrite(d.id, addr, before, raw, user, c.state, c.reason);
    resolve();
  }, latency));
  await Promise.race([done, new Promise((res) => setTimeout(res, 1500))]);
  if (c.state === 'applied') return { status: 200, body: { state: 'applied', cmd: c.cmd, addr, raw: c.raw } };
  if (c.state === 'pending') return { status: 202, body: { state: 'pending', cmd: c.cmd, addr } };
  if (c.state === 'uncertain') return { status: 202, body: { state: 'uncertain', cmd: c.cmd, addr, reason: c.reason } };
  return { status: 409, body: { error: 'rejected', state: 'rejected', cmd: c.cmd, addr, reason: c.reason } };
}

// ------------------------------------------------------------------------------------------------
// Users, sessions, rate limiting
// ------------------------------------------------------------------------------------------------
const FACTORY_PASS = 'mestio150!';
const users = new Map();
const hashPw = (salt, pw) => createHash('sha256').update(salt).update(pw).digest();
function setPassword(u, pw) { u.salt = randomBytes(16); u.hash = hashPw(u.salt, pw); }
function checkPassword(u, pw) { const h = hashPw(u ? u.salt : Buffer.alloc(16), pw); return !!u && timingSafeEqual(h, u.hash); }
function addUser(name, role, pw, mustChange, changed) { const u = { name, role, must_change: mustChange, changed }; setPassword(u, pw); users.set(name, u); return u; }
function resetUsers() {
  users.clear();
  if (OPT.ready) addUser('admin', 'admin', 'Mestio-Admin#2026', false, wallMs());
  else addUser('admin', 'admin', FACTORY_PASS, true, null);
}
resetUsers();
const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };

function policyRules(pw, name, current) {
  const rules = [];
  if ([...pw].length < 10) rules.push('min_length');
  if (Buffer.byteLength(pw) > 64) rules.push('max_length');
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (classes < 3) rules.push('classes');
  if (pw.toLowerCase() === name.toLowerCase()) rules.push('not_username');
  if (pw === FACTORY_PASS) rules.push('not_default');
  if (current !== undefined && pw === current) rules.push('not_previous');
  if (/[\u0000-\u001f\u007f]/.test(pw)) rules.push('charset');
  return rules;
}

const sessions = new Map(); // sha256(token) hex -> session
const tokenHash = (t) => createHash('sha256').update(t).digest('hex');
const b64url = (n) => randomBytes(n).toString('base64url');
let sidSeq = 0;
function createSession(u) {
  if (sessions.size >= 8) {
    let oldest = null;
    for (const [k, s] of sessions) if (!oldest || s.last < oldest[1].last) oldest = [k, s];
    endSession(oldest[0], 'session_expired');
  }
  const token = b64url(16);
  const s = { sid: ++sidSeq, user: u.name, csrf: b64url(16), created: monoMs(), last: monoMs() };
  sessions.set(tokenHash(token), s);
  return { token, s };
}
function endSession(key, reason) {
  const s = sessions.get(key);
  if (!s) return;
  sessions.delete(key);
  closeWsSession(s.sid, reason);
}
function revokeUserSessions(name, reason, exceptSid) {
  for (const [k, s] of [...sessions]) if (s.user === name && s.sid !== exceptSid) endSession(k, reason);
}
function sessionAlive(s) {
  const now = monoMs();
  return now - s.last < cfg.security.idle_min * 60000 && now - s.created < 12 * 3600000 && users.has(s.user);
}
function expireSessions() {
  for (const [k, s] of [...sessions]) if (!sessionAlive(s)) endSession(k, 'session_expired');
}
function cookieToken(req) {
  const m = /(?:^|;\s*)gw_sid=([A-Za-z0-9_-]{22})(?:;|$)/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
}
function lookupSession(req) {
  const t = cookieToken(req);
  if (!t) return null;
  const key = tokenHash(t);
  const s = sessions.get(key);
  if (!s) return null;
  if (!sessionAlive(s)) { endSession(key, 'session_expired'); return null; }
  return { key, s, u: users.get(s.user) };
}

const limiter = new Map(); // ip -> {fails:[ms], lockUntil, locks}
const globalFails = [];
function rlCheck(ip) {
  const e = limiter.get(ip);
  if (e && e.lockUntil > monoMs()) return Math.max(1, Math.ceil((e.lockUntil - monoMs()) / 1000));
  return 0;
}
/** Record a failed attempt; returns the lock seconds when this failure triggered a lock (→ 429). */
function rlFail(ip, user) {
  const now = monoMs();
  const e = limiter.get(ip) || { fails: [], lockUntil: 0, locks: 0 };
  e.fails = e.fails.filter((t) => now - t < 300000);
  e.fails.push(now);
  globalFails.push(now);
  while (globalFails.length && now - globalFails[0] > 60000) globalFails.shift();
  if (e.fails.length >= cfg.security.lockout.max_fail) {
    const mins = Math.min(30, cfg.security.lockout.lock_min * 2 ** e.locks);
    e.locks++; e.lockUntil = now + mins * 60000; e.fails = [];
    audit('lockout', user, { extra: ip2u32(ip), value: mins });
    limiter.set(ip, e);
    return mins * 60;
  }
  limiter.set(ip, e);
  return 0;
}
const lockedErr = (s) => E(429, 'rate_limited', 'too many failed attempts', { retry_after: s });
function rlSuccess(ip) { const e = limiter.get(ip); if (e) e.fails = []; }

// ------------------------------------------------------------------------------------------------
// Network provisional state, firmware, reboot
// ------------------------------------------------------------------------------------------------
let provisional = null; // {cand, psk, applyAt, deadline, user}
function provisionalView() {
  if (!provisional) return null;
  const now = monoMs();
  if (now < provisional.applyAt) return { state: 'apply_pending', left_s: Math.ceil((provisional.applyAt - now) / 1000) };
  return { state: 'await_confirm', left_s: Math.max(0, Math.ceil((provisional.deadline - now) / 1000)) };
}
function startProvisional(cand, psk, user) {
  provisional = { cand, psk, applyAt: monoMs() + 3000, deadline: monoMs() + 3000 + 120000, user };
  logAppend('system', 'net_provisional', { value: 1 });
  return { apply_in_s: 3, confirm_within_s: 120 };
}
function tickProvisional() {
  if (provisional && monoMs() > provisional.deadline) {
    logAppend('system', 'net_provisional', { value: 0 });
    log('network: provisional change not confirmed -> reverted');
    provisional = null;
  }
}

const fw = { running: { slot: 'ota_0', version: FW_VERSION, state: 'valid' }, other: { slot: 'ota_1', version: '0.0.9', valid: true },
  uploading: false, pendingSince: 0 };
let rebootUntil = 0;
function scheduleReboot(reason, afterMs, then) {
  setTimeout(() => {
    for (const ws of wsClients) { send(ws, { t: 'bye', reason: 'reboot' }); ws.close(1001, 'reboot'); }
    for (const k of [...sessions.keys()]) sessions.delete(k);
    rebootUntil = monoMs() + 6000;
    logAppend('system', 'reboot', { code: reason });
    if (then) then();
    log(`simulated reboot (${reason}); unreachable for 6 s`);
    setTimeout(() => logAppend('system', 'boot', {}), 6000);
  }, afterMs);
}

// ------------------------------------------------------------------------------------------------
// Response helpers
// ------------------------------------------------------------------------------------------------
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
function baseHeaders(extra = {}) {
  return { 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', ...extra };
}
function sendJson(res, status, obj, extra = {}) {
  const body = obj === undefined ? '' : JSON.stringify(obj);
  res.writeHead(status, baseHeaders({ 'Cache-Control': 'no-store', ...(body ? { 'Content-Type': 'application/json' } : {}), ...extra }));
  res.end(body);
}
class HttpError extends Error {
  constructor(status, error, message, extra = {}) { super(message); this.status = status; this.body = { error, message, ...extra }; }
}
const E = (status, error, message, extra) => new HttpError(status, error, message, extra);
class Reply { constructor(status, body, headers) { this.status = status; this.body = body; this.headers = headers; } }
const reply = (status, body, headers = {}) => new Reply(status, body, headers);
/** Non-JSON 200 body (CSV, gzip MIB). */
class RawBody { constructor(body, type, headers) { this.body = body; this.type = type; this.headers = headers; } }

// Host check (DNS rebinding, API.md §1.1): the gateway's names plus this machine's own addresses,
// so the mock can be opened from the LAN when bound to 0.0.0.0.
const LOCAL_ADDRS = Object.values(networkInterfaces()).flat().filter(Boolean).map((i) => i.address.toLowerCase());
function hostAllowed(hostHeader) {
  if (!hostHeader) return false;
  const h = hostHeader.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  const hn = cfg.network.hostname.toLowerCase();
  return ['localhost', cfg.network.eth.ip, '192.168.150.1', hn, `${hn}.local`, OPT.host.toLowerCase()].includes(h) || LOCAL_ADDRS.includes(h);
}
function originOk(req) {
  const src = req.headers.origin || req.headers.referer;
  if (!src) return true;
  try { return new URL(src).host.toLowerCase() === String(req.headers.host).toLowerCase(); } catch { return false; }
}
function clientIp(req) { return (req.socket.remoteAddress || '').replace(/^::ffff:/, ''); }

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers['content-length'] || 0);
    if (len > limit) { req.resume(); reject(E(413, 'payload_too_large', 'body too large')); return; }
    const chunks = []; let n = 0; let failed = false;
    req.on('data', (c) => {
      if (failed) return;
      n += c.length;
      if (n > limit) { failed = true; reject(E(413, 'payload_too_large', 'body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!failed) resolve(Buffer.concat(chunks)); });
    req.on('error', (e) => { if (!failed) reject(e); });
  });
}

// ------------------------------------------------------------------------------------------------
// Views (responses)
// ------------------------------------------------------------------------------------------------
function liveView(d) {
  const regs = {};
  if (d.snapRegs) {
    for (const r of REGS) {
      if (SLOW_ADDRS.has(r.addr) && !d.slowValid) continue;
      regs[String(r.addr)] = d.snapRegs.get(r.addr) ?? 0;
    }
  }
  return { seq: d.seq, ts: d.snapMono === null ? null : toWall(d.snapMono), online: d.online, fresh: isFresh(d), slow_valid: d.slowValid,
    regs, coils: d.snapRegs ? d.snapCoils : 0, derived: d.snapRegs ? derived(d.snapRegs, d.snapCoils) : null };
}
function derived(regs, coils) {
  const b = (n) => (coils >>> (n - 1)) & 1;
  const mode = [];
  if (b(12)) mode.push('cool'); if (b(13)) mode.push('heat'); if (b(14)) mode.push('hum'); if (b(15)) mode.push('dehum');
  const w = regs.get(40005) ?? 0;
  return { temp: clamp((regs.get(40036) ?? 0) / 10, -25, 85), hum: clamp((regs.get(40037) ?? 0) / 10, 0, 99), current: clamp((regs.get(40011) ?? 0) / 10, 0, 99.9),
    running: (w & 1) === 1, stages: { cool: b(2) + b(3) + b(16), heat: b(4) + b(5) + b(6) + b(7), hum: b(8) + b(9), dehum: b(15) }, mode, delay_s: (w >> 8) & 0xff };
}
function commFrame(d) {
  const s = d.stats;
  return { t: 'comm', dev: d.id, online: d.online, rtt: s.rtt_last, err: { crc: s.crc, timeout: s.timeout, exception: s.exception, malformed: s.malformed } };
}
function statsView(d) {
  const s = d.stats;
  return { tx: s.tx >>> 0, rx_ok: s.rx_ok >>> 0, crc: s.crc, timeout: s.timeout, exception: s.exception, malformed: s.malformed,
    rtt_ms: { last: s.rtt_last, avg: s.rtt_n ? Math.round(s.rtt_sum / s.rtt_n) : 0, max: s.rtt_max }, online_since: s.online_since,
    offline_count: s.offline_count, cycles: s.cycles };
}
function snmpView() {
  const c = cfg.snmp;
  return { enabled: c.enabled, v1: c.v1, v2c: c.v2c, ro_set: secrets.ro !== '', rw_set: secrets.rw !== '', auth_traps: c.auth_traps,
    v3: { enabled: c.v3.enabled, users: c.v3.users.map((u, i) => ({ ...u, auth: 'sha', priv: 'aes', keys_set: !!(secrets.v3[i].auth && secrets.v3[i].priv) })) },
    traps: c.traps.map((t, i) => ({ host: t.host, port: t.port, version: t.version, inform: t.inform, community_set: !!secrets.traps[i], enabled: t.enabled })),
    sys: c.sys };
}
function sectionView(s) {
  if (s === 'network') return { ...clone(cfg.network), ap: { ...clone(cfg.network.ap), psk_set: true }, provisional: provisionalView() };
  if (s === 'snmp') return snmpView();
  if (s === 'alarms') { const { rules, ...rest } = cfg.alarms; return clone(rest); }
  return clone(cfg[s]);
}
function userView(u) { return { name: u.name, role: u.role, must_change: u.must_change, changed: u.changed }; }
function bundle() {
  const b = { schema: 1, rev: cfgRev, fw: FW_VERSION };
  for (const s of SECTIONS) b[s] = clone(cfg[s]);
  return b;
}

// ------------------------------------------------------------------------------------------------
// Semantic validation (beyond the JSON schemas)
// ------------------------------------------------------------------------------------------------
const ip4n = (s) => s.split('.').reduce((a, x) => ((a << 8) | +x) >>> 0, 0);
function validateSection(s, v, clientIpAddr) {
  const bad = (field, code, message) => { throw E(422, 'validation', message, { field, code }); };
  if (s === 'modbus') {
    const ids = new Set(); const slaves = new Set();
    for (const [i, dv] of v.devices.entries()) {
      if (ids.has(dv.id)) bad(`devices[${i}].id`, 'duplicate', 'duplicate device id');
      ids.add(dv.id);
      if (Buffer.byteLength(dv.name) > 23) bad(`devices[${i}].name`, 'length', 'at most 23 bytes');
      if (dv.enabled) { if (slaves.has(dv.slave)) bad(`devices[${i}].slave`, 'duplicate', 'slave id already used'); slaves.add(dv.slave); }
    }
  } else if (s === 'network') {
    const e = v.eth;
    if (e.mode === 'static') {
      const mask = ip4n(e.mask);
      if (mask !== 0 && ((~mask >>> 0) & ((~mask >>> 0) + 1)) !== 0) bad('eth.mask', 'format', 'not a contiguous netmask');
      if (mask === 0) bad('eth.mask', 'format', 'netmask must not be 0.0.0.0');
      const apNet = ip4n('192.168.150.0'), apMask = ip4n('255.255.255.0');
      const m = (mask & apMask) >>> 0;
      if (((ip4n(e.ip) & m) >>> 0) === ((apNet & m) >>> 0)) bad('eth.ip', 'overlap', 'overlaps the recovery AP subnet 192.168.150.0/24');
      if (e.gw && ((ip4n(e.gw) & mask) >>> 0) !== ((ip4n(e.ip) & mask) >>> 0)) bad('eth.gw', 'format', 'gateway outside the subnet');
    }
  } else if (s === 'security') {
    for (const [i, c] of v.ip_allow.entries()) {
      const [a, n = '32'] = c.split('/');
      const mask = Number(n) === 0 ? 0 : (0xffffffff << (32 - Number(n))) >>> 0;
      if (((ip4n(a) & ~mask) >>> 0) !== 0) bad(`ip_allow[${i}]`, 'format', 'host bits must be zero');
    }
    if (v.ip_allow.length && clientIpAddr && /^\d+\.\d+\.\d+\.\d+$/.test(clientIpAddr)) {
      const ok = v.ip_allow.some((c) => { const [a, n = '32'] = c.split('/'); const mask = Number(n) === 0 ? 0 : (0xffffffff << (32 - Number(n))) >>> 0; return ((ip4n(clientIpAddr) & mask) >>> 0) === ((ip4n(a) & mask) >>> 0); });
      if (!ok) bad('ip_allow', 'lockout', 'the list would exclude this client');
    }
  } else if (s === 'general') {
    for (const k of ['site', 'location', 'contact']) if (Buffer.byteLength(v[k]) > 63) bad(k, 'length', 'at most 63 bytes');
  } else if (s === 'alarms') {
    for (const id of Object.keys(v.sev_override)) if (!ALM_BY_ID.has(id) || id.startsWith('rule_')) bad(`sev_override.${id}`, 'unknown_field', 'unknown alarm id');
  } else if (s === 'notify') {
    if (v.syslog.enabled && !v.syslog.host) bad('syslog.host', 'required', 'host required when enabled');
  }
}
function validateRules(list) {
  const bad = (field, code, message) => { throw E(422, 'validation', message, { field, code }); };
  const ids = new Set();
  list.forEach((r, i) => {
    if (ids.has(r.id)) bad(`[${i}].id`, 'duplicate', 'duplicate rule id');
    ids.add(r.id);
    if (Buffer.byteLength(r.name) > 23) bad(`[${i}].name`, 'length', 'at most 23 bytes');
    if (!cfg.modbus.devices.some((d) => d.id === r.dev)) bad(`[${i}].dev`, 'range', 'unknown device');
    if (r.src.startsWith('reg:') && !REG_BY_ADDR.has(Number(r.src.slice(4)))) bad(`[${i}].src`, 'unknown_register', 'unknown register');
  });
}
function schemaCheck(name, body) {
  const errs = SCHEMAS.validate(name, body);
  if (errs.length) {
    const v = toValidationError(errs);
    if (!v.field) delete v.field;
    throw new HttpError(422, 'validation', v.message, { ...(v.field ? { field: v.field } : {}), code: v.code });
  }
}

/** Apply a validated PUT /config/<s> body (merge semantics) incl. write-only secrets. */
function applySectionPut(s, body, user, ip) {
  if (s === 'snmp') return applySnmpPut(body, user);
  const next = deepMerge(cfg[s], body);
  // sev_override is a map value: a present object replaces the stored map (otherwise no override
  // could ever be removed by a merge); every other object merges member-wise (API.md §1).
  if (s === 'alarms' && body.sev_override) next.sev_override = clone(body.sev_override);
  validateSection(s, next, ip);
  commit(s, next, user);
  return sectionView(s);
}
function commit(s, next, user) {
  cfg[s] = next;
  cfgRev++;
  audit('config_change', user, { code: SECTIONS.indexOf(s), extra: cfgRev });
  if (s === 'modbus') { syncDevices(); restartPolling(); }
  if (s === 'time' && next.ntp.enabled && !clock.valid) { clock.valid = true; clock.offset = 0; logAppend('system', 'time_set', { code: 1 }); }
}
function applySnmpPut(body, user) {
  const next = deepMerge(cfg.snmp, (({ ro, rw, ...rest }) => rest)(body));
  if (body.v3?.users) next.v3.users = body.v3.users.map((u, i) => ({ ...cfg.snmp.v3.users[i], ...(({ auth_pass, priv_pass, ...x }) => x)(u) }));
  let trapSecrets = secrets.traps;
  if (body.traps) {
    trapSecrets = body.traps.map((t) => {
      if (t.community !== undefined) return t.community || null;
      const old = cfg.snmp.traps.findIndex((o) => o.host === t.host && o.port === (t.port ?? 162));
      return old >= 0 ? secrets.traps[old] : null;
    });
    next.traps = body.traps.map((t) => ({ host: t.host, port: t.port ?? 162, version: t.version ?? 'v2c', inform: t.inform ?? false, enabled: t.enabled ?? true }));
  }
  for (const [i, u] of (body.v3?.users || []).entries()) {
    const has = !!(secrets.v3[i].auth && secrets.v3[i].priv);
    if (!has && (u.auth_pass !== undefined) !== (u.priv_pass !== undefined)) {
      throw E(422, 'validation', 'both passphrases are required', { field: `v3.users[${i}].${u.auth_pass === undefined ? 'auth_pass' : 'priv_pass'}`, code: 'required' });
    }
  }
  const ro = body.ro !== undefined ? body.ro : secrets.ro;
  if ((next.v1 || next.v2c) && !ro) throw E(422, 'validation', 'a read community is required to enable v1/v2c', { field: 'ro', code: 'required' });
  for (const k of ['name', 'contact', 'location']) if (Buffer.byteLength(next.sys[k]) > 63) throw E(422, 'validation', 'at most 63 bytes', { field: `sys.${k}`, code: 'length' });
  if (body.ro !== undefined) secrets.ro = body.ro;
  if (body.rw !== undefined) secrets.rw = body.rw;
  body.v3?.users?.forEach((u, i) => {
    if (u.auth_pass) secrets.v3[i].auth = createHash('sha1').update(u.auth_pass).digest('hex');
    if (u.priv_pass) secrets.v3[i].priv = createHash('sha1').update(u.priv_pass).digest('hex');
  });
  secrets.traps = trapSecrets;
  commit('snmp', next, user);
  return snmpView();
}

// ------------------------------------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------------------------------------
const R = [];
function route(m, p, role, opts, h) {
  const names = [];
  const re = new RegExp(`^${p.replace(/\{(\w+)\}/g, (_, n) => { names.push(n); return '([^/]+)'; })}$`);
  R.push({ m, re, names, role, csrf: m !== 'GET' && opts.csrf !== false, body: opts.body || (m === 'GET' ? 'none' : 'none'), req: opts.req, h, p });
}
const LIMITS = { none: 0, json: 8192, import: 32768, firmware: 3 * 1024 * 1024 };

function devOf(params) {
  const id = Number(params.d);
  if (!/^\d$/.test(params.d) || !devCfg(id) || !devs.has(id)) throw E(404, 'not_found', 'unknown device');
  return devs.get(id);
}
function intQ(q, k, def, min, max) {
  if (!q.has(k)) return def;
  const s = q.get(k);
  if (!/^-?\d+$/.test(s)) throw E(400, 'bad_request', `${k} must be an integer`);
  const v = Number(s);
  if (v < min || v > max) throw E(400, 'bad_request', `${k} out of range`);
  return v;
}

// --- auth ---
route('POST', '/auth/login', 'none', { body: 'json', req: 'auth-login.request' }, async (ctx) => {
  const ip = ctx.ip;
  const wait = rlCheck(ip);
  if (wait) throw E(429, 'rate_limited', 'too many failed logins', { retry_after: wait });
  if (globalFails.length > 20) await new Promise((r) => setTimeout(r, 1000));
  const u = users.get(ctx.body.user);
  await new Promise((r) => setTimeout(r, 120)); // PBKDF2 cost
  if (!checkPassword(u, ctx.body.pass)) {
    audit('login_fail', (ctx.body.user || '').slice(0, 11), { extra: ip2u32(ip) });
    const locked = rlFail(ip, (ctx.body.user || '').slice(0, 11));
    if (locked) throw lockedErr(locked);
    throw E(401, 'bad_credentials', 'wrong user name or password');
  }
  rlSuccess(ip);
  const { token, s } = createSession(u);
  audit('login_ok', u.name, { extra: ip2u32(ip) });
  ctx.setCookie = `gw_sid=${token}; Path=/; HttpOnly; SameSite=Strict`;
  return { user: u.name, role: u.role, csrf: s.csrf, must_change: u.must_change, idle_s: cfg.security.idle_min * 60 };
});
route('POST', '/auth/logout', 'cookie', {}, (ctx) => {
  audit('logout', ctx.u.name, { code: 0 });
  endSession(ctx.sess.key, 'logout');
  ctx.setCookie = 'gw_sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';
  return reply(204);
});
route('GET', '/session', 'none', {}, (ctx) => {
  const ss = lookupSession(ctx.req);
  if (!ss) return reply(401, {});
  const { s, u } = ss;
  const expires = Math.max(0, Math.floor(Math.min(cfg.security.idle_min * 60000 - (monoMs() - s.last), 12 * 3600000 - (monoMs() - s.created)) / 1000));
  return { user: u.name, role: u.role, csrf: s.csrf, must_change: u.must_change, idle_s: cfg.security.idle_min * 60, expires_in: expires };
});
route('POST', '/auth/password', 'cookie', { body: 'json', req: 'auth-password.request' }, (ctx) => {
  const wait = rlCheck(ctx.ip);
  if (wait) throw E(429, 'rate_limited', 'too many failed attempts', { retry_after: wait });
  const u = ctx.u;
  if (!checkPassword(u, ctx.body.current)) {
    const locked = rlFail(ctx.ip, u.name);
    if (locked) throw lockedErr(locked);
    throw E(422, 'wrong_password', 'current password is wrong', { field: 'current' });
  }
  const rules = policyRules(ctx.body.new, u.name, ctx.body.current);
  if (rules.length) throw E(422, 'policy', 'password does not meet the policy', { field: 'new', rules });
  setPassword(u, ctx.body.new);
  u.must_change = false; u.changed = wallMs();
  audit('password', u.name, { extra: 0 });
  revokeUserSessions(u.name, 'revoked', ctx.sess.s.sid);
  return reply(204);
});

// --- meta ---
route('GET', '/meta/registers', 'viewer', {}, (ctx) => {
  if (ctx.req.headers['if-none-match'] === META_ETAG) return reply(304, undefined, { ETag: META_ETAG, 'Cache-Control': 'no-cache' });
  return reply(200, META_REGISTERS, { ETag: META_ETAG, 'Cache-Control': 'no-cache' });
});
route('GET', '/meta/alarms', 'viewer', {}, (ctx) => {
  const body = CATALOG.map((a) => ({ id: a.id, code: a.code, sev: a.kind === 'SRC_RULE' ? (cfg.alarms.rules.find((r) => `rule_${r.id}` === a.id)?.sev ?? a.sev) : effSev(a.id), ko: a.ko, en: a.en, source: a.source }));
  const etag = `"${createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 8)}"`;
  if (ctx.req.headers['if-none-match'] === etag) return reply(304, undefined, { ETag: etag, 'Cache-Control': 'no-cache' });
  return reply(200, body, { ETag: etag, 'Cache-Control': 'no-cache' });
});

// --- system status ---
route('GET', '/system/info', 'viewer', {}, () => ({
  fw: FW_VERSION, build: '2026-10-19 10:12:03', idf: 'v6.1', mac: 'a0:85:e3:12:34:56', hostname: cfg.network.hostname, uptime_s: uptimeS(),
  time_valid: clock.valid, time_ms: wallMs(),
  heap: { int_free: 98304 + rint(-2048, 2048), int_min: 71680, psram_free: 7340032 + rint(-8192, 8192) },
  part: { running: fw.running.slot, state: fw.running.state },
  diag: { reset_reason: 1, boot_count: 12, evt_dropped: 0, hb_stale: 0, init_faults: 0, ws_clients: Math.min(4, wsClients.size), fs: { total: 10289152, used: 1048576 + logs.system.length * 32 } },
}));
route('GET', '/system/network', 'admin', {}, () => {
  const e = cfg.network.eth;
  return { eth: { link: true, has_ip: true, mode: e.mode, ip: e.ip, mask: e.mask, gw: e.gw, dns1: e.dns1, dns2: e.dns2, mac: 'a0:85:e3:12:34:59', link_changes: 1 },
    ap: { active: false, reason: 'none', clients: 0, ssid: cfg.network.ap.ssid, ip: '', off_in_s: 0 }, provisional: provisionalView(),
    sntp: { enabled: cfg.time.ntp.enabled, synced: cfg.time.ntp.enabled && clock.valid, last_ms: cfg.time.ntp.enabled && clock.valid ? wallMs() - 600000 : null } };
});

// --- devices ---
route('GET', '/devices', 'viewer', {}, () => cfg.modbus.devices.map((c) => {
  const d = devs.get(c.id);
  return { id: c.id, name: c.name, slave: c.slave, enabled: c.enabled, online: !!d?.online, last_ms: d?.snapMono ? toWall(d.snapMono) : null, seq: d?.seq ?? 0 };
}));
route('GET', '/devices/{d}/live', 'viewer', {}, (ctx) => liveView(devOf(ctx.params)));
route('PUT', '/devices/{d}/registers/{addr}', 'operator', { body: 'json', req: 'register-write.request' }, async (ctx) => {
  const d = devOf(ctx.params);
  if (!/^\d{5}$/.test(ctx.params.addr)) throw E(404, 'not_found', 'unknown register', { code: 'unknown_register' });
  const r = await doWrite(d, Number(ctx.params.addr), ctx.body.value ?? null, ctx.body.raw ?? null, ctx.u.name);
  return reply(r.status, r.body);
});
route('POST', '/devices/{d}/run', 'operator', { body: 'json', req: 'device-run.request' }, async (ctx) => {
  const d = devOf(ctx.params);
  const r = await doWrite(d, 40005, null, ctx.body.run ? 1 : 0, ctx.u.name);
  return reply(r.status, r.body);
});
route('GET', '/devices/{d}/commands/{id}', 'operator', {}, (ctx) => {
  const d = devOf(ctx.params);
  const c = commands.find((x) => String(x.cmd) === ctx.params.id && x.dev === d.id);
  if (!c) throw E(404, 'not_found', 'unknown or evicted command');
  return { cmd: c.cmd, dev: c.dev, addr: c.addr, state: c.state, raw: c.raw, requested: c.requested, reason: c.reason, ts: toWall(c.mono) };
});
route('GET', '/devices/{d}/stats', 'viewer', {}, (ctx) => statsView(devOf(ctx.params)));
route('POST', '/devices/{d}/stats/reset', 'admin', {}, (ctx) => {
  const d = devOf(ctx.params);
  Object.assign(d.stats, { tx: 0, rx_ok: 0, crc: 0, timeout: 0, exception: 0, malformed: 0, rtt_sum: 0, rtt_n: 0, rtt_max: 0, offline_count: 0, cycles: 0 });
  audit('stats_reset', ctx.u.name, { dev: d.id });
  return reply(204);
});

// --- history ---
const DTS = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200];
function historyRange(q) {
  const now = monoMs();
  let a, b;
  if (q.has('span')) {
    const span = intQ(q, 'span', 0, 1, 30 * 86400);
    b = Math.floor(now / 1000) * 1000; a = b - span * 1000;
  } else if (q.has('from') && q.has('to')) {
    if (!clock.valid) throw E(400, 'bad_request', 'wall clock is not valid; use span');
    const from = intQ(q, 'from', 0, 0, 4102444800000), to = intQ(q, 'to', 0, 0, 4102444800000);
    if (to <= from || to - from > 30 * 86400000) throw E(400, 'bad_request', 'invalid from/to');
    a = from - clock.offset; b = Math.min(to - clock.offset, now);
    if (b <= a) throw E(400, 'bad_request', 'range is in the future');
    // history is retained for 30 days; older starts would also break t0_age_ms (schema max 31 d)
    if (now - a > 30 * 86400000) throw E(400, 'bad_request', 'from is older than the retained history (30 days)');
  } else throw E(400, 'bad_request', 'span or from/to required');
  const res = intQ(q, 'res', 1, 1, 7200);
  for (const dt of DTS) {
    if (dt < res) continue;
    const dtMs = dt * 1000;
    const a0 = Math.floor(a / dtMs) * dtMs;
    if (dt < 60 && a0 < now - 3600000 - dtMs) continue; // fine steps only within the fast ring (last hour)
    const n = Math.ceil((b - a0) / dtMs);
    if (n <= 1500) return { a: a0, dt, n };
  }
  throw E(400, 'bad_request', 'no resolution fits 1500 points');
}
route('GET', '/devices/{d}/history', 'viewer', {}, (ctx) => {
  const d = devOf(ctx.params);
  const { a, dt, n } = historyRange(ctx.query);
  const stages = ctx.query.get('stages') === '1';
  const q = d.hist.query(a, dt, n, stages);
  return { t0: toWall(a), t0_age_ms: Math.max(0, monoMs() - a), dt, n, ...q };
});
route('GET', '/devices/{d}/history.csv', 'viewer', {}, (ctx) => {
  const d = devOf(ctx.params);
  // firmware rule (API.md §4.6): CSV rows carry ISO 8601 UTC times, so no export without a valid clock
  if (!clock.valid) throw E(400, 'bad_request', 'wall clock not valid: set the time to export CSV');
  const { a, dt, n } = historyRange(ctx.query);
  const q = d.hist.query(a, dt, n, false);
  const f = (v) => (v === null ? '' : (v / 10).toFixed(1));
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const wall0 = toWall(a) ?? a;
  const lines = [dt < 60 ? 'time,temp,hum,current,set_temp,set_hum' : 'time,temp,hum,current,set_temp,set_hum,temp_min,temp_max,hum_min,hum_max,current_min,current_max'];
  for (let i = 0; i < n; i++) {
    const row = [iso(wall0 + i * dt * 1000), f(q.ch.temp[i]), f(q.ch.hum[i]), f(q.ch.cur[i]), f(q.ch.st[i]), f(q.ch.sh[i])];
    if (dt >= 60) row.push(f(q.min.temp[i]), f(q.max.temp[i]), f(q.min.hum[i]), f(q.max.hum[i]), f(q.min.cur[i]), f(q.max.cur[i]));
    lines.push(row.join(','));
  }
  const secs = (ms) => Math.floor(ms / 1000);
  return new RawBody(`\ufeff${lines.join('\r\n')}\r\n`, 'text/csv; charset=utf-8', { 'Content-Disposition': `attachment; filename="mestio-d${d.id}-${secs(wall0)}-${secs(wall0 + n * dt * 1000)}.csv"` });
});

// --- alarms ---
route('GET', '/alarms/active', 'viewer', {}, () => [...activeAlarms.values()]
  .sort((x, y) => y.sev - x.sev || (x.mono - y.mono))
  .map(({ mono, ...a }) => a));
route('POST', '/alarms/ack', 'operator', { body: 'json', req: 'alarms-ack.request' }, (ctx) => {
  const list = ctx.body.all ? [...activeAlarms.values()] : ctx.body.keys.map((k) => activeAlarms.get(k)).filter(Boolean);
  for (const a of list) ackAlarm(a, ctx.u.name);
  audit('alarm_ack_req', ctx.u.name, { value: list.length });
  return reply(204);
});
function alarmItems(q, max) {
  const before = q.has('before') ? intQ(q, 'before', 0, 0, 4294967295) : Infinity;
  const dev = q.has('dev') ? intQ(q, 'dev', 0, 0, 3) : null;
  const sev = q.has('sev') ? intQ(q, 'sev', 0, 0, 3) : 0;
  const out = [];
  for (let i = logs.system.length - 1; i >= 0 && out.length < max + 1; i--) {
    const r = logs.system[i];
    if (!r.type.startsWith('alarm_') || r.seq >= before) continue;
    if (dev !== null && r.dev !== dev) continue;
    if (r.sev < sev) continue;
    const cat = ALM_BY_CODE.get(r.code);
    out.push({ seq: r.seq, ts: toWall(r.mono), dev: r.dev, id: cat.id, code: r.code, type: r.type.slice(6), sev: r.sev, value: r.value, user: r.user });
  }
  return out;
}
route('GET', '/alarms/history', 'viewer', {}, (ctx) => {
  const limit = intQ(ctx.query, 'limit', 50, 1, 200);
  const items = alarmItems(ctx.query, limit);
  const more = items.length > limit;
  if (more) items.length = limit;
  return { items, next: more ? items[items.length - 1].seq : null };
});
route('GET', '/alarms/history.csv', 'viewer', {}, (ctx) => {
  const items = alarmItems(ctx.query, 8192).slice(0, 8192);
  const iso = (ms) => (ms === null ? '' : new Date(ms).toISOString());
  const lines = ['seq,time,dev,id,code,type,sev,value,user', ...items.map((i) => [i.seq, iso(i.ts), i.dev, i.id, i.code, i.type, i.sev, i.value, i.user ?? ''].join(','))];
  return new RawBody(`\ufeff${lines.join('\r\n')}\r\n`, 'text/csv; charset=utf-8', { 'Content-Disposition': 'attachment; filename="mestio-alarms.csv"' });
});

// --- configuration ---
route('GET', '/config/rules', 'viewer', {}, () => clone(cfg.alarms.rules));
// The firmware stores a rule source as a register address and names 40036/40037/40011 back as
// temp/hum/cur (components/store/config_json.c rule_src_addr / its writer); so does the mock.
const SRC_ALIAS = { 'reg:40036': 'temp', 'reg:40037': 'hum', 'reg:40011': 'cur' };
route('PUT', '/config/rules', 'admin', { body: 'json', req: 'config-rules' }, (ctx) => {
  validateRules(ctx.body);
  const rules = clone(ctx.body).map((r) => ({ ...r, src: SRC_ALIAS[r.src] || r.src }));
  commit('alarms', { ...cfg.alarms, rules: rules.sort((a, b) => a.id - b.id) }, ctx.u.name);
  return clone(cfg.alarms.rules);
});
for (const s of ['general', 'modbus', 'time', 'alarms']) {
  route('GET', `/config/${s}`, 'viewer', {}, () => sectionView(s));
  route('PUT', `/config/${s}`, 'admin', { body: 'json', req: `config-${s}.request` }, (ctx) => applySectionPut(s, ctx.body, ctx.u.name, ctx.ip));
}
for (const s of ['snmp', 'security', 'notify']) {
  route('GET', `/config/${s}`, 'admin', {}, () => sectionView(s));
  route('PUT', `/config/${s}`, 'admin', { body: 'json', req: `config-${s}.request` }, (ctx) => applySectionPut(s, ctx.body, ctx.u.name, ctx.ip));
}
route('GET', '/config/network', 'admin', {}, () => sectionView('network'));
route('PUT', '/config/network', 'admin', { body: 'json', req: 'config-network.request' }, (ctx) => {
  if (provisional) throw E(423, 'locked', 'a network change is already pending');
  const { psk, ...apRest } = ctx.body.ap || {};
  const cand = deepMerge(cfg.network, { ...ctx.body, ...(ctx.body.ap ? { ap: apRest } : {}) });
  validateSection('network', cand);
  audit('config_change', ctx.u.name, { code: 1, extra: cfgRev });
  return reply(202, startProvisional(cand, psk, ctx.u.name));
});
route('POST', '/config/network/confirm', 'admin', {}, (ctx) => {
  if (!provisional || provisionalView().state !== 'await_confirm') throw E(409, 'conflict', 'no network change awaiting confirmation');
  const p = provisional; provisional = null;
  if (p.psk) secrets.apPsk = p.psk;
  commit('network', p.cand, ctx.u.name);
  return reply(204);
});
// The real module, generated once (lazily) from the same single sources the firmware build embeds
// (cmake/gw_mib.cmake -> tools/gen_mib.py). Only when Python is unavailable does the mock fall back
// to a stub, and it says so on stderr.
let mibGz = null;
function mibText() {
  const out = join(tmpdir(), `mestio-gw-mib-${process.pid}.txt`);
  for (const py of [process.env.PYTHON, 'python3', 'python'].filter(Boolean)) {
    const r = spawnSync(py, ['-I', join(ROOT, 'tools', 'gen_mib.py'), '--regmap', join(ROOT, 'components/mex150/regmap.def'),
      '--catalog', join(ROOT, 'components/alarm/alarm_catalog.def'), '--pen', '32473', '--out', out], { encoding: 'utf8', timeout: 20000 });
    if (r.status === 0 && existsSync(out)) { const text = readFileSync(out); rmSync(out, { force: true }); return text; }
  }
  console.error('mock: tools/gen_mib.py could not run (no Python?): serving a placeholder MIB');
  return Buffer.from('MESTIO-GW-MIB DEFINITIONS ::= BEGIN\n-- mock server placeholder: tools/gen_mib.py could not run\nEND\n');
}
route('GET', '/snmp/mib', 'viewer', {}, () => {
  if (!mibGz) mibGz = gzipSync(mibText(), { level: 9 });
  return new RawBody(mibGz, 'text/plain; charset=utf-8', { 'Content-Encoding': 'gzip', 'Content-Disposition': 'attachment; filename="MESTIO-GW-MIB.txt"' });
});
route('POST', '/snmp/test-trap', 'admin', {}, async (ctx) => {
  const targets = cfg.snmp.traps.filter((t) => t.enabled);
  if (!cfg.snmp.enabled || !cfg.security.services.snmp || !targets.length) throw E(409, 'conflict', 'SNMP disabled or no enabled trap target');
  await new Promise((r) => setTimeout(r, targets.some((t) => t.inform) ? 400 : 50));
  audit('snmp_test', ctx.u.name, { value: targets.length });
  return { sent: targets.map((t) => ({ host: t.host, ok: t.inform ? rnd() > 0.2 : true })) };
});
route('POST', '/time', 'admin', { body: 'json', req: 'time-set.request' }, (ctx) => {
  clock.offset = ctx.body.epoch_ms - monoMs(); clock.valid = true;
  logAppend('system', 'time_set', { code: 2 });
  audit('time_sync', ctx.u.name, { code: 2 });
  return reply(204);
});

// --- users ---
route('GET', '/users', 'admin', {}, () => [...users.values()].map(userView));
route('POST', '/users', 'admin', { body: 'json', req: 'user-create.request' }, (ctx) => {
  const b = ctx.body;
  if (users.has(b.name)) throw E(409, 'exists', 'user already exists');
  if (users.size >= 4) throw E(409, 'limit', 'at most 4 accounts');
  const rules = policyRules(b.password, b.name);
  if (rules.length) throw E(422, 'policy', 'password does not meet the policy', { field: 'password', rules });
  const u = addUser(b.name, b.role, b.password, b.must_change ?? true, wallMs());
  auditAccount('user_add', ctx.u.name, b.name, { value: ROLE_RANK[b.role] });
  return reply(201, userView(u));
});
route('PUT', '/users/{name}', 'admin', { body: 'json', req: 'user-update.request' }, (ctx) => {
  const u = users.get(ctx.params.name);
  if (!u) throw E(404, 'not_found', 'unknown user');
  const b = ctx.body;
  if (b.role && u.name === ctx.u.name && b.role !== u.role) throw E(409, 'self', 'cannot change your own role');
  if (b.role && u.role === 'admin' && b.role !== 'admin' && [...users.values()].filter((x) => x.role === 'admin').length === 1) throw E(409, 'last_admin', 'last admin');
  if (b.password !== undefined) {
    const rules = policyRules(b.password, u.name);
    if (rules.length) throw E(422, 'policy', 'password does not meet the policy', { field: 'password', rules });
  }
  let revoke = false;
  if (b.role && b.role !== u.role) { u.role = b.role; revoke = true; }
  if (b.password !== undefined) { setPassword(u, b.password); u.changed = wallMs(); revoke = true; u.must_change = b.must_change ?? true; }
  if (b.must_change !== undefined) { if (b.must_change && !u.must_change) revoke = true; u.must_change = b.must_change; }
  if (revoke && u.name !== ctx.u.name) revokeUserSessions(u.name, 'revoked');
  auditAccount('user_mod', ctx.u.name, u.name, { value: ROLE_RANK[u.role] });
  if (b.password !== undefined) auditAccount('password', ctx.u.name, u.name, { extra: 1 });
  return userView(u);
});
route('DELETE', '/users/{name}', 'admin', {}, (ctx) => {
  const u = users.get(ctx.params.name);
  if (!u) throw E(404, 'not_found', 'unknown user');
  if (u.name === ctx.u.name) throw E(409, 'self', 'cannot delete yourself');
  if (u.role === 'admin' && [...users.values()].filter((x) => x.role === 'admin').length === 1) throw E(409, 'last_admin', 'last admin');
  users.delete(u.name);
  revokeUserSessions(u.name, 'revoked');
  auditAccount('user_del', ctx.u.name, u.name);
  return reply(204);
});

// --- firmware / system ---
route('GET', '/system/firmware', 'admin', {}, () => ({ running: clone(fw.running), other: { slot: fw.other.slot, version: fw.other.version, valid: fw.other.valid } }));
function parseVersion(v) { return (v.match(/\d+/g) || []).slice(0, 3).map(Number); }
function cmpVersion(a, b) { const x = parseVersion(a), y = parseVersion(b); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); } return 0; }
route('POST', '/system/firmware', 'admin', { body: 'firmware' }, (ctx) => {
  const sha = String(ctx.req.headers['x-firmware-sha256'] || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) throw E(400, 'bad_request', 'X-Firmware-SHA256 header required');
  if (fw.uploading) throw E(423, 'locked', 'upload in progress');
  const img = ctx.raw;
  if (createHash('sha256').update(img).digest('hex') !== sha) { audit('ota_upload', ctx.u.name, { code: 1 }); throw E(422, 'hash_mismatch', 'SHA-256 mismatch'); }
  // ESP image: magic 0xE9; esp_app_desc_t at 32: magic 0xABCD5432, version[32] at +16, project_name[32] at +48.
  const cstr = (o) => { const s = img.subarray(o, o + 32); const z = s.indexOf(0); return s.subarray(0, z < 0 ? 32 : z).toString('latin1'); };
  if (img.length < 288 || img[0] !== 0xe9 || img.readUInt32LE(32) !== 0xabcd5432) throw E(422, 'image_invalid', 'not an ESP application image');
  if (cstr(80) !== 'mestio_gw') throw E(422, 'image_invalid', 'not a mestio_gw image');
  const version = cstr(48).slice(0, 31);
  if (cmpVersion(version, fw.running.version) < 0 && ctx.query.get('allow_downgrade') !== '1') throw E(422, 'image_invalid', 'downgrade refused');
  audit('ota_upload', ctx.u.name, { code: 0 });
  scheduleReboot(1, 2000, () => {
    const prev = fw.running;
    fw.running = { slot: fw.other.slot, version, state: 'pending_verify' };
    fw.other = { slot: prev.slot, version: prev.version, valid: true };
    setTimeout(() => { if (fw.running.state === 'pending_verify') fw.running.state = 'valid'; }, 60000);
  });
  return { version, reboot_in_s: 2 };
});
route('POST', '/system/firmware/rollback', 'admin', {}, (ctx) => {
  if (!fw.other.valid || !fw.other.version) throw E(404, 'not_found', 'no valid image in the other slot');
  audit('rollback', ctx.u.name);
  scheduleReboot(2, 2000, () => {
    const prev = fw.running;
    fw.running = { slot: fw.other.slot, version: fw.other.version, state: 'valid' };
    fw.other = { slot: prev.slot, version: prev.version, valid: true };
  });
  return reply(202, { reboot_in_s: 2 });
});
route('GET', '/system/config/export', 'admin', {}, () => reply(200, bundle(), { 'Content-Disposition': `attachment; filename="mestio-gw-config-${cfg.network.hostname}-${cfgRev}.json"` }));
route('POST', '/system/config/import', 'admin', { body: 'import' }, (ctx) => {
  const b = ctx.body;
  if (b === null || typeof b !== 'object' || Array.isArray(b)) throw E(400, 'invalid_json', 'bundle must be an object');
  if (Number.isInteger(b.schema) && b.schema > 1) throw E(422, 'validation', 'bundle schema is newer than this firmware', { field: 'schema', code: 'unsupported_schema' });
  schemaCheck('config-bundle', b);
  const includeNet = ctx.query.get('include_network') === '1';
  const next = {};
  for (const s of SECTIONS) {
    if (s === 'network' || b[s] === undefined) continue;
    next[s] = deepMerge(defaultConfig()[s], b[s]);
    if (s === 'alarms') validateRules(next.alarms.rules);
    else if (s !== 'snmp') validateSection(s, next[s], ctx.ip);
  }
  if (next.snmp && (next.snmp.v1 || next.snmp.v2c) && !secrets.ro) throw E(422, 'validation', 'no read community stored', { field: 'snmp.ro', code: 'required' });
  if (includeNet && b.network) { if (provisional) throw E(423, 'locked', 'a network change is already pending'); validateSection('network', deepMerge(cfg.network, b.network)); }
  const changed = [];
  for (const [s, v] of Object.entries(next)) {
    if (JSON.stringify(v) === JSON.stringify(cfg[s])) continue;
    if (s === 'snmp') {
      secrets.traps = v.traps.map((t) => { const i = cfg.snmp.traps.findIndex((o) => o.host === t.host && o.port === t.port); return i >= 0 ? secrets.traps[i] : null; });
    }
    cfg[s] = v; changed.push(s);
  }
  if (changed.length) { cfgRev++; if (changed.includes('modbus')) { syncDevices(); restartPolling(); } }
  let network = null;
  if (includeNet && b.network) { network = startProvisional(deepMerge(cfg.network, b.network), undefined, ctx.u.name); changed.push('network'); }
  audit('config_import', ctx.u.name, { extra: cfgRev });
  return { rev: cfgRev, changed, network };
});
route('POST', '/system/reboot', 'admin', {}, (ctx) => { audit('reboot_req', ctx.u.name, { code: 0 }); scheduleReboot(0, 2000); return reply(202, { reboot_in_s: 2 }); });
route('POST', '/system/factory-reset', 'admin', { body: 'json', req: 'factory-reset.request' }, (ctx) => {
  const wait = rlCheck(ctx.ip);
  if (wait) throw E(429, 'rate_limited', 'too many failed attempts', { retry_after: wait });
  if (!checkPassword(ctx.u, ctx.body.password)) {
    const locked = rlFail(ctx.ip, ctx.u.name);
    if (locked) throw lockedErr(locked);
    throw E(422, 'wrong_password', 'password is wrong', { field: 'password' });
  }
  audit('factory_reset', ctx.u.name, { value: ctx.body.keep_network ? 1 : 0 });
  const keepNet = !!ctx.body.keep_network;
  scheduleReboot(3, 2000, () => {
    const net = cfg.network;
    cfg = defaultConfig(); if (keepNet) cfg.network = net;
    Object.assign(secrets, { ro: '', rw: '', v3: [{ auth: null, priv: null }, { auth: null, priv: null }], traps: [] });
    if (!keepNet) { logs.system.length = 0; logs.audit.length = 0; }
    cfgRev = 1; resetUsers(); activeAlarms.clear(); syncDevices(); restartPolling();
  });
  return reply(202, { reboot_in_s: 2 });
});
route('GET', '/system/logs', 'admin', {}, (ctx) => {
  const q = ctx.query;
  const kind = q.get('kind') || 'system';
  if (kind !== 'audit' && kind !== 'system') throw E(400, 'bad_request', 'kind must be audit or system');
  const limit = intQ(q, 'limit', 50, 1, 200);
  const before = q.has('before') ? intQ(q, 'before', 0, 0, 4294967295) : Infinity;
  const list = logs[kind];
  const items = [];
  for (let i = list.length - 1; i >= 0 && items.length < limit + 1; i--) {
    const r = list[i];
    if (r.seq >= before) continue;
    items.push({ seq: r.seq, ts: toWall(r.mono), type: r.type, dev: r.dev, code: r.code, sev: r.sev, value: r.value, user: r.user, extra: r.extra });
  }
  const more = items.length > limit;
  if (more) items.length = limit;
  return { kind, items, next: more ? items[items.length - 1].seq : null };
});
route('GET', '/system/coredump', 'admin', {}, () => {
  if (!OPT.coredump) throw E(404, 'not_found', 'no core dump stored');
  return { task: 'httpd', pc: 1074590724, cause: 29, vaddr: 0, backtrace: [1074590724, 1074601234, 1074612345], backtrace_corrupted: false, app_sha256: '3f9a1c0d2' };
});

// ------------------------------------------------------------------------------------------------
// HTTP dispatch
// ------------------------------------------------------------------------------------------------
async function handleApi(req, res, url) {
  const path = url.pathname.slice(API.length) || '/';
  let r = null; let rawParams = [];
  for (const x of R) {
    const m = x.re.exec(path);
    if (m && x.m === req.method) { r = x; rawParams = m.slice(1); break; }
  }
  if (!r) throw E(404, 'not_found', 'no such route');
  const ctx = { req, res, params: {}, query: url.searchParams, ip: clientIp(req) };
  if (r.role !== 'none') {
    const ss = lookupSession(req);
    if (!ss) throw E(401, 'unauthorized', 'login required');
    ctx.sess = ss; ctx.u = ss.u;
    if (r.role !== 'cookie' && ROLE_RANK[ss.u.role] < ROLE_RANK[r.role]) throw E(403, 'forbidden', 'insufficient role');
    const allowedWhileMustChange = r.p === '/auth/password' || r.p === '/auth/logout';
    if (ss.u.must_change && !allowedWhileMustChange) throw E(403, 'password_change_required', 'change your password first');
    if (req.method !== 'GET' && !originOk(req)) throw E(403, 'origin', 'Origin/Referer does not match Host');
    if (r.csrf) {
      const t = String(req.headers['x-csrf-token'] || '');
      const ok = t.length === ss.s.csrf.length && timingSafeEqual(Buffer.from(t), Buffer.from(ss.s.csrf));
      if (!ok) throw E(403, 'csrf', 'missing or wrong CSRF token');
    }
    ss.s.last = monoMs(); // authenticated REST request refreshes the idle timer
  }
  if (r.role === 'none' && req.method !== 'GET' && !originOk(req)) throw E(403, 'origin', 'Origin/Referer does not match Host');
  // path parameters are decoded after authentication; a malformed %-escape is a 400, not a 500
  try {
    ctx.params = Object.fromEntries(r.names.map((n, i) => [n, decodeURIComponent(rawParams[i])]));
  } catch { throw E(400, 'bad_request', 'malformed path'); }
  const raw = await readBody(req, LIMITS[r.body]);
  if (r.body === 'none' && raw.length) throw E(413, 'payload_too_large', 'this route takes no body');
  if (r.body === 'firmware') {
    if (!/^application\/octet-stream\b/i.test(req.headers['content-type'] || '')) throw E(400, 'bad_request', 'application/octet-stream required');
    if (!req.headers['content-length']) throw E(400, 'bad_request', 'Content-Length required');
    ctx.raw = raw;
  } else if (r.body !== 'none') {
    if (raw.length && !/^application\/json\b/i.test(req.headers['content-type'] || '')) throw E(400, 'bad_request', 'application/json required');
    try { ctx.body = JSON.parse(raw.toString('utf8')); } catch { throw E(400, 'invalid_json', 'body is not valid JSON'); }
    if (r.req) {
      const want = r.req === 'config-rules' ? 'array' : 'object';
      if ((want === 'array') !== Array.isArray(ctx.body) || ctx.body === null || typeof ctx.body !== 'object') throw E(400, 'invalid_json', `body must be a JSON ${want}`);
      schemaCheck(r.req, ctx.body);
    }
  }
  const out = await r.h(ctx);
  const extra = ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {};
  if (out instanceof RawBody) {
    res.writeHead(200, baseHeaders({ 'Cache-Control': 'no-store', 'Content-Type': out.type, ...out.headers, ...extra }));
    res.end(out.body);
  } else if (out instanceof Reply) {
    if (out.status === 304) { res.writeHead(304, baseHeaders(out.headers)); res.end(); return; }
    sendJson(res, out.status, out.status === 204 ? undefined : out.body, { ...extra, ...out.headers });
  } else sendJson(res, 200, out, extra);
}

// ------------------------------------------------------------------------------------------------
// Static files: web/dist (manifest) or unbundled sources (--dev)
// ------------------------------------------------------------------------------------------------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' };
let devTools = null;
async function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { sendJson(res, 404, { error: 'not_found', message: 'no such route' }); return; }
  const p = url.pathname;
  if (OPT.dev) {
    devTools ||= await import('./build_web.mjs');
    let body; let type;
    if (p === '/') { body = devTools.renderIndexDev(); type = MIME['.html']; }
    else if (p === '/favicon.svg') { body = devTools.faviconSvg(); type = MIME['.svg']; }
    else {
      const rel = normalize(p).replace(/^[/\\]+/, '');
      const file = join(ROOT, 'web', rel);
      if (!(rel.startsWith(`src${sep}`) || rel.startsWith(`styles${sep}`)) || !file.startsWith(join(ROOT, 'web') + sep) || !existsSync(file) || !statSync(file).isFile()) {
        res.writeHead(404, baseHeaders({ 'Content-Type': 'text/plain' })); res.end('not found'); return;
      }
      body = readFileSync(file); type = MIME[extname(file)] || 'application/octet-stream';
    }
    res.writeHead(200, baseHeaders({ 'Content-Type': type, 'Cache-Control': 'no-cache' }));
    res.end(req.method === 'HEAD' ? undefined : body);
    return;
  }
  const dist = join(ROOT, 'web', 'dist');
  const manPath = join(dist, 'manifest.json');
  if (!existsSync(manPath)) { res.writeHead(503, baseHeaders({ 'Content-Type': 'text/plain' })); res.end('web/dist missing: run `npm run build:web` or use --dev'); return; }
  const man = JSON.parse(readFileSync(manPath, 'utf8'));
  const a = man.assets.find((x) => x.path === p);
  if (!a) { res.writeHead(404, baseHeaders({ 'Content-Type': 'text/plain' })); res.end('not found'); return; }
  if (req.headers['if-none-match'] === a.etag) { res.writeHead(304, baseHeaders({ ETag: a.etag })); res.end(); return; }
  const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  const body = readFileSync(join(dist, gz ? a.gz : a.file));
  res.writeHead(200, baseHeaders({ 'Content-Type': a.mime, ETag: a.etag, ...(gz ? { 'Content-Encoding': 'gzip' } : {}),
    'Cache-Control': a.immutable ? 'public, max-age=31536000, immutable' : 'no-cache', Vary: 'Accept-Encoding' }));
  res.end(req.method === 'HEAD' ? undefined : body);
}

// ------------------------------------------------------------------------------------------------
// Proxy to a real gateway (--proxy)
// ------------------------------------------------------------------------------------------------
/**
 * Host names under which this developer proxy may be addressed. Deliberately narrower than the
 * device list of hostAllowed(): a page that rebinds its own name to 127.0.0.1 must not reach the
 * device's API through the proxy (DNS rebinding).
 */
function proxyHostAllowed(hostHeader) {
  if (!hostHeader) return false;
  const h = hostHeader.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  return ['localhost', '127.0.0.1', '::1', OPT.host.toLowerCase()].includes(h);
}
/**
 * Upstream headers. Origin/Referer are rewritten to the device's origin only when they name this
 * proxy's own origin (the UI served from here); any other origin is forwarded unchanged so the
 * firmware's Origin check still rejects cross-site requests.
 */
function proxyHeaders(req) {
  const h = { ...req.headers, host: OPT.proxy.host };
  const self = `http://${String(req.headers.host).toLowerCase()}`;
  const dev = `${OPT.proxy.protocol}//${OPT.proxy.host}`;
  if (h.origin && h.origin.toLowerCase() === self) h.origin = dev;
  if (h.referer && (h.referer.toLowerCase() === self || h.referer.toLowerCase().startsWith(`${self}/`))) h.referer = dev + h.referer.slice(self.length);
  return h;
}
function proxyHttp(req, res) {
  const up = http.request({ hostname: OPT.proxy.hostname, port: OPT.proxy.port || 80, method: req.method, path: req.url, headers: proxyHeaders(req) }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  up.on('error', (e) => { if (!res.headersSent) sendJson(res, 502, { error: 'unavailable', message: `proxy: ${e.message}` }); else res.destroy(); });
  req.pipe(up);
}
function proxyUpgrade(req, socket, head) {
  const up = http.request({ hostname: OPT.proxy.hostname, port: OPT.proxy.port || 80, method: 'GET', path: req.url, headers: proxyHeaders(req) });
  up.on('upgrade', (r, upSock, upHead) => {
    socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
    if (upHead.length) socket.write(upHead);
    if (head.length) upSock.write(head);
    upSock.pipe(socket); socket.pipe(upSock);
    upSock.on('error', () => socket.destroy()); socket.on('error', () => upSock.destroy());
  });
  up.on('response', (r) => { socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); });
  up.on('error', () => socket.destroy());
  up.end();
}

// ------------------------------------------------------------------------------------------------
// WebSocket hub
// ------------------------------------------------------------------------------------------------
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 });
const wsClients = new Set();
function send(ws, obj) { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); }
function closeWsSession(sid, reason) {
  for (const ws of wsClients) if (ws.gw.sid === sid) { send(ws, { t: 'bye', reason }); ws.close(1000, reason); }
}
function broadcast(topic, frame) {
  for (const ws of wsClients) if (ws.gw.topics.has(topic)) send(ws, frame);
}
function broadcastSnap(d) {
  const now = monoMs();
  for (const ws of wsClients) {
    if (!ws.gw.topics.has('snap')) continue;
    const st = ws.gw.snap.get(d.id) || { lastFull: 0, regs: null, coils: null };
    const full = !st.regs || now - st.lastFull >= 30000;
    const r = {};
    for (const reg of REGS) {
      if (SLOW_ADDRS.has(reg.addr) && !d.slowValid) continue;
      const v = d.snapRegs.get(reg.addr) ?? 0;
      if (full || st.regs.get(reg.addr) !== v) r[String(reg.addr)] = v;
    }
    const f = { t: 'snap', dev: d.id, seq: d.seq, ts: toWall(d.snapMono), on: d.online, full, r };
    if (full || st.coils !== d.snapCoils) f.c = d.snapCoils;
    if (full) st.lastFull = now;
    st.regs = new Map(d.snapRegs); st.coils = d.snapCoils;
    ws.gw.snap.set(d.id, st);
    send(ws, f);
  }
}
function rejectUpgrade(socket, status, text) {
  socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}
function onUpgrade(req, socket, head) {
  const url = new URL(req.url, 'http://x');
  if (OPT.proxy) {
    if (!proxyHostAllowed(req.headers.host)) { rejectUpgrade(socket, 421, 'Misdirected Request'); return; }
    if (url.pathname === '/ws') { proxyUpgrade(req, socket, head); return; }
  }
  if (monoMs() < rebootUntil) { socket.destroy(); return; }
  if (url.pathname !== '/ws') { rejectUpgrade(socket, 404, 'Not Found'); return; }
  if (!hostAllowed(req.headers.host)) { rejectUpgrade(socket, 421, 'Misdirected Request'); return; }
  const ss = lookupSession(req);
  if (!ss) { rejectUpgrade(socket, 401, 'Unauthorized'); return; }
  if (ss.u.must_change) { rejectUpgrade(socket, 403, 'Forbidden'); return; }
  if (req.headers.origin && !originOk(req)) { rejectUpgrade(socket, 403, 'Forbidden'); return; }
  if (wsClients.size >= 4) { rejectUpgrade(socket, 503, 'Service Unavailable'); return; }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.gw = { sid: ss.s.sid, topics: new Set(), snap: new Map() };
    wsClients.add(ws);
    ws.on('close', () => wsClients.delete(ws));
    ws.on('error', () => wsClients.delete(ws));
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      let m; try { m = JSON.parse(data.toString('utf8')); } catch { return; }
      if (!m || typeof m !== 'object') return;
      if (m.t === 'ping') send(ws, { t: 'pong', srv: wallMs() });
      else if (m.t === 'sub' && Array.isArray(m.topics)) {
        ws.gw.topics = new Set(m.topics.filter((x) => ['snap', 'alarm', 'comm', 'write', 'sys'].includes(x)));
        ws.gw.snap.clear();
        if (ws.gw.topics.has('comm')) for (const id of enabledDevs()) { const d = devs.get(id); if (d) send(ws, commFrame(d)); }
      }
    });
    const seq = {};
    for (const id of enabledDevs()) seq[String(id)] = devs.get(id)?.seq ?? 0;
    send(ws, { t: 'hello', v: 1, srv: wallMs(), devs: enabledDevs(), seq, meta: META_ETAG });
  });
}

// ------------------------------------------------------------------------------------------------
// Timers
// ------------------------------------------------------------------------------------------------
let pollTimer = null;
function restartPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(() => { for (const id of enabledDevs()) { const d = devs.get(id); if (d) pollCycle(d); } }, cfg.modbus.poll_ms);
}
let tickN = 0;
function tick() {
  tickN++;
  const now = monoMs();
  for (const d of devs.values()) {
    const en = devCfg(d.id)?.enabled;
    d.sim.step(1, tod(now));
    // Random equipment faults
    if (OPT.faults && en) {
      if (rnd() < 1 / 1500) d.sim.faults.set(FAULT_COILS[rint(0, FAULT_COILS.length - 1)], rint(40, 240));
      if (rnd() < 1 / 20000) d.sim.faults.set(23, rint(30, 90)); // leak
      if (rnd() < 1 / 8000) d.sim.contam = !d.sim.contam;
    }
    // Comm loss episodes
    if (OPT.commLoss && en && d.commLossLeft === 0 && now >= d.nextCommLoss) { d.commLossLeft = rint(15, 50); d.nextCommLoss = now + rint(20, 40) * 60000; }
    if (d.commLossLeft > 0) d.commLossLeft--;
    // 1 Hz history sample from the latest snapshot (hold); offline/stale -> gap
    if (en) {
      const t = Math.floor(now / 1000) * 1000;
      if (t > d.lastSample) {
        d.hist.sampleFast(t, isFresh(d) ? { temp: d.snapRegs.get(40036), hum: d.snapRegs.get(40037), cur: d.snapRegs.get(40011), st: d.snapRegs.get(40012), sh: d.snapRegs.get(40013), coils: d.snapCoils } : null);
        d.lastSample = t;
      }
    }
    if (en && tickN % 5 === 0) broadcast('comm', commFrame(d));
  }
  evalRules();
  expireSessions();
  tickProvisional();
  if (tickN % 10 === 0) broadcast('sys', { t: 'sys', heap: 98304 + rint(-2048, 2048), heap_min: 71680, psram: 7340032, up: uptimeS(), time: wallMs(), alarms: Math.min(200, activeAlarms.size) });
}

// ------------------------------------------------------------------------------------------------
// Seed logs so pages are not empty, then start
// ------------------------------------------------------------------------------------------------
function seedLogs() {
  const now = monoMs();
  logAppend('system', 'boot', { mono: now - 3 * 86400000 });
  audit('login_ok', 'admin', { extra: ip2u32('192.168.10.20'), mono: now - 3 * 86400000 + 60000 });
  audit('config_change', 'admin', { code: 2, value: 2, mono: now - 3 * 86400000 + 120000 });
  const seq = [['high_temp', 312, 2 * 86400000], ['drain_fault', 1, 30 * 3600000], ['comm_lost', 1, 20 * 3600000], ['rule_1', 281, 5 * 3600000]];
  for (const [id, value, ago] of seq) {
    const cat = ALM_BY_ID.get(id);
    logAppend('system', 'alarm_raise', { dev: 0, code: cat.code, sev: cat.sev, value, mono: now - ago });
    logAppend('system', 'alarm_ack', { dev: 0, code: cat.code, sev: cat.sev, value, user: 'admin', mono: now - ago + 240000 });
    logAppend('system', 'alarm_clear', { dev: 0, code: cat.code, sev: cat.sev, value, mono: now - ago + 900000 });
  }
  logAppend('system', 'boot', { mono: now });
}

seedLogs();
syncDevices();
restartPolling();
setInterval(tick, 1000);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (monoMs() < rebootUntil && !OPT.proxy) { req.socket.destroy(); return; }
  const isApi = url.pathname === API || url.pathname.startsWith(`${API}/`);
  if (url.pathname.startsWith('/__mock/')) { mockHook(req, res, url).catch((e) => sendJson(res, 500, { error: 'internal', message: e.message })); return; }
  // Host check first in every mode: in --proxy mode it is the only DNS-rebinding guard in front of
  // the real device, because the forwarded Host names the device itself.
  if (!(OPT.proxy ? proxyHostAllowed : hostAllowed)(req.headers.host)) { sendJson(res, 421, { error: 'misdirected', message: 'Host does not name this device' }); return; }
  if (OPT.proxy && isApi) { proxyHttp(req, res); return; }
  const work = isApi ? handleApi(req, res, url) : serveStatic(req, res, url);
  work.catch((e) => {
    if (e instanceof HttpError) {
      if (!res.headersSent) sendJson(res, e.status, e.body);
      // drain whatever is left of a rejected body so keep-alive stays usable
      req.resume();
    } else {
      console.error(e);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal', message: 'unexpected mock error' });
    }
  });
});
server.on('upgrade', onUpgrade);

/** Mock-only control hooks for tests (loopback only). */
async function mockHook(req, res, url) {
  const ip = clientIp(req);
  if (ip !== '127.0.0.1' && ip !== '::1') { sendJson(res, 404, { error: 'not_found', message: 'no such route' }); return; }
  const raw = await readBody(req, 4096);
  const b = raw.length ? JSON.parse(raw.toString('utf8')) : {};
  const d = devs.get(b.dev ?? 0);
  switch (url.pathname) {
    case '/__mock/comm': d.forcedOffline = !b.online; if (b.online) d.commLossLeft = 0; break;
    case '/__mock/fault': if (b.on) d.sim.faults.set(b.coil, Infinity); else d.sim.faults.delete(b.coil); d.sim.updateDerivedRegs(); break;
    case '/__mock/expire': for (const s of sessions.values()) s.last = 0; expireSessions(); break;
    case '/__mock/state': sendJson(res, 200, { sessions: sessions.size, ws: wsClients.size, alarms: [...activeAlarms.keys()], provisional: provisionalView(), clock }); return;
    default: sendJson(res, 404, { error: 'not_found', message: 'no such hook' }); return;
  }
  sendJson(res, 204);
}

server.listen(OPT.port, OPT.host, () => {
  const { port } = server.address();
  const mode = OPT.proxy ? `proxy -> ${OPT.proxy.origin}` : OPT.dev ? 'dev (web/ sources)' : 'dist (web/dist)';
  console.log(`mock gateway listening on http://${OPT.host}:${port}  [${mode}]  seed=${OPT.seed}${OPT.ready ? '  admin/Mestio-Admin#2026' : '  admin/mestio150! (must change)'}`);
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.close(); process.exit(0); });
