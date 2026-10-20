// Application orchestration: boot → session → (login | forced password change | app), data loading,
// WebSocket wiring (hello → history backfill, snap delta merge, alarms, comm, sys, write, bye),
// REST polling fallback while the socket is down, theme and language.
import { h, clear, storage } from './dom.js';
import { t, setLang, onLang, initialLang, lang } from './i18n/index.js';
import * as api from './api.js';
import { state, emit, set, resetData, updateDevices, live as liveOf } from './store.js';
import { applySnap, applyAlarm, sortAlarms, fromRest } from './live.js';
import { DevSeries } from './series.js';
import { LiveSocket } from './ws.js';
import { refreshPalette } from './chart/timeseries.js';
import { renderLogin, renderPasswordChange } from './views/login.js';
import { buildShell } from './shell.js';
import { loadAlarmMeta } from './meta.js';
import { startRouter, stopRouter } from './router.js';
import { setTimeZone } from './time_zone.js';
import { toast } from './ui.js';

const root = document.getElementById('app');
let sock = null;
let fallbackTimer = 0;
let downSince = 0;
let tickTimer = 0;
let loginPass = null; // password typed at sign-in, kept only until the forced change completes
let metaEtag = null;
let shell = null;

// ---------------------------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------------------------
const mq = window.matchMedia('(prefers-color-scheme: dark)');
const storedTheme = () => { const v = storage.get('gw.theme'); return v === 'light' || v === 'dark' ? v : null; };
export const effectiveTheme = () => document.documentElement.dataset.theme || (mq.matches ? 'dark' : 'light');
export const themeFollowsSystem = () => storedTheme() === null;
function applyTheme() {
  document.documentElement.dataset.theme = storedTheme() || (mq.matches ? 'dark' : 'light');
}
/** Set 'light' | 'dark', or null to follow the operating system. */
export function setTheme(th) {
  storage.set('gw.theme', th || null);
  applyTheme();
  refreshPalette();
  emit('theme', effectiveTheme());
}
mq.addEventListener('change', () => { if (themeFollowsSystem()) { applyTheme(); refreshPalette(); emit('theme', effectiveTheme()); } });

// ---------------------------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------------------------
export async function boot() {
  applyTheme();
  setLang(initialLang(storage.get('gw.lang'), navigator.languages));
  document.documentElement.lang = lang();
  onLang((l) => {
    document.documentElement.lang = l;
    if (quietLang) return;
    storage.set('gw.lang', l); // an explicit choice in this browser wins over the site default
    rerender();
  });
  api.setHandlers({ authLost: (why) => sessionLost(why === 'expired' ? 'login.expired' : null), mustChange: () => checkSession() });
  await checkSession();
}

let view = null; // 'login' | 'pw' | 'app'
let quietLang = false;
function rerender() {
  if (view === 'app') mountApp();
  else if (view === 'pw') showPasswordChange();
  else showLogin(null);
}

async function checkSession() {
  let s;
  try {
    const r = await api.get('/session', null, { ok: [401] });
    s = r.status === 200 ? r.body : null;
  } catch (e) {
    showLogin(null);
    if (e instanceof api.ApiError && e.status === 0) toast(t('err.network'), 'alarm');
    return;
  }
  if (!s) { showLogin(null); return; }
  api.setCsrf(s.csrf);
  set('session', s);
  if (s.must_change) showPasswordChange();
  else startApp();
}

function showLogin(notice) {
  stopApp();
  view = 'login';
  set('session', null);
  api.setCsrf(null);
  renderLogin(root, (s, pass) => {
    set('session', s);
    if (s.must_change) {
      loginPass = pass;
      showPasswordChange();
    } else startApp();
  }, notice);
  document.title = 'MESTIO';
}

function showPasswordChange() {
  stopApp();
  view = 'pw';
  renderPasswordChange(root, state.session, loginPass, () => {
    loginPass = null;
    toast(t('pw.changed'));
    checkSession();
  }, logout);
}

let lostOnce = false;
export function sessionLost(notice) {
  if (view !== 'app' || lostOnce) return;
  lostOnce = true;
  showLogin(notice || 'login.expired');
}

export async function logout() {
  try { await api.post('/auth/logout'); } catch { /* the session may already be gone */ }
  loginPass = null;
  showLogin(null);
}

// ---------------------------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------------------------
async function loadMeta() {
  const res = await api.req('GET', '/meta/registers', { raw: true });
  if (!res.ok) throw new api.ApiError(res.status, null);
  metaEtag = res.headers.get('ETag');
  const meta = await res.json();
  state.regs = new Map(meta.regs.map((r) => [r.addr, r]));
  set('meta', meta);
}

async function loadDevices() {
  const devs = await api.get('/devices');
  updateDevices(devs);
}


async function startApp() {
  view = 'app';
  lostOnce = false;
  root.replaceChildren(h('div.login', h('p.muted', { text: t('loading') })));
  try {
    const [, , , alarms, general, modbus, templates, time, info] = await Promise.all([
      loadMeta(), loadAlarmMeta(), loadDevices(), api.get('/alarms/active'), api.get('/config/general'),
      api.get('/config/modbus').catch(() => null), api.get('/meta/device-templates'), api.get('/config/time'), api.get('/system/info'), // poll_ms → freshness window (live.js staleAfterMs)
    ]);
    state.templates = templates;
    state.timeConfig = time;
    setTimeZone(time.tz);
    state.info = info;
    state.srvValid = info.time_valid && info.time_ms !== null;
    state.srvOffset = state.srvValid ? info.time_ms - Date.now() : 0;
    state.alarms = sortAlarms(alarms);
    state.general = general;
    if (modbus) state.pollMs = modbus.poll_ms;
    // site default language (config/general) applies unless this browser has an explicit choice
    if (storage.get('gw.lang') === null && general.lang && general.lang !== lang()) {
      quietLang = true;
      setLang(general.lang);
      quietLang = false;
    }
    const stored = storage.get('gw.dev');
    if (stored !== null && state.devices.some((d) => String(d.id) === stored && d.enabled)) state.dev = Number(stored);
  } catch (e) {
    if (e instanceof api.ApiError && (e.status === 401 || e.status === 403)) return; // handlers switch views
    root.replaceChildren(h('div.login', h('div.login-box',
      h('h1', { text: t('err.load_title') }), h('p.muted', { text: api.errText(e) }),
      h('button.btn.primary', { type: 'button', text: t('retry'), on: { click: startApp } }))));
    return;
  }
  // site name fallback (hostname) and the init-fault latch (storage failure banner)
  api.get('/system/info').then((i) => { set('info', i); }).catch(() => {});
  mountApp();
  startLive();
}

function mountApp() {
  stopRouter();
  if (shell) shell.dispose();
  shell = buildShell({ logout, setTheme, effectiveTheme, themeFollowsSystem });
  root.replaceChildren(shell.el);
  startRouter(shell.outlet);
  document.title = `${state.general?.site || 'MESTIO'} · MESTIO`;
}

function stopApp() {
  stopRouter();
  if (shell) { shell.dispose(); shell = null; }
  if (sock) { sock.stop(); sock = null; }
  clearInterval(fallbackTimer);
  fallbackTimer = 0;
  clearInterval(tickTimer);
  tickTimer = 0;
  resetData();
  view = null;
  clear(root);
}

// ---------------------------------------------------------------------------------------------
// Live data
// ---------------------------------------------------------------------------------------------
function series(d) {
  let s = state.series.get(d);
  if (!s) { s = new DevSeries(); state.series.set(d, s); }
  return s;
}

async function backfill(d) {
  const s = series(d);
  s.beginBackfill();
  try {
    const hres = await api.get(`/devices/${d}/history`, { span: 3600, res: 1, stages: 1 });
    s.backfill(hres, Date.now());
  } catch {
    s.abortBackfill();
  }
  emit(`series:${d}`);
}

function onMessage(m) {
  const now = Date.now();
  switch (m.t) {
    case 'hello': {
      set('srvValid', m.srv !== null);
      if (m.srv !== null) state.srvOffset = m.srv - now;
      if (metaEtag && m.meta && m.meta !== metaEtag) loadMeta().catch(() => {});
      const known = state.devices.filter((x) => x.enabled).map((x) => x.id).join(',');
      if (known !== m.devs.join(',')) loadDevices().catch(() => {});
      for (const d of m.devs) backfill(d);
      break;
    }
    case 'snap': {
      const r = applySnap(state.live.get(m.dev), m, now);
      if (!r.applied) break;
      state.live.set(m.dev, r.state);
      series(m.dev).add(now, r.state);
      emit(`live:${m.dev}`, r);
      emit(`series:${m.dev}`);
      break;
    }
    case 'alarm':
      state.alarms = applyAlarm(state.alarms, m);
      emit('alarms', m);
      break;
    case 'comm': {
      const prev = state.comm.get(m.dev);
      const rtts = prev ? prev.rtts : [];
      if (m.online) { rtts.push(m.rtt); if (rtts.length > 60) rtts.shift(); }
      state.comm.set(m.dev, { online: m.online, rtt: m.rtt, err: m.err, rtts });
      if (!m.online) {
        const lv = state.live.get(m.dev);
        if (lv && lv.on) { state.live.set(m.dev, { ...lv, on: false, ready: false }); emit(`live:${m.dev}`, { changed: [] }); }
        series(m.dev).add(now, null);
        emit(`series:${m.dev}`);
      }
      emit(`comm:${m.dev}`, m);
      break;
    }
    case 'sys':
      if (m.time !== null) { state.srvOffset = m.time - now; state.srvValid = true; }
      set('sys', m);
      break;
    case 'pong':
      if (m.srv !== null) { state.srvOffset = m.srv - m.rx; state.srvValid = true; }
      break;
    case 'write':
      emit('write', m);
      break;
    case 'bye':
      if (m.reason === 'reboot') {
        toast(t('sys.rebooting'), 'warn', 8000);
        setTimeout(() => { if (sock) { sock.stopped = false; sock.connectNow(); } }, 4000);
      } else sessionLost(m.reason === 'logout' ? null : 'login.expired');
      break;
    default:
      break; // unknown types are ignored (API.md §5.2)
  }
}

function startLive() {
  if (sock) sock.stop();
  let firstOpen = true; // startApp() fetched /alarms/active just before this first connection
  sock = new LiveSocket({
    message: onMessage,
    status: (st) => {
      if (st === 'open') downSince = 0;
      else if (!downSince) downSince = Date.now();
      set('ws', st);
    },
    opened: () => {
      clearInterval(fallbackTimer);
      fallbackTimer = 0;
      // re-sync the alarm list after a gap (frames may have been missed)
      if (firstOpen) { firstOpen = false; return; }
      api.get('/alarms/active').then((a) => { state.alarms = sortAlarms(a); emit('alarms'); }).catch(() => {});
    },
    failed: async () => {
      firstOpen = false; // a gap before the first open: re-sync when it finally opens
      try {
        const r = await api.get('/session', null, { ok: [401] });
        if (r.status === 401) sessionLost('login.expired');
        else if (r.body && r.body.must_change) checkSession();
      } catch { /* network down: keep retrying */ }
      startFallback();
    },
  });
  sock.start();
  clearInterval(tickTimer);
  tickTimer = setInterval(() => { if (!document.hidden) emit('clock', Date.now()); }, 1000);
}

/** REST polling while the socket is down for more than 6 s (e.g. 5th client → 503). */
function startFallback() {
  if (fallbackTimer) return;
  let n = 0;
  let busy = false;
  fallbackTimer = setInterval(async () => {
    if (busy || document.hidden || state.ws === 'open' || !downSince || Date.now() - downSince < 6000) return;
    busy = true;
    try {
      for (const device of state.devices.filter((d) => d.enabled)) {
        const d = device.id;
        const lv = await api.get(`/devices/${d}/live`);
        if (view !== 'app' || state.ws === 'open') return;
        const now = Date.now();
        const prev = liveOf(d);
        const st = fromRest(lv, now);
        state.live.set(d, st);
        series(d).add(now, st);
        emit(`live:${d}`, { state: st, changed: Object.keys(st.regs).filter((k) => prev.regs[k] !== st.regs[k]), coilsChanged: prev.coils !== st.coils });
        emit(`series:${d}`);
      }
      if (n++ % 5 === 0) {
        state.alarms = sortAlarms(await api.get('/alarms/active'));
        emit('alarms');
      }
    } catch { /* keep trying */ } finally { busy = false; }
  }, 2000);
}
