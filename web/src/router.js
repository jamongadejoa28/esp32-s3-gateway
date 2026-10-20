// Hash router: #/<view>[/<sub>]. Each view module exports mount(root, args, scope); the scope is
// disposed on navigation so subscriptions, timers and charts never leak.
import { Scope, clear, h } from './dom.js';
import { emit, on, state, selectDevice } from './store.js';
import * as devices from './views/devices.js';
import * as dashboard from './views/dashboard.js';
import { t } from './i18n/index.js';
import * as device from './views/device.js';
import * as monitor from './views/monitor.js';
import * as controller from './views/controller.js';
import * as alarms from './views/alarms.js';
import * as settings from './views/settings.js';

export const VIEWS = { dashboard, devices, device, monitor, controller, alarms, settings };
export const NAV = ['dashboard', 'devices', 'controller', 'alarms', 'settings'];

let outlet = null;
let scope = null;
let current = null;
let offDev = null;
let routing = false;

const safeDecode = (x) => {
  try { return decodeURIComponent(x); } catch { return x; } // malformed %-escape: keep it raw
};

/** Parse "#/settings/network" -> {view: 'settings', args: ['network']}. */
export function parseHash(hash) {
  const parts = String(hash || '').replace(/^#\/?/, '').split('/').filter(Boolean).map(safeDecode);
  const view = VIEWS[parts[0]] ? parts[0] : 'dashboard';
  return { view, args: VIEWS[parts[0]] ? parts.slice(1) : [] };
}

function route() {
  if (!outlet || routing) return;
  routing = true;
  const r = parseHash(location.hash);
  if (scope) scope.dispose();
  scope = new Scope();
  current = r;
  clear(outlet);
  outlet.scrollTop = 0;
  window.scrollTo(0, 0);
  try {
    const specific = ['device', 'monitor', 'controller'].includes(r.view) && r.args.length > 0;
    const id = /^\d+$/.test(r.args[0] || '') ? Number(r.args[0]) : -1;
    if (specific && !state.devices.some((d) => d.id === id)) {
      outlet.append(h('div.page', h('p.empty', { text: t('devices.not_found') }),
        h('a', { href: '#/dashboard', text: t('devices.back') })));
    } else {
      if (specific) selectDevice(id);
      VIEWS[r.view].mount(outlet, r.args, scope);
    }
  } catch (e) {
    console.error(e);
  }
  routing = false;
  emit('route', r);
}

export function startRouter(el) {
  outlet = el;
  window.addEventListener('hashchange', route);
  offDev = on('dev', () => {
    if (routing) return;
    if (current?.args.length && ['monitor', 'controller'].includes(current.view)) go(`${current.view}/${state.dev}`);
    else route();
  }); // device-scoped views re-mount for the newly selected device
  route();
}

export function stopRouter() {
  window.removeEventListener('hashchange', route);
  if (offDev) { offDev(); offDev = null; }
  if (scope) scope.dispose();
  scope = null;
  outlet = null;
}

export const currentRoute = () => current;

export function go(path) {
  if (location.hash === `#/${path}`) route();
  else location.hash = `#/${path}`;
}
