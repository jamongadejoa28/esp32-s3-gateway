// Hash router: #/<view>[/<sub>]. Each view module exports mount(root, args, scope); the scope is
// disposed on navigation so subscriptions, timers and charts never leak.
import { Scope, clear } from './dom.js';
import { emit, on } from './store.js';
import * as dashboard from './views/dashboard.js';
import * as controller from './views/controller.js';
import * as trends from './views/trends.js';
import * as alarms from './views/alarms.js';
import * as settings from './views/settings.js';

export const VIEWS = { dashboard, controller, trends, alarms, settings };
export const NAV = ['dashboard', 'controller', 'trends', 'alarms', 'settings'];

let outlet = null;
let scope = null;
let current = null;
let offDev = null;

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
  if (!outlet) return;
  const r = parseHash(location.hash);
  if (scope) scope.dispose();
  scope = new Scope();
  current = r;
  clear(outlet);
  outlet.scrollTop = 0;
  window.scrollTo(0, 0);
  try {
    VIEWS[r.view].mount(outlet, r.args, scope);
  } catch (e) {
    console.error(e);
  }
  emit('route', r);
}

export function startRouter(el) {
  outlet = el;
  window.addEventListener('hashchange', route);
  offDev = on('dev', route); // device-scoped views re-mount for the newly selected device
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
