// App shell: left rail (56 px icons, expandable to 208 px; drawer below 768 px) and the 40 px
// status strip: site · RUN/STOP · comm + data age · alarm count · clock · KO/EN · theme · user.
import { h, icon, sprite, setText, toggle, storage, Scope, replace } from './dom.js';
import { t, lang, setLang, name } from './i18n/index.js';
import { state, on, live, devName } from './store.js';
import { derive, alarmSummary, staleAfterMs, storageFailed } from './live.js';
import { NAV, currentRoute } from './router.js';
import * as fmt from './fmt.js';
import { changeOwnPassword } from './views/account.js';

const NAV_ICON = { dashboard: 'dash', devices: 'plug', monitor: 'trend', controller: 'ctrl', alarms: 'bell', settings: 'gear' };

/** Run state pill model for the selected device. */
export function runPill(d) {
  const st = live(d);
  const dv = derive(st);
  if (!st.known || !st.on || Date.now() - st.rx > staleAfterMs(state.pollMs) || !dv || dv.running === null) return { cls: '', text: t('run.unknown') };
  if (dv.running && dv.runDelay && dv.delay) return { cls: 'warn', text: t('run.starting', { n: dv.delay }) };
  if (!dv.running && dv.stopDelay && dv.delay) return { cls: 'warn', text: t('run.stopping', { n: dv.delay }) };
  return dv.running ? { cls: 'ok', text: t('run.run') } : { cls: '', text: t('run.stop') };
}

export function buildShell({ logout, setTheme, effectiveTheme, themeFollowsSystem }) {
  const sc = new Scope();
  const app = h('div.app');
  if (storage.get('gw.rail') === '1') app.classList.add('rail-open');

  const navLinks = (drawer) => NAV.map((v) => h('a', { href: `#/${v}`, data: { v }, title: drawer ? null : t(`nav.${v}`) },
    icon(NAV_ICON[v]), h('span.lbl', { text: t(`nav.${v}`) })));
  const railNav = h('nav.nav', { 'aria-label': t('nav.main') }, navLinks(false));
  const railToggle = h('button', { type: 'button', 'aria-expanded': app.classList.contains('rail-open') ? 'true' : 'false' },
    icon('rail'), h('span.lbl', { text: t('nav.collapse') }));
  railToggle.addEventListener('click', () => {
    const open = app.classList.toggle('rail-open');
    railToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    storage.set('gw.rail', open ? '1' : '0');
  });
  const rail = h('aside.rail', h('div.brand', sprite('logo'), h('span', 'MESTIO')), railNav, h('div.rail-foot', railToggle));

  // ---- strip ----
  const menuBtn = h('button.btn.ghost.icon.menu-btn', { type: 'button', 'aria-label': t('nav.menu'), 'aria-expanded': 'false', 'aria-controls': 'drawer' }, icon('menu'));
  const site = h('span.site');
  const pill = h('span.pill', { role: 'status' });
  const commDot = h('span.dot');
  const commTxt = h('span.age');
  const comm = h('span.stat', { title: t('strip.comm') }, commDot, commTxt);
  const almCount = h('span.badge');
  const alm = h('a.stat', { href: '#/alarms' }, icon('bell'), almCount);
  const clockEl = h('span.clock');
  const langBtn = h('button.btn.ghost.sm.hide-xs', { type: 'button', 'aria-label': t('strip.lang') }, lang() === 'ko' ? 'EN' : 'KO');
  langBtn.addEventListener('click', () => setLang(lang() === 'ko' ? 'en' : 'ko'));
  const themeBtn = h('button.btn.ghost.icon', { type: 'button' });
  const paintTheme = () => {
    const dark = effectiveTheme() === 'dark';
    themeBtn.replaceChildren(icon(dark ? 'sun' : 'moon'));
    themeBtn.setAttribute('aria-label', t(dark ? 'strip.light' : 'strip.dark'));
    themeBtn.title = t(dark ? 'strip.light' : 'strip.dark');
  };
  themeBtn.addEventListener('click', () => setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'));
  paintTheme();

  const menu = h('div.menu', { role: 'menu', hidden: true });
  const userBtn = h('button.btn.ghost.icon', { type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-label': t('strip.user') }, icon('user'));
  const closeMenu = () => { menu.hidden = true; userBtn.setAttribute('aria-expanded', 'false'); };
  const item = (ic, label, fn) => h('button', { type: 'button', role: 'menuitem', on: { click: () => { closeMenu(); fn(); } } }, icon(ic), label);
  const fillMenu = () => {
    const s = state.session;
    replace(menu,
      h('div.who', s.user, h('small', { text: t(`role.${s.role}`) })),
      item('lock', t('menu.password'), changeOwnPassword),
      item('globe', lang() === 'ko' ? 'English' : '한국어', () => setLang(lang() === 'ko' ? 'en' : 'ko')),
      themeFollowsSystem() ? null : item('redo', t('menu.theme_auto'), () => setTheme(null)),
      item('out', t('logout'), logout));
  };
  userBtn.addEventListener('click', () => {
    if (!menu.hidden) { closeMenu(); return; }
    fillMenu();
    menu.hidden = false;
    userBtn.setAttribute('aria-expanded', 'true');
    menu.querySelector('button').focus();
  });
  menu.addEventListener('keydown', (e) => {
    const items = [...menu.querySelectorAll('button')];
    const i = items.indexOf(document.activeElement);
    if (e.key === 'Escape') { closeMenu(); userBtn.focus(); } else if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); } else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
  });
  sc.listen(document, 'pointerdown', (e) => { if (!menu.hidden && !menu.parentNode.contains(e.target)) closeMenu(); });

  const strip = h('header.strip', menuBtn, site, h('span.sep.hide-xs'), pill, comm, alm, h('span.grow'), clockEl,
    h('div.tools', langBtn, themeBtn, h('div.menu-wrap', userBtn, menu)));

  // ---- drawer (mobile) ----
  const drawer = h('div.drawer', { id: 'drawer' }, h('nav.nav', { 'aria-label': t('nav.main') }, navLinks(true)));
  const setDrawer = (open) => {
    drawer.classList.toggle('open', open);
    menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    menuBtn.replaceChildren(icon(open ? 'x' : 'menu'));
  };
  menuBtn.addEventListener('click', () => setDrawer(!drawer.classList.contains('open')));
  drawer.addEventListener('click', (e) => { if (e.target.closest('a')) setDrawer(false); });

  // persistent system banner above every page (the router only replaces `outlet`)
  const sysBar = h('div.sysbar', { hidden: true, role: 'status' });
  const outlet = h('div.outlet');
  const main = h('main', { id: 'main', tabindex: '-1' }, sysBar, outlet);
  const announce = h('div.sr', { 'aria-live': 'assertive', role: 'alert' });
  app.append(h('a.sr.skip', { href: '#main', text: t('nav.skip'), on: { click: (e) => { e.preventDefault(); main.focus(); } } }), rail, strip, drawer, main, announce);

  // ---- live updates ----
  const paintSite = () => {
    const s = state.general?.site || state.info?.hostname || '';
    const multi = state.devices.filter((d) => d.enabled).length > 1;
    setText(site, multi ? `${s}${s ? ' · ' : ''}${devName(state.dev)}` : s || devName(state.dev));
  };
  const paintPill = () => {
    const p = runPill(state.dev);
    pill.className = `pill ${p.cls}`;
    setText(pill, p.text);
  };
  const paintComm = () => {
    const st = live(state.dev);
    const ws = state.ws;
    let cls = 'dot';
    let txt;
    if (ws !== 'open' && ws !== 'idle') { cls += ' warn'; txt = fmt.DASH; comm.title = t('strip.reconnecting'); } else if (!st.known) { txt = fmt.DASH; comm.title = t('strip.waiting'); } else if (!st.on) { cls += ' alarm'; txt = fmt.DASH; comm.title = t('strip.offline'); } else {
      const a = Date.now() - st.rx;
      const stale = a > staleAfterMs(state.pollMs);
      cls += stale ? ' warn' : ' ok';
      txt = stale ? fmt.DASH : fmt.age(a);
      comm.title = t(stale ? 'devices.status.stale' : 'devices.status.online');
      toggle(comm, 'stale', stale);
    }
    commDot.className = cls;
    setText(commTxt, txt);
  };
  const paintAlarms = (m) => {
    const s = alarmSummary(state.alarms);
    almCount.className = `badge${s.unacked ? ' alarm' : s.total ? ' alarm-o' : ''}`;
    setText(almCount, String(s.total));
    alm.setAttribute('aria-label', t('strip.alarms', { n: s.total, u: s.unacked }));
    if (m && m.type === 'raise') {
      const am = state.alarmMeta.get(m.id);
      announce.textContent = t('strip.alarm_raised', { name: am ? name(am) : m.id, dev: devName(m.dev) });
    }
  };
  let sysBarOn = false;
  const paintSysBar = () => {
    const on1 = storageFailed(state.info);
    if (on1 === sysBarOn) return;
    sysBarOn = on1;
    sysBar.hidden = !on1;
    replace(sysBar, on1 ? h('div.banner.alarm', icon('alert'), h('div.grow',
      h('b', { text: t('sys.no_persist_t') }), h('p', { text: t('sys.no_persist') })),
    h('a', { href: '#/settings/system', text: t('sys.see_diag') })) : null);
  };
  const paintClock = () => {
    const now = state.srvValid ? Date.now() + state.srvOffset : null;
    setText(clockEl, fmt.clock(now));
  };
  const paintRoute = () => {
    const r = currentRoute();
    for (const a of app.querySelectorAll('.nav a')) {
      if (r && a.dataset.v === (r.view === 'device' ? 'dashboard' : r.view)) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
  };
  let devOff = [];
  const bindDev = () => {
    devOff.forEach((f) => f());
    devOff = [on(`live:${state.dev}`, () => { paintPill(); paintComm(); }), on(`comm:${state.dev}`, paintComm)];
    paintSite();
    paintPill();
    paintComm();
  };
  sc.add(() => devOff.forEach((f) => f()));
  sc.add(on('dev', bindDev));
  sc.add(on('devices', paintSite));
  sc.add(on('info', () => { paintSite(); paintSysBar(); }));
  sc.add(on('general', paintSite));
  sc.add(on('ws', paintComm));
  sc.add(on('alarms', paintAlarms));
  sc.add(on('clock', () => { paintClock(); paintComm(); paintPill(); }));
  sc.add(on('theme', paintTheme));
  sc.add(on('route', () => { paintRoute(); setDrawer(false); }));
  bindDev();
  paintAlarms();
  paintClock();
  paintSysBar();
  return { el: app, outlet, dispose: () => sc.dispose() };
}
