// IA-style device cards: normal channels followed by details expanded in place.
import { h, icon, replace, setText } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, live, can } from '../store.js';
import { templateFor, deviceStatus } from '../device_templates.js';
import { channelsFor, channelVisible, channelText } from '../channel_display.js';
import { openMonitor } from '../monitor_popup.js';

export function mount(root, args, scope) {
  const count = h('span.meta');
  const grid = h('div.ia-device-grid');
  const updates = [];
  const expanded = new Map();
  let listeners = [];
  const allDetails = h('button.btn', { type: 'button', 'aria-pressed': 'false', text: t('devices.expand_all') });
  let allOpen = false;
  allDetails.addEventListener('click', () => {
    allOpen = !allOpen;
    grid.querySelectorAll('details').forEach((d) => { d.open = allOpen; });
    allDetails.setAttribute('aria-pressed', String(allOpen));
    allDetails.textContent = t(allOpen ? 'devices.collapse_all' : 'devices.expand_all');
  });
  replace(root, h('div.page',
    h('div.page-head', h('h1', { text: t('devices.title') }), count, h('span.grow'), allDetails,
      can('admin') ? h('a.btn.primary', { href: '#/devices/add' }, icon('plus'), t('mb.add')) : null), grid));
  function paintCards() {
    listeners.forEach((off) => off()); listeners = []; updates.length = 0;
    grid.querySelectorAll('[data-device] details').forEach((el) => expanded.set(Number(el.closest('[data-device]').dataset.device), el.open));
    setText(count, t('devices.count', { n: state.devices.length }));
    replace(grid, state.devices.length ? state.devices.map((d) => {
      const tpl = templateFor(d, state.templates);
      const status = h('span.device-status');
      const values = [];
      const channels = channelsFor(d).filter((ch) => channelVisible(d, ch));
      function row(ch) {
        const value = h('b');
        values.push([ch, value]);
        return h('div.ia-channel', { data: { channel: ch.id } }, h('span.ia-label', ch.access === 'rw_conf' ? icon('gear', 's16') : null, name(ch)),
          h('span.ia-reading', value, ch.unit ? h('small', { text: ch.unit }) : null));
      }
      const normal = channels.filter((ch) => ch.access !== 'rw_conf');
      const advanced = channels.filter((ch) => ch.access === 'rw_conf');
      const details = h('details.ia-card-details', { open: expanded.get(d.id) ?? allOpen },
        h('summary', t('devices.details')), advanced.map(row),
        can('operator') && d.enabled ? h('div.ia-control', h('a.btn.sm', { href: `#/controller/${d.id}`, text: t('devices.control') })) : null);
      const update = () => {
        const st = deviceStatus(d, live(d.id), Date.now(), state.pollMs, state.comm.get(d.id));
        status.className = `device-status ${st}`;
        setText(status, t(`devices.status.${st}`));
        for (const [ch, el] of values) setText(el, channelText(d, ch, false));
      };
      updates.push(update);
      listeners.push(on(`live:${d.id}`, update), on(`comm:${d.id}`, update));
      return h('article.panel.ia-device-card', { data: { device: d.id } },
        h('div.ia-card-head', h('div.meta', { text: tpl?.name || d.template_id }), h('h2', { text: d.name || `#${d.id}` }),
          h('div.ia-card-meta', status, h('span.meta', { text: `${t('mb.slave')} ${d.slave}` }))),
        normal.length ? normal.map(row) : h('p.panel-b.muted', { text: t('devices.no_channels') }), details,
        h('div.ia-card-actions', h('button.btn.sm', { type: 'button', text: t('nav.monitor'), on: { click: () => openMonitor(d.id, scope) } }),
          can('admin') ? h('a.btn.sm.ghost', { href: `#/devices/edit/${d.id}`, text: t('devices.manage') }) : null));
    }) : h('div.empty', { text: t('devices.empty') }));
    updates.forEach((fn) => fn());
  }
  scope.add(() => listeners.forEach((off) => off()));
  for (const topic of ['clock', 'alarms', 'ws']) scope.add(on(topic, () => updates.forEach((fn) => fn())));
  scope.add(on('devices', paintCards));
  paintCards();
}
