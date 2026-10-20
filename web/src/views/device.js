import { h, replace, setText } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, live, can } from '../store.js';
import { templateFor, deviceStatus } from '../device_templates.js';
import { channelText } from '../channel_display.js';
import { openMonitor } from '../monitor_popup.js';
import { panel } from '../ui.js';
import * as fmt from '../fmt.js';

export function mount(root, args, scope) {
  const d = state.devices.find((x) => x.id === Number(args[0]));
  if (!d) { replace(root, h('div.empty', { text: t('devices.not_found') })); return; }
  const template = templateFor(d, state.templates);
  const status = h('span.device-status');
  const values = [];
  const channels = template?.channels || [];
  const rows = channels.map((ch) => {
    const value = h('td.template-value');
    values.push([ch, value]);
    return h(`tr${ch.source === 'none' ? '.muted' : ''}`, { data: { channel: ch.id } },
      h('th', { scope: 'row' }, name(ch)), value,
      h('td', t(`template.access.${ch.access}`)));
  });
  const head = h('thead', h('tr',
    h('th', { scope: 'col' }, t('template.item')),
    h('th', { scope: 'col' }, t('template.value')),
    h('th', { scope: 'col' }, t('template.access'))));
  const body = h('tbody', rows.length ? rows : h('tr', h('td', { colspan: 3, text: t('template.unknown') })));
  const details = panel(t('template.channels'), h('div',
    h('p.panel-b.muted', { text: t('template.help') }),
    h('div.tbl-wrap', h('table.tbl.template-table', h('caption.sr', t('template.channels')), head, body))));
  replace(root, h('div.page',
    h('a.device-back', { href: '#/dashboard', text: t('devices.back') }),
    h('div.page-head', h('h1', { text: d.name || `#${d.id}` }), status, h('span.grow'),
      h('button.btn', { type: 'button', text: t('nav.monitor'), on: { click: () => openMonitor(d.id, scope) } }),
      can('operator') && d.enabled ? h('a.btn.primary', { href: `#/controller/${d.id}`, text: t('devices.control') }) : null),
    h('p.muted', { text: `${template?.name || d.template_id} · ${template?.vendor || ''} · ${t('mb.dev_id')} ${d.id} · ${t('mb.slave')} ${d.slave}` }),
    details));

  function paint() {
    const lv = live(d.id);
    const st = deviceStatus(d, lv, Date.now(), state.pollMs, state.comm.get(d.id));
    status.className = `device-status ${st}`;
    setText(status, t(`devices.status.${st}`));
    for (const [ch, el] of values) setText(el, channelText(d, ch));
  }
  for (const topic of [`live:${d.id}`, `comm:${d.id}`, 'clock', 'alarms']) scope.add(on(topic, paint));
  paint();
}
