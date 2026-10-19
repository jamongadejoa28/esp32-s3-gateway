// Settings frame: sub navigation + page. Admin-only pages are hidden for other roles; pages
// readable by viewers render read-only forms for them.
import { h, icon, replace } from '../dom.js';
import { t } from '../i18n/index.js';
import { can } from '../store.js';
import * as general from './set_general.js';
import * as network from './set_network.js';
import * as modbus from './set_modbus.js';
import * as alarmsCfg from './set_alarms.js';
import * as snmp from './set_snmp.js';
import * as time from './set_time.js';
import * as users from './set_users.js';
import * as system from './set_system.js';

const PAGES = [
  ['general', 'home', general, 'viewer'],
  ['network', 'net', network, 'admin'],
  ['modbus', 'plug', modbus, 'viewer'],
  ['alarms', 'rules', alarmsCfg, 'viewer'],
  ['snmp', 'snmp', snmp, 'admin'],
  ['time', 'clock', time, 'viewer'],
  ['users', 'shield', users, 'admin'],
  ['system', 'chip', system, 'viewer'],
];

export function mount(root, args, scope) {
  const pages = PAGES.filter(([, , , role]) => can(role));
  const cur = pages.find(([k]) => k === args[0]) || pages[0];
  const nav = h('nav.subnav', { 'aria-label': t('nav.settings') }, pages.map(([k, ic]) => h('a', {
    href: `#/settings/${k}`, 'aria-current': k === cur[0] ? 'page' : null,
  }, icon(ic), t(`set.${k}`))));
  const body = h('div.set-body');
  replace(root, h('div.page', h('div.page-head', h('h1', { text: t('nav.settings') })), h('div.settings', nav, body)));
  cur[2].mount(body, scope, { admin: can('admin') });
}
