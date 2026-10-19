// Settings · Modbus / RS485: port, timing, devices (up to 4) and live per-device counters.
import { h, icon, replace } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put, post } from '../api.js';
import { state, emit } from '../store.js';
import { Form, panel, confirmDlg, toast, toastErr, table } from '../ui.js';
import * as fmt from '../fmt.js';
import { utf8Len } from '../fmt.js';

export function mount(el, scope, { admin }) {
  const f = new Form({
    readOnly: !admin,
    onSave: (v) => put('/config/modbus', v),
    onSaved: (m) => { state.pollMs = m.poll_ms; get('/devices').then((d) => { state.devices = d; emit('devices', d); }).catch(() => {}); },
  });
  const baud = f.select('port.baud', t('mb.baud'), [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200].map((b) => [b, String(b)]));
  const parity = f.select('port.parity', t('mb.parity'), [['N', t('mb.none')], ['E', t('mb.even')], ['O', t('mb.odd')]]);
  const stop = f.select('port.stop', t('mb.stop'), [[1, '1'], [2, '2']]);
  const poll = f.num('poll_ms', t('mb.poll'), { min: 200, max: 60000, unit: 'ms' });
  const tmo = f.num('timeout_ms', t('mb.timeout'), { min: 50, max: 2000, unit: 'ms' });
  const retries = f.num('retries', t('mb.retries'), { min: 0, max: 3 });
  const gap = f.num('gap_ms', t('mb.gap'), { min: 0, max: 100, unit: 'ms' });
  const offline = f.num('offline_after', t('mb.offline'), { min: 1, max: 10, hint: t('mb.offline_hint') });

  // devices editor
  let devs = [];
  const devBox = h('div');
  const addBtn = h('button.btn.sm', { type: 'button', hidden: !admin }, icon('plus'), t('mb.add'));
  const devErr = h('div.err', { hidden: true, role: 'alert' });
  addBtn.addEventListener('click', () => {
    const used = new Set(devs.map((d) => d.id));
    const id = [0, 1, 2, 3].find((i) => !used.has(i));
    if (id === undefined) return;
    const slaves = new Set(devs.map((d) => d.slave));
    let slave = 1;
    while (slaves.has(slave)) slave++;
    devs.push({ id, name: `${t('alarms.col.dev')} ${id + 1}`, slave, enabled: true });
    paintDevs();
    f.refresh();
  });
  function paintDevs() {
    addBtn.disabled = devs.length >= 4;
    replace(devBox, table([
      { label: t('mb.dev_id'), cls: 'n', cell: (d) => String(d.id) },
      { label: t('mb.dev_name'), cell: (d) => inp(d, 'name', 'text') },
      { label: t('mb.slave'), cell: (d) => inp(d, 'slave', 'num') },
      { label: t('mb.enabled'), cell: (d) => { const c = h('input.switch', { type: 'checkbox', role: 'switch', checked: d.enabled, disabled: !admin, 'aria-label': t('mb.enabled') }); c.addEventListener('change', () => { d.enabled = c.checked; f.refresh(); }); return c; } },
      { label: '', cls: 'act', cell: (d) => (admin && devs.length > 1 ? h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('remove'), title: t('remove'), on: { click: () => { devs = devs.filter((x) => x !== d); paintDevs(); f.refresh(); } } }, icon('trash')) : null) },
    ], devs, { caption: t('mb.devices') }));
  }
  function inp(d, k, kind) {
    const i = h(`input.inp${kind === 'num' ? '.num' : ''}`, { type: 'text', value: String(d[k]), disabled: !admin, 'aria-label': t(k === 'name' ? 'mb.dev_name' : 'mb.slave'), inputmode: kind === 'num' ? 'numeric' : null });
    i.addEventListener('input', () => { d[k] = kind === 'num' ? Number(i.value) : i.value; });
    return i;
  }
  f.custom({
    path: 'devices',
    row: devBox,
    get: () => devs.map((d) => ({ id: d.id, name: d.name.trim(), slave: d.slave, enabled: d.enabled })),
    set: (v) => { devs = (v || []).map((d) => ({ ...d })); paintDevs(); },
    err: devErr,
    validate: (v) => {
      const slaves = new Set();
      for (const d of v) {
        if (utf8Len(d.name) > 23) return t('v.bytes_x', { x: t('mb.dev_name'), n: 23 });
        if (!Number.isInteger(d.slave) || d.slave < 1 || d.slave > 247) return t('v.slave');
        if (d.enabled && slaves.has(d.slave)) return t('v.slave_dup');
        if (d.enabled) slaves.add(d.slave);
      }
      return null;
    },
  });

  f.el.append(
    panel(t('mb.port'), h('div.panel-b', h('div.grid', baud.row, parity.row, stop.row))),
    panel(t('mb.timing'), h('div.panel-b', h('div.grid', poll.row, tmo.row, retries.row, gap.row, offline.row))),
    panel(t('mb.devices'), h('div', devBox, h('div.panel-b', devErr, addBtn))));
  if (admin) f.saveBar();

  // live counters
  const statsBox = h('div');
  const resetBtn = h('button.btn.sm', { type: 'button', hidden: !admin }, icon('redo'), t('mb.reset'));
  resetBtn.addEventListener('click', async () => {
    if (!await confirmDlg({ title: t('mb.reset_q'), text: t('mb.reset_text'), ok: t('mb.reset') })) return;
    try {
      for (const d of state.devices.filter((x) => x.enabled)) await post(`/devices/${d.id}/stats/reset`);
      toast(t('mb.reset_done'));
      paintStats();
    } catch (e) { toastErr(e); }
  });
  el.append(panel(t('mb.counters'), statsBox, resetBtn), f.el);

  async function paintStats() {
    const list = state.devices.filter((x) => x.enabled);
    try {
      const rows = await Promise.all(list.map(async (d) => ({ d, s: await get(`/devices/${d.id}/stats`) })));
      if (scope.dead) return;
      const n = (v) => fmt.num(v, 0);
      replace(statsBox, table([
        { label: t('mb.dev_name'), cell: (r) => r.d.name },
        { label: t('stats.tx'), cls: 'n', cell: (r) => n(r.s.tx) },
        { label: t('stats.rx'), cls: 'n', cell: (r) => n(r.s.rx_ok) },
        { label: 'CRC', cls: 'n', cell: (r) => n(r.s.crc) },
        { label: t('stats.timeout'), cls: 'n', cell: (r) => n(r.s.timeout) },
        { label: t('stats.exception'), cls: 'n', cell: (r) => n(r.s.exception) },
        { label: t('stats.malformed'), cls: 'n', cell: (r) => n(r.s.malformed) },
        { label: t('stats.rtt'), cls: 'n', cell: (r) => `${r.s.rtt_ms.last} / ${r.s.rtt_ms.avg} / ${r.s.rtt_ms.max}` },
        { label: t('stats.offline'), cls: 'n', cell: (r) => n(r.s.offline_count) },
        { label: t('stats.since'), cls: 'nowrap', cell: (r) => (r.s.online_since ? fmt.dateTime(r.s.online_since) : t('strip.offline')) },
      ], rows, { caption: t('mb.counters'), empty: t('mb.no_dev') }));
    } catch { /* keep the previous numbers */ }
  }
  paintStats();
  scope.every(2000, () => { if (!document.hidden) paintStats(); });
  get('/config/modbus').then((m) => { if (!scope.dead) f.load(m); }).catch(toastErr);
}
