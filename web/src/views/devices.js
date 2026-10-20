// Registration owns device configuration only; shared serial settings have their own page.
import { h, icon, replace } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, can, updateDevices } from '../store.js';
import { get, put, req, errText } from '../api.js';
import { panel, table, dialog, confirmDlg, toast, toastErr } from '../ui.js';
import { templateFor } from '../device_templates.js';
import { channelSupported, channelVisible } from '../channel_display.js';
import { utf8Len } from '../fmt.js';
import { openMonitor } from '../monitor_popup.js';

const family = (tpl) => tpl.category.split('.')[0];
const familyLabel = (key) => key === 'HVAC' ? t('devices.kind_hvac') : key === 'TH' ? t('devices.kind_th') : key;

export function mount(root, args, scope) {
  const box = h('div');
  const add = h('button.btn.primary', { type: 'button', hidden: !can('admin'), text: t('mb.add'), on: { click: () => editDevice() } });
  replace(root, h('div.page', h('div.page-head', h('h1', { text: t('nav.devices') }), h('span.grow'), add),
    h('p.muted', t('devices.management_help')), box));
  let busy = false;
  function paint() {
    add.disabled = state.devices.length >= 4;
    replace(box, panel(t('devices.title'), table([
      { label: t('mb.dev_name'), cell: (d) => d.name },
      { label: t('devices.kind'), cell: (d) => familyLabel(family(templateFor(d, state.templates) || { category: '?' })) },
      { label: t('template.model'), cell: (d) => templateFor(d, state.templates)?.name || d.template_id },
      { label: t('mb.slave'), cell: (d) => String(d.slave) },
      { label: t('mb.enabled'), cell: (d) => t(d.enabled ? 'yes' : 'disabled') },
      { label: t('devices.actions'), cell: (d) => h('div.btn-row',
        h('button.btn.sm', { type: 'button', text: t('nav.monitor'), on: { click: () => openMonitor(d.id, scope) } }),
        can('admin') ? h('button.btn.sm.danger', { type: 'button', text: t('devices.clear_history'), on: { click: () => clearHistory(d) } }) : null,
        can('admin') ? h('button.btn.sm', { type: 'button', text: t('edit'), on: { click: () => editDevice(d.id) } }) : null,
        can('admin') && state.devices.length > 1 ? h('button.btn.sm.danger', { type: 'button', text: t('remove'), on: { click: () => removeDevice(d.id) } }) : null) },
    ], state.devices, { caption: t('devices.title'), empty: t('devices.empty') })));
  }
  async function clearHistory(d) {
    if (busy || !await confirmDlg({ title: t('devices.clear_history_q'), text: t('devices.clear_history_text', { name: d.name }), ok: t('devices.clear_history'), danger: true })) return;
    busy = true;
    try { await req('DELETE', `/devices/${d.id}/history`); state.series.delete(d.id); toast(t('history.deleted')); }
    catch (e) { toastErr(e); }
    busy = false;
  }
  async function reload() { updateDevices(await get('/devices')); }
  async function removeDevice(id) {
    if (busy || !await confirmDlg({ title: t('devices.remove_q'), text: t('devices.remove_text', { name: state.devices.find((d) => d.id === id)?.name }), ok: t('remove'), danger: true })) return;
    busy = true;
    try {
      const current = await get('/config/modbus');
      await put('/config/modbus', { devices: current.devices.filter((d) => d.id !== id) });
      await reload(); toast(t('saved'));
    } catch (e) { toastErr(e); }
    busy = false;
  }
  async function editDevice(id) {
    if (!can('admin') || busy || scope.dead) return;
    busy = true;
    let config;
    try { config = await get('/config/modbus'); } catch (e) { busy = false; toastErr(e); return; }
    if (scope.dead) { busy = false; return; }
    const original = config.devices.find((d) => d.id === id);
    const used = new Set(config.devices.map((d) => d.id));
    const newId = original?.id ?? [0, 1, 2, 3].find((i) => !used.has(i));
    if (newId === undefined || (id !== undefined && !original)) { busy = false; return; }
    const families = [...new Set(state.templates.map(family))];
    const kind = h('select.inp', { id: 'device-kind', disabled: !!original }, families.map((k) => h('option', { value: k, text: familyLabel(k) })));
    const model = h('select.inp', { id: 'device-template', disabled: !!original });
    const label = h('input.inp', { id: 'device-name', type: 'text', value: original?.name || '', autocomplete: 'off' });
    let slave = 1;
    while (config.devices.some((d) => d.slave === slave)) slave++;
    const address = h('input.inp', { id: 'device-slave', type: 'number', min: 1, max: 247, value: original?.slave ?? slave });
    const enabled = h('input.switch', { id: 'device-enabled', type: 'checkbox', role: 'switch', checked: original?.enabled ?? true });
    const channels = h('div.device-channel-options');
    const summary = h('p.muted');
    const message = h('p.err', { role: 'alert' });
    const checks = new Map();
    const selectedTemplate = () => state.templates.find((t) => t.id === model.value);
    function paintChannels() {
      const tpl = selectedTemplate();
      checks.clear();
      if (!tpl) { replace(channels, t('template.unknown')); return; }
      setSummary(tpl);
      replace(channels, tpl.channels.map((ch) => {
        const supported = channelSupported(ch);
        const check = h('input', { type: 'checkbox', checked: supported && (!original || channelVisible(original, ch)), disabled: !supported, 'aria-label': name(ch) });
        checks.set(ch.id, check);
        return h('label.device-channel-option', check, h('span', name(ch)), h('small.muted', supported ? ch.unit : t('template.disabled')));
      }));
      if (!original && !label.value) label.value = `${familyLabel(family(tpl))} ${newId + 1}`;
    }
    function setSummary(tpl) { summary.textContent = t('devices.shared_port', { baud: config.port.baud, parity: config.port.parity, stop: config.port.stop }); }
    function models() {
      replace(model, state.templates.filter((tpl) => family(tpl) === kind.value).map((tpl) => h('option', { value: tpl.id, text: `${tpl.vendor} · ${tpl.name}` })));
      if (original) model.value = original.template_id || 'mex150';
      paintChannels();
    }
    if (original) kind.value = family(templateFor(original, state.templates));
    kind.addEventListener('change', models); model.addEventListener('change', paintChannels); models();
    const field = (text, input) => h('div.field', h('label', { for: input.id, text }), input);
    const result = await dialog({
      title: original ? t('devices.edit') : t('mb.add'),
      body: h('div.device-form', h('div.grid.g2', field(t('devices.kind'), kind), field(t('template.model'), model),
        field(t('mb.dev_name'), label), field(t('mb.slave'), address)),
        h('div.field.inline', enabled, h('label', { for: enabled.id, text: t('mb.enabled') })), summary,
        h('details', h('summary', t('devices.display_channels')), h('p.hint', t('devices.display_help')), channels), message),
      initialFocus: label,
      actions: [{ label: t('cancel'), value: null }, { label: original ? t('save') : t('devices.register'), value: true, kind: 'primary', submit: true }],
      onSubmit: async () => {
        const tpl = selectedTemplate(); const n = Number(address.value);
        if (!tpl) { message.textContent = t('template.unknown'); return false; }
        if (!label.value.trim()) { message.textContent = t('v.required'); label.focus(); return false; }
        if (utf8Len(label.value.trim()) > 23) { message.textContent = t('v.bytes', { n: 23 }); label.focus(); return false; }
        if (!Number.isInteger(n) || n < 1 || n > 247) { message.textContent = t('v.slave'); return false; }
        let display_mask = 0;
        for (const [ch, input] of checks) if (input.checked && !input.disabled) display_mask = (display_mask | (1 << ch)) >>> 0;
        try {
          const latest = await get('/config/modbus');
          if (enabled.checked && latest.devices.some((d) => d.id !== newId && d.enabled && d.slave === n)) { message.textContent = t('v.slave_dup'); return false; }
          if (!original && latest.devices.some((d) => d.id === newId)) { message.textContent = t('devices.changed'); return false; }
          if (original && !latest.devices.some((d) => d.id === newId)) { message.textContent = t('devices.changed'); return false; }
          const item = { id: newId, name: label.value.trim(), slave: n, enabled: enabled.checked, template_id: tpl.id, display_mask };
          const devices = original ? latest.devices.map((d) => d.id === newId ? item : d) : [...latest.devices, item];
          await put('/config/modbus', { devices });
          await reload(); toast(t('saved')); return true;
        } catch (e) { message.textContent = errText(e); return false; }
      },
    });
    busy = false;
    if (result) paint();
  }
  scope.add(on('devices', paint));
  paint();
  // Canonical management URL prevents a closed editor reopening on a language/role refresh.
  if (args[0] === 'add' || args[0] === 'edit') {
    history.replaceState(null, '', '#/devices');
    editDevice(args[0] === 'edit' ? Number(args[1]) : undefined);
  }
}
