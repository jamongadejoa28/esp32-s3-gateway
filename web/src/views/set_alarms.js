// Settings · Alarms: debounce, severity overrides, user threshold rules (max 8) and syslog.
import { h, icon, replace } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { get, put } from '../api.js';
import { state } from '../store.js';
import { Form, panel, toastErr, table } from '../ui.js';
import { utf8Len } from '../fmt.js';
import { loadAlarmMeta } from '../meta.js';

const SRC_ALIAS = { 'reg:40036': 'temp', 'reg:40037': 'hum', 'reg:40011': 'cur' };
const FACILITIES = Array.from({ length: 24 }, (_, i) => [i, i >= 16 ? `local${i - 16} (${i})` : String(i)]);

export function mount(el, scope, { admin }) {
  // ---- debounce + severity overrides ----
  const fa = new Form({ readOnly: !admin, onSave: (v) => put('/config/alarms', v), onSaved: () => loadAlarmMeta().catch(() => {}) });
  const dr = fa.num('debounce_raise', t('al.deb_raise'), { min: 1, max: 10, hint: t('al.deb_hint') });
  const dc = fa.num('debounce_clear', t('al.deb_clear'), { min: 1, max: 10 });
  const catalog = [...state.alarmMeta.values()].filter((a) => !a.id.startsWith('rule_'));
  let ov = {};
  const sevSel = new Map();
  const ovBox = table([
    { label: t('al.alarm'), cell: (a) => name(a) },
    { label: t('al.source'), cls: 'nowrap', cell: (a) => h('span.muted', { text: a.source }) },
    {
      label: t('al.severity'),
      cell: (a) => {
        const s = h('select.inp', { 'aria-label': t('al.sev_of', { name: name(a) }), disabled: !admin },
          h('option', { value: '', text: t('al.sev_default') }), [0, 1, 2, 3].map((v) => h('option', { value: String(v), text: t(`sev.${v}`) })));
        sevSel.set(a.id, s);
        return s;
      },
    },
  ], catalog, { caption: t('al.overrides') });
  fa.custom({
    path: 'sev_override',
    row: ovBox,
    get: () => {
      const o = {};
      for (const [id, s] of sevSel) if (s.value !== '') o[id] = Number(s.value);
      return o;
    },
    set: (v) => { ov = v || {}; for (const [id, s] of sevSel) s.value = ov[id] === undefined ? '' : String(ov[id]); },
  });
  fa.el.append(panel(t('al.debounce'), h('div.panel-b', h('div.grid', dr.row, dc.row))), panel(t('al.overrides'), ovBox));
  if (admin) fa.saveBar();

  // ---- rules ----
  const readable = state.meta.regs.filter((r) => !r.bits);
  const srcOpts = [['temp', t('kpi.temp')], ['hum', t('kpi.hum')], ['cur', t('kpi.cur')],
    ...readable.filter((r) => ![40036, 40037, 40011].includes(r.addr)).map((r) => [`reg:${r.addr}`, `${name(r)} (${r.addr})`])];
  let rules = [];
  const rulesBox = h('div');
  const addRule = h('button.btn.sm', { type: 'button', hidden: !admin }, icon('plus'), t('al.add_rule'));
  const fr = new Form({ readOnly: !admin, onSave: async (v) => ({ rules: await put('/config/rules', v.rules) }), onSaved: () => loadAlarmMeta().catch(() => {}) });
  const rulesErr = h('div.err', { hidden: true, role: 'alert' });
  addRule.addEventListener('click', () => {
    const used = new Set(rules.map((r) => r.id));
    const id = [1, 2, 3, 4, 5, 6, 7, 8].find((i) => !used.has(i));
    if (!id) return;
    rules.push({ id, name: `${t('al.rule')} ${id}`, enabled: true, dev: state.dev, src: 'temp', op: '>', thr: 30, hyst: 1, delay_s: 60, sev: 2 });
    paintRules();
    fr.refresh();
  });
  const devOpts = state.devices.map((d) => [d.id, d.name]);
  function cellInput(r, k, kind, opts) {
    let el;
    if (kind === 'sel') {
      el = h('select.inp', { disabled: !admin, 'aria-label': t(`al.r.${k}`) }, opts.map(([v, l]) => h('option', { value: String(v), text: l })));
      // a stored value without an option (e.g. a register no longer in the map) stays visible
      if (!opts.some(([v]) => String(v) === String(r[k]))) el.appendChild(h('option', { value: String(r[k]), text: String(r[k]) }));
      el.value = String(r[k]);
      el.addEventListener('change', () => { const o = opts.find(([v]) => String(v) === el.value); r[k] = o ? o[0] : el.value; fr.refresh(); });
    } else if (kind === 'bool') {
      el = h('input.switch', { type: 'checkbox', role: 'switch', checked: r[k], disabled: !admin, 'aria-label': t(`al.r.${k}`) });
      el.addEventListener('change', () => { r[k] = el.checked; });
    } else {
      el = h(`input.inp${kind === 'num' ? '.num' : ''}`, { type: 'text', value: String(r[k]), disabled: !admin, 'aria-label': t(`al.r.${k}`), inputmode: kind === 'num' ? 'decimal' : null });
      el.addEventListener('input', () => { r[k] = kind === 'num' ? Number(el.value.replace(',', '.')) : el.value; });
    }
    return el;
  }
  function paintRules() {
    addRule.disabled = rules.length >= 8;
    replace(rulesBox, table([
      { label: '#', cls: 'n', cell: (r) => String(r.id) },
      { label: t('al.r.enabled'), cell: (r) => cellInput(r, 'enabled', 'bool') },
      { label: t('al.r.name'), cell: (r) => cellInput(r, 'name', 'text') },
      devOpts.length > 1 ? { label: t('al.r.dev'), cell: (r) => cellInput(r, 'dev', 'sel', devOpts) } : null,
      { label: t('al.r.src'), cell: (r) => cellInput(r, 'src', 'sel', srcOpts) },
      { label: t('al.r.op'), cell: (r) => cellInput(r, 'op', 'sel', [['>', '>'], ['<', '<']]) },
      { label: t('al.r.thr'), cell: (r) => cellInput(r, 'thr', 'num') },
      { label: t('al.r.hyst'), cell: (r) => cellInput(r, 'hyst', 'num') },
      { label: t('al.r.delay'), cell: (r) => cellInput(r, 'delay_s', 'num') },
      { label: t('al.r.sev'), cell: (r) => cellInput(r, 'sev', 'sel', [[1, t('sev.1')], [2, t('sev.2')], [3, t('sev.3')]]) },
      { label: '', cls: 'act', cell: (r) => (admin ? h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('remove'), on: { click: () => { rules = rules.filter((x) => x !== r); paintRules(); fr.refresh(); } } }, icon('trash')) : null) },
    ].filter(Boolean), rules, { caption: t('al.rules'), empty: t('al.no_rules') }));
  }
  fr.custom({
    path: 'rules',
    row: rulesBox,
    err: rulesErr,
    get: () => rules.map((r) => ({ ...r, name: String(r.name).trim() })),
    // 40036/40037/40011 are offered as temp/hum/cur, the names the firmware returns for them
    set: (v) => { rules = (v || []).map((r) => ({ ...r, src: SRC_ALIAS[r.src] || r.src })); paintRules(); },
    validate: (v) => {
      for (const r of v) {
        if (utf8Len(r.name) > 23) return t('v.bytes_x', { x: `${t('al.rule')} ${r.id}`, n: 23 });
        if (!Number.isFinite(r.thr)) return t('v.rule_thr', { id: r.id });
        if (!Number.isFinite(r.hyst) || r.hyst < 0) return t('v.rule_hyst', { id: r.id });
        if (!Number.isInteger(r.delay_s) || r.delay_s < 0 || r.delay_s > 3600) return t('v.rule_delay', { id: r.id });
      }
      return null;
    },
  });
  fr.el.append(panel(t('al.rules'), h('div', h('div.panel-b', h('p.muted', { text: t('al.rules_hint') })), rulesBox, h('div.panel-b', rulesErr, addRule))));
  if (admin) fr.saveBar();
  el.append(fa.el, fr.el);

  // ---- syslog (admin only) ----
  let fn = null;
  if (admin) {
    fn = new Form({ onSave: (v) => put('/config/notify', v) });
    const en = fn.toggle('syslog.enabled', t('sl.enabled'));
    const host = fn.text('syslog.host', t('sl.host'), { max: 63, pattern: /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/, validate: (v) => (en.get() && !v ? t('v.required') : null) });
    const port = fn.num('syslog.port', t('sl.port'), { min: 1, max: 65535 });
    const fac = fn.select('syslog.facility', t('sl.facility'), FACILITIES);
    const sev = fn.select('syslog.min_sev', t('sl.min_sev'), [0, 1, 2, 3, 4, 5, 6, 7].map((v) => [v, t(`sl.sev.${v}`)]), { hint: t('sl.min_sev_hint') });
    fn.el.append(panel(t('sl.title'), h('div.panel-b', h('div.grid.g2', h('div.span2', en.row), host.row, port.row, fac.row, sev.row))));
    fn.saveBar();
    el.append(fn.el);
  }

  Promise.all([get('/config/alarms'), get('/config/rules'), admin ? get('/config/notify') : null]).then(([a, r, n]) => {
    if (scope.dead) return;
    fa.load(a);
    fr.load({ rules: r });
    if (fn && n) fn.load(n);
  }).catch(toastErr);
}
