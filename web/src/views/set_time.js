// Settings · Time: gateway clock vs browser, sync from browser (writes the RTC), NTP servers and
// interval, POSIX time zone.
import { h, icon, setText } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put, post } from '../api.js';
import { state, set, emit } from '../store.js';
import { Form, panel, toast, toastErr } from '../ui.js';
import * as fmt from '../fmt.js';

const TZ = [
  ['KST-9', 'Asia/Seoul (KST)'], ['JST-9', 'Asia/Tokyo (JST)'], ['CST-8', 'Asia/Shanghai (CST)'], ['SGT-8', 'Asia/Singapore (SGT)'],
  ['ICT-7', 'Asia/Bangkok (ICT)'], ['IST-5:30', 'Asia/Kolkata (IST)'], ['GST-4', 'Asia/Dubai (GST)'],
  ['CET-1CEST,M3.5.0,M10.5.0/3', 'Europe/Berlin (CET/CEST)'], ['GMT0BST,M3.5.0/1,M10.5.0', 'Europe/London (GMT/BST)'],
  ['EST5EDT,M3.2.0,M11.1.0', 'America/New_York (EST/EDT)'], ['PST8PDT,M3.2.0,M11.1.0', 'America/Los_Angeles (PST/PDT)'],
  ['UTC0', 'UTC'],
];
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;

export function mount(el, scope, { admin }) {
  const f = new Form({ readOnly: !admin, onSave: (v) => put('/config/time', v), onSaved: (m) => { fmt.setTimeZone(m.tz); state.timeConfig = m; emit('clock', Date.now()); paintClock(); } });
  const ntp = f.toggle('ntp.enabled', t('time.ntp'));
  const s1 = h('input.inp', { type: 'text', 'aria-label': t('time.server1'), spellcheck: 'false' });
  const s2 = h('input.inp', { type: 'text', 'aria-label': t('time.server2'), spellcheck: 'false' });
  const srvErr = h('div.err', { hidden: true });
  const srvRow = h('div.field.span2', h('div.lbl', { text: t('time.servers') }), h('div.grid.g2', s1, s2), srvErr);
  f.custom({
    path: 'ntp.servers', row: srvRow, err: srvErr, input: s1,
    get: () => [s1.value.trim(), s2.value.trim()].filter(Boolean),
    set: (v) => { s1.value = (v && v[0]) || ''; s2.value = (v && v[1]) || ''; },
    validate: (v) => (v.some((x) => !HOST_RE.test(x) || x.length > 63) ? t('v.host') : ntp.get() && !v.length ? t('time.need_server') : null),
  });
  if (!admin) { s1.disabled = true; s2.disabled = true; }
  const iv = f.num('ntp.interval_min', t('time.interval'), { min: 15, max: 1440, unit: t('u.min_short') });
  const tzSel = h('select.inp', { id: 'tz-sel', disabled: !admin }, TZ.map(([v, l]) => h('option', { value: v, text: l })), h('option', { value: '', text: t('time.tz_custom') }));
  const tzTxt = h('input.inp', { type: 'text', 'aria-label': t('time.tz_posix'), spellcheck: 'false', disabled: !admin, placeholder: 'KST-9' });
  const tzErr = h('div.err', { hidden: true });
  const syncTz = () => { tzTxt.hidden = tzSel.value !== ''; };
  tzSel.addEventListener('change', () => { if (tzSel.value) tzTxt.value = tzSel.value; syncTz(); });
  const tzRow = h('div.field', h('label', { for: 'tz-sel', text: t('time.tz') }), tzSel, tzTxt, h('div.hint', { text: t('time.tz_hint') }), tzErr);
  f.custom({
    path: 'tz', row: tzRow, err: tzErr, input: tzSel,
    get: () => (tzSel.value || tzTxt.value.trim()),
    set: (v) => { tzSel.value = TZ.some(([x]) => x === v) ? v : ''; tzTxt.value = v || ''; syncTz(); },
    validate: (v) => (!/^[A-Za-z<>+\-0-9,.:/]{1,47}$/.test(v) ? t('v.tz') : null),
  });
  f.el.append(panel(t('time.sync'), h('div.panel-b', h('div.grid.g2', h('div.span2', ntp.row), srvRow, iv.row, tzRow))));
  if (admin) f.saveBar();

  // clock comparison
  const gwT = h('dd');
  const brT = h('dd');
  const diff = h('dd');
  const validT = h('dd');
  const syncBtn = h('button.btn', { type: 'button', hidden: !admin }, icon('clock'), t('time.from_browser'));
  syncBtn.addEventListener('click', async () => {
    syncBtn.disabled = true;
    try {
      await post('/time', { epoch_ms: Date.now() });
      toast(t('time.synced'));
      await refreshInfo();
    } catch (e) { toastErr(e); }
    syncBtn.disabled = false;
  });
  el.append(panel(t('time.clock'), h('div.panel-b', h('dl.kv',
    h('dt', { text: t('time.gw') }), gwT, h('dt', { text: t('time.browser') }), brT,
    h('dt', { text: t('time.diff') }), diff, h('dt', { text: t('time.valid') }), validT)), syncBtn), f.el);

  let offset = null;
  async function refreshInfo() {
    const t0 = Date.now();
    const i = await get('/system/info');
    const t1 = Date.now();
    if (scope.dead) return;
    offset = i.time_ms === null ? null : i.time_ms - (t0 + t1) / 2;
    state.srvOffset = offset ?? 0;
    set('srvValid', i.time_valid && offset !== null);
    set('info', i);
    emit('clock', t1);
    setText(validT, i.time_valid ? t('yes') : t('time.invalid'));
    paintClock();
  }
  function paintClock() {
    const now = Date.now();
    setText(brT, fmt.dateTime(now));
    setText(gwT, offset === null ? t('time.invalid') : fmt.dateTime(now + offset));
    setText(diff, offset === null ? fmt.DASH : `${fmt.signed(offset / 1000, 1)} s`);
  }
  scope.every(1000, paintClock);
  refreshInfo().catch(() => {});
  get('/config/time').then((m) => { if (!scope.dead) { f.load(m); fmt.setTimeZone(m.tz); state.timeConfig = m; paintClock(); } }).catch(toastErr);
}
