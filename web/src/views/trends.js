// Trends: 15 min / 1 h / 24 h / 7 d / 30 d, small multiples (one y axis per measure, shared time
// axis, shared crosshair), min/max envelope for minute-and-coarser buckets, setpoint overlays,
// stage activity lanes, stage run-hours, table view and CSV export.
import { h, icon, replace, storage, download } from '../dom.js';
import { t } from '../i18n/index.js';
import { state } from '../store.js';
import { get, fetchBlob } from '../api.js';
import { ArraySeries } from '../chart/ring.js';
import { TimeChart, ChartGroup } from '../chart/timeseries.js';
import { historyArrays, stageTotals } from '../series.js';
import * as fmt from '../fmt.js';
import { toastErr, table } from '../ui.js';
import { devicePicker } from './dashboard.js';

const SPANS = [['15m', 900], ['1h', 3600], ['24h', 86400], ['7d', 604800], ['30d', 2592000]];
const SERIES = [
  { id: 'temp', s: 0, sp: 3, env: [5, 6], color: 'temp', key: 'k-temp', unit: '°C', minSpan: 2 },
  { id: 'hum', s: 1, sp: 4, env: [7, 8], color: 'hum', key: 'k-hum', unit: '%', minSpan: 5 },
  { id: 'cur', s: 2, sp: null, env: [9, 10], color: 'cur', key: 'k-cur', unit: 'A', minSpan: 2 },
];
const STAGES = ['blower', 'cool', 'heat', 'hum', 'dehum'];

export function mount(root, args, scope) {
  const dev = state.dev;
  let span = Number(storage.get('gw.tspan')) || 3600;
  if (!SPANS.some(([, s]) => s === span)) span = 3600;
  const show = { temp: true, hum: true, cur: true, set: true, env: true };
  let data = null;
  let resp = null;
  let tableOn = false;

  const seg = h('div.seg', { role: 'group', 'aria-label': t('tr.span') }, SPANS.map(([k, s]) => h('button', {
    type: 'button', 'aria-pressed': s === span ? 'true' : 'false', text: t(`win.${k}`), on: { click: () => { span = s; storage.set('gw.tspan', String(s)); paintSeg(); load(true); } },
  })));
  const chip = (id, label, keyCls) => {
    const b = h('button.chip', { type: 'button', 'aria-pressed': 'true' }, h('i.key', { class: keyCls }), label);
    b.addEventListener('click', () => { show[id] = !show[id]; b.setAttribute('aria-pressed', show[id] ? 'true' : 'false'); build(); });
    return b;
  };
  const chips = [chip('temp', t('kpi.temp'), 'k-temp'), chip('hum', t('kpi.hum'), 'k-hum'), chip('cur', t('kpi.cur'), 'k-cur'),
    chip('set', t('lg.setpoint'), 'k-set'), chip('env', t('lg.envelope'), 'k-env')];
  const envChip = chips[4];
  const tblBtn = h('button.btn', { type: 'button', 'aria-pressed': 'false' }, t('tr.table'));
  tblBtn.addEventListener('click', () => { tableOn = !tableOn; tblBtn.setAttribute('aria-pressed', String(tableOn)); paintTable(); });
  const csvBtn = h('button.btn', { type: 'button' }, icon('down'), 'CSV');
  csvBtn.addEventListener('click', async () => {
    csvBtn.disabled = true;
    try {
      const { blob, filename } = await fetchBlob(`/devices/${dev}/history.csv`, { span, res: 1 });
      download(blob, filename || `mestio-d${dev}.csv`);
    } catch (e) { toastErr(e); }
    csvBtn.disabled = false;
  });
  const info = h('span.muted');
  const stack = h('div.stack.chart-host');
  const hoursBox = h('div');
  const tableBox = h('div');

  replace(root, h('div.page',
    h('div.page-head', h('h1', { text: t('nav.trends') }), devicePicker(scope)),
    h('div.filters', seg, h('div.btn-row', chips), h('span.grow'), info, tblBtn, csvBtn),
    h('section.panel', stack),
    tableBox,
    h('section.panel', h('div.panel-h', h('h2', { text: t('tr.hours') }), h('span.grow'), h('span.meta', { text: t('tr.hours_note') })), hoursBox)));

  let group = null;
  let charts = [];
  const teardown = () => {
    charts.forEach((c) => c.destroy());
    charts = [];
    if (group) group.destroy();
    group = null;
    replace(stack);
  };
  scope.add(teardown);

  function paintSeg() {
    [...seg.children].forEach((b, i) => b.setAttribute('aria-pressed', SPANS[i][1] === span ? 'true' : 'false'));
  }

  let sig = '';
  function build() {
    if (!data) { teardown(); return; }
    const src = new ArraySeries(data.t, data.v, data.f);
    const coarse = resp.dt >= 60;
    envChip.disabled = !coarse;
    const t0 = data.t.length ? data.t[0] : Date.now() - span * 1000;
    const t1 = data.t.length ? data.t[data.t.length - 1] + resp.dt * 1000 : Date.now();
    const nsig = JSON.stringify([show, resp.dt, span]);
    if (nsig === sig && charts.length) {
      // same layout: swap the data in place (no canvas re-creation, hover survives)
      for (const c of charts) { c.setSource(src); c.fixed(t0, t1); }
      return;
    }
    sig = nsig;
    teardown();
    group = new ChartGroup(stack, (tm) => (resp.dt >= 60 ? fmt.dateTime(tm, false) : fmt.dateTime(tm)));
    const vis = SERIES.filter((x) => show[x.id]);
    if (!vis.length) {
      stack.appendChild(h('div.empty', { text: t('tr.none') }));
      sig = '';
      return;
    }
    for (const x of vis) {
      const host = h('div.h160');
      const lg = h('div.lg', h('span', h('i.key', { class: x.key }), coarse ? t('lg.avg') : t('lg.actual')));
      if (coarse && show.env) lg.append(h('span', h('i.key.k-env'), t('lg.envelope')));
      if (x.sp !== null && show.set) lg.append(h('span', h('i.key.k-set'), t('lg.setpoint')));
      stack.appendChild(h('div.tc-wrap', h('div.tc-title', h('b', { text: t(`kpi.${x.id}`) }), h('span', { text: x.unit }), h('span.grow'), lg), host));
      const c = new TimeChart(host, {
        group, label: t(`kpi.${x.id}`), unit: x.unit, fmt: (v) => fmt.num(v, 1), minSpan: x.minSpan, timeTick: fmt.tickLabel,
        tick: (v, d) => fmt.num(v, d),
        lines: [{ s: x.s, color: x.color, key: x.key, label: () => (coarse ? t('lg.avg') : t('lg.actual')) }],
        setpoint: x.sp !== null && show.set ? { s: x.sp, label: () => t('lg.setpoint') } : null,
        envelope: coarse && show.env ? { lo: x.env[0], hi: x.env[1], label: () => t('lg.envelope') } : null,
      });
      c.setSource(src);
      c.fixed(t0, t1);
      charts.push(c);
    }
    const lanes = h('div.lanes');
    stack.appendChild(h('div.tc-wrap', h('div.tc-title', h('b', { text: t('dash.stages') })), lanes));
    const lc = new TimeChart(lanes, {
      group, label: t('dash.stages'), noXAxis: true,
      lanes: [{ bit: 1, label: () => t('stage.cool') }, { bit: 2, label: () => t('stage.heat') }, { bit: 3, label: () => t('stage.hum') }, { bit: 4, label: () => t('stage.dehum') }],
    });
    lc.setSource(src);
    lc.fixed(t0, t1);
    charts.push(lc);
  }

  function paintHours() {
    if (!resp) { replace(hoursBox); return; }
    const tot = stageTotals(resp);
    replace(hoursBox, table([
      { label: t('tr.stage'), cell: (k) => t(`stage.${k}`) },
      { label: t('tr.runtime'), cls: 'n', cell: (k) => fmt.hoursMin(tot[k].on) },
      { label: t('tr.duty'), cls: 'n', cell: (k) => fmt.pct(tot[k].duty, 0) },
      { label: '', cell: (k) => h('div.meter', { role: 'presentation' }, meterFill(tot[k].duty)) },
    ], STAGES, { caption: t('tr.hours') }));
  }

  function meterFill(v) {
    const i = h('i');
    i.style.width = `${Math.round((v || 0) * 100)}%`;
    return i;
  }

  function paintTable() {
    if (!tableOn || !resp) { replace(tableBox); return; }
    const coarse = resp.dt >= 60;
    const idx = [];
    for (let i = resp.n - 1; i >= 0; i--) idx.push(i);
    const v = (arr, i) => (arr && arr[i] !== null && arr[i] !== undefined ? fmt.num(arr[i] / 10, 1) : fmt.DASH);
    const cols = [
      { label: t('tr.time'), cls: 'nowrap', cell: (i) => fmt.dateTime(data.t[i], !coarse) },
      { label: `${t('kpi.temp')} (°C)`, cls: 'n', cell: (i) => v(resp.ch.temp, i) },
      { label: `${t('kpi.hum')} (%)`, cls: 'n', cell: (i) => v(resp.ch.hum, i) },
      { label: `${t('kpi.cur')} (A)`, cls: 'n', cell: (i) => v(resp.ch.cur, i) },
      { label: t('tr.set_t'), cls: 'n', cell: (i) => v(resp.ch.st, i) },
      { label: t('tr.set_h'), cls: 'n', cell: (i) => v(resp.ch.sh, i) },
    ];
    if (coarse) {
      cols.push({ label: t('tr.t_range'), cls: 'n', cell: (i) => `${v(resp.min.temp, i)} – ${v(resp.max.temp, i)}` });
      cols.push({ label: t('tr.h_range'), cls: 'n', cell: (i) => `${v(resp.min.hum, i)} – ${v(resp.max.hum, i)}` });
    }
    replace(tableBox, h('section.panel', h('div.panel-h', h('h2', { text: t('tr.table') }), h('span.grow'), h('span.meta', { text: t('tr.rows', { n: resp.n }) })),
      table(cols, idx, { caption: t('tr.table') })));
  }

  // A newer load always supersedes an older one: the in-flight request is aborted and any late
  // response is ignored (gen check), so a span click is never dropped or answered with stale data.
  let gen = 0;
  let ctl = null;
  async function load(user) {
    if (!user && ctl) return; // background refresh never preempts a running load
    if (ctl) ctl.abort();
    const my = ++gen;
    const c = new AbortController();
    ctl = c;
    if (user) stack.classList.add('loading');
    try {
      const r = await get(`/devices/${dev}/history`, { span, res: 1, stages: 1 }, { signal: c.signal });
      if (scope.dead || my !== gen) return;
      resp = r;
      data = historyArrays(r, Date.now());
      info.textContent = t('tr.res', { s: fmt.duration(r.dt) });
      build();
      paintHours();
      paintTable();
    } catch (e) {
      if (!scope.dead && user && my === gen) toastErr(e);
    } finally {
      if (my === gen) {
        ctl = null;
        stack.classList.remove('loading');
      }
    }
  }
  scope.add(() => { if (ctl) ctl.abort(); });

  load(true);
  // keep short spans current; long spans change slowly
  scope.every(15000, () => { if (!document.hidden && span <= 3600) load(false); });
  scope.every(120000, () => { if (!document.hidden && span > 3600) load(false); });
}
