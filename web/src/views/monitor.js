// Dashboard: KPI row (temperature, humidity, current, mode — with setpoint and Δ), two synchronized
// live band charts (actual, setpoint dashed, deadband shaded, alarm limits dotted) with the stage
// activity strip, and a side column with the equipment matrix, active alarms and Modbus RTT.
import { h, sprite, setText, toggle, replace, storage } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, live, devName, enabledDevices } from '../store.js';
import { derive, equipment, EQUIPMENT } from '../live.js';
import { S_TEMP, S_HUM, S_ST, S_SH } from '../series.js';
import { TimeChart, ChartGroup, sparkline } from '../chart/timeseries.js';
import * as fmt from '../fmt.js';
import { get } from '../api.js';
import { deviceStatus, templateFor } from '../device_templates.js';
import { devicePicker } from '../device_picker.js';

const WINDOWS = [[5, '5m'], [15, '15m'], [60, '1h']];


function kpi(label) {
  const val = h('span.v');
  const unit = h('span.u');
  const sub = h('div.sub');
  const lbl = h('div.lbl', { text: label });
  const el = h('div.kpi', lbl, h('div.val', val, unit), sub);
  return { el, val, unit, sub, lbl, valWrap: el.children[1] };
}

export function mount(root, args, scope, { deviceId = state.dev, popup = false } = {}) {
  const device = state.devices.find((d) => d.id === deviceId);
  let win = Number(storage.get('gw.win')) || 15;
  if (!WINDOWS.some(([m]) => m === win)) win = 15;
  const seg = h('div.seg', { role: 'group', 'aria-label': t('dash.window') });
  const segBtns = WINDOWS.map(([m, lbl]) => h('button', { type: 'button', 'aria-pressed': m === win ? 'true' : 'false', text: t(`win.${lbl}`), on: { click: () => setWin(m) } }));
  seg.append(...segBtns);

  const kT = kpi(t('kpi.temp'));
  const kH = kpi(t('kpi.hum'));
  const kC = kpi(t('kpi.cur'));
  const kM = kpi(t('kpi.mode'));
  const kAll = [kT, kH, kC, kM];
  kT.unit.textContent = '°C';
  kH.unit.textContent = '%';
  kC.unit.textContent = 'A';
  kM.valWrap.classList.add('word');
  kM.sub.classList.add('stgs');

  // ---- charts ----
  const main = h('div.dash-main.chart-host');
  const group = new ChartGroup(main, (tm) => fmt.dateTime(tm + (state.srvValid ? state.srvOffset : 0)));
  scope.add(() => group.destroy());
  const legend = (k) => h('div.lg',
    h('span', h('i.key', { class: k }), t('lg.actual')),
    h('span', h('i.key.k-set'), t('lg.setpoint')),
    h('span', h('i.key.k-band'), t('lg.deadband')),
    h('span.lim', h('i.key.k-lim'), t('lg.limits')));
  const tLeg = legend('k-temp');
  const hLeg = legend('k-hum');
  const tLim = tLeg.querySelector('.lim');
  const hLim = hLeg.querySelector('.lim');
  const tHost = h('div');
  const hHost = h('div.h160');
  const lHost = h('div.lanes');
  const dv = () => derive(live(deviceId));
  const f1 = (v) => fmt.num(v, 1);
  const tChart = new TimeChart(tHost, {
    group, label: t('kpi.temp'), unit: '°C', fmt: f1, minSpan: 2, marker: true, timeTick: (tm, unit) => fmt.tickLabel(tm + (state.srvValid ? state.srvOffset : 0), unit),
    tick: (v, d) => fmt.num(v, d),
    lines: [{ s: S_TEMP, color: 'temp', key: 'k-temp', label: () => t('kpi.temp') }],
    setpoint: { s: S_ST, label: () => t('lg.setpoint') },
    band: () => { const d = dv(); return d && d.heatDev !== null && d.coolDev !== null ? [d.heatDev, d.coolDev] : null; },
    limits: () => { const d = dv(); return d ? [d.loTemp, d.hiTemp] : null; },
  });
  const hChart = new TimeChart(hHost, {
    group, label: t('kpi.hum'), unit: '%', fmt: f1, minSpan: 5, marker: true, timeTick: (tm, unit) => fmt.tickLabel(tm + (state.srvValid ? state.srvOffset : 0), unit),
    tick: (v, d) => fmt.num(v, d),
    lines: [{ s: S_HUM, color: 'hum', key: 'k-hum', label: () => t('kpi.hum') }],
    setpoint: { s: S_SH, label: () => t('lg.setpoint') },
    band: () => { const d = dv(); return d && d.humDev !== null && d.dehumDev !== null ? [d.humDev, d.dehumDev] : null; },
    limits: () => { const d = dv(); return d ? [d.loHum, d.hiHum] : null; },
  });
  const lChart = new TimeChart(lHost, {
    group, label: t('dash.stages'), noXAxis: true,
    lanes: [{ bit: 1, label: () => t('stage.cool') }, { bit: 2, label: () => t('stage.heat') }, { bit: 3, label: () => t('stage.hum') }, { bit: 4, label: () => t('stage.dehum') }],
  });
  const charts = [tChart, hChart, lChart];
  scope.add(() => charts.forEach((c) => c.destroy()));

  const title = (txt, unit) => h('h2', txt, h('span.unit', { text: unit }));
  const tPanel = h('section.panel', h('div.panel-h', title(t('kpi.temp'), '°C'), h('span.grow'), tLeg), tHost);
  const hPanel = h('section.panel', h('div.panel-h', title(t('kpi.hum'), '%'), h('span.grow'), hLeg), hHost, lHost);
  main.append(h('section.panel', h('div.kpis', kT.el, kH.el, kC.el, kM.el)), tPanel, hPanel);

  // ---- side column ----
  const eqBox = h('div.eq');
  const almBox = h('div.alist');
  const almMeta = h('span.meta');
  const rttCanvas = h('canvas', { 'aria-hidden': 'true' });
  const rttV = h('div.v');
  const rttCrc = h('span');
  const rttTmo = h('span');
  const rttS = h('div.s', rttCrc, rttTmo);
  rttV.title = t('dash.rtt');
  const side = h('div.dash-side',
    h('section.panel', h('div.panel-h', h('h2', { text: t('dash.equipment') })), eqBox),
    h('section.panel', h('div.panel-h', h('h2', { text: t('dash.alarms') }), h('span.grow'), almMeta, h('a', { href: '#/alarms', text: t('dash.all') })), almBox),
    h('section.panel', h('div.panel-h', h('h2', { text: t('dash.comm') })), h('div.rtt', rttCanvas, h('div', rttV, rttS))));

  const noData = h('div.chart-wait.panel', { role: 'status', text: t('devices.wait_data') });
  main.appendChild(noData);
  const head = h('div.page-head', h('div', h('h1', { text: `${devName(deviceId)} · ${t('nav.monitor')}` }),
    h('p.meta', { text: `${templateFor(device, state.templates)?.name || device?.template_id || 'MEX150'} · ${t('mb.slave')} ${device?.slave ?? '?'}` })), popup ? null : devicePicker(scope), h('span.grow'), seg);
  replace(root, h('div.page', head, h('div.dash', main, side)));

  function setWin(m) {
    win = m;
    storage.set('gw.win', String(m));
    segBtns.forEach((b, i) => b.setAttribute('aria-pressed', WINDOWS[i][0] === m ? 'true' : 'false'));
    charts.forEach((c) => c.follow(m * 60000));
  }

  // ---- painting ----
  const eqItems = EQUIPMENT.map(([key, n]) => {
    const meta = state.meta.coils.find((c) => c.n === n);
    const dot = h('span.dot.unk', { role: 'img', 'aria-label': t('eq.unknown') });
    const f = h('span.f', { hidden: true, text: t('dash.fault') });
    const el = h('div.eq-i.unk', dot, h('span', { text: meta ? name(meta) : key }), f);
    return { key, el, dot, f, s: 'unk' };
  });
  eqBox.append(...eqItems.map((x) => x.el));

  // KPI sub-lines are rebuilt only when their text changes (signature), not on every snap
  const subs = (k, sig, build) => { if (k.sig !== sig) { k.sig = sig; k.sub.replaceChildren(...build()); } };
  function paintKpis() {
    const st = live(deviceId);
    const deviceState = deviceStatus(device, st, Date.now(), state.pollMs, state.comm.get(deviceId));
    const ready = deviceState === 'online';
    const d = ready ? derive(st) : null;
    tPanel.hidden = !ready; hPanel.hidden = !ready; noData.hidden = ready;
    noData.textContent = t(`devices.status.${deviceState}`);
    kAll.forEach((k) => toggle(k.el, 'stale', !ready));
    if (!d) {
      kAll.forEach((k) => { setText(k.val, fmt.DASH); subs(k, '', () => []); });
      return;
    }
    const band = (v, set, lo, hi) => (v === null || set === null ? false : v < set - lo || v > set + hi);
    const dSub = (k, v, set, lo, hi) => {
      const sp = t('kpi.set', { v: fmt.num(set, 1) });
      const dl = `Δ ${fmt.signed(v - set, 1)}`;
      const w = band(v, set, lo ?? 0, hi ?? 0);
      subs(k, `${sp}|${dl}|${w}`, () => [h('span', sp), h(`span${w ? '.warn-t' : ''}`, dl)]);
    };
    setText(kT.val, fmt.num(d.temp, 1));
    dSub(kT, d.temp, d.setTemp, d.heatDev, d.coolDev);
    setText(kH.val, fmt.num(d.hum, 1));
    dSub(kH, d.hum, d.setHum, d.humDev, d.dehumDev);
    setText(kC.val, fmt.num(d.current, 1));
    const running = d.stages.cool + d.stages.heat + d.stages.hum + d.stages.dehum;
    const cs = [t('kpi.stages_on', { n: running }), d.stages.blower ? t('kpi.blower_on') : t('kpi.blower_off')];
    subs(kC, cs.join('|'), () => cs.map((x) => h('span', x)));
    let word;
    if (!d.running) word = d.stopDelay && d.delay ? t('run.stopping', { n: d.delay }) : t('run.stop');
    else if (d.runDelay && d.delay) word = t('run.starting', { n: d.delay });
    else if (!d.mode.length) word = t('mode.idle');
    else word = d.mode.map((m) => t(`mode.${m}`)).join(' · ');
    setText(kM.val, word);
    const pips = (n, max) => h('span.pips', Array.from({ length: max }, (_, i) => h(`i${i < n ? '.on' : ''}`)));
    subs(kM, `${d.stages.cool}${d.stages.heat}${d.stages.hum}${d.stages.dehum}`, () => [
      h('span.stg', t('stage.cool'), pips(d.stages.cool, 3)),
      h('span.stg', t('stage.heat'), pips(d.stages.heat, 4)),
      h('span.stg', t('stage.hum'), pips(d.stages.hum, 2)),
      h('span.stg', t('stage.dehum'), pips(d.stages.dehum, 1))]);
    // limits legend only when a limit is enabled
    const anyT = d.loTemp !== null || d.hiTemp !== null;
    const anyH = d.loHum !== null || d.hiHum !== null;
    tLim.hidden = !anyT;
    hLim.hidden = !anyH;
  }

  function paintEquipment() {
    const st = live(deviceId);
    const eq = equipment(st.coils);
    const ok = deviceStatus(device, st, Date.now(), state.pollMs, state.comm.get(deviceId)) === 'online';
    eq.forEach((e, i) => {
      const it = eqItems[i];
      // no data = unknown (hollow dashed), distinct from a machine that reports "off"
      const s = !ok ? 'unk' : e.fault ? 'alarm' : e.on ? 'ok' : 'off';
      if (it.s === s) return;
      it.s = s;
      it.dot.className = `dot ${s}`;
      it.f.hidden = s !== 'alarm';
      it.el.className = `eq-i${s === 'off' || s === 'unk' ? ` ${s}` : ''}`;
      it.dot.setAttribute('aria-label', t({ unk: 'eq.unknown', alarm: 'dash.fault', ok: 'eq.on', off: 'eq.off' }[s]));
    });
  }

  let almTimes = []; // [{el, since}] of the rendered rows: the 10 s refresh rewrites only these
  const durText = (since) => {
    const now = state.srvValid ? Date.now() + state.srvOffset : null;
    return since && now ? fmt.duration((now - since) / 1000) : fmt.DASH;
  };
  function paintAlarms() {
    const list = state.alarms.filter((a) => a.dev === deviceId);
    const multi = enabledDevices().length > 1;
    setText(almMeta, list.length ? t('dash.alarm_count', { n: list.length }) : '');
    almTimes = [];
    if (!list.length) {
      replace(almBox, h('div.empty', { text: t('alarms.none') }));
      return;
    }
    replace(almBox, list.slice(0, 6).map((a) => {
      const m = state.alarmMeta.get(a.id);
      const tm = h('time', { text: durText(a.since), title: fmt.dateTime(a.since) });
      almTimes.push({ el: tm, since: a.since });
      return h(`div.alist-i${a.acked ? '' : '.unacked'}`,
        h(`span.sev.s${a.sev}`, { title: t(`sev.${a.sev}`) }, sprite(`sv${a.sev}`), h('span.sr', { text: t(`sev.${a.sev}`) })),
        h('span.nm', { text: `${m ? name(m) : a.id}${multi ? ` · ${devName(a.dev)}` : ''}` }), tm);
    }), list.length > 6 ? h('div.alist-i', h('span'), h('span.nm.muted', { text: t('dash.more', { n: list.length - 6 }) }), h('span')) : null);
  }
  const durations = () => { for (const x of almTimes) setText(x.el, durText(x.since)); };

  function paintComm() {
    const c = state.comm.get(deviceId);
    rttS.hidden = !c;
    if (!c) { setText(rttV, fmt.DASH); return; }
    setText(rttV, c.online ? `${c.rtt} ms` : fmt.DASH);
    setText(rttCrc, `CRC ${c.err.crc}`);
    setText(rttTmo, `${t('stats.timeout')} ${c.err.timeout}`);
    sparkline(rttCanvas, c.rtts, 'temp');
  }

  let devOff = [];
  function bindDev() {
    const d = deviceId;
    const src = () => state.series.get(d) && state.series.get(d).ring;
    charts.forEach((c) => { if (src()) c.setSource(src()); });
    devOff = [
      on(`live:${d}`, () => { paintKpis(); paintEquipment(); tChart.invalidate(); hChart.invalidate(); }),
      on(`series:${d}`, () => { const s = src(); if (s) charts.forEach((c) => { if (c.src !== s) c.setSource(s); }); }),
      on(`comm:${d}`, () => { paintKpis(); paintEquipment(); paintComm(); }),
    ];
    paintKpis();
    paintEquipment();
    paintComm();
  }
  scope.add(() => devOff.forEach((f) => f()));
  scope.add(on('alarms', paintAlarms));
  scope.add(on('alarmMeta', paintAlarms));
  scope.every(10000, durations);
  // the "last value · age" line of stale KPIs ages with the clock
  scope.add(on('clock', () => { paintKpis(); paintEquipment(); }));
  setWin(win);
  bindDev();
  paintAlarms();
  // RTT avg/max are not in WS comm frames: one stats read on mount
  get(`/devices/${deviceId}/stats`).then((s) => {
    if (scope.dead) return;
    rttS.title = `${t('stats.avg')} ${s.rtt_ms.avg} ms · ${t('stats.max')} ${s.rtt_ms.max} ms`;
  }).catch(() => {});
}
