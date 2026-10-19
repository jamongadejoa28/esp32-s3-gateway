// Alarms: active list (live via WS, select + acknowledge, acknowledge all) and history (device /
// severity filters, cursor paging, CSV export).
import { h, icon, replace, download, setText, toggle } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, can, devName } from '../store.js';
import { post, get, fetchBlob } from '../api.js';
import * as fmt from '../fmt.js';
import { sevMark, toast, toastErr } from '../ui.js';

/** Display of an alarm `value` (raw of its value register; temperature/humidity alarms are ×10). */
export function alarmValue(id, v) {
  if (/(^|_)temp$/.test(id)) return `${fmt.num(v / 10, 1)} °C`;
  if (/(^|_)hum$/.test(id)) return `${fmt.num(v / 10, 1)} %`;
  return '';
}

const alarmName = (id) => { const m = state.alarmMeta.get(id); return m ? name(m) : id; };

export function mount(root, args, scope) {
  const tab = args[0] === 'history' ? 'history' : 'active';
  const multi = state.devices.filter((d) => d.enabled).length > 1;
  const tabs = h('div.tabs', { role: 'tablist' },
    h('a', { href: '#/alarms', role: 'tab', 'aria-selected': String(tab === 'active') }, t('alarms.active')),
    h('a', { href: '#/alarms/history', role: 'tab', 'aria-selected': String(tab === 'history') }, t('alarms.history')));
  const body = h('div', { role: 'tabpanel' });
  replace(root, h('div.page', h('div.page-head', h('h1', { text: t('nav.alarms') })), tabs, body));
  if (tab === 'active') active(body, scope, multi);
  else history(body, scope, multi);
}

function active(body, scope, multi) {
  const sel = new Set();
  const op = can('operator');
  const ackSel = h('button.btn', { type: 'button', disabled: true }, icon('check'), t('alarms.ack_sel'));
  const ackAll = h('button.btn', { type: 'button' }, t('alarms.ack_all'));
  const count = h('span.meta');
  const tbody = h('tbody');
  const all = h('input', { type: 'checkbox', 'aria-label': t('alarms.sel_all') });
  const head = h('tr',
    op ? h('th.act', all) : null,
    h('th', { scope: 'col', text: t('alarms.col.sev') }), h('th', { scope: 'col', text: t('alarms.col.alarm') }),
    multi ? h('th', { scope: 'col', text: t('alarms.col.dev') }) : null,
    h('th.ts', { scope: 'col', text: t('alarms.col.since') }), h('th.n', { scope: 'col', text: t('alarms.col.dur') }),
    h('th.n', { scope: 'col', text: t('alarms.col.value') }), h('th', { scope: 'col', text: t('alarms.col.ack') }));
  body.append(h('section.panel',
    h('div.panel-h', h('h2', { text: t('alarms.active') }), count, h('span.grow'), op ? h('div.btn-row', ackSel, ackAll) : null),
    h('div.tbl-wrap', h('table.tbl', h('caption.sr', { text: t('alarms.active') }), h('thead', head), tbody))));

  const ack = async (b) => {
    try {
      await post('/alarms/ack', b);
      sel.clear();
      toast(t('alarms.acked'));
    } catch (e) { toastErr(e); }
    paint();
  };
  ackSel.addEventListener('click', () => { if (sel.size) ack({ keys: [...sel] }); });
  ackAll.addEventListener('click', () => ack({ all: true }));
  all.addEventListener('change', () => {
    sel.clear();
    if (all.checked) state.alarms.filter((a) => !a.acked).forEach((a) => sel.add(a.key));
    paint();
  });

  // Rows are reconciled by alarm key (never rebuilt wholesale), so a focused checkbox keeps focus
  // across WS alarm frames and the 10 s duration refresh, which only rewrites the duration text.
  const rowMap = new Map(); // key -> { tr, cb, act, dur, a, sig }
  let emptyRow = null;
  const durText = (a) => {
    const now = state.srvValid ? Date.now() + state.srvOffset : null;
    return a.since && now ? fmt.duration((now - a.since) / 1000) : fmt.DASH;
  };
  function rowFor(a) {
    let r = rowMap.get(a.key);
    if (!r) {
      const cb = op ? h('input', { type: 'checkbox' }) : null;
      r = { tr: h('tr'), cb, act: op ? h('td.act', cb) : null, dur: h('td.n'), sig: '' };
      if (cb) cb.addEventListener('change', () => { if (cb.checked) sel.add(a.key); else sel.delete(a.key); paint(); });
      rowMap.set(a.key, r);
    }
    r.a = a;
    const sig = JSON.stringify([a.sev, a.id, a.dev, a.since, a.value, a.acked, a.ack_by, a.ack_ts, state.alarmMeta.has(a.id)]);
    if (sig !== r.sig) {
      r.sig = sig;
      const cells = [h('td', sevMark(a.sev)),
        h('td.nm', { text: alarmName(a.id) }),
        multi ? h('td', { text: devName(a.dev) }) : null,
        h('td.ts', { text: fmt.dateTime(a.since) }),
        r.dur,
        h('td.n', { text: alarmValue(a.id, a.value) }),
        h('td', a.acked ? h('span.muted', { text: t('alarms.acked_by', { u: a.ack_by || '—', t: fmt.clock(a.ack_ts, false) }) }) : h('span.alarm-t', { text: t('alarms.unacked') }))];
      if (r.act) {
        while (r.tr.lastChild && r.tr.lastChild !== r.act) r.tr.removeChild(r.tr.lastChild);
        if (!r.act.parentNode) r.tr.appendChild(r.act);
        for (const c of cells) if (c) r.tr.appendChild(c);
      } else replace(r.tr, cells);
      if (r.cb) {
        r.cb.disabled = !!a.acked;
        r.cb.setAttribute('aria-label', t('alarms.sel_x', { name: alarmName(a.id) }));
      }
    }
    if (r.cb) r.cb.checked = sel.has(a.key);
    toggle(r.tr, 'unacked', !a.acked);
    toggle(r.tr, 'sel', sel.has(a.key));
    setText(r.dur, durText(a));
    return r.tr;
  }

  function paint() {
    const list = state.alarms;
    for (const k of [...sel]) if (!list.some((a) => a.key === k && !a.acked)) sel.delete(k);
    const unacked = list.filter((a) => !a.acked).length;
    count.textContent = list.length ? t('alarms.counts', { n: list.length, u: unacked }) : '';
    ackSel.disabled = !sel.size;
    ackAll.disabled = !unacked;
    all.disabled = !unacked;
    all.checked = unacked > 0 && sel.size === unacked;
    all.indeterminate = sel.size > 0 && sel.size < unacked;
    const keys = new Set(list.map((a) => a.key));
    for (const k of [...rowMap.keys()]) if (!keys.has(k)) rowMap.delete(k);
    if (!list.length) {
      if (!emptyRow) emptyRow = h('tr', h('td.empty', { colspan: 8, text: t('alarms.none') }));
      if (tbody.firstChild !== emptyRow || tbody.childNodes.length !== 1) replace(tbody, emptyRow);
      return;
    }
    const trs = list.map(rowFor);
    const kids = tbody.children;
    if (kids.length === trs.length && trs.every((tr, i) => kids[i] === tr)) return;
    // order changed: re-seat rows, then put focus back where it was (moving a node blurs it)
    const f = document.activeElement;
    const had = f && tbody.contains(f) ? f : null;
    replace(tbody, trs);
    if (had && had.isConnected && !had.disabled) had.focus();
  }
  function durations() {
    for (const r of rowMap.values()) setText(r.dur, durText(r.a));
  }
  scope.add(on('alarms', paint));
  scope.add(on('alarmMeta', paint));
  scope.every(10000, durations);
  paint();
}

function history(body, scope, multi) {
  let next = null;
  let items = [];
  const devSel = h('select.inp', { 'aria-label': t('alarms.col.dev') }, h('option', { value: '', text: t('alarms.all_dev') }),
    state.devices.map((d) => h('option', { value: String(d.id), text: d.name })));
  const sevSel = h('select.inp', { 'aria-label': t('alarms.min_sev') }, h('option', { value: '', text: t('alarms.all_sev') }),
    [3, 2, 1].map((s) => h('option', { value: String(s), text: t('alarms.sev_min', { s: t(`sev.${s}`) }) })));
  const csv = h('button.btn', { type: 'button' }, icon('down'), 'CSV');
  const more = h('button.btn', { type: 'button', hidden: true, text: t('more') });
  const tbody = h('tbody');
  const q = () => ({ dev: devSel.value, sev: sevSel.value });
  body.append(
    h('div.filters', multi ? h('div', devSel) : null, h('div', sevSel), h('span.grow'), csv),
    h('section.panel', h('div.tbl-wrap', h('table.tbl', h('caption.sr', { text: t('alarms.history') }),
      h('thead', h('tr', h('th', { scope: 'col', text: t('alarms.col.time') }), h('th', { scope: 'col', text: t('alarms.col.event') }),
        h('th', { scope: 'col', text: t('alarms.col.sev') }), h('th', { scope: 'col', text: t('alarms.col.alarm') }),
        multi ? h('th', { scope: 'col', text: t('alarms.col.dev') }) : null,
        h('th.n', { scope: 'col', text: t('alarms.col.value') }), h('th', { scope: 'col', text: t('alarms.col.user') }))),
      tbody)), h('div.panel-b', more)));

  const evIcon = { raise: 'alert', clear: 'check', ack: 'user' };
  function paint() {
    if (!items.length) { replace(tbody, h('tr', h('td.empty', { colspan: 7, text: t('alarms.no_history') }))); return; }
    replace(tbody, items.map((it) => h('tr',
      h('td.ts', { text: fmt.dateTime(it.ts) }),
      h('td', h('span.state-t', icon(evIcon[it.type], 's16'), t(`alarms.ev.${it.type}`))),
      h('td', sevMark(it.sev)),
      h('td.nm', { text: alarmName(it.id) }),
      multi ? h('td', { text: devName(it.dev) }) : null,
      h('td.n', { text: alarmValue(it.id, it.value) }),
      h('td', { text: it.user || '' }))));
    more.hidden = next === null;
  }
  // Each filter change starts a new generation: older responses are dropped, so the list always
  // matches the selected filters and pages from different cursors are never mixed.
  let gen = 0;
  async function load(reset) {
    if (!reset && more.disabled) return;
    const my = reset ? ++gen : gen;
    more.disabled = true;
    try {
      const r = await get('/alarms/history', { ...q(), limit: 50, before: reset ? null : next });
      if (scope.dead || my !== gen) return;
      items = reset ? r.items : items.concat(r.items);
      next = r.next;
      paint();
    } catch (e) {
      if (my === gen && !scope.dead) toastErr(e);
    }
    if (my === gen) more.disabled = false;
  }
  devSel.addEventListener('change', () => load(true));
  sevSel.addEventListener('change', () => load(true));
  more.addEventListener('click', () => load(false));
  csv.addEventListener('click', async () => {
    csv.disabled = true;
    try {
      const { blob, filename } = await fetchBlob('/alarms/history.csv', q());
      download(blob, filename || 'mestio-alarms.csv');
    } catch (e) { toastErr(e); }
    csv.disabled = false;
  });
  load(true);
}
