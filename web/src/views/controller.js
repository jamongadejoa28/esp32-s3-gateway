// Controller: run/stop with confirmation, grouped register table with inline edit (range hint,
// disabled sentinel, enum), write state pending → applied / rejected / uncertain (REST result,
// then WS "write" or a command poll), stopped-only lock while running, and raw status bits.
import { h, icon, setText, replace, toggle } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { state, on, live, can } from '../store.js';
import { derive } from '../live.js';
import * as fmt from '../fmt.js';
import { req, get, reasonText, errText } from '../api.js';
import { confirmDlg, toast, stateText } from '../ui.js';
import { deviceStatus } from '../device_templates.js';
import { devicePicker } from '../device_picker.js';

const GROUPS = ['setpoint', 'deviation', 'delay', 'limits', 'calibration', 'options', 'info'];

/**
 * Write a register and follow the command to its final state.
 * onState(state, reason, raw) is called for pending and for the final outcome.
 * Returns an unsubscribe function for the WS listener.
 */
export async function writeRegister(dev, addr, body, onState) {
  const path = addr === 40005 ? `/devices/${dev}/run` : `/devices/${dev}/registers/${addr}`;
  const method = addr === 40005 ? 'POST' : 'PUT';
  let r;
  try {
    r = await req(method, path, { body, ok: [202, 409], timeout: 10000 });
  } catch (e) {
    onState('error', errText(e));
    return;
  }
  const b = r.body || {};
  if (r.status === 200) { onState('applied', null, b.raw); return; }
  if (r.status === 409) { onState('rejected', reasonText(b.reason)); return; }
  if (b.state === 'uncertain') { onState('uncertain', reasonText(b.reason)); return; }
  onState('pending', null);
  // final state arrives as WS "write" (any origin) or via the command endpoint
  await new Promise((resolve) => {
    let done = false;
    const finish = (st, reason, raw) => {
      if (done) return;
      done = true;
      off();
      clearTimeout(poll);
      onState(st, reason, raw);
      resolve();
    };
    const off = on('write', (m) => {
      if (m.dev === dev && m.cmd === b.cmd) finish(m.state, m.reason ? reasonText(m.reason) : null, m.raw);
    });
    let tries = 0;
    const check = async () => {
      try {
        const c = await get(`/devices/${dev}/commands/${b.cmd}`);
        if (c.state !== 'pending') { finish(c.state, c.reason ? reasonText(c.reason) : null, c.raw); return; }
      } catch (e) {
        if (e.status === 404) { finish('uncertain', t('wr.evicted')); return; }
      }
      if (++tries < 8) poll = setTimeout(check, 2000);
      else finish('uncertain', t('wr.timeout'));
    };
    let poll = setTimeout(check, 3000);
  });
}

export function mount(root, args, scope) {
  const dev = state.dev;
  const canWrite = can('operator');
  const regs = state.meta.regs;
  const rows = new Map(); // addr -> row model

  // ---- run panel ----
  const runDot = h('span.dot');
  const runTxt = h('span');
  const runSub = h('span.muted');
  const runBtn = h('button.btn', { type: 'button', hidden: !canWrite });
  const runState = h('span.state-t');
  const runPanel = h('section.panel', h('div.runbar', h('div.state', runDot, runTxt), runSub, h('span.grow'), runState, runBtn));
  let runBusy = false; // a run/stop command is in flight: no second command until it settles
  runBtn.addEventListener('click', async () => {
    const d = derive(live(dev));
    if (!d || runBusy) return;
    const start = !d.running;
    const ok = await confirmDlg({
      title: t(start ? 'ctl.start_q' : 'ctl.stop_q'),
      text: t(start ? 'ctl.start_text' : 'ctl.stop_text', { n: start ? live(dev).regs['40018'] ?? '—' : live(dev).regs['40019'] ?? '—' }),
      ok: t(start ? 'ctl.start' : 'ctl.stop'),
      danger: !start,
    });
    if (!ok || runBusy) return;
    runBusy = true;
    runBtn.disabled = true;
    await writeRegister(dev, 40005, { run: start }, (st, reason) => {
      runState.replaceChildren(stateText(st === 'error' ? 'rejected' : st, reason));
      if (st !== 'pending') {
        runBusy = false;
        if (st === 'applied') setTimeout(() => runState.replaceChildren(), 5000);
      }
    });
    runBusy = false;
    if (!scope.dead) paint();
  });

  // ---- register table ----
  const tbody = h('tbody');
  for (const g of GROUPS) {
    const list = regs.filter((r) => r.group === g && !r.bits && !r.runbit);
    if (!list.length) continue;
    tbody.appendChild(h('tr.group', h('td', { colspan: canWrite ? 4 : 3, text: t(`grp.${g}`) })));
    for (const r of list) {
      const val = h('span.reg-v');
      const valCell = h('td.n', val);
      const st = h('span'); // write state, shown next to the edit button
      const lock = r.stopped_only ? icon('lock', 's16 lock') : null;
      if (lock) lock.setAttribute('aria-label', t('ctl.stopped_only'));
      const hint = r.access === 'rw' ? rangeHint(r) : '';
      // phones: the range column is hidden and the hint moves under the name (edit stays in view)
      const nameCell = h('td.nm', h('span', { text: name(r) }), lock ? ' ' : null, lock, hint ? h('small.rng', { text: hint }) : null);
      if (lock) nameCell.title = t('ctl.stopped_only');
      const range = h('td.muted.nowrap.rng-c', { text: hint });
      const edit = h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('ctl.edit_x', { name: name(r) }), title: t('edit') }, icon('edit'));
      const tr = h('tr', nameCell, valCell, range, canWrite ? h('td.act', st, r.access === 'rw' ? edit : null) : null);
      const row = { r, tr, val, valCell, st, edit, editing: false, busy: false };
      rows.set(r.addr, row);
      edit.addEventListener('click', () => openEditor(row));
      tbody.appendChild(tr);
    }
  }
  const table = h('div.tbl-wrap', h('table.tbl',
    h('caption.sr', { text: t('ctl.registers') }),
    h('thead', h('tr', h('th', { scope: 'col', text: t('ctl.col.name') }), h('th.n', { scope: 'col', text: t('ctl.col.value') }),
      h('th.rng-c', { scope: 'col', text: t('ctl.col.range') }), canWrite ? h('th.act', { scope: 'col' }, h('span.sr', { text: `${t('ctl.col.state')} · ${t('edit')}` })) : null)),
    tbody));

  // ---- status bits ----
  const bitBox = h('div');
  const bitDots = [];
  for (const r of regs.filter((x) => x.bits)) {
    const bits = state.meta.bits.filter((b) => b.addr === r.addr);
    if (!bits.length) continue;
    const items = bits.map((b) => {
      const dot = h('span.dot.off');
      const v = b.width > 1 ? h('span.reg-v') : null;
      bitDots.push({ b, dot, v });
      return h('div.eq-i', dot, h('span', { text: name(b) }), v);
    });
    bitBox.append(h('div.section-title', { text: `${name(r)} · ${r.addr}` }), h('div.bitgrid', items));
  }
  const bitsPanel = h('details.panel', h('summary.panel-h', h('h2', { text: t('ctl.bits') }), icon('chev')), h('div.panel-b', bitBox));

  replace(root, h('div.page.narrow',
    h('div.page-head', h('h1', { text: t('nav.controller') }), devicePicker(scope)),
    runPanel,
    h('section.panel', table),
    bitsPanel));

  // ---- behaviour ----
  function rangeHint(r) {
    let s = fmt.rangeText(r);
    if (r.disabled !== null) s += ` · ${t('disabled')} ${fmt.num(r.disabled, fmt.decimals(r.scale))}`;
    return s;
  }

  function locked(r) {
    const d = derive(live(dev));
    return r.stopped_only && (!d || d.running !== false);
  }

  function paint() {
    const st = live(dev);
    const d = derive(st);
    const ok = deviceStatus(state.devices.find((x) => x.id === dev), st, Date.now(), state.pollMs, state.comm.get(dev)) === 'online';
    // run panel
    if (!d || !ok) {
      runDot.className = 'dot';
      setText(runTxt, ok ? fmt.DASH : t('strip.offline'));
      setText(runSub, '');
      runBtn.disabled = true;
    } else {
      runDot.className = d.running ? 'dot ok' : 'dot off';
      let s = d.running ? t('run.run') : t('run.stop');
      if (d.runDelay && d.delay) s = t('run.starting', { n: d.delay });
      else if (d.stopDelay && d.delay) s = t('run.stopping', { n: d.delay });
      setText(runTxt, s);
      setText(runSub, t('ctl.delays', { a: st.regs['40018'] ?? '—', b: st.regs['40019'] ?? '—' }));
      runBtn.disabled = runBusy;
      runBtn.className = d.running ? 'btn danger' : 'btn primary';
      runBtn.replaceChildren(icon('power'), t(d.running ? 'ctl.stop' : 'ctl.start'));
    }
    // registers
    for (const row of rows.values()) {
      const raw = ok ? st.regs[String(row.r.addr)] : undefined;
      if (!row.editing) {
        const txt = raw === undefined ? fmt.DASH : fmt.regValue(row.r, raw);
        const unit = raw === undefined || fmt.isDisabled(row.r, raw) || row.r.enum ? '' : row.r.unit;
        if (row.val.dataset.v !== `${txt}|${unit}`) {
          row.val.dataset.v = `${txt}|${unit}`;
          replace(row.val, txt, unit ? h('span.u', { text: unit }) : null);
          toggle(row.val, 'dis', raw !== undefined && fmt.isDisabled(row.r, raw));
        }
      }
      const lk = locked(row.r);
      row.edit.disabled = !ok || lk || row.busy;
      row.edit.title = lk ? t('ctl.stopped_only') : t('edit');
    }
    // bits
    for (const x of bitDots) {
      const raw = ok ? st.regs[String(x.b.addr)] : undefined;
      const v = raw === undefined ? null : (raw >> x.b.lsb) & ((1 << x.b.width) - 1);
      if (x.v) {
        setText(x.v, v === null ? fmt.DASH : `${v} ${x.b.unit}`.trim());
        x.dot.className = v ? 'dot accent' : 'dot off';
      } else x.dot.className = v === null ? 'dot off' : v ? 'dot accent' : 'dot off';
    }
  }

  function openEditor(row) {
    for (const other of rows.values()) if (other.editing && other !== row) closeEditor(other);
    const r = row.r;
    const st = live(dev);
    const raw = st.regs[String(r.addr)];
    row.editing = true;
    const err = h('div.err', { role: 'alert' });
    let input;
    let disBox = null;
    if (r.enum) {
      input = h('select.inp', { 'aria-label': name(r) }, r.enum.map((e) => h('option', { value: String(e.value), text: name(e) })));
      if (raw !== undefined) input.value = String(raw);
    } else {
      input = h('input.inp.num', { type: 'text', inputmode: 'decimal', autocomplete: 'off', 'aria-label': name(r) });
      if (raw !== undefined && !fmt.isDisabled(r, raw)) input.value = String(raw / r.scale);
      if (r.disabled !== null) {
        disBox = h('input', { type: 'checkbox', id: `dis-${r.addr}`, checked: raw !== undefined && fmt.isDisabled(r, raw) });
        input.disabled = disBox.checked;
        disBox.addEventListener('change', () => { input.disabled = disBox.checked; if (!disBox.checked) input.focus(); });
      }
    }
    const save = h('button.btn.primary.sm', { type: 'submit', text: t('apply') });
    const cancel = h('button.btn.ghost.sm', { type: 'button', text: t('cancel'), on: { click: () => closeEditor(row) } });
    const form = h('form.edit-row', { novalidate: true },
      r.enum ? input : h('div.unit-wrap', input, r.unit ? h('span.u', { text: r.unit }) : null),
      disBox ? h('label.field.inline', disBox, h('span', { text: t('disabled') })) : null,
      save, cancel);
    form.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); closeEditor(row); row.edit.focus(); } });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      let body;
      if (r.enum) body = { raw: Number(input.value) };
      else if (disBox && disBox.checked) body = { raw: Math.round(r.disabled * r.scale) };
      else {
        const p = fmt.parseRegInput(r, input.value);
        if (!p.ok) {
          err.textContent = p.why === 'range' ? t('v.range_reg', { r: fmt.rangeText(r) }) : p.why === 'scale' ? t('v.scale', { n: fmt.decimals(r.scale) }) : t('v.number');
          input.setAttribute('aria-invalid', 'true');
          input.focus();
          return;
        }
        body = { value: p.value };
      }
      save.disabled = true;
      row.busy = true;
      closeEditor(row);
      await writeRegister(dev, r.addr, body, (s, reason) => {
        if (s !== 'pending') row.busy = false;
        row.st.replaceChildren(stateText(s === 'error' ? 'rejected' : s, reason));
        if (s === 'applied') {
          setTimeout(() => { if (row.st.isConnected) row.st.replaceChildren(); }, 6000);
        } else if (s === 'rejected' || s === 'error') toast(`${name(r)}: ${reason}`, 'alarm', 6000);
      });
      row.busy = false;
      if (!scope.dead) paint();
    });
    row.valCell.replaceChildren(form, err);
    input.focus();
    if (input.select) input.select();
  }

  function closeEditor(row) {
    row.editing = false;
    row.val.dataset.v = '';
    row.valCell.replaceChildren(row.val);
    paint();
  }

  scope.add(on(`live:${dev}`, paint));
  paint();
}
