// Shared UI pieces: toasts, modal dialogs (native <dialog>: focus trap + Esc), severity marks, and
// Form — a small declarative form builder with dirty tracking, inline validation, server error
// mapping (422 `field`) and a sticky Save / Revert bar.
import { h, icon, sprite, clear } from './dom.js';
import { t } from './i18n/index.js';
import { errText, ApiError } from './api.js';
import { utf8Len } from './fmt.js';
import { state } from './store.js';
import { storageFailed } from './live.js';

// ---------------------------------------------------------------------------------------------
// Toasts (aria-live polite region)
// ---------------------------------------------------------------------------------------------
let toastBox = null;
export function toast(msg, kind = 'ok', ms = 4000) {
  if (!toastBox) {
    toastBox = h('div.toasts', { role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastBox);
  }
  const ic = kind === 'ok' ? 'check' : kind === 'alarm' || kind === 'warn' ? 'alert' : 'info';
  const el = h(`div.toast.${kind}`, icon(ic), h('div.grow', msg));
  toastBox.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

export const toastErr = (e) => toast(errText(e), 'alarm', 6000);

// ---------------------------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------------------------
/**
 * Modal dialog. actions: [{label, value, kind: 'primary'|'danger'|'', submit?: true}]
 * `onSubmit(value)` may return false (keep open) or a Promise; errors keep it open.
 * Resolves with the action value, or null on cancel/Esc.
 */
export function dialog({ title, body, actions, onSubmit, initialFocus }) {
  return new Promise((resolve) => {
    const dlg = h('dialog.dlg', { 'aria-labelledby': 'dlg-title' });
    const form = h('form', { method: 'dialog', novalidate: true });
    const foot = h('div.dlg-f');
    let busy = false;
    for (const a of actions) {
      const b = h(`button.btn${a.kind === 'primary' ? '.primary' : a.kind === 'danger' ? '.danger.solid' : ''}`, {
        type: a.submit ? 'submit' : 'button', value: a.value === null ? '' : String(a.value), text: a.label,
      });
      if (!a.submit) b.addEventListener('click', () => close(a.value ?? null));
      foot.appendChild(b);
    }
    form.append(h('div.dlg-h', h('h2', { id: 'dlg-title', text: title })), h('div.dlg-b', body), foot);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (busy) return;
      const value = actions.find((a) => a.submit)?.value ?? true;
      if (onSubmit) {
        busy = true;
        foot.querySelectorAll('button').forEach((b) => { b.disabled = true; });
        try {
          const r = await onSubmit(value);
          if (r === false) return;
        } catch (err) {
          if (!(err instanceof ApiError)) console.error(err);
          return;
        } finally {
          busy = false;
          foot.querySelectorAll('button').forEach((b) => { b.disabled = false; });
        }
      }
      close(value);
    });
    dlg.appendChild(form);
    dlg.addEventListener('cancel', (e) => { if (busy) e.preventDefault(); else { e.preventDefault(); close(null); } });
    function close(v) {
      dlg.close();
      dlg.remove();
      resolve(v);
    }
    document.body.appendChild(dlg);
    dlg.showModal();
    if (initialFocus) initialFocus.focus();
  });
}

/** Yes/no confirmation. */
export async function confirmDlg({ title, text, ok, danger }) {
  const r = await dialog({
    title,
    body: h('p', text),
    actions: [{ label: t('cancel'), value: null }, { label: ok, value: true, kind: danger ? 'danger' : 'primary', submit: true }],
  });
  return r === true;
}

// ---------------------------------------------------------------------------------------------
// Small marks
// ---------------------------------------------------------------------------------------------
export function sevMark(sev) {
  return h(`span.sev.s${sev}`, sprite(`sv${sev}`), t(`sev.${sev}`));
}

export function stateText(state, reason) {
  const map = { applied: ['ok-t', 'check'], rejected: ['alarm-t', 'x'], uncertain: ['warn-t', 'alert'], pending: ['muted', 'clock'] };
  const [cls, ic] = map[state] || map.pending;
  return h(`span.state-t.${cls}`, icon(ic, 's16'), t(`ws.${state}`), reason ? h('span', ` · ${reason}`) : null);
}

// ---------------------------------------------------------------------------------------------
// Form builder
// ---------------------------------------------------------------------------------------------
let uid = 0;
const getPath = (o, p) => p.split('.').reduce((a, k) => (a === null || a === undefined ? undefined : a[k]), o);
function setPath(o, p, v) {
  const ks = p.split('.');
  let cur = o;
  for (let i = 0; i < ks.length - 1; i++) cur = cur[ks[i]] ?? (cur[ks[i]] = {});
  cur[ks[ks.length - 1]] = v;
}

export class Form {
  /**
   * @param {object} o {readOnly, onSave(values) => Promise<model>, onSaved(model)}
   */
  constructor(o = {}) {
    this.o = o;
    this.ctrls = [];
    this.el = h('form.form', { novalidate: true, on: { submit: (e) => { e.preventDefault(); this.save(); } } });
    this.el.addEventListener('input', () => this.refresh());
    this.el.addEventListener('change', () => this.refresh());
    this.base = null;
    this.bar = null;
    this.saving = false;
  }

  /** Register a control: {path, row, input, get(), set(v), validate?(v) -> msg|null, skip?(v), err} */
  add(c) {
    this.ctrls.push(c);
    if (this.o.readOnly && c.input) c.input.disabled = true;
    return c;
  }

  field(label, input, opts = {}) {
    const id = input.id || (input.id = `f${++uid}`);
    const err = h('div.err', { id: `${id}-e`, hidden: true });
    const hint = opts.hint ? h('div.hint', { id: `${id}-h`, text: opts.hint }) : null;
    if (hint) input.setAttribute('aria-describedby', `${id}-h`);
    const row = h(`div.field${opts.cls ? `.${opts.cls}` : ''}`, h('label', { for: id, text: label }), opts.wrap ? opts.wrap(input) : input, hint, err);
    return { row, err };
  }

  /** Text input. opts: {max (bytes), min, pattern RegExp, hint, required, placeholder, ac, cls} */
  text(path, label, opts = {}) {
    const input = h('input.inp', { type: opts.type || 'text', autocomplete: opts.ac || 'off', placeholder: opts.placeholder, spellcheck: 'false', inputmode: opts.inputmode });
    const { row, err } = this.field(label, input, opts);
    return this.add({
      path, row, input, err,
      get: () => input.value.trim(),
      set: (v) => { input.value = v ?? ''; },
      validate: (v) => {
        if (opts.required && !v) return t('v.required');
        if (opts.max && utf8Len(v) > opts.max) return t('v.bytes', { n: opts.max });
        if (v && opts.pattern && !opts.pattern.test(v)) return opts.patternMsg || t('v.format');
        return opts.validate ? opts.validate(v) : null;
      },
    });
  }

  /** Write-only secret: empty = keep stored value (not sent). */
  secret(path, label, opts = {}) {
    const c = this.text(path, label, { ...opts, type: 'password', ac: 'new-password' });
    c.secret = true;
    c.get = () => c.input.value; // never trimmed: spaces are legal in a PSK/community/password
    c.skip = (v) => v === '';
    c.setStored = (isSet) => { c.input.placeholder = isSet ? t('secret.set') : t('secret.unset'); };
    c.set = () => { c.input.value = ''; };
    return c;
  }

  /** Integer/decimal input. opts: {min, max, step, unit, dec} */
  num(path, label, opts = {}) {
    const input = h('input.inp.num', { type: 'text', inputmode: opts.dec ? 'decimal' : 'numeric', autocomplete: 'off' });
    const wrap = opts.unit ? (i) => h('div.unit-wrap', i, h('span.u', { text: opts.unit })) : null;
    const hint = opts.hint ?? (opts.min !== undefined ? t('v.range_hint', { min: opts.min, max: opts.max }) : undefined);
    const { row, err } = this.field(label, input, { ...opts, hint, wrap });
    return this.add({
      path, row, input, err,
      get: () => {
        const s = input.value.trim().replace(',', '.');
        return s === '' ? null : Number(s);
      },
      set: (v) => { input.value = v === null || v === undefined ? '' : String(v); },
      validate: (v) => {
        if (v === null) return opts.optional ? null : t('v.required');
        if (!Number.isFinite(v) || (!opts.dec && !Number.isInteger(v))) return t('v.number');
        if ((opts.min !== undefined && v < opts.min) || (opts.max !== undefined && v > opts.max)) return t('v.range', { min: opts.min, max: opts.max });
        return null;
      },
    });
  }

  /** Select. options: [[value, label]]; values keep their type (number/string). */
  select(path, label, options, opts = {}) {
    const input = h('select.inp', options.map(([v, l]) => h('option', { value: String(v), text: l })));
    const { row, err } = this.field(label, input, opts);
    return this.add({
      path, row, input, err,
      get: () => {
        const o = options.find(([v]) => String(v) === input.value);
        return o ? o[0] : input.value;
      },
      set: (v) => { input.value = String(v); },
    });
  }

  /** Switch (checkbox role=switch) with inline label. */
  toggle(path, label, opts = {}) {
    const input = h('input.switch', { type: 'checkbox', role: 'switch' });
    const id = (input.id = `f${++uid}`);
    const row = h('div.field.inline', input, h('label', { for: id, text: label }), opts.hint ? h('span.hint', { text: opts.hint }) : null);
    return this.add({ path, row, input, get: () => input.checked, set: (v) => { input.checked = !!v; } });
  }

  /** Custom control: {path, row, get, set, validate?} */
  custom(c) { return this.add(c); }

  fill(model) {
    for (const c of this.ctrls) {
      if (c.path) c.set(getPath(model, c.path));
      this.setError(c, null);
    }
    this.base = JSON.stringify(this.values());
    this.refresh();
  }

  values() {
    const out = {};
    for (const c of this.ctrls) {
      if (!c.path) continue;
      const v = c.get();
      if (c.skip && c.skip(v)) continue;
      setPath(out, c.path, v);
    }
    return out;
  }

  dirty() { return this.base !== null && JSON.stringify(this.values()) !== this.base; }

  /** Show/hide the save bar according to the dirty state. */
  refresh() {
    const d = this.dirty();
    if (this.bar) this.bar.hidden = !d || !!this.o.readOnly;
    return d;
  }

  setError(c, msg) {
    if (!c.err) return;
    c.err.hidden = !msg;
    c.err.textContent = msg || '';
    if (c.input) {
      if (msg) {
        c.input.setAttribute('aria-invalid', 'true');
        c.input.setAttribute('aria-errormessage', c.err.id);
      } else {
        c.input.removeAttribute('aria-invalid');
      }
    }
  }

  validate() {
    let first = null;
    for (const c of this.ctrls) {
      const msg = c.validate ? c.validate(c.get()) : null;
      this.setError(c, msg);
      if (msg && !first) first = c;
    }
    if (first && first.input) first.input.focus();
    return !first;
  }

  /** Map a 422 `field` (dotted path, maybe with [i]) to a control; otherwise toast. */
  serverError(e) {
    if (e instanceof ApiError && e.field) {
      const f = e.field.replace(/\[(\d+)\]/g, '.$1');
      const c = this.ctrls.find((x) => x.path && (x.path === f || f.startsWith(`${x.path}.`) || x.path.endsWith(`.${f}`) || x.path === f.split('.').pop()));
      if (c) {
        this.setError(c, errText(e));
        if (c.input) c.input.focus();
        return;
      }
    }
    toastErr(e);
  }

  /** Sticky save bar (hidden until dirty). */
  saveBar() {
    const save = h('button.btn.primary', { type: 'submit', text: t('save') });
    const revert = h('button.btn', { type: 'button', text: t('revert'), on: { click: () => this.revert() } });
    this.bar = h('div.savebar', { hidden: true }, h('span.grow', t('unsaved')), revert, save);
    this.saveBtn = save;
    this.el.appendChild(this.bar);
    return this.bar;
  }

  revert() {
    if (this.base === null) return;
    const model = this.lastModel;
    if (model) this.fill(model);
  }

  load(model) {
    this.lastModel = model;
    this.fill(model);
  }

  async save() {
    if (this.saving || this.o.readOnly || !this.o.onSave) return;
    if (!this.validate()) return;
    this.saving = true;
    if (this.saveBtn) this.saveBtn.disabled = true;
    try {
      const model = await this.o.onSave(this.values());
      if (model !== undefined && model !== false) {
        this.load(model);
        if (this.o.onSaved) this.o.onSaved(model);
        // with a failed store the gateway applies the change in RAM only (degraded mode)
        if (storageFailed(state.info)) toast(t('saved_volatile'), 'warn', 8000);
        else toast(t('saved'));
      }
    } catch (e) {
      this.serverError(e);
    } finally {
      this.saving = false;
      if (this.saveBtn) this.saveBtn.disabled = false;
    }
  }
}

/** Panel with header (title + optional actions) and body. */
export function panel(title, body, ...actions) {
  return h('section.panel',
    h('div.panel-h', h('h2', { text: title }), h('span.grow'), ...actions),
    body);
}

/** Simple table from columns [{label, cls, cell(row) -> Node|string}] and rows. */
export function table(cols, rows, opts = {}) {
  const thead = h('thead', h('tr', cols.map((c) => h(`th${c.cls ? `.${c.cls}` : ''}`, { scope: 'col', text: c.label }))));
  const tbody = h('tbody');
  if (!rows.length && opts.empty) {
    tbody.appendChild(h('tr', h('td.empty', { colspan: cols.length, text: opts.empty })));
  }
  for (const r of rows) {
    const tr = h('tr', { class: opts.rowCls ? opts.rowCls(r) : null }, cols.map((c) => h(`td${c.cls ? `.${c.cls}` : ''}`, c.cell(r))));
    tbody.appendChild(tr);
  }
  return h('div.tbl-wrap', h('table.tbl', opts.caption ? h('caption.sr', { text: opts.caption }) : null, thead, tbody));
}

export function emptyRow(el, text) {
  clear(el);
  el.appendChild(h('div.empty', { text }));
}
