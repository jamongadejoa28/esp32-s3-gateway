// Settings · System: diagnostics (all roles); for admins also firmware update (browser-side
// SHA-256, upload progress, rollback), configuration backup/restore, reboot, factory reset
// (password + typed RESET) and the audit/system logs.
import { h, icon, replace, setText, download } from '../dom.js';
import { t, name } from '../i18n/index.js';
import { get, post, upload, fetchBlob, errText, ApiError, req } from '../api.js';
import { state, set } from '../store.js';
import { initFaultNames } from '../live.js';
import { panel, dialog, confirmDlg, toast, toastErr, table } from '../ui.js';
import * as fmt from '../fmt.js';
import { sha256Hex } from '../sha256.js';

const SECTIONS = ['general', 'network', 'modbus', 'alarms', 'snmp', 'time', 'security', 'notify'];
const CFG_SEC_SECRETS = 0x7f; // components/store/include/store/config.h: secrets-only change
/** Label of a config section wire name ("secrets" for credential-only changes). */
export function sectionLabel(s) {
  return t(s === 'notify' ? 'sl.title' : SECTIONS.includes(s) || s === 'secrets' ? `set.${s}` : 'set.general');
}
const MAX_FW = 3 * 1024 * 1024;
const hex = (n) => `0x${(n >>> 0).toString(16).padStart(8, '0')}`;
/** esp_reset_reason_t as text (the number when there is no name for it). */
export function rstText(n) {
  const k = `rst.${n}`;
  const s = t(k);
  return s === k ? String(n) : s;
}
/** Named SYS_INIT_FAULT_* bits; bits without a name are appended as hex. */
function faultText(bits) {
  const names = initFaultNames(bits).map((n) => t(`if.${n}`));
  if (bits & ~0xff) names.push(hex(bits & ~0xff));
  return names.join(', ');
}
const ipStr = (u) => (u ? [u >>> 24, (u >>> 16) & 255, (u >>> 8) & 255, u & 255].join('.') : '');

/** Full-page "restarting" state; reloads once the gateway answers again. */
export function waitReboot(msgKey, delayS = 2) {
  const root = document.getElementById('app');
  const st = h('p.muted', { text: t('sys.wait') });
  root.replaceChildren(h('div.login', h('div.login-box', h('h1', { text: t(msgKey) }), st)));
  const started = Date.now();
  setTimeout(function poll() {
    fetch('/api/v1/session', { credentials: 'same-origin', cache: 'no-store' })
      .then((r) => { if (r.status === 200 || r.status === 401) location.reload(); else setTimeout(poll, 2000); })
      .catch(() => {
        setText(st, t('sys.wait_s', { n: Math.round((Date.now() - started) / 1000) }));
        setTimeout(poll, 2000);
      });
  }, (delayS + 3) * 1000);
}

export function mount(el, scope, { admin }) {
  // ---- diagnostics ----
  const diag = h('dl.kv');
  const dump = h('div');
  el.append(panel(t('sys.diag'), h('div.panel-b', diag)));
  async function paintDiag() {
    try {
      const i = await get('/system/info');
      if (scope.dead) return;
      set('info', i); // keeps the shell's storage-failure banner current
      const row = (k, v, cls) => [h('dt', { text: k }), h(`dd${cls ? `.${cls}` : ''}`, { text: v })];
      const f = i.diag.init_faults;
      replace(diag,
        row(t('sys.fw'), `${i.fw} (${i.build})`), row('SDK', i.idf), row('MAC', i.mac), row(t('net.hostname'), i.hostname),
        row(t('sys.uptime'), fmt.duration(i.uptime_s)), row(t('sys.time'), i.time_valid ? fmt.dateTime(i.time_ms) : t('time.invalid')),
        row(t('sys.heap'), `${fmt.bytes(i.heap.int_free)} · ${t('sys.min')} ${fmt.bytes(i.heap.int_min)}`), row('PSRAM', fmt.bytes(i.heap.psram_free)),
        row(t('sys.part'), `${i.part.running} · ${t(`fw.state.${i.part.state}`)}`),
        row(t('sys.reset'), rstText(i.diag.reset_reason)), row(t('sys.boots'), String(i.diag.boot_count)),
        row(t('sys.evt_drop'), String(i.diag.evt_dropped)),
        row(t('sys.hb'), i.diag.hb_stale ? hex(i.diag.hb_stale) : t('sys.ok'), i.diag.hb_stale ? 'warn-t' : null),
        row(t('sys.init_fault'), f ? faultText(f) : t('sys.ok'), f ? 'alarm-t' : null),
        row(t('sys.ws'), String(i.diag.ws_clients)), row(t('sys.fs'), `${fmt.bytes(i.diag.fs.used)} / ${fmt.bytes(i.diag.fs.total)}`));
    } catch { /* keep the previous values */ }
  }
  paintDiag();
  scope.every(10000, () => { if (!document.hidden) paintDiag(); });
  if (!admin) return;

  // ---- firmware ----
  const fwInfo = h('dl.kv');
  const file = h('input.sr', { type: 'file', accept: '.bin,application/octet-stream' });
  const fileName = h('span.fname', { text: t('fw.no_file') });
  const hashEl = h('div.hash.muted');
  const allowDown = h('input', { type: 'checkbox', id: 'fw-down' });
  const upBtn = h('button.btn.primary', { type: 'button', disabled: true }, icon('up'), t('fw.upload'));
  const prog = h('div.progress', { hidden: true, role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100' }, h('i'));
  const progTxt = h('span.muted');
  const rbBtn = h('button.btn', { type: 'button', hidden: true }, icon('redo'), t('fw.rollback'));
  let img = null;
  let sha = null;
  file.addEventListener('change', async () => {
    img = null; sha = null; upBtn.disabled = true; setText(hashEl, '');
    const fl = file.files[0];
    setText(fileName, fl ? `${fl.name} · ${fmt.bytes(fl.size)}` : t('fw.no_file'));
    if (!fl) return;
    const still = () => file.files[0] === fl; // a newer pick supersedes this (slower) hash
    if (fl.size > MAX_FW) { setText(hashEl, t('fw.too_big')); return; }
    setText(hashEl, t('fw.hashing'));
    try {
      const ab = await fl.arrayBuffer();
      if (!still()) return;
      const hx = await sha256Hex(ab);
      if (!still()) return;
      sha = hx;
      img = fl;
      setText(hashEl, `SHA-256 ${sha}`);
      upBtn.disabled = false;
    } catch { if (still()) setText(hashEl, t('fw.read_fail')); }
  });
  upBtn.addEventListener('click', async () => {
    if (!img || !sha || file.files[0] !== img) return;
    if (!await confirmDlg({ title: t('fw.confirm_q'), text: t('fw.confirm_text', { name: img.name, size: fmt.bytes(img.size) }), ok: t('fw.upload') })) return;
    upBtn.disabled = true; file.disabled = true; prog.hidden = false;
    const bar = prog.firstChild;
    try {
      const r = await upload('/system/firmware', img, { 'X-Firmware-SHA256': sha }, (s, tot) => {
        const p = Math.round((s / tot) * 100);
        bar.style.width = `${p}%`;
        prog.setAttribute('aria-valuenow', String(p));
        setText(progTxt, `${p}% · ${fmt.bytes(s)} / ${fmt.bytes(tot)}`);
      }, allowDown.checked ? { allow_downgrade: 1 } : null);
      toast(t('fw.done', { v: r.version }));
      waitReboot('sys.updating', r.reboot_in_s);
    } catch (e) {
      prog.hidden = true;
      setText(progTxt, '');
      upBtn.disabled = false; file.disabled = false;
      toast(e instanceof ApiError && e.code === 'image_invalid' ? `${t('err.image_invalid')}: ${e.message}` : errText(e), 'alarm', 8000);
    }
  });
  rbBtn.addEventListener('click', async () => {
    if (!await confirmDlg({ title: t('fw.rollback_q'), text: t('fw.rollback_text'), ok: t('fw.rollback'), danger: true })) return;
    try {
      const r = await post('/system/firmware/rollback');
      waitReboot('sys.rebooting', r.reboot_in_s);
    } catch (e) { toastErr(e); }
  });
  async function paintFw() {
    try {
      const f = await get('/system/firmware');
      if (scope.dead) return;
      replace(fwInfo,
        h('dt', { text: t('fw.running') }), h('dd', { text: `${f.running.version} · ${f.running.slot} · ${t(`fw.state.${f.running.state}`)}` }),
        h('dt', { text: t('fw.other') }), h('dd', { text: f.other.version ? `${f.other.version} · ${f.other.slot} · ${f.other.valid ? t('fw.valid') : t('fw.invalid')}` : t('fw.empty') }));
      rbBtn.hidden = !(f.other.valid && f.other.version);
    } catch (e) { toastErr(e); }
  }
  const drop = h('div.drop', icon('up'), h('div.grow', h('b', { text: t('fw.file') }), fileName), h('label.btn', t('fw.choose'), file));
  drop.addEventListener('dragover', (e) => { if (file.disabled) return; e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    if (file.disabled || !e.dataTransfer.files.length) return;
    file.files = e.dataTransfer.files;
    file.dispatchEvent(new Event('change'));
  });
  el.append(panel(t('fw.title'), h('div.panel-b', fwInfo,
    drop, hashEl,
    h('div.field.inline', allowDown, h('label', { for: 'fw-down', text: t('fw.allow_down') })),
    h('div.btn-row', upBtn, progTxt), prog), rbBtn));
  paintFw();

  // ---- backup / restore ----
  const exp = h('button.btn', { type: 'button' }, icon('down'), t('bk.export'));
  exp.addEventListener('click', async () => {
    try {
      const { blob, filename } = await fetchBlob('/system/config/export');
      download(blob, filename || 'config-backup.json');
    } catch (e) { toastErr(e); }
  });
  const imp = h('input', { type: 'file', accept: '.json,application/json', 'aria-label': t('bk.import') });
  imp.addEventListener('change', async () => {
    const fl = imp.files[0];
    imp.value = '';
    if (!fl) return;
    let bundle;
    try {
      if (fl.size > 32768) throw new Error('size');
      bundle = JSON.parse(await fl.text());
      if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) throw new Error('shape');
    } catch { toast(t('bk.bad_file'), 'alarm'); return; }
    const incNet = h('input', { type: 'checkbox', id: 'bk-net' });
    const ok = await dialog({
      title: t('bk.import_q'),
      body: [h('p', { text: t('bk.import_text', { fw: bundle.fw || '?', rev: bundle.rev ?? '?' }) }),
        h('div.field.inline', incNet, h('label', { for: 'bk-net', text: t('bk.inc_net') })), h('p', { text: t('bk.net_note') })],
      actions: [{ label: t('cancel'), value: null }, { label: t('bk.import'), value: true, kind: 'primary', submit: true }],
    });
    if (!ok) return;
    try {
      const r = await req('POST', '/system/config/import', { body: bundle, query: incNet.checked ? { include_network: 1 } : null });
      toast(r.changed.length ? t('bk.imported', { s: r.changed.map(sectionLabel).join(', ') }) : t('bk.nochange'));
      if (r.network) toast(t('bk.net_pending'), 'warn', 10000);
    } catch (e) { toastErr(e); }
  });
  el.append(panel(t('bk.title'), h('div.panel-b', h('p.muted', { text: t('bk.hint') }), h('div.btn-row', exp, h('label.btn', icon('up'), t('bk.import'), imp)))));
  imp.classList.add('sr');

  // ---- maintenance ----
  const reboot = h('button.btn', { type: 'button' }, icon('power'), t('sys.reboot'));
  reboot.addEventListener('click', async () => {
    if (!await confirmDlg({ title: t('sys.reboot_q'), text: t('sys.reboot_text'), ok: t('sys.reboot') })) return;
    try {
      const r = await post('/system/reboot');
      waitReboot('sys.rebooting', r.reboot_in_s);
    } catch (e) { toastErr(e); }
  });
  const reset = h('button.btn.danger', { type: 'button' }, icon('alert'), t('sys.factory'));
  reset.addEventListener('click', factoryReset);
  el.append(panel(t('sys.maint'), h('div.panel-b', h('div.btn-row', reboot, reset), h('p.muted', { text: t('sys.factory_note') }))));

  // ---- logs ----
  let kind = 'audit';
  let next = null;
  let items = [];
  const logBox = h('div');
  const more = h('button.btn', { type: 'button', hidden: true, text: t('more') });
  const kinds = h('div.seg', { role: 'group', 'aria-label': t('log.kind') }, ['audit', 'system'].map((k) => h('button', { type: 'button', 'aria-pressed': String(k === kind), text: k === 'audit' ? t('log.audit') : t('log.system'), on: { click: () => { kind = k; [...kinds.children].forEach((b, i) => b.setAttribute('aria-pressed', String(['audit', 'system'][i] === k))); loadLogs(true); } } })));
  more.addEventListener('click', () => loadLogs(false));
  el.append(panel(t('log.title'), h('div', logBox, h('div.panel-b', more)), kinds));
  async function loadLogs(reset0) {
    try {
      const r = await get('/system/logs', { kind, limit: 50, before: reset0 ? null : next });
      if (scope.dead) return;
      items = reset0 ? r.items : items.concat(r.items);
      next = r.next;
      more.hidden = next === null;
      // account changes come as a pair (action by the actor + user_target naming the account):
      // the target is shown on its action row; an orphan (other half not loaded) stays visible
      const targets = new Map();
      for (const x of items) if (x.type === 'user_target') targets.set(x.extra, x.user);
      const seqs = new Set(items.map((x) => x.seq));
      const rows = items.filter((x) => x.type !== 'user_target' || !seqs.has(x.extra));
      replace(logBox, table([
        { label: '#', cls: 'n', cell: (x) => String(x.seq) },
        { label: t('log.time'), cls: 'ts', cell: (x) => fmt.dateTime(x.ts) },
        { label: t('log.type'), cls: 'nowrap', cell: (x) => logType(x.type) },
        { label: t('log.user'), cell: (x) => x.user || '' },
        { label: t('log.detail'), cell: (x) => logDetail(x, targets.get(x.seq)) },
      ], rows, { caption: t('log.title'), empty: t('log.empty') }));
    } catch (e) { toastErr(e); }
  }
  loadLogs(true);

  // ---- core dump ----
  el.append(panel(t('cd.title'), h('div.panel-b', dump)));
  get('/system/coredump', null, { ok: [404] }).then((r) => {
    if (scope.dead) return;
    if (r.status === 404) { replace(dump, h('p.muted', { text: t('cd.none') })); return; }
    const c = r.body;
    replace(dump, h('dl.kv',
      h('dt', { text: t('cd.task') }), h('dd', { text: c.task }), h('dt', { text: 'PC' }), h('dd', { text: hex(c.pc) }),
      h('dt', { text: t('cd.cause') }), h('dd', { text: `${c.cause} · ${hex(c.vaddr)}` }),
      h('dt', { text: t('cd.bt') }), h('dd.hash', { text: `${c.backtrace.map(hex).join(' ')}${c.backtrace_corrupted ? ` (${t('cd.corrupt')})` : ''}` }),
      h('dt', { text: 'ELF SHA-256' }), h('dd.hash', { text: c.app_sha256 })), h('p.muted', { text: t('cd.usb') }));
  }).catch(() => {});

  async function factoryReset() {
    const pw = h('input.inp', { id: 'fr-p', type: 'password', autocomplete: 'current-password' });
    const cf = h('input.inp', { id: 'fr-c', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'RESET' });
    const keep = h('input', { type: 'checkbox', id: 'fr-k', checked: true });
    const msg = h('div.form-msg', { role: 'alert' });
    const ok = await dialog({
      title: t('sys.factory_q'),
      body: [h('p', { text: t('sys.factory_text') }),
        h('div.field', h('label', { for: 'fr-p', text: t('sys.your_pw') }), pw),
        h('div.field', h('label', { for: 'fr-c', text: t('sys.type_reset') }), cf),
        h('div.field.inline', keep, h('label', { for: 'fr-k', text: t('sys.keep_net') })), msg],
      initialFocus: pw,
      actions: [{ label: t('cancel'), value: null }, { label: t('sys.factory'), value: true, kind: 'danger', submit: true }],
      onSubmit: async () => {
        msg.textContent = '';
        if (cf.value !== 'RESET') { msg.textContent = t('sys.type_reset_err'); cf.focus(); return false; }
        if (!pw.value) { msg.textContent = t('pw.need_current'); pw.focus(); return false; }
        try {
          await post('/system/factory-reset', { password: pw.value, confirm: 'RESET', keep_network: keep.checked });
          return true;
        } catch (e) {
          msg.textContent = e instanceof ApiError && e.code === 'wrong_password' ? t('pw.wrong_current') : errText(e);
          pw.value = '';
          return false;
        }
      },
    });
    if (ok) waitReboot('sys.resetting', 2);
  }
}

const SRC = ['rtc', 'ntp', 'browser', 'console'];
const RB = ['user', 'ota', 'rollback', 'factory_reset', 'config_import', 'console', 'health'];
const WSTATES = ['pending', 'applied', 'rejected', 'uncertain'];

function logType(type) {
  const k = `log.t.${type}`;
  const s = t(k);
  return s === k ? type : s;
}

const ROLES = [null, 'viewer', 'operator', 'admin'];
const ACCOUNT_TYPES = { 36: 'password', 37: 'user_add', 38: 'user_mod', 39: 'user_del' };

/**
 * Human detail of a log record (field meanings: components/store/include/store/eventlog.h).
 * `target` is the account named by the user_target record paired with an account action.
 */
export function logDetail(x, target) {
  const role = () => (ROLES[x.value] ? t(`role.${ROLES[x.value]}`) : '');
  const acct = (...rest) => [target ? t('log.target', { u: target }) : '', ...rest].filter(Boolean).join(' · ');
  const dev = x.dev === null ? '' : `${t('alarms.col.dev')} ${x.dev} · `;
  const am = () => { for (const a of state.alarmMeta.values()) if (a.code === x.code) return name(a); return String(x.code); };
  switch (x.type) {
    case 'alarm_raise': case 'alarm_clear': case 'alarm_ack': return `${dev}${am()}`;
    case 'comm_lost': case 'comm_restored': case 'stats_reset': return dev.replace(/ · $/, '');
    case 'login_ok': case 'login_fail': return ipStr(x.extra);
    case 'lockout': return `${ipStr(x.extra)} · ${t('u.min', { n: x.value })}`;
    case 'config_change': return `${sectionLabel(x.code === CFG_SEC_SECRETS ? 'secrets' : SECTIONS[x.code])} · rev ${x.extra}`;
    case 'config_import': return `rev ${x.extra}`;
    case 'reg_write': {
      const r = state.regs.get(x.code);
      const st = WSTATES[(x.extra >>> 16) & 0xff] || '';
      const before = x.extra & 0xffff;
      const scale = r ? r.scale : 1;
      const bv = r && r.signed && before > 32767 ? before - 65536 : before;
      return `${dev}${r ? name(r) : x.code}: ${fmt.num(bv / scale, scale === 10 ? 1 : 0)} → ${fmt.num(x.value / scale, scale === 10 ? 1 : 0)} · ${t(`ws.${st}`)}`;
    }
    case 'time_set': case 'time_sync': return t(`log.src.${SRC[x.code] || 'rtc'}`);
    case 'reboot': case 'reboot_req': return t(`log.rb.${RB[x.code] || 'user'}`);
    case 'boot': return `${t('sys.reset')}: ${rstText(x.code)}`;
    case 'factory_reset': return x.value ? t('sys.keep_net') : '';
    case 'ota_upload': return x.code ? t('ws.rejected') : t('ws.applied');
    case 'user_add': case 'user_mod': return acct(role());
    case 'user_del': return acct();
    case 'password': return x.extra === 1 ? acct(t('log.pw_reset')) : t('log.pw_self');
    case 'user_target': return `${ACCOUNT_TYPES[x.code] ? logType(ACCOUNT_TYPES[x.code]) : x.code} · #${x.extra}`;
    default: return x.code || x.value ? `${x.code} / ${x.value}` : '';
  }
}
