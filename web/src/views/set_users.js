// Settings · Users & security: accounts (max 4; add, role, password reset, must-change, delete)
// and security settings (idle timeout, lockout, IP allowlist, service master switches).
import { h, icon, replace } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put, post, del, errText, ApiError } from '../api.js';
import { state } from '../store.js';
import { Form, panel, dialog, confirmDlg, toast, toastErr, table } from '../ui.js';
import * as fmt from '../fmt.js';
import { policyList, policyOk, rulesText } from '../password.js';
import { parseCidr } from '../ip4.js';

const NAME_RE = /^[a-z][a-z0-9_.-]{0,10}$/;
const ROLES = ['viewer', 'operator', 'admin'];

export function mount(el, scope) {
  const usersBox = h('div');
  const addBtn = h('button.btn.sm', { type: 'button' }, icon('plus'), t('usr.add'));
  addBtn.addEventListener('click', () => userDialog(null));
  el.append(panel(t('usr.title'), usersBox, addBtn));
  let users = [];

  async function loadUsers() {
    try {
      users = await get('/users');
      if (scope.dead) return;
      addBtn.disabled = users.length >= 4;
      const me = state.session.user;
      replace(usersBox, table([
        { label: t('usr.name'), cell: (u) => [u.name, u.name === me ? h('span.muted', { text: ` (${t('usr.you')})` }) : null] },
        { label: t('usr.role'), cell: (u) => t(`role.${u.role}`) },
        { label: t('usr.must'), cell: (u) => (u.must_change ? h('span.warn-t', { text: t('usr.must_yes') }) : '') },
        { label: t('usr.changed'), cls: 'n', cell: (u) => fmt.dateTime(u.changed, false) },
        {
          label: '', cls: 'act',
          cell: (u) => h('div.btn-row',
            h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('usr.edit_x', { name: u.name }), title: t('edit'), on: { click: () => userDialog(u) } }, icon('edit')),
            u.name !== me ? h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('usr.del_x', { name: u.name }), title: t('remove'), on: { click: () => removeUser(u) } }, icon('trash')) : null),
        },
      ], users, { caption: t('usr.title') }));
    } catch (e) { toastErr(e); }
  }

  async function removeUser(u) {
    if (!await confirmDlg({ title: t('usr.del_q', { name: u.name }), text: t('usr.del_text'), ok: t('remove'), danger: true })) return;
    try {
      await del(`/users/${encodeURIComponent(u.name)}`);
      toast(t('usr.deleted'));
    } catch (e) { toastErr(e); }
    loadUsers();
  }

  async function userDialog(u) {
    const isNew = !u;
    const self = u && u.name === state.session.user;
    const nameIn = h('input.inp', { id: 'ud-n', type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', value: u ? u.name : '', disabled: !isNew });
    const roleIn = h('select.inp', { id: 'ud-r', disabled: self }, ROLES.map((r) => h('option', { value: r, text: t(`role.${r}`) })));
    roleIn.value = u ? u.role : 'operator';
    const pwIn = h('input.inp', { id: 'ud-p', type: 'password', autocomplete: 'new-password' });
    const mc = h('input', { id: 'ud-m', type: 'checkbox', checked: u ? u.must_change : true });
    const msg = h('div.form-msg', { role: 'alert' });
    const rules = policyList(pwIn, () => nameIn.value.trim());
    const body = [
      h('div.field', h('label', { for: 'ud-n', text: t('usr.name') }), nameIn, isNew ? h('div.hint', { text: t('usr.name_hint') }) : null),
      h('div.field', h('label', { for: 'ud-r', text: t('usr.role') }), roleIn, h('div.hint', { text: t(`usr.role_hint.${roleIn.value}`) })),
      h('div.field', h('label', { for: 'ud-p', text: isNew ? t('usr.password') : t('usr.new_password') }), pwIn, rules.el, isNew ? null : h('div.hint', { text: t('usr.pw_keep') })),
      h('div.field.inline', mc, h('label', { for: 'ud-m', text: t('usr.must_label') })),
      msg,
    ];
    roleIn.addEventListener('change', () => { body[1].querySelector('.hint').textContent = t(`usr.role_hint.${roleIn.value}`); });
    const ok = await dialog({
      title: isNew ? t('usr.add') : t('usr.edit_x', { name: u.name }),
      body,
      initialFocus: isNew ? nameIn : roleIn,
      actions: [{ label: t('cancel'), value: null }, { label: isNew ? t('usr.create') : t('save'), value: true, kind: 'primary', submit: true }],
      onSubmit: async () => {
        msg.textContent = '';
        const nm = nameIn.value.trim();
        if (isNew && !NAME_RE.test(nm)) { msg.textContent = t('usr.name_hint'); nameIn.focus(); return false; }
        const pw = pwIn.value;
        if ((isNew || pw) && !policyOk(pw, nm)) { msg.textContent = t('pw.policy_fail'); pwIn.focus(); return false; }
        try {
          if (isNew) await post('/users', { name: nm, role: roleIn.value, password: pw, must_change: mc.checked });
          else {
            const b = {};
            if (!self && roleIn.value !== u.role) b.role = roleIn.value;
            if (pw) b.password = pw;
            if (mc.checked !== u.must_change) b.must_change = mc.checked;
            if (!Object.keys(b).length) return true;
            await put(`/users/${encodeURIComponent(u.name)}`, b);
          }
          return true;
        } catch (e) {
          msg.textContent = e instanceof ApiError && e.code === 'policy' ? `${t('pw.policy_fail')}: ${rulesText(e.rules)}` : errText(e);
          return false;
        }
      },
    });
    if (ok) { toast(t('saved')); loadUsers(); }
  }

  // ---- security ----
  const f = new Form({ onSave: (v) => put('/config/security', v) });
  const idle = f.num('idle_min', t('sec.idle'), { min: 5, max: 120, unit: t('u.min_short') });
  const mf = f.num('lockout.max_fail', t('sec.max_fail'), { min: 3, max: 10 });
  const lm = f.num('lockout.lock_min', t('sec.lock_min'), { min: 1, max: 30, unit: t('u.min_short'), hint: t('sec.lock_hint') });
  const ipIn = h('textarea.inp', { id: 'sec-ip', rows: '4', spellcheck: 'false', placeholder: '192.168.10.0/24' });
  const ipErr = h('div.err', { hidden: true });
  const ipRow = h('div.field.span2', h('label', { for: 'sec-ip', text: t('sec.allow') }), ipIn, h('div.hint', { text: t('sec.allow_hint') }), ipErr);
  f.custom({
    path: 'ip_allow', row: ipRow, err: ipErr, input: ipIn,
    get: () => ipIn.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
    set: (v) => { ipIn.value = (v || []).join('\n'); },
    validate: (v) => {
      if (v.length > 8) return t('v.allow_max');
      const bad = v.find((c) => !parseCidr(c));
      return bad ? t('v.cidr', { c: bad }) : null;
    },
  });
  const svcS = f.toggle('services.snmp', t('sec.svc_snmp'));
  const svcL = f.toggle('services.syslog', t('sec.svc_syslog'));
  f.el.append(panel(t('sec.title'), h('div.panel-b', h('div.grid.g2', idle.row, h('div'), mf.row, lm.row, ipRow, svcS.row, svcL.row))));
  f.saveBar();
  el.append(f.el);

  loadUsers();
  get('/config/security').then((m) => { if (!scope.dead) f.load(m); }).catch(toastErr);
}
