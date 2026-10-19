// Own password change (user menu). Other sessions of the user are revoked by the gateway.
import { h } from '../dom.js';
import { t } from '../i18n/index.js';
import { post, errText, ApiError } from '../api.js';
import { state } from '../store.js';
import { dialog, toast } from '../ui.js';
import { policyList, policyOk, rulesText } from '../password.js';

export async function changeOwnPassword() {
  const cur = h('input.inp', { id: 'op-c', type: 'password', autocomplete: 'current-password' });
  const nw = h('input.inp', { id: 'op-n', type: 'password', autocomplete: 'new-password' });
  const cf = h('input.inp', { id: 'op-r', type: 'password', autocomplete: 'new-password' });
  const msg = h('div.form-msg', { role: 'alert' });
  const rules = policyList(nw, () => state.session.user, () => cur.value);
  const body = [
    h('div.field', h('label', { for: 'op-c', text: t('pw.current') }), cur),
    h('div.field', h('label', { for: 'op-n', text: t('pw.new') }), nw, rules.el),
    h('div.field', h('label', { for: 'op-r', text: t('pw.confirm') }), cf),
    msg,
  ];
  const ok = await dialog({
    title: t('menu.password'),
    body,
    initialFocus: cur,
    actions: [{ label: t('cancel'), value: null }, { label: t('pw.submit'), value: true, kind: 'primary', submit: true }],
    onSubmit: async () => {
      msg.textContent = '';
      if (!cur.value) { msg.textContent = t('pw.need_current'); cur.focus(); return false; }
      if (!policyOk(nw.value, state.session.user, cur.value)) { msg.textContent = t('pw.policy_fail'); nw.focus(); return false; }
      if (nw.value !== cf.value) { msg.textContent = t('pw.mismatch'); cf.focus(); return false; }
      try {
        await post('/auth/password', { current: cur.value, new: nw.value });
        return true;
      } catch (e) {
        if (e instanceof ApiError && e.code === 'policy') msg.textContent = `${t('pw.policy_fail')}: ${rulesText(e.rules)}`;
        else if (e instanceof ApiError && e.code === 'wrong_password') { msg.textContent = t('pw.wrong_current'); cur.value = ''; cur.focus(); } else msg.textContent = errText(e);
        return false;
      }
    },
  });
  if (ok) toast(t('pw.changed'));
}
