// Login and forced password change. The login page shows only the MESTIO symbol and the sign-in
// form: no product, model, version or device information (DESIGN.md §6/§11).
import { h, sprite, replace } from '../dom.js';
import { t, lang, setLang } from '../i18n/index.js';
import { post, errText, ApiError, setCsrf } from '../api.js';
import { policyList, policyOk, rulesText } from '../password.js';

function langSwitch() {
  const other = lang() === 'ko' ? 'en' : 'ko';
  return h('button.btn.ghost.sm', { type: 'button', on: { click: () => setLang(other) } }, other === 'en' ? 'English' : '한국어');
}

/**
 * Sign-in form. onDone(session) after a successful login.
 * @param {string} [notice] i18n key shown above the form (e.g. session expired)
 */
export function renderLogin(root, onDone, notice) {
  const user = h('input.inp', { id: 'lg-u', name: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
  const pass = h('input.inp', { id: 'lg-p', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const msg = h('div.form-msg', { role: 'alert', 'aria-live': 'assertive' });
  const btn = h('button.btn.primary', { type: 'submit', text: t('login.submit') });
  if (notice) msg.textContent = t(notice);
  const form = h('form', { novalidate: true },
    h('div.field', h('label', { for: 'lg-u', text: t('login.user') }), user),
    h('div.field', h('label', { for: 'lg-p', text: t('login.pass') }), pass),
    msg, btn);
  let lockTimer = 0;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!user.value || !pass.value) {
      msg.textContent = t('login.missing');
      (user.value ? pass : user).focus();
      return;
    }
    btn.disabled = true;
    msg.textContent = '';
    try {
      const s = await post('/auth/login', { user: user.value.trim(), pass: pass.value });
      setCsrf(s.csrf);
      onDone(s, pass.value);
    } catch (err) {
      pass.value = '';
      pass.focus();
      if (err instanceof ApiError && err.code === 'rate_limited' && err.retryAfter) {
        let left = err.retryAfter;
        const tick = () => {
          msg.textContent = t('login.locked', { n: left });
          if (left-- <= 0) { clearInterval(lockTimer); msg.textContent = ''; btn.disabled = false; }
        };
        clearInterval(lockTimer);
        tick();
        lockTimer = setInterval(tick, 1000);
        return;
      }
      msg.textContent = err instanceof ApiError && err.code === 'bad_credentials' ? t('login.bad') : errText(err);
    }
    btn.disabled = false;
  });
  replace(root, h('div.login', h('div.login-box',
    sprite('logo'),
    h('h1', { text: t('login.title') }),
    form,
    h('div.login-foot', h('span'), langSwitch()))));
  user.focus();
}

/**
 * Forced password change (must_change). `current` is the password just used to sign in (kept in
 * memory only for this step); when unknown (page reload) the user types it.
 * @param {string} [notice] i18n key shown in the form message (e.g. wrong current password)
 */
export function renderPasswordChange(root, session, current, onDone, onLogout, notice) {
  const cur = h('input.inp', { id: 'pc-c', type: 'password', autocomplete: 'current-password' });
  const nw = h('input.inp', { id: 'pc-n', type: 'password', autocomplete: 'new-password' });
  const cf = h('input.inp', { id: 'pc-r', type: 'password', autocomplete: 'new-password' });
  const msg = h('div.form-msg', { role: 'alert', 'aria-live': 'assertive' });
  const btn = h('button.btn.primary', { type: 'submit', text: t('pw.submit') });
  if (notice) msg.textContent = t(notice);
  const rules = policyList(nw, () => session.user, () => current || cur.value);
  const form = h('form', { novalidate: true },
    current ? null : h('div.field', h('label', { for: 'pc-c', text: t('pw.current') }), cur),
    h('div.field', h('label', { for: 'pc-n', text: t('pw.new') }), nw, rules.el),
    h('div.field', h('label', { for: 'pc-r', text: t('pw.confirm') }), cf),
    msg, btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const c = current || cur.value;
    if (!c) { msg.textContent = t('pw.need_current'); cur.focus(); return; }
    if (!policyOk(nw.value, session.user, c)) { msg.textContent = t('pw.policy_fail'); nw.focus(); return; }
    if (nw.value !== cf.value) { msg.textContent = t('pw.mismatch'); cf.focus(); return; }
    btn.disabled = true;
    msg.textContent = '';
    try {
      await post('/auth/password', { current: c, new: nw.value });
      onDone();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'policy') msg.textContent = `${t('pw.policy_fail')}: ${rulesText(err.rules)}`;
      else if (err instanceof ApiError && err.code === 'wrong_password') {
        // the remembered sign-in password no longer matches: ask for it, keeping the explanation
        if (current) { renderPasswordChange(root, session, null, onDone, onLogout, 'pw.wrong_current'); return; }
        msg.textContent = t('pw.wrong_current');
      } else msg.textContent = errText(err);
      btn.disabled = false;
    }
  });
  replace(root, h('div.login', h('div.login-box',
    sprite('logo'),
    h('div', h('h1', { text: t('pw.title') }), h('p.muted', { text: t('pw.intro') })),
    form,
    h('div.login-foot', h('button.btn.ghost.sm', { type: 'button', text: t('logout'), on: { click: onLogout } }), langSwitch()))));
  (current ? nw : cur).focus();
}
