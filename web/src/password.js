// Password policy checklist (API.md §4.1): live client-side hints; the server remains authoritative
// (422 policy with `rules`).
import { h, toggle } from './dom.js';
import { t } from './i18n/index.js';
import { utf8Len } from './fmt.js';

/** Client-checkable rules for a candidate password. */
export function policyState(pw, user, current) {
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  return {
    min_length: [...pw].length >= 10,
    max_length: utf8Len(pw) <= 64,
    classes: classes >= 3,
    not_username: !user || pw.toLowerCase() !== user.toLowerCase(),
    not_previous: !current || pw !== current,
    charset: !/[\u0000-\u001f\u007f]/.test(pw),
  };
}

export const policyOk = (pw, user, current) => Object.values(policyState(pw, user, current)).every(Boolean);

/** Checklist element bound to an input; returns {el, update()}. */
export function policyList(input, getUser, getCurrent) {
  const keys = ['min_length', 'classes', 'not_username'];
  const items = keys.map((k) => h('li', { data: { k } }, h('span.dot.off'), t(`pw.${k}`)));
  const el = h('ul.rules', { 'aria-label': t('pw.rules') }, items);
  const update = () => {
    const st = policyState(input.value, getUser(), getCurrent ? getCurrent() : null);
    items.forEach((li, i) => {
      const ok = st[keys[i]] && input.value !== '';
      toggle(li, 'met', ok);
      li.firstChild.className = ok ? 'dot ok' : 'dot off';
    });
  };
  input.addEventListener('input', update);
  update();
  return { el, update };
}

/** Text for server policy rule codes. */
export const rulesText = (rules) => (rules || []).map((r) => t(`pw.${r}`)).join(' · ');
