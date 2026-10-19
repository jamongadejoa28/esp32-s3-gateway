// Settings · General: site name, location, contact, default UI language.
import { h } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put } from '../api.js';
import { state, emit } from '../store.js';
import { Form, panel, toastErr } from '../ui.js';

export function mount(el, scope, { admin }) {
  const f = new Form({
    readOnly: !admin,
    onSave: (v) => put('/config/general', v),
    onSaved: (m) => { state.general = m; emit('general', m); document.title = `${m.site || 'MESTIO'} · MESTIO`; },
  });
  const g = h('div.grid.g2',
    f.text('site', t('gen.site'), { max: 63, hint: t('gen.site_hint') }).row,
    f.text('location', t('gen.location'), { max: 63 }).row,
    f.text('contact', t('gen.contact'), { max: 63 }).row,
    f.select('lang', t('gen.lang'), [['ko', '한국어'], ['en', 'English']], { hint: t('gen.lang_hint') }).row);
  f.el.append(panel(t('set.general'), h('div.panel-b', g)));
  if (admin) f.saveBar();
  el.append(f.el);
  get('/config/general').then((m) => { if (!scope.dead) f.load(m); }).catch(toastErr);
}
