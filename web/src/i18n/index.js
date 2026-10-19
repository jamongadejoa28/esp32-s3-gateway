// i18n: flat key dictionaries (ko default, en). Register and alarm names come from /meta/*.
import ko from './ko.js';
import en from './en.js';
import KEYS from './keys.js';

export const DICTS = { ko, en };
export const LANGS = ['ko', 'en'];
const LOCALES = { ko: 'ko-KR', en: 'en-GB' };
// production bundle: name i of KEYS is dictionary index i (computed-name lookups only)
const IDX = KEYS && Object.fromEntries(KEYS.map((k, i) => [k, i]));
let cur = 'ko';
const listeners = new Set();

/** Current language code. */
export const lang = () => cur;

/** BCP 47 locale for Intl of the current language. */
export const locale = () => LOCALES[cur];

function look(d, key) {
  if (typeof key === 'number' || IDX === null) return d[key];
  const i = IDX[key];
  return i === undefined ? undefined : d[i];
}

/**
 * Translate `key`, replacing {name} placeholders from `p`. Missing keys return the key itself.
 * (In the production bundle literal keys arrive as numeric indices, see keys.js.)
 */
export function t(key, p) {
  const s = look(DICTS[cur], key) ?? look(DICTS.ko, key) ?? String(key);
  return p ? s.replace(/\{(\w+)\}/g, (m, k) => (p[k] ?? m)) : s;
}

/** Localised label of a meta object carrying `ko`/`en` members. */
export const name = (o) => (o ? o[cur] || o.ko || o.en || '' : '');

/** Language preferred at boot: stored choice, else browser language, else ko. */
export function initialLang(stored, navLangs) {
  if (LANGS.includes(stored)) return stored;
  for (const l of navLangs || []) {
    const c = String(l).slice(0, 2).toLowerCase();
    if (c === 'ko') return 'ko';
    if (c === 'en') return 'en';
  }
  return 'ko';
}

export function setLang(l) {
  if (!LANGS.includes(l) || l === cur) return;
  cur = l;
  for (const fn of listeners) fn(l);
}

export function onLang(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
