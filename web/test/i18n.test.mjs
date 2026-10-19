// i18n tests: ko/en key parity and placeholder parity, every literal key used by the sources
// exists, dynamic key families cover every value the API can send, and the build-time compaction
// (tools/build_web.mjs i18nPlan) resolves every key exactly like the source dictionaries.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import ko from '../src/i18n/ko.js';
import en from '../src/i18n/en.js';
import { t, setLang, lang, initialLang, name, onLang } from '../src/i18n/index.js';
import { i18nPlan } from '../../tools/build_web.mjs';
import { ROOT } from './helpers.mjs';

afterEach(() => setLang('ko'));

function sources() {
  const out = new Map();
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js') && !/i18n[\\/](ko|en|keys)\.js$/.test(p)) out.set(p, readFileSync(p, 'utf8'));
    }
  };
  walk(join(ROOT, 'web', 'src'));
  return out;
}

test('ko and en define exactly the same keys', () => {
  const k = Object.keys(ko).sort();
  const e = Object.keys(en).sort();
  assert.deepEqual(k.filter((x) => !(x in en)), [], 'missing in en');
  assert.deepEqual(e.filter((x) => !(x in ko)), [], 'missing in ko');
  assert.ok(k.length > 300);
});

test('placeholders match between languages; no empty strings', () => {
  const ph = (s) => (s.match(/\{\w+\}/g) || []).sort().join(',');
  for (const k of Object.keys(ko)) {
    assert.equal(typeof ko[k], 'string', k);
    assert.ok(ko[k].length > 0 && en[k].length > 0, `empty: ${k}`);
    assert.equal(ph(ko[k]), ph(en[k]), `placeholders of ${k}`);
  }
});

test('every literal t() key used in the sources exists', () => {
  const missing = [];
  for (const [p, src] of sources()) {
    for (const m of src.matchAll(/\bt\('([^'\n]+)'/g)) if (!(m[1] in ko)) missing.push(`${p}: ${m[1]}`);
  }
  assert.deepEqual(missing, []);
});

test('dynamic key families cover every API value', () => {
  const common = JSON.parse(readFileSync(join(ROOT, 'docs', 'api', 'common.schema.json'), 'utf8')).$defs;
  for (const r of common.role.enum) assert.ok(`role.${r}` in ko, r);
  for (let s = 0; s <= 3; s++) assert.ok(`sev.${s}` in ko);
  for (const w of common.wstate.enum) assert.ok(`ws.${w}` in ko, w);
  const reasons = common.write_reason.pattern.replace(/^\^\(|\)\$$/g, '').split('|').filter((x) => !x.startsWith('exception'));
  for (const r of reasons) assert.ok(`wr.${r}` in ko, r);
  assert.ok('wr.exception' in ko);
  const fw = JSON.parse(readFileSync(join(ROOT, 'docs', 'api', 'firmware.response.schema.json'), 'utf8'));
  for (const s of fw.properties.running.properties.state.enum) assert.ok(`fw.state.${s}` in ko, s);
  const net = JSON.parse(readFileSync(join(ROOT, 'docs', 'api', 'system-network.response.schema.json'), 'utf8'));
  for (const r of net.properties.ap.properties.reason.enum) assert.ok(`net.ap_reason.${r}` in ko, r);
  const err = JSON.parse(readFileSync(join(ROOT, 'docs', 'api', 'error.schema.json'), 'utf8'));
  for (const r of err.properties.rules.items.enum) assert.ok(`pw.${r}` in ko, r);
  // documented error codes (API.md §2) and validation codes
  const api = readFileSync(join(ROOT, 'docs', 'API.md'), 'utf8');
  const sect = api.slice(api.indexOf('| HTTP | `error`'), api.indexOf('## 3. Endpoint index'));
  const codes = new Set([...sect.matchAll(/^\| \d{3} \| ([^|]+)\|/gm)].flatMap((m) => [...m[1].matchAll(/`([a-z_]+)`/g)].map((x) => x[1])));
  for (const c of codes) assert.ok(`err.${c}` in ko, `err.${c}`);
  const vcodes = /`required` `type`[^\n]+/.exec(sect)[0].match(/`([a-z_]+)`/g).map((x) => x.slice(1, -1));
  for (const c of vcodes) assert.ok(`v.${c}` in ko, `v.${c}`);
  // log types (API.md §4.12)
  // the type list ends at "(audit)."; the prose after it names record fields, not types
  const logs0 = api.slice(api.indexOf('**GET /system/logs**'), api.indexOf('**GET /system/coredump**'));
  const logs = logs0.slice(0, logs0.indexOf('(audit)'));
  assert.ok(logs.includes('`user_target`') && logs.includes('`login_ok`'), 'API.md log type list moved');
  const types = [...logs.matchAll(/`([a-z_]+)`/g)].map((m) => m[1]).filter((x) => !['audit', 'system', 'kind', 'before', 'limit', 'type', 'code', 'value', 'extra'].includes(x));
  for (const ty of types) assert.ok(`log.t.${ty}` in ko, `log.t.${ty}`);
  for (const k of ['dashboard', 'controller', 'trends', 'alarms', 'settings']) assert.ok(`nav.${k}` in ko);
  for (const g of ['setpoint', 'deviation', 'delay', 'limits', 'calibration', 'options', 'info']) assert.ok(`grp.${g}` in ko, g);
});

test('t(): placeholders, fallback, language switch, listeners', () => {
  assert.equal(lang(), 'ko');
  assert.equal(t('login.title'), '로그인');
  assert.equal(t('u.s', { n: 5 }), '5초');
  assert.equal(t('no.such.key'), 'no.such.key');
  assert.equal(t('u.h_min', { h: 1 }), '1시간 {m}분', 'missing params stay visible');
  let seen = null;
  const off = onLang((l) => { seen = l; });
  setLang('en');
  assert.equal(seen, 'en');
  off();
  assert.equal(t('login.title'), 'Sign in');
  setLang('xx');
  assert.equal(lang(), 'en');
  assert.equal(name({ ko: '설정온도', en: 'Temperature setpoint' }), 'Temperature setpoint');
  assert.equal(name(null), '');
});

test('initial language: stored, then browser, then ko', () => {
  assert.equal(initialLang('en', ['ko-KR']), 'en');
  assert.equal(initialLang(null, ['de-DE', 'en-US']), 'en');
  assert.equal(initialLang(null, ['ko']), 'ko');
  assert.equal(initialLang('fr', ['fr-FR']), 'ko');
  assert.equal(initialLang(undefined, undefined), 'ko');
});

test('build compaction resolves every key like the source dictionaries', () => {
  const src = sources();
  const plan = i18nPlan(ko, en, src);
  assert.equal(plan.ko.length, Object.keys(ko).length);
  // literal calls are rewritten to indices that point at the same strings
  const sample = "x = t('login.title'); y = t('u.s', { n: 1 }); z = t(`nav.${v}`);";
  const out = plan.rewrite(sample);
  const i = plan.keys.indexOf('login.title');
  assert.ok(out.includes(`t(${i})`));
  assert.equal(plan.ko[i], ko['login.title']);
  assert.equal(plan.en[i], en['login.title']);
  assert.ok(out.includes('t(`nav.${v}`)'), 'computed keys untouched');
  // every computed family and every key passed around as a value stays resolvable at runtime
  for (const k of ['nav.dashboard', 'err.csrf', 'v.overlap', 'wr.running_interlock', 'log.t.reg_write', 'sev.3', 'login.expired', 'ctl.start_q', 'sys.rebooting', 'pw.not_default']) {
    assert.ok(k in plan.runtime, `${k} must be in the runtime map`);
    assert.equal(plan.ko[plan.runtime[k]], ko[k]);
  }
  assert.ok(Object.keys(plan.runtime).length < plan.keys.length, 'most keys are compiled away');
  assert.throws(() => i18nPlan(ko, en, new Map([['x.js', "t('definitely.missing')"]])), /not defined/);
  assert.throws(() => i18nPlan(ko, { ...en, extra: 'x' }, new Map()), /mismatch/);
});
