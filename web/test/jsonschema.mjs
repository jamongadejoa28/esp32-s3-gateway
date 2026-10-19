// Minimal, strict JSON Schema (draft 2020-12 subset) validator for docs/api/*.schema.json.
// Vendored instead of a dependency: the contract schemas use a small keyword set, and this
// validator REJECTS any keyword it does not implement, so a schema change can never be silently
// ignored by the contract tests. Used by web/test/contract.test.mjs and tools/mock_server.mjs
// (request validation -> 422 validation {field, code}).
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', 'examples', '$comment', '$defs', 'default']);
const KNOWN = new Set([
  ...ANNOTATIONS, 'type', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'maxItems',
  'enum', 'const', 'pattern', 'minLength', 'maxLength', 'minimum', 'maximum', 'oneOf', 'anyOf', '$ref',
  'propertyNames', 'maxProperties', 'minProperties',
]);

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function typeMatches(t, v) {
  const a = typeOf(v);
  return t === a || (t === 'number' && a === 'integer');
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => deepEqual(a[k], b[k]));
}

const codePoints = (s) => { let n = 0; for (const _ of s) n++; return n; };

/** Maps a failed keyword to the API's validation `code` (API.md §2). */
const CODE = {
  type: 'type', required: 'required', additionalProperties: 'unknown_field', enum: 'range', const: 'range',
  pattern: 'format', minLength: 'length', maxLength: 'length', minimum: 'range', maximum: 'range',
  minItems: 'too_many', maxItems: 'too_many', maxProperties: 'too_many', minProperties: 'required',
  propertyNames: 'format', oneOf: 'type', anyOf: 'type',
};

export class SchemaSet {
  /** @param {string} dir directory holding *.schema.json */
  constructor(dir) {
    this.byId = new Map();
    for (const f of readdirSync(dir)) {
      if (!f.endsWith('.schema.json')) continue;
      const s = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      this.byId.set(f, s);
    }
    this.regex = new Map();
  }

  names() { return [...this.byId.keys()].map((f) => f.replace(/\.schema\.json$/, '')); }

  /** Validate `value` against schema `name` (e.g. 'device-live.response'). Returns [] when valid. */
  validate(name, value) {
    const file = name.endsWith('.json') ? name : `${name}.schema.json`;
    const root = this.byId.get(file);
    if (!root) throw new Error(`unknown schema ${name}`);
    const errors = [];
    this.#check(root, value, '', { file, root }, errors);
    return errors;
  }

  #resolve(ref, ctx) {
    const [filePart, ptr = ''] = ref.split('#');
    const file = filePart || ctx.file;
    const root = this.byId.get(file);
    if (!root) throw new Error(`unresolved $ref ${ref}`);
    let node = root;
    for (const seg of ptr.split('/').filter(Boolean)) {
      node = node[seg.replace(/~1/g, '/').replace(/~0/g, '~')];
      if (node === undefined) throw new Error(`bad $ref pointer ${ref}`);
    }
    return { node, ctx: { file, root } };
  }

  #re(p) {
    let r = this.regex.get(p);
    if (!r) { r = new RegExp(p, 'u'); this.regex.set(p, r); }
    return r;
  }

  #check(s, v, path, ctx, errs) {
    if (s === true) return;
    if (s === false) { errs.push({ path, keyword: 'false', message: 'not allowed' }); return; }
    for (const k of Object.keys(s)) {
      if (!KNOWN.has(k)) throw new Error(`jsonschema: unsupported keyword "${k}" in ${ctx.file}`);
    }
    const err = (keyword, message) => errs.push({ path, keyword, message });
    if (s.$ref) {
      const r = this.#resolve(s.$ref, ctx);
      this.#check(r.node, v, path, r.ctx, errs);
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some((t) => typeMatches(t, v))) { err('type', `expected ${types.join('|')}, got ${typeOf(v)}`); return; }
    }
    if (s.const !== undefined && !deepEqual(s.const, v)) err('const', `must be ${JSON.stringify(s.const)}`);
    if (s.enum && !s.enum.some((e) => deepEqual(e, v))) err('enum', `must be one of ${JSON.stringify(s.enum)}`);
    if (typeof v === 'string') {
      if (s.minLength !== undefined && codePoints(v) < s.minLength) err('minLength', `shorter than ${s.minLength}`);
      if (s.maxLength !== undefined && codePoints(v) > s.maxLength) err('maxLength', `longer than ${s.maxLength}`);
      if (s.pattern !== undefined && !this.#re(s.pattern).test(v)) err('pattern', `does not match ${s.pattern}`);
    }
    if (typeof v === 'number') {
      if (s.minimum !== undefined && v < s.minimum) err('minimum', `< ${s.minimum}`);
      if (s.maximum !== undefined && v > s.maximum) err('maximum', `> ${s.maximum}`);
    }
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) err('minItems', `fewer than ${s.minItems} items`);
      if (s.maxItems !== undefined && v.length > s.maxItems) err('maxItems', `more than ${s.maxItems} items`);
      if (s.items !== undefined) v.forEach((it, i) => this.#check(s.items, it, `${path}[${i}]`, ctx, errs));
    }
    if (typeOf(v) === 'object') {
      const keys = Object.keys(v);
      if (s.maxProperties !== undefined && keys.length > s.maxProperties) err('maxProperties', `more than ${s.maxProperties} members`);
      if (s.minProperties !== undefined && keys.length < s.minProperties) err('minProperties', `fewer than ${s.minProperties} members`);
      for (const r of s.required || []) {
        if (!(r in v)) errs.push({ path: path ? `${path}.${r}` : r, keyword: 'required', message: 'is required' });
      }
      const props = s.properties || {};
      for (const k of keys) {
        const sub = path ? `${path}.${k}` : k;
        if (s.propertyNames !== undefined) this.#check(s.propertyNames, k, sub, ctx, errs);
        if (k in props) this.#check(props[k], v[k], sub, ctx, errs);
        else if (s.additionalProperties === false) errs.push({ path: sub, keyword: 'additionalProperties', message: 'unknown member' });
        else if (s.additionalProperties && typeof s.additionalProperties === 'object') this.#check(s.additionalProperties, v[k], sub, ctx, errs);
      }
    }
    if (s.anyOf) {
      const ok = s.anyOf.some((b) => { const e = []; this.#check(b, v, path, ctx, e); return e.length === 0; });
      if (!ok) {
        // Report the branch errors of the first branch whose type matches, for a useful field path.
        const detail = [];
        for (const b of s.anyOf) { const e = []; this.#check(b, v, path, ctx, e); if (!e.some((x) => x.keyword === 'type')) { detail.push(...e); break; } }
        if (detail.length) errs.push(...detail); else err('anyOf', 'matches no alternative');
      }
    }
    if (s.oneOf) {
      const results = s.oneOf.map((b) => { const e = []; this.#check(b, v, path, ctx, e); return e; });
      const n = results.filter((e) => e.length === 0).length;
      if (n !== 1) {
        if (n > 1) err('oneOf', 'matches more than one alternative');
        else {
          const best = results.reduce((a, b) => (b.length < a.length ? b : a));
          errs.push(...(best.length ? best : [{ path, keyword: 'oneOf', message: 'matches no alternative' }]));
        }
      }
    }
  }
}

/** First error mapped to the API's 422 shape: {field, code, message}. */
export function toValidationError(errors) {
  const e = errors[0];
  return { error: 'validation', message: `${e.path || 'body'}: ${e.message}`.slice(0, 200), field: (e.path || '').slice(0, 48), code: CODE[e.keyword] || 'format' };
}
