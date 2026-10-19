// Test helpers: spawn the mock server, a cookie-jar HTTP client with CSRF handling, schema checks.
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { SchemaSet } from './jsonschema.mjs';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const schemas = new SchemaSet(join(ROOT, 'docs', 'api'));

/** Assert that `value` validates against schema `name`. */
export function valid(name, value) {
  const errs = schemas.validate(name, value);
  assert.deepEqual(errs, [], `${name}: ${JSON.stringify(errs.slice(0, 3))}\nvalue: ${JSON.stringify(value).slice(0, 400)}`);
  return value;
}

/** Start tools/mock_server.mjs on a free port; resolves {base, port, stop()}. */
export function startMock(args = []) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [join(ROOT, 'tools', 'mock_server.mjs'), '--port', '0', '--quiet', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => { p.kill(); reject(new Error(`mock did not start: ${out}${err}`)); }, 20000);
    p.stdout.on('data', (d) => {
      out += d;
      const m = /listening on http:\/\/([\d.]+):(\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve({ base: `http://127.0.0.1:${m[2]}`, port: Number(m[2]), proc: p, stderr: () => err, stop: () => new Promise((r) => { p.once('exit', r); p.kill('SIGTERM'); }) });
      }
    });
    p.stderr.on('data', (d) => { err += d; });
    p.on('exit', (code) => { clearTimeout(timer); if (!/listening/.test(out)) reject(new Error(`mock exited ${code}: ${err}`)); });
  });
}

/** Minimal HTTP client with a cookie jar and the session CSRF token. */
export class Client {
  constructor(base) {
    this.base = base;
    this.cookie = null;
    this.csrf = null;
  }

  /**
   * @param {string} method
   * @param {string} path path below /api/v1 (or absolute when starting with '//')
   * @param {object} [o] {body, raw (Buffer), type, headers, csrf: false to omit}
   */
  async req(method, path, o = {}) {
    const url = path.startsWith('//') ? this.base + path.slice(1) : `${this.base}/api/v1${path}`;
    const headers = { ...(o.headers || {}) };
    if (this.cookie) headers.Cookie = this.cookie;
    if (method !== 'GET' && this.csrf && o.csrf !== false) headers['X-CSRF-Token'] = this.csrf;
    let body;
    if (o.raw !== undefined) { body = o.raw; headers['Content-Type'] = o.type || 'application/octet-stream'; } else if (o.body !== undefined) { body = typeof o.body === 'string' ? o.body : JSON.stringify(o.body); headers['Content-Type'] = o.type || 'application/json'; }
    const res = await fetch(url, { method, headers, body, redirect: 'manual' });
    const sc = res.headers.get('set-cookie');
    if (sc) {
      const m = /gw_sid=([^;]*)/.exec(sc);
      if (m) this.cookie = m[1] ? `gw_sid=${m[1]}` : null;
    }
    const buf = Buffer.from(await res.arrayBuffer());
    let json;
    const ct = res.headers.get('content-type') || '';
    if (ct.startsWith('application/json') && buf.length) json = JSON.parse(buf.toString('utf8'));
    return { status: res.status, headers: res.headers, json, buf, text: buf.toString('utf8') };
  }

  get(p, o) { return this.req('GET', p, o); }
  post(p, body, o) { return this.req('POST', p, { ...o, body }); }
  put(p, body, o) { return this.req('PUT', p, { ...o, body }); }
  del(p, o) { return this.req('DELETE', p, o); }

  /** Expect `status`; validate the body against `schema` (or error.schema for >= 400). */
  async expect(method, path, status, schema, o) {
    const r = await this.req(method, path, o);
    assert.equal(r.status, status, `${method} ${path}: expected ${status}, got ${r.status} ${r.text.slice(0, 300)}`);
    if (schema) valid(schema, r.json);
    else if (status >= 400 && r.json) valid('error', r.json);
    return r;
  }

  async login(user, pass) {
    const r = await this.req('POST', '/auth/login', { body: { user, pass } });
    if (r.status === 200) this.csrf = r.json.csrf;
    return r;
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll fn until it returns truthy (or time out). */
export async function until(fn, ms = 8000, step = 200) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('until: timed out');
    await sleep(step);
  }
}
