// REST client for /api/v1 (docs/API.md): same-origin credentials, X-CSRF-Token on every mutating
// request, JSON bodies, timeouts, and error mapping to ApiError + localized messages.
import { t } from './i18n/index.js';

export const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(status, body, fallback) {
    super((body && body.message) || fallback || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
    this.code = this.body.error || (status === 0 ? 'network' : `http_${status}`);
    this.field = this.body.field || null;
    this.vcode = this.body.code || null; // validation code
    this.rules = this.body.rules || null;
    this.retryAfter = this.body.retry_after || null;
  }
}

let csrf = null;
let onAuthLost = () => {};
let onMustChange = () => {};

export const setCsrf = (v) => { csrf = v; };
export function setHandlers(h) {
  if (h.authLost) onAuthLost = h.authLost;
  if (h.mustChange) onMustChange = h.mustChange;
}

/** Build "/api/v1/path?query" skipping null/undefined query values. */
export function url(path, query) {
  let u = BASE + path;
  if (query) {
    const q = Object.entries(query).filter(([, v]) => v !== null && v !== undefined && v !== '');
    if (q.length) u += `?${q.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`;
  }
  return u;
}

/**
 * Perform a request.
 * @param {string} method
 * @param {string} path path below /api/v1
 * @param {object} [o] {body, query, ok: extra non-2xx statuses returned instead of thrown,
 *   timeout ms, signal, raw: return the Response}
 * @returns {Promise<any>} parsed JSON (or null for 204), or {status, body} when `o.ok` is given
 */
export async function req(method, path, o = {}) {
  const headers = { Accept: 'application/json' };
  let body;
  if (o.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(o.body);
  }
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), o.timeout || 15000);
  if (o.signal) o.signal.addEventListener('abort', () => ctl.abort(), { once: true });
  let res;
  try {
    res = await fetch(url(path, o.query), { method, headers, body, credentials: 'same-origin', cache: 'no-store', signal: ctl.signal });
  } catch (e) {
    clearTimeout(timer);
    throw new ApiError(0, { error: o.signal && o.signal.aborted ? 'aborted' : 'network' }, e.message);
  }
  clearTimeout(timer);
  if (o.raw) return res;
  let data = null;
  if (res.status !== 204 && res.status !== 304) {
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch { data = null; }
    }
  }
  const authRoute = path === '/auth/login' || path === '/session';
  if (res.status === 401 && !authRoute) onAuthLost('expired');
  if (res.status === 403 && data && data.error === 'password_change_required') onMustChange();
  if (o.ok && o.ok.includes(res.status)) return { status: res.status, body: data };
  if (!res.ok) throw new ApiError(res.status, data);
  if (o.ok) return { status: res.status, body: data };
  return data;
}

export const get = (p, query, o) => req('GET', p, { ...o, query });
export const put = (p, body, o) => req('PUT', p, { ...o, body });
export const post = (p, body, o) => req('POST', p, { ...o, body });
export const del = (p, o) => req('DELETE', p, o);

/**
 * Upload a binary body with progress (fetch has no upload progress): firmware.
 * @param {(sent: number, total: number) => void} onProgress
 */
export function upload(path, blob, headers, onProgress, query) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('POST', url(path, query));
    x.setRequestHeader('Content-Type', 'application/octet-stream');
    if (csrf) x.setRequestHeader('X-CSRF-Token', csrf);
    for (const [k, v] of Object.entries(headers || {})) x.setRequestHeader(k, v);
    x.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
    x.onload = () => {
      let data = null;
      try { data = x.responseText ? JSON.parse(x.responseText) : null; } catch { data = null; }
      if (x.status === 401) onAuthLost('expired');
      if (x.status >= 200 && x.status < 300) resolve(data);
      else reject(new ApiError(x.status, data));
    };
    x.onerror = () => reject(new ApiError(0, { error: 'network' }));
    x.ontimeout = () => reject(new ApiError(0, { error: 'network' }));
    x.timeout = 300000;
    x.send(blob);
  });
}

/** Human message for an error: specific code text, then HTTP status text, then server message. */
export function errText(e) {
  if (!(e instanceof ApiError)) return t('err.unexpected');
  if (e.code === 'validation' && e.vcode) {
    const s = t(`v.${e.vcode}`);
    if (s !== `v.${e.vcode}`) return e.field ? `${s} (${e.field})` : s;
  }
  if (e.code === 'rate_limited' && e.retryAfter) return t('err.rate_limited_s', { n: e.retryAfter });
  if (e.code === 'rejected' && e.body.reason) return reasonText(e.body.reason);
  const k = `err.${e.code}`;
  const s = t(k);
  if (s !== k) return s;
  const byStatus = { 400: 'bad_request', 404: 'not_found', 413: 'payload_too_large', 500: 'internal', 502: 'network', 503: 'unavailable' }[e.status];
  return byStatus ? t(`err.${byStatus}`) : e.message || t('err.unexpected');
}

/** Text for a write rejection/uncertain reason ("exception:N" included). */
export function reasonText(r) {
  if (!r) return '';
  if (r.startsWith('exception:')) return t('wr.exception', { n: r.slice(10) });
  const k = `wr.${r}`;
  const s = t(k);
  return s === k ? r : s;
}

/** Download a GET endpoint as a file (uses the session cookie). */
export async function fetchBlob(path, query) {
  const res = await req('GET', path, { query, raw: true, timeout: 60000 });
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (res.status === 401) onAuthLost('expired');
    throw new ApiError(res.status, data);
  }
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="([^"]+)"/.exec(cd);
  return { blob: await res.blob(), filename: m ? m[1] : null };
}
