// Tiny DOM toolkit. Everything is built with createElement/textContent (never innerHTML), so API
// strings can never inject markup, and no inline style attributes are produced (CSP style-src 'self').
const SVGNS = 'http://www.w3.org/2000/svg';

/**
 * h('button.btn.primary', {type: 'submit', on: {click}}, 'Save')
 * props: class/className, text, on: {event: fn}, data: {k: v}, aria-* and other attributes,
 * boolean attributes (true -> present, false/null/undefined -> absent), value/checked as properties.
 */
export function h(sel, props, ...kids) {
  const [tag, ...cls] = sel.split('.');
  const el = document.createElement(tag || 'div');
  if (cls.length) el.className = cls.join(' ');
  if (props && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) {
    kids.unshift(props);
    props = null;
  }
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = el.className ? `${el.className} ${v}` : v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else if (k === 'data') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
      else if (k === 'value' || k === 'checked' || k === 'selected' || k === 'indeterminate') el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) append(el, k);
    else el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

/** <svg class="i"><use href="#i-name"/></svg> from the inlined sprite. */
export function icon(nameId, cls = '') {
  const s = document.createElementNS(SVGNS, 'svg');
  s.setAttribute('class', `i${cls ? ` ${cls}` : ''}`);
  s.setAttribute('aria-hidden', 'true');
  const u = document.createElementNS(SVGNS, 'use');
  u.setAttribute('href', `#${nameId.startsWith('sv') || nameId === 'logo' ? nameId : `i-${nameId}`}`);
  s.appendChild(u);
  return s;
}

/** Bare sprite reference without the .i line-icon class (logo, severity markers). */
export function sprite(id, cls = '') {
  const s = icon(id);
  s.setAttribute('class', cls);
  return s;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function replace(el, ...kids) {
  clear(el);
  append(el, kids);
  return el;
}

/** Set textContent only when it changed (avoids layout work on 1 Hz updates). */
export function setText(el, s) {
  if (el.textContent !== s) el.textContent = s;
}

export function toggle(el, cls, on) {
  if (el.classList.contains(cls) !== !!on) el.classList.toggle(cls, !!on);
}

/**
 * Cleanup scope for a view: collects unsubscribe functions, listeners and timers and disposes them
 * all when the route changes.
 */
export class Scope {
  constructor() {
    this.fns = [];
    this.dead = false;
  }

  add(fn) {
    if (this.dead) fn();
    else this.fns.push(fn);
    return fn;
  }

  listen(target, ev, fn, opts) {
    target.addEventListener(ev, fn, opts);
    this.add(() => target.removeEventListener(ev, fn, opts));
  }

  every(ms, fn) {
    const id = setInterval(fn, ms);
    this.add(() => clearInterval(id));
    return id;
  }

  later(ms, fn) {
    const id = setTimeout(fn, ms);
    this.add(() => clearTimeout(id));
    return id;
  }

  dispose() {
    this.dead = true;
    const fns = this.fns;
    this.fns = [];
    for (let i = fns.length - 1; i >= 0; i--) {
      try { fns[i](); } catch (e) { console.error(e); }
    }
  }
}

/** Trigger a browser download of a Blob. */
export function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** localStorage access that never throws (private mode, blocked storage). */
export const storage = {
  get(k) {
    try { return localStorage.getItem(k); } catch { return null; }
  },
  set(k, v) {
    try {
      if (v === null || v === undefined) localStorage.removeItem(k);
      else localStorage.setItem(k, v);
    } catch { /* storage unavailable: preference is not persisted */ }
  },
};
