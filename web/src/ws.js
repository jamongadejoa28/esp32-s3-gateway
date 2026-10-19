// WebSocket client (/ws, API.md §5): connect, subscribe, ping/clock offset, dead-socket detection
// and reconnect with exponential backoff capped at 10 s. Message handling is delegated to the
// app through callbacks so this module stays small and testable.

/** Reconnect delay for attempt n (0-based): 0.5 s · 2^n capped at 10 s, ±20 % jitter. */
export function backoffDelay(n, rand = Math.random) {
  const base = Math.min(10000, 500 * 2 ** Math.min(n, 10));
  return Math.round(base * (0.8 + 0.4 * rand()));
}

export const TOPICS = ['snap', 'alarm', 'comm', 'write', 'sys'];
const PING_MS = 20000;
const DEAD_MS = 30000; // comm frames arrive every 5 s; silence this long means a dead socket

export class LiveSocket {
  /**
   * @param {object} cb {message(msg), status(s), opened(), failed()} — failed() is called when a
   *   connection attempt closes before it ever opened (auth refused, limit, network).
   */
  constructor(cb) {
    this.cb = cb;
    this.ws = null;
    this.attempt = 0;
    this.timer = 0;
    this.pingTimer = 0;
    this.lastRx = 0;
    this.stopped = true;
    this.pingSent = 0;
    this.rtt = null;
    this.onVis = () => {
      if (document.visibilityState === 'visible' && !this.stopped && (!this.ws || this.ws.readyState > 1)) this.connectNow();
    };
  }

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    document.addEventListener('visibilitychange', this.onVis);
    this.connectNow();
  }

  stop() {
    this.stopped = true;
    document.removeEventListener('visibilitychange', this.onVis);
    clearTimeout(this.timer);
    clearInterval(this.pingTimer);
    if (this.ws) {
      this.ws.onclose = null;
      try { this.ws.close(1000); } catch { /* already closed */ }
      this.ws = null;
    }
    this.cb.status('idle');
  }

  connectNow() {
    clearTimeout(this.timer);
    if (this.ws) {
      this.ws.onclose = null;
      try { this.ws.close(); } catch { /* ignore */ }
    }
    this.cb.status(this.attempt ? 'reconnecting' : 'connecting');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    let ws;
    try {
      ws = new WebSocket(`${proto}//${location.host}/ws`);
    } catch {
      this.schedule();
      return;
    }
    this.ws = ws;
    let opened = false;
    ws.onopen = () => {
      opened = true;
      this.attempt = 0;
      this.lastRx = Date.now();
      this.send({ t: 'sub', topics: TOPICS });
      this.cb.status('open');
      this.cb.opened();
      clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => this.tick(), 5000);
    };
    ws.onmessage = (ev) => {
      this.lastRx = Date.now();
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      if (!m || typeof m.t !== 'string') return;
      if (m.t === 'pong' && this.pingSent) {
        this.rtt = Date.now() - this.pingSent;
        m.rtt = this.rtt;
        m.rx = Date.now() - this.rtt / 2;
        this.pingSent = 0;
      }
      this.cb.message(m);
      if (m.t === 'bye') this.stopped = true;
    };
    ws.onclose = () => {
      clearInterval(this.pingTimer);
      this.ws = null;
      if (this.stopped) {
        this.cb.status('idle');
        return;
      }
      if (!opened) this.cb.failed();
      this.schedule();
    };
    ws.onerror = () => { /* onclose follows */ };
  }

  schedule() {
    if (this.stopped) return;
    const d = backoffDelay(this.attempt++);
    this.cb.status('reconnecting');
    this.timer = setTimeout(() => {
      if (document.visibilityState === 'hidden') return; // resume on visibilitychange
      this.connectNow();
    }, d);
  }

  tick() {
    const now = Date.now();
    if (now - this.lastRx > DEAD_MS) {
      // A dead TCP path cannot finish the close handshake (the browser may sit in CLOSING for a
      // minute), so detach the socket and schedule the reconnect now instead of waiting for onclose.
      clearInterval(this.pingTimer);
      const ws = this.ws;
      this.ws = null;
      this.pingSent = 0;
      if (ws) {
        ws.onclose = ws.onmessage = ws.onopen = null;
        try { ws.close(); } catch { /* ignore */ }
      }
      this.schedule();
      return;
    }
    if (!this.pingSent || now - this.pingSent > PING_MS) {
      if (now - (this.lastPing || 0) >= PING_MS) {
        this.lastPing = now;
        this.pingSent = now;
        this.send({ t: 'ping' });
      }
    }
  }

  send(o) {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(o));
  }
}
