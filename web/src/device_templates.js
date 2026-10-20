// Pure template data helpers. Unknown/offline/stale devices never produce apparent live values.
import { derive, staleAfterMs, snapshotReady } from './live.js';
export const templateFor = (device, templates) => templates.find((t) => t.id === (device.template_id || 'mex150'));
export function deviceStatus(device, live, now, pollMs, comm) {
  if (!device.enabled) return 'disabled';
  if (!live?.known || !live.seq) return comm?.online === false ? 'offline' : 'waiting';
  if (!live.on) return 'offline';
  if (live.fresh === false) return 'stale';
  if (!snapshotReady(live)) return 'waiting';
  if (now - live.rx > staleAfterMs(pollMs)) return 'stale';
  return 'online';
}
export function deviceValues(device, live, now, pollMs, comm) {
  return deviceStatus(device, live, now, pollMs, comm) === 'online' ? derive(live) : null;
}
export function channelRaw(channel, live) {
  if (channel.source !== 'reg' || channel.access === 'disabled' || !live?.known) return null;
  const raw = live.regs[channel.addr];
  if (!Number.isFinite(raw)) return null;
  return channel.addr === 40005 ? raw & 1 : raw / channel.scale;
}
