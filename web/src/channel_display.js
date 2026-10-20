// Shared template readings for the cards, expanded details and device settings.
import { t, name } from './i18n/index.js';
import { state, live } from './store.js';
import { templateFor, deviceValues, channelRaw } from './device_templates.js';
import { equipment } from './live.js';
import * as fmt from './fmt.js';
export const channelSupported = (ch) => ch.source !== 'none' && ch.access !== 'disabled' && ch.access !== 'conf_only';
export const channelVisible = (d, ch) => channelSupported(ch) && !!((d.display_mask ?? 0x3fffff) & (1 << ch.id));
export const channelsFor = (d) => templateFor(d, state.templates)?.channels || [];
export function channelText(d, ch, withUnit = true) {
  if (ch.access === 'disabled') return t('template.disabled');
  if (ch.access === 'conf_only') return t('template.config_only');
  const lv = live(d.id);
  const derived = deviceValues(d, lv, Date.now(), state.pollMs, state.comm.get(d.id));
  if (!derived) return fmt.DASH;
  if (ch.source === 'reg') {
    const v = channelRaw(ch, lv);
    if (v === null) return fmt.DASH;
    if (ch.addr === 40005) return t(v ? 'run.run' : 'run.stop');
    return `${fmt.num(v, ch.scale > 1 ? 1 : 0)}${withUnit && ch.unit ? ` ${ch.unit}` : ''}`;
  }
  if (ch.source === 'mode') return derived.running === null ? fmt.DASH : !derived.running ? t('run.stop') : derived.mode.length ? derived.mode.map((m) => t(`mode.${m}`)).join(' · ') : t('mode.idle');
  if (ch.source === 'outputs') {
    const active = equipment(lv.coils).filter((e) => e.on).map((e) => name(state.meta.coils.find((c) => c.key === `run_${e.key}`)) || e.key);
    if ((lv.coils >>> 14) & 1) active.push(t('mode.dehum'));
    return active.join(' · ') || t('eq.off');
  }
  if (ch.source === 'alarms') return state.meta.coils.filter((c) => c.n >= 17 && ((lv.coils >>> (c.n - 1)) & 1)).map(name).join(' · ') || t('alarms.none');
  return fmt.DASH;
}
