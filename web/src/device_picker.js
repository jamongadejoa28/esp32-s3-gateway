import { h } from './dom.js';
import { t } from './i18n/index.js';
import { state, on, selectDevice, enabledDevices } from './store.js';

export function devicePicker(scope) {
  const devs = enabledDevices();
  if (devs.length < 2) return null;
  const sel = h('select.inp', { 'aria-label': t('dev.pick'), on: { change: () => selectDevice(Number(sel.value)) } },
    devs.map((d) => h('option', { value: String(d.id), text: d.name || `#${d.id}` })));
  sel.value = String(state.dev);
  scope.add(on('dev', () => { sel.value = String(state.dev); }));
  return h('div', sel);
}
