import { h, Scope } from './dom.js';
import { t } from './i18n/index.js';
import { state, on } from './store.js';
import { mount } from './views/monitor.js';
let dismiss = null;
export function openMonitor(id, owner) {
  dismiss?.();
  const device = state.devices.find((d) => d.id === id);
  if (!device) return;
  const focus = document.activeElement;
  const scope = new Scope();
  const body = h('div.monitor-body');
  const dlg = h('dialog.monitor-popup', { 'aria-label': `${device.name} · ${t('nav.monitor')}` },
    h('div.monitor-toolbar', h('b', { text: device.name }), h('span.grow'),
      h('button.btn', { type: 'button', text: t('close'), on: { click: close } })), body);
  function close() {
    if (scope.dead) return;
    scope.dispose();
    dlg.close();
    dlg.remove();
    if (focus?.isConnected) focus.focus();
    if (dismiss === close) dismiss = null;
  }
  dismiss = close;
  owner?.add(close);
  dlg.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  scope.add(on('devices', () => {
    const next = state.devices.find((d) => d.id === id);
    if (!next || next.slave !== device.slave || next.template_id !== device.template_id) close();
  }));
  document.body.appendChild(dlg);
  dlg.showModal();
  mount(body, [], scope, { deviceId: id, popup: true });
}
