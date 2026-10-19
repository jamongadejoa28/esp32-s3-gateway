// Settings · Network: Ethernet (static/DHCP), hostname, recovery AP. Changes are applied
// provisionally: after `apply_in_s` they take effect and must be confirmed within
// `confirm_within_s` (from the new address if it changed), otherwise the gateway reverts.
import { h, icon, setText, replace } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put, post, errText } from '../api.js';
import { Form, panel, dialog, toast, toastErr } from '../ui.js';
import * as fmt from '../fmt.js';
import { isIp, isMask, overlaps, sameSubnet, AP_NET, AP_MASK } from '../ip4.js';

export function mount(el, scope) {
  let model = null;
  const f = new Form({ onSave: save });
  const ipOpt = (v) => (v && !isIp(v) ? t('v.ip') : null);
  const mode = f.select('eth.mode', t('net.mode'), [['static', t('net.static')], ['dhcp', 'DHCP']]);
  const ip = f.text('eth.ip', t('net.ip'), { validate: (v) => (staticMode() && !isIp(v) ? t('v.ip') : null), inputmode: 'decimal' });
  const mask = f.text('eth.mask', t('net.mask'), { validate: (v) => (staticMode() && !isMask(v) ? t('v.mask') : null), inputmode: 'decimal' });
  const gw = f.text('eth.gw', t('net.gw'), {
    inputmode: 'decimal',
    validate: (v) => ipOpt(v) || (staticMode() && v && isIp(ip.get()) && isMask(mask.get()) && !sameSubnet(ip.get(), v, mask.get()) ? t('v.gw_subnet') : null),
  });
  const dns1 = f.text('eth.dns1', t('net.dns1'), { validate: ipOpt, inputmode: 'decimal' });
  const dns2 = f.text('eth.dns2', t('net.dns2'), { validate: ipOpt, inputmode: 'decimal' });
  const host = f.text('hostname', t('net.hostname'), { required: true, max: 32, pattern: /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/, patternMsg: t('v.hostname'), hint: t('net.hostname_hint') });
  const staticMode = () => mode.get() === 'static';
  ip.validate = ((orig) => (v) => orig(v) || (staticMode() && isIp(v) && isMask(mask.get()) && overlaps(v, mask.get(), AP_NET, AP_MASK) ? t('v.overlap') : null))(ip.validate);
  const syncMode = () => { for (const c of [ip, mask, gw, dns1, dns2]) c.input.disabled = !staticMode(); };
  mode.input.addEventListener('change', syncMode);

  const fb = f.toggle('ap.fallback', t('net.ap_fallback'));
  const ssid = f.text('ap.ssid', t('net.ssid'), { required: true, max: 32 });
  const psk = f.secret('ap.psk', t('net.psk'), {
    hint: t('net.psk_hint'),
    validate: (v) => (v && !/^[\x20-\x7e]{8,63}$/.test(v) ? t('v.psk') : null),
  });
  const ch = f.num('ap.channel', t('net.channel'), { min: 1, max: 13 });
  const idle = f.num('ap.idle_min', t('net.ap_idle'), { min: 1, max: 120, unit: t('u.min_short') });
  const after = f.num('ap.fallback_after_s', t('net.ap_after'), { min: 30, max: 3600, unit: t('u.s_short') });

  // ---- live status ----
  const status = h('dl.kv');
  const banner = h('div', { 'aria-live': 'polite' });
  f.el.append(
    panel(t('net.eth'), h('div.panel-b', h('div.grid.g2', mode.row, h('div'), ip.row, mask.row, gw.row, h('div'), dns1.row, dns2.row, host.row))),
    panel(t('net.ap'), h('div.panel-b', h('div.grid.g2', h('div.span2', fb.row), ssid.row, psk.row, ch.row, idle.row, after.row))));
  f.saveBar();
  el.append(banner, panel(t('net.status'), h('div.panel-b', status)), f.el);

  async function save(v) {
    // static → DHCP: the new address is unknown here (no mDNS); say where to find it
    const toDhcp = v.eth.mode === 'dhcp' && model && model.eth.mode !== 'dhcp';
    const ok = await dialog({
      title: t('net.apply_q'),
      body: [h('p', { text: t('net.apply_text') }), v.eth.mode === 'static' && model && v.eth.ip !== model.eth.ip ? h('p', { text: t('net.apply_newip', { ip: v.eth.ip }) }) : null,
        toDhcp ? h('p.warn-t', { text: t('net.apply_dhcp') }) : null],
      actions: [{ label: t('cancel'), value: null }, { label: t('net.apply'), value: true, kind: 'primary', submit: true }],
    });
    if (!ok) return false;
    const body = { eth: v.eth, hostname: v.hostname, ap: v.ap };
    if (body.eth.mode === 'dhcp') body.eth = { mode: 'dhcp' };
    const r = await put('/config/network', body);
    newIp = v.eth.mode === 'static' && model && v.eth.ip !== model.eth.ip ? v.eth.ip : null;
    dhcpHost = toDhcp ? v.hostname : null;
    startProvisional({ state: 'apply_pending', left_s: r.apply_in_s + r.confirm_within_s }, r.apply_in_s);
    return false;
  }

  // ---- provisional banner ----
  let newIp = null;
  let dhcpHost = null; // set while a static → DHCP change waits for confirmation
  let deadline = 0;
  let applyAt = 0;
  let pollT = 0;
  let lost = false;
  const cdEl = h('div.countdown');
  const keepBtn = h('button.btn.primary', { type: 'button', text: t('net.keep') });
  keepBtn.addEventListener('click', async () => {
    keepBtn.disabled = true;
    try {
      await post('/config/network/confirm');
      toast(t('net.confirmed'));
      stopProvisional();
      load();
    } catch (e) { toast(errText(e), 'alarm'); keepBtn.disabled = false; }
  });

  function startProvisional(p, applyIn) {
    const now = Date.now();
    applyAt = p.state === 'apply_pending' ? now + (applyIn ?? 0) * 1000 : 0;
    deadline = now + p.left_s * 1000;
    lost = false;
    paintBanner();
    clearInterval(pollT);
    pollT = setInterval(pollProv, 2000);
  }
  function stopProvisional() {
    clearInterval(pollT);
    pollT = 0;
    deadline = 0;
    replace(banner);
  }
  scope.add(() => clearInterval(pollT));

  async function pollProv() {
    try {
      const m = await get('/config/network', null, { timeout: 3000 });
      lost = false;
      if (!m.provisional) {
        stopProvisional();
        load();
        return;
      }
      deadline = Date.now() + m.provisional.left_s * 1000 + (m.provisional.state === 'apply_pending' ? 120000 : 0);
      if (m.provisional.state === 'await_confirm') applyAt = 0;
    } catch {
      lost = true; // the address may have changed: confirm from the new one
    }
  }

  function paintBanner() {
    if (!deadline) return;
    const now = Date.now();
    const left = Math.max(0, Math.round((deadline - now) / 1000));
    const pending = applyAt && now < applyAt;
    setText(cdEl, pending ? t('net.applying', { n: Math.ceil((applyAt - now) / 1000) }) : `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`);
    if (!banner.firstChild) {
      const url = newIp ? `http://${newIp}/` : dhcpHost ? `http://${dhcpHost}/` : null;
      const link = url ? h('a', { href: url, text: url }) : null;
      banner.append(h('div.banner.warn', icon('alert'), h('div.grow',
        h('b', { text: t('net.prov_title') }),
        h('p', { text: newIp ? t('net.prov_newip') : dhcpHost ? t('net.prov_dhcp') : t('net.prov_text') }),
        link ? h('p', dhcpHost ? `${t('net.try_host')} ` : null, link) : null,
        h('p.lost.alarm-t', { hidden: true, text: t('net.prov_lost') })),
      h('div', cdEl, keepBtn)));
    }
    const lostEl = banner.querySelector('.lost');
    if (lostEl) lostEl.hidden = !lost;
    keepBtn.disabled = !!pending;
    if (left === 0) { stopProvisional(); toast(t('net.reverted'), 'warn'); load(); }
  }
  scope.every(1000, paintBanner);

  async function paintStatus() {
    try {
      const s = await get('/system/network');
      if (scope.dead) return;
      const row = (k, v) => [h('dt', { text: k }), h('dd', { text: v })];
      replace(status,
        row(t('net.link'), s.eth.link ? t('net.up') : t('net.down')),
        row(t('net.ip'), s.eth.has_ip ? `${s.eth.ip} / ${s.eth.mask}` : fmt.DASH),
        row(t('net.gw'), s.eth.gw || fmt.DASH),
        row('MAC', s.eth.mac),
        row(t('net.ap'), s.ap.active ? `${t('net.ap_on', { ssid: s.ap.ssid, n: s.ap.clients })} · ${t(`net.ap_reason.${s.ap.reason}`)}` : t('net.ap_off')),
        row('NTP', s.sntp.enabled ? (s.sntp.synced ? t('time.synced_at', { t: fmt.dateTime(s.sntp.last_ms) }) : t('time.not_synced')) : t('off')));
    } catch { /* status is informational */ }
  }

  async function load() {
    try {
      const m = await get('/config/network');
      if (scope.dead) return;
      model = m;
      f.load(m);
      psk.setStored(m.ap.psk_set);
      syncMode();
      if (m.provisional && !deadline) {
        // apply_pending reports the seconds until apply; the confirm window (120 s) follows it
        const p = m.provisional;
        startProvisional(p.state === 'apply_pending' ? { state: p.state, left_s: p.left_s + 120 } : p, p.state === 'apply_pending' ? p.left_s : 0);
      }
    } catch (e) { toastErr(e); }
  }
  load();
  paintStatus();
  scope.every(10000, () => { if (!document.hidden) paintStatus(); });
}
