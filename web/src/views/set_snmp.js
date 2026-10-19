// Settings · SNMP: agent switches, v1/v2c communities (write-only), two fixed SNMPv3 users
// (authPriv SHA + AES; passphrases write-only), trap targets (≤ 4), system group, test trap and
// MIB download.
import { h, icon, replace, download } from '../dom.js';
import { t } from '../i18n/index.js';
import { get, put, post, fetchBlob } from '../api.js';
import { Form, panel, dialog, toastErr, table } from '../ui.js';
import { isIp } from '../ip4.js';

/** Write-only community with an explicit "remove" action (sends ""). */
function community(f, path, label) {
  const c = f.secret(path, label, { validate: (v) => (v && !/^[\x21-\x7e]{1,32}$/.test(v) ? t('v.community') : null) });
  c.cleared = false;
  const rm = h('button.btn.ghost.sm', { type: 'button', text: t('remove') });
  rm.addEventListener('click', () => { c.cleared = true; c.input.value = ''; c.input.placeholder = t('secret.removing'); f.refresh(); });
  c.input.addEventListener('input', () => { c.cleared = false; });
  const get0 = c.get;
  c.get = () => (c.cleared ? '' : get0());
  c.skip = (v) => v === '' && !c.cleared;
  const setStored = c.setStored;
  c.setStored = (isSet) => { setStored(isSet); c.cleared = false; rm.hidden = !isSet; };
  c.row.appendChild(rm);
  return c;
}

export function mount(el, scope) {
  const f = new Form({ onSave: save });
  const en = f.toggle('enabled', t('snmp.enabled'));
  const v1 = f.toggle('v1', 'SNMPv1');
  const v2 = f.toggle('v2c', 'SNMPv2c');
  const at = f.toggle('auth_traps', t('snmp.auth_traps'));
  const ro = community(f, 'ro', t('snmp.ro'));
  const rw = community(f, 'rw', t('snmp.rw'));
  ro.validate = ((o) => (v) => o(v) || ((v1.get() || v2.get()) && !roSet && !v ? t('snmp.ro_required') : null))(ro.validate);
  let roSet = false;
  const v3en = f.toggle('v3.enabled', t('snmp.v3_enabled'));
  const sysName = f.text('sys.name', t('snmp.sys_name'), { max: 63 });
  const sysContact = f.text('sys.contact', t('snmp.sys_contact'), { max: 63 });
  const sysLoc = f.text('sys.location', t('snmp.sys_location'), { max: 63 });

  // v3 users (2 fixed slots)
  let users = [];
  const usersBox = h('div');
  const passIn = (u, k, label) => {
    const i = h('input.inp', { type: 'password', autocomplete: 'new-password', placeholder: u.keys_set ? t('secret.set') : t('secret.unset'), 'aria-label': label });
    i.addEventListener('input', () => { u[k] = i.value; });
    return i;
  };
  function paintUsers() {
    replace(usersBox, table([
      { label: t('snmp.user'), cell: (u) => { const i = h('input.inp', { type: 'text', value: u.name, 'aria-label': t('snmp.user') }); i.addEventListener('input', () => { u.name = i.value.trim(); }); return i; } },
      { label: t('snmp.access'), cell: (u) => { const s = h('select.inp', { 'aria-label': t('snmp.access') }, h('option', { value: 'ro', text: t('snmp.ro_acc') }), h('option', { value: 'rw', text: t('snmp.rw_acc') })); s.value = u.access; s.addEventListener('change', () => { u.access = s.value; f.refresh(); }); return s; } },
      { label: t('snmp.user_on'), cell: (u) => { const c = h('input.switch', { type: 'checkbox', role: 'switch', checked: u.enabled, 'aria-label': t('snmp.user_on') }); c.addEventListener('change', () => { u.enabled = c.checked; f.refresh(); }); return c; } },
      { label: t('snmp.auth_pass'), cell: (u) => passIn(u, 'auth_pass', t('snmp.auth_pass')) },
      { label: t('snmp.priv_pass'), cell: (u) => passIn(u, 'priv_pass', t('snmp.priv_pass')) },
      { label: t('snmp.keys'), cls: 'nowrap', cell: (u) => (u.keys_set ? h('span.ok-t', { text: t('snmp.keys_set') }) : h('span.warn-t', { text: t('snmp.keys_unset') })) },
    ], users, { caption: t('snmp.v3') }));
  }
  const usersErr = h('div.err', { hidden: true, role: 'alert' });
  f.custom({
    path: 'v3.users', row: usersBox, err: usersErr,
    get: () => users.map((u) => {
      const o = { name: u.name, access: u.access, enabled: u.enabled };
      if (u.auth_pass) o.auth_pass = u.auth_pass;
      if (u.priv_pass) o.priv_pass = u.priv_pass;
      return o;
    }),
    set: (v) => { users = (v || []).map((u) => ({ ...u, auth_pass: '', priv_pass: '' })); paintUsers(); },
    validate: (v) => {
      for (const u of v) {
        if (!/^[A-Za-z0-9_.-]{1,32}$/.test(u.name)) return t('v.snmp_user');
        for (const k of ['auth_pass', 'priv_pass']) if (u[k] !== undefined && (u[k].length < 8 || u[k].length > 64)) return t('v.passphrase');
        if ((u.auth_pass === undefined) !== (u.priv_pass === undefined) && !users.find((x) => x.name === u.name)?.keys_set) return t('v.passphrase_both');
      }
      return null;
    },
  });

  // trap targets
  let traps = [];
  const trapsBox = h('div');
  const addTrap = h('button.btn.sm', { type: 'button' }, icon('plus'), t('snmp.add_trap'));
  addTrap.addEventListener('click', () => { traps.push({ host: '', port: 162, version: 'v2c', inform: false, enabled: true, community_set: false, community: '' }); paintTraps(); f.refresh(); });
  const tin = (tr, k, kind, label) => {
    const i = h(`input.inp${kind === 'num' ? '.num' : ''}`, { type: kind === 'pw' ? 'password' : 'text', value: kind === 'pw' ? '' : String(tr[k]), autocomplete: kind === 'pw' ? 'new-password' : 'off', 'aria-label': label, placeholder: kind === 'pw' ? (tr.community_set ? t('secret.set') : t('snmp.default_comm')) : null, inputmode: kind === 'num' ? 'numeric' : null });
    i.addEventListener('input', () => { tr[k] = kind === 'num' ? Number(i.value) : i.value.trim(); });
    return i;
  };
  function paintTraps() {
    addTrap.disabled = traps.length >= 4;
    replace(trapsBox, table([
      { label: t('snmp.trap_host'), cell: (tr) => tin(tr, 'host', 'text', t('snmp.trap_host')) },
      { label: t('snmp.trap_port'), cell: (tr) => tin(tr, 'port', 'num', t('snmp.trap_port')) },
      { label: t('snmp.trap_version'), cell: (tr) => { const s = h('select.inp', { 'aria-label': t('snmp.trap_version') }, h('option', { value: 'v1', text: 'v1' }), h('option', { value: 'v2c', text: 'v2c' })); s.value = tr.version; s.addEventListener('change', () => { tr.version = s.value; if (s.value === 'v1') tr.inform = false; paintTraps(); f.refresh(); }); return s; } },
      { label: t('snmp.trap_inform'), cell: (tr) => { const c = h('input.switch', { type: 'checkbox', role: 'switch', checked: tr.inform, disabled: tr.version === 'v1', 'aria-label': t('snmp.trap_inform') }); c.addEventListener('change', () => { tr.inform = c.checked; f.refresh(); }); return c; } },
      { label: t('snmp.trap_enabled'), cell: (tr) => { const c = h('input.switch', { type: 'checkbox', role: 'switch', checked: tr.enabled, 'aria-label': t('snmp.trap_enabled') }); c.addEventListener('change', () => { tr.enabled = c.checked; f.refresh(); }); return c; } },
      { label: t('snmp.trap_community'), cell: (tr) => tin(tr, 'community', 'pw', t('snmp.trap_community')) },
      { label: '', cls: 'act', cell: (tr) => h('button.btn.ghost.sm.icon', { type: 'button', 'aria-label': t('remove'), on: { click: () => { traps = traps.filter((x) => x !== tr); paintTraps(); f.refresh(); } } }, icon('trash')) },
    ], traps, { caption: t('snmp.traps'), empty: t('snmp.no_traps') }));
  }
  const trapsErr = h('div.err', { hidden: true, role: 'alert' });
  f.custom({
    path: 'traps', row: trapsBox, err: trapsErr,
    get: () => traps.map((tr) => {
      const o = { host: tr.host, port: tr.port, version: tr.version, inform: tr.inform, enabled: tr.enabled };
      if (tr.community) o.community = tr.community;
      return o;
    }),
    set: (v) => { traps = (v || []).map((tr) => ({ ...tr, community: '' })); paintTraps(); },
    validate: (v) => {
      for (const tr of v) {
        if (!isIp(tr.host)) return t('v.trap_host');
        if (!Number.isInteger(tr.port) || tr.port < 1 || tr.port > 65535) return t('v.port');
        if (tr.community !== undefined && !/^[\x21-\x7e]{1,32}$/.test(tr.community)) return t('v.community');
      }
      return null;
    },
  });

  const testBtn = h('button.btn', { type: 'button' }, icon('snmp'), t('snmp.test'));
  testBtn.addEventListener('click', async () => {
    testBtn.disabled = true;
    try {
      const r = await post('/snmp/test-trap', undefined, { timeout: 15000 });
      await dialog({
        title: t('snmp.test_result'),
        body: table([{ label: t('snmp.trap_host'), cell: (x) => x.host }, { label: t('snmp.result'), cell: (x) => (x.ok ? h('span.ok-t', { text: t('snmp.sent_ok') }) : h('span.alarm-t', { text: t('snmp.sent_fail') })) }], r.sent),
        actions: [{ label: t('close'), value: true, kind: 'primary', submit: true }],
      });
    } catch (e) { toastErr(e); }
    testBtn.disabled = false;
  });
  const mibBtn = h('button.btn', { type: 'button' }, icon('down'), t('snmp.mib'));
  mibBtn.addEventListener('click', async () => {
    try {
      const { blob, filename } = await fetchBlob('/snmp/mib');
      download(blob, filename || 'MIB.txt');
    } catch (e) { toastErr(e); }
  });

  const svcWarn = h('div');
  f.el.append(
    panel(t('snmp.agent'), h('div.panel-b', h('div.grid.g2', en.row, at.row, v1.row, v2.row, ro.row, rw.row)), testBtn, mibBtn),
    panel(t('snmp.v3'), h('div', h('div.panel-b', v3en.row, h('p.muted', { text: t('snmp.v3_hint') })), usersBox, h('div.panel-b', usersErr))),
    panel(t('snmp.traps'), h('div', trapsBox, h('div.panel-b', trapsErr, addTrap))),
    panel(t('snmp.system'), h('div.panel-b', h('div.grid', sysName.row, sysContact.row, sysLoc.row))));
  f.saveBar();
  el.append(svcWarn, f.el);

  function apply(m) {
    roSet = m.ro_set;
    ro.setStored(m.ro_set);
    rw.setStored(m.rw_set);
  }
  async function save(v) {
    const m = await put('/config/snmp', v, { timeout: 20000 });
    apply(m);
    return m;
  }
  Promise.all([get('/config/snmp'), get('/config/security')]).then(([m, sec]) => {
    if (scope.dead) return;
    f.load(m);
    apply(m);
    if (!sec.services.snmp) replace(svcWarn, h('div.banner.warn', icon('alert'), h('div.grow', { text: t('snmp.svc_off') }), h('a', { href: '#/settings/users', text: t('set.users') })));
  }).catch(toastErr);
}
