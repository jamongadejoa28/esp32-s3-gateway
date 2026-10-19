"""net pure logic (stream F): ip_filter.c (allowlist, AP exemption, lock-out guard, Host header check)
and net_prov.c (provisional apply/confirm/revert state machine, recovery-AP fallback/idle policy)."""
import ctypes
import ipaddress

import pytest

from conftest import compile_and_run

ESP_OK, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_STATE = 0, 0x102, 0x103
NONE, APPLY_PENDING, AWAIT_CONFIRM, CONFIRMED, REVERTED = range(5)
ACT_NONE, ACT_APPLY_CAND, ACT_APPLY_PREV = range(3)
AP_NONE, AP_BUTTON, AP_NO_LINK, AP_CONSOLE = range(4)
AP_IP, AP_MASK = 0xC0A89601, 0xFFFFFF00
MAX_ALLOW = 8


def ip(s):
    return int(ipaddress.IPv4Address(s))


class IpFilter(ctypes.Structure):
    _fields_ = [('net', ctypes.c_uint32 * MAX_ALLOW), ('mask', ctypes.c_uint32 * MAX_ALLOW), ('n', ctypes.c_uint8)]


class ProvFsm(ctypes.Structure):
    _fields_ = [('state', ctypes.c_uint8), ('confirming', ctypes.c_bool), ('deadline_ms', ctypes.c_uint64),
                ('confirm_s', ctypes.c_uint32)]


@pytest.fixture(scope='module')
def lib(host_lib):
    lib = host_lib('NET')
    P = ctypes.POINTER
    u32, u64, b = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_bool
    lib.ip_filter_set.argtypes = [P(IpFilter), P(u32), P(u32), ctypes.c_size_t]
    lib.ip_filter_match.argtypes = [P(IpFilter), u32]
    lib.ip_filter_match.restype = b
    lib.ip_filter_allows.argtypes = [P(IpFilter), u32, u32, u32, u32]
    lib.ip_filter_allows.restype = b
    lib.ip_filter_would_lock_out.argtypes = [P(IpFilter), u32, b]
    lib.ip_filter_would_lock_out.restype = b
    lib.ip_filter_host_ok.argtypes = [ctypes.c_char_p, P(u32), ctypes.c_size_t, ctypes.c_char_p]
    lib.ip_filter_host_ok.restype = b
    lib.net_prov_init.argtypes = [P(ProvFsm)]
    lib.net_prov_start.argtypes = [P(ProvFsm), u64, u32, u32]
    lib.net_prov_tick.argtypes = [P(ProvFsm), u64]
    lib.net_prov_confirm_begin.argtypes = [P(ProvFsm)]
    lib.net_prov_confirm_end.argtypes = [P(ProvFsm), b]
    lib.net_prov_revert.argtypes = [P(ProvFsm), P(ctypes.c_int)]
    lib.net_prov_settle.argtypes = [P(ProvFsm)]
    lib.net_prov_pending.argtypes = [P(ProvFsm)]
    lib.net_prov_pending.restype = b
    lib.net_prov_left_s.argtypes = [P(ProvFsm), u64]
    lib.net_prov_left_s.restype = u32
    lib.net_ap_should_fallback.argtypes = [b, b, b, u64, u64, u32]
    lib.net_ap_should_fallback.restype = b
    lib.net_ap_should_stop.argtypes = [b, ctypes.c_uint8, ctypes.c_uint8, b, u64, u64, u32]
    lib.net_ap_should_stop.restype = b
    lib.net_ap_off_in_s.argtypes = [b, ctypes.c_uint8, ctypes.c_uint8, b, u64, u64, u32]
    lib.net_ap_off_in_s.restype = u32
    return lib


def make_filter(lib, cidrs):
    # pass the address as written (host bits possibly set) to check that ip_filter_set masks them
    nets = [ip(c.split('/')[0]) for c in cidrs]
    masks = [int(ipaddress.IPv4Network(c, strict=False).netmask) for c in cidrs]
    f = IpFilter()
    arr_t = ctypes.c_uint32 * max(1, len(cidrs))
    lib.ip_filter_set(ctypes.byref(f), arr_t(*nets), arr_t(*masks), len(cidrs))
    return f


def test_enum_values_match_headers(tmp_path):
    out = compile_and_run(tmp_path, r'''
#include <stdio.h>
#include "net/net.h"
#include "net/ip_filter.h"
int main(void) {
    printf("%d %d %d %d %d|%d %d %d %d|%d|%d|%u %u\n", NET_PROV_NONE, NET_PROV_APPLY_PENDING, NET_PROV_AWAIT_CONFIRM,
           NET_PROV_CONFIRMED, NET_PROV_REVERTED, NET_AP_REASON_NONE, NET_AP_REASON_BUTTON, NET_AP_REASON_NO_LINK,
           NET_AP_REASON_CONSOLE, GW_MAX_IP_ALLOW, (int)sizeof(ip_filter_t), CFG_AP_IP, CFG_AP_MASK);
    return 0;
}
''')
    assert out.strip() == (f'0 1 2 3 4|0 1 2 3|{MAX_ALLOW}|{ctypes.sizeof(IpFilter)}|{AP_IP} {AP_MASK}')


# ---------------- allowlist ----------------

def test_set_masks_host_bits_and_truncates(lib):
    f = make_filter(lib, ['10.1.2.3/8', '192.168.10.77/24'])
    assert f.n == 2 and f.net[0] == ip('10.0.0.0') and f.net[1] == ip('192.168.10.0')
    big = make_filter(lib, [f'10.{i}.0.0/16' for i in range(12)])
    assert big.n == MAX_ALLOW
    assert lib.ip_filter_match(ctypes.byref(big), ip('10.7.1.1'))
    assert not lib.ip_filter_match(ctypes.byref(big), ip('10.8.1.1'))  # entry 9 dropped


def test_empty_and_null_allow_everyone(lib):
    f = make_filter(lib, [])
    assert lib.ip_filter_match(ctypes.byref(f), ip('8.8.8.8'))
    assert lib.ip_filter_match(None, ip('8.8.8.8'))
    assert lib.ip_filter_allows(None, ip('8.8.8.8'), ip('192.168.10.150'), AP_IP, AP_MASK)


@pytest.mark.parametrize('peer,ok', [('192.168.10.20', True), ('192.168.11.20', False), ('10.200.0.1', True),
                                     ('172.16.0.1', True), ('172.16.0.2', False), ('0.0.0.0', False)])
def test_match(lib, peer, ok):
    f = make_filter(lib, ['192.168.10.0/24', '10.0.0.0/8', '172.16.0.1/32'])
    assert lib.ip_filter_match(ctypes.byref(f), ip(peer)) is ok


def test_slash_zero_allows_all(lib):
    f = make_filter(lib, ['0.0.0.0/0'])
    assert lib.ip_filter_match(ctypes.byref(f), ip('203.0.113.9'))


@pytest.mark.parametrize('peer,local,ok', [
    ('127.0.0.1', '127.0.0.1', True),            # real loopback flow
    ('127.9.9.9', '127.0.0.1', True),
    ('127.0.0.1', '192.168.10.150', False),      # spoofed loopback source arriving on Ethernet
    ('127.9.9.9', '192.168.150.1', False),       # ... or on the AP
    ('127.0.0.1', '0.0.0.0', False),             # local unknown: no exemption
    ('192.168.150.2', '192.168.150.1', True),    # AP client: exempt
    ('192.168.150.254', '192.168.150.1', True),
    ('192.168.151.2', '192.168.150.1', False),   # local is the AP address but peer outside the AP subnet
    ('192.168.150.2', '192.168.10.150', False),  # peer looks like AP subnet but arrived on Ethernet
    ('192.168.10.5', '192.168.10.150', True),    # allowlisted LAN peer
    ('192.168.20.5', '192.168.10.150', False),
])
def test_allows_with_ap_rule(lib, peer, local, ok):
    f = make_filter(lib, ['192.168.10.0/24'])
    assert lib.ip_filter_allows(ctypes.byref(f), ip(peer), ip(local), AP_IP, AP_MASK) is ok


def test_ap_rule_disabled_with_zero_ap_ip(lib):
    f = make_filter(lib, ['10.0.0.0/8'])
    assert not lib.ip_filter_allows(ctypes.byref(f), ip('0.0.0.5'), 0, 0, 0)


@pytest.mark.parametrize('cidrs,client,via_ap,locked', [
    (['192.168.10.0/24'], '192.168.10.9', False, False),
    (['192.168.10.0/24'], '192.168.20.9', False, True),
    (['192.168.10.0/24'], '192.168.150.2', True, False),
    ([], '8.8.8.8', False, False),
    (['10.0.0.0/8'], '127.0.0.1', False, False),
])
def test_would_lock_out(lib, cidrs, client, via_ap, locked):
    f = make_filter(lib, cidrs)
    assert lib.ip_filter_would_lock_out(ctypes.byref(f), ip(client), via_ap) is locked


# ---------------- Host header ----------------

HOST = b'mestio-gw-3456'
IPS = (ctypes.c_uint32 * 3)(ip('192.168.10.150'), AP_IP, 0)


@pytest.mark.parametrize('hdr', [
    '192.168.10.150', '192.168.10.150:80', '192.168.10.150:65535', '192.168.150.1', '192.168.150.1:8080',
    'mestio-gw-3456', 'MESTIO-GW-3456', 'mestio-gw-3456:1', 'mestio-gw-3456.local', 'Mestio-Gw-3456.LOCAL:443',
])
def test_host_ok(lib, hdr):
    assert lib.ip_filter_host_ok(hdr.encode(), IPS, 3, HOST)


@pytest.mark.parametrize('hdr', [
    '', 'evil.example', '192.168.10.151', '192.168.010.150', '0192.168.10.150', '192.168.10.150.',
    'mestio-gw-3456.', 'mestio-gw-3456.local.', 'mestio-gw-3456.localx', 'xmestio-gw-3456', 'mestio-gw-345',
    'mestio-gw-3456.lan', '[::1]', '[::1]:80', '[fe80::1]', 'mestio-gw-3456:', 'mestio-gw-3456:0',
    'mestio-gw-3456:65536', 'mestio-gw-3456:123456', 'mestio-gw-3456:80:80', 'mestio-gw-3456:8a',
    'mestio-gw-3456: 80', ' mestio-gw-3456', 'mestio-gw-3456 ', '0.0.0.0', '1.2.3', '1.2.3.4.5', '256.1.1.1',
    '1.2.3.-4', '+1.2.3.4', ':80', '.local', 'a' * 200, '192.168.10.150:80/x',
])
def test_host_rejected(lib, hdr):
    assert not lib.ip_filter_host_ok(hdr.encode(), IPS, 3, HOST)


def test_host_without_hostname_or_ips(lib):
    assert not lib.ip_filter_host_ok(b'mestio-gw-3456', IPS, 3, None)
    assert not lib.ip_filter_host_ok(b'mestio-gw-3456', IPS, 3, b'')
    assert lib.ip_filter_host_ok(b'192.168.150.1', IPS, 3, None)
    assert not lib.ip_filter_host_ok(b'192.168.150.1', None, 0, HOST)
    assert not lib.ip_filter_host_ok(None, IPS, 3, HOST)


def test_host_eth_ip_zero_never_matches(lib):
    ips = (ctypes.c_uint32 * 2)(0, AP_IP)
    assert not lib.ip_filter_host_ok(b'0.0.0.0', ips, 2, HOST)
    assert lib.ip_filter_host_ok(b'192.168.150.1:80', ips, 2, HOST)


def test_host_hostname_max_length(lib):
    name = b'a' * 32
    assert lib.ip_filter_host_ok(name + b'.local:65535', IPS, 3, name)
    assert not lib.ip_filter_host_ok(b'a' * 33, IPS, 3, b'a' * 33)  # longer than GW_HOSTNAME_MAX


# ---------------- provisional state machine ----------------

def fsm(lib):
    f = ProvFsm()
    lib.net_prov_init(ctypes.byref(f))
    return f


def revert(lib, f):
    act = ctypes.c_int(-1)
    err = lib.net_prov_revert(ctypes.byref(f), ctypes.byref(act))
    return err, act.value


def test_prov_apply_then_timeout_revert(lib):
    f = fsm(lib)
    assert f.state == NONE and not lib.net_prov_pending(ctypes.byref(f))
    assert lib.net_prov_start(ctypes.byref(f), 1000, 3, 120) == ESP_OK
    assert f.state == APPLY_PENDING and lib.net_prov_pending(ctypes.byref(f))
    assert lib.net_prov_left_s(ctypes.byref(f), 1000) == 3
    assert lib.net_prov_left_s(ctypes.byref(f), 3001) == 1  # rounded up
    assert lib.net_prov_tick(ctypes.byref(f), 3999) == ACT_NONE
    assert lib.net_prov_tick(ctypes.byref(f), 4000) == ACT_APPLY_CAND
    assert f.state == AWAIT_CONFIRM
    assert lib.net_prov_left_s(ctypes.byref(f), 4000) == 120
    assert lib.net_prov_tick(ctypes.byref(f), 4000 + 119_999) == ACT_NONE
    assert lib.net_prov_tick(ctypes.byref(f), 4000 + 120_000) == ACT_APPLY_PREV
    assert f.state == REVERTED and not lib.net_prov_pending(ctypes.byref(f))
    assert lib.net_prov_left_s(ctypes.byref(f), 200_000) == 0
    assert lib.net_prov_tick(ctypes.byref(f), 10**9) == ACT_NONE  # nothing more to do
    lib.net_prov_settle(ctypes.byref(f))
    assert f.state == NONE


def test_prov_start_rejections(lib):
    f = fsm(lib)
    assert lib.net_prov_start(ctypes.byref(f), 0, 61, 120) == ESP_ERR_INVALID_ARG
    assert lib.net_prov_start(ctypes.byref(f), 0, 3, 9) == ESP_ERR_INVALID_ARG
    assert lib.net_prov_start(ctypes.byref(f), 0, 3, 3601) == ESP_ERR_INVALID_ARG
    assert f.state == NONE
    assert lib.net_prov_start(ctypes.byref(f), 0, 0, 10) == ESP_OK
    assert lib.net_prov_start(ctypes.byref(f), 0, 3, 120) == ESP_ERR_INVALID_STATE  # pending
    assert lib.net_prov_tick(ctypes.byref(f), 0) == ACT_APPLY_CAND  # apply_in_s 0: first tick applies
    assert lib.net_prov_start(ctypes.byref(f), 0, 3, 120) == ESP_ERR_INVALID_STATE  # awaiting confirm


def test_prov_confirm_after_apply(lib):
    f = fsm(lib)
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    lib.net_prov_tick(ctypes.byref(f), 3000)
    assert lib.net_prov_confirm_begin(ctypes.byref(f)) == ESP_OK
    assert lib.net_prov_confirm_begin(ctypes.byref(f)) == ESP_ERR_INVALID_STATE  # one confirm at a time
    assert lib.net_prov_tick(ctypes.byref(f), 10**7) == ACT_NONE  # frozen while committing
    assert f.state == AWAIT_CONFIRM
    assert revert(lib, f)[0] == ESP_ERR_INVALID_STATE
    assert lib.net_prov_confirm_end(ctypes.byref(f), True) == ACT_NONE  # already applied
    assert f.state == CONFIRMED and not f.confirming
    lib.net_prov_settle(ctypes.byref(f))
    assert f.state == NONE
    assert lib.net_prov_start(ctypes.byref(f), 0, 3, 120) == ESP_OK  # a new change may start


def test_prov_confirm_before_apply_applies_now(lib):
    f = fsm(lib)
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    assert lib.net_prov_confirm_begin(ctypes.byref(f)) == ESP_OK
    assert lib.net_prov_confirm_end(ctypes.byref(f), True) == ACT_APPLY_CAND
    assert f.state == CONFIRMED


def test_prov_failed_commit_resumes_timers(lib):
    f = fsm(lib)
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    lib.net_prov_tick(ctypes.byref(f), 3000)
    lib.net_prov_confirm_begin(ctypes.byref(f))
    assert lib.net_prov_tick(ctypes.byref(f), 200_000) == ACT_NONE
    assert lib.net_prov_confirm_end(ctypes.byref(f), False) == ACT_NONE
    assert f.state == AWAIT_CONFIRM and not f.confirming
    assert lib.net_prov_tick(ctypes.byref(f), 200_000) == ACT_APPLY_PREV  # deadline passed meanwhile


def test_prov_confirm_without_pending(lib):
    f = fsm(lib)
    assert lib.net_prov_confirm_begin(ctypes.byref(f)) == ESP_ERR_INVALID_STATE
    assert lib.net_prov_confirm_end(ctypes.byref(f), True) == ACT_NONE
    assert f.state == NONE


def test_prov_manual_revert(lib):
    f = fsm(lib)
    assert revert(lib, f)[0] == ESP_ERR_INVALID_STATE
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    assert revert(lib, f) == (ESP_OK, ACT_NONE)  # never applied
    assert f.state == REVERTED
    lib.net_prov_settle(ctypes.byref(f))
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    lib.net_prov_tick(ctypes.byref(f), 3000)
    assert revert(lib, f) == (ESP_OK, ACT_APPLY_PREV)
    assert revert(lib, f)[0] == ESP_ERR_INVALID_STATE


def test_prov_start_allowed_from_transient_states(lib):
    f = fsm(lib)
    lib.net_prov_start(ctypes.byref(f), 0, 3, 120)
    revert(lib, f)
    assert f.state == REVERTED
    assert lib.net_prov_start(ctypes.byref(f), 5000, 3, 120) == ESP_OK
    assert f.state == APPLY_PENDING


# ---------------- recovery AP policy ----------------

@pytest.mark.parametrize('en,active,has_ip,since,now,after,want', [
    (True, False, False, 0, 119_999, 120, False),
    (True, False, False, 0, 120_000, 120, True),
    (True, False, False, 50_000, 169_999, 120, False),
    (True, False, True, 0, 10**7, 120, False),   # Ethernet has an address
    (False, False, False, 0, 10**7, 120, False),  # fallback disabled
    (True, True, False, 0, 10**7, 120, False),    # already running
    (True, False, False, 10_000, 5_000, 30, False),  # clock before since: never
    (True, False, False, 0, 3_600_000, 3600, True),
])
def test_ap_fallback(lib, en, active, has_ip, since, now, after, want):
    assert lib.net_ap_should_fallback(en, active, has_ip, since, now, after) is want


@pytest.mark.parametrize('active,reason,clients,has_ip,idle_since,now,idle_min,stop,off_in', [
    (True, AP_BUTTON, 0, True, 0, 15 * 60_000 - 1, 15, False, 1),
    (True, AP_BUTTON, 0, True, 0, 15 * 60_000, 15, True, 0),
    (True, AP_BUTTON, 1, True, 0, 10**8, 15, False, 0),       # station connected
    (True, AP_CONSOLE, 0, False, 0, 60_000, 1, True, 0),
    (True, AP_NO_LINK, 0, False, 0, 10**8, 15, False, 0),     # only way in while Ethernet is down
    (True, AP_NO_LINK, 0, True, 0, 15 * 60_000, 15, True, 0),  # Ethernet back: idle rule applies
    (False, AP_BUTTON, 0, True, 0, 10**8, 15, False, 0),       # not running
    (True, AP_BUTTON, 0, True, 1000, 61_000, 2, False, 60),
])
def test_ap_idle_stop(lib, active, reason, clients, has_ip, idle_since, now, idle_min, stop, off_in):
    args = (active, reason, clients, has_ip, idle_since, now, idle_min)
    assert lib.net_ap_should_stop(*args) is stop
    assert lib.net_ap_off_in_s(*args) == off_in


# ---------------- AP start back-off, Ethernet/AP subnet overlap (fixer F) ----------------

@pytest.fixture(scope='module')
def lib2(lib):
    u32 = ctypes.c_uint32
    lib.net_ap_retry_delay_s.argtypes = [u32, ctypes.c_uint8]
    lib.net_ap_retry_delay_s.restype = u32
    lib.net_subnet_overlaps.argtypes = [u32, u32, u32, u32]
    lib.net_subnet_overlaps.restype = ctypes.c_bool
    return lib


@pytest.mark.parametrize('after,fails,want', [
    (120, 0, 0),      # no failure: no back-off
    (120, 1, 120),    # first failure: one fallback period
    (120, 2, 240),
    (120, 3, 480),
    (120, 4, 600),    # capped
    (120, 255, 600),
    (5, 1, 30),       # never faster than NET_AP_RETRY_MIN_S
    (5, 2, 60),
    (0, 1, 30),
    (3600, 1, 600),   # a long fallback period is still capped
])
def test_ap_retry_delay(lib2, after, fails, want):
    assert lib2.net_ap_retry_delay_s(after, fails) == want


@pytest.mark.parametrize('addr,mask,want', [
    ('192.168.150.1', '255.255.255.0', True),     # rogue lease of the AP address itself
    ('192.168.150.77', '255.255.255.0', True),
    ('192.168.150.200', '255.255.255.128', True),  # narrower subnet inside the AP subnet
    ('192.168.0.10', '255.255.0.0', True),         # wider subnet containing the AP subnet
    ('10.0.0.5', '255.0.0.0', False),
    ('192.168.151.10', '255.255.255.0', False),
    ('192.168.149.10', '255.255.255.0', False),
    ('192.168.148.10', '255.255.254.0', False),    # 192.168.148.0/23 stops at .149.255
    ('192.168.150.10', '255.255.255.255', True),
    ('0.0.0.0', '255.255.255.0', False),           # no address
    ('172.16.0.1', '0.0.0.0', True),               # everything on-link overlaps
])
def test_subnet_overlaps_ap(lib2, addr, mask, want):
    assert lib2.net_subnet_overlaps(ip(addr), ip(mask), AP_IP, AP_MASK) is want
