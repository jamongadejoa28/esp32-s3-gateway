"""sysmgr pure logic (stream F): firmware version compare / OTA downgrade guard (ota_version.c),
RFC 5424 syslog formatting, rate limiting and severity mapping (syslog_fmt.c), status LED policy
(led_policy.c)."""
import ctypes
import datetime as dt
import itertools
import re

import pytest

from conftest import compile_and_run

ESP_OK, ESP_ERR_INVALID_VERSION = 0, 0x10A
LED = dict(OFF=0, BOOT=1, OK=2, NO_NET=3, AP=4, COMM_LOST=5, ALARM=6, CRITICAL=7, FAULT=8, OTA=9, AP_ARMED=10,
           RESET_ARMED=11)
BOM = '﻿'


class Ver(ctypes.Structure):
    _fields_ = [('major', ctypes.c_uint32), ('minor', ctypes.c_uint32), ('patch', ctypes.c_uint32),
                ('pre', ctypes.c_char * 32)]


class RateLimiter(ctypes.Structure):
    _fields_ = [('milli_tokens', ctypes.c_uint32), ('last_ms', ctypes.c_uint32), ('primed', ctypes.c_bool),
                ('dropped', ctypes.c_uint32)]


class LedIn(ctypes.Structure):
    _fields_ = [('reset_armed', ctypes.c_bool), ('ap_armed', ctypes.c_bool), ('booting', ctypes.c_bool),
                ('ota', ctypes.c_bool), ('fault', ctypes.c_bool), ('critical', ctypes.c_uint16),
                ('alarms', ctypes.c_uint16), ('comm_lost', ctypes.c_bool), ('ap_active', ctypes.c_bool),
                ('net_ok', ctypes.c_bool)]


@pytest.fixture(scope='module')
def lib(host_lib):
    lib = host_lib('SYSMGR')
    P = ctypes.POINTER
    lib.sys_ver_parse.argtypes = [ctypes.c_char_p, P(Ver)]
    lib.sys_ver_parse.restype = ctypes.c_bool
    lib.sys_ver_cmp.argtypes = [P(Ver), P(Ver)]
    lib.sys_ota_check_image.argtypes = [ctypes.c_char_p] * 4 + [ctypes.c_bool]
    lib.sys_build_date_iso.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.sys_build_date_iso.restype = ctypes.c_bool
    lib.syslog_format.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_int64,
                                  ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.syslog_format.restype = ctypes.c_size_t
    lib.syslog_rl_take.argtypes = [P(RateLimiter), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.syslog_rl_take.restype = ctypes.c_bool
    lib.syslog_rl_take_dropped.argtypes = [P(RateLimiter)]
    lib.syslog_rl_take_dropped.restype = ctypes.c_uint32
    lib.syslog_alarm_severity.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
    lib.syslog_alarm_severity.restype = ctypes.c_uint8
    lib.sys_led_select.argtypes = [P(LedIn)]
    lib.sys_led_select.restype = ctypes.c_uint8
    return lib


def test_layouts_and_constants(tmp_path):
    out = compile_and_run(tmp_path, r'''
#include <stdio.h>
#include "board/board.h"
#include "alarm/alarm.h"
''' + '#include "' + str((__import__('conftest').ROOT / 'components/sysmgr/sysmgr_pure.h')) + r'''"
int main(void) {
    printf("%zu %zu %zu|%d %d %d %d %d %d %d %d %d %d %d %d|%d %d %d %d\n", sizeof(sys_ver_t),
           sizeof(syslog_rl_t), sizeof(sys_led_inputs_t), BOARD_LED_OFF, BOARD_LED_BOOT, BOARD_LED_OK,
           BOARD_LED_NO_NET, BOARD_LED_AP, BOARD_LED_COMM_LOST, BOARD_LED_ALARM, BOARD_LED_CRITICAL, BOARD_LED_FAULT,
           BOARD_LED_OTA, BOARD_LED_AP_ARMED, BOARD_LED_RESET_ARMED, ALM_SEV_INFO, ALM_SEV_MINOR, ALM_SEV_MAJOR, ALM_SEV_CRITICAL);
    return 0;
}
''')
    sizes, leds, sevs = out.strip().split('|')
    assert sizes == f'{ctypes.sizeof(Ver)} {ctypes.sizeof(RateLimiter)} {ctypes.sizeof(LedIn)}'
    assert leds == ' '.join(str(LED[k]) for k in ['OFF', 'BOOT', 'OK', 'NO_NET', 'AP', 'COMM_LOST', 'ALARM',
                                                  'CRITICAL', 'FAULT', 'OTA', 'AP_ARMED', 'RESET_ARMED'])
    assert sevs == '0 1 2 3'


# ---------------- versions ----------------

def parse(lib, s):
    v = Ver()
    ok = lib.sys_ver_parse(s.encode(), ctypes.byref(v))
    return (v.major, v.minor, v.patch, v.pre.decode()) if ok else None


@pytest.mark.parametrize('s,want', [
    ('1.0.0', (1, 0, 0, '')), ('v1.2.3', (1, 2, 3, '')), ('V10.20.30', (10, 20, 30, '')),
    ('1.0.0-alpha', (1, 0, 0, 'alpha')), ('1.0.0-alpha.1', (1, 0, 0, 'alpha.1')),
    ('1.0.0-rc.1+build.5', (1, 0, 0, 'rc.1')), ('1.0.0+20261019', (1, 0, 0, '')),
    ('0.0.0', (0, 0, 0, '')), ('4294967295.0.0', (4294967295, 0, 0, '')), ('1.0.0-0A.is.legal', (1, 0, 0, '0A.is.legal')),
    ('1.0.0-x-y-z.--', (1, 0, 0, 'x-y-z.--')),
])
def test_ver_parse_valid(lib, s, want):
    assert parse(lib, s) == want


@pytest.mark.parametrize('s', ['', '1', '1.0', '1.0.0.0', '01.0.0', '1.02.0', '1.0.00', '1.0.0-', '1.0.0-01',
                               '1.0.0-alpha..1', '1.0.0+', '1.0.0-al$pha', 'a.b.c', '1.0.0 ', ' 1.0.0', '4294967296.0.0',
                               '1.0.0-' + 'a' * 32, 'vv1.0.0', '-1.0.0', '1.0.0+build..1'])
def test_ver_parse_invalid(lib, s):
    assert parse(lib, s) is None


def test_ver_semver_precedence(lib):
    order = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11',
             '1.0.0-rc.1', '1.0.0', '1.0.1', '1.1.0', '1.10.0', '2.0.0-rc.1', '2.0.0']
    vers = []
    for s in order:
        v = Ver()
        assert lib.sys_ver_parse(s.encode(), ctypes.byref(v)), s
        vers.append(v)
    for (i, a), (j, b) in itertools.product(enumerate(vers), repeat=2):
        c = lib.sys_ver_cmp(ctypes.byref(a), ctypes.byref(b))
        assert (c > 0) - (c < 0) == (i > j) - (i < j), (order[i], order[j], c)
    x, y = Ver(), Ver()
    lib.sys_ver_parse(b'1.2.3+a', ctypes.byref(x))
    lib.sys_ver_parse(b'v1.2.3+b', ctypes.byref(y))
    assert lib.sys_ver_cmp(ctypes.byref(x), ctypes.byref(y)) == 0  # build metadata ignored


@pytest.mark.parametrize('proj,new,running,allow,want', [
    ('mestio_gw', '1.2.0', '1.1.0', False, ESP_OK),
    ('mestio_gw', '1.1.0', '1.1.0', False, ESP_OK),            # reinstall same version
    ('mestio_gw', '1.0.9', '1.1.0', False, ESP_ERR_INVALID_VERSION),  # downgrade refused
    ('mestio_gw', '1.0.9', '1.1.0', True, ESP_OK),             # ?allow_downgrade=1
    ('mestio_gw', '1.1.0-rc.1', '1.1.0', False, ESP_ERR_INVALID_VERSION),
    ('mestio_gw', '1.1.0', '1.1.0-rc.1', False, ESP_OK),
    ('other_app', '9.9.9', '1.0.0', True, ESP_ERR_INVALID_VERSION),  # wrong project: never
    ('mestio_gw2', '9.9.9', '1.0.0', False, ESP_ERR_INVALID_VERSION),
    ('mestio_gw', 'garbage', '1.0.0', True, ESP_ERR_INVALID_VERSION),
    ('mestio_gw', '0.0.1', 'v1.0-dirty', False, ESP_OK),       # dev build running: any valid image
])
def test_ota_check_image(lib, proj, new, running, allow, want):
    assert lib.sys_ota_check_image(proj.encode(), new.encode(), b'mestio_gw', running.encode(), allow) == want


def test_ota_check_image_nulls(lib):
    assert lib.sys_ota_check_image(None, b'1.0.0', b'mestio_gw', b'1.0.0', True) == ESP_ERR_INVALID_VERSION
    assert lib.sys_ota_check_image(b'mestio_gw', None, b'mestio_gw', b'1.0.0', True) == ESP_ERR_INVALID_VERSION
    assert lib.sys_ota_check_image(b'mestio_gw', b'1.0.0', b'mestio_gw', None, False) == ESP_OK


@pytest.mark.parametrize('date,time,want', [
    ('Oct 19 2026', '10:12:03', '2026-10-19 10:12:03'), ('Jan  1 2025', '00:00:00', '2025-01-01 00:00:00'),
    ('Dec 31 2099', '23:59:59', '2099-12-31 23:59:59'), ('Feb  9 2026', '07:08:09', '2026-02-09 07:08:09'),
    ('Foo 19 2026', '10:12:03', None), ('Oct 19 26', '10:12:03', None), ('Oct 19 2026', '10:12', None),
    ('Oct-19-2026', '10:12:03', None), ('', '', None), ('Oct 1x 2026', '10:12:03', None),
])
def test_build_date_iso(lib, date, time, want):
    out = ctypes.create_string_buffer(24)
    ok = lib.sys_build_date_iso(date.encode(), time.encode(), out, 24)
    assert ok is (want is not None)
    assert out.value.decode() == (want or '')


def test_build_date_iso_small_buffer(lib):
    out = ctypes.create_string_buffer(19)
    assert not lib.sys_build_date_iso(b'Oct 19 2026', b'10:12:03', out, 19)


# ---------------- syslog ----------------

def fmt(lib, fac=16, sev=5, ms=1792371600123, host='mestio-gw-3456', app='mestio-gw', msgid='ALARM', msg='hello',
        cap=512):
    buf = ctypes.create_string_buffer(cap)
    enc = lambda s: None if s is None else s.encode()  # noqa: E731
    n = lib.syslog_format(buf, cap, fac, sev, ms, enc(host), enc(app), enc(msgid), enc(msg))
    raw = buf.raw[:n]
    assert buf.raw[n] == 0
    return raw.decode('utf-8')


def test_syslog_basic_line(lib):
    assert fmt(lib) == '<133>1 2026-10-19T01:00:00.123Z mestio-gw-3456 mestio-gw - ALARM - hello'


RFC5424 = re.compile(r'^<(\d{1,3})>1 (\S+) (\S+) (\S+) - (\S+) - ?(.*)$', re.S)


@pytest.mark.parametrize('fac,sev,pri', [(0, 0, 0), (16, 2, 130), (23, 7, 191), (99, 9, 191), (4, 9, 39)])
def test_syslog_pri_clamped(lib, fac, sev, pri):
    assert fmt(lib, fac=fac, sev=sev).startswith(f'<{pri}>1 ')


def test_syslog_nil_fields(lib):
    line = fmt(lib, ms=0, host='', app=None, msgid='', msg='')
    assert line == '<133>1 - - - - - -'
    assert fmt(lib, ms=-5, msg=None).startswith('<133>1 - ')


def test_syslog_field_sanitizing_and_limits(lib):
    line = fmt(lib, host='bad host\x01', msgid='M' * 40 + ' x', app='a' * 60)
    m = RFC5424.match(line)
    assert m and m.group(3) == 'bad_host_' and m.group(4) == 'a' * 48 and m.group(5) == 'M' * 32


def test_syslog_msg_control_chars_and_bom(lib):
    assert fmt(lib, msg='a\nb\tc\x7f').endswith(' - a b c ')
    line = fmt(lib, msg='dev=0 고온경보 raise')
    assert line.endswith(' - ' + BOM + 'dev=0 고온경보 raise')
    assert BOM not in fmt(lib, msg='ascii only')


def test_syslog_truncation_on_utf8_boundary(lib):
    for pad in range(4):
        line = fmt(lib, msg='x' * pad + '한' * 300)  # 3-byte characters
        raw = line.encode('utf-8')
        assert len(raw) <= 480
        assert len(raw) >= 477
        raw.decode('utf-8')  # never ends inside a sequence
    long_ascii = fmt(lib, msg='y' * 1000)
    assert len(long_ascii) == 480


def test_syslog_small_buffers(lib):
    assert fmt(lib, cap=40) == '<133>1 2026-10-19T01:00:00.123Z mestio-'
    buf = ctypes.create_string_buffer(1)
    assert lib.syslog_format(buf, 1, 16, 5, 0, b'h', b'a', b'm', b'x') == 0
    assert lib.syslog_format(None, 100, 16, 5, 0, b'h', b'a', b'm', b'x') == 0


def test_syslog_timestamp_is_utc_iso(lib):
    ms = 1704067200000 + 59_999
    line = fmt(lib, ms=ms)
    ref = dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + '999Z'
    assert RFC5424.match(line).group(2) == ref


def test_rate_limiter(lib):
    rl = RateLimiter()
    take = lambda t: lib.syslog_rl_take(ctypes.byref(rl), t, 10, 30)  # noqa: E731
    assert all(take(1000) for _ in range(30))  # full burst
    assert not take(1000) and not take(1050)
    assert lib.syslog_rl_take_dropped(ctypes.byref(rl)) == 2
    assert lib.syslog_rl_take_dropped(ctypes.byref(rl)) == 0
    assert take(1100)  # 10/s: one token per 100 ms
    assert not take(1150)
    assert sum(take(1150 + 100 * k) for k in range(1, 11)) == 10
    assert sum(take(100_000) for _ in range(40)) == 30  # long idle refills to the burst only


def test_rate_limiter_wraparound(lib):
    rl = RateLimiter()
    t0 = 0xFFFFFF00
    for _ in range(5):
        assert lib.syslog_rl_take(ctypes.byref(rl), t0, 10, 5)
    assert not lib.syslog_rl_take(ctypes.byref(rl), t0, 10, 5)
    assert lib.syslog_rl_take(ctypes.byref(rl), (t0 + 200) & 0xFFFFFFFF, 10, 5)


@pytest.mark.parametrize('typ,sev,want', [(1, 3, 2), (1, 2, 3), (1, 1, 4), (1, 0, 5), (2, 3, 5), (3, 3, 5),
                                          (1, 9, 5)])
def test_alarm_severity(lib, typ, sev, want):
    assert lib.syslog_alarm_severity(typ, sev) == want


# ---------------- LED policy ----------------

def led(lib, **kw):
    base = dict(net_ok=True)
    base.update(kw)
    return lib.sys_led_select(ctypes.byref(LedIn(**base)))


@pytest.mark.parametrize('kw,want', [
    ({}, 'OK'),
    ({'net_ok': False}, 'NO_NET'),
    ({'ap_active': True}, 'AP'),
    ({'ap_active': True, 'net_ok': False}, 'AP'),
    ({'comm_lost': True, 'ap_active': True}, 'COMM_LOST'),
    ({'alarms': 2, 'comm_lost': True}, 'ALARM'),
    ({'critical': 1, 'alarms': 3}, 'CRITICAL'),
    ({'fault': True, 'critical': 1}, 'FAULT'),
    ({'ota': True, 'fault': True}, 'OTA'),
    ({'booting': True, 'ota': True, 'net_ok': False}, 'BOOT'),
    ({'ap_armed': True, 'booting': True}, 'AP_ARMED'),
    ({'reset_armed': True, 'ap_armed': True, 'critical': 5}, 'RESET_ARMED'),
])
def test_led_priority(lib, kw, want):
    assert led(lib, **kw) == LED[want]


def test_led_null_is_fault(lib):
    assert lib.sys_led_select(None) == LED['FAULT']


# ---------------- health reboot policy (led_policy.c, fixer F) ----------------

class StaleTrack(ctypes.Structure):
    _fields_ = [('mask', ctypes.c_uint32), ('stale', ctypes.c_bool), ('since_ms', ctypes.c_uint64)]


@pytest.fixture(scope='module')
def hlib(lib):
    P = ctypes.POINTER
    u32, u64 = ctypes.c_uint32, ctypes.c_uint64
    lib.sys_stale_update.argtypes = [P(StaleTrack), u32, u64]
    lib.sys_stale_update.restype = ctypes.c_bool
    lib.sys_health_reboot_due.argtypes = [P(StaleTrack), ctypes.c_bool, u64, u64, u32, u32]
    lib.sys_health_reboot_due.restype = ctypes.c_bool
    return lib


LIMIT = 120_000


def test_stale_since_not_restarted_by_mask_changes(hlib):
    t = StaleTrack()
    assert hlib.sys_stale_update(ctypes.byref(t), 0, 1000) is False
    assert hlib.sys_stale_update(ctypes.byref(t), 0x01, 40_000) is True
    assert t.stale and t.since_ms == 40_000
    # a second heartbeat goes stale, then the mask flips between non-zero values: countdown kept
    assert hlib.sys_stale_update(ctypes.byref(t), 0x03, 70_000) is True
    assert hlib.sys_stale_update(ctypes.byref(t), 0x02, 90_000) is True
    assert hlib.sys_stale_update(ctypes.byref(t), 0x02, 100_000) is False
    assert t.since_ms == 40_000
    assert not hlib.sys_health_reboot_due(ctypes.byref(t), True, 40_000 + LIMIT - 1, LIMIT, 0, 3)
    assert hlib.sys_health_reboot_due(ctypes.byref(t), True, 40_000 + LIMIT, LIMIT, 0, 3)
    # healthy again: cleared; a new stale period starts its own countdown
    assert hlib.sys_stale_update(ctypes.byref(t), 0, 170_000) is True
    assert not t.stale and t.since_ms == 0
    assert not hlib.sys_health_reboot_due(ctypes.byref(t), True, 10**9, LIMIT, 0, 3)
    hlib.sys_stale_update(ctypes.byref(t), 0x04, 200_000)
    assert t.since_ms == 200_000


def test_health_reboot_gates(hlib):
    t = StaleTrack()
    hlib.sys_stale_update(ctypes.byref(t), 0x08, 30_000)  # stale from the end of the boot grace
    now = 30_000 + LIMIT
    assert hlib.sys_health_reboot_due(ctypes.byref(t), True, now, LIMIT, 0, 3)
    assert not hlib.sys_health_reboot_due(ctypes.byref(t), False, now, LIMIT, 0, 3)  # not armed
    assert hlib.sys_health_reboot_due(ctypes.byref(t), True, now, LIMIT, 2, 3)
    assert not hlib.sys_health_reboot_due(ctypes.byref(t), True, now, LIMIT, 3, 3)  # bounded
    assert not hlib.sys_health_reboot_due(ctypes.byref(t), True, 10_000, LIMIT, 0, 3)  # clock before since
    assert not hlib.sys_health_reboot_due(None, True, now, LIMIT, 0, 3)
    assert hlib.sys_stale_update(None, 1, 0) is False
