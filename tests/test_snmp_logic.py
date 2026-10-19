"""Pure SNMP agent logic (components/snmp_gw/snmp_logic.c): OID builders, token bucket, comm-loss
coalescing, inform tracking, USM user lookup rules, alarm event ring, text validation, error mapping,
key localization. Randomized sequences are checked against small Python reference models."""
import ctypes as C
import random
import re
import subprocess

import pytest

from conftest import CFLAGS, COMPONENTS, INCLUDE_FLAGS, LIBS, LISTS, ROOT, cc

SNMP_GW = COMPONENTS / 'snmp_gw'
DRIVER = ROOT / 'tests' / 'snmp_host' / 'logic_driver.c'
PEN_DEFAULT = 32473
MAX_DEVICES = 4
HOLD_MS, MIN_INTERVAL_MS = 2000, 10000
EVENTS_KEPT = 32
INFORM_TIMEOUT_MS, INFORM_IDS = 5000, 4
INFORM_SLOTS = int(re.search(r'#define SNMP_INFORM_SLOTS (\d+)', (SNMP_GW / 'snmp_logic.h').read_text()).group(1))


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope='module')
def lib(host_lib):
    l = host_lib('SNMP_GW')
    l.snmp_oid_build.argtypes = [C.c_uint32, C.POINTER(C.c_uint32), C.c_size_t, C.POINTER(C.c_uint32), C.c_size_t]
    l.snmp_oid_build.restype = C.c_size_t
    l.snmp_gw_oid.argtypes = [C.POINTER(C.c_uint32), C.c_size_t, C.POINTER(C.c_uint32), C.c_size_t]
    l.snmp_gw_oid.restype = C.c_size_t
    l.snmp_gw_pen.restype = C.c_uint32
    l.snmp_err_for_reason.argtypes = [C.c_int]
    l.snmp_write_result_code.argtypes = [C.c_int]
    l.snmp_write_result_code.restype = C.c_int32
    l.snmp_localize_key_for.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t, C.c_char_p]
    l.snmp_text_ok.argtypes = [C.c_char_p, C.c_size_t, C.c_size_t]
    l.snmp_text_ok.restype = C.c_bool
    l.snmp_principal_view.argtypes = [C.c_char_p, C.c_bool]
    l.snmp_principal_view.restype = C.c_char_p
    l.snmp_last_write_supersedes.argtypes = [C.c_bool, C.c_uint32, C.c_uint32]
    l.snmp_last_write_supersedes.restype = C.c_bool
    assert l.gw_crypto_init() == 0
    return l


@pytest.fixture(scope='module')
def driver(tmp_path_factory):
    """The stdin-driven logic driver, compiled with GW_CORE + snmp_logic.c (+ host crypto)."""
    srcs = [ROOT / p for p in LISTS['GW_HOST_SOURCES_GW_CORE'] + LISTS['GW_HOST_SOURCES_SNMP_GW']
            + LISTS.get('GW_HOST_ONLY_SOURCES', [])]
    exe = tmp_path_factory.mktemp('snmp_logic') / 'driver'
    cc([*CFLAGS, *INCLUDE_FLAGS, f'-I{SNMP_GW}', str(DRIVER), *map(str, srcs), '-o', str(exe), *LIBS])

    def run(lines):
        r = subprocess.run([str(exe)], input='\n'.join(lines) + '\n', capture_output=True, text=True, check=True)
        out = r.stdout.splitlines()
        assert len(out) == len(lines), r.stdout
        return out
    return run


def oid(lib, pen, suffix, cap=32):
    arr = (C.c_uint32 * max(len(suffix), 1))(*suffix)
    out = (C.c_uint32 * cap)()
    n = lib.snmp_oid_build(pen, arr if suffix else None, len(suffix), out, cap)
    return list(out[:n])


# ---------------------------------------------------------------- OIDs


def test_oid_builder(lib):
    assert oid(lib, 32473, []) == [1, 3, 6, 1, 4, 1, 32473, 1]
    assert oid(lib, 32473, [3, 1, 1, 2, 4]) == [1, 3, 6, 1, 4, 1, 32473, 1, 3, 1, 1, 2, 4]
    assert oid(lib, 4294967295, [0, 7]) == [1, 3, 6, 1, 4, 1, 4294967295, 1, 0, 7]


def test_oid_builder_bounds(lib):
    assert oid(lib, 32473, [1, 2], cap=10) == [1, 3, 6, 1, 4, 1, 32473, 1, 1, 2]
    assert oid(lib, 32473, [1, 2, 3], cap=10) == []  # does not fit
    assert oid(lib, 0, [1]) == []  # PEN 0 is invalid
    out = (C.c_uint32 * 8)()
    assert lib.snmp_oid_build(32473, None, 1, out, 8) == 0  # NULL suffix with n > 0
    assert lib.snmp_oid_build(32473, None, 0, None, 8) == 0  # NULL out


def test_registry_oid_uses_configured_pen(lib):
    # Host builds have no sdkconfig: the Kconfig default (RFC 5612 documentation PEN).
    assert lib.snmp_gw_pen() == PEN_DEFAULT
    out = (C.c_uint32 * 32)()
    sfx = (C.c_uint32 * 2)(1, 1)
    n = lib.snmp_gw_oid(sfx, 2, out, 32)
    assert list(out[:n]) == [1, 3, 6, 1, 4, 1, PEN_DEFAULT, 1, 1, 1]


def test_kconfig_default_pen_matches_host_fallback():
    kconfig = (ROOT / 'main' / 'Kconfig.projbuild').read_text()
    assert f'default {PEN_DEFAULT}' in kconfig


# ---------------------------------------------------------------- token bucket


class Bucket:
    def __init__(self, rate, burst):
        self.rate, self.burst, self.milli, self.last = rate, burst, burst * 1000, None

    def take(self, now):
        if self.last is None:
            self.last = now
        elif now > self.last:
            self.milli = min(self.burst * 1000, self.milli + (now - self.last) * self.rate)
            self.last = now
        if self.milli < 1000:
            return 0
        self.milli -= 1000
        return 1


def test_token_bucket_burst_then_rate(driver):
    lines = ['tb_init 10 10'] + ['tb_take 1000'] * 12 + ['tb_take 1099', 'tb_take 1100', 'tb_take 1100',
                                                           'tb_take 2100'] + ['tb_take 2100'] * 10
    out = driver(lines)[1:]
    assert out[:12] == ['1'] * 10 + ['0', '0'], 'a burst of 10, then empty'
    assert out[12:15] == ['0', '1', '0'], 'one token per 100 ms at 10/s'
    assert out[15:].count('1') == 10, 'refill caps at the burst size'


def test_token_bucket_time_going_backwards_does_not_refill(driver):
    out = driver(['tb_init 10 1', 'tb_take 5000', 'tb_take 4000', 'tb_take 4999', 'tb_take 5100'])
    assert out[1:] == ['1', '0', '0', '1']


@pytest.mark.parametrize('seed', range(5))
def test_token_bucket_random_against_model(driver, seed):
    rnd = random.Random(seed)
    rate, burst = rnd.choice([(10, 10), (1, 1), (5, 20)])
    model = Bucket(rate, burst)
    now = rnd.randint(0, 10**9)
    lines, expect = [f'tb_init {rate} {burst}'], ['ok']
    for _ in range(400):
        now += rnd.choice([0, 0, 1, 7, 50, 99, 100, 101, 1000, 30000])
        lines.append(f'tb_take {now}')
        expect.append(str(model.take(now)))
    assert driver(lines) == expect


# ---------------------------------------------------------------- comm coalescing


class Coalesce:
    """Reference model of snmp_logic.h's coalescer."""

    def __init__(self):
        self.d = [dict(rep=True, pending=False, latest=True, ever=False, due=0, last=0) for _ in range(MAX_DEVICES)]

    def event(self, dev, online, now):
        if dev >= MAX_DEVICES:
            return
        d = self.d[dev]
        d['latest'] = online
        if d['pending'] or online == d['rep']:
            return
        due = now + HOLD_MS
        if d['ever']:
            due = max(due, d['last'] + MIN_INTERVAL_MS)
        d['pending'], d['due'] = True, due

    def poll(self, now):
        out = []
        for i, d in enumerate(self.d):
            if not d['pending'] or now < d['due']:
                continue
            d['pending'] = False
            if d['latest'] == d['rep']:
                continue
            d['rep'], d['ever'], d['last'] = d['latest'], True, now
            out.append(f'{i}:{int(d["latest"])}')
        return ' '.join(out) or '-'


def test_first_online_after_boot_is_silent_and_offline_is_reported(driver):
    out = driver(['cc_init', 'cc_event 0 1 0', 'cc_poll 5000', 'cc_event 1 0 100', 'cc_poll 2099',
                  'cc_poll 2100', 'cc_poll 9999'])
    assert out[2] == '-', 'first decision online=true sends nothing'
    assert out[4] == '-', 'held for 2 s'
    assert out[5] == '1:0', 'device that never answered -> gwCommLost'
    assert out[6] == '-'


def test_flap_within_hold_window_is_suppressed(driver):
    out = driver(['cc_init', 'cc_event 0 0 0', 'cc_event 0 1 500', 'cc_poll 3000', 'cc_poll 60000'])
    assert out[3:] == ['-', '-']


def test_storm_is_limited_to_one_report_per_interval_and_final_state_wins(driver):
    lines = ['cc_init', 'cc_event 2 0 0', 'cc_poll 2000']
    t = 2000
    for i in range(20):  # flapping every 300 ms
        t += 300
        lines.append(f'cc_event 2 {i % 2} {t}')
        lines.append(f'cc_poll {t}')
    lines += ['cc_poll 11999', 'cc_poll 12000', 'cc_poll 30000']
    out = driver(lines)
    assert out[2] == '2:0'
    reports = [o for o in out[3:] if o not in ('ok', '-')]
    assert reports == ['2:1'], f'only the final state after the minimum interval: {reports}'
    assert out[-3] == '-' and out[-2] == '2:1'


def test_devices_are_independent_and_out_of_range_ignored(driver):
    out = driver(['cc_init', 'cc_event 0 0 0', 'cc_event 3 0 0', 'cc_event 4 0 0', 'cc_event 255 0 0',
                  'cc_poll 2000'])
    assert out[-1] == '0:0 3:0'


@pytest.mark.parametrize('seed', range(8))
def test_coalescer_random_against_model(driver, seed):
    rnd = random.Random(1000 + seed)
    model = Coalesce()
    lines, expect = ['cc_init'], ['ok']
    now = 0
    for _ in range(600):
        now += rnd.choice([0, 10, 300, 1999, 2000, 2500, 9000, 10000, 15000])
        if rnd.random() < 0.6:
            dev, online = rnd.randrange(MAX_DEVICES + 1), rnd.random() < 0.5
            model.event(dev, online, now)
            lines.append(f'cc_event {dev} {int(online)} {now}')
            expect.append('ok')
        else:
            lines.append(f'cc_poll {now}')
            expect.append(model.poll(now))
    assert driver(lines) == expect


# ---------------------------------------------------------------- alarm event ring


def test_event_ring_keeps_newest_sorted_unique(driver):
    lines = ['ev_init'] + [f'ev_ins {s}' for s in (5, 3, 9, 3, 0, 7)] + ['ev_dump', 'ev_find 7', 'ev_find 4',
                                                                          'ev_next 0', 'ev_next 5', 'ev_next 9']
    out = driver(lines)
    assert out[1:7] == ['1', '1', '1', '0', '0', '1'], 'duplicates and seq 0 are rejected'
    assert out[7] == '3 5 7 9'
    assert out[8:] == ['7', '0', '3', '7', '0']


@pytest.mark.parametrize('seed', range(5))
def test_event_ring_random_against_model(driver, seed):
    rnd = random.Random(seed)
    kept = []
    lines, expect = ['ev_init'], ['ok']
    for _ in range(300):
        s = rnd.randint(0, 120)
        ok = s != 0 and s not in kept and not (len(kept) == EVENTS_KEPT and s < kept[0])
        if ok:
            kept = sorted(kept + [s])[-EVENTS_KEPT:]
        lines.append(f'ev_ins {s}')
        expect.append(str(int(ok)))
        if rnd.random() < 0.1:
            lines.append('ev_dump')
            expect.append(' '.join(map(str, kept)) or '-')
    assert driver(lines) == expect


# ---------------------------------------------------------------- informs


def test_inform_lifecycle(driver):
    ip = 0xC0A80A14
    out = driver([
        'inf_init',
        f'inf_add 1 {ip} 100 1000 0',     # slot 0
        f'inf_peer {ip}', 'inf_peer 1',
        'inf_due 5999', 'inf_due 6000',   # due after SNMP_GW_INFORM_TIMEOUT_MS
        'inf_retry 0', 'inf_resent 0 101 6000', 'inf_resent 0 102 11000', 'inf_resent 0 103 16000',
        'inf_retry 0',                    # 1 send + 3 retries used up
        f'inf_match 100 {ip}', f'inf_match 103 {ip}', 'inf_match 103 1', f'inf_match 999 {ip}',
        'inf_free 0', f'inf_peer {ip}', 'inf_due 99999999',
    ])
    assert out[1] == '0 0 -1'
    assert out[2:4] == ['0', '-1']
    assert out[4:6] == ['-1', '0']
    assert out[6:10] == ['1', '2', '3', '4']
    assert out[10] == '0'
    assert out[11:15] == ['0', '0', '-1', '-1'], 'any request id of the slot matches, only from its peer'
    assert out[16:] == ['-1', '-1']


def test_inform_table_evicts_oldest_and_drops_by_target(driver):
    lines = ['inf_init'] + [f'inf_add {i % 2} {1000 + i} {i} {i} 0' for i in range(INFORM_SLOTS)]
    lines += [f'inf_add 3 2000 77 100 5', 'inf_drop 0', 'inf_drop 3', 'inf_drop 1']
    out = driver(lines)
    assert [o.split()[0] for o in out[1:1 + INFORM_SLOTS]] == [str(i) for i in range(INFORM_SLOTS)]
    assert out[1 + INFORM_SLOTS] == '0 1 0', 'full table: the oldest (req 0) is evicted and reported'
    half = INFORM_SLOTS // 2
    # slot 0 now belongs to target 3; target 0 keeps the other even slots, target 1 the odd ones
    assert out[-3:] == [str(half - 1), '1', str(half)]


def test_inform_free_slots(driver):
    lines = ['inf_init', 'inf_free_slots'] + [f'inf_add 0 1 {i} 0 0' for i in range(INFORM_SLOTS)]
    lines += ['inf_free_slots', 'inf_free 3', 'inf_free_slots', 'inf_drop 0', 'inf_free_slots']
    out = driver(lines)
    assert out[1] == str(INFORM_SLOTS)
    assert out[2 + INFORM_SLOTS:] == ['0', 'ok', '1', str(INFORM_SLOTS - 1), str(INFORM_SLOTS)]
    assert INFORM_SLOTS >= 16, 'room for one burst to every target (SNMP_MSG_QUEUE_LEN, 4 targets)'


# ---------------------------------------------------------------- USM lookup rules (snmp_gw.h contract)


def usm(driver, cfg, queries):
    out = driver([f'usm {cfg}'] + queries)
    return out[0], out[1:]


def test_usm_valid_users_and_access(driver):
    n, out = usm(driver, '1 1 gwmonitor 0 1 1 gwadmin 1 1',
                 ['usm_find gwmonitor', 'usm_find gwadmin', 'usm_at 0', 'usm_at 1', 'usm_at 2'])
    assert n == '2'
    assert out[0] == '0 0 10 20', 'slot 0, RO, slot-aligned keys'
    assert out[1] == '1 1 11 21', 'slot 1, RW'
    assert out[2:] == ['gwmonitor', 'gwadmin', 'NONE']


@pytest.mark.parametrize('cfg,name', [
    ('0 1 gwmonitor 0 1 1 gwadmin 1 1', 'gwadmin'),     # v3 disabled -> every user unknown
    ('1 1 gwmonitor 0 1 0 gwadmin 1 1', 'gwadmin'),     # slot disabled
    ('1 1 gwmonitor 0 1 1 gwadmin 1 0', 'gwadmin'),     # keyless (passphrases never entered)
    ('1 1 gwmonitor 0 1 1 gwadmin 1 1', '-'),           # empty user name (discovery only)
    ('1 1 gwmonitor 0 1 1 gwadmin 1 1', 'GWADMIN'),     # case-sensitive
    ('1 1 gwmonitor 0 1 1 gwadmin 1 1', 'gwadmin2'),    # prefix is not a match
    ('1 1 gwmonitor 0 1 1 gwadmin 1 1', 'gwadmi'),
    ('1 1 gwmonitor 0 1 1 gwadmin 7 1', 'gwadmin'),     # invalid access value
    ('1 1 - 0 1 1 gwadmin 1 1', '-'),                   # empty configured name never matches ""
])
def test_usm_unknown_disabled_keyless_users_are_rejected(driver, cfg, name):
    _, out = usm(driver, cfg, [f'usm_find {name}'])
    assert out == ['NONE']


def test_usm_duplicate_name_keeps_first_slot_only(driver):
    n, out = usm(driver, '1 1 same 0 1 1 same 1 1', ['usm_find same', 'usm_at 1'])
    assert n == '1'
    assert out == ['0 0 10 20', 'NONE'], 'the RW duplicate must not shadow or escalate the RO slot'


def test_usm_overlong_name_is_rejected(driver):
    name = 'u' * 40  # > GW_SNMP_USER_MAX (32), also fills the cfg buffer without NUL
    n, out = usm(driver, f'1 1 {name} 0 1 1 gwadmin 1 1', [f'usm_find {name}', f'usm_find {name[:32]}'])
    assert n == '1' and out == ['NONE', 'NONE']


def test_usm_lookup_never_reports_noauth_algorithms():
    """usm.c reports SHA + AES for every valid user (never *_ALGO_INVAL): noAuthNoPriv as gwadmin is
    rejected by lwIP with unsupportedSecLevel. Checked end to end in test_snmp_agent_host.py; here
    the source is pinned so a refactor cannot silently drop it."""
    src = (SNMP_GW / 'usm.c').read_text()
    assert '*auth_algo = SNMP_V3_AUTH_ALGO_SHA;' in src and '*priv_algo = SNMP_V3_PRIV_ALGO_AES;' in src
    assert 'ALGO_INVAL' not in src.split('err_t snmpv3_get_user')[1].split('\n}\n')[0]


# ---------------------------------------------------------------- misc


@pytest.mark.parametrize('text,ok', [
    (b'', True), (b'B-dong server room 3', True), ('B동 전산실'.encode(), True), (b'x' * 63, True),
    (b'x' * 64, False),                          # > max
    (b'a\x00b', False), (b'a\nb', False), (b'\x7f', False),
    (b'\xc3\x28', False),                        # bad continuation
    (b'\xc0\xaf', False), (b'\xe0\x80\xaf', False),  # overlong
    (b'\xed\xa0\x80', False),                    # surrogate
    (b'\xf4\x90\x80\x80', False),                # > U+10FFFF
    ('😀'.encode(), True), (b'\xe2\x82', False),  # truncated sequence at the end
])
def test_text_ok(lib, text, ok):
    assert lib.snmp_text_ok(text, len(text), 63) is ok


def test_text_ok_driver_agrees(driver):
    out = driver(['text - 63', 'text 41 0', 'text e282ac 3', 'text e282ac 2'])
    assert out == ['1', '0', '1', '0']


def test_reason_to_snmp_error(lib):
    # mex_reason_t (regmap.h) -> RFC 3416 error-status
    expect = {0: 0, 1: 17, 2: 17, 3: 10, 4: 12, 5: 13, 6: 13, 7: 5, 8: 5, 9: 5, 0x102: 5}
    for reason, err in expect.items():
        assert lib.snmp_err_for_reason(reason) == err, reason


def test_write_result_codes(lib):
    # mex_wstate_t PENDING..UNCERTAIN -> GwWriteResult pending(2)..uncertain(5); unknown -> none(1)
    assert [lib.snmp_write_result_code(s) for s in (0, 1, 2, 3, 9, -1)] == [2, 3, 4, 5, 1, 1]


RFC3414_ENGINE = bytes.fromhex('000000000000000000000002')


def test_localize_key_for_rfc3414_and_bounds(lib):
    out = C.create_string_buffer(20)
    assert lib.snmp_localize_key_for(b'maplesyrup', RFC3414_ENGINE, 12, out) == 0
    assert out.raw.hex() == '6695febc9288e36282235fc7151f128497b38f3f'
    for bad in (b'', b'1234567', b'x' * 65):
        out = C.create_string_buffer(b'\xaa' * 20, 20)
        assert lib.snmp_localize_key_for(bad, RFC3414_ENGINE, 12, out) == -1
        assert out.raw == bytes(20), 'zeroed on error'
    assert lib.snmp_localize_key_for(b'x' * 64, RFC3414_ENGINE, 12, C.create_string_buffer(20)) == 0
    assert lib.snmp_localize_key_for(b'12345678', RFC3414_ENGINE, 12, C.create_string_buffer(20)) == 0


def test_mib_branch_lengths_match_the_oid_builder(tmp_path):
    """Module base OIDs are fixed-size arrays (GWMIB_BRANCH_LEN): must equal what snmp_gw_oid() builds."""
    from conftest import compile_and_run
    prog = r'''
#include <stdio.h>
#include "mib_oids.h"
#include "snmp_gw/registry.h"
int main(void) {
    uint32_t out[SNMP_GW_OID_MAX];
    const uint32_t sfx[] = {GWMIB_mexSetpoints};
    printf("%u %u %u %u\n", (unsigned)snmp_gw_oid(NULL, 0, out, SNMP_GW_OID_MAX), (unsigned)GWMIB_ROOT_LEN,
           (unsigned)snmp_gw_oid(sfx, 1, out, SNMP_GW_OID_MAX), (unsigned)GWMIB_BRANCH_LEN);
    printf("%u\n", (unsigned)snmp_gw_oid(sfx, 1, out, GWMIB_BRANCH_LEN));
    return 0;
}
'''
    srcs = [ROOT / p for p in LISTS['GW_HOST_SOURCES_GW_CORE'] + LISTS['GW_HOST_SOURCES_SNMP_GW']
            + LISTS.get('GW_HOST_ONLY_SOURCES', [])]
    out = compile_and_run(tmp_path, prog, extra_sources=srcs, flags=[f'-I{SNMP_GW}']).split()
    assert out[0] == out[1] == '8' and out[2] == out[3] == '9'
    assert out[4] == '9', 'a branch base OID fits its GWMIB_BRANCH_LEN array exactly'


# ---------------------------------------------------------------- principals and last-write ordering


@pytest.mark.parametrize('by,authenticated,shown', [
    ('admin', False, 'web'), ('admin', True, 'admin'), ('@snmp', False, '@snmp'), ('@console', False, '@console'),
    ('', False, ''), ('', True, ''), (None, True, ''),
])
def test_principal_view(lib, by, authenticated, shown):
    """Web login names only to SNMPv3 (authenticated, encrypted) readers; v1/v2c see the class."""
    arg = by.encode() if by is not None else None
    assert lib.snmp_principal_view(arg, authenticated).decode() == shown


def test_pending_record_never_replaces_the_final_result(lib):
    sup = lib.snmp_last_write_supersedes
    assert sup(True, 42, 42), 'final result for this command already stored'
    assert sup(True, 43, 42), 'a later write already stored'
    assert not sup(True, 41, 42) and not sup(False, 42, 42), 'older record / none: store pending'
    assert not sup(True, 0, 42), 'a rejected-before-queueing record (cmd 0) is replaced'
    assert sup(True, 3, 0xFFFFFFFE), 'serial arithmetic across the 2^32 wrap'
    assert not sup(True, 0xFFFFFFFE, 3)
