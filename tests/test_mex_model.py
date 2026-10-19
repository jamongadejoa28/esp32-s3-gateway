"""mex150 model.c: port of esp32-s3-monitor tests/test_model.py (validate ranges, read-only, interlock,
delay byte), exhaustive equivalence of mex_validate()/mex_check_write() with the legacy monitor
predicate, reason priority, freshness, and derived values (running, delay, stages, mode, alarm coils)."""
import ctypes as C

import pytest

from conftest import COMPONENTS, compile_and_run

R_OK, R_UNKNOWN, R_READONLY, R_RANGE, R_INTERLOCK, R_OFFLINE = range(6)
FRESH_MS = 3000


class Snapshot(C.Structure):
    _fields_ = [('regs', C.c_uint16 * 60), ('coils', C.c_uint32), ('wall_ms', C.c_int64), ('mono_ms', C.c_uint64),
                ('seq', C.c_uint32), ('online', C.c_bool), ('slow_valid', C.c_bool)]


class Command(C.Structure):
    _fields_ = [('fc', C.c_uint8), ('address', C.c_uint16), ('value', C.c_int32), ('stopped_only', C.c_bool),
                ('id', C.c_uint32)]


class Stages(C.Structure):
    _fields_ = [('cool', C.c_uint8), ('heat', C.c_uint8), ('hum', C.c_uint8), ('dehum', C.c_uint8),
                ('blower', C.c_bool)]


@pytest.fixture(scope='module')
def lib(host_lib):
    l = host_lib('MEX150')
    SP = C.POINTER(Snapshot)
    l.mex_validate.argtypes = [C.POINTER(Command), C.c_bool, C.c_bool]
    l.mex_validate.restype = C.c_bool
    l.mex_running.argtypes = [SP]
    l.mex_running.restype = C.c_bool
    l.mex_delay_s.argtypes = [SP]
    l.mex_delay_s.restype = C.c_uint8
    l.mex_fresh.argtypes = [SP, C.c_uint64]
    l.mex_fresh.restype = C.c_bool
    l.mex_check_write.argtypes = [C.c_uint16, C.c_int32, C.c_bool, C.c_bool]
    l.mex_check_write.restype = C.c_int
    l.mex_check_write_snap.argtypes = [C.c_uint16, C.c_int32, SP, C.c_uint64]
    l.mex_check_write_snap.restype = C.c_int
    l.mex_snap_raw.argtypes = [SP, C.c_uint16]
    l.mex_snap_raw.restype = C.c_int32
    l.mex_derive_stages.argtypes = [SP, C.POINTER(Stages)]
    l.mex_derive_stages.restype = None
    l.mex_mode_mask.argtypes = [SP]
    l.mex_mode_mask.restype = C.c_uint8
    return l


def validate(lib, fc, a, v, online=True, running=False, stopped_only=False):
    return lib.mex_validate(C.byref(Command(fc, a, v, stopped_only, 0)), online, running)


def coils(*ns):
    m = 0
    for n in ns:
        m |= 1 << (n - 1)
    return m


# ---------------------------------------------------------------- monitor tests (ported)


@pytest.mark.parametrize('a,lo,hi', [(40012, 50, 500), (40013, 200, 800), (40014, 1, 100), (40016, 10, 100),
                                     (40021, -100, 100), (40022, -300, 300), (40027, 249, 500),
                                     (40059, 1000, 20000)])
def test_writable_ranges(lib, a, lo, hi):
    for val in [lo, hi]:
        assert validate(lib, 6, a, val)
    for val in [lo - 1, hi + 1]:
        assert not validate(lib, 6, a, val)


def test_read_only_and_interlock(lib):
    for a in [40002, 40006, 40020, 40023, 40036]:
        assert not validate(lib, 6, a, 1)
    assert not validate(lib, 5, 10, 1, running=True)
    # Deviation from the monitor (DECISIONS.md CONTRACTS): coils are read-only, FC05 is never valid.
    assert not validate(lib, 5, 10, 1, running=False)
    assert not validate(lib, 6, 40012, 250, online=False)
    assert not validate(lib, 6, 40021, 0, running=True)
    assert validate(lib, 6, 40012, 250, running=True)
    assert not validate(lib, 6, 40012, 250, running=True, stopped_only=True)
    assert not validate(lib, 3, 40012, 250)
    assert not lib.mex_validate(None, True, False)


def test_delay_byte_is_not_running(lib):
    s = Snapshot()
    s.regs[5] = 0x0500
    assert not lib.mex_running(C.byref(s))
    assert lib.mex_delay_s(C.byref(s)) == 5
    s.regs[5] |= 1
    assert lib.mex_running(C.byref(s))
    s.regs[5] = 0x0080  # any low-byte bit counts as running (monitor rule)
    assert lib.mex_running(C.byref(s)) and lib.mex_delay_s(C.byref(s)) == 0


# ---------------------------------------------------------------- equivalence with the legacy monitor


LEGACY = r'''
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "mex150/model.h"

/* esp32-s3-monitor src/domain/model.c mex_validate(), verbatim apart from the name. */
static bool legacy_validate(const mex_command_t *c, bool online, bool running) {
    if (!online || (c->stopped_only && running))
        return false;
    if (c->fc == 5)
        return !running && c->address >= 1 && c->address <= 16 && (c->value == 0 || c->value == 1);
    if (c->fc != 6)
        return false;
    int lo = 0, hi = -1;
    switch (c->address) {
    case 40005: lo = 0; hi = 1; break;
    case 40012: lo = 50; hi = 500; break;
    case 40013: lo = 200; hi = 800; break;
    case 40014: case 40015: lo = 1; hi = 100; break;
    case 40016: case 40017: lo = 10; hi = 100; break;
    case 40018: case 40019: lo = 1; hi = 180; break;
    case 40021: lo = -100; hi = 100; break;
    case 40022: lo = -300; hi = 300; break;
    case 40027: lo = 249; hi = 500; break;
    case 40028: lo = 49; hi = 200; break;
    case 40029: lo = 599; hi = 900; break;
    case 40030: lo = 99; hi = 400; break;
    case 40053: case 40054: lo = 0; hi = 1; break;
    case 40059: lo = 1000; hi = 20000; break;
    default: return false;
    }
    if (running && (c->address == 40021 || c->address == 40022 || c->address >= 40027))
        return false;
    return c->value >= lo && c->value <= hi;
}

int main(void) {
    unsigned long n = 0, bad_validate = 0, bad_check = 0, ok_count = 0, bad_fc5 = 0, bad_stopped = 0;
    for (unsigned a = 40000; a <= 40060; a++)
        for (int32_t v = -400; v <= 20100; v++)
            for (int m = 0; m < 4; m++) {
                const bool online = m & 1, running = m & 2;
                const mex_command_t c = {6, (uint16_t)a, v, false, 0};
                const bool want = legacy_validate(&c, online, running);
                n++;
                ok_count += want;
                if (mex_validate(&c, online, running) != want) bad_validate++;
                if ((mex_check_write((uint16_t)a, v, online, running) == MEX_R_OK) != want) bad_check++;
                const mex_command_t cs = {6, (uint16_t)a, v, true, 0};
                if (mex_validate(&cs, online, running) != legacy_validate(&cs, online, running)) bad_stopped++;
            }
    for (unsigned a = 0; a <= 20; a++)
        for (int32_t v = -1; v <= 2; v++)
            for (int m = 0; m < 4; m++) {
                const mex_command_t c = {5, (uint16_t)a, v, false, 0};
                if (mex_validate(&c, m & 1, m & 2)) bad_fc5++;
            }
    printf("%lu %lu %lu %lu %lu %lu\n", n, ok_count, bad_validate, bad_check, bad_fc5, bad_stopped);
    return 0;
}
'''


def test_exhaustive_equivalence_with_legacy_monitor(tmp_path):
    """model.h invariant: addr 40000..40060 x raw -400..20100 x online x running."""
    src = COMPONENTS / 'mex150'
    out = compile_and_run(tmp_path, LEGACY, name='legacy_eq', extra_sources=[src / 'regmap.c', src / 'model.c'])
    n, ok_count, bad_validate, bad_check, bad_fc5, bad_stopped = map(int, out.split())
    assert n == 61 * 20501 * 4
    assert ok_count > 10000  # the OK set is not trivially empty
    assert (bad_validate, bad_check, bad_fc5, bad_stopped) == (0, 0, 0, 0)


# ---------------------------------------------------------------- mex_check_write


def test_check_write_reason_priority(lib):
    # UNKNOWN > READONLY > OFFLINE > INTERLOCK > RANGE
    assert lib.mex_check_write(40001, 0, False, True) == R_UNKNOWN
    assert lib.mex_check_write(40023, 0, True, False) == R_UNKNOWN
    assert lib.mex_check_write(40036, 99999, False, True) == R_READONLY
    assert lib.mex_check_write(40027, 99999, False, True) == R_OFFLINE
    assert lib.mex_check_write(40027, 99999, True, True) == R_INTERLOCK
    assert lib.mex_check_write(40027, 99999, True, False) == R_RANGE
    assert lib.mex_check_write(40027, 249, True, False) == R_OK      # disabled sentinel
    assert lib.mex_check_write(40012, 501, True, True) == R_RANGE    # not interlocked while running
    assert lib.mex_check_write(40005, 1, True, True) == R_OK
    assert lib.mex_check_write(40005, 2561, True, True) == R_RANGE   # read word is not a write request
    assert lib.mex_check_write(40021, -100, True, False) == R_OK
    assert lib.mex_check_write(40021, -100, True, True) == R_INTERLOCK


def test_check_write_snap_freshness(lib):
    s = Snapshot()
    s.online, s.mono_ms = True, 10_000
    assert lib.mex_check_write_snap(40012, 250, C.byref(s), 10_000 + FRESH_MS - 1) == R_OK
    assert lib.mex_check_write_snap(40012, 250, C.byref(s), 10_000 + FRESH_MS) == R_OFFLINE
    s.regs[5] = 1
    assert lib.mex_check_write_snap(40027, 300, C.byref(s), 10_500) == R_INTERLOCK
    s.online = False
    assert lib.mex_check_write_snap(40012, 250, C.byref(s), 10_500) == R_OFFLINE


def test_fresh(lib):
    s = Snapshot()
    assert not lib.mex_fresh(C.byref(s), 0)          # never polled
    s.online, s.mono_ms = True, 5000
    assert lib.mex_fresh(C.byref(s), 5000)
    assert lib.mex_fresh(C.byref(s), 7999)
    assert not lib.mex_fresh(C.byref(s), 8000)
    assert not lib.mex_fresh(C.byref(s), 4999)       # snapshot from the "future": not trusted
    s.online = False
    assert not lib.mex_fresh(C.byref(s), 5000)
    assert not lib.mex_fresh(None, 5000)


def test_snap_raw(lib):
    s = Snapshot()
    s.regs[36] = 0xFF06
    s.regs[5] = 0x0A01
    s.regs[21] = 0xFFF1
    s.regs[12] = 235
    assert lib.mex_snap_raw(C.byref(s), 40036) == -250
    assert lib.mex_snap_raw(C.byref(s), 40005) == 0x0A01
    assert lib.mex_snap_raw(C.byref(s), 40021) == -15
    assert lib.mex_snap_raw(C.byref(s), 40012) == 235
    assert lib.mex_snap_raw(C.byref(s), 40023) == 0   # not a REG row
    assert lib.mex_snap_raw(None, 40012) == 0


# ---------------------------------------------------------------- derived values


def stages(lib, mask):
    s = Snapshot()
    s.coils = mask
    out = Stages()
    lib.mex_derive_stages(C.byref(s), C.byref(out))
    return (out.cool, out.heat, out.hum, out.dehum, out.blower)


def test_stages_from_coils(lib):
    assert stages(lib, 0) == (0, 0, 0, 0, False)
    assert stages(lib, coils(1)) == (0, 0, 0, 0, True)
    assert stages(lib, coils(2, 3, 16)) == (3, 0, 0, 0, False)
    assert stages(lib, coils(3)) == (1, 0, 0, 0, False)   # stage 2 alone counts 1 (no fill)
    assert stages(lib, coils(4, 5, 6, 7)) == (0, 4, 0, 0, False)
    assert stages(lib, coils(8, 9)) == (0, 0, 2, 0, False)
    assert stages(lib, coils(15)) == (0, 0, 0, 1, False)
    # supply/drain/mode/alarm coils do not count as stages
    assert stages(lib, coils(10, 11, 12, 13, 14, *range(17, 33))) == (0, 0, 0, 0, False)
    assert stages(lib, 0xFFFFFFFF) == (3, 4, 2, 1, True)


def test_stages_null_safe(lib):
    out = Stages(9, 9, 9, 9, True)
    lib.mex_derive_stages(None, C.byref(out))
    assert (out.cool, out.heat, out.hum, out.dehum, out.blower) == (0, 0, 0, 0, False)
    lib.mex_derive_stages(None, None)


def test_mode_mask(lib):
    s = Snapshot()
    for n, bit in [(12, 1), (13, 2), (14, 4), (15, 8)]:
        s.coils = coils(n)
        assert lib.mex_mode_mask(C.byref(s)) == bit
    s.coils = coils(1, 2, 11, 16, 17, 32)
    assert lib.mex_mode_mask(C.byref(s)) == 0
    s.coils = 0xFFFFFFFF
    assert lib.mex_mode_mask(C.byref(s)) == 0x0F
    assert lib.mex_mode_mask(None) == 0


ALARM_PROG = r'''
#include <stdio.h>
#include "mex150/model.h"
int main(void) {
    mex_snapshot_t s = {0};
    s.coils = (1u << 22) | (1u << 31) | 0xFFFFu; /* coil 23 leak, coil 32 combined, run coils */
    printf("%u %d %d %d\n", mex_alarm_coils(&s), mex_coil(&s, 23), mex_coil(&s, 0), mex_coil(&s, 33));
    return 0;
}
'''


def test_alarm_coils_and_coil_helper(tmp_path):
    src = COMPONENTS / 'mex150'
    out = compile_and_run(tmp_path, ALARM_PROG, name='alarm_coils', extra_sources=[src / 'regmap.c', src / 'model.c'])
    mask, leak, c0, c33 = map(int, out.split())
    assert mask == (1 << 6) | (1 << 15) and leak == 1 and c0 == 0 and c33 == 0
