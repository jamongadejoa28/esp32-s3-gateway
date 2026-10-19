"""board pure logic (stream F): PCF85063 BCD/time codec (pcf85063_codec.c) and the BOOT button
debounce/gesture state machine (button_fsm.c) with injected time."""
import calendar
import ctypes
import datetime as dt

import pytest

from conftest import compile_and_run

PRESSED, AP_ARMED, AP_DISARMED, RESET_ARMED, REL_SHORT, REL_AP, REL_NONE, REL_RESET, RESET_DISARMED = range(9)
NAMES = ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'RESET_ARMED', 'REL_SHORT', 'REL_AP', 'REL_NONE', 'REL_RESET',
         'RESET_DISARMED']
PCF_OK, PCF_E_OSF, PCF_E_BCD, PCF_E_RANGE = range(4)
DEBOUNCE = 30
POLL = 20


class BtnFsm(ctypes.Structure):
    _fields_ = [('level', ctypes.c_bool), ('ignore', ctypes.c_bool), ('cand_active', ctypes.c_bool),
                ('cand_ms', ctypes.c_uint32), ('press_ms', ctypes.c_uint32), ('flags', ctypes.c_uint8),
                ('debounce_ms', ctypes.c_uint32)]


class BtnEvent(ctypes.Structure):
    _fields_ = [('ev', ctypes.c_uint8), ('held_ms', ctypes.c_uint32)]


@pytest.fixture(scope='module')
def lib(host_lib):
    lib = host_lib('BOARD')
    lib.pcf_bcd_decode.argtypes = [ctypes.c_uint8]
    lib.pcf_bcd_encode.argtypes = [ctypes.c_uint8]
    lib.pcf_bcd_encode.restype = ctypes.c_uint8
    lib.pcf85063_decode.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int64)]
    lib.pcf85063_encode.argtypes = [ctypes.c_int64, ctypes.c_char_p]
    lib.pcf85063_encode.restype = ctypes.c_bool
    lib.btn_fsm_init.argtypes = [ctypes.POINTER(BtnFsm), ctypes.c_bool, ctypes.c_uint32, ctypes.c_uint32]
    lib.btn_fsm_step.argtypes = [ctypes.POINTER(BtnFsm), ctypes.c_bool, ctypes.c_uint32, ctypes.POINTER(BtnEvent),
                                 ctypes.c_size_t]
    lib.btn_fsm_step.restype = ctypes.c_size_t
    lib.btn_fsm_pressed.argtypes = [ctypes.POINTER(BtnFsm)]
    lib.btn_fsm_pressed.restype = ctypes.c_bool
    lib.btn_fsm_classify.argtypes = [ctypes.c_uint32, ctypes.c_bool]
    lib.btn_fsm_classify.restype = ctypes.c_uint8
    return lib


def test_constants_match_headers(tmp_path):
    out = compile_and_run(tmp_path, r'''
#include <stdio.h>
#include "board/board.h"
int main(void) {
    printf("%d %d %d %d %d %d %d %d %d|%d %d %d %d %d|%d\n", BOARD_BTN_PRESSED, BOARD_BTN_AP_ARMED,
           BOARD_BTN_AP_DISARMED, BOARD_BTN_RESET_ARMED, BOARD_BTN_RELEASED_SHORT, BOARD_BTN_RELEASED_AP,
           BOARD_BTN_RELEASED_NONE, BOARD_BTN_RELEASED_RESET, BOARD_BTN_RESET_DISARMED, BOARD_BTN_DEBOUNCE_MS,
           BOARD_BTN_AP_MIN_MS, BOARD_BTN_AP_MAX_MS, BOARD_BTN_RESET_MS, BOARD_BTN_RESET_CANCEL_MS, BOARD_LED_COUNT);
    return 0;
}
''')
    assert out.strip() == '0 1 2 3 4 5 6 7 8|30 3000 8000 10000 30000|12'


# ---------------- PCF85063 codec ----------------

def test_bcd_all(lib):
    for v in range(100):
        b = lib.pcf_bcd_encode(v)
        assert b == (v // 10) << 4 | v % 10
        assert lib.pcf_bcd_decode(b) == v
    assert lib.pcf_bcd_encode(123) == 0x23
    for b in (0x0A, 0x1F, 0xA0, 0xFF, 0x9A):
        assert lib.pcf_bcd_decode(b) == -1


def regs_for(t):
    d = dt.datetime.fromtimestamp(t, dt.timezone.utc)
    bcd = lambda v: (v // 10) << 4 | v % 10  # noqa: E731
    return bytes([bcd(d.second), bcd(d.minute), bcd(d.hour), bcd(d.day), (d.weekday() + 1) % 7, bcd(d.month),
                  bcd(d.year - 2000)])


SAMPLES = [1704067200, 1709164800, 1709251199, 1792371600, 1798761599, 2524607999, 4102444799, 3000000000]


@pytest.mark.parametrize('t', SAMPLES)
def test_encode_decode_roundtrip(lib, t):
    buf = ctypes.create_string_buffer(7)
    assert lib.pcf85063_encode(t, buf)
    assert buf.raw == regs_for(t)
    out = ctypes.c_int64()
    assert lib.pcf85063_decode(buf.raw, ctypes.byref(out)) == PCF_OK
    assert out.value == t


def test_encode_range(lib):
    buf = ctypes.create_string_buffer(7)
    assert lib.pcf85063_encode(calendar.timegm((2000, 1, 1, 0, 0, 0)), buf)
    assert not lib.pcf85063_encode(calendar.timegm((1999, 12, 31, 23, 59, 59)), buf)
    assert not lib.pcf85063_encode(calendar.timegm((2100, 1, 1, 0, 0, 0)), buf)
    assert not lib.pcf85063_encode(-1, buf)


def decode(lib, regs):
    out = ctypes.c_int64(-7)
    rc = lib.pcf85063_decode(bytes(regs), ctypes.byref(out))
    return rc, out.value


def test_decode_errors(lib):
    good = bytearray(regs_for(1792371600))
    assert decode(lib, good)[0] == PCF_OK
    osf = bytearray(good)
    osf[0] |= 0x80
    assert decode(lib, osf) == (PCF_E_OSF, -7)  # output untouched
    bad = bytearray(good)
    bad[1] = 0x5A
    assert decode(lib, bad)[0] == PCF_E_BCD
    feb30 = bytearray(good)
    feb30[3], feb30[5] = 0x30, 0x02
    assert decode(lib, feb30)[0] == PCF_E_RANGE
    month13 = bytearray(good)
    month13[5] = 0x13
    assert decode(lib, month13)[0] == PCF_E_RANGE
    hour24 = bytearray(good)
    hour24[2] = 0x24
    assert decode(lib, hour24)[0] == PCF_E_RANGE
    assert decode(lib, regs_for(1704067199 - 86400 * 365))[0] == PCF_E_RANGE  # 2022: before valid minimum
    assert decode(lib, bytes(7))[0] == PCF_E_RANGE  # all zero: day 0


def test_decode_ignores_unused_bits_and_weekday(lib):
    t = 1792371600
    r = bytearray(regs_for(t))
    r[1] |= 0x80  # minutes bit 7 unused
    r[2] |= 0xC0  # hours bits 7..6 unused
    r[3] |= 0xC0
    r[4] = 6      # wrong weekday: ignored
    r[5] |= 0xE0
    assert decode(lib, r) == (PCF_OK, t)


# ---------------- button gestures ----------------

class Btn:
    def __init__(self, lib, pressed=False, t0=1000):
        self.lib, self.t = lib, t0
        self.f = BtnFsm()
        lib.btn_fsm_init(ctypes.byref(self.f), pressed, t0, DEBOUNCE)
        self.events = []

    def run(self, level, ms, step=POLL):
        end = self.t + ms
        while self.t < end:
            self.t += step
            out = (BtnEvent * 6)()
            n = self.lib.btn_fsm_step(ctypes.byref(self.f), level, self.t & 0xFFFFFFFF, out, 6)
            self.events += [(NAMES[out[i].ev], out[i].held_ms) for i in range(n)]
        return self

    def names(self):
        return [e for e, _ in self.events]

    def held(self, name):
        return [h for e, h in self.events if e == name]


def gesture(lib, hold_ms, step=POLL):
    return Btn(lib).run(False, 100, step).run(True, hold_ms, step).run(False, 200, step)


def test_short_press(lib):
    b = gesture(lib, 500)
    assert b.names() == ['PRESSED', 'REL_SHORT']
    assert b.held('REL_SHORT') == [500]  # raw edge to raw edge, debounce excluded


def test_ap_gesture(lib):
    b = gesture(lib, 5000)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'REL_AP']
    assert 3000 <= b.held('AP_ARMED')[0] < 3000 + POLL + DEBOUNCE
    assert b.held('REL_AP') == [5000]


def test_cancel_window_8_to_10_s(lib):
    assert gesture(lib, 9000).names() == ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'REL_NONE']


def test_factory_reset_gesture(lib):
    b = gesture(lib, 12000)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'RESET_ARMED', 'REL_RESET']
    assert b.held('REL_RESET') == [12000]


def test_stuck_button_cancels_reset(lib):
    b = gesture(lib, 35000)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'RESET_ARMED', 'RESET_DISARMED', 'REL_NONE']


@pytest.mark.parametrize('held,want', [(0, REL_SHORT), (2999, REL_SHORT), (3000, REL_AP), (8000, REL_AP),
                                       (8001, REL_NONE), (9999, REL_NONE), (10000, REL_RESET),
                                       (29999, REL_RESET)])
def test_classify_boundaries(lib, held, want):
    assert lib.btn_fsm_classify(held, False) == want
    assert lib.btn_fsm_classify(held, True) == (REL_NONE if want == REL_RESET else want)


@pytest.mark.parametrize('hold,last', [(3000, 'REL_AP'), (8000, 'REL_AP'), (8020, 'REL_NONE'),
                                       (10000, 'REL_RESET')])
def test_boundaries_through_fsm(lib, hold, last):
    assert gesture(lib, hold).names()[-1] == last


def test_bounce_is_filtered(lib):
    b = Btn(lib).run(False, 100, 5)
    for _ in range(4):  # 5 ms glitches while pressing
        b.run(True, 5, 5).run(False, 5, 5)
    b.run(True, 1000, 5)
    for _ in range(3):  # release bounce
        b.run(False, 5, 5).run(True, 5, 5)
    b.run(False, 200, 5)
    assert b.names() == ['PRESSED', 'REL_SHORT']


def test_glitch_while_held_does_not_release(lib):
    b = Btn(lib).run(False, 100).run(True, 4000).run(False, 20).run(True, 2000).run(False, 200)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'REL_AP']
    assert b.held('REL_AP') == [6020]


def test_thresholds_emitted_before_release_with_coarse_sampling(lib):
    # 400 ms sampling: the 10 s threshold is crossed between samples and the release edge lands after it.
    b = Btn(lib).run(False, 400, 400).run(True, 10_400, 400).run(False, 1200, 400)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'RESET_ARMED', 'REL_RESET']


def test_no_reset_armed_when_release_precedes_threshold(lib):
    # Raw release at 9990 ms, debounced 30 ms later (past 10 s): must stay a "none" release.
    b = Btn(lib).run(False, 100, 10).run(True, 9990, 10).run(False, 200, 10)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'AP_DISARMED', 'REL_NONE']


def test_pressed_at_init_is_ignored_until_released(lib):
    b = Btn(lib, pressed=True).run(True, 15000)
    assert b.events == [] and not lib.btn_fsm_pressed(ctypes.byref(b.f))
    b.run(False, 200)
    assert b.events == []
    b.run(True, 4000).run(False, 200)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'REL_AP']


def test_pressed_level_is_debounced(lib):
    b = Btn(lib).run(False, 100).run(True, 20)
    assert not lib.btn_fsm_pressed(ctypes.byref(b.f))
    b.run(True, 40)
    assert lib.btn_fsm_pressed(ctypes.byref(b.f))


def test_time_wraparound(lib):
    b = Btn(lib, t0=0xFFFFFFFF - 2000).run(False, 100).run(True, 5000).run(False, 200)
    assert b.names() == ['PRESSED', 'AP_ARMED', 'REL_AP']
    assert b.held('REL_AP') == [5000]
