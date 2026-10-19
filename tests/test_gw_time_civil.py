"""gw_core/gw_time_civil.c: pure calendar helpers of gw_time.h, checked against Python's datetime."""
import ctypes
import datetime as dt

import pytest


class Civil(ctypes.Structure):
    _fields_ = [('year', ctypes.c_uint16), ('mon', ctypes.c_uint8), ('day', ctypes.c_uint8),
                ('hour', ctypes.c_uint8), ('min', ctypes.c_uint8), ('sec', ctypes.c_uint8),
                ('wday', ctypes.c_uint8)]


@pytest.fixture(scope='module')
def lib(host_lib):
    lib = host_lib()  # GW_CORE only
    lib.gw_time_to_civil.argtypes = [ctypes.c_int64, ctypes.POINTER(Civil)]
    lib.gw_time_from_civil.argtypes = [ctypes.POINTER(Civil)]
    lib.gw_time_from_civil.restype = ctypes.c_int64
    lib.gw_time_yyyymmdd.argtypes = [ctypes.c_int64]
    lib.gw_time_yyyymmdd.restype = ctypes.c_uint32
    lib.gw_time_snmp_date.argtypes = [ctypes.c_int64, ctypes.c_char_p]
    lib.gw_time_snmp_date.restype = ctypes.c_size_t
    lib.gw_time_iso8601.argtypes = [ctypes.c_int64, ctypes.c_char_p, ctypes.c_size_t]
    lib.gw_time_iso8601.restype = ctypes.c_size_t
    return lib


SAMPLES = [0, 86399, 86400, 951782400, 951868799, 1704067200, 1709164800, 1792371600, 4102444800,
           4291747199]


@pytest.mark.parametrize('t', SAMPLES)
def test_civil_round_trip(lib, t):
    c = Civil()
    lib.gw_time_to_civil(t, ctypes.byref(c))
    ref = dt.datetime.fromtimestamp(t, dt.timezone.utc)
    assert (c.year, c.mon, c.day, c.hour, c.min, c.sec) == (ref.year, ref.month, ref.day, ref.hour,
                                                            ref.minute, ref.second)
    assert c.wday == (ref.weekday() + 1) % 7
    assert lib.gw_time_from_civil(ctypes.byref(c)) == t
    assert lib.gw_time_yyyymmdd(t) == int(ref.strftime('%Y%m%d'))


@pytest.mark.parametrize('fields', [(1969, 12, 31, 0, 0, 0), (2106, 1, 1, 0, 0, 0), (2023, 2, 29, 0, 0, 0),
                                    (2024, 13, 1, 0, 0, 0), (2024, 1, 0, 0, 0, 0), (2024, 1, 1, 24, 0, 0),
                                    (2024, 4, 31, 0, 0, 0)])
def test_from_civil_rejects(lib, fields):
    c = Civil(*fields, 0)
    assert lib.gw_time_from_civil(ctypes.byref(c)) == -1


def test_snmp_date_and_iso(lib):
    ms = 1792371600123
    buf = ctypes.create_string_buffer(11)
    assert lib.gw_time_snmp_date(ms, buf) == 11
    ref = dt.datetime.fromtimestamp(ms // 1000, dt.timezone.utc)
    assert buf.raw == bytes([ref.year >> 8, ref.year & 0xFF, ref.month, ref.day, ref.hour, ref.minute,
                             ref.second, 1, ord('+'), 0, 0])
    out = ctypes.create_string_buffer(25)
    assert lib.gw_time_iso8601(ms, out, 25) == 24
    assert out.value.decode() == ref.strftime('%Y-%m-%dT%H:%M:%S') + '.123Z'
    assert lib.gw_time_iso8601(ms, out, 24) == 0
