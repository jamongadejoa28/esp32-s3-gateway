"""gw_core/gw_ident.c: hostname/SSID/suffix, factory AP PSK format, SNMP engine ID (stream F)."""
import base64
import ctypes
import os
import re

import pytest

MAC = bytes.fromhex('a085e3123456')


@pytest.fixture(scope='module')
def lib(host_lib):
    lib = host_lib()  # GW_CORE only
    for name in ('gw_ident_suffix', 'gw_ident_hostname', 'gw_ident_ssid', 'gw_ident_ap_psk_format'):
        getattr(lib, name).argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        getattr(lib, name).restype = None
    lib.gw_ident_engine_id.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p]
    lib.gw_ident_engine_id.restype = ctypes.c_size_t
    return lib


def call_str(fn, arg, size=65):
    buf = ctypes.create_string_buffer(b'\xaa' * size, size)
    fn(arg, buf)
    return buf.value.decode()


@pytest.mark.parametrize('mac,sfx', [(MAC, '3456'), (bytes.fromhex('0011223344ab'), '44AB'),
                                     (bytes.fromhex('ffffffffffff'), 'FFFF'), (bytes(6), '0000')])
def test_suffix_hostname_ssid(lib, mac, sfx):
    assert call_str(lib.gw_ident_suffix, mac, 5) == sfx
    assert call_str(lib.gw_ident_hostname, mac, 33) == f'mestio-gw-{sfx.lower()}'
    assert call_str(lib.gw_ident_ssid, mac, 33) == f'MESTIO-GW-{sfx}'


def test_hostname_is_rfc1123_label(lib):
    host = call_str(lib.gw_ident_hostname, bytes.fromhex('a0b1c2d3e4f5'), 33)
    assert re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', host)


def test_psk_known_vector(lib):
    assert call_str(lib.gw_ident_ap_psk_format, b'abcdefghij', 64) == 'mfrg-gzdf-mztw-q2lk'


@pytest.mark.parametrize('seed', range(40))
def test_psk_matches_rfc4648_base32(lib, seed):
    rnd = os.urandom(10) if seed else bytes(10)
    psk = call_str(lib.gw_ident_ap_psk_format, rnd, 64)
    ref = base64.b32encode(rnd).decode().lower()  # 80 bits -> 16 chars, no padding
    assert psk == '-'.join(ref[i:i + 4] for i in range(0, 16, 4))
    assert len(psk) == 19 and re.fullmatch(r'([a-z2-7]{4}-){3}[a-z2-7]{4}', psk)


@pytest.mark.parametrize('pen,head', [(32473, '80007ed9'), (0, '80000000'), (2147483647, 'ffffffff'),
                                      (1, '80000001')])
def test_engine_id(lib, pen, head):
    out = ctypes.create_string_buffer(11)
    assert lib.gw_ident_engine_id(pen, MAC, out) == 11
    assert out.raw.hex() == head + '03' + MAC.hex()
