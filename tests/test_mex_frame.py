"""mex150 frame.c: CRC-16/MODBUS, request build, response parse (ported esp32-s3-monitor tests plus
edge cases), expected-length helper, and fuzzing of mex_response() with random/mutated frames under
AddressSanitizer + UBSan (must never crash or read out of bounds)."""
import ctypes as C
import random
import shutil
import subprocess

import pytest

from conftest import CC, COMPONENTS, INCLUDE_FLAGS, compile_and_run

E_FRAME, E_FC, E_ECHO, E_LEN = -1, -2, -3, -4


@pytest.fixture(scope='module')
def lib(host_lib):
    l = host_lib('MEX150')
    l.mex_crc.argtypes = [C.c_char_p, C.c_size_t]
    l.mex_crc.restype = C.c_uint16
    l.mex_frame_crc_ok.argtypes = [C.c_char_p, C.c_size_t]
    l.mex_frame_crc_ok.restype = C.c_bool
    l.mex_request.argtypes = [C.c_uint8, C.c_uint8, C.c_uint16, C.c_uint16, C.c_char_p]
    l.mex_request.restype = C.c_size_t
    l.mex_response.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t, C.c_void_p, C.c_size_t]
    l.mex_response.restype = C.c_int
    l.mex_response_expected.argtypes = [C.c_char_p, C.c_size_t, C.c_uint8]
    l.mex_response_expected.restype = C.c_size_t
    return l


def py_crc(data):
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0xA001 if c & 1 else 0)
    return c


def packet(body):
    return body + py_crc(body).to_bytes(2, 'little')


def req(lib, unit, fc, addr, val):
    out = C.create_string_buffer(8)
    assert lib.mex_request(unit, fc, addr, val, out) == 8
    return out.raw


def resp(lib, q, p, cap=16):
    v = (C.c_uint16 * max(cap, 1))()
    r = lib.mex_response(q, p, len(p), v, cap)
    return r, list(v)[:cap]


# ---------------------------------------------------------------- CRC / request


def test_crc_reference_vectors(lib):
    assert lib.mex_crc(b'', 0) == 0xFFFF
    assert lib.mex_crc(b'123456789', 9) == 0x4B37  # CRC-16/MODBUS check value
    body = bytes.fromhex('01 03 00 00 00 0A')
    assert lib.mex_crc(body, 6).to_bytes(2, 'little') == bytes.fromhex('C5 CD')


def test_crc_matches_reference_random(lib):
    rnd = random.Random(1)
    for _ in range(300):
        data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 64)))
        assert lib.mex_crc(data, len(data)) == py_crc(data)


def test_document_coil_frame(lib):
    """Monitor test: the example frame from the MEX150 map."""
    assert req(lib, 1, 1, 0, 8) == bytes.fromhex('01 01 00 00 00 08 3d cc')


def test_request_layout(lib):
    q = req(lib, 0x11, 6, 0x0B, 0xFFF1)
    assert q[:6] == bytes([0x11, 6, 0x00, 0x0B, 0xFF, 0xF1])
    assert q[6:] == py_crc(q[:6]).to_bytes(2, 'little')
    assert lib.mex_frame_crc_ok(q, 8)


def test_frame_crc_ok(lib):
    p = packet(bytes.fromhex('01 03 02 00 ea'))
    assert lib.mex_frame_crc_ok(p, len(p))
    assert not lib.mex_frame_crc_ok(p[:-1], len(p) - 1)
    assert not lib.mex_frame_crc_ok(b'\x01\x02', 2)
    bad = bytearray(p)
    bad[3] ^= 0x40
    assert not lib.mex_frame_crc_ok(bytes(bad), len(bad))


# ---------------------------------------------------------------- response (monitor port)


def test_response_identity_crc_length(lib):
    """Monitor test_response_identity_crc_length, verbatim semantics."""
    q = bytes.fromhex('01 03 00 23 00 02 00 00')
    p = packet(bytes.fromhex('01 03 04 ff e7 01 f4'))
    assert resp(lib, q, p, 2) == (0, [65511, 500])
    assert lib.mex_response(q, p[:-1], len(p) - 1, (C.c_uint16 * 2)(), 2) < 0
    assert resp(lib, q, p, 1)[0] < 0
    bad = packet(bytes.fromhex('02 03 04 ff e7 01 f4'))
    assert resp(lib, q, bad, 2)[0] < 0
    bad = bytearray(p)
    bad[4] ^= 1
    assert resp(lib, q, bytes(bad), 2)[0] < 0
    exception = packet(bytes.fromhex('01 83 02'))
    assert resp(lib, q, exception, 2)[0] == 2


def test_response_error_codes(lib):
    q = req(lib, 1, 3, 0x23, 2)
    ok = packet(bytes.fromhex('01 03 04 00 01 00 02'))
    assert resp(lib, q, ok, 2) == (0, [1, 2])
    assert resp(lib, q, ok[:4], 2)[0] == E_FRAME                                # < 5 bytes
    assert resp(lib, q, packet(bytes.fromhex('07 03 04 00 01 00 02')), 2)[0] == E_FRAME  # unit
    assert resp(lib, q, packet(bytes.fromhex('01 04 04 00 01 00 02')), 2)[0] == E_FC
    assert resp(lib, q, packet(bytes.fromhex('01 03 02 00 01')), 2)[0] == E_LEN  # count mismatch
    assert resp(lib, q, packet(bytes.fromhex('01 03 06 00 01 00 02 00 03')), 2)[0] == E_LEN
    assert resp(lib, q, ok, 1)[0] == E_LEN                                        # capacity
    assert lib.mex_response(q, ok, len(ok), None, 2) == E_LEN                     # no buffer
    assert resp(lib, q, packet(bytes.fromhex('01 83 00')), 2)[0] == E_FRAME       # exception code 0
    assert resp(lib, q, packet(bytes.fromhex('01 83 02 00')), 2)[0] == E_FRAME    # exception length
    assert resp(lib, q, packet(bytes.fromhex('01 86 02')), 2)[0] == E_FC          # other fc's exception
    for code in (1, 2, 3, 4, 6, 11, 255):
        assert resp(lib, q, packet(bytes([1, 0x83, code])), 2)[0] == code
    big = packet(bytes([1, 3, 255]) + bytes(255))
    assert len(big) == 260 and resp(lib, q, big, 16)[0] == E_FRAME               # > RTU ADU max


def test_response_coils_unpack(lib):
    q = req(lib, 1, 1, 0, 8)
    r, v = resp(lib, q, packet(bytes.fromhex('01 01 01 85')), 8)
    assert r == 0 and v == [1, 0, 1, 0, 0, 0, 0, 1]
    q = req(lib, 1, 1, 16, 10)
    r, v = resp(lib, q, packet(bytes.fromhex('01 01 02 ff 02')), 10)
    assert r == 0 and v == [1] * 8 + [0, 1]
    assert resp(lib, q, packet(bytes.fromhex('01 01 01 ff')), 10)[0] == E_LEN


def test_response_write_echo(lib):
    q = req(lib, 1, 6, 11, 250)
    assert resp(lib, q, q, 0)[0] == 0
    other = packet(q[:5] + bytes([q[5] ^ 1]))
    assert resp(lib, q, other, 0)[0] == E_ECHO
    assert resp(lib, q, packet(q[:6] + b'\x00'), 0)[0] == E_ECHO
    assert resp(lib, q, packet(bytes([1, 0x86, 3])), 0)[0] == 3


def test_response_expected_length(lib):
    assert lib.mex_response_expected(b'\x01\x03', 2, 3) == 0
    assert lib.mex_response_expected(b'\x01\x83\x02', 3, 3) == 5
    assert lib.mex_response_expected(b'\x01\x86\x02', 3, 6) == 5
    assert lib.mex_response_expected(b'\x01\x06\x00', 3, 6) == 8
    assert lib.mex_response_expected(b'\x01\x03\x04', 3, 3) == 9
    assert lib.mex_response_expected(b'\x01\x01\x01', 3, 1) == 6
    assert lib.mex_response_expected(b'\x01\x03\xff', 3, 3) == 260


def test_response_random_bytes_ctypes(lib):
    """Random garbage through the shared library: never OK unless it is a well-formed frame."""
    rnd = random.Random(7)
    q = req(lib, 1, 3, 9, 12)
    for _ in range(5000):
        p = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
        r, _ = resp(lib, q, p, 16)
        if r == 0:
            assert len(p) == 29 and p[:3] == b'\x01\x03\x18' and py_crc(p[:-2]) == int.from_bytes(p[-2:], 'little')


# ---------------------------------------------------------------- sanitizer fuzz


FUZZ = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mex150/frame.h"

static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint32_t)s; }

int main(void) {
    static const uint8_t fcs[] = {1, 3, 5, 6, 0x10};
    unsigned ok = 0, exc = 0, err = 0;
    for (unsigned it = 0; it < 400000; it++) {
        uint8_t q[MEX_REQ_LEN];
        const uint8_t fc = fcs[rnd() % sizeof fcs];
        mex_request((uint8_t)(rnd() % 3), fc, (uint16_t)rnd(), (uint16_t)(rnd() % 40), q);
        /* exact-size heap buffer: any over-read is reported by ASan */
        size_t n = rnd() % 300;
        uint8_t *p = malloc(n ? n : 1);
        if (it % 3 == 0 && n >= 5) {            /* plausible frame: header copied, valid CRC */
            for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd();
            p[0] = q[0]; p[1] = (rnd() & 7) ? fc : (uint8_t)(fc | 0x80);
            if (rnd() & 1) p[2] = (uint8_t)(n - 5);
            uint16_t c = mex_crc(p, n - 2); p[n - 2] = (uint8_t)c; p[n - 1] = (uint8_t)(c >> 8);
        } else {
            for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd();
        }
        const size_t cap = rnd() % 20;
        uint16_t *v = (rnd() % 8) ? malloc(cap ? cap * sizeof *v : 1) : NULL;
        const int r = mex_response(q, p, n, v, cap);
        if (r == 0) {
            ok++;
            if (fc == 1 || fc == 3) {
                const unsigned count = (unsigned)q[4] * 256u + q[5];
                const unsigned bytes = fc == 1 ? (count + 7) / 8 : count * 2;
                if (n != bytes + 5 || count > cap || !v) { printf("BAD ok n=%zu\n", n); return 1; }
            } else if (n != 8 || memcmp(p, q, 6)) { printf("BAD echo\n"); return 1; }
        } else if (r > 0) {
            exc++;
            if (n != 5 || p[1] != (uint8_t)(q[1] | 0x80) || r != p[2] || r > 255) { printf("BAD exc\n"); return 1; }
        } else {
            err++;
            if (r != MEX_RESP_E_FRAME && r != MEX_RESP_E_FC && r != MEX_RESP_E_ECHO && r != MEX_RESP_E_LEN) {
                printf("BAD code %d\n", r); return 1;
            }
        }
        (void)mex_response_expected(p, n, fc);
        (void)mex_frame_crc_ok(p, n);
        free(p);
        free(v);
    }
    printf("%u %u %u\n", ok, exc, err);
    return 0;
}
'''


def _sanitizers_available(tmp_path):
    src = tmp_path / 'probe.c'
    src.write_text('int main(void) { return 0; }\n')
    r = subprocess.run([CC, '-fsanitize=address,undefined', str(src), '-o', str(tmp_path / 'probe')],
                       capture_output=True)
    return r.returncode == 0


def test_response_fuzz_sanitizers(tmp_path):
    flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    if not shutil.which(CC) or not _sanitizers_available(tmp_path):
        flags = []  # still a functional fuzz run without instrumentation
    out = compile_and_run(tmp_path, FUZZ, name='fuzz_frame', flags=flags,
                          extra_sources=[COMPONENTS / 'mex150' / 'frame.c'])
    ok, exc, err = map(int, out.split())
    assert ok > 0 and exc > 0 and err > 0  # every outcome class was exercised
    assert INCLUDE_FLAGS  # harness sanity
