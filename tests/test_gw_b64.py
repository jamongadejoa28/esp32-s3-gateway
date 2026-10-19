"""gw_core/gw_b64.c: base64 (RFC 4648 §4), base64url unpadded (§5) and hex, strict decoders."""
import base64
import ctypes as C
import os

import pytest

from stream_c_lib import clib  # noqa: F401  (fixture)

STD, URL = 0, 1


def enc(lib, data, v, cap=None):
    cap = cap if cap is not None else len(data) * 2 + 8
    out = C.create_string_buffer(cap)
    n = lib.gw_b64_encode(data, len(data), out, cap, v)
    return n, out.value.decode() if n >= 0 else None


def dec(lib, text, v, cap=256):
    raw = text.encode() if isinstance(text, str) else text
    out = C.create_string_buffer(cap)
    n = lib.gw_b64_decode(raw, len(raw), out, cap, v)
    return n, out.raw[:n] if n >= 0 else None


RFC4648 = [(b'', ''), (b'f', 'Zg=='), (b'fo', 'Zm8='), (b'foo', 'Zm9v'), (b'foob', 'Zm9vYg=='),
           (b'fooba', 'Zm9vYmE='), (b'foobar', 'Zm9vYmFy')]


@pytest.mark.parametrize('data,text', RFC4648)
def test_rfc4648_vectors_std(clib, data, text):
    assert enc(clib, data, STD) == (len(text), text)
    assert dec(clib, text, STD) == (len(data), data)


@pytest.mark.parametrize('data,text', RFC4648)
def test_rfc4648_vectors_url_unpadded(clib, data, text):
    t = text.rstrip('=')
    assert enc(clib, data, URL) == (len(t), t)
    assert dec(clib, t, URL) == (len(data), data)


def test_roundtrip_random(clib):
    for n in list(range(0, 70)) + [255, 1000]:
        data = os.urandom(n)
        for v, ref in ((STD, base64.b64encode(data).decode()),
                       (URL, base64.urlsafe_b64encode(data).decode().rstrip('='))):
            k, text = enc(clib, data, v)
            assert text == ref
            assert dec(clib, text, v, cap=max(n, 1)) == (n, data)


def test_url_alphabet_and_token_length(clib):
    data = bytes([0xfb, 0xff, 0xbf] * 6)
    _, text = enc(clib, data, URL)
    assert set(text) <= set('-_') | set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    assert '-' in text and '_' in text
    assert enc(clib, os.urandom(16), URL)[0] == 22  # session token / CSRF length


@pytest.mark.parametrize('text', ['Zg=', 'Zg', 'Z===', '=Zg=', 'Zm9v Zg==', 'Zh==', 'Zm9=', 'Zm8=Zm8=', 'Zm-v',
                                  'Zm_v', 'Zm9v\n', '****'])
def test_std_decode_rejects(clib, text):
    assert dec(clib, text, STD)[0] == -1


@pytest.mark.parametrize('text', ['Zg==', 'Z', 'Zh', 'Zm9', 'Zm+v', 'Zm/v', 'Zm9v=', 'Zm 9v'])
def test_url_decode_rejects(clib, text):
    # 'Zm9' decodes to 2 bytes only if the trailing bits are zero: '9' = 0b111101 -> non-zero low bits.
    assert dec(clib, text, URL)[0] == -1


def test_encode_capacity_checks(clib):
    data = b'foobar'
    assert enc(clib, data, STD, cap=8)[0] == -1  # needs 8 + NUL
    assert enc(clib, data, STD, cap=9)[0] == 8
    assert enc(clib, b'\x00' * 16, URL, cap=22)[0] == -1
    assert enc(clib, b'\x00' * 16, URL, cap=23)[0] == 22
    assert clib.gw_b64_encode(b'x', 1, None, 8, STD) == -1
    assert clib.gw_b64_encode(b'x', 1, C.create_string_buffer(8), 8, 7) == -1


def test_decode_capacity_checks(clib):
    assert dec(clib, 'Zm9vYmFy', STD, cap=5)[0] == -1
    assert dec(clib, 'Zm9vYmFy', STD, cap=6) == (6, b'foobar')
    assert dec(clib, '', STD, cap=0)[0] == 0


def test_hex(clib):
    data = bytes(range(256))
    out = C.create_string_buffer(513)
    assert clib.gw_hex_encode(data, 256, out, 513) == 512
    assert out.value.decode() == data.hex()
    assert clib.gw_hex_encode(data, 256, out, 512) == -1
    back = C.create_string_buffer(256)
    assert clib.gw_hex_decode(data.hex().upper().encode(), 512, back, 256) == 256
    assert back.raw == data
    for bad in (b'abc', b'zz', b'0g', b' 0'):
        assert clib.gw_hex_decode(bad, len(bad), back, 256) == -1
    assert clib.gw_hex_decode(b'0011', 4, back, 1) == -1
