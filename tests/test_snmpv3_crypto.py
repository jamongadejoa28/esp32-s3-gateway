"""gw_crypto.h on the host backend (crypto_openssl.c) + gw_snmp_key_localize (gw_snmp_key.c).

Vectors: RFC 3414 A.3 (SNMPv3 key localization), RFC 7914 §11 (PBKDF2-HMAC-SHA256),
RFC 2202/4231 (HMAC), NIST SP 800-38A F.3.13/F.3.14 (AES-128-CFB128, as RFC 3826 uses it).
The device backend (crypto_psa.c) must pass the same vectors (on-device test, see HW_TEST.md).
"""
import ctypes as C
import hashlib
import hmac
import os

import pytest

MD5, SHA1, SHA256 = 0, 1, 2
OK, E_ARG = 0, -1
RFC3414_ENGINE = bytes.fromhex('000000000000000000000002')


@pytest.fixture(scope='module')
def lib(gwlib):
    l = gwlib
    l.gw_crypto_init.restype = C.c_int
    l.gw_hash_len.argtypes = [C.c_int]
    l.gw_hash_len.restype = C.c_size_t
    l.gw_hash.argtypes = [C.c_int, C.c_char_p, C.c_size_t, C.c_char_p]
    l.gw_hmac.argtypes = [C.c_int, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p]
    l.gw_pbkdf2_sha256.argtypes = [C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_uint32, C.c_char_p,
                                   C.c_size_t]
    l.gw_aes128_cfb.argtypes = [C.c_bool, C.c_char_p, C.c_char_p, C.c_void_p, C.c_void_p, C.c_size_t]
    l.gw_random.argtypes = [C.c_void_p, C.c_size_t]
    l.gw_ct_equal.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t]
    l.gw_ct_equal.restype = C.c_bool
    l.gw_secure_zero.argtypes = [C.c_void_p, C.c_size_t]
    l.gw_secure_zero.restype = None
    l.gw_hash_begin.argtypes = [C.c_int]
    l.gw_hash_begin.restype = C.c_void_p
    l.gw_hmac_begin.argtypes = [C.c_int, C.c_char_p, C.c_size_t]
    l.gw_hmac_begin.restype = C.c_void_p
    l.gw_hash_update.argtypes = [C.c_void_p, C.c_char_p, C.c_size_t]
    l.gw_hash_finish.argtypes = [C.c_void_p, C.c_char_p]
    l.gw_hash_abort.argtypes = [C.c_void_p]
    l.gw_hash_abort.restype = None
    l.gw_snmp_key_localize.argtypes = [C.c_int, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p]
    assert l.gw_crypto_init() == OK
    return l


def localize(lib, alg, password, engine):
    out = C.create_string_buffer(20)
    assert lib.gw_snmp_key_localize(alg, password, len(password), engine, len(engine), out) == OK
    return out.raw[:16 if alg == MD5 else 20]


def py_localize(name, password, engine):
    buf = (password * (1048576 // len(password) + 1))[:1048576]
    ku = hashlib.new(name, buf).digest()
    return hashlib.new(name, ku + engine + ku).digest()


# ---------------------------------------------------------------- SNMPv3 USM keys (RFC 3414 A.3)


def test_rfc3414_a32_sha(lib):
    assert localize(lib, SHA1, b'maplesyrup', RFC3414_ENGINE).hex() == '6695febc9288e36282235fc7151f128497b38f3f'


def test_rfc3414_a31_md5(lib):
    assert localize(lib, MD5, b'maplesyrup', RFC3414_ENGINE).hex() == '526f5eed9fcce26f8964c2930787d82b'


@pytest.mark.parametrize('password,engine', [
    (b'12345678', bytes.fromhex('80007ed903a0b1c2d3e4f5')),  # gateway engine-ID format (PEN 32473 + MAC)
    (b'a' * 64, bytes.fromhex('8000000001')),
    (b'pass phrase with spaces', os.urandom(32)),
    (b'x', b'\x01'),
])
def test_localize_matches_reference(lib, password, engine):
    for alg, name in ((SHA1, 'sha1'), (MD5, 'md5')):
        assert localize(lib, alg, password, engine) == py_localize(name, password, engine)


def test_localize_rejects_bad_args(lib):
    out = C.create_string_buffer(b'\xaa' * 20, 20)
    assert lib.gw_snmp_key_localize(SHA1, b'', 0, RFC3414_ENGINE, 12, out) == E_ARG
    assert out.raw == bytes(20), 'output must be zeroed on error'
    assert lib.gw_snmp_key_localize(SHA1, b'maplesyrup', 10, RFC3414_ENGINE, 0, out) == E_ARG
    assert lib.gw_snmp_key_localize(SHA1, b'maplesyrup', 10, bytes(33), 33, out) == E_ARG
    assert lib.gw_snmp_key_localize(SHA256, b'maplesyrup', 10, RFC3414_ENGINE, 12, out) == E_ARG


# ---------------------------------------------------------------- PBKDF2-HMAC-SHA256 (auth records)


@pytest.mark.parametrize('password,salt,iters,hexdk', [
    (b'passwd', b'salt', 1, '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'
                            '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'),  # RFC 7914 §11
    (b'Password', b'NaCl', 80000, '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56'
                                  'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d'),  # RFC 7914 §11
    (b'password', b'salt', 4096, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'),
])
def test_pbkdf2_sha256_vectors(lib, password, salt, iters, hexdk):
    n = len(hexdk) // 2
    out = C.create_string_buffer(n)
    assert lib.gw_pbkdf2_sha256(password, len(password), salt, len(salt), iters, out, n) == OK
    assert out.raw.hex() == hexdk
    assert hashlib.pbkdf2_hmac('sha256', password, salt, iters, n).hex() == hexdk


def test_pbkdf2_arg_checks(lib):
    out = C.create_string_buffer(65)
    assert lib.gw_pbkdf2_sha256(b'p', 1, b's', 1, 0, out, 32) == E_ARG
    assert lib.gw_pbkdf2_sha256(b'p', 1, b's', 1, 1, out, 0) == E_ARG
    assert lib.gw_pbkdf2_sha256(b'p', 1, b's', 1, 1, out, 65) == E_ARG


# ---------------------------------------------------------------- hash / HMAC


@pytest.mark.parametrize('alg,name,length', [(MD5, 'md5', 16), (SHA1, 'sha1', 20), (SHA256, 'sha256', 32)])
def test_hash_hmac_oneshot_and_streaming(lib, alg, name, length):
    assert lib.gw_hash_len(alg) == length
    for data in (b'', b'abc', os.urandom(1000)):
        out = C.create_string_buffer(length)
        assert lib.gw_hash(alg, data, len(data), out) == OK
        assert out.raw == hashlib.new(name, data).digest()
    # RFC 2202 / RFC 4231 test case 2, plus a key longer than the block size.
    for key, data in ((b'Jefe', b'what do ya want for nothing?'), (b'\xaa' * 131, b'x' * 77)):
        out = C.create_string_buffer(length)
        assert lib.gw_hmac(alg, key, len(key), data, len(data), out) == OK
        assert out.raw == hmac.new(key, data, name).digest()
        ctx = lib.gw_hmac_begin(alg, key, len(key))
        assert ctx
        for i in range(0, len(data), 5):
            assert lib.gw_hash_update(ctx, data[i:i + 5], len(data[i:i + 5])) == OK
        out2 = C.create_string_buffer(length)
        assert lib.gw_hash_finish(ctx, out2) == OK
        assert out2.raw == out.raw
    ctx = lib.gw_hash_begin(alg)
    lib.gw_hash_abort(ctx)
    lib.gw_hash_abort(None)


def test_rfc_hmac_literals(lib):
    data = b'what do ya want for nothing?'
    expect = {MD5: '750c783e6ab0b503eaa86e310a5db738', SHA1: 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
              SHA256: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'}
    for alg, hexmac in expect.items():
        out = C.create_string_buffer(32)
        assert lib.gw_hmac(alg, b'Jefe', 4, data, len(data), out) == OK
        assert out.raw[:len(hexmac) // 2].hex() == hexmac


def test_bad_alg(lib):
    out = C.create_string_buffer(32)
    assert lib.gw_hash_len(7) == 0
    assert lib.gw_hash(7, b'a', 1, out) == E_ARG
    assert not lib.gw_hash_begin(7)


# ---------------------------------------------------------------- AES-128-CFB128 (RFC 3826 privacy)

KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
IV = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
PT = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'
                   '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
CT = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b'
                   '26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6')


def aes(lib, enc, data, inplace=False):
    buf = C.create_string_buffer(data, len(data))
    out = buf if inplace else C.create_string_buffer(len(data))
    assert lib.gw_aes128_cfb(enc, KEY, IV, buf, out, len(data)) == OK
    return out.raw[:len(data)]


@pytest.mark.parametrize('inplace', [False, True])
def test_aes_cfb128_sp800_38a(lib, inplace):
    assert aes(lib, True, PT, inplace) == CT
    assert aes(lib, False, CT, inplace) == PT


@pytest.mark.parametrize('n', [0, 1, 15, 17, 33, 63, 64, 65, 1000])
def test_aes_cfb128_any_length(lib, n):
    """CFB is a stream mode: any prefix of the vector stream encrypts to the prefix (no padding)."""
    data = (PT * (n // len(PT) + 1))[:n]
    ct = aes(lib, True, data)
    if n <= len(PT):
        assert ct == CT[:n]
    assert aes(lib, False, ct) == data
    assert aes(lib, True, data, inplace=True) == ct


# ---------------------------------------------------------------- helpers


def test_ct_equal_and_secure_zero(lib):
    a = os.urandom(32)
    assert lib.gw_ct_equal(a, a, 32)
    assert lib.gw_ct_equal(b'', b'', 0)
    for i in (0, 15, 31):
        b = bytearray(a)
        b[i] ^= 0x01
        assert not lib.gw_ct_equal(a, bytes(b), 32)
    buf = C.create_string_buffer(b'\xff' * 16, 16)
    lib.gw_secure_zero(buf, 16)
    assert buf.raw == bytes(16)


def test_random(lib):
    a, b = C.create_string_buffer(32), C.create_string_buffer(32)
    assert lib.gw_random(a, 32) == OK and lib.gw_random(b, 32) == OK
    assert a.raw != b.raw and a.raw != bytes(32)
    assert lib.gw_random(None, 0) == OK


# ---------------------------------------------------------------- HMAC_DRBG (gw_drbg.c, SP 800-90A §10.1.2)

class PyHmacDrbg:
    """Independent reference: NIST SP 800-90A Rev.1 HMAC_DRBG with SHA-256, no prediction resistance."""

    def __init__(self, entropy, pers=b''):
        self.k, self.v = b'\x00' * 32, b'\x01' * 32
        self._update(entropy + pers)

    def _h(self, data):
        return hmac.new(self.k, data, hashlib.sha256).digest()

    def _update(self, provided):
        self.k = self._h(self.v + b'\x00' + provided)
        self.v = self._h(self.v)
        if provided:
            self.k = self._h(self.v + b'\x01' + provided)
            self.v = self._h(self.v)

    def reseed(self, entropy, add=b''):
        self._update(entropy + add)

    def generate(self, n, add=b''):
        if add:
            self._update(add)
        out = b''
        while len(out) < n:
            self.v = self._h(self.v)
            out += self.v
        self._update(add)
        return out[:n]


class Drbg(C.Structure):
    _fields_ = [('k', C.c_uint8 * 32), ('v', C.c_uint8 * 32), ('reseed_counter', C.c_uint32)]


@pytest.fixture(scope='module')
def dlib(lib):
    lib.gw_drbg_instantiate.argtypes = [C.POINTER(Drbg), C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t]
    lib.gw_drbg_reseed.argtypes = [C.POINTER(Drbg), C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t]
    lib.gw_drbg_generate.argtypes = [C.POINTER(Drbg), C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t]
    lib.gw_drbg_needs_reseed.argtypes = [C.POINTER(Drbg)]
    lib.gw_drbg_needs_reseed.restype = C.c_bool
    return lib


def test_drbg_matches_reference(dlib):
    rnd = __import__('random').Random(0xD5B6)
    for _ in range(30):
        ent = bytes(rnd.randrange(256) for _ in range(rnd.choice([32, 48, 64])))
        pers = bytes(rnd.randrange(256) for _ in range(rnd.choice([0, 7, 22])))
        d = Drbg()
        assert dlib.gw_drbg_instantiate(C.byref(d), ent, len(ent), pers or None, len(pers)) == OK
        ref = PyHmacDrbg(ent, pers)
        assert bytes(d.k) == ref.k and bytes(d.v) == ref.v
        for _ in range(5):
            if rnd.random() < 0.2:
                e2 = os.urandom(32)
                a2 = os.urandom(rnd.choice([0, 9]))
                assert dlib.gw_drbg_reseed(C.byref(d), e2, 32, a2 or None, len(a2)) == OK
                ref.reseed(e2, a2)
            n = rnd.choice([1, 16, 31, 32, 33, 100])
            add = os.urandom(rnd.choice([0, 24]))
            out = C.create_string_buffer(n)
            assert dlib.gw_drbg_generate(C.byref(d), out, n, add or None, len(add)) == OK
            assert out.raw == ref.generate(n, add)


def test_drbg_rejects_misuse(dlib):
    d = Drbg()
    out = C.create_string_buffer(16)
    assert dlib.gw_drbg_generate(C.byref(d), out, 16, None, 0) == E_ARG          # not instantiated
    assert dlib.gw_drbg_needs_reseed(C.byref(d))
    assert dlib.gw_drbg_instantiate(C.byref(d), b'x' * 31, 31, None, 0) == E_ARG  # < 256-bit seed
    assert dlib.gw_drbg_instantiate(C.byref(d), b'x' * 32, 32, None, 0) == OK
    assert not dlib.gw_drbg_needs_reseed(C.byref(d))
    assert dlib.gw_drbg_generate(C.byref(d), out, 0, None, 0) == E_ARG
    d.reseed_counter = 100001                                                     # interval exhausted
    assert dlib.gw_drbg_generate(C.byref(d), out, 16, None, 0) == E_ARG and out.raw == b'\0' * 16
    assert dlib.gw_drbg_reseed(C.byref(d), b'y' * 32, 32, None, 0) == OK
    assert dlib.gw_drbg_generate(C.byref(d), out, 16, None, 0) == OK
