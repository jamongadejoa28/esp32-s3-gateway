"""SNMPv3 crypto known answers on the host.

* RFC 3826 AES-128-CFB privacy through the OpenSSL gw_crypto backend with the IV/key derivation shared
  with the device backend (components/snmp_lwip/include/snmp_lwip/snmpv3_util.h, used verbatim by
  snmpv3_psa.c), checked against pysnmp's independent RFC 3826 implementation and `cryptography`.
* RFC 3414 A.3 key localization through snmp_gw's snmp_localize_key_for() (the function behind
  snmp_gw_localize_key()) and the gateway engine-ID format (PEN + MAC, gw_ident).
* The vectors embedded in the on-target self-test (components/snmp_lwip/snmpv3_selftest.c) are
  recomputed independently, so a wrong constant there fails here.
"""
import hashlib
import hmac
import random
import re

import pytest

from conftest import COMPONENTS, LISTS, ROOT, compile_and_run

SELFTEST = COMPONENTS / 'snmp_lwip' / 'snmpv3_selftest.c'
RFC3414_ENGINE = bytes.fromhex('000000000000000000000002')
SHA_MAPLE = bytes.fromhex('6695febc9288e36282235fc7151f128497b38f3f')
MD5_MAPLE = bytes.fromhex('526f5eed9fcce26f8964c2930787d82b')

cryptography = pytest.importorskip('cryptography')
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms  # noqa: E402

try:  # cryptography >= 43 moved CFB to the "decrepit" package
    from cryptography.hazmat.decrepit.ciphers.modes import CFB  # noqa: E402
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB  # noqa: E402


def py_localize(name, password, engine):
    buf = (password * (1048576 // len(password) + 1))[:1048576]
    ku = hashlib.new(name, buf).digest()
    return hashlib.new(name, ku + engine + ku).digest()


def aes_cfb(key, iv, data, encrypt=True):
    c = Cipher(algorithms.AES(key), CFB(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def host_sources():
    return [ROOT / p for p in LISTS['GW_HOST_SOURCES_GW_CORE'] + LISTS['GW_HOST_SOURCES_SNMP_GW']
            + LISTS.get('GW_HOST_ONLY_SOURCES', [])]


# ---------------------------------------------------------------- RFC 3826 via the shared helpers

AES_PROG = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gw_core/gw_crypto.h"
#include "snmp_lwip/snmpv3_util.h"

static int hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n && i < cap; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
    return (int)n;
}

/* argv-free: one case per stdin line "localized_hex boots time salt_hex plaintext_hex" */
int main(void) {
    char a[200], s[40], p[2100];
    unsigned long boots, t;
    if (gw_crypto_init() != 0) return 1;
    while (scanf("%199s %lu %lu %39s %2099s", a, &boots, &t, s, p) == 5) {
        uint8_t loc[32], salt[8], pt[1100], ct[1100], back[1100], iv[SNMPV3_AES_IV_LEN], key[SNMPV3_AES_KEY_LEN];
        int ln = hex(a, loc, sizeof loc), n = hex(p, pt, sizeof pt);
        hex(s, salt, sizeof salt);
        if (!snmpv3_aes_key(loc, (size_t)ln, key)) { puts("NOKEY"); continue; }
        snmpv3_aes_iv((uint32_t)boots, (uint32_t)t, salt, iv);
        if (gw_aes128_cfb(true, key, iv, pt, ct, (size_t)n) != 0) return 2;
        if (gw_aes128_cfb(false, key, iv, ct, back, (size_t)n) != 0 || memcmp(back, pt, (size_t)n) != 0) return 3;
        for (int i = 0; i < 16; i++) printf("%02x", iv[i]);
        putchar(' ');
        for (int i = 0; i < n; i++) printf("%02x", ct[i]);
        putchar('\n');
    }
    return 0;
}
'''


@pytest.fixture(scope='module')
def aes_case(tmp_path_factory):
    import subprocess
    from conftest import CFLAGS, INCLUDE_FLAGS, LIBS, cc
    d = tmp_path_factory.mktemp('aes')
    (d / 'aes.c').write_text(AES_PROG)
    cc([*CFLAGS, *INCLUDE_FLAGS, str(d / 'aes.c'), *map(str, host_sources()), '-o', str(d / 'aes'), *LIBS])

    def run(cases):
        inp = '\n'.join(f'{loc.hex()} {b} {t} {salt.hex()} {pt.hex() or "-"}' for loc, b, t, salt, pt in cases)
        r = subprocess.run([str(d / 'aes')], input=inp + '\n', capture_output=True, text=True, check=True)
        return [ln.split() for ln in r.stdout.splitlines()]
    return run


def test_rfc3826_iv_layout(aes_case):
    salt = bytes.fromhex('0102030405060708')
    ((iv, _),) = aes_case([(SHA_MAPLE, 0x01020304, 0xA0B0C0D0, salt, b'\x00' * 16)])
    assert iv == '01020304a0b0c0d00102030405060708', 'boots BE32 || time BE32 || salt'


@pytest.mark.parametrize('seed', range(4))
def test_rfc3826_aes_matches_pysnmp_and_cryptography(aes_case, seed):
    import pysnmp.entity.config  # noqa: F401  (import order: avoids a circular import inside pysnmp)
    from pyasn1.type.univ import OctetString
    from pysnmp.proto.secmod.rfc3826.priv.aes import Aes
    rnd = random.Random(seed)
    cases = []
    for n in (1, 15, 16, 17, 63, 64, 65, 100, 512, 1000):
        cases.append((bytes(rnd.getrandbits(8) for _ in range(20)), rnd.getrandbits(31), rnd.getrandbits(31),
                      bytes(rnd.getrandbits(8) for _ in range(8)), bytes(rnd.getrandbits(8) for _ in range(n))))
    for (loc, boots, t, salt, pt), (iv, ct) in zip(cases, aes_case(cases)):
        ct = bytes.fromhex(ct)
        assert bytes.fromhex(iv) == boots.to_bytes(4, 'big') + t.to_bytes(4, 'big') + salt
        assert ct == aes_cfb(loc[:16], bytes.fromhex(iv), pt)
        # pysnmp: independent RFC 3826 code (key/data as pyasn1 OctetString, salt as a list of octets)
        back = Aes().decrypt_data(OctetString(loc), (boots, t, list(salt)), OctetString(ct))
        assert bytes(back) == pt


def test_aes_key_needs_16_octets(aes_case):
    assert aes_case([(bytes(15), 1, 1, bytes(8), b'\x00')]) == [['NOKEY']]


# ---------------------------------------------------------------- RFC 3414 A.3 + gateway engine ID

def test_localization_rfc3414_through_snmp_gw(tmp_path):
    prog = r'''
#include <stdio.h>
#include "gw_core/gw_crypto.h"
#include "snmp_logic.h"
int main(void) {
    static const uint8_t eng[12] = {0,0,0,0,0,0,0,0,0,0,0,2};
    uint8_t k[20];
    if (gw_crypto_init() != 0 || snmp_localize_key_for("maplesyrup", eng, sizeof eng, k) != 0) return 1;
    for (int i = 0; i < 20; i++) printf("%02x", k[i]);
    puts("");
    return 0;
}
'''
    out = compile_and_run(tmp_path, prog, extra_sources=host_sources(), flags=[f'-I{COMPONENTS / "snmp_gw"}'])
    assert out.strip() == SHA_MAPLE.hex()


def test_gateway_engine_id_and_key_localization(tmp_path):
    """snmp_gw_engine_id() = gw_ident_engine_id(PEN, base MAC): 80 00 7E D9 03 <mac> for PEN 32473."""
    if not (COMPONENTS / 'gw_core' / 'gw_ident.c').is_file():
        pytest.skip('gw_ident.c (stream F) not landed yet')
    prog = r'''
#include <stdio.h>
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_ident.h"
#include "snmp_gw/registry.h"
#include "snmp_logic.h"
int main(void) {
    const uint8_t mac[6] = {0x24, 0x6f, 0x28, 0xa0, 0xb1, 0xc2};
    uint8_t eid[GW_ENGINE_ID_LEN], k[20];
    size_t n = gw_ident_engine_id(snmp_gw_pen(), mac, eid);
    for (size_t i = 0; i < n; i++) printf("%02x", eid[i]);
    if (gw_crypto_init() != 0 || snmp_localize_key_for("monitor-auth-1", eid, n, k) != 0) return 1;
    putchar(' ');
    for (int i = 0; i < 20; i++) printf("%02x", k[i]);
    puts("");
    return 0;
}
'''
    srcs = host_sources()
    out = compile_and_run(tmp_path, prog, extra_sources=srcs, flags=[f'-I{COMPONENTS / "snmp_gw"}']).split()
    assert out[0] == '80007ed903' + '246f28a0b1c2'
    assert out[1] == py_localize('sha1', b'monitor-auth-1', bytes.fromhex(out[0])).hex()


# ---------------------------------------------------------------- on-target self-test vectors


def c_array(src, name):
    m = re.search(rf'{name}\[[^\]]*\]\s*=\s*\{{([^}}]*)\}}', src)
    assert m, name
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1)))


def c_define(src, name):
    m = re.search(rf'#define {name} (\d+)u?\b', src)
    assert m, name
    return int(m.group(1))


def test_selftest_vectors_are_correct():
    src = SELFTEST.read_text()
    engine = bytes(int(x) for x in re.search(r'KAT_ENGINE_ID\[12\] = \{([^}]*)\}', src).group(1).split(','))
    assert engine == RFC3414_ENGINE
    assert 'KAT_PASSWORD[] = "maplesyrup"' in src
    key_sha, key_md5 = c_array(src, 'KAT_KEY_SHA'), c_array(src, 'KAT_KEY_MD5')
    assert key_sha == SHA_MAPLE == py_localize('sha1', b'maplesyrup', engine)
    assert key_md5 == MD5_MAPLE == py_localize('md5', b'maplesyrup', engine)

    # message / plaintext formulas must match the C macros
    assert '#define KAT_MSG(i) ((uint8_t)(((i) * 7 + 3) & 0xff))' in src
    assert '#define KAT_PT(i) ((uint8_t)(((i) * 13 + 5) & 0xff))' in src
    msg = bytes((i * 7 + 3) & 0xff for i in range(c_define(src, 'KAT_MSG_LEN')))
    assert c_array(src, 'KAT_HMAC_SHA') == hmac.new(key_sha, msg, 'sha1').digest()
    assert c_array(src, 'KAT_HMAC_MD5') == hmac.new(key_md5, msg, 'md5').digest()
    assert 0 < c_define(src, 'KAT_MSG_SPLIT') < len(msg)

    n = c_define(src, 'KAT_PT_LEN')
    pt = bytes((i * 13 + 5) & 0xff for i in range(n))
    boots, t = c_define(src, 'KAT_BOOTS'), c_define(src, 'KAT_TIME')
    salt = c_array(src, 'KAT_SALT')
    iv = boots.to_bytes(4, 'big') + t.to_bytes(4, 'big') + salt
    ct = c_array(src, 'KAT_CT')
    assert len(ct) == n and ct == aes_cfb(key_sha[:16], iv, pt)
    split = c_define(src, 'KAT_PT_SPLIT')
    assert 0 < split < 64 < n, 'a 64-byte CFB chunk must cross the pbuf boundary'


def test_selftest_runs_only_in_debug_builds():
    agent = (COMPONENTS / 'snmp_gw' / 'agent.c').read_text()
    block = agent.split('#if defined(CONFIG_LOG_DEFAULT_LEVEL_DEBUG)')[1].split('#endif')[0]
    assert 'snmpv3_selftest()' in block
    assert 'CONFIG_LOG_DEFAULT_LEVEL_DEBUG=y' in (ROOT / 'sdkconfig.defaults.debug').read_text()
