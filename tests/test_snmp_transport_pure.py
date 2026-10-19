"""Per-datagram decisions of components/snmp_lwip/snmp_transport.c, compiled from the header-only
snmp_transport_util.h the transport itself uses: BER header peek (version, PDU tag, community) on
messages encoded independently by pysnmp, the community mapping (v3 placeholder / RW-also-reads / RO),
and the trap destination port substitution."""
import ctypes as C
import random

import pytest

from conftest import CFLAGS, COMPONENTS, ROOT, cc

pytest.importorskip('pysnmp')
from pyasn1.codec.ber import encoder  # noqa: E402
from pysnmp.proto import api  # noqa: E402

HOST = ROOT / 'tests' / 'snmp_host'
GET_RESP, GET, SET, TRAP2, INFORM = 0xA2, 0xA0, 0xA3, 0xA7, 0xA6
COMM_V3, COMM_RW, COMM_RO = 0, 1, 2


@pytest.fixture(scope='module')
def lib(tmp_path_factory):
    so = tmp_path_factory.mktemp('snmp_tr') / 'libtr.so'
    cc([*CFLAGS, '-fPIC', '-shared', f'-I{HOST / "include"}', f'-I{COMPONENTS / "snmp_lwip"}',
        f'-I{COMPONENTS / "snmp_lwip" / "include"}', f'-I{COMPONENTS / "gw_core" / "include"}',
        str(HOST / 'transport_util_driver.c'), '-o', str(so)])
    l = C.CDLL(str(so))
    l.tr_peek.argtypes = [C.c_char_p, C.c_size_t, C.POINTER(C.c_int), C.c_char_p]
    l.tr_pick.argtypes = [C.c_int, C.c_char_p, C.c_char_p]
    return l


def peek(lib, data):
    tag = C.c_int(99)
    comm = C.create_string_buffer(b'\xee' * (lib.tr_community_sz() - 1), lib.tr_community_sz())
    v = lib.tr_peek(data, len(data), C.byref(tag), comm)
    return v, tag.value, comm.value.decode('latin-1')


def message(ver, community, pdu_kind):
    """BER of a v1/v2c message built by pysnmp (independent encoder)."""
    p = api.PROTOCOL_MODULES[ver]
    pdu = {'get': p.GetRequestPDU, 'set': p.SetRequestPDU, 'resp': p.GetResponsePDU}[pdu_kind]()
    p.apiPDU.set_defaults(pdu)
    p.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), p.Null(''))])
    msg = p.Message()
    p.apiMessage.set_defaults(msg)
    p.apiMessage.set_community(msg, community)
    p.apiMessage.set_pdu(msg, pdu)
    return encoder.encode(msg)


@pytest.mark.parametrize('ver', [0, 1])
@pytest.mark.parametrize('kind,tag', [('get', GET), ('set', SET), ('resp', GET_RESP)])
def test_peek_v1_v2c(lib, ver, kind, tag):
    assert peek(lib, message(ver, 'pub-ro-123', kind)) == (ver, tag, 'pub-ro-123')


def test_peek_community_lengths(lib):
    assert peek(lib, message(1, 'x' * 32, 'get')) == (1, GET, 'x' * 32), 'longest community lwIP accepts'
    assert peek(lib, message(1, 'x' * 33, 'get')) == (1, GET, ''), 'too long: not copied'
    assert peek(lib, message(1, '', 'get')) == (1, GET, '')


def test_peek_long_form_outer_length(lib):
    data = message(1, 'c', 'get')
    body = data[2:]
    for lf in (bytes([0x81, len(body)]), bytes([0x82, 0, len(body)])):
        assert peek(lib, b'\x30' + lf + body) == (1, GET, 'c')
    assert peek(lib, b'\x30\x83\x00\x00' + bytes([len(body)]) + body)[0] == -1, '> 2 length octets'


def test_peek_v3_has_no_community(lib):
    # SNMPv3: SEQUENCE { INTEGER 3, SEQUENCE msgGlobalData ... } -> version only
    data = bytes.fromhex('303e020103') + bytes.fromhex('3011020400000001020300ffe30401040201030410') + b'\x00' * 40
    v, tag, comm = peek(lib, data)
    assert (v, tag, comm) == (3, -1, '')


@pytest.mark.parametrize('data', [b'', b'\x30', b'\x30\x03\x02\x01', b'\x31\x05\x02\x01\x01\x04\x00',
                                  b'\x30\x05\x02\x02\x00\x01\x04', b'\x30\x80\x02\x01\x01'])
def test_peek_rejects_garbage(lib, data):
    assert peek(lib, data)[0] == -1


def test_peek_never_reads_past_the_buffer(lib):
    """Every truncation of real messages (header limited to what was received)."""
    rnd = random.Random(7)
    for ver, kind in ((0, 'get'), (1, 'resp'), (1, 'set')):
        data = message(ver, 'community-' + str(rnd.randint(0, 999)), kind)
        for n in range(len(data)):
            buf = C.create_string_buffer(data[:n], n)  # exact-size allocation (ASan-friendly)
            tag = C.c_int()
            comm = C.create_string_buffer(lib.tr_community_sz())
            v = lib.tr_peek(buf, n, C.byref(tag), comm)
            assert v in (-1, ver)
            if tag.value != -1:
                assert tag.value == {'get': GET, 'resp': GET_RESP, 'set': SET}[kind]


def test_community_mapping(lib):
    assert lib.tr_pick(3, b'', b'rw') == COMM_V3
    assert lib.tr_pick(3, b'rw', b'rw') == COMM_V3
    assert lib.tr_pick(1, b'rw-secret', b'rw-secret') == COMM_RW, 'the RW community also reads'
    assert lib.tr_pick(0, b'rw-secret', b'rw-secret') == COMM_RW
    assert lib.tr_pick(1, b'ro', b'rw-secret') == COMM_RO
    assert lib.tr_pick(1, b'', b'') == COMM_RO, 'an empty RW community never matches'
    assert lib.tr_pick(1, b'RW-SECRET', b'rw-secret') == COMM_RO, 'case-sensitive'
    assert lib.tr_pick(1, b'rw-secret', None) == COMM_RO


def test_trap_destination_port(lib):
    assert lib.tr_dest_port(0, 162, 1162) == 1162, 'trap/inform to a non-standard target port'
    assert lib.tr_dest_port(0, 162, 0) == 162
    assert lib.tr_dest_port(1, 162, 1162) == 162, 'responses inside snmp_receive keep the requester port'
    assert lib.tr_dest_port(0, 40000, 1162) == 40000
