"""mex150 regmap.c: C tables == regmap.def (Python parse), lookups, wire<->raw conversion (signed rows
incl. negative 40036 temperatures), disabled sentinels, write-request checks, value<->raw, formatting,
enum labels, bit extraction and reason/group names."""
import ctypes as C
import math

import pytest

from test_contracts import GROUPS, REGMAP, parse_def

MEX_DIS_NONE = -2**31
F_STOPPED, F_SNMP_RW, F_RUNBIT, F_BITS = 1, 2, 4, 8
R_OK, R_UNKNOWN, R_READONLY, R_RANGE, R_INTERLOCK, R_OFFLINE, R_BUSY, R_NO_ACK, R_VERIFY, R_CANCELLED = range(10)


class Reg(C.Structure):
    _fields_ = [('key', C.c_char_p), ('addr', C.c_uint16), ('scale', C.c_uint16), ('is_signed', C.c_bool),
                ('writable', C.c_bool), ('min', C.c_int32), ('max', C.c_int32), ('disabled', C.c_int32),
                ('flags', C.c_uint32), ('group', C.c_int), ('unit', C.c_char_p), ('ko', C.c_char_p),
                ('en', C.c_char_p)]


class Bit(C.Structure):
    _fields_ = [('key', C.c_char_p), ('addr', C.c_uint16), ('lsb', C.c_uint8), ('width', C.c_uint8),
                ('unit', C.c_char_p), ('ko', C.c_char_p), ('en', C.c_char_p)]


class Coil(C.Structure):
    _fields_ = [('key', C.c_char_p), ('n', C.c_uint8), ('group', C.c_int), ('ko', C.c_char_p), ('en', C.c_char_p)]


class Enum(C.Structure):
    _fields_ = [('reg', C.c_int), ('value', C.c_int32), ('ko', C.c_char_p), ('en', C.c_char_p)]


@pytest.fixture(scope='module')
def rm():
    return parse_def(REGMAP)


@pytest.fixture(scope='module')
def lib(host_lib, rm):
    l = host_lib('MEX150')
    RP = C.POINTER(Reg)
    l.mex_reg_find.argtypes = [C.c_uint16]
    l.mex_reg_find.restype = RP
    l.mex_reg_find_key.argtypes = [C.c_char_p]
    l.mex_reg_find_key.restype = RP
    l.mex_coil_find.argtypes = [C.c_uint8]
    l.mex_coil_find.restype = C.POINTER(Coil)
    l.mex_reg_decode.argtypes = [RP, C.c_uint16]
    l.mex_reg_decode.restype = C.c_int32
    l.mex_reg_encode.argtypes = [RP, C.c_int32]
    l.mex_reg_encode.restype = C.c_uint16
    l.mex_reg_write_matches.argtypes = [RP, C.c_int32, C.c_int32]
    l.mex_reg_write_matches.restype = C.c_bool
    l.mex_bit_get.argtypes = [C.POINTER(Bit), C.c_uint16]
    l.mex_bit_get.restype = C.c_uint32
    l.mex_reg_is_disabled.argtypes = [RP, C.c_int32]
    l.mex_reg_is_disabled.restype = C.c_bool
    l.mex_reg_check_value.argtypes = [RP, C.c_int32]
    l.mex_reg_check_value.restype = C.c_int
    l.mex_reg_from_value.argtypes = [RP, C.c_double, C.POINTER(C.c_int32)]
    l.mex_reg_from_value.restype = C.c_bool
    l.mex_reg_format.argtypes = [RP, C.c_int32, C.c_char_p, C.c_size_t]
    l.mex_reg_format.restype = C.c_int
    l.mex_group_name.argtypes = [C.c_int]
    l.mex_group_name.restype = C.c_char_p
    l.mex_reason_name.argtypes = [C.c_int, C.c_char_p, C.c_size_t]
    l.mex_reason_name.restype = C.c_char_p
    l.regs = (Reg * len(rm['REG'])).in_dll(l, 'mex_regs')
    l.bits = (Bit * (len(rm['REGBIT']) + len(rm['FIELD']))).in_dll(l, 'mex_bits')
    l.coils = (Coil * len(rm['COIL'])).in_dll(l, 'mex_coils')
    l.enums = (Enum * len(rm['ENUM'])).in_dll(l, 'mex_enums')
    return l


def find(lib, addr):
    p = lib.mex_reg_find(addr)
    return p if p else None


def s(b):
    return b.decode('utf-8')


# ---------------------------------------------------------------- tables


def test_reg_table_matches_def(lib, rm):
    flag_bits = {'STOPPED': F_STOPPED, 'SNMP_RW': F_SNMP_RW, 'RUNBIT': F_RUNBIT, 'BITS': F_BITS}
    for c, r in zip(lib.regs, rm['REG']):
        fl = 0 if r['flags'] == '0' else sum(flag_bits[f] for f in r['flags'].split('|'))
        assert (s(c.key), c.addr, c.scale, c.is_signed, c.writable, c.min, c.max) == (
            r['key'], r['addr'], r['scale'], r['sign'] == 'S', r['access'] == 'RW', r['min'], r['max'])
        assert c.disabled == (MEX_DIS_NONE if r['disabled'] == 'NONE' else r['disabled'])
        assert c.flags == fl and c.group == GROUPS.index(r['group'])
        assert (s(c.unit), s(c.ko), s(c.en)) == (r['unit'], r['ko'], r['en'])


def test_bit_coil_enum_tables_match_def(lib, rm):
    rows = rm['REGBIT'] + rm['FIELD']  # C order: REGBIT and FIELD rows interleave in file order
    by_key = {r['key']: r for r in rows}
    assert len(lib.bits) == len(rows)
    for b in lib.bits:
        r = by_key[s(b.key)]
        lsb, width = (r['bit'], 1) if 'bit' in r else (r['lsb'], r['width'])
        assert (b.addr, b.lsb, b.width, s(b.ko), s(b.en)) == (r['addr'], lsb, width, r['ko'], r['en'])
        assert s(b.unit) == r.get('unit', '')
    for c, r in zip(lib.coils, rm['COIL']):
        assert (s(c.key), c.n, c.group, s(c.ko), s(c.en)) == (r['key'], r['n'], GROUPS.index(r['group']),
                                                              r['ko'], r['en'])
    keys = [r['key'] for r in rm['REG']]
    for e, r in zip(lib.enums, rm['ENUM']):
        assert (keys[e.reg], e.value, s(e.ko), s(e.en)) == (r['regkey'], r['value'], r['ko'], r['en'])


def test_enum_labels_run_and_options(lib):
    keys = [s(r.key) for r in lib.regs]
    labels = {(keys[e.reg], e.value): (s(e.ko), s(e.en)) for e in lib.enums}
    assert labels[('run', 0)] == ('정지', 'Stop') and labels[('run', 1)] == ('운전', 'Run')
    assert labels[('no_hum_cool', 1)] == ('금지', 'Prohibited')
    assert labels[('no_dehum_heat', 0)] == ('사용', 'Allowed')


# ---------------------------------------------------------------- lookups


def test_find_every_address(lib, rm):
    present = {r['addr']: r['key'] for r in rm['REG']}
    for addr in list(range(39990, 40070)) + [0, 1, 65535]:
        p = find(lib, addr)
        if addr in present:
            assert p and p.contents.addr == addr and s(p.contents.key) == present[addr]
        else:
            assert p is None, addr


def test_find_key(lib, rm):
    for r in rm['REG']:
        p = lib.mex_reg_find_key(r['key'].encode())
        assert p and p.contents.addr == r['addr']
    for bad in [b'', b'TEMP', b'temp ', b'nope', b'in1', b'run_blower']:
        assert not lib.mex_reg_find_key(bad)
    assert not lib.mex_reg_find_key(None)


def test_coil_find(lib, rm):
    for n in range(1, 33):
        p = lib.mex_coil_find(n)
        assert p and p.contents.n == n and s(p.contents.key) == rm['COIL'][n - 1]['key']
    for n in (0, 33, 255):
        assert not lib.mex_coil_find(n)
    assert lib.mex_coil_find(23).contents.key == b'alm_leak'


# ---------------------------------------------------------------- conversion


@pytest.mark.parametrize('wire,raw', [(0x0000, 0), (0x00EB, 235), (0xFFFF, -1), (0xFFFB, -5), (0xFF06, -250),
                                      (0x8000, -32768), (0x7FFF, 32767), (0x0352, 850)])
def test_signed_decode_40036(lib, wire, raw):
    """Current temperature is signed: -25.0 degC arrives as 0xFF06."""
    assert lib.mex_reg_decode(find(lib, 40036), wire) == raw


def test_decode_signed_rows_only(lib, rm):
    for r in rm['REG']:
        got = lib.mex_reg_decode(find(lib, r['addr']), 0xFF9C)
        assert got == (-100 if r['sign'] == 'S' else 0xFF9C), r['key']
    # 40005 and bitfields keep the full word (one raw convention)
    assert lib.mex_reg_decode(find(lib, 40005), 0x0A01) == 2561
    assert lib.mex_reg_decode(find(lib, 40003), 0x8040) == 0x8040
    assert lib.mex_reg_decode(None, 0xFFFF) == 0xFFFF


def test_encode(lib):
    assert lib.mex_reg_encode(find(lib, 40021), -15) == 0xFFF1
    assert lib.mex_reg_encode(find(lib, 40022), -300) == 0xFED4
    assert lib.mex_reg_encode(find(lib, 40012), 235) == 235
    assert lib.mex_reg_encode(find(lib, 40059), 20000) == 20000
    assert lib.mex_reg_encode(find(lib, 40005), 1) == 1
    assert lib.mex_reg_encode(find(lib, 40005), 0) == 0
    assert lib.mex_reg_encode(find(lib, 40005), 7) == 1  # RUNBIT sends 0/1 only
    for raw in range(-300, 301, 7):  # round trip through the wire for signed rows
        r = find(lib, 40022)
        assert lib.mex_reg_decode(r, lib.mex_reg_encode(r, raw)) == raw


def test_write_matches(lib):
    run = find(lib, 40005)
    assert lib.mex_reg_write_matches(run, 1, 0x0A01)       # run bit + 10 s delay byte
    assert lib.mex_reg_write_matches(run, 1, 0x0001)
    assert not lib.mex_reg_write_matches(run, 1, 0x0A00)   # delay only: not running
    assert lib.mex_reg_write_matches(run, 0, 0x0500)
    assert not lib.mex_reg_write_matches(run, 0, 0x0001)
    t = find(lib, 40012)
    assert lib.mex_reg_write_matches(t, 235, 235) and not lib.mex_reg_write_matches(t, 235, 234)
    o = find(lib, 40021)
    assert lib.mex_reg_write_matches(o, -15, -15) and not lib.mex_reg_write_matches(o, -15, 0xFFF1)
    assert not lib.mex_reg_write_matches(None, 0, 0)


def test_bit_get(lib):
    bits = {s(b.key): b for b in lib.bits}
    assert lib.mex_bit_get(bits['ad1_leak'], 0x0040) == 1
    assert lib.mex_bit_get(bits['ad1_leak'], 0xFFBF) == 0
    assert lib.mex_bit_get(bits['in8'], 0x8000) == 1 and lib.mex_bit_get(bits['in9'], 0x0001) == 1
    assert lib.mex_bit_get(bits['run_delay_left'], 0x0A01) == 10
    assert lib.mex_bit_get(bits['run_on'], 0x0A01) == 1
    assert lib.mex_bit_get(bits['cp_cool1'], 0x0100) == 1
    for b in lib.bits:
        assert lib.mex_bit_get(b, 0xFFFF) == (1 << b.width) - 1
        assert lib.mex_bit_get(b, 0) == 0
        assert lib.mex_bit_get(b, 1 << b.lsb) == 1


# ---------------------------------------------------------------- sentinels / checks


@pytest.mark.parametrize('addr,sentinel', [(40027, 249), (40028, 49), (40029, 599), (40030, 99)])
def test_disabled_sentinels(lib, addr, sentinel):
    r = find(lib, addr)
    assert lib.mex_reg_is_disabled(r, sentinel)
    assert not lib.mex_reg_is_disabled(r, sentinel + 1)
    assert lib.mex_reg_check_value(r, sentinel) == R_OK
    assert lib.mex_reg_check_value(r, sentinel - 1) == R_RANGE
    assert lib.mex_reg_check_value(r, r.contents.min) == R_OK
    assert lib.mex_reg_check_value(r, r.contents.max) == R_OK
    assert lib.mex_reg_check_value(r, r.contents.max + 1) == R_RANGE


def test_no_sentinel_rows_never_disabled(lib, rm):
    for r in rm['REG']:
        if r['disabled'] == 'NONE':
            p = find(lib, r['addr'])
            for v in (MEX_DIS_NONE, -1, 0, 249, 49):
                assert not lib.mex_reg_is_disabled(p, v)
    assert not lib.mex_reg_is_disabled(None, 0)


def test_check_value_all_rows(lib, rm):
    for r in rm['REG']:
        p = find(lib, r['addr'])
        if r['access'] == 'RO':
            for v in (r['min'], r['max'], 0):
                assert lib.mex_reg_check_value(p, v) == R_READONLY
            continue
        for v in range(r['min'] - 3, r['max'] + 4):
            ok = r['min'] <= v <= r['max'] or v == r['disabled']
            assert lib.mex_reg_check_value(p, v) == (R_OK if ok else R_RANGE), (r['key'], v)
    run = find(lib, 40005)
    assert lib.mex_reg_check_value(run, 2561) == R_RANGE  # a read 40005 word is not a write request
    assert lib.mex_reg_check_value(None, 0) == R_UNKNOWN


# ---------------------------------------------------------------- value <-> raw / format


@pytest.mark.parametrize('addr,value,raw', [
    (40012, 23.5, 235), (40012, 5.0, 50), (40021, -1.5, -15), (40021, -0.5, -5), (40022, 30.0, 300),
    (40018, 180, 180), (40059, 20000, 20000), (40005, 1, 1), (40012, 0.1, 1), (40013, 79.9, 799),
    (40012, 23.500000001, 235),
])
def test_from_value_ok(lib, addr, value, raw):
    out = C.c_int32()
    assert lib.mex_reg_from_value(find(lib, addr), value, C.byref(out))
    assert out.value == raw


@pytest.mark.parametrize('addr,value', [
    (40012, 23.45), (40018, 1.5), (40012, math.nan), (40012, math.inf), (40012, -math.inf),
    (40012, 3e9), (40021, -3e8), (40059, 0.5),
])
def test_from_value_rejects(lib, addr, value):
    out = C.c_int32(1234)
    assert not lib.mex_reg_from_value(find(lib, addr), value, C.byref(out))
    assert out.value == 1234


def test_from_value_range_not_checked(lib):
    out = C.c_int32()
    assert lib.mex_reg_from_value(find(lib, 40012), 99.9, C.byref(out)) and out.value == 999
    assert not lib.mex_reg_from_value(None, 1.0, C.byref(out))


@pytest.mark.parametrize('addr,raw,text', [
    (40036, 235, '23.5'), (40036, -5, '-0.5'), (40036, -250, '-25.0'), (40036, 0, '0.0'), (40036, 850, '85.0'),
    (40018, 180, '180'), (40059, 20000, '20000'), (40021, -100, '-10.0'), (40005, 2561, '2561'),
    (40036, -2**31, '-214748364.8'),
])
def test_format(lib, addr, raw, text):
    buf = C.create_string_buffer(32)
    assert lib.mex_reg_format(find(lib, addr), raw, buf, 32) == len(text)
    assert buf.value.decode() == text


def test_format_small_buffer(lib):
    buf = C.create_string_buffer(8)
    assert lib.mex_reg_format(find(lib, 40036), -250, buf, 5) == -1  # "-25.0" needs 6 bytes
    assert lib.mex_reg_format(find(lib, 40036), -250, buf, 6) == 5
    assert lib.mex_reg_format(find(lib, 40036), 1, None, 6) == -1
    assert lib.mex_reg_format(None, 1, buf, 6) == -1


# ---------------------------------------------------------------- names


def test_group_names(lib):
    for i, g in enumerate(GROUPS):
        assert lib.mex_group_name(i).decode() == g
    assert lib.mex_group_name(99) == b'unknown' and lib.mex_group_name(-1) == b'unknown'


@pytest.mark.parametrize('reason,name', [
    (R_OK, 'ok'), (R_UNKNOWN, 'unknown_register'), (R_READONLY, 'readonly'), (R_RANGE, 'range'),
    (R_INTERLOCK, 'running_interlock'), (R_OFFLINE, 'offline'), (R_BUSY, 'busy'), (R_NO_ACK, 'no_ack'),
    (R_VERIFY, 'verify_mismatch'), (R_CANCELLED, 'cancelled'), (0x100 + 2, 'exception:2'),
    (0x100 + 255, 'exception:255'), (0x100, 'internal'), (-1, 'internal'), (77, 'internal'),
])
def test_reason_names(lib, reason, name):
    buf = C.create_string_buffer(32)
    assert lib.mex_reason_name(reason, buf, 32).decode() == name
    assert buf.value.decode() == name
    # with the documented 16-byte buffer the return value is always the full name
    small = C.create_string_buffer(16)
    assert lib.mex_reason_name(reason, small, 16).decode() == name
    assert lib.mex_reason_name(reason, None, 0).decode() in (name, 'exception')
