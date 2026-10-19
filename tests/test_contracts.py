"""Frozen-interface checks: public headers compile on the host, and the two X-macro tables
(regmap.def, alarm_catalog.def) are internally consistent and agree with DESIGN.md §8/§9."""
import re

import pytest

from conftest import COMPONENTS, IDF_HEADERS, INCLUDE_FLAGS, ROOT, cc, compile_and_run, public_headers

REGMAP = COMPONENTS / 'mex150' / 'regmap.def'
CATALOG = COMPONENTS / 'alarm' / 'alarm_catalog.def'
PURE_HEADERS = [h for h in public_headers() if h not in IDF_HEADERS]
STRICT = ['-std=c11', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-fsyntax-only']

ROW_COLUMNS = {
    'REG': ['key', 'addr', 'scale', 'sign', 'access', 'min', 'max', 'disabled', 'flags', 'group', 'unit', 'ko', 'en'],
    'REGBIT': ['key', 'addr', 'bit', 'ko', 'en'],
    'FIELD': ['key', 'addr', 'lsb', 'width', 'unit', 'ko', 'en'],
    'COIL': ['key', 'n', 'group', 'ko', 'en'],
    'ENUM': ['regkey', 'value', 'ko', 'en'],
    'ALM': ['id', 'code', 'kind', 'addr', 'bit', 'sev', 'vreg', 'ko', 'en'],
}
INT_COLUMNS = {'addr', 'scale', 'min', 'max', 'bit', 'lsb', 'width', 'n', 'value', 'code', 'vreg'}
GROUPS = ['status', 'control', 'setpoint', 'deviation', 'delay', 'calibration', 'limits', 'options', 'info', 'alarm']
HANGUL = re.compile('[가-힣]')


def parse_def(path):
    """Rows of a .def table as dicts, by row macro. One row per line (documented format)."""
    rows = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        m = re.match(r'^([A-Z]+)\((.*)\)\s*$', line)
        if not m:
            assert not re.match(r'^\s*[A-Z]+\(', line), f'row not on one line: {line!r}'
            continue
        kind, body = m.groups()
        args = [a.strip() for a in re.findall(r'"[^"]*"|[^,]+', body)]
        cols = ROW_COLUMNS[kind]
        assert len(args) == len(cols), f'{kind} row has {len(args)} columns: {line!r}'
        row = {}
        for c, a in zip(cols, args):
            if a.startswith('"'):
                row[c] = a[1:-1]
            elif c in INT_COLUMNS or (c == 'disabled' and a != 'NONE'):
                row[c] = int(a)
            else:
                row[c] = a
        rows.setdefault(kind, []).append(row)
    return rows


@pytest.fixture(scope='module')
def regmap():
    return parse_def(REGMAP)


@pytest.fixture(scope='module')
def regs(regmap):
    return {r['addr']: r for r in regmap['REG']}


def flags(r):
    return set() if r['flags'] == '0' else set(r['flags'].split('|'))


# ---------------------------------------------------------------- headers


@pytest.mark.parametrize('header', PURE_HEADERS)
def test_pure_header_compiles_alone_and_twice(tmp_path, header):
    src = tmp_path / 't.c'
    src.write_text(f'#include "{header}"\n#include "{header}"\nint gw_hdr_check_dummy;\n')
    cc([*STRICT, *INCLUDE_FLAGS, str(src)])


def test_all_pure_headers_together_c_and_cxx(tmp_path):
    body = ''.join(f'#include "{h}"\n' for h in PURE_HEADERS) + 'int main(void) { return 0; }\n'
    (tmp_path / 'all.c').write_text(body)
    (tmp_path / 'all.cpp').write_text(body)
    cc([*STRICT, *INCLUDE_FLAGS, str(tmp_path / 'all.c')])
    cc(['-x', 'c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', *INCLUDE_FLAGS,
        str(tmp_path / 'all.cpp')])


def test_pure_headers_include_no_idf_headers():
    std = re.compile(r'^(assert|stdarg|stdbool|stddef|stdint|string)\.h$')
    for h in PURE_HEADERS:
        path = next(inc / h for inc in COMPONENTS.glob('*/include') if (inc / h).is_file())
        text = path.read_text()
        if h == 'gw_core/gw_err.h':
            continue  # includes esp_err.h only under ESP_PLATFORM, by design
        for inc in re.findall(r'#\s*include\s*[<"]([^>"]+)[>"]', text):
            ok = std.match(inc) or inc in public_headers() or inc.startswith('../../')
            assert ok, f'{h} includes non-pure header {inc}'


def test_contract_check_includes_every_public_header():
    text = (ROOT / 'main' / 'contract_check.c').read_text()
    included = set(re.findall(r'#include "([^"]+)"', text))
    expanders = {'mex150/regmap_x.h', 'alarm/alarm_x.h'}  # pulled in by regmap.h / alarm.h
    missing = set(public_headers()) - included - expanders
    assert not missing, f'add to main/contract_check.c: {sorted(missing)}'


def test_x_macro_tokens_do_not_leak(tmp_path):
    src = '#include "mex150/model.h"\n#include "alarm/alarm.h"\n'
    for tok in ['REG', 'REGBIT', 'FIELD', 'COIL', 'ENUM', 'ALM', 'U', 'S', 'RO', 'RW', 'NONE', 'STOPPED',
                'SNMP_RW', 'RUNBIT', 'BITS', *GROUPS, 'SRC_COIL', 'SRC_BIT', 'SRC_COMM', 'SRC_RULE', 'INFO',
                'MINOR', 'MAJOR', 'CRITICAL']:
        src += f'#ifdef {tok}\n#error "{tok} leaked"\n#endif\n'
    # A foreign BIT(nr) macro (IDF esp_bit_defs.h) must survive the expansion untouched.
    src = '#define BIT(nr) (1UL << (nr))\n' + src + '_Static_assert(BIT(3) == 8, "BIT clobbered");\n'
    (tmp_path / 't.c').write_text(src + 'int x;\n')
    cc([*STRICT, *INCLUDE_FLAGS, str(tmp_path / 't.c')])


# ---------------------------------------------------------------- regmap.def (Python view)


def test_regmap_row_counts(regmap):
    """Only the coil count is fixed by the protocol; other counts are whatever regmap.def holds (the C
    expansion is compared with this parse below), so editing the map needs no test edits."""
    assert len(regmap['COIL']) == 32
    assert regmap['REG'] and regmap['REGBIT'] and regmap['FIELD'] and regmap['ENUM']


def test_regmap_columns_well_formed(regmap):
    keys = [r['key'] for k in ('REG', 'REGBIT', 'FIELD', 'COIL') for r in regmap[k]]
    assert len(keys) == len(set(keys)), 'keys must be unique across all row kinds'
    addrs = [r['addr'] for r in regmap['REG']]
    assert len(addrs) == len(set(addrs))
    for r in regmap['REG']:
        assert re.fullmatch(r'[a-z][a-z0-9_]*', r['key'])
        assert 40001 <= r['addr'] <= 40059, r
        assert r['scale'] in (1, 10), r
        assert r['sign'] in ('U', 'S') and r['access'] in ('RO', 'RW'), r
        assert r['min'] <= r['max'], r
        lo, hi = (-32768, 32767) if r['sign'] == 'S' else (0, 65535)
        assert lo <= r['min'] and r['max'] <= hi, r
        assert flags(r) <= {'STOPPED', 'SNMP_RW', 'RUNBIT', 'BITS'}, r
        assert r['group'] in GROUPS and r['group'] != 'alarm', r
        if r['disabled'] != 'NONE':
            assert r['access'] == 'RW' and not r['min'] <= r['disabled'] <= r['max'], r
        if r['access'] == 'RO':
            assert not flags(r) & {'STOPPED', 'SNMP_RW', 'RUNBIT'}, r


def test_signed_rows_exactly(regmap):
    assert {r['addr'] for r in regmap['REG'] if r['sign'] == 'S'} == {40021, 40022, 40036}


def test_stopped_rows_exactly(regmap):
    """Monitor interlock: 40021, 40022 and every writable address >= 40027 only while stopped."""
    stopped = {r['addr'] for r in regmap['REG'] if 'STOPPED' in flags(r)}
    expected = {40021, 40022} | {r['addr'] for r in regmap['REG'] if r['access'] == 'RW' and r['addr'] >= 40027}
    assert stopped == expected
    assert {40027, 40028, 40029, 40030, 40053, 40054, 40059} <= stopped


def test_runbit_and_bits(regmap, regs):
    assert [r['addr'] for r in regmap['REG'] if 'RUNBIT' in flags(r)] == [40005]
    assert {r['addr'] for r in regmap['REG'] if 'BITS' in flags(r)} == {40002, 40003, 40004, 40006, 40007, 40008}
    used = {}
    for r in regmap['REGBIT'] + regmap['FIELD']:
        reg = regs.get(r['addr'])
        assert reg and flags(reg) & {'BITS', 'RUNBIT'}, f'{r["key"]}: parent must be a BITS/RUNBIT REG row'
        lsb, width = (r['bit'], 1) if 'bit' in r else (r['lsb'], r['width'])
        assert 0 <= lsb and lsb + width <= 16, r
        for b in range(lsb, lsb + width):
            assert (r['addr'], b) not in used, f'{r["key"]} overlaps {used.get((r["addr"], b))}'
            used[(r['addr'], b)] = r['key']
    for addr in (40002, 40003, 40004, 40006, 40007, 40008):
        assert any(a == addr for a, _ in used), f'BITS register {addr} has no REGBIT rows'


@pytest.mark.parametrize('addr,lo,hi,dis', [
    (40005, 0, 1, 'NONE'), (40011, 0, 999, 'NONE'), (40012, 50, 500, 'NONE'), (40013, 200, 800, 'NONE'),
    (40014, 1, 100, 'NONE'), (40015, 1, 100, 'NONE'), (40016, 10, 100, 'NONE'), (40017, 10, 100, 'NONE'),
    (40018, 1, 180, 'NONE'), (40019, 1, 180, 'NONE'), (40020, 1, 99, 'NONE'), (40021, -100, 100, 'NONE'),
    (40022, -300, 300, 'NONE'), (40027, 250, 500, 249), (40028, 50, 200, 49), (40029, 600, 900, 599),
    (40030, 100, 400, 99), (40036, -250, 850, 'NONE'), (40037, 0, 990, 'NONE'), (40053, 0, 1, 'NONE'),
    (40054, 0, 1, 'NONE'), (40059, 1000, 20000, 'NONE'),
])
def test_regmap_ranges_match_design(regs, addr, lo, hi, dis):
    """DESIGN.md §9 / monitor mex_validate ranges (raw units)."""
    r = regs[addr]
    assert (r['min'], r['max'], r['disabled']) == (lo, hi, dis)


def test_writable_set_matches_design(regs):
    rw = {a for a, r in regs.items() if r['access'] == 'RW'}
    assert rw == {40005, *range(40012, 40020), 40021, 40022, 40027, 40028, 40029, 40030, 40053, 40054, 40059}


def test_coils_complete(regmap):
    ns = [c['n'] for c in regmap['COIL']]
    assert sorted(ns) == list(range(1, 33)) and ns == sorted(ns)
    for c in regmap['COIL']:
        assert c['group'] == ('status' if c['n'] <= 16 else 'alarm'), c


def test_enums_reference_registers(regmap, regs):
    by_key = {r['key']: r for r in regs.values()}
    seen = set()
    for e in regmap['ENUM']:
        r = by_key[e['regkey']]
        assert r['min'] <= e['value'] <= r['max'], e
        assert (e['regkey'], e['value']) not in seen
        seen.add((e['regkey'], e['value']))


def test_names_present(regmap):
    for kind, rows in regmap.items():
        for r in rows:
            assert r['ko'].strip() and r['en'].strip(), f'{kind} {r}'
            assert '"' not in r['ko'] + r['en']
            if kind in ('REG', 'COIL', 'ENUM'):
                assert HANGUL.search(r['ko']), f'{kind} {r} Korean name has no Hangul'


# ---------------------------------------------------------------- alarm_catalog.def


def test_alarm_catalog(regmap, regs):
    rows = parse_def(CATALOG)['ALM']
    assert len(rows) <= 32  # alarm masks are uint32_t
    assert len({r['id'] for r in rows}) == len(rows) and len({r['code'] for r in rows}) == len(rows)
    coils = {c['n']: c for c in regmap['COIL']}
    bits = {(b['addr'], b['bit']) for b in regmap['REGBIT']}
    for r in rows:
        assert r['sev'] in ('INFO', 'MINOR', 'MAJOR', 'CRITICAL'), r
        assert r['vreg'] == 0 or r['vreg'] in regs, r
        assert r['ko'].strip() and r['en'].strip() and HANGUL.search(r['ko']), r
        if r['kind'] == 'SRC_COIL':
            assert 17 <= r['addr'] <= 31 and coils[r['addr']]['group'] == 'alarm', r
            assert r['code'] == 100 + r['addr'], r
        elif r['kind'] == 'SRC_BIT':
            assert (r['addr'], r['bit']) in bits and 200 <= r['code'] < 300, r
        elif r['kind'] == 'SRC_COMM':
            assert 300 <= r['code'] < 400, r
        else:
            assert r['kind'] == 'SRC_RULE' and 1 <= r['addr'] <= 8, r
            assert r['code'] == 400 + r['addr'] and r['id'] == f'rule_{r["addr"]}', r
    assert sorted(r['addr'] for r in rows if r['kind'] == 'SRC_COIL') == list(range(17, 32))
    assert sorted(r['addr'] for r in rows if r['kind'] == 'SRC_RULE') == list(range(1, 9))  # GW_MAX_RULES
    sev = {r['id']: r['sev'] for r in rows}
    assert sev['leak'] == sev['fire'] == 'CRITICAL'
    assert {r['id'] for r in rows if r['kind'] == 'SRC_COMM'} == {'comm_lost'}


# ---------------------------------------------------------------- C view == Python view


def test_c_expansion_matches_python_parse(tmp_path, regmap):
    """The X-macro tokens must expand to the values the Python tools read from the same file."""
    prog = r'''
#include <stdio.h>
#include "mex150/regmap.h"
#include "alarm/alarm.h"
int main(void) {
#define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en) \
    printf("REG %s %d %d %d %d %ld %ld %ld %lu %d %s|%s|%s\n", #key, addr, scale, (int)(sign), (int)(access), \
           (long)(min), (long)(max), (long)(disabled), (unsigned long)(flags), (int)(group), unit, ko, en);
#define REGBIT(key, addr, bit, ko, en) printf("REGBIT %s %d %d %s|%s\n", #key, addr, bit, ko, en);
#define FIELD(key, addr, lsb, width, unit, ko, en) printf("FIELD %s %d %d %d %s|%s|%s\n", #key, addr, lsb, width, unit, ko, en);
#define COIL(key, n, group, ko, en) printf("COIL %s %d %d %s|%s\n", #key, n, (int)(group), ko, en);
#define ENUM(regkey, value, ko, en) printf("ENUM %s %d %s|%s\n", #regkey, value, ko, en);
#include "mex150/regmap_x.h"
#define ALM(id, code, kind, addr, bit, sev, vreg, ko, en) \
    printf("ALM %s %d %d %d %d %d %d %s|%s\n", #id, code, (int)(kind), addr, bit, (int)(sev), vreg, ko, en);
#include "alarm/alarm_x.h"
    printf("COUNTS %d %d %d %d %d\n", MEX_REG_COUNT, MEX_BIT_COUNT, MEX_COIL_COUNT, MEX_ENUM_COUNT, ALM_COUNT);
    return 0;
}
'''
    out = compile_and_run(tmp_path, prog, flags=['-Wno-format'])
    lines = out.splitlines()
    flag_bits = {'STOPPED': 1, 'SNMP_RW': 2, 'RUNBIT': 4, 'BITS': 8}
    exp = []
    for r in regmap['REG']:
        fl = sum(flag_bits[f] for f in flags(r))
        dis = -2**31 if r['disabled'] == 'NONE' else r['disabled']
        exp.append(f"REG {r['key']} {r['addr']} {r['scale']} {int(r['sign'] == 'S')} {int(r['access'] == 'RW')} "
                   f"{r['min']} {r['max']} {dis} {fl} {GROUPS.index(r['group'])} {r['unit']}|{r['ko']}|{r['en']}")
    for r in regmap['REGBIT']:
        exp.append(f"REGBIT {r['key']} {r['addr']} {r['bit']} {r['ko']}|{r['en']}")
    for r in regmap['FIELD']:
        exp.append(f"FIELD {r['key']} {r['addr']} {r['lsb']} {r['width']} {r['unit']}|{r['ko']}|{r['en']}")
    for r in regmap['COIL']:
        exp.append(f"COIL {r['key']} {r['n']} {GROUPS.index(r['group'])} {r['ko']}|{r['en']}")
    for r in regmap['ENUM']:
        exp.append(f"ENUM {r['regkey']} {r['value']} {r['ko']}|{r['en']}")
    kinds = ['SRC_COIL', 'SRC_BIT', 'SRC_COMM', 'SRC_RULE']
    sevs = ['INFO', 'MINOR', 'MAJOR', 'CRITICAL']
    for r in parse_def(CATALOG)['ALM']:
        exp.append(f"ALM {r['id']} {r['code']} {kinds.index(r['kind'])} {r['addr']} {r['bit']} "
                   f"{sevs.index(r['sev'])} {r['vreg']} {r['ko']}|{r['en']}")
    order = ['REG', 'REGBIT', 'FIELD', 'COIL', 'ENUM', 'ALM']
    got = sorted(lines[:-1], key=lambda s: order.index(s.split()[0]))
    exp_sorted = sorted(exp, key=lambda s: order.index(s.split()[0]))
    # Within a kind the C order is the file order, as in Python.
    assert [l for l in got] == exp_sorted
    alm = parse_def(CATALOG)['ALM']
    assert lines[-1] == (f"COUNTS {len(regmap['REG'])} {len(regmap['REGBIT']) + len(regmap['FIELD'])} "
                         f"{len(regmap['COIL'])} {len(regmap['ENUM'])} {len(alm)}")
