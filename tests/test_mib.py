"""tools/gen_mib.py -> MESTIO-GW-MIB: strict SMIv2 compile (pysmi), semantic lint, load into pysnmp, and
cross-checks of every OID against the agent's C tables:
  - components/snmp_gw/mib_oids.h GWMIB_NODES (names and arcs the agent serves / sends),
  - mexSetpointTable columns as the C module derives them from regmap.def (GWMIB_SP_COLUMN),
  - GwAlarmCode enumeration as the C alarm catalog expands alarm_catalog.def,
plus the build contract (deterministic gzip, PEN from argument or sdkconfig)."""
import gzip
import importlib.util
import json
import re

import pytest

from conftest import COMPONENTS, ROOT, compile_and_run

GEN = ROOT / 'tools' / 'gen_mib.py'
BASE_MIBS = ROOT / 'tests' / 'mibs'
OIDS_H = COMPONENTS / 'snmp_gw' / 'mib_oids.h'
GW_DEFS = COMPONENTS / 'gw_core' / 'include' / 'gw_core' / 'gw_defs.h'
MODULE = 'MESTIO-GW-MIB'
PEN = 32473

pysmi = pytest.importorskip('pysmi')
from pysmi.codegen import JsonCodeGen, PySnmpCodeGen  # noqa: E402
from pysmi.compiler import MibCompiler  # noqa: E402
from pysmi.parser.dialect import smi_v2  # noqa: E402
from pysmi.parser.smi import parserFactory  # noqa: E402
from pysmi.reader import FileReader  # noqa: E402
from pysmi.searcher import StubSearcher  # noqa: E402
from pysmi.writer import CallbackWriter, PyFileWriter  # noqa: E402


def load_gen():
    spec = importlib.util.spec_from_file_location('gen_mib', GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen_mib = load_gen()


def generate(tmp_path, pen=PEN, name='MESTIO-GW-MIB.txt'):
    out = tmp_path / name
    assert gen_mib.main(['--pen', str(pen), '--out', str(out)]) == 0
    return out


def compile_json(mib_dir):
    """Strict SMIv2 grammar (no SMIv1 / relaxed dialect options); returns the JsonCodeGen symbol dict."""
    out = {}
    c = MibCompiler(parserFactory(**smi_v2)(), JsonCodeGen(), CallbackWriter(lambda n, d, ctx: out.__setitem__(n, d)))
    c.add_sources(FileReader(str(mib_dir)), FileReader(str(BASE_MIBS)))
    c.add_searchers(StubSearcher(*JsonCodeGen.baseMibs))
    status = c.compile(MODULE, rebuild=True, genTexts=True)
    assert status[MODULE] == 'compiled', f'{status[MODULE]}: {getattr(status[MODULE], "error", "")}'
    return json.loads(out[MODULE])


@pytest.fixture(scope='module')
def mib_text_path(tmp_path_factory):
    return generate(tmp_path_factory.mktemp('mib'))


@pytest.fixture(scope='module')
def mib(mib_text_path):
    return compile_json(mib_text_path.parent)


@pytest.fixture(scope='module')
def text(mib_text_path):
    return mib_text_path.read_text()


def objects(mib, *classes):
    return {k: v for k, v in mib.items() if isinstance(v, dict) and v.get('class') in classes}


def oid_of(mib, name):
    return tuple(int(x) for x in mib[name]['oid'].split('.'))


# ---------------------------------------------------------------- grammar / semantics


def test_mib_is_ascii_and_has_no_trailing_space(text):
    assert text.isascii()
    assert not re.search(r'[ \t]+$', text, re.M)
    assert text.startswith(f'{MODULE} DEFINITIONS ::= BEGIN') and text.rstrip().endswith('END')


def test_module_identity(mib):
    mi = objects(mib, 'moduleidentity')
    assert list(mi) == ['mestioGwMIB']
    assert mi['mestioGwMIB']['oid'] == f'1.3.6.1.4.1.{PEN}.1'
    assert re.fullmatch(r'\d{12}Z', mi['mestioGwMIB']['lastupdated'])


def test_imports_exist_in_base_mibs(text):
    imports = re.search(r'IMPORTS(.*?);', text, re.S).group(1)
    for names, module in re.findall(r'((?:[\w-]+,\s*)*[\w-]+)\s+FROM\s+([\w-]+)', imports):
        base = (BASE_MIBS / f'{module}.txt').read_text()
        for n in re.split(r',\s*', names.strip()):
            assert re.search(rf'^\s*{re.escape(n)}\b', base, re.M), f'{n} is not defined in {module}'


def test_descriptors_are_valid_and_unique(mib):
    names = [k for k, v in mib.items() if isinstance(v, dict) and 'class' in v and k == v.get('name')]
    for n in names:
        assert re.fullmatch(r'[a-zA-Z][A-Za-z0-9]{0,63}', n), n
        assert '-' not in n and '_' not in n
    assert len(names) == len(set(names))


def test_every_reference_resolves(mib):
    """pysmi does not resolve OBJECTS/INDEX/group references; check them here."""
    defined = set(mib)
    for name, v in mib.items():
        if not isinstance(v, dict):
            continue
        refs = [o['object'] for o in v.get('objects', [])] + [o['object'] for o in v.get('modulecompliance', [])]
        refs += [i['object'] for i in v.get('indices', [])]
        for r in refs:
            assert r in defined, f'{name} references undefined {r}'


def test_conformance_covers_every_object_and_notification(mib):
    accessible = {k for k, v in objects(mib, 'objecttype').items()
                  if v.get('maxaccess') in ('read-only', 'read-write', 'accessible-for-notify')}
    in_groups = [o['object'] for g in objects(mib, 'objectgroup').values() for o in g['objects']]
    assert sorted(in_groups) == sorted(set(in_groups)), 'an object is in two groups'
    assert set(in_groups) == accessible
    notifs = set(objects(mib, 'notificationtype'))
    in_ngroups = {o['object'] for g in objects(mib, 'notificationgroup').values() for o in g['objects']}
    assert in_ngroups == notifs
    compliance = objects(mib, 'modulecompliance')
    assert len(compliance) == 1
    mandatory = {o['object'] for o in next(iter(compliance.values()))['modulecompliance']}
    assert mandatory == set(objects(mib, 'objectgroup')) | set(objects(mib, 'notificationgroup'))


def test_tables_are_well_formed(mib):
    for name, v in objects(mib, 'objecttype').items():
        if v.get('nodetype') == 'row':
            idx = [i['object'] for i in v['indices']]
            assert idx, name
            for i in idx:
                assert mib[i].get('maxaccess') in ('not-accessible', 'read-only', 'read-write'), i
        if v.get('nodetype') == 'column' and v.get('maxaccess') == 'not-accessible':
            assert name.endswith(('Index', 'Addr', 'Code', 'Seq')), f'unexpected not-accessible column {name}'


def test_notifications_and_their_objects(mib):
    n = objects(mib, 'notificationtype')
    assert {k: v['oid'] for k, v in n.items()} == {
        'gwAlarmRaised': f'1.3.6.1.4.1.{PEN}.1.0.1', 'gwAlarmCleared': f'1.3.6.1.4.1.{PEN}.1.0.2',
        'gwCommLost': f'1.3.6.1.4.1.{PEN}.1.0.3', 'gwCommRestored': f'1.3.6.1.4.1.{PEN}.1.0.4',
        'gwConfigChanged': f'1.3.6.1.4.1.{PEN}.1.0.5', 'gwFirmwareUpdated': f'1.3.6.1.4.1.{PEN}.1.0.6',
        'gwTestNotification': f'1.3.6.1.4.1.{PEN}.1.0.7'}
    alarm_vbs = ['gwAlarmDevIndex', 'gwAlarmCode', 'gwAlarmName', 'gwAlarmSeverity', 'gwAlarmTime', 'gwAlarmValue',
                 'gwAlarmSeq']  # DESIGN.md §10 varbinds (after sysUpTime/snmpTrapOID)
    assert [o['object'] for o in n['gwAlarmRaised']['objects']] == alarm_vbs
    assert [o['object'] for o in n['gwAlarmCleared']['objects']] == alarm_vbs
    for o in alarm_vbs:
        assert mib[o]['maxaccess'] == 'accessible-for-notify'


def test_textual_conventions(mib):
    tc = objects(mib, 'textualconvention')
    assert tc['GwTenths']['displayhint'] == 'd-1'
    assert tc['GwUtf8String']['displayhint'] == '255t'
    assert tc['GwAlarmSeverity']['type']['constraints']['enumeration'] == {
        'info': 1, 'minor': 2, 'major': 3, 'critical': 4}
    assert tc['GwWriteResult']['type']['constraints']['enumeration'] == {
        'none': 1, 'pending': 2, 'applied': 3, 'rejected': 4, 'uncertain': 5}
    assert mib['mexTemperature']['syntax']['type'] == 'GwTenths'
    assert mib['mexHumidity']['syntax']['type'] == 'GwTenths'
    assert mib['mexCurrent']['syntax']['type'] == 'GwTenths'


def test_dev_index_range_matches_gw_max_devices(mib):
    max_dev = int(re.search(r'#define GW_MAX_DEVICES (\d+)', GW_DEFS.read_text()).group(1))
    assert gen_mib.MAX_DEVICES == max_dev
    assert mib['GwDevIndex']['type']['constraints']['range'] == [{'min': 1, 'max': max_dev}]


@pytest.mark.filterwarnings('ignore::DeprecationWarning')  # generated pysnmp code uses old names
def test_loads_into_pysnmp(tmp_path, mib_text_path):
    """Second, independent consumer: pysmi -> pysnmp code, loaded by pysnmp's MibBuilder."""
    from pysnmp.smi import builder
    out = tmp_path / 'py'
    c = MibCompiler(parserFactory(**smi_v2)(), PySnmpCodeGen(), PyFileWriter(str(out)))
    c.add_sources(FileReader(str(mib_text_path.parent)), FileReader(str(BASE_MIBS)))
    c.add_searchers(StubSearcher(*PySnmpCodeGen.baseMibs))
    assert c.compile(MODULE, rebuild=True)[MODULE] == 'compiled'
    mb = builder.MibBuilder()
    mb.add_mib_sources(builder.DirMibSource(str(out)))
    mb.load_modules(MODULE)
    (sp,) = mb.import_symbols(MODULE, 'mexSpSetTemp')
    assert sp.getName() == (1, 3, 6, 1, 4, 1, PEN, 1, 4, 1, 1, 12)
    assert sp.getMaxAccess() == 'read-write'


# ---------------------------------------------------------------- cross-check with the C agent


def c_nodes():
    """GWMIB_NODES X(name, parent, arc) lines of mib_oids.h -> {name: full OID}."""
    rows = re.findall(r'^\s*X\((\w+),\s*(\w+),\s*(\d+)\)', OIDS_H.read_text(), re.M)
    assert rows, 'GWMIB_NODES not found'
    root = (1, 3, 6, 1, 4, 1, PEN, 1)
    oids = {'mestioGwMIB': root}
    pending = list(rows)
    while pending:
        progress = False
        for row in list(pending):
            name, parent, arc = row
            if parent in oids:
                assert name not in oids, f'duplicate {name}'
                oids[name] = oids[parent] + (int(arc),)
                pending.remove(row)
                progress = True
        assert progress, f'unresolved parents: {pending}'
    return oids


def test_every_agent_oid_matches_the_mib(mib):
    for name, oid in c_nodes().items():
        assert name in mib, f'{name} (mib_oids.h) is missing from the MIB'
        assert oid_of(mib, name) == oid, f'{name}: C {oid} != MIB {mib[name]["oid"]}'


def c_setpoint_columns(tmp_path):
    prog = r'''
#include <stdio.h>
#include "mib_oids.h"
int main(void) {
#define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en) \
    if ((flags) & MEX_F_SNMP_RW) printf("%s %u %d %ld %ld %ld\n", #key, (unsigned)GWMIB_SP_COLUMN(addr), (int)(scale), \
                                        (long)(min), (long)(max), (long)(disabled));
#include "mex150/regmap_x.h"
    return 0;
}
'''
    out = compile_and_run(tmp_path, prog, name='sp', flags=[f'-I{COMPONENTS / "snmp_gw"}'])
    return [ln.split() for ln in out.splitlines()]


def test_setpoint_columns_match_the_c_module(tmp_path, mib):
    rows = c_setpoint_columns(tmp_path)
    assert rows, 'no SNMP_RW register'
    entry = oid_of(mib, 'mexSetpointEntry')
    mib_cols = {k: v for k, v in objects(mib, 'objecttype').items() if v.get('nodetype') == 'column'
                and oid_of(mib, k)[:-1] == entry}
    assert len(mib_cols) == len(rows)
    for key, col, scale, lo, hi, dis in rows:
        name = gen_mib.setpoint_name(key)
        assert name in mib_cols, f'{key} -> {name} missing'
        v = mib_cols[name]
        assert oid_of(mib, name) == entry + (int(col),)
        assert v['maxaccess'] == 'read-write'
        assert v['syntax']['type'] == ('GwTenths' if scale == '10' else 'Integer32')
        rng = v['syntax']['constraints']['range']
        lo_allowed = int(lo) if int(dis) == -2147483648 else int(dis)  # MEX_DIS_NONE = INT32_MIN
        assert min(r['min'] for r in rng) == lo_allowed and max(r['max'] for r in rng) == int(hi)


def test_every_mib_object_is_served_or_generated(mib, tmp_path):
    served = set(c_nodes())
    generated = {gen_mib.setpoint_name(r[0]) for r in c_setpoint_columns(tmp_path)}
    for name, v in objects(mib, 'objecttype', 'notificationtype').items():
        if v.get('maxaccess') == 'not-accessible' and v.get('nodetype') in ('table', 'row'):
            assert name in served, name
        assert name in served or name in generated, f'{name} is in the MIB but unknown to the agent'


def test_alarm_codes_match_the_c_catalog(tmp_path, mib):
    prog = r'''
#include <stdio.h>
int main(void) {
#define ALM(id, code, kind, addr, bit, sev, vreg, ko, en) printf("%s %d\n", #id, (int)(code));
#include "alarm/alarm_x.h"
    return 0;
}
'''
    rows = [ln.split() for ln in compile_and_run(tmp_path, prog, name='alm').splitlines()]
    enum = mib['GwAlarmCode']['type']['constraints']['enumeration']
    assert enum == {gen_mib.camel(i): int(c) for i, c in rows}


def test_status_columns_used_by_the_agent_exist(mib):
    src = (COMPONENTS / 'snmp_gw').glob('mib_*.c')
    used = set()
    for f in src:
        used |= set(re.findall(r'GWMIB_(\w+)', f.read_text()))
    used -= {'NODES', 'SP_COLUMN', 'ROOT_LEN', 'BRANCH_LEN', 'TRUTH', 'SEVERITY', 'EVENT_TYPE', 'DEV_INDEX',
             'RUNSTATE_STOPPED', 'RUNSTATE_RUNNING'}
    for name in used:
        assert name in mib, f'GWMIB_{name} used by a module is not in the MIB'


# ---------------------------------------------------------------- build contract


def test_gzip_is_deterministic_and_matches_text(tmp_path, text):
    a = generate(tmp_path, name='a.txt.gz')
    b = generate(tmp_path, name='b.txt.gz')
    assert a.read_bytes() == b.read_bytes()
    raw = a.read_bytes()
    assert raw[:2] == b'\x1f\x8b' and raw[4:8] == b'\0\0\0\0', 'gzip mtime must be 0'
    assert raw[3] & 0x08 == 0, 'no embedded file name'
    assert gzip.decompress(raw).decode('ascii') == text


def test_pen_argument_and_sdkconfig(tmp_path):
    (tmp_path / 'sdkconfig').write_text('CONFIG_FOO=y\nCONFIG_GW_SNMP_ENTERPRISE_PEN=4242\n')
    d = tmp_path / 'm'
    d.mkdir()
    assert gen_mib.main(['--sdkconfig', str(tmp_path / 'sdkconfig'), '--out', str(d / 'MESTIO-GW-MIB.txt')]) == 0
    m = compile_json(d)
    assert m['mestioGwMIB']['oid'] == '1.3.6.1.4.1.4242.1'
    assert m['gwAlarmRaised']['oid'] == '1.3.6.1.4.1.4242.1.0.1'
    assert gen_mib.pen_from_sdkconfig(ROOT / 'sdkconfig') == PEN


@pytest.mark.parametrize('args', [['--pen', '0'], ['--pen', '2147483648']])
def test_bad_pen_fails(tmp_path, args, capsys):
    assert gen_mib.main([*args, '--out', str(tmp_path / 'x.txt')]) == 1
    assert 'PEN out of range' in capsys.readouterr().err
    assert not (tmp_path / 'x.txt').exists()


def test_generator_rejects_broken_inputs(tmp_path, capsys):
    bad = tmp_path / 'regmap.def'
    bad.write_text('REG(set_temp, 40012, 10, U, RO, 50, 500, NONE, SNMP_RW, setpoint, "C", "x", "y")\n')
    assert gen_mib.main(['--regmap', str(bad), '--pen', '1', '--out', str(tmp_path / 'x.txt')]) == 1
    assert 'SNMP_RW on a read-only register' in capsys.readouterr().err
    bad.write_text('REG(set_temp, 40012, 10, U, RW\n')
    assert gen_mib.main(['--regmap', str(bad), '--pen', '1', '--out', str(tmp_path / 'x.txt')]) == 1


def test_cmake_hook_matches_the_contract():
    cm = (ROOT / 'cmake' / 'gw_mib.cmake').read_text()
    for frag in ('tools/gen_mib.py', '--regmap', '--catalog', '--pen', '${CONFIG_GW_SNMP_ENTERPRISE_PEN}',
                 'MESTIO-GW-MIB.txt.gz', 'target_add_binary_data(${target} "${out}" BINARY)',
                 'DEPENDS "${regmap}" "${catalog}" "${gen}"'):
        assert frag in cm, frag
    assert 'gw_mib(${COMPONENT_LIB})' in (COMPONENTS / 'snmp_gw' / 'CMakeLists.txt').read_text()
    agent = (COMPONENTS / 'snmp_gw' / 'agent.c').read_text()
    assert '_binary_MESTIO_GW_MIB_txt_gz_start' in agent and '_binary_MESTIO_GW_MIB_txt_gz_end' in agent
