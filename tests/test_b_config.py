"""Stream B store/config.c + config_json.c + secrets.c (pure parts).

* t_config.c: defaults (DESIGN §5 + DECISIONS), every validation rule, metadata, trap remap, file/REST JSON.
* Python: REST GET bodies validate against docs/api schemas, API.md request examples parse, export bundle
  validates against config-bundle, random mutations and fuzzed JSON never crash and round-trip stably.
"""
import ctypes
import json
import random
import re

import pytest

from b_store.harness import b_lib, b_objs, run_c  # noqa: F401  (fixtures)
from conftest import ROOT

jsonschema = pytest.importorskip('jsonschema')
referencing = pytest.importorskip('referencing')

SCHEMA_DIR = ROOT / 'docs' / 'api'
API_MD = ROOT / 'docs' / 'API.md'
SECTIONS = ['general', 'network', 'modbus', 'alarms', 'snmp', 'time', 'security', 'notify']
OUT = 1 << 16


@pytest.fixture(scope='module')
def schemas():
    docs = {p.name[:-len('.schema.json')]: json.loads(p.read_text()) for p in SCHEMA_DIR.glob('*.schema.json')}
    reg = referencing.Registry().with_resources(
        [(d['$id'], referencing.Resource.from_contents(d)) for d in docs.values()])

    def validate(name, inst):
        cls = jsonschema.validators.validator_for(docs[name])
        errs = sorted(str(e.message) for e in cls(docs[name], registry=reg).iter_errors(inst))
        assert not errs, f'{name}: {errs}\n{json.dumps(inst, ensure_ascii=False)}'
    return validate


@pytest.fixture(scope='module')
def lib(b_lib):
    L = b_lib
    L.t_install_catalog.argtypes = [ctypes.c_int]
    for f in ('t_cfg_roundtrip',):
        getattr(L, f).argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                  ctypes.c_char_p]
    L.t_cfg_defaults_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    L.t_section_get.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_char_p,
                                ctypes.c_size_t]
    L.t_section_put.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    L.t_rules_put.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    L.t_network_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    L.t_install_catalog(1)
    return L


def roundtrip(lib, doc: bytes):
    out, err = ctypes.create_string_buffer(OUT), ctypes.create_string_buffer(96)
    rc = lib.t_cfg_roundtrip(doc, len(doc), out, OUT, err)
    return rc, (json.loads(out.value) if rc == 0 else None), err.value.decode()


def defaults(lib, fw=None):
    out = ctypes.create_string_buffer(OUT)
    assert lib.t_cfg_defaults_json(fw.encode() if fw else None, out, OUT) == 0
    return json.loads(out.value)


def section_get(lib, s, base=b'', flags=0x3F):
    out = ctypes.create_string_buffer(OUT)
    assert lib.t_section_get(SECTIONS.index(s), base, len(base), flags, out, OUT) == 0
    return json.loads(out.value)


def section_put(lib, s, body, base=b''):
    out, err = ctypes.create_string_buffer(OUT), ctypes.create_string_buffer(96)
    body = body if isinstance(body, bytes) else json.dumps(body).encode()
    rc = lib.t_section_put(SECTIONS.index(s), base, len(base), body, len(body), out, OUT, err)
    return rc, (json.loads(out.value) if rc == 0 else None), err.value.decode()


def test_config_c(b_objs, tmp_path):
    run_c(b_objs, tmp_path, 't_config')


# ---------------------------------------------------------------- shapes vs. docs/api schemas


def test_rest_get_bodies_match_schemas(lib, schemas):
    base = json.dumps({'snmp': {'traps': [{'host': '192.168.10.20', 'port': 162, 'version': 'v2c', 'inform': True,
                                           'enabled': True}]},
                       'alarms': {'sev_override': {'high_hum': 2},
                                  'rules': [{'id': 1, 'name': 'warm', 'src': 'temp', 'op': '>', 'thr': 28}]},
                       'security': {'ip_allow': ['192.168.10.0/24']}}).encode()
    for s in SECTIONS:
        body = section_get(lib, s, base)
        if s == 'network':
            schemas('config-network.response', body)
        else:
            schemas(f'config-{s}.response', body)
    out = ctypes.create_string_buffer(OUT)
    assert lib.t_network_get(b'{"state":"apply_pending","left_s":3}', out, OUT) == 0
    schemas('config-network.response', json.loads(out.value))


def test_export_bundle_matches_schema(lib, schemas):
    doc = defaults(lib, fw='1.0.0')
    schemas('config-bundle', doc)
    assert doc['schema'] == 1 and doc['fw'] == '1.0.0'
    # API.md export example: defaults equal the documented bundle except identity/site values
    example = json.loads(re.search(r'<!-- schema: config-bundle -->\s*```json\n(.*?)```', API_MD.read_text(),
                                   re.S).group(1))
    for sec in ('modbus', 'alarms', 'snmp', 'time', 'security', 'notify'):
        assert doc[sec] == example[sec], sec
    assert doc['network']['eth'] == example['network']['eth']
    assert {k: v for k, v in doc['network']['ap'].items() if k != 'ssid'} == \
        {k: v for k, v in example['network']['ap'].items() if k != 'ssid'}


def test_api_examples_parse(lib, schemas):
    """Every documented PUT /config/* request example is accepted and yields a valid section."""
    text = API_MD.read_text()
    found = 0
    for name, body in re.findall(r'<!-- schema: (config-[a-z]+)\.request -->\s*```json\n(.*?)```', text, re.S):
        s = name.split('-')[1]
        rc, res, err = section_put(lib, s, body.encode())
        assert rc == 0, (name, err)
        if s == 'snmp':  # enabling v2c etc. needs secrets checks done by the caller; structure must be valid
            assert res['secrets']['v3'][0]['auth'] == 'monitor-pass-1'
            assert res['secrets']['trap'][0] == 'nms-trap'
        assert res['valid'], (name, err)
        schemas(f'config-{s}.response', res['section'])
        found += 1
    assert found >= 8
    rules = re.search(r'<!-- schema: config-rules -->\s*```json\n(.*?)```', text, re.S).group(1).encode()
    out, err = ctypes.create_string_buffer(OUT), ctypes.create_string_buffer(96)
    assert lib.t_rules_put(rules, len(rules), out, OUT, err) == 0, err.value
    got = json.loads(out.value)
    schemas('config-rules', got)
    want = json.loads(rules)
    for g, w in zip(got, want):
        assert {k: v for k, v in g.items() if k != 'src'} == {k: v for k, v in w.items() if k != 'src'}
    assert got[1]['src'] == 'cur'  # reg:40011 is canonicalised to its alias


def test_import_example_and_unknown_members(lib):
    text = API_MD.read_text()
    bundle = json.loads(re.search(r'<!-- schema: config-bundle -->\s*```json\n(.*?)```', text, re.S).group(1))
    bundle['future_section'] = {'x': 1}
    bundle['general']['future_field'] = True
    rc, doc, err = roundtrip(lib, json.dumps(bundle).encode())
    assert rc == 0, err
    assert doc['general']['site'] == 'Server room B'
    assert doc['rev'] == 42 and 'fw' not in doc and 'future_section' not in doc


# ---------------------------------------------------------------- robustness


def test_roundtrip_is_a_fixed_point(lib):
    base = defaults(lib)
    rc, doc, _ = roundtrip(lib, json.dumps(base).encode())
    assert rc == 0 and doc == base
    rc, doc2, _ = roundtrip(lib, json.dumps(doc, ensure_ascii=False).encode())
    assert doc2 == doc


def _mutations(rnd, value):
    """Yield (path, new value) candidates for a random leaf."""
    junk = [None, True, False, 0, -1, 1.5, 2 ** 31, 2 ** 40, -(2 ** 40), '', 'x', 'x' * 80, '한글', '\x00',
            '256.1.1.1', '10.0.0.0/8', [], {}, [1, 2], {'a': 1}, 1e308, 'reg:40036', '>', '<']
    return rnd.choice(junk)


def _leaves(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaves(v, path + (i,))
    yield path


def test_random_mutations_never_crash_and_stay_valid(lib, schemas):
    rnd = random.Random(20261019)
    base = defaults(lib, fw=None)
    base['alarms']['rules'] = [{'id': 1, 'name': 'r', 'enabled': True, 'dev': 0, 'src': 'temp', 'op': '>',
                                'thr': 28.0, 'hyst': 1.0, 'delay_s': 0, 'sev': 2}]
    base['snmp']['traps'] = [{'host': '10.0.0.1', 'port': 162, 'version': 'v2c', 'inform': False, 'enabled': True}]
    leaves = [p for p in _leaves(base) if p]
    accepted = 0
    for _ in range(1500):
        doc = json.loads(json.dumps(base))
        for _ in range(rnd.randint(1, 3)):
            path = rnd.choice(leaves)
            node = doc
            try:
                for k in path[:-1]:
                    node = node[k]
                node[path[-1]] = _mutations(rnd, node[path[-1]])
            except (KeyError, IndexError, TypeError):
                continue
        rc, out, err = roundtrip(lib, json.dumps(doc).encode())
        assert rc in (0, -2, -3), (rc, doc)
        if rc == 0:
            accepted += 1
            schemas('config-bundle', out)
            rc2, out2, _ = roundtrip(lib, json.dumps(out).encode())
            assert rc2 == 0 and out2 == out
        else:
            assert '|' in err and err.split('|')[1], (doc, err)
    assert accepted > 25  # most junk values are rightly rejected; some must survive


def test_malformed_bytes_never_crash(lib):
    rnd = random.Random(7)
    seed = json.dumps(defaults(lib)).encode()
    for i in range(2500):
        b = bytearray(seed)
        for _ in range(rnd.randint(1, 8)):
            op = rnd.randrange(3)
            pos = rnd.randrange(len(b))
            if op == 0:
                b[pos] = rnd.randrange(256)
            elif op == 1:
                del b[pos:pos + rnd.randint(1, 20)]
            else:
                b[pos:pos] = bytes(rnd.choice(b'{}[]",:\\0123456789truefalsenull ') for _ in range(rnd.randint(1, 6)))
        if i % 10 == 0:
            b = b[:rnd.randrange(len(b) + 1)]
        rc, out, _ = roundtrip(lib, bytes(b))
        assert rc in (0, -1, -2, -3)
        if rc == 0:
            rc2, out2, _ = roundtrip(lib, json.dumps(out).encode())
            assert rc2 == 0 and out2 == out
    for bad in [b'', b'\x00', b'[' * 5000, b'{"a":' * 3000, b'"x"', b'1', b'{"general":{"site":"\xff"}}']:
        rc, _, _ = roundtrip(lib, bad)
        assert rc in (-1, -3)


def test_rest_put_fuzz(lib):
    rnd = random.Random(99)
    keys = {s: list(section_get(lib, s).keys()) for s in SECTIONS}
    vals = [None, True, 1, -5, 3.5, 'x', '', '10.0.0.1', [], {}, [{}], [{'id': 0}], {'enabled': True}]
    for _ in range(1500):
        s = rnd.choice(SECTIONS)
        body = {rnd.choice(keys[s] + ['bogus']): rnd.choice(vals) for _ in range(rnd.randint(0, 3))}
        rc, res, err = section_put(lib, s, body)
        assert rc in (0, -3), (s, body, rc)
        if rc == 0:
            assert set(res) == {'section', 'secrets', 'valid'}
        else:
            field, code = err.split('|')
            assert code in {'required', 'type', 'range', 'format', 'length', 'duplicate', 'overlap',
                            'unknown_register', 'unknown_field', 'too_many'}, err
            assert field.startswith(s), err


def test_secret_flags_in_get(lib):
    snmp = section_get(lib, 'snmp', flags=0x02 | 0x08 | (0x20 << 1))
    assert snmp['ro_set'] is True and snmp['rw_set'] is False
    assert [u['keys_set'] for u in snmp['v3']['users']] == [True, False]
    no_flags = section_get(lib, 'snmp', flags=-1)
    assert 'ro_set' not in no_flags and 'keys_set' not in no_flags['v3']['users'][0]
    net = section_get(lib, 'network', flags=0)
    assert net['ap']['psk_set'] is False and net['provisional'] is None
