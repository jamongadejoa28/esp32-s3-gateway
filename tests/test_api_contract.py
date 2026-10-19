"""API contract (docs/API.md §6): schemas, documented examples, and the mock server's behaviour.

* every docs/api/*.schema.json is a valid JSON Schema 2020-12 document with a consistent $id;
* every JSON example in API.md names its schema and validates (and every schema has an example);
* the endpoint index only names existing schemas;
* when node and tools/mock_server.mjs exist (stream D): the mock answers every documented request
  example with the documented status and a schema-valid body, and tools/hw_smoke.py (all HTTP/WS
  checks, WS frames validated against ws-server) passes against it. Skipped while the mock is absent.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import ROOT

jsonschema = pytest.importorskip('jsonschema')
sys.path.insert(0, str(ROOT / 'tools'))
from gw_http import GwClient, SchemaSet  # noqa: E402

API_MD = ROOT / 'docs' / 'API.md'
SCHEMA_DIR = ROOT / 'docs' / 'api'
MOCK = ROOT / 'tools' / 'mock_server.mjs'
ID_BASE = 'https://mestio.invalid/gw/api/v1/'
EXAMPLE_RE = re.compile(r'<!-- schema: ([\w.-]+) -->\s*```json\n(.*?)```', re.S)
SCHEMAS = SchemaSet(SCHEMA_DIR)


def examples():
    return [(name, json.loads(body)) for name, body in EXAMPLE_RE.findall(API_MD.read_text(encoding='utf-8'))]


def example(name, index=0):
    return [e for n, e in examples() if n == name][index]


# ---------------------------------------------------------------- schemas and examples


@pytest.mark.parametrize('name', sorted(SCHEMAS.schemas))
def test_schema_is_valid_2020_12(name):
    schema = SCHEMAS.schemas[name]
    assert schema.get('$schema') == 'https://json-schema.org/draft/2020-12/schema'
    assert schema.get('$id') == f'{ID_BASE}{name}.schema.json'
    jsonschema.Draft202012Validator.check_schema(schema)


def test_all_refs_resolve():
    """Every $ref (local or into common.schema.json) points at an existing definition."""
    def walk(node, owner):
        if isinstance(node, dict):
            ref = node.get('$ref')
            if isinstance(ref, str):
                doc, _, frag = ref.partition('#')
                target = SCHEMAS.schemas[doc[:-len('.schema.json')]] if doc else SCHEMAS.schemas[owner]
                for part in [p for p in frag.split('/') if p]:
                    assert part in target, f'{owner}: unresolved $ref {ref}'
                    target = target[part]
            for v in node.values():
                walk(v, owner)
        elif isinstance(node, list):
            for v in node:
                walk(v, owner)
    for name, schema in SCHEMAS.schemas.items():
        walk(schema, name)


def test_every_json_block_is_tagged():
    text = API_MD.read_text(encoding='utf-8')
    assert text.count('```json') == len(EXAMPLE_RE.findall(text)), 'a ```json block in API.md has no schema tag'


@pytest.mark.parametrize('i, name, instance', [(i, n, e) for i, (n, e) in enumerate(examples())],
                         ids=lambda v: str(v)[:24] if not isinstance(v, (dict, list)) else '')
def test_api_md_example_validates(i, name, instance):
    assert name in SCHEMAS.schemas, f'example {i} names unknown schema {name}'
    errs = SCHEMAS.errors(name, instance)
    assert not errs, errs


def test_every_schema_has_an_example():
    named = {n for n, _ in examples()}
    assert len(named) and set(SCHEMAS.schemas) - named <= {'common'}


def test_endpoint_index_names_existing_schemas():
    text = API_MD.read_text(encoding='utf-8')
    section = text[text.index('## 3. Endpoint index'):text.index('## 4. Endpoints')]
    names = set()
    for row in section.splitlines():
        if row.startswith('| ') and '/' in row:
            for cell in row.split('|')[5:8:2]:                         # request / response columns
                names |= set(re.findall(r'\b([a-z][a-z0-9-]*(?:\.(?:request|response))?)\b', cell))
    names -= {'octet-stream', 'text', 'mib', 'csv'}                       # non-JSON bodies
    missing = sorted(n for n in names if n not in SCHEMAS.schemas and n not in ('ws-client', 'ws-server'))
    assert not missing, missing
    assert {'ws-client', 'ws-server'} <= set(SCHEMAS.schemas)


def test_negative_examples_are_rejected():
    """The schemas are not vacuous: obvious contract violations fail validation."""
    bad = [
        ('auth-login.request', {'user': 'admin'}),
        ('auth-login.request', {'user': 'admin', 'pass': 'x', 'extra': 1}),
        ('write-result.response', {'state': 'done', 'cmd': 1, 'addr': 40012}),
        ('ws-server', {'t': 'snap', 'dev': 9}),
        ('ws-client', {'t': 'sub', 'topics': ['bogus']}),
        ('error', {'message': 'no code'}),
        ('config-security.request', {'ip_allow': ['300.1.1.1/8']}),
        ('device-live.response', {'seq': -1}),
    ]
    for name, inst in bad:
        assert SCHEMAS.errors(name, inst), f'{name} accepted {inst}'


# ---------------------------------------------------------------- mock server


def find_node():
    cands = [shutil.which('node')] + sorted((str(p) for p in Path.home().glob('.nvm/versions/node/v*/bin/node')),
                                            reverse=True)
    for c in cands:
        if not c:
            continue
        try:
            v = subprocess.run([c, '--version'], capture_output=True, text=True, timeout=10).stdout
        except OSError:
            continue
        m = re.match(r'v(\d+)\.', v)
        if m and int(m.group(1)) >= 22:
            return c
    return None


NODE = find_node()
needs_mock = pytest.mark.skipif(not (NODE and MOCK.is_file() and (ROOT / 'node_modules' / 'ws').is_dir()),
                                reason='mock server not available yet (node, tools/mock_server.mjs, node_modules/ws)')


@pytest.fixture
def mock():
    """A fresh mock gateway per test (state starts at factory defaults). Yields its base URL."""
    yield from run_mock()


@pytest.fixture
def mock_time_invalid():
    """A fresh mock whose wall clock is not valid (no RTC time, no NTP): --time-invalid."""
    yield from run_mock('--time-invalid')


def run_mock(*extra):
    env = {**os.environ, 'PATH': f'{Path(NODE).parent}{os.pathsep}{os.environ.get("PATH", "")}'}
    proc = subprocess.Popen([NODE, str(MOCK), '--port', '0', '--host', '127.0.0.1', '--quiet', '--seed', '7',
                             '--no-faults', '--no-comm-loss', *extra],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    url = None
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            m = re.search(r'(http://127\.0\.0\.1:\d+)', line)
            if m:
                url = m.group(1)
                break
        if not url:
            proc.kill()
            out, err = proc.communicate(timeout=5)
            pytest.fail(f'mock server did not start: {out}{err}')
        yield url
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        for s in (proc.stdout, proc.stderr):
            if s:
                s.close()


def check(r, statuses, schema, what):
    statuses = statuses if isinstance(statuses, tuple) else (statuses,)
    assert r.status in statuses, f'{what}: expected {statuses}, got {r.short()}'
    if schema is None:
        assert not r.body, f'{what}: expected no body, got {r.short()}'
        return r.json
    errs = SCHEMAS.errors(schema if r.status < 400 or schema == 'write-result.response' else 'error', r.json)
    assert not errs, f'{what}: {errs}'
    return r.json


@needs_mock
def test_mock_documented_requests(mock):
    """Every documented request example, in a state-consistent order, against a fresh mock."""
    c = GwClient(mock)
    check(c.login(**{'user': example('auth-login.request')['user'], 'password': example('auth-login.request')['pass']}),
          200, 'auth-login.response', 'login')
    check(c.api('POST', '/auth/password', example('auth-password.request')), 204, None, 'password change')
    check(c.get('/session'), 200, 'session.response', 'session')

    for name, path in [('config-general.request', '/config/general'), ('config-modbus.request', '/config/modbus'),
                       ('config-alarms.request', '/config/alarms'), ('config-time.request', '/config/time'),
                       ('config-notify.request', '/config/notify'), ('config-snmp.request', '/config/snmp'),
                       ('config-security.request', '/config/security')]:
        resp = name.replace('.request', '.response')
        got = check(c.api('PUT', path, example(name)), 200, resp, f'PUT {path}')
        assert got == check(c.get(path), 200, resp, f'GET {path}'), f'PUT {path} response != GET'
    rules = example('config-rules')
    assert check(c.api('PUT', '/config/rules', rules), 200, 'config-rules', 'PUT /config/rules') == rules

    apply = check(c.api('PUT', '/config/network', example('config-network.request')), 202,
                  'network-apply.response', 'PUT /config/network')
    check(c.api('PUT', '/config/network', example('config-network.request')), 423, 'error', 'second network PUT')
    time.sleep(apply['apply_in_s'] + 0.5)     # confirm after the change applied
    check(c.api('POST', '/config/network/confirm'), 204, None, 'network confirm')
    check(c.api('POST', '/config/network/confirm'), 409, 'error', 'confirm without pending change')

    for body in (example('register-write.request', 0), example('register-write.request', 1)):
        check(c.api('PUT', '/devices/0/registers/40012', body), (200, 202, 409), 'write-result.response', 'write')
    res = check(c.api('POST', '/devices/0/run', example('device-run.request')), (200, 202, 409),
                'write-result.response', 'run')
    if res.get('cmd'):
        check(c.get(f'/devices/0/commands/{res["cmd"]}'), 200, 'command.response', 'command')
    check(c.api('POST', '/devices/0/stats/reset'), 204, None, 'stats reset')
    for i in (0, 1):
        check(c.api('POST', '/alarms/ack', example('alarms-ack.request', i)), 204, None, 'ack')
    check(c.api('POST', '/time', example('time-set.request')), 204, None, 'POST /time')
    check(c.api('POST', '/snmp/test-trap'), (200, 409), 'snmp-test-trap.response', 'test trap')

    check(c.api('POST', '/users', example('user-create.request')), 201, 'user.response', 'create user')
    check(c.api('POST', '/users', example('user-create.request')), 409, 'error', 'duplicate user')
    name = example('user-create.request')['name']
    check(c.api('PUT', f'/users/{name}', example('user-update.request')), 200, 'user.response', 'update user')
    check(c.get('/users'), 200, 'users.response', 'users')
    check(c.api('DELETE', f'/users/{name}'), 204, None, 'delete user')
    check(c.api('DELETE', '/users/admin'), 409, 'error', 'delete self/last admin')

    bundle = check(c.get('/system/config/export'), 200, 'config-bundle', 'export')
    check(c.api('POST', '/system/config/import', bundle), 200, 'config-import.response', 'import export')
    check(c.api('POST', '/system/config/import', example('config-bundle')), 200, 'config-import.response',
          'import example')
    check(c.api('POST', '/system/factory-reset', {**example('factory-reset.request'), 'password': 'wrong-Pass#123'}),
          422, 'error', 'factory reset wrong password')
    check(c.api('POST', '/system/factory-reset', example('factory-reset.request')), 202, 'reboot.response',
          'factory reset')


@needs_mock
def test_mock_validation_errors(mock):
    c = GwClient(mock)
    c.login('admin', 'mestio150!')
    c.api('POST', '/auth/password', example('auth-password.request'))
    cases = [
        ('PUT', '/config/general', {'lang': 'xx'}, 422),
        ('PUT', '/config/modbus', {'poll_ms': 1}, 422),
        ('PUT', '/config/security', {'idle_min': 1}, 422),
        ('PUT', '/config/snmp', {'v2c': True}, 422),                       # no RO community stored
        ('PUT', '/config/rules', [example('config-rules')[0]] * 9, 422),
        ('POST', '/time', {'epoch_ms': 1000}, 422),
        ('POST', '/alarms/ack', {'keys': ['nonsense']}, 422),
        ('PUT', '/devices/0/registers/40012', {}, 422),
    ]
    for method, path, body, status in cases:
        r = c.api(method, path, body)
        assert r.status == status, f'{method} {path} {body}: {r.short()}'
        assert not SCHEMAS.errors('error', r.json), r.json
    r = c.api('PUT', '/config/snmp', {'v2c': True})
    assert r.json.get('field') == 'ro' and r.json.get('code') == 'required', r.json
    r = c.api('PUT', '/config/general', raw_body=b'x' * 9000)
    assert r.status == 413 and r.json['error'] == 'payload_too_large', r.short()


@needs_mock
def test_hw_smoke_passes_against_mock(mock, tmp_path):
    out = tmp_path / 'smoke.json'
    r = subprocess.run([sys.executable, str(ROOT / 'tools' / 'hw_smoke.py'), '--url', mock, '--json', str(out),
                        '--ws-seconds', '4'], capture_output=True, text=True, timeout=300)
    results = json.loads(out.read_text())['results'] if out.exists() else []
    fails = [f"{x['name']}: {x['detail']}" for x in results if x['status'] == 'FAIL']
    assert r.returncode == 0 and not fails, '\n'.join(fails) or r.stdout[-3000:] + r.stderr[-3000:]
    assert sum(x['status'] == 'PASS' for x in results) >= 90


# ---------------------------------------------------------------- endpoints that reboot (fresh mock each)


def admin(url):
    c = GwClient(url)
    check(c.login('admin', 'mestio150!'), 200, 'auth-login.response', 'login')
    check(c.api('POST', '/auth/password', example('auth-password.request')), 204, None, 'password change')
    return c


def esp_image(version: str, project: str = 'mestio_gw', size: int = 4096) -> bytes:
    """Minimal ESP application image header: magic 0xE9, esp_app_desc_t at 32 (magic 0xABCD5432,
    version[32] at +16, project_name[32] at +48)."""
    img = bytearray(size)
    img[0] = 0xE9
    img[32:36] = (0xABCD5432).to_bytes(4, 'little')
    img[48:48 + len(version)] = version.encode()
    img[80:80 + len(project)] = project.encode()
    return bytes(img)


def upload(c, img, query=''):
    import hashlib
    return c.api('POST', f'/system/firmware{query}', raw_body=img, content_type='',
                 headers={'Content-Type': 'application/octet-stream',
                          'X-Firmware-SHA256': hashlib.sha256(img).hexdigest()})


@needs_mock
def test_mock_firmware_upload(mock):
    c = admin(mock)
    check(upload(c, esp_image('9.9.9', project='other_app')), 422, 'error', 'foreign project')
    assert upload(c, esp_image('0.0.1')).json['error'] == 'image_invalid'          # downgrade refused
    check(upload(c, esp_image('0.0.0-test'), '?allow_downgrade=1'), 200, 'firmware-upload.response',
          'downgrade allowed')


@needs_mock
def test_mock_firmware_upload_success(mock):
    c = admin(mock)
    res = check(upload(c, esp_image('9.9.9')), 200, 'firmware-upload.response', 'upload')
    assert res['version'] == '9.9.9' and res['reboot_in_s'] > 0


@needs_mock
def test_mock_firmware_rollback(mock):
    c = admin(mock)
    fw = check(c.get('/system/firmware'), 200, 'firmware.response', 'firmware')
    r = c.api('POST', '/system/firmware/rollback')
    if fw['other'].get('valid'):
        check(r, 202, 'reboot.response', 'rollback')
    else:
        check(r, 404, 'error', 'rollback without a valid other slot')


@needs_mock
def test_mock_reboot(mock):
    c = admin(mock)
    check(c.api('POST', '/system/reboot', csrf=False), 403, 'error', 'reboot without CSRF')
    check(c.api('POST', '/system/reboot'), 202, 'reboot.response', 'reboot')


@needs_mock
def test_mock_csv_exports(mock):
    c = admin(mock)
    r = c.get('/alarms/history.csv')
    assert r.status == 200 and 'text/csv' in (r.header('Content-Type') or ''), r.short()
    assert r.body.startswith(b'\xef\xbb\xbfseq,time,dev,id,code,type,sev,value,user\r\n'), r.body[:80]
    r = c.get('/devices/0/history.csv?span=900&res=1')
    assert r.status == 200 and r.body.startswith(b'\xef\xbb\xbftime,'), r.short()


@needs_mock
def test_mock_history_without_valid_clock(mock_time_invalid):
    """API.md §4.6: without a valid wall clock, span queries still work (JSON t0 = null), from/to
    queries are refused, and CSV export is refused in both modes (rows carry ISO 8601 UTC times)."""
    c = admin(mock_time_invalid)
    info = check(c.get('/system/info'), 200, 'system-info.response', 'system info')
    assert info['time_valid'] is False, info
    res = check(c.get('/devices/0/history?span=900'), 200, 'history.response', 'history span')
    assert res['t0'] is None and res['n'] > 0, res
    now_ms = int(time.time() * 1000)
    rng = f'from={now_ms - 900_000}&to={now_ms}'
    check(c.get(f'/devices/0/history?{rng}'), 400, 'error', 'history from/to')
    assert c.get(f'/devices/0/history?{rng}').json['error'] == 'bad_request'
    for q in ('span=900', 'span=900&res=1', rng):
        r = c.get(f'/devices/0/history.csv?{q}')
        check(r, 400, 'error', f'history.csv?{q}')
        assert r.json['error'] == 'bad_request', r.short()


@needs_mock
def test_mock_rule_src_is_canonical(mock):
    """API.md /config/rules: reg:40036/40037/40011 are stored and returned as temp/hum/cur (firmware
    config_json.c w_rule); other registers keep reg:<addr>."""
    c = admin(mock)
    rules = [dict(example('config-rules')[0], id=i + 1, src=src)
             for i, src in enumerate(('reg:40036', 'reg:40037', 'reg:40011', 'reg:40012'))]
    got = check(c.api('PUT', '/config/rules', rules), 200, 'config-rules', 'PUT /config/rules')
    assert [r['src'] for r in got] == ['temp', 'hum', 'cur', 'reg:40012'], got
    assert check(c.get('/config/rules'), 200, 'config-rules', 'GET /config/rules') == got
