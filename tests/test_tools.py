"""Stream G tool safety + wiring checks (no hardware is touched by any of these tests)."""
import gzip
import json
import re
import subprocess
import sys
import time

import pytest

from conftest import ROOT

RUN_DEVICE = ROOT / 'tools' / 'run_device.py'


def run(*args):
    return subprocess.run([sys.executable, str(RUN_DEVICE), *args], capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize('args', [(), ('--port', '/dev/ttyFAKE0'), ('--yes',), ('--dry-run',),
                                  ('--port', '', '--yes'), ('--yes', '--dry-run')])
def test_run_device_refuses_without_port_and_yes(args):
    r = run(*args)
    assert r.returncode == 2
    assert 'refusing' in r.stderr and r.stdout == ''


def test_run_device_explicit_no_wins():
    r = run('--port', '/dev/ttyFAKE0', '--yes', '--no', '--dry-run')
    assert r.returncode == 2 and 'declined' in r.stderr and r.stdout == ''


def test_run_device_dry_run_builds_commands_without_touching_port():
    r = run('--port', '/dev/ttyFAKE0', '--yes', '--dry-run', '--build-dir', 'build-x', '--baud', '921600')
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert len(lines) == 2
    assert lines[0].endswith('tools/idf.py -B build-x -p /dev/ttyFAKE0 -b 921600 flash')
    assert lines[1].endswith('monitor')
    r = run('--port', '/dev/ttyFAKE0', '--yes', '--dry-run', '--no-monitor')
    assert r.stdout.strip().endswith('flash') and len(r.stdout.splitlines()) == 1


def test_run_device_missing_port_path_is_an_error():
    r = run('--port', '/dev/ttyFAKE-does-not-exist', '--yes', '--no-monitor')
    assert r.returncode == 2 and 'does not exist' in r.stderr


def test_no_other_tool_opens_serial_ports():
    """Only run_device.py may reference serial devices / flash / monitor."""
    pat = re.compile(r'/dev/tty|serial\.Serial|\bflash\b.*idf|esptool|[\'"]monitor[\'"]')
    for f in ['gen_web_assets.py', 'gw_http.py', 'hw_smoke.py', 'snmp_smoke.py']:
        text = (ROOT / 'tools' / f).read_text()
        assert not pat.search(text), f'{f} references a serial device or flashing'


def cmdline(task):
    return ' '.join([task['command'], *task.get('args', [])])


def test_vscode_tasks():
    text = (ROOT / '.vscode' / 'tasks.json').read_text()
    tasks = json.loads(text)
    by_label = {t['label']: t for t in tasks['tasks']}
    build = [t for t in tasks['tasks'] if isinstance(t.get('group'), dict) and t['group'].get('isDefault')
             and t['group']['kind'] == 'build']
    assert len(build) == 1 and 'run_device' not in cmdline(build[0])
    hw = [t for t in tasks['tasks'] if 'run_device.py' in cmdline(t)]
    assert len(hw) == 1 and 'HARDWARE' in hw[0]['label']
    assert '--port ${input:serialPort}' in cmdline(hw[0]) and '${input:confirmHardware}' in cmdline(hw[0])
    inputs = {i['id']: i for i in tasks['inputs']}
    assert inputs['confirmHardware']['default'] != '--yes'                   # must be picked by hand
    assert not inputs['serialPort'].get('default')
    for t in by_label.values():
        if 'run_device' not in cmdline(t):
            assert '/dev/tty' not in cmdline(t) and 'flash' not in cmdline(t).split()


def test_vscode_tasks_never_put_prompted_values_through_a_shell():
    """Prompted values are not quoted by VS Code: a secret in a shell command line would be expanded
    by the shell (`Pa$$w0rd` -> `Pa<pid>w0rd` set as the admin password) and echoed in the terminal.
    Secrets go through options.env; other prompted values only into a process task's args."""
    tasks = json.loads((ROOT / '.vscode' / 'tasks.json').read_text())
    secret = {i['id'] for i in tasks['inputs'] if i.get('password')}
    assert {'newPassword', 'snmpCommunity'} <= secret
    for t in tasks['tasks']:
        line = cmdline(t)
        for sid in secret:
            assert f'${{input:{sid}}}' not in line, f'{t["label"]}: secret {sid} on the command line'
        if '${input:' in line:
            assert t['type'] == 'process', f'{t["label"]}: prompted value in a shell command'
            assert '${input:' not in t['command']
    envs = [v for t in tasks['tasks'] for v in t.get('options', {}).get('env', {}).values()]
    assert '${input:newPassword}' in envs and '${input:snmpCommunity}' in envs


def test_vscode_no_ui_build_uses_its_own_build_dir():
    """GW_WEB_ASSETS is a cached option: OFF must not stick in the default build dir."""
    tasks = json.loads((ROOT / '.vscode' / 'tasks.json').read_text())
    for t in tasks['tasks']:
        line = cmdline(t)
        if 'GW_WEB_ASSETS=OFF' in line:
            assert ' -B build-' in line, t['label']


def test_hw_smoke_treats_empty_env_secrets_as_unset(monkeypatch):
    sys.path.insert(0, str(ROOT / 'tools'))
    import hw_smoke
    monkeypatch.setenv('GW_NEW_PASSWORD', '')
    monkeypatch.setenv('GW_PASSWORD', '')
    a = hw_smoke.parse_args([])
    assert a.new_password is None and a.password == hw_smoke.FACTORY_PASS
    monkeypatch.setenv('GW_NEW_PASSWORD', 'Pa$$w0rd-2026 x')
    assert hw_smoke.parse_args([]).new_password == 'Pa$$w0rd-2026 x'


# ---------------------------------------------------------------- hw_smoke pure helpers (no device)

def _hw_smoke():
    sys.path.insert(0, str(ROOT / 'tools'))
    import hw_smoke
    return hw_smoke


def _serve_once(payload: bytes, close: bool):
    """One-shot TCP server answering any request with payload; keeps the socket open unless close
    (esp_http_server never closes after an HTTP/1.0 answer). Returns (port, thread)."""
    import socket
    import threading
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(payload)
        if close:
            conn.close()
        else:
            time.sleep(4)
            conn.close()
        srv.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv.getsockname()[1], t


def _smoke(url, **kw):
    hw = _hw_smoke()
    args = hw.parse_args(['--url', url, '--timeout', '3', *kw.pop('argv', [])])
    return hw.Smoke(args)


@pytest.mark.parametrize('payload, close, body', [
    (b'HTTP/1.1 421 Misdirected Request\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n'
     b'{"error":"misdirected"}\n', False, b'{"error":"misdirected"}\n'),
    (b'HTTP/1.1 421 Misdirected Request\r\nTransfer-Encoding: chunked\r\n\r\n'
     b'c\r\n{"error":"mi\r\nb\r\nsdirected"}\r\n0\r\n\r\n', False, b'{"error":"misdirected"}'),
    (b'HTTP/1.0 421 Misdirected Request\r\n\r\n{"error":"misdirected"}', True, b'{"error":"misdirected"}'),
])
def test_raw_http10_does_not_wait_for_close(payload, close, body):
    port, t = _serve_once(payload, close)
    s = _smoke(f'http://127.0.0.1:{port}')
    t0 = time.monotonic()
    r = s.raw_http10('GET /api/v1/session')
    assert r.status == 421 and r.body == body
    assert time.monotonic() - t0 < 2.5                    # never the 3 s socket timeout
    t.join(6)


def test_run_continues_after_a_step_timeout(monkeypatch):
    s = _smoke('http://127.0.0.1:9')
    ran = []

    def make(name, exc=None):
        def f():
            ran.append(name)
            if exc:
                raise exc
        f.__name__ = name
        return f
    names = ['step_reachable', 'step_headers_and_host', 'step_unauthenticated', 'step_login_negatives',
             'step_login', 'step_csrf', 'step_get_sweep', 'step_info_leak', 'step_register_writes',
             'step_websocket', 'step_ota_negatives', 'step_heap', 'step_logout', 'step_rate_limit']
    for n in names:
        monkeypatch.setattr(s, n, make(n, TimeoutError('timed out') if n == 'step_headers_and_host' else None))
    assert s.run() == 1
    assert ran == names                                  # a timeout fails one step only
    ran.clear()
    s.results.clear()
    monkeypatch.setattr(s, 'step_unauthenticated', make('step_unauthenticated', ConnectionRefusedError()))
    s.run()
    assert ran == names[:3]                              # an unreachable server ends the run


def test_hw_smoke_refuses_without_jsonschema(monkeypatch, capsys):
    s = _smoke('http://127.0.0.1:9')
    s.schemas.available = False
    assert s.run() == 2 and 'jsonschema' in capsys.readouterr().err
    s2 = _smoke('http://127.0.0.1:9', argv=['--no-schema'])
    s2.schemas.available = False
    monkeypatch.setattr(s2, 'step_reachable', lambda: False)
    s2.run()
    assert s2.results[0]['status'] == 'SKIP' and 'NOT schema-checked' in s2.results[0]['detail']


def test_leak_patterns():
    hw = _hw_smoke()
    s = _smoke('http://127.0.0.1:9')
    s.info = {'fw': '1.2.3', 'build': 'g1a2b3c4d', 'idf': '6.1.0', 'mac': '24:6f:28:aa:bb:cc',
              'hostname': 'mestio-gw-bbcc'}
    pats = s.leak_patterns()

    def leaks(text, headers=()):
        return s.leaks(hw.Response(200, 'OK', list(headers), text.encode()), pats)
    assert leaks('{"error":"unauthorized"}') == []
    assert leaks('a=1.2.30;b=11.2.3;c=1.2.3.4;opacity:1.0') == []
    assert leaks('fw v1.2.3)') == ['fw version 1.2.3']
    assert leaks('ID 246F28AABBCC') == ['MAC 24:6f:28:aa:bb:cc']
    assert leaks('x', [('X-Build', 'g1a2b3c4d')]) == ['build g1a2b3c4d']
    assert 'MEX150' in leaks('name:"MEX150 #1"')
    assert 'esp-idf' in leaks('ESP-IDF v6.1.0') and 'idf version 6.1.0' in leaks('ESP-IDF v6.1.0')
    assert 'hostname mestio-gw-bbcc' in leaks('MESTIO-GW-BBCC')
    gz = gzip.compress(b'<title>Waveshare</title>')
    assert s.leaks(hw.Response(200, 'OK', [('Content-Encoding', 'gzip')], gz), pats) == ['Waveshare']


def test_hashed_asset_names():
    hw = _hw_smoke()
    for name in ('app.3f9a1c0d.js', 'app-5HQKP2ZB.js', 'style.0123456789abcdef.css'):
        assert hw.HASHED_NAME_RE.match(name), name
    for name in ('icons.svg', 'app.js', 'app-settings.js', 'app.Settings1.js'):
        assert not hw.HASHED_NAME_RE.match(name), name


def test_current_raw():
    hw = _hw_smoke()
    assert hw.current_raw({'regs': {'40012': 230}}, '40012') == 230
    assert hw.current_raw({'regs': {'40012': True}}, '40012') is None
    assert hw.current_raw({'regs': {}}, '40012') is None
    assert hw.current_raw(None, '40012') is None


@pytest.mark.parametrize('argv, status', [([], 'FAIL'), (['--no-ui'], 'SKIP')])
def test_missing_ui_fails_on_a_device_target(argv, status):
    port, t = _serve_once(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n', close=True)
    s = _smoke(f'http://127.0.0.1:{port}', argv=argv)
    s.loopback = False                                   # as for http://192.168.10.150
    s.check_static_ui()
    assert [r['status'] for r in s.results] == [status] and s.ui is False
    t.join(6)


def _info_response(int_min):
    hw = _hw_smoke()
    # the documented example (schema-valid) with the heap figures under test
    text = (ROOT / 'docs' / 'API.md').read_text(encoding='utf-8')
    m = re.search(r'<!-- schema: system-info\.response -->\s*```json\n(.*?)```', text, re.S)
    body = json.loads(m.group(1))
    body['uptime_s'] = 600
    body['heap'] = {'int_free': 90000, 'int_min': int_min, 'psram_free': 7000000}
    return hw.Response(200, 'OK', [('Content-Type', 'application/json')], json.dumps(body).encode())


@pytest.mark.parametrize('loopback, argv, int_min, statuses', [
    (False, [], 70000, ['PASS']),                         # device, above the 60 KB gate
    (False, [], 61440, ['FAIL']),                         # device, gate is strictly greater
    (True, [], 50000, ['INFO']),                          # mock: advisory only
    (True, ['--heap-gate', 'on'], 50000, ['FAIL']),
    (False, ['--heap-gate', 'off'], 50000, ['SKIP']),
    (False, ['--heap-min', '40000'], 50000, ['PASS']),
])
def test_heap_gate(monkeypatch, loopback, argv, int_min, statuses):
    s = _smoke('http://127.0.0.1:9', argv=argv)
    s.loopback = loopback
    monkeypatch.setattr(s.c, 'get', lambda path, **kw: _info_response(int_min))
    assert s.step_heap() is None                          # never aborts the remaining steps
    got = [(r['status'], r['name']) for r in s.results]
    if s.schemas.available:
        assert got[0] == ('PASS', 'GET /system/info (heap gate)'), got
    assert got[-2][0] == 'INFO' and f'int_min={int_min}' in s.results[-2]['detail']
    assert [st for st, _ in got[-1:]] == statuses, got
    assert s.heap == {'int_free': 90000, 'int_min': int_min, 'psram_free': 7000000, 'uptime_s': 600}


def test_heap_only_runs_login_and_heap(monkeypatch):
    s = _smoke('http://127.0.0.1:9', argv=['--heap-only'])
    ran = []
    for n in ('step_reachable', 'step_login', 'step_heap', 'step_get_sweep', 'step_rate_limit'):
        monkeypatch.setattr(s, n, (lambda n: lambda: ran.append(n))(n))
    s.run()
    assert ran == ['step_reachable', 'step_login', 'step_heap']


def test_docs_mib_copy_is_current(tmp_path):
    """docs/mib/MESTIO-GW-MIB.txt (docs/SNMP.md) is gen_mib.py's output for the default PEN.
    Regenerate: uv run --locked python tools/gen_mib.py --pen 32473 --out docs/mib/MESTIO-GW-MIB.txt"""
    out = tmp_path / 'MESTIO-GW-MIB.txt'
    r = subprocess.run([sys.executable, str(ROOT / 'tools' / 'gen_mib.py'), '--pen', '32473', '--out', str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (ROOT / 'docs' / 'mib' / 'MESTIO-GW-MIB.txt').read_bytes() == out.read_bytes(), \
        'docs/mib/MESTIO-GW-MIB.txt is stale: ' + test_docs_mib_copy_is_current.__doc__.splitlines()[1].strip()
