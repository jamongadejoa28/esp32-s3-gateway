#!/usr/bin/env python3
"""End-to-end smoke test of the gateway's HTTP/WS surface (docs/API.md, DESIGN.md §6, docs/HW_TEST.md).

Runs against the device (`--url http://192.168.10.150`) or the mock server (default: the mock on
localhost). Talks HTTP/WS only; never opens a serial port. Every JSON response is validated against
docs/api/*.schema.json.

Checks, in order: security headers / no Server header, static UI (GET / gzip + ETag/304, every
asset referenced by index.html: gzip, immutable caching for hashed names, headers), Host allowlist
(421) for API, static files and the WS upgrade, unauthenticated surface (401/404), login negatives
(bad Origin, bad content type, unknown member, wrong password), login + cookie attributes, forced
password change (403 password_change_required, WS refused, CSRF/wrong_password/policy negatives,
change), CSRF/Origin/Referer negatives on a no-op PUT, a schema sweep of every GET endpoint, no
product/device information in any unauthenticated response (deny-list + this device's version,
build, MAC and hostname from /system/info), register-write negatives (readonly, range, unknown
register, CSRF), WebSocket refusals + hello/sub/snap/ping, OTA negatives (401, 403 csrf, 400
missing hash, 413 oversize), the internal-RAM gate (GET /system/info heap.int_min > 60 KB, read after
the WS/OTA load; int_free/int_min/psram_free are always printed), logout (WS bye) and finally the
login rate limit (429 + retry_after).

The heap gate (ARCHITECTURE §6, docs/HW_TEST.md §5) is a FAIL on a device and advisory (INFO) on a
loopback target, whose numbers are synthetic (--heap-gate on|off|auto, --heap-min BYTES).
`--heap-only` logs in, prints the heap figures and applies the gate without any other step, so it can
sample the device repeatedly during the §5 load test (no failed logins, no rate-limit lock).

On a non-loopback target a missing static UI (GET / not 200) is a FAIL unless --no-ui is given.
Schema checks need `jsonschema` (run through `uv run --locked`); without it the tool refuses to run
unless --no-schema is given.

Steps that change device state beyond the password are opt-in on a real device (always on for a
loopback target such as the mock). No step ever writes a register value other than the one the
device reports, so a regressed check under test cannot change the HVAC setpoint:
  --write       re-write set_temp (40012) with its current raw value from a fresh snapshot and
                expect "applied" (skipped without a fresh value; while the device is offline the
                last-known raw is written and 409 offline expected); also the "not representable"
                negative (23.45), which a regressed scale check would round and apply
  --ota-write   upload junk images (422 hash_mismatch / image_invalid); this ERASES the inactive OTA
                slot, i.e. the rollback image
  the rate-limit check locks this client IP out of login for 5 minutes, doubling with every repeated
  lock up to 30 minutes (API.md §1.1): repeated runs lock out for longer (--no-rate-limit skips it)

Secrets can be passed through the environment instead of the command line: GW_PASSWORD (current
password) and GW_NEW_PASSWORD (password to set while the account must change it).

Exit status 0 = no FAIL. `--json FILE` writes the results.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gw_http import CSP, GwClient, Response, SchemaSet  # noqa: E402

DEFAULT_URL = os.environ.get('GW_URL', 'http://127.0.0.1:8080')
FACTORY_USER, FACTORY_PASS = 'admin', 'mestio150!'
LOOPBACK_NEW_PASS = 'Smoke-Test#2026'
EVIL = 'evil.example'
# Never returned unauthenticated (DESIGN §6, API.md §1.1): product/model/platform names. The device's
# own version/build/MAC/hostname are added from GET /system/info.
LEAK_TERMS = ('MEX150', 'ESP32', 'Waveshare', 'Espressif', 'esp-idf', 'esp_idf', 'W5500', 'mestio_gw',
              'mestio-gw')
ASSET_REF_RE = re.compile(r'''(?:src|href)\s*=\s*["'](/[^"'#?\s]*)''', re.I)
# web_assets.h: content-hashed bundle files "/assets/<name>.<hash>.<ext>" (hex or esbuild base32 hash)
HASHED_NAME_RE = re.compile(r'^[^/]+[.-](?:[0-9a-f]{8,64}|[0-9A-Z]{8,64})\.[A-Za-z0-9]+$')
IMMUTABLE_CC = 'public, max-age=31536000, immutable'
# Phase-2 RAM gate (ARCHITECTURE §6, HW_TEST §5): heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL)
HEAP_GATE_MIN = 61440


class Smoke:
    def __init__(self, args):
        self.args = args
        self.url = args.url.rstrip('/')
        self.schemas = SchemaSet()
        self.results: list[dict] = []
        self.c = GwClient(self.url, timeout=args.timeout)
        self.loopback = is_loopback(self.c.host)
        self.allow_write = args.write or self.loopback
        self.allow_ota_write = args.ota_write or self.loopback
        self.password = args.password
        self.dev = None
        self.live = None
        self.max_fail = 5
        self.ui = False
        self.anon_seen: list[tuple[str, Response]] = []   # unauthenticated responses (leak check)
        self.info = None                                   # authenticated GET /system/info
        self.heap = None                                   # heap figures recorded by step_heap

    # ------------------------------------------------------------------ result helpers
    def record(self, status: str, name: str, detail: str = '') -> None:
        self.results.append({'status': status, 'name': name, 'detail': detail})
        line = f'{status:4} {name}' + (f' - {detail}' if detail else '')
        print(line, flush=True)

    def check(self, name: str, ok: bool, detail: str = '') -> bool:
        self.record('PASS' if ok else 'FAIL', name, '' if ok else detail)
        return ok

    def skip(self, name: str, why: str) -> None:
        self.record('SKIP', name, why)

    def schema_ok(self, name: str, schema: str, instance) -> bool:
        errs = self.schemas.errors(schema, instance)
        return self.check(name, not errs, '; '.join(errs[:3]))

    def expect(self, name: str, r: Response, status, error: str | None = None, schema: str | None = None) -> bool:
        """status: int or tuple; error: expected `error` member (error schema checked)."""
        statuses = status if isinstance(status, tuple) else (status,)
        body = r.json
        if r.status not in statuses:
            return self.check(name, False, f'expected {statuses}, got {r.short()}')
        if error is not None:
            if not isinstance(body, dict) or body.get('error') != error:
                return self.check(name, False, f'expected error {error!r}, got {r.short()}')
            errs = self.schemas.errors('error', body) if schema is None else []
            if errs:
                return self.check(name, False, '; '.join(errs[:3]))
        if schema is not None:
            errs = self.schemas.errors(schema, body)
            if errs:
                return self.check(name, False, '; '.join(errs[:3]))
        return self.check(name, True)

    # ------------------------------------------------------------------ steps
    def run(self) -> int:
        if not self.schemas.available:
            if not self.args.no_schema:
                print('hw_smoke: error: jsonschema/referencing not importable, so no response could be '
                      'schema-checked; run through `uv run --locked python tools/hw_smoke.py` or pass '
                      '--no-schema', file=sys.stderr)
                return 2
            self.skip('JSON schema validation', '--no-schema: responses are NOT schema-checked')
        if self.args.heap_only:
            steps = [self.step_reachable, self.step_login, self.step_heap]
        else:
            steps = [self.step_reachable, self.step_headers_and_host, self.step_unauthenticated,
                     self.step_login_negatives, self.step_login, self.step_csrf, self.step_get_sweep,
                     self.step_info_leak, self.step_register_writes, self.step_websocket,
                     self.step_ota_negatives, self.step_heap, self.step_logout, self.step_rate_limit]
        for step in steps:
            try:
                if step() is False:
                    self.record('FAIL', step.__name__, 'aborted: later steps depend on this one')
                    break
            except (OSError, http_errors()) as e:
                # A timeout or reset fails this step only; an unreachable server ends the run.
                self.record('FAIL', step.__name__, f'{type(e).__name__}: {e}')
                if isinstance(e, ConnectionRefusedError):
                    break
            except Exception as e:  # report and continue with the next step
                self.record('FAIL', step.__name__, f'{type(e).__name__}: {e}')
                if self.args.verbose:
                    traceback.print_exc()
        fails = sum(r['status'] == 'FAIL' for r in self.results)
        passes = sum(r['status'] == 'PASS' for r in self.results)
        skips = sum(r['status'] == 'SKIP' for r in self.results)
        print(f'\n{passes} passed, {fails} failed, {skips} skipped ({self.url})')
        if self.args.json:
            Path(self.args.json).write_text(json.dumps({'url': self.url, 'heap': self.heap,
                                                        'results': self.results}, indent=1))
        return 1 if fails else 0

    def step_reachable(self):
        try:
            r = self.c.raw('GET', '/api/v1/session', skip_cookie=True)
        except OSError as e:
            return self.check('reachable', False, f'{self.url}: {e}')
        return self.check('reachable', r.status in (200, 401), r.short())

    def step_headers_and_host(self):
        r = self.c.raw('GET', '/api/v1/session', skip_cookie=True)
        self.anon_seen.append(('GET /api/v1/session', r))
        self.expect('GET /session unauthenticated -> 401 {}', r, 401, schema='empty')
        self.check_security_headers('API response headers', r, api=True)
        self.check_static_ui()
        for path in ('/api/v1/session', '/'):
            r = self.c.raw('GET', path, host=EVIL)
            self.anon_seen.append((f'GET {path} Host {EVIL}', r))
            self.expect(f'Host {EVIL} on {path} -> 421', r, 421, 'misdirected')
        r = self.raw_http10('GET /api/v1/session')
        self.anon_seen.append(('HTTP/1.0 without Host', r))
        self.expect('missing Host (HTTP/1.0) -> 421', r, 421, 'misdirected')
        r = self.c.raw('GET', '/api/v1/session', host=f'{self.c.host}.{EVIL}')
        self.expect('Host suffix trick -> 421', r, 421, 'misdirected')
        if self.c.host_header != self.c.host:
            r = self.c.raw('GET', '/api/v1/session', host=self.c.host, skip_cookie=True)
            self.check('Host without port accepted', r.status == 401, r.short())

    def check_static_ui(self):
        """GET / and every local asset index.html references (DESIGN §6/§11, web_assets.h)."""
        anon = GwClient(self.url, timeout=self.args.timeout)
        gz = {'Accept-Encoding': 'gzip'}                    # as every browser sends
        idx = anon.raw('GET', '/', headers=gz)
        self.anon_seen.append(('GET /', idx))
        self.ui = idx.status == 200
        if idx.status != 200:
            if self.loopback or self.args.no_ui:
                return self.skip('GET / static UI', f'HTTP {idx.status} (UI not embedded; accepted: '
                                 f'{"--no-ui" if self.args.no_ui else "loopback target"})')
            return self.check('GET / static UI -> 200', False,
                              f'{idx.short()} (embedded UI missing or not public; pass --no-ui to accept)')
        self.check_security_headers('GET / headers', idx, api=False)
        self.check('GET / is gzip with ETag + no-cache',
                   idx.header('Content-Encoding') == 'gzip' and bool(idx.header('ETag')) and
                   'no-cache' in (idx.header('Cache-Control') or ''),
                   f'{idx.header("Content-Encoding")} {idx.header("ETag")} {idx.header("Cache-Control")}')
        etag = idx.header('ETag')
        if etag:
            r304 = anon.raw('GET', '/', headers={**gz, 'If-None-Match': etag})
            self.check('GET / If-None-Match -> 304', r304.status == 304, r304.short())
        refs = sorted({ref for ref in ASSET_REF_RE.findall(body_text(idx))
                       if ref != '/' and not ref.startswith(('/api/', '/ws', '//'))})
        if not self.check('index.html references its assets', bool(refs), 'no local src/href in GET /'):
            return
        for ref in refs:
            r = anon.raw('GET', ref, headers=gz)
            self.anon_seen.append((f'GET {ref}', r))
            problems = []
            if r.status != 200:
                problems.append(f'HTTP {r.status}')
            else:
                problems += self.security_header_problems(r, api=False)
                if r.header('Content-Encoding') != 'gzip':
                    problems.append(f'Content-Encoding: {r.header("Content-Encoding")!r}')
                if not r.header('ETag'):
                    problems.append('no ETag')
                cc = (r.header('Cache-Control') or '').replace(' ', '')
                hashed = ref.startswith('/assets/') and HASHED_NAME_RE.match(ref.rsplit('/', 1)[-1])
                if hashed and cc != IMMUTABLE_CC.replace(' ', ''):
                    problems.append(f'hashed asset Cache-Control: {r.header("Cache-Control")!r}')
                if not hashed and 'immutable' in cc:
                    problems.append(f'unhashed asset cached immutable: {r.header("Cache-Control")!r}')
            self.check(f'GET {ref} (gzip, ETag, caching, headers)', not problems, '; '.join(problems))

    def security_header_problems(self, r: Response, api: bool) -> list[str]:
        problems = []
        if r.header('Server') is not None:
            problems.append(f'Server: {r.header("Server")}')
        want = {'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY'}
        for k, v in want.items():
            if (r.header(k) or '').strip() != v:
                problems.append(f'{k}: {r.header(k)!r}')
        for k, _ in r.headers:
            if k.lower().startswith('access-control-'):
                problems.append(f'CORS header {k}')
        if api and 'no-store' not in (r.header('Cache-Control') or ''):
            problems.append(f'Cache-Control: {r.header("Cache-Control")!r}')
        return problems

    def check_security_headers(self, name, r: Response, api: bool):
        problems = self.security_header_problems(r, api)
        self.check(name, not problems, '; '.join(problems))

    def step_unauthenticated(self):
        anon = GwClient(self.url, timeout=self.args.timeout)
        for path in ('/system/info', '/devices', '/config/general', '/meta/registers'):
            r = anon.get(path)
            self.anon_seen.append((f'GET /api/v1{path}', r))
            self.expect(f'GET {path} unauthenticated -> 401', r, 401, 'unauthorized')
        r = anon.api('PUT', '/config/general', {})
        self.expect('PUT /config/general unauthenticated -> 401', r, 401, 'unauthorized')
        r = anon.get('/no/such/route')
        self.anon_seen.append(('GET /api/v1/no/such/route', r))
        self.expect('unknown API path -> 404', r, 404, 'not_found')
        if not self.ui:
            return self.skip('static 404s', 'no UI served')
        r = anon.raw('GET', '/no-such-file.js')
        self.anon_seen.append(('GET /no-such-file.js', r))
        self.check('unknown static path -> 404', r.status == 404, r.short())
        r = anon.raw('GET', '/index.html')
        self.check('/index.html is not an alias of / -> 404', r.status == 404, r.short())
        r = anon.raw('GET', '/favicon.svg', headers={'Accept-Encoding': 'gzip'})
        self.anon_seen.append(('GET /favicon.svg', r))
        self.check('GET /favicon.svg unauthenticated -> 200', r.status == 200, r.short())

    def step_login_negatives(self):
        anon = GwClient(self.url, timeout=self.args.timeout)
        r = anon.api('POST', '/auth/login', {'user': self.args.user, 'pass': self.password},
                     origin=f'http://{EVIL}')
        self.anon_seen.append(('login with foreign Origin', r))
        self.expect('login with foreign Origin -> 403 origin', r, 403, 'origin')
        self.check('no cookie after refused login', anon.sid is None, f'sid={anon.sid}')
        r = anon.api('POST', '/auth/login', raw_body=b'user=admin', content_type='application/x-www-form-urlencoded')
        self.expect('login with form body -> 400', r, 400)
        r = anon.api('POST', '/auth/login', raw_body=b'{"user":', content_type='application/json')
        self.expect('login with broken JSON -> 400 invalid_json', r, 400, 'invalid_json')
        r = anon.api('POST', '/auth/login', {'user': self.args.user, 'pass': self.password, 'x': 1})
        self.expect('login with unknown member -> 422', r, 422, 'validation')
        r = anon.login(self.args.user, 'Wrong-Password#1')
        self.anon_seen.append(('login wrong password', r))
        self.expect('login wrong password -> 401 bad_credentials', r, 401, 'bad_credentials')
        r = anon.login('nosuchuser', 'Wrong-Password#1')
        self.anon_seen.append(('login unknown user', r))
        self.expect('login unknown user -> 401 bad_credentials', r, 401, 'bad_credentials')

    def step_login(self):
        r = self.c.login(self.args.user, self.password)
        if r.status == 401 and self.args.new_password and self.password != self.args.new_password:
            # Password already changed by an earlier run: log in with it on the same client (no
            # extra session). Pass --password / GW_PASSWORD to avoid the failed attempt above.
            r2 = self.c.login(self.args.user, self.args.new_password)
            if r2.status == 200:
                self.password = self.args.new_password
                r = r2
        if not self.expect('login -> 200', r, 200, schema='auth-login.response'):
            return False
        sc = ';'.join(r.header_all('Set-Cookie'))
        attrs = {a.strip().lower() for a in sc.split(';')}
        self.check('session cookie HttpOnly; SameSite=Strict; Path=/',
                   {'httponly', 'samesite=strict', 'path=/'} <= attrs, sc)
        self.check('csrf token present', bool(self.c.csrf), str(r.json))
        if r.json.get('must_change'):
            return self.password_change_flow()
        self.skip('forced password change', 'account has no must_change')
        return True

    def password_change_flow(self):
        r = self.c.get('/system/info')
        self.expect('must_change: GET /system/info -> 403', r, 403, 'password_change_required')
        r = self.c.ws_upgrade_status()
        self.check('must_change: WS upgrade refused (403)', r.status == 403, r.short())
        new = self.args.new_password or (LOOPBACK_NEW_PASS if self.loopback else None)
        if not new:
            self.check('password change', False, 'account must change its password: pass --new-password')
            return False
        r = self.c.api('POST', '/auth/password', {'current': self.password, 'new': new}, csrf=False)
        self.expect('POST /auth/password without CSRF -> 403 csrf', r, 403, 'csrf')
        r = self.c.api('POST', '/auth/password', {'current': 'Not-The-Password#9', 'new': new})
        self.expect('POST /auth/password wrong current -> 422 wrong_password', r, 422, 'wrong_password')
        if isinstance(r.json, dict):
            self.check('wrong_password field = current', r.json.get('field') == 'current', str(r.json))
        r = self.c.api('POST', '/auth/password', {'current': self.password, 'new': 'short'})
        ok = self.expect('POST /auth/password weak -> 422 policy', r, 422, 'policy')
        if ok:
            self.check('policy lists rules', 'min_length' in (r.json.get('rules') or []), str(r.json))
        r = self.c.api('POST', '/auth/password', {'current': self.password, 'new': self.password})
        self.expect('POST /auth/password same as current -> 422 policy', r, 422, 'policy')
        r = self.c.api('POST', '/auth/password', {'current': self.password, 'new': new})
        if not self.expect('POST /auth/password -> 204', r, 204):
            return False
        self.password = new
        r = self.c.get('/session')
        ok = self.expect('GET /session after change', r, 200, schema='session.response')
        if ok:
            self.check('must_change cleared', r.json.get('must_change') is False, str(r.json))
            self.c.csrf = r.json.get('csrf') or self.c.csrf
        return True

    def step_csrf(self):
        r = self.c.get('/config/general')
        if not self.expect('GET /config/general', r, 200, schema='config-general.response'):
            return
        body = {'site': r.json['site']}                      # writing the current value is a no-op
        self.expect('PUT without X-CSRF-Token -> 403 csrf',
                    self.c.api('PUT', '/config/general', body, csrf=False), 403, 'csrf')
        self.expect('PUT with wrong X-CSRF-Token -> 403 csrf',
                    self.c.api('PUT', '/config/general', body, csrf='AAAAAAAAAAAAAAAAAAAAAA'), 403, 'csrf')
        self.expect('PUT with foreign Origin -> 403 origin',
                    self.c.api('PUT', '/config/general', body, origin=f'http://{EVIL}'), 403, 'origin')
        self.expect('PUT with foreign Referer -> 403 origin',
                    self.c.api('PUT', '/config/general', body, referer=f'http://{EVIL}/x'), 403, 'origin')
        self.expect('PUT with Origin on another port -> 403 origin',
                    self.c.api('PUT', '/config/general', body, origin=f'http://{self.c.host}:1'), 403, 'origin')
        self.expect('PUT unknown member -> 422 validation',
                    self.c.api('PUT', '/config/general', {'site': body['site'], 'bogus': 1}), 422, 'validation')
        self.expect('PUT same-origin with CSRF -> 200',
                    self.c.api('PUT', '/config/general', body, origin=self.c.origin), 200,
                    schema='config-general.response')

    def step_get_sweep(self):
        r = self.c.get('/devices')
        if self.expect('GET /devices', r, 200, schema='devices.response') and r.json:
            enabled = [d for d in r.json if d.get('enabled', True)]
            self.dev = (enabled or r.json)[0]['id']
        if self.dev is None:
            self.skip('device endpoints', 'no device configured')
        d = self.dev
        endpoints = [
            ('/session', 'session.response'), ('/meta/registers', 'meta-registers.response'),
            ('/meta/alarms', 'meta-alarms.response'), ('/system/info', 'system-info.response'),
            ('/system/network', 'system-network.response'), ('/alarms/active', 'alarms-active.response'),
            ('/alarms/history?limit=5', 'alarms-history.response'), ('/config/rules', 'config-rules'),
            ('/config/alarms', 'config-alarms.response'), ('/config/general', 'config-general.response'),
            ('/config/network', 'config-network.response'), ('/config/modbus', 'config-modbus.response'),
            ('/config/snmp', 'config-snmp.response'), ('/config/time', 'config-time.response'),
            ('/config/security', 'config-security.response'), ('/config/notify', 'config-notify.response'),
            ('/users', 'users.response'), ('/system/firmware', 'firmware.response'),
            ('/system/logs?kind=audit&limit=5', 'logs.response'),
            ('/system/logs?kind=system&limit=5', 'logs.response'),
            ('/system/config/export', 'config-bundle'),
        ]
        if d is not None:
            endpoints += [(f'/devices/{d}/live', 'device-live.response'),
                          (f'/devices/{d}/stats', 'device-stats.response'),
                          (f'/devices/{d}/history?span=900&res=1', 'history.response'),
                          (f'/devices/{d}/history?span=86400&res=60&stages=1', 'history.response')]
        for path, schema in endpoints:
            r = self.c.get(path)
            self.expect(f'GET {path}', r, 200, schema=schema)
            if path == '/meta/registers' and r.status == 200:
                etag = r.header('ETag')
                if etag:
                    r2 = self.c.get(path, headers={'If-None-Match': etag})
                    self.check('GET /meta/registers If-None-Match -> 304', r2.status == 304, r2.short())
                else:
                    self.check('GET /meta/registers has ETag', False, 'no ETag')
            if path.endswith('/live') and r.status == 200:
                self.live = r.json
            if path == '/system/info' and r.status == 200 and isinstance(r.json, dict):
                self.info = r.json
        r = self.c.get('/system/coredump')
        if r.status == 404:
            self.expect('GET /system/coredump (none stored)', r, 404, 'not_found')
        else:
            self.expect('GET /system/coredump', r, 200, schema='coredump.response')
        r = self.c.get('/snmp/mib')
        self.check('GET /snmp/mib text', r.status == 200 and 'text/plain' in (r.header('Content-Type') or ''),
                   f'{r.status} {r.header("Content-Type")}')
        if d is not None:
            r = self.c.get(f'/devices/{d}/history.csv?span=900&res=1')
            if isinstance(self.info, dict) and self.info.get('time_valid') is False:
                # API.md §4.6: CSV rows carry ISO 8601 UTC times, so no export without a valid clock
                self.expect('GET history.csv without a valid clock -> 400', r, 400, 'bad_request')
            else:
                self.check('GET history.csv (BOM + header)',
                           r.status == 200 and r.body.startswith(b'\xef\xbb\xbftime,'), r.short())
            self.expect('GET /devices/9/live -> 404', self.c.get('/devices/9/live'), 404, 'not_found')
            self.expect('GET history without span -> 400', self.c.get(f'/devices/{d}/history'), 400, 'bad_request')

    def leak_patterns(self) -> list[tuple[str, re.Pattern]]:
        """Deny-list for unauthenticated responses: product/platform names plus this device's own
        identity from the authenticated GET /system/info."""
        pats = [(t, re.compile(re.escape(t), re.I)) for t in LEAK_TERMS]
        info = self.info or {}
        for key in ('fw', 'idf'):
            v = info.get(key)
            if isinstance(v, str) and v.count('.') >= 2:          # x.y.z: no false hits on "1.0"
                pats.append((f'{key} version {v}', re.compile(r'(?<![\w.])v?' + re.escape(v) + r'(?![\w-]|\.\d)')))
        build = info.get('build')
        if isinstance(build, str) and len(build) >= 6:
            pats.append((f'build {build}', re.compile(r'(?<!\w)' + re.escape(build) + r'(?!\w)')))
        mac = info.get('mac')
        if isinstance(mac, str) and re.fullmatch(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            octets = mac.split(':')
            alts = '|'.join(re.escape(sep.join(octets)) for sep in (':', '-', ''))
            pats.append((f'MAC {mac}', re.compile(f'(?<![0-9a-fA-F])(?:{alts})(?![0-9a-fA-F])', re.I)))
        host = info.get('hostname')
        if isinstance(host, str) and len(host) >= 3:
            pats.append((f'hostname {host}', re.compile(r'(?<![\w-])' + re.escape(host) + r'(?![\w-])', re.I)))
        return pats

    def leaks(self, r: Response, pats) -> list[str]:
        text = body_text(r) + '\n' + '\n'.join(f'{k}: {v}' for k, v in r.headers)
        return [label for label, pat in pats if pat.search(text)]

    def step_info_leak(self):
        """DESIGN §6 / API.md §1.1: no product name/model/version or device information is ever
        returned unauthenticated (login page, static files, error bodies, headers).
        The SPA bundle under /assets/ carries every UI string of the authenticated views, so generic
        product/platform words found there are reported as INFO (see docs/HW_TEST.md §4); this
        device's own version/build/MAC/hostname there are a FAIL (the bundle must be device-neutral)."""
        if self.info is None:
            self.skip('device identity for the leak check', 'GET /system/info failed: deny-list only')
        pats = self.leak_patterns()
        generic = set(LEAK_TERMS)
        bundle_info, bundle_fail, other = [], [], []
        n_assets = 0
        for where, resp in self.anon_seen:
            is_asset = where.startswith('GET /assets/')
            n_assets += is_asset
            hits = self.leaks(resp, pats)
            if not hits:
                continue
            if is_asset:
                g = [h for h in hits if h in generic]
                d = [h for h in hits if h not in generic]
                if g:
                    bundle_info.append(f'{where}: {", ".join(g)}')
                if d:
                    bundle_fail.append(f'{where}: {", ".join(d)}')
            else:
                other.append(f'{where}: {", ".join(hits)}')
        self.check('no product/device info in unauthenticated API, HTML and error responses', not other,
                   '; '.join(other[:5]))
        if not n_assets:
            return self.skip('static assets leak check', 'no /assets/ files fetched')
        self.check("no device identity (version/build/MAC/hostname) in the static bundle", not bundle_fail,
                   '; '.join(bundle_fail[:5]))
        if bundle_info:
            self.record('INFO', 'generic product/platform words in the static bundle', '; '.join(bundle_info[:5]))

    def step_register_writes(self):
        d = self.dev
        if d is None:
            return self.skip('register writes', 'no device')
        base = f'/devices/{d}/registers'
        rejected = ('readonly', 'offline')
        # Every negative must be a no-op if the check under test regressed and the write went through:
        # read-only 40036, the device's own current raw, or values the MEX150 itself refuses.
        r = self.c.api('PUT', f'{base}/40036', {'raw': 0})
        if self.expect('write read-only 40036 -> 409', r, 409, 'rejected', schema='write-result.response'):
            self.check('reason readonly/offline', r.json.get('reason') in rejected, str(r.json))
        negatives = [({'value': 99.9}, 'out of range')]          # outside the MEX150's own 5.0..50.0 too
        if self.allow_write:
            negatives.append(({'value': 23.45}, 'not representable'))  # a regressed check would round + apply
        else:
            self.skip('write 40012 not representable', 'would be rounded and applied if the scale check '
                      'regressed: pass --write')
        for body, label in negatives:
            r = self.c.api('PUT', f'{base}/40012', body)
            if self.expect(f'write 40012 {label} -> 409', r, 409, 'rejected', schema='write-result.response'):
                self.check(f'{label}: reason range/offline', r.json.get('reason') in ('range', 'offline'), str(r.json))
        r = self.c.api('PUT', f'{base}/40001', {'raw': 1})
        self.expect('write unknown register -> 404', r, 404, 'not_found')
        cur = current_raw(self.live, '40012')
        target, body = (('40012', {'raw': cur}) if cur is not None and (self.live or {}).get('online')
                        else ('40036', {'raw': 0}))
        r = self.c.api('PUT', f'{base}/{target}', body, csrf=False)
        self.expect(f'write {target} (no-op value) without CSRF -> 403', r, 403, 'csrf')
        r = self.c.api('PUT', f'{base}/40012', {'value': 'hot'})
        self.expect('write with string value -> 422', r, 422, 'validation')
        if not self.allow_write:
            return self.skip('write current set_temp', 'device target: pass --write')
        deadline = time.monotonic() + 6                        # first poll / slow group may be pending
        while True:
            live = self.c.get(f'/devices/{d}/live').json or {}
            if live.get('fresh') or live.get('online') is False or time.monotonic() > deadline:
                break
            time.sleep(0.5)
        cur = current_raw(live, '40012')
        if live.get('online') is False:
            if cur is None:
                return self.skip('write while offline', 'no last-known raw of 40012 to re-write')
            r = self.c.api('PUT', f'{base}/40012', {'raw': cur})
            if self.expect('write (last-known raw) while offline -> 409', r, 409, 'rejected',
                           schema='write-result.response'):
                self.check('reason offline', r.json.get('reason') == 'offline', str(r.json))
            return
        if not live.get('fresh') or cur is None:
            # An online device with poll_ms > 3 s is never "fresh" here, and the gateway would accept
            # the write: never send a value that may be stale.
            return self.skip('write current set_temp', 'no fresh snapshot with 40012 within 6 s')
        r = self.c.api('PUT', f'{base}/40012', {'raw': cur})
        if not self.expect('write 40012 = current raw', r, (200, 202), schema='write-result.response'):
            return
        res = r.json
        if r.status == 200:
            self.check('applied with read-back raw', res.get('state') == 'applied' and res.get('raw') == cur, str(res))
        cmd = res.get('cmd')
        if cmd:
            deadline = time.monotonic() + 5
            while True:
                rc = self.c.get(f'/devices/{d}/commands/{cmd}')
                if rc.status != 200 or rc.json.get('state') != 'pending' or time.monotonic() > deadline:
                    break
                time.sleep(0.3)
            if self.expect(f'GET /devices/{d}/commands/{cmd}', rc, 200, schema='command.response'):
                self.check('command final state applied', rc.json.get('state') == 'applied', str(rc.json))

    def step_websocket(self):
        r = self.c.ws_upgrade_status(cookie=False)
        self.check('WS without cookie refused (401)', r.status == 401, r.short())
        r = self.c.ws_upgrade_status(origin=f'http://{EVIL}')
        self.check('WS with foreign Origin refused (403)', r.status == 403, r.short())
        r = self.c.ws_upgrade_status(host=EVIL)
        self.check(f'WS with Host {EVIL} refused (421)', r.status == 421, r.short())
        try:
            import websockets  # noqa: F401
        except ImportError:
            return self.skip('WS session', 'python websockets not installed')
        with self.c.ws_connect() as ws:
            hello = json.loads(ws.recv(timeout=5))
            if not self.schema_ok('WS hello', 'ws-server', hello) or hello.get('t') != 'hello':
                return self.check('WS first frame is hello', False, str(hello)[:200])
            ws.send(json.dumps({'t': 'sub', 'topics': ['snap', 'alarm', 'comm', 'write', 'sys']}))
            ws.send(json.dumps({'t': 'ping'}))
            seen, bad = {}, []
            online = bool(self.live and self.live.get('online'))
            deadline = time.monotonic() + self.args.ws_seconds
            while time.monotonic() < deadline:
                try:
                    msg = json.loads(ws.recv(timeout=max(0.1, deadline - time.monotonic())))
                except TimeoutError:
                    break
                bad += self.schemas.errors('ws-server', msg)
                seen.setdefault(msg.get('t'), msg)
                if 'pong' in seen and ('snap' in seen or not online) and 'comm' in seen:
                    break
            self.check('WS frames match ws-server schema', not bad, '; '.join(bad[:3]))
            self.check('WS ping -> pong', 'pong' in seen, f'seen {sorted(seen)}')
            if online:
                snap = seen.get('snap')
                self.check('WS first snap is full', bool(snap) and snap.get('full') is True, str(snap)[:200])
            else:
                self.skip('WS snap', 'device offline: no poll data')
            self.check('WS comm frame', 'comm' in seen or not online, f'seen {sorted(seen)}')

    def step_ota_negatives(self):
        anon = GwClient(self.url, timeout=self.args.timeout)
        junk = os.urandom(4096)
        sha = hashlib.sha256(junk).hexdigest()
        octet = {'Content-Type': 'application/octet-stream'}
        r = anon.api('POST', '/system/firmware', raw_body=junk, content_type='',
                     headers={**octet, 'X-Firmware-SHA256': sha})
        self.expect('OTA unauthenticated -> 401', r, 401, 'unauthorized')
        r = self.c.api('POST', '/system/firmware', raw_body=junk, content_type='', csrf=False,
                       headers={**octet, 'X-Firmware-SHA256': sha})
        self.expect('OTA without CSRF -> 403 csrf', r, 403, 'csrf')
        r = self.c.api('POST', '/system/firmware', raw_body=junk, content_type='', headers=octet)
        self.expect('OTA without X-Firmware-SHA256 -> 400', r, 400)
        r = self.c.api('POST', '/system/firmware', raw_body=junk, content_type='',
                       headers={**octet, 'X-Firmware-SHA256': 'xyz'})
        self.expect('OTA malformed X-Firmware-SHA256 -> 400', r, 400)
        r = self.oversize_upload()
        self.expect('OTA Content-Length 4 MB -> 413', r, 413, 'payload_too_large')
        if not self.allow_ota_write:
            return self.skip('OTA hash_mismatch/image_invalid', 'erases the inactive slot: pass --ota-write')
        r = self.c.api('POST', '/system/firmware', raw_body=junk, content_type='',
                       headers={**octet, 'X-Firmware-SHA256': '0' * 64})
        self.expect('OTA hash mismatch -> 422 hash_mismatch', r, (422,), None)
        if r.status == 422:
            self.check('error hash_mismatch or image_invalid (header checked first)',
                       r.json.get('error') in ('hash_mismatch', 'image_invalid'), str(r.json))
        r = self.c.api('POST', '/system/firmware', raw_body=junk, content_type='',
                       headers={**octet, 'X-Firmware-SHA256': sha})
        self.expect('OTA junk image -> 422 image_invalid', r, 422, 'image_invalid')
        r = self.c.get('/system/firmware')
        if self.expect('GET /system/firmware after rejected uploads', r, 200, schema='firmware.response'):
            self.check('running slot still valid', r.json['running']['state'] in ('valid', 'undefined', 'pending_verify'),
                       str(r.json))

    def raw_http10(self, request_line: str) -> Response:
        """HTTP/1.0 request without any header (no Host): exercises the server's own Host check
        rather than an HTTP/1.1 parser's mandatory-Host rule. esp_http_server keeps the socket open
        after answering (no HTTP/1.0 close handling), so the response is framed by Content-Length /
        chunked encoding, not by the connection closing."""
        with socket.create_connection((self.c.host, self.c.port), timeout=self.args.timeout) as s:
            s.sendall(f'{request_line} HTTP/1.0\r\n\r\n'.encode())
            return read_http_response(s, method=request_line.split(' ', 1)[0])

    def oversize_upload(self) -> Response:
        """Announce 4 MB but send only 64 KB: the server must answer 413 from Content-Length."""
        import http.client
        conn = http.client.HTTPConnection(self.c.host, self.c.port, timeout=self.args.timeout)
        try:
            conn.putrequest('POST', '/api/v1/system/firmware', skip_host=True, skip_accept_encoding=True)
            for k, v in (('Host', self.c.host_header), ('Cookie', f'gw_sid={self.c.sid}'),
                         ('X-CSRF-Token', self.c.csrf), ('Content-Type', 'application/octet-stream'),
                         ('X-Firmware-SHA256', '0' * 64), ('Content-Length', str(4 * 1024 * 1024))):
                conn.putheader(k, v)
            conn.endheaders()
            try:
                conn.send(b'\0' * 65536)
            except OSError:
                pass                                         # server may close early: fine
            r = conn.getresponse()
            return Response(r.status, r.reason, list(r.getheaders()), r.read())
        finally:
            conn.close()

    def heap_gate_enforced(self) -> bool:
        mode = self.args.heap_gate
        return mode == 'on' or (mode == 'auto' and not self.loopback)

    def step_heap(self):
        """Internal-RAM gate (ARCHITECTURE §6, HW_TEST §5): heap.int_min (minimum free internal RAM
        since boot) > --heap-min. Read after the WS/OTA steps so their load is included. A FAIL on a
        device; INFO on a loopback target (the mock's figures are synthetic) unless --heap-gate on."""
        r = self.c.get('/system/info')
        if not self.expect('GET /system/info (heap gate)', r, 200, schema='system-info.response'):
            return None
        heap = r.json.get('heap') if isinstance(r.json, dict) else None
        keys = ('int_free', 'int_min', 'psram_free')
        if not isinstance(heap, dict) or not all(isinstance(heap.get(k), int) for k in keys):
            self.check('heap figures present', False, f'heap={heap!r}')
            return None
        self.heap = {k: heap[k] for k in keys}
        self.heap['uptime_s'] = r.json.get('uptime_s')
        figures = (f'int_free={heap["int_free"]} int_min={heap["int_min"]} '
                   f'psram_free={heap["psram_free"]} uptime_s={r.json.get("uptime_s")}')
        self.record('INFO', 'heap', figures)
        limit = self.args.heap_min
        if limit <= 0 or self.args.heap_gate == 'off':
            return self.skip(f'heap gate int_min > {limit}', 'disabled (--heap-gate off / --heap-min 0)')
        ok = heap['int_min'] > limit
        name = f'heap gate int_min > {limit} B'
        if self.heap_gate_enforced():
            self.check(name, ok, f'int_min={heap["int_min"]} (AT RISK, see ARCHITECTURE §6.1)')
            return None                                    # a low heap does not abort the later steps
        self.record('INFO', name, ('ok' if ok else f'below: int_min={heap["int_min"]}') +
                    ' (advisory: loopback target, synthetic figures; --heap-gate on enforces)')

    def step_logout(self):
        sid = self.c.sid
        try:
            import websockets  # noqa: F401
            ws_cm = self.c.ws_connect()
        except Exception as e:  # WS failures were reported by step_websocket
            ws_cm = None
            self.skip('WS bye on logout', f'no WS: {e}')
        if ws_cm is None:
            self.expect('POST /auth/logout -> 204', self.c.logout(), 204)
        else:
            with ws_cm as ws:
                json.loads(ws.recv(timeout=5))                # hello
                self.expect('POST /auth/logout -> 204', self.c.logout(), 204)
                reason = None
                deadline = time.monotonic() + 5
                try:
                    while time.monotonic() < deadline:
                        m = json.loads(ws.recv(timeout=max(0.05, deadline - time.monotonic())))
                        if m.get('t') == 'bye':
                            reason = m.get('reason')
                            break
                except Exception:
                    pass
                self.check('WS bye logout', reason == 'logout', f'bye reason {reason!r}')
        old = GwClient(self.url, timeout=self.args.timeout, sid=sid)
        self.expect('old cookie after logout -> 401', old.get('/system/info'), 401, 'unauthorized')

    def step_rate_limit(self):
        if self.args.no_rate_limit:
            return self.skip('login rate limit', '--no-rate-limit')
        anon = GwClient(self.url, timeout=self.args.timeout)
        got = None
        for i in range(self.max_fail + 3):
            r = anon.login(self.args.user, f'Wrong-Password#{i}')
            if r.status == 429:
                got = r
                break
            if r.status != 401:
                return self.check('rate limit', False, f'attempt {i + 1}: {r.short()}')
        if not self.check(f'429 within {self.max_fail + 3} failed logins', got is not None, 'never limited'):
            return
        self.expect('429 body rate_limited', got, 429, 'rate_limited')
        self.check('retry_after > 0', isinstance(got.json.get('retry_after'), int) and got.json['retry_after'] > 0,
                   str(got.json))
        r = anon.login(self.args.user, self.password)
        self.check('correct password while locked -> 429', r.status == 429, r.short())
        hits = self.leaks(got, self.leak_patterns())
        self.check('429 body/headers carry no product/device info', not hits, ', '.join(hits))


MAX_RAW_RESPONSE = 1024 * 1024
LINGER_S = 2.0          # no framing at all: wait this long after the last byte, then take what came


def dechunk(body: bytes) -> tuple[bytes, bool]:
    """(decoded body, complete) for a chunked body; complete once the last (0-size) chunk arrived."""
    out = b''
    while True:
        size_line, sep, rest = body.partition(b'\r\n')
        if not sep:
            return out, False
        try:
            n = int(size_line.split(b';')[0].strip(), 16)
        except ValueError:
            return out, True                                # malformed: stop here
        if n == 0:
            return out, True
        if len(rest) < n + 2:
            return out, False
        out += rest[:n]
        body = rest[n + 2:]


def read_http_response(sock: socket.socket, method: str = 'GET') -> Response:
    """Read exactly one HTTP response from sock (keep-alive safe): the head, then Content-Length
    bytes, or chunks up to the last one, or (no framing) until close or LINGER_S of silence.
    A timeout before the head is complete propagates (TimeoutError)."""
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_RAW_RESPONSE:
            raise OSError('response head too large')
    head, sep, body = data.partition(b'\r\n\r\n')
    lines = head.decode('latin-1').split('\r\n')
    parts = lines[0].split(' ', 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    hdrs = [tuple(x.strip() for x in ln.split(':', 1)) for ln in lines[1:] if ':' in ln]
    reason = parts[2] if len(parts) > 2 else ''
    if not sep:
        return Response(status, reason, hdrs, b'')
    get = {k.lower(): v for k, v in reversed(hdrs)}
    if method == 'HEAD' or status in (204, 304) or 100 <= status < 200:
        return Response(status, reason, hdrs, b'')
    chunked = 'chunked' in get.get('transfer-encoding', '').lower()
    length = get.get('content-length')
    want = int(length) if (length or '').isdigit() and not chunked else None
    if want is not None and want > MAX_RAW_RESPONSE:
        raise OSError(f'Content-Length {want} too large')
    while True:
        if want is not None and len(body) >= want:
            return Response(status, reason, hdrs, body[:want])
        if chunked:
            decoded, done = dechunk(body)
            if done:
                return Response(status, reason, hdrs, decoded)
        if want is None and not chunked:
            sock.settimeout(LINGER_S)                       # unframed: close or silence ends it
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            if want is None and not chunked:
                return Response(status, reason, hdrs, body)
            raise
        if not chunk:
            return Response(status, reason, hdrs, dechunk(body)[0] if chunked else body)
        body += chunk
        if len(body) > MAX_RAW_RESPONSE:
            raise OSError('response body too large')


def body_text(r: Response) -> str:
    """Response body as text (gzip Content-Encoding decoded; undecodable bytes kept as latin-1)."""
    data = r.body or b''
    if (r.header('Content-Encoding') or '').lower() == 'gzip' or data[:2] == b'\x1f\x8b':
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            pass
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def current_raw(live, addr: str):
    """Raw value of addr in a /live snapshot, or None."""
    v = ((live or {}).get('regs') or {}).get(addr) if isinstance(live, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def http_errors():
    import http.client
    return http.client.HTTPException


def is_loopback(host: str) -> bool:
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 epilog='Opt-in device-state changes are described in the module docstring.')
    ap.add_argument('--url', default=DEFAULT_URL, help=f'gateway or mock base URL (default {DEFAULT_URL}, env GW_URL)')
    ap.add_argument('--user', default=FACTORY_USER)
    ap.add_argument('--password', default=os.environ.get('GW_PASSWORD') or FACTORY_PASS,
                    help='current password (default factory mestio150!, env GW_PASSWORD)')
    ap.add_argument('--new-password', default=os.environ.get('GW_NEW_PASSWORD') or None,
                    help='password to set when the account must change it (required on a device; '
                         'env GW_NEW_PASSWORD, empty = not given)')
    ap.add_argument('--write', action='store_true', help='also write 40012 with its current value')
    ap.add_argument('--ota-write', action='store_true', help='also upload junk images (erases inactive slot)')
    ap.add_argument('--no-rate-limit', action='store_true',
                    help='skip the lockout check (it locks this IP 5 min, doubling up to 30 min per repeat)')
    ap.add_argument('--no-ui', action='store_true', help='accept a device without the embedded web UI')
    ap.add_argument('--no-schema', action='store_true',
                    help='run without jsonschema (responses are then NOT schema-checked)')
    ap.add_argument('--heap-gate', choices=('auto', 'on', 'off'), default='auto',
                    help='internal-RAM gate heap.int_min > --heap-min: auto = FAIL on a device, '
                         'INFO on a loopback target (default auto)')
    ap.add_argument('--heap-min', type=int, default=HEAP_GATE_MIN,
                    help=f'heap gate threshold in bytes (default {HEAP_GATE_MIN} = 60 KB; 0 = report only)')
    ap.add_argument('--heap-only', action='store_true',
                    help='only log in, print the heap figures and apply the heap gate (HW_TEST §5 sampling)')
    ap.add_argument('--ws-seconds', type=float, default=6.0, help='how long to watch WS frames')
    ap.add_argument('--timeout', type=float, default=15.0)
    ap.add_argument('--json', help='write results to this file')
    ap.add_argument('-v', '--verbose', action='store_true')
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    return Smoke(args).run()


if __name__ == '__main__':
    sys.exit(main())
