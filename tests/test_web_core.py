"""web pure core (components/web: web_path.c, web_policy.c, web_routes.c, web_json.c, web_csv.c,
ws_frame.c) on the host: route matching and the default-deny route table vs docs/API.md, the router
permission matrix, cookie/query/Origin parsing, JSON/CSV builders and WebSocket frames (schema-checked).
"""
import ctypes as C
import json
import re

import pytest

from conftest import ROOT
from stream_c_lib import (Facts, HistSeries, HistSlow, RPolicy, RouteMeta, SnapState, WebParams, Writer,  # noqa: F401
                          clib, schema_validator)

M_DELETE, M_GET, M_POST, M_PUT = 0, 1, 3, 4
METHODS = {'GET': M_GET, 'POST': M_POST, 'PUT': M_PUT, 'DELETE': M_DELETE}
NONE, VIEWER, OPERATOR, ADMIN = 0, 1, 2, 3
F_CSRF, F_MC, F_RAW, F_SLOW, F_NOTOUCH = 1, 2, 4, 8, 16
B_JSON, B_IMPORT, B_OTA = 8 * 1024, 32 * 1024, 3 * 1024 * 1024
HIST_GAP = -32768
API_MD = ROOT / 'docs' / 'API.md'


# ---------------------------------------------------------------- path matching


def match(lib, pattern, path):
    p = WebParams()
    ok = lib.web_path_match(pattern.encode(), path.encode(), len(path.encode()), C.byref(p))
    params = {}
    if ok:
        for i in range(p.n):
            name = C.string_at(p.name[i], p.name_len[i]).decode()
            params[name] = p.value[i].value.decode()
    return ok, params


@pytest.mark.parametrize('pattern,path,params', [
    ('/api/v1/devices', '/api/v1/devices', {}),
    ('/api/v1/devices/{d}/live', '/api/v1/devices/0/live', {'d': '0'}),
    ('/api/v1/devices/{d}/registers/{addr}', '/api/v1/devices/3/registers/40012', {'d': '3', 'addr': '40012'}),
    ('/api/v1/users/{name}', '/api/v1/users/op.er-1_x~', {'name': 'op.er-1_x~'}),
    ('/api/v1/devices/{d}/history.csv', '/api/v1/devices/1/history.csv', {'d': '1'}),
    ('/', '/', {}),
])
def test_path_match(clib, pattern, path, params):
    assert match(clib, pattern, path) == (True, params)


@pytest.mark.parametrize('pattern,path', [
    ('/api/v1/devices', '/api/v1/devices/'),          # trailing slash is significant
    ('/api/v1/devices/', '/api/v1/devices'),
    ('/api/v1/devices', '/api/v1/Devices'),           # case-sensitive
    ('/api/v1/devices/{d}/live', '/api/v1/devices//live'),
    ('/api/v1/devices/{d}/live', '/api/v1/devices/0/live/x'),
    ('/api/v1/devices/{d}/live', '/api/v1/devices/0'),
    ('/api/v1/users/{name}', '/api/v1/users/a%20b'),   # no percent-decoding, '%' never matches
    ('/api/v1/users/{name}', '/api/v1/users/a b'),
    ('/api/v1/users/{name}', '/api/v1/users/' + 'x' * 32),  # value must be < WEB_PARAM_SZ
    ('/api/v1/devices/{d}/history', '/api/v1/devices/0/history.csv'),
    ('/a/{x}/{y}/{z}/{w}', '/a/1/2/3/4'),              # more than WEB_MAX_PARAMS captures
    ('/api', 'api'),
    ('', '/'),
    ('/x', ''),
])
def test_path_mismatch(clib, pattern, path):
    assert not match(clib, pattern, path)[0]


def test_path_match_length_bound_and_null_out(clib):
    path = b'/api/v1/devices?x=1'
    assert clib.web_path_match(b'/api/v1/devices', path, 15, None)
    assert match(clib, '/api/v1/users/{name}', '/api/v1/users/' + 'x' * 31) == (True, {'name': 'x' * 31})
    p = WebParams()
    assert clib.web_path_match(b'/a/{x}', b'/a/1', 4, C.byref(p))
    assert clib.web_params_get(C.byref(p), b'x') == b'1'
    assert clib.web_params_get(C.byref(p), b'y') is None
    assert clib.web_params_get(C.byref(p), b'') is None


# ---------------------------------------------------------------- url decoding, query, cookie, origin


def url_decode(lib, s, cap=64):
    out = C.create_string_buffer(cap)
    n = lib.web_url_decode(s, len(s), out, cap)
    return n, out.raw[:n] if n >= 0 else None


def test_url_decode(clib):
    assert url_decode(clib, b'a+b%20c%2F%e2%82%ac') == (9, b'a b c/\xe2\x82\xac')
    assert url_decode(clib, b'') == (0, b'')
    for bad in (b'%', b'%2', b'%zz', b'%0g', b'a%00b', b'%%41'):
        assert url_decode(clib, bad)[0] == -1, bad
    assert url_decode(clib, b'abcd', cap=4)[0] == -1  # needs room for the NUL
    assert url_decode(clib, b'abc', cap=4) == (3, b'abc')


def query(lib, q, key, cap=64):
    out = C.create_string_buffer(cap)
    ok = lib.web_query_get(q.encode(), key.encode(), out, cap)
    return out.value.decode() if ok else None


def test_query_get(clib):
    q = 'span=900&res=1&stages&from=&na%6De=x%20y&dup=1&dup=2'
    assert query(clib, q, 'span') == '900'
    assert query(clib, q, 'res') == '1'
    assert query(clib, q, 'stages') == ''
    assert query(clib, q, 'from') == ''
    assert query(clib, q, 'name') == 'x y'
    assert query(clib, q, 'dup') == '1'
    assert query(clib, q, 'spa') is None
    assert query(clib, q, 'missing') is None
    assert query(clib, 'a=%zz', 'a') is None
    assert query(clib, 'a=12345', 'a', cap=4) is None
    assert query(clib, '', 'a') is None


def cookie(lib, header, name, cap=32):
    out = C.create_string_buffer(cap)
    ok = lib.web_cookie_get(header.encode() if header is not None else None, name.encode(), out, cap)
    return out.value.decode() if ok else None


def test_cookie_get(clib):
    tok = 'q0Vb3mJ8sZ1xT5yR2wK9dA'
    assert cookie(clib, f'gw_sid={tok}', 'gw_sid') == tok
    assert cookie(clib, f'theme=dark; gw_sid={tok}; lang=ko', 'gw_sid') == tok
    assert cookie(clib, f'theme=dark;gw_sid={tok}', 'gw_sid') == tok
    assert cookie(clib, f' gw_sid = "{tok}" ', 'gw_sid') == tok
    assert cookie(clib, f'xgw_sid=evil; gw_sid2=evil2; gw_sid={tok}', 'gw_sid') == tok
    assert cookie(clib, 'xgw_sid=evil; gw_sid2=evil2', 'gw_sid') is None
    assert cookie(clib, 'gw_sid=' + 'x' * 40, 'gw_sid') is None          # too long for the buffer
    assert cookie(clib, 'gw_sid=', 'gw_sid') == ''
    assert cookie(clib, '', 'gw_sid') is None
    assert cookie(clib, None, 'gw_sid') is None
    assert cookie(clib, 'gw_sid', 'gw_sid') is None


@pytest.mark.parametrize('origin,host,ok', [
    ('http://192.168.10.150', '192.168.10.150', True),
    ('http://192.168.10.150:8080', '192.168.10.150:8080', True),
    ('HTTP://Mestio-GW-3456.local', 'mestio-gw-3456.local', True),
    ('https://192.168.10.150', '192.168.10.150', True),
    ('http://192.168.10.150/settings?x=1', '192.168.10.150', True),    # Referer form
    ('http://192.168.10.150#frag', '192.168.10.150', True),
    ('http://192.168.10.150', '192.168.10.150:80', False),             # strict authority equality
    ('http://192.168.10.150:8080', '192.168.10.150', False),
    ('http://evil.example', '192.168.10.150', False),
    ('http://192.168.10.150.evil.example', '192.168.10.150', False),
    ('http://user@192.168.10.150', '192.168.10.150', False),
    ('null', '192.168.10.150', False),
    ('ftp://192.168.10.150', '192.168.10.150', False),
    ('//192.168.10.150', '192.168.10.150', False),
    ('http://', '192.168.10.150', False),
    ('http://192.168.10.150', '', False),
])
def test_origin_matches_host(clib, origin, host, ok):
    assert clib.web_origin_matches_host(origin.encode(), host.encode()) is ok


def test_origin_null_args(clib):
    assert not clib.web_origin_matches_host(None, b'h')
    assert not clib.web_origin_matches_host(b'http://h', None)


# ---------------------------------------------------------------- small HTTP helpers


@pytest.mark.parametrize('ct,ok', [('application/json', True), ('Application/JSON; charset=utf-8', True),
                                   ('  application/json ;x', True), ('application/jsonx', False),
                                   ('text/plain', False), ('', False), ('application/json-patch+json', False)])
def test_ct_is_json(clib, ct, ok):
    assert clib.web_ct_is_json(ct.encode()) is ok


def test_ct_is_octet(clib):
    assert clib.web_ct_is_octet(b'application/octet-stream')
    assert not clib.web_ct_is_octet(b'application/json')
    assert not clib.web_ct_is_json(None)


@pytest.mark.parametrize('inm,ok', [('"abc"', True), ('W/"abc"', True), ('"x", "abc"', True), ('*', True),
                                    ('"abcd"', False), ('"ab"', False), ('', False), ('abc', False)])
def test_etag_match(clib, inm, ok):
    assert clib.web_etag_match(inm.encode(), b'"abc"') is ok


def test_status_lines(clib):
    for code, text in ((200, b'200 OK'), (204, b'204 No Content'), (304, b'304 Not Modified'),
                       (421, b'421 Misdirected Request'), (422, b'422 Unprocessable Content'), (423, b'423 Locked'),
                       (429, b'429 Too Many Requests'), (503, b'503 Service Unavailable'),
                       (999, b'500 Internal Server Error')):
        assert clib.web_status_line(code) == text


# ---------------------------------------------------------------- policy core


def decide(lib, min_role=VIEWER, flags=0, max_body=0, method=M_GET, authed=True, role=ADMIN, must_change=False,
           origin_present=False, origin_ok=False, csrf_ok=True, content_len=0, json_ct=True):
    r = RPolicy(min_role, flags, max_body)
    f = Facts(method, authed, role, must_change, origin_present, origin_ok, csrf_ok, content_len, json_ct)
    v = lib.web_policy_decide(C.byref(r), C.byref(f))
    return v.status, (v.code.decode() if v.code else None)


def test_policy_order(clib):
    ok = (0, None)
    assert decide(clib) == ok
    assert decide(clib, authed=False) == (401, 'unauthorized')
    assert decide(clib, min_role=ADMIN, role=OPERATOR) == (403, 'forbidden')
    assert decide(clib, must_change=True) == (403, 'password_change_required')
    assert decide(clib, must_change=True, flags=F_MC) == ok
    # role is checked before must_change, must_change before origin/csrf
    assert decide(clib, min_role=ADMIN, role=VIEWER, must_change=True) == (403, 'forbidden')
    assert decide(clib, method=M_POST, flags=F_CSRF, must_change=True, csrf_ok=False) == \
        (403, 'password_change_required')
    assert decide(clib, method=M_POST, flags=F_CSRF, csrf_ok=False) == (403, 'csrf')
    assert decide(clib, method=M_POST, flags=F_CSRF, origin_present=True, origin_ok=False) == (403, 'origin')
    assert decide(clib, method=M_POST, flags=F_CSRF, origin_present=True, origin_ok=True) == ok
    assert decide(clib, method=M_GET, origin_present=True, origin_ok=False) == ok   # only mutations
    assert decide(clib, method=M_DELETE, origin_present=True) == (403, 'origin')
    assert decide(clib, method=M_PUT, flags=F_CSRF, content_len=10, max_body=B_JSON) == ok
    assert decide(clib, method=M_PUT, flags=F_CSRF, content_len=B_JSON + 1, max_body=B_JSON) == \
        (413, 'payload_too_large')
    assert decide(clib, content_len=1, max_body=0) == (413, 'payload_too_large')
    assert decide(clib, method=M_PUT, content_len=10, max_body=B_JSON, json_ct=False) == (400, 'bad_request')
    assert decide(clib, method=M_POST, flags=F_RAW, content_len=10, max_body=B_OTA, json_ct=False) == ok


def test_policy_public_routes(clib):
    # login: public, mutating, no CSRF -> Origin still checked; a must_change session may log in again.
    login = dict(min_role=NONE, flags=F_SLOW, max_body=B_JSON, method=M_POST)
    assert decide(clib, authed=False, csrf_ok=False, content_len=40, **login) == (0, None)
    assert decide(clib, authed=True, must_change=True, csrf_ok=False, content_len=40, **login) == (0, None)
    assert decide(clib, authed=False, origin_present=True, origin_ok=False, content_len=40, **login) == \
        (403, 'origin')
    # a CSRF route can never pass without a session
    assert decide(clib, min_role=NONE, flags=F_CSRF, method=M_POST, authed=False, csrf_ok=True) == (403, 'csrf')


# ---------------------------------------------------------------- route table vs API.md


def api_md_routes():
    """{(method, path): (role, csrf, request_schema)} from API.md §3 (paths under /api/v1)."""
    text = API_MD.read_text(encoding='utf-8')
    sec = text.split('## 3. Endpoint index', 1)[1].split('## 4.', 1)[0]
    roles = {'—': NONE, '— (cookie)': NONE, 'cookie': VIEWER, 'viewer': VIEWER, 'operator': OPERATOR,
             'admin': ADMIN}
    out = {}
    for line in sec.splitlines():
        cols = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cols) != 7 or cols[0] in ('Method', '---') or cols[1] == '/ws':
            continue
        methods = [m.strip() for m in cols[0].split('/')]
        role_parts = [r.strip() for r in cols[2].split(' / ')] if ' / ' in cols[2] else [cols[2]]
        for i, m in enumerate(methods):
            role = roles[role_parts[i] if len(role_parts) > 1 else role_parts[0]]
            csrf = cols[3] == '✓' or cols[3] == f'{m} ✓'
            req = cols[4] if m != 'GET' else '—'
            out[(METHODS[m], '/api/v1' + cols[1])] = (role, csrf, req)
    return out


def route_table(lib):
    n = C.c_size_t.in_dll(lib, 'web_route_meta_count').value
    arr = (RouteMeta * n).in_dll(lib, 'web_route_meta')
    return [(r.method, r.pattern.decode(), r.min_role, r.flags, r.max_body, r.handler.decode()) for r in arr]


def test_route_table_matches_api_md(clib):
    doc = api_md_routes()
    table = route_table(clib)
    keys = [(m, p) for m, p, *_ in table]
    assert len(keys) == len(set(keys)), 'duplicate routes'
    assert set(keys) == set(doc), f'missing {set(doc) - set(keys)}, extra {set(keys) - set(doc)}'
    for m, p, role, flags, max_body, handler in table:
        drole, dcsrf, req = doc[(m, p)]
        assert role == drole, p
        assert bool(flags & F_CSRF) == dcsrf, p
        if m != M_GET and p != '/api/v1/auth/login':
            assert flags & F_CSRF, f'mutating route without CSRF: {p}'
        expect_body = {'—': 0, 'octet-stream': B_OTA, 'config-bundle': B_IMPORT}.get(req, B_JSON)
        assert max_body == expect_body, p
        assert bool(flags & F_RAW) == (req == 'octet-stream'), p
        assert re.fullmatch(r'h_[a-z_]+', handler)


def test_must_change_and_slow_flags(clib):
    table = route_table(clib)
    mc = {(m, p) for m, p, _, f, *_ in table if f & F_MC}
    assert mc == {(M_GET, '/api/v1/session'), (M_POST, '/api/v1/auth/password'), (M_POST, '/api/v1/auth/logout')}
    slow = {p for m, p, _, f, *_ in table if f & F_SLOW}
    # Every PBKDF2 / key-localization / blocking call runs on the async worker.
    for p in ('/api/v1/auth/login', '/api/v1/auth/password', '/api/v1/users', '/api/v1/users/{name}',
              '/api/v1/system/factory-reset', '/api/v1/config/snmp', '/api/v1/snmp/test-trap',
              '/api/v1/devices/{d}/registers/{addr}', '/api/v1/devices/{d}/run'):
        assert p in slow, p
    notouch = {p for m, p, _, f, *_ in table if f & F_NOTOUCH}
    assert notouch == {'/api/v1/session'}


ROLE_NAMES = {NONE: None, VIEWER: 'viewer', OPERATOR: 'operator', ADMIN: 'admin'}


def test_permission_matrix(clib):
    """Every route x every caller (anonymous, viewer, operator, admin, admin with must_change)."""
    for m, p, min_role, flags, max_body, _ in route_table(clib):
        body = 2 if max_body else 0
        for caller in (None, VIEWER, OPERATOR, ADMIN, 'mc'):
            authed = caller is not None
            role = ADMIN if caller == 'mc' else (caller or NONE)
            st, code = decide(clib, min_role=min_role, flags=flags, max_body=max_body, method=m, authed=authed,
                              role=role, must_change=caller == 'mc', csrf_ok=authed, content_len=body,
                              json_ct=not (flags & F_RAW))
            if min_role > NONE and not authed:
                assert (st, code) == (401, 'unauthorized'), (p, caller)
            elif min_role > NONE and role < min_role:
                assert (st, code) == (403, 'forbidden'), (p, caller)
            elif caller == 'mc' and min_role > NONE and not flags & F_MC:
                assert (st, code) == (403, 'password_change_required'), (p, caller)
            elif flags & F_CSRF and not authed:
                assert (st, code) == (403, 'csrf'), (p, caller)
            else:
                assert (st, code) == (0, None), (p, caller)


@pytest.mark.parametrize('method,path,handler', [
    (M_GET, '/api/v1/devices/2/live', 'h_device_live'),
    (M_PUT, '/api/v1/devices/0/registers/40012', 'h_register_write'),
    (M_GET, '/api/v1/devices/0/history.csv', 'h_device_history_csv'),
    (M_GET, '/api/v1/devices/0/history', 'h_device_history'),
    (M_GET, '/api/v1/config/general', 'h_config_section_get'),
    (M_PUT, '/api/v1/config/snmp', 'h_config_snmp_put'),
    (M_DELETE, '/api/v1/users/operator1', 'h_users_delete'),
    (M_POST, '/api/v1/system/firmware', 'h_firmware_upload'),
    (M_POST, '/api/v1/system/firmware/rollback', 'h_firmware_rollback'),
])
def test_route_find(clib, method, path, handler):
    i = clib.web_route_meta_find(method, path.encode(), len(path), None)
    assert i >= 0 and route_table(clib)[i][5] == handler


def test_route_find_default_deny(clib):
    mm = C.c_bool()
    for method, path, mismatch in [(M_DELETE, '/api/v1/devices', True), (M_GET, '/api/v1/auth/login', True),
                                   (M_GET, '/api/v1/unknown', False), (M_GET, '/api/v1/devices/', False),
                                   (M_GET, '/api/v1/system/coredump.elf', False), (M_GET, '/api/v2/devices', False)]:
        assert clib.web_route_meta_find(method, path.encode(), len(path), C.byref(mm)) == -1, path
        assert mm.value is mismatch, path


# ---------------------------------------------------------------- JSON builders


def test_error_json(clib):
    v = schema_validator('error')
    for args in ((b'validation', b'must be within 5.0..50.0', b'thr'), (b'not_found', None, None)):
        w = Writer(clib)
        clib.web_json_error(w.ptr, *args)
        doc = w.json()
        v.validate(doc)
        assert doc['error'] == args[0].decode()
        assert ('message' in doc) is (args[1] is not None) and ('field' in doc) is (args[2] is not None)


def test_write_range_rejected_json(clib):
    """409 for {"value": 23.45} on a x10 register: write-result schema, no "message" member."""
    w = Writer(clib)
    clib.web_json_write_range_rejected(w.ptr, 40015)
    doc = w.json()
    schema_validator('write-result.response').validate(doc)
    assert doc == {'error': 'rejected', 'state': 'rejected', 'cmd': 0, 'addr': 40015, 'reason': 'range'}


def meta_alarms_etag(lib, build, sev):
    out = C.create_string_buffer(40)
    arr = (C.c_uint8 * max(len(sev), 1))(*sev)
    lib.web_meta_alarms_etag(out, build, arr, len(sev))
    return out.value.decode()


def test_meta_alarms_etag(clib):
    def fnv(data):
        h = 2166136261
        for b in data:
            h = ((h ^ b) * 16777619) & 0xFFFFFFFF
        return h
    sev = [1, 2, 3, 0, 2]
    e = meta_alarms_etag(clib, b'0123456789abcdef', sev)
    assert e == f'"0123456789ab-a{fnv(sev):08x}"'                 # build id truncated to 12
    assert meta_alarms_etag(clib, b'0123456789abcdef', [1, 2, 3, 0, 3]) != e   # sev_override changes it
    assert meta_alarms_etag(clib, b'fedcba987654', sev) != e                   # new build changes it
    assert meta_alarms_etag(clib, b'', []) == '"-a811c9dc5"'
    assert clib.web_etag_match(e.encode(), e.encode())


def test_policy_rules_json(clib):
    w = Writer(clib)
    clib.web_json_policy_rules(w.ptr, 1 | 4 | 32 | 0x80)
    assert w.json() == ['min_length', 'classes', 'not_previous']


def series(n, values):
    return (C.c_int16 * n)(*values)


def test_history_json_fast_and_slow(clib):
    v = schema_validator('history.response')
    n = 4
    avg = [series(n, [235, 235, HIST_GAP, 236]), series(n, [480, 481, HIST_GAP, 481]),
           series(n, [42, 42, HIST_GAP, 41]), series(n, [230] * 2 + [HIST_GAP, 230]),
           series(n, [500, 500, HIST_GAP, 500])]
    stage = [(C.c_uint16 * n)(1, 1, 0xFFFF, 1) for _ in range(5)]
    s = HistSeries()
    s.n_max, s.n, s.dt_s, s.t0_ms, s.t0_age_ms = n, n, 1, 1792371540000, 4120
    for i in range(5):
        s.avg[i] = C.cast(avg[i], C.POINTER(C.c_int16))
        s.stage[i] = C.cast(stage[i], C.POINTER(C.c_uint16))
    w = Writer(clib)
    clib.web_json_history(w.ptr, C.byref(s), False, True)
    doc = w.json()
    v.validate(doc)
    assert doc['ch']['temp'] == [235, 235, None, 236] and doc['t0'] == 1792371540000
    assert doc['stages']['cool'] == [1, 1, None, 1] and 'min' not in doc

    mins = [series(n, [232, 233, 1, 2]) for _ in range(3)]
    maxs = [series(n, [236, 237, 3, 4]) for _ in range(3)]
    for i in range(3):
        s.min[i] = C.cast(mins[i], C.POINTER(C.c_int16))
        s.max[i] = C.cast(maxs[i], C.POINTER(C.c_int16))
    s.dt_s, s.t0_ms = 60, 0
    w = Writer(clib)
    clib.web_json_history(w.ptr, C.byref(s), True, False)
    doc = w.json()
    v.validate(doc)
    assert doc['t0'] is None and doc['dt'] == 60 and doc['min']['temp'][:2] == [232, 233]
    assert set(doc['max']) == {'temp', 'hum', 'cur'} and 'stages' not in doc


def test_history_json_large(clib):
    """1500 points x 5 channels + min/max fit a streaming writer; here a big fixed buffer."""
    n = 1500
    data = [series(n, [(i % 600) - 300 if i % 97 else HIST_GAP for i in range(n)]) for _ in range(11)]
    s = HistSeries()
    s.n_max, s.n, s.dt_s, s.t0_ms, s.t0_age_ms = n, n, 60, 1, 0
    for i in range(5):
        s.avg[i] = C.cast(data[i], C.POINTER(C.c_int16))
    for i in range(3):
        s.min[i] = C.cast(data[5 + i], C.POINTER(C.c_int16))
        s.max[i] = C.cast(data[8 + i], C.POINTER(C.c_int16))
    w = Writer(clib, cap=200_000)
    clib.web_json_history(w.ptr, C.byref(s), True, False)
    doc = w.json()
    schema_validator('history.response').validate(doc)
    assert len(doc['ch']['sh']) == n and doc['ch']['temp'][97] is None


def test_wstate_names(clib):
    assert [clib.web_wstate_name(i) for i in range(4)] == [b'pending', b'applied', b'rejected', b'uncertain']


# ---------------------------------------------------------------- CSV


def csv_row(lib, ts, row, agg):
    out = C.create_string_buffer(192)
    n = lib.web_csv_hist_row(out, 192, ts, C.byref(row), agg)
    assert n == len(out.value)
    return out.value.decode()


def test_csv_history(clib):
    out = C.create_string_buffer(128)
    assert clib.web_csv_hist_header(out, 128, False) > 0
    assert out.value == b'time,temp,hum,current,set_temp,set_hum\r\n'
    clib.web_csv_hist_header(out, 128, True)
    assert out.value == (b'time,temp,hum,current,set_temp,set_hum,temp_min,temp_max,hum_min,hum_max,'
                         b'current_min,current_max\r\n')
    r = HistSlow(tavg=235, havg=480, cavg=42, st=230, sh=500, samples=60, tmin=-5, tmax=240, hmin=470,
                 hmax=490, cmin=0, cmax=HIST_GAP)
    assert csv_row(clib, 1792371540000, r, False) == '2026-10-19T00:59:00.000Z,23.5,48.0,4.2,23.0,50.0\r\n'
    assert csv_row(clib, 1792371540000, r, True) == \
        '2026-10-19T00:59:00.000Z,23.5,48.0,4.2,23.0,50.0,-0.5,24.0,47.0,49.0,0.0,\r\n'
    gap = HistSlow(tavg=1, samples=0)
    assert csv_row(clib, 0, gap, True) == ',,,,,,,,,,,\r\n'
    neg = HistSlow(tavg=-250, havg=0, cavg=999, st=HIST_GAP, sh=5, samples=1)
    assert csv_row(clib, 1, neg, False) == '1970-01-01T00:00:00.001Z,-25.0,0.0,99.9,,0.5\r\n'
    small = C.create_string_buffer(10)
    assert clib.web_csv_hist_row(small, 10, 0, C.byref(r), False) == -1


def test_csv_alarm(clib):
    out = C.create_string_buffer(192)
    assert clib.web_csv_alarm_header(out, 192) > 0
    assert out.value == b'seq,time,dev,id,code,type,sev,value,user\r\n'
    n = clib.web_csv_alarm_row(out, 192, 912, 1792371100000, 0, b'high_temp', 127, b'ack', 2, 312, b'operator1')
    assert out.value == b'912,2026-10-19T00:51:40.000Z,0,high_temp,127,ack,2,312,operator1\r\n' and n == len(out.value)
    clib.web_csv_alarm_row(out, 192, 1, 0, 3, b'comm_lost', 301, b'raise', 2, -5, None)
    assert out.value == b'1,,3,comm_lost,301,raise,2,-5,\r\n'


@pytest.mark.parametrize('field,expect', [('plain', 'plain'), ('a,b', '"a,b"'), ('say "hi"', '"say ""hi"""'),
                                          ('=1+2', "'=1+2"), ('-x', "'-x"), ('@cmd', "'@cmd"), ('+,x', '"\'+,x"'),
                                          ('line\nbreak', '"line\nbreak"'), ('', '')])
def test_csv_field_escaping(clib, field, expect):
    out = C.create_string_buffer(64)
    ln = C.c_size_t(0)
    assert clib.web_csv_field(out, 64, C.byref(ln), field.encode())
    assert out.value.decode() == expect and ln.value == len(expect)


def test_csv_field_overflow(clib):
    out = C.create_string_buffer(4)
    ln = C.c_size_t(0)
    assert not clib.web_csv_field(out, 4, C.byref(ln), b'abcd')
    assert clib.web_csv_field(out, 4, C.byref(ln), None)


# ---------------------------------------------------------------- WebSocket frames


@pytest.fixture(scope='module')
def ws_schema():
    return schema_validator('ws-server')


def snap(lib, st, regs, coils, seq=1, now=0, force=False, online=True, ts=1792371601000):
    addrs = (C.c_uint16 * len(regs))(*regs.keys())
    raws = (C.c_int32 * len(regs))(*regs.values())
    w = Writer(lib)
    assert lib.ws_frame_snap(C.byref(st), w.ptr, 0, seq, ts, online, addrs, raws, len(regs), coils, force, now,
                             30) == 0
    return w.json()


def test_snap_full_then_delta_then_periodic_full(clib, ws_schema):
    st = SnapState()
    regs = {40005: 1, 40012: 230, 40036: 235, 40037: 480}
    f = snap(clib, st, regs, 2051, seq=1, now=1000)
    ws_schema.validate(f)
    assert f['full'] and f['r'] == {str(k): v for k, v in regs.items()} and f['c'] == 2051
    regs[40036] = 236
    d = snap(clib, st, regs, 2051, seq=2, now=2000)
    ws_schema.validate(d)
    assert not d['full'] and d['r'] == {'40036': 236} and 'c' not in d
    d = snap(clib, st, regs, 2049, seq=3, now=3000)
    assert d['r'] == {} and d['c'] == 2049
    regs[40027] = 300  # slow register appears once slow_valid
    d = snap(clib, st, regs, 2049, seq=4, now=4000)
    assert d['r'] == {'40027': 300}
    d = snap(clib, st, regs, 2049, seq=5, now=31_000)  # 30 s after the last full frame
    assert d['full'] and len(d['r']) == 5 and d['c'] == 2049
    d = snap(clib, st, regs, 2049, seq=6, now=32_000, force=True)  # new subscriber
    assert d['full']
    d = snap(clib, st, regs, 2049, seq=7, now=33_000, online=False, ts=0)
    ws_schema.validate(d)
    assert d['ts'] is None and d['on'] is False and not d['full']


def test_snap_negative_raw_and_reset(clib, ws_schema):
    st = SnapState()
    f = snap(clib, st, {40021: -5, 40036: -250}, 0)
    ws_schema.validate(f)
    assert f['r'] == {'40021': -5, '40036': -250}
    st.valid = False  # a frame was lost -> next one is full
    assert snap(clib, st, {40021: -5, 40036: -250}, 0, now=10)['full']


def build(lib, fn, *args):
    w = Writer(lib)
    fn(w.ptr, *args)
    return w.json()


def test_frames_validate(clib, ws_schema):
    frames = [
        build(clib, clib.ws_frame_alarm, 0, b'high_temp', 127, 1, 2, 1792371000000, 911, 312, None),
        build(clib, clib.ws_frame_alarm, 1, b'comm_lost', 301, 2, 2, 0, 5, 1, b''),
        build(clib, clib.ws_frame_alarm, 0, b'high_temp', 127, 3, 2, 1792371100000, 912, 312, b'operator1'),
        build(clib, clib.ws_frame_write, 0, 17, 40012, 1, True, 235, None, b'admin'),
        build(clib, clib.ws_frame_write, 0, 0, 40021, 2, False, 0, b'running_interlock', b'@snmp'),
        build(clib, clib.ws_frame_write, 0, 18, 40012, 3, True, 236, b'verify_mismatch', b'@console'),
        build(clib, clib.ws_frame_comm, 0, True, 42, 2, 7, 0, 0),
        build(clib, clib.ws_frame_comm, 3, False, 70000, 0, 0, 0, 0),
        build(clib, clib.ws_frame_sys, 98304, 71680, 7340032, 86400, 1792371600000, 2),
        build(clib, clib.ws_frame_sys, 1, 1, 0, 0, 0, 999),
        build(clib, clib.ws_frame_bye, b'session_expired'),
        build(clib, clib.ws_frame_bye, b'revoked'),
        build(clib, clib.ws_frame_pong, 1792371600123),
        build(clib, clib.ws_frame_pong, 0),
        build(clib, clib.ws_frame_hello, 1792371600000, (C.c_uint8 * 2)(0, 2), (C.c_uint32 * 2)(1234, 7), 2,
              b'"b1f3c2a9-1"'),
        build(clib, clib.ws_frame_hello, 0, None, None, 0, b'"x"'),
    ]
    for f in frames:
        ws_schema.validate(f)
    assert frames[0]['key'] == '0:high_temp' and 'user' not in frames[0]
    assert frames[1]['ts'] is None and frames[2]['user'] == 'operator1'
    assert 'reason' not in frames[3] and frames[4]['reason'] == 'running_interlock' and 'raw' not in frames[4]
    assert frames[7]['rtt'] == 65535 and frames[9]['alarms'] == 200
    assert frames[14]['seq'] == {'0': 1234, '2': 7} and frames[14]['devs'] == [0, 2]
    assert frames[15]['srv'] is None and frames[13]['srv'] is None


@pytest.mark.parametrize('msg,kind,topics', [
    ('{"t":"sub","topics":["snap","alarm","comm","write","sys"]}', 1, 0x1F),
    ('{"t":"sub","topics":[]}', 1, 0),
    ('{"t":"sub","topics":["alarm","bogus",3,"alarm"]}', 1, 0x02),
    ('{"t":"ping"}', 2, None),
    ('{"t":"other"}', 0, None),
    ('{"x":1}', 0, None),
    ('{"t":"sub"}', -1, None),
    ('{"t":"sub","topics":"snap"}', -1, None),
    ('[1,2]', -1, None),
    ('not json', -1, None),
    ('', -1, None),
])
def test_parse_client(clib, msg, kind, topics):
    t = C.c_uint32(0xDEAD)
    raw = msg.encode()
    assert clib.ws_parse_client(raw, len(raw), C.byref(t)) == kind
    if topics is not None:
        assert t.value == topics
