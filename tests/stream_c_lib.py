"""Shared host build + ctypes declarations for the web/auth/gw_b64 tests (stream C).

The library is GW_HOST_SOURCES_GW_CORE + AUTH + WEB (+ gw_json_writer.c if the gw_core list does not
carry it yet) + the host crypto backend + cJSON, so only these lists can break these tests.
Struct mirrors below are checked against the C layout by test_auth_core.py::test_struct_layouts.
"""
import ctypes as C
import json
from pathlib import Path

import pytest

from conftest import LISTS, ROOT, _build_so

GW_MAX_SESSIONS = 8
AUTH_RL_IP_SLOTS = 16
AUTH_TOKEN_SZ = 23
AUTH_CSRF_SZ = 23
USER_SZ = 12


def stream_c_sources():
    core = list(LISTS.get('GW_HOST_SOURCES_GW_CORE', []))
    jw = 'components/gw_core/gw_json_writer.c'
    if jw not in core:
        core.append(jw)
    names = core + LISTS.get('GW_HOST_SOURCES_AUTH', []) + LISTS.get('GW_HOST_SOURCES_WEB', []) + \
        LISTS.get('GW_HOST_ONLY_SOURCES', [])
    return [ROOT / p for p in dict.fromkeys(names)]


class RlSlot(C.Structure):
    _fields_ = [('ip', C.c_uint32), ('fails', C.c_uint8), ('locks', C.c_uint8), ('fail_user', C.c_uint32),
                ('window_start_ms', C.c_uint64), ('locked_until_ms', C.c_uint64), ('last_ms', C.c_uint64)]


class Rl(C.Structure):
    _fields_ = [('max_fail', C.c_uint8), ('lock_min', C.c_uint8), ('slot', RlSlot * AUTH_RL_IP_SLOTS),
                ('global_fails', C.c_uint32), ('global_minute_start_ms', C.c_uint64)]


class SessSlot(C.Structure):
    _fields_ = [('used', C.c_bool), ('gen', C.c_uint32), ('tok_hash', C.c_uint8 * 32), ('user', C.c_char * USER_SZ),
                ('role', C.c_int), ('must_change', C.c_bool), ('csrf', C.c_char * AUTH_CSRF_SZ),
                ('created_ms', C.c_uint64), ('last_ms', C.c_uint64)]


class SessTable(C.Structure):
    _fields_ = [('slot', SessSlot * GW_MAX_SESSIONS), ('next_gen', C.c_uint32), ('idle_s', C.c_uint32),
                ('abs_s', C.c_uint32)]


class SessInfo(C.Structure):
    _fields_ = [('sid', C.c_uint32), ('user', C.c_char * USER_SZ), ('role', C.c_int), ('must_change', C.c_bool),
                ('csrf', C.c_char * AUTH_CSRF_SZ), ('idle_left_s', C.c_uint32), ('abs_left_s', C.c_uint32),
                ('idle_s', C.c_uint32)]


class SessEnd(C.Structure):
    _fields_ = [('sid', C.c_uint32), ('kind', C.c_uint8), ('user', C.c_char * USER_SZ)]


SESS_END_MAX = GW_MAX_SESSIONS + 1


class Facts(C.Structure):
    _fields_ = [('method', C.c_int), ('authed', C.c_bool), ('role', C.c_int), ('must_change', C.c_bool),
                ('origin_present', C.c_bool), ('origin_ok', C.c_bool), ('csrf_ok', C.c_bool),
                ('content_len', C.c_uint64), ('content_type_json', C.c_bool)]


class RPolicy(C.Structure):
    _fields_ = [('min_role', C.c_int), ('flags', C.c_uint8), ('max_body', C.c_uint32)]


class Verdict(C.Structure):
    _fields_ = [('status', C.c_int), ('code', C.c_char_p)]


class RouteMeta(C.Structure):
    _fields_ = [('method', C.c_int), ('pattern', C.c_char_p), ('min_role', C.c_int), ('flags', C.c_uint8),
                ('max_body', C.c_uint32), ('handler', C.c_char_p)]


class WebParams(C.Structure):
    _fields_ = [('n', C.c_uint8), ('name', C.c_char_p * 3), ('name_len', C.c_uint8 * 3),
                ('value', (C.c_char * 32) * 3)]


class JsonWriter(C.Structure):
    """gw_jw_t mirror (sized generously; only passed by pointer)."""
    _fields_ = [('buf', C.c_void_p), ('len', C.c_size_t), ('cap', C.c_size_t), ('max_cap', C.c_size_t),
                ('total', C.c_size_t), ('sink', C.c_void_p), ('sink_arg', C.c_void_p), ('comma', C.c_uint32),
                ('is_obj', C.c_uint32), ('depth', C.c_uint8), ('mode', C.c_uint8), ('after_key', C.c_bool),
                ('err', C.c_int), ('_pad', C.c_uint8 * 64)]


class HistSlow(C.Structure):
    _fields_ = [('ts_s', C.c_uint32), ('tmin', C.c_int16), ('tavg', C.c_int16), ('tmax', C.c_int16),
                ('hmin', C.c_int16), ('havg', C.c_int16), ('hmax', C.c_int16),
                ('cmin', C.c_int16), ('cavg', C.c_int16), ('cmax', C.c_int16),
                ('st', C.c_int16), ('sh', C.c_int16), ('samples', C.c_uint8), ('flags', C.c_uint8),
                ('stage_on_s', C.c_uint8 * 5), ('reserved', C.c_uint8), ('alarm_mask', C.c_uint32)]


class HistSeries(C.Structure):
    _fields_ = [('n_max', C.c_uint32), ('avg', C.POINTER(C.c_int16) * 5), ('min', C.POINTER(C.c_int16) * 5),
                ('max', C.POINTER(C.c_int16) * 5), ('stage', C.POINTER(C.c_uint16) * 5), ('t0_ms', C.c_int64),
                ('t0_age_ms', C.c_uint64), ('dt_s', C.c_uint32), ('n', C.c_uint32)]


class SnapState(C.Structure):
    _fields_ = [('valid', C.c_bool), ('coils', C.c_uint32), ('n', C.c_uint8), ('addr', C.c_uint16 * 64),
                ('raw', C.c_int32 * 64), ('last_full_mono_ms', C.c_uint64)]


def declare(lib):
    """Set argtypes/restype for every function the tests call."""
    sig = {
        # gw_core
        'gw_crypto_init': ([], C.c_int),
        'gw_b64_encode': ([C.c_void_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_int], C.c_int),
        'gw_b64_decode': ([C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_int], C.c_int),
        'gw_hex_encode': ([C.c_void_p, C.c_size_t, C.c_char_p, C.c_size_t], C.c_int),
        'gw_hex_decode': ([C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t], C.c_int),
        'gw_jw_init_fixed': ([C.c_void_p, C.c_char_p, C.c_size_t], None),
        'gw_jw_finish': ([C.c_void_p], C.c_int),
        'gw_jw_length': ([C.c_void_p], C.c_size_t),
        # auth: records / policy / names / status
        'auth_pw_hash_salt': ([C.c_char_p, C.c_uint32, C.c_char_p, C.c_char_p, C.c_size_t], C.c_int),
        'auth_pw_hash': ([C.c_char_p, C.c_uint32, C.c_char_p, C.c_size_t], C.c_int),
        'auth_pw_parse': ([C.c_char_p, C.POINTER(C.c_uint32), C.c_char_p, C.c_char_p], C.c_bool),
        'auth_pw_verify': ([C.c_char_p, C.c_char_p], C.c_bool),
        'auth_pw_record_iterations': ([C.c_char_p], C.c_uint32),
        'auth_policy_check': ([C.c_char_p, C.c_char_p], C.c_uint32),
        'auth_policy_rule_name': ([C.c_uint32], C.c_char_p),
        'auth_name_valid': ([C.c_char_p], C.c_bool),
        'auth_http_status': ([C.c_int], C.c_int),
        'auth_status_code': ([C.c_int], C.c_char_p),
        # auth: rate limiter
        'auth_rl_init': ([C.POINTER(Rl), C.c_uint8, C.c_uint8], None),
        'auth_rl_check': ([C.POINTER(Rl), C.c_uint32, C.c_uint64], C.c_uint32),
        'auth_rl_record': ([C.POINTER(Rl), C.c_uint32, C.c_uint32, C.c_bool, C.c_uint64], C.c_uint32),
        'auth_rl_user_key': ([C.c_char_p], C.c_uint32),
        'auth_rl_global_delay_ms': ([C.POINTER(Rl), C.c_uint64], C.c_uint32),
        # auth: session table
        'auth_st_init': ([C.POINTER(SessTable), C.c_uint32, C.c_uint32], None),
        'auth_st_set_idle': ([C.POINTER(SessTable), C.c_uint32], None),
        'auth_st_expire': ([C.POINTER(SessTable), C.c_uint64, C.POINTER(SessEnd), C.POINTER(C.c_size_t)], None),
        'auth_st_create': ([C.POINTER(SessTable), C.c_char_p, C.c_int, C.c_bool, C.c_uint64, C.c_char_p,
                            C.c_char_p, C.c_char_p, C.POINTER(SessInfo), C.POINTER(SessEnd),
                            C.POINTER(C.c_size_t)], C.c_bool),
        'auth_st_lookup': ([C.POINTER(SessTable), C.c_char_p, C.c_bool, C.c_uint64, C.POINTER(SessInfo),
                            C.POINTER(SessEnd), C.POINTER(C.c_size_t)], C.c_int),
        'auth_st_check': ([C.POINTER(SessTable), C.c_uint32, C.c_uint64, C.POINTER(SessInfo), C.POINTER(SessEnd),
                           C.POINTER(C.c_size_t)], C.c_int),
        'auth_st_csrf_ok': ([C.POINTER(SessTable), C.c_uint32, C.c_char_p], C.c_bool),
        'auth_st_remove': ([C.POINTER(SessTable), C.c_uint32, C.c_uint8, C.POINTER(SessEnd),
                            C.POINTER(C.c_size_t)], C.c_bool),
        'auth_st_revoke_user': ([C.POINTER(SessTable), C.c_char_p, C.c_uint32, C.POINTER(SessEnd),
                                 C.POINTER(C.c_size_t)], C.c_size_t),
        'auth_st_set_must_change': ([C.POINTER(SessTable), C.c_uint32, C.c_bool], C.c_bool),
        'auth_st_count': ([C.POINTER(SessTable)], C.c_size_t),
        # web: path helpers
        'web_path_match': ([C.c_char_p, C.c_char_p, C.c_size_t, C.POINTER(WebParams)], C.c_bool),
        'web_params_get': ([C.POINTER(WebParams), C.c_char_p], C.c_char_p),
        'web_url_decode': ([C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t], C.c_int),
        'web_query_get': ([C.c_char_p, C.c_char_p, C.c_char_p, C.c_size_t], C.c_bool),
        'web_cookie_get': ([C.c_char_p, C.c_char_p, C.c_char_p, C.c_size_t], C.c_bool),
        'web_origin_matches_host': ([C.c_char_p, C.c_char_p], C.c_bool),
        # web: policy / routes / http helpers
        'web_policy_decide': ([C.POINTER(RPolicy), C.POINTER(Facts)], Verdict),
        'web_ct_is_json': ([C.c_char_p], C.c_bool),
        'web_ct_is_octet': ([C.c_char_p], C.c_bool),
        'web_etag_match': ([C.c_char_p, C.c_char_p], C.c_bool),
        'web_status_line': ([C.c_int], C.c_char_p),
        'web_route_meta_find': ([C.c_int, C.c_char_p, C.c_size_t, C.POINTER(C.c_bool)], C.c_int),
        # web: JSON / CSV builders
        'web_json_error': ([C.c_void_p, C.c_char_p, C.c_char_p, C.c_char_p], None),
        'web_json_history': ([C.c_void_p, C.POINTER(HistSeries), C.c_bool, C.c_bool], None),
        'web_json_policy_rules': ([C.c_void_p, C.c_uint32], None),
        'web_json_write_range_rejected': ([C.c_void_p, C.c_uint16], None),
        'web_meta_alarms_etag': ([C.c_char_p, C.c_char_p, C.POINTER(C.c_uint8), C.c_size_t], None),
        'web_wstate_name': ([C.c_int], C.c_char_p),
        'web_csv_hist_header': ([C.c_char_p, C.c_size_t, C.c_bool], C.c_int),
        'web_csv_hist_row': ([C.c_char_p, C.c_size_t, C.c_int64, C.POINTER(HistSlow), C.c_bool], C.c_int),
        'web_csv_alarm_header': ([C.c_char_p, C.c_size_t], C.c_int),
        'web_csv_alarm_row': ([C.c_char_p, C.c_size_t, C.c_uint32, C.c_int64, C.c_uint, C.c_char_p, C.c_uint,
                               C.c_char_p, C.c_uint, C.c_int, C.c_char_p], C.c_int),
        'web_csv_field': ([C.c_char_p, C.c_size_t, C.POINTER(C.c_size_t), C.c_char_p], C.c_bool),
        # web: WS frames
        'ws_frame_snap': ([C.POINTER(SnapState), C.c_void_p, C.c_uint8, C.c_uint32, C.c_int64, C.c_bool,
                           C.POINTER(C.c_uint16), C.POINTER(C.c_int32), C.c_size_t, C.c_uint32, C.c_bool,
                           C.c_uint64, C.c_uint32, C.c_bool], C.c_int),
        'ws_frame_alarm': ([C.c_void_p, C.c_uint8, C.c_char_p, C.c_uint, C.c_uint, C.c_uint, C.c_int64,
                            C.c_uint32, C.c_int, C.c_char_p], None),
        'ws_frame_write': ([C.c_void_p, C.c_uint8, C.c_uint32, C.c_uint, C.c_int, C.c_bool, C.c_int32, C.c_char_p,
                            C.c_char_p], None),
        'ws_frame_comm': ([C.c_void_p, C.c_uint8, C.c_bool, C.c_uint, C.c_uint32, C.c_uint32, C.c_uint32,
                           C.c_uint32], None),
        'ws_frame_sys': ([C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32, C.c_int64, C.c_uint32], None),
        'ws_frame_hello': ([C.c_void_p, C.c_int64, C.POINTER(C.c_uint8), C.POINTER(C.c_uint32), C.c_size_t,
                            C.c_char_p], None),
        'ws_frame_bye': ([C.c_void_p, C.c_char_p], None),
        'ws_frame_pong': ([C.c_void_p, C.c_int64], None),
        'ws_parse_client': ([C.c_char_p, C.c_size_t, C.POINTER(C.c_uint32)], C.c_int),
    }
    for name, (args, res) in sig.items():
        fn = getattr(lib, name)
        fn.argtypes = args
        fn.restype = res
    assert lib.gw_crypto_init() == 0
    return lib


@pytest.fixture(scope='session')
def clib(tmp_path_factory, third_party_objs):
    lib = _build_so(tmp_path_factory.mktemp('stream_c') / 'libgw_stream_c.so', stream_c_sources(), third_party_objs)
    return declare(lib)


class Writer:
    """Fixed-buffer gw_jw writer for builder tests: w = Writer(lib); fn(w.ptr, ...); w.json()."""

    def __init__(self, lib, cap=8192):
        self.lib = lib
        self.jw = JsonWriter()
        self.buf = C.create_string_buffer(cap)
        lib.gw_jw_init_fixed(C.byref(self.jw), self.buf, cap)

    @property
    def ptr(self):
        return C.byref(self.jw)

    def text(self):
        assert self.lib.gw_jw_finish(self.ptr) == 0, 'json writer error'
        return self.buf.value.decode('utf-8')

    def json(self):
        return json.loads(self.text())


def schema_validator(name):
    """Draft 2020-12 validator for docs/api/<name>.schema.json with every schema registered."""
    jsonschema = pytest.importorskip('jsonschema')
    from referencing import Registry, Resource
    schemas = [json.loads(p.read_text(encoding='utf-8')) for p in sorted((ROOT / 'docs' / 'api').glob('*.json'))]
    reg = Registry().with_resources([(s['$id'], Resource.from_contents(s)) for s in schemas])
    target = next(s for s in schemas if s['$id'].endswith(f'/{name}.schema.json'))
    return jsonschema.Draft202012Validator(target, registry=reg)


def struct_layout_program():
    """C program printing sizeof/offsetof of the mirrored structs."""
    return r'''
#include <stddef.h>
#include <stdio.h>
#include "auth/auth.h"
#include "auth_priv.h"
#include "web_core.h"
#include "web/web_path.h"
#include "gw_core/gw_json_writer.h"
#define P(name, expr) printf("%s %zu\n", name, (size_t)(expr));
int main(void) {
    P("Rl", sizeof(auth_rl_t)); P("RlSlot", sizeof(auth_rl_slot_t));
    P("SessTable", sizeof(auth_sess_table_t)); P("SessSlot", sizeof(auth_sess_slot_t));
    P("SessInfo", sizeof(auth_session_info_t)); P("SessEnd", sizeof(auth_sess_end_t));
    P("Facts", sizeof(web_facts_t)); P("RPolicy", sizeof(web_rpolicy_t)); P("Verdict", sizeof(web_verdict_t));
    P("RouteMeta", sizeof(web_route_meta_t)); P("WebParams", sizeof(web_params_t));
    P("HistSlow", sizeof(hist_slow_t)); P("HistSeries", sizeof(hist_series_t)); P("SnapState", sizeof(ws_snap_state_t));
    P("JsonWriterMax", sizeof(gw_jw_t));
    P("SessInfo.csrf", offsetof(auth_session_info_t, csrf)); P("SessInfo.idle_s", offsetof(auth_session_info_t, idle_s));
    P("HistSeries.t0_ms", offsetof(hist_series_t, t0_ms)); P("SnapState.last_full_mono_ms", offsetof(ws_snap_state_t, last_full_mono_ms));
    return 0;
}
'''


def private_include_flags():
    return [f'-I{ROOT / "components" / "auth"}', f'-I{ROOT / "components" / "web"}']
