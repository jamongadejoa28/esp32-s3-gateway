"""auth pure core (components/auth: password.c, policy.c, ratelimit.c, session_table.c) on the host.

PBKDF2 runs on the OpenSSL backend (crypto_openssl.c); records are cross-checked with hashlib.
Rate limiter and session table use an injected monotonic clock (milliseconds).
"""
import base64
import ctypes as C
import hashlib
import os
import re

import pytest

from conftest import compile_and_run
from stream_c_lib import (SESS_END_MAX, Rl, SessEnd, SessInfo, SessTable, clib,  # noqa: F401
                          private_include_flags, struct_layout_program)
import stream_c_lib as S

VIEWER, OPERATOR, ADMIN = 1, 2, 3
AUTH_OK, E_BAD_CRED, E_LOCKED, E_NO_SESSION = 0, 1, 2, 3
END_LOGOUT, END_EXPIRED, END_REVOKED = 1, 2, 3
MIN = 60_000

TOO_SHORT, TOO_LONG, CLASSES, EQ_USER, FACTORY, REUSED, CHARSET = 1, 2, 4, 8, 16, 32, 64


# ---------------------------------------------------------------- layouts


def test_struct_layouts(tmp_path):
    out = compile_and_run(tmp_path, struct_layout_program(), flags=private_include_flags())
    sizes = dict(line.split() for line in out.splitlines())
    expect = {'Rl': C.sizeof(S.Rl), 'RlSlot': C.sizeof(S.RlSlot), 'SessTable': C.sizeof(S.SessTable),
              'SessSlot': C.sizeof(S.SessSlot), 'SessInfo': C.sizeof(S.SessInfo), 'SessEnd': C.sizeof(S.SessEnd),
              'Facts': C.sizeof(S.Facts), 'RPolicy': C.sizeof(S.RPolicy), 'Verdict': C.sizeof(S.Verdict),
              'RouteMeta': C.sizeof(S.RouteMeta), 'WebParams': C.sizeof(S.WebParams),
              'HistSlow': C.sizeof(S.HistSlow), 'HistSeries': C.sizeof(S.HistSeries),
              'SnapState': C.sizeof(S.SnapState), 'SessInfo.csrf': S.SessInfo.csrf.offset,
              'SessInfo.idle_s': S.SessInfo.idle_s.offset, 'HistSeries.t0_ms': S.HistSeries.t0_ms.offset,
              'SnapState.last_full_mono_ms': S.SnapState.last_full_mono_ms.offset}
    for k, v in expect.items():
        assert int(sizes[k]) == v, k
    assert int(sizes['JsonWriterMax']) <= C.sizeof(S.JsonWriter)


# ---------------------------------------------------------------- password records


def record(lib, password, iters, salt):
    out = C.create_string_buffer(100)
    assert lib.auth_pw_hash_salt(password, iters, salt, out, 100) == 0
    return out.value.decode()


def test_record_format_matches_hashlib(clib):
    salt = bytes(range(16))
    rec = record(clib, b'Plant-Room#2026', 10000, salt)
    prefix, iters, s64, dk64 = rec.split('$')
    assert prefix == 'pbkdf2-sha256' and iters == '10000'
    assert base64.b64decode(s64) == salt
    assert base64.b64decode(dk64) == hashlib.pbkdf2_hmac('sha256', b'Plant-Room#2026', salt, 10000, 32)
    assert len(rec) < 100  # SEC_HASH_SZ


@pytest.mark.parametrize('password,salt,iters', [
    (b'passwd', b'salt' * 4, 1000),
    (b'mestio150!', b'\x00' * 16, 10000),
    ('한글비밀번호-2026'.encode(), os.urandom(16), 1500),
    (b'', b'\xff' * 16, 1000),
])
def test_pbkdf2_vectors_and_verify(clib, password, salt, iters):
    rec = record(clib, password, iters, salt)
    dk = base64.b64decode(rec.split('$')[3])
    assert dk == hashlib.pbkdf2_hmac('sha256', password, salt, iters, 32)
    assert clib.auth_pw_verify(password, rec.encode())
    assert not clib.auth_pw_verify(password + b'x', rec.encode())
    assert clib.auth_pw_record_iterations(rec.encode()) == iters


def test_hash_random_salt(clib):
    a = C.create_string_buffer(100)
    b = C.create_string_buffer(100)
    assert clib.auth_pw_hash(b'secret-Password1', 1000, a, 100) == 0
    assert clib.auth_pw_hash(b'secret-Password1', 1000, b, 100) == 0
    assert a.value != b.value
    assert clib.auth_pw_verify(b'secret-Password1', a.value)
    assert clib.auth_pw_verify(b'secret-Password1', b.value)


def test_hash_rejects_bad_args(clib):
    out = C.create_string_buffer(100)
    salt = bytes(16)
    assert clib.auth_pw_hash_salt(b'x', 999, salt, out, 100) == -1       # below AUTH_PBKDF2_ITER_MIN
    assert clib.auth_pw_hash_salt(b'x', 1000001, salt, out, 100) == -1   # above the DoS guard
    assert clib.auth_pw_hash_salt(b'x', 1000, salt, out, 40) == -1        # cap too small
    assert out.value == b''


def test_parse(clib):
    salt = bytes(range(16, 32))
    rec = record(clib, b'pw', 4321, salt)
    it = C.c_uint32()
    s = C.create_string_buffer(16)
    d = C.create_string_buffer(32)
    assert clib.auth_pw_parse(rec.encode(), C.byref(it), s, d)
    assert it.value == 4321 and s.raw == salt
    assert clib.auth_pw_parse(rec.encode(), None, None, None)


def malformed(rec):
    p, i, s, d = rec.split('$')
    return [
        '', 'pbkdf2-sha256', rec.replace('pbkdf2-sha256', 'pbkdf2-sha1'), rec.upper(),
        f'{p}$0{i}${s}${d}', f'{p}$999${s}${d}', f'{p}$1000001${s}${d}', f'{p}$-1000${s}${d}', f'{p}$${s}${d}',
        f'{p}$1e4${s}${d}', f'{p}${i}${s[:-1]}${d}', f'{p}${i}${s}${d[:-1]}', f'{p}${i}${s}${d}=',
        f'{p}${i}${s}$', f'{p}${i}${s}', f'{p}${i}${s}${d}$x', f'{p}${i}${s.replace("A", "-")}${d}',
        f'{p}${i}$ {s[1:]}${d}', f'{p}${i}${s}${d[:-2]}AA'[:-1],
    ]


def test_parse_rejects_malformed(clib):
    rec = record(clib, b'pw', 1000, b'ABCDEFGHIJKLMNOP')
    for bad in malformed(rec):
        assert not clib.auth_pw_parse(bad.encode(), None, None, None), bad
        assert not clib.auth_pw_verify(b'pw', bad.encode()), bad
        assert clib.auth_pw_record_iterations(bad.encode()) == 0
    assert not clib.auth_pw_verify(b'pw', None)
    assert not clib.auth_pw_verify(None, rec.encode())


# ---------------------------------------------------------------- policy


@pytest.mark.parametrize('user,pw,bits', [
    ('admin', 'Plant-Room#2026', 0),
    ('admin', 'short1A!', TOO_SHORT),
    ('admin', 'alllowercaseletters', CLASSES),
    ('admin', 'lowercase1234', CLASSES),           # 2 classes
    ('admin', 'lowercase1234X', 0),                # 3 classes
    ('admin', 'lowercase-1234', 0),                # lower + other + digit
    ('admin', 'mestio150!', FACTORY),              # 3 classes, 10 chars, but the factory default
    ('Operator1x', 'operator1X', EQ_USER),         # case-insensitive equality with the user name
    ('admin', 'A' * 30 + 'b' * 30 + '12345', TOO_LONG),
    ('admin', 'Ab1!' * 16, 0),                     # exactly 64 bytes
    ('admin', 'Ab1!\x01defghij', CHARSET),
    ('admin', 'Ab1!\x7fdefghij', CHARSET),
    ('admin', 'Ab1!\tdefghij', CHARSET),
    ('admin', '', TOO_SHORT | CLASSES),
    ('admin', '비밀번호입니다비밀번A1', 0),           # Hangul counts as "other", 12 code points
    ('admin', '비밀번호1A', TOO_SHORT),               # 6 code points (16 bytes) < 10 characters
    ('admin', '가' * 21 + 'A1', TOO_LONG),           # 65 bytes
    (None, 'Plant-Room#2026', 0),
])
def test_policy(clib, user, pw, bits):
    u = user.encode() if user is not None else None
    assert clib.auth_policy_check(u, pw.encode('utf-8')) == bits


def test_policy_invalid_utf8(clib):
    assert clib.auth_policy_check(b'admin', b'Abcdefgh1!\xff') & CHARSET
    assert clib.auth_policy_check(b'admin', b'Abcdefgh1!\xc0\xaf') & CHARSET   # overlong '/'
    assert clib.auth_policy_check(b'admin', b'Abcdefgh1!\xed\xa0\x80') & CHARSET  # surrogate
    assert clib.auth_policy_check(b'admin', b'Abcdefgh1!\xc2\x85') & CHARSET   # C1 control U+0085
    assert clib.auth_policy_check(b'admin', None) == TOO_SHORT


def test_rule_names(clib):
    names = {1: 'min_length', 2: 'max_length', 4: 'classes', 8: 'not_username', 16: 'not_default',
             32: 'not_previous', 64: 'charset'}
    for bit, name in names.items():
        assert clib.auth_policy_rule_name(bit) == name.encode()
    assert clib.auth_policy_rule_name(128) is None
    assert clib.auth_policy_rule_name(3) is None


@pytest.mark.parametrize('name,ok', [
    ('admin', True), ('a', True), ('operator1', True), ('a_b.c-d', True), ('abcdefghijk', True),
    ('abcdefghijkl', False), ('', False), ('1admin', False), ('Admin', False), ('_x', False),
    ('ad min', False), ('adm\xe4n', False), ('@snmp', False), ('a/b', False),
])
def test_name_valid(clib, name, ok):
    assert clib.auth_name_valid(name.encode('latin-1')) is ok


def test_name_valid_matches_api_pattern(clib):
    pat = re.compile(r'^[a-z][a-z0-9_.-]{0,10}$')
    for n in ['x', 'xx', 'x' * 11, 'x' * 12, 'z9', 'z.', '9z', 'a$', 'q--', 'abc_def.ghi']:
        assert clib.auth_name_valid(n.encode()) is bool(pat.match(n))


def test_status_mapping(clib):
    expect = [(0, 200, 'ok'), (1, 401, 'bad_credentials'), (2, 429, 'rate_limited'), (3, 401, 'unauthorized'),
              (4, 422, 'policy'), (5, 409, 'exists'), (6, 404, 'not_found'), (7, 409, 'limit'),
              (8, 409, 'last_admin'), (9, 422, 'validation'), (10, 422, 'validation'), (11, 409, 'self'),
              (12, 503, 'unavailable'), (13, 422, 'wrong_password')]
    for st, http, code in expect:
        assert clib.auth_http_status(st) == http
        assert clib.auth_status_code(st) == code.encode()


# ---------------------------------------------------------------- rate limiter


def rl(lib, max_fail=5, lock_min=5):
    r = Rl()
    lib.auth_rl_init(C.byref(r), max_fail, lock_min)
    return r


IP1, IP2 = 0xC0A80A14, 0xC0A80A15
UA = 0x1234  # an account key (auth_rl_user_key); same account for every attempt unless a test says
UB = 0x5678
NONE_KEY = 0  # AUTH_RL_USER_NONE


def test_lockout_after_max_fail(clib):
    r = rl(clib)
    t = 1_000_000
    for i in range(4):
        assert clib.auth_rl_check(C.byref(r), IP1, t) == 0
        assert clib.auth_rl_record(C.byref(r), IP1, UA, False, t) == 0
        t += 1000
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, t) == 300  # 5th failure -> 5 min
    assert clib.auth_rl_check(C.byref(r), IP1, t) == 300
    assert clib.auth_rl_check(C.byref(r), IP1, t + 1) == 300       # rounded up
    assert clib.auth_rl_check(C.byref(r), IP1, t + 299_500) == 1
    assert clib.auth_rl_check(C.byref(r), IP1, t + 300_000) == 0
    assert clib.auth_rl_check(C.byref(r), IP2, t) == 0               # other IPs unaffected


def test_failures_outside_window_do_not_count(clib):
    r = rl(clib)
    t = 0
    for _ in range(4):
        clib.auth_rl_record(C.byref(r), IP1, UA, False, t)
    t += 5 * MIN  # window passed
    for _ in range(4):
        assert clib.auth_rl_record(C.byref(r), IP1, UA, False, t) == 0
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, t) == 300


def test_success_resets_failures(clib):
    r = rl(clib)
    for _ in range(4):
        clib.auth_rl_record(C.byref(r), IP1, UA, False, 10)
    clib.auth_rl_record(C.byref(r), IP1, UA, True, 20)
    for _ in range(4):
        assert clib.auth_rl_record(C.byref(r), IP1, UA, False, 30) == 0


def test_success_of_other_account_does_not_reset_failures(clib):
    """4 wrong guesses at account A + 1 valid login of account B, repeated, must still lock."""
    r = rl(clib, max_fail=5, lock_min=5)
    t = 1_000_000
    locked = 0
    guesses = 0
    for _ in range(100):
        if clib.auth_rl_check(C.byref(r), IP1, t):
            locked += 1
            t += 1000
            continue
        for _ in range(4):
            if clib.auth_rl_check(C.byref(r), IP1, t):
                break
            guesses += 1
            clib.auth_rl_record(C.byref(r), IP1, UA, False, t)
            t += 1000
        clib.auth_rl_record(C.byref(r), IP1, UB, True, t)   # own (viewer) login
        t += 1000
    assert locked > 0
    assert guesses <= 10   # 5 failures, lock (5 min > the loop's remaining time)


def test_own_password_success_never_resets(clib):
    """verify_own() success records AUTH_RL_USER_NONE: clears nothing."""
    r = rl(clib, max_fail=5, lock_min=5)
    for _ in range(4):
        clib.auth_rl_record(C.byref(r), IP1, UA, False, 10)
    clib.auth_rl_record(C.byref(r), IP1, NONE_KEY, True, 20)
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, 30) == 300


def test_mixed_targets_not_cleared_by_either_account(clib):
    r = rl(clib, max_fail=5, lock_min=5)
    for _ in range(2):
        clib.auth_rl_record(C.byref(r), IP1, UA, False, 10)
    for _ in range(2):
        clib.auth_rl_record(C.byref(r), IP1, UB, False, 10)
    clib.auth_rl_record(C.byref(r), IP1, UA, True, 20)
    clib.auth_rl_record(C.byref(r), IP1, UB, True, 20)
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, 30) == 300


def test_user_key(clib):
    ka, kb = clib.auth_rl_user_key(b'admin'), clib.auth_rl_user_key(b'viewer')
    assert ka == clib.auth_rl_user_key(b'admin') and ka != kb
    assert ka not in (0, 0xFFFFFFFF) and clib.auth_rl_user_key(None) not in (0, 0xFFFFFFFF)


def test_lock_doubles_up_to_30_min_and_decays(clib):
    r = rl(clib, max_fail=3, lock_min=5)
    t = 0
    durations = []
    for _ in range(5):
        d = 0
        for _ in range(3):
            d = clib.auth_rl_record(C.byref(r), IP1, UA, False, t)
        durations.append(d)
        t += d * 1000  # wait out the lock, fail again immediately
    assert durations == [300, 600, 1200, 1800, 1800]
    # Quiet for a full window after the lock expired: back to the base duration.
    t += 5 * MIN
    for _ in range(2):
        clib.auth_rl_record(C.byref(r), IP1, UA, False, t)
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, t) == 300


def test_failure_while_locked_does_not_extend(clib):
    r = rl(clib, max_fail=2, lock_min=1)
    clib.auth_rl_record(C.byref(r), IP1, UA, False, 0)
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, 0) == 60
    assert clib.auth_rl_record(C.byref(r), IP1, UA, False, 30_000) == 0
    assert clib.auth_rl_check(C.byref(r), IP1, 30_000) == 30


def test_lru_prefers_unlocked_slots(clib):
    r = rl(clib, max_fail=1, lock_min=1)
    base = 0x0A000001
    assert clib.auth_rl_record(C.byref(r), base, UA, False, 0) == 60          # locked
    for i in range(1, 16):
        clib.auth_rl_record(C.byref(r), 0, UA, True, 0)                      # successes allocate nothing
    r2 = rl(clib, max_fail=2, lock_min=1)
    clib.auth_rl_record(C.byref(r2), base, UA, False, 0)
    clib.auth_rl_record(C.byref(r2), base, UA, False, 1)                     # locked IP in slot
    for i in range(1, 16):
        clib.auth_rl_record(C.byref(r2), base + i, UA, False, 10 + i)          # fill the table
    clib.auth_rl_record(C.byref(r2), base + 100, UA, False, 100)              # evicts the oldest UNLOCKED
    assert clib.auth_rl_check(C.byref(r2), base, 200) > 0                 # lock survived
    ips = {s.ip for s in r2.slot}
    assert base + 1 not in ips and base + 100 in ips


def test_rotation_through_many_ips_cannot_reset_locks(clib):
    """17+ addresses must not evict a locked slot (that reset its lock and doubling)."""
    r = rl(clib, max_fail=5, lock_min=5)
    base = 0x0A000001
    t = 0
    for k in range(5):
        t += 1
        d = clib.auth_rl_record(C.byref(r), base, UA, False, t)
    assert d == 300
    for i in range(1, 16):                                           # 15 more IPs, all locked
        for k in range(5):
            t += 1
            clib.auth_rl_record(C.byref(r), base + i, UA, False, t)
    assert all(s.locked_until_ms > t for s in r.slot)
    newcomer = base + 1000
    left = clib.auth_rl_check(C.byref(r), newcomer, t)               # table full of locks
    assert left == (r.slot[0].locked_until_ms - t + 999) // 1000 and left > 0
    assert clib.auth_rl_record(C.byref(r), newcomer, UA, False, t) == 0  # nothing allocated
    assert newcomer not in {s.ip for s in r.slot}
    assert clib.auth_rl_check(C.byref(r), base, t + 85) > 0          # A is still locked
    # the earliest lock ends -> its slot may be reused by a new IP, the others stay locked
    t_free = r.slot[0].locked_until_ms
    assert clib.auth_rl_check(C.byref(r), newcomer, t_free) == 0
    clib.auth_rl_record(C.byref(r), newcomer, UA, False, t_free)
    assert newcomer in {s.ip for s in r.slot}
    assert base not in {s.ip for s in r.slot}
    assert clib.auth_rl_check(C.byref(r), base + 15, t_free) > 0


def test_locked_slot_keeps_doubling_under_rotation(clib):
    r = rl(clib, max_fail=1, lock_min=5)
    a = 0x0A000001
    assert clib.auth_rl_record(C.byref(r), a, UA, False, 0) == 300
    for i in range(1, 16):
        clib.auth_rl_record(C.byref(r), a + i, UA, False, 1)               # 15 more locks
    for i in range(16, 40):                                            # rotation: no slot is taken
        assert clib.auth_rl_check(C.byref(r), a + i, 2) > 0
        clib.auth_rl_record(C.byref(r), a + i, UA, False, 2)
    t = 300_000                                                        # A's (and the others') lock ended
    assert clib.auth_rl_check(C.byref(r), a, t + 1) == 0
    assert clib.auth_rl_record(C.byref(r), a, UA, False, t + 1) == 600     # doubled: history kept


def test_ip_zero_is_tracked(clib):
    r = rl(clib, max_fail=1, lock_min=1)
    assert clib.auth_rl_record(C.byref(r), 0, UA, False, 0) == 60
    assert clib.auth_rl_check(C.byref(r), 0, 1) == 60


def test_global_delay(clib):
    r = rl(clib, max_fail=10, lock_min=1)
    t = 5 * MIN
    for i in range(20):
        clib.auth_rl_record(C.byref(r), 0x0B000000 + i, UA, False, t + i)
    assert clib.auth_rl_global_delay_ms(C.byref(r), t + 100) == 0         # 20 is not "more than 20"
    clib.auth_rl_record(C.byref(r), 0x0B0000FF, UA, False, t + 200)
    assert clib.auth_rl_global_delay_ms(C.byref(r), t + 300) == 1000
    assert clib.auth_rl_global_delay_ms(C.byref(r), t + MIN) == 0         # next minute


# ---------------------------------------------------------------- session table


class Sessions:
    def __init__(self, lib, idle_s=900, abs_s=43200):
        self.lib = lib
        self.t = SessTable()
        lib.auth_st_init(C.byref(self.t), idle_s, abs_s)
        self.ends = []

    def _ends(self):
        return (SessEnd * SESS_END_MAX)(), C.c_size_t(0)

    def _collect(self, arr, n):
        self.ends += [(arr[i].sid, arr[i].kind, arr[i].user.decode()) for i in range(n.value)]

    def create(self, user, role=ADMIN, must_change=False, now=0, tok=None, csrf=None):
        tok = tok or os.urandom(16)
        csrf = csrf or os.urandom(16)
        out = C.create_string_buffer(23)
        info = SessInfo()
        arr, n = self._ends()
        assert self.lib.auth_st_create(C.byref(self.t), user.encode(), role, must_change, now, tok, csrf, out,
                                       C.byref(info), arr, C.byref(n))
        self._collect(arr, n)
        return out.value.decode(), info

    def lookup(self, token, now, touch=True):
        info = SessInfo()
        arr, n = self._ends()
        st = self.lib.auth_st_lookup(C.byref(self.t), token.encode() if token is not None else None, touch, now,
                                     C.byref(info), arr, C.byref(n))
        self._collect(arr, n)
        return st, info

    def check(self, sid, now):
        info = SessInfo()
        arr, n = self._ends()
        st = self.lib.auth_st_check(C.byref(self.t), sid, now, C.byref(info), arr, C.byref(n))
        self._collect(arr, n)
        return st, info

    def count(self):
        return self.lib.auth_st_count(C.byref(self.t))


def test_create_and_lookup(clib):
    s = Sessions(clib)
    tok_raw = bytes(range(16))
    token, info = s.create('admin', ADMIN, True, now=1000, tok=tok_raw, csrf=b'\x01' * 16)
    assert token == base64.urlsafe_b64encode(tok_raw).decode().rstrip('=') and len(token) == 22
    assert info.user == b'admin' and info.role == ADMIN and info.must_change
    assert len(info.csrf) == 22 and info.csrf == base64.urlsafe_b64encode(b'\x01' * 16).rstrip(b'=')
    assert info.idle_s == 900 and info.idle_left_s == 900 and info.abs_left_s == 43200
    assert info.sid & 0xFF < 8 and info.sid >> 8 >= 1
    st, got = s.lookup(token, 61_000)
    assert st == AUTH_OK and got.sid == info.sid and got.idle_left_s == 900
    # The table stores only SHA-256(token).
    slot = s.t.slot[info.sid & 0xFF]
    assert bytes(slot.tok_hash) == hashlib.sha256(tok_raw).digest()
    assert token.encode() not in bytes(s.t)


@pytest.mark.parametrize('bad', [None, '', 'x', 'A' * 21, 'A' * 23, '+' * 22, 'AAAAAAAAAAAAAAAAAAAAA=',
                                 'AAAAAAAAAAAAAAAAAAAAAB'])
def test_lookup_rejects_bad_tokens(clib, bad):
    s = Sessions(clib)
    s.create('admin')
    assert s.lookup(bad, 0)[0] == E_NO_SESSION


def test_unknown_token_and_unused_slot_hash(clib):
    s = Sessions(clib)
    assert s.lookup(base64.urlsafe_b64encode(bytes(16)).decode().rstrip('='), 0)[0] == E_NO_SESSION
    s.create('admin')
    assert s.lookup(base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('='), 0)[0] == E_NO_SESSION


def test_idle_expiry_touch_and_no_touch(clib):
    s = Sessions(clib, idle_s=300)
    token, info = s.create('op', OPERATOR, now=0)
    assert s.lookup(token, 200_000)[0] == AUTH_OK            # touch -> idle restarts at 200 s
    st, i = s.lookup(token, 450_000, touch=False)            # 250 s idle: alive, not touched
    assert st == AUTH_OK and i.idle_left_s == 50
    assert s.check(info.sid, 499_000)[0] == AUTH_OK
    assert s.check(info.sid, 500_000)[0] == E_NO_SESSION      # 300 s idle since last touch
    assert s.ends == [(info.sid, END_EXPIRED, 'op')]
    assert s.lookup(token, 500_001)[0] == E_NO_SESSION
    assert s.count() == 0


def test_absolute_expiry_despite_activity(clib):
    s = Sessions(clib, idle_s=900, abs_s=3600)
    token, info = s.create('v', VIEWER, now=0)
    t = 0
    while t < 3_600_000 - 600_000:
        t += 600_000
        st, i = s.lookup(token, t)
        assert st == AUTH_OK
    assert i.abs_left_s == 600
    assert s.lookup(token, 3_600_000)[0] == E_NO_SESSION
    assert s.ends[-1][1] == END_EXPIRED


def test_eviction_of_least_recently_used(clib):
    s = Sessions(clib)
    tokens = []
    for i in range(8):
        tok, info = s.create(f'u{i}', VIEWER, now=i * 1000)
        tokens.append((tok, info.sid))
    s.lookup(tokens[0][0], 10_000)          # u0 becomes most recent; u1 is now LRU
    tok9, info9 = s.create('new', VIEWER, now=11_000)
    assert s.ends == [(tokens[1][1], END_REVOKED, 'u1')]
    assert s.lookup(tokens[1][0], 12_000)[0] == E_NO_SESSION
    assert s.lookup(tokens[0][0], 12_000)[0] == AUTH_OK
    assert s.count() == 8
    assert info9.sid & 0xFF == tokens[1][1] & 0xFF and info9.sid != tokens[1][1]  # same slot, new generation


def test_create_purges_expired_first(clib):
    s = Sessions(clib, idle_s=60)
    s.create('old', now=0)
    s.create('new', now=120_000)
    assert s.ends[0][1:] == (END_EXPIRED, 'old')
    assert s.count() == 1


def test_stale_sid_after_slot_reuse(clib):
    s = Sessions(clib)
    _, a = s.create('a')
    arr, n = (SessEnd * SESS_END_MAX)(), C.c_size_t(0)
    assert clib.auth_st_remove(C.byref(s.t), a.sid, END_LOGOUT, arr, C.byref(n))
    assert n.value == 1 and arr[0].kind == END_LOGOUT
    _, b = s.create('b')
    assert b.sid & 0xFF == a.sid & 0xFF and b.sid != a.sid
    assert s.check(a.sid, 0)[0] == E_NO_SESSION
    assert not clib.auth_st_remove(C.byref(s.t), a.sid, END_LOGOUT, arr, C.byref(n))
    assert s.check(0, 0)[0] == E_NO_SESSION
    assert s.check(0xFF, 0)[0] == E_NO_SESSION


def test_csrf(clib):
    s = Sessions(clib)
    _, info = s.create('admin', csrf=b'\x02' * 16)
    good = base64.urlsafe_b64encode(b'\x02' * 16).rstrip(b'=')
    assert clib.auth_st_csrf_ok(C.byref(s.t), info.sid, good)
    assert not clib.auth_st_csrf_ok(C.byref(s.t), info.sid, good[:-1] + b'B')
    assert not clib.auth_st_csrf_ok(C.byref(s.t), info.sid, good + b'A')
    assert not clib.auth_st_csrf_ok(C.byref(s.t), info.sid, b'')
    assert not clib.auth_st_csrf_ok(C.byref(s.t), info.sid, None)
    assert not clib.auth_st_csrf_ok(C.byref(s.t), info.sid ^ 0x100, good)


def test_revoke_user_keeps_current(clib):
    s = Sessions(clib)
    _, a1 = s.create('alice')
    _, a2 = s.create('alice')
    _, b1 = s.create('bob')
    arr, n = (SessEnd * SESS_END_MAX)(), C.c_size_t(0)
    assert clib.auth_st_revoke_user(C.byref(s.t), b'alice', a2.sid, arr, C.byref(n)) == 1
    assert (arr[0].sid, arr[0].kind) == (a1.sid, END_REVOKED)
    assert s.check(a2.sid, 0)[0] == AUTH_OK and s.check(b1.sid, 0)[0] == AUTH_OK
    assert clib.auth_st_revoke_user(C.byref(s.t), b'alice', 0, arr, C.byref(n)) == 1
    assert s.count() == 1


def test_must_change_and_idle_update(clib):
    s = Sessions(clib, idle_s=900)
    _, info = s.create('admin', must_change=True)
    assert clib.auth_st_set_must_change(C.byref(s.t), info.sid, False)
    assert not s.check(info.sid, 0)[1].must_change
    clib.auth_st_set_idle(C.byref(s.t), 300)
    st, i = s.check(info.sid, 1000)
    assert i.idle_s == 300 and i.idle_left_s == 299
    assert s.check(info.sid, 300_000)[0] == E_NO_SESSION


def test_create_rejects_bad_args(clib):
    s = Sessions(clib)
    out = C.create_string_buffer(23)
    arr, n = (SessEnd * SESS_END_MAX)(), C.c_size_t(0)
    for user, role in ((b'', ADMIN), (None, ADMIN), (b'x', 0), (b'x', 4)):
        assert not clib.auth_st_create(C.byref(s.t), user, role, False, 0, bytes(16), bytes(16), out, None, arr,
                                       C.byref(n))
    assert s.count() == 0


def test_end_record_capacity(clib):
    s = Sessions(clib, idle_s=1)
    for i in range(8):
        s.create(f'u{i}', now=0)
    arr, n = (SessEnd * SESS_END_MAX)(), C.c_size_t(0)
    clib.auth_st_expire(C.byref(s.t), 10_000, arr, C.byref(n))
    assert n.value == 8 and s.count() == 0
    assert sorted(arr[i].user.decode() for i in range(8)) == [f'u{i}' for i in range(8)]
