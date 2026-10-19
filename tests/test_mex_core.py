"""mex150 mex_core.c (the host-testable engine behind service.c), driven through ctypes with a simulated
RS485 bus and MEX150 slaves: poll plan on the wire, retries and per-error counters, RTT, COMM decisions
(first decision after boot / reconfigure, online<->offline, offline single-block probing), the write
queue (validation at enqueue and before send, FC06 -> read-back -> APPLIED / REJECTED / UNCERTAIN,
monitor rule PENDING until the post-write snapshot is published), command history, reconfiguration,
multi-device round-robin and its fairness (write traffic, offline peers), the total-deadline receive
(mex_rx_bounded) against an IDF-like per-chunk-timeout UART model, local-echo tolerance and
garbage-response fuzzing.

Every callback asserts that the core never holds its lock across bus I/O or callbacks."""
import ctypes as C
import random

import pytest

from conftest import COMPONENTS, compile_and_run

# ---------------------------------------------------------------- C types

ESP_OK, ESP_FAIL, ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_STATE = 0, -1, 0x101, 0x102, 0x103
W_PENDING, W_APPLIED, W_REJECTED, W_UNCERTAIN = range(4)
R_OK, R_UNKNOWN, R_READONLY, R_RANGE, R_INTERLOCK, R_OFFLINE, R_BUSY, R_NO_ACK, R_VERIFY, R_CANCELLED = range(10)
TXN_TIMEOUT, TXN_UART = -10, -11
COMM_UNKNOWN, COMM_ONLINE, COMM_OFFLINE = range(3)
FAST = [(1, 0, 8), (1, 8, 8), (1, 16, 8), (1, 24, 8), (3, 1, 3), (3, 4, 4), (3, 10, 12), (3, 35, 2)]
SLOW = [(3, 26, 4), (3, 52, 2), (3, 58, 1)]
WALL0 = 1_792_371_600_000
MEX_FRESH_MS = 3000


class PortCfg(C.Structure):
    _fields_ = [('baud', C.c_uint32), ('parity', C.c_char), ('stop', C.c_uint8), ('poll_ms', C.c_uint16),
                ('timeout_ms', C.c_uint16), ('gap_ms', C.c_uint16), ('retries', C.c_uint8),
                ('offline_after', C.c_uint8)]


class DevCfg(C.Structure):
    _fields_ = [('id', C.c_uint8), ('slave', C.c_uint8), ('enabled', C.c_bool), ('name', C.c_char * 24)]


class Snapshot(C.Structure):
    _fields_ = [('regs', C.c_uint16 * 60), ('coils', C.c_uint32), ('wall_ms', C.c_int64), ('mono_ms', C.c_uint64),
                ('seq', C.c_uint32), ('online', C.c_bool), ('slow_valid', C.c_bool)]


class WResult(C.Structure):
    _fields_ = [('cmd', C.c_uint32), ('state', C.c_int), ('reason', C.c_int), ('raw_after', C.c_int32),
                ('dev', C.c_uint8), ('addr', C.c_uint16), ('raw_req', C.c_int32), ('ts_ms', C.c_int64)]


class Stats(C.Structure):
    _fields_ = [('tx', C.c_uint32), ('rx_ok', C.c_uint32), ('crc', C.c_uint32), ('timeout', C.c_uint32),
                ('exception', C.c_uint32), ('malformed', C.c_uint32), ('offline_count', C.c_uint32),
                ('rtt_last', C.c_uint16), ('rtt_avg', C.c_uint16), ('rtt_max', C.c_uint16),
                ('online_since_ms', C.c_int64), ('cycles', C.c_uint32)]


LOCK = C.CFUNCTYPE(None, C.c_void_p)
MONO = C.CFUNCTYPE(C.c_uint64, C.c_void_p)
WALL = C.CFUNCTYPE(C.c_int64, C.c_void_p)
GAP = C.CFUNCTYPE(None, C.c_void_p, C.c_uint16)
WRITE = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)
READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t, C.c_uint32)
PORT_APPLY = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(PortCfg))
FEED = C.CFUNCTYPE(None, C.c_void_p)
ON_SNAP = C.CFUNCTYPE(None, C.c_void_p, C.c_uint8, C.c_uint32, C.c_uint64, C.c_bool)
ON_COMM = C.CFUNCTYPE(None, C.c_void_p, C.c_uint8, C.c_bool, C.c_int, C.c_uint32, C.c_int64)
ON_WRITE = C.CFUNCTYPE(None, C.c_void_p, C.POINTER(WResult), C.c_int32, C.c_char_p)


class CoreIO(C.Structure):
    _fields_ = [('ctx', C.c_void_p), ('lock', LOCK), ('unlock', LOCK), ('mono_ms', MONO), ('wall_ms', WALL),
                ('gap', GAP), ('write', WRITE), ('read', READ), ('port_apply', PORT_APPLY), ('feed', FEED),
                ('on_snapshot', ON_SNAP), ('on_comm', ON_COMM), ('on_write', ON_WRITE)]


RX_NOW = C.CFUNCTYPE(C.c_uint32, C.c_void_p)
RX_AVAIL = C.CFUNCTYPE(C.c_int, C.c_void_p)
RX_RECV = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t, C.c_uint32)


class RxOps(C.Structure):
    _fields_ = [('ctx', C.c_void_p), ('now', RX_NOW), ('avail', RX_AVAIL), ('recv', RX_RECV)]


@pytest.fixture(scope='module')
def lib(host_lib):
    l = host_lib('MEX150')
    V = C.c_void_p
    sig = {
        'mex_core_sizeof': ([], C.c_size_t),
        'mex_core_init': ([V, C.POINTER(CoreIO)], None),
        'mex_core_port_valid': ([C.POINTER(PortCfg)], C.c_bool),
        'mex_core_cfg_valid': ([C.POINTER(PortCfg), C.POINTER(DevCfg), C.c_size_t], C.c_bool),
        'mex_core_configure': ([V, C.POINTER(PortCfg), C.POINTER(DevCfg), C.c_size_t], C.c_int),
        'mex_core_reconfigure': ([V, C.POINTER(PortCfg), C.POINTER(DevCfg), C.c_size_t], C.c_int),
        'mex_core_run_once': ([V], C.c_uint32),
        'mex_core_write_submit': ([V, C.c_uint8, C.c_uint16, C.c_int32, C.c_char_p, C.POINTER(WResult)], C.c_int),
        'mex_core_command': ([V, C.c_uint8, C.c_uint32, C.POINTER(WResult)], C.c_bool),
        'mex_core_snapshot': ([V, C.c_uint8, C.POINTER(Snapshot)], C.c_bool),
        'mex_core_stats': ([V, C.c_uint8, C.POINTER(Stats), C.c_bool], None),
        'mex_core_comm': ([V, C.c_uint8], C.c_uint8),
        'mex_rx_bounded': ([C.POINTER(RxOps), V, C.c_size_t, C.c_uint32], C.c_int),
    }
    for name, (args, res) in sig.items():
        fn = getattr(l, name)
        fn.argtypes, fn.restype = args, res
    return l


LAYOUT = r'''
#include <stddef.h>
#include <stdio.h>
#include "mex_core.h"
#define P(t) printf(#t " %zu\n", sizeof(t))
#define O(t, m) printf(#t "." #m " %zu\n", offsetof(t, m))
int main(void) {
    P(mex_port_cfg_t); P(mex_dev_cfg_t); P(mex_snapshot_t); P(mex_wresult_t); P(mex_stats_t); P(mex_core_io_t);
    O(mex_snapshot_t, coils); O(mex_snapshot_t, mono_ms); O(mex_snapshot_t, seq); O(mex_snapshot_t, slow_valid);
    O(mex_wresult_t, raw_after); O(mex_wresult_t, ts_ms); O(mex_stats_t, rtt_last); O(mex_stats_t, online_since_ms);
    O(mex_stats_t, cycles); O(mex_core_io_t, on_write); O(mex_port_cfg_t, offline_after); O(mex_dev_cfg_t, name);
    return 0;
}
'''


def test_ctypes_layouts_match_c(tmp_path):
    out = compile_and_run(tmp_path, LAYOUT, name='layout', flags=[f'-I{COMPONENTS / "mex150"}'])
    got = dict(line.rsplit(' ', 1) for line in out.splitlines())
    py = {'mex_port_cfg_t': PortCfg, 'mex_dev_cfg_t': DevCfg, 'mex_snapshot_t': Snapshot, 'mex_wresult_t': WResult,
          'mex_stats_t': Stats, 'mex_core_io_t': CoreIO}
    for k, v in got.items():
        if '.' in k:
            t, m = k.split('.')
            assert getattr(py[t], m).offset == int(v), k
        else:
            assert C.sizeof(py[k]) == int(v), k


# ---------------------------------------------------------------- simulated MEX150 + bus


def crc16(data):
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0xA001 if c & 1 else 0)
    return c


def frame(body):
    body = bytes(body)
    return body + crc16(body).to_bytes(2, 'little')


class Mex150:
    """Behavioural model of one MEX150 slave (registers 40001..40099, coils 1..32, FC01/03/06)."""

    def __init__(self, slave=1):
        self.slave = slave
        self.regs = [0] * 100
        self.coils = [0] * 32
        for addr, v in {40002: 0x0100, 40011: 42, 40012: 230, 40013: 500, 40014: 10, 40015: 10, 40016: 50,
                        40017: 50, 40018: 5, 40019: 5, 40020: slave, 40021: 0xFFFB, 40027: 300, 40028: 49,
                        40029: 599, 40030: 99, 40036: 0xFF06, 40037: 480, 40059: 5000}.items():
            self.regs[addr - 40000] = v
        for n in (1, 2, 12):
            self.coils[n - 1] = 1
        self.alive = True
        self.run_delay = 0
        self.write_exc = {}  # addr -> exception code
        self.read_exc = {}   # (fc, start, count) -> exception code
        self.ignore_writes = False

    def handle(self, q):
        if not self.alive or len(q) != 8 or crc16(q[:6]) != int.from_bytes(q[6:], 'little') or q[0] != self.slave:
            return b''
        fc, a, v = q[1], q[2] << 8 | q[3], q[4] << 8 | q[5]
        if (fc, a, v) in self.read_exc:
            return frame([self.slave, fc | 0x80, self.read_exc[(fc, a, v)]])
        if fc == 1:
            if not 1 <= v or a + v > 32:
                return frame([self.slave, 0x81, 2])
            data = bytearray((v + 7) // 8)
            for i in range(v):
                data[i // 8] |= self.coils[a + i] << (i % 8)
            return frame([self.slave, 1, len(data), *data])
        if fc == 3:
            if not 1 <= v or a + v > 99:
                return frame([self.slave, 0x83, 2])
            data = b''.join(self.regs[a + 1 + i].to_bytes(2, 'big') for i in range(v))
            return frame([self.slave, 3, len(data), *data])
        if fc == 6:
            addr = a + 40001
            if addr in self.write_exc:
                return frame([self.slave, 0x86, self.write_exc[addr]])
            if not self.ignore_writes:
                if addr == 40005:
                    self.regs[5] = ((self.run_delay << 8) | 1) if v else 0
                else:
                    self.regs[addr - 40000] = v
            return bytes(q)
        return frame([self.slave, fc | 0x80, 1])


class Bus:
    """Fake UART: one request -> the addressed slave's response; deterministic simulated clock."""

    def __init__(self, sims, tx_ms=9, latency_ms=20):
        self.sims = sims
        self.t = 1000
        self.wall_valid = True
        self.tx_ms, self.latency_ms = tx_ms, latency_ms
        self.pending, self.first = b'', False
        self.log = []          # (slave, fc, start, value)
        self.faults = []       # f(q, resp) -> new resp or None (no change); may remove itself
        self.hooks = []        # h(index, q) called after each request was sent
        self.echo = False
        self.uart_error = False
        self.locked = False
        self.errors = []
        self.feeds = 0
        self.gaps = []
        self.port_applies = []


class Harness:
    def __init__(self, lib, devs=((0, 1, True),), port=None, sims=None, configure=True, **bus_kw):
        self.lib = lib
        slaves = {d[1] for d in devs} | {d[1] for d in devs}
        self.sims = sims if sims is not None else {s: Mex150(s) for s in slaves}
        self.bus = Bus(self.sims, **bus_kw)
        self.events = []  # ('snap', dev, seq, mono, slow) / ('comm', dev, online, err, offl, ts) / ('write', dict)
        self._cb = dict(lock=LOCK(self._lock), unlock=LOCK(self._unlock), mono_ms=MONO(self._mono),
                        wall_ms=WALL(self._wall), gap=GAP(self._gap), write=WRITE(self._write), read=READ(self._read),
                        port_apply=PORT_APPLY(self._port_apply), feed=FEED(self._feed),
                        on_snapshot=ON_SNAP(self._on_snap), on_comm=ON_COMM(self._on_comm),
                        on_write=ON_WRITE(self._on_write))
        self.io = CoreIO(None, **self._cb)
        self.mem = C.create_string_buffer(lib.mex_core_sizeof())
        lib.mex_core_init(self.mem, C.byref(self.io))
        self.port = port or make_port()
        if configure:
            assert self.configure(devs) == ESP_OK

    # -- callbacks (exceptions inside ctypes callbacks are swallowed: record them instead)
    def _guard(self, what, fn, *a):
        try:
            return fn(*a)
        except Exception as e:  # pragma: no cover - surfaced by check()
            self.bus.errors.append(f'{what}: {e!r}')
            return 0

    def _unlocked(self, what):
        if self.bus.locked:
            self.bus.errors.append(f'{what} called with the core lock held')

    def _lock(self, _):
        if self.bus.locked:
            self.bus.errors.append('recursive lock')
        self.bus.locked = True

    def _unlock(self, _):
        if not self.bus.locked:
            self.bus.errors.append('unlock without lock')
        self.bus.locked = False

    def _mono(self, _):
        return self.bus.t

    def _wall(self, _):
        return WALL0 + self.bus.t if self.bus.wall_valid else 0

    def _gap(self, _, ms):
        self._unlocked('gap')
        self.bus.gaps.append(ms)
        self.bus.t += ms
        self.bus.pending = b''

    def _write(self, _, ptr, n):
        return self._guard('write', self._write_impl, ptr, n)

    def _write_impl(self, ptr, n):
        self._unlocked('write')
        b = self.bus
        if b.uart_error:
            return TXN_UART
        q = C.string_at(ptr, n)
        b.log.append((q[0], q[1], q[2] << 8 | q[3], q[4] << 8 | q[5]))
        b.t += b.tx_ms
        sim = b.sims.get(q[0])
        resp = sim.handle(q) if sim else b''
        for f in list(b.faults):
            r = f(q, resp)
            if r is not None:
                resp = r
        if b.echo and q[1] in (1, 3):
            resp = q + resp
        b.pending, b.first = resp, True
        for h in list(b.hooks):
            h(len(b.log) - 1, q)
        return 0

    def _read(self, _, ptr, want, timeout):
        return self._guard('read', self._read_impl, ptr, want, timeout)

    def _read_impl(self, ptr, want, timeout):
        self._unlocked('read')
        b = self.bus
        if not b.pending:
            b.t += timeout
            return 0
        if b.first:
            b.t += b.latency_ms
            b.first = False
        k = min(want, len(b.pending))
        C.memmove(ptr, b.pending[:k], k)
        b.pending = b.pending[k:]
        if k < want:
            b.t += timeout
        return k

    def _port_apply(self, _, p):
        self._unlocked('port_apply')
        self.bus.port_applies.append((p.contents.baud, p.contents.parity, p.contents.stop))
        return 0

    def _feed(self, _):
        self.bus.feeds += 1

    def _on_snap(self, _, dev, seq, mono, slow):
        self._unlocked('on_snapshot')
        self.events.append(('snap', dev, seq, mono, slow))

    def _on_comm(self, _, dev, online, err, offl, ts):
        self._unlocked('on_comm')
        self.events.append(('comm', dev, online, err, offl, ts))

    def _on_write(self, _, res, raw_before, who):
        self._unlocked('on_write')
        r = res.contents
        self.events.append(('write', dict(cmd=r.cmd, state=r.state, reason=r.reason, raw_after=r.raw_after, dev=r.dev,
                                          addr=r.addr, raw_req=r.raw_req, ts=r.ts_ms, raw_before=raw_before,
                                          who=(who or b'').decode())))
        # a callback may use the API (lock must be free)
        self.lib.mex_core_comm(self.mem, r.dev)

    # -- API wrappers
    def configure(self, devs, port=None):
        arr, n = make_devs(devs)
        return self.lib.mex_core_configure(self.mem, C.byref(port or self.port), arr, n)

    def reconfigure(self, devs, port=None):
        arr, n = make_devs(devs)
        return self.lib.mex_core_reconfigure(self.mem, C.byref(port or self.port), arr, n)

    def run_once(self):
        w = self.lib.mex_core_run_once(self.mem)
        assert w <= 500
        self.bus.t += w
        return w

    def run_for(self, ms):
        end = self.bus.t + ms
        for _ in range(100000):
            if self.bus.t >= end:
                return
            self.run_once()
        raise AssertionError('run_for did not advance')

    def cycle(self):
        """Run until one device cycle executed."""
        for _ in range(1000):
            if self.run_once() == 0:
                return
        raise AssertionError('no cycle ran')

    def submit(self, dev, addr, raw, who=b'op'):
        out = WResult()
        rc = self.lib.mex_core_write_submit(self.mem, dev, addr, raw, who, C.byref(out))
        return rc, out

    def command(self, dev, cmd):
        out = WResult()
        ok = self.lib.mex_core_command(self.mem, dev, cmd, C.byref(out))
        return ok, out

    def snapshot(self, dev=0):
        s = Snapshot()
        ok = self.lib.mex_core_snapshot(self.mem, dev, C.byref(s))
        return ok, s

    def stats(self, dev=0, reset=False):
        s = Stats()
        self.lib.mex_core_stats(self.mem, dev, C.byref(s), reset)
        return s

    def comm(self, dev=0):
        return self.lib.mex_core_comm(self.mem, dev)

    # -- event helpers
    def of(self, kind):
        return [e for e in self.events if e[0] == kind]

    def writes(self):
        return [e[1] for e in self.events if e[0] == 'write']

    def comms(self, dev=None):
        return [(e[1], e[2], e[3], e[4]) for e in self.events if e[0] == 'comm' and (dev is None or e[1] == dev)]

    def blocks(self, since=0, slave=None):
        return [(fc, a, v) for s, fc, a, v in self.bus.log[since:] if slave is None or s == slave]

    def check(self):
        assert not self.bus.errors, self.bus.errors
        assert not self.bus.locked


def make_port(**kw):
    p = dict(baud=9600, parity=b'N', stop=1, poll_ms=1000, timeout_ms=300, gap_ms=5, retries=1, offline_after=3)
    p.update(kw)
    return PortCfg(**p)


def make_devs(devs):
    arr = (DevCfg * max(len(devs), 1))()
    for i, d in enumerate(devs):
        dev_id, slave, enabled = d[:3]
        name = d[3] if len(d) > 3 else f'MEX150 #{dev_id}'.encode()
        arr[i] = DevCfg(dev_id, slave, enabled, name)
    return arr, len(devs)


def drop(n, pred=lambda q: True):
    """Fault: the next n matching requests get no answer."""
    left = [n]

    def f(q, resp):
        if left[0] > 0 and pred(q):
            left[0] -= 1
            return b''
        return None
    return f


def mangle(n, fn, pred=lambda q: True):
    left = [n]

    def f(q, resp):
        if left[0] > 0 and pred(q) and resp:
            left[0] -= 1
            return fn(resp)
        return None
    return f


@pytest.fixture
def H(lib):
    made = []

    def make(*a, **kw):
        h = Harness(lib, *a, **kw)
        made.append(h)
        return h
    yield make
    for h in made:
        h.check()


def counters_consistent(st):
    return st.tx == st.rx_ok + st.crc + st.timeout + st.exception + st.malformed


# ---------------------------------------------------------------- polling


def test_first_cycle_reads_full_plan_and_publishes(H):
    h = H()
    assert h.comm() == COMM_UNKNOWN
    ok, s = h.snapshot()
    assert ok and s.seq == 0 and not s.online and s.mono_ms == 0
    assert h.run_once() == 0
    assert h.blocks() == FAST + SLOW
    assert all(sl == 1 for sl, *_ in h.bus.log)
    ok, s = h.snapshot()
    sim = h.sims[1]
    assert ok and s.seq == 1 and s.online and s.slow_valid
    assert [s.regs[i] for i in range(60)] == [sim.regs[i] if i in (2, 3, 4, 5, 6, 7, 8) or 11 <= i <= 22 or
                                              i in (26 + 1, 28, 29, 30, 36, 37, 53, 54, 59) else 0
                                              for i in range(60)]
    assert s.regs[36] == 0xFF06  # -25.0 degC wire value (decoded by mex_reg_decode)
    assert s.coils == sum(sim.coils[n] << n for n in range(32))
    assert s.mono_ms == h.bus.t and s.wall_ms == WALL0 + h.bus.t
    # COMM first decision, then SNAPSHOT
    assert [e[0] for e in h.events] == ['comm', 'snap']
    assert h.comms() == [(0, True, 0, 0)]
    assert h.of('snap') == [('snap', 0, 1, h.bus.t, True)]
    st = h.stats()
    assert (st.tx, st.rx_ok, st.cycles, st.offline_count) == (11, 11, 1, 0)
    assert st.rtt_last == st.rtt_avg == st.rtt_max == 29  # tx 9 ms + first byte 20 ms
    assert st.online_since_ms == WALL0 + h.bus.t
    assert h.comm() == COMM_ONLINE
    assert h.bus.gaps == [5] * 11 and h.bus.feeds >= 11


def test_poll_period_and_slow_cadence(H):
    h = H()
    h.run_for(25_000)
    snaps = h.of('snap')
    assert 24 <= len(snaps) <= 26
    assert [e[2] for e in snaps] == list(range(1, len(snaps) + 1))
    slow_cycles = [e for e in snaps if e[4]]
    assert len(slow_cycles) == 3
    gaps = [b[3] - a[3] for a, b in zip(slow_cycles, slow_cycles[1:])]
    assert all(g >= 10_000 for g in gaps)
    assert h.blocks().count((3, 26, 4)) == 3
    assert h.comms() == [(0, True, 0, 0)]
    starts = [i for i, (_, fc, a, v) in enumerate(h.bus.log) if (fc, a, v) == FAST[0]]
    assert len(starts) == len(snaps)


def test_offline_from_boot_then_probe_and_recover(H):
    h = H()
    h.sims[1].alive = False
    h.run_for(1500)  # two failed cycles (t=1000, 2000)
    assert h.comms() == []  # undecided until offline_after failed cycles
    h.run_for(10_000)
    assert h.comms() == [(0, False, TXN_TIMEOUT, 1)]
    ok, s = h.snapshot()
    assert ok and not s.online and s.seq == 0 and not s.slow_valid
    st = h.stats()
    assert st.tx == st.timeout and st.rx_ok == 0 and st.offline_count == 1 and st.cycles == 0
    assert counters_consistent(st)
    # offline: only the first block, every 2 s, a single attempt (no retries for probes)
    mark = len(h.bus.log)
    t0 = h.bus.t
    h.run_for(10_000)
    probes = h.blocks(mark)
    assert set(probes) == {FAST[0]}
    assert 4 <= len(probes) <= 6
    assert h.comm() == COMM_OFFLINE
    # recovery: the probe answers -> full plan incl. slow group in the same cycle
    h.sims[1].alive = True
    mark = len(h.bus.log)
    while not h.of('snap'):
        h.run_once()
    assert h.blocks(mark) == FAST + SLOW  # probe block + rest of the plan, one cycle
    assert h.comms()[-1] == (0, True, 0, 1)
    ok, s = h.snapshot()
    assert s.online and s.slow_valid and s.seq == 1
    assert h.bus.t - t0 > 10_000


def test_online_to_offline_exactly_one_event(H):
    h = H()
    h.cycle()
    h.sims[1].alive = False
    for k in (1, 2):
        h.cycle()
        ok, s = h.snapshot()
        assert s.online and s.seq == 1, f'still online after {k} failed cycles'
        assert len(h.comms()) == 1
    h.cycle()
    assert h.comms() == [(0, True, 0, 0), (0, False, TXN_TIMEOUT, 1)]
    ok, s = h.snapshot()
    assert not s.online and not s.slow_valid and s.seq == 1 and s.regs[12] == 230  # last data kept
    h.run_for(20_000)
    assert len(h.comms()) == 2  # no repeats while offline
    assert h.stats().offline_count == 1


def test_transient_failure_below_threshold(H):
    h = H()
    h.cycle()
    h.bus.faults.append(drop(2))  # both attempts of the next block 0
    h.cycle()
    h.cycle()
    assert h.comms() == [(0, True, 0, 0)]
    ok, s = h.snapshot()
    assert s.seq == 2 and s.online
    st = h.stats()
    assert st.timeout == 2 and st.cycles == 2 and counters_consistent(st)


def test_retry_recovers_within_cycle(H):
    h = H()
    h.bus.faults.append(drop(1))
    h.cycle()
    st = h.stats()
    assert (st.tx, st.timeout, st.rx_ok, st.cycles) == (12, 1, 11, 1)
    assert h.blocks() == [FAST[0]] + FAST + SLOW


def test_retries_zero_fails_cycle(H):
    h = H(port=make_port(retries=0, offline_after=1))
    h.bus.faults.append(drop(1))
    h.cycle()
    assert h.comms() == [(0, False, TXN_TIMEOUT, 1)]
    assert h.stats().tx == 1


def test_error_counters(H):
    h = H()
    flip = lambda r: r[:-1] + bytes([r[-1] ^ 0xFF])
    h.bus.faults.append(mangle(1, flip))                               # CRC error -> retried
    h.bus.faults.append(mangle(1, lambda r: frame([1, 4, 0]), lambda q: q[1] == 3))  # wrong fc, valid CRC
    h.cycle()
    st = h.stats()
    assert (st.crc, st.malformed, st.rx_ok, st.tx) == (1, 1, 11, 13)
    assert h.of('snap')
    # exception on a read block: definitive answer, not retried, cycle fails
    h.sims[1].read_exc[(3, 10, 12)] = 2
    h.cycle()
    st = h.stats()
    assert st.exception == 1 and st.tx == 13 + 7
    assert len(h.of('snap')) == 1
    assert counters_consistent(st)
    # partial frame -> CRC class; wrong unit -> CRC class is not used (valid CRC) -> malformed
    del h.sims[1].read_exc[(3, 10, 12)]
    h.bus.faults.append(mangle(1, lambda r: r[:4], lambda q: q[1] == 1))
    h.bus.faults.append(mangle(1, lambda r: frame([9] + list(r[1:-2])), lambda q: q[1] == 3))
    h.cycle()
    st = h.stats()
    assert st.crc == 2 and st.malformed == 2 and counters_consistent(st)


def test_uart_error_counts_no_tx_and_fails(H):
    h = H(port=make_port(offline_after=1))
    h.bus.uart_error = True
    h.cycle()
    st = h.stats()
    assert st.tx == 0 and h.comms() == [(0, False, TXN_UART, 1)]


def test_local_echo_is_skipped(H):
    h = H()
    h.bus.echo = True
    h.cycle()
    st = h.stats()
    assert st.rx_ok == 11 and st.crc == st.malformed == st.timeout == 0
    ok, s = h.snapshot()
    assert s.online and s.regs[12] == 230
    h.bus.t += 100
    rc, out = h.submit(0, 40012, 250)
    assert rc == ESP_OK and out.state == W_PENDING
    h.cycle()
    assert h.writes()[-1]['state'] == W_APPLIED


def test_rtt_ewma_and_max(H):
    h = H()
    h.cycle()
    h.bus.latency_ms = 100
    h.cycle()
    st = h.stats()
    assert st.rtt_last == 109 and st.rtt_max == 109
    assert 29 < st.rtt_avg < 109


def test_stats_reset_keeps_online_since(H):
    h = H()
    h.cycle()
    before = h.stats(reset=True)
    assert before.tx == 11 and before.online_since_ms
    after = h.stats()
    assert (after.tx, after.rx_ok, after.cycles, after.rtt_max, after.rtt_avg) == (0, 0, 0, 0, 0)
    assert after.online_since_ms == before.online_since_ms
    h.cycle()
    assert h.stats().rtt_avg == 29
    assert h.stats(dev=3).tx == 0 and h.stats(dev=200).tx == 0


def test_idle_wait_bounds(H):
    h = H(devs=((0, 1, False),))
    assert h.run_once() == 500
    assert h.bus.log == []
    h2 = H()
    h2.cycle()
    w = h2.run_once()
    assert 0 < w <= 500


# ---------------------------------------------------------------- writes


def online(H, **kw):
    h = H(**kw)
    h.cycle()
    return h


def test_write_applied_full_flow(H):
    h = online(H)
    mark = len(h.bus.log)
    rc, out = h.submit(0, 40012, 250, b'alice')
    assert rc == ESP_OK and out.state == W_PENDING and out.cmd == 1 and out.raw_after == 230
    assert (out.dev, out.addr, out.raw_req) == (0, 40012, 250)
    ok, c = h.command(0, 1)
    assert ok and c.state == W_PENDING
    assert h.writes() == []  # nothing posted while pending
    h.run_once()
    # write first (published snapshot fresh), read-back, then fast + slow (post-write snapshot)
    assert h.blocks(mark) == [(6, 11, 250), (3, 11, 1)] + FAST + SLOW
    w = h.writes()
    assert w == [dict(cmd=1, state=W_APPLIED, reason=R_OK, raw_after=250, dev=0, addr=40012, raw_req=250,
                      ts=WALL0 + h.bus.t, raw_before=230, who='alice')]
    kinds = [e[0] for e in h.events]
    assert kinds.index('write') > len(kinds) - 2 and kinds[-2] == 'snap'  # snapshot published first
    assert h.of('snap')[-1][4] is True
    ok, c = h.command(0, 1)
    assert ok and c.state == W_APPLIED and c.raw_after == 250
    ok, s = h.snapshot()
    assert s.regs[12] == 250 and s.seq == 2


def test_write_exception_rejected(H):
    h = online(H)
    h.sims[1].write_exc[40012] = 3
    mark = len(h.bus.log)
    h.submit(0, 40012, 250)
    h.cycle()
    assert h.blocks(mark)[:2] == [(6, 11, 250), (3, 11, 1)]  # exception not retried
    w = h.writes()[-1]
    assert (w['state'], w['reason'], w['raw_after']) == (W_REJECTED, 0x100 + 3, 230)


def test_write_lost_ack_but_readback_matches_is_applied(H):
    """Monitor rule: a matching read-back confirms the write even when the FC06 answer was lost."""
    h = online(H)
    h.bus.faults.append(drop(2, lambda q: q[1] == 6))
    h.submit(0, 40013, 550)
    h.cycle()
    w = h.writes()[-1]
    assert (w['state'], w['reason'], w['raw_after']) == (W_APPLIED, R_OK, 550)
    assert h.stats().timeout == 2


def test_write_verify_mismatch_uncertain(H):
    h = online(H)
    h.sims[1].ignore_writes = True
    h.submit(0, 40012, 250)
    h.cycle()
    w = h.writes()[-1]
    assert (w['state'], w['reason'], w['raw_after'], w['raw_before']) == (W_UNCERTAIN, R_VERIFY, 230, 230)


def test_write_no_ack_uncertain(H):
    h = online(H)
    h.sims[1].ignore_writes = True
    h.bus.faults.append(drop(2, lambda q: q[1] == 6))
    h.bus.faults.append(drop(2, lambda q: q[1] == 3 and q[2:6] == bytes([0, 11, 0, 1])))
    h.submit(0, 40012, 250)
    h.cycle()
    w = h.writes()[-1]
    # raw_after from the post-write snapshot (nothing was read back)
    assert (w['state'], w['reason'], w['raw_after']) == (W_UNCERTAIN, R_NO_ACK, 230)
    ok, c = h.command(0, w['cmd'])
    assert c.state == W_UNCERTAIN


def test_runbit_write_and_full_word(H):
    h = online(H)
    h.sims[1].run_delay = 10
    mark = len(h.bus.log)
    h.submit(0, 40005, 1)
    h.cycle()
    assert h.blocks(mark)[0] == (6, 4, 1)
    w = h.writes()[-1]
    assert (w['state'], w['raw_after'], w['raw_req']) == (W_APPLIED, 0x0A01, 1)
    ok, s = h.snapshot()
    assert s.regs[5] == 0x0A01


def test_signed_write(H):
    h = online(H)
    mark = len(h.bus.log)
    h.submit(0, 40021, -15)
    h.cycle()
    assert h.blocks(mark)[0] == (6, 20, 0xFFF1)
    w = h.writes()[-1]
    assert (w['state'], w['raw_after'], w['raw_before']) == (W_APPLIED, -15, -5)


def test_enqueue_rejections(H):
    h = online(H)
    cases = [(40001, 0, R_UNKNOWN), (40023, 1, R_UNKNOWN), (40036, 100, R_READONLY), (40020, 1, R_READONLY),
             (40012, 49, R_RANGE), (40012, 501, R_RANGE), (40005, 2, R_RANGE), (40005, 0x0A01, R_RANGE),
             (40027, 248, R_RANGE), (40021, -101, R_RANGE)]
    for addr, raw, reason in cases:
        rc, out = h.submit(0, addr, raw)
        assert rc == ESP_OK and (out.state, out.reason, out.cmd) == (W_REJECTED, reason, 0), (addr, raw)
        ev = h.writes()[-1]
        assert (ev['cmd'], ev['reason'], ev['addr'], ev['raw_req'], ev['who']) == (0, reason, addr, raw, 'op')
    assert len(h.writes()) == len(cases)
    rc, out = h.submit(0, 40027, 249)  # disabled sentinel is a valid request
    assert rc == ESP_OK and out.state == W_PENDING
    # unknown / unconfigured device: INVALID_ARG, nothing posted
    n = len(h.writes())
    for dev in (1, 3, 4, 255):
        rc, out = h.submit(dev, 40012, 250)
        assert rc == ESP_ERR_INVALID_ARG and out.state == W_REJECTED and out.cmd == 0
    assert len(h.writes()) == n
    assert h.lib.mex_core_write_submit(h.mem, 0, 40012, 250, b'x', None) == ESP_ERR_INVALID_ARG


def test_enqueue_interlock_and_who(H):
    h = H()
    h.sims[1].regs[5] = 1  # running
    h.cycle()
    rc, out = h.submit(0, 40027, 300, b'operator_with_long_name')
    assert (out.state, out.reason) == (W_REJECTED, R_INTERLOCK)
    assert h.writes()[-1]['who'] == 'operator_wi'  # GW_USER_NAME_MAX = 11
    rc, out = h.submit(0, 40012, 250, None)
    assert out.state == W_PENDING
    h.cycle()
    assert h.writes()[-1]['who'] == '' and h.writes()[-1]['state'] == W_APPLIED


def test_enqueue_offline(H):
    h = H()
    h.sims[1].alive = False
    rc, out = h.submit(0, 40012, 250)  # never polled
    assert (out.state, out.reason, out.cmd) == (W_REJECTED, R_OFFLINE, 0)
    h.run_for(5000)
    rc, out = h.submit(0, 40012, 250)
    assert (out.state, out.reason) == (W_REJECTED, R_OFFLINE)


def test_enqueue_after_failed_cycle_requires_fresh(H):
    h = online(H, port=make_port(poll_ms=5000))
    h.sims[1].alive = False
    h.bus.t += 4000
    h.cycle()  # one failed cycle: still ONLINE but no longer trusted for enqueue
    h.bus.t += 100
    rc, out = h.submit(0, 40012, 250)
    assert (out.state, out.reason) == (W_REJECTED, R_OFFLINE)


def test_queue_full_busy(H):
    h = online(H)
    for i in range(8):
        rc, out = h.submit(0, 40012, 200 + i)
        assert rc == ESP_OK and out.state == W_PENDING and out.cmd == i + 1
    rc, out = h.submit(0, 40013, 300)
    assert rc == ESP_ERR_NO_MEM and (out.state, out.reason, out.cmd) == (W_REJECTED, R_BUSY, 0)
    assert h.writes()[-1]['reason'] == R_BUSY
    mark = len(h.bus.log)
    h.cycle()
    assert [w['state'] for w in h.writes()[1:]] == [W_APPLIED] * 8
    assert [w['cmd'] for w in h.writes()[1:]] == list(range(1, 9))  # FIFO
    assert h.blocks(mark).count((3, 26, 4)) == 1
    ok, s = h.snapshot()
    assert s.regs[12] == 207


def test_revalidation_before_send_uses_new_running_state(H):
    h = online(H)
    h.sims[1].run_delay = 3
    _, a = h.submit(0, 40005, 1)
    _, b = h.submit(0, 40027, 300)  # valid at enqueue (stopped)
    assert a.state == b.state == W_PENDING
    mark = len(h.bus.log)
    h.cycle()
    assert (6, 26, 300) not in h.blocks(mark)
    w = {x['cmd']: x for x in h.writes()}
    assert w[a.cmd]['state'] == W_APPLIED and w[a.cmd]['raw_after'] == 0x0301
    assert (w[b.cmd]['state'], w[b.cmd]['reason']) == (W_REJECTED, R_INTERLOCK)
    assert w[b.cmd]['cmd'] == 2


def test_stale_snapshot_write_waits_for_fast_group(H):
    """poll_ms > MEX_FRESH_MS: enqueue accepted for an ONLINE device, sent after the fast group re-read."""
    h = online(H, port=make_port(poll_ms=5000))
    h.bus.t += 3500
    rc, out = h.submit(0, 40012, 250)
    assert rc == ESP_OK and out.state == W_PENDING
    mark = len(h.bus.log)
    assert h.run_once() == 0  # the queued write starts the device's cycle early
    assert h.blocks(mark) == FAST + [(6, 11, 250), (3, 11, 1)] + SLOW
    assert h.writes()[-1]['state'] == W_APPLIED


def test_failed_cycle_rejects_deferred_write_offline(H):
    h = online(H, port=make_port(poll_ms=5000))
    h.bus.t += 3500
    rc, out = h.submit(0, 40012, 250)
    assert out.state == W_PENDING
    h.sims[1].alive = False
    h.cycle()
    w = h.writes()[-1]
    assert (w['cmd'], w['state'], w['reason']) == (out.cmd, W_REJECTED, R_OFFLINE)
    assert all(fc != 6 for _, fc, _, _ in h.bus.log)


def test_write_between_blocks(H):
    h = online(H)
    mark = len(h.bus.log)
    h.bus.t += 100

    def hook(idx, q):
        if idx == mark + 3:
            h.bus.hooks.clear()
            rc, out = h.submit(0, 40013, 550)
            assert out.state == W_PENDING
    h.bus.hooks.append(hook)
    h.cycle()
    assert h.blocks(mark) == FAST[:4] + [(6, 12, 550), (3, 12, 1)] + FAST[4:] + SLOW
    assert h.writes()[-1]['state'] == W_APPLIED
    ok, s = h.snapshot()
    assert s.regs[13] == 550


def test_write_after_last_block_same_cycle(H):
    h = online(H)
    mark = len(h.bus.log)
    h.bus.t += 100

    def hook(idx, q):
        if idx == mark + 7:
            h.bus.hooks.clear()
            h.submit(0, 40013, 560)
    h.bus.hooks.append(hook)
    h.cycle()
    assert h.blocks(mark) == FAST + [(6, 12, 560), (3, 12, 1)] + SLOW
    assert len(h.of('snap')) == 2 and h.writes()[-1]['state'] == W_APPLIED


def test_write_during_slow_group_rereads_slow(H):
    h = online(H)
    h.run_for(5000)  # regular polling keeps the published snapshot fresh until the slow group is due
    seen = []

    def hook(idx, q):
        if (q[1], q[2] << 8 | q[3], q[4] << 8 | q[5]) == SLOW[1]:  # second slow block on the wire
            h.bus.hooks.clear()
            seen.append(idx)
            rc, out = h.submit(0, 40028, 60)
            assert out.state == W_PENDING
    h.bus.hooks.append(hook)
    while not h.writes():
        h.run_once()
    mark = seen[0] - len(FAST) - 1
    assert h.blocks(mark) == FAST + SLOW[:2] + [(6, 27, 60), (3, 27, 1)] + SLOW[2:] + SLOW
    ok, s = h.snapshot()
    assert s.regs[28] == 60


def test_command_history_eviction(H):
    h = online(H)
    for i in range(20):
        h.bus.t += 50
        rc, out = h.submit(0, 40012, 100 + i)
        assert out.cmd == i + 1
        h.cycle()
    for cmd in range(1, 5):
        assert not h.command(0, cmd)[0]
    for cmd in range(5, 21):
        ok, c = h.command(0, cmd)
        assert ok and c.state == W_APPLIED and c.raw_req == 100 + cmd - 1
    assert not h.command(1, 20)[0]  # dev must match
    assert not h.command(0, 0)[0] and not h.command(0, 999)[0]
    h.bus.t += 50
    for i in range(8):  # pending commands evict the oldest finals, never each other
        h.submit(0, 40013, 300 + i)
    for cmd in range(21, 29):
        ok, c = h.command(0, cmd)
        assert ok and c.state == W_PENDING
    assert [h.command(0, c)[0] for c in range(5, 21)] == [False] * 8 + [True] * 8


# ---------------------------------------------------------------- configuration


def test_cfg_validation(lib):
    good = make_port()
    assert lib.mex_core_port_valid(C.byref(good))
    bad_ports = [dict(baud=1199), dict(baud=115201), dict(parity=b'X'), dict(stop=0), dict(stop=3),
                 dict(poll_ms=199), dict(poll_ms=60001), dict(timeout_ms=49), dict(timeout_ms=2001),
                 dict(gap_ms=101), dict(retries=4), dict(offline_after=0), dict(offline_after=11)]
    for kw in bad_ports:
        assert not lib.mex_core_port_valid(C.byref(make_port(**kw))), kw
    for kw in [dict(baud=1200), dict(baud=115200), dict(parity=b'E'), dict(parity=b'O'), dict(stop=2),
               dict(gap_ms=0), dict(retries=0), dict(offline_after=10)]:
        assert lib.mex_core_port_valid(C.byref(make_port(**kw))), kw
    assert not lib.mex_core_port_valid(None)

    def valid(devs):
        arr, n = make_devs(devs)
        return lib.mex_core_cfg_valid(C.byref(good), arr, n)
    assert valid([]) and valid([(0, 1, True)]) and valid([(0, 1, True), (1, 2, True), (2, 3, True), (3, 247, True)])
    assert valid([(0, 1, True), (1, 1, False)])          # duplicate slave allowed if one is disabled
    assert not valid([(0, 1, True), (1, 1, True)])
    assert not valid([(0, 1, True), (0, 2, True)])       # duplicate id
    assert not valid([(4, 1, True)]) and not valid([(0, 0, True)]) and not valid([(0, 248, True)])
    assert not valid([(0, 1, True), (1, 2, True), (2, 3, True), (3, 4, True), (3, 5, False)])  # n > 4
    arr, _ = make_devs([(0, 1, True)])
    C.memmove(C.addressof(arr[0]) + DevCfg.name.offset, b'x' * 24, 24)  # unterminated name
    assert not lib.mex_core_cfg_valid(C.byref(good), arr, 1)
    assert not lib.mex_core_cfg_valid(C.byref(good), None, 1)


def test_configure_and_reconfigure_states(H, lib):
    h = H(configure=False)
    assert h.run_once() == 500  # not configured: idle
    assert h.reconfigure([(0, 1, True)]) == ESP_ERR_INVALID_STATE
    assert h.configure([(0, 1, True), (0, 2, True)]) == ESP_ERR_INVALID_ARG
    assert h.configure([(0, 1, True)]) == ESP_OK
    assert h.bus.port_applies == [(9600, b'N', 1)]
    assert h.configure([(0, 1, True)]) == ESP_ERR_INVALID_STATE
    assert h.reconfigure([(0, 1, True)], port=make_port(baud=7)) == ESP_ERR_INVALID_ARG
    rc, out = h.submit(1, 40012, 250)
    assert rc == ESP_ERR_INVALID_ARG


def test_reconfigure_slave_change_cancels_and_resets_silently(H):
    sims = {1: Mex150(1), 2: Mex150(2)}
    sims[2].regs[12] = 240
    h = H(sims=sims)
    h.cycle()
    h.bus.t += 100
    rc, out = h.submit(0, 40012, 250)
    assert out.state == W_PENDING
    assert h.reconfigure([(0, 2, True)]) == ESP_OK
    ok, c = h.command(0, out.cmd)
    assert c.state == W_PENDING  # applied only at the next cycle boundary
    n_comm = len(h.comms())
    mark = len(h.bus.log)
    h.run_once()
    w = h.writes()[-1]
    assert (w['cmd'], w['state'], w['reason']) == (out.cmd, W_REJECTED, R_CANCELLED)
    assert h.bus.port_applies == [(9600, b'N', 1)]  # line settings unchanged: no UART re-apply
    assert all(s == 2 for s, *_ in h.bus.log[mark:])  # polls the new slave
    # first decision after reconfigure is posted (online again)
    assert h.comms()[n_comm:] == [(0, True, 0, 0)]
    ok, s = h.snapshot()
    assert s.seq == 2 and s.online and s.regs[12] == 240


def test_reconfigure_slave_change_snapshot_cleared_before_first_poll(H):
    sims = {1: Mex150(1), 2: Mex150(2)}
    sims[2].alive = False
    h = H(sims=sims)
    h.cycle()
    h.reconfigure([(0, 2, True)])
    n_comm = len(h.comms())
    h.run_once()
    ok, s = h.snapshot()
    assert ok and not s.online and not s.slow_valid and s.seq == 1 and s.regs[12] == 0 and s.coils == 0
    assert h.comms()[n_comm:] == []  # no COMM for the reset itself
    h.run_for(5000)
    assert h.comms()[n_comm:] == [(0, False, TXN_TIMEOUT, 1)]


def test_reconfigure_port_and_name_only(H):
    h = H()
    h.cycle()
    h.reconfigure([(0, 1, True, b'Renamed')], port=make_port(baud=19200, parity=b'E', poll_ms=2000))
    h.run_once()
    assert h.bus.port_applies[-1] == (19200, b'E', 1)
    ok, s = h.snapshot()
    assert s.online and s.seq >= 1
    assert len(h.comms()) == 1  # no reset for a name/port change
    seq = s.seq
    h.run_for(4100)
    ok, s = h.snapshot()
    assert s.seq - seq in (2, 3)  # 2 s poll period now


def test_disabled_device_never_polled(H):
    h = H(devs=((0, 1, True), (1, 2, False)))
    h.run_for(5000)
    assert h.blocks(slave=2) == []
    assert {d for d, *_ in h.comms()} == {0}
    ok, s = h.snapshot(1)
    assert ok and not s.online and s.seq == 0
    rc, out = h.submit(1, 40012, 250)
    assert rc == ESP_OK and out.reason == R_OFFLINE
    # enable dev 1, disable dev 0 with a queued write
    h.bus.t += 100
    rc, out = h.submit(0, 40012, 250)
    assert out.state == W_PENDING
    h.reconfigure([(0, 1, False), (1, 2, True)])
    n_comm = len(h.comms(0))
    h.run_for(3000)
    w = h.writes()[-1]
    assert (w['cmd'], w['reason']) == (out.cmd, R_CANCELLED)
    assert len(h.comms(0)) == n_comm  # disabling posts nothing
    assert h.comms(1) == [(1, True, 0, 0)]
    mark = len(h.bus.log)
    h.run_for(3000)
    assert h.blocks(mark, slave=1) == []
    ok, s = h.snapshot(0)
    assert ok and not s.online


def test_remove_device(H):
    h = H(devs=((0, 1, True), (1, 2, True)))
    h.run_for(3000)
    h.reconfigure([(0, 1, True)])
    h.run_once()
    ok, s = h.snapshot(1)
    assert not ok and s.seq == 0
    assert h.stats(1).tx == 0
    rc, _ = h.submit(1, 40012, 250)
    assert rc == ESP_ERR_INVALID_ARG
    assert h.comm(1) == COMM_UNKNOWN
    mark = len(h.bus.log)
    h.run_for(3000)
    assert h.blocks(mark, slave=2) == []


def test_round_robin_fairness(H):
    h = H(devs=tuple((i, i + 1, True) for i in range(4)))
    h.run_for(30_000)
    per = [len([e for e in h.of('snap') if e[1] == d]) for d in range(4)]
    assert min(per) >= 15 and max(per) - min(per) <= 1, per
    firsts = [s for s, fc, a, v in h.bus.log if (fc, a, v) == FAST[0]]
    assert firsts[:8] == [1, 2, 3, 4, 1, 2, 3, 4]
    assert {d for d, *_ in h.comms()} == {0, 1, 2, 3}


def test_write_preempts_round_robin(H):
    h = H(devs=((0, 1, True), (1, 2, True)))
    h.run_for(1500)
    h.bus.t += 50
    rc, out = h.submit(1, 40012, 250)
    assert out.state == W_PENDING
    mark = len(h.bus.log)
    h.run_once()
    assert h.bus.log[mark][:2] == (2, 6)
    assert h.writes()[-1]['state'] == W_APPLIED


def test_wall_time_invalid(H):
    h = H()
    h.bus.wall_valid = False
    h.cycle()
    ok, s = h.snapshot()
    assert s.wall_ms == 0 and s.mono_ms
    assert h.of('comm')[0][5] == 0 and h.stats().online_since_ms == 0


# ---------------------------------------------------------------- fuzz


def test_garbage_responses_never_break_invariants(H):
    rnd = random.Random(1234)
    h = H(devs=((0, 1, True), (1, 2, True)))

    def garbage(q, resp):
        k = rnd.random()
        if k < 0.35:
            return None
        if k < 0.5:
            return b''
        if k < 0.7:
            return bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
        if k < 0.85 and resp:  # one flipped bit
            b = bytearray(resp)
            i = rnd.randrange(len(b))
            b[i] ^= 1 << rnd.randrange(8)
            return bytes(b)
        body = [q[0], q[1] | (0x80 if rnd.random() < 0.3 else 0), rnd.randrange(256)]
        body += [rnd.randrange(256) for _ in range(rnd.randrange(0, 8))]
        return frame(body)
    h.bus.faults.append(garbage)
    for _ in range(300):
        h.run_for(rnd.randrange(1, 3000))
        if rnd.random() < 0.3:
            h.submit(rnd.randrange(2), rnd.choice([40005, 40012, 40013, 40021, 40027, 40036]), rnd.randrange(-50, 600))
        if rnd.random() < 0.05:
            h.sims[rnd.choice([1, 2])].alive = rnd.random() < 0.7
    for d in (0, 1):
        assert counters_consistent(h.stats(d))
        states = [on for dev, on, *_ in h.comms(d)]
        assert all(a != b for a, b in zip(states, states[1:])), states  # never twice the same state
        ok, s = h.snapshot(d)
        assert ok
    finals = h.writes()
    assert all(w['state'] in (W_APPLIED, W_REJECTED, W_UNCERTAIN) for w in finals)
    queued = [w['cmd'] for w in finals if w['cmd']]
    assert len(queued) == len(set(queued))  # each queued command finalised exactly once
    assert h.bus.feeds >= sum(h.stats(d).tx for d in (0, 1))


CORE_FUZZ = r'''
#include <stdio.h>
#include <string.h>
#include "mex_core.h"

static uint64_t s = 0x2545F4914F6CDD1Dull;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint32_t)s; }

static uint64_t now = 1000;
static int locked, bad;
static uint8_t resp[300];
static size_t resp_n, resp_off;
static unsigned writes_seen;

static void lk(void *c) { (void)c; if (locked) bad++; locked = 1; }
static void ul(void *c) { (void)c; if (!locked) bad++; locked = 0; }
static uint64_t mono(void *c) { (void)c; return now; }
static int64_t wall(void *c) { (void)c; return (rnd() & 7) ? 1792371600000LL + (int64_t)now : 0; }
static void gap(void *c, uint16_t ms) { (void)c; if (locked) bad++; now += ms; resp_n = resp_off = 0; }
static int wr(void *c, const uint8_t *b, size_t n) {
    (void)c;
    if (locked || n != 8) bad++;
    if ((rnd() & 63) == 0) return MEX_TXN_E_UART;
    now += 9;
    resp_off = 0;
    unsigned k = rnd() % 16;
    if (k >= 4) {                                  /* correct answer (random data) */
        const unsigned count = (unsigned)b[4] << 8 | b[5];
        if (b[1] == 6) { memcpy(resp, b, 8); resp_n = 8; return 0; }
        const size_t nb = b[1] == 1 ? (count + 7) / 8 : count * 2u;
        if (nb > 250) { resp_n = 0; return 0; }
        resp[0] = b[0]; resp[1] = b[1]; resp[2] = (uint8_t)nb;
        for (size_t i = 0; i < nb; i++) resp[3 + i] = (uint8_t)rnd();
        if (b[1] == 3 && b[3] == 4 && (rnd() & 1)) resp[4] = 0; /* 40005: often stopped */
        uint16_t crc = mex_crc(resp, nb + 3); resp[nb + 3] = (uint8_t)crc; resp[nb + 4] = (uint8_t)(crc >> 8);
        resp_n = nb + 5;
        return 0;
    }
    if (k < 1) { resp_n = 0; return 0; }
    if (k < 2) {                                   /* plausible answer with a valid CRC */
        resp[0] = b[0]; resp[1] = (rnd() & 7) ? b[1] : (uint8_t)(b[1] | 0x80);
        resp_n = 5 + rnd() % 30;
        if (b[1] == 3 || b[1] == 1) resp[2] = (uint8_t)(resp_n - 5);
        for (size_t i = 3; i < resp_n - 2; i++) resp[i] = (uint8_t)rnd();
        uint16_t crc = mex_crc(resp, resp_n - 2); resp[resp_n - 2] = (uint8_t)crc; resp[resp_n - 1] = (uint8_t)(crc >> 8);
        return 0;
    }
    if (k < 3) { memcpy(resp, b, 8); memcpy(resp + 8, b, 8); resp_n = 8 + (rnd() % 9); return 0; } /* echo */
    resp_n = rnd() % sizeof resp;
    for (size_t i = 0; i < resp_n; i++) resp[i] = (uint8_t)rnd();
    return 0;
}
static int rd(void *c, uint8_t *b, size_t want, uint32_t tmo) {
    (void)c;
    if (locked) bad++;
    if ((rnd() & 255) == 0) return MEX_TXN_E_UART;
    size_t avail = resp_n - resp_off, k = want < avail ? want : avail;
    if (rnd() % 5 == 0 && k > 1) k = rnd() % k;    /* short read = timeout elapsed */
    memcpy(b, resp + resp_off, k);
    resp_off += k;
    now += k < want ? tmo : 1 + rnd() % 20;
    return (int)k;
}
static int papply(void *c, const mex_port_cfg_t *p) { (void)c; (void)p; if (locked) bad++; return 0; }
static void on_w(void *c, const mex_wresult_t *r, int32_t before, const char *who) {
    (void)c; (void)before;
    if (locked || r->state == MEX_W_PENDING || !who || strlen(who) > GW_USER_NAME_MAX) bad++;
    writes_seen++;
}
static void on_s(void *c, uint8_t d, uint32_t seq, uint64_t m, bool sf) { (void)c; (void)seq; (void)m; (void)sf; if (locked || d >= GW_MAX_DEVICES) bad++; }
static void on_c(void *c, uint8_t d, bool on, int e, uint32_t oc, int64_t ts) { (void)c; (void)on; (void)e; (void)oc; (void)ts; if (locked || d >= GW_MAX_DEVICES) bad++; }

static mex_core_t core;

int main(void) {
    const mex_core_io_t io = {NULL, lk, ul, mono, wall, gap, wr, rd, papply, NULL, on_s, on_c, on_w};
    mex_core_init(&core, &io);
    mex_port_cfg_t port = {9600, 'N', 1, 300, 60, 2, 1, 2};
    mex_dev_cfg_t devs[GW_MAX_DEVICES] = {{0, 1, true, "a"}, {1, 2, true, "b"}, {2, 3, false, "c"}, {3, 4, true, "d"}};
    if (mex_core_configure(&core, &port, devs, 4) != ESP_OK) return 2;
    static const uint16_t addrs[] = {40005, 40012, 40013, 40021, 40027, 40036, 40001, 40059};
    unsigned submitted = 0;
    for (unsigned it = 0; it < 60000; it++) {
        now += mex_core_run_once(&core);
        if (rnd() % 3 == 0) {
            mex_wresult_t r;
            const char *who = (rnd() & 1) ? "operator_with_a_long_name" : NULL;
            if (mex_core_write_submit(&core, (uint8_t)(rnd() % 5), addrs[rnd() % 8], (int32_t)(rnd() % 700) - 100, who, &r) == ESP_OK &&
                r.state == MEX_W_PENDING)
                submitted++;
        }
        if (rnd() % 2000 == 0) {
            for (unsigned i = 0; i < GW_MAX_DEVICES; i++) { devs[i].enabled = rnd() & 1; devs[i].slave = (uint8_t)(1 + i + (rnd() & 1) * 10); }
            port.retries = (uint8_t)(rnd() % 4);
            port.baud = (rnd() & 1) ? 9600 : 19200;
            (void)mex_core_reconfigure(&core, &port, devs, 1 + rnd() % GW_MAX_DEVICES);
        }
        mex_snapshot_t snap; mex_stats_t st; mex_wresult_t cr;
        (void)mex_core_snapshot(&core, (uint8_t)(rnd() % 5), &snap);
        mex_core_stats(&core, (uint8_t)(rnd() % 5), &st, (rnd() % 500) == 0);
        (void)mex_core_command(&core, (uint8_t)(rnd() % 4), rnd() % 64, &cr);
    }
    for (uint8_t d = 0; d < GW_MAX_DEVICES; d++) {
        mex_stats_t st;
        mex_core_stats(&core, d, &st, false);
        if (st.tx != st.rx_ok + st.crc + st.timeout + st.exception + st.malformed) bad++;
    }
    printf("%d %u %u\n", bad, submitted, writes_seen);
    return 0;
}
'''


def test_core_fuzz_sanitizers(tmp_path):
    from test_mex_frame import _sanitizers_available
    src = COMPONENTS / 'mex150'
    flags = [f'-I{src}']
    if _sanitizers_available(tmp_path):
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    out = compile_and_run(tmp_path, CORE_FUZZ, name='core_fuzz', flags=flags,
                          extra_sources=[src / f for f in ('frame.c', 'regmap.c', 'model.c', 'poll_plan.c', 'mex_core.c')])
    bad, submitted, writes_seen = map(int, out.split())
    assert bad == 0
    # enqueue needs a snapshot < 3 s old (strict for poll_ms <= MEX_FRESH_MS), which the random bus
    # often denies: this only guards that the queue/verify paths are exercised at all
    assert submitted > 50 and writes_seen > submitted


# ---------------------------------------------------------------- bounded receive (uart_port.c helper)


class ChunkDriver:
    """Model of IDF uart_read_bytes(): bytes arrive at scheduled times into the RX ring buffer; a read of n
    bytes loops until n arrived and restarts its `wait` for every chunk (xRingbufferReceiveUpTo per chunk)."""

    def __init__(self, clk, arrivals=()):
        self.clk = clk           # object with attribute t (ms)
        self.arr = sorted(arrivals)
        self.buf = bytearray()
        self.calls = []
        self.lie = 0             # avail() over-reports this many bytes
        self.fail = False
        self.ops = RxOps(None, RX_NOW(self._now), RX_AVAIL(self._avail), RX_RECV(self._recv))

    def load(self, arrivals):
        self.arr = sorted(arrivals)
        self.buf = bytearray()

    def _arrive(self):
        while self.arr and self.arr[0][0] <= self.clk.t:
            self.buf.append(self.arr.pop(0)[1])

    def _now(self, _):
        return self.clk.t & 0xFFFFFFFF

    def _avail(self, _):
        self._arrive()
        return len(self.buf) + self.lie

    def recv_py(self, n, wait):
        self.calls.append((n, wait))
        if self.fail:
            return None
        out = bytearray()
        while len(out) < n:
            self._arrive()
            if self.buf:
                k = min(n - len(out), len(self.buf))
                out += self.buf[:k]
                del self.buf[:k]
                continue
            if not self.arr or self.arr[0][0] - self.clk.t > wait:
                self.clk.t += wait   # this chunk's wait expired
                break
            self.clk.t = self.arr[0][0]  # wait restarts after every chunk
        return bytes(out)

    def _recv(self, _, ptr, n, wait):
        out = self.recv_py(n, wait)
        if out is None:
            return -1
        C.memmove(ptr, out, len(out))
        return len(out)


class Clk:
    def __init__(self, t=0):
        self.t = t


def rx(lib, drv, want, timeout):
    buf = C.create_string_buffer(max(want, 1))
    n = lib.mex_rx_bounded(C.byref(drv.ops), buf, want, timeout)
    return n, buf.raw[:max(n, 0)]


def trickle(t0, burst=(0x01, 0x03, 0xF0), every=250, count=2000):
    return [(t0 + 10 + i, b) for i, b in enumerate(burst)] + \
        [(t0 + 12 + every * k, 0x55) for k in range(1, count)]


def test_chunk_driver_models_the_idf_problem():
    """Sanity of the model: one plain 253-byte read on a trickling line blocks ~250 ms per byte."""
    clk = Clk(1000)
    drv = ChunkDriver(clk, trickle(1000))
    drv.recv_py(253, 300)
    assert clk.t - 1000 > 60_000


def test_rx_bounded_total_deadline_on_trickling_line(lib):
    clk = Clk(1000)
    drv = ChunkDriver(clk, trickle(1000))
    n, data = rx(lib, drv, 253, 300)
    assert clk.t - 1000 <= 300
    assert data == bytes([1, 3, 0xF0, 0x55])  # burst + the one noise byte that arrived before the deadline
    assert all(w <= 300 for _, w in drv.calls)
    assert all(k == 1 for k, w in drv.calls if w)  # a blocking receive only ever asks for one byte


def test_rx_bounded_complete_frame_returns_at_last_byte(lib):
    clk = Clk(0)
    frame_bytes = list(range(1, 9))
    drv = ChunkDriver(clk, [(20 + i, b) for i, b in enumerate(frame_bytes)])
    n, data = rx(lib, drv, 8, 300)
    assert (n, data) == (8, bytes(frame_bytes)) and clk.t == 27


def test_rx_bounded_buffered_bytes_taken_without_waiting(lib):
    clk = Clk(50)
    drv = ChunkDriver(clk, [(0, b) for b in b'ABCDE'])
    n, data = rx(lib, drv, 3, 300)
    assert (n, data, clk.t) == (3, b'ABC', 50)
    assert drv.calls == [(3, 0)]


def test_rx_bounded_silence_times_out_exactly(lib):
    clk = Clk(0)
    drv = ChunkDriver(clk)
    assert rx(lib, drv, 5, 300) == (0, b'') and clk.t == 300
    assert rx(lib, drv, 5, 0) == (0, b'') and clk.t == 300  # zero timeout: buffered bytes only


def test_rx_bounded_overreporting_driver_does_not_spin(lib):
    clk = Clk(0)
    drv = ChunkDriver(clk, [(100, 0x11)])
    drv.lie = 4
    n, data = rx(lib, drv, 5, 300)
    assert (n, data) == (1, b'\x11') and clk.t == 300 and len(drv.calls) < 20


def test_rx_bounded_errors_and_partial(lib):
    clk = Clk(0)
    drv = ChunkDriver(clk)
    drv.fail = True
    assert rx(lib, drv, 4, 100)[0] == TXN_UART
    drv = ChunkDriver(clk, [(clk.t, 0x22)])
    real = drv.recv_py

    def flaky(n, wait):
        out = real(n, wait)
        drv.fail = True  # the next call fails: the byte already received is returned
        return out
    drv.recv_py = flaky
    assert rx(lib, drv, 4, 100) == (1, b'\x22')
    assert lib.mex_rx_bounded(None, C.create_string_buffer(4), 4, 100) == TXN_UART


def test_rx_bounded_tick_wrap(lib):
    clk = Clk(0xFFFFFFFF - 100)
    drv = ChunkDriver(clk, [(clk.t + 150, 0x33), (clk.t + 160, 0x44)])
    assert rx(lib, drv, 2, 300) == (2, b'\x33\x44')
    clk2 = Clk(0xFFFFFFFF - 100)
    drv2 = ChunkDriver(clk2)
    assert rx(lib, drv2, 2, 300) == (0, b'') and clk2.t == 0xFFFFFFFF - 100 + 300


class TrickleHarness(Harness):
    """The core on top of mex_rx_bounded + the IDF-like driver; after every request the line only
    produces a plausible header (huge byte count) and then a noise byte every 250 ms."""

    def __init__(self, lib, **kw):
        super().__init__(lib, **kw)
        self.drv = ChunkDriver(self.bus)

    def _write_impl(self, ptr, n):
        r = Harness._write_impl(self, ptr, n)
        q = C.string_at(ptr, n)
        self.drv.load(trickle(self.bus.t, burst=(q[0], q[1], 0xF0)))
        return r

    def _gap(self, ctx, ms):
        Harness._gap(self, ctx, ms)
        self.drv.load(())

    def _read_impl(self, ptr, want, timeout):
        self._unlocked('read')
        return self.lib.mex_rx_bounded(C.byref(self.drv.ops), ptr, want, timeout)


def test_trickling_line_cannot_block_the_poll_task(lib):
    h = TrickleHarness(lib, port=make_port(timeout_ms=300, retries=1, gap_ms=5))
    t0, feeds0 = h.bus.t, h.bus.feeds
    assert h.lib.mex_core_run_once(h.mem) == 0
    # two attempts of gap + request + timeout each (previously ~61 s with 3 feeds)
    assert h.bus.t - t0 <= 2 * (5 + 9 + 300) + 10
    st = h.stats()
    assert st.tx == 2 and st.rx_ok == 0 and counters_consistent(st)
    h.run_for(30_000)
    assert h.comm() == COMM_OFFLINE
    h.check()


# ---------------------------------------------------------------- scheduler fairness


class ResubmitHarness(Harness):
    """A client (BMS / SNMP manager / script) that issues its next write to dev 0 as soon as the previous
    one finished."""

    def __init__(self, lib, **kw):
        super().__init__(lib, **kw)
        self.left = 400

    def _on_write(self, ctx, res, raw_before, who):
        Harness._on_write(self, ctx, res, raw_before, who)
        if res.contents.dev == 0 and self.left > 0:
            self.left -= 1
            out = WResult()
            self.lib.mex_core_write_submit(self.mem, 0, 40012, 200 + self.left % 50, b'bms', C.byref(out))


def snaps_of(h, dev, since=0):
    return [e for e in h.of('snap')[since:] if e[1] == dev]


def test_continuous_writes_do_not_starve_other_devices(lib):
    h = ResubmitHarness(lib, devs=((0, 1, True), (1, 2, True), (2, 3, True)))
    h.run_for(2500)
    mark = len(h.of('snap'))
    rc, out = h.submit(0, 40012, 210, b'bms')
    assert out.state == W_PENDING
    h.run_for(60_000)
    applied = [w for w in h.writes() if w['dev'] == 0 and w['state'] == W_APPLIED]
    assert len(applied) >= 60  # the writer still makes progress
    for dev in (1, 2):
        s = snaps_of(h, dev, mark)
        assert len(s) >= 40, (dev, len(s))
        gaps = [b[3] - a[3] for a, b in zip(s, s[1:])]
        assert max(gaps) < MEX_FRESH_MS, (dev, max(gaps))
        ok, snap = h.snapshot(dev)
        assert snap.online and h.bus.t - snap.mono_ms < MEX_FRESH_MS
    h.check()


def test_concurrent_writers_do_not_starve_other_devices(H):
    h = H(devs=((0, 1, True), (1, 2, True)))
    h.run_for(2500)
    mark = len(h.of('snap'))
    end = h.bus.t + 30_000
    k = 0
    while h.bus.t < end:
        h.submit(0, 40012, 250 + k % 2)  # two writers keep dev 0's queue non-empty
        h.submit(0, 40013, 500 + k % 2)
        k += 1
        h.run_once()
    s = snaps_of(h, 1, mark)
    assert len(s) >= 20
    ok, snap = h.snapshot(1)
    assert h.bus.t - snap.mono_ms < MEX_FRESH_MS
    assert len([w for w in h.writes() if w['state'] == W_APPLIED]) >= 40


def test_write_still_preempts_when_nothing_else_is_due(H):
    h = H(devs=((0, 1, True), (1, 2, True)), port=make_port(poll_ms=10_000))
    h.run_for(1500)
    for _ in range(3):  # consecutive write-triggered cycles while the other device is not due
        h.bus.t += 20
        rc, out = h.submit(0, 40012, 240)
        mark = len(h.bus.log)
        h.run_once()
        assert h.bus.log[mark][:2] == (1, 6)


def online_poll_gaps(h, dev=0, skip=3):
    s = snaps_of(h, dev)[skip:]
    return [b[3] - a[3] for a, b in zip(s, s[1:])]


def test_offline_peers_do_not_starve_online_device_max_timing(lib):
    h = Harness(lib, devs=tuple((i, i + 1, True) for i in range(4)),
                port=make_port(timeout_ms=2000, retries=3, gap_ms=100))
    for s in (2, 3, 4):
        h.sims[s].alive = False
    h.run_for(120_000)
    assert [h.comm(d) for d in range(4)] == [COMM_ONLINE, COMM_OFFLINE, COMM_OFFLINE, COMM_OFFLINE]
    gaps = online_poll_gaps(h, skip=10)
    # one online cycle + at most one single-attempt probe (gap + request + timeout) in between
    assert max(gaps) < 4_000, max(gaps)  # was ~27 s with full-retry probes scheduled as equals
    probes = [x for x in h.blocks(slave=None) if x == FAST[0]]
    assert probes
    # the offline devices are still probed (recovery stays possible)
    h.sims[3].alive = True
    h.run_for(15_000)
    assert h.comm(2) == COMM_ONLINE
    h.check()


def test_offline_peers_default_timing_keep_poll_period(lib):
    h = Harness(lib, devs=tuple((i, i + 1, True) for i in range(4)))
    for s in (2, 3, 4):
        h.sims[s].alive = False
    h.run_for(60_000)
    gaps = online_poll_gaps(h, skip=10)
    assert sum(gaps) / len(gaps) < 1_150 and max(gaps) < 1_500, (sum(gaps) / len(gaps), max(gaps))
    h.check()


# ---------------------------------------------------------------- contract details


def test_raw_after_equals_raw_before_without_readback(H):
    """gw_events.h: raw_after == raw_before when nothing was read back (even if the post-write snapshot
    shows the new value)."""
    h = online(H)
    h.bus.faults.append(drop(2, lambda q: q[1] == 3 and q[2:6] == bytes([0, 11, 0, 1])))
    h.submit(0, 40012, 250)
    h.cycle()
    w = h.writes()[-1]
    assert (w['state'], w['reason'], w['raw_before'], w['raw_after']) == (W_UNCERTAIN, R_VERIFY, 230, 230)
    ok, c = h.command(0, w['cmd'])
    assert c.raw_after == 230
    ok, s = h.snapshot()
    assert s.regs[12] == 250  # the slave did apply it; only the verification is missing


def test_enqueue_freshness_strict_at_default_poll(H):
    h = online(H)  # poll_ms 1000 <= MEX_FRESH_MS: DESIGN §9 rule exactly
    h.bus.t += 2900
    assert h.submit(0, 40012, 250)[1].state == W_PENDING
    h.cycle()
    h.bus.t += 3100
    rc, out = h.submit(0, 40012, 251)
    assert (out.state, out.reason) == (W_REJECTED, R_OFFLINE)
    assert h.comm() == COMM_ONLINE


def test_enqueue_freshness_bounded_for_long_poll(H):
    h = online(H, port=make_port(poll_ms=5000))
    h.bus.t += 7900  # < poll_ms + MEX_FRESH_MS
    assert h.submit(0, 40012, 250)[1].state == W_PENDING
    h.cycle()
    h.bus.t += 8100  # missed more than one poll period: no longer accepted
    rc, out = h.submit(0, 40012, 251)
    assert (out.state, out.reason) == (W_REJECTED, R_OFFLINE)
