"""mex150 poll_plan.c: DESIGN.md §9 block lists (coil blocks 0/8/16/24 included), register coverage
against regmap.def, slow-group scheduling, cycle composition (online / offline single block) and
storing block values into a snapshot."""
import ctypes as C

import pytest

from test_contracts import REGMAP, parse_def

SLOW_MS = 10_000


class Block(C.Structure):
    _fields_ = [('fc', C.c_uint8), ('start', C.c_uint16), ('count', C.c_uint16)]


class Snapshot(C.Structure):
    _fields_ = [('regs', C.c_uint16 * 60), ('coils', C.c_uint32), ('wall_ms', C.c_int64), ('mono_ms', C.c_uint64),
                ('seq', C.c_uint32), ('online', C.c_bool), ('slow_valid', C.c_bool), ('measurement_valid', C.c_bool)]


FAST = [(1, 0, 8), (1, 8, 8), (1, 16, 8), (1, 24, 8), (3, 1, 3), (3, 4, 4), (3, 10, 12), (3, 35, 2)]
SLOW = [(3, 26, 4), (3, 52, 2), (3, 58, 1)]


@pytest.fixture(scope='module')
def lib(host_lib):
    l = host_lib('MEX150')
    l.mex_plan_slow_due.argtypes = [C.c_uint64, C.c_uint64, C.c_bool]
    l.mex_plan_slow_due.restype = C.c_bool
    l.mex_plan_cycle.argtypes = [C.c_bool, C.c_bool, C.POINTER(Block), C.c_size_t]
    l.mex_plan_cycle.restype = C.c_size_t
    l.mex_block_store.argtypes = [C.POINTER(Block), C.POINTER(C.c_uint16), C.POINTER(Snapshot)]
    l.mex_block_store.restype = None
    l.fast = (Block * 8).in_dll(l, 'mex_fast_blocks')
    l.slow = (Block * 3).in_dll(l, 'mex_slow_blocks')
    return l


def tup(b):
    return (b.fc, b.start, b.count)


def plan(lib, online, slow_due, cap=11):
    out = (Block * max(cap, 1))()
    n = lib.mex_plan_cycle(online, slow_due, out, cap)
    return [tup(out[i]) for i in range(n)]


def test_block_tables_match_design(lib):
    assert [tup(b) for b in lib.fast] == FAST
    assert [tup(b) for b in lib.slow] == SLOW


def test_blocks_cover_every_register_exactly_once():
    """Every REG row of regmap.def is read by exactly one block; fast/slow split as DESIGN §9."""
    regs = {r['addr'] for r in parse_def(REGMAP)['REG']}
    seen = {}
    for group, blocks in (('fast', FAST), ('slow', SLOW)):
        for fc, start, count in blocks:
            if fc != 3:
                continue
            for a in range(40001 + start, 40001 + start + count):
                assert a not in seen, a
                seen[a] = group
    assert regs <= set(seen)
    assert {a for a, g in seen.items() if g == 'slow'} == {40027, 40028, 40029, 40030, 40053, 40054, 40059}
    coils = sorted(n for fc, start, count in FAST if fc == 1 for n in range(start + 1, start + count + 1))
    assert coils == list(range(1, 33))
    assert max(count for _, _, count in FAST + SLOW) <= 16  # MEX_MAX_READ


def test_slow_due(lib):
    assert lib.mex_plan_slow_due(5000, 0, False)                 # never read
    assert lib.mex_plan_slow_due(5000, 4000, True)               # write since
    assert not lib.mex_plan_slow_due(5000, 4000, False)
    assert not lib.mex_plan_slow_due(4000 + SLOW_MS - 1, 4000, False)
    assert lib.mex_plan_slow_due(4000 + SLOW_MS, 4000, False)
    assert lib.mex_plan_slow_due(3000, 4000, False)              # clock anomaly -> read


def test_plan_cycle(lib):
    assert plan(lib, True, False) == FAST
    assert plan(lib, True, True) == FAST + SLOW
    assert plan(lib, False, True) == [FAST[0]]                   # offline: first block only
    assert plan(lib, False, False) == [FAST[0]]
    assert plan(lib, True, True, cap=5) == FAST[:5]              # never overflows cap
    assert plan(lib, True, True, cap=9) == FAST + SLOW[:1]
    assert lib.mex_plan_cycle(True, True, None, 11) == 0
    assert plan(lib, True, True, cap=0) == []


def test_block_store_coils(lib):
    s = Snapshot()
    s.coils = 0xFFFFFFFF
    vals = (C.c_uint16 * 16)(*([1, 0] * 8))
    lib.mex_block_store(C.byref(Block(1, 16, 8)), vals, C.byref(s))
    assert (s.coils >> 16) & 0xFF == 0b01010101                  # cleared bits are cleared
    assert s.coils & 0xFF00FFFF == 0xFF00FFFF                    # other bits untouched
    lib.mex_block_store(C.byref(Block(1, 28, 8)), (C.c_uint16 * 16)(*([1] * 8)), C.byref(s))
    assert s.coils >> 28 == 0xF                                  # bits >= 32 ignored, no UB


def test_block_store_holding(lib):
    s = Snapshot()
    vals = (C.c_uint16 * 16)(*range(100, 116))
    lib.mex_block_store(C.byref(Block(3, 10, 12)), vals, C.byref(s))
    assert [s.regs[i] for i in range(11, 23)] == list(range(100, 112))
    assert s.regs[10] == 0 and s.regs[23] == 0
    lib.mex_block_store(C.byref(Block(3, 58, 4)), vals, C.byref(s))
    assert s.regs[59] == 100                                     # 40059; indexes >= 60 ignored
    lib.mex_block_store(C.byref(Block(3, 35, 2)), (C.c_uint16 * 2)(0xFF06, 480), C.byref(s))
    assert s.regs[36] == 0xFF06 and s.regs[37] == 480
    lib.mex_block_store(C.byref(Block(6, 0, 2)), vals, C.byref(s))  # unknown fc: no effect
    lib.mex_block_store(None, vals, C.byref(s))
    lib.mex_block_store(C.byref(Block(3, 1, 1)), None, C.byref(s))
