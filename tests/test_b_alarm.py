"""Stream B alarm/catalog.c + engine.c: catalog/keys, params, debounce, register-bit alarms, comm-loss
freeze, enable/disable, rules (on-delay, hysteresis, LT/GT, freeze, slow group), ack, sorting, mask;
plus the catalog expansion against the Python parse of alarm_catalog.def."""
import ctypes
import re

from b_store.harness import b_lib, b_objs, run_c  # noqa: F401  (fixtures)
from conftest import COMPONENTS


def test_alarm_engine_c(b_objs, tmp_path):
    run_c(b_objs, tmp_path, 't_alarm')


class Desc(ctypes.Structure):
    _fields_ = [('id', ctypes.c_char_p), ('code', ctypes.c_uint16), ('src', ctypes.c_int), ('addr', ctypes.c_uint16),
                ('bit', ctypes.c_uint8), ('sev', ctypes.c_int), ('vreg', ctypes.c_uint16), ('ko', ctypes.c_char_p),
                ('en', ctypes.c_char_p)]


def test_catalog_matches_def(b_lib):
    rows = re.findall(r'^ALM\((.*)\)\s*$', (COMPONENTS / 'alarm' / 'alarm_catalog.def').read_text(encoding='utf-8'),
                      re.M)
    table = (Desc * len(rows)).in_dll(b_lib, 'alm_catalog')
    kinds = {'SRC_COIL': 0, 'SRC_BIT': 1, 'SRC_COMM': 2, 'SRC_RULE': 3}
    sevs = {'INFO': 0, 'MINOR': 1, 'MAJOR': 2, 'CRITICAL': 3}
    for c, row in zip(table, rows):
        args = [a.strip() for a in re.findall(r'"[^"]*"|[^,]+', row)]
        assert c.id.decode() == args[0]
        assert c.code == int(args[1])
        assert c.src == kinds[args[2]]
        assert (c.addr, c.bit) == (int(args[3]), int(args[4]))
        assert c.sev == sevs[args[5]]
        assert c.vreg == int(args[6])
        assert c.ko.decode() == args[7].strip('"') and c.en.decode() == args[8].strip('"')
