"""Stream B store/evlog_core.c: two-file rings, rotation, seq recovery, torn tails, RAM-tail merge,
paging/filters, and the wire type names (must equal the docs/API.md §4.12 list)."""
import re

from b_store.harness import b_objs, run_c  # noqa: F401  (fixtures)
from conftest import ROOT


def test_eventlog_c(b_objs, tmp_path):
    d = tmp_path / 'log'
    d.mkdir()
    out = run_c(b_objs, tmp_path, 't_evlog', d)
    names = dict((int(t), n) for t, n in re.findall(r'^type (\d+) (\S+)$', out, re.M))
    api = (ROOT / 'docs' / 'API.md').read_text()
    para = api[api.index('**GET /system/logs**'):api.index('<!-- schema: logs.response -->')]
    # record field names quoted in the paragraph are not type names
    documented = set(re.findall(r'`([a-z_]+)`', para)) - {'kind', 'audit', 'system', 'before', 'limit', 'type',
                                                          'code', 'value', 'extra', 'user', 'seq'}
    assert set(names.values()) == documented
    assert all(1 <= t <= 31 for t, n in names.items() if n in {'alarm_raise', 'comm_lost', 'boot', 'health'})
    assert all(32 <= t <= 63 for t, n in names.items() if n in {'login_ok', 'reg_write', 'snmp_test'})
