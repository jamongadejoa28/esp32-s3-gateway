"""Notification path on the host: the real components/snmp_gw/traps.c + snmp_logic.c on the real IDF 6.1
lwIP trap encoder (upstream snmp_traps.c after components/snmp_lwip/snmp_traps_fix.cmake, with
snmp_lwip_port.h force-included exactly like the firmware build), outgoing datagrams captured by
tests/snmp_host/trap_harness.c and decoded independently with pysnmp/pyasn1.

Covers: v1/v2c PDU shape (RFC 3416 4.2.6 sysUpTime.0 / snmpTrapOID.0 first, RFC 3584 3.2 mapping),
generic coldStart/authenticationFailure OIDs, enterprise notification varbinds (DESIGN §10),
per-target port/community/version fan-out, informs (request ids, ack matching, retries, give-up),
coldStart deferral until a route exists, rate-limit separation (authenticationFailure vs alarms,
COMM reports not dropped), inform-table overflow, disabling SNMP, and the test-trap rendezvous."""
import shutil
import subprocess

import pytest

from conftest import CFLAGS, COMPONENTS, INCLUDE_FLAGS, LISTS, ROOT, cc

pytest.importorskip('pysnmp')
from pyasn1.codec.ber import decoder  # noqa: E402
from pysnmp.proto import api  # noqa: E402

HOST = ROOT / 'tests' / 'snmp_host'
FIX = COMPONENTS / 'snmp_lwip' / 'snmp_traps_fix.cmake'
PEN = 32473
GW = (1, 3, 6, 1, 4, 1, PEN, 1)
SYS_UPTIME_0 = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SNMP_TRAP_OID_0 = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
COLD_START, AUTH_FAILURE = (1, 3, 6, 1, 6, 3, 1, 1, 5, 1), (1, 3, 6, 1, 6, 3, 1, 1, 5, 5)
SNMP_GRP = (1, 3, 6, 1, 2, 1, 11)
INFORM_SLOTS = 16


def idf_lwip():
    import os
    from pathlib import Path
    p = Path(os.environ.get('IDF_PATH', '/home/hajun/esp-idf-v6.1')) / 'components/lwip/lwip/src'
    if not (p / 'apps/snmp/snmp_traps.c').is_file():
        pytest.skip('ESP-IDF lwIP sources not found (set IDF_PATH)')
    return p


def run_fix(src, out):
    cmake = shutil.which('cmake')
    if cmake is None:
        pytest.skip('cmake not found')
    return subprocess.run([cmake, f'-DSNMP_TRAPS_IN={src}', f'-DSNMP_TRAPS_OUT={out}', '-P', str(FIX)],
                          capture_output=True, text=True)


@pytest.fixture(scope='module')
def harness(tmp_path_factory):
    lwip = idf_lwip()
    out = tmp_path_factory.mktemp('snmp_traps')
    fixed = out / 'snmp_traps_fixed.c'
    r = run_fix(lwip / 'apps/snmp/snmp_traps.c', fixed)
    assert r.returncode == 0, r.stderr
    inc = [f'-I{HOST / "include"}', f'-I{lwip / "include"}', f'-I{lwip / "apps/snmp"}', *INCLUDE_FLAGS,
           f'-I{COMPONENTS / "snmp_gw"}']
    objs = []
    upstream = [lwip / 'apps/snmp' / f'{n}.c' for n in ('snmp_asn1', 'snmp_core', 'snmp_msg', 'snmp_pbuf_stream',
                                                         'snmpv3')]
    upstream += [lwip / 'core' / f'{n}.c' for n in ('pbuf', 'mem', 'memp', 'def')] + [lwip / 'core/ipv4/ip4_addr.c']
    for src in upstream:
        obj = out / (src.stem + '.o')
        cc(['-std=gnu11', '-funsigned-char', '-w', '-O1', '-g', *inc, '-c', str(src), '-o', str(obj)])
        objs.append(obj)
    obj = out / 'snmp_traps_fixed.o'  # like the firmware: -include snmp_lwip_port.h (real sysUpTime)
    cc(['-std=gnu11', '-funsigned-char', '-w', '-O1', '-g', *inc, '-include',
        str(COMPONENTS / 'snmp_lwip' / 'snmp_lwip_port.h'), '-c', str(fixed), '-o', str(obj)])
    objs.append(obj)
    ours = [HOST / 'trap_harness.c', COMPONENTS / 'snmp_gw' / 'traps.c', COMPONENTS / 'snmp_gw' / 'snmp_logic.c',
            *[ROOT / p for p in LISTS['GW_HOST_SOURCES_ALARM'] if p.endswith('catalog.c')]]
    ours += [ROOT / p for p in LISTS['GW_HOST_SOURCES_GW_CORE'] + LISTS.get('GW_HOST_ONLY_SOURCES', [])]
    exe = out / 'trap_harness'
    flags = [f for f in CFLAGS if f != '-std=c11'] + ['-std=gnu11', '-funsigned-char']
    cc([*flags, *inc, *map(str, ours), *map(str, objs), '-o', str(exe), '-lcrypto', '-lm'])
    return exe


class Run:
    """Run a command script; .results[i] = (lines, packets) of the i-th command."""

    def __init__(self, exe, cmds):
        r = subprocess.run([str(exe)], input='\n'.join(cmds) + '\n', capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        self.log = r.stderr
        self.results, lines, pkts = [], [], []
        for line in r.stdout.splitlines():
            if line == 'OK':
                self.results.append((lines, pkts))
                lines, pkts = [], []
            elif line.startswith('PKT '):
                _, ip, port, hexdata = line.split()
                pkts.append(Pdu(ip, int(port), bytes.fromhex(hexdata)))
            else:
                assert not line.startswith('ERR'), line
                lines.append(line)
        assert len(self.results) == len(cmds), r.stdout

    def pkts(self, i):
        return self.results[i][1]

    def line(self, i):
        return self.results[i][0][0]

    def all_pkts(self):
        return [p for _, ps in self.results for p in ps]


class Pdu:
    def __init__(self, ip, port, data):
        self.ip, self.port, self.data = ip, port, data
        ver = int(api.decodeMessageVersion(data))
        self.version = ver
        msg, rest = decoder.decode(data, asn1Spec=api.PROTOCOL_MODULES[ver].Message())
        assert not rest
        self.community = bytes(msg['community']).decode()
        pdus = msg['data']
        self.kind = pdus.getName()
        pdu = pdus.getComponent()
        self.vbs = [(tuple(vb['name']), vb[1]) for vb in pdu['variable-bindings']]
        if self.kind == 'trap':  # v1 Trap-PDU
            self.enterprise = tuple(pdu['enterprise'])
            self.generic = int(pdu['generic-trap'])
            self.specific = int(pdu['specific-trap'])
            self.uptime = int(pdu['time-stamp'])
            self.agent_addr = '.'.join(str(b) for b in bytes(pdu['agent-addr'].getComponent()))
        else:
            self.request_id = int(pdu['request-id'])

    def value(self, vb):
        """Plain Python value of an ObjectSyntax CHOICE."""
        v = vb
        while hasattr(v, 'getComponent') and not hasattr(v, 'asTuple') and not hasattr(v, 'asOctets'):
            try:
                v = v.getComponent()
            except Exception:
                break
        if hasattr(v, 'asTuple'):
            return tuple(v)
        if hasattr(v, 'asOctets'):
            return bytes(v)
        return int(v)

    @property
    def trap_oid(self):
        assert self.vbs[1][0] == SNMP_TRAP_OID_0
        return self.value(self.vbs[1][1])

    @property
    def uptime_vb(self):
        assert self.vbs[0][0] == SYS_UPTIME_0
        return self.value(self.vbs[0][1])

    def payload(self):
        """Varbinds after sysUpTime.0/snmpTrapOID.0 (v2c) or all (v1) as (oid, value)."""
        vbs = self.vbs[2:] if self.version == 1 else self.vbs
        return [(n, self.value(v)) for n, v in vbs]


V2 = 'target 10.0.0.5 162 1 0 1 pub-trap'
V1 = 'target 10.0.0.6 1162 0 0 1 v1-comm'
INF = 'target 10.0.0.7 2162 1 1 1 inf-comm'


def base(*targets, enabled=1, auth=1):
    return ['init', *targets, f'apply {enabled} {auth}']


# ---------------------------------------------------------------- the build-time lwIP fix


def test_fix_script_refuses_a_changed_upstream(tmp_path):
    src = (idf_lwip() / 'apps/snmp/snmp_traps.c').read_text()
    changed = tmp_path / 'snmp_traps.c'
    changed.write_text(src.replace('{1, 3, 6, 1, 2, 1, 1, 3}       /* oid for sysUpTime */',
                                   '{1, 3, 6, 1, 2, 1, 1, 3, 0}    /* oid for sysUpTime */'))
    r = run_fix(changed, tmp_path / 'out.c')
    assert r.returncode != 0 and 'changed' in r.stderr and not (tmp_path / 'out.c').exists()


def test_fix_script_is_idempotent_and_minimal(tmp_path):
    src = idf_lwip() / 'apps/snmp/snmp_traps.c'
    out = tmp_path / 'out.c'
    assert run_fix(src, out).returncode == 0
    first = out.stat().st_mtime_ns
    assert run_fix(src, out).returncode == 0
    assert out.stat().st_mtime_ns == first, 'unchanged output is not rewritten (no rebuilds)'
    added = set(out.read_text().splitlines()) - set(src.read_text().splitlines())
    assert all(l.startswith(('/*', ' *', '  /*', '  snmp_v2_special_varbinds')) for l in added), added
    assert sum('oid.len++] = 0;' in l for l in added) == 2


# ---------------------------------------------------------------- PDU shape


def test_v2c_coldstart_has_instance_arcs_and_coldstart_oid(harness):
    r = Run(harness, base(V2) + ['clock 123450', 'cold'])
    [p] = r.pkts(-1)
    assert (p.ip, p.port, p.version, p.kind, p.community) == ('10.0.0.5', 162, 1, 'snmpV2-trap', 'pub-trap')
    assert [n for n, _ in p.vbs[:2]] == [SYS_UPTIME_0, SNMP_TRAP_OID_0], 'RFC 3416 4.2.6 first two varbinds'
    assert p.trap_oid == COLD_START
    assert p.uptime_vb == 12345, 'sysUpTime from snmp_lwip_port.h (centiseconds), not 0'
    assert p.payload() == []


def test_v2c_authentication_failure_oid_is_not_coldstart(harness):
    r = Run(harness, base(V2) + ['authfail 10.9.9.9'])
    [p] = r.pkts(-1)
    assert p.trap_oid == AUTH_FAILURE


def test_v1_generic_traps(harness):
    r = Run(harness, base(V1) + ['clock 5000', 'cold', 'authfail 10.9.9.9'])
    cold, auth = r.pkts(-2)[0], r.pkts(-1)[0]
    for p, gen in ((cold, 0), (auth, 4)):
        assert (p.version, p.kind, p.port, p.community) == (0, 'trap', 1162, 'v1-comm')
        assert (p.enterprise, p.generic, p.specific) == (SNMP_GRP, gen, 0)
        assert p.agent_addr == '192.168.1.2' and p.uptime == 500
        assert p.vbs == []


def test_enterprise_alarm_notification_v2c_and_v1(harness):
    r = Run(harness, base(V2, V1) + ['alarm 0 117 2 1 -35 4242'])
    v2, v1 = r.pkts(-1)
    notif = (1, 3, 6, 1, 4, 1, PEN, 1, 6, 8)  # gwAlarms.gwAlarmNotifObjects
    expect = [(notif + (1, 0), 1), (notif + (2, 0), 117), (notif + (4, 0), 3), (notif + (6, 0), -35),
              (notif + (7, 0), 4242)]
    assert v2.trap_oid == GW + (0, 1), 'gwAlarmRaised = mestioGwMIB.0.1'
    got = dict(v2.payload())
    for oid, val in expect:
        assert got[oid] == val, oid
    assert isinstance(got[notif + (3, 0)], bytes) and len(got[notif + (5, 0)]) == 11, 'name, DateAndTime'
    assert (v1.enterprise, v1.generic, v1.specific) == (GW, 6, 1)
    assert dict(v1.payload()) == got, 'same varbinds in v1'


def test_comm_config_firmware_notifications(harness):
    r = Run(harness, base(V2) + ['comm 0 0', 'clock 3500', 'idle', 'config 5 77', 'fw 9.9.9'])
    [comm], [cfg], [fw] = r.pkts(-3), r.pkts(-2), r.pkts(-1)
    assert comm.trap_oid == GW + (0, 3)
    dev = (1, 3, 6, 1, 4, 1, PEN, 1, 2, 1, 1)
    pl = dict(comm.payload())
    assert pl[dev + (2, 1)] == b'MEX150 #1' and pl[dev + (5, 1)] == 2, 'gwDevName.1, gwDevOnline.1 = false(2)'
    assert cfg.trap_oid == GW + (0, 5) and 77 in dict(cfg.payload()).values()
    assert fw.trap_oid == GW + (0, 6) and b'9.9.9' in dict(fw.payload()).values()


def test_disabled_targets_and_disabled_agent_send_nothing(harness):
    r = Run(harness, base('target 10.0.0.5 162 1 0 0 c', 'target bad-host 162 1 0 1 c', V2) + ['cold'])
    assert [p.ip for p in r.pkts(-1)] == ['10.0.0.5'] and r.pkts(-1)[0].community == 'pub-trap'
    r = Run(harness, base(V2, enabled=0) + ['cold', 'alarm 0 117 2 1 1 1', 'authfail 1.2.3.4', 'clock 9999999',
                                            'idle'])
    assert r.all_pkts() == []


# ---------------------------------------------------------------- informs


def test_inform_ack_retry_and_give_up(harness):
    cmds = base(INF) + ['alarm 0 117 2 1 1 1', 'peer 10.0.0.7', 'clock 6001', 'idle', 'clock 11002', 'idle',
                        'clock 16003', 'idle', 'clock 21004', 'idle', 'peer 10.0.0.7', 'stats']
    r = Run(harness, cmds)
    first = r.pkts(3)[0]
    assert (first.kind, first.port, first.community) == ('inform-request', 2162, 'inf-comm')
    assert r.line(4) == 'PEER 1 inf-comm'
    retries = [r.pkts(i)[0] for i in (6, 8, 10)]
    assert [p.kind for p in retries] == ['inform-request'] * 3
    assert len({first.request_id, *[p.request_id for p in retries]}) == 4, 'new request id per retransmission'
    assert r.pkts(12) == [], 'given up after 3 retries'
    assert r.line(13) == 'PEER 0' and r.line(14).split()[3] == '1', 'counted in gwInformsFailed'


def test_inform_ack_by_any_request_id_stops_retries(harness):
    cmds = base(INF) + ['alarm 0 117 2 1 1 1', 'clock 6001', 'idle']
    r = Run(harness, cmds)
    ids = [r.pkts(3)[0].request_id, r.pkts(5)[0].request_id]
    assert ids[0] != ids[1]
    r = Run(harness, cmds + [f'ack {ids[1]} 10.0.0.9', 'clock 11002', 'idle', f'ack {ids[0]} 10.0.0.7',
                             'clock 16003', 'idle', 'clock 30000', 'idle', 'stats'])
    assert len(r.pkts(8)) == 1, 'ack from another address is ignored'
    assert r.pkts(11) == [] and r.pkts(13) == [] and r.line(14).split()[3] == '0', 'the first id still acks'


def test_failed_first_inform_is_tracked_and_retransmitted(harness):
    r = Run(harness, base(INF) + ['route 0', 'alarm 0 117 2 1 1 1', 'route 1', 'clock 6001', 'idle', 'stats'])
    assert r.pkts(4) == []
    [p] = r.pkts(7)
    assert p.kind == 'inform-request' and p.trap_oid == GW + (0, 1)


def test_full_inform_table_degrades_to_traps_instead_of_evicting(harness):
    """4 devices x 4 inform targets fill the 16 slots (COMM reports bypass the bucket); the next
    notification goes out as plain traps and no inform in flight is evicted or counted as failed."""
    tgt = [f'target 10.0.1.{i} 162 1 1 1 c{i}' for i in range(4)]
    cmds = base(*tgt)
    # 4 devices go offline -> 4 reports x 4 inform targets = 16 informs (table full), then config change
    cmds += [f'comm {d} 0' for d in range(4)] + ['clock 3500', 'idle', 'config 5 1', 'stats']
    r = Run(harness, cmds)
    comm = r.pkts(-3)
    assert len(comm) == 16 and all(p.kind == 'inform-request' for p in comm)
    cfg = r.pkts(-2)
    assert [p.kind for p in cfg] == ['snmpV2-trap'] * 4, 'no free slot: sent as trap, nothing evicted'
    assert r.line(-1).split()[3] == '0', 'no inform counted as failed'


def test_disabling_snmp_abandons_pending_informs(harness):
    r = Run(harness, base(INF) + ['alarm 0 117 2 1 1 1', INF, 'apply 0 1', 'clock 6001', 'idle', 'peer 10.0.0.7',
                                  'stats'])
    assert r.pkts(7) == [] and r.line(8) == 'PEER 0' and r.line(9).split()[3] == '0'


def test_unchanged_target_keeps_its_informs(harness):
    r = Run(harness, base(INF) + ['alarm 0 117 2 1 1 1', INF, 'apply 1 1', 'clock 6001', 'idle'])
    assert len(r.pkts(7)) == 1


# ---------------------------------------------------------------- coldStart, rate limits


def test_coldstart_waits_for_a_route(harness):
    cmds = base(V2, INF) + ['route 0', 'cold', 'clock 1500', 'idle', 'clock 2000', 'idle', 'route 1',
                            'clock 2500', 'idle', 'clock 3000', 'idle', 'clock 9000', 'idle']
    r = Run(harness, cmds)
    assert r.pkts(5) == [] and r.pkts(7) == [] and r.pkts(9) == [] and r.pkts(12) == []
    sent = r.pkts(14)
    assert sorted(p.ip for p in sent) == ['10.0.0.5', '10.0.0.7']
    assert all(p.trap_oid == COLD_START for p in sent)
    assert {p.kind for p in sent} == {'snmpV2-trap', 'inform-request'}
    later = r.pkts(16)
    assert [(p.ip, p.kind) for p in later] == [('10.0.0.7', 'inform-request')], \
        'no second coldStart; only the unacknowledged inform is retransmitted'
    assert 'failed' not in r.log, 'retries while there is no route are quiet'


def test_coldstart_gives_up_after_its_window(harness):
    r = Run(harness, base(V2) + ['route 0', 'cold', 'clock 301001', 'idle', 'route 1', 'clock 400000', 'idle'])
    assert r.pkts(4) == [] and r.pkts(6) == [] and r.pkts(9) == [], 'window of 300 s'
    assert 'coldStart not delivered' in r.log


def test_coldstart_inform_is_acknowledged_like_others(harness):
    r = Run(harness, base(INF) + ['cold'])
    p = r.pkts(-1)[0]
    r = Run(harness, base(INF) + ['cold', f'ack {p.request_id} 10.0.0.7', 'clock 9000', 'idle'])
    assert r.pkts(-1) == []


def test_auth_failure_flood_does_not_starve_alarms(harness):
    cmds = base(V2) + [f'authfail 10.6.6.{i}' for i in range(50)] + ['alarm 0 117 2 1 1 1', 'stats']
    r = Run(harness, cmds)
    auth = [p for i in range(3, 53) for p in r.pkts(i)]
    assert len(auth) == 2, 'own bucket: burst 2'
    assert [p.trap_oid for p in r.pkts(53)] == [GW + (0, 1)], 'the alarm still goes out'
    assert r.log.count('authentication failure') == 1, 'log line rate-limited'


def test_auth_failure_is_never_an_inform(harness):
    r = Run(harness, base(INF) + ['authfail 10.6.6.6', 'peer 10.0.0.7'])
    assert r.pkts(3)[0].kind == 'snmpV2-trap' and r.line(4) == 'PEER 0'


def test_auth_traps_off(harness):
    r = Run(harness, base(V2, auth=0) + ['authfail 10.6.6.6'])
    assert r.pkts(-1) == []


def test_alarm_rate_limit_and_comm_reports_bypass_it(harness):
    alarms = [f'alarm 0 117 2 1 1 {i + 1}' for i in range(15)]
    cmds = base(V2) + ['comm 1 0', 'clock 3000'] + alarms + ['idle', 'stats']  # report due at 3000
    r = Run(harness, cmds)
    sent = [p for i in range(5, 20) for p in r.pkts(i)]
    assert len(sent) == 10, 'burst of 10'
    assert [p.trap_oid for p in r.pkts(20)] == [GW + (0, 3)], 'gwCommLost although the bucket is empty'
    assert r.line(-1).split()[2] == '5'


# ---------------------------------------------------------------- test-trap rendezvous


def test_test_trap_results(harness):
    r = Run(harness, base(V2, V1) + ['test 1000'])
    assert r.line(-1) == 'TEST 2 10.0.0.5:1 10.0.0.6:1'
    assert {p.trap_oid if p.version == 1 else (p.enterprise + (0, p.specific)) for p in r.pkts(-1)} == {GW + (0, 7)}
    assert {p.version for p in r.pkts(-1)} == {0, 1}


def test_test_trap_inform_waits_for_ack_and_queue_full(harness):
    r = Run(harness, base(INF) + ['test 10'])
    assert r.line(-1) == 'TEST 1 10.0.0.7:0', 'not acknowledged within the timeout'
    r = Run(harness, base(V2) + ['queue 0', 'test 10'])
    assert r.line(-1) == 'TEST 0'
