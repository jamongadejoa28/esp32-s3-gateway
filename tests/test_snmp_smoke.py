"""tools/snmp_smoke.py against a local pysnmp agent (no hardware).

The stand-in agent mirrors the gateway's access model: v2c read-only community, v3 users authPriv
SHA/AES with gwmonitor read-only and gwadmin read-write. A pysnmp notification originator sends a
v2c trap and an inform to the smoke tool's trap receiver.
"""
import asyncio
import json
import socket
import subprocess
import sys
import threading
import time

import pytest

from conftest import ROOT

pysnmp = pytest.importorskip('pysnmp')
from pysnmp.carrier.asyncio.dgram import udp  # noqa: E402
from pysnmp.entity import config, engine  # noqa: E402
from pysnmp.entity.rfc3413 import cmdrsp, context  # noqa: E402
from pysnmp.hlapi.v3arch.asyncio import (  # noqa: E402
    USM_AUTH_HMAC96_SHA, USM_PRIV_CFB128_AES, CommunityData, ContextData, NotificationType, ObjectIdentity,
    ObjectType, OctetString, SnmpEngine, UdpTransportTarget, send_notification,
)

TOOL = ROOT / 'tools' / 'snmp_smoke.py'
RO_COMM = 'ro-comm-123'
USERS = {'gwmonitor': ('monitor-auth', 'monitor-priv'), 'gwadmin': ('admin-auth-1', 'admin-priv-1')}


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture(scope='module')
def agent():
    port = free_udp_port()
    ready = threading.Event()
    loop = asyncio.new_event_loop()

    holder = {}

    async def start():
        eng = holder['eng'] = engine.SnmpEngine()
        config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', port)))
        config.add_v1_system(eng, 'ro-area', RO_COMM)
        # pysnmp grants SET when a write view has no entries, so read-only users get an unrelated one
        nowrite = (1, 3, 6, 1, 4, 1, 99999)
        config.add_vacm_user(eng, 2, 'ro-area', 'noAuthNoPriv', (1, 3, 6, 1), nowrite)
        for name, (auth, priv) in USERS.items():
            config.add_v3_user(eng, name, USM_AUTH_HMAC96_SHA, auth, USM_PRIV_CFB128_AES, priv)
            write = (1, 3, 6, 1) if name == 'gwadmin' else nowrite
            config.add_vacm_user(eng, 3, name, 'authPriv', (1, 3, 6, 1), write)
        ctx = context.SnmpContext(eng)
        for cls in (cmdrsp.GetCommandResponder, cmdrsp.NextCommandResponder, cmdrsp.BulkCommandResponder,
                    cmdrsp.SetCommandResponder):
            cls(eng, ctx)
        await asyncio.sleep(0.2)
        ready.set()

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start())
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(10)
    yield port

    def shutdown():
        holder['eng'].close_dispatcher()
        for task in asyncio.all_tasks(loop):
            task.cancel()
        loop.call_later(0.05, loop.stop)

    loop.call_soon_threadsafe(shutdown)
    t.join(5)
    loop.close()


def smoke(*args, timeout=120):
    r = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True, timeout=timeout)
    return r


def statuses(path):
    return {r['name']: r['status'] for r in json.loads(path.read_text())}


def test_v2c_checks(agent, tmp_path):
    out = tmp_path / 'r.json'
    r = smoke('--host', '127.0.0.1', '--port', str(agent), '--community', RO_COMM,
              '--walk-root', '1.3.6.1.2.1.1', '--walk-root', '1.3.6.1.6.3.10.2.1', '--json', str(out), 'v2c')
    assert r.returncode == 0, r.stdout + r.stderr
    st = statuses(out)
    assert st['v2c GET sysDescr.0 sysUpTime.0'] == 'PASS'
    assert st['v2c walk 1.3.6.1.2.1.1'] == 'PASS'
    assert st['v2c SET with RO community rejected'] == 'PASS'
    assert st['v2c wrong community gets no answer'] == 'PASS'


def test_v2c_walk_of_missing_enterprise_subtree_fails(agent, tmp_path):
    out = tmp_path / 'r.json'
    r = smoke('--host', '127.0.0.1', '--port', str(agent), '--community', RO_COMM, '--json', str(out), 'v2c')
    assert r.returncode == 1
    assert statuses(out)['v2c walk 1.3.6.1.4.1.32473'] == 'FAIL'           # stand-in agent has no MESTIO MIB


def test_v3_checks(agent, tmp_path):
    out = tmp_path / 'r.json'
    (ra, rp), (wa, wp) = USERS['gwmonitor'], USERS['gwadmin']
    r = smoke('--host', '127.0.0.1', '--port', str(agent), '--ro-auth', ra, '--ro-priv', rp,
              '--rw-auth', wa, '--rw-priv', wp, '--json', str(out), 'v3')
    assert r.returncode == 0, r.stdout + r.stderr
    st = statuses(out)
    assert all(v == 'PASS' for v in st.values()), st
    names = ' '.join(st)
    for needle in ('authPriv GET as gwmonitor', 'authPriv GET as gwadmin', 'SET sysLocation.0',
                   'SET as RO user gwmonitor rejected', 'noAuthNoPriv', 'authNoPriv', 'wrong auth passphrase',
                   'unknown user'):
        assert needle in names


def test_v3_wrong_credentials_fail(agent, tmp_path):
    out = tmp_path / 'r.json'
    r = smoke('--host', '127.0.0.1', '--port', str(agent), '--timeout', '1', '--retries', '0',
              '--ro-auth', 'wrong-auth-x', '--ro-priv', 'wrong-priv-x', '--json', str(out), 'v3')
    assert r.returncode == 1
    assert statuses(out)['v3 authPriv GET as gwmonitor (RO)'] == 'FAIL'


@pytest.mark.parametrize('inform', [False, True])
def test_trap_receiver(tmp_path, inform):
    port = free_udp_port()
    out, traps = tmp_path / 'r.json', tmp_path / 't.json'
    proc = subprocess.Popen([sys.executable, str(TOOL), '--trap-port', str(port), '--trap-listen', '127.0.0.1',
                             '--trap-community', 'mestio-trap', '--trap-seconds', '20', '--trap-count', '1',
                             '--json', str(out), '--trap-json', str(traps), 'trap'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        line = proc.stdout.readline()
        assert 'listening for traps' in line, line

        async def send():
            eng = SnmpEngine()
            res = await send_notification(
                eng, CommunityData('mestio-trap', mpModel=1),
                await UdpTransportTarget.create(('127.0.0.1', port), timeout=2, retries=1), ContextData(),
                'inform' if inform else 'trap',
                NotificationType(ObjectIdentity('1.3.6.1.4.1.32473.1.0.3')).add_varbinds(
                    ObjectType(ObjectIdentity('1.3.6.1.4.1.32473.1.6.9.0'), OctetString('comm_lost'))),
                lookupMib=False)
            eng.close_dispatcher()
            return res

        time.sleep(0.3)
        ei, es, _, _ = asyncio.run(send())
        assert not ei and not es, (ei, es)                                  # inform acknowledged
        rest, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, rest
    got = json.loads(traps.read_text())
    assert got[0]['trap_oid'] == '1.3.6.1.4.1.32473.1.0.3'
    assert statuses(out)['received >= 1 notification(s)'] == 'PASS'


def test_trap_receiver_times_out(tmp_path):
    out = tmp_path / 'r.json'
    r = smoke('--trap-port', str(free_udp_port()), '--trap-listen', '127.0.0.1', '--trap-seconds', '1',
              '--json', str(out), 'trap')
    assert r.returncode == 1
    assert statuses(out)['received >= 1 notification(s)'] == 'FAIL'
