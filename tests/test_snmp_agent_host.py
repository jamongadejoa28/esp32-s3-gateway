"""End-to-end SNMP agent tests on the host: the real lwIP SNMP core (IDF 6.1 sources) with the gateway's
usm.c, registry.c, mib_system.c, mib_mex_setpoint.c, mib_util.c and snmp_logic.c, the host twin of the
PSA crypto backend (tests/snmp_host/snmpv3_host.c, sharing snmp_lwip/snmpv3_util.h) and fakes for other
components (tests/snmp_host/agent_harness.c), driven over UDP by pysnmp as the manager.

Covers the USM contract of snmp_gw.h (stream E required test: a noAuthNoPriv GET as "gwadmin" must
yield a report, never data), RO/RW enforcement through the transport context, RFC 3414/3826
interoperability with an independent implementation, and the mexSetpointTable SET semantics."""
import asyncio
import subprocess

import pytest

from conftest import CFLAGS, COMPONENTS, INCLUDE_FLAGS, LISTS, ROOT, cc

pytest.importorskip('pysnmp')
import pysnmp.entity.config  # noqa: E402,F401  (import order: avoids a circular import inside pysnmp)
from pysnmp.hlapi.v3arch.asyncio import (  # noqa: E402
    USM_AUTH_HMAC96_SHA, USM_AUTH_NONE, USM_PRIV_CFB128_AES, USM_PRIV_NONE, CommunityData, ContextData,
    Integer32, ObjectIdentity, ObjectType, OctetString, SnmpEngine, UdpTransportTarget, UsmUserData, get_cmd,
    next_cmd, set_cmd,
)

HOST = ROOT / 'tests' / 'snmp_host'
LWIP = None  # resolved in the fixture (IDF_PATH)
PASS = {'gwmonitor': ('monitor-auth-1', 'monitor-priv-1'), 'gwadmin': ('admin-auth-12', 'admin-priv-12')}
ENGINE_ID = '80007ed903246f28a0b1c2'
PEN = 32473
SYS_DESCR, SYS_OBJID, SYS_NAME = '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.5.0'
SP_SET_TEMP = f'1.3.6.1.4.1.{PEN}.1.4.1.1.12.1'   # mexSpSetTemp.<gwDevIndex 1>
SP_HI_TEMP = f'1.3.6.1.4.1.{PEN}.1.4.1.1.27.1'    # mexSpHiTemp.1 (STOPPED row, sentinel 249)
SNMP_ENGINE_ID, SNMP_ENGINE_BOOTS = '1.3.6.1.6.3.10.2.1.1.0', '1.3.6.1.6.3.10.2.1.2.0'
USM_USER_STATUS = '1.3.6.1.6.3.15.1.2.2.1.13'


def idf_path():
    import os
    from pathlib import Path
    p = Path(os.environ.get('IDF_PATH', '/home/hajun/esp-idf-v6.1'))
    if not (p / 'components/lwip/lwip/src/apps/snmp/snmp_msg.c').is_file():
        pytest.skip('ESP-IDF lwIP sources not found (set IDF_PATH)')
    return p


@pytest.fixture(scope='module')
def harness(tmp_path_factory):
    lwip = idf_path() / 'components/lwip/lwip/src'
    out = tmp_path_factory.mktemp('snmp_agent')
    inc = [f'-I{HOST / "include"}', f'-I{lwip / "include"}', f'-I{lwip / "apps/snmp"}', *INCLUDE_FLAGS,
           f'-I{COMPONENTS / "snmp_gw"}', f'-I{COMPONENTS / "snmp_lwip"}']
    objs = []
    upstream = [lwip / 'apps/snmp' / f'{n}.c' for n in (
        'snmp_asn1', 'snmp_core', 'snmp_msg', 'snmp_pbuf_stream', 'snmp_scalar', 'snmp_table', 'snmp_traps',
        'snmpv3', 'snmp_snmpv2_framework', 'snmp_snmpv2_usm')]
    upstream += [lwip / 'core' / f'{n}.c' for n in ('pbuf', 'mem', 'memp', 'def')] + [lwip / 'core/ipv4/ip4_addr.c']
    # char is unsigned on the target (Xtensa __CHAR_UNSIGNED__); lwIP's usmUserTable index code depends
    # on it (engine-ID octets >= 0x80), so the host build uses the same ABI.
    for src in upstream:  # third-party: relaxed warnings, like the IDF build keeps its defaults
        obj = out / (src.stem + '.o')
        cc(['-std=gnu11', '-funsigned-char', '-w', '-O1', '-g', *inc, '-c', str(src), '-o', str(obj)])
        objs.append(obj)
    ours = [HOST / 'agent_harness.c', HOST / 'snmpv3_host.c'] + [
        COMPONENTS / 'snmp_gw' / f for f in ('usm.c', 'registry.c', 'mib_system.c', 'mib_mex_setpoint.c',
                                             'mib_util.c', 'snmp_logic.c')]
    ours += [ROOT / p for p in LISTS['GW_HOST_SOURCES_GW_CORE'] + LISTS.get('GW_HOST_ONLY_SOURCES', [])
             if not p.endswith('gw_ident.c')]
    exe = out / 'harness'
    flags = [f for f in CFLAGS if f != '-std=c11'] + ['-std=gnu11', '-funsigned-char']  # POSIX sockets
    cc([*flags, *inc, *map(str, ours), *map(str, objs), '-o', str(exe), '-lcrypto'])
    return exe


class Agent:
    def __init__(self, exe, write_mode=0):
        args = [str(exe), *PASS['gwmonitor'], *PASS['gwadmin'], str(write_mode)]
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.p.stdout.readline().split()
        assert line and line[0] == 'PORT', line
        self.port = int(line[1])
        self.events = None

    def stop(self):
        self.p.terminate()
        out, err = self.p.communicate(timeout=10)
        self.events = out.splitlines()
        self.log = err
        return self.events


@pytest.fixture
def agent(harness):
    a = Agent(harness)
    yield a
    if a.events is None:
        a.stop()


def usm(user, auth=None, priv=None, level='authPriv'):
    a, p = PASS.get(user, ('x' * 8, 'y' * 8))
    if level == 'noAuthNoPriv':
        return UsmUserData(user, authProtocol=USM_AUTH_NONE, privProtocol=USM_PRIV_NONE)
    if level == 'authNoPriv':
        return UsmUserData(user, auth or a, authProtocol=USM_AUTH_HMAC96_SHA, privProtocol=USM_PRIV_NONE)
    return UsmUserData(user, auth or a, priv or p, authProtocol=USM_AUTH_HMAC96_SHA, privProtocol=USM_PRIV_CFB128_AES)


def run(coro):
    return asyncio.run(coro)


async def _target(port):
    return await UdpTransportTarget.create(('127.0.0.1', port), timeout=1, retries=0)


def get(agent, auth, *oids):
    async def go():
        err, status, idx, vbs = await get_cmd(SnmpEngine(), auth, await _target(agent.port), ContextData(),
                                              *[ObjectType(ObjectIdentity(o)) for o in oids])
        return (str(err) if err else None), int(status), [(str(n), v) for n, v in vbs]
    return run(go())


def set_(agent, auth, oid, value):
    async def go():
        err, status, idx, vbs = await set_cmd(SnmpEngine(), auth, await _target(agent.port), ContextData(),
                                              ObjectType(ObjectIdentity(oid), value))
        return (str(err) if err else None), status.prettyPrint() if status else 'noError', [(str(n), v) for n, v in vbs]
    return run(go())


def walk(agent, auth, oid, limit=20):
    """GetNext walk below oid (numeric OIDs only, so pysnmp's MIB resolution cannot alter the index)."""
    prefix = tuple(int(x) for x in oid.split('.'))

    async def go():
        eng, tgt, out, cur = SnmpEngine(), await _target(agent.port), [], prefix
        for _ in range(limit):
            err, status, idx, vbs = await next_cmd(eng, auth, tgt, ContextData(),
                                                   ObjectType(ObjectIdentity(cur)), lookupMib=False)
            if err or status or not vbs:
                break
            name, val = tuple(vbs[0][0]), vbs[0][1]
            if name[:len(prefix)] != prefix or type(val).__name__ in ('EndOfMibView', 'NoSuchObject', 'NoSuchInstance'):
                break
            out.append(('.'.join(map(str, name)), val))
            cur = name
        return out
    return run(go())


# ---------------------------------------------------------------- USM contract (snmp_gw.h)


@pytest.mark.parametrize('user', ['gwmonitor', 'gwadmin'])
def test_authpriv_get_with_correct_keys(agent, user):
    err, status, vbs = get(agent, usm(user), SYS_DESCR, SYS_OBJID)
    assert err is None and status == 0
    assert str(vbs[0][1]) == 'MESTIO Gateway 1.2.3-test'
    assert tuple(vbs[1][1]) == (1, 3, 6, 1, 4, 1, PEN, 1, 1), 'sysObjectID = gwInfo (…PEN.1.1)'


@pytest.mark.parametrize('user', ['gwadmin', 'gwmonitor'])
def test_noauthnopriv_get_is_refused_with_a_report(agent, user):
    """Stream E required test: noAuthNoPriv as a valid user yields unsupportedSecLevel, never data."""
    err, status, vbs = get(agent, usm(user, level='noAuthNoPriv'), SYS_DESCR)
    assert err is not None and 'security level' in err.lower(), err
    assert vbs == []
    ev = agent.stop()
    assert any(e.startswith('USMSTATS') and 'seclevel=1' in e for e in ev), ev


def test_authnopriv_is_refused_too(agent):
    err, _, vbs = get(agent, usm('gwadmin', level='authNoPriv'), SYS_DESCR)
    assert err is not None and 'security level' in err.lower() and vbs == []


@pytest.mark.parametrize('user', ['nobody', 'GWADMIN', 'gwadmin2'])
def test_unknown_user_is_refused(agent, user):
    err, _, vbs = get(agent, usm(user), SYS_DESCR)
    assert err is not None and 'unknown' in err.lower() and 'user' in err.lower(), err
    assert vbs == []


def test_wrong_auth_key_is_a_wrong_digest(agent):
    err, _, vbs = get(agent, usm('gwmonitor', auth='not-the-pass'), SYS_DESCR)
    assert err is not None and 'digest' in err.lower() and vbs == []
    ev = agent.stop()
    assert any('digest=1' in e for e in ev)


def test_wrong_priv_key_fails_decryption(agent):
    err, _, vbs = get(agent, usm('gwmonitor', priv='not-the-priv'), SYS_DESCR)
    assert err is not None and vbs == [], 'garbage after decryption must never produce data'


def test_engine_discovery_and_framework_mib(agent):
    err, status, vbs = get(agent, usm('gwmonitor'), SNMP_ENGINE_ID, SNMP_ENGINE_BOOTS)
    assert err is None and status == 0
    assert bytes(vbs[0][1]).hex() == ENGINE_ID, 'engine ID = 0x80000000|PEN, format 3, MAC'
    assert int(vbs[1][1]) == 5


def usm_row_index(name):
    """usmUserTable row index -> (engineID hex, user name); both length-prefixed OCTET STRINGs."""
    arcs = [int(x) for x in name[len(USM_USER_STATUS) + 1:].split('.')]
    elen = arcs[0]
    nlen = arcs[1 + elen]
    return bytes(arcs[1:1 + elen]).hex(), bytes(arcs[2 + elen:2 + elen + nlen]).decode()


def test_usm_user_table_lists_only_valid_users(agent):
    rows = walk(agent, usm('gwmonitor'), USM_USER_STATUS)
    assert sorted(usm_row_index(n) for n, _ in rows) == [(ENGINE_ID, 'gwadmin'), (ENGINE_ID, 'gwmonitor')]


# ---------------------------------------------------------------- RO / RW (snmp_ctx_can_write)


def test_ro_user_cannot_set(agent):
    err, status, _ = set_(agent, usm('gwmonitor'), SYS_NAME, OctetString('evil'))
    assert err is None and status == 'notWritable'
    assert not any(e.startswith('COMMIT') for e in agent.stop())


def test_rw_user_sets_sysname_and_it_is_persisted_via_config(agent):
    err, status, vbs = set_(agent, usm('gwadmin'), SYS_NAME, OctetString('rack-7 gateway'))
    assert err is None and status == 'noError'
    err, status, vbs = get(agent, usm('gwmonitor'), SYS_NAME)
    assert str(vbs[0][1]) == 'rack-7 gateway'
    ev = agent.stop()
    assert 'COMMIT snmp by=@snmp name=rack-7 gateway contact= location=' in ev


@pytest.mark.parametrize('value,expect', [(OctetString(b'\xff\xfe'), 'wrongValue'),
                                          (OctetString(b'a\nb'), 'wrongValue'),
                                          (OctetString(b'x' * 64), 'wrongLength')])
def test_sysname_set_validation(agent, value, expect):
    err, status, _ = set_(agent, usm('gwadmin'), SYS_NAME, value)
    assert err is None and status == expect
    assert not any(e.startswith('COMMIT') for e in agent.stop())


def test_v2c_read_community_reads_and_cannot_write(agent):
    err, status, vbs = get(agent, CommunityData('pub-ro-123', mpModel=1), SYS_DESCR)
    assert err is None and str(vbs[0][1]).startswith('MESTIO Gateway')
    err, _, _ = set_(agent, CommunityData('pub-ro-123', mpModel=1), SYS_NAME, OctetString('x'))
    assert err is not None, 'wrong write community: lwIP drops the request (no response)'


def test_v2c_write_community_can_write(agent):
    err, status, _ = set_(agent, CommunityData('priv-rw-456', mpModel=1), SYS_NAME, OctetString('via-v2c'))
    assert err is None and status == 'noError'


def test_v2c_write_community_also_reads(agent):
    """net-snmp rwcommunity semantics through the transport's community mapping (snmp_transport_util.h)."""
    err, status, vbs = get(agent, CommunityData('priv-rw-456', mpModel=1), SYS_DESCR)
    assert err is None and status == 0 and str(vbs[0][1]).startswith('MESTIO Gateway')


def test_v2c_unknown_community_gets_nothing(agent):
    err, _, vbs = get(agent, CommunityData('guess', mpModel=1), SYS_DESCR)
    assert err is not None and vbs == []


# ---------------------------------------------------------------- mexSetpointTable SET semantics


def test_setpoint_get_and_applied_set(agent):
    err, status, vbs = get(agent, usm('gwmonitor'), SP_SET_TEMP)
    assert err is None and int(vbs[0][1]) == 230
    err, status, vbs = set_(agent, usm('gwadmin'), SP_SET_TEMP, Integer32(235))
    assert err is None and status == 'noError'
    err, status, vbs = get(agent, usm('gwmonitor'), SP_SET_TEMP)
    assert int(vbs[0][1]) == 235
    assert 'WRITE dev=0 addr=40012 raw=235 who=@snmp wait=1000' in agent.stop()


@pytest.mark.parametrize('oid,value,expect', [
    (SP_SET_TEMP, 501, 'wrongValue'),   # outside 50..500
    (SP_SET_TEMP, 49, 'wrongValue'),
    (SP_HI_TEMP, 248, 'wrongValue'),    # below the 249 sentinel
])
def test_setpoint_validation_happens_before_the_write(agent, oid, value, expect):
    err, status, _ = set_(agent, usm('gwadmin'), oid, Integer32(value))
    assert err is None and status == expect
    assert not any(e.startswith('WRITE') for e in agent.stop())


def test_setpoint_wrong_type(agent):
    err, status, _ = set_(agent, usm('gwadmin'), SP_SET_TEMP, OctetString('235'))
    assert err is None and status == 'wrongType'
    assert not any(e.startswith('WRITE') for e in agent.stop())


def test_setpoint_sentinel_is_accepted(agent):
    err, status, _ = set_(agent, usm('gwadmin'), SP_HI_TEMP, Integer32(249))
    assert err is None and status == 'noError'
    assert 'WRITE dev=0 addr=40027 raw=249 who=@snmp wait=1000' in agent.stop()


def test_setpoint_ro_user_is_not_writable(agent):
    err, status, _ = set_(agent, usm('gwmonitor'), SP_SET_TEMP, Integer32(240))
    assert err is None and status == 'notWritable'
    assert not any(e.startswith('WRITE') for e in agent.stop())


def test_setpoint_unknown_device_row(agent):
    err, status, _ = set_(agent, usm('gwadmin'), SP_SET_TEMP[:-1] + '2', Integer32(240))
    assert err is None and status != 'noError'


@pytest.mark.parametrize('mode,expect,lastwrite', [
    (1, 'commitFailed', None),          # REJECTED (device exception) -> commitFailed
    (2, 'noError', None),               # UNCERTAIN -> noError (result in gwLastWriteResult via the event)
    (3, 'noError', 'LASTWRITE state=0 addr=40012 raw=240 by=@snmp'),  # still PENDING after 1 s
])
def test_setpoint_write_outcomes(harness, mode, expect, lastwrite):
    a = Agent(harness, write_mode=mode)
    try:
        err, status, _ = set_(a, usm('gwadmin'), SP_SET_TEMP, Integer32(240))
        assert err is None and status == expect
    finally:
        ev = a.stop()
    assert 'WRITE dev=0 addr=40012 raw=240 who=@snmp wait=1000' in ev
    if lastwrite:
        assert lastwrite in ev


def test_setpoint_table_walk_matches_regmap(agent):
    """GetNext over mexSetpointTable visits one column per SNMP_RW register (column = address - 40000)."""
    rows = walk(agent, usm('gwmonitor'), f'1.3.6.1.4.1.{PEN}.1.4', limit=40)
    cols = [int(n.split('.')[-2]) for n, _ in rows]
    assert cols == [12, 13, 14, 15, 16, 17, 18, 19, 27, 28, 29, 30]
    assert all(n.endswith('.1') for n, _ in rows), 'one configured device: gwDevIndex 1'
