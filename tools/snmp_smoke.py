#!/usr/bin/env python3
"""SNMP smoke test of the gateway agent (DESIGN.md §10, docs/HW_TEST.md "SNMP"), pysnmp 7 asyncio API.

Network only (UDP); never opens a serial port. Never run automatically against hardware.

Checks (each is skipped when its credentials are not given):
  v2c   walk of system (1.3.6.1.2.1.1) and the enterprise subtree (1.3.6.1.4.1.<PEN>) with --community;
        SET with the RO community is rejected; a wrong community gets no answer
  v3    authPriv (HMAC-SHA-96 + AES-128) GET as --ro-user and --rw-user; SET sysLocation.0 to its
        current value as the RW user succeeds; the same SET as the RO user is rejected;
        noAuthNoPriv and authNoPriv requests and a wrong auth passphrase are rejected
  trap  receive v1/v2c traps/informs on --trap-port for --trap-seconds (optionally triggered with
        POST /api/v1/snmp/test-trap via --web-url/--web-user/--web-pass); trap OIDs must lie under
        the enterprise subtree

Examples:
  snmp_smoke.py --host 192.168.10.150 --community <ro> v2c
  snmp_smoke.py --host 192.168.10.150 --ro-user gwmonitor --ro-auth A --ro-priv P \
                --rw-user gwadmin --rw-auth A2 --rw-priv P2 v3
  snmp_smoke.py --trap-port 1162 --trap-community mestio-trap --web-url http://192.168.10.150 \
                --web-user admin --web-pass ... trap
Exit status 0 = no FAIL.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config as snmp_config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_SHA, USM_PRIV_CFB128_AES, CommunityData, ContextData, ObjectIdentity, ObjectType,
    OctetString, SnmpEngine, UdpTransportTarget, UsmUserData, get_cmd, set_cmd, walk_cmd,
)

DEFAULT_PEN = 32473
SYS = '1.3.6.1.2.1.1'
SYS_DESCR = SYS + '.1.0'
SYS_UPTIME = SYS + '.3.0'
SYS_LOCATION = SYS + '.6.0'
SNMP_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0'
STD_TRAPS = '1.3.6.1.6.3.1.1.5'          # coldStart, authenticationFailure, ...


class Runner:
    def __init__(self, args):
        self.a = args
        self.results: list[dict] = []
        self.ent = args.enterprise_oid or f'1.3.6.1.4.1.{args.pen}'

    def record(self, ok: bool | None, name: str, detail: str = '') -> bool:
        status = 'SKIP' if ok is None else 'PASS' if ok else 'FAIL'
        self.results.append({'status': status, 'name': name, 'detail': detail})
        print(f'{status:4} {name}' + (f' - {detail}' if detail else ''), flush=True)
        return bool(ok)

    async def target(self, timeout=None, retries=None):
        return await UdpTransportTarget.create((self.a.host, self.a.port),
                                               timeout=timeout or self.a.timeout,
                                               retries=self.a.retries if retries is None else retries)

    @staticmethod
    def engine():
        return SnmpEngine()

    @staticmethod
    def close(eng):
        try:
            eng.close_dispatcher()
        except Exception:
            pass

    async def get(self, auth, *oids, timeout=None, retries=None):
        eng = self.engine()
        try:
            return await get_cmd(eng, auth, await self.target(timeout, retries), ContextData(),
                                 *[ObjectType(ObjectIdentity(o)) for o in oids], lookupMib=False)
        finally:
            self.close(eng)

    async def set(self, auth, oid, value, timeout=None, retries=None):
        eng = self.engine()
        try:
            return await set_cmd(eng, auth, await self.target(timeout, retries), ContextData(),
                                 ObjectType(ObjectIdentity(oid), value), lookupMib=False)
        finally:
            self.close(eng)

    async def walk(self, auth, root):
        eng = self.engine()
        rows = []
        try:
            async for ei, es, _, vbs in walk_cmd(eng, auth, await self.target(), ContextData(),
                                                 ObjectType(ObjectIdentity(root)), lookupMib=False,
                                                 lexicographicMode=False, maxRows=self.a.max_rows):
                if ei or es:
                    return rows, f'{ei or es.prettyPrint()}'
                rows += [(str(n), v) for n, v in vbs]
        finally:
            self.close(eng)
        return rows, None

    @staticmethod
    def outcome(res) -> tuple[bool, str]:
        """(answered without error, description)."""
        ei, es, eidx, vbs = res
        if ei:
            return False, str(ei)
        if es:
            return False, f'{es.prettyPrint()} at {eidx}'
        return True, ', '.join(f'{n}={v.prettyPrint()}' for n, v in vbs)[:200]

    def usm(self, user, auth=None, priv=None):
        if auth and priv:
            return UsmUserData(user, authKey=auth, privKey=priv, authProtocol=USM_AUTH_HMAC96_SHA,
                               privProtocol=USM_PRIV_CFB128_AES)
        if auth:
            return UsmUserData(user, authKey=auth, authProtocol=USM_AUTH_HMAC96_SHA)
        return UsmUserData(user)

    # ------------------------------------------------------------------ v2c
    async def v2c(self):
        if not self.a.community:
            return self.record(None, 'v2c', 'no --community')
        comm = CommunityData(self.a.community, mpModel=1)
        ok, d = self.outcome(await self.get(comm, SYS_DESCR, SYS_UPTIME))
        if not self.record(ok, 'v2c GET sysDescr.0 sysUpTime.0', d):
            return self.record(None, 'v2c walk/negative checks', 'agent did not answer the first GET')
        for root in self.a.walk_root or [SYS, self.ent]:
            rows, err = await self.walk(comm, root)
            detail = err or (f'{len(rows)} varbinds' if rows else 'empty subtree')
            self.record(err is None and len(rows) > 0, f'v2c walk {root}', detail)
            if self.a.verbose:
                for n, v in rows:
                    print(f'    {n} = {v.prettyPrint()}')
        res = await self.get(comm, SYS_LOCATION)
        ok, d = self.outcome(res)
        if ok:
            cur = res[3][0][1]
            ok2, d2 = self.outcome(await self.set(comm, SYS_LOCATION, OctetString(bytes(cur)), retries=0))
            self.record(not ok2, 'v2c SET with RO community rejected', d2 if ok2 else '')
        else:
            self.record(False, 'v2c GET sysLocation.0', d)
        ok, d = self.outcome(await self.get(CommunityData(self.a.community + '-wrong', mpModel=1), SYS_DESCR,
                                            timeout=1, retries=0))
        self.record(not ok, 'v2c wrong community gets no answer', d if ok else '')
        if self.a.v1:
            ok, d = self.outcome(await self.get(CommunityData(self.a.community, mpModel=0), SYS_DESCR))
            self.record(ok, 'v1 GET sysDescr.0', d)

    # ------------------------------------------------------------------ v3
    async def v3(self):
        a = self.a
        ro = (a.ro_user, a.ro_auth, a.ro_priv) if a.ro_user and a.ro_auth and a.ro_priv else None
        rw = (a.rw_user, a.rw_auth, a.rw_priv) if a.rw_user and a.rw_auth and a.rw_priv else None
        if not ro and not rw:
            return self.record(None, 'v3', 'no --ro-user/--rw-user credentials')
        cur = None
        for label, cred in (('RO', ro), ('RW', rw)):
            if not cred:
                self.record(None, f'v3 {label} user', 'no credentials')
                continue
            res = await self.get(self.usm(*cred), SYS_DESCR, SYS_LOCATION)
            ok, d = self.outcome(res)
            self.record(ok, f'v3 authPriv GET as {cred[0]} ({label})', d)
            if ok:
                cur = res[3][1][1]
        if cur is None:
            return
        if rw:
            ok, d = self.outcome(await self.set(self.usm(*rw), SYS_LOCATION, OctetString(bytes(cur))))
            self.record(ok, f'v3 SET sysLocation.0 (unchanged value) as {rw[0]}', d)
        if ro:
            ok, d = self.outcome(await self.set(self.usm(*ro), SYS_LOCATION, OctetString(bytes(cur)), retries=0))
            self.record(not ok, f'v3 SET as RO user {ro[0]} rejected', d)
        who = rw or ro
        for label, auth in (('noAuthNoPriv', self.usm(who[0])), ('authNoPriv', self.usm(who[0], who[1])),
                            ('wrong auth passphrase', self.usm(who[0], who[1] + 'x', who[2])),
                            ('unknown user', self.usm('nosuchuser', who[1], who[2]))):
            ok, d = self.outcome(await self.get(auth, SYS_DESCR, timeout=2, retries=0))
            self.record(not ok, f'v3 {label} as {who[0] if label != "unknown user" else "nosuchuser"} rejected',
                        d)

    # ------------------------------------------------------------------ traps
    async def trap(self):
        a = self.a
        if not a.trap_port:
            return self.record(None, 'trap receiver', 'no --trap-port')
        eng = SnmpEngine()
        got: list[dict] = []
        try:
            snmp_config.add_transport(eng, udp.DOMAIN_NAME,
                                      udp.UdpAsyncioTransport().open_server_mode((a.trap_listen, a.trap_port)))
            for i, comm in enumerate(a.trap_community):
                snmp_config.add_v1_system(eng, f'trap-{i}', comm)

            def on_trap(snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, cb_ctx):
                _, addr = snmp_engine.message_dispatcher.get_transport_info(state_ref)
                vb = {str(n): v.prettyPrint() for n, v in var_binds}
                got.append({'from': f'{addr[0]}:{addr[1]}', 'trap_oid': vb.get(SNMP_TRAP_OID), 'varbinds': vb})
                print(f'     trap from {addr[0]}:{addr[1]} {vb.get(SNMP_TRAP_OID)} ({len(vb)} varbinds)', flush=True)
                if a.verbose:
                    for n, v in vb.items():
                        print(f'       {n} = {v}')

            ntfrcv.NotificationReceiver(eng, on_trap)
            eng.open_dispatcher()
            await asyncio.sleep(0.2)
            print(f'     listening for traps on {a.trap_listen}:{a.trap_port} for {a.trap_seconds:.0f} s', flush=True)
            if a.web_url:
                await asyncio.to_thread(self.trigger_test_trap)
            deadline = asyncio.get_running_loop().time() + a.trap_seconds
            while asyncio.get_running_loop().time() < deadline and len(got) < a.trap_count:
                await asyncio.sleep(0.1)
        finally:
            self.close(eng)
        self.record(len(got) >= a.trap_count, f'received >= {a.trap_count} notification(s)', f'got {len(got)}')
        for t in got:
            oid = t['trap_oid'] or ''
            self.record(oid.startswith(self.ent + '.') or oid.startswith(STD_TRAPS + '.'),
                        f'trap OID {oid} under {self.ent} or snmpTraps', '')
        if a.trap_json:
            Path(a.trap_json).write_text(json.dumps(got, indent=1))

    def trigger_test_trap(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from gw_http import GwClient
        c = GwClient(self.a.web_url)
        r = c.login(self.a.web_user, self.a.web_pass)
        if not self.record(r.status == 200 and not (r.json or {}).get('must_change'), 'web login for test-trap',
                           r.short()):
            return
        r = c.api('POST', '/snmp/test-trap')
        self.record(r.status == 200, 'POST /snmp/test-trap', r.short())
        c.logout()

    async def run(self) -> int:
        for name in self.a.checks:
            await getattr(self, name.replace('-', '_'))()
        fails = sum(r['status'] == 'FAIL' for r in self.results)
        print(f'\n{sum(r["status"] == "PASS" for r in self.results)} passed, {fails} failed, '
              f'{sum(r["status"] == "SKIP" for r in self.results)} skipped')
        if self.a.json:
            Path(self.a.json).write_text(json.dumps(self.results, indent=1))
        return 1 if fails else 0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split('\n\n', 1)[1])
    ap.add_argument('checks', nargs='*', choices=['v2c', 'v3', 'trap'], default=None,
                    help='checks to run (default: v2c v3, plus trap when --trap-port is given)')
    ap.add_argument('--host', default=os.environ.get('GW_HOST', '192.168.10.150'))
    ap.add_argument('--port', type=int, default=161)
    ap.add_argument('--pen', type=int, default=DEFAULT_PEN, help='enterprise PEN (CONFIG_GW_SNMP_ENTERPRISE_PEN)')
    ap.add_argument('--enterprise-oid', help='override the enterprise subtree (default 1.3.6.1.4.1.<PEN>)')
    ap.add_argument('--walk-root', action='append', help='subtree(s) to walk (default system + enterprise)')
    ap.add_argument('--max-rows', type=int, default=2000)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--retries', type=int, default=1)
    ap.add_argument('--community', default=os.environ.get('GW_SNMP_RO') or None, help='v1/v2c RO community (env GW_SNMP_RO)')
    ap.add_argument('--v1', action='store_true', help='also GET with SNMPv1')
    for role in ('ro', 'rw'):
        ap.add_argument(f'--{role}-user', default='gwmonitor' if role == 'ro' else 'gwadmin')
        ap.add_argument(f'--{role}-auth', default=os.environ.get(f'GW_SNMP_{role.upper()}_AUTH') or None,
                        help=f'{role.upper()} user auth passphrase (env GW_SNMP_{role.upper()}_AUTH)')
        ap.add_argument(f'--{role}-priv', default=os.environ.get(f'GW_SNMP_{role.upper()}_PRIV') or None,
                        help=f'{role.upper()} user priv passphrase (env GW_SNMP_{role.upper()}_PRIV)')
    ap.add_argument('--trap-port', type=int, help='UDP port to receive traps on (162 needs root; e.g. 1162)')
    ap.add_argument('--trap-listen', default='0.0.0.0')
    ap.add_argument('--trap-community', action='append', default=None,
                    help='accepted trap community (repeatable; default mestio-trap)')
    ap.add_argument('--trap-seconds', type=float, default=15.0)
    ap.add_argument('--trap-count', type=int, default=1, help='notifications expected')
    ap.add_argument('--trap-json', help='write received notifications to this file')
    ap.add_argument('--web-url', help='trigger POST /api/v1/snmp/test-trap on this gateway URL')
    ap.add_argument('--web-user', default='admin')
    ap.add_argument('--web-pass', default=os.environ.get('GW_PASSWORD') or None)
    ap.add_argument('--json', help='write results to this file')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args(argv)
    a.trap_community = a.trap_community or ['mestio-trap']
    if not a.checks:
        a.checks = ['v2c', 'v3'] + (['trap'] if a.trap_port else [])
    return a


def main(argv=None) -> int:
    return asyncio.run(Runner(parse_args(argv)).run())


if __name__ == '__main__':
    sys.exit(main())
