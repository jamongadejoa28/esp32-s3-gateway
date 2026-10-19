#!/usr/bin/env python3
"""Generate the SMIv2 module MESTIO-GW-MIB from the single sources of truth.

Inputs: components/mex150/regmap.def (setpoint columns of mexSetpointTable = REG rows flagged
SNMP_RW, column number = register address - 40000), components/alarm/alarm_catalog.def (the
GwAlarmCode enumeration) and the enterprise PEN (CONFIG_GW_SNMP_ENTERPRISE_PEN, from --pen or from an
sdkconfig file). Every other object mirrors the agent's OID table components/snmp_gw/mib_oids.h;
tests/test_mib.py compiles the output with pysmi (strict SMIv2 grammar) and cross-checks every OID
against that table and against the regmap/catalog expansion of the C code.

Build contract (cmake/gw_mib.cmake, docs: snmp_gw.h snmp_gw_mib_gz()):
    gen_mib.py --regmap R --catalog C --pen N --out X.txt.gz      (gzip -9, mtime 0, no file name)
An --out path not ending in .gz receives the plain text. The output is deterministic (fixed
revision date, no timestamps), ASCII only.
"""
import argparse
import gzip
import io
import re
import sys
import textwrap
from pathlib import Path

MODULE = 'MESTIO-GW-MIB'
REVISION = '202610190000Z'
MAX_DEVICES = 4  # == GW_MAX_DEVICES (components/gw_core/include/gw_core/gw_defs.h), checked by tests
MAX_REG_ADDR = 40059  # highest address of mex_snapshot_t.regs[] (MEX_ADDR_BASE + MEX_REGS_LEN - 1)
DEFAULT_PEN = 32473

ROW_COLUMNS = {
    'REG': ['key', 'addr', 'scale', 'sign', 'access', 'min', 'max', 'disabled', 'flags', 'group', 'unit', 'ko', 'en'],
    'REGBIT': ['key', 'addr', 'bit', 'ko', 'en'],
    'FIELD': ['key', 'addr', 'lsb', 'width', 'unit', 'ko', 'en'],
    'COIL': ['key', 'n', 'group', 'ko', 'en'],
    'ENUM': ['regkey', 'value', 'ko', 'en'],
    'ALM': ['id', 'code', 'kind', 'addr', 'bit', 'sev', 'vreg', 'ko', 'en'],
}
INT_COLUMNS = {'addr', 'scale', 'min', 'max', 'bit', 'lsb', 'width', 'n', 'value', 'code', 'vreg'}
UNITS = {'°C': 'degrees Celsius', '%': 'percent', 'A': 'amperes', 's': 'seconds', 'h': 'hours', '': None}
SEVERITIES = ['INFO', 'MINOR', 'MAJOR', 'CRITICAL']  # alm_sev_t order; GwAlarmSeverity = index + 1
DESCRIPTOR = re.compile(r'^[a-z][A-Za-z0-9]{0,63}$')


class MibError(Exception):
    pass


def parse_def(path):
    """Rows of a .def X-macro table ({macro: [row dict]}); one row per line (documented format)."""
    rows = {}
    for lineno, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        m = re.match(r'^([A-Z]+)\((.*)\)\s*$', line)
        if not m:
            if re.match(r'^\s*[A-Z]+\(', line):
                raise MibError(f'{path}:{lineno}: row not on one line')
            continue
        kind, body = m.groups()
        if kind not in ROW_COLUMNS:
            raise MibError(f'{path}:{lineno}: unknown row macro {kind}')
        args = [a.strip() for a in re.findall(r'"[^"]*"|[^,]+', body)]
        cols = ROW_COLUMNS[kind]
        if len(args) != len(cols):
            raise MibError(f'{path}:{lineno}: {kind} row has {len(args)} columns, expected {len(cols)}')
        row = {}
        for c, a in zip(cols, args):
            if a.startswith('"'):
                row[c] = a[1:-1]
            elif c in INT_COLUMNS or (c == 'disabled' and a != 'NONE'):
                row[c] = int(a)
            else:
                row[c] = a
        rows.setdefault(kind, []).append(row)
    return rows


def flags(row):
    return set() if row['flags'] == '0' else set(row['flags'].split('|'))


def camel(key):
    """'blower_fault' -> 'blowerFault', 'rule_1' -> 'rule1'."""
    parts = key.split('_')
    return parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])


def setpoint_name(key):
    return 'mexSp' + ''.join(p[:1].upper() + p[1:] for p in key.split('_'))


def setpoint_rows(regmap):
    """REG rows writable through mexSetpointTable, in column (address) order: (name, column, row)."""
    out = []
    for r in regmap.get('REG', []):
        if 'SNMP_RW' in flags(r):
            if r['access'] != 'RW':
                raise MibError(f"{r['key']}: SNMP_RW on a read-only register")
            out.append((setpoint_name(r['key']), r['addr'] - 40000, r))
    out.sort(key=lambda t: t[1])
    return out


def alarm_codes(catalog):
    """GwAlarmCode enumeration: [(label, code, row)] in code order."""
    out = [(camel(a['id']), a['code'], a) for a in catalog.get('ALM', [])]
    out.sort(key=lambda t: t[1])
    return out


def ascii_text(s):
    s = s.replace('°C', 'degrees Celsius').replace('"', "'")
    if not s.isascii():
        raise MibError(f'non-ASCII text in MIB: {s!r}')
    return s


def quoted(text, indent=12):
    """DESCRIPTION-style quoted string: ASCII, no embedded double quotes, each input line wrapped
    separately (an empty input line stays an empty line)."""
    body = ascii_text(text)
    pad = ' ' * indent
    lines = []
    for line in body.split('\n'):
        lines += textwrap.wrap(line, width=96 - indent, break_long_words=False, break_on_hyphens=False) or ['']
    return '"' + ('\n' + pad).join(lines) + '"'


# ---------------------------------------------------------------- hand-written objects
# Mirrors components/snmp_gw/mib_oids.h (GWMIB_NODES). (name, arc, syntax, access, description[, units])

INFO = [
    ('gwFwVersion', 1, 'DisplayString (SIZE (0..31))', 'read-only',
     'Firmware version of the gateway (application image version).'),
    ('gwMacAddress', 2, 'MacAddress', 'read-only',
     'Base MAC address of the gateway (eFuse); the hostname, SSID and SNMP engine ID derive from it.'),
    ('gwUptime', 3, 'TimeTicks', 'read-only', 'Time since the gateway booted (same clock as sysUpTime).'),
    ('gwTimeValid', 4, 'TruthValue', 'read-only',
     'true(1) once the wall clock has been set (RTC, NTP or a user); otherwise every DateAndTime of '
     'this MIB reads 1970-01-01.'),
    ('gwWallTime', 5, 'DateAndTime', 'read-only', 'Current wall clock time (UTC).'),
    ('gwActiveAlarms', 6, 'Gauge32', 'read-only', 'Number of active alarms over all devices.'),
    ('gwConfigRev', 7, 'Unsigned32', 'read-only',
     'Configuration revision; incremented by every committed configuration change.'),
    ('gwLastConfigSection', 8, 'DisplayString (SIZE (0..16))', 'read-only',
     'Name of the configuration section changed last (general, network, modbus, alarms, snmp, time, '
     'security, notify or secrets); empty until the first change since boot.'),
    ('gwLastWriteResult', 9, 'GwWriteResult', 'read-only',
     'Outcome of the most recent register write request from any origin (web, SNMP, console). A SET '
     'of mexSetpointTable that the device did not verify answers noError and is reported here as '
     'uncertain(5) or pending(2).'),
    ('gwLastWriteDevIndex', 10, 'Integer32 (0..4)', 'read-only',
     'Device index of the most recent write request; 0 when there was none.'),
    ('gwLastWriteRegAddr', 11, 'Integer32 (0..65535)', 'read-only',
     'Register address (4xxxx) of the most recent write request; 0 when there was none.'),
    ('gwLastWriteValue', 12, 'Integer32', 'read-only',
     'Requested raw value (register scale) of the most recent write request.'),
    ('gwLastWriteReason', 13, 'DisplayString (SIZE (0..32))', 'read-only',
     'Reason of a rejected or uncertain write (for example range, running_interlock, offline, '
     'exception:2, verify_mismatch); empty when applied.'),
    ('gwLastWriteTime', 14, 'DateAndTime', 'read-only', 'Time of the most recent write result.'),
    ('gwLastWriteCommand', 15, 'Unsigned32', 'read-only',
     'Command identifier of the most recent write (0 when it was rejected before queueing).'),
    ('gwLastWritePrincipal', 16, 'GwUtf8String (SIZE (0..11))', 'read-only',
     'Who requested the most recent write: @snmp, @console, or for a web user the account name '
     '(SNMPv3 requests only; SNMPv1/v2c requests read web).'),
    ('gwTrapsSent', 17, 'Counter32', 'read-only', 'Notifications sent (trap or inform datagrams).'),
    ('gwTrapsDropped', 18, 'Counter32', 'read-only',
     'Notifications not sent because of the rate limit (10 per second) or a full queue.'),
    ('gwInformsFailed', 19, 'Counter32', 'read-only',
     'Inform requests that were not acknowledged after all retransmissions.'),
]

DEV_COLUMNS = [
    ('gwDevIndex', 1, 'GwDevIndex', 'not-accessible', 'Device index (configured Modbus device id + 1).'),
    ('gwDevName', 2, 'GwUtf8String (SIZE (0..23))', 'read-only', 'Configured device name.'),
    ('gwDevSlave', 3, 'Integer32 (1..247)', 'read-only', 'Modbus unit address of the device.'),
    ('gwDevEnabled', 4, 'TruthValue', 'read-only', 'true(1) if the device is polled.'),
    ('gwDevOnline', 5, 'TruthValue', 'read-only', 'true(1) while the device answers polls.'),
    ('gwDevDataAge', 6, 'Unsigned32', 'read-only',
     'Age of the last successful poll cycle; 4294967295 if the device was never polled.', 'milliseconds'),
    ('gwDevSeq', 7, 'Counter32', 'read-only', 'Number of successful poll cycles (snapshot sequence).'),
]

STATUS_COLUMNS = [
    ('mexStatusValid', 1, 'TruthValue', 'read-only',
     'true(1) if the device is online and its data is fresh (younger than 3 seconds); otherwise the '
     'other columns show the last known values.'),
    ('mexTemperature', 2, 'GwTenths', 'read-only', 'Current temperature (register 40036).', 'degrees Celsius'),
    ('mexHumidity', 3, 'GwTenths', 'read-only', 'Current relative humidity (register 40037).', 'percent'),
    ('mexCurrent', 4, 'GwTenths', 'read-only', 'Current consumption (register 40011).', 'amperes'),
    ('mexRunState', 5, 'INTEGER { stopped(1), running(2) }', 'read-only',
     'Run state of the unit (register 40005, low byte).'),
    ('mexDelayRemaining', 6, 'Integer32 (0..255)', 'read-only',
     'Remaining run/stop delay (register 40005, high byte).', 'seconds'),
    ('mexModeFlags', 7, 'BITS { cooling(0), heating(1), humidifying(2), dehumidifying(3) }', 'read-only',
     'Active operating modes (coils 12 to 15).'),
    ('mexStagesCool', 8, 'Unsigned32 (0..3)', 'read-only', 'Running cooling stages (coils 2, 3 and 16).'),
    ('mexStagesHeat', 9, 'Unsigned32 (0..4)', 'read-only', 'Running heating stages (coils 4 to 7).'),
    ('mexStagesHum', 10, 'Unsigned32 (0..2)', 'read-only', 'Running humidifier stages (coils 8 and 9).'),
    ('mexStagesDehum', 11, 'Unsigned32 (0..1)', 'read-only', 'Dehumidifying active (coil 15).'),
    ('mexBlower', 12, 'TruthValue', 'read-only', 'Blower running (coil 1).'),
    ('mexCoils', 13, 'Unsigned32', 'read-only',
     'All 32 coils as a bit map: bit n-1 (value 2^(n-1)) is coil n. Coils 1 to 16 are run states, '
     'coils 17 to 31 alarms, coil 32 the combined alarm.'),
    ('mexInputPort', 14, 'Unsigned32 (0..65535)', 'read-only', 'Input port bits (register 40002).'),
    ('mexAlarmDetail1', 15, 'Unsigned32 (0..65535)', 'read-only', 'Alarm detail 1 bits (register 40003).'),
    ('mexAlarmDetail2', 16, 'Unsigned32 (0..65535)', 'read-only', 'Alarm detail 2 bits (register 40004).'),
    ('mexCoolProp', 17, 'Unsigned32 (0..65535)', 'read-only', 'Cooling proportional bits (register 40006).'),
    ('mexHeatProp', 18, 'Unsigned32 (0..65535)', 'read-only', 'Heating proportional bits (register 40007).'),
    ('mexHumProp', 19, 'Unsigned32 (0..65535)', 'read-only',
     'Humidifying proportional bits (register 40008).'),
]

REG_COLUMNS = [
    ('mexRegAddr', 1, f'Integer32 (40001..{MAX_REG_ADDR})', 'not-accessible', 'Register address (4xxxx).'),
    ('mexRegKey', 2, 'DisplayString (SIZE (1..32))', 'read-only', 'Stable register key (for example set_temp).'),
    ('mexRegName', 3, 'GwUtf8String (SIZE (0..63))', 'read-only', 'English register name.'),
    ('mexRegRaw', 4, 'Integer32 (-32768..65535)', 'read-only',
     'Decoded register value at register scale: sign-extended for signed registers, otherwise the '
     'full 16-bit word (also for 40005 and bit-field registers).'),
    ('mexRegValue', 5, 'DisplayString (SIZE (0..16))', 'read-only',
     'Register value as a decimal number (raw divided by the scale), for example 23.5.'),
    ('mexRegScale', 6, 'Integer32 (1..100)', 'read-only', 'Divisor of the raw value (1 or 10).'),
    ('mexRegUnit', 7, 'GwUtf8String (SIZE (0..8))', 'read-only', 'Display unit (UTF-8), empty if none.'),
    ('mexRegWritable', 8, 'TruthValue', 'read-only',
     'true(1) if the register is writable (through the web API, and through mexSetpointTable when it '
     'is listed there).'),
    ('mexRegValid', 9, 'TruthValue', 'read-only',
     'true(1) if the value was read from the device: device online with fresh data and, for the '
     'slowly polled limit and option registers, read at least once since it came online.'),
]

ALARM_ACTIVE_COLUMNS = [
    ('gwAlarmActiveCode', 1, 'GwAlarmCode', 'not-accessible', 'Alarm code.'),
    ('gwAlarmActiveName', 2, 'GwUtf8String (SIZE (0..63))', 'read-only', 'Alarm name (English).'),
    ('gwAlarmActiveSeverity', 3, 'GwAlarmSeverity', 'read-only', 'Effective severity.'),
    ('gwAlarmActiveSince', 4, 'DateAndTime', 'read-only', 'Time the alarm was raised.'),
    ('gwAlarmActiveAcked', 5, 'TruthValue', 'read-only', 'true(1) if the alarm has been acknowledged.'),
    ('gwAlarmActiveAckedBy', 6, 'GwUtf8String (SIZE (0..11))', 'read-only',
     'Who acknowledged the alarm (empty if not acknowledged): the web account name for SNMPv3 '
     'requests, web for SNMPv1/v2c requests.'),
    ('gwAlarmActiveValue', 7, 'Integer32', 'read-only',
     'Raw value of the related register when the alarm was raised (1 for pure bit alarms).'),
]

ALARM_SCALARS = [
    ('gwAlarmActiveCount', 2, 'Gauge32', 'read-only', 'Number of active alarms.'),
    ('gwAlarmCriticalCount', 3, 'Gauge32', 'read-only', 'Number of active critical alarms.'),
    ('gwAlarmMajorCount', 4, 'Gauge32', 'read-only', 'Number of active major alarms.'),
    ('gwAlarmMinorCount', 5, 'Gauge32', 'read-only', 'Number of active minor alarms.'),
    ('gwAlarmInfoCount', 6, 'Gauge32', 'read-only', 'Number of active informational alarms.'),
]

ALARM_EVENT_COLUMNS = [
    ('gwAlarmEventSeq', 1, 'Unsigned32 (1..4294967295)', 'not-accessible',
     'Event log sequence number of the transition.'),
    ('gwAlarmEventTime', 2, 'DateAndTime', 'read-only', 'Time of the transition.'),
    ('gwAlarmEventType', 3, 'INTEGER { raise(1), clear(2), ack(3) }', 'read-only', 'Kind of transition.'),
    ('gwAlarmEventDevIndex', 4, 'GwDevIndex', 'read-only', 'Device index.'),
    ('gwAlarmEventCode', 5, 'GwAlarmCode', 'read-only', 'Alarm code.'),
    ('gwAlarmEventSeverity', 6, 'GwAlarmSeverity', 'read-only', 'Severity at the transition.'),
    ('gwAlarmEventValue', 7, 'Integer32', 'read-only', 'Raw value of the related register.'),
    ('gwAlarmEventUser', 8, 'GwUtf8String (SIZE (0..11))', 'read-only',
     'Acknowledging user for ack(3) events, otherwise empty: the web account name for SNMPv3 '
     'requests, web for SNMPv1/v2c requests.'),
]

ALARM_NOTIF_OBJECTS = [
    ('gwAlarmDevIndex', 1, 'GwDevIndex', 'accessible-for-notify', 'Device index of the alarm.'),
    ('gwAlarmCode', 2, 'GwAlarmCode', 'accessible-for-notify', 'Alarm code.'),
    ('gwAlarmName', 3, 'GwUtf8String (SIZE (0..63))', 'accessible-for-notify',
     'Alarm name (English; for user rules the configured rule name if set).'),
    ('gwAlarmSeverity', 4, 'GwAlarmSeverity', 'accessible-for-notify', 'Effective severity.'),
    ('gwAlarmTime', 5, 'DateAndTime', 'accessible-for-notify', 'Time of the event.'),
    ('gwAlarmValue', 6, 'Integer32', 'accessible-for-notify', 'Raw value of the related register.'),
    ('gwAlarmSeq', 7, 'Unsigned32', 'accessible-for-notify',
     'Event log sequence number (matches gwAlarmEventSeq).'),
]

COMM_COLUMNS = [
    ('gwCommTx', 1, 'Counter32', 'read-only', 'Modbus requests sent.'),
    ('gwCommRxOk', 2, 'Counter32', 'read-only', 'Valid responses received.'),
    ('gwCommCrcErrors', 3, 'Counter32', 'read-only', 'Responses with a CRC error.'),
    ('gwCommTimeouts', 4, 'Counter32', 'read-only', 'Requests without a response in time.'),
    ('gwCommExceptions', 5, 'Counter32', 'read-only', 'Modbus exception responses.'),
    ('gwCommMalformed', 6, 'Counter32', 'read-only', 'Malformed responses.'),
    ('gwCommOfflineCount', 7, 'Counter32', 'read-only', 'Transitions to offline.'),
    ('gwCommRttLast', 8, 'Gauge32', 'read-only', 'Round-trip time of the last transaction.', 'milliseconds'),
    ('gwCommRttAvg', 9, 'Gauge32', 'read-only', 'Average round-trip time (EWMA 1/8).', 'milliseconds'),
    ('gwCommRttMax', 10, 'Gauge32', 'read-only', 'Maximum round-trip time.', 'milliseconds'),
    ('gwCommCycles', 11, 'Counter32', 'read-only', 'Successful poll cycles.'),
    ('gwCommOnlineSince', 12, 'DateAndTime', 'read-only',
     'Time of the last offline to online transition (1970-01-01 if none).'),
]
COMM_RESET_NOTE = (' The counters of this table can be reset by an administrator (web API); a '
                   'management application must treat a decrease as a discontinuity.')

NOTIFICATIONS = [
    ('gwAlarmRaised', 1, ['gwAlarmDevIndex', 'gwAlarmCode', 'gwAlarmName', 'gwAlarmSeverity', 'gwAlarmTime',
                          'gwAlarmValue', 'gwAlarmSeq'], 'An alarm was raised.'),
    ('gwAlarmCleared', 2, ['gwAlarmDevIndex', 'gwAlarmCode', 'gwAlarmName', 'gwAlarmSeverity', 'gwAlarmTime',
                           'gwAlarmValue', 'gwAlarmSeq'], 'An alarm was cleared.'),
    ('gwCommLost', 3, ['gwDevName', 'gwDevOnline', 'gwAlarmTime'],
     'Communication with a device was lost. Transitions are coalesced: at most one notification per '
     'device every 10 seconds, reporting the latest state.'),
    ('gwCommRestored', 4, ['gwDevName', 'gwDevOnline', 'gwAlarmTime'],
     'Communication with a device was restored (coalesced like gwCommLost).'),
    ('gwConfigChanged', 5, ['gwLastConfigSection', 'gwConfigRev'], 'A configuration section was changed.'),
    ('gwFirmwareUpdated', 6, ['gwFwVersion'],
     'A new firmware image passed its health check after an update and was marked valid.'),
    ('gwTestNotification', 7, ['gwFwVersion'], 'Test notification requested by an administrator.'),
]


def object_type(name, syntax, access, desc, parent, arc, units=None, index=None):
    out = [f'{name} OBJECT-TYPE', f'    SYNTAX      {syntax}']
    if units:
        out.append(f'    UNITS       "{ascii_text(units)}"')
    out += [f'    MAX-ACCESS  {access}', '    STATUS      current', f'    DESCRIPTION {quoted(desc)}']
    if index:
        out.append(f'    INDEX       {{ {", ".join(index)} }}')
    out.append(f'    ::= {{ {parent} {arc} }}')
    return '\n'.join(out) + '\n'


def seq_syntax(syntax):
    """Type of a column inside its SEQUENCE: drop sub-typing and enumerations."""
    base = syntax.split(' (', 1)[0].split(' {', 1)[0]
    return base


def table(tname, ename, parent, arc, index, columns, tdesc, edesc, sequence_name):
    out = [f'{tname} OBJECT-TYPE',
           f'    SYNTAX      SEQUENCE OF {sequence_name}',
           '    MAX-ACCESS  not-accessible',
           '    STATUS      current',
           f'    DESCRIPTION {quoted(tdesc)}',
           f'    ::= {{ {parent} {arc} }}', '',
           f'{ename} OBJECT-TYPE',
           f'    SYNTAX      {sequence_name}',
           '    MAX-ACCESS  not-accessible',
           '    STATUS      current',
           f'    DESCRIPTION {quoted(edesc)}',
           f'    INDEX       {{ {", ".join(index)} }}',
           f'    ::= {{ {tname} 1 }}', '']
    width = max(len(c[0]) for c in columns)
    members = [f'    {c[0].ljust(width)} {seq_syntax(c[2])}' for c in columns]
    out += [f'{sequence_name} ::= SEQUENCE {{', ',\n'.join(members), '}', '']
    text = '\n'.join(out) + '\n'
    for c in columns:
        units = c[5] if len(c) > 5 else None
        text += object_type(c[0], c[2], c[3], c[4], ename, c[1], units) + '\n'
    return text


def setpoint_column(name, col, r):
    lo, hi, dis = r['min'], r['max'], r['disabled']
    base = 'GwTenths' if r['scale'] == 10 else 'Integer32'
    if r['scale'] not in (1, 10):
        raise MibError(f"{r['key']}: unsupported scale {r['scale']}")
    if dis == 'NONE':
        rng = f'({lo}..{hi})'
        sentinel = ''
    else:
        rng = f'({dis}..{hi})' if dis == lo - 1 else f'({dis} | {lo}..{hi})'
        sentinel = f' The raw value {dis} switches the function off.'
    scale = 'tenths of a unit' if r['scale'] == 10 else 'units'
    stopped = ' Writable only while the unit is stopped.' if 'STOPPED' in flags(r) else ''
    desc = (f"{r['en']} (register {r['addr']}, key {r['key']}). Raw value in {scale}; valid range "
            f"{lo} to {hi}.{sentinel}{stopped} A SET is checked like a web write (device online with "
            f"fresh data, range, run interlock) and then written to the device and read back: a "
            f"rejection by the gateway or the device answers an error (commitFailed for a single "
            f"varbind), an unverified write answers noError and is reported in gwLastWriteResult.")
    return (name, col, f'{base} {rng}', 'read-write', desc, UNITS.get(r['unit']))


def generate(regmap, catalog, pen):
    if not (1 <= pen <= 2147483647):
        raise MibError(f'PEN out of range: {pen}')
    sp = setpoint_rows(regmap)
    codes = alarm_codes(catalog)
    if not sp:
        raise MibError('regmap.def has no SNMP_RW register')
    if not codes:
        raise MibError('alarm_catalog.def has no ALM row')
    sp_columns = [setpoint_column(n, c, r) for n, c, r in sp]
    if len({c for _, c, _ in sp}) != len(sp):
        raise MibError('duplicate mexSetpointTable column')

    enum_items = []
    code_lines = []
    for label, code, a in codes:
        sev = a['sev']
        if sev not in SEVERITIES:
            raise MibError(f"{a['id']}: unknown severity {sev}")
        enum_items.append(f'{label}({code})')
        if a['kind'] == 'SRC_COIL':
            src = f"MEX150 coil {a['addr']}"
        elif a['kind'] == 'SRC_BIT':
            src = f"register {a['addr']} bit {a['bit']}"
        elif a['kind'] == 'SRC_COMM':
            src = 'gateway: device communication lost'
        else:
            src = f"user threshold rule {a['addr']}"
        code_lines.append(f"{code} {label}: {a['en']} ({src}; default severity {sev.lower()}).")

    code_desc = quoted('Stable alarm code (never renumbered). 1xx: MEX150 alarm coils (100 + coil), '
                       '2xx: MEX150 register bits, 3xx: gateway-generated, 4xx: user threshold rules '
                       '(400 + rule id).\n\n' + '\n'.join(code_lines), 17)

    names = ([n for n, *_ in INFO] + [c[0] for c in DEV_COLUMNS] + ['gwDevCount']
             + [c[0] for c in STATUS_COLUMNS] + [c[0] for c in sp_columns] + [c[0] for c in REG_COLUMNS]
             + [c[0] for c in ALARM_ACTIVE_COLUMNS] + [c[0] for c in ALARM_SCALARS]
             + [c[0] for c in ALARM_EVENT_COLUMNS] + [c[0] for c in ALARM_NOTIF_OBJECTS]
             + [c[0] for c in COMM_COLUMNS] + [n[0] for n in NOTIFICATIONS] + [e.split('(')[0] for e in enum_items])
    for n in names:
        if not DESCRIPTOR.match(n):
            raise MibError(f'invalid SMIv2 descriptor: {n}')
    objects = [n for n in names[:len(names) - len(enum_items)]]
    if len(set(objects)) != len(objects):
        raise MibError('duplicate descriptor')

    t = []
    t.append(f'''{MODULE} DEFINITIONS ::= BEGIN

-- Generated by tools/gen_mib.py from components/mex150/regmap.def and
-- components/alarm/alarm_catalog.def (enterprise {pen}). Do not edit.

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, enterprises,
    Integer32, Unsigned32, Counter32, Gauge32, TimeTicks
        FROM SNMPv2-SMI
    TEXTUAL-CONVENTION, DisplayString, TruthValue, DateAndTime, MacAddress
        FROM SNMPv2-TC
    MODULE-COMPLIANCE, OBJECT-GROUP, NOTIFICATION-GROUP
        FROM SNMPv2-CONF;

mestioGwMIB MODULE-IDENTITY
    LAST-UPDATED "{REVISION}"
    ORGANIZATION "MESTIO"
    CONTACT-INFO "MESTIO technical support"
    DESCRIPTION {quoted("Management information of the MESTIO Gateway, a Modbus RTU (RS485) to "
                        "SNMP/HTTP gateway for MEX150 HVAC controllers. Device tables are indexed by "
                        "gwDevIndex (configured device id + 1). SNMPv3 access uses USM authPriv with "
                        "HMAC-SHA-96 and AES-128; read-only and read-write users are separate.")}
    REVISION     "{REVISION}"
    DESCRIPTION  "Initial version."
    ::= {{ enterprises {pen} 1 }}

-- ---------------------------------------------------------------- textual conventions

GwTenths ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "d-1"
    STATUS       current
    DESCRIPTION  "An integer in tenths of the unit given by the object (235 means 23.5)."
    SYNTAX       Integer32

GwDevIndex ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "d"
    STATUS       current
    DESCRIPTION  "Index of a configured Modbus device: device id + 1."
    SYNTAX       Integer32 (1..{MAX_DEVICES})

GwUtf8String ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "255t"
    STATUS       current
    DESCRIPTION  "Text in UTF-8 (RFC 3629), not NUL-terminated."
    SYNTAX       OCTET STRING (SIZE (0..255))

GwAlarmSeverity ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION  "Alarm severity."
    SYNTAX       INTEGER {{ info(1), minor(2), major(3), critical(4) }}

GwWriteResult ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION  {quoted("Outcome of a register write: none(1) no write since boot, pending(2) queued "
                         "and not finished yet, applied(3) written and verified by reading back, "
                         "rejected(4) refused by the gateway or the device, uncertain(5) written but "
                         "not verified.", 17)}
    SYNTAX       INTEGER {{ none(1), pending(2), applied(3), rejected(4), uncertain(5) }}

GwAlarmCode ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION  {code_desc}
    SYNTAX       INTEGER {{
''')
    t.append(',\n'.join(f'                     {e}' for e in enum_items) + '\n                 }\n\n')

    t.append('''-- ---------------------------------------------------------------- branches

gwNotifications OBJECT IDENTIFIER ::= { mestioGwMIB 0 }
gwInfo          OBJECT IDENTIFIER ::= { mestioGwMIB 1 }
gwDevices       OBJECT IDENTIFIER ::= { mestioGwMIB 2 }
mexStatus       OBJECT IDENTIFIER ::= { mestioGwMIB 3 }
mexSetpoints    OBJECT IDENTIFIER ::= { mestioGwMIB 4 }
mexRegisters    OBJECT IDENTIFIER ::= { mestioGwMIB 5 }
gwAlarms        OBJECT IDENTIFIER ::= { mestioGwMIB 6 }
gwComm          OBJECT IDENTIFIER ::= { mestioGwMIB 7 }
gwConformance   OBJECT IDENTIFIER ::= { mestioGwMIB 8 }

-- ---------------------------------------------------------------- gwInfo (also sysObjectID)

''')
    for n, arc, syn, acc, desc, *u in INFO:
        t.append(object_type(n, syn, acc, desc, 'gwInfo', arc, u[0] if u else None) + '\n')

    t.append('-- ---------------------------------------------------------------- gwDevices\n\n')
    t.append(table('gwDevTable', 'gwDevEntry', 'gwDevices', 1, ['gwDevIndex'], DEV_COLUMNS,
                   'Configured Modbus devices.', 'One configured device.', 'GwDevEntry'))
    t.append(object_type('gwDevCount', f'Integer32 (0..{MAX_DEVICES})', 'read-only',
                         'Number of configured devices (rows of gwDevTable).', 'gwDevices', 2) + '\n')

    t.append('-- ---------------------------------------------------------------- mexStatus\n\n')
    t.append(table('mexStatusTable', 'mexStatusEntry', 'mexStatus', 1, ['gwDevIndex'], STATUS_COLUMNS,
                   'Live status of each configured MEX150.', 'Status of one device.', 'MexStatusEntry'))

    t.append('-- ---------------------------------------------------------------- mexSetpoints\n\n')
    t.append(table('mexSetpointTable', 'mexSetpointEntry', 'mexSetpoints', 1, ['gwDevIndex'], sp_columns,
                   'Writable set points of each configured MEX150. Column numbers are the register '
                   'address minus 40000. Write access requires the read-write community (SNMPv1/v2c) '
                   'or a read-write SNMPv3 user.',
                   'Set points of one device.', 'MexSetpointEntry'))

    t.append('-- ---------------------------------------------------------------- mexRegisters\n\n')
    t.append(table('mexRegTable', 'mexRegEntry', 'mexRegisters', 1, ['gwDevIndex', 'mexRegAddr'], REG_COLUMNS,
                   'Every mapped holding register of every configured device (read-only, generic '
                   'extension point for other controller types).',
                   'One register of one device.', 'MexRegEntry'))

    t.append('-- ---------------------------------------------------------------- gwAlarms\n\n')
    t.append(table('gwAlarmActiveTable', 'gwAlarmActiveEntry', 'gwAlarms', 1,
                   ['gwDevIndex', 'gwAlarmActiveCode'], ALARM_ACTIVE_COLUMNS,
                   'Active alarms.', 'One active alarm of one device.', 'GwAlarmActiveEntry'))
    for n, arc, syn, acc, desc in ALARM_SCALARS:
        t.append(object_type(n, syn, acc, desc, 'gwAlarms', arc) + '\n')
    t.append(table('gwAlarmEventTable', 'gwAlarmEventEntry', 'gwAlarms', 7, ['gwAlarmEventSeq'],
                   ALARM_EVENT_COLUMNS,
                   'The 32 most recent alarm transitions (raise, clear, acknowledge), oldest first.',
                   'One alarm transition.', 'GwAlarmEventEntry'))
    t.append('gwAlarmNotifObjects OBJECT IDENTIFIER ::= { gwAlarms 8 }\n\n')
    for n, arc, syn, acc, desc in ALARM_NOTIF_OBJECTS:
        t.append(object_type(n, syn, acc, desc, 'gwAlarmNotifObjects', arc) + '\n')

    t.append('-- ---------------------------------------------------------------- gwComm\n\n')
    t.append(table('gwCommTable', 'gwCommEntry', 'gwComm', 1, ['gwDevIndex'], COMM_COLUMNS,
                   'Modbus communication statistics per configured device.' + COMM_RESET_NOTE,
                   'Statistics of one device.', 'GwCommEntry'))

    t.append('-- ---------------------------------------------------------------- notifications\n\n')
    for n, arc, objs, desc in NOTIFICATIONS:
        t.append(f'{n} NOTIFICATION-TYPE\n    OBJECTS     {{ {", ".join(objs)} }}\n    STATUS      current\n'
                 f'    DESCRIPTION {quoted(desc)}\n    ::= {{ gwNotifications {arc} }}\n\n')

    groups = [
        ('gwInfoGroup', 1, [n for n, *_ in INFO], 'Gateway information and write results.'),
        ('gwDeviceGroup', 2, [c[0] for c in DEV_COLUMNS[1:]] + ['gwDevCount'], 'Configured devices.'),
        ('mexStatusGroup', 3, [c[0] for c in STATUS_COLUMNS], 'MEX150 live status.'),
        ('mexSetpointGroup', 4, [c[0] for c in sp_columns], 'MEX150 writable set points.'),
        ('mexRegisterGroup', 5, [c[0] for c in REG_COLUMNS[1:]], 'Generic register table.'),
        ('gwAlarmGroup', 6, [c[0] for c in ALARM_ACTIVE_COLUMNS[1:]] + [c[0] for c in ALARM_SCALARS]
         + [c[0] for c in ALARM_EVENT_COLUMNS[1:]], 'Alarm tables and counters.'),
        ('gwCommGroup', 7, [c[0] for c in COMM_COLUMNS], 'Communication statistics.'),
        ('gwNotifObjectsGroup', 8, [c[0] for c in ALARM_NOTIF_OBJECTS], 'Objects carried by notifications.'),
    ]
    t.append('''-- ---------------------------------------------------------------- conformance

gwCompliances OBJECT IDENTIFIER ::= { gwConformance 1 }
gwGroups      OBJECT IDENTIFIER ::= { gwConformance 2 }

gwCompliance MODULE-COMPLIANCE
    STATUS      current
    DESCRIPTION "Requirements for a MESTIO Gateway agent."
    MODULE      -- this module
        MANDATORY-GROUPS { ''' + ',\n                           '.join(g[0] for g in groups) + ''',
                           gwNotificationsGroup }
    ::= { gwCompliances 1 }

''')
    for g, arc, objs, desc in groups:
        t.append(f'{g} OBJECT-GROUP\n    OBJECTS     {{ ' + ',\n                  '.join(objs)
                 + f' }}\n    STATUS      current\n    DESCRIPTION {quoted(desc)}\n    ::= {{ gwGroups {arc} }}\n\n')
    t.append('gwNotificationsGroup NOTIFICATION-GROUP\n    NOTIFICATIONS { '
             + ',\n                    '.join(n[0] for n in NOTIFICATIONS)
             + ' }\n    STATUS      current\n    DESCRIPTION "Notifications sent by the gateway."\n'
             f'    ::= {{ gwGroups {len(groups) + 1} }}\n\nEND\n')
    text = re.sub(r'[ ]+\n', '\n', ''.join(t))
    if not text.isascii():
        raise MibError('generated MIB is not ASCII')
    return text


def pen_from_sdkconfig(path):
    m = re.search(r'^CONFIG_GW_SNMP_ENTERPRISE_PEN=(\d+)\s*$', Path(path).read_text(), re.M)
    if not m:
        raise MibError(f'CONFIG_GW_SNMP_ENTERPRISE_PEN not found in {path}')
    return int(m.group(1))


def gzip_bytes(data):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, compresslevel=9, mtime=0) as g:
        g.write(data)
    return buf.getvalue()


def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--regmap', default=str(root / 'components/mex150/regmap.def'))
    ap.add_argument('--catalog', default=str(root / 'components/alarm/alarm_catalog.def'))
    src = ap.add_mutually_exclusive_group()
    src.add_argument('--pen', type=int, help='enterprise number (default: from --sdkconfig, else 32473)')
    src.add_argument('--sdkconfig', help='read CONFIG_GW_SNMP_ENTERPRISE_PEN from this sdkconfig')
    ap.add_argument('--out', required=True, help='output file; *.gz is gzip -9 with mtime 0')
    a = ap.parse_args(argv)
    try:
        pen = a.pen if a.pen is not None else (pen_from_sdkconfig(a.sdkconfig) if a.sdkconfig else DEFAULT_PEN)
        text = generate(parse_def(a.regmap), parse_def(a.catalog), pen).encode('ascii')
    except (MibError, OSError, ValueError) as e:
        print(f'gen_mib.py: error: {e}', file=sys.stderr)
        return 1
    out = Path(a.out)
    data = gzip_bytes(text) if out.suffix == '.gz' else text
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + '.tmp')
    tmp.write_bytes(data)
    tmp.replace(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
