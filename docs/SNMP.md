# MESTIO Gateway — SNMP integration guide

For the team that connects the gateway to an external integrated monitoring system (NMS). It covers
what the agent serves, which notifications it sends and how to set it up. Sources of truth:
`components/snmp_gw/mib_oids.h` (OID arcs), `tools/gen_mib.py` (MIB text),
`components/mex150/regmap.def` (set point columns), `components/alarm/alarm_catalog.def` (alarm
codes), DESIGN.md §10 and the stream E entries in DECISIONS.md (these override DESIGN).

The MIB module is **`MESTIO-GW-MIB`**. A copy for the default PEN is in
[`docs/mib/MESTIO-GW-MIB.txt`](mib/MESTIO-GW-MIB.txt). The running device serves the copy that
matches its own build at `GET /api/v1/snmp/mib` (viewer; Settings → SNMP → "Download MIB"). Load
that file into the NMS, because the PEN in it can differ from the default.

## 1. Quick facts

| Item | Value |
|---|---|
| Protocols | SNMPv1, SNMPv2c, SNMPv3 (USM, authPriv only), UDP/161 on every interface |
| Enterprise PEN | `CONFIG_GW_SNMP_ENTERPRISE_PEN`, default **32473**. This is a **placeholder** (RFC 5612 documentation PEN), see §7 |
| Module root | `mestioGwMIB` = `1.3.6.1.4.1.<PEN>.1` (also `sysObjectID` = `…<PEN>.1.1`, gwInfo) |
| sysDescr | `MESTIO Gateway <fw version>` (read-only) |
| sysContact / sysName / sysLocation | read-write (RW community or the v3 RW user), ≤ 63 UTF-8 bytes, persisted; `""` restores the web-configured fallback |
| SNMPv3 engine ID | `80 00 7E D9 03 <base MAC>` for PEN 32473 (`0x80000000 \| PEN`, format 3 = MAC) |
| snmpEngineBoots | persisted in NVS `gw_fact`, increments every boot and never decreases, also across a factory reset |
| Notifications | v1 traps, v2c traps, v2c informs to ≤ 4 targets. **No v3 notifications** |
| Factory state | SNMP disabled, v1/v2c off, no RO community, v3 users without keys. Nothing answers until it is configured |

## 2. OID map

`.PEN` below stands for `1.3.6.1.4.1.<PEN>`. All tables are read-only except `mexSetpointTable`.

| OID | Node | Content | Index |
|---|---|---|---|
| `.PEN.1.0` | gwNotifications | notification types, §4 | — |
| `.PEN.1.1` | gwInfo | scalars: `gwFwVersion.1`, `gwMacAddress.2`, `gwUptime.3`, `gwTimeValid.4`, `gwWallTime.5`, `gwActiveAlarms.6`, `gwConfigRev.7`, `gwLastConfigSection.8`, last register write `gwLastWrite{Result.9, DevIndex.10, RegAddr.11, Value.12, Reason.13, Time.14, Command.15, Principal.16}`, notification counters `gwTrapsSent.17`, `gwTrapsDropped.18`, `gwInformsFailed.19` | scalars (`.0`) |
| `.PEN.1.2.1` | gwDevTable | per device: name, Modbus slave address, enabled, online, data age (ms), poll sequence | `gwDevIndex` |
| `.PEN.1.2.2` | gwDevCount | number of configured devices | scalar |
| `.PEN.1.3.1` | mexStatusTable | MEX150 live status: `mexStatusValid.1` (data fresh), temperature/humidity/current (`GwTenths`, 235 = 23.5), run state, start/stop delay remaining, mode flags (BITS), stage counts for cool/heat/hum/dehum, blower, alarm coil bitmap, input port, alarm detail words, proportional outputs | `gwDevIndex` |
| `.PEN.1.4.1` | mexSetpointTable | **read-write** set points, column = Modbus address − 40000 (§2.2) | `gwDevIndex` |
| `.PEN.1.5.1` | mexRegTable | every mapped MEX150 register: key, name, raw word, scaled value as text, scale, unit, writable, valid. This is the generic extension point: new `regmap.def` rows appear here without a MIB change | `gwDevIndex`, `mexRegAddr` (40001..40059) |
| `.PEN.1.6.1` | gwAlarmActiveTable | active alarms: name, severity, since, acked, acked by, value | `gwDevIndex`, `gwAlarmActiveCode` |
| `.PEN.1.6.2`–`.6` | gwAlarm{Active,Critical,Major,Minor,Info}Count | active alarm counts by severity | scalars |
| `.PEN.1.6.7` | gwAlarmEventTable | the last 32 alarm transitions (raise / clear / ack): time, device, code, severity, value, user | `gwAlarmEventSeq` |
| `.PEN.1.6.8` | gwAlarmNotifObjects | accessible-for-notify varbinds of the alarm notifications | — |
| `.PEN.1.7.1` | gwCommTable | Modbus statistics per device: tx, rx ok, CRC errors, timeouts, exceptions, malformed, offline count, RTT last/avg/max (ms), poll cycles, online since | `gwDevIndex` |
| `.PEN.1.8` | gwConformance | compliance and groups | — |

Standard MIBs that are also served are the MIB-II `system` group (`1.3.6.1.2.1.1`),
SNMP-FRAMEWORK-MIB (`snmpEngine*`) and SNMP-USER-BASED-SM-MIB (`usmUserTable`, read-only).

### 2.1 Indexes and value conventions

- **`gwDevIndex` = configured device id + 1** (1..4). Device id 0 in the web UI and REST API is
  index 1 in SNMP. Rows exist only for configured devices.
- `GwTenths` (DISPLAY-HINT `d-1`) carries values in tenths. 235 means 23.5 °C, and −15 means −1.5.
- `TruthValue`: true(1), false(2). `mexRunState`: stopped(1), running(2).
- `DateAndTime` values are 11 octets in UTC (`+0:0`). While the gateway has no valid clock
  (`gwTimeValid` = false(2)), and for events that happened before it had one, they read
  1970-01-01 00:00:00.
- `GwAlarmCode` is stable and never renumbered. 1xx are MEX150 alarm coils (100 + coil), 201 is a
  MEX150 register bit, 301 is `commLost` (generated by the gateway), and 4xx are user threshold
  rules (400 + rule id). The full list with default severities is in the MIB's `GwAlarmCode`.
- `GwAlarmSeverity`: info(1), minor(2), major(3), critical(4).
- Principals (`gwLastWritePrincipal`, `gwAlarmActiveAckedBy`, `gwAlarmEventUser`): web account
  names are returned only to SNMPv3 requests. v1/v2c requests read `web`. `@snmp` and `@console`
  are always shown.

### 2.2 Set points (mexSetpointTable)

| Column | Object | Register | Range (raw) | Unit |
|---|---|---|---|---|
| 12 | mexSpSetTemp | 40012 | 50..500 (5.0–50.0) | °C ×10 |
| 13 | mexSpSetHum | 40013 | 200..800 | % ×10 |
| 14 | mexSpCoolDev | 40014 | 1..100 | °C ×10 |
| 15 | mexSpHeatDev | 40015 | 1..100 | °C ×10 |
| 16 | mexSpHumDev | 40016 | 10..100 | % ×10 |
| 17 | mexSpDehumDev | 40017 | 10..100 | % ×10 |
| 18 | mexSpRunDelay | 40018 | 1..180 | s |
| 19 | mexSpStopDelay | 40019 | 1..180 | s |
| 27 | mexSpHiTemp | 40027 | 249..500 | °C ×10 (stopped only) |
| 28 | mexSpLoTemp | 40028 | 49..200 | °C ×10 (stopped only) |
| 29 | mexSpHiHum | 40029 | 599..900 | % ×10 (stopped only) |
| 30 | mexSpLoHum | 40030 | 99..400 | % ×10 (stopped only) |

The table is generated from `regmap.def` rows flagged `SNMP_RW`. Check the served MIB for the exact
column set of a given firmware. Example: set device 1 to 23.5 °C with
`snmpset … .PEN.1.4.1.1.12.1 i 235`.

SET outcomes: wrong type or range gives `wrongValue`, a read-only user or community gives
`notWritable`, a register that is writable only while the unit is stopped gives
`inconsistentValue`, and stale data or a full write queue gives `resourceUnavailable`. The gateway
then writes the register and verifies it by reading it back, waiting up to 1 s. If the device
rejects the write, the SET answers `commitFailed`. Applied, unverified (`uncertain`) and still
`pending` writes answer `noError`. The final result appears in `gwLastWriteResult` and its group,
and in the audit log with principal `@snmp`.

## 3. Access setup

Set it up in the web UI (Settings → SNMP) or with `PUT /api/v1/config/snmp` (API.md §4.8). SNMP
runs only when both `snmp.enabled` and `/config/security services.snmp` are true. The IP allowlist
(`/config/security ip_allow`) also applies to UDP/161.

### 3.1 SNMPv1 / v2c

- `ro`: the read community. It is required before `v1` or `v2c` can be enabled, and there is no
  default.
- `rw`: the write community. Empty (the default) disables SET over v1/v2c. The RW community can
  also read (net-snmp `rwcommunity` semantics).
- Communities are write-only over REST (`ro_set` / `rw_set` show only whether one is stored). They
  are up to 32 printable ASCII characters with no spaces.
- Requests with a wrong community get no answer, plus an optional `authenticationFailure` trap.
  v1/v2c send the community in cleartext. Prefer v3 across untrusted networks.

### 3.2 SNMPv3 users

There are two fixed slots: by default slot 0 `gwmonitor` (read-only) and slot 1 `gwadmin`
(read-write). The names and the access of each slot can be changed. Security is always **authPriv with HMAC-SHA-96 + AES-128 (CFB)**.
noAuthNoPriv, authNoPriv, MD5 and DES are refused.

1. Set the passphrases (8–64 UTF-8 bytes each, auth and priv separately) in the UI, or send
   `{"v3":{"users":[{"name":"gwmonitor","access":"ro","enabled":true,"auth_pass":"…","priv_pass":"…"}, …]}}`.
   The gateway converts them to keys localized to its engine ID (RFC 3414 A.2). It never stores
   the passphrases, and the PUT takes about 1 s.
2. A user works only when `enabled` and `keys_set` are both true. Otherwise it behaves as an
   unknown user.
3. On the NMS, configure the same user name, SHA, AES and passphrases. Discover the engine ID
   automatically, or enter it as `80007ED903` followed by the base MAC (for PEN 32473).
4. Test it: `snmpget -v3 -l authPriv -u gwmonitor -a SHA -A '<auth>' -x AES -X '<priv>' <ip> 1.3.6.1.2.1.1.1.0`.

The localized keys depend on the engine ID, which is derived from the PEN and the MAC. **Changing
the PEN, or moving a configuration export to another unit, invalidates the stored v3 keys.**
Re-enter the passphrases afterwards (`keys_set` shows false until then).

## 4. Notifications

| OID | Notification | Varbinds (after `sysUpTime.0`, `snmpTrapOID.0`) | When |
|---|---|---|---|
| `.PEN.1.0.1` | gwAlarmRaised | `gwAlarmDevIndex.0`, `gwAlarmCode.0`, `gwAlarmName.0`, `gwAlarmSeverity.0`, `gwAlarmTime.0`, `gwAlarmValue.0`, `gwAlarmSeq.0` | an alarm becomes active |
| `.PEN.1.0.2` | gwAlarmCleared | same as gwAlarmRaised | an alarm clears |
| `.PEN.1.0.3` | gwCommLost | `gwDevName.<idx>`, `gwDevOnline.<idx>`, `gwAlarmTime.0` | Modbus communication with a device is lost |
| `.PEN.1.0.4` | gwCommRestored | same as gwCommLost | communication is restored |
| `.PEN.1.0.5` | gwConfigChanged | `gwLastConfigSection.0`, `gwConfigRev.0` | a configuration section is saved |
| `.PEN.1.0.6` | gwFirmwareUpdated | `gwFwVersion.0` | a new firmware passed its health check and was marked valid |
| `.PEN.1.0.7` | gwTestNotification | `gwFwVersion.0` | `POST /api/v1/snmp/test-trap` (UI "Send test") |
| `1.3.6.1.6.3.1.1.5.1` | coldStart | — | agent start, retried every 1 s for up to 300 s until each target is reachable |
| `1.3.6.1.6.3.1.1.5.5` | authenticationFailure | — | bad community or wrong v3 digest, only when `auth_traps` is on |

- **v2c** carries `snmpTrapOID.0` = the OID above. **v1** uses enterprise `.PEN.1` with
  specific-trap N for the gateway notifications (RFC 3584 mapping), and enterprise `snmp` with the
  generic trap for coldStart and authenticationFailure.
- `gwAlarmSeq` is the global alarm event sequence number. Use it to detect lost notifications by
  comparing it against `gwAlarmEventTable`, which is indexed by the same sequence.
- **Targets**: up to 4, each with `host` (IPv4), `port` (default 162), `version` (`v1` / `v2c`),
  `community` (default `mestio-trap`, so change it), `inform` (v2c only) and `enabled`.
- **Informs**: retried 3 times at 5 s intervals and matched by request id. Up to 16 can be in
  flight; beyond that a notification goes out as a plain trap. An inform that is never
  acknowledged increments `gwInformsFailed`. Acknowledgements are accepted from the target with its
  trap community even when v2c polling is off or the target is outside the IP allowlist.
  Limitation: two targets on the same IP with different ports or communities cannot both use
  informs reliably.
- **Rate limits**: each alarm, config or firmware notification draws one token from a bucket of
  10/s with a burst of 10, and the token covers the fan-out to every target. Excess notifications are dropped and counted in
  `gwTrapsDropped`; the alarm itself stays visible in the tables. Comm notifications are
  coalesced instead: a state must hold 2 s, each device reports at most once every 10 s, and the
  latest state is always reported eventually. authenticationFailure has its own bucket (1/s,
  burst 2) and is never sent as an inform. Inform retransmissions and test notifications are not
  limited.
- After a reboot, poll `gwAlarmActiveTable` to resynchronize. Notifications are edge events and
  the gateway does not replay them.
- Disabling SNMP stops every notification and abandons pending informs.

## 5. Integration checklist (NMS side)

1. Get the MIB from the device (`GET /api/v1/snmp/mib`) and load it together with SNMPv2-SMI, -TC
   and -CONF. `snmptranslate -M +. -m +MESTIO-GW-MIB -Tp` must parse it.
2. Configure the v3 user `gwmonitor` (or a v2c RO community) for polling. Suggested intervals are
   10–30 s for `mexStatusTable` and `gwDevTable`, and 60 s for `gwCommTable` and the alarm
   counters. The gateway polls each MEX150 every `modbus.poll_ms` (default 1 s), and data older
   than max(3 s, poll_ms + 3 s) reads `mexStatusValid` = false(2).
3. Add the NMS as a trap target. Use v2c with `inform: true` for reliable delivery, and set a
   non-default trap community. Send a test notification from the UI and check that it arrives.
4. Map alarm severity from `gwAlarmSeverity` (or from the `GwAlarmCode` defaults), and key alarms
   by (`gwAlarmDevIndex`, `gwAlarmCode`). A matching gwAlarmCleared closes the alarm.
5. Use only the read-write credentials (`gwadmin` or the RW community) for set point writes, and
   watch `gwLastWriteResult`.
6. Verify with `tools/snmp_smoke.py` (docs/HW_TEST.md §6).

## 6. Extending the agent

- **New MEX150 registers**: add a row to `components/mex150/regmap.def`. The row appears in
  `mexRegTable` automatically. If it is flagged `SNMP_RW`, it also becomes a `mexSetpointTable`
  column (column = address − 40000, so existing OIDs never move).
- **New alarm codes**: add them to `components/alarm/alarm_catalog.def`. The `GwAlarmCode`
  enumeration is regenerated, and codes are never reused.
- **New MIB branch**: implement an `snmp_module_t` (`components/snmp_gw/include/snmp_gw/registry.h`,
  10 of 12 slots used), add its arcs to `GWMIB_NODES` in `mib_oids.h` under a new
  `mestioGwMIB` arc (`.PEN.1.9`+), and add its objects to `tools/gen_mib.py`.
  `tests/test_mib.py` checks that the MIB and the agent agree OID by OID.
- Regenerate this folder's copy afterwards:
  `uv run --locked python tools/gen_mib.py --pen 32473 --out docs/mib/MESTIO-GW-MIB.txt`.
  `tests/test_tools.py` fails while the copy is stale.

## 7. Before production: replace the placeholder PEN

32473 is reserved for documentation (RFC 5612) and must not be used by a shipped product.

1. Obtain the vendor's IANA Private Enterprise Number.
2. Set it with `idf.py menuconfig` → *MESTIO Gateway* → *SNMP enterprise PEN*, or put
   `CONFIG_GW_SNMP_ENTERPRISE_PEN=<pen>` in `sdkconfig.defaults` and delete `sdkconfig`. Rebuild.
   The build regenerates the embedded MIB with the new PEN (`cmake/gw_mib.cmake`).
3. Regenerate `docs/mib/MESTIO-GW-MIB.txt` with `--pen <pen>`, and update the default in
   `tools/gen_mib.py` and in the drift test so they agree.
4. Every OID under `.PEN`, `sysObjectID`, the notification OIDs and the v3 engine ID change.
   Existing v3 keys become invalid, so re-enter the passphrases on each unit. NMS templates built
   against 32473 must be re-imported.
