# MESTIO Gateway — REST & WebSocket API (v1)

Status: **frozen Phase 0 contract** (DESIGN.md §6, §7). Firmware (`components/web`), the mock server
(`tools/mock_server.mjs`) and the UI (`web/`) implement exactly this document. Machine-readable
schemas: `docs/api/*.schema.json` (JSON Schema draft 2020-12, `$id` base
`https://mestio.invalid/gw/api/v1/`). Every JSON example below is preceded by an HTML comment naming
its schema and is validated by the contract tests.

## 1. Conventions

| Topic | Rule |
|---|---|
| Base path | `/api/v1`. All paths below are relative to it except `/ws`. |
| Encoding | Request and response bodies are UTF-8 JSON (`Content-Type: application/json`) unless stated. A non-empty body with another content type → 400 `bad_request`. |
| Body limits | JSON 8 KB, config import 32 KB, firmware 3 MB (partition size). Larger → 413 `payload_too_large`. Routes without a body reject any body with 413. |
| Time | Timestamps are Unix epoch **milliseconds UTC** (`ts`, `since`, `*_ms`). `null` when the gateway's wall clock was not valid at that moment. Durations are seconds (`*_s`). |
| Numbers | Register *values* are decimal numbers at display scale (`23.5`). *Raw* integers (register scale, e.g. `235`) appear only in members named `raw`, `regs`, `r`, `requested`, history channels and alarm `value`. Every raw that is **read** (live `regs`, WS `snap.r`, write-result/command/WS `write` `raw`) is the decoded register word: sign-extended for signed registers (40021, 40022, 40036), the full 16-bit word for bitfield registers and 40005 (bit 0 run, bits 15..8 delay seconds). A raw that is **written** (`{"raw"}` body, command `requested`) is the same except for 40005, where it is the run bit 0/1 (`/meta/registers` `min`/`max`); writing back a read 40005 word such as 2561 is `rejected`/`range`. |
| Strings | Length limits on UTF-8 strings are in **bytes** (device/rule names 23, texts 63, passwords at most 64), except the password minimum (10 characters). Schema `maxLength` (characters) is only an upper bound; the UI checks bytes. |
| Register keys | Holding registers are addressed by their 4xxxx number (`"40036"` as object key, `40036` as path/number). |
| Devices | `{d}` / `dev` is the device index 0..3 (not the Modbus slave id). Unknown or unconfigured index → 404. |
| Unknown members | Clients MUST ignore unknown response members. The firmware rejects unknown request members with 422 `validation` (`code: "unknown_field"`), except in config import (ignored). |
| PUT semantics | `PUT /config/*` merges: absent members keep their current value; arrays that are present replace the whole array, and so does the map `alarms.sev_override`. Response = full resulting section (same as GET). |
| Write-only secrets | Passwords, PSK, communities, SNMPv3 passphrases are accepted on PUT/POST and never returned; GET shows `<x>_set: true/false` instead. |
| Caching | Every `/api` response carries `Cache-Control: no-store`, except `GET /meta/*` (strong `ETag` = build id, + map version for `/meta/registers`, + effective-severity hash for `/meta/alarms` (it changes with `sev_override`); `Cache-Control: no-cache`, `If-None-Match` → 304). |
| Headers | Every response: `Content-Security-Policy` (DESIGN.md §6), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`. Never `Server`, never CORS headers. |
| Versioning | Additive changes (new endpoints, new optional request members, new response members, new enum values in responses documented as extensible: error codes, log types, WS message types) stay in v1. Renaming/removing members, changing types/units/semantics → `/api/v2` and WS `v:2`. `GET /meta/registers` `version` changes with the register map. |

### 1.1 Authentication, roles, CSRF

* **Host check (DNS-rebinding defence)**: every HTTP request and the WebSocket upgrade must carry a
  `Host` naming this device: its current Ethernet IPv4, the recovery AP address `192.168.150.1`, the
  configured hostname or `<hostname>.local` (optional `:port`). Anything else (including a missing
  `Host`) → 421 `misdirected` before any session handling, for static files too. Other DNS names
  that resolve to the gateway are therefore not usable; use the address or the hostname.
* Login (`POST /auth/login`) sets `gw_sid=<token>; Path=/; HttpOnly; SameSite=Strict` (128-bit token).
  Sessions expire after `idle_min` (config/security, default 15) without an authenticated REST request,
  and 12 h after login regardless. WebSocket traffic does not refresh the idle timer (deliberate: a
  forgotten open dashboard must not keep a session alive). A purely passive dashboard therefore
  ends after `idle_min` — the server sends WS `bye` `expired` and the UI returns to the sign-in page
  with "Your session has ended". For wall displays raise `idle_min` (max 120) and use a `viewer`
  account; the 12 h absolute limit always applies.
* Roles: `viewer` < `operator` < `admin`. A route with role R accepts R and higher.
  `operator` adds register writes, run/stop and alarm ack; `admin` adds configuration, users, firmware and system.
* **CSRF**: every route marked ✓ in the CSRF column (all POST/PUT/DELETE except login) requires header
  `X-CSRF-Token: <csrf>` (value from login/session) → else 403 `csrf`. For every POST/PUT/DELETE,
  login included, if `Origin` or `Referer` is present its `host[:port]` must equal `Host` → else 403
  `origin`.
* **Forced password change**: while the session has `must_change: true`, every route except
  `GET /session`, `POST /auth/password` and `POST /auth/logout` answers 403 `password_change_required`,
  and the WebSocket upgrade is refused with 403. An admin setting `must_change` on a user revokes that
  user's sessions.
* Unauthenticated surface (complete): `GET /`, hashed static assets, `GET /favicon.svg`,
  `POST /api/v1/auth/login`, `GET /api/v1/session`. Anything else without a valid session → 401
  `unauthorized` (unknown paths → 404 regardless of authentication). No device or product
  information is ever returned unauthenticated.
* Rate limit (per client IP, shared by login and by re-entering one's own password in
  `POST /auth/password` and `POST /system/factory-reset`): 5 failures per IP within 5 min
  (configurable) → locked 5 min, doubling per repeated lock up to 30 min; > 20 login failures/min
  globally → every login answer delayed 1 s. Locked → 429 `rate_limited`.

## 2. Errors

All 4xx/5xx JSON responses use `error.schema.json`. `error` and validation `code` values are
extensible (§1 Versioning): a client that meets an unknown one falls back to the HTTP status.

<!-- schema: error -->
```json
{"error": "validation", "message": "must be within 5.0..50.0", "field": "thr", "code": "range"}
```

| HTTP | `error` | When / extra members |
|---|---|---|
| 400 | `bad_request` | malformed query/path/content type |
| 400 | `invalid_json` | body is not valid JSON or wrong top-level type |
| 401 | `unauthorized` | no/expired session |
| 401 | `bad_credentials` | login failed (unknown user and wrong password are indistinguishable) |
| 403 | `forbidden` | role too low |
| 403 | `csrf` / `origin` | CSRF token missing/wrong; Origin/Referer host ≠ Host |
| 403 | `password_change_required` | session must change its password first |
| 404 | `not_found` | unknown route, device, register, user, command, alarm key, core dump, rollback slot |
| 421 | `misdirected` | `Host` header does not name this device (§1.1) |
| 409 | `rejected` | register write rejected — extra `state:"rejected"`, `reason`, `cmd`, `addr` (see §4.4) |
| 409 | `conflict` | operation not valid in current state (e.g. confirm without pending network change) |
| 409 | `exists` / `limit` / `last_admin` / `self` | user management (name taken / 4 users / last admin / acting on oneself) |
| 413 | `payload_too_large` | body over the route limit |
| 422 | `validation` | semantic validation; extra `field` (dotted path, e.g. `devices[1].slave`) and `code`: `required` `type` `range` `format` `length` `duplicate` `overlap` `unknown_register` `unknown_field` `too_many` `unsupported_schema` `lockout` |
| 422 | `policy` | password policy; extra `rules: [...]` of `min_length` `max_length` `classes` `not_username` `not_default` `not_previous` `charset` |
| 422 | `wrong_password` | own password re-entry wrong: `field` `current` (password change) or `password` (factory reset); counts toward the rate limit. Never 401, so the UI keeps the session |
| 422 | `hash_mismatch` / `image_invalid` | firmware SHA-256 mismatch / wrong project, downgrade, corrupt image |
| 423 | `locked` | resource busy: network change already pending, firmware upload in progress, running firmware still being validated |
| 429 | `rate_limited` | extra `retry_after` (seconds); login and own-password re-entry |
| 500 | `internal` | unexpected firmware error |
| 503 | `unavailable` / `busy` | service not ready or storage failure / write queue full |

<!-- schema: error -->
```json
{"error": "rate_limited", "message": "too many failed logins", "retry_after": 287}
```

<!-- schema: error -->
```json
{"error": "policy", "message": "password does not meet the policy", "field": "new", "rules": ["min_length", "classes"]}
```

## 3. Endpoint index

Role: `—` public, `cookie` = any valid session. CSRF ✓ = `X-CSRF-Token` + Origin check.

| Method | Path | Role | CSRF | Request schema | Success | Response schema |
|---|---|---|---|---|---|---|
| POST | /auth/login | — | | auth-login.request | 200 | auth-login.response |
| POST | /auth/logout | cookie | ✓ | — | 204 | — |
| GET | /session | — (cookie) | | — | 200 / 401 | session.response / empty |
| POST | /auth/password | cookie | ✓ | auth-password.request | 204 | — |
| GET | /meta/registers | viewer | | — | 200 | meta-registers.response |
| GET | /meta/alarms | viewer | | — | 200 | meta-alarms.response |
| GET | /system/info | viewer | | — | 200 | system-info.response |
| GET | /system/network | admin | | — | 200 | system-network.response |
| GET | /devices | viewer | | — | 200 | devices.response |
| GET | /devices/{d}/live | viewer | | — | 200 | device-live.response |
| PUT | /devices/{d}/registers/{addr} | operator | ✓ | register-write.request | 200/202/409 | write-result.response |
| POST | /devices/{d}/run | operator | ✓ | device-run.request | 200/202/409 | write-result.response |
| GET | /devices/{d}/commands/{id} | operator | | — | 200 | command.response |
| GET | /devices/{d}/history | viewer | | — | 200 | history.response |
| GET | /devices/{d}/history.csv | viewer | | — | 200 | CSV §4.6 |
| GET | /devices/{d}/stats | viewer | | — | 200 | device-stats.response |
| POST | /devices/{d}/stats/reset | admin | ✓ | — | 204 | — |
| GET | /alarms/active | viewer | | — | 200 | alarms-active.response |
| POST | /alarms/ack | operator | ✓ | alarms-ack.request | 204 | — |
| GET | /alarms/history | viewer | | — | 200 | alarms-history.response |
| GET | /alarms/history.csv | viewer | | — | 200 | CSV §4.7 |
| GET / PUT | /config/rules | viewer / admin | PUT ✓ | config-rules | 200 | config-rules |
| GET / PUT | /config/alarms | viewer / admin | PUT ✓ | config-alarms.request | 200 | config-alarms.response |
| GET / PUT | /config/general | viewer / admin | PUT ✓ | config-general.request | 200 | config-general.response |
| GET / PUT | /config/network | admin | PUT ✓ | config-network.request | 200 / 202 | config-network.response / network-apply.response |
| POST | /config/network/confirm | admin | ✓ | — | 204 | — |
| GET / PUT | /config/modbus | viewer / admin | PUT ✓ | config-modbus.request | 200 | config-modbus.response |
| GET / PUT | /config/snmp | admin | PUT ✓ | config-snmp.request | 200 | config-snmp.response |
| GET | /snmp/mib | viewer | | — | 200 | text (MIB) |
| POST | /snmp/test-trap | admin | ✓ | — | 200 | snmp-test-trap.response |
| GET / PUT | /config/time | viewer / admin | PUT ✓ | config-time.request | 200 | config-time.response |
| POST | /time | admin | ✓ | time-set.request | 204 | — |
| GET / PUT | /config/security | admin | PUT ✓ | config-security.request | 200 | config-security.response |
| GET / PUT | /config/notify | admin | PUT ✓ | config-notify.request | 200 | config-notify.response |
| GET | /users | admin | | — | 200 | users.response |
| POST | /users | admin | ✓ | user-create.request | 201 | user.response |
| PUT | /users/{name} | admin | ✓ | user-update.request | 200 | user.response |
| DELETE | /users/{name} | admin | ✓ | — | 204 | — |
| GET | /system/firmware | admin | | — | 200 | firmware.response |
| POST | /system/firmware | admin | ✓ | octet-stream | 200 | firmware-upload.response |
| POST | /system/firmware/rollback | admin | ✓ | — | 202 | reboot.response |
| GET | /system/config/export | admin | | — | 200 | config-bundle |
| POST | /system/config/import | admin | ✓ | config-bundle | 200 | config-import.response |
| POST | /system/reboot | admin | ✓ | — | 202 | reboot.response |
| POST | /system/factory-reset | admin | ✓ | factory-reset.request | 202 | reboot.response |
| GET | /system/logs | admin | | — | 200 | logs.response |
| GET | /system/coredump | admin | | — | 200 | coredump.response |
| GET (Upgrade) | /ws | cookie + Origin | | ws-client | 101 | ws-server |

`/config/alarms` and `/system/network` are additions to the DESIGN.md §7 table (see DECISIONS.md).

## 4. Endpoints

### 4.1 Auth & session

**POST /auth/login** — public, PBKDF2 (≈0.1–0.4 s). 200 + `Set-Cookie`; 401 `bad_credentials`; 429 `rate_limited`.

<!-- schema: auth-login.request -->
```json
{"user": "admin", "pass": "mestio150!"}
```
<!-- schema: auth-login.response -->
```json
{"user": "admin", "role": "admin", "csrf": "q0Vb3mJ8sZ1xT5yR2wK9dA", "must_change": true, "idle_s": 900}
```

**POST /auth/logout** — 204, clears the cookie, WS clients of the session receive `bye` `logout`.

**GET /session** — public route that reports the current session (does not refresh the idle timer).
200 with the session, or 401 with `{}`.

<!-- schema: session.response -->
```json
{"user": "admin", "role": "admin", "csrf": "q0Vb3mJ8sZ1xT5yR2wK9dA", "must_change": false, "idle_s": 900, "expires_in": 873}
```
<!-- schema: empty -->
```json
{}
```

**POST /auth/password** — change own password. 204; 422 `wrong_password` (current wrong, `field:"current"`;
counted by the per-IP rate limiter), 429 `rate_limited`, 422 `policy` (`rules`, includes `not_previous`).
Clears `must_change`; the user's other sessions are revoked (their WS gets `bye` `revoked`).

<!-- schema: auth-password.request -->
```json
{"current": "mestio150!", "new": "Plant-Room#2026"}
```

Password policy: at least 10 characters and at most 64 UTF-8 bytes, at least 3 of {lower, upper,
digit, other}, ≠ user name, ≠ factory default, ≠ current password, no control characters.

### 4.2 Meta

**GET /meta/registers** — the register map from `regmap.def` (single source; the UI has no copy).
`min`/`max`/`disabled` are scaled values; `disabled` = sentinel meaning "function disabled" (UI shows
"사용 안 함 / Disabled"). `stopped_only` registers are writable only while the unit is stopped.
Arrays shortened in this example.

<!-- schema: meta-registers.response -->
```json
{
  "version": 1,
  "groups": ["status", "control", "setpoint", "deviation", "delay", "calibration", "limits", "options", "info", "alarm"],
  "regs": [
    {"key": "run", "addr": 40005, "scale": 1, "signed": false, "access": "rw", "min": 0, "max": 1, "disabled": null,
     "stopped_only": false, "snmp_rw": false, "runbit": true, "bits": false, "group": "control", "unit": "",
     "ko": "운전/정지", "en": "Run/Stop", "enum": [{"value": 0, "ko": "정지", "en": "Stop"}, {"value": 1, "ko": "운전", "en": "Run"}]},
    {"key": "set_temp", "addr": 40012, "scale": 10, "signed": false, "access": "rw", "min": 5.0, "max": 50.0,
     "disabled": null, "stopped_only": false, "snmp_rw": true, "runbit": false, "bits": false, "group": "setpoint",
     "unit": "°C", "ko": "설정온도", "en": "Temperature setpoint"},
    {"key": "hi_temp", "addr": 40027, "scale": 10, "signed": false, "access": "rw", "min": 25.0, "max": 50.0,
     "disabled": 24.9, "stopped_only": true, "snmp_rw": true, "runbit": false, "bits": false, "group": "limits",
     "unit": "°C", "ko": "고온설정", "en": "High temperature limit"},
    {"key": "temp", "addr": 40036, "scale": 10, "signed": true, "access": "ro", "min": -25.0, "max": 85.0,
     "disabled": null, "stopped_only": false, "snmp_rw": false, "runbit": false, "bits": false, "group": "status",
     "unit": "°C", "ko": "현재온도", "en": "Temperature"}
  ],
  "bits": [
    {"key": "ad1_leak", "addr": 40003, "lsb": 6, "width": 1, "unit": "", "ko": "누수", "en": "Leak"},
    {"key": "run_delay_left", "addr": 40005, "lsb": 8, "width": 8, "unit": "s", "ko": "지연시간", "en": "Delay remaining"}
  ],
  "coils": [
    {"key": "run_blower", "n": 1, "group": "status", "ko": "송풍기운전", "en": "Blower"},
    {"key": "alm_high_temp", "n": 27, "group": "alarm", "ko": "고온경보", "en": "High temperature alarm"}
  ]
}
```

**GET /meta/alarms** — alarm catalog (`alarm_catalog.def`) with effective severities.
`source`: `coil:<n>`, `bit:<addr>.<bit>`, `comm`, `rule:<id>`.

<!-- schema: meta-alarms.response -->
```json
[
  {"id": "high_temp", "code": 127, "sev": 2, "ko": "고온경보", "en": "High temperature", "source": "coil:27"},
  {"id": "contamination", "code": 201, "sev": 1, "ko": "실린더오염경보", "en": "Cylinder contamination", "source": "bit:40003.7"},
  {"id": "comm_lost", "code": 301, "sev": 2, "ko": "통신두절", "en": "Communication lost", "source": "comm"},
  {"id": "rule_1", "code": 401, "sev": 2, "ko": "사용자규칙 1", "en": "User rule 1", "source": "rule:1"}
]
```

### 4.3 System status

**GET /system/info** (viewer)

<!-- schema: system-info.response -->
```json
{
  "fw": "1.0.0", "build": "2026-10-19 10:12:03", "idf": "v6.1", "mac": "a0:85:e3:12:34:56",
  "hostname": "mestio-gw-3456", "uptime_s": 86400, "time_valid": true, "time_ms": 1792371600000,
  "heap": {"int_free": 98304, "int_min": 71680, "psram_free": 7340032},
  "part": {"running": "ota_0", "state": "valid"},
  "diag": {"reset_reason": 1, "boot_count": 12, "evt_dropped": 0, "hb_stale": 0, "init_faults": 0,
           "ws_clients": 1, "fs": {"total": 10289152, "used": 1048576}}
}
```
`diag.init_faults` (optional) = subsystems that failed at boot (bits: 1 storage mount — running on
RAM defaults, nothing is saved; 2 store; 4 Modbus; 8 network; 16 web/auth; 32 SNMP; 64 syslog;
128 core). Non-zero also selects the FAULT LED. `boot_count` survives a factory reset (it is the
SNMP engine boots counter, which must never decrease).

**GET /system/network** (admin) — live interface state (the committed config is `GET /config/network`).

<!-- schema: system-network.response -->
```json
{
  "eth": {"link": true, "has_ip": true, "mode": "static", "ip": "192.168.10.150", "mask": "255.255.255.0",
          "gw": "192.168.10.1", "dns1": "192.168.10.1", "dns2": "", "mac": "a0:85:e3:12:34:59", "link_changes": 1},
  "ap": {"active": false, "reason": "none", "clients": 0, "ssid": "MESTIO-GW-3456", "ip": "", "off_in_s": 0},
  "provisional": null,
  "sntp": {"enabled": false, "synced": false, "last_ms": null}
}
```

### 4.4 Devices, live data, writes

**GET /devices**

<!-- schema: devices.response -->
```json
[{"id": 0, "name": "MEX150", "slave": 1, "enabled": true, "online": true, "last_ms": 1792371600000, "seq": 1234}]
```

**GET /devices/{d}/live** — latest snapshot. `regs` contains every register of `regmap.def`
(slow-group registers 40027–40030, 40053, 40054, 40059 only once `slow_valid`); `coils` bit n-1 = coil n.
`fresh` = online and snapshot younger than max(3 s, `poll_ms` + 3 s) (§4.4 Freshness). `derived` is `null` before the first successful poll.
`stages` are active stage counts from the run-status coils; `mode` from coils 12–15.

<!-- schema: device-live.response -->
```json
{
  "seq": 1235, "ts": 1792371601000, "online": true, "fresh": true, "slow_valid": true,
  "regs": {"40002": 0, "40003": 0, "40004": 0, "40005": 1, "40006": 512, "40007": 0, "40008": 0,
           "40011": 42, "40012": 230, "40013": 500, "40014": 10, "40015": 10, "40016": 50, "40017": 50,
           "40018": 5, "40019": 5, "40020": 1, "40021": -5, "40022": 0, "40027": 300, "40028": 49,
           "40029": 599, "40030": 99, "40036": 235, "40037": 480, "40053": 0, "40054": 0, "40059": 5000},
  "coils": 2051,
  "derived": {"temp": 23.5, "hum": 48.0, "current": 4.2, "running": true,
              "stages": {"cool": 1, "heat": 0, "hum": 0, "dehum": 0}, "mode": ["cool"], "delay_s": 0}
}
```

**PUT /devices/{d}/registers/{addr}** (operator, CSRF) — write one holding register (FC06). Body is
either `{"value": <scaled number>}` or `{"raw": <int>}`. The firmware validates (range or disabled
sentinel, read-only, online & fresh (see Freshness below), running interlock for 40021/40022/≥40027), queues, writes,
reads back, and waits up to 1.5 s:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"state":"applied","cmd","addr","raw"}` | written and verified (`raw` read back) |
| 202 | `{"state":"pending","cmd","addr"}` | still queued/in progress after 1.5 s → poll `GET /devices/{d}/commands/{cmd}` or watch WS `write` |
| 202 | `{"state":"uncertain","cmd","addr","reason"}` | sent, but no reply (`no_ack`) or read-back differs (`verify_mismatch`, `raw` = read-back) |
| 409 | `{"error":"rejected","state":"rejected","cmd","addr","reason"}` | `range` `readonly` `running_interlock` `offline` `cancelled` `exception:N`; `cmd` 0 if rejected before queueing |
| 404 | error `not_found` | unknown device or address not in the register map (`unknown_register`) |
| 503 | error `busy` | write queue (8) full |

`raw` in results is the register word read back (§1 Numbers); for 40005 the request is `{"raw":0|1}`
(or `/run`) while the result `raw` is the full word including the delay byte.

Freshness: a write is only *sent* with data younger than 3 s (the published snapshot, or the fast
register group re-read in the same poll cycle). At enqueue the snapshot must be younger than
max(3 s, `poll_ms` + 3 s) — the longer window applies only when `poll_ms` > 3000 and the device's
last cycle succeeded — otherwise 409 `offline`. Live `fresh` (REST, SNMP `mexStatusValid`) uses
the same max(3 s, `poll_ms` + 3 s) window. WS `snap` frames carry only `on`, not `fresh`; the UI
derives staleness from `poll_ms` (`GET /config/modbus`) and the frame arrival time.

A value not representable at the register scale (e.g. 23.45 for ×10) is `rejected`/`range` (cmd 0,
body exactly `{"error","state","cmd","addr","reason"}`). It is a malformed request that never
reaches the Modbus service, so — like 400/404/422 answers — it is neither audited nor broadcast.
Every other write attempt is audited (`reg_write`, old → new) and broadcast as WS `write`,
including rejections before queueing (`cmd` 0) and a full queue.

<!-- schema: register-write.request -->
```json
{"value": 23.5}
```
<!-- schema: register-write.request -->
```json
{"raw": 235}
```
<!-- schema: write-result.response -->
```json
{"state": "applied", "cmd": 17, "addr": 40012, "raw": 235}
```
<!-- schema: write-result.response -->
```json
{"state": "pending", "cmd": 18, "addr": 40012}
```
<!-- schema: write-result.response -->
```json
{"error": "rejected", "state": "rejected", "cmd": 0, "addr": 40021, "reason": "running_interlock"}
```
<!-- schema: write-result.response -->
```json
{"error": "rejected", "state": "rejected", "cmd": 19, "addr": 40012, "reason": "exception:3"}
```

**POST /devices/{d}/run** (operator, CSRF) — run/stop (40005 bit 0) with the same outcomes.
The UI asks for confirmation first.

<!-- schema: device-run.request -->
```json
{"run": false}
```

**GET /devices/{d}/commands/{id}** (operator) — one of the last 16 commands; 404 when evicted.
`reason` is `null` for applied/pending.

<!-- schema: command.response -->
```json
{"cmd": 18, "dev": 0, "addr": 40012, "state": "applied", "raw": 235, "requested": 235, "reason": null, "ts": 1792371602000}
```

### 4.5 Statistics

**GET /devices/{d}/stats** (viewer), **POST /devices/{d}/stats/reset** (admin, CSRF → 204, audited).

<!-- schema: device-stats.response -->
```json
{"tx": 86400, "rx_ok": 86391, "crc": 2, "timeout": 7, "exception": 0, "malformed": 0,
 "rtt_ms": {"last": 41, "avg": 43, "max": 118}, "online_since": 1792285200000, "offline_count": 1, "cycles": 10790}
```

### 4.6 History

**GET /devices/{d}/history** (viewer). Query either `span=<s>` (relative: the last `span` seconds up to
now; works whether or not the wall clock is valid) or `from=<ms>&to=<ms>` (absolute; 400
`bad_request` while the wall clock is not valid), plus optional `res=<s>` (requested resolution) and
`stages=1`. The server picks `dt` = smallest allowed step ≥ `res` with ≤ 1500 points
(1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200 s); steps < 60 only within the last hour.
Channels `temp`, `hum`, `cur` (current), `st`/`sh` (set temperature/humidity) are raw ×10 integers;
`null` = gap (offline/no data). For `dt ≥ 60`, `ch` holds bucket averages and `min`/`max` hold the
extremes of `temp`, `hum`, `cur`. `t0` = wall time of the start of bucket 0, or `null` when the
gateway's clock is not valid; `t0_age_ms` = how long before the response bucket 0 started
(monotonic, always present), so point i is at `t0 + i*dt*1000`, or at
`now − t0_age_ms + i*dt*1000` on the client's own clock. With `stages=1` the response adds `stages`:
per bucket, the seconds in which at least one stage of each kind (`blower`, `cool`, `heat`, `hum`,
`dehum`) was running (0..`dt`, `null` = gap) — the dashboard activity strip and the run-hours of the
Trends page. 400 `bad_request` for missing/invalid parameters or span > 30 days.

Precision older than 48 h: the RAM rings cover the last 48 h at minute resolution. Older parts of a
query with `dt` a multiple of 600 s (7-day → 600, 30-day → 1800) are served from 10-minute rollups
(one per device and UTC day, kept in PSRAM), so in that part bucket edges are exact to 10 minutes
rather than to the minute (buckets aligned to 10 minutes are identical to a minute-exact answer).
Queries with `dt` = 300 s (2–5 day spans) still read the daily minute files.

<!-- schema: history.response -->
```json
{"t0": 1792371540000, "t0_age_ms": 4120, "dt": 1, "n": 4,
 "ch": {"temp": [235, 235, null, 236], "hum": [480, 481, null, 481], "cur": [42, 42, null, 41],
        "st": [230, 230, null, 230], "sh": [500, 500, null, 500]},
 "stages": {"blower": [1, 1, null, 1], "cool": [1, 1, null, 0], "heat": [0, 0, null, 0],
            "hum": [0, 0, null, 0], "dehum": [0, 0, null, 0]}}
```
<!-- schema: history.response -->
```json
{"t0": null, "t0_age_ms": 120500, "dt": 60, "n": 2,
 "ch": {"temp": [234, 235], "hum": [479, 480], "cur": [42, 41], "st": [230, 230], "sh": [500, 500]},
 "min": {"temp": [232, 233], "hum": [476, 478], "cur": [40, 40]},
 "max": {"temp": [236, 237], "hum": [482, 483], "cur": [44, 43]}}
```

**GET /devices/{d}/history.csv** — same query; `text/csv; charset=utf-8`, chunked, UTF-8 BOM,
`Content-Disposition: attachment; filename="mestio-d0-<from>-<to>.csv"`, `\r\n` line ends, values
scaled with one decimal, empty field = gap, time ISO 8601 UTC (`<from>`/`<to>` = epoch seconds).
While the wall clock is not valid the export answers 400 `bad_request` in both modes (rows could
not carry a time; the JSON `?span=` query still works). Header for `dt < 60`:
`time,temp,hum,current,set_temp,set_hum`; for `dt ≥ 60` additionally
`temp_min,temp_max,hum_min,hum_max,current_min,current_max`.

### 4.7 Alarms

**GET /alarms/active** (viewer) — sorted by severity desc, then `since` asc. `value` = raw of the
alarm's value register at raise (temperature alarms: ×10 temperature; pure bit alarms 1); for
`rule_*` alarms the raw of the rule's source register (`src`) at raise; for `comm_lost` 1.

<!-- schema: alarms-active.response -->
```json
[{"key": "0:high_temp", "dev": 0, "id": "high_temp", "code": 127, "sev": 2, "since": 1792371000000,
  "acked": true, "ack_by": "operator1", "ack_ts": 1792371100000, "value": 312},
 {"key": "0:comm_lost", "dev": 0, "id": "comm_lost", "code": 301, "sev": 2, "since": 1792371500000,
  "acked": false, "ack_by": null, "ack_ts": null, "value": 1}]
```

**POST /alarms/ack** (operator, CSRF) → 204. Keys that are not active are ignored (idempotent);
malformed keys → 422. Ack never clears an alarm.

<!-- schema: alarms-ack.request -->
```json
{"keys": ["0:high_temp"]}
```
<!-- schema: alarms-ack.request -->
```json
{"all": true}
```

**GET /alarms/history** (viewer) — newest first. Query: `before=<seq>` (page cursor, default newest),
`limit` (1–200, default 50), `dev`, `sev` (minimum). `next` = cursor for the following page, `null` at the end.

<!-- schema: alarms-history.response -->
```json
{"items": [
  {"seq": 912, "ts": 1792371100000, "dev": 0, "id": "high_temp", "code": 127, "type": "ack", "sev": 2, "value": 312, "user": "operator1"},
  {"seq": 911, "ts": 1792371000000, "dev": 0, "id": "high_temp", "code": 127, "type": "raise", "sev": 2, "value": 312, "user": null}
 ], "next": 911}
```

**GET /alarms/history.csv** — same filters, all matching records (≤ 8192), header
`seq,time,dev,id,code,type,sev,value,user`.

### 4.8 Configuration

All `GET /config/<section>` return the full section; `PUT` merges (§1) and returns the full section
(200). Validation failures → 422 `validation` with `field`/`code`. Config changes are audited and
broadcast internally (`GW_EVT_CONFIG_CHANGED`) and raise the SNMP `gwConfigChanged` trap.

**/config/general** (GET viewer, PUT admin)

<!-- schema: config-general.response -->
```json
{"site": "B동 전산실", "location": "Seoul", "contact": "facility@example.com", "lang": "ko"}
```
<!-- schema: config-general.request -->
```json
{"site": "Server room B"}
```

**/config/network** (admin). PUT applies **provisionally**: the new settings take effect after
`apply_in_s`; unless `POST /config/network/confirm` arrives within `confirm_within_s`, the previous
configuration is restored automatically. PUT → 202 `network-apply.response`; 423 `locked` while a
change is pending; 422 for invalid/overlapping settings (the Ethernet subnet must not overlap the
recovery AP subnet 192.168.150.0/24). `ap.psk` is write-only (8–63 printable ASCII) and part of the
provisional change: the AP uses it after `apply_in_s` and it is stored on confirm or discarded on
revert. The factory PSK is random per device (80 bits, `xxxx-xxxx-xxxx-xxxx`), printed on the serial
console at boot while unchanged, and never returned by the API (`psk_set` only); it survives factory
reset.
`POST /config/network/confirm` → 204, or 409 `conflict` when nothing awaits confirmation — also while
the change is still scheduled (before `apply_in_s` elapsed): reconnect on the new address first.

<!-- schema: config-network.response -->
```json
{"eth": {"mode": "static", "ip": "192.168.10.150", "mask": "255.255.255.0", "gw": "192.168.10.1", "dns1": "192.168.10.1", "dns2": ""},
 "hostname": "mestio-gw-3456",
 "ap": {"fallback": true, "ssid": "MESTIO-GW-3456", "psk_set": true, "channel": 6, "idle_min": 15, "fallback_after_s": 120},
 "provisional": null}
```
<!-- schema: config-network.request -->
```json
{"eth": {"mode": "static", "ip": "10.20.30.40", "mask": "255.255.255.0", "gw": "10.20.30.1"}, "ap": {"psk": "new-ap-secret-42"}}
```
<!-- schema: network-apply.response -->
```json
{"apply_in_s": 3, "confirm_within_s": 120}
```

**/config/modbus** (GET viewer, PUT admin). Devices are matched by `id`; `slave` unique among enabled
devices. Applied at the next poll cycle.

<!-- schema: config-modbus.response -->
```json
{"devices": [{"id": 0, "name": "MEX150", "slave": 1, "enabled": true}],
 "port": {"baud": 9600, "parity": "N", "stop": 1},
 "poll_ms": 1000, "timeout_ms": 300, "retries": 1, "gap_ms": 5, "offline_after": 3}
```
<!-- schema: config-modbus.request -->
```json
{"poll_ms": 2000, "devices": [{"id": 0, "name": "MEX150 #1", "slave": 1, "enabled": true}, {"id": 1, "name": "MEX150 #2", "slave": 2, "enabled": true}]}
```

**/config/rules** (GET viewer, PUT admin) — user threshold rules (max 8), evaluated every second.
`src`: `temp` (40036), `hum` (40037), `cur` (40011) or `reg:<addr>` (any readable register); `src` is
stored canonically, so `reg:40036`/`reg:40037`/`reg:40011` come back as `temp`/`hum`/`cur`. `thr` and
`hyst` are scaled values of the source register. `>`: raise when value > thr for `delay_s`, clear when
value ≤ thr − hyst (`<` mirrored). Alarm id `rule_<id>`. PUT replaces the list and returns it as GET
would (canonical `src`).

<!-- schema: config-rules -->
```json
[{"id": 1, "name": "Room too warm", "enabled": true, "dev": 0, "src": "temp", "op": ">", "thr": 28.0, "hyst": 1.0, "delay_s": 60, "sev": 2},
 {"id": 2, "name": "Overcurrent", "enabled": false, "dev": 0, "src": "cur", "op": ">", "thr": 15.0, "hyst": 0.5, "delay_s": 5, "sev": 3}]
```

**/config/alarms** (GET viewer, PUT admin) — debounce (consecutive polls) and severity overrides keyed
by alarm id (`/meta/alarms`); unknown ids and `rule_*` ids (their severities come from the rules) →
422 `validation` `unknown_field`. `sev_override` is a value, not a mergeable object: when present it
replaces the whole override set (`{}` removes every override, as in the request example below);
when absent the current overrides are kept.

<!-- schema: config-alarms.response -->
```json
{"debounce_raise": 2, "debounce_clear": 3, "sev_override": {"high_hum": 2}}
```
<!-- schema: config-alarms.request -->
```json
{"sev_override": {}}
```

**/config/snmp** (admin). Write-only: `ro`, `rw` (v1/v2c communities; `rw: ""` disables SET via
community), `v3.users[i].auth_pass`/`priv_pass` (8–64 bytes of UTF-8 without control characters; converted to localized keys, never
stored), `traps[i].community`. There is no default RO community: `ro` is empty and `v1`/`v2c` are
off at factory state, and enabling `v1` or `v2c` without a non-empty `ro` (stored or in the same PUT)
→ 422 `validation` `field:"ro"` `code:"required"`. `v3.users` always has exactly 2 slots (slot 0
default `gwmonitor` ro, slot 1 `gwadmin` rw); a v3 user works only when `enabled` and `keys_set`
(otherwise it is an unknown user; noAuthNoPriv access is never possible). v3 is always authPriv
HMAC-SHA-96 + AES-128. Traps are v1/v2c (v3 notifications are not supported) and go to each target's
`port`. A present `traps` array replaces the list; a target without `community` in the body keeps the
community stored for the same `host`+`port` before the change, and a new or changed target gets the
default trap community (`community_set:false`), so a community never follows another host.
`auth_traps` sends authenticationFailure to every enabled target. PUT with passphrases takes up to
~1 s. SNMP runs only if `enabled` and `config/security services.snmp` are both true.

<!-- schema: config-snmp.response -->
```json
{"enabled": true, "v1": false, "v2c": true, "ro_set": true, "rw_set": false, "auth_traps": false,
 "v3": {"enabled": true, "users": [
   {"name": "gwmonitor", "access": "ro", "enabled": true, "auth": "sha", "priv": "aes", "keys_set": true},
   {"name": "gwadmin", "access": "rw", "enabled": true, "auth": "sha", "priv": "aes", "keys_set": false}]},
 "traps": [{"host": "192.168.10.20", "port": 162, "version": "v2c", "inform": false, "community_set": true, "enabled": true}],
 "sys": {"name": "mestio-gw-3456", "contact": "facility@example.com", "location": "B동 전산실"}}
```
<!-- schema: config-snmp.request -->
```json
{"enabled": true, "rw": "",
 "v3": {"users": [{"name": "gwmonitor", "access": "ro", "enabled": true, "auth_pass": "monitor-pass-1", "priv_pass": "monitor-priv-1"},
                  {"name": "gwadmin", "access": "rw", "enabled": false}]},
 "traps": [{"host": "192.168.10.20", "port": 162, "version": "v2c", "inform": true, "enabled": true, "community": "nms-trap"}]}
```

**GET /snmp/mib** (viewer) — `MESTIO-GW-MIB` text (`text/plain; charset=utf-8`,
`Content-Encoding: gzip`, attachment `MESTIO-GW-MIB.txt`).

**POST /snmp/test-trap** (admin, CSRF) — sends `gwTestNotification` to every enabled target; waits for
inform acknowledgements (≤ 5 s; an acknowledgement is accepted from the target with its trap
community even when v2c polling is off or the target is outside the IP allowlist). 409 `conflict` if
SNMP is disabled or no target is enabled.

<!-- schema: snmp-test-trap.response -->
```json
{"sent": [{"host": "192.168.10.20", "ok": true}]}
```

**/config/time** (GET viewer, PUT admin) — `tz` is a POSIX TZ string (default `KST-9`).

<!-- schema: config-time.response -->
```json
{"ntp": {"enabled": false, "servers": ["pool.ntp.org", "time.google.com"], "interval_min": 60}, "tz": "KST-9"}
```
<!-- schema: config-time.request -->
```json
{"ntp": {"enabled": true}}
```

**POST /time** (admin, CSRF) → 204. Sets the system clock and the RTC (browser sync). Rejected (422)
before 2024-01-01.

<!-- schema: time-set.request -->
```json
{"epoch_ms": 1792371600000}
```

**/config/security** (admin). `ip_allow`: up to 8 CIDRs (empty = allow all; the recovery AP is always
exempt). A list that would exclude the requesting client (not via AP) → 422 `validation`
`field:"ip_allow"`, `code:"lockout"`. `services.*` are master switches for SNMP and syslog.

<!-- schema: config-security.response -->
```json
{"idle_min": 15, "lockout": {"max_fail": 5, "lock_min": 5}, "ip_allow": ["192.168.10.0/24"], "services": {"snmp": true, "syslog": true}}
```
<!-- schema: config-security.request -->
```json
{"idle_min": 30, "ip_allow": []}
```

**/config/notify** (admin) — syslog (RFC 5424 over UDP). `min_sev` is a syslog severity 0–7: messages
with severity ≤ `min_sev` are sent (alarms: critical→2, major→3, minor→4, info/clear/ack→5; audit→5).

<!-- schema: config-notify.response -->
```json
{"syslog": {"enabled": false, "host": "", "port": 514, "facility": 16, "min_sev": 5}}
```
<!-- schema: config-notify.request -->
```json
{"syslog": {"enabled": true, "host": "192.168.10.20"}}
```

### 4.9 Users (admin)

Max 4 accounts. Names `^[a-z][a-z0-9_.-]{0,10}$`. Creating a user or setting another user's
password applies the policy (`422 policy`) and usually sets `must_change`. Changing a user's role or
password revokes that user's sessions. 409 `exists` / `limit` / `last_admin` / `self` (an admin
cannot delete itself or change its own role). PBKDF2 makes create/password updates take ≈0.1–0.4 s.

<!-- schema: users.response -->
```json
[{"name": "admin", "role": "admin", "must_change": false, "changed": 1792285200000},
 {"name": "operator1", "role": "operator", "must_change": true, "changed": null}]
```
<!-- schema: user-create.request -->
```json
{"name": "operator1", "role": "operator", "password": "Temp-Start#2026", "must_change": true}
```
<!-- schema: user-update.request -->
```json
{"role": "viewer"}
```
<!-- schema: user.response -->
```json
{"name": "operator1", "role": "viewer", "must_change": true, "changed": null}
```

### 4.10 Firmware

**GET /system/firmware** (admin)

<!-- schema: firmware.response -->
```json
{"running": {"slot": "ota_0", "version": "1.0.0", "state": "valid"}, "other": {"slot": "ota_1", "version": "0.9.2", "valid": true}}
```

**POST /system/firmware** (admin, CSRF) — `Content-Type: application/octet-stream`, `Content-Length`
required (≤ 3 MB), header `X-Firmware-SHA256: <64 hex>` (computed by the browser). Optional
`?allow_downgrade=1`. The image is hashed while written; on success the boot slot is switched and
the device reboots after 2 s into `pending_verify`; the supervisor marks it valid after 60 s of
healthy operation, otherwise the bootloader rolls back. Errors: 400 (missing header/length), 413,
422 `hash_mismatch`, 422 `image_invalid` (not a `mestio_gw` image, corrupt, or downgrade without
`allow_downgrade`), 423 `locked` (upload already running or a reboot pending; also while the
running image is still `pending_verify` after an update — "firmware still being validated, retry
shortly", ≤ 60 s after a healthy boot).

<!-- schema: firmware-upload.response -->
```json
{"version": "1.0.1", "reboot_in_s": 2}
```

**POST /system/firmware/rollback** (admin, CSRF) → 202, reboot into the other slot; 404 if it holds no valid image.

<!-- schema: reboot.response -->
```json
{"reboot_in_s": 2}
```

### 4.11 Backup / restore

**GET /system/config/export** (admin) — `config-bundle` (the `gateway.json` shape plus `fw`),
attachment `mestio-gw-config-<hostname>-<rev>.json`. Never contains secrets (passwords, PSK,
communities, SNMP keys).

<!-- schema: config-bundle -->
```json
{"schema": 1, "rev": 42, "fw": "1.0.0",
 "general": {"site": "Server room B", "location": "Seoul", "contact": "", "lang": "ko"},
 "network": {"eth": {"mode": "static", "ip": "192.168.10.150", "mask": "255.255.255.0", "gw": "192.168.10.1", "dns1": "192.168.10.1", "dns2": ""},
             "hostname": "mestio-gw-3456",
             "ap": {"fallback": true, "ssid": "MESTIO-GW-3456", "channel": 6, "idle_min": 15, "fallback_after_s": 120}},
 "modbus": {"devices": [{"id": 0, "name": "MEX150", "slave": 1, "enabled": true}], "port": {"baud": 9600, "parity": "N", "stop": 1},
            "poll_ms": 1000, "timeout_ms": 300, "retries": 1, "gap_ms": 5, "offline_after": 3},
 "alarms": {"debounce_raise": 2, "debounce_clear": 3, "sev_override": {}, "rules": []},
 "snmp": {"enabled": false, "v1": false, "v2c": false, "auth_traps": false,
          "v3": {"enabled": true, "users": [{"name": "gwmonitor", "access": "ro", "enabled": true}, {"name": "gwadmin", "access": "rw", "enabled": true}]},
          "traps": [], "sys": {"name": "", "contact": "", "location": ""}},
 "time": {"ntp": {"enabled": false, "servers": ["pool.ntp.org", "time.google.com"], "interval_min": 60}, "tz": "KST-9"},
 "security": {"idle_min": 15, "lockout": {"max_fail": 5, "lock_min": 5}, "ip_allow": [], "services": {"snmp": true, "syslog": true}},
 "notify": {"syslog": {"enabled": false, "host": "", "port": 514, "facility": 16, "min_sev": 5}}}
```

**POST /system/config/import** (admin, CSRF, ≤ 32 KB) — body = bundle. Validated and migrated as a
whole (all-or-nothing, 422 on error, `unsupported_schema` for a newer schema). Missing members get
defaults; unknown members are ignored. The `network` section is applied only with
`?include_network=1`, and then provisionally (confirm within 120 s, response member `network`);
otherwise it is ignored. Secrets are untouched, except that trap communities are remapped by target
`host`+`port` exactly as for `PUT /config/snmp` (targets not present before get the default trap
community), and a bundle enabling `v1`/`v2c` while no RO community is stored → 422 `field:"snmp.ro"`.

<!-- schema: config-import.response -->
```json
{"rev": 43, "changed": ["general", "modbus", "alarms"], "network": null}
```

### 4.12 Reboot, factory reset, logs, core dump

**POST /system/reboot** (admin, CSRF) → 202 `{"reboot_in_s":2}`; WS clients get `bye` `reboot`.

**POST /system/factory-reset** (admin, CSRF) — requires the admin's password and `confirm:"RESET"`.
Deletes configuration and secrets (and logs/history unless `keep_network`), restores defaults
including `admin`/`mestio150!` (must change), and reboots. The factory AP PSK is kept. 422
`wrong_password` (`field:"password"`, rate-limited like login, 429) / `validation`.

<!-- schema: factory-reset.request -->
```json
{"password": "Plant-Room#2026", "confirm": "RESET", "keep_network": true}
```

**GET /system/logs** (admin) — `kind=audit|system` (system = event log), `before=<seq>`, `limit`
(1–200, default 50); newest first. `type` names (extensible): `alarm_raise` `alarm_clear` `alarm_ack`
`comm_lost` `comm_restored` `boot` `time_set` `net_link` `ap` `ota` `reboot` `net_provisional`
`health` (system) and `login_ok` `login_fail` `lockout` `logout` `password` `user_add` `user_mod`
`user_del` `config_change` `reg_write` `ota_upload` `rollback` `reboot_req` `factory_reset`
`config_import` `time_sync` `alarm_ack_req` `stats_reset` `snmp_test` `user_target` (audit). An
account change by an admin is logged as a pair: the action record (`user_add` `user_mod` `user_del`,
or `password` with `extra` 1) carries the actor in `user`, and the `user_target` record that follows
it carries the affected account in `user`, the action's type number in `code`, its `value` and its
`seq` in `extra`. `code`/`value`/`extra` meanings per type are defined in
`components/store/include/store/eventlog.h`.

<!-- schema: logs.response -->
```json
{"kind": "audit", "items": [
  {"seq": 77, "ts": 1792371602000, "type": "reg_write", "dev": 0, "code": 40012, "sev": 0, "value": 235, "user": "operator1", "extra": 65766},
  {"seq": 76, "ts": 1792371500000, "type": "login_ok", "dev": null, "code": 0, "sev": 0, "value": 0, "user": "operator1", "extra": 3232238100}
 ], "next": 76}
```

**GET /system/coredump** (admin) — summary of the stored core dump (crashed task, PC, exception
cause/address, backtrace, image hash prefix), or 404 when none is stored. The full ELF core dump is
never served over HTTP: it holds RAM contents (password hashes, keys, session tokens, in-flight
secrets); read it over USB with `idf.py coredump-info`.

<!-- schema: coredump.response -->
```json
{"task": "httpd", "pc": 1074590724, "cause": 29, "vaddr": 0, "backtrace": [1074590724, 1074601234, 1074612345],
 "backtrace_corrupted": false, "app_sha256": "3f9a1c0d2"}
```

## 5. WebSocket `/ws`

Upgrade requires an allowed `Host` (§1.1, else 421), a valid session cookie (else 401), a session
without `must_change` (else 403) and, when `Origin` is present, `Origin` host = `Host` (else 403);
otherwise there is no upgrade. At most 4 clients (5th → 503). Text frames, one JSON object each
(`ws-server.schema.json` / `ws-client.schema.json`). The server pushes; **writes always go through REST**.
The session is re-checked continuously; on expiry/logout/revocation/reboot the server sends `bye`
and closes. A client that stops draining its socket never blocks the others: while it is not
writable it skips `snap`/`comm`/`sys` frames (it gets a `full` snapshot when it drains again), and it
is dropped without a close frame after 10 s of stall or when an `alarm`/`write` frame cannot be sent
(send timeout 1 s). Client frames > 256 bytes close the connection (1009); unknown client messages are ignored.

### 5.1 Client → server

| Message | Meaning |
|---|---|
| `{"t":"sub","topics":[...]}` | Replace the subscription set (`snap` `alarm` `comm` `write` `sys`; `[]` = none). Nothing but `hello`/`pong`/`bye` is sent before the first `sub`. |
| `{"t":"ping"}` | Server answers `pong` with its clock (clock offset / liveness). |

<!-- schema: ws-client -->
```json
{"t": "sub", "topics": ["snap", "alarm", "comm", "write", "sys"]}
```
<!-- schema: ws-client -->
```json
{"t": "ping"}
```

### 5.2 Server → client

New message types may be added within v1 (§1 Versioning); clients ignore unknown `t`.

| `t` | When | Members |
|---|---|---|
| `hello` | right after connect | `v` protocol (1), `srv` server time ms (`null` while the clock is not valid), `devs` enabled device indexes, `seq` latest snapshot seq per device, `meta` ETag of `/meta/registers`. On receipt the client backfills via `GET /devices/{d}/history?span=3600&res=1&stages=1` (relative, so it also works without valid time). |
| `snap` | ≤ 1 Hz per device on new poll data | `dev`, `seq`, `ts`, `on` (online), `full`, `r` (register raw values as in `live.regs`), `c` (coils). `full:true` for the first frame after subscribing and every 30 s (all registers + `c`); otherwise only changed registers and `c` only if changed. A gap in `seq` is harmless (frames are snapshots). |
| `alarm` | each raise/clear/ack | `dev`, `key`, `id`, `code`, `type`, `sev`, `ts`, `seq` (event-log seq), `value`, `user` (ack only) |
| `write` | each final write outcome (any origin: web, SNMP) | `dev`, `cmd`, `addr`, `state` (`applied`/`rejected`/`uncertain`), `raw`, `reason`, `by` (`@snmp` for SNMP) |
| `comm` | on online/offline change and every 5 s | `dev`, `online`, `rtt` (last ms), `err` (cumulative counters) |
| `sys` | every 10 s | `heap` (internal free), `heap_min`, `psram`, `up` (s), `time` (ms or null), `alarms` (active count) |
| `pong` | reply to `ping` | `srv` |
| `bye` | before the server closes | `reason`: `session_expired` `logout` `revoked` `reboot` |

<!-- schema: ws-server -->
```json
{"t": "hello", "v": 1, "srv": 1792371600000, "devs": [0], "seq": {"0": 1234}, "meta": "\"b1f3c2a9\""}
```
<!-- schema: ws-server -->
```json
{"t": "snap", "dev": 0, "seq": 1235, "ts": 1792371601000, "on": true, "full": false, "r": {"40036": 236}, "c": 2051}
```
<!-- schema: ws-server -->
```json
{"t": "alarm", "dev": 0, "key": "0:high_temp", "id": "high_temp", "code": 127, "type": "raise", "sev": 2, "ts": 1792371000000, "seq": 911, "value": 312}
```
<!-- schema: ws-server -->
```json
{"t": "write", "dev": 0, "cmd": 17, "addr": 40012, "state": "applied", "raw": 235, "by": "admin"}
```
<!-- schema: ws-server -->
```json
{"t": "comm", "dev": 0, "online": true, "rtt": 42, "err": {"crc": 2, "timeout": 7, "exception": 0, "malformed": 0}}
```
<!-- schema: ws-server -->
```json
{"t": "sys", "heap": 98304, "heap_min": 71680, "psram": 7340032, "up": 86400, "time": 1792371600000, "alarms": 2}
```
<!-- schema: ws-server -->
```json
{"t": "pong", "srv": 1792371600123}
```
<!-- schema: ws-server -->
```json
{"t": "bye", "reason": "session_expired"}
```

## 6. Contract tests

`tests/test_api_contract.py` (stream G/D) validates: every example in this file against its schema,
every schema against the 2020-12 meta-schema, and the mock server's responses for every endpoint.
The firmware's JSON output for the same endpoints is checked in Phase 2 against the same schemas.
