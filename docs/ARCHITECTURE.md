# MESTIO Gateway — Architecture

Companion to `DESIGN.md` (requirements/spec) and `API.md` (external contract). This document fixes
the internal structure every Phase 1 stream codes against: components and their dependencies,
tasks, data flows, threading/locking rules and memory placement. The frozen interfaces are the
public headers under `components/*/include/`; deviations from DESIGN.md are logged in
`DECISIONS.md`.

## 1. Components

```
                 +--------------------------------------------------------------+
                 |                          main/app_main.c                     |
                 +--------------------------------------------------------------+
                    |          |          |          |          |          |
   +-----------+ +--------+ +-------+ +---------+ +--------+ +---------+ +--------+
   |  sysmgr   | |  web   | | snmp_ | |   net   | | alarm  | |  auth   | | board  |
   | supervisor| | router | |  gw   | | eth/ap/ | | engine | | users/  | | rtc/led|
   | ota/reset | | api_*  | |modules| | sntp/   | | rules  | | session | | button |
   | syslog    | | ws_hub | | traps | | ipfilter| |        | | ratelim | | board_io
   +-----------+ +--------+ +-------+ +---------+ +--------+ +---------+ +--------+
        |  \         |  \       |  \        |          |  \        |          |
        |   \        |   \      |  snmp_lwip (lwIP SNMP subset, PSA v3 crypto,  |
        |    \       |    \     |   single-thread transport)                    |
        v     v      v     v    v           v          v   v       v          |
   +------------------------------------------------------------------------+   |
   |  store: fs, atomic_file, config(+json), secrets, history, eventlog,    |   |
   |         persist (the only flash writer)                                |   |
   +------------------------------------------------------------------------+   |
                 |                                                              |
   +--------------------------------------+                                     |
   | mex150: regmap.def, regmap, frame,   |                                     |
   | model, poll_plan, service (mex_poll) |                                     |
   +--------------------------------------+                                     |
                 |                                                              |
   +------------------------------------------------------------------------+   |
   | gw_core: gw_events (gw_evt loop), gw_crypto (PSA), gw_json_writer,      |<--+
   |          gw_ring, gw_time, gw_b64, gw_ip4, gw_ident, gw_defs, gw_err    |
   +------------------------------------------------------------------------+
```

Allowed dependencies (CMake `REQUIRES` for public headers, `PRIV_REQUIRES` otherwise); arrows point
down only, no cycles:

| Component | May depend on |
|---|---|
| gw_core | IDF only (esp_event, esp_timer, mbedtls/PSA); owns the heartbeat registry `gw_health.h` so every producer can beat without depending on sysmgr |
| mex150 | gw_core (public: regmap/frame/model/service/poll_plan headers are IDF-free); priv: esp_driver_uart, board (pins header only) |
| store | gw_core, mex150 (types only), cJSON (priv), joltwallet/littlefs (priv) |
| alarm | gw_core, mex150, store |
| auth | gw_core, store |
| board | gw_core; priv: esp_driver_i2c, esp_driver_gpio, led_strip |
| net | gw_core, store; priv: board (pins), esp_eth, espressif/w5500, esp_wifi, esp_netif |
| snmp_lwip | lwip (its header includes `esp_err.h` directly); priv: gw_core (password-to-key delegates to `gw_snmp_key_localize`), mbedtls |
| snmp_gw | gw_core, snmp_lwip, mex150, store, alarm, net |
| web | gw_core, mex150, store, alarm, auth, net, sysmgr, snmp_gw; esp_http_server, cJSON |
| sysmgr | gw_core; priv: store, board, net, alarm (LED severity, syslog names), mex150 (COMM_LOST LED, console status), app_update, esp_partition, espcoredump, console. Never web (web handles GW_EVT_REBOOT itself) |
| main | everything |

Each stream owns the `CMakeLists.txt` of its own components and may add edges that this table
allows; a new edge outside the table needs an ARCHITECTURE change first (no cycles).

Include convention: every public header is included as `"<component>/<file>.h"`
(`components/<c>/include/<c>/<file>.h`), except the two paths fixed by DESIGN.md:
`board_pins.h` (`components/board/include/board_pins.h`) and `snmp_transport.h`
(`components/snmp_lwip/include/snmp_transport.h`). X-macro tables are consumed only through
`mex150/regmap_x.h` and `alarm/alarm_x.h`.

### 1.1 Pure (host-testable) code

Headers that include no IDF header (they use `gw_core/gw_err.h`, which only includes `esp_err.h`
when `ESP_PLATFORM` is defined): everything except `gw_core/gw_events.h`, `web/router.h`,
`web/ws_hub.h` and `snmp_transport.h` (device-only, includes `esp_err.h`). Pure *implementations* (listed in `cmake/gw_host_sources.cmake`, compiled by both
the IDF build and `tests/`):

| Component | Pure sources (functions) |
|---|---|
| gw_core | gw_json_writer.c, gw_b64.c, gw_ip4.c, gw_ident.c, gw_time_civil.c (`gw_time_to_civil` … `gw_time_iso8601`; the [device] clock functions are in gw_time.c, not host-built), gw_crypto_util.c (`gw_hash_len`/`gw_ct_equal`/`gw_secure_zero`), gw_snmp_key.c (`gw_snmp_key_localize`); crypto backend `crypto_openssl.c` on host (`GW_HOST_ONLY_SOURCES`) |
| mex150 | regmap.c, frame.c, model.c, poll_plan.c |
| store | config.c pure part (`cfg_defaults`, `cfg_validate*`, `cfg_trap_remap`, `cfg_snmp_check_secrets`, section metadata), config_json.c, secrets JSON/validate/`sec_trap_remap`, history math (`hist_acc_*`, `hist_fast_from_snapshot`, `hist_pick_res`), atomic_file.c — cJSON comes from `GW_HOST_THIRD_PARTY_SOURCES` on the host |
| alarm | engine.c (`alm_*`), catalog |
| auth | password records, policy, rate limiter core, `auth_name_valid` |
| web | web_path.c |
| net | ip_filter.c (allowlist + `ip_filter_host_ok`) |
| snmp_lwip | header-only `snmp_lwip/snmpv3_util.h` (RFC 3826 IV/key helpers) and private `snmp_transport_util.h` (BER peek, per-datagram community mapping, trap-port substitution); snmpv3_psa.c is PSA-only, its key derivation is gw_snmp_key.c (host-tested with RFC 3414 A.3). `snmpv3_auth`/`snmpv3_crypt` get an on-target known-answer test (`snmpv3_selftest()`, debug builds) |

Host harness: `tests/conftest.py` offers `gwlib` (every list in one .so) and `host_lib('STORE', …)`
(GW_CORE + the named lists only), so one stream's compile error does not break another stream's tests.

## 2. Tasks

| Task | Prio | Stack | Core | Owner | Responsibilities |
|---|---|---|---|---|---|
| tcpip (lwIP) | 18 | 4096 | 0 | IDF | TCP/IP |
| w5500 rx | 15 | 4096 | 0 | IDF/w5500 | Ethernet RX |
| mex_poll | 10 | 4096 | 1 | mex150 | owns UART1; polls, executes write queue between blocks; posts SNAPSHOT/COMM/WRITE_RESULT; TWDT; heartbeat MEX |
| gw_evt | 7 | 6144 | 1 | gw_core | esp_event's own loop task; runs every gw_events handler: alarm engine, 1 Hz history sampling + rule evaluation, WS frame building, SNMP trap enqueue, event-log glue, main's MODBUS reconfigure; never touches flash |
| httpd | 5 | 8192 | 0 | web | REST handlers, WS sockets, static assets, OTA upload (RAW_BODY: other HTTP/WS traffic waits for the upload's duration) |
| httpd_login | 5 | 6144 | 0 | web | public `WEB_RF_SLOW` route: POST /auth/login (PBKDF2 + global delay); ≤ 4 admitted jobs |
| httpd_async | 5 | 6144 | 0 | web | authenticated `WEB_RF_SLOW` routes: password change, user create/update, factory reset, PUT /config/snmp (key localization), test trap, register write and run/stop (wait ≤ 1.5 s); ≤ 4 admitted jobs, full → 503 `busy` |
| snmp_agent | 4 | 6144 | 0 | snmp_lwip | all lwIP SNMP calls; request handling; trap/inform queue |
| sys_reboot | 4 | 3072 | any | sysmgr | transient: waits the reboot delay, history flush request, `persist_flush(3000)`, `esp_restart()` |
| net_mgr | 3 | 4096 | 0 | net | every esp_netif/esp_wifi/SNTP reconfiguration; 1 s timers (provisional apply/revert, AP fallback, AP idle stop); beats the required `GW_HB_NET` every loop (≤ 1 s) |
| persist | 3 | 4096 | 1 | store | every LittleFS write (config, secrets, logs, history); TWDT |
| supervisor | 2 | 3584 | 1 | sysmgr | heartbeats, mark-valid, LED state, button gestures, RTC write on time sync, syslog service (DNS, audit queue drain) |
| console | 1 | 4096 | any | sysmgr | USB-Serial-JTAG REPL |
| esp_timer | 22 (IDF) | 4096 | 0 | IDF | 1 Hz SYS_TICK post, button debounce timer callbacks (non-blocking only) |
| sys_evt, Tmr Svc, ipc0/1, IDLE0/1, wifi | IDF | 4096, 3072, 1280×2, 1536×2, ≈ 6.5 K | — | IDF | default event loop (esp_netif/eth/wifi events), FreeRTOS timers, IPC, idle; `wifi` exists only while the AP is up (`net_wifi_ap_stop()` calls `esp_wifi_deinit()`, so the task, its stack and the driver RAM are released; the next AP start re-creates them) |
| syslog | — | — | — | sysmgr | no own task: messages are sent from the gw_evt handler via non-blocking UDP `sendto` (drop on EAGAIN); AUDIT records without an event (login_fail, lockout, password, user_*, config_import, factory_reset) reach it through the evlog append hook and are sent by the supervisor's `syslog_service()` (≤ 1 s later) |

Heartbeats (`gw_hb_beat()`, `gw_core/gw_health.h`, lock-free atomics), each beaten by its producer:
MEX (mex_poll loop), EVT (gw_core's own SYS_TICK handler), PERSIST (persist loop ≤ 1 s), HTTPD (web's
2 s esp_timer queues a no-op `httpd_queue_work` that beats), NET (net_mgr loop ≤ 1 s), SNMP (snmp_gw
on_idle, `GW_HB_WATCHED_MASK`: stale for 10 s while SNMP runs → FAULT LED + EVT_HEALTH, never a reboot).
The supervisor only reads `gw_hb_stale_mask()`; image marked valid after 60 s with
`GW_HB_REQUIRED_MASK` (MEX/EVT/PERSIST/HTTPD/NET) fresh and no FS/STORE/NET/WEB/CORE init fault (§4.6).

## 3. Init order (app_main)

0. arm the 120 s one-shot boot watchdog (esp_timer → `esp_restart()`; disarmed after step 14), so a
   new image that hangs in init (W5500, LittleFS format, PBKDF2, httpd) restarts and rolls back
1. log version; note `ESP_OTA_IMG_PENDING_VERIFY`
2. `nvs_flash_init` (erase+retry), increment `GW_NVS_KEY_BOOTS` in NVS `GW_NVS_NS_BOOTS` = `gw_fact`
   (gw_defs.h; survives factory reset so snmpEngineBoots never decreases; a legacy `gw/boots` is merged)
3. `gw_crypto_init()`, `board_init()` (RTC → system time; LED boot; buzzer low; button)
4. `fs_mount(FS_BASE, FS_PARTITION_LABEL)`
5. `cfg_set_alarm_catalog(&alm_cfg_catalog)`, `config_load()`, `secrets_load()` (factory AP PSK from NVS `gw_fact`)
6. `gw_events_init()`
7. `eventlog_init()`, `history_init()`, `persist_start()`
8. `alarm_init()`
9. `esp_netif_init()` (fatal on failure, like the event loop; lwIP/tcpip must exist before any web,
   SNMP or syslog socket even when net_init fails early), then `net_init()` (calls it again first,
   idempotent)
10. `mex_service_start()` (from `cfg_modbus_t`), then main's CONFIG_CHANGED{MODBUS} handler
11. `auth_init()` (creates factory admin if no users), `web_start()`
12. `snmp_gw_start()`
13. `syslog_init()`, `console_start()`
14. `supervisor_start()`

Failure policy (main/app_main.c): only `gw_events_init()` failing is fatal (FAULT LED, restart after
10 s; a PENDING_VERIFY image then rolls back). Every other failure is logged, latched with
`sys_init_fault_set(SYS_INIT_FAULT_*)` (FAULT LED at once, also during the boot grace; exposed as
`GET /system/info` `diag.init_faults`) and the boot continues: a failed LittleFS mount runs on RAM
defaults (stores load defaults, persist writes fail and are retried/logged, nothing survives a
reboot); a failed `mex_service_start()` is retried on the next CONFIG_CHANGED{MODBUS}; SNMP, syslog,
console and the AP are optional; web starts even if `auth_init()` failed. A subsystem whose
heartbeat never becomes fresh is handled by the supervisor (bounded health reboots / rollback).

## 4. Data flows

### 4.1 Poll → snapshot → consumers

```
mex_poll ──(blocks via UART1)──> assemble snapshot ──lock──> state[dev]
   │                                                         ▲
   └─ gw_events_post(SNAPSHOT{dev,seq}, timeout 0) ──> gw_evt │ mex_service_snapshot(dev) (copy)
                                                        │
          ┌─────────────────────────────────────────────┼───────────────────────────┐
          v                                             v                           v
  alarm: alm_engine_feed_snapshot()          web/ws: build "snap" frame       snmp_gw: nothing per
   → transitions → evlog_append(EVENTS)        (delta vs last sent, full       snapshot (MIB GETs read
   → GW_EVT_ALARM ─> ws "alarm" frame,          every 30 s / on subscribe)      mex_service_snapshot
                     snmp trap enqueue,       → ws_hub_broadcast(WS_T_SNAP)    on demand)
                     syslog, LED (supervisor)
SYS_TICK (1 Hz) ──> gw_evt: gw_core beats EVT; alarm service: alm_engine_tick_rules() then
                    history_sample(dev, snapshot, fresh, alarm_mask(dev) != 0) for EVERY dev index;
                    ws "comm" (5 s) / "sys" (10 s)
history: fast ring (1 s) → minute accumulator → slow ring → every 10 minutes persist_mark_dirty(HISTORY)
         → persist task appends /data/hist/d<dev>/YYYYMMDD.bin
```

COMM transitions: `mex_poll` posts `GW_EVT_COMM` for enabled devices — the first decision after
boot/reconfigure (also `online=false` for a device that never answered) and every later change
(rules in gw_events.h) → alarm `comm_lost` raise/clear (device alarms frozen while offline) →
eventlog glue logs `comm_lost/restored` → ws `comm` → snmp `gwCommLost/Restored` (coalesced).
Disabled devices produce no COMM; on CONFIG_CHANGED{MODBUS} the alarm service calls
`alm_engine_set_enabled()` (clears a disabled device's alarms).

### 4.2 REST write → service queue → verify → event

```
httpd: PUT /devices/0/registers/40012 {"value":23.5}
  router: session, role >= operator, CSRF, body → handler
  handler: mex_reg_find → mex_reg_from_value → mex_service_write(dev, addr, raw, user, 1500 ms, &res)
     mex_service_write: mex_check_write(addr, raw, fresh, running)  -- reject now (cmd 0) or
                        enqueue (depth 8, cmd id) and wait on a per-command semaphore ≤ wait_ms
mex_poll (between blocks): dequeue → re-validate with the newest snapshot → FC06 → read-back
     → slow group re-read in the same cycle → publish snapshot → final state:
        exception → REJECTED(exception:N) | read-back == requested → APPLIED | else UNCERTAIN
     → record in command history (16) → wake waiter → GW_EVT_WRITE_RESULT
gw_evt: eventlog glue → AUDIT reg_write (old → new); ws "write" frame; snmp gwLastWriteResult
httpd: 200 applied / 202 pending|uncertain / 409 rejected (API.md §4.4)
```
SNMP SET (`mib_mex_setpoint`): `set_test` → `snmp_ctx_can_write()` + `mex_check_write()`;
`set_value` → `mex_service_write(..., "@snmp", 1000 ms)`; REJECTED → `commitFailed`; UNCERTAIN or
timeout → `noError` (result visible in `gwLastWriteResult` and the audit log).

### 4.3 Configuration change

```
httpd PUT /config/<s> → cfg_get(&cur) → cfg_section_from_json(s, body, &cur, &sec, &secret_in)
  → (secrets present) secrets_modify(...)   [SNMP passphrases: snmp_gw_localize_key first]
  → cfg_commit(s, &sec, size, user, &err)   validate (cross-section) → swap under mutex → rev++
       → persist_mark_dirty(CONFIG) → gw_events_post(CONFIG_CHANGED{s, rev, user})
gw_evt consumers of CONFIG_CHANGED:
  eventlog glue (audit config_change) · alarm (ALARMS → alm_engine_set_params, MODBUS →
  alm_engine_set_enabled) · auth (SECURITY → lockout/idle params) · net (TIME → gw_time_set_tz +
  SNTP, SECURITY → allowlist, SECRETS → AP PSK) ·
  snmp_gw (SNMP/SECURITY/GENERAL/SECRETS → snmp_gw_apply_config → agent task; trap gwConfigChanged) ·
  sysmgr syslog (NOTIFY/SECURITY) · mex150 is reconfigured by the MODBUS handler registered in
  main (calls mex_service_reconfigure with the new section)
persist task: cfg_snapshot_json → atomic_write(FS_PATH_CONFIG)
```
Network is the exception (provisional): `PUT /config/network` → `cfg_validate_with` →
`net_apply_provisional(cand, ap_psk)` → 202; `POST /config/network/confirm` → `net_confirm()` →
`cfg_commit(NETWORK)` (+ `secrets_modify` for a new AP PSK). `net` ignores `CONFIG_CHANGED{NETWORK}`;
timeout → revert (PSK too), `NET_STATE` event.

SNMP trap list replacement (`PUT /config/snmp`, config import): `cfg_section_from_json` / the import
handler compute `cfg_trap_remap(old, new)`; the handler runs `cfg_snmp_check_secrets()`, then
`secrets_modify(sec_trap_remap …)` and `cfg_commit(SNMP)`, so a community stays with its host:port.

### 4.4 Sessions and WebSocket lifetime

login → `auth_login` → session slot (SHA-256(token) only) → cookie. Every REST request →
`auth_session_lookup(touch)`. Expiry/logout/revocation → `GW_EVT_SESSION{kind,sid}` → gw_evt
handler in web → `ws_hub_close_session(sid, reason)` → `bye` + close. The hub additionally re-checks
`auth_session_check(sid)` for each client before sending a broadcast frame.

### 4.5 Time

Boot: RTC → `gw_time_set_wall_ms(RTC)` (event skipped, loop not yet running). NTP (net/sntp
callback), browser (`POST /time`), console → `gw_time_set_wall_ms(src)` → `GW_EVT_TIME_SYNC` →
sysmgr writes the RTC (source ≠ RTC) · eventlog `time_set` · history starts writing files once valid.

### 4.6 Firmware update

httpd (RAW_BODY route) → `sys_ota_begin` → `sys_ota_write` per chunk (hash + `esp_ota_write`) →
`sys_ota_end` (hash compare, app desc checks, set boot) → `GW_EVT_OTA{DONE}` →
`sys_reboot(OTA, 2000)` → `GW_EVT_REBOOT` (web's ws_hub handler: bye "reboot"; history flush
request; sysmgr never calls web) → `persist_flush` → restart → boot in PENDING_VERIFY (`GW_EVT_OTA{PENDING}`) → supervisor after 60 s
healthy → mark valid → `GW_EVT_OTA{VALIDATED}` → SNMP `gwFirmwareUpdated`.

Mark-valid rule: `GW_HB_REQUIRED_MASK` fresh AND none of the init faults FS, STORE, NET, WEB, CORE
latched (`sys_init_fault_*`). SNMP/SYSLOG faults (optional services) and MODBUS (retried; its heartbeat
already gates) do not block. A blocked image is never marked valid, so `SYS_PENDING_VERIFY_LIMIT_MS`
reboots it and the bootloader returns to the previous image. A hang before `supervisor_start()` is
caught by the 120 s boot watchdog (§3 step 0).

## 5. Threading and locking rules

1. **Flash writes only in `persist`.** Other tasks call `persist_mark_dirty()` / `persist_submit()`.
   Reads (config load at boot, history/log queries in httpd/snmp) are allowed anywhere except gw_evt.
2. **gw_evt handlers** are short (< 10 ms), never block on sockets, flash, the UART or another
   task's response; they post events with timeout 0 and use non-blocking hand-offs
   (`ws_hub_broadcast`, `snmp_transport_post`, `evlog_append`, `persist_mark_dirty`).
3. **lwIP SNMP API only in `snmp_agent`.** Other tasks use `snmp_gw_*` / `snmp_transport_post`.
4. **UART1 only in `mex_poll`.** Everyone else uses `mex_service_*` (copies).
5. **httpd socket I/O only in the httpd task** (`httpd_queue_work` from other tasks; WS broadcast
   is queued work).
6. **Copies, not pointers:** config, secrets, snapshots, stats, alarm lists, session info are
   returned by value into caller buffers. No API returns a pointer into a locked structure except
   the immutable const tables (`mex_regs`, `alm_catalog`, …).
7. **Locks are leaf locks.** Each module has one mutex (config, secrets, mex state, alarm engine,
   history rings, auth sessions/rate limiter, eventlog RAM tail, ws client table, net state). A
   module never calls another module's API while holding its own lock, except `gw_events_post(...,
   0)`, `persist_mark_dirty()` and `evlog_append()` which are lock-free/non-blocking. This makes
   deadlock impossible by construction.
8. **Callable-from matrix** (✓ allowed, — not allowed):

| API group | ISR | esp_timer cb | gw_evt | mex_poll | httpd / async | snmp_agent | persist | supervisor/console |
|---|---|---|---|---|---|---|---|---|
| gw_events_post | — | ✓ (0 ms) | ✓ (0 ms) | ✓ (0 ms) | ✓ | ✓ | ✓ | ✓ |
| mex_service_snapshot/stats/command | — | — | ✓ | — | ✓ | ✓ | — | ✓ |
| mex_service_write | — | — | — | — | ✓ | ✓ | — | ✓ |
| cfg_get*, secrets_get | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| cfg_commit*, secrets_modify | — | — | — | — | ✓ | ✓ | — | ✓ |
| evlog_append / evlog_event / evlog_audit | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| evlog_query, history_query*/foreach* | — | — | — | — | ✓ | ✓ | — | ✓ |
| history_sample | — | — | ✓ only | — | — | — | — | — |
| alarm_get_active/ack/counts/mask | — | — | ✓ | — | ✓ | ✓ | — | ✓ |
| auth_* (PBKDF2 ones on async worker) | — | — | session_check only | — | ✓ | — | — | ✓ |
| ws_hub_broadcast / close_session | — | — | ✓ | — | ✓ | — | — | ✓ |
| snmp_transport_post, snmp_gw_trap_* | — | — | ✓ | — | ✓ | ✓ | — | ✓ |
| snmp_ctx_*, snmp_registry_start | — | — | — | — | — | ✓ only | — | — |
| net_* status/allowed | — | — | ✓ | — | ✓ | ✓ | — | ✓ |
| board_led_set | — | ✓ | ✓ | — | ✓ | — | — | ✓ |
| board_rtc_* | — | — | — | — | ✓ | — | — | ✓ |
| gw_hb_beat / gw_hb_stale_mask | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| sys_ota_*, sys_reboot, sys_factory_reset | — | — | — | — | ✓ | — | — | ✓ |
| config_/secrets_/evlog_/history_factory_reset | — | — | — | — | ✓ | — | — | ✓ |
| persist_mark_dirty / submit | — | — | ✓ | ✓ | ✓ | ✓ | ✓ (mark) | ✓ |
| persist_flush | — | — | — | — | ✓ | — | — | ✓ |

## 6. Memory placement

8 MB octal PSRAM (`SPIRAM_USE_MALLOC`, `MALLOC_ALWAYSINTERNAL=4096`, 64 KB reserved internal).
Gate: `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) > 60 KB` with AP up, 4 WS clients and
an SNMP walk (Phase 2).

| Data | Size | Placement | How |
|---|---|---|---|
| History fast ring | 4 dev × 3600 × 24 B = 338 KB | PSRAM | `heap_caps_malloc(MALLOC_CAP_SPIRAM)` at `history_init` |
| History slow ring | 4 × 2880 × 40 B = 461 KB | PSRAM | same |
| History day rollups (> 48 h) | ≤ 4 dev × 32 days × ≈ 6.3 KB ≈ 0.8 MB | PSRAM | one `hist_day_t` (144 × 10-min aggregates) per device and UTC day, built once from the day file (lazy + warm-up job 60 s after boot), kept current by the history writer |
| Task-only statics (`EXT_RAM_BSS_ATTR`) | 35 076 B ext .bss (incl. IDF Wi-Fi/lwIP .bss) | PSRAM | alarm `s_eng`, evlog `s_log` + writer scratch, history writer scratch, SNMP `s_inf`/`s_vb`, WS `s_snap`, console log buffer; none touched from ISRs or with the cache disabled |
| History query arrays | ≤ 11 × 1500 × 2 B = 33 KB | PSRAM | per request (httpd), freed after reply |
| WS frame pool | 8 × 4 KB | PSRAM | ref-counted buffers |
| JSON response buffers | > 4 KB | PSRAM | `malloc` threshold; small ones internal |
| Config import body (32 KB), cJSON trees of large bodies | ≤ 64 KB | PSRAM | `cJSON_InitHooks` with PSRAM-preferring malloc in web/store |
| OTA chunk buffer | 4 KB | internal | `esp_ota_write` source |
| Task stacks | ≈ 76 KB (+ 6.5 KB `wifi` once the AP ran) | internal (candidates for PSRAM: §6.2) | `xTaskCreatePinnedToCore`; a stack must be internal only for a task that writes/erases flash (§6.2); see §6.1 |
| gw_config_t (+ scratch copy) | ≈ 2 × 2 KB | internal | static |
| gw_secrets_t (+ scratch) | ≈ 2 × 1 KB | internal | static; wiped scratch |
| Alarm engine | ≈ 5.2 KB | PSRAM | static `alm_engine_t`, `EXT_RAM_BSS_ATTR` |
| Session table + rate limiter | < 2 KB | internal | static |
| Event queue | 32 × 64 B | internal | esp_event |
| Eventlog RAM tails | 2 × 64 × 32 B = 4 KB | PSRAM | static, `EXT_RAM_BSS_ATTR` |
| Persist queue | 16 × 8 B | internal | FreeRTOS queue |
| SNMP trap queue | 16 × 96 B | internal | FreeRTOS queue |
| lwIP pbufs, Wi-Fi buffers | IDF | PSRAM preferred | `SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y` |
| ETH/SPI DMA, httpd sockets | IDF | internal | IDF defaults (DESIGN.md §4) |
| Web assets (gz) ≤ 64 KB | flash (rodata) | XIP | generated `web_assets.c` |

Anything touched from an ISR or with the flash cache disabled (UART ISR, `IRAM_ATTR` code) must be
internal RAM; nothing in this design shares PSRAM data with ISRs. With `CONFIG_SPIRAM_XIP_FROM_PSRAM=y`
(code and rodata copied to PSRAM) the cache is disabled far less often than in a flash-XIP app — see
§6.2 for exactly when, and what that means for task stacks.

### 6.1 Internal RAM budget (Phase 2 estimate, from the configured stacks/buffers)

**Update (FIXER firmware + final verifier, 2026-10-19): mitigations 1–3 below are applied.** Measured
on the clean `build/`: DIRAM static 129 438 B used of 341 760 (.bss 32 176, .text 72 923), External RAM
.bss 35 076 B; Wi-Fi/lwIP buffers prefer PSRAM; `LWIP_TCP_SND_BUF_DEFAULT` 5760 (lwIP row below:
worst case sockets × 5 760 B, rarely all at once). The pre-mitigation analysis is kept below for
reference; the HW_TEST §5 heap gate is the final check.

Static, measured on the clean `build/` (`idf.py size`, 2026-10-19, before mitigations): DIRAM 167 174 B used
(.text 76 763 in IRAM-executable DIRAM, .bss 65 840, .data 24 571) of 341 760 → **≈ 174.6 KB left
for the heap at boot** (+ ≈ 8 KB RTC-FAST heap). Our components' static internal RAM ≈ 44.6 KB:
store 13.0, snmp_gw 11.6, alarm 5.2, mex150 4.2, sysmgr 3.6, net 3.1, web 2.3, auth 1.4,
snmp_lwip 0.4 (largest: alarm `s_eng` 5.2, evlog `s_log` 4.7, mex `s_core` 2.8, snmp `s_inf` 2.4,
history/evlog writer scratch 2.4 + 2.0, config `s_cfg` 1.7, snmp `s_snap` 1.6). IDF static: Wi-Fi
libs ≈ 15 (net80211 8.9, pp 5.1), freertos 10.7, spi_flash 20.1 (mostly IRAM-safe code), phy 8.5.

Runtime heap consumers, scenario of the gate (Ethernet up, recovery AP up with a station, 4 WS
clients + 2 REST requests, an SNMPv3 walk, history/alarm/persist running):

| Consumer | Internal KB | Basis |
|---|---|---|
| Task stacks, our tasks | 55.5 | mex_poll 4, gw_evt 6, httpd 8, httpd_login 6, httpd_async 6, snmp_agent 6, persist 4, supervisor 3.5, console 4, net_mgr 4, w5500 rx 4, sys_reboot 3 (transient, not counted) |
| Task stacks, IDF | 20.5 (+ 6.5 wifi) | esp_timer 4, sys_evt 4, tcpip 4, Tmr Svc 3, ipc 2 × 1.25, IDLE 2 × 1.5; main's 8 KB is freed when app_main returns |
| TCBs, queues, semaphores, event loops | ≈ 9 | ≈ 19 tasks × 0.35; gw_evt queue 32 × 80 B; default loop; persist/SNMP/supervisor queues; mutexes |
| Wi-Fi AP (driver, wpa_supplicant, 4 static RX × 1.6, mgmt buffers, dynamic RX/TX in flight) | ≈ 35–45 | `ESP_WIFI_*` buffers above; AMPDU and IRAM opts off; before mitigation 1 (now applied: Wi-Fi/lwIP buffers prefer PSRAM) |
| lwIP (PCBs, netconns, mboxes, pbufs in flight for ~6 TCP + 3 UDP) | ≈ 10–15 MSS 1440, WND 5760, SND_BUF 5760 per socket (was 11520; worst case sockets × 5 760 B, rarely all at once; pbufs now prefer PSRAM) |
| httpd (server, 12 session slots, 2 KB header scratch) + WS hub | ≈ 5 | WS frame pool and JSON buffers > 4 KB are PSRAM |
| W5500 (driver, SPI DMA) + UART1 driver (1 KB RX ring) + I2C/RMT | ≈ 6 | DMA-capable memory must be internal |
| PSA crypto, NVS cache, console/linenoise, LittleFS internals | ≈ 6 | LittleFS caches PSRAM (`LITTLEFS_MALLOC_STRATEGY_SPIRAM_PREFER`) |
| Transient small mallocs (≤ 4 KB → internal by `MALLOC_ALWAYSINTERNAL`): JSON writers, FILE*, OTA 4 KB chunk | ≈ 6–10 | per request, freed afterwards |
| **Total** | **≈ 160–180** | |

**Verdict: the gate `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) > 60 KB` (AP up, 4 WS,
SNMP walk) is AT RISK** — the estimate leaves ≈ 5–25 KB minimum free in that scenario (≈ 45–70 KB
without the AP). The figures are estimates (Wi-Fi and lwIP dynamic use cannot be measured
without hardware); `GET /system/info` `heap.int_min` and the boot log line of app_main report the
real values in HW_TEST. Mitigations, in order of value/risk (1–3 applied as noted in the update above;
0 and 4 not applied, each needs the HW gate re-run):
0. **Stacks of tasks that never write flash in PSRAM** (§6.2): `snmp_agent` 6 KB, `httpd_login`
   6 KB, `mex_poll` 4 KB with `xTaskCreatePinnedToCoreWithCaps(..., MALLOC_CAP_SPIRAM |
   MALLOC_CAP_8BIT)`: ≈ 16 KB, no sdkconfig change (`FREERTOS_TASK_CREATE_ALLOW_EXT_MEM=y` and
   `SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y` are already set). Cheapest lever; apply first if the gate fails.
1. `CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y` — Wi-Fi/lwIP dynamic buffers in PSRAM: ≈ 20–30 KB.
2. Move our large cache-safe statics to PSRAM (`EXT_RAM_BSS_ATTR` + `SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`):
   alarm engine, evlog tails, SNMP statics, history writer scratch, config/secret copies: ≈ 25–30 KB
   (none is touched from ISRs or with the cache disabled).
3. IRAM → flash (applied form: `RMT_{ENCODER_FUNC,TX_ISR_HANDLER,RX_ISR_HANDLER}_IN_IRAM=n` and
   `ESP_PHY_IRAM_OPT=n`, DIRAM .text 76 763 → 72 923 B; the FreeRTOS/heap/ringbuf options below
   were not applied): `FREERTOS_PLACE_FUNCTIONS_INTO_FLASH`, `HEAP_PLACE_FUNCTION_INTO_FLASH`,
   `RINGBUF_PLACE_FUNCTIONS_INTO_FLASH`: ≈ 10–15 KB of DIRAM .text, small speed cost.
4. Trim stacks after measuring high-water marks on hardware (httpd 8 K, the two async workers,
   snmp_agent): ≈ 6–10 KB.

### 6.2 Which task stacks must be internal (IDF 6.1, XIP from PSRAM)

The usual rule "task stacks must be internal because flash operations disable the cache" is too
strict for this configuration. `CONFIG_SPIRAM_XIP_FROM_PSRAM=y` selects `SPIRAM_FETCH_INSTRUCTIONS`
and `SPIRAM_RODATA`, so `MMAP_EXECUTABLES_FROM_FLASH` is 0 (`esp_private/flash_mmap.h`). In
`spi_flash_os_func_app.c` `spi1_start()` then:
- **flash reads** never disable the cache (SPI1 mutex only);
- **writes/erases** take the mmap lock and keep the cache enabled unless an mmap page is still
  mapped (`flash_mmap_remain()`, e.g. a live `esp_partition_mmap()`); only then the cache is
  disabled (`OP_TYPE_CACHE_DIS`).

While the cache is disabled, only the **calling** task must have an internal stack
(`cache_utils.c` asserts `esp_task_stack_is_sane_cache_disabled()` on that path); the other core is
parked by the IPC task, so tasks with PSRAM stacks simply do not run. A PSRAM stack is therefore a
problem only for a task that itself writes or erases flash. Rule: **a task may have a PSRAM stack
only if it never writes/erases flash, directly or through an IDF call**.

| Task (stack) | Writes flash? | Stack |
|---|---|---|
| main (8 KB, freed) | NVS boot counter, AP PSK, `nvs_flash_init`/erase, LittleFS format on first mount | internal |
| persist (4 KB) | every config/secrets/history/evlog/user file write (rule 1 of §5) | internal |
| httpd (8 KB) | OTA upload (`esp_ota_begin/write/end`, `set_boot_partition`), rollback (`sys_rollback` → `esp_ota_set_boot_partition`) | internal |
| httpd_async (6 KB) | factory reset (NVS/LittleFS erase, core dump erase) | internal |
| supervisor (3.5 KB) | `esp_ota_mark_app_valid_cancel_rollback` (otadata), factory reset from the button | internal |
| console (4 KB) | `factory_reset` command | internal |
| net_mgr (4 KB) | **yes, indirectly**: `esp_wifi_start()` runs PHY init in the caller, and with `ESP_PHY_CALIBRATION_AND_DATA_STORAGE=y` it stores new RF calibration data to NVS when none is valid (first AP start after a full erase, chip/firmware change) | internal |
| gw_evt (6 KB) | no, but created by `esp_event` (internal by construction) | internal |
| **snmp_agent** (6 KB) | no: SETs go through `cfg_commit` → `persist_mark_dirty`, setpoints through `mex_service_write`; engine boots are read in `snmp_gw_start()` (main) | **PSRAM candidate** |
| **httpd_login** (6 KB) | no: PBKDF2 + session table in RAM; audit/lockout through `evlog_append`/persist | **PSRAM candidate** |
| **mex_poll** (4 KB) | no: UART1 + RAM snapshots only | **PSRAM candidate** |

Conditions for moving a candidate (owners: snmp_lwip `snmp_transport.c`, web `httpd_srv.c`,
mex150 `service.c`):
1. Create it with `xTaskCreatePinnedToCoreWithCaps(..., MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)` (and
   delete with `vTaskDeleteWithCaps` if it is ever deleted).
2. Debug guard: the flash-writing entry points we own (persist writer, `ota_writer`,
   `factory_reset`, `sys_rollback`, supervisor mark-valid) assert
   `esp_ptr_internal(pxTaskGetStackStart(NULL))` under `CONFIG_LOG_DEFAULT_LEVEL_DEBUG`. IDF's own
   assert fires only on the rare cache-disable path, so a regression would otherwise pass most tests.
3. No buffer on these stacks may be handed to a DMA engine that cannot read PSRAM. Our code passes
   static/heap buffers to UART, SNMP AES and SHA; verify on hardware that login (PBKDF2 over the SHA
   accelerator) and the SNMPv3 on-target KAT still pass, and watch the latency: PSRAM stacks are
   slower for stack-heavy code (login time, Modbus cycle RTT in `gwCommRttAvg`).
4. Re-run the HW_TEST §5 heap gate (`tools/hw_smoke.py --heap-only`) and record the gain.

## 7. Stream ownership (Phase 1)

| Stream | Owns | Implements against |
|---|---|---|
| A Modbus | `components/mex150/*.c`, tests for frame/regmap/model/poll_plan | `mex150/*.h`, `gw_events.h`, `gw_health.h` |
| B store + alarm | `components/store/*.c`, `components/alarm/*.c`; gw_core: `gw_events.c`, `gw_json_writer.c`, `gw_ip4.c` | `store/*.h`, `alarm/alarm.h`, `gw_core/*` |
| C web + auth | `components/web/*.c` (incl. `static.c` → `web_asset_find`), `components/auth/*.c`; gw_core: `gw_b64.c`, `crypto_psa.c` (device gw_crypto backend; must not redefine gw_crypto_util.c functions) | `web/*.h`, `auth/auth.h`, `API.md` |
| D front-end + mock | `web/`, `tools/mock_server.mjs`, `tools/build_web.mjs`, `package-lock.json` (`npm install`) | `API.md`, `docs/api/*.schema.json` |
| E SNMP | `components/snmp_lwip/*.c`, `components/snmp_gw/*.c`, `tools/gen_mib.py`, `cmake/gw_mib.cmake` (MIB gz embed, contract in snmp_gw.h) | `snmp_transport.h`, `snmp_gw/*.h`, `regmap.def`, `alarm_catalog.def` |
| F net/board/sysmgr | `components/net/*.c` (incl. the strong-host lwIP hook header), `components/board/*.c`, `components/sysmgr/*.c`; gw_core: `gw_time.c` (device clocks), `gw_ident.c` | `net/*.h`, `board/*.h`, `board_pins.h`, `sysmgr/sysmgr.h` |
| G tooling | `tools/gen_web_assets.py`, `cmake/gw_web_assets.cmake` (contract in web/web_assets.h), smoke tools, VS Code tasks, contract tests | `API.md`, schemas |
| Integrator (Phase 2) | `main/app_main.c` | everything |

Already landed (FIXER, Phase 0.5), maintained by the stream named: `gw_core/gw_health.c` (F),
`gw_core/gw_time_civil.c` (F), `gw_core/gw_crypto_util.c` + `gw_snmp_key.c` + `crypto_openssl.c` (C),
`components/web/fallback/web_assets_fallback.c` (G).

Shared files: any stream may append `#include` lines for its new public headers (and static asserts
for its own constants) to `main/contract_check.c`, and its own sources to its
`GW_HOST_SOURCES_<COMPONENT>` list in `cmake/gw_host_sources.cmake`. Row counts of `regmap.def` /
`alarm_catalog.def` are not pinned anywhere (tests compare the C expansion with the Python parse).

## 8. main/app_main.c wiring (Phase 2 integrator)

Init order §3, plus these glue duties no component owns:
- NVS: `nvs_flash_init` (erase+retry), increment `GW_NVS_NS_BOOTS`/`GW_NVS_KEY_BOOTS` before `snmp_gw_start()`.
- `gw_crypto_init()` before anything that hashes (secrets_load generates the factory AP PSK).
- `cfg_set_alarm_catalog(&alm_cfg_catalog)` before `config_load()`.
- gw_evt handler for `CONFIG_CHANGED{MODBUS}` → `cfg_get_section(MODBUS)` → `mex_service_reconfigure()`.
- Start `mex_service_start()` from `cfg_modbus_t`; if it failed, the MODBUS handler retries the start.
- Init failures: §3 failure policy (`sys_init_fault_set`, FAULT LED, `diag.init_faults`).
Everything else is registered by its owner: eventlog glue (`eventlog_init`), alarm incl. the history
sampler (`alarm_init`), TZ/SNTP/allowlist/AP PSK and the AP fallback timer (`net_init`), session/WS
(`auth_init`, `web_start` incl. the HTTPD heartbeat), SNMP (`snmp_gw_start`), supervisor (LED,
button, mark-valid, RTC write on TIME_SYNC).
