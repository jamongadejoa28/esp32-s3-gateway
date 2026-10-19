# MESTIO Gateway — Hardware Test Checklist

Everything here needs the real board (Waveshare ESP32-S3-ETH-8DI-8RO) and/or a MEX150. None of it
was run during Phase 1 (DESIGN.md §15: no hardware access in this effort); it is the checklist the
user runs later. Host tests, web tests and the mock-server checks (`uv run --locked pytest -q`)
cover everything that does not need hardware.

Record each item as PASS / FAIL / N/A with date, firmware version (`GET /api/v1/system/info` `fw`)
and notes in the results table at the end. Items marked **(fix)** have a known follow-up action
depending on the result.

## 0. Setup

| What | Notes |
|---|---|
| Firmware | `uv run --locked python tools/idf.py build` (zero warnings in our components). Note the build id and `version.txt`. |
| Flash + monitor | Manual only: `uv run --locked python tools/run_device.py --port /dev/ttyACM0 --yes` (refuses without both flags; `--no-monitor` / `--no-flash` available). VS Code task "GW: HARDWARE flash + monitor" asks for the port and requires picking `--yes`. |
| PC tools | `curl`, net-snmp (`snmpget snmpwalk snmpset snmpbulkwalk snmptrapd snmptranslate`), Chrome/Firefox devtools, a syslog receiver (`rsyslog` or `nc -klu 514`), the project venv (`uv run --locked python tools/hw_smoke.py …`, `tools/snmp_smoke.py …`). |
| Instruments | Oscilloscope or logic analyzer (RS485 A/B, UART1 TX/RX GPIO17/18, W5500 INT GPIO12 / RST GPIO39), USB-serial console (USB-Serial-JTAG). |
| Network | PC on 192.168.10.0/24 (e.g. 192.168.10.20), gateway factory IP 192.168.10.150/24, gw 192.168.10.1. A second NIC/Wi-Fi for the recovery AP (192.168.150.0/24). |
| Credentials | Factory admin `admin` / `mestio150!` (must change). AP PSK: printed on the serial console at boot while unchanged (random per device, kept in NVS `gw_fact`). |

Shorthands used below: `GW=http://192.168.10.150`, `API=$GW/api/v1`. A logged-in curl session:

```sh
curl -s -c jar -b jar -H 'Content-Type: application/json' -d '{"user":"admin","pass":"<pw>"}' $API/auth/login
CSRF=$(curl -s -b jar $API/session | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])')
curl -s -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X PUT -d '{"value":23.5}' $API/devices/0/registers/40012
```

## 1. First boot

- [ ] Serial log shows version (= `version.txt`), partition `ota_0`, `ESP_OTA_IMG_PENDING_VERIFY` note on an OTA boot, NVS init, LittleFS mount (format on first boot), factory admin created, AP PSK printed, all tasks started (`mex_poll gw_evt httpd httpd_login httpd_async snmp_agent net_mgr persist supervisor console`); `wifi` only while the AP is up.
- [ ] No `E (…)` log lines, no task watchdog, no `Guru Meditation`.
- [ ] Console `status` (and `GET /system/info`) report heap: `int_free`, `int_min`, `psram_free` (≈ 7 MB), `boot_count` increments on each reset.
- [ ] Second boot: config/secrets load from `/data/cfg/gateway.json` / `/data/sec/secrets.json`, no re-format, admin password unchanged.
- [ ] Strapping pins: GPIO46 (buzzer) stays LOW at boot (no beep), GPIO0 not held, GPIO45 untouched (TF card unused).
- [ ] DI1–DI8 (GPIO4–11) and the TCA9554 relays are never driven: no relay clicks at boot/reset/OTA, relay LEDs off.

## 2. Board bring-up

### 2.1 W5500 Ethernet (DESIGN §0 risk: INT 12 not 4, RST 39 unverified, no factory MAC)
- [ ] **INT = GPIO12**: scope GPIO12 during `ping -f` (falling edges per RX burst). Confirm nothing toggles on GPIO4 (DI1). **(fix)** if the board routes INT elsewhere: `board_pins.h`.
- [ ] **RST = GPIO39**: scope GPIO39 at boot — one low pulse before SPI init and the W5500 version register read succeeds. If GPIO39 is not connected, the driver must still come up with `rst_gpio = -1` **(fix)** `board_pins.h`.
- [ ] SPI2 @ 20 MHz stable: `ping -c 1000 -i 0.01 192.168.10.150` → 0 % loss; then try 33 MHz only if needed.
- [ ] MAC = eFuse `ESP_MAC_ETH` (`GET /system/network` `eth.mac`), unique per board, not 00:00:00…
- [ ] Link down/up (unplug 10 s): `link_changes` increments, event log `net_link`, IP restored, sessions keep working.
- [ ] DHCP mode: lease obtained, hostname `mestio-gw-XXXX` visible on the DHCP server; static mode restored afterwards.

### 2.2 RTC, LED, button
- [ ] PCF85063 (I²C 0x51 on SDA 42 / SCL 41): power off 10 min → on: `time_valid=true` right after boot, drift < 2 s/day.
- [ ] RTC is written after NTP sync and after `POST /time` (browser sync), not before (log `time_set`).
- [ ] RTC battery/cap absent or invalid time (VL flag) → `time_valid=false`, history files not written, UI shows "clock not set".
- [ ] WS2812 (GPIO38) states: booting, normal, alarm by severity, comm lost, AP active, factory-reset armed (solid red at 10 s), OTA in progress.
- [ ] BOOT button: < 3 s ignored; 3–8 s → recovery AP; ≥ 10 s → factory reset on release (see §9, §10).

## 3. RS485 / MEX150

### 3.1 Wiring
- [ ] Gateway RS485 **A → MEX150 TRX+**, **B → MEX150 TRX−**, signal GND connected if the MEX150 offers it; shielded twisted pair.
- [ ] **120 Ω termination jumper ON** on the gateway (and at the far end of the bus only); measure ≈ 60 Ω across A/B with both ends terminated and power off.
- [ ] MEX150 at 9600 8N1, slave 1 (panel menu); gateway defaults match (`GET /config/modbus`).

### 3.2 Link quality
- [ ] 10 min idle polling: `GET /devices/0/stats` → `crc = 0`, `timeout = 0`, `malformed = 0`, `rx_ok ≈ tx`; record `rtt_ms.{last,avg,max}` (expect ≈ 40–60 ms per block at 9600).
- [ ] **RS485 echo / turnaround** (auto-direction transceiver, no DE pin): on the scope or logic analyzer (UART1 RX GPIO18 vs TX GPIO17), measure (a) time from the last stop bit of the request to the driver releasing the bus, (b) MEX150 response latency, (c) whether our own request appears on RX while we transmit (RX activity during TX = local echo). Do **not** rely on the `malformed` counter for (c): an exact echo of an FC01/FC03 request is skipped before parsing (DECISIONS "A: local echo"), so `malformed` stays 0 on an echoing transceiver. Tune `gap_ms` (default 5) / `timeout_ms` (default 300) if responses are clipped; record the final values. **(fix)** defaults in `config.h` if they must change.
- [ ] 30 min with `poll_ms=500`: no errors; CPU/heap stable.

### 3.3 Register map
- [ ] `/devices/0/live` matches the MEX150 panel: 40036 temperature (incl. a negative value if a sensor can be cooled/offset — must decode **signed**), 40037 humidity, 40011 current, 40012/40013 setpoints, 40018/40019 delays, 40020 device number.
- [ ] **40006 byte position (DECISIONS CONTRACTS)**: run a cooling stage; observe `regs["40006"]`: the design assumes cool1..4/dehum1..4 in bits 15..8 (map), the monitor code read the low byte. If the device uses the LOW byte **(fix)** the `REGBIT` rows for 40006–40008 in `components/mex150/regmap.def` (one line each) and re-run `pytest tests/test_contracts.py`. Same check for 40007 (heating) and 40008 (humidify/supply/drain).
- [ ] Coils 1–16 (run status) match the equipment LEDs on the panel; `derived.stages`/`mode` correct for cool/heat/hum/dehum.
- [ ] Coils 17–31 alarms: provoke at least `high_temp` (lower 40027 below the room temperature while stopped) → coil 27 → alarm raise after 2 polls (debounce), clear after 3.

### 3.4 Writes and interlocks
- [ ] `PUT 40012 {"value":23.5}` → 200 `applied`, panel shows 23.5, audit log `reg_write` old→new, WS `write` frame.
- [ ] Out of range (`99.9`) → 409 `range`; `23.45` → 409 `range`; read-only 40036 → 409 `readonly`.
- [ ] **Running interlock**: while running, `PUT 40021 {"value":1.0}` → 409 `running_interlock`; same for 40027; after Stop (`POST /devices/0/run {"run":false}`, confirm on panel) → `applied`.
- [ ] Disabled sentinel: write 24.9 to 40027 (stopped) → applied, UI shows "사용 안 함 / Disabled".
- [ ] Run/Stop from the UI with confirmation; 40005 bits 15..8 show the delay countdown.
- [ ] Panel change of a setpoint is visible in the UI within 10 s (slow group) / 1 s (fast group).
- [ ] Device exception: write a value the MEX150 refuses (if any) → 409 `exception:N`.
- [ ] Write during comm loss → 409 `offline`; write queue full (9 rapid writes) → 503 `busy`.
- [ ] **FC06 echo vs ack (DECISIONS "A: local echo")**: an FC06 echo is byte-identical to the MEX150's ack, so only the read-back decides. Only if (c) in §3.2 showed an echo: with the MEX150 powered off (or A/B to the MEX150 disconnected, gateway side still wired to the transceiver), `PUT 40012` with a *different* value must end `uncertain` (`no_ack`/`verify_mismatch`) or `offline` — **never `applied`**; reconnect and confirm the panel value is unchanged. With the MEX150 connected, a real write ends `applied` with `raw` = read-back.

### 3.5 Comm loss
- [ ] Disconnect A/B: after `offline_after` (3) failed cycles → `comm_lost` alarm, LED, WS `comm online:false`, event log, SNMP `gwCommLost`; device bit alarms frozen (not cleared). Offline polling every 2 s (scope).
- [ ] Reconnect → `comm_restored`, alarm clear, `gwCommRestored`, `online_since` updated.
- [ ] Power-cycle the MEX150 while polling: recovery without gateway reboot.

## 4. HTTP / security (tools/hw_smoke.py)

Run from the PC (network only; no serial):

```sh
# secrets via the environment (not on the command line / shell history); read -s keeps them off screen
read -rs GW_NEW_PASSWORD; export GW_NEW_PASSWORD       # only while the account still must change it
uv run --locked python tools/hw_smoke.py --url http://192.168.10.150
# after the change: export GW_PASSWORD=<current password> (avoids one failed factory-password login)
# optional, changes device state: --write (re-writes 40012 with its current raw from a fresh snapshot,
# and the 23.45 "not representable" negative), --ota-write (junk uploads; ERASES the inactive OTA slot
# = the rollback image). --no-ui accepts a firmware built without the web UI.
```

It checks (all must PASS): no `Server` header and the security headers on API/static responses;
static UI (`GET /` gzip + `no-cache` + ETag/304, every asset referenced by index.html served gzip
with an ETag, hashed `/assets/` names `public, max-age=31536000, immutable`, nothing else immutable;
a missing UI is a FAIL on a device unless `--no-ui`); no product/device information in any
unauthenticated response (deny-list `MEX150 ESP32 Waveshare Espressif esp-idf W5500 mestio_gw
mestio-gw` + this device's fw/idf version, build, MAC, hostname from `/system/info`; generic words in
the SPA bundle are printed as `INFO`, device identity there is a FAIL);
Host allowlist 421 (API, static, WS, missing Host); unauthenticated 401 / unknown 404; login
negatives (foreign Origin 403, form body 400, broken JSON 400, unknown member 422, wrong password /
unknown user 401); cookie `HttpOnly; SameSite=Strict; Path=/`; forced password change (403
`password_change_required`, WS refused, CSRF / wrong_password / policy negatives, change → 204);
CSRF/Origin/Referer negatives; schema validation of every GET endpoint; register-write negatives;
WS refusals (no cookie 401, foreign Origin 403, foreign Host 421) and hello → sub → snap/comm/pong;
OTA negatives (401, 403, 400, 413); the internal-RAM gate (`GET /system/info` `heap.int_min` > 61440 B,
read after the WS/OTA load: a FAIL on a device, `INFO` against the mock; `--heap-min`, `--heap-gate
on|off|auto`; `int_free`/`int_min`/`psram_free` are printed as `INFO heap` and stored under `heap` in
`--json`); `history.csv` is 200 with a valid clock and 400 `bad_request` while `time_valid` is false;
logout → WS `bye logout`; finally the rate limit (429 with
`retry_after`; **this locks the PC's IP out of login for 5 min, doubling with each repeated lock up
to 30 min** (API.md §1.1) — wait for the lock to expire between runs or use `--no-rate-limit`).
Register-write negatives only ever send values that are no-ops if accepted (read-only 40036, the
device's current raw of 40012, or 99.9 which the MEX150 itself refuses), so a regressed check cannot
move the setpoint. Secrets: `GW_PASSWORD`, `GW_NEW_PASSWORD` (the VS Code task passes them this way).

Manual additions:
- [ ] **No product/device info unauthenticated** (DESIGN §6/§11, API.md §1.1): in a private browser window open `$GW/` — the login page shows only the MESTIO symbol and the sign-in form (no product/model/version/hostname/MAC). `curl -s --compressed $GW/ $GW/favicon.svg`, `curl -s $API/system/info`, `curl -s -H 'Host: x' $API/session` and a failed login body contain none of `MEX150 ESP32 Waveshare esp-idf mestio`, the fw version or the MAC. Review the hw_smoke `INFO` line (generic words inside the SPA bundle) with the integrator's decision in DECISIONS.
- [ ] `curl -sI $GW/` shows `Content-Encoding: gzip`, `Cache-Control: no-cache`, `ETag`; hashed assets `Cache-Control: public, max-age=31536000, immutable`.
- [ ] Access by hostname: `http://mestio-gw-XXXX/` (via DNS/hosts) works; a different DNS name pointing to the gateway → 421.
- [ ] IP allowlist: set `ip_allow` to a CIDR excluding the PC from another allowed host → the PC's TCP connections are refused (httpd `open_fn`) and SNMP is dropped; a list excluding the requesting client itself → 422 `lockout`.
- [ ] Session idle timeout (set `idle_min=5`): after 5 min idle → 401 and WS `bye session_expired`; absolute 12 h.
- [ ] Two sessions of the same user: password change revokes the other (`bye revoked`).
- [ ] User management: 4 users max (`limit`), last admin cannot be deleted (`last_admin`), self delete (`self`), viewer cannot write (403), operator cannot change config (403).

### 4.1 PBKDF2 timing
- [ ] `for i in $(seq 10); do curl -s -o /dev/null -w '%{time_total}\n' -H 'Content-Type: application/json' -d '{"user":"admin","pass":"<pw>"}' $API/auth/login; done` → median ≤ 0.4 s at the default 10000 iterations. **(fix)** If > 0.4 s, lower `AUTH_PBKDF2_ITER` (auth.h; existing records keep their own iteration count) or confirm the async worker keeps other requests responsive.
- [ ] While 3 logins run in parallel, `GET /api/v1/session` from another client still answers < 100 ms (PBKDF2 on the async worker, not the httpd task).

### 4.2 WebSocket
- [ ] Browser devtools: `/ws` → `hello`, then `snap` ~1 Hz (first `full:true`, then deltas, full every 30 s), `comm` every 5 s, `sys` every 10 s.
- [ ] 4 clients (4 browser tabs) OK; 5th upgrade → 503.
- [ ] Unplug the PC cable 30 s: UI shows "reconnecting", backs off ≤ 10 s, resumes and backfills history.
- [ ] **Stalled client**: a phone on the recovery AP with the dashboard open walks out of range (or freeze it with the Wi-Fi off but the app still connected). The other clients keep receiving `snap` at ~1 Hz without gaps; the stalled client is dropped after ≈ 10 s; when it returns it reconnects and receives a `full` snapshot.
- [ ] With `poll_ms` = 5000 the comm strip and KPIs do not flicker to "stale" between polls (UI window = max(3 s, poll_ms + 3 s) + 1 s).

## 5. Heap gate (ARCHITECTURE §6)
- [ ] With the recovery AP up and one station connected, 4 WS clients subscribed to everything, and an SNMP walk loop running (`while :; do snmpbulkwalk -v2c -c <ro> 192.168.10.150 .1.3.6.1.4.1.32473; done`) for 10 min: `GET /system/info` `heap.int_min` (= `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL)`) **> 60 KB (61440)**. Record `int_free`, `int_min`, `psram_free`. Sample and gate it from the PC with `uv run --locked python tools/hw_smoke.py --url http://192.168.10.150 --heap-only --json heap-$(date +%H%M).json` (logs in, prints `INFO heap …`, exit status 1 when `int_min` ≤ 61440; no failed logins, so it can run every few minutes during the load).
- [ ] Console `status`/`diag` shows no task with < 512 B stack headroom (`uxTaskGetStackHighWaterMark`).
- [ ] Record the boot log line of app_main (internal/PSRAM heap after init) and compare with ARCHITECTURE §6.1: internal-RAM mitigations 1–3 are applied (Wi-Fi/lwIP buffers prefer PSRAM, 35 KB of statics in PSRAM, RMT/PHY code out of IRAM, TCP send buffer 5760 B). Static DIRAM use is 129 438 B of 341 760. **(fix)** If the gate still fails, apply ARCHITECTURE §6.2 mitigation 0 (snmp_agent, httpd_login, mex_poll stacks in PSRAM, ≈ 16 KB) and re-run; never move net_mgr's stack.
- [ ] **AP memory is returned**: note `int_free` with the AP off; start the AP (BOOT 3–8 s), connect a station, disconnect it and wait for the idle stop (or stop via unplug/replug of Ethernet). `int_free` returns to within ≈ 2 KB of the first value. Repeat 5 times: no downward trend (`esp_wifi_deinit()` on every stop releases the driver, `wifi` task and buffers).

## 6. SNMP (tools/snmp_smoke.py + net-snmp)

OID map, notification varbinds and v3 setup: docs/SNMP.md.

Enable via the UI or REST: `PUT /config/snmp` with `enabled:true`, `v2c:true`, `ro:"<ro-community>"`,
v3 passphrases for `gwmonitor`/`gwadmin` (≥ 8 chars), and `services.snmp:true` in `/config/security`.

```sh
# v2c
snmpwalk -v2c -c <ro> 192.168.10.150 1.3.6.1.2.1.1
snmpbulkwalk -v2c -c <ro> 192.168.10.150 1.3.6.1.4.1.32473
snmpset -v2c -c <ro> 192.168.10.150 1.3.6.1.2.1.1.6.0 s x        # expect noAccess/notWritable
snmpget -v2c -c wrong 192.168.10.150 1.3.6.1.2.1.1.1.0            # expect Timeout (no answer)
# v3 authPriv SHA/AES
snmpget  -v3 -l authPriv -u gwmonitor -a SHA -A '<auth>' -x AES -X '<priv>' 192.168.10.150 1.3.6.1.2.1.1.1.0
snmpset  -v3 -l authPriv -u gwadmin   -a SHA -A '<auth>' -x AES -X '<priv>' 192.168.10.150 1.3.6.1.2.1.1.6.0 s 'Server room B'
snmpset  -v3 -l authPriv -u gwmonitor -a SHA -A '<auth>' -x AES -X '<priv>' 192.168.10.150 1.3.6.1.2.1.1.6.0 s x   # rejected
snmpget  -v3 -l noAuthNoPriv -u gwadmin 192.168.10.150 1.3.6.1.2.1.1.1.0                                          # rejected
snmpget  -v3 -l authNoPriv -u gwadmin -a SHA -A '<auth>' 192.168.10.150 1.3.6.1.2.1.1.1.0                         # rejected
# all of the above automated:
uv run --locked python tools/snmp_smoke.py --host 192.168.10.150 --community '<ro>' \
  --ro-auth '<a1>' --ro-priv '<p1>' --rw-auth '<a2>' --rw-priv '<p2>' v2c v3
```

- [ ] MIB: `curl -s -b jar $API/snmp/mib --compressed -o MESTIO-GW-MIB.txt`; `snmptranslate -M +. -m +MESTIO-GW-MIB -Tp` parses; `snmpwalk -M +. -m +MESTIO-GW-MIB …` shows names.
- [ ] Setpoint SET (mexSetpointTable, OID from the MIB) as `gwadmin`: applied value on the panel; out of range → `wrongValue`/`commitFailed`; while running on a stopped-only row → `commitFailed`; `gwLastWriteResult` reflects the outcome; audit `reg_write` by `@snmp`.
- [ ] Engine boots increment per reboot (`snmpget … SNMP-FRAMEWORK-MIB::snmpEngineBoots.0`), engine ID `80 00 7E D9 03 <MAC>`.
- [ ] **On-target known-answer test of `snmpv3_auth`/`snmpv3_crypt`** (stream E, RFC 3414/3826 vectors) passes (console/diag command).
- [ ] Traps: trap target = PC, port 162 (or 1162 for the tool), community `mestio-trap`:
  ```sh
  printf 'authCommunity log,net mestio-trap\n' > snmptrapd.conf
  sudo snmptrapd -f -Lo -C -c snmptrapd.conf udp:162
  # or without root:
  uv run --locked python tools/snmp_smoke.py --trap-port 1162 --trap-community mestio-trap \
     --web-url http://192.168.10.150 --web-pass '<pw>' --trap-seconds 30 trap
  ```
  - [ ] `POST /snmp/test-trap` → `gwTestNotification` received, `{"sent":[{"host":…,"ok":true}]}`.
  - [ ] v2c inform target: ack received → `ok:true`; with snmptrapd stopped → `ok:false` after 3 retries/5 s.
  - [ ] Disconnect RS485 → `gwCommLost` (one trap, coalesced), reconnect → `gwCommRestored`.
  - [ ] Alarm raise/clear → `gwAlarmRaised`/`gwAlarmCleared` with varbinds dev, code, name, severity, DateAndTime, value, seq.
  - [ ] Config change → `gwConfigChanged`; OTA validated → `gwFirmwareUpdated`; boot → `coldStart`.
  - [ ] `auth_traps:true` + wrong community → `authenticationFailure` to every enabled target.
  - [ ] Token bucket: 30 alarm transitions in 1 s → ≤ 10 traps/s, no task starvation.
- [ ] SNMP disabled (`enabled:false` or `services.snmp:false`): no answer on UDP/161, no traps.
- [ ] **Spoofed loopback source**: with an `ip_allow` list that excludes the PC, send a v2c GET from the LAN with source 127.0.0.1 (e.g. `scapy`: `send(IP(src='127.0.0.1',dst='192.168.10.150')/UDP(sport=40000,dport=161)/SNMP(community='<ro>',PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])))`) → no response and no agent activity (dropped by the `LWIP_HOOK_IP4_INPUT` martian check).

## 7. OTA and rollback
- [ ] Build a new version (`version.txt` +1), upload in the UI (System → Firmware) with progress: `{version, reboot_in_s:2}`, reboot, `GET /system/firmware` → running `pending_verify`, after 60 s healthy → `valid` (event log `ota`, SNMP `gwFirmwareUpdated`).
- [ ] **Rollback on boot failure**: upload an image built with a deliberate `abort()` early in `app_main` (temporary local change, never committed) → bootloader rolls back to the previous slot; `GET /system/firmware` shows the old version `valid`, other slot invalid.
- [ ] **Rollback on unhealthy image**: an image whose `mex_poll` or `persist` never beats (e.g. temporary change) is never marked valid → after reset it rolls back.
- [ ] Hash mismatch (`X-Firmware-SHA256` wrong) → 422 `hash_mismatch`, running image unaffected; wrong project / truncated image → 422 `image_invalid`; downgrade → 422 unless `?allow_downgrade=1`; second concurrent upload → 423 `locked`; > 3 MB → 413.
- [ ] `POST /system/firmware/rollback` → reboot into the other valid slot; 404 if none.
- [ ] Power loss during upload (pull power at ~50 %): device boots the old image, next upload works.
- [ ] **Mark-valid blocked by an init fault**: an image that boots with a latched FS/STORE/NET/WEB/CORE init fault (temporary local change, e.g. `sys_init_fault_set(SYS_INIT_FAULT_WEB)` after `web_start()`) stays `pending_verify`, shows the FAULT LED and reboots into the previous image after `SYS_PENDING_VERIFY_LIMIT_MS` (300 s). An image with only an SNMP/SYSLOG fault is marked valid.
- [ ] **Boot watchdog**: an image that blocks in init before `supervisor_start()` (temporary `vTaskDelay(portMAX_DELAY)` in app_main) restarts after 120 s and the bootloader rolls it back. A normal boot (including a first-boot LittleFS format) never trips it: note the init time from the app_main log line.
- [ ] WS2812 colours and timing stay correct during an OTA upload and a factory reset (RMT ISR/encoder are no longer in IRAM; one frame fits the RMT block).

## 8. Network change and recovery AP
- [ ] `PUT /config/network` (new static IP) → 202 `{apply_in_s:3, confirm_within_s:120}`; reachable on the new IP; `POST /config/network/confirm` from the new IP → kept after reboot.
- [ ] Same without confirm → reverts to the old IP after 120 s (event log `net_provisional`), AP PSK change reverted too.
- [ ] Subnet overlapping 192.168.150.0/24 → 422.
- [ ] **AP via button**: BOOT held 3–8 s → SSID `MESTIO-GW-XXXX` (WPA2/WPA3), PSK from the serial log; client gets 192.168.150.x; `http://192.168.150.1/` works even with an IP allowlist that excludes the client; max 2 stations; AP off 15 min after the last station leaves.
- [ ] **AP via no Ethernet**: unplug Ethernet at boot → AP after 120 s (`fallback_after_s`); plug back → Ethernet works, AP times out.
- [ ] **Strong-host check**: from the Ethernet side, `ip route add 192.168.150.1 via 192.168.10.150` then `curl http://192.168.150.1/` → no answer (dropped by the `LWIP_HOOK_IP4_INPUT` hook).
- [ ] AP PSK change via `PUT /config/network {"ap":{"psk":…}}` + confirm; factory PSK no longer printed at boot.

## 9. Factory reset
- [ ] **Button**: BOOT ≥ 10 s → LED solid red at 10 s, reset executes on release (not while held), reboot; config/secrets defaults, `admin`/`mestio150!` must change, AP PSK unchanged (NVS `gw_fact`), logs/history deleted.
- [ ] **Web**: System → Factory reset with password + `RESET`, `keep_network:true` → network settings and logs/history kept; wrong password → 422 `wrong_password` (counts toward the rate limit).
- [ ] **Console**: `factory-reset --yes` over USB-Serial-JTAG.
- [ ] After any reset: SNMP disabled, v3 keys cleared, NVS ns `gw` cleared (engine boots restart), no leftover `/data/cfg/*.tmp|.bak`.

## 10. Time, logs, syslog, core dump
- [ ] NTP enabled (`/config/time`): sync within 1 min, `sntp.synced`, RTC written; TZ `KST-9` in CSV/UI times.
- [ ] Browser sync (`POST /time`) on a device without NTP; rejected before 2024-01-01 (422).
- [ ] History: 24 h of data survives a reboot (files `/data/hist/d0/YYYYMMDD.bin`), 7 d/30 d queries ≤ 2 s, CSV export opens in Excel (UTF-8 BOM, Korean headers OK).
- [ ] Syslog to the PC (`/config/notify`): RFC 5424 messages for alarms/audit with the configured facility and `min_sev` filter.
- [ ] Event/audit log debounce (10 s): after a planned reboot (`POST /system/reboot`) the last records before the reboot are present; after pulling power, at most the last ≈ 10 s of records are missing. 20 failed logins in a burst are all logged (half-full RAM tail forces an immediate write).
- [ ] History beyond 48 h (needs ≥ 3 days of data): 7-day and 30-day Trends queries answer ≤ 2 s, WS `snap` keeps arriving during the query, and `psram_free` drops by ≤ ≈ 0.8 MB after the warm-up job (60 s after boot). Compare a 7-day chart before and after a reboot: identical except bucket edges older than 48 h (10-minute precision).
- [ ] Core dump: trigger a panic (console `panic` / debug command) → after reboot `GET /system/coredump` returns the summary (task, PC, backtrace); `idf.py coredump-info` over USB decodes the ELF.

## 11. Browser performance
- [ ] LAN, cache disabled: first load ≤ 7 requests, total transfer ≤ 64 KB gz UI + API, TTI < 1 s.
- [ ] Dashboard with live charts: frame time ≤ 16 ms (Performance panel), idle CPU near 0 when the tab is hidden.

## 12. 72 h soak
Conditions: 1 MEX150 polled at 1 s; 4 WS clients (browser tabs or a script) subscribed to all
topics; SNMP walk of the enterprise subtree every 60 s and a v3 GET every 10 s; one setpoint write
(same value) per minute via curl with one logged-in session (§0 shorthand, `{"raw":<current raw>}`) —
not `tools/hw_smoke.py` in a loop (its login negatives alone reach the 5-failures-per-5-min lock); NTP on; syslog on; one alarm
raise/clear per hour (limit change).
- [ ] No reboot (`uptime_s` monotonic, `boot_count` unchanged), no watchdog, no `E` logs except expected.
- [ ] `int_min` stays > 60 KB and does not trend down (sample every 10 min with `tools/hw_smoke.py --heap-only`, §5).
- [ ] Modbus `crc`/`timeout` < 0.01 % of `tx`; no stuck `pending` commands.
- [ ] History has no gaps except deliberate ones; LittleFS usage stable (`diag.fs.used`), log rings wrap correctly.
- [ ] WS clients never dropped except on network faults; SNMP agent answers throughout; trap queue never overflows.

## 13. Items reported by the implementation streams

Collected from `docs/DECISIONS.md` (Phase 1). Each stream appends its hardware-only items here or in
DECISIONS.md; the integrator merges them.

| Source | Item | Result |
|---|---|---|
| CONTRACTS | 40006–40008 bit positions (§3.3) | |
| FIXER | W5500 RST GPIO39 / INT GPIO12 (§2.1) | |
| FIXER | snmpv3_auth/snmpv3_crypt on-target KAT (§6) | |
| A | Local echo: FC01/FC03 echo skipped (scope, not `malformed`, §3.2 c); FC06 echo vs ack decided by read-back, never `applied` without the MEX150 (§3.4) | |
| A | Write freshness with `poll_ms` > 3000: a write is accepted while ONLINE and sent after the fast group is re-read in the same cycle; `[run=1, hi_temp=30.0]` queued together → second one `running_interlock` (§3.4) | |
| F | W5500 install retry with `reset_gpio_num = -1` when GPIO39 is not wired (log line, link up) (§2.1) | |
| F | RTC: CTRL1 STOP bit or 12-hour mode → `time_valid=false` until set; `board_rtc_set_utc()` clears both (§2.2) | |
| F | BOOT button sampled every 20 ms: 3–8 s AP, ≥ 10 s reset armed (buzzer beep + red), release between 8 and 10 s cancels, held past 30 s disarms (stuck button) (§2.2, §9) | |
| F | Recovery AP: fallback after `fallback_after_s` without IPv4 also after a later address loss; never stops while a station is connected or while Ethernet has no address; DHCP offers no router/DNS (§8) | |
| F | Supervisor: LED BOOT ≤ 30 s, mark-valid after 60 s healthy, PENDING_VERIFY not healthy in 300 s → reboot + rollback, valid image with a required heartbeat stale 120 s → reboot (§7) | |
| F | OTA sequential-write erase: upload does not stall httpd beyond the chunk writes; header/app-desc rejected within the first 288 bytes (§7) | |
| F | Factory reset restarts snmpEngineBoots at 1 with the same engine ID (accepted, DECISIONS F contract issue) (§6, §9) | |
| F | Static DNS slot clearing; config re-apply with unchanged eth/hostname keeps the DHCP lease and connections (§2.1, §8) | |
| C | OTA upload runs on the httpd task: measure the WS `snap` gap and API latency during a 1.5 MB upload (§7, §4.2) | |
| C | PBKDF2 on `httpd_async`: 4 parallel logins + register writes → 503 `busy` only when the queue (4) is full, other requests stay responsive (§4.1) | |
| C | WS: 5th client → 503 in the pre-handshake callback; `hello` arrives after the 101; frames > 256 B → close 1009 (§4.2) | |
| G | `tools/hw_smoke.py` full run against the device (§4) | |
| G | `tools/snmp_smoke.py` v2c/v3/trap against the device (§6) | |
| INTEGRATOR | Init-fault policy: LittleFS mount failure → boot continues on RAM defaults, FAULT LED, UI banner "settings are not saved" (`diag.init_faults` 0x01/0x02) (§1) | |
| FIXER (firmware) | Internal-RAM gate with mitigations 1–3 applied; mitigation 0 only if it fails (§5) | |
| FIXER (firmware) | AP stop releases the Wi-Fi driver; stop/start ×5 without a heap trend (§5) | |
| FIXER (firmware) | Stalled WS client (phone leaving AP range) never freezes the others; dropped after 10 s (§4.2) | |
| FIXER (firmware) | Boot watchdog 120 s and mark-valid blocked by FS/STORE/NET/WEB/CORE init faults → rollback (§7) | |
| FIXER (firmware) | `GW_HB_NET` required: no false health reboot while the AP starts (PHY calibration) or during a provisional network apply; stale SNMP heartbeat → FAULT LED + `health` event, no reboot (§7, §8) | |
| FIXER (firmware) | DRBG seeding at boot (ADC entropy before Wi-Fi): two boards after a full NVS erase get different AP PSKs; session cookies differ across reboots (§0, §4) | |
| FIXER (firmware) | Spoofed 127.0.0.1 SNMP from the LAN dropped with an allowlist (§6) | |
| FIXER (firmware) | Event/audit log 10 s debounce: crash loses ≤ 10 s, bursts kept (§10) | |
| FIXER (firmware) | 7 d / 30 d history from PSRAM rollups: latency, no WS stall, PSRAM use ≤ 0.8 MB (§10) | |
| FIXER (firmware) | WS2812 with RMT code out of IRAM: correct colours during flash writes (§7) | |
| FIXER (frontend) | Dashboard frame time and idle CPU on the real device; comm strip with `poll_ms` > 3000 (§11, §4.2) | |
| FIXER (docs-tooling) | `hw_smoke.py --heap-only` sampling during the §5 load and the 72 h soak (§5, §12) | |

## Results

| Date | FW | Section / item | Result | Notes |
|---|---|---|---|---|
| | | | | |
