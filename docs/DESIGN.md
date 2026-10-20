# MESTIO ESP32-S3 Gateway — Detailed Design Spec (source of truth for implementers)

Korean summary of the approved plan: `docs/PLAN.ko.md`. This file is the detailed engineering spec every implementer must follow. If you must deviate, record the deviation in `docs/DECISIONS.md` (create if missing) with the reason.

Hardware: Waveshare ESP32-S3-ETH-8DI-8RO (ESP32-S3-WROOM-1 N16R8: 16 MB QIO flash, 8 MB octal PSRAM; GPIO33–37 reserved by PSRAM).
Peer: MEX150 HVAC controller, Modbus RTU over RS485 2-wire, 9600 8N1, slave 1 default.
Toolchain: ESP-IDF **v6.1.0** at `/home/hajun/esp-idf-v6.1`, tools at `/home/hajun/dev_ws/wokwipj/.tools/espressif`, per-project uv `.venv`. Build via VS Code ESP-IDF extension or `uv run --locked python tools/idf.py build`. Node v24 via nvm (`~/.nvm/versions/node/v24.14.0/bin`).
Reference projects (read-only): `/home/hajun/dev_ws/esp32-s3-monitor` (IDF 6.1 proven: MEX150 RTU code, RTC, tooling), `/home/hajun/dev_ws/recovery-gateway` (feature reference; DO NOT copy its defaults: 192.168.127.254/16, ofats/One4all@, public/private, OID 61310, "ofats" naming, embedded TLS keys).

---

## 0. Verified facts about IDF 6.1 (do not re-litigate)

| Topic | Fact | Consequence |
|---|---|---|
| lwIP SNMP | IDF lwip CMake does not compile `apps/snmp`. `snmpv3_mbedtls.c` includes `mbedtls/cipher.h`, `md5.h`, `sha1.h` which are private in mbedTLS 4.1 (TF-PSA-Crypto); DES removed entirely. Only `mbedtls/md.h` public. | Own component `snmp_lwip` compiling a subset of `$IDF_PATH/components/lwip/lwip/src/apps/snmp/*.c`, with `LWIP_SNMP_V3_MBEDTLS=0`, `LWIP_SNMP_V3_CRYPTO=1`, and our own `snmpv3_psa.c` (PSA Crypto API: HMAC-SHA1/MD5, AES-128-CFB, hashing for password→key). DES → `ERR_ARG`. |
| lwIP SNMPv3 limits | Auth HMAC-MD5-96 / HMAC-SHA-96 only; priv DES/AES-128-CFB. v3 traps NOT implemented (`snmp_send_trap*` rejects v3). No VACM. | Traps/informs are v1/v2c. v3 RO/RW enforced by our own per-request context: `snmpv3_get_user` records resolved user; every `set_test` calls `snmp_ctx_can_write()`. |
| `snmp_netconn.c` | Single thread; not safe to call trap APIs from other threads. | Replace with own `snmp_transport.c`: one agent thread that receives requests AND drains a trap queue. All lwIP SNMP API calls happen only in that thread. |
| `SNMP_MAX_COMMUNITY_STR_LEN` | Default = 7 chars. | Project-wide `-DSNMP_MAX_COMMUNITY_STR_LEN=32`. |
| Project-wide defines | `idf_build_set_property(COMPILE_DEFINITIONS "X=1" APPEND)` before `project()` works in 6.1. | Used for SNMP option block (struct layouts depend on them, so must be global). |
| W5500 | Removed from IDF tree in 6.0. Registry `espressif/w5500` (2.0.x, idf>=6.0, depends `espressif/wiznet_common`). API: `eth_w5500_config_t` with `.base` (`int_gpio_num`, `poll_period_ms`, `spi_host_id`, `spi_devcfg`…), `ETH_W5500_DEFAULT_CONFIG(host, &devcfg)`, `esp_eth_mac_new_w5500()`, `esp_eth_phy_new_w5500()`. Verify exact names in `managed_components/` after first resolve. | Default `int_gpio_num` is 4 = DI1 on this board → **set 12**. RST GPIO39 (from pin matrix; verify on hardware, fall back to -1). No burned MAC → set from `esp_read_mac(ESP_MAC_ETH)` via `ETH_CMD_S_MAC_ADDR`. Call `gpio_install_isr_service(0)` before MAC creation. SPI2 @ 20 MHz first. |
| LittleFS | `joltwallet/littlefs` 1.22.3 supports 6.1. `littlefs_create_partition_image(<part> <dir> [FLASH_IN_PROJECT])` exists (needs pip at build time). | Mount `data` with `format_if_mount_failed=true`; defaults written from code at first boot; no image creation in normal flow. |
| cJSON | Removed from IDF 6.0. | `espressif/cjson` registry component. Prefer streaming writer (`gw_json_writer`) for responses; cJSON for parsing requests/config. |
| httpd WS | `CONFIG_HTTPD_WS_SUPPORT`, `CONFIG_HTTPD_WS_PRE_HANDSHAKE_CB_SUPPORT` (`ws_pre_handshake_cb` in `httpd_uri_t`), `httpd_queue_work`, `httpd_ws_send_frame_async`, `httpd_get_client_list`, `httpd_ws_get_fd_info`, `httpd_req_async_handler_begin`. | Wildcard handlers + own router; WS auth in pre-handshake. |
| Drivers | 6.x split driver components: `esp_driver_uart`, `esp_driver_gpio`, `esp_driver_i2c` (`driver/i2c_master.h`), `esp_driver_spi`, `esp_driver_rmt`. Use `UART_SCLK_DEFAULT`. | Use the new APIs only. |

## 1. Board pins (`components/board/include/board_pins.h`)

| Function | GPIO |
|---|---|
| W5500 MOSI/MISO/SCLK/CS/INT/RST | 13 / 14 / 15 / 16 / 12 / 39 |
| RS485 TX / RX (UART1, auto-direction, no DE) | 17 / 18 |
| I2C SDA / SCL (TCA9554 0x20 relays — untouched; PCF85063 RTC 0x51) | 42 / 41 |
| RTC INT | 40 |
| WS2812 status LED | 38 |
| Buzzer (strapping pin; keep LOW) | 46 |
| BOOT button (active low) | 0 |
| DI1..8 (NOT used; reserved for `board_io` hook) | 4..11 |
| TF card (NOT used; GPIO45 strapping) | 45/47/48 |

## 2. Project layout

```
esp32-s3-gateway/
├─ CMakeLists.txt            IDF==6.1 guard (FATAL_ERROR otherwise), PROJECT_VER from version.txt, project-wide SNMP defines, web asset hook
├─ version.txt               semver (single source: app desc, UI, sysDescr)
├─ partitions.csv  sdkconfig.defaults  sdkconfig.defaults.debug
├─ pyproject.toml  uv.lock  .python-version   (IDF python deps copied from esp32-s3-monitor + pytest, pysmi, pysnmp, websockets)
├─ package.json  package-lock.json            (esbuild exact pin; ws for mock server)
├─ .clang-format (from monitor) .editorconfig .gitignore
├─ .vscode/settings.json tasks.json extensions.json
├─ main/ CMakeLists.txt idf_component.yml Kconfig.projbuild app_main.c
├─ components/
│  ├─ gw_core/   gw_events.[ch] (custom esp_event loop + IDs + payloads), gw_json_writer.[ch] (streaming JSON), gw_b64.[ch] (base64url), gw_ring.h, gw_time.[ch], gw_crypto.h (+ crypto_psa.c device / tests use crypto_openssl.c)
│  ├─ board/     board_pins.h board.[ch] i2c_bus.c rtc_pcf85063.c status_led.c buzzer.c button.c board_io.[ch](stub)
│  ├─ net/       net.h eth_w5500.c wifi_ap.c net_mgr.c sntp_time.c ip_filter.[ch]
│  ├─ mex150/    regmap.def regmap.[ch] frame.[ch] model.[ch] poll_plan.[ch] service.[ch] uart_port.c
│  ├─ store/     fs.c atomic_file.[ch] config.[ch] config_json.c secrets.[ch] history.[ch] eventlog.[ch] persist.[ch]
│  ├─ alarm/     alarm_catalog.def alarm.h engine.c rules.[ch]
│  ├─ auth/      auth.h users.c session.c ratelimit.c password_policy.c
│  ├─ web/       router.h httpd_srv.c router.c static.c http_util.[ch] api_*.c ota_upload.c ws_hub.[ch] (+ generated web_assets.c)
│  ├─ snmp_lwip/ CMakeLists.txt snmpv3_psa.c snmp_transport.c include/snmp_transport.h
│  ├─ snmp_gw/   registry.h agent.c registry.c usm.c traps.c mib_system.c mib_gw.c mib_dev.c mib_mex_status.c mib_mex_setpoint.c mib_mex_regs.c mib_alarm.c mib_comm.c
│  └─ sysmgr/    supervisor.c ota_writer.c factory_reset.c syslog.c console.c diag.c sysmgr.h
├─ cmake/gw_host_sources.cmake   pure-C sources shared by IDF build and host tests
├─ web/  index.html assets/ styles/ src/ test/
├─ tools/ idf.py build_web.mjs gen_web_assets.py gen_mib.py mock_server.mjs hw_smoke.py snmp_smoke.py run_device.py
├─ tests/ conftest.py + test_*.py (host C via cc → .so + ctypes/cffi, monitor pattern)
└─ docs/ DESIGN.md PLAN.ko.md API.md api/*.schema.json ARCHITECTURE.md SNMP.md HW_TEST.md mib/MESTIO-GW-MIB.txt (generated)
```

Every component: own `CMakeLists.txt` with explicit `REQUIRES`/`PRIV_REQUIRES`, `include/` public dir. Pure logic (no IDF headers) goes in files listed in `cmake/gw_host_sources.cmake` so host tests compile them with gcc. Compile flags: `-Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048` for our components.

### Init order (`app_main`)
1. Log version (serial only). Note if running partition is `ESP_OTA_IMG_PENDING_VERIFY`.
2. `nvs_flash_init` (erase+retry on NO_FREE_PAGES/NEW_VERSION). Increment SNMP engine boots in NVS ns `gw_fact` (`GW_NVS_NS_BOOTS`; survives factory reset so snmpEngineBoots never decreases).
3. `board_init()`: I2C bus → PCF85063 read → `settimeofday` if valid; LED "booting"; buzzer GPIO46 low; button ISR. Do NOT touch GPIO4–11 or TCA9554.
4. `fs_mount("/data","data")`.
5. `config_load()`, `secrets_load()`; if no users, create default admin (must_change=1).
6. `gw_events_init()` (custom loop task `gw_evt`).
7. `eventlog_init()`, `history_init()`, `persist_start()`.
8. `alarm_init()`.
9. `net_init()` (netif, default loop, ISR service, SPI2, W5500, static/DHCP, net_mgr fallback, SNTP).
10. `mex_service_start()`.
11. `auth_init()`, `web_start()`.
12. `snmp_gw_start()` (thread always created; drops packets if disabled).
13. `syslog_init()`, `console_start()`.
14. `supervisor_start()` → after 60 s with mex, gw_evt, persist, httpd heartbeats alive (`gw_core/gw_health.h`, beaten by the producers themselves) → `esp_ota_mark_app_valid_cancel_rollback()`.

### Tasks
| Task | Prio | Stack | Core | Notes |
|---|---|---|---|---|
| tcpip (lwIP) | 18 | 4096 | 0 | |
| w5500 rx | 15 | 4096 | 0 | mac_config rx task |
| mex_poll | 10 | 4096 | 1 | owns UART1; TWDT; checks write queue between blocks |
| gw_evt | 7 | 6144 | 1 | alarm engine, 1 Hz history sampler, WS frame build; never touches flash |
| httpd | 5 | 8192 | 0 | |
| snmp_agent | 4 | 6144 | 0 | netconn_recv 100 ms timeout; drains trap queue |
| persist | 3 | 4096 | 1 | ALL LittleFS writes; TWDT |
| supervisor | 2 | 3584 | 1 | button/LED/AP timers/health/mark-valid |
| console | 1 | 4096 | any | status, ip, net-reset, factory-reset, reboot, log |

## 3. Partitions (16 MB)
```
# Name,    Type, SubType,  Offset,    Size
nvs,       data, nvs,      0x9000,    0x6000
otadata,   data, ota,      0xF000,    0x2000
phy_init,  data, phy,      0x11000,   0x1000
ota_0,     app,  ota_0,    0x20000,   0x280000
web_0,     data, littlefs, 0x2A0000,  0x80000
ota_1,     app,  ota_1,    0x320000,  0x280000
web_1,     data, littlefs, 0x5A0000,  0x80000
data,      data, littlefs, 0x620000,  0x9D0000
coredump,  data, coredump, 0xFF0000,  0x10000
```
Static UI = gzip files in read-only LittleFS `web_0`/`web_1`, paired with app `ota_0`/`ota_1`. Only asset metadata is compiled into the app. `.gwota` updates and rolls back the app/web pair together. LittleFS `data` still holds config, secrets, history, logs at its original offset and size.

## 4. sdkconfig.defaults (baseline; adjust only if a symbol does not exist in 6.1 — verify with `grep -r "config NAME" $IDF_PATH/components`)
```
CONFIG_IDF_TARGET="esp32s3"
CONFIG_ESPTOOLPY_FLASHMODE_QIO=y
CONFIG_ESPTOOLPY_FLASHFREQ_80M=y
CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y
CONFIG_COMPILER_OPTIMIZATION_PERF=y
CONFIG_COMPILER_STACK_CHECK_MODE_STRONG=y
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_SPEED_80M=y
CONFIG_SPIRAM_XIP_FROM_PSRAM=y
CONFIG_SPIRAM_USE_MALLOC=y
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=65536
CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y
CONFIG_FREERTOS_HZ=1000
CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y
CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK=y
CONFIG_FREERTOS_USE_TRACE_FACILITY=y
CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS=y
CONFIG_FREERTOS_TIMER_TASK_STACK_DEPTH=3072
CONFIG_ESP_TIMER_TASK_STACK_SIZE=4096
CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE=4096
CONFIG_ESP_TASK_WDT_EN=y
CONFIG_ESP_TASK_WDT_TIMEOUT_S=10
CONFIG_ESP_TASK_WDT_PANIC=y
CONFIG_ESP_INT_WDT=y
CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=y
CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y
CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF=y
CONFIG_ESP_COREDUMP_CHECK_BOOT=y
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_WDT_ENABLE=y
CONFIG_UART_ISR_IN_IRAM=y
CONFIG_HTTPD_WS_SUPPORT=y
CONFIG_HTTPD_WS_PRE_HANDSHAKE_CB_SUPPORT=y
CONFIG_HTTPD_MAX_REQ_HDR_LEN=2048
CONFIG_HTTPD_MAX_URI_LEN=256
CONFIG_HTTPD_ERR_RESP_NO_DELAY=y
CONFIG_LWIP_MAX_SOCKETS=20
CONFIG_LWIP_IPV6=n
CONFIG_LWIP_TCPIP_TASK_AFFINITY_CPU0=y
CONFIG_LWIP_TCPIP_TASK_STACK_SIZE=4096
CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=32
CONFIG_LWIP_UDP_RECVMBOX_SIZE=8
CONFIG_LWIP_MAX_UDP_PCBS=16
CONFIG_LWIP_MAX_ACTIVE_TCP=16
CONFIG_LWIP_TCP_SND_BUF_DEFAULT=11520
CONFIG_LWIP_TCP_WND_DEFAULT=5760
CONFIG_LWIP_SO_REUSE=y
CONFIG_LWIP_SNTP_MAX_SERVERS=2
CONFIG_LWIP_SNTP_UPDATE_DELAY=3600000
CONFIG_LWIP_DHCPS=y
CONFIG_ETH_ENABLED=y
CONFIG_ETH_USE_SPI_ETHERNET=y
CONFIG_ESP_WIFI_SOFTAP_SUPPORT=y
CONFIG_ESP_WIFI_NVS_ENABLED=n
CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=4
CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=8
CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=16
CONFIG_ESP_WIFI_AMPDU_TX_ENABLED=n
CONFIG_ESP_WIFI_AMPDU_RX_ENABLED=n
CONFIG_ESP_WIFI_IRAM_OPT=n
CONFIG_ESP_WIFI_RX_IRAM_OPT=n
CONFIG_ESP_WIFI_ENABLE_WPA3_SAE=y
CONFIG_MBEDTLS_HARDWARE_AES=y
CONFIG_MBEDTLS_HARDWARE_SHA=y
CONFIG_LITTLEFS_MALLOC_STRATEGY_SPIRAM_PREFER=y   (verify symbol in component Kconfig)
CONFIG_LITTLEFS_USE_MTIME=y
CONFIG_LITTLEFS_OBJ_NAME_LEN=64
CONFIG_LOG_DEFAULT_LEVEL_INFO=y
```
PSA algorithm availability (MD5, SHA-1, CFB, PBKDF2-HMAC, HMAC) must be verified against `components/mbedtls` Kconfig in 6.1 and enabled explicitly if not default. `sdkconfig.defaults.debug`: `CONFIG_LWIP_CHECK_THREAD_SAFETY=y`, `CONFIG_LOG_DEFAULT_LEVEL_DEBUG=y`, `CONFIG_HEAP_POISONING_LIGHT=y`.

httpd runtime config: `max_uri_handlers=8`, `max_open_sockets=12`, `max_resp_headers=12`, `lru_purge_enable=true`, keep-alive on, `send_wait_timeout=3`, `stack_size=8192`, `core_id=0`, `open_fn` (IP allowlist), `close_fn` (WS cleanup).

Top-level SNMP defines (before `project()`):
```cmake
foreach(d LWIP_SNMP=1 SNMP_USE_NETCONN=1 SNMP_USE_RAW=0 LWIP_SNMP_V3=1 LWIP_SNMP_V3_MBEDTLS=0
          LWIP_SNMP_V3_CRYPTO=1 LWIP_SNMP_CONFIGURE_VERSIONS=1 SNMP_LWIP_MIB2=0
          SNMP_TRAP_DESTINATIONS=1 SNMP_MAX_COMMUNITY_STR_LEN=32 SNMP_MAX_OBJ_ID_LEN=50
          SNMP_LWIP_GETBULK_MAX_REPETITIONS=16)
  idf_build_set_property(COMPILE_DEFINITIONS "${d}" APPEND)
endforeach()
```
(Validate each against `snmp_opts.h`; if `SNMP_USE_NETCONN=1` forces compilation expectations of `snmp_netconn.c`, set it as needed for our transport — document in DECISIONS.md.)

`main/idf_component.yml`: `idf: "==6.1.0"`, `espressif/w5500` (2.0.x), `joltwallet/littlefs: "==1.22.3"`, `espressif/cjson: "^1.7.19"`, `espressif/led_strip: "^3.0.0"`. Pin exact resolved versions in `dependencies.lock`.

## 5. Defaults (single-sourced in the C headers; only the enterprise PEN is a Kconfig option — DECISIONS.md FIXER)
| Item | Default |
|---|---|
| Ethernet | static 192.168.10.150 / 255.255.255.0, gw 192.168.10.1, DNS 192.168.10.1, DHCP off |
| Hostname | `mestio-gw-XXXX` (last 2 MAC bytes hex) |
| Recovery AP | SSID `MESTIO-GW-XXXX`, WPA2/WPA3-PSK, 192.168.150.1/24, DHCP server, max 2 clients, ch 6, off 15 min after last station leaves |
| AP PSK | Random per device, generated once at first boot from the hardware RNG (80 bits, `xxxx-xxxx-xxxx-xxxx`), kept in NVS `gw_fact` (survives factory reset, fit for a production label); printed on serial at boot while unchanged; never returned by the API (write-only, changeable). Not derived from the MAC (MAC-derived values are public) — DECISIONS.md FIXER |
| AP triggers | BOOT held 3–8 s; or no Ethernet link/IP for 120 s after boot (configurable) |
| Web admin | `admin` / `mestio150!`, must change on first login. Until changed, every API except `/session`, `/auth/password`, `/auth/logout` → 403 `password_change_required` |
| Password policy | 10–64 chars, ≥3 of 4 classes, ≠ username, ≠ factory default, ≠ previous |
| Roles | admin / operator (setpoints, run/stop, ack) / viewer. Max 4 accounts |
| SNMP | disabled by default; v1 and v2c off; no RO community (empty; v1/v2c can only be enabled after one is set); RW community empty (SET disabled); v3 users `gwmonitor` (RO) and `gwadmin` (RW), authPriv SHA/AES, passphrases must be entered (≥8 chars), keyless/disabled users are unknown users; trap targets empty; default trap community `mestio-trap` |
| Enterprise PEN | `CONFIG_GW_SNMP_ENTERPRISE_PEN=32473` (RFC 5612 documentation PEN — placeholder) |
| SNMP engine ID | `80 00 7E D9 03 <MAC6>` i.e. (0x80000000\|PEN) BE + format 3 + MAC — derive from PEN |
| Modbus | slave 1, 9600 8N1, poll 1000 ms, timeout 300 ms, 1 retry, gap 5 ms, offline after 3 failed cycles |
| Time | NTP off; servers pool.ntp.org, time.google.com; TZ `KST-9`; RTC stores UTC |
| Security | idle 15 min (5–120), absolute 12 h, lockout 5 fails/5 min → 5 min lock (doubling to 30), IP allowlist empty |
| UI | ko default (fallback browser lang), theme follows OS |

Factory reset: web (admin, password re-entry + type `RESET`, option keep network), BOOT ≥10 s (LED solid red at 10 s, executes on release), USB console `factory-reset --yes`. Deletes `/data/cfg/*`, `/data/sec/*`, logs (unless keep), NVS ns `gw` (ns `gw_fact` with the factory AP PSK and the boot counter is kept); reboot.

## 6. Security
- Passwords: PBKDF2-HMAC-SHA256 via PSA, 16-byte salt, record `pbkdf2-sha256$<iter>$<salt_b64>$<dk_b64>`, start 10000 iter (tune ≤400 ms on device), constant-time compare, dummy verify for unknown user.
- Sessions: 128-bit random token, base64url; store only SHA-256(token) in RAM table of 8; cookie `gw_sid=…; Path=/; HttpOnly; SameSite=Strict`; idle + absolute timeouts enforced on every request and WS (`bye` then close).
- Host check (DNS rebinding): every HTTP request and WS upgrade must carry a `Host` that is a current interface IPv4, `192.168.150.1`, the hostname or `<hostname>.local` (any port) → else 421 `misdirected`, before session lookup, static files included (`net_host_allowed()`).
- CSRF: all POST/PUT/PATCH/DELETE require `X-CSRF-Token` == session csrf (login excepted); for all of them, login included, if `Origin`/`Referer` present, host must equal `Host`. WS pre-handshake checks Host, cookie, `must_change` (refused until the password is changed) and Origin.
- Rate limit: per-IP table 16 entries + global; 5 failures/5 min → lock 5 min doubling to 30; >20 global failures/min → +1 s delay; 429 `{retry_after}`; audit log. Failed re-entry of one's own password (password change, factory reset) counts like a failed login and answers 422 `wrong_password`.
- OTA: admin + CSRF; `application/octet-stream` + `X-Firmware-SHA256`; hash while `esp_ota_write`; mismatch → 422; `esp_ota_end`; check `esp_app_desc.project_name=="mestio_gw"`; downgrade refused unless `?allow_downgrade=1`; set boot, reply, reboot after 2 s; rollback via PENDING_VERIFY.
- No path-taking file endpoints; no CORS headers; headers on every response: CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; `Cache-Control: no-store` on `/api`. No `Server` header. No device data unauthenticated: no model, firmware/IDF version, build, MAC, hostname or site in any unauthenticated response; the static UI bundle is code only (generic strings, the MESTIO brand on the login page) and contains no device-specific values (hw_smoke leak check).
- Unauthenticated surface (complete): `GET /`, hashed static assets, `GET /favicon.svg`, `POST /api/v1/auth/login`, `GET /api/v1/session` (401 `{}` if not logged in).
- Router default-deny: every route declares `{method, path pattern, min_role, csrf, max_body}`; unlisted → 404.
- Body limits: JSON 8 KB, config import 32 KB, OTA package 3 MiB + 80 bytes (2.5 MiB app + 512 KiB web + header).
- IP allowlist (≤8 CIDRs) in httpd `open_fn` and SNMP transport; recovery AP clients exempt — "from the AP" = local address 192.168.150.1 AND peer in 192.168.150.0/24, plus a strong-host `LWIP_HOOK_IP4_INPUT` that drops packets for the AP address arriving on another netif (lwIP accepts any own address on any interface).
- Secrets in `/data/sec/secrets.json`; never returned (write-only fields read back as `"…_set": true`); excluded from export. The core dump is served only as a summary (task, PC, backtrace) because the ELF contains RAM.
- Firmware images are not signed (accepted risk, §14): integrity (SHA-256), project name and version are checked; authenticity relies on the admin session.
- Audit log: login/logout/lockout/config change/register write (old→new)/OTA/reboot/factory reset.

## 7. REST API (`/api/v1`) and WebSocket — full contract in `docs/API.md`

Conventions: JSON; errors `{"error":"code","message":"…","field":"…"}` with 400/401/403/404/409/413/422/423/429/503; scaled values are numbers (23.5), raw ints where named `raw`; timestamps epoch ms UTC.

| Method | Path | Role / CSRF | Request → Response |
|---|---|---|---|
| POST | /auth/login | none | `{user,pass}` → `{user,role,csrf,must_change,idle_s}` + Set-Cookie; 401; 429 `{retry_after}` |
| POST | /auth/logout | any ✓ | 204 |
| GET | /session | cookie | `{user,role,csrf,must_change,expires_in}` or 401 |
| POST | /auth/password | any ✓ | `{current,new}` → 204 / 422 `{error:"policy",rules:[…]}` |
| GET | /meta/device-templates | viewer | device template catalog (from device_templates.def) |
| GET | /meta/registers | viewer | register table (from regmap). Strong ETag (build hash) |
| GET | /meta/alarms | viewer | `[{id,code,sev,ko,en,source}]` |
| GET | /system/info | viewer | `{fw,build,idf,mac,uptime_s,time_valid,heap:{int_free,int_min,psram_free},part:{running,state}}` |
| GET | /devices | viewer | `[{id,name,slave,online,last_ms,seq}]` |
| GET | /devices/{d}/live | viewer | `{seq,ts,online,regs:{"40036":235,…},coils:u32,derived:{temp,hum,current,running,stages:{cool,heat,hum,dehum},delay_s}}` |
| PUT | /devices/{d}/registers/{addr} | operator ✓ | `{value:23.5}` or `{raw:235}` → 200 `{state:"applied",raw}` / 409 `{state:"rejected",reason:"running_interlock\|range\|offline\|readonly\|exception:N"}` / 202 `{state:"uncertain"\|"pending",cmd}` |
| POST | /devices/{d}/run | operator ✓ | `{run:bool}` → same as above (40005) |
| GET | /devices/{d}/commands/{id} | operator | `{state,raw,ts}` |
| GET | /devices/{d}/history | viewer | `?span=900&res=1` or `?from&to&res=60` → `{t0,dt,n,ch:{temp:[…],hum:[…],cur:[…],st:[…],sh:[…]},min:{…},max:{…}}` raw ×10, `null` gaps, ≤1500 points |
| GET | /devices/{d}/history.csv | viewer | chunked CSV with UTF-8 BOM |
| GET/POST | /devices/{d}/stats[/reset] | viewer / admin ✓ | `{tx,rx_ok,crc,timeout,exception,malformed,rtt_ms:{last,avg,max},online_since,offline_count}` |
| GET | /alarms/active | viewer | `[{key,dev,id,sev,since,acked,ack_by,value}]` |
| POST | /alarms/ack | operator ✓ | `{keys:[…]}` or `{all:true}` → 204 |
| GET | /alarms/history | viewer | `?before=<seq>&limit=50&dev&sev` → `{items:[{seq,ts,dev,id,type:"raise\|clear\|ack",sev,value,user}],next}` |
| GET | /alarms/history.csv | viewer | CSV |
| GET/PUT | /config/rules | viewer / admin ✓ | `[{id,name,enabled,src:"temp\|hum\|cur\|reg:40011",op:">\|<",thr,hyst,delay_s,sev}]` max 8 |
| GET/PUT | /config/general | viewer / admin ✓ | `{site,location,contact,lang}` |
| GET/PUT | /config/network | admin ✓ | `{eth:{mode,ip,mask,gw,dns1,dns2},hostname,ap:{fallback,ssid,psk_set,channel,idle_min}}` → `{apply_in_s:3,confirm_within_s:120}` |
| POST | /config/network/confirm | admin ✓ | keep provisional config (else revert after 120 s) |
| GET/PUT | /config/modbus | viewer / admin ✓ | `{devices:[{id,name,slave,enabled}],port:{baud,parity,stop},poll_ms,timeout_ms,retries,gap_ms,offline_after}` |
| GET/PUT | /config/snmp | admin ✓ | `{enabled,v1,v2c,ro_set,rw_set,v3:{enabled,users:[{name,access,auth:"sha",priv:"aes",keys_set}]},traps:[{host,port,version:"v1\|v2c",inform,community_set,enabled}],sys:{name,contact,location}}`; secrets write-only: `ro`,`rw`,`auth_pass`,`priv_pass`,`community` |
| GET | /snmp/mib | viewer | MIB text (embedded gz) |
| POST | /snmp/test-trap | admin ✓ | `{sent:[{host,ok}]}` |
| GET/PUT | /config/time | viewer / admin ✓ | `{ntp:{enabled,servers:[2],interval_min},tz}` |
| POST | /time | admin ✓ | `{epoch_ms}` (sync from browser; writes RTC) |
| GET/PUT | /config/security | admin ✓ | `{idle_min,lockout:{max_fail,lock_min},ip_allow:["10.0.0.0/8"],services:{snmp,syslog}}` |
| GET/POST/PUT/DELETE | /users[/{name}] | admin ✓ | `{name,role,password?,must_change?}`; cannot delete last admin |
| GET/PUT | /config/notify | admin ✓ | `{syslog:{enabled,host,port,facility,min_sev}}` |
| GET | /system/firmware | admin | `{running:{slot,version,state},other:{slot,version,valid}}` |
| POST | /system/firmware | admin ✓ | octet-stream + `X-Firmware-SHA256` → `{version,reboot_in_s}` |
| POST | /system/firmware/rollback | admin ✓ | reboot into other valid slot |
| GET / POST | /system/config/export, /system/config/import | admin ✓ | JSON without secrets; import validates + migrates |
| POST | /system/reboot, /system/factory-reset | admin ✓ | factory-reset `{password,confirm:"RESET",keep_network}` |
| GET | /system/logs | admin | `?kind=audit\|system&before&limit` |
| GET | /system/coredump | admin | summary JSON `{task,pc,cause,vaddr,backtrace,…}` or 404 (no ELF over HTTP) |
| GET (Upgrade) | /ws | cookie + Origin | WebSocket |

WebSocket (text JSON, server push only; writes always via REST):
- `{"t":"hello","v":1,"srv":<ms>,"devs":[0],"seq":{"0":1234},"meta":"<etag>"}` → client fetches `/history?span=3600&res=1` to backfill.
- `{"t":"snap","dev":0,"seq":1235,"ts":…,"on":true,"full":false,"r":{"40036":236},"c":4194305}` ≤1 Hz; `full:true` first frame after subscribe and every 30 s; else only changed regs + `c` if changed.
- `{"t":"alarm","dev":0,"id":"high_temp","type":"raise|clear|ack","sev":2,"ts":…,"seq":…,"value":312}`
- `{"t":"write","dev":0,"cmd":17,"addr":40012,"state":"applied|rejected|uncertain","raw":235,"by":"admin"}`
- `{"t":"comm","dev":0,"online":true,"rtt":42,"err":{…}}` on change and every 5 s
- `{"t":"sys","heap":…,"up":…}` every 10 s when subscribed
- `{"t":"bye","reason":"session_expired|logout|reboot"}`
Client → server: `{"t":"sub","topics":["snap","alarm","comm","write","sys"]}`, `{"t":"ping"}`.
Implementation: `gw_evt` builds each frame once (ref-counted PSRAM buffer) → `httpd_queue_work` → iterate `httpd_get_client_list`, WS + subscribed + valid session → `httpd_ws_send_frame_async`; failed send drops client. Max 4 WS clients.

Config files (LittleFS):
- `/data/cfg/gateway.json`: `{"schema":1,"rev":N,"general":{…},"network":{…},"modbus":{…},"alarms":{"debounce_raise":2,"debounce_clear":3,"sev_override":{},"rules":[…]},"snmp":{…non-secret…},"time":{…},"security":{…},"notify":{…}}`
- `/data/sec/secrets.json`: `{"schema":1,"users":[{name,role,hash,must_change,changed}],"snmp":{"ro","rw","v3":[{name,auth_key,priv_key}],"trap_comm":[…]},"ap_psk"}` (v3 stores localized keys hex, never passphrases).
- Atomic write in persist task: write `X.tmp` → fflush+fsync → rename `X`→`X.bak` → rename `X.tmp`→`X`. Load order `X`→`X.tmp`→`X.bak`→defaults; each must parse + `cfg_validate()`. Missing fields filled from defaults; unknown ignored. `cfg_migrate(from)` chain. `rev` increments per save.
- In-memory `gw_config_t` behind mutex; `cfg_get_section()` copies; `cfg_commit(section,new)` validates, swaps, posts `GW_EVT_CONFIG_CHANGED{section}`, queues persist.

## 8. History, logs, alarms
- Fast ring (PSRAM): 1 s × 3600; record `{u32 ts_s; i16 temp,hum,cur,st,sh; u32 coils; u8 flags}`.
- Slow ring: 1 min × 2880 (48 h); record `{ts; min/avg/max temp,hum,cur; st; sh; stage-on seconds; alarm mask}`.
- 1 Hz `esp_timer` → `gw_evt` samples latest snapshot (hold); offline/stale → gap flag → `null`.
- Slow records appended to `/data/hist/YYYYMMDD.bin` in batches of 10 (and on reboot/OTA); retention 30 days; reload last 24 h at boot; write files only when wall time valid.
- 7 d/30 d queries stream daily files, min/max bucket decimation.
- Event/audit logs: fixed 32-byte records `{u32 seq,u32 ts,u16 dev,u16 code,u8 type,u8 sev,i16 value,char user[12],u32 extra}`, two-file ring (`events.0/1`, `audit.0/1`, 128 KB each), seq recovered at boot.
- Alarm catalog `alarm_catalog.def` `ALM(id, code, source, sev, ko, en)`: coils 17–31 (blower, cool1, cool2, heater, humidifier, sensor, **leak critical**, supply, drain, low_temp, high_temp, low_hum, high_hum, **fire critical**, cool3); coil 32 (combined) is a status only; 40003 bit7 contamination (minor); `comm_lost` (major, gateway-generated); `rule_1..8`.
- Debounce raise N=2 polls, clear M=3 (configurable). Each transition → event log + `GW_EVT_ALARM` (WS, SNMP traps, syslog, LED). Active set keeps `since`, `acked`. Ack ≠ clear. Comm loss freezes (not clears) device bit alarms.
- User rules: `src op thr` + hysteresis + on-delay on 1 Hz samples.

## 9. Modbus (`mex150`)
MEX150 map (docs/modbusmap.pdf): PDU address = ADDRESS-1; FC01 read coils (blocks of 8), FC03 read holding, FC06 write single; FC16 unsupported; ×10 integer decimals.
- Coils 1–16 run status: blower, cool1, cool2, heat1, heat2, heat3, heat4, humid1, humid2, water supply, drain, cooling, heating, humidifying, dehumidifying, cool3. Coils 17–32 alarms (see §8). All coils read-only (FC05 disabled).
- Holding: 40002 input port bits (bits 15..8 = inputs 1..8? see map: bit15=8 … bit8=1; bits 2..0 = 11,10,9); 40003 alarm detail1 (15..0: LED1..LED6, drain, supply, contamination, leak, fire, humid, heat, cool2, cool1, blower); 40004 alarm detail2 (15 low hum, 14 high hum, 13 low temp, 12 high temp, 11 sensor, 2 cool3, 1 stop-delay, 0 run-delay); 40005 run/stop RW (bit0 run; bits15–8 delay seconds remaining); 40006 cooling proportional (15..8: dehum4, dehum3, dehum2, dehum1, cool4, cool3, cool2, cool1); 40007 heating prop (12..8: heat5..heat1); 40008 humid prop (15 drain, 14 supply, 9 hum2, 8 hum1); 40011 current A ×10 R; 40012 set temp 5.0–50.0 RW; 40013 set hum 20.0–80.0 RW; 40014/40015 cool/heat deviation 0.1–10.0; 40016/40017 hum/dehum deviation 1.0–10.0; 40018/40019 run/stop delay 1–180 s; 40020 device no 1–99 R; 40021 temp offset −10.0..10.0 signed; 40022 hum offset −30.0..30.0 signed; 40027 high temp 25.0–50.0 (24.9 = disabled); 40028 low temp 5.0–20.0 (4.9 disabled); 40029 high hum 60.0–90.0 (59.9 disabled); 40030 low hum 10.0–40.0 (9.9 disabled); 40036 current temp −25.0..85.0 (decode SIGNED); 40037 current hum 0.0–99.0; 40053/40054 enum 0 allow/1 prohibit; 40059 cylinder contamination hours 1000–20000.
- Write interlock (from monitor `mex_validate`, keep exactly): writes only when online & fresh (<3 s when sent; at enqueue < max(3 s, poll_ms + 3 s), see API.md §4.4 Freshness); 40021, 40022 and every address ≥40027 only while stopped (`regs[5]&0xFF == 0` means stopped per monitor `mex_running`).

`regmap.def` is the single source of truth (C, REST meta, SNMP modules, MIB generator, UI):
```
/* REG(key, addr, scale, signed, access, min, max, disabled, flags, group, unit, ko, en) */
REG(temp,     40036, 10, S, RO, -250, 850,  NONE, 0,       status,   "°C", "현재온도", "Temperature")
REG(set_temp, 40012, 10, U, RW,   50, 500,  NONE, SNMP_RW, setpoint, "°C", "설정온도", "Temperature setpoint")
REG(hi_temp,  40027, 10, U, RW,  250, 500,  249,  STOPPED, limits,   "°C", "고온설정", "High temp limit")
REG(run,      40005,  1, U, RW,    0,   1,  NONE, RUNBIT,  control,  "",   "운전/정지", "Run/Stop")
BIT(alm_leak, 40003, 6, ...)   COIL(run_blower, 1, status, "송풍기운전", "Blower")
```
Port monitor tests (`/home/hajun/dev_ws/esp32-s3-monitor/tests/test_model.py`) as equivalence tests.

Service API (`mex150/include/mex150/service.h`, frozen):
```c
typedef struct { uint32_t baud; char parity; uint8_t stop; uint16_t poll_ms, timeout_ms, gap_ms; uint8_t retries, offline_after; } mex_port_cfg_t;
typedef struct { uint8_t id, slave; bool enabled; char name[24]; } mex_dev_cfg_t;
typedef struct { uint16_t regs[60]; uint32_t coils; int64_t wall_ms; uint64_t mono_ms; uint32_t seq; bool online; } mex_snapshot_t;
typedef enum { MEX_W_PENDING, MEX_W_APPLIED, MEX_W_REJECTED, MEX_W_UNCERTAIN } mex_wstate_t;
typedef struct { uint32_t cmd; mex_wstate_t state; int reason; uint16_t raw_after; } mex_wresult_t;
typedef struct { uint32_t tx, rx_ok, crc, timeout, exception, malformed, offline_count; uint16_t rtt_last, rtt_avg, rtt_max; } mex_stats_t;
esp_err_t mex_service_start(const mex_port_cfg_t *, const mex_dev_cfg_t *, size_t n);
esp_err_t mex_service_reconfigure(const mex_port_cfg_t *, const mex_dev_cfg_t *, size_t n);
bool      mex_service_snapshot(uint8_t dev, mex_snapshot_t *out);
esp_err_t mex_service_write(uint8_t dev, uint16_t addr, int32_t raw, const char *who, uint32_t wait_ms, mex_wresult_t *out);
void      mex_service_stats(uint8_t dev, mex_stats_t *out, bool reset);
```
`regs[]` indexed by (register − 40000), i.e. regs[36] = 40036.
Poll plan: fast group every cycle: coils `{1,0,8}{1,8,8}{1,16,8}{1,24,8}` + holding `{3,1,3}{3,4,4}{3,10,12}{3,35,2}`; slow group every 10 s and right after any write: `{3,26,4}{3,52,2}{3,58,1}`. Write queue depth 8, checked between blocks; validate at enqueue and before send; write → read-back verify → APPLIED/REJECTED/UNCERTAIN (monitor semantics). Transaction: monitor `exchange()` + retries + per-error counters + RTT. Offline after `offline_after` failed cycles → `GW_EVT_COMM{online=false}`; offline polling every 2 s with first block only. Each successful cycle → `GW_EVT_SNAPSHOT{dev,seq}`, feed TWDT. Multi-device round-robin, `GW_MAX_DEVICES=4`.

## 10. SNMP
`components/snmp_lwip` compiles from `$IDF_PATH/components/lwip/lwip/src/apps/snmp/`: `snmp_asn1.c snmp_core.c snmp_msg.c snmp_pbuf_stream.c snmp_scalar.c snmp_table.c snmp_traps.c snmpv3.c snmp_snmpv2_framework.c snmp_snmpv2_usm.c` + own `snmpv3_psa.c` + `snmp_transport.c`. Excludes `snmp_netconn.c`, `snmpv3_mbedtls.c`, `snmp_raw.c`, `snmp_mib2*.c`, `snmp_threadsync.c`. Upstream dir in `PRIV_INCLUDE_DIRS`; `-Wno-address -Wno-format` etc. as needed for upstream files only.
- `snmpv3_psa.c`: `snmpv3_auth` (HMAC-SHA1/MD5 streaming over pbuf), `snmpv3_crypt` (AES-128-CFB via PSA; DES → ERR_ARG; error paths return ERR_ARG), `snmpv3_password_to_key_{sha,md5}` (1 MB expansion; only on config save; store localized keys). Host-test vectors: RFC 3414 A.3 ("maplesyrup", engine 000000000000000000000002 → SHA localized `6695febc9288e36282235fc7151f128497b38f3f`), RFC 3826 AES.
- `snmp_transport.c`: UDP/161 netconn bound `IP4_ADDR_ANY`, `snmp_traps_handle = conn`; loop `netconn_recv` (100 ms) → drop if disabled / not allowlisted → ctx reset → `snmp_receive()`; on timeout drain trap queue. `snmp_get_local_ip_for_dst` from `esp_netif_get_ip_info`.
- `usm.c`: implements lwIP v3 user/engine callbacks (`snmpv3_get_user`, `snmpv3_get_amount_of_users`, `snmpv3_get_username`, `snmpv3_get_user_storagetype`, `snmpv3_get_engine_id`, `snmpv3_set_engine_id`, `snmpv3_get_engine_boots`/`set`, `snmpv3_get_engine_time`, `snmpv3_reset_engine_time` — verify exact names in `include/lwip/apps/snmpv3.h`); records resolved user in request ctx for RO/RW (first lookup per request only); users must be authPriv SHA+AES: `snmpv3_get_user` returns ERR_VAL for unknown, disabled or keyless users and never reports `*_ALGO_INVAL` (lwIP would accept noAuthNoPriv) — contract in `snmp_gw.h`.
- Registry (`snmp_gw/include/snmp_gw/registry.h`, frozen):
```c
typedef struct { const char *name; const struct snmp_mib *mib; esp_err_t (*init)(void); void (*on_config)(void); } snmp_module_t;
esp_err_t snmp_registry_add(const snmp_module_t *m);   /* max 12, before start */
esp_err_t snmp_registry_start(void);                    /* builds array → snmp_set_mibs() */
```
Base OIDs built at init from PEN. `snmp_set_device_enterprise_oid()` = `…PEN.1.1`.
- Modules: `mib_system` (1.3.6.1.2.1.1; sysDescr "MESTIO Gateway <ver>" configurable; sysContact/Name/Location RW persisted), lwIP `snmpframeworkmib` + `snmpusmmib`, `mib_gw` `.PEN.1.1` (fw, MAC, uptime, wall time, active alarm count, config rev, last write result), `mib_dev` `.1.2` gwDevTable, `mib_mex_status` `.1.3` mexStatusTable (temp/hum/current Integer32 DISPLAY-HINT "d-1", run state, stage bitmaps, coils, input port), `mib_mex_setpoint` `.1.4` (RW columns from rows flagged SNMP_RW; set_test uses `mex_validate`; set_value → `mex_service_write(wait 1000)`; REJECTED → commitFailed; UNCERTAIN/timeout → noError + logged, visible in gwLastWriteResult), `mib_mex_regs` `.1.5` generic (devIndex, regAddr) table (extension point), `mib_alarm` `.1.6` (gwAlarmActiveTable by (devIndex, alarmCode) + counters + last 32 events), `mib_comm` `.1.7` (per-device counters/RTT). Notifications `.PEN.1.0.N`: gwAlarmRaised, gwAlarmCleared, gwCommLost, gwCommRestored, gwConfigChanged, gwFirmwareUpdated; plus coldStart, authenticationFailure (configurable).
- Traps: ≤4 targets each v1/v2c, community, port (`snmp_transport_set_trap_port`), optional v2c inform (acks admitted by the transport for the target's trap community even with v2c polling off, matched by request id via the transport's `on_inform_ack` hook, 3 retries/5 s); lwIP destination slot 0 re-pointed per target; token bucket 10/s; coalesce comm-loss storms; lwIP's own auth trap disabled, authenticationFailure fanned out to all targets from the transport's `on_auth_fail` hook. Varbinds: sysUpTime, snmpTrapOID, gwAlarmDevIndex, gwAlarmCode, gwAlarmName, gwAlarmSeverity, gwAlarmTime (DateAndTime), gwAlarmValue, gwAlarmSeq.
- Integration guide for external monitoring systems (OID map, notifications, v1/v2c/v3 setup, PEN replacement): `docs/SNMP.md`; MIB copy for the default PEN: `docs/mib/MESTIO-GW-MIB.txt`.
- `tools/gen_mib.py` generates SMIv2 `MESTIO-GW-MIB` from `regmap.def`, `alarm_catalog.def`, PEN from sdkconfig; embedded gz, served at `/api/v1/snmp/mib`; `tests/test_mib.py` compiles it with pysmi.

## 11. Front-end
Build: `tools/build_web.mjs` (esbuild exact pin) bundles `web/src/main.js` → ES2020 minified + CSS bundle; HTML whitespace collapsed; SVG logo/sprite minified (strip `<title>/<desc>`); content-hashed names; gzip -9; `manifest.json` + size report; **warn if total gz > 256 KiB**. `tools/gen_web_assets.py` stages validated gzip files and emits only `{path,mime,etag,file,len,immutable}` metadata plus an asset identity. `tools/build_web_fs.py` creates and verifies a 512 KiB LittleFS image; filesystem capacity is the hard limit. `tools/package_ota.py` bundles the matching app and filesystem into `.gwota`. Runtime uses a 1 KiB file buffer, not an in-memory copy of all assets; CMake custom command re-runs on `web/**` change; `tools/idf.py` puts nvm node bin on PATH. Hashed files `Cache-Control: public, max-age=31536000, immutable`; `index.html` `no-cache` + ETag/304.

Visual system (industrial HMI, professional, NOT generic-AI):
- Type: system stack, no webfonts: `-apple-system, BlinkMacSystemFont, "Segoe UI", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", Roboto, sans-serif`; numbers `font-variant-numeric: tabular-nums`; scale 12/13/14 base/16/20/28/40 (KPI). Sentence case, left-aligned.
- Color: light bg `#F5F6F8`, surface `#FFFFFF`, line `#E2E5EA`, text `#151920`, muted `#5A6372`; dark bg `#0D1014`, surface `#141920`, line `#252C36`, text `#E5E8ED`, muted `#8A93A2`. Single accent `#3155E7` (dark `#5D7CF0`). Status ok `#1E9E5A`, warn `#C68A00`, alarm `#D7322B`, offline grey. Chart: temp = accent, hum = teal `#0F8F9A`, current = `#6B7280`, setpoint = dashed text 60%.
- 8 px grid (4 half-step), radius 4 controls / 6 panels, 1 px hairlines, shadows only on overlays. No gradients, glass, emoji, illustrations, rounded shadow cards. ~20 custom line icons in one SVG sprite (20 px, 1.5 px stroke, square caps). Motion 120–160 ms ease-out only for state changes; live numbers update without animation.
- Layout: left rail 56 px icons → expandable 208 px; <768 px becomes top drawer. Top status strip 40 px: site name · RUN/STOP pill · comm dot + data age · alarm count badge · clock · KO/EN · theme · user menu. Dense tables/panels separated by hairlines.
- Branding: favicon.svg = MESTIO symbol (from `MESTIO_Symbol.svg`, fill `#3155E7`, metadata stripped). Login: symbol + "로그인 / Sign in" form only — no product/model/version/device info.

Pages: Login; Dashboard (registered-device cards with detail links); Device details (22 MEX150 template channels and access flags); Live monitor (KPI row temp/hum/current/mode with setpoint & Δ; two synchronized band charts — temp: actual, setpoint, shaded deadband [set−heatDev, set+coolDev], dotted alarm limits if enabled; hum likewise; 4 px stage-activity strip; right column equipment matrix (blower, cool1–3, heat1–4, hum1–2, supply, drain) as status LEDs, active alarms by severity, RTT sparkline); Controller (grouped register table Setpoints/Deviations/Delays/Limits/Calibration/Options/Info; inline edit with range hint; pending→applied/rejected; lock icon for stopped-only; Run/Stop confirm; disabled sentinels shown as "사용 안 함 / Disabled"); Trends (15m/1h/24h/7d/30d, series toggles, min/max envelope, stage run-hours, CSV); Alarms (active + ack, history filter/paging/CSV); Settings: Network (apply → 120 s confirm countdown), Modbus/RS485 (template-based device registration, live counters), SNMP (communities, v3 users, trap targets, test trap, MIB download), Time (NTP/TZ/RTC, sync from browser), Users & security, System (firmware upload with browser-side SHA-256 via `crypto.subtle`, progress, rollback; config backup/restore; reboot; factory reset; logs; diagnostics). Forms: sticky Save/Revert bar, dirty tracking, inline validation from meta ranges.

Canvas chart `web/src/chart/timeseries.js` (~8 KB min): ring buffer Float64Array timestamps + Float32Array per series; two canvases (grid/axes redraw on resize/range change only; data canvas rAF only when dirty); DPR via ResizeObserver; min/max per pixel column decimation when points > 2× width; time window anchored to interpolated server time, capped 30 fps, idle when unchanged; nice ticks with hysteresis; shared crosshair (binary search) + single DOM tooltip; stop on `visibilitychange` hidden; WS reconnect exponential backoff ≤10 s with "reconnecting" indicator.
i18n: `web/src/i18n/ko.js`, `en.js` flat key dictionaries; register/alarm names from `/meta/*`; `Intl` for dates/numbers; choice in localStorage (try/catch).
Mock server `tools/mock_server.mjs`: full REST/WS contract with simulated MEX150 (drifting temp/hum, stage logic, random alarms); `--proxy http://192.168.10.150` forwards to device.

## 12. Tooling & tests
- `.vscode/settings.json`: from monitor with `IDF_PYTHON_ENV_PATH=/home/hajun/dev_ws/esp32-s3-gateway/.venv`. `tasks.json`: build (`uv run --locked python tools/idf.py build`), host tests (`uv run --locked pytest -q`), web (`npm run build:web`, `npm test`), mock server, flash+monitor, hw_smoke.
- Host tests (pytest compiling `.so` with cc; crypto backend `crypto_openssl.c` `-lcrypto`): frame/CRC/response; regmap ranges/sentinels/interlocks/signed decode + equivalence with legacy monitor `mex_validate`; poll plan; alarm engine (debounce, comm-loss suppression, ack); rules; config_json (defaults, validate, migrate, malformed/fuzz); auth (PBKDF2 vectors, record parse/verify, policy, rate limit, session expiry); ip_filter; snmpv3 crypto (RFC 3414/3826); history ring/aggregation/decimation; MIB pysmi compile; API contract (JSON Schemas vs mock server).
- Web: `node --test` (decimate, ring, ticks, i18n key parity, fmt).
- Hardware checklist in `docs/HW_TEST.md` (see PLAN.ko.md 검증 section).

## 13. Frozen interfaces (Phase 0 deliverable) — parallel streams code only against these
`gw_core/gw_events.h`, `gw_core/gw_crypto.h`, `gw_core/gw_json_writer.h`, `mex150/regmap.h` + `regmap.def`, `mex150/service.h`, `mex150/model.h`, `store/config.h`, `store/history.h`, `store/eventlog.h`, `store/persist.h`, `alarm/alarm.h` + `alarm_catalog.def`, `auth/auth.h`, `web/router.h`, `web/ws_hub.h`, `snmp_gw/registry.h`, `snmp_lwip/snmp_transport.h`, `net/net.h`, `board/board.h`, `sysmgr/sysmgr.h`, `docs/API.md` + `docs/api/*.schema.json`.

Parallel streams (Phase 1), each owns disjoint directories:
A Modbus (`components/mex150`, tests), B store+alarm (`components/store`, `components/alarm`), C web backend+auth (`components/web` except generated assets, `components/auth`), D front-end (`web/`, `tools/mock_server.mjs`, `tools/build_web.mjs`, `package-lock.json`), E SNMP (`components/snmp_lwip`, `components/snmp_gw`, `tools/gen_mib.py`, `cmake/gw_mib.cmake`), F net/board/sysmgr (`components/net`, `components/board`, `components/sysmgr`), G tooling (`tools/gen_web_assets.py`, `cmake/gw_web_assets.cmake`, `tools/hw_smoke.py`, `tools/snmp_smoke.py`, VS Code tasks). `components/gw_core/*.c` files are assigned one by one in ARCHITECTURE.md §7; `main/app_main.c` belongs to the Phase-2 integrator. Each stream owns the `CMakeLists.txt` of its components (edges limited to ARCHITECTURE.md §1).

## 14. Risks
SNMP crypto on mbedTLS 4.1 (own PSA backend); W5500 component/pins (INT 12 not 4; RST 39 unverified; no factory MAC); RS485 auto-direction echo/turnaround (configurable gap/timeout); internal RAM gate `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) > 60 KB` with AP up + 4 WS + SNMP walk; node on PATH in VS Code build; PBKDF2 latency on httpd task (async handler if >400 ms); AP/Ethernet subnet overlap validation; strapping pins 0/45/46; placeholder PEN; universal default password (forced change); brand asset not cleared; **unsigned OTA images (accepted for v1: any admin session can install firmware; mitigated by Host/Origin/CSRF checks, forced password change and rate limiting; planned: `SECURE_SIGNED_APPS_NO_SECURE_BOOT` + `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT` with an offline key)**; Host allowlist means LAN DNS names other than the hostname cannot be used for the web UI.

## 15. HARD RULE for all implementers (user instruction, 2026-10-19)
No physical hardware connection or testing in this effort. **Never open, flash, monitor, or probe any serial/USB device** (`/dev/ttyACM*`, `/dev/ttyUSB*`, `idf.py flash/monitor`, esptool, `tools/run_device.py`, etc.) — the attached USB device belongs to another ongoing test. Verification is limited to: firmware compiles/links with IDF 6.1, host unit tests, web tests/build, mock-server based end-to-end checks. Hardware spikes (W5500 ping, MEX150 UART) are deferred to `docs/HW_TEST.md` for the user to run later.
