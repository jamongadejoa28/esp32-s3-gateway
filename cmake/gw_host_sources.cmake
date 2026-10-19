# Pure-C sources (no ESP-IDF / FreeRTOS headers) shared by the firmware build and host tests.
# Paths are relative to the repository root. Host tests may parse the GW_HOST_SOURCES_*
# lists, so keep one quoted path per line inside each set(...).
# Ownership: each implementation stream appends its own files to its component's list.

set(GW_HOST_SOURCES_GW_CORE
  "components/gw_core/gw_crypto_util.c"
  "components/gw_core/gw_drbg.c"
  "components/gw_core/gw_snmp_key.c"
  "components/gw_core/gw_time_civil.c"
  "components/gw_core/gw_ident.c"
  "components/gw_core/gw_b64.c"
  "components/gw_core/gw_json_writer.c"
  "components/gw_core/gw_ip4.c"
)
set(GW_HOST_SOURCES_MEX150
  "components/mex150/frame.c"
  "components/mex150/regmap.c"
  "components/mex150/model.c"
  "components/mex150/poll_plan.c"
  "components/mex150/mex_core.c"
)
set(GW_HOST_SOURCES_STORE
  "components/store/atomic_file.c"
  "components/store/config.c"
  "components/store/config_json.c"
  "components/store/secrets.c"
  "components/store/history_core.c"
  "components/store/evlog_core.c"
)
set(GW_HOST_SOURCES_ALARM
  "components/alarm/catalog.c"
  "components/alarm/engine.c"
)
set(GW_HOST_SOURCES_AUTH
  "components/auth/password.c"
  "components/auth/policy.c"
  "components/auth/ratelimit.c"
  "components/auth/session_table.c"
)
set(GW_HOST_SOURCES_NET
  "components/net/ip_filter.c"
  "components/net/net_prov.c"
)
set(GW_HOST_SOURCES_BOARD
  "components/board/button_fsm.c"
  "components/board/pcf85063_codec.c"
)
set(GW_HOST_SOURCES_SYSMGR
  "components/sysmgr/ota_version.c"
  "components/sysmgr/syslog_fmt.c"
  "components/sysmgr/led_policy.c"
)
set(GW_HOST_SOURCES_SNMP_GW
  "components/snmp_gw/snmp_logic.c"
)
set(GW_HOST_SOURCES_WEB
  "components/web/web_path.c"
  "components/web/web_policy.c"
  "components/web/web_routes.c"
  "components/web/web_json.c"
  "components/web/web_csv.c"
  "components/web/ws_frame.c"
)

# Host-only replacements of device-only backends (never compiled by the IDF build).
set(GW_HOST_ONLY_SOURCES
  "components/gw_core/crypto_openssl.c"
)

# Third-party sources the pure code needs on the host (the IDF build gets them as managed
# components). tests/conftest.py compiles them without -Werror, adds the include dirs below and
# CJSON_NESTING_LIMIT/CJSON_CIRCULAR_LIMIT like the espressif/cjson component. They exist after the
# first `idf.py reconfigure`/build (managed_components/ is not committed).
set(GW_HOST_THIRD_PARTY_SOURCES
  "managed_components/espressif__cjson/cJSON/cJSON.c"
)
set(GW_HOST_THIRD_PARTY_INCLUDE_DIRS
  "managed_components/espressif__cjson/cJSON"
)

set(GW_HOST_SOURCES
  ${GW_HOST_SOURCES_GW_CORE}
  ${GW_HOST_SOURCES_MEX150}
  ${GW_HOST_SOURCES_STORE}
  ${GW_HOST_SOURCES_ALARM}
  ${GW_HOST_SOURCES_AUTH}
  ${GW_HOST_SOURCES_NET}
  ${GW_HOST_SOURCES_BOARD}
  ${GW_HOST_SOURCES_SYSMGR}
  ${GW_HOST_SOURCES_SNMP_GW}
  ${GW_HOST_SOURCES_WEB}
)
