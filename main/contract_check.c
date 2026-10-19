/* Compile-time check of the frozen interfaces (DESIGN.md §13) with the IDF toolchain.
 *
 * Includes EVERY public header of every component, so header/IDF mismatches fail the firmware build,
 * and pins record layouts and cross-component constants with static asserts. Generates no code.
 * Shared file: any stream that adds a public header appends its #include line under its component's
 * comment below (tests/test_contracts.py checks the list), and may append static asserts for its
 * own constants. Table row counts are not pinned here; tests compare the C expansion with the
 * Python parse of the same .def files instead. */
#include <assert.h>
#include <stddef.h>

/* gw_core */
#include "gw_core/gw_b64.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_defs.h"
#include "gw_core/gw_drbg.h"
#include "gw_core/gw_err.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_ident.h"
#include "gw_core/gw_ip4.h"
#include "gw_core/gw_json_writer.h"
#include "gw_core/gw_ring.h"
#include "gw_core/gw_time.h"
/* board */
#include "board/board.h"
#include "board/board_io.h"
#include "board_pins.h"
/* mex150 */
#include "mex150/frame.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mex150/regmap.h"
#include "mex150/service.h"
/* store */
#include "store/atomic_file.h"
#include "store/config.h"
#include "store/config_json.h"
#include "store/eventlog.h"
#include "store/fs.h"
#include "store/history.h"
#include "store/persist.h"
#include "store/secrets.h"
/* alarm */
#include "alarm/alarm.h"
/* auth */
#include "auth/auth.h"
/* net */
#include "net/ip_filter.h"
#include "net/net.h"
/* web */
#include "web/router.h"
#include "web/web.h"
#include "web/web_assets.h"
#include "web/web_path.h"
#include "web/ws_hub.h"
/* snmp */
#include "snmp_gw/registry.h"
#include "snmp_gw/snmp_gw.h"
#include "snmp_lwip/snmpv3_util.h"
#include "snmp_transport.h"
/* sysmgr */
#include "sysmgr/sysmgr.h"

/* IDF facts the contracts depend on */
#include "esp_app_desc.h"
#include "hal/spi_types.h"
#include "hal/uart_types.h"
#include "lwip/apps/snmp_opts.h"
#include "sdkconfig.h"

#define FIELD_SIZE(type, member) sizeof(((type *)0)->member)

/* ---- Persistent / wire record layouts ---- */
static_assert(sizeof(evlog_rec_t) == 32, "event log record");
static_assert(offsetof(evlog_rec_t, user) == 16 && FIELD_SIZE(evlog_rec_t, user) == 12, "evlog user field");
static_assert(GW_USER_NAME_MAX <= FIELD_SIZE(evlog_rec_t, user), "user names fit the log record");
static_assert(EVLOG_RECS_PER_FILE * sizeof(evlog_rec_t) == EVLOG_FILE_BYTES, "evlog file size");
static_assert(sizeof(hist_fast_t) == 24, "history fast record");
static_assert(sizeof(hist_slow_t) == 40, "history slow (on-disk) record");
static_assert(sizeof(hist_file_hdr_t) == 16, "history file header");
static_assert(HIST_STG_COUNT == 5, "hist_slow_t.stage_on_s layout assumes 5 stage kinds");

/* ---- Event bus payloads ---- */
static_assert(
    sizeof(gw_evt_snapshot_t) <= GW_EVT_PAYLOAD_MAX && sizeof(gw_evt_comm_t) <= GW_EVT_PAYLOAD_MAX &&
        sizeof(gw_evt_alarm_t) <= GW_EVT_PAYLOAD_MAX && sizeof(gw_evt_write_t) <= GW_EVT_PAYLOAD_MAX &&
        sizeof(gw_evt_config_t) <= GW_EVT_PAYLOAD_MAX && sizeof(gw_evt_net_t) <= GW_EVT_PAYLOAD_MAX &&
        sizeof(gw_evt_time_t) <= GW_EVT_PAYLOAD_MAX && sizeof(gw_evt_ota_t) <= GW_EVT_PAYLOAD_MAX &&
        sizeof(gw_evt_session_t) <= GW_EVT_PAYLOAD_MAX && sizeof(gw_evt_tick_t) <= GW_EVT_PAYLOAD_MAX &&
        sizeof(gw_evt_reboot_t) <= GW_EVT_PAYLOAD_MAX,
    "gw_evt payloads");
static_assert((int)GW_ALARM_RAISE == (int)ALM_EV_RAISE && (int)GW_ALARM_CLEAR == (int)ALM_EV_CLEAR &&
                  (int)GW_ALARM_ACK == (int)ALM_EV_ACK,
              "alarm transition types");
static_assert(CFG_SEC_COUNT <= 255 && CFG_SEC_SECRETS <= 255, "cfg_section_t fits gw_evt_config_t.section");
static_assert(sizeof(auth_sid_t) == FIELD_SIZE(gw_evt_session_t, sid), "session id width");

/* ---- Register map / alarm catalog ---- */
static_assert(MEX_COIL_COUNT == MEX_COILS_LEN, "regmap.def must describe every coil");
static_assert(ALM_COUNT <= 32, "alarm masks are uint32_t");
static_assert(MEX_ADDR_BASE + MEX_REGS_LEN - 1 >= 40059, "regs[] covers the highest mapped register");
static_assert(FIELD_SIZE(mex_snapshot_t, regs) == MEX_REGS_LEN * sizeof(uint16_t), "snapshot regs");
static_assert(FIELD_SIZE(mex_snapshot_t, coils) * 8 >= MEX_COILS_LEN, "snapshot coils");
static_assert(FIELD_SIZE(alm_engine_t, slot) / FIELD_SIZE(alm_engine_t, slot[0]) == GW_MAX_DEVICES,
              "alarm slots");
static_assert(FIELD_SIZE(mex_dev_cfg_t, name) == GW_DEV_NAME_SZ, "device name");
static_assert(FIELD_SIZE(alm_engine_t, enabled) == GW_MAX_DEVICES, "alarm enabled flags");

/* ---- Health / audit encodings ---- */
static_assert(GW_HB_COUNT <= 32 && (GW_HB_REQUIRED_MASK >> GW_HB_COUNT) == 0, "heartbeat masks");
static_assert(EVLOG_REASON_FROM_BYTE(EVLOG_REASON_BYTE(MEX_R_EXCEPTION(4))) == MEX_R_EXCEPTION(4) &&
                  EVLOG_REASON_FROM_BYTE(EVLOG_REASON_BYTE(MEX_R_INTERLOCK)) == MEX_R_INTERLOCK &&
                  EVLOG_REASON_BYTE(MEX_R_EXCEPTION(4)) != EVLOG_REASON_BYTE(MEX_R_INTERLOCK),
              "AUD_REG_WRITE reason byte round-trips and keeps exceptions distinct");
static_assert(FIELD_SIZE(mex_wresult_t, raw_after) == 4 && FIELD_SIZE(gw_evt_write_t, raw_after) == 4,
              "write results carry decoded raw (int32)");
static_assert(CFG_AP_IP == 0xC0A89601u && CFG_AP_MASK == 0xFFFFFF00u,
              "AP address fixed by contract (API.md)");
static_assert(GW_AP_PSK_DEFAULT_LEN >= GW_PSK_MIN && GW_AP_PSK_DEFAULT_LEN <= GW_PSK_MAX,
              "factory AP PSK length");

/* ---- Crypto / auth sizes ---- */
static_assert(AUTH_TOKEN_B64_LEN == GW_B64_URL_LEN(AUTH_TOKEN_BYTES), "session token encoding");
static_assert(AUTH_DK_LEN == GW_SHA256_LEN, "PBKDF2 derived key");
static_assert(SEC_V3_KEY_LEN == GW_SHA1_LEN && SEC_V3_KEY_LEN >= GW_AES128_KEY_LEN, "SNMPv3 key length");
static_assert(GW_ENGINE_ID_LEN <= 32, "engine id <= SNMP_V3_MAX_ENGINE_ID_LENGTH");

/* ---- SNMP ---- */
static_assert(GW_COMMUNITY_MAX == SNMP_MAX_COMMUNITY_STR_LEN, "community length == project lwIP define");
static_assert(SNMP_COMMUNITY_SZ == GW_COMMUNITY_SZ, "transport community buffer");
static_assert(SNMP_GW_OID_MAX <= SNMP_MAX_OBJ_ID_LEN, "gateway OID buffers");
static_assert(GW_SNMP_USER_MAX <= 32, "v3 user name <= SNMP_V3_MAX_USER_LENGTH");
static_assert(GW_SNMP_USER_SZ <= SNMP_COMMUNITY_SZ, "snmp_ctx user buffer");

/* ---- IDF facts ---- */
static_assert(GW_VERSION_SZ == FIELD_SIZE(esp_app_desc_t, version), "version string size");
static_assert(BOARD_ETH_SPI_HOST == SPI2_HOST, "W5500 on SPI2");
static_assert(BOARD_RS485_UART == UART_NUM_1, "RS485 on UART1");
/* gw_err.h host fallback must carry IDF's exact values. */
static_assert(ESP_OK == 0 && ESP_FAIL == -1 && ESP_ERR_NO_MEM == 0x101 && ESP_ERR_INVALID_ARG == 0x102 &&
                  ESP_ERR_INVALID_STATE == 0x103 && ESP_ERR_INVALID_SIZE == 0x104 &&
                  ESP_ERR_NOT_FOUND == 0x105 && ESP_ERR_NOT_SUPPORTED == 0x106 && ESP_ERR_TIMEOUT == 0x107 &&
                  ESP_ERR_INVALID_RESPONSE == 0x108 && ESP_ERR_INVALID_CRC == 0x109 &&
                  ESP_ERR_INVALID_VERSION == 0x10A && ESP_ERR_INVALID_MAC == 0x10B &&
                  ESP_ERR_NOT_FINISHED == 0x10C && ESP_ERR_NOT_ALLOWED == 0x10D,
              "gw_err.h host codes");

/* ---- Stream F (board/net/sysmgr) ---- */
static_assert(BOARD_BTN_AP_MIN_MS < BOARD_BTN_AP_MAX_MS && BOARD_BTN_AP_MAX_MS < BOARD_BTN_RESET_MS &&
                  BOARD_BTN_RESET_MS < BOARD_BTN_RESET_CANCEL_MS,
              "BOOT gesture windows are ordered");
static_assert(BOARD_BTN_RESET_DISARMED > BOARD_BTN_RELEASED_RESET, "button events only appended");
static_assert(NET_APPLY_DELAY_S <= 60 && NET_CONFIRM_S >= 10 && NET_CONFIRM_S <= 3600, "net_prov limits");

/* Integrator (Phase 2) */
static_assert(MEX_REASON_NAME_SZ >= sizeof("running_interlock") && MEX_REASON_NAME_SZ >= sizeof("exception:255"),
              "mex_reason_name buffer must hold every wire name");
static_assert(sizeof(GW_NVS_NS_BOOTS) <= 16 && sizeof(GW_NVS_KEY_BOOTS) <= 16, "NVS names <= 15 chars");
static_assert(SYS_INIT_FAULT_CORE == 0x80u, "init fault bits are wire values (diag.init_faults)");
