/*
 * snmp_gw.h - gateway SNMP agent facade: start, configuration, traps (DESIGN.md §10).
 *
 * snmp_gw_start() registers the built-in modules (mib_system, lwIP snmpframeworkmib/snmpusmmib,
 * mib_gw .1.1, mib_dev .1.2, mib_mex_status .1.3, mib_mex_setpoint .1.4, mib_mex_regs .1.5,
 * mib_alarm .1.6, mib_comm .1.7), starts the transport (agent thread always created), and
 * registers gw_evt handlers: ALARM -> gwAlarmRaised/Cleared, COMM -> gwCommLost/Restored
 * (coalesced), CONFIG_CHANGED -> gwConfigChanged + apply, OTA{VALIDATED} -> gwFirmwareUpdated.
 * Handlers only enqueue (snmp_transport_post); all lwIP calls happen in the agent task.
 *
 * Traps: v1/v2c only (lwIP has no v3 notifications), <= GW_MAX_TRAP_TARGETS, lwIP destination slot
 * 0 re-pointed per target (snmp_trap_dst_ip_set + snmp_transport_set_trap_port for its port, trap
 * community = that target's secret), token bucket SNMP_GW_TRAP_RATE/s, v2c informs retried
 * SNMP_GW_INFORM_RETRIES x SNMP_GW_INFORM_TIMEOUT_MS and matched by request id through the
 * transport hooks inform_peer/on_inform_ack. authenticationFailure (generic-trap 4 / snmpTraps.5)
 * is sent to every enabled target from the transport's on_auth_fail hook when
 * cfg_snmp_t.auth_traps is set; lwIP's built-in auth trap stays disabled. Notification OIDs:
 * …PEN.1.0.N (N below).
 *
 * USM contract (usm.c implements lwIP's snmpv3_get_user() & co., DESIGN.md §10). For a user name:
 *   - not one of the GW_MAX_SNMP_V3_USERS configured names, or a slot that is disabled
 *     (cfg_snmp_v3user_t.enabled false), has no keys (sec_v3_keys_t.set false), or v3 is disabled
 *     -> return ERR_VAL (lwIP answers usmStatsUnknownUserNames). This includes the empty name.
 *   - otherwise ALWAYS report SNMP_V3_AUTH_ALGO_SHA + SNMP_V3_PRIV_ALGO_AES with the stored
 *     localized keys, never *_ALGO_INVAL: lwIP accepts noAuthNoPriv for a user whose algorithms are
 *     INVAL (snmp_msg.c step 5), which would allow unauthenticated GET/SET as gwadmin.
 *   - call snmp_ctx_set_user(name, RO|RW) for a valid user (only the first call per request counts).
 * Engine-ID discovery (empty user, noAuthNoPriv) still works: lwIP answers it before user lookup.
 * Required test (stream E): a noAuthNoPriv GET as "gwadmin" must yield a usmStatsUnknownUserNames
 * or unsupportedSecLevel report, never data.
 *
 * All functions are non-blocking and callable from any task except where noted.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNMP_GW_TRAP_RATE 10
#define SNMP_GW_INFORM_RETRIES 3
#define SNMP_GW_INFORM_TIMEOUT_MS 5000
#define SNMP_GW_EVENTS_KEPT 32 /* mib_alarm last-events table */

/** Notification numbers under …PEN.1.0 (stable). */
typedef enum {
    SNMP_GW_TRAP_ALARM_RAISED = 1,
    SNMP_GW_TRAP_ALARM_CLEARED = 2,
    SNMP_GW_TRAP_COMM_LOST = 3,
    SNMP_GW_TRAP_COMM_RESTORED = 4,
    SNMP_GW_TRAP_CONFIG_CHANGED = 5,
    SNMP_GW_TRAP_FIRMWARE_UPDATED = 6,
    SNMP_GW_TRAP_TEST = 7,
} snmp_gw_trap_t;

/** Start the agent (init order step 12). Reads config/secrets; disabled config still starts the task. */
esp_err_t snmp_gw_start(void);

/** Re-read snmp/security config and secrets and apply them in the agent task (async). */
esp_err_t snmp_gw_apply_config(void);

/* Trap requests (also produced automatically from gw_evt; exposed for tests/console). */
esp_err_t snmp_gw_trap_alarm(uint8_t dev, uint16_t code, uint8_t sev, bool raised, int16_t value,
                             uint32_t seq, int64_t ts_ms);
esp_err_t snmp_gw_trap_comm(uint8_t dev, bool online);
esp_err_t snmp_gw_trap_config(uint8_t section, uint32_t rev);
esp_err_t snmp_gw_trap_firmware(const char *version);

typedef struct {
    char host[GW_HOST_SZ];
    bool ok; /* datagram sent (trap) or acknowledged (inform) */
} snmp_gw_test_result_t;

/**
 * Send gwTest… (SNMP_GW_TRAP_TEST) to every enabled target and wait up to timeout_ms for the
 * results (informs wait for the ack). Blocking: call from the httpd async worker, not gw_evt.
 * Returns the number of results written to out[cap].
 */
size_t snmp_gw_test_trap(snmp_gw_test_result_t *out, size_t cap, uint32_t timeout_ms);

/**
 * Localize an SNMPv3 passphrase for this agent's engine ID (RFC 3414 A.2, SHA: 1 MB expansion then
 * localization). ~100-300 ms; call from the httpd async worker when saving config. Never store
 * the passphrase. pass 8..64 UTF-8 bytes. Returns ESP_OK, ESP_ERR_INVALID_ARG (bad passphrase) or
 * ESP_ERR_INVALID_STATE (engine ID unavailable: base MAC unreadable; web answers 500).
 */
esp_err_t snmp_gw_localize_key(const char *pass, uint8_t out[20]);

/** This agent's engine ID (gw_ident_engine_id with the PEN and base MAC). Returns its length. */
size_t snmp_gw_engine_id(uint8_t *out, size_t cap);

/**
 * MIB text (gzip of the generated MESTIO-GW-MIB) embedded in the image, for GET /snmp/mib.
 * Build contract (owner: stream E): cmake/gw_mib.cmake, included from
 * components/snmp_gw/CMakeLists.txt after idf_component_register(), runs
 *   ${python} tools/gen_mib.py --regmap components/mex150/regmap.def
 *       --catalog components/alarm/alarm_catalog.def --pen ${CONFIG_GW_SNMP_ENTERPRISE_PEN}
 *       --out ${CMAKE_CURRENT_BINARY_DIR}/MESTIO-GW-MIB.txt.gz        (gzip -9, mtime 0)
 * as a custom command depending on both .def files and the generator, and embeds the result with
 * target_add_binary_data(${COMPONENT_LIB} <file> BINARY). The function returns
 * _binary_MESTIO_GW_MIB_txt_gz_start and sets *len = _end - _start. Never NULL (gen_mib.py and
 * Python are always available in the IDF build; a generator failure fails the build).
 */
const uint8_t *snmp_gw_mib_gz(size_t *len);

#ifdef __cplusplus
}
#endif
