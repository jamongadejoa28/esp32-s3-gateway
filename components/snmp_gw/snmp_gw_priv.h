/*
 * snmp_gw_priv.h - internals shared by the snmp_gw sources (device only; private to the component).
 *
 * Threading: functions marked [agent] run only in the snmp_agent task (snmp_transport.h); their data
 * needs no lock. [any] functions are thread-safe (short mutex or atomics) and are called from the
 * gw_evt handlers and the httpd worker as well.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmpv3.h"
#include "snmp_gw/registry.h"
#include "snmp_gw/snmp_gw.h"
#include "snmp_logic.h"
#include "snmp_transport.h"
#include "store/config.h"
#include "store/secrets.h"

#define SGW_WHO "@snmp"          /* principal of SNMP writes (audit, events) */
#define SGW_SET_WAIT_MS 1000u    /* mexSetpointTable SET waits this long for the write result */
#define SGW_TEST_POST_MS 100u    /* httpd worker: wait for room in the agent queue */
#define SGW_EVENT_SEED_BATCH 8u  /* evlog_query batch when seeding the alarm event table at start */
#define SGW_COLD_RETRY_MS 1000u  /* coldStart retry period while a target has no route */
#define SGW_COLD_WINDOW_MS 300000u /* ...for at most this long after agent start */
#define SGW_AUTH_TRAP_RATE 1u    /* authenticationFailure: own token bucket (per s) ... */
#define SGW_AUTH_TRAP_BURST 2u   /* ... separate from the alarm/comm bucket */
#define SGW_LOG_INTERVAL_MS 10000u /* repeated warnings (rate limit, auth failures) at most this often */

_Static_assert(SNMP_MSG_BYTES_MAX == SNMP_MSG_MAX, "snmp_logic.h message size");

/* lwIP values from its private snmp_msg.h / snmpv3_priv.h (not on snmp_gw's include path). */
#define SGW_SNMP_V1 0             /* SNMP_VERSION_1 */
#define SGW_SNMP_V2C 1            /* SNMP_VERSION_2c */
#define SGW_SNMP_V3 3             /* SNMP_VERSION_3 */
#define SGW_V3_KEY_BUF 20         /* lwIP key buffers (u8_t key[20], SNMP_V3_SHA_LEN) */
#define SGW_V3_USER_BUF 33        /* SNMP_V3_MAX_USER_LENGTH (32) + 1 */
_Static_assert(SEC_V3_KEY_LEN == SGW_V3_KEY_BUF, "localized key length = lwIP key buffer");
_Static_assert(GW_SNMP_USER_SZ <= SGW_V3_USER_BUF, "user names fit lwIP's buffer");

/* ---------------------------------------------------------------- agent messages */

typedef enum {
    /* 1 was SGW_MSG_APPLY: configuration applies use an atomic flag (agent.c), never the queue */
    SGW_MSG_ALARM = 2,    /* gwAlarmRaised / gwAlarmCleared */
    SGW_MSG_COMM = 3,     /* COMM transition -> coalescer */
    SGW_MSG_CONFIG = 4,   /* gwConfigChanged */
    SGW_MSG_FIRMWARE = 5, /* gwFirmwareUpdated */
    SGW_MSG_TEST = 6,     /* gwTestNotification (snmp_gw_test_trap) */
} sgw_msg_type_t;

typedef struct {
    uint8_t type; /* sgw_msg_type_t */
    union {
        struct {
            uint8_t dev, sev;
            bool raised;
            uint16_t code;
            int16_t value;
            uint32_t seq;
            int64_t ts_ms;
        } alarm;
        struct {
            uint8_t dev;
            bool online;
        } comm;
        struct {
            uint8_t section;
            uint32_t rev;
        } config;
        struct {
            char version[GW_VERSION_SZ];
        } fw;
        struct {
            uint32_t gen;
        } test;
    } u;
} sgw_msg_t;

_Static_assert(sizeof(sgw_msg_t) <= SNMP_MSG_MAX, "agent message must fit the transport queue");

/** [any] Post a message to the agent without blocking (gw_evt-safe). */
esp_err_t sgw_post(const sgw_msg_t *m, uint32_t timeout_ms);

/* ---------------------------------------------------------------- agent state (agent.c) */

typedef struct {
    uint8_t id; /* device index 0..GW_MAX_DEVICES-1 (GwDevIndex = id + 1) */
    uint8_t slave;
    bool enabled;
    char name[GW_DEV_NAME_SZ];
} sgw_dev_t;

/** [agent] Configured devices, ascending id (refreshed on every configuration apply). */
uint8_t sgw_dev_count(void);
const sgw_dev_t *sgw_dev_at(uint8_t i);
/** [agent] Device for a GwDevIndex (1-based), or NULL when not configured. */
const sgw_dev_t *sgw_dev_by_index(uint32_t dev_index);

/** [agent] Snapshot freshness for mexStatusValid / mexRegValid: the poll-aware window of
 * alm_sample_fresh() (same as REST/WS `fresh`, writes at enqueue and the rule pass). */
bool sgw_snap_fresh(const mex_snapshot_t *s);

/** [agent] sysName/sysContact/sysLocation as served (configured value or its fallback). */
typedef enum { SGW_SYS_CONTACT = 0, SGW_SYS_NAME = 1, SGW_SYS_LOCATION = 2 } sgw_sys_t;
const char *sgw_sys_string(sgw_sys_t which);
/** [agent] Update one cached string after a successful SET (before CONFIG_CHANGED arrives). */
void sgw_sys_string_set(sgw_sys_t which, const char *value);

/** [agent] Engine identity used by usm.c. */
const uint8_t *sgw_engine_id(uint8_t *len);
uint32_t sgw_engine_boots(void);
void sgw_engine_boots_set(uint32_t boots);
uint32_t sgw_engine_time(void);
void sgw_engine_time_reset(void);

/** [any] Base MAC and firmware version (set once at start). */
const uint8_t *sgw_mac(void);
const char *sgw_fw_version(void);

/** [any] sysUpTime in centiseconds since boot (same formula as snmp_lwip's trap timestamps). */
uint32_t sgw_uptime_cs(void);

/** [any] Last register write (any origin), fed by GW_EVT_WRITE_RESULT and SNMP SETs. */
typedef struct {
    bool valid;
    uint8_t dev;
    uint8_t state; /* mex_wstate_t */
    uint16_t addr;
    int32_t raw_req;
    int32_t reason;
    uint32_t cmd;
    int64_t ts_ms;
    char by[GW_USER_NAME_SZ];
} sgw_last_write_t;
void sgw_last_write_get(sgw_last_write_t *out);
void sgw_last_write_put(const sgw_last_write_t *in);
/** [any] Store a PENDING record unless the record already holds this command (or a later one). */
void sgw_last_write_put_pending(const sgw_last_write_t *in);

/** [agent] Principal (write origin / acknowledging user) as served to the current requester
 * (snmp_principal_view with "authenticated" = SNMPv3 request). */
const char *sgw_principal(const char *by);

/** [any] Last configuration change seen (section name, "" if none since boot). */
void sgw_last_config_get(char out[16]);

/** [any] Alarm event table (mib_alarm): copy of the event with seq, or of the whole ring. */
bool sgw_event_get(uint32_t seq, snmp_alarm_ev_t *out);
void sgw_events_copy(snmp_evring_t *out);

/* ---------------------------------------------------------------- usm.c */

/** [agent] Rebuild the USM table from configuration and secrets (snmp_gw.h USM contract). */
void sgw_usm_configure(const cfg_snmp_t *cfg, const sec_v3_keys_t *keys);

/* ---------------------------------------------------------------- traps.c */

typedef struct {
    bool enabled; /* SNMP enabled (snmp.enabled && security.svc_snmp) */
    bool auth_traps;
    uint8_t n;
    cfg_trap_t traps[GW_MAX_TRAP_TARGETS];
    char community[GW_MAX_TRAP_TARGETS][GW_COMMUNITY_SZ];
} sgw_trap_cfg_t;

/** [agent] One-time init (token bucket, coalescer, inform table, enterprise OID). */
void sgw_traps_init(void);
/** [agent] Apply targets/communities (copied; caller wipes cfg). */
void sgw_traps_configure(const sgw_trap_cfg_t *cfg);
/** [agent] Handle a queued notification message (ALARM/COMM/CONFIG/FIRMWARE/TEST). */
void sgw_traps_on_msg(const sgw_msg_t *m);
/** [agent] Periodic work: comm coalescer reports, inform retransmissions/give-ups. */
void sgw_traps_on_idle(uint64_t now_ms);
/** [agent] coldStart to every enabled target (agent start; retried until each target was reached or
 * SGW_COLD_WINDOW_MS passed, so it survives a link/DHCP that is not up yet). */
void sgw_traps_cold_start(void);
/** [agent] authenticationFailure fan-out (transport on_auth_fail hook). */
void sgw_traps_auth_fail(uint32_t peer_ip);
/** [agent] Transport hooks for inform acknowledgements. */
bool sgw_traps_inform_peer(uint32_t peer_ip, char community[SNMP_COMMUNITY_SZ]);
void sgw_traps_inform_ack(int32_t request_id, uint32_t peer_ip);
/** [any] Counters for gwInfo. */
uint32_t sgw_traps_sent(void);
uint32_t sgw_traps_dropped(void);
uint32_t sgw_informs_failed(void);
/** [any] Count a notification that could not even be queued. */
void sgw_traps_count_drop(void);
/** [any] snmp_gw_test_trap() implementation (traps.c). */
size_t sgw_traps_test(snmp_gw_test_result_t *out, size_t cap, uint32_t timeout_ms);
/** [any] Create the test-trap synchronisation objects (snmp_gw_start, before the agent runs). */
esp_err_t sgw_traps_sync_init(void);

/* ---------------------------------------------------------------- MIB helpers (mib_util.c) */

/** Fill a module base OID (mestioGwMIB + suffix); returns its length (0 on overflow, logged). */
uint8_t sgw_oid(uint32_t *out, size_t cap, const uint32_t *suffix, size_t n);

/** Copy a string value into lwIP's value buffer (<= max bytes); returns the length. */
s16_t sgw_value_str(void *value, const char *s, size_t max);
/** DateAndTime (11 octets) of a wall time in ms (0 -> 1970-01-01). Returns 11. */
s16_t sgw_value_date(void *value, int64_t wall_ms);
static inline s16_t sgw_value_s32(void *value, int32_t v) {
    *(s32_t *)value = v;
    return (s16_t)sizeof(s32_t);
}
static inline s16_t sgw_value_u32(void *value, uint32_t v) {
    *(u32_t *)value = v;
    return (s16_t)sizeof(u32_t);
}

/** Table helpers for tables indexed by GwDevIndex only (configured devices). */
snmp_err_t sgw_dev_row_get(const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell);
snmp_err_t sgw_dev_row_next(struct snmp_obj_id *row_oid, struct snmp_node_instance *cell);
/** Device id stored by the helpers in cell->reference. */
static inline uint8_t sgw_cell_dev(const struct snmp_node_instance *cell) {
    return (uint8_t)cell->reference.u32;
}
/** Column number of a table cell (lwIP: instance_oid = 1.<column>.<row>). */
static inline u32_t sgw_cell_column(const struct snmp_node_instance *cell) {
    return cell->instance_oid.id[1];
}

/* ---------------------------------------------------------------- MIB modules */

extern const snmp_module_t sgw_mod_system;
extern const snmp_module_t sgw_mod_framework;
extern const snmp_module_t sgw_mod_usm;
extern const snmp_module_t sgw_mod_gw;
extern const snmp_module_t sgw_mod_dev;
extern const snmp_module_t sgw_mod_mex_status;
extern const snmp_module_t sgw_mod_mex_setpoint;
extern const snmp_module_t sgw_mod_mex_regs;
extern const snmp_module_t sgw_mod_alarm;
extern const snmp_module_t sgw_mod_comm;
