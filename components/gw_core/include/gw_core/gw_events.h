/*
 * gw_events.h - gateway-internal event bus (ESP-IDF esp_event custom loop "gw_evt").
 *
 * Delivery model
 *   - One dedicated esp_event loop with its own task: name "gw_evt", priority 7, core 1,
 *     stack GW_EVT_TASK_STACK, queue GW_EVT_QUEUE_LEN. ALL handlers registered through this API
 *     run sequentially in that task, in registration order.
 *   - Handlers must be short (< 10 ms), must never block on the network or flash (enqueue to
 *     persist / ws_hub / snmp transport instead) and must post further events with timeout 0.
 *   - Payloads are copied by esp_event at post time; a handler's event_data pointer is valid only
 *     for the duration of the call. Every payload is a POD struct of at most GW_EVT_PAYLOAD_MAX
 *     bytes. Large data (snapshots, history) is fetched by the handler through the owning API.
 *   - Posting is allowed from any task (not from ISRs). gw_events_post() never blocks longer
 *     than timeout_ms; on a full queue the event is dropped and counted.
 *
 * Producers (who posts what) are listed per ID. Consumers are documented in docs/ARCHITECTURE.md.
 */
#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_event.h"
#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

ESP_EVENT_DECLARE_BASE(GW_EVENT);

#define GW_EVT_TASK_NAME "gw_evt"
#define GW_EVT_TASK_PRIO 7
#define GW_EVT_TASK_CORE 1
#define GW_EVT_TASK_STACK 6144
#define GW_EVT_QUEUE_LEN 32
#define GW_EVT_PAYLOAD_MAX 64 /* bytes; enforced by static asserts below */

/** Event IDs on base GW_EVENT. Values are stable (used in logs/diagnostics). */
typedef enum {
    GW_EVT_SNAPSHOT = 0,       /* gw_evt_snapshot_t; mex_poll after each successful poll cycle */
    GW_EVT_COMM = 1,           /* gw_evt_comm_t; mex_poll when an enabled device's state is decided/changes */
    GW_EVT_ALARM = 2,          /* gw_evt_alarm_t; alarm engine on raise/clear/ack (already logged) */
    GW_EVT_WRITE_RESULT = 3,   /* gw_evt_write_t; mex_poll when a queued write reaches a final state */
    GW_EVT_CONFIG_CHANGED = 4, /* gw_evt_config_t; cfg_commit()/secrets commit after the in-RAM swap */
    GW_EVT_NET_STATE = 5,      /* gw_evt_net_t; net_mgr on link/IP/AP/provisional-state changes */
    GW_EVT_TIME_SYNC = 6,      /* gw_evt_time_t; gw_time_set_wall_ms() (RTC boot load, NTP, browser) */
    GW_EVT_OTA = 7,            /* gw_evt_ota_t; sysmgr OTA writer / supervisor */
    GW_EVT_SESSION = 8,        /* gw_evt_session_t; auth on login/logout/expiry/revocation */
    GW_EVT_SYS_TICK = 9,       /* gw_evt_tick_t; gw_core 1 Hz esp_timer (history/rules/WS/EVT beat) */
    GW_EVT_REBOOT = 10,        /* gw_evt_reboot_t; sysmgr when a reboot/factory reset is scheduled */
    GW_EVT_ID_COUNT
} gw_event_id_t;

/* ---- Payloads ---- */

/** GW_EVT_SNAPSHOT: a new complete snapshot is available via mex_service_snapshot(dev). */
typedef struct {
    uint8_t dev;      /* device index 0..GW_MAX_DEVICES-1 */
    bool slow_fresh;  /* this cycle also refreshed the slow register group */
    uint32_t seq;     /* == mex_snapshot_t.seq */
    uint64_t mono_ms; /* == mex_snapshot_t.mono_ms */
} gw_evt_snapshot_t;

/**
 * GW_EVT_COMM: communication state of an ENABLED device was decided or changed.
 *   - Every enabled device starts in an "unknown" state (no event) at boot and after
 *     mex_service_reconfigure() changed its slave or enabled it. The first decision is posted even
 *     if nothing was "online" before: online=true after the first successful cycle, online=false
 *     after offline_after consecutive failed cycles (e.g. cable unplugged at power-up).
 *   - Afterwards an event is posted on every online<->offline transition (never twice in a row
 *     with the same `online`).
 *   - Disabled devices are not polled and never produce COMM. Disabling a device posts nothing;
 *     consumers learn it from CONFIG_CHANGED{MODBUS} (alarm clears that device's alarms with
 *     alm_engine_set_enabled(); the supervisor's COMM_LOST LED only considers enabled devices).
 */
typedef struct {
    uint8_t dev;
    bool online;
    int16_t last_err;       /* last transaction result: 0 ok, >0 Modbus exception, <0 MEX_TXN_E_* */
    uint32_t offline_count; /* == mex_stats_t.offline_count after this transition */
    int64_t ts_ms;          /* wall clock ms UTC (0 if wall time invalid) */
} gw_evt_comm_t;

typedef enum { GW_ALARM_RAISE = 1, GW_ALARM_CLEAR = 2, GW_ALARM_ACK = 3 } gw_alarm_type_t;

/** GW_EVT_ALARM: alarm transition (already appended to the event log with seq). */
typedef struct {
    uint8_t dev;
    uint8_t type;               /* gw_alarm_type_t */
    uint8_t sev;                /* alm_sev_t (after overrides) */
    uint16_t code;              /* alarm catalog code (alarm_catalog.def) */
    int16_t value;              /* raw x scale of the related register, 1 for pure bit alarms */
    uint32_t seq;               /* event-log sequence number of this transition */
    int64_t ts_ms;              /* wall ms UTC, 0 if invalid */
    char user[GW_USER_NAME_SZ]; /* acknowledging user for GW_ALARM_ACK, else "" */
} gw_evt_alarm_t;

/**
 * GW_EVT_WRITE_RESULT: a register write reached APPLIED, REJECTED or UNCERTAIN. Also posted for a
 * write rejected at enqueue (cmd = 0) and for a full queue (REJECTED/MEX_R_BUSY, cmd = 0), so every
 * write attempt is audited and broadcast (service.h). Not posted for an unknown device index.
 */
typedef struct {
    uint8_t dev;
    uint8_t state;            /* mex_wstate_t (never MEX_W_PENDING) */
    uint16_t addr;            /* 4xxxx register address */
    int16_t reason;           /* mex_reason_t / MEX_R_EXCEPTION(n); 0 when applied */
    uint32_t cmd;             /* command id returned by mex_service_write() */
    int32_t raw_req;          /* requested raw value as passed to mex_service_write() (0/1 for 40005) */
    int32_t raw_before;       /* register raw (mex_reg_decode, regmap.h) from the last snapshot */
    int32_t raw_after;        /* register raw read back; == raw_before when nothing was read back */
    char by[GW_USER_NAME_SZ]; /* web user name, or a non-web principal "@snmp"/"@console" (see service.h) */
} gw_evt_write_t;

/** GW_EVT_CONFIG_CHANGED: a configuration section was committed (validated, swapped, queued). */
typedef struct {
    uint8_t section; /* cfg_section_t; CFG_SEC_SECRETS for secrets-only changes */
    uint32_t rev;    /* gw_config_t.rev after the commit */
    char by[GW_USER_NAME_SZ];
} gw_evt_config_t;

typedef enum { GW_NETIF_ETH = 0, GW_NETIF_AP = 1 } gw_netif_t;

/** GW_EVT_NET_STATE: interface state changed (see net.h for semantics). */
typedef struct {
    uint8_t netif;         /* gw_netif_t */
    bool link_up;          /* ETH: PHY link; AP: AP running */
    bool has_ip;           /* ETH: address assigned (static applied or DHCP lease) */
    uint8_t prov;          /* net_prov_state_t (ETH only) */
    uint8_t ap_clients;    /* AP only */
    uint32_t ip, mask, gw; /* host byte order; 0 when not assigned */
} gw_evt_net_t;

typedef enum {
    GW_TIME_SRC_RTC = 0,
    GW_TIME_SRC_NTP = 1,
    GW_TIME_SRC_BROWSER = 2,
    GW_TIME_SRC_CONSOLE = 3
} gw_time_src_t;

/** GW_EVT_TIME_SYNC: system wall clock was set. */
typedef struct {
    uint8_t source;   /* gw_time_src_t */
    bool first_valid; /* wall time became valid for the first time since boot */
    int64_t wall_ms;  /* new wall time ms UTC */
    int64_t delta_ms; /* new - old (0 if old was invalid) */
    char by[GW_USER_NAME_SZ];
} gw_evt_time_t;

typedef enum {
    GW_OTA_BEGIN = 0,     /* upload accepted, writing */
    GW_OTA_DONE = 1,      /* image verified, boot partition set, reboot scheduled */
    GW_OTA_FAILED = 2,    /* aborted (err holds esp_err_t) */
    GW_OTA_ROLLBACK = 3,  /* user-requested rollback, reboot scheduled */
    GW_OTA_PENDING = 4,   /* booted a new image in ESP_OTA_IMG_PENDING_VERIFY (posted at boot) */
    GW_OTA_VALIDATED = 5, /* supervisor marked the running image valid */
} gw_ota_phase_t;

/** GW_EVT_OTA: firmware update lifecycle. */
typedef struct {
    uint8_t phase; /* gw_ota_phase_t */
    int32_t err;   /* esp_err_t for GW_OTA_FAILED, else 0 */
    char version[GW_VERSION_SZ];
    char by[GW_USER_NAME_SZ];
} gw_evt_ota_t;

typedef enum {
    GW_SESSION_LOGIN = 0,
    GW_SESSION_LOGOUT = 1,  /* explicit logout */
    GW_SESSION_EXPIRED = 2, /* idle or absolute timeout */
    GW_SESSION_REVOKED = 3, /* password change, role change, user deletion, eviction */
} gw_session_kind_t;

/** GW_EVT_SESSION: a web session started or ended. WS clients bound to `sid` must be closed on end. */
typedef struct {
    uint8_t kind; /* gw_session_kind_t */
    uint32_t sid; /* auth_sid_t */
    char user[GW_USER_NAME_SZ];
} gw_evt_session_t;

/** GW_EVT_SYS_TICK: 1 Hz heartbeat posted by gw_core (esp_timer, not phase-locked to wall time). */
typedef struct {
    uint32_t uptime_s;
    bool time_valid;
    int64_t wall_ms; /* 0 if !time_valid */
    uint64_t mono_ms;
} gw_evt_tick_t;

typedef enum {
    GW_REBOOT_USER = 0,
    GW_REBOOT_OTA = 1,
    GW_REBOOT_ROLLBACK = 2,
    GW_REBOOT_FACTORY_RESET = 3,
    GW_REBOOT_CONFIG_IMPORT = 4,
    GW_REBOOT_CONSOLE = 5,
    GW_REBOOT_HEALTH = 6, /* supervisor gave up on a stuck task */
} gw_reboot_reason_t;

/** GW_EVT_REBOOT: the device will restart in `in_ms` (WS sends bye, history flushes). */
typedef struct {
    uint8_t reason; /* gw_reboot_reason_t */
    uint32_t in_ms;
} gw_evt_reboot_t;

static_assert(sizeof(gw_evt_snapshot_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_comm_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_alarm_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_write_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_config_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_net_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_time_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_ota_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_session_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_tick_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");
static_assert(sizeof(gw_evt_reboot_t) <= GW_EVT_PAYLOAD_MAX, "payload too large");

/* ---- API ---- */

/**
 * Create the "gw_evt" loop/task, start the 1 Hz GW_EVT_SYS_TICK timer and register the first
 * SYS_TICK handler, which beats GW_HB_EVT (gw_core/gw_health.h).
 * Call once from app_main (init order step 6). Idempotent: returns ESP_OK if already running.
 */
esp_err_t gw_events_init(void);

/**
 * Post an event. `data` (may be NULL when len == 0) is copied; len must equal the payload struct
 * size for `id` and be <= GW_EVT_PAYLOAD_MAX. Any task, not ISR. From inside a gw_evt handler
 * timeout_ms MUST be 0 (a full queue would otherwise deadlock).
 * @return ESP_OK, ESP_ERR_TIMEOUT (queue full: dropped and counted), ESP_ERR_INVALID_STATE (not
 *         initialised), ESP_ERR_INVALID_ARG.
 */
esp_err_t gw_events_post(gw_event_id_t id, const void *data, size_t len, uint32_t timeout_ms);

/**
 * Register `handler` for `id` (or ESP_EVENT_ANY_ID) on base GW_EVENT. The handler runs in the
 * gw_evt task with event_base == GW_EVENT. `instance` (optional) receives the handle for
 * gw_events_unregister(). Safe to call before or after gw_events_init() has started dispatching;
 * registrations made before gw_events_init() return ESP_ERR_INVALID_STATE.
 */
esp_err_t gw_events_register(int32_t id, esp_event_handler_t handler, void *arg,
                             esp_event_handler_instance_t *instance);

/** Unregister a handler previously registered with gw_events_register(). Any task except gw_evt. */
esp_err_t gw_events_unregister(int32_t id, esp_event_handler_instance_t instance);

/** Number of events dropped because the queue was full since boot (diagnostics). Any task. */
uint32_t gw_events_dropped(void);

/** True when the caller runs in the gw_evt task (for asserts in handlers/APIs). */
bool gw_events_in_loop_task(void);

#ifdef __cplusplus
}
#endif
