/*
 * alarm.h - alarm catalog, pure alarm engine, and the alarm service (DESIGN.md §8).
 *
 * Engine semantics (pure, host-tested):
 *   - Device alarms (SRC_COIL / SRC_BIT) are evaluated on every successful poll
 *     (alm_engine_feed_snapshot): raise after debounce_raise consecutive polls with the bit set,
 *     clear after debounce_clear consecutive polls with it clear.
 *   - comm_lost is raised/cleared immediately by alm_engine_feed_comm() (the poller already
 *     debounces with offline_after, and also reports a device that never came online after boot,
 *     see gw_events.h GW_EVT_COMM). While a device is offline its device and rule alarms are
 *     FROZEN: no raise, no clear, counters reset when it returns.
 *   - A disabled (or unconfigured) device has no alarms: alm_engine_set_enabled(false) clears all
 *     of its active alarms (CLEAR emitted for each) and later feeds for it are ignored.
 *   - Rules (SRC_RULE) run on 1 Hz samples (alm_engine_tick_rules): GT raises when v > thr held
 *     for delay_s, clears when v <= thr - hyst (LT mirrored); a disabled/removed rule clears.
 *   - Ack marks an active alarm acknowledged (who/when); it never clears it. A clear removes the
 *     alarm from the active set whether acked or not. Each raise/clear/ack is emitted once.
 * Service (alarm.c): engine instance behind a mutex, fed by gw_evt handlers (SNAPSHOT, COMM,
 * SYS_TICK, CONFIG_CHANGED{ALARMS, MODBUS}); each transition is appended to the EVENTS log and then
 * posted as GW_EVT_ALARM (consumers: ws, snmp traps, syslog, LED). Its SYS_TICK handler also drives
 * the 1 Hz history sampler: for every dev it calls history_sample() (store/history.h) with
 * any_alarm = alarm mask != 0, after evaluating the rules. Query/ack functions are callable from
 * any task except ISRs.
 */
#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "mex150/service.h"
#include "store/config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { ALM_SEV_INFO = 0, ALM_SEV_MINOR = 1, ALM_SEV_MAJOR = 2, ALM_SEV_CRITICAL = 3 } alm_sev_t;
typedef enum { ALM_SRC_COIL = 0, ALM_SRC_BIT = 1, ALM_SRC_COMM = 2, ALM_SRC_RULE = 3 } alm_src_t;
typedef enum { ALM_EV_RAISE = 1, ALM_EV_CLEAR = 2, ALM_EV_ACK = 3 } alm_ev_type_t; /* == gw_alarm_type_t */

/* Catalog IDs in alarm_catalog.def order (ALM_blower_fault ... ALM_rule_8). */
typedef enum {
#define ALM(id, ...) ALM_##id,
#include "alarm/alarm_x.h"
    ALM_COUNT
} alm_id_t;

static_assert(ALM_COUNT <= 32, "alarm masks are uint32_t");

typedef struct {
    const char *id; /* stable wire id, e.g. "high_temp" */
    uint16_t code;  /* stable numeric code */
    alm_src_t src;
    uint16_t addr; /* coil number / register / rule id */
    uint8_t bit;
    alm_sev_t sev; /* default severity */
    uint16_t vreg; /* value register or 0 */
    const char *ko;
    const char *en;
} alm_desc_t;

extern const alm_desc_t alm_catalog[ALM_COUNT];

const alm_desc_t *alm_find_code(uint16_t code);
const alm_desc_t *alm_find_id(const char *id);
/** True iff code is in the catalog. */
bool alarm_code_valid(uint16_t code);

/**
 * Catalog hooks for store (cfg_set_alarm_catalog(&alm_cfg_catalog) in app_main before
 * config_load()): id <-> code for every catalog entry except rule_* (not overridable).
 */
extern const cfg_alarm_catalog_t alm_cfg_catalog;
/** "info" | "minor" | "major" | "critical". */
const char *alm_sev_name(alm_sev_t s);

#define ALM_KEY_SZ 24 /* "<dev>:<id>", e.g. "0:high_temp" (REST/WS "key") */

void alm_key_format(uint8_t dev, alm_id_t id, char out[ALM_KEY_SZ]);
bool alm_key_parse(const char *key, uint8_t *dev, alm_id_t *id);

/** Active alarm as reported by the API. */
typedef struct {
    uint8_t dev;
    alm_id_t id;
    alm_sev_t sev;    /* effective severity */
    int16_t value;    /* raw of vreg at raise (or rule source), else 1 */
    int64_t since_ms; /* wall ms of raise (0 if wall time invalid then) */
    bool acked;
    int64_t ack_ms;
    char ack_by[GW_USER_NAME_SZ];
} alm_active_t;

/** One transition emitted by the engine. */
typedef struct {
    uint8_t dev;
    alm_id_t id;
    alm_ev_type_t type;
    alm_sev_t sev;
    int16_t value;
    int64_t ts_ms;
    char user[GW_USER_NAME_SZ]; /* ack only */
} alm_transition_t;

/** Called synchronously for each transition, with the engine in a consistent state. */
typedef void (*alm_emit_fn)(void *arg, const alm_transition_t *t);

/** Engine parameters (derived from cfg_alarms_t). */
typedef struct {
    uint8_t debounce_raise;
    uint8_t debounce_clear;
    uint8_t sev[ALM_COUNT]; /* effective severity: catalog default, then sev_override, rules from rule.sev */
    cfg_rule_t rules[GW_MAX_RULES];
    uint8_t n_rules;
} alm_params_t;

void alm_params_from_config(const cfg_alarms_t *c, alm_params_t *out);

/* Engine state. Fields are private to engine.c; exposed only for static allocation. */
typedef struct {
    bool active, acked;
    uint8_t up, down; /* debounce counters */
    int16_t value;
    int64_t since_ms, ack_ms;
    uint64_t pend_mono_ms; /* rule on-delay start, 0 = condition false */
    char ack_by[GW_USER_NAME_SZ];
} alm_slot_t;

typedef struct {
    alm_params_t p;
    alm_slot_t slot[GW_MAX_DEVICES][ALM_COUNT];
    bool online[GW_MAX_DEVICES];
    bool enabled[GW_MAX_DEVICES];
    alm_emit_fn emit;
    void *emit_arg;
} alm_engine_t;

/* ---- Pure engine ---- */
void alm_engine_init(alm_engine_t *e, const alm_params_t *p, alm_emit_fn emit, void *arg);
/** Replace parameters; rules removed or disabled are cleared (emitting CLEAR). */
void alm_engine_set_params(alm_engine_t *e, const alm_params_t *p, int64_t wall_ms);
/** One successful poll of dev (s->online true). */
void alm_engine_feed_snapshot(alm_engine_t *e, uint8_t dev, const mex_snapshot_t *s, int64_t wall_ms);
/** Communication state change of dev (ignored while dev is disabled). */
void alm_engine_feed_comm(alm_engine_t *e, uint8_t dev, bool online, int64_t wall_ms);
/**
 * Enable/disable dev (from cfg_modbus_t: configured and enabled). Disabling clears every active
 * alarm of dev (CLEAR emitted) and resets its counters; feeds and rule ticks for a disabled dev are
 * ignored. alm_engine_init() starts with every dev disabled; the service enables the configured ones
 * at alarm_init() and re-applies on CONFIG_CHANGED{MODBUS}.
 */
void alm_engine_set_enabled(alm_engine_t *e, uint8_t dev, bool enabled, int64_t wall_ms);
/**
 * Freshness of a snapshot for the 1 Hz rule/history pass, judged at the time of evaluation
 * (now_mono_ms read AFTER fetching the snapshot): online, mono_ms != 0, and age below
 * MEX_FRESH_MS, or below poll_ms + MEX_FRESH_MS when poll_ms > MEX_FRESH_MS (a long poll period
 * is not staleness; same window as mex150's enqueue check). A snapshot stamped after now_mono_ms
 * counts as age 0.
 */
bool alm_sample_fresh(const mex_snapshot_t *s, uint64_t now_mono_ms, uint32_t poll_ms);
/** 1 Hz rule evaluation for dev; s may be NULL or stale (fresh=false) -> rules frozen. */
void alm_engine_tick_rules(alm_engine_t *e, uint8_t dev, const mex_snapshot_t *s, bool fresh,
                           uint64_t mono_ms, int64_t wall_ms);
/** Ack: 0 = acked now (ACK emitted), 1 = already acked (no event), -1 = not active. */
int alm_engine_ack(alm_engine_t *e, uint8_t dev, alm_id_t id, const char *user, int64_t wall_ms);
/** Ack every unacked active alarm; returns how many were acked. */
size_t alm_engine_ack_all(alm_engine_t *e, const char *user, int64_t wall_ms);
/** Active alarms sorted by severity desc, then since asc. Returns the total active (may exceed cap). */
size_t alm_engine_active(const alm_engine_t *e, alm_active_t *out, size_t cap);
/** Bitmask (bit = alm_id_t) of active alarms of dev. */
uint32_t alm_engine_mask(const alm_engine_t *e, uint8_t dev);

/* ---- Service ---- */

/** Build the engine from config, register gw_evt handlers. After gw_events_init() and eventlog_init(). */
esp_err_t alarm_init(void);

/** Copy active alarms (see alm_engine_active). Any task. */
size_t alarm_get_active(alm_active_t *out, size_t cap);

/** Ack one alarm. ESP_OK (also if already acked), ESP_ERR_NOT_FOUND if not active. Audits AUD_ALARM_ACK. */
esp_err_t alarm_ack(uint8_t dev, alm_id_t id, const char *user);

/** Ack all; returns the number newly acked. Audits once (code 0). */
size_t alarm_ack_all(const char *user);

/** Active count per severity (index = alm_sev_t) and total. Any task. */
uint32_t alarm_counts(uint16_t per_sev[4]);

/** Active alarm mask of dev (history flags, SNMP). Any task. */
uint32_t alarm_mask(uint8_t dev);

#ifdef __cplusplus
}
#endif
