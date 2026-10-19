/*
 * snmp_logic.h - pure (host-testable) building blocks of the gateway SNMP agent. Private to snmp_gw.
 *
 * Everything here is plain C11 without IDF, FreeRTOS or lwIP headers; snmp_logic.c is listed in
 * cmake/gw_host_sources.cmake (GW_HOST_SOURCES_SNMP_GW) and exercised by tests/test_snmp_logic.py.
 * None of these objects is thread-safe by itself: the agent keeps them in the snmp_agent task, or
 * behind its own lock where noted by the caller.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "snmp_gw/snmp_gw.h"
#include "store/config.h"
#include "store/secrets.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- OIDs */

/** 1.3.6.1.4.1.<pen>.1 followed by suffix[0..n) into out[cap]; total length or 0 if it does not fit
 * (or pen is 0 / suffix NULL with n > 0). */
size_t snmp_oid_build(uint32_t pen, const uint32_t *suffix, size_t n, uint32_t *out, size_t cap);

/* ---------------------------------------------------------------- token bucket */

/** Token bucket in milli-tokens: `rate` tokens per second, at most `burst` tokens stored. */
typedef struct {
    uint32_t rate;
    uint32_t burst;
    uint64_t milli; /* stored tokens x 1000 */
    uint64_t last_ms;
    bool started;
} snmp_tbucket_t;

/** Start full (burst tokens). rate and burst >= 1. */
void snmp_tb_init(snmp_tbucket_t *tb, uint32_t rate, uint32_t burst);
/** Refill up to now_ms (monotonic) and take one token; false if none is available. */
bool snmp_tb_take(snmp_tbucket_t *tb, uint64_t now_ms);

/* ---------------------------------------------------------------- comm-loss coalescing */

#define SNMP_COMM_HOLD_MS 2000u          /* a state must persist this long before it is reported */
#define SNMP_COMM_MIN_INTERVAL_MS 10000u /* at most one gwCommLost/Restored per device per interval */

/**
 * Per-device coalescing of GW_EVT_COMM transitions into gwCommLost/gwCommRestored decisions.
 * A device starts as "reported online" (the first decision online=true after boot sends nothing;
 * a device that never answers produces gwCommLost). Each change schedules a report at
 * max(now + HOLD, last report + MIN_INTERVAL); when it is due, the LATEST state is reported only if it
 * differs from the last reported one. Flapping therefore yields at most one notification per
 * device per MIN_INTERVAL and the final state is always reported.
 */
typedef struct {
    bool reported_online;
    bool pending;
    bool latest_online;
    bool ever_reported;
    uint64_t due_ms;
    uint64_t last_report_ms;
} snmp_comm_dev_t;

typedef struct {
    snmp_comm_dev_t dev[GW_MAX_DEVICES];
} snmp_comm_coalesce_t;

typedef struct {
    uint8_t dev;
    bool online;
} snmp_comm_report_t;

void snmp_cc_init(snmp_comm_coalesce_t *cc);
/** A COMM event for dev (ignored for dev >= GW_MAX_DEVICES). */
void snmp_cc_event(snmp_comm_coalesce_t *cc, uint8_t dev, bool online, uint64_t now_ms);
/** Reports due at now_ms, at most cap (GW_MAX_DEVICES suffices). Returns the number written. */
size_t snmp_cc_poll(snmp_comm_coalesce_t *cc, uint64_t now_ms, snmp_comm_report_t *out, size_t cap);

/* ---------------------------------------------------------------- USM user table */

typedef struct {
    bool valid;
    char name[GW_SNMP_USER_SZ];
    uint8_t access; /* cfg_snmp_access_t */
    uint8_t auth_key[SEC_V3_KEY_LEN];
    uint8_t priv_key[SEC_V3_KEY_LEN];
} snmp_usm_user_t;

typedef struct {
    snmp_usm_user_t user[GW_MAX_SNMP_V3_USERS];
} snmp_usm_table_t;

/**
 * Build the table (snmp_gw.h USM contract): a slot is valid only if v3 is enabled, the slot is
 * enabled, its name is non-empty and fits, its localized keys are set, and no earlier slot has the
 * same name. Invalid slots carry no keys. `keys` may be NULL (= no keys).
 */
void snmp_usm_build(snmp_usm_table_t *t, const cfg_snmp_t *cfg, const sec_v3_keys_t *keys);
/** Valid user with exactly this name (case-sensitive), or NULL (also for NULL/""). */
const snmp_usm_user_t *snmp_usm_find(const snmp_usm_table_t *t, const char *name);
/** Number of valid users and the idx-th valid one (NULL if idx is out of range). */
uint8_t snmp_usm_count(const snmp_usm_table_t *t);
const snmp_usm_user_t *snmp_usm_at(const snmp_usm_table_t *t, uint8_t idx);
/** Wipe keys and names. */
void snmp_usm_clear(snmp_usm_table_t *t);

/* ---------------------------------------------------------------- inform tracking */

#define SNMP_MSG_BYTES_MAX 96 /* == SNMP_MSG_MAX (snmp_transport.h; static_assert in traps.c) */

/* Informs in flight. A full table does not evict a tracked inform for a new notification: traps.c then
 * sends the new one as a plain trap (snmp_inf_free_slots), so this bounds memory, not delivery. Only
 * the admin test notification may evict (snmp_inf_add), so that its result is always reported. */
#define SNMP_INFORM_SLOTS 16
#define SNMP_INFORM_IDS (SNMP_GW_INFORM_RETRIES + 1) /* request ids of the first send + every retry */

typedef struct {
    bool used;
    uint8_t target;  /* trap target index */
    uint32_t ip;     /* target IPv4, host order */
    uint8_t sends;   /* datagrams sent so far (1 + retries) */
    int32_t req_id[SNMP_INFORM_IDS];
    uint64_t due_ms; /* next retry / give-up time */
    uint32_t test_gen; /* test-trap generation waiting for this inform (0 = none) */
    uint32_t order;    /* insertion order, for eviction of the oldest */
    uint16_t msg_len;
    uint8_t msg[SNMP_MSG_BYTES_MAX];
} snmp_inform_t;

typedef struct {
    snmp_inform_t slot[SNMP_INFORM_SLOTS];
    uint32_t next_order;
} snmp_inform_table_t;

void snmp_inf_init(snmp_inform_table_t *t);
/**
 * Track a sent inform. Uses a free slot, else evicts the oldest (*evicted = true, its contents copied
 * to *evicted_out when non-NULL). Returns the slot index. msg (<= SNMP_MSG_BYTES_MAX) is kept for
 * retransmissions.
 */
int snmp_inf_add(snmp_inform_table_t *t, uint8_t target, uint32_t ip, int32_t req_id, uint64_t now_ms,
                 uint32_t test_gen, const void *msg, size_t msg_len, bool *evicted, snmp_inform_t *evicted_out);
/** Record a retransmission of slot i with a new request id (due again after the timeout). */
void snmp_inf_resent(snmp_inform_table_t *t, int i, int32_t req_id, uint64_t now_ms);
/** Slot acknowledged by (req_id, peer_ip): any request id of the slot matches. -1 if none. */
int snmp_inf_match(const snmp_inform_table_t *t, int32_t req_id, uint32_t peer_ip);
/** First used slot towards peer_ip (inform_peer hook), -1 if none. */
int snmp_inf_peer(const snmp_inform_table_t *t, uint32_t peer_ip);
/** A used slot whose due time has passed, or -1. Caller retransmits (sends < 1 + RETRIES) or gives up. */
int snmp_inf_due(const snmp_inform_table_t *t, uint64_t now_ms);
/** True if slot i may be retransmitted once more. */
bool snmp_inf_can_retry(const snmp_inform_table_t *t, int i);
void snmp_inf_free(snmp_inform_table_t *t, int i);
/** Drop every slot of a target (configuration changed). Returns how many were dropped. */
size_t snmp_inf_drop_target(snmp_inform_table_t *t, uint8_t target);
/** Number of unused slots. */
size_t snmp_inf_free_slots(const snmp_inform_table_t *t);

/* ---------------------------------------------------------------- alarm event ring */

typedef struct {
    uint32_t seq; /* > 0 */
    int64_t ts_ms;
    uint8_t type; /* gw_alarm_type_t: 1 raise, 2 clear, 3 ack */
    uint8_t dev;
    uint8_t sev;
    uint16_t code;
    int16_t value;
    char user[GW_USER_NAME_SZ];
} snmp_alarm_ev_t;

/** The SNMP_GW_EVENTS_KEPT newest alarm transitions, ascending seq, unique seq. */
typedef struct {
    snmp_alarm_ev_t ev[SNMP_GW_EVENTS_KEPT];
    uint8_t n;
} snmp_evring_t;

void snmp_evring_init(snmp_evring_t *r);
/** Insert keeping order; ignores seq 0, duplicates and anything older than a full ring's oldest.
 * Returns true if inserted. */
bool snmp_evring_insert(snmp_evring_t *r, const snmp_alarm_ev_t *ev);
/** Event with seq, or NULL. */
const snmp_alarm_ev_t *snmp_evring_find(const snmp_evring_t *r, uint32_t seq);
/** First event with seq > after, or NULL. */
const snmp_alarm_ev_t *snmp_evring_next(const snmp_evring_t *r, uint32_t after);

/* ---------------------------------------------------------------- misc */

/** Text acceptable for sysContact/sysName/sysLocation: len <= max, valid UTF-8 (no overlong forms,
 * no surrogates), no NUL and no ASCII control characters. */
bool snmp_text_ok(const uint8_t *s, size_t len, size_t max);

/** SNMPv3 key for a passphrase of 8..64 chars localized to engine_id (RFC 3414 A.2, SHA-1). */
int snmp_localize_key_for(const char *pass, const uint8_t *engine_id, size_t engine_len,
                          uint8_t out[SEC_V3_KEY_LEN]);

/**
 * SNMP error-status for a set_test rejected by mex_check_write(): reason (mex_reason_t) ->
 * wrongValue (range), notWritable (readonly / unknown), inconsistentValue (running interlock),
 * resourceUnavailable (offline / busy), genErr otherwise. 0 (noError) for MEX_R_OK.
 * Values are the SNMP protocol codes (RFC 3416), equal to lwIP's snmp_err_t.
 */
int snmp_err_for_reason(int reason);

#define SNMP_PROTO_NOERROR 0
#define SNMP_PROTO_GENERR 5
#define SNMP_PROTO_NOACCESS 6
#define SNMP_PROTO_WRONGTYPE 7
#define SNMP_PROTO_WRONGLENGTH 8
#define SNMP_PROTO_WRONGVALUE 10
#define SNMP_PROTO_RESOURCEUNAVAILABLE 13
#define SNMP_PROTO_COMMITFAILED 14
#define SNMP_PROTO_NOTWRITABLE 17
#define SNMP_PROTO_INCONSISTENTVALUE 12

/** GwWriteResult value for a mex_wstate_t (none(1) for anything unknown). */
int32_t snmp_write_result_code(int state);

#define SNMP_PRINCIPAL_WEB "web"

/**
 * Principal as served in gwLastWritePrincipal / gwAlarmActiveAckedBy / gwAlarmEventUser. Web account
 * names are login names, so they are disclosed only to authenticated (SNMPv3 authPriv) readers; a
 * v1/v2c reader (cleartext community) sees the origin class "web". Non-web principals ("@snmp",
 * "@console") are always shown. "" for NULL/"".
 */
const char *snmp_principal_view(const char *by, bool authenticated);

/**
 * True when the stored last-write record (have = valid, stored_cmd) already describes the write
 * pending_cmd or a later one, i.e. a "pending" record for pending_cmd must not overwrite it (the final
 * GW_EVT_WRITE_RESULT can arrive before the SNMP SET stores its "pending" record).
 */
bool snmp_last_write_supersedes(bool have, uint32_t stored_cmd, uint32_t pending_cmd);

#ifdef __cplusplus
}
#endif
