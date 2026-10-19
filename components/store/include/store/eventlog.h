/*
 * eventlog.h - event and audit logs: fixed 32-byte records in two-file rings (DESIGN.md §8).
 *
 * Logs: EVLOG_EVENTS (/data/log/events.0|1) and EVLOG_AUDIT (/data/log/audit.0|1), 128 KB per
 * file (4096 records). When the active file is full the other one is truncated and becomes active.
 * Sequence numbers are per log, strictly increasing, recovered at boot (max seq in both files).
 *
 * Writers: evlog_append() is non-blocking and callable from any task (incl. gw_evt): it assigns
 * seq/ts, stores the record in a RAM tail (last EVLOG_RAM_TAIL per log) and marks the log dirty;
 * the persist task appends to flash. Readers (evlog_query) merge the RAM tail with the files.
 *
 * Event -> log glue owned by this module (registered in eventlog_init() on the gw_evt loop):
 *   GW_EVT_COMM           -> EVENTS  EVT_COMM_LOST / EVT_COMM_RESTORED
 *   GW_EVT_WRITE_RESULT   -> AUDIT   AUD_REG_WRITE (code=addr, value=raw_req, extra=see below)
 *   GW_EVT_CONFIG_CHANGED -> AUDIT   AUD_CONFIG_CHANGE (code=section)
 *   GW_EVT_NET_STATE      -> EVENTS  EVT_NET_LINK / EVT_AP
 *   GW_EVT_TIME_SYNC      -> EVENTS  EVT_TIME_SET (code=source)
 *   GW_EVT_OTA            -> EVENTS  EVT_OTA (code=phase)
 *   GW_EVT_REBOOT         -> EVENTS  EVT_REBOOT (code=reason)
 * Alarm transitions are appended by the alarm service itself (it needs the seq for the event).
 * Auth/user/OTA-upload/factory-reset audits are appended explicitly by auth/web/sysmgr.
 * Appended by their owners, never by the glue: EVT_NET_PROVISIONAL (net), EVT_BOOT and
 * EVT_HEALTH (sysmgr supervisor).
 */
#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EVLOG_FILE_BYTES (128u * 1024u)
#define EVLOG_RECS_PER_FILE (EVLOG_FILE_BYTES / 32u)
#define EVLOG_RAM_TAIL 64
#define EVLOG_QUERY_MAX 200 /* max records per evlog_query() call */

typedef enum { EVLOG_EVENTS = 0, EVLOG_AUDIT = 1, EVLOG_COUNT } evlog_kind_t;

/**
 * Record types. EVENTS log: 1..31, AUDIT log: 32..63. Each comment starts with the wire name
 * (evlog_type_name(), REST "type", docs/API.md §4.12), then the meaning of code/value/extra.
 */
typedef enum {
    /* EVENTS */
    EVT_ALARM_RAISE = 1,      /* "alarm_raise": dev, code=alarm code, sev, value=related raw */
    EVT_ALARM_CLEAR = 2,      /* "alarm_clear": dev, code, sev, value */
    EVT_ALARM_ACK = 3,        /* "alarm_ack": dev, code, sev, user */
    EVT_COMM_LOST = 4,        /* "comm_lost": dev, value=last_err */
    EVT_COMM_RESTORED = 5,    /* "comm_restored": dev */
    EVT_BOOT = 6,             /* "boot": code=esp_reset_reason(), extra=boot count */
    EVT_TIME_SET = 7,         /* "time_set": code=gw_time_src_t, extra=(uint32_t)(delta_ms/1000) */
    EVT_NET_LINK = 8,         /* "net_link": code=gw_netif_t, value=1 up / 0 down, extra=ip */
    EVT_AP = 9,               /* "ap": value=1 started / 0 stopped, code=reason */
    EVT_OTA = 10,             /* "ota": code=gw_ota_phase_t, extra=err */
    EVT_REBOOT = 11,          /* "reboot": code=gw_reboot_reason_t, user */
    EVT_NET_PROVISIONAL = 12, /* "net_provisional": code=net_prov_state_t */
    EVT_HEALTH = 13,          /* "health": code=stale heartbeat mask */
    /* AUDIT */
    AUD_LOGIN_OK = 32,      /* "login_ok": user, extra=client ip */
    AUD_LOGIN_FAIL = 33,    /* "login_fail": user (as typed, truncated), extra=client ip */
    AUD_LOCKOUT = 34,       /* "lockout": extra=client ip, value=lock minutes */
    AUD_LOGOUT = 35,        /* "logout": user, code=gw_session_kind_t */
    AUD_PASSWORD = 36,      /* "password": user=actor, extra=0 self / 1 by admin (then + user_target) */
    AUD_USER_ADD = 37,      /* "user_add": user=actor, value=role, extra=0 (+ user_target) */
    AUD_USER_MOD = 38,      /* "user_mod": user=actor, value=role (+ user_target) */
    AUD_USER_DEL = 39,      /* "user_del": user=actor (+ user_target) */
    AUD_CONFIG_CHANGE = 40, /* "config_change": user, code=cfg_section_t, extra=rev */
    AUD_REG_WRITE = 41,     /* "reg_write": dev, user, code=addr, value=raw_req, extra=EVLOG_REG_WRITE_EXTRA()
                               (every attempt incl. rejections at enqueue, cmd 0) */
    AUD_OTA_UPLOAD = 42,    /* "ota_upload": user, code=0 ok / 1 failed, extra=esp_err_t */
    AUD_ROLLBACK = 43,      /* "rollback": user */
    AUD_REBOOT = 44,        /* "reboot_req": user, code=gw_reboot_reason_t */
    AUD_FACTORY_RESET = 45, /* "factory_reset": user, value=keep_network */
    AUD_CONFIG_IMPORT = 46, /* "config_import": user, extra=new rev */
    AUD_TIME_SET = 47,      /* "time_sync": user, code=gw_time_src_t */
    AUD_ALARM_ACK = 48,     /* "alarm_ack_req": dev, user, code=alarm code (0 = all) */
    AUD_STATS_RESET = 49,   /* "stats_reset": dev, user */
    AUD_SNMP_TEST = 50,     /* "snmp_test": user */
    AUD_USER_TARGET = 51,   /* "user_target": user=the account acted on by the record it follows
                               (user_add/user_mod/user_del, password by admin), code=that record's
                               type, value=its value, extra=its seq. The 32-byte record has room for
                               one name only, so account changes are logged as this pair. */
} evlog_type_t;

/** On-disk/in-RAM record (32 bytes, little-endian). */
typedef struct {
    uint32_t seq; /* assigned by evlog_append (starts at 1) */
    uint32_t ts;  /* epoch s UTC; 0 if wall time was invalid */
    uint16_t dev; /* device index, 0xFFFF = n/a */
    uint16_t code;
    uint8_t type; /* evlog_type_t */
    uint8_t sev;  /* alm_sev_t for alarms, else 0 */
    int16_t value;
    char user[12]; /* NUL-padded, not necessarily NUL-terminated when 12 chars (names are <= 11) */
    uint32_t extra;
} evlog_rec_t;

static_assert(sizeof(evlog_rec_t) == 32, "evlog_rec_t must be 32 bytes");

#define EVLOG_DEV_NONE 0xFFFFu

/**
 * AUD_REG_WRITE "extra": bits 0..15 = raw_before as uint16 (two's complement for signed rows),
 * bits 16..23 = mex_wstate_t, bits 24..31 = reason byte: mex_reason_t 0..0x7F as is, Modbus
 * exception n (MEX_R_EXCEPTION(n), n 1..127) as 0x80 | n. Decode with EVLOG_REASON_FROM_BYTE().
 */
#define EVLOG_REASON_BYTE(reason)                                                                            \
    ((uint8_t)((reason) >= 0x100 ? (0x80u | ((unsigned)(reason) - 0x100u)) : ((unsigned)(reason) & 0x7Fu)))
#define EVLOG_REASON_FROM_BYTE(b) (((b) & 0x80u) ? (0x100 + (int)((b) & 0x7Fu)) : (int)(b))
#define EVLOG_REG_WRITE_EXTRA(raw_before, state, reason)                                                     \
    ((uint32_t)(uint16_t)(raw_before) | ((uint32_t)(uint8_t)(state) << 16) |                                 \
     ((uint32_t)EVLOG_REASON_BYTE(reason) << 24))

/** Query filter (all conditions AND-ed). */
typedef struct {
    int16_t dev;      /* -1 any */
    int8_t min_sev;   /* -1 any, else sev >= min_sev */
    uint8_t type_min; /* inclusive type range; 0/0xFF = any */
    uint8_t type_max;
} evlog_filter_t;

#define EVLOG_FILTER_ANY ((evlog_filter_t){-1, -1, 0, 0xFF})

/** Recover seq numbers from files, start RAM tails, register gw_evt glue handlers. After gw_events_init(). */
esp_err_t eventlog_init(void);

/**
 * Append a record (r->seq/r->ts are overwritten). Non-blocking, any task. Returns the assigned
 * seq (> 0), or 0 if the log is not initialised.
 */
uint32_t evlog_append(evlog_kind_t kind, const evlog_rec_t *r);

/**
 * Append observer (one, e.g. the syslog client for AUDIT records that no gw_evt event carries:
 * login_fail, lockout, password, user_*). Called by evlog_append() in the APPENDING task after the
 * record got its seq, outside every evlog lock, possibly while the caller holds its own module
 * lock: it must only copy the record and return (no blocking, no evlog/config calls). NULL removes
 * it. Any task.
 */
typedef void (*evlog_hook_t)(evlog_kind_t kind, const evlog_rec_t *r);
void evlog_set_hook(evlog_hook_t fn);

/** Shorthand for an EVENTS record. user may be NULL. */
uint32_t evlog_event(evlog_type_t type, uint16_t dev, uint16_t code, uint8_t sev, int16_t value,
                     const char *user, uint32_t extra);

/** Shorthand for an AUDIT record. user may be NULL. */
uint32_t evlog_audit(evlog_type_t type, uint16_t dev, uint16_t code, int16_t value, const char *user,
                     uint32_t extra);

/**
 * Newest-first query: records with seq < before (0 = from newest), matching f, up to
 * min(limit, EVLOG_QUERY_MAX). Returns the count written to out. *next (optional) receives the
 * seq to pass as `before` for the next page, or 0 when exhausted. Reads files: not from gw_evt
 * or persist.
 */
size_t evlog_query(evlog_kind_t kind, uint32_t before, size_t limit, const evlog_filter_t *f,
                   evlog_rec_t *out, uint32_t *next);

/** Highest seq assigned so far in a log. */
uint32_t evlog_last_seq(evlog_kind_t kind);

/**
 * Factory reset (sysmgr, when logs are not kept): drop both RAM tails and pending appends, ask the
 * persist task to delete FS_DIR_LOG contents, and discard later evlog_append() calls (return 0)
 * until reboot. Returns once the job is queued.
 */
esp_err_t evlog_factory_reset(void);

/** Wire name of a type ("alarm_raise", "login_fail", ...) for JSON/CSV/syslog. */
const char *evlog_type_name(uint8_t type);

#ifdef __cplusplus
}
#endif
