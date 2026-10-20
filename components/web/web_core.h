/*
 * web_core.h - pure (IDF-free, host-tested) internals of the web component.
 *
 *   web_policy.c  router decision core: role/must_change/Origin/CSRF/body checks in router order
 *   web_routes.c  route metadata generated from api_routes.def (host checks it against API.md)
 *   web_json.c    JSON body builders shared by handlers (errors, history series, write results)
 *   web_csv.c     CSV rows for /history.csv and /alarms/history.csv
 *   ws_frame.c    WebSocket frame builders (snap delta/full, alarm, write, comm, sys, hello, bye,
 *                 pong) and the client message parser
 * Not a public interface: only the web component sources and tests/ use it.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_json_writer.h"
#include "store/history.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Route flags/limits: identical values to web/router.h (router.c static-asserts the match). */
#define WEB_CORE_RF_CSRF 0x01u
#define WEB_CORE_RF_ALLOW_MUST_CHANGE 0x02u
#define WEB_CORE_RF_RAW_BODY 0x04u
#define WEB_CORE_RF_SLOW 0x08u
#define WEB_CORE_RF_NO_TOUCH 0x10u

/* Methods as in http_parser's enum http_method (== httpd_method_t values). */
#define WEB_CORE_M_DELETE 0
#define WEB_CORE_M_GET 1
#define WEB_CORE_M_POST 3
#define WEB_CORE_M_PUT 4

/* ---------------------------------------------------------------- policy */

/** What the router knows about a request once the route matched and the session was resolved. */
typedef struct {
    int method;             /* WEB_CORE_M_* */
    bool authed;            /* a valid session cookie was presented */
    gw_role_t role;         /* session role (valid iff authed) */
    bool must_change;       /* session must change its password */
    bool origin_present;    /* Origin or Referer header present */
    bool origin_ok;         /* ... and its authority equals Host */
    bool csrf_ok;           /* X-CSRF-Token equals the session's token */
    uint64_t content_len;   /* request body length (Content-Length, 0 if none) */
    bool content_type_json; /* Content-Type is application/json (params allowed) */
} web_facts_t;

/** Route policy subset (from web_route_t / web_route_meta_t). */
typedef struct {
    gw_role_t min_role;
    uint8_t flags; /* WEB_CORE_RF_* */
    uint32_t max_body;
} web_rpolicy_t;

typedef struct {
    int status;       /* 0 = proceed to the handler */
    const char *code; /* REST error code (router.h WEB_E_*), NULL when status == 0 */
} web_verdict_t;

/**
 * Router steps 3-6 (router.h): 401 unauthorized / 403 forbidden / 403 password_change_required
 * (only routes that require a role and lack ALLOW_MUST_CHANGE; public routes such as login stay
 * reachable) / 403 origin (every POST/PUT/DELETE) / 403 csrf (CSRF routes) / 413 payload_too_large
 * / 400 bad_request (non-empty body that is not JSON, unless RAW_BODY).
 */
web_verdict_t web_policy_decide(const web_rpolicy_t *r, const web_facts_t *f);

/** True for "application/json" with optional parameters (case-insensitive, OWS allowed). */
bool web_ct_is_json(const char *content_type);

/** True for "application/octet-stream" with optional parameters. */
bool web_ct_is_octet(const char *content_type);

/**
 * If-None-Match evaluation for a strong ETag: true if the header lists etag (comma separated,
 * optional W/ prefix accepted for the comparison) or is "*".
 */
bool web_etag_match(const char *if_none_match, const char *etag);

/** Status line ("200 OK") for an HTTP status; "500 Internal Server Error" for unknown codes. */
const char *web_status_line(int status);

/* ---------------------------------------------------------------- route metadata */

typedef struct {
    int method; /* WEB_CORE_M_* */
    const char *pattern;
    gw_role_t min_role;
    uint8_t flags;
    uint32_t max_body;
    const char *handler; /* handler function name (diagnostics/tests) */
} web_route_meta_t;

extern const web_route_meta_t web_route_meta[];
extern const size_t web_route_meta_count;

/**
 * Index of the first route whose method and pattern match path[0..len), or -1. *method_mismatch
 * (optional) is set when some pattern matched but no method did (still a 404 for the API).
 */
int web_route_meta_find(int method, const char *path, size_t len, bool *method_mismatch);

/* ---------------------------------------------------------------- JSON builders */

/** Open an error object {"error":code[,"message":msg][,"field":field] ... (left open). */
void web_json_error_open(gw_jw_t *w, const char *code, const char *message, const char *field);

/** Complete error body {"error":..,"message":..,"field":..}. */
void web_json_error(gw_jw_t *w, const char *code, const char *message, const char *field);

/**
 * 409 body for a register value not representable at the register's scale (write-result schema:
 * {"error":"rejected","state":"rejected","cmd":0,"addr":addr,"reason":"range"}, no "message").
 */
void web_json_write_range_rejected(gw_jw_t *w, uint16_t addr);

#define WEB_META_ALARMS_ETAG_SZ 40

/**
 * Strong ETag of GET /meta/alarms: "\"<build>-a<8 hex>\"" where the hex is FNV-1a 32 over the
 * effective severities sev[0..n) (they change with /config/alarms sev_override). build = build id
 * prefix (at most 12 characters are used). out receives a quoted, NUL-terminated string.
 */
void web_meta_alarms_etag(char out[WEB_META_ALARMS_ETAG_SZ], const char *build, const uint8_t *sev, size_t n);

/** Write a raw x10 history value (HIST_GAP -> null). */
void web_json_hist_value(gw_jw_t *w, int16_t v);

/**
 * GET /devices/{d}/history body from a query result. minmax: add "min"/"max" (dt >= 60);
 * stages: add "stages" (?stages=1). time_valid false -> "t0": null.
 */
void web_json_history(gw_jw_t *w, const hist_series_t *s, bool minmax, bool stages);

/** Wire name of a mex_wstate_t value: "pending","applied","rejected","uncertain". */
const char *web_wstate_name(int state);

/** Policy rule bits -> JSON array of rule names (auth.h AUTH_PW_*). */
void web_json_policy_rules(gw_jw_t *w, uint32_t bits);

/** Write epoch ms, or null when 0 (wall time unknown). */
void web_json_epoch_ms(gw_jw_t *w, int64_t ms);

/* ---------------------------------------------------------------- CSV */

#define WEB_CSV_BOM "\xEF\xBB\xBF"
#define WEB_CSV_ROW_MAX 192

/** History CSV header line (with CRLF). agg = dt >= 60 (adds min/max columns). */
int web_csv_hist_header(char *out, size_t cap, bool agg);

/** One history row (with CRLF): ISO-8601 time (empty if ts_ms == 0), values with one decimal,
 * empty fields for gaps. Returns the length or -1 if cap is too small. */
int web_csv_hist_row(char *out, size_t cap, int64_t ts_ms, const hist_slow_t *row, bool agg);

/** Alarm history CSV header "seq,time,dev,id,code,type,sev,value,user\r\n". */
int web_csv_alarm_header(char *out, size_t cap);

/** One alarm history row. id/user may be NULL (empty field). */
int web_csv_alarm_row(char *out, size_t cap, uint32_t seq, int64_t ts_ms, unsigned dev, const char *id,
                      unsigned code, const char *type, unsigned sev, int value, const char *user);

/**
 * Append a CSV field to out (at *len, cap total): quoted when it contains ',', '"', CR or LF, and
 * prefixed with an apostrophe when it starts with '=', '+', '-' or '@' (spreadsheet formula
 * injection). Returns false on overflow.
 */
bool web_csv_field(char *out, size_t cap, size_t *len, const char *s);

/* ---------------------------------------------------------------- WebSocket frames */

#define WS_TOPIC_SNAP_BIT 0x01u /* == ws_hub.h WS_T_SNAP ... (ws_hub.c asserts) */
#define WS_TOPIC_ALARM_BIT 0x02u
#define WS_TOPIC_COMM_BIT 0x04u
#define WS_TOPIC_WRITE_BIT 0x08u
#define WS_TOPIC_SYS_BIT 0x10u

#define WS_SNAP_MAX_REGS 64

/** Per-device delta state of the snap frame builder (gw_evt task only). */
typedef struct {
    bool valid; /* a frame was built since the last reset */
    uint32_t coils;
    uint8_t n;
    uint16_t addr[WS_SNAP_MAX_REGS];
    int32_t raw[WS_SNAP_MAX_REGS];
    uint64_t last_full_mono_ms;
} ws_snap_state_t;

/**
 * Build {"t":"snap",...}. addr/raw[0..n) are the registers to report now (live.regs set). The
 * frame is full (all registers + "c") when !st->valid, force_full, or WS_FULL_SNAP_S elapsed since
 * the last full frame; otherwise only registers whose raw changed or that were not reported before,
 * and "c" only if the coils changed. Updates st. Returns gw_jw error (GW_JW_OK on success).
 */
int ws_frame_snap(ws_snap_state_t *st, gw_jw_t *w, uint8_t dev, uint32_t seq, int64_t ts_ms, bool online,
                  const uint16_t *addr, const int32_t *raw, size_t n, uint32_t coils, bool force_full,
                  uint64_t now_mono_ms, uint32_t full_period_s, bool measurement_valid);

/** {"t":"alarm",...}; type 1 raise / 2 clear / 3 ack; user only for ack (NULL/"" omitted). */
void ws_frame_alarm(gw_jw_t *w, uint8_t dev, const char *id, unsigned code, unsigned type, unsigned sev,
                    int64_t ts_ms, uint32_t seq, int value, const char *user);

/** {"t":"write",...}; reason NULL omits it; include_raw false omits "raw". */
void ws_frame_write(gw_jw_t *w, uint8_t dev, uint32_t cmd, unsigned addr, int state, bool include_raw,
                    int32_t raw, const char *reason, const char *by);

void ws_frame_comm(gw_jw_t *w, uint8_t dev, bool online, unsigned rtt, uint32_t crc, uint32_t timeout,
                   uint32_t exception, uint32_t malformed);

void ws_frame_sys(gw_jw_t *w, uint32_t heap, uint32_t heap_min, uint32_t psram, uint32_t up_s,
                  int64_t time_ms, uint32_t alarms);

/** {"t":"hello","v":1,"srv":..,"devs":[..],"seq":{"<dev>":seq},"meta":etag}. */
void ws_frame_hello(gw_jw_t *w, int64_t srv_ms, const uint8_t *devs, const uint32_t *seqs, size_t n,
                    const char *meta_etag);

void ws_frame_bye(gw_jw_t *w, const char *reason);
void ws_frame_pong(gw_jw_t *w, int64_t srv_ms);

typedef enum { WS_MSG_INVALID = -1, WS_MSG_UNKNOWN = 0, WS_MSG_SUB = 1, WS_MSG_PING = 2 } ws_msg_t;

/** Parse a client text frame: sub (topics -> *topics, unknown names ignored), ping, or other. */
ws_msg_t ws_parse_client(const char *data, size_t len, uint32_t *topics);

#ifdef __cplusplus
}
#endif
