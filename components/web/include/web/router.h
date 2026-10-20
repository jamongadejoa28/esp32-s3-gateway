/*
 * router.h - default-deny REST router on top of esp_http_server (DESIGN.md §6, docs/API.md).
 *
 * httpd_srv.c registers one wildcard URI handler per method (GET/POST/PUT/DELETE). Pipeline:
 *   0. Host check (DNS-rebinding defence) for EVERY request, static files and /ws included, before
 *      anything else: net_host_allowed(Host) (net/net.h) must accept the Host header (an address of
 *      this device, the configured hostname or "<hostname>.local", optional ":port"); missing or
 *      other -> 421 misdirected (error body, no session lookup). Then non-/api GETs go to the static
 *      UI and everything else to web_router_dispatch().
 *   1. Match method + path (query stripped) against the registered tables in registration order.
 *      No match -> 404 not_found (also when only the method differs).
 *   2. Session: cookie AUTH_COOKIE_NAME -> auth_session_lookup(touch = !(flags & WEB_RF_NO_TOUCH)).
 *   3. min_role > GW_ROLE_NONE and no session -> 401 unauthorized; role < min_role -> 403 forbidden.
 *   4. Only for routes with min_role > GW_ROLE_NONE: session.must_change and
 *      !(flags & WEB_RF_ALLOW_MUST_CHANGE) -> 403 password_change_required. Public routes (login)
 *      stay reachable with a must_change cookie, so such a cookie never blocks a new login.
 *   5. Every POST/PUT/DELETE (login included): if Origin or Referer is present its authority must
 *      equal Host (403 origin). WEB_RF_CSRF routes additionally need X-CSRF-Token equal to the
 *      session token (403 csrf).
 *   6. Body: Content-Length > max_body -> 413 payload_too_large. Unless WEB_RF_RAW_BODY, the body
 *      (must be Content-Type application/json when non-empty, else 400 bad_request) is read fully
 *      into ctx->body (NUL-terminated, heap, freed after the handler).
 *   7. Handler. WEB_RF_SLOW handlers run on an async worker (httpd_req_async_handler_begin):
 *      "httpd_login" for public routes (login), "httpd_async" for authenticated ones; admission
 *      (<= 4 jobs per lane) is decided before begin, a full lane -> 503 busy.
 * Every response gets the security headers (CSP, nosniff, no-referrer, X-Frame-Options DENY) and
 * "Cache-Control: no-store"; never a Server header or CORS headers.
 *
 * Threading: handlers run in the httpd task (or an async worker for WEB_RF_SLOW); all
 * helpers below must be called from the handler's own task with its ctx.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth/auth.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "gw_core/gw_defs.h"
#include "gw_core/gw_json_writer.h"
#include "web/web_path.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cJSON;

#define WEB_API_PREFIX "/api/v1"
#define WEB_QUERY_SZ 256
#define WEB_BODY_JSON_MAX (8u * 1024u)
#define WEB_BODY_IMPORT_MAX (32u * 1024u)
#define WEB_BODY_OTA_MAX (3u * 1024u * 1024u + 80u) /* app + paired LittleFS + GWOTA1 header */
#define WEB_MAX_ROUTE_TABLES 16
#define WEB_CSRF_HEADER "X-CSRF-Token"

/* Route flags */
#define WEB_RF_CSRF 0x01u              /* mutating route: X-CSRF-Token required (Origin: see step 5) */
#define WEB_RF_ALLOW_MUST_CHANGE 0x02u /* reachable while the password must be changed */
#define WEB_RF_RAW_BODY 0x04u          /* handler streams the body itself (OTA upload) */
#define WEB_RF_SLOW 0x08u              /* may take > 200 ms (PBKDF2): run on the async worker */
#define WEB_RF_NO_TOUCH 0x10u          /* does not refresh the session idle timer */

/* REST error codes (docs/API.md §Errors). */
#define WEB_E_BAD_REQUEST "bad_request"                  /* 400 */
#define WEB_E_MISDIRECTED "misdirected"                  /* 421 Host header not one of ours */
#define WEB_E_INVALID_JSON "invalid_json"                /* 400 */
#define WEB_E_UNAUTHORIZED "unauthorized"                /* 401 */
#define WEB_E_BAD_CREDENTIALS "bad_credentials"          /* 401 */
#define WEB_E_FORBIDDEN "forbidden"                      /* 403 */
#define WEB_E_CSRF "csrf"                                /* 403 */
#define WEB_E_ORIGIN "origin"                            /* 403 */
#define WEB_E_PASSWORD_CHANGE "password_change_required" /* 403 */
#define WEB_E_NOT_FOUND "not_found"                      /* 404 */
#define WEB_E_CONFLICT "conflict"                        /* 409 */
#define WEB_E_REJECTED "rejected"                        /* 409 register write rejected */
#define WEB_E_EXISTS "exists"                            /* 409 user name taken */
#define WEB_E_LIMIT "limit"                              /* 409 GW_MAX_USERS reached */
#define WEB_E_LAST_ADMIN "last_admin"                    /* 409 */
#define WEB_E_SELF "self"                                /* 409 admin acting on itself */
#define WEB_E_TOO_LARGE "payload_too_large"              /* 413 */
#define WEB_E_VALIDATION "validation"                    /* 422 */
#define WEB_E_POLICY "policy"                            /* 422 */
#define WEB_E_WRONG_PASSWORD "wrong_password"            /* 422 */
#define WEB_E_HASH_MISMATCH "hash_mismatch"              /* 422 */
#define WEB_E_IMAGE_INVALID "image_invalid"              /* 422 */
#define WEB_E_LOCKED "locked"                            /* 423 */
#define WEB_E_RATE_LIMITED "rate_limited"                /* 429 */
#define WEB_E_INTERNAL "internal"                        /* 500 */
#define WEB_E_UNAVAILABLE "unavailable"                  /* 503 */
#define WEB_E_BUSY "busy"                                /* 503 */

typedef struct web_ctx web_ctx_t;

/** Route handler. Must send exactly one response through the helpers below and return ESP_OK;
 * returning an error without having responded makes the router send 500 internal. */
typedef esp_err_t (*web_handler_t)(web_ctx_t *ctx);

typedef struct {
    httpd_method_t method; /* HTTP_GET / HTTP_POST / HTTP_PUT / HTTP_DELETE */
    const char *pattern;   /* full path incl. WEB_API_PREFIX, "{name}" segments allowed */
    gw_role_t min_role;    /* GW_ROLE_NONE = public (session still resolved when a cookie is sent) */
    uint8_t flags;         /* WEB_RF_* */
    uint32_t max_body;     /* bytes; 0 = no body allowed */
    web_handler_t handler;
} web_route_t;

/** Per-request context (stack of the dispatcher; valid only during the handler call). */
struct web_ctx {
    httpd_req_t *req;
    const web_route_t *route;
    bool authed;
    auth_session_info_t sess; /* valid iff authed */
    uint32_t client_ip;       /* host order */
    bool via_ap;              /* request from the recovery AP (net_sock_info, ip_filter.h AP rule) */
    web_params_t params;
    char query[WEB_QUERY_SZ]; /* raw query without '?', "" if none; longer queries -> 400 */
    char *body;               /* NUL-terminated JSON body or NULL */
    size_t body_len;
    bool responded; /* set by the send helpers */
};

/** Register a route table (static storage). Before web_start(). Max WEB_MAX_ROUTE_TABLES. */
esp_err_t web_router_register(const web_route_t *routes, size_t n);

/** Entry point from the httpd wildcard handlers. */
esp_err_t web_router_dispatch(httpd_req_t *req);

/* ---- Request helpers ---- */

/** Path parameter value by name ("d", "addr", "id", "name") or NULL. */
const char *web_param(const web_ctx_t *c, const char *name);
/** Parse a decimal path parameter (no sign, no leading zeros except "0"). */
bool web_param_u32(const web_ctx_t *c, const char *name, uint32_t *out);

typedef enum { WEB_Q_ABSENT = 0, WEB_Q_OK = 1, WEB_Q_INVALID = 2 } web_q_t;
/** Decoded query value. */
web_q_t web_query_str(const web_ctx_t *c, const char *key, char *out, size_t cap);
/** Decimal int64 query value (optional leading '-'). */
web_q_t web_query_i64(const web_ctx_t *c, const char *key, int64_t *out);
/** "1"/"true" -> true, "0"/"false" -> false. */
web_q_t web_query_bool(const web_ctx_t *c, const char *key, bool *out);

/** Copy a request header into buf. Returns false if absent or too long. */
bool web_header(const web_ctx_t *c, const char *name, char *buf, size_t cap);

/** Parse ctx->body as JSON. On failure sends 400 invalid_json and returns NULL. Caller cJSON_Delete()s. */
struct cJSON *web_body_json(web_ctx_t *c);

/** WEB_RF_RAW_BODY: read up to cap bytes. Returns bytes read (> 0), 0 at end, < 0 on error/timeout. */
int web_body_read(web_ctx_t *c, char *buf, size_t cap);

/* ---- Responses (each sends exactly one response) ---- */

/** Add a response header; strings must stay valid until the response is sent. Before sending. */
esp_err_t web_set_header(web_ctx_t *c, const char *name, const char *value);

/** Set "gw_sid=<token>; Path=/; HttpOnly; SameSite=Strict" (token NULL -> expire the cookie). */
esp_err_t web_set_session_cookie(web_ctx_t *c, const char *token);

/** Send a JSON text with status (200/201/202/409...). */
esp_err_t web_send_json(web_ctx_t *c, int status, const char *json, size_t len);

/** Send a finished fixed/dynamic writer's buffer (gw_jw_finish() is called here). */
esp_err_t web_send_jw(web_ctx_t *c, int status, gw_jw_t *w);

/** Send a body-less status (204, or 202 without body). */
esp_err_t web_send_status(web_ctx_t *c, int status);

/** Error body {"error":code,"message":msg,"field":field}; message/field omitted when NULL. */
esp_err_t web_send_error(web_ctx_t *c, int status, const char *code, const char *message, const char *field);

/** Error with extra members written by `extra` into the open error object (e.g. "retry_after", "rules"). */
esp_err_t web_send_error_ex(web_ctx_t *c, int status, const char *code, const char *message,
                            const char *field, void (*extra)(gw_jw_t *w, void *arg), void *arg);

/**
 * Start a chunked response. If w is non-NULL it is initialised in stream mode over an internal
 * chunk buffer whose sink is httpd_resp_send_chunk(). content_type e.g. "application/json",
 * "text/csv; charset=utf-8". Optional download name -> Content-Disposition: attachment.
 */
esp_err_t web_stream_begin(web_ctx_t *c, int status, const char *content_type, const char *filename,
                           gw_jw_t *w);
/** Write raw bytes to a started stream. */
esp_err_t web_stream_write(web_ctx_t *c, const char *data, size_t len);
/** Finish (flushes w if one was given, sends the terminating chunk). */
esp_err_t web_stream_end(web_ctx_t *c, gw_jw_t *w);

/** Map an esp_err_t from a lower layer to a generic error response (503 unavailable / 500 internal). */
esp_err_t web_send_esp_err(web_ctx_t *c, esp_err_t err);

#ifdef __cplusplus
}
#endif
