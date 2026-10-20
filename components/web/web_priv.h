/*
 * web_priv.h - device-only internals shared by the web component's translation units.
 * Not a public interface.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "web/router.h"
#include "web_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- per-request response state (req->user_ctx points here while a REST/static request runs) ---- */

#define WEB_CHUNK_SZ 2048

typedef struct {
    bool cache_set;    /* a handler set Cache-Control itself */
    bool headers_done; /* security headers already added */
    bool api;          /* /api request: Cache-Control no-store unless cache_set */
    bool streaming;    /* web_stream_begin() was called */
    size_t chunk_len;  /* bytes buffered in chunk (raw writes) */
    char *chunk;       /* stream mode scratch buffer (freed by web_stream_end / cleanup) */
    char cookie[96];   /* Set-Cookie value storage */
    char disposition[112];
} web_rstate_t;

/** Response state of a request (never NULL for requests that went through the router). */
web_rstate_t *web_rs(httpd_req_t *req);

/** Add CSP/nosniff/no-referrer/X-Frame-Options (+ Cache-Control no-store for API). Idempotent. */
void web_security_headers(httpd_req_t *req);

/** Error response without a router context (Host check, WS handshake, httpd error hooks). */
esp_err_t web_send_error_raw(httpd_req_t *req, int status, const char *code);

/** Free per-request allocations (stream buffer). */
void web_rstate_cleanup(web_rstate_t *rs);

/* ---- server (httpd_srv.c) ---- */

#define WEB_HTTPD_MAX_SOCKETS 12 /* httpd_config_t.max_open_sockets */

httpd_handle_t web_httpd(void);

/** Run a WEB_RF_SLOW request on an async worker lane (login lane for public routes, control lane
 * otherwise). httpd task only. Takes ownership of ctx->body on success; ESP_ERR_NO_MEM = lane busy
 * (nothing was started, the caller answers 503). */
esp_err_t web_async_submit(httpd_req_t *req, const web_ctx_t *ctx);

/** Close a connection from any task: httpd_sess_trigger_close(), or, when the control mailbox is
 * full, shutdown(SHUT_WR) so httpd reads EOF and deletes the session on its next pass. */
void web_close_fd(int sockfd);

/* ---- router (router.c) ---- */

/** Host-header check (step 0). On failure sends 421 and returns false. */
bool web_host_check(httpd_req_t *req);

/** Run route handler with the completed ctx (httpd task or async worker). Sends 500 when the
 * handler did not respond. Returns true when the connection must be closed (the handler failed after
 * starting its response, e.g. a truncated chunked stream, or failed mid-body). */
bool web_router_run_handler(web_ctx_t *ctx);

/** Route tables of this component (api_routes.c). */
extern const web_route_t web_api_routes[];
extern const size_t web_api_routes_count;

/* ---- config handlers (api_config.c) ---- */

/** Create the lock that serializes SNMP secrets + config commits (web_start, before httpd). */
esp_err_t web_api_config_init(void);

/* ---- static UI (static.c) ---- */
esp_err_t web_assets_mount(void);

/** Serve a GET for a non-/api path. Sends 404 when no asset matches. */
esp_err_t web_static_serve(httpd_req_t *req, const char *path, size_t len);

/** ETag of /meta/registers (strong, quoted; build id + register map version). */
const char *web_meta_etag(void);

/* ---- WebSocket hub (ws_hub.c) ---- */

void ws_hub_stop(void);

/* ---- helpers for API handlers (http_util.c) ---- */

/** Acting user name for audit/events ("" when unauthenticated). */
const char *web_user(const web_ctx_t *c);

/** Parse path parameter {d}: 0..GW_MAX_DEVICES-1 and configured; else sends 404 and returns false. */
bool web_dev_param(web_ctx_t *c, uint8_t *dev);

/** 422 validation with field/code ({"error":"validation","message":..,"field":..,"code":..}). */
esp_err_t web_send_validation(web_ctx_t *c, const char *field, const char *code, const char *message);

/** Body JSON object (400 invalid_json if not an object). Caller cJSON_Delete()s. */
cJSON *web_body_object(web_ctx_t *c);

/**
 * Reject members of obj not listed in allowed[] (NULL-terminated): sends 422 validation
 * code "unknown_field" and returns false.
 */
bool web_json_only(web_ctx_t *c, const cJSON *obj, const char *const *allowed, const char *prefix);

/** Typed member access; on a type/range error sends 422 (field = name) and returns false.
 * Absent members leave *out untouched and set *present = false (present may be NULL = required). */
bool web_json_bool(web_ctx_t *c, const cJSON *obj, const char *name, bool *out, bool *present);
bool web_json_int(web_ctx_t *c, const cJSON *obj, const char *name, int64_t min, int64_t max, int64_t *out,
                  bool *present);
bool web_json_str(web_ctx_t *c, const cJSON *obj, const char *name, size_t max_bytes, const char **out,
                  bool *present);

/** Writer on a PSRAM-preferring dynamic buffer (initial 512 B, limit max_cap). */
int web_jw_dynamic(gw_jw_t *w, size_t max_cap);

/** Send the writer's JSON (dynamic or fixed) with status and free it; 500 on writer error. */
esp_err_t web_send_jw_free(web_ctx_t *c, int status, gw_jw_t *w);

/** Send a body of any content type (security headers added). */
esp_err_t web_send_body(web_ctx_t *c, int status, const char *type, const char *body, size_t len);

/** 429 rate_limited with "retry_after". */
esp_err_t web_send_rate_limited(web_ctx_t *c, uint32_t retry_after_s, const char *message);

/** 422 policy with "rules" (auth.h AUTH_PW_* bits). */
esp_err_t web_send_policy(web_ctx_t *c, const char *field, uint32_t rules);

/** 404 not_found with code "unknown_register". */
esp_err_t web_send_unknown_register(web_ctx_t *c);

/** Standard JSON response for a cfg_verr_t. */
esp_err_t web_send_cfg_verr(web_ctx_t *c, const char *field, const char *code);

/** cJSON allocation hooks (PSRAM-preferring) installed once by web_start(). */
void web_cjson_hooks_install(void);

/* ---- handlers (api_*.c), generated from api_routes.def ---- */
#define ROUTE(m, pat, role, flags, body, h) esp_err_t h(web_ctx_t *ctx);
#include "api_routes.def"
#undef ROUTE

#ifdef __cplusplus
}
#endif
