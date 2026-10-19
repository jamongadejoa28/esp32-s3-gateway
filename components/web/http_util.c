/* Response helpers (web/router.h) and shared handler utilities (web_priv.h): JSON replies and
 * errors exactly as docs/API.md §2, security headers on every response, chunked streams. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "store/config.h"
#include "web_priv.h"

static const char *TAG = "web_http";

#define CSP_VALUE                                                                                            \
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "    \
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
#define ERR_BUF_SZ 512

/* ---------------------------------------------------------------- response state */

web_rstate_t *web_rs(httpd_req_t *req) {
    return (web_rstate_t *)req->user_ctx;
}

void web_rstate_cleanup(web_rstate_t *rs) {
    if (rs && rs->chunk) {
        free(rs->chunk);
        rs->chunk = NULL;
    }
}

void web_security_headers(httpd_req_t *req) {
    web_rstate_t *rs = web_rs(req);
    if (rs && rs->headers_done) {
        return;
    }
    httpd_resp_set_hdr(req, "Content-Security-Policy", CSP_VALUE);
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    if (!rs || (rs->api && !rs->cache_set)) {
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    }
    if (rs) {
        rs->headers_done = true;
    }
}

static esp_err_t send_body(httpd_req_t *req, int status, const char *type, const char *body, size_t len) {
    httpd_resp_set_status(req, web_status_line(status));
    httpd_resp_set_type(req, type);
    web_security_headers(req);
    esp_err_t err = httpd_resp_send(req, body, (ssize_t)len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "send failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t web_send_error_raw(httpd_req_t *req, int status, const char *code) {
    char buf[96];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    web_json_error(&w, code, NULL, NULL);
    if (gw_jw_finish(&w) != GW_JW_OK) {
        return ESP_FAIL;
    }
    return send_body(req, status, "application/json", gw_jw_data(&w), gw_jw_length(&w));
}

/* ---------------------------------------------------------------- router.h responses */

esp_err_t web_set_header(web_ctx_t *c, const char *name, const char *value) {
    if (!c || !name || !value) {
        return ESP_ERR_INVALID_ARG;
    }
    web_rstate_t *rs = web_rs(c->req);
    if (rs && strcasecmp(name, "Cache-Control") == 0) {
        rs->cache_set = true;
    }
    return httpd_resp_set_hdr(c->req, name, value);
}

esp_err_t web_set_session_cookie(web_ctx_t *c, const char *token) {
    web_rstate_t *rs = web_rs(c->req);
    if (!rs) {
        return ESP_ERR_INVALID_STATE;
    }
    int n;
    if (token && token[0]) {
        n = snprintf(rs->cookie, sizeof(rs->cookie),
                     AUTH_COOKIE_NAME "=%s; Path=/; HttpOnly; SameSite=Strict", token);
    } else {
        n = snprintf(rs->cookie, sizeof(rs->cookie),
                     AUTH_COOKIE_NAME "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    }
    if (n <= 0 || (size_t)n >= sizeof(rs->cookie)) {
        return ESP_ERR_INVALID_SIZE;
    }
    return httpd_resp_set_hdr(c->req, "Set-Cookie", rs->cookie);
}

esp_err_t web_send_json(web_ctx_t *c, int status, const char *json, size_t len) {
    if (c->responded) {
        return ESP_ERR_INVALID_STATE;
    }
    c->responded = true;
    return send_body(c->req, status, "application/json", json, len);
}

esp_err_t web_send_body(web_ctx_t *c, int status, const char *type, const char *body, size_t len) {
    if (c->responded) {
        return ESP_ERR_INVALID_STATE;
    }
    c->responded = true;
    return send_body(c->req, status, type, body, len);
}

esp_err_t web_send_jw(web_ctx_t *c, int status, gw_jw_t *w) {
    if (gw_jw_finish(w) != GW_JW_OK) {
        ESP_LOGE(TAG, "json writer error %d", gw_jw_error(w));
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
    return web_send_json(c, status, gw_jw_data(w), gw_jw_length(w));
}

esp_err_t web_send_status(web_ctx_t *c, int status) {
    if (c->responded) {
        return ESP_ERR_INVALID_STATE;
    }
    c->responded = true;
    httpd_resp_set_status(c->req, web_status_line(status));
    web_security_headers(c->req);
    return httpd_resp_send(c->req, NULL, 0);
}

esp_err_t web_send_error_ex(web_ctx_t *c, int status, const char *code, const char *message,
                            const char *field, void (*extra)(gw_jw_t *w, void *arg), void *arg) {
    char *buf = malloc(ERR_BUF_SZ);
    if (!buf) {
        c->responded = true;
        return send_body(c->req, status, "application/json", "{\"error\":\"internal\"}", 20);
    }
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, ERR_BUF_SZ);
    web_json_error_open(&w, code, message, field);
    if (extra) {
        extra(&w, arg);
    }
    gw_jw_obj_close(&w);
    esp_err_t err;
    if (gw_jw_finish(&w) == GW_JW_OK) {
        err = web_send_json(c, status, gw_jw_data(&w), gw_jw_length(&w));
    } else {
        /* message too long or extra() misbehaved: fall back to the bare code */
        c->responded = false;
        gw_jw_init_fixed(&w, buf, ERR_BUF_SZ);
        web_json_error(&w, code, NULL, NULL);
        gw_jw_finish(&w);
        err = web_send_json(c, status, gw_jw_data(&w), gw_jw_length(&w));
    }
    free(buf);
    return err;
}

esp_err_t web_send_error(web_ctx_t *c, int status, const char *code, const char *message, const char *field) {
    return web_send_error_ex(c, status, code, message, field, NULL, NULL);
}

esp_err_t web_send_esp_err(web_ctx_t *c, esp_err_t err) {
    switch (err) {
    case ESP_ERR_NO_MEM:
    case ESP_ERR_TIMEOUT:
    case ESP_ERR_INVALID_STATE:
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, esp_err_to_name(err), NULL);
    default:
        return web_send_error(c, 500, WEB_E_INTERNAL, esp_err_to_name(err), NULL);
    }
}

/* ---------------------------------------------------------------- chunked streams */

static int stream_sink(void *arg, const char *data, size_t len) {
    web_ctx_t *c = arg;
    return httpd_resp_send_chunk(c->req, data, (ssize_t)len) == ESP_OK ? 0 : -1;
}

static void sanitize_filename(char *dst, size_t cap, const char *src) {
    size_t o = 0;
    for (const char *p = src; *p && o + 1 < cap; p++) {
        char ch = *p;
        bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '.';
        dst[o++] = ok ? ch : '_';
    }
    dst[o] = '\0';
}

esp_err_t web_stream_begin(web_ctx_t *c, int status, const char *content_type, const char *filename,
                           gw_jw_t *w) {
    if (c->responded) {
        return ESP_ERR_INVALID_STATE;
    }
    web_rstate_t *rs = web_rs(c->req);
    rs->chunk = malloc(WEB_CHUNK_SZ);
    if (!rs->chunk) {
        web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
        return ESP_ERR_NO_MEM; /* response sent; the handler just returns ESP_OK */
    }
    rs->streaming = true;
    rs->chunk_len = 0;
    c->responded = true;
    httpd_resp_set_status(c->req, web_status_line(status));
    httpd_resp_set_type(c->req, content_type ? content_type : "application/octet-stream");
    if (filename && filename[0]) {
        char safe[80];
        sanitize_filename(safe, sizeof(safe), filename);
        snprintf(rs->disposition, sizeof(rs->disposition), "attachment; filename=\"%s\"", safe);
        httpd_resp_set_hdr(c->req, "Content-Disposition", rs->disposition);
    }
    web_security_headers(c->req);
    if (w) {
        gw_jw_init_stream(w, rs->chunk, WEB_CHUNK_SZ, stream_sink, c);
    }
    return ESP_OK;
}

esp_err_t web_stream_write(web_ctx_t *c, const char *data, size_t len) {
    web_rstate_t *rs = web_rs(c->req);
    if (!rs || !rs->streaming || !rs->chunk) {
        return ESP_ERR_INVALID_STATE;
    }
    while (len) {
        size_t room = WEB_CHUNK_SZ - rs->chunk_len;
        size_t n = len < room ? len : room;
        memcpy(rs->chunk + rs->chunk_len, data, n);
        rs->chunk_len += n;
        data += n;
        len -= n;
        if (rs->chunk_len == WEB_CHUNK_SZ) {
            esp_err_t err = httpd_resp_send_chunk(c->req, rs->chunk, (ssize_t)rs->chunk_len);
            rs->chunk_len = 0;
            if (err != ESP_OK) {
                return err;
            }
        }
    }
    return ESP_OK;
}

esp_err_t web_stream_end(web_ctx_t *c, gw_jw_t *w) {
    web_rstate_t *rs = web_rs(c->req);
    if (!rs || !rs->streaming) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = ESP_OK;
    if (w) {
        err = gw_jw_finish(w) == GW_JW_OK ? ESP_OK : ESP_FAIL;
    } else if (rs->chunk_len) {
        err = httpd_resp_send_chunk(c->req, rs->chunk, (ssize_t)rs->chunk_len);
        rs->chunk_len = 0;
    }
    if (err == ESP_OK) {
        err = httpd_resp_send_chunk(c->req, NULL, 0);
    }
    rs->streaming = false;
    web_rstate_cleanup(rs);
    return err;
}

/* ---------------------------------------------------------------- handler utilities */

const char *web_user(const web_ctx_t *c) {
    return (c && c->authed) ? c->sess.user : "";
}

bool web_dev_param(web_ctx_t *c, uint8_t *dev) {
    uint32_t d = 0;
    if (web_param_u32(c, "d", &d) && d < GW_MAX_DEVICES) {
        cfg_modbus_t *m = malloc(sizeof(*m));
        bool ok = false;
        if (m && cfg_get_section(CFG_SEC_MODBUS, m, sizeof(*m)) == ESP_OK) {
            for (size_t i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++) {
                if (m->devices[i].id == d) {
                    ok = true;
                    break;
                }
            }
        }
        free(m);
        if (ok) {
            *dev = (uint8_t)d;
            return true;
        }
    }
    web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown device", NULL);
    return false;
}

typedef struct {
    const char *code;
} verr_arg_t;

static void verr_extra(gw_jw_t *w, void *arg) {
    const verr_arg_t *a = arg;
    if (a->code) {
        gw_jw_kstr(w, "code", a->code);
    }
}

esp_err_t web_send_validation(web_ctx_t *c, const char *field, const char *code, const char *message) {
    verr_arg_t a = {.code = code};
    return web_send_error_ex(c, 422, WEB_E_VALIDATION, message ? message : "invalid value", field, verr_extra,
                             &a);
}

esp_err_t web_send_unknown_register(web_ctx_t *c) {
    verr_arg_t a = {.code = "unknown_register"};
    return web_send_error_ex(c, 404, WEB_E_NOT_FOUND, "address not in the register map", NULL, verr_extra,
                             &a);
}

esp_err_t web_send_cfg_verr(web_ctx_t *c, const char *field, const char *code) {
    if (code && strcmp(code, "unsupported_schema") == 0) {
        return web_send_validation(c, field && field[0] ? field : "schema", code,
                                   "unsupported schema version");
    }
    return web_send_validation(c, field && field[0] ? field : NULL, code && code[0] ? code : "format", NULL);
}

cJSON *web_body_object(web_ctx_t *c) {
    cJSON *root = web_body_json(c);
    if (root && !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        web_send_error(c, 400, WEB_E_INVALID_JSON, "expected a JSON object", NULL);
        return NULL;
    }
    return root;
}

bool web_json_only(web_ctx_t *c, const cJSON *obj, const char *const *allowed, const char *prefix) {
    const cJSON *it;
    cJSON_ArrayForEach(it, obj) {
        bool ok = false;
        for (const char *const *a = allowed; *a; a++) {
            if (it->string && strcmp(it->string, *a) == 0) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            char field[48];
            snprintf(field, sizeof(field), "%s%s", prefix ? prefix : "", it->string ? it->string : "");
            web_send_validation(c, field, "unknown_field", "unknown member");
            return false;
        }
    }
    return true;
}

bool web_json_bool(web_ctx_t *c, const cJSON *obj, const char *name, bool *out, bool *present) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (present) {
        *present = it != NULL;
    }
    if (!it) {
        if (!present) {
            web_send_validation(c, name, "required", "required");
            return false;
        }
        return true;
    }
    if (!cJSON_IsBool(it)) {
        web_send_validation(c, name, "type", "must be a boolean");
        return false;
    }
    *out = cJSON_IsTrue(it);
    return true;
}

bool web_json_int(web_ctx_t *c, const cJSON *obj, const char *name, int64_t min, int64_t max, int64_t *out,
                  bool *present) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (present) {
        *present = it != NULL;
    }
    if (!it) {
        if (!present) {
            web_send_validation(c, name, "required", "required");
            return false;
        }
        return true;
    }
    if (!cJSON_IsNumber(it)) {
        web_send_validation(c, name, "type", "must be an integer");
        return false;
    }
    double d = it->valuedouble;
    if (d != d || d < -9.0e15 || d > 9.0e15 || (double)(int64_t)d != d) {
        web_send_validation(c, name, "type", "must be an integer");
        return false;
    }
    int64_t v = (int64_t)d;
    if (v < min || v > max) {
        web_send_validation(c, name, "range", "out of range");
        return false;
    }
    *out = v;
    return true;
}

bool web_json_str(web_ctx_t *c, const cJSON *obj, const char *name, size_t max_bytes, const char **out,
                  bool *present) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (present) {
        *present = it != NULL;
    }
    if (!it) {
        if (!present) {
            web_send_validation(c, name, "required", "required");
            return false;
        }
        return true;
    }
    if (!cJSON_IsString(it) || !it->valuestring) {
        web_send_validation(c, name, "type", "must be a string");
        return false;
    }
    if (strlen(it->valuestring) > max_bytes) {
        web_send_validation(c, name, "length", "too long");
        return false;
    }
    *out = it->valuestring;
    return true;
}

/* PSRAM-preferring allocator for large writer/cJSON buffers (SPIRAM_USE_MALLOC already places
 * blocks > 4 KB in PSRAM; this keeps mid-size ones out of internal RAM too). */
static void *psram_malloc(size_t n) {
    void *p = heap_caps_malloc_prefer(n, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT, MALLOC_CAP_DEFAULT);
    return p;
}

int web_jw_dynamic(gw_jw_t *w, size_t max_cap) {
    return gw_jw_init_dynamic(w, 512, max_cap);
}

esp_err_t web_send_jw_free(web_ctx_t *c, int status, gw_jw_t *w) {
    esp_err_t err = web_send_jw(c, status, w);
    gw_jw_free(w);
    return err;
}

void web_cjson_hooks_install(void) {
    cJSON_Hooks hooks = {.malloc_fn = psram_malloc, .free_fn = free};
    cJSON_InitHooks(&hooks);
}
