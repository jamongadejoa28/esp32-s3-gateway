/* Default-deny REST router (web/router.h): Host check, route match, session, role, must_change,
 * Origin/Referer, CSRF, body limits, async dispatch of slow handlers, request helpers. */
#include <stdlib.h>
#include <string.h>

#include "auth/auth.h"
#include "gw_core/gw_crypto.h"
#include "esp_log.h"
#include "net/net.h"
#include "web/router.h"
#include "web/web_path.h"
#include "web_core.h"
#include "web_priv.h"

static const char *TAG = "web_router";

static_assert(WEB_RF_CSRF == WEB_CORE_RF_CSRF, "flag mismatch");
static_assert(WEB_RF_ALLOW_MUST_CHANGE == WEB_CORE_RF_ALLOW_MUST_CHANGE, "flag mismatch");
static_assert(WEB_RF_RAW_BODY == WEB_CORE_RF_RAW_BODY, "flag mismatch");
static_assert(WEB_RF_SLOW == WEB_CORE_RF_SLOW, "flag mismatch");
static_assert(WEB_RF_NO_TOUCH == WEB_CORE_RF_NO_TOUCH, "flag mismatch");
static_assert(HTTP_GET == WEB_CORE_M_GET && HTTP_POST == WEB_CORE_M_POST && HTTP_PUT == WEB_CORE_M_PUT &&
                  HTTP_DELETE == WEB_CORE_M_DELETE,
              "method mismatch");

#define HOST_HDR_MAX 96
#define ORIGIN_HDR_MAX 256
#define COOKIE_HDR_MAX 512
#define BODY_RECV_RETRIES 3

typedef struct {
    const web_route_t *routes;
    size_t n;
} route_table_t;

static route_table_t s_tables[WEB_MAX_ROUTE_TABLES];
static size_t s_n_tables;

esp_err_t web_router_register(const web_route_t *routes, size_t n) {
    if (!routes || !n) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_n_tables >= WEB_MAX_ROUTE_TABLES) {
        return ESP_ERR_NO_MEM;
    }
    for (size_t i = 0; i < s_n_tables; i++) {
        if (s_tables[i].routes == routes) {
            return ESP_OK;
        }
    }
    s_tables[s_n_tables].routes = routes;
    s_tables[s_n_tables].n = n;
    s_n_tables++;
    return ESP_OK;
}

static const web_route_t *find_route(int method, const char *path, size_t len, web_params_t *params) {
    for (size_t t = 0; t < s_n_tables; t++) {
        for (size_t i = 0; i < s_tables[t].n; i++) {
            const web_route_t *r = &s_tables[t].routes[i];
            if ((int)r->method == method && web_path_match(r->pattern, path, len, params)) {
                return r;
            }
        }
    }
    return NULL;
}

/* Header copy helper usable without a ctx. */
static bool hdr(httpd_req_t *req, const char *name, char *buf, size_t cap) {
    size_t n = httpd_req_get_hdr_value_len(req, name);
    if (n == 0 || n + 1 > cap) {
        return false;
    }
    return httpd_req_get_hdr_value_str(req, name, buf, cap) == ESP_OK;
}

bool web_host_check(httpd_req_t *req) {
    char host[HOST_HDR_MAX];
    if (hdr(req, "Host", host, sizeof(host)) && net_host_allowed(host)) {
        return true;
    }
    web_send_error_raw(req, 421, WEB_E_MISDIRECTED);
    return false;
}

typedef enum { BODY_OK = 0, BODY_NO_MEM, BODY_IO } body_rc_t;

static body_rc_t read_body(web_ctx_t *c) {
    const size_t len = c->req->content_len;
    if (!len) {
        return BODY_OK;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        ESP_LOGE(TAG, "no memory for a %u byte body", (unsigned)len);
        return BODY_NO_MEM;
    }
    size_t got = 0;
    int retries = 0;
    while (got < len) {
        int r = httpd_req_recv(c->req, buf + got, len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT && ++retries <= BODY_RECV_RETRIES) {
            continue;
        }
        if (r <= 0) {
            free(buf);
            return BODY_IO;
        }
        got += (size_t)r;
    }
    buf[len] = '\0';
    c->body = buf;
    c->body_len = len;
    return BODY_OK;
}

bool web_router_run_handler(web_ctx_t *ctx) {
    esp_err_t err = ctx->route->handler(ctx);
    if (!ctx->responded) {
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "%s failed without a response: %s", ctx->route->pattern, esp_err_to_name(err));
        } else {
            ESP_LOGE(TAG, "%s sent no response", ctx->route->pattern);
        }
        web_send_error(ctx, 500, WEB_E_INTERNAL, NULL, NULL);
        /* A RAW_BODY handler may have left part of the body unread: do not let httpd drain it. */
        return (ctx->route->flags & WEB_RF_RAW_BODY) != 0;
    }
    /* Response already sent or started (stream) and the handler failed: close the connection so
     * the client sees the truncation and httpd does not drain an unread upload body. On the httpd
     * task the caller returns ESP_FAIL (synchronous session delete, no control-mailbox slot). */
    return err != ESP_OK;
}

static void wipe_ctx(web_ctx_t *c) {
    if (c->body) {
        gw_secure_zero(c->body, c->body_len); /* bodies may carry passwords */
        free(c->body);
        c->body = NULL;
    }
    memset(&c->sess, 0, sizeof(c->sess));
}

esp_err_t web_router_dispatch(httpd_req_t *req) {
    web_rstate_t rs;
    memset(&rs, 0, sizeof(rs));
    req->user_ctx = &rs;

    /* IP allowlist per request too: open_fn only saw the connection when it was accepted and the
     * list may have been narrowed since (keep-alive). Excluded peers are dropped without an answer. */
    const int fd = httpd_req_to_sockfd(req);
    if (!net_ip_allowed_fd(fd)) {
        ESP_LOGD(TAG, "fd %d no longer allowed by the IP allowlist: closing", fd);
        return ESP_FAIL;
    }

    if (!web_host_check(req)) {
        return ESP_OK;
    }
    const char *uri = req->uri;
    const char *q = strchr(uri, '?');
    const size_t path_len = q ? (size_t)(q - uri) : strlen(uri);
    const bool api = path_len >= strlen(WEB_API_PREFIX) &&
                     strncmp(uri, WEB_API_PREFIX, strlen(WEB_API_PREFIX)) == 0 &&
                     (path_len == strlen(WEB_API_PREFIX) || uri[strlen(WEB_API_PREFIX)] == '/');
    if (!api) {
        if (req->method == HTTP_GET && path_len > 0) {
            esp_err_t r = web_static_serve(req, uri, path_len);
            web_rstate_cleanup(&rs);
            return r;
        }
        rs.api = true;
        web_send_error_raw(req, 404, WEB_E_NOT_FOUND);
        return ESP_OK;
    }
    rs.api = true;

    web_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = req;
    if (q && strlen(q + 1) >= sizeof(ctx.query)) {
        web_send_error_raw(req, 400, WEB_E_BAD_REQUEST);
        return ESP_OK;
    }
    if (q) {
        gw_strlcpy(ctx.query, q + 1, sizeof(ctx.query));
    }
    const web_route_t *route = find_route(req->method, uri, path_len, &ctx.params);
    if (!route) {
        web_send_error_raw(req, 404, WEB_E_NOT_FOUND);
        return ESP_OK;
    }
    ctx.route = route;
    uint32_t local = 0;
    if (!net_sock_info(fd, &ctx.client_ip, &local, &ctx.via_ap)) {
        ctx.client_ip = 0;
        ctx.via_ap = false;
    }

    /* Step 2: session (resolved whenever a cookie is sent, also on public routes). */
    char *cookie = malloc(COOKIE_HDR_MAX);
    if (!cookie) {
        web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
        return ESP_OK;
    }
    char token[AUTH_TOKEN_SZ + 8];
    if (hdr(req, "Cookie", cookie, COOKIE_HDR_MAX) &&
        web_cookie_get(cookie, AUTH_COOKIE_NAME, token, sizeof(token)) &&
        auth_session_lookup(token, !(route->flags & WEB_RF_NO_TOUCH), &ctx.sess) == AUTH_OK) {
        ctx.authed = true;
    }
    free(cookie);
    memset(token, 0, sizeof(token));

    /* Steps 3-6 decision inputs. */
    web_facts_t f = {.method = req->method,
                     .authed = ctx.authed,
                     .role = ctx.authed ? ctx.sess.role : GW_ROLE_NONE,
                     .must_change = ctx.authed && ctx.sess.must_change,
                     .content_len = req->content_len};
    char *hbuf = malloc(ORIGIN_HDR_MAX + HOST_HDR_MAX);
    if (!hbuf) {
        wipe_ctx(&ctx);
        web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
        return ESP_OK;
    }
    char *origin = hbuf;
    char *host = hbuf + ORIGIN_HDR_MAX;
    host[0] = '\0';
    (void)hdr(req, "Host", host, HOST_HDR_MAX);
    const bool has_origin = hdr(req, "Origin", origin, ORIGIN_HDR_MAX);
    const bool has_referer = !has_origin && hdr(req, "Referer", origin, ORIGIN_HDR_MAX);
    if (!has_origin && !has_referer &&
        (httpd_req_get_hdr_value_len(req, "Origin") || httpd_req_get_hdr_value_len(req, "Referer"))) {
        f.origin_present = true; /* present but too long to check: refuse */
        f.origin_ok = false;
    } else if (has_origin || has_referer) {
        f.origin_present = true;
        f.origin_ok = web_origin_matches_host(origin, host);
    }
    char csrf[AUTH_CSRF_SZ + 8];
    f.csrf_ok =
        ctx.authed && hdr(req, WEB_CSRF_HEADER, csrf, sizeof(csrf)) && auth_csrf_ok(ctx.sess.sid, csrf);
    char ct[64];
    f.content_type_json = hdr(req, "Content-Type", ct, sizeof(ct)) && web_ct_is_json(ct);
    free(hbuf);

    const web_rpolicy_t pol = {
        .min_role = route->min_role, .flags = route->flags, .max_body = route->max_body};
    web_verdict_t v = web_policy_decide(&pol, &f);
    if (v.status) {
        wipe_ctx(&ctx);
        web_send_error_raw(req, v.status, v.code);
        /* Small refused bodies are drained by httpd (keep-alive); large ones close the socket. */
        return req->content_len > WEB_BODY_IMPORT_MAX ? ESP_FAIL : ESP_OK;
    }

    if (!(route->flags & WEB_RF_RAW_BODY)) {
        body_rc_t br = read_body(&ctx);
        if (br == BODY_NO_MEM) {
            wipe_ctx(&ctx);
            web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
            return ESP_OK;
        }
        if (br != BODY_OK) {
            wipe_ctx(&ctx);
            return ESP_FAIL; /* socket error mid-body: drop the connection */
        }
    }

    if (route->flags & WEB_RF_SLOW) {
        esp_err_t err = web_async_submit(req, &ctx);
        if (err == ESP_OK) {
            /* body ownership moved to the async job */
            memset(&ctx.sess, 0, sizeof(ctx.sess));
            return ESP_OK;
        }
        wipe_ctx(&ctx);
        web_send_error_raw(req, 503, WEB_E_BUSY);
        return ESP_OK;
    }

    const bool close_conn = web_router_run_handler(&ctx);
    wipe_ctx(&ctx);
    web_rstate_cleanup(&rs);
    return close_conn ? ESP_FAIL : ESP_OK; /* ESP_FAIL: httpd deletes the session right away */
}

/* ---------------------------------------------------------------- request helpers */

const char *web_param(const web_ctx_t *c, const char *name) {
    return c ? web_params_get(&c->params, name) : NULL;
}

bool web_param_u32(const web_ctx_t *c, const char *name, uint32_t *out) {
    const char *s = web_param(c, name);
    if (!s || !*s || (s[0] == '0' && s[1])) {
        return false;
    }
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        v = v * 10u + (uint64_t)(*p - '0');
        if (v > UINT32_MAX) {
            return false;
        }
    }
    *out = (uint32_t)v;
    return true;
}

/* True if the raw query contains key (decoded comparison). */
static bool query_has(const char *query, const char *key) {
    char tmp[2];
    if (web_query_get(query, key, tmp, sizeof(tmp))) {
        return true;
    }
    const size_t kl = strlen(key);
    for (const char *p = query; p && *p;) {
        const char *amp = strchr(p, '&');
        const char *end = amp ? amp : p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        const char *ke = eq ? eq : end;
        char kb[32];
        if ((size_t)(ke - p) < sizeof(kb) && web_url_decode(p, (size_t)(ke - p), kb, sizeof(kb)) == (int)kl &&
            memcmp(kb, key, kl) == 0) {
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

web_q_t web_query_str(const web_ctx_t *c, const char *key, char *out, size_t cap) {
    if (!c || !key || !out || !cap) {
        return WEB_Q_INVALID;
    }
    if (web_query_get(c->query, key, out, cap)) {
        return WEB_Q_OK;
    }
    out[0] = '\0';
    return query_has(c->query, key) ? WEB_Q_INVALID : WEB_Q_ABSENT;
}

web_q_t web_query_i64(const web_ctx_t *c, const char *key, int64_t *out) {
    char b[24];
    web_q_t r = web_query_str(c, key, b, sizeof(b));
    if (r != WEB_Q_OK) {
        return r;
    }
    const char *p = b;
    bool neg = false;
    if (*p == '-') {
        neg = true;
        p++;
    }
    if (!*p || strlen(p) > 18) {
        return WEB_Q_INVALID;
    }
    int64_t v = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') {
            return WEB_Q_INVALID;
        }
        v = v * 10 + (*p - '0');
    }
    *out = neg ? -v : v;
    return WEB_Q_OK;
}

web_q_t web_query_bool(const web_ctx_t *c, const char *key, bool *out) {
    char b[8];
    web_q_t r = web_query_str(c, key, b, sizeof(b));
    if (r != WEB_Q_OK) {
        return r;
    }
    if (!strcmp(b, "1") || !strcmp(b, "true")) {
        *out = true;
    } else if (!strcmp(b, "0") || !strcmp(b, "false")) {
        *out = false;
    } else {
        return WEB_Q_INVALID;
    }
    return WEB_Q_OK;
}

bool web_header(const web_ctx_t *c, const char *name, char *buf, size_t cap) {
    return c && name && buf && cap && hdr(c->req, name, buf, cap);
}

cJSON *web_body_json(web_ctx_t *c) {
    cJSON *root = (c->body && c->body_len) ? cJSON_ParseWithLength(c->body, c->body_len) : NULL;
    if (!root) {
        web_send_error(c, 400, WEB_E_INVALID_JSON, "body is not valid JSON", NULL);
    }
    return root;
}

int web_body_read(web_ctx_t *c, char *buf, size_t cap) {
    if (!c || !buf || !cap) {
        return -1;
    }
    for (int retries = 0;; retries++) {
        int r = httpd_req_recv(c->req, buf, cap);
        if (r == HTTPD_SOCK_ERR_TIMEOUT && retries < BODY_RECV_RETRIES) {
            continue;
        }
        return r < 0 ? -1 : r;
    }
}
