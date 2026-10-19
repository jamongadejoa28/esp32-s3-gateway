/* /auth/login, /auth/logout, /session, /auth/password (docs/API.md §4.1). */
#include <string.h>

#include "auth/auth.h"
#include "esp_log.h"
#include "web_priv.h"

static const char *TAG = "api_auth";

static void wipe_str(cJSON *obj, const char *name) {
    cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsString(it) && it->valuestring) {
        memset(it->valuestring, 0, strlen(it->valuestring));
    }
}

static void retry_extra(gw_jw_t *w, void *arg) {
    gw_jw_kuint(w, "retry_after", *(const uint32_t *)arg);
}

esp_err_t web_send_rate_limited(web_ctx_t *c, uint32_t retry_after_s, const char *message) {
    uint32_t r = retry_after_s ? retry_after_s : 1;
    return web_send_error_ex(c, 429, WEB_E_RATE_LIMITED, message, NULL, retry_extra, &r);
}

static void rules_extra(gw_jw_t *w, void *arg) {
    gw_jw_key(w, "rules");
    web_json_policy_rules(w, *(const uint32_t *)arg);
}

esp_err_t web_send_policy(web_ctx_t *c, const char *field, uint32_t rules) {
    return web_send_error_ex(c, 422, WEB_E_POLICY, "password does not meet the policy", field, rules_extra,
                             &rules);
}

static void session_body(gw_jw_t *w, const auth_session_info_t *s, bool with_expiry) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "user", s->user);
    gw_jw_kstr(w, "role", gw_role_name(s->role));
    gw_jw_kstr(w, "csrf", s->csrf);
    gw_jw_kbool(w, "must_change", s->must_change);
    gw_jw_kuint(w, "idle_s", s->idle_s);
    if (with_expiry) {
        gw_jw_kuint(w, "expires_in", s->idle_left_s < s->abs_left_s ? s->idle_left_s : s->abs_left_s);
    }
    gw_jw_obj_close(w);
}

esp_err_t h_auth_login(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"user", "pass", NULL};
    const char *user = NULL;
    const char *pass = NULL;
    if (!web_json_only(c, root, allowed, NULL) || !web_json_str(c, root, "user", 64, &user, NULL) ||
        !web_json_str(c, root, "pass", 256, &pass, NULL)) {
        wipe_str(root, "pass");
        cJSON_Delete(root);
        return ESP_OK;
    }
    char token[AUTH_TOKEN_SZ];
    auth_session_info_t info;
    uint32_t retry = 0;
    auth_status_t st = auth_login(user, pass, c->client_ip, token, &info, &retry);
    wipe_str(root, "pass");
    cJSON_Delete(root);
    switch (st) {
    case AUTH_OK: {
        char buf[192];
        gw_jw_t w;
        gw_jw_init_fixed(&w, buf, sizeof(buf));
        session_body(&w, &info, false);
        web_set_session_cookie(c, token);
        memset(token, 0, sizeof(token));
        memset(&info, 0, sizeof(info));
        esp_err_t err = web_send_jw(c, 200, &w);
        memset(buf, 0, sizeof(buf));
        return err;
    }
    case AUTH_E_LOCKED:
        return web_send_rate_limited(c, retry, "too many failed logins");
    case AUTH_E_BAD_CREDENTIALS:
        return web_send_error(c, 401, WEB_E_BAD_CREDENTIALS, "wrong user name or password", NULL);
    default:
        ESP_LOGW(TAG, "login failed internally (%d)", (int)st);
        return web_send_error(c, auth_http_status(st), auth_status_code(st), NULL, NULL);
    }
}

esp_err_t h_auth_logout(web_ctx_t *c) {
    auth_logout(c->sess.sid);
    web_set_session_cookie(c, NULL);
    return web_send_status(c, 204);
}

esp_err_t h_session(web_ctx_t *c) {
    if (!c->authed) {
        return web_send_json(c, 401, "{}", 2);
    }
    char buf[192];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    session_body(&w, &c->sess, true);
    esp_err_t err = web_send_jw(c, 200, &w);
    memset(buf, 0, sizeof(buf));
    return err;
}

esp_err_t h_auth_password(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"current", "new", NULL};
    const char *cur = NULL;
    const char *nw = NULL;
    if (!web_json_only(c, root, allowed, NULL) || !web_json_str(c, root, "current", 256, &cur, NULL) ||
        !web_json_str(c, root, "new", 256, &nw, NULL)) {
        wipe_str(root, "current");
        wipe_str(root, "new");
        cJSON_Delete(root);
        return ESP_OK;
    }
    uint32_t rules = 0;
    uint32_t retry = 0;
    auth_status_t st = auth_change_password(c->sess.sid, cur, nw, c->client_ip, &rules, &retry);
    wipe_str(root, "current");
    wipe_str(root, "new");
    cJSON_Delete(root);
    switch (st) {
    case AUTH_OK:
        return web_send_status(c, 204);
    case AUTH_E_LOCKED:
        return web_send_rate_limited(c, retry, "too many failed attempts");
    case AUTH_E_WRONG_PASSWORD:
        return web_send_error(c, 422, WEB_E_WRONG_PASSWORD, "current password is wrong", "current");
    case AUTH_E_POLICY:
        return web_send_policy(c, "new", rules);
    case AUTH_E_NO_SESSION:
        return web_send_error(c, 401, WEB_E_UNAUTHORIZED, NULL, NULL);
    default:
        return web_send_error(c, auth_http_status(st), auth_status_code(st), NULL, NULL);
    }
}
