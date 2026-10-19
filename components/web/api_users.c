/* /users (docs/API.md §4.9): list, create, update, delete. PBKDF2 runs in auth on the async worker. */
#include <string.h>

#include "auth/auth.h"
#include "web_priv.h"

static void user_obj(gw_jw_t *w, const auth_user_info_t *u) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "name", u->name);
    gw_jw_kstr(w, "role", gw_role_name(u->role));
    gw_jw_kbool(w, "must_change", u->must_change);
    gw_jw_key(w, "changed");
    web_json_epoch_ms(w, u->changed_ms);
    gw_jw_obj_close(w);
}

static bool find_user(const char *name, auth_user_info_t *out) {
    auth_user_info_t list[GW_MAX_USERS];
    size_t n = auth_users_list(list, GW_MAX_USERS);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(list[i].name, name) == 0) {
            *out = list[i];
            return true;
        }
    }
    return false;
}

static esp_err_t send_user(web_ctx_t *c, int status, const char *name) {
    auth_user_info_t u;
    if (!find_user(name, &u)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown user", NULL);
    }
    char buf[160];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    user_obj(&w, &u);
    return web_send_jw(c, status, &w);
}

static esp_err_t send_auth_error(web_ctx_t *c, auth_status_t st, uint32_t rules) {
    switch (st) {
    case AUTH_E_POLICY:
        return web_send_policy(c, "password", rules);
    case AUTH_E_BAD_NAME:
        return web_send_validation(c, "name", "format", "1..11 of [a-z0-9_.-], starting with a letter");
    case AUTH_E_BAD_ROLE:
        return web_send_validation(c, "role", "format", "viewer, operator or admin");
    case AUTH_E_NOT_FOUND:
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown user", NULL);
    case AUTH_E_EXISTS:
        return web_send_error(c, 409, WEB_E_EXISTS, "user name taken", NULL);
    case AUTH_E_LIMIT:
        return web_send_error(c, 409, WEB_E_LIMIT, "at most 4 users", NULL);
    case AUTH_E_LAST_ADMIN:
        return web_send_error(c, 409, WEB_E_LAST_ADMIN, "the last admin cannot be removed or demoted", NULL);
    case AUTH_E_SELF:
        return web_send_error(c, 409, WEB_E_SELF, "use the password page for your own account", NULL);
    default:
        return web_send_error(c, auth_http_status(st), auth_status_code(st), NULL, NULL);
    }
}

static void wipe_member(cJSON *obj, const char *name) {
    cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsString(it) && it->valuestring) {
        memset(it->valuestring, 0, strlen(it->valuestring));
    }
}

esp_err_t h_users_list(web_ctx_t *c) {
    auth_user_info_t list[GW_MAX_USERS];
    size_t n = auth_users_list(list, GW_MAX_USERS);
    char buf[640];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_arr_open(&w);
    for (size_t i = 0; i < n; i++) {
        user_obj(&w, &list[i]);
    }
    gw_jw_arr_close(&w);
    return web_send_jw(c, 200, &w);
}

esp_err_t h_users_create(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"name", "role", "password", "must_change", NULL};
    const char *name = NULL, *role_s = NULL, *pass = NULL;
    bool must_change = true;
    bool mc_present = false;
    esp_err_t ret = ESP_OK;
    if (web_json_only(c, root, allowed, NULL) && web_json_str(c, root, "name", 32, &name, NULL) &&
        web_json_str(c, root, "role", 16, &role_s, NULL) &&
        web_json_str(c, root, "password", 256, &pass, NULL) &&
        web_json_bool(c, root, "must_change", &must_change, &mc_present)) {
        gw_role_t role;
        if (!gw_role_from_name(role_s, &role)) {
            ret = send_auth_error(c, AUTH_E_BAD_ROLE, 0);
        } else {
            uint32_t rules = 0;
            auth_status_t st = auth_user_add(name, role, pass, must_change, web_user(c), &rules);
            ret = st == AUTH_OK ? send_user(c, 201, name) : send_auth_error(c, st, rules);
        }
    }
    wipe_member(root, "password");
    cJSON_Delete(root);
    return ret;
}

esp_err_t h_users_update(web_ctx_t *c) {
    const char *name = web_param(c, "name");
    if (!name || !auth_name_valid(name)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown user", NULL);
    }
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"role", "password", "must_change", NULL};
    const char *role_s = NULL, *pass = NULL;
    bool mc = false, has_role = false, has_pass = false, has_mc = false;
    esp_err_t ret = ESP_OK;
    if (web_json_only(c, root, allowed, NULL) && web_json_str(c, root, "role", 16, &role_s, &has_role) &&
        web_json_str(c, root, "password", 256, &pass, &has_pass) &&
        web_json_bool(c, root, "must_change", &mc, &has_mc)) {
        gw_role_t role = GW_ROLE_NONE;
        if (!has_role && !has_pass && !has_mc) {
            ret = web_send_validation(c, NULL, "required", "nothing to change");
        } else if (has_role && !gw_role_from_name(role_s, &role)) {
            ret = send_auth_error(c, AUTH_E_BAD_ROLE, 0);
        } else {
            uint32_t rules = 0;
            auth_status_t st = auth_user_update(name, role, has_pass ? pass : NULL,
                                                has_mc ? (mc ? 1 : 0) : -1, web_user(c), &rules);
            ret = st == AUTH_OK ? send_user(c, 200, name) : send_auth_error(c, st, rules);
        }
    }
    wipe_member(root, "password");
    cJSON_Delete(root);
    return ret;
}

esp_err_t h_users_delete(web_ctx_t *c) {
    const char *name = web_param(c, "name");
    if (!name || !auth_name_valid(name)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown user", NULL);
    }
    auth_status_t st = auth_user_delete(name, web_user(c));
    return st == AUTH_OK ? web_send_status(c, 204) : send_auth_error(c, st, 0);
}
