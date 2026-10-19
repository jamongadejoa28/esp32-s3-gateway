/* Web users, login, own-password operations (auth.h). Users live in secrets (store/secrets.h);
 * every change goes through secrets_modify(). PBKDF2 runs outside every lock; callers are the httpd
 * async worker (WEB_RF_SLOW routes) and auth_init() at boot. */
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "auth/auth.h"
#include "auth_priv.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/secrets.h"

static const char *TAG = "auth";

static bool s_inited;

/* ---------------------------------------------------------------- helpers */

/* Heap copy of the secrets (keeps ~1 KB off the caller's stack). Wipe with put_secrets(). */
static gw_secrets_t *get_secrets(void) {
    gw_secrets_t *s = malloc(sizeof(*s));
    if (s) {
        secrets_get(s);
    }
    return s;
}

static void put_secrets(gw_secrets_t *s) {
    if (s) {
        gw_secure_zero(s, sizeof(*s));
        free(s);
    }
}

static size_t count_admins(const gw_secrets_t *s) {
    size_t n = 0;
    for (size_t i = 0; i < s->n_users && i < GW_MAX_USERS; i++) {
        n += (s->users[i].role == GW_ROLE_ADMIN) ? 1u : 0u;
    }
    return n;
}

static bool role_valid(gw_role_t r) {
    return r >= GW_ROLE_VIEWER && r <= GW_ROLE_ADMIN;
}

/* ---- secrets_modify callbacks ---- */

typedef struct {
    const char *name;
    const char *old_hash; /* expected current hash (upgrade/password change), NULL = any */
    const char *new_hash; /* NULL = keep */
    int must_change;      /* -1 keep */
    gw_role_t role;       /* GW_ROLE_NONE = keep */
    bool add;
    bool del;
    auth_status_t st; /* result when the callback refuses */
} user_op_t;

static esp_err_t user_op_fn(gw_secrets_t *s, void *arg) {
    user_op_t *op = arg;
    int idx = sec_find_user(s, op->name);
    if (op->add) {
        if (idx >= 0) {
            op->st = AUTH_E_EXISTS;
            return ESP_FAIL;
        }
        if (s->n_users >= GW_MAX_USERS) {
            op->st = AUTH_E_LIMIT;
            return ESP_FAIL;
        }
        sec_user_t *u = &s->users[s->n_users++];
        memset(u, 0, sizeof(*u));
        gw_strlcpy(u->name, op->name, sizeof(u->name));
        u->role = (uint8_t)op->role;
        u->must_change = op->must_change > 0;
        gw_strlcpy(u->hash, op->new_hash, sizeof(u->hash));
        u->changed_ms = gw_time_wall_ms();
        return ESP_OK;
    }
    if (idx < 0) {
        op->st = AUTH_E_NOT_FOUND;
        return ESP_FAIL;
    }
    sec_user_t *u = &s->users[idx];
    if (op->old_hash && strcmp(u->hash, op->old_hash) != 0) {
        op->st = AUTH_E_STORE; /* concurrent change: refuse rather than overwrite */
        return ESP_FAIL;
    }
    if (op->del) {
        if (u->role == GW_ROLE_ADMIN && count_admins(s) <= 1) {
            op->st = AUTH_E_LAST_ADMIN;
            return ESP_FAIL;
        }
        for (size_t i = (size_t)idx; i + 1 < s->n_users; i++) {
            s->users[i] = s->users[i + 1];
        }
        s->n_users--;
        gw_secure_zero(&s->users[s->n_users], sizeof(s->users[0]));
        return ESP_OK;
    }
    if (op->role != GW_ROLE_NONE && op->role != (gw_role_t)u->role) {
        if (u->role == GW_ROLE_ADMIN && count_admins(s) <= 1) {
            op->st = AUTH_E_LAST_ADMIN;
            return ESP_FAIL;
        }
        u->role = (uint8_t)op->role;
    }
    if (op->new_hash) {
        gw_strlcpy(u->hash, op->new_hash, sizeof(u->hash));
        u->changed_ms = gw_time_wall_ms();
    }
    if (op->must_change >= 0) {
        u->must_change = op->must_change > 0;
    }
    return ESP_OK;
}

static auth_status_t run_user_op(user_op_t *op, const char *by) {
    op->st = AUTH_E_STORE;
    esp_err_t err = secrets_modify(user_op_fn, op, by);
    if (err == ESP_OK) {
        return AUTH_OK;
    }
    if (err != ESP_FAIL) {
        ESP_LOGE(TAG, "secrets_modify failed: %s", esp_err_to_name(err));
        return AUTH_E_STORE;
    }
    return op->st;
}

/* ---------------------------------------------------------------- init / config */

static void apply_security(void) {
    cfg_security_t sec;
    if (cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec)) == ESP_OK) {
        auth_session_apply_security((uint32_t)sec.idle_min * 60u, sec.max_fail, sec.lock_min);
    }
}

static void on_config_changed(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_config_t *ev = data;
    if (ev && ev->section == CFG_SEC_SECURITY) {
        apply_security();
    }
}

static esp_err_t create_factory_admin(void) {
    char hash[SEC_HASH_SZ];
    if (auth_pw_hash(AUTH_FACTORY_PASSWORD, AUTH_PBKDF2_ITER_DEFAULT, hash, sizeof(hash)) != 0) {
        return ESP_FAIL;
    }
    user_op_t op = {
        .name = AUTH_FACTORY_USER, .new_hash = hash, .must_change = 1, .role = GW_ROLE_ADMIN, .add = true};
    auth_status_t st = run_user_op(&op, "@system");
    gw_secure_zero(hash, sizeof(hash));
    if (st != AUTH_OK && st != AUTH_E_EXISTS) {
        return ESP_FAIL;
    }
    ESP_LOGW(TAG, "factory admin account created (password must be changed at first login)");
    return ESP_OK;
}

esp_err_t auth_init(void) {
    if (s_inited) {
        return ESP_OK;
    }
    cfg_security_t sec;
    esp_err_t err = cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "security config unavailable: %s", esp_err_to_name(err));
        return err;
    }
    err = auth_session_module_init((uint32_t)sec.idle_min * 60u, sec.max_fail, sec.lock_min);
    if (err != ESP_OK) {
        return err;
    }
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return ESP_ERR_NO_MEM;
    }
    const bool no_users = s->n_users == 0;
    put_secrets(s);
    if (no_users) {
        err = create_factory_admin();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "cannot create the factory admin");
            return err;
        }
    }
    err = gw_events_register(GW_EVT_CONFIG_CHANGED, on_config_changed, NULL, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "event registration failed: %s", esp_err_to_name(err));
        return err;
    }
    s_inited = true;
    return ESP_OK;
}

/* ---------------------------------------------------------------- login */

/* Re-hash a verified password with the current default cost (iteration upgrade). */
static void maybe_upgrade(const char *user, const char *password, const char *old_hash) {
    uint32_t iter = auth_pw_record_iterations(old_hash);
    if (!iter || iter >= AUTH_PBKDF2_ITER_DEFAULT) {
        return;
    }
    char hash[SEC_HASH_SZ];
    if (auth_pw_hash(password, AUTH_PBKDF2_ITER_DEFAULT, hash, sizeof(hash)) == 0) {
        user_op_t op = {.name = user, .old_hash = old_hash, .new_hash = hash, .must_change = -1};
        if (run_user_op(&op, "@system") == AUTH_OK) {
            ESP_LOGI(TAG, "password record of %s upgraded to %u iterations", user, AUTH_PBKDF2_ITER_DEFAULT);
        }
    }
    gw_secure_zero(hash, sizeof(hash));
}

auth_status_t auth_login(const char *user, const char *password, uint32_t ip, char token_out[AUTH_TOKEN_SZ],
                         auth_session_info_t *info, uint32_t *retry_after_s) {
    if (retry_after_s) {
        *retry_after_s = 0;
    }
    if (token_out) {
        token_out[0] = '\0';
    }
    if (!s_inited || !token_out) {
        return AUTH_E_STORE;
    }
    uint32_t locked = auth_rl_locked_for(ip);
    if (locked) {
        if (retry_after_s) {
            *retry_after_s = locked;
        }
        return AUTH_E_LOCKED;
    }
    uint32_t delay = auth_rl_delay_ms();
    if (delay) {
        vTaskDelay(pdMS_TO_TICKS(delay));
    }
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return AUTH_E_STORE;
    }
    int idx = (user && password) ? sec_find_user(s, user) : -1;
    bool ok = false;
    if (idx >= 0) {
        ok = auth_pw_verify(password, s->users[idx].hash);
    } else {
        auth_pw_dummy_verify(password, AUTH_PBKDF2_ITER_DEFAULT);
    }
    if (!ok) {
        put_secrets(s);
        evlog_audit(AUD_LOGIN_FAIL, EVLOG_DEV_NONE, 0, 0, user, ip);
        uint32_t lock_s = auth_rl_note(ip, user, false);
        if (lock_s) {
            if (retry_after_s) {
                *retry_after_s = lock_s;
            }
            return AUTH_E_LOCKED;
        }
        return AUTH_E_BAD_CREDENTIALS;
    }
    (void)auth_rl_note(ip, s->users[idx].name, true);
    sec_user_t u = s->users[idx];
    put_secrets(s);
    maybe_upgrade(u.name, password, u.hash);
    auth_status_t st = AUTH_OK;
    if (!auth_session_create(u.name, (gw_role_t)u.role, u.must_change, token_out, info)) {
        st = AUTH_E_STORE;
    } else {
        evlog_audit(AUD_LOGIN_OK, EVLOG_DEV_NONE, 0, 0, u.name, ip);
        ESP_LOGI(TAG, "login %s", u.name);
    }
    gw_secure_zero(&u, sizeof(u));
    return st;
}

/* ---------------------------------------------------------------- own password */

/* Verify the session user's password with rate limiting. On AUTH_OK *rec receives the user record. */
static auth_status_t verify_own(auth_sid_t sid, const char *password, uint32_t ip, uint32_t *retry_after_s,
                                auth_session_info_t *info, sec_user_t *rec) {
    if (retry_after_s) {
        *retry_after_s = 0;
    }
    if (!s_inited || auth_session_check(sid, info) != AUTH_OK) {
        return AUTH_E_NO_SESSION;
    }
    uint32_t locked = auth_rl_locked_for(ip);
    if (locked) {
        if (retry_after_s) {
            *retry_after_s = locked;
        }
        return AUTH_E_LOCKED;
    }
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return AUTH_E_STORE;
    }
    int idx = sec_find_user(s, info->user);
    bool ok = false;
    if (idx >= 0 && password) {
        ok = auth_pw_verify(password, s->users[idx].hash);
    } else {
        auth_pw_dummy_verify(password, AUTH_PBKDF2_ITER_DEFAULT);
    }
    if (ok) {
        *rec = s->users[idx];
    }
    put_secrets(s);
    if (idx < 0) {
        return AUTH_E_NO_SESSION; /* user deleted meanwhile */
    }
    if (!ok) {
        evlog_audit(AUD_LOGIN_FAIL, EVLOG_DEV_NONE, 0, 0, info->user, ip);
        (void)auth_rl_note(ip, info->user, false);
        return AUTH_E_WRONG_PASSWORD;
    }
    /* No success note: own-password re-entry must never clear failures recorded against any
     * account (a valid session plus a policy-violating change would otherwise reset the
     * limiter for free between guesses at another account). */
    return AUTH_OK;
}

auth_status_t auth_change_password(auth_sid_t sid, const char *current, const char *new_password, uint32_t ip,
                                   uint32_t *rules, uint32_t *retry_after_s) {
    if (rules) {
        *rules = 0;
    }
    auth_session_info_t info;
    sec_user_t rec;
    auth_status_t st = verify_own(sid, current, ip, retry_after_s, &info, &rec);
    if (st != AUTH_OK) {
        return st;
    }
    uint32_t bad = auth_policy_check(info.user, new_password);
    if (new_password && current && strcmp(new_password, current) == 0) {
        bad |= AUTH_PW_REUSED;
    }
    if (bad) {
        if (rules) {
            *rules = bad;
        }
        gw_secure_zero(&rec, sizeof(rec));
        return AUTH_E_POLICY;
    }
    char hash[SEC_HASH_SZ];
    if (auth_pw_hash(new_password, AUTH_PBKDF2_ITER_DEFAULT, hash, sizeof(hash)) != 0) {
        gw_secure_zero(&rec, sizeof(rec));
        return AUTH_E_STORE;
    }
    user_op_t op = {.name = info.user, .old_hash = rec.hash, .new_hash = hash, .must_change = 0};
    st = run_user_op(&op, info.user);
    gw_secure_zero(hash, sizeof(hash));
    gw_secure_zero(&rec, sizeof(rec));
    if (st != AUTH_OK) {
        return st == AUTH_E_NOT_FOUND ? AUTH_E_NO_SESSION : st;
    }
    auth_session_set_must_change(sid, false);
    auth_session_revoke_user(info.user, sid);
    evlog_audit(AUD_PASSWORD, EVLOG_DEV_NONE, 0, 0, info.user, 0);
    ESP_LOGI(TAG, "password of %s changed", info.user);
    return AUTH_OK;
}

auth_status_t auth_verify_session_password(auth_sid_t sid, const char *password, uint32_t ip,
                                           uint32_t *retry_after_s) {
    auth_session_info_t info;
    sec_user_t rec;
    auth_status_t st = verify_own(sid, password, ip, retry_after_s, &info, &rec);
    gw_secure_zero(&rec, sizeof(rec));
    return st;
}

/* ---------------------------------------------------------------- user management */

size_t auth_users_list(auth_user_info_t *out, size_t cap) {
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < s->n_users && i < GW_MAX_USERS && n < cap; i++, n++) {
        gw_strlcpy(out[n].name, s->users[i].name, sizeof(out[n].name));
        out[n].role = (gw_role_t)s->users[i].role;
        out[n].must_change = s->users[i].must_change;
        out[n].changed_ms = s->users[i].changed_ms;
    }
    put_secrets(s);
    return n;
}

/* Account-management audit: the action record (user=actor, as before) followed by a user_target
 * record naming the account acted on (eventlog.h AUD_USER_TARGET; extra links the two by seq). */
static void audit_account(evlog_type_t type, int16_t value, const char *by, uint32_t extra, const char *target) {
    const uint32_t seq = evlog_audit(type, EVLOG_DEV_NONE, 0, value, by, extra);
    (void)evlog_audit(AUD_USER_TARGET, EVLOG_DEV_NONE, (uint16_t)type, value, target, seq);
}

auth_status_t auth_user_add(const char *name, gw_role_t role, const char *password, bool must_change,
                            const char *by, uint32_t *rules) {
    if (rules) {
        *rules = 0;
    }
    if (!s_inited) {
        return AUTH_E_STORE;
    }
    if (!auth_name_valid(name)) {
        return AUTH_E_BAD_NAME;
    }
    if (!role_valid(role)) {
        return AUTH_E_BAD_ROLE;
    }
    uint32_t bad = auth_policy_check(name, password);
    if (bad) {
        if (rules) {
            *rules = bad;
        }
        return AUTH_E_POLICY;
    }
    /* Cheap pre-checks before spending PBKDF2 time (re-checked under the secrets lock). */
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return AUTH_E_STORE;
    }
    auth_status_t pre = sec_find_user(s, name) >= 0  ? AUTH_E_EXISTS
                        : s->n_users >= GW_MAX_USERS ? AUTH_E_LIMIT
                                                     : AUTH_OK;
    put_secrets(s);
    if (pre != AUTH_OK) {
        return pre;
    }
    char hash[SEC_HASH_SZ];
    if (auth_pw_hash(password, AUTH_PBKDF2_ITER_DEFAULT, hash, sizeof(hash)) != 0) {
        return AUTH_E_STORE;
    }
    user_op_t op = {
        .name = name, .new_hash = hash, .must_change = must_change ? 1 : 0, .role = role, .add = true};
    auth_status_t st = run_user_op(&op, by);
    gw_secure_zero(hash, sizeof(hash));
    if (st == AUTH_OK) {
        audit_account(AUD_USER_ADD, (int16_t)role, by, 0, name);
        ESP_LOGI(TAG, "user %s added by %s", name, by ? by : "?");
    }
    return st;
}

auth_status_t auth_user_update(const char *name, gw_role_t role, const char *password, int must_change,
                               const char *by, uint32_t *rules) {
    if (rules) {
        *rules = 0;
    }
    if (!s_inited) {
        return AUTH_E_STORE;
    }
    if (!name || !auth_name_valid(name)) {
        return AUTH_E_NOT_FOUND;
    }
    if (role != GW_ROLE_NONE && !role_valid(role)) {
        return AUTH_E_BAD_ROLE;
    }
    gw_secrets_t *s = get_secrets();
    if (!s) {
        return AUTH_E_STORE;
    }
    int idx = sec_find_user(s, name);
    gw_role_t cur_role = idx >= 0 ? (gw_role_t)s->users[idx].role : GW_ROLE_NONE;
    put_secrets(s);
    if (idx < 0) {
        return AUTH_E_NOT_FOUND;
    }
    const bool self = by && strcmp(by, name) == 0;
    const bool role_change = role != GW_ROLE_NONE && role != cur_role;
    if (self && (role_change || password)) {
        return AUTH_E_SELF;
    }
    char hash[SEC_HASH_SZ];
    hash[0] = '\0';
    if (password) {
        uint32_t bad = auth_policy_check(name, password);
        if (bad) {
            if (rules) {
                *rules = bad;
            }
            return AUTH_E_POLICY;
        }
        if (auth_pw_hash(password, AUTH_PBKDF2_ITER_DEFAULT, hash, sizeof(hash)) != 0) {
            return AUTH_E_STORE;
        }
    }
    user_op_t op = {.name = name,
                    .new_hash = password ? hash : NULL,
                    .must_change = must_change < 0 ? -1 : (must_change ? 1 : 0),
                    .role = role};
    auth_status_t st = run_user_op(&op, by);
    gw_secure_zero(hash, sizeof(hash));
    if (st != AUTH_OK) {
        return st;
    }
    if (role_change || password || must_change == 1) {
        auth_session_revoke_user(name, 0);
    }
    audit_account(AUD_USER_MOD, (int16_t)(role != GW_ROLE_NONE ? role : cur_role), by, 0, name);
    if (password) {
        audit_account(AUD_PASSWORD, 0, by, 1, name);
    }
    ESP_LOGI(TAG, "user %s updated by %s", name, by ? by : "?");
    return AUTH_OK;
}

auth_status_t auth_user_delete(const char *name, const char *by) {
    if (!s_inited) {
        return AUTH_E_STORE;
    }
    if (!name || !auth_name_valid(name)) {
        return AUTH_E_NOT_FOUND;
    }
    if (by && strcmp(by, name) == 0) {
        return AUTH_E_SELF;
    }
    user_op_t op = {.name = name, .must_change = -1, .del = true};
    auth_status_t st = run_user_op(&op, by);
    if (st != AUTH_OK) {
        return st;
    }
    auth_session_revoke_user(name, 0);
    audit_account(AUD_USER_DEL, 0, by, 0, name);
    ESP_LOGI(TAG, "user %s deleted by %s", name, by ? by : "?");
    return AUTH_OK;
}
