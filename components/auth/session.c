/* Device session store and shared rate limiter (auth.h). One mutex guards the session table and the
 * limiter (leaf lock: nothing else is called while it is held); GW_EVT_SESSION posts and audit
 * records happen after unlocking (ARCHITECTURE.md §5 rule 7). */
#include <inttypes.h>
#include <string.h>

#include "auth/auth.h"
#include "auth_priv.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "store/config.h"
#include "store/eventlog.h"

static const char *TAG = "auth_sess";

static_assert(AUTH_END_LOGOUT == GW_SESSION_LOGOUT, "end kind mapping");
static_assert(AUTH_END_EXPIRED == GW_SESSION_EXPIRED, "end kind mapping");
static_assert(AUTH_END_REVOKED == GW_SESSION_REVOKED, "end kind mapping");

static SemaphoreHandle_t s_mtx;
static StaticSemaphore_t s_mtx_buf;
static auth_sess_table_t s_tab;
static auth_rl_t s_rl;

uint64_t auth_now_ms(void) {
    return gw_time_mono_ms();
}

static void lock(void) {
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void unlock(void) {
    xSemaphoreGive(s_mtx);
}

static void post_session(uint8_t kind, auth_sid_t sid, const char *user) {
    gw_evt_session_t ev = {.kind = kind, .sid = sid};
    gw_strlcpy(ev.user, user, sizeof(ev.user));
    esp_err_t err = gw_events_post(GW_EVT_SESSION, &ev, sizeof(ev), 0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "session event dropped (%s)", esp_err_to_name(err));
    }
}

/* Post and audit every collected end record (outside the lock). */
static void flush_ends(const auth_sess_end_t *end, size_t n) {
    for (size_t i = 0; i < n; i++) {
        post_session(end[i].kind, end[i].sid, end[i].user);
        evlog_audit(AUD_LOGOUT, EVLOG_DEV_NONE, end[i].kind, 0, end[i].user, 0);
        ESP_LOGI(TAG, "session %08" PRIx32 " of %s ended (%u)", end[i].sid, end[i].user,
                 (unsigned)end[i].kind);
    }
}

esp_err_t auth_session_module_init(uint32_t idle_s, uint8_t max_fail, uint8_t lock_min) {
    if (!s_mtx) {
        s_mtx = xSemaphoreCreateMutexStatic(&s_mtx_buf);
        if (!s_mtx) {
            return ESP_ERR_NO_MEM;
        }
    }
    lock();
    auth_st_init(&s_tab, idle_s, CFG_ABS_SESSION_S);
    auth_rl_init(&s_rl, max_fail, lock_min);
    unlock();
    return ESP_OK;
}

void auth_session_apply_security(uint32_t idle_s, uint8_t max_fail, uint8_t lock_min) {
    if (!s_mtx) {
        return;
    }
    lock();
    auth_st_set_idle(&s_tab, idle_s);
    s_rl.max_fail = max_fail ? max_fail : 1;
    s_rl.lock_min = lock_min ? lock_min : 1;
    unlock();
}

bool auth_session_create(const char *user, gw_role_t role, bool must_change, char token_out[AUTH_TOKEN_SZ],
                         auth_session_info_t *info) {
    uint8_t tok[AUTH_TOKEN_BYTES];
    uint8_t csrf[AUTH_TOKEN_BYTES];
    if (!s_mtx || gw_random(tok, sizeof(tok)) != GW_CRYPTO_OK ||
        gw_random(csrf, sizeof(csrf)) != GW_CRYPTO_OK) {
        gw_secure_zero(tok, sizeof(tok));
        return false;
    }
    auth_sess_end_t end[AUTH_SESS_END_MAX];
    size_t n_end = 0;
    auth_session_info_t tmp;
    lock();
    bool ok = auth_st_create(&s_tab, user, role, must_change, auth_now_ms(), tok, csrf, token_out, &tmp, end,
                             &n_end);
    unlock();
    gw_secure_zero(tok, sizeof(tok));
    gw_secure_zero(csrf, sizeof(csrf));
    flush_ends(end, n_end);
    if (ok) {
        post_session(GW_SESSION_LOGIN, tmp.sid, user);
        if (info) {
            *info = tmp;
        }
    }
    gw_secure_zero(&tmp, sizeof(tmp));
    return ok;
}

auth_status_t auth_session_lookup(const char *token, bool touch, auth_session_info_t *out) {
    if (!s_mtx) {
        return AUTH_E_NO_SESSION;
    }
    auth_sess_end_t end[AUTH_SESS_END_MAX];
    size_t n_end = 0;
    lock();
    auth_status_t st = auth_st_lookup(&s_tab, token, touch, auth_now_ms(), out, end, &n_end);
    unlock();
    flush_ends(end, n_end);
    return st;
}

auth_status_t auth_session_check(auth_sid_t sid, auth_session_info_t *out) {
    if (!s_mtx) {
        return AUTH_E_NO_SESSION;
    }
    auth_sess_end_t end[AUTH_SESS_END_MAX];
    size_t n_end = 0;
    lock();
    auth_status_t st = auth_st_check(&s_tab, sid, auth_now_ms(), out, end, &n_end);
    unlock();
    flush_ends(end, n_end);
    return st;
}

bool auth_csrf_ok(auth_sid_t sid, const char *header_value) {
    if (!s_mtx) {
        return false;
    }
    lock();
    bool ok = auth_st_csrf_ok(&s_tab, sid, header_value);
    unlock();
    return ok;
}

void auth_logout(auth_sid_t sid) {
    if (!s_mtx) {
        return;
    }
    auth_sess_end_t end[AUTH_SESS_END_MAX];
    size_t n_end = 0;
    lock();
    (void)auth_st_remove(&s_tab, sid, AUTH_END_LOGOUT, end, &n_end);
    unlock();
    flush_ends(end, n_end);
}

void auth_session_revoke_user(const char *user, auth_sid_t keep) {
    if (!s_mtx) {
        return;
    }
    auth_sess_end_t end[AUTH_SESS_END_MAX];
    size_t n_end = 0;
    lock();
    (void)auth_st_revoke_user(&s_tab, user, keep, end, &n_end);
    unlock();
    flush_ends(end, n_end);
}

void auth_session_set_must_change(auth_sid_t sid, bool must_change) {
    if (!s_mtx) {
        return;
    }
    lock();
    (void)auth_st_set_must_change(&s_tab, sid, must_change);
    unlock();
}

uint32_t auth_rl_locked_for(uint32_t ip) {
    if (!s_mtx) {
        return 0;
    }
    lock();
    uint32_t s = auth_rl_check(&s_rl, ip, auth_now_ms());
    unlock();
    return s;
}

uint32_t auth_rl_note(uint32_t ip, const char *user, bool success) {
    if (!s_mtx) {
        return 0;
    }
    lock();
    const uint32_t key = user ? auth_rl_user_key(user) : AUTH_RL_USER_NONE;
    uint32_t lock_s = auth_rl_record(&s_rl, ip, key, success, auth_now_ms());
    unlock();
    if (lock_s) {
        ESP_LOGW(TAG, "client %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 " locked for %" PRIu32 " s",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, lock_s);
        evlog_audit(AUD_LOCKOUT, EVLOG_DEV_NONE, 0, (int16_t)(lock_s / 60u), NULL, ip);
    }
    return lock_s;
}

uint32_t auth_rl_delay_ms(void) {
    if (!s_mtx) {
        return 0;
    }
    lock();
    uint32_t d = auth_rl_global_delay_ms(&s_rl, auth_now_ms());
    unlock();
    return d;
}
