/* Session table core (auth_priv.h): GW_MAX_SESSIONS slots holding only SHA-256(token).
 * Pure C with injected clock and randomness; the device wrapper (session.c) adds the mutex and
 * posts GW_EVT_SESSION for the end records collected here. */
#include <string.h>

#include "auth_priv.h"
#include "gw_core/gw_b64.h"
#include "gw_core/gw_crypto.h"

#define GEN_MASK 0xFFFFFFu

static inline uint8_t sid_slot(auth_sid_t sid) {
    return (uint8_t)(sid & 0xFFu);
}

static inline uint32_t sid_gen(auth_sid_t sid) {
    return sid >> 8;
}

static inline auth_sid_t make_sid(uint32_t gen, size_t slot) {
    return (auth_sid_t)((gen << 8) | (uint32_t)slot);
}

static void add_end(auth_sess_end_t *end, size_t *n_end, auth_sid_t sid, uint8_t kind, const char *user) {
    if (!end || !n_end || *n_end >= AUTH_SESS_END_MAX) {
        return;
    }
    auth_sess_end_t *e = &end[(*n_end)++];
    e->sid = sid;
    e->kind = kind;
    gw_strlcpy(e->user, user, sizeof(e->user));
}

static void drop(auth_sess_table_t *t, size_t i, uint8_t kind, auth_sess_end_t *end, size_t *n_end) {
    auth_sess_slot_t *s = &t->slot[i];
    add_end(end, n_end, make_sid(s->gen, i), kind, s->user);
    gw_secure_zero(s, sizeof(*s));
}

static bool expired(const auth_sess_table_t *t, const auth_sess_slot_t *s, uint64_t now) {
    if (now < s->created_ms || now < s->last_ms) {
        return false; /* clock cannot go backwards; be lenient */
    }
    return now - s->last_ms >= (uint64_t)t->idle_s * 1000u ||
           now - s->created_ms >= (uint64_t)t->abs_s * 1000u;
}

static void fill_info(const auth_sess_table_t *t, size_t i, uint64_t now, auth_session_info_t *out) {
    if (!out) {
        return;
    }
    const auth_sess_slot_t *s = &t->slot[i];
    memset(out, 0, sizeof(*out));
    out->sid = make_sid(s->gen, i);
    gw_strlcpy(out->user, s->user, sizeof(out->user));
    out->role = s->role;
    out->must_change = s->must_change;
    memcpy(out->csrf, s->csrf, sizeof(out->csrf));
    uint64_t idle_used = now > s->last_ms ? (now - s->last_ms) / 1000u : 0;
    uint64_t abs_used = now > s->created_ms ? (now - s->created_ms) / 1000u : 0;
    out->idle_left_s = idle_used < t->idle_s ? (uint32_t)(t->idle_s - idle_used) : 0;
    out->abs_left_s = abs_used < t->abs_s ? (uint32_t)(t->abs_s - abs_used) : 0;
    out->idle_s = t->idle_s;
}

/* Index of the live slot for sid, or -1. */
static int live_index(const auth_sess_table_t *t, auth_sid_t sid) {
    uint8_t i = sid_slot(sid);
    if (!sid || i >= GW_MAX_SESSIONS) {
        return -1;
    }
    const auth_sess_slot_t *s = &t->slot[i];
    return (s->used && s->gen == sid_gen(sid)) ? (int)i : -1;
}

void auth_st_init(auth_sess_table_t *t, uint32_t idle_s, uint32_t abs_s) {
    gw_secure_zero(t, sizeof(*t));
    t->next_gen = 1;
    t->idle_s = idle_s ? idle_s : 1;
    t->abs_s = abs_s ? abs_s : 1;
}

void auth_st_set_idle(auth_sess_table_t *t, uint32_t idle_s) {
    t->idle_s = idle_s ? idle_s : 1;
}

void auth_st_expire(auth_sess_table_t *t, uint64_t now_ms, auth_sess_end_t *end, size_t *n_end) {
    for (size_t i = 0; i < GW_MAX_SESSIONS; i++) {
        if (t->slot[i].used && expired(t, &t->slot[i], now_ms)) {
            drop(t, i, AUTH_END_EXPIRED, end, n_end);
        }
    }
}

bool auth_st_create(auth_sess_table_t *t, const char *user, gw_role_t role, bool must_change, uint64_t now_ms,
                    const uint8_t tok_raw[AUTH_TOKEN_BYTES], const uint8_t csrf_raw[AUTH_TOKEN_BYTES],
                    char token_out[AUTH_TOKEN_SZ], auth_session_info_t *info, auth_sess_end_t *end,
                    size_t *n_end) {
    if (!t || !user || !user[0] || !tok_raw || !csrf_raw || !token_out || role < GW_ROLE_VIEWER ||
        role > GW_ROLE_ADMIN) {
        return false;
    }
    auth_st_expire(t, now_ms, end, n_end);
    int idx = -1;
    for (size_t i = 0; i < GW_MAX_SESSIONS; i++) {
        if (!t->slot[i].used) {
            idx = (int)i;
            break;
        }
    }
    if (idx < 0) {
        idx = 0;
        for (size_t i = 1; i < GW_MAX_SESSIONS; i++) {
            if (t->slot[i].last_ms < t->slot[idx].last_ms) {
                idx = (int)i;
            }
        }
        drop(t, (size_t)idx, AUTH_END_REVOKED, end, n_end);
    }
    auth_sess_slot_t *s = &t->slot[idx];
    if (gw_b64_encode(tok_raw, AUTH_TOKEN_BYTES, token_out, AUTH_TOKEN_SZ, GW_B64_URL) !=
            AUTH_TOKEN_B64_LEN ||
        gw_b64_encode(csrf_raw, AUTH_TOKEN_BYTES, s->csrf, sizeof(s->csrf), GW_B64_URL) !=
            AUTH_TOKEN_B64_LEN ||
        gw_hash(GW_HASH_SHA256, tok_raw, AUTH_TOKEN_BYTES, s->tok_hash) != GW_CRYPTO_OK) {
        gw_secure_zero(s, sizeof(*s));
        token_out[0] = '\0';
        return false;
    }
    s->used = true;
    s->gen = t->next_gen;
    t->next_gen = (t->next_gen + 1u) & GEN_MASK;
    if (!t->next_gen) {
        t->next_gen = 1;
    }
    gw_strlcpy(s->user, user, sizeof(s->user));
    s->role = role;
    s->must_change = must_change;
    s->created_ms = now_ms;
    s->last_ms = now_ms;
    fill_info(t, (size_t)idx, now_ms, info);
    return true;
}

auth_status_t auth_st_lookup(auth_sess_table_t *t, const char *token, bool touch, uint64_t now_ms,
                             auth_session_info_t *out, auth_sess_end_t *end, size_t *n_end) {
    uint8_t raw[AUTH_TOKEN_BYTES];
    uint8_t h[GW_SHA256_LEN];
    if (!t || !token || strlen(token) != AUTH_TOKEN_B64_LEN ||
        gw_b64_decode(token, AUTH_TOKEN_B64_LEN, raw, sizeof(raw), GW_B64_URL) != AUTH_TOKEN_BYTES ||
        gw_hash(GW_HASH_SHA256, raw, sizeof(raw), h) != GW_CRYPTO_OK) {
        gw_secure_zero(raw, sizeof(raw));
        return AUTH_E_NO_SESSION;
    }
    gw_secure_zero(raw, sizeof(raw));
    int found = -1;
    for (size_t i = 0; i < GW_MAX_SESSIONS; i++) {
        /* Compare every slot (unused ones against a zero hash) so timing does not reveal which. */
        bool eq = gw_ct_equal(t->slot[i].tok_hash, h, sizeof(h));
        if (eq && t->slot[i].used && found < 0) {
            found = (int)i;
        }
    }
    gw_secure_zero(h, sizeof(h));
    if (found < 0) {
        return AUTH_E_NO_SESSION;
    }
    auth_sess_slot_t *s = &t->slot[found];
    if (expired(t, s, now_ms)) {
        drop(t, (size_t)found, AUTH_END_EXPIRED, end, n_end);
        return AUTH_E_NO_SESSION;
    }
    if (touch && now_ms > s->last_ms) {
        s->last_ms = now_ms;
    }
    fill_info(t, (size_t)found, now_ms, out);
    return AUTH_OK;
}

auth_status_t auth_st_check(auth_sess_table_t *t, auth_sid_t sid, uint64_t now_ms, auth_session_info_t *out,
                            auth_sess_end_t *end, size_t *n_end) {
    if (!t) {
        return AUTH_E_NO_SESSION;
    }
    int i = live_index(t, sid);
    if (i < 0) {
        return AUTH_E_NO_SESSION;
    }
    if (expired(t, &t->slot[i], now_ms)) {
        drop(t, (size_t)i, AUTH_END_EXPIRED, end, n_end);
        return AUTH_E_NO_SESSION;
    }
    fill_info(t, (size_t)i, now_ms, out);
    return AUTH_OK;
}

bool auth_st_csrf_ok(const auth_sess_table_t *t, auth_sid_t sid, const char *header_value) {
    if (!t || !header_value) {
        return false;
    }
    int i = live_index(t, sid);
    if (i < 0 || strlen(header_value) != AUTH_TOKEN_B64_LEN) {
        return false;
    }
    return gw_ct_equal(t->slot[i].csrf, header_value, AUTH_TOKEN_B64_LEN);
}

bool auth_st_remove(auth_sess_table_t *t, auth_sid_t sid, uint8_t kind, auth_sess_end_t *end, size_t *n_end) {
    if (!t) {
        return false;
    }
    int i = live_index(t, sid);
    if (i < 0) {
        return false;
    }
    drop(t, (size_t)i, kind, end, n_end);
    return true;
}

size_t auth_st_revoke_user(auth_sess_table_t *t, const char *user, auth_sid_t keep, auth_sess_end_t *end,
                           size_t *n_end) {
    if (!t || !user) {
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < GW_MAX_SESSIONS; i++) {
        auth_sess_slot_t *s = &t->slot[i];
        if (s->used && strcmp(s->user, user) == 0 && make_sid(s->gen, i) != keep) {
            drop(t, i, AUTH_END_REVOKED, end, n_end);
            n++;
        }
    }
    return n;
}

bool auth_st_set_must_change(auth_sess_table_t *t, auth_sid_t sid, bool must_change) {
    if (!t) {
        return false;
    }
    int i = live_index(t, sid);
    if (i < 0) {
        return false;
    }
    t->slot[i].must_change = must_change;
    return true;
}

size_t auth_st_count(const auth_sess_table_t *t) {
    size_t n = 0;
    for (size_t i = 0; t && i < GW_MAX_SESSIONS; i++) {
        n += t->slot[i].used ? 1u : 0u;
    }
    return n;
}
