/*
 * auth_priv.h - internals of the auth component (not a public interface).
 *
 * Pure parts (host-tested, listed in GW_HOST_SOURCES_AUTH): the session table (session_table.c)
 * with an injected monotonic clock and injected random bytes, and password-record helpers.
 * Device parts (session.c, users.c) wrap them with a mutex, events and audit records.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth/auth.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- password records (password.c) ---- */

#define AUTH_PW_PREFIX "pbkdf2-sha256$"
#define AUTH_PBKDF2_ITER_MAX 1000000u /* records claiming more are malformed (DoS guard) */

/** Iteration count of a well-formed record, 0 if malformed. */
uint32_t auth_pw_record_iterations(const char *record);

/** Derive against a fixed dummy record (unknown user / malformed record): same cost as a real check. */
void auth_pw_dummy_verify(const char *password, uint32_t iterations);

/* ---- session table (session_table.c) ---- */

typedef struct {
    bool used;
    uint32_t gen;                    /* sid = (gen << 8) | slot */
    uint8_t tok_hash[GW_SHA256_LEN]; /* SHA-256 of the 16 raw token bytes */
    char user[GW_USER_NAME_SZ];
    gw_role_t role;
    bool must_change;
    char csrf[AUTH_CSRF_SZ];
    uint64_t created_ms; /* monotonic */
    uint64_t last_ms;    /* last touching request */
} auth_sess_slot_t;

typedef struct {
    auth_sess_slot_t slot[GW_MAX_SESSIONS];
    uint32_t next_gen; /* 1..0xFFFFFF, wraps */
    uint32_t idle_s;
    uint32_t abs_s;
} auth_sess_table_t;

/* End kinds, numerically equal to gw_session_kind_t (gw_events.h is IDF-only; session.c asserts it). */
#define AUTH_END_LOGOUT 1u
#define AUTH_END_EXPIRED 2u
#define AUTH_END_REVOKED 3u

/** A session that ended inside a table call; the caller posts GW_EVT_SESSION after unlocking. */
typedef struct {
    auth_sid_t sid;
    uint8_t kind; /* AUTH_END_* == gw_session_kind_t */
    char user[GW_USER_NAME_SZ];
} auth_sess_end_t;

#define AUTH_SESS_END_MAX (GW_MAX_SESSIONS + 1)

void auth_st_init(auth_sess_table_t *t, uint32_t idle_s, uint32_t abs_s);
/** Change the idle timeout (applies to existing sessions from now on). */
void auth_st_set_idle(auth_sess_table_t *t, uint32_t idle_s);

/**
 * Remove every expired session (idle or absolute) at now_ms. Ended sessions (kind EXPIRED) are
 * appended to end[*n_end] while *n_end < AUTH_SESS_END_MAX.
 */
void auth_st_expire(auth_sess_table_t *t, uint64_t now_ms, auth_sess_end_t *end, size_t *n_end);

/**
 * Create a session from 16 random token bytes and 16 random CSRF bytes. Expired sessions are
 * purged first (EXPIRED); a full table evicts the least recently used session (REVOKED). Writes the
 * base64url token (cookie value) and the session info. Returns false on bad arguments.
 */
bool auth_st_create(auth_sess_table_t *t, const char *user, gw_role_t role, bool must_change, uint64_t now_ms,
                    const uint8_t tok_raw[AUTH_TOKEN_BYTES], const uint8_t csrf_raw[AUTH_TOKEN_BYTES],
                    char token_out[AUTH_TOKEN_SZ], auth_session_info_t *info, auth_sess_end_t *end,
                    size_t *n_end);

/**
 * Resolve a cookie token. Malformed/unknown -> AUTH_E_NO_SESSION. Expired -> removed (EXPIRED end
 * record) and AUTH_E_NO_SESSION. touch refreshes last_ms. Every used slot hash is compared
 * (constant time per slot) regardless of an earlier match.
 */
auth_status_t auth_st_lookup(auth_sess_table_t *t, const char *token, bool touch, uint64_t now_ms,
                             auth_session_info_t *out, auth_sess_end_t *end, size_t *n_end);

/** Same by handle; never touches. */
auth_status_t auth_st_check(auth_sess_table_t *t, auth_sid_t sid, uint64_t now_ms, auth_session_info_t *out,
                            auth_sess_end_t *end, size_t *n_end);

/** Constant-time CSRF comparison for a live slot (expiry is not re-evaluated here). */
bool auth_st_csrf_ok(const auth_sess_table_t *t, auth_sid_t sid, const char *header_value);

/** Remove one session with the given end kind. False if sid is not live. */
bool auth_st_remove(auth_sess_table_t *t, auth_sid_t sid, uint8_t kind, auth_sess_end_t *end, size_t *n_end);

/** Remove (REVOKED) every session of user except `keep` (0 = none). Returns how many. */
size_t auth_st_revoke_user(auth_sess_table_t *t, const char *user, auth_sid_t keep, auth_sess_end_t *end,
                           size_t *n_end);

/** Set must_change of one live session. False if sid is not live. */
bool auth_st_set_must_change(auth_sess_table_t *t, auth_sid_t sid, bool must_change);

/** Number of live (not necessarily unexpired) sessions. */
size_t auth_st_count(const auth_sess_table_t *t);

/* ---- device glue shared by session.c and users.c (device only) ---- */

/** Create the mutex, session table and limiter (auth_init). */
esp_err_t auth_session_module_init(uint32_t idle_s, uint8_t max_fail, uint8_t lock_min);
/** Re-apply security parameters (CONFIG_CHANGED{SECURITY}). */
void auth_session_apply_security(uint32_t idle_s, uint8_t max_fail, uint8_t lock_min);

/** Monotonic ms (gw_time_mono_ms on the device). */
uint64_t auth_now_ms(void);

/** Create a session for an authenticated user (posts LOGIN, may post an eviction). */
bool auth_session_create(const char *user, gw_role_t role, bool must_change, char token_out[AUTH_TOKEN_SZ],
                         auth_session_info_t *info);
/** Revoke every session of user except keep (posts REVOKED). */
void auth_session_revoke_user(const char *user, auth_sid_t keep);
/** Update must_change of one session. */
void auth_session_set_must_change(auth_sid_t sid, bool must_change);

/** Shared per-IP limiter (session.c owns the instance). */
uint32_t auth_rl_locked_for(uint32_t ip);
/** Record an attempt outcome against account user (NULL = none: a success then clears nothing);
 *  returns the lock duration (s) a failure triggered, else 0. */
uint32_t auth_rl_note(uint32_t ip, const char *user, bool success);
/** Global delay to apply before answering a login. */
uint32_t auth_rl_delay_ms(void);

#ifdef __cplusplus
}
#endif
