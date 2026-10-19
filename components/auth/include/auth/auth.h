/*
 * auth.h - web users, password records/policy, sessions, CSRF, login rate limiting (DESIGN.md §6).
 *
 * Pure parts (host-tested, no IDF): password records (auth_pw_*), policy (auth_policy_*), name
 * check, rate limiter core (auth_rl_*).
 * Device parts (users.c, session.c): users stored in secrets (store/secrets.h); sessions in a RAM
 * table of GW_MAX_SESSIONS holding only SHA-256(token). All device functions are thread-safe
 * (internal mutex) and callable from any task except ISRs. Functions that run PBKDF2 (login,
 * password change, user add/update with password) take ~0.1-0.4 s: web routes calling them are
 * flagged WEB_RF_SLOW.
 * Session events: every session start/end posts GW_EVT_SESSION (ws_hub closes bound sockets).
 * Audit: login ok/fail, lockout, logout, password and user changes are appended by this module.
 * Rate limiting: one per-IP limiter (auth_rl_t) counts failed logins AND failed re-verifications
 * of the session user's own password (auth_change_password, auth_verify_session_password), so a
 * stolen session cannot be used to guess the account password online. Only a successful LOGIN of
 * the account the failures targeted clears them; own-password successes never do.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_COOKIE_NAME "gw_sid"
#define AUTH_TOKEN_BYTES 16   /* 128-bit session token */
#define AUTH_TOKEN_B64_LEN 22 /* base64url, unpadded */
#define AUTH_TOKEN_SZ (AUTH_TOKEN_B64_LEN + 1)
#define AUTH_CSRF_SZ (AUTH_TOKEN_B64_LEN + 1) /* 128-bit CSRF token, base64url */
#define AUTH_PBKDF2_ITER_DEFAULT 10000
#define AUTH_PBKDF2_ITER_MIN 1000
#define AUTH_SALT_LEN 16
#define AUTH_DK_LEN 32
#define AUTH_FACTORY_USER "admin"
#define AUTH_FACTORY_PASSWORD "mestio150!"
#define AUTH_LOCK_MAX_MIN 30        /* lock duration doubles up to this */
#define AUTH_FAIL_WINDOW_S 300      /* failures counted within 5 minutes */
#define AUTH_GLOBAL_FAIL_PER_MIN 20 /* above this, every login is delayed by 1 s */
#define AUTH_RL_IP_SLOTS 16

/** Result codes of user/session operations (mapped to HTTP by web, see docs/API.md). */
typedef enum {
    AUTH_OK = 0,
    AUTH_E_BAD_CREDENTIALS, /* unknown user or wrong password (indistinguishable) -> 401 */
    AUTH_E_LOCKED,          /* rate limited / locked out; *retry_after_s set     -> 429 */
    AUTH_E_NO_SESSION,      /* token unknown, expired or revoked                  -> 401 */
    AUTH_E_POLICY,          /* new password violates policy; *rules set           -> 422 policy */
    AUTH_E_EXISTS,          /* user name already exists                           -> 409 */
    AUTH_E_NOT_FOUND,       /* no such user                                       -> 404 */
    AUTH_E_LIMIT,           /* GW_MAX_USERS reached                               -> 409 */
    AUTH_E_LAST_ADMIN,      /* would remove/demote the last admin                 -> 409 */
    AUTH_E_BAD_NAME,        /* name fails auth_name_valid()                       -> 422 */
    AUTH_E_BAD_ROLE,        /*                                                    -> 422 */
    AUTH_E_SELF,            /* admin deleting or demoting itself                  -> 409 */
    AUTH_E_STORE,           /* secrets update failed                              -> 503 */
    AUTH_E_WRONG_PASSWORD,  /* re-verification of the session user's own password failed
                               (password change "current", factory reset)        -> 422 wrong_password */
} auth_status_t;

/* ---- Password records: "pbkdf2-sha256$<iter>$<salt b64 std>$<dk b64 std>" ---- */

/** Create a record with a fresh random 16-byte salt. Returns 0 or -1 (cap too small / crypto error). */
int auth_pw_hash(const char *password, uint32_t iterations, char *out, size_t cap);
/** Same with a caller-provided salt (tests / vectors). */
int auth_pw_hash_salt(const char *password, uint32_t iterations, const uint8_t salt[AUTH_SALT_LEN], char *out,
                      size_t cap);
/** Parse a record. False if malformed (wrong prefix, iter < AUTH_PBKDF2_ITER_MIN, bad base64/lengths). */
bool auth_pw_parse(const char *record, uint32_t *iterations, uint8_t salt[AUTH_SALT_LEN],
                   uint8_t dk[AUTH_DK_LEN]);
/** Verify in constant time w.r.t. the derived key. Malformed record -> false (after a dummy derive). */
bool auth_pw_verify(const char *password, const char *record);

/* ---- Password policy (bit set = rule violated; names are the REST "rules" strings) ---- */
#define AUTH_PW_TOO_SHORT 0x01u       /* "min_length"   < GW_PASSWORD_MIN characters (code points) */
#define AUTH_PW_TOO_LONG 0x02u        /* "max_length"   > GW_PASSWORD_MAX UTF-8 bytes (API.md §4.1) */
#define AUTH_PW_CLASSES 0x04u         /* "classes"      < 3 of: lower, upper, digit, other */
#define AUTH_PW_EQUALS_USER 0x08u     /* "not_username" equals the user name (case-insensitive) */
#define AUTH_PW_FACTORY_DEFAULT 0x10u /* "not_default"  equals AUTH_FACTORY_PASSWORD */
#define AUTH_PW_REUSED 0x20u          /* "not_previous" equals the current password (set by caller) */
#define AUTH_PW_INVALID_CHARS 0x40u   /* "charset"      control characters or invalid UTF-8 */
#define AUTH_PW_RULE_COUNT 7

/** Check all rules except AUTH_PW_REUSED. Returns the violated-rules bitmask (0 = acceptable). */
uint32_t auth_policy_check(const char *user, const char *password);
/** Wire name of a single rule bit, NULL for unknown. */
const char *auth_policy_rule_name(uint32_t bit);

/** User name rule: 1..GW_USER_NAME_MAX chars of [a-z0-9_.-], starting with [a-z]. */
bool auth_name_valid(const char *name);

/* ---- Rate limiter core (pure; instance owned by the device module) ---- */
typedef struct {
    uint32_t ip;   /* host order, 0 = free */
    uint8_t fails; /* failures within the window */
    uint8_t locks; /* consecutive locks (doubling exponent) */
    uint32_t fail_user; /* auth_rl_user_key() of the account the window's failures targeted */
    uint64_t window_start_ms;
    uint64_t locked_until_ms;
    uint64_t last_ms;
} auth_rl_slot_t;

typedef struct {
    uint8_t max_fail; /* from cfg_security_t */
    uint8_t lock_min;
    auth_rl_slot_t slot[AUTH_RL_IP_SLOTS]; /* LRU replacement */
    uint32_t global_fails;                 /* in the current minute */
    uint64_t global_minute_start_ms;
} auth_rl_t;

#define AUTH_RL_USER_NONE 0u           /* no account (own-password re-entry success: clears nothing) */
#define AUTH_RL_USER_MIXED 0xFFFFFFFFu /* failures targeted more than one account */

void auth_rl_init(auth_rl_t *rl, uint8_t max_fail, uint8_t lock_min);
/** Non-zero key of an account name for auth_rl_record (FNV-1a, never NONE/MIXED). */
uint32_t auth_rl_user_key(const char *name);
/** 0 if ip may attempt a login now, else seconds until it may (>= 1). */
uint32_t auth_rl_check(const auth_rl_t *rl, uint32_t ip, uint64_t now_ms);
/**
 * Record an attempt outcome against account user_key (auth_rl_user_key(), or AUTH_RL_USER_NONE).
 * A success resets the ip's failures (not its lock exponent until the window passes) ONLY when
 * every failure in the current window targeted that same account; a success of another account
 * or with AUTH_RL_USER_NONE leaves them in place, so a valid account cannot be used to keep
 * guessing someone else's password. Returns the lock duration in seconds if this failure
 * triggered a lockout, else 0.
 */
uint32_t auth_rl_record(auth_rl_t *rl, uint32_t ip, uint32_t user_key, bool success, uint64_t now_ms);
/** Extra delay (ms) to apply before answering any login: 1000 above AUTH_GLOBAL_FAIL_PER_MIN, else 0. */
uint32_t auth_rl_global_delay_ms(const auth_rl_t *rl, uint64_t now_ms);

/* ---- Sessions ---- */

/** Opaque session handle: (generation << 8) | slot. 0 = none. Stable for the session's lifetime. */
typedef uint32_t auth_sid_t;

typedef struct {
    auth_sid_t sid;
    char user[GW_USER_NAME_SZ];
    gw_role_t role;
    bool must_change;
    char csrf[AUTH_CSRF_SZ];
    uint32_t idle_left_s; /* until idle expiry */
    uint32_t abs_left_s;  /* until absolute expiry */
    uint32_t idle_s;      /* configured idle timeout (seconds) */
} auth_session_info_t;

typedef struct {
    char name[GW_USER_NAME_SZ];
    gw_role_t role;
    bool must_change;
    int64_t changed_ms;
} auth_user_info_t;

/** Load lockout/idle parameters from config, create the factory admin if no user exists
 * (must_change = true), register a CONFIG_CHANGED handler for SECURITY. After secrets_load(). */
esp_err_t auth_init(void);

/**
 * Full login: rate-limit check (and global delay), verify (dummy verify for unknown users),
 * record outcome, create a session (evicting the least recently used one if the table is full;
 * the evicted session gets GW_SESSION_REVOKED), audit. On AUTH_OK token_out holds the cookie value.
 * ip = client IPv4 host order. retry_after_s set on AUTH_E_LOCKED.
 */
auth_status_t auth_login(const char *user, const char *password, uint32_t ip, char token_out[AUTH_TOKEN_SZ],
                         auth_session_info_t *info, uint32_t *retry_after_s);

/**
 * Resolve a cookie token. Enforces idle and absolute expiry (expired -> removed, GW_SESSION_EXPIRED
 * posted, AUTH_E_NO_SESSION). touch=true refreshes the idle timer (every authenticated REST
 * request); WebSocket traffic never touches.
 */
auth_status_t auth_session_lookup(const char *token, bool touch, auth_session_info_t *out);

/** Same check by handle (WS hub periodic validation). Never touches. */
auth_status_t auth_session_check(auth_sid_t sid, auth_session_info_t *out);

/** Constant-time CSRF check against the session's token. False if session unknown. */
bool auth_csrf_ok(auth_sid_t sid, const char *header_value);

/** End one session (logout). Posts GW_SESSION_LOGOUT, audits. */
void auth_logout(auth_sid_t sid);

/**
 * Change own password: rate-limit check for `ip` (shared per-IP limiter with login), verify
 * `current` (failure -> AUTH_E_WRONG_PASSWORD, counted as a failed attempt for `ip` and audited as
 * login_fail), check policy (+ AUTH_PW_REUSED), store, clear must_change, revoke the user's OTHER
 * sessions. *rules receives the violated bits on AUTH_E_POLICY; *retry_after_s on AUTH_E_LOCKED.
 * @return AUTH_OK, AUTH_E_NO_SESSION, AUTH_E_LOCKED, AUTH_E_WRONG_PASSWORD, AUTH_E_POLICY, AUTH_E_STORE.
 */
auth_status_t auth_change_password(auth_sid_t sid, const char *current, const char *new_password, uint32_t ip,
                                   uint32_t *rules, uint32_t *retry_after_s);

/**
 * Re-verify the session user's password (factory reset confirmation) with the same rate limiting
 * and failure accounting as auth_change_password().
 * @return AUTH_OK, AUTH_E_NO_SESSION, AUTH_E_LOCKED (*retry_after_s set), AUTH_E_WRONG_PASSWORD.
 */
auth_status_t auth_verify_session_password(auth_sid_t sid, const char *password, uint32_t ip,
                                           uint32_t *retry_after_s);

/* ---- Users (admin operations; `by` = acting admin for audit) ---- */

size_t auth_users_list(auth_user_info_t *out, size_t cap);

/** Add a user. must_change typically true when an admin sets the initial password. */
auth_status_t auth_user_add(const char *name, gw_role_t role, const char *password, bool must_change,
                            const char *by, uint32_t *rules);

/**
 * Update a user: role (GW_ROLE_NONE = keep), password (NULL = keep; admin reset bypasses
 * AUTH_PW_REUSED), must_change (-1 keep, 0/1 set). A role change, a password change or setting
 * must_change to 1 revokes all of that user's sessions (their WS clients get bye "revoked"). An
 * admin cannot change its own role (AUTH_E_SELF) and must use auth_change_password() for its own
 * password.
 */
auth_status_t auth_user_update(const char *name, gw_role_t role, const char *password, int must_change,
                               const char *by, uint32_t *rules);

/** Delete a user and revoke its sessions. Cannot delete the last admin or oneself. */
auth_status_t auth_user_delete(const char *name, const char *by);

/** HTTP status for a status code (200, 401, 404, 409, 422, 429, 503). */
int auth_http_status(auth_status_t st);
/** REST error code string ("bad_credentials", "rate_limited", "unauthorized", "policy", "exists",
 * "not_found", "limit", "last_admin", "validation", "self", "unavailable", "wrong_password").
 * AUTH_E_WRONG_PASSWORD answers 422 with field "current" (password change) or "password" (factory
 * reset); never 401, so the UI does not treat it as an expired session. */
const char *auth_status_code(auth_status_t st);

#ifdef __cplusplus
}
#endif
