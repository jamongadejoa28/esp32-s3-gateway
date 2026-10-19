/* Login / own-password rate limiter core (auth.h, DESIGN.md §6). Pure C with an injected clock.
 *
 * Per IP (AUTH_RL_IP_SLOTS, LRU replacement of UNLOCKED slots only): max_fail failures within
 * AUTH_FAIL_WINDOW_S lock the IP for lock_min minutes, doubling per consecutive lock up to
 * AUTH_LOCK_MAX_MIN. The doubling exponent decays once the IP stayed quiet for a full window after
 * its last lock expired. Globally, more than AUTH_GLOBAL_FAIL_PER_MIN failures in the current
 * minute delay every login answer by 1 s.
 *
 * A locked slot is never evicted: otherwise an attacker rotating through more than
 * AUTH_RL_IP_SLOTS addresses would reset every lock and its doubling. While every slot is locked
 * ("table full of locks") an IP without a slot is treated as locked until the earliest slot lock
 * ends, so new addresses get no guesses at all until a slot frees up.
 *
 * A success clears the IP's failures only when it is a login of the SAME account every failure in
 * the current window targeted (slot.fail_user). Otherwise a holder of any valid account (or of a
 * session, through own-password re-entry) could interleave guesses at another account with
 * successes of their own and never reach max_fail. Own-password re-entry never records a success
 * (callers pass AUTH_RL_USER_NONE, which clears nothing). */
#include <string.h>

#include "auth/auth.h"

#define WINDOW_MS ((uint64_t)AUTH_FAIL_WINDOW_S * 1000u)
#define MINUTE_MS 60000u
#define IP_KEY(ip) ((ip) ? (ip) : 0xFFFFFFFFu) /* slot.ip 0 means "free" */

uint32_t auth_rl_user_key(const char *name) {
    uint32_t h = 2166136261u; /* FNV-1a */
    for (const unsigned char *p = (const unsigned char *)(name ? name : ""); *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    if (h == AUTH_RL_USER_NONE || h == AUTH_RL_USER_MIXED) {
        h = 1u; /* both values are reserved */
    }
    return h;
}

void auth_rl_init(auth_rl_t *rl, uint8_t max_fail, uint8_t lock_min) {
    if (!rl) {
        return;
    }
    memset(rl, 0, sizeof(*rl));
    rl->max_fail = max_fail ? max_fail : 1;
    rl->lock_min = lock_min ? lock_min : 1;
}

static auth_rl_slot_t *find(const auth_rl_t *rl, uint32_t key) {
    for (size_t i = 0; i < AUTH_RL_IP_SLOTS; i++) {
        if (rl->slot[i].ip == key) {
            return (auth_rl_slot_t *)&rl->slot[i];
        }
    }
    return NULL;
}

/* Earliest lock end if every slot is in use and locked at now, else 0. */
static uint64_t table_locked_until(const auth_rl_t *rl, uint64_t now) {
    uint64_t earliest = 0;
    for (size_t i = 0; i < AUTH_RL_IP_SLOTS; i++) {
        const auth_rl_slot_t *s = &rl->slot[i];
        if (s->ip == 0 || s->locked_until_ms <= now) {
            return 0;
        }
        if (!earliest || s->locked_until_ms < earliest) {
            earliest = s->locked_until_ms;
        }
    }
    return earliest;
}

/* Free slot, else the least recently used unlocked one; NULL when every slot is locked. */
static auth_rl_slot_t *alloc(auth_rl_t *rl, uint32_t key, uint64_t now) {
    auth_rl_slot_t *best = NULL;
    for (size_t i = 0; i < AUTH_RL_IP_SLOTS; i++) {
        auth_rl_slot_t *s = &rl->slot[i];
        if (s->ip == 0) {
            best = s;
            break;
        }
        if (s->locked_until_ms > now) {
            continue; /* never evict a lock */
        }
        if (!best || s->last_ms < best->last_ms) {
            best = s;
        }
    }
    if (!best) {
        return NULL;
    }
    memset(best, 0, sizeof(*best));
    best->ip = key;
    best->window_start_ms = now;
    best->last_ms = now;
    return best;
}

/* Age the slot: window restart, lock-exponent decay. */
static void age(auth_rl_slot_t *s, uint64_t now) {
    if (now >= s->window_start_ms + WINDOW_MS) {
        s->fails = 0;
        s->fail_user = AUTH_RL_USER_NONE;
        s->window_start_ms = now;
    }
    if (s->locks && now >= s->locked_until_ms && now - s->locked_until_ms >= WINDOW_MS &&
        now - s->last_ms >= WINDOW_MS) {
        s->locks = 0;
    }
}

uint32_t auth_rl_check(const auth_rl_t *rl, uint32_t ip, uint64_t now_ms) {
    if (!rl) {
        return 0;
    }
    const auth_rl_slot_t *s = find(rl, IP_KEY(ip));
    uint64_t until = s ? s->locked_until_ms : table_locked_until(rl, now_ms);
    if (until <= now_ms) {
        return 0;
    }
    uint64_t left = until - now_ms;
    return (uint32_t)((left + 999u) / 1000u);
}

uint32_t auth_rl_record(auth_rl_t *rl, uint32_t ip, uint32_t user_key, bool success, uint64_t now_ms) {
    if (!rl) {
        return 0;
    }
    const uint32_t key = IP_KEY(ip);
    if (now_ms >= rl->global_minute_start_ms + MINUTE_MS || now_ms < rl->global_minute_start_ms) {
        rl->global_minute_start_ms = now_ms;
        rl->global_fails = 0;
    }
    auth_rl_slot_t *s = find(rl, key);
    if (success) {
        if (s) {
            age(s, now_ms);
            /* Only a login of the account the failures were aimed at proves they were typos. */
            if (user_key != AUTH_RL_USER_NONE && user_key != AUTH_RL_USER_MIXED && s->fail_user == user_key) {
                s->fails = 0;
                s->fail_user = AUTH_RL_USER_NONE;
            }
            s->last_ms = now_ms;
        }
        return 0;
    }
    if (rl->global_fails < UINT32_MAX) {
        rl->global_fails++;
    }
    if (!s) {
        s = alloc(rl, key, now_ms);
        if (!s) {
            return 0; /* table full of locks: auth_rl_check() already refuses this IP */
        }
    }
    age(s, now_ms);
    s->last_ms = now_ms;
    if (s->locked_until_ms > now_ms) {
        return 0; /* already locked: callers check first; do not extend */
    }
    if (s->fails == 0) {
        s->fail_user = user_key;
    } else if (s->fail_user != user_key) {
        s->fail_user = AUTH_RL_USER_MIXED; /* no single success may clear these any more */
    }
    if (s->fails < UINT8_MAX) {
        s->fails++;
    }
    if (s->fails < rl->max_fail) {
        return 0;
    }
    uint32_t minutes = rl->lock_min;
    for (uint8_t i = 0; i < s->locks && minutes < AUTH_LOCK_MAX_MIN; i++) {
        minutes *= 2u;
    }
    if (minutes > AUTH_LOCK_MAX_MIN) {
        minutes = AUTH_LOCK_MAX_MIN;
    }
    if (s->locks < 8) {
        s->locks++;
    }
    s->fails = 0;
    s->fail_user = AUTH_RL_USER_NONE;
    s->window_start_ms = now_ms;
    s->locked_until_ms = now_ms + (uint64_t)minutes * MINUTE_MS;
    return minutes * 60u;
}

uint32_t auth_rl_global_delay_ms(const auth_rl_t *rl, uint64_t now_ms) {
    if (!rl || now_ms >= rl->global_minute_start_ms + MINUTE_MS || now_ms < rl->global_minute_start_ms) {
        return 0;
    }
    return rl->global_fails > AUTH_GLOBAL_FAIL_PER_MIN ? 1000u : 0u;
}
