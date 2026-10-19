/*
 * net_prov.h - pure decision logic of net_mgr (host-tested in tests/test_net_pure.py):
 *   1. the provisional apply / confirm / revert state machine of PUT /config/network (net.h)
 *   2. the recovery-AP policy: fallback start (no Ethernet IP for fallback_after_s) and idle stop
 *      (no station for idle_min).
 * Private to the net component. Times are injected monotonic milliseconds. Not thread-safe: net_mgr
 * calls it under its state lock.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- provisional state machine ---------------- */

/** What net_mgr must do to the interfaces after a call. */
typedef enum {
    NET_PROV_ACT_NONE = 0,
    NET_PROV_ACT_APPLY_CAND = 1, /* reconfigure with the candidate (and provisional AP PSK) */
    NET_PROV_ACT_APPLY_PREV = 2, /* restore the previous (committed) config and PSK */
} net_prov_action_t;

#define NET_PROV_APPLY_MAX_S 60
#define NET_PROV_CONFIRM_MIN_S 10
#define NET_PROV_CONFIRM_MAX_S 3600

typedef struct {
    uint8_t state;        /* net_prov_state_t (net.h) */
    bool confirming;      /* a confirm commit is in progress: timers frozen */
    uint64_t deadline_ms; /* APPLY_PENDING: apply time; AWAIT_CONFIRM: revert time */
    uint32_t confirm_s;
} net_prov_fsm_t;

void net_prov_init(net_prov_fsm_t *f);

/** NONE -> APPLY_PENDING. ESP_ERR_INVALID_STATE while a change is pending (APPLY_PENDING or
 * AWAIT_CONFIRM; the transient CONFIRMED/REVERTED states count as finished),
 * ESP_ERR_INVALID_ARG for apply_in_s > NET_PROV_APPLY_MAX_S or confirm_s outside
 * NET_PROV_CONFIRM_MIN_S..NET_PROV_CONFIRM_MAX_S. */
esp_err_t net_prov_start(net_prov_fsm_t *f, uint64_t now_ms, uint32_t apply_in_s, uint32_t confirm_s);

/** Advance timers: APPLY_PENDING past its deadline -> AWAIT_CONFIRM (APPLY_CAND);
 * AWAIT_CONFIRM past its deadline -> REVERTED (APPLY_PREV). Frozen while confirming. */
net_prov_action_t net_prov_tick(net_prov_fsm_t *f, uint64_t now_ms);

/** Begin a confirm (APPLY_PENDING/AWAIT_CONFIRM, not already confirming): freezes the timers while
 * the caller commits the candidate outside its lock. ESP_ERR_INVALID_STATE otherwise. */
esp_err_t net_prov_confirm_begin(net_prov_fsm_t *f);

/** Finish a confirm. committed=true -> CONFIRMED; returns APPLY_CAND if the candidate had not been
 * applied yet (confirm during APPLY_PENDING). committed=false -> timers resume (state unchanged;
 * an expired AWAIT_CONFIRM reverts at the next tick). */
net_prov_action_t net_prov_confirm_end(net_prov_fsm_t *f, bool committed);

/** Revert now: APPLY_PENDING -> REVERTED (NONE: nothing applied yet), AWAIT_CONFIRM -> REVERTED
 * (APPLY_PREV). ESP_ERR_INVALID_STATE when nothing is pending or a confirm is in progress. */
esp_err_t net_prov_revert(net_prov_fsm_t *f, net_prov_action_t *act);

/** CONFIRMED/REVERTED -> NONE (after the transition has been published). */
void net_prov_settle(net_prov_fsm_t *f);

/** True while a change is pending (APPLY_PENDING or AWAIT_CONFIRM). */
bool net_prov_pending(const net_prov_fsm_t *f);

/** Seconds until apply (APPLY_PENDING) or revert (AWAIT_CONFIRM), rounded up; 0 otherwise. */
uint32_t net_prov_left_s(const net_prov_fsm_t *f, uint64_t now_ms);

/* ---------------- recovery AP policy ---------------- */

/**
 * Fallback start: the AP should be started (reason NO_LINK) when fallback is enabled, the AP is not
 * running, Ethernet has no IP, and has had none since no_ip_since_ms for at least after_s seconds.
 */
bool net_ap_should_fallback(bool fallback_en, bool ap_active, bool eth_has_ip, uint64_t no_ip_since_ms,
                            uint64_t now_ms, uint32_t after_s);

/**
 * Idle stop: true when the AP should stop because no station has been connected since
 * idle_since_ms for idle_min minutes. Never while stations are connected, and never for a NO_LINK
 * AP while Ethernet still has no IP (it is the only way in).
 */
bool net_ap_should_stop(bool ap_active, uint8_t reason, uint8_t clients, bool eth_has_ip,
                        uint64_t idle_since_ms, uint64_t now_ms, uint32_t idle_min);

/** Seconds until net_ap_should_stop() becomes true (rounded up), 0 when it does not apply. */
uint32_t net_ap_off_in_s(bool ap_active, uint8_t reason, uint8_t clients, bool eth_has_ip,
                         uint64_t idle_since_ms, uint64_t now_ms, uint32_t idle_min);

/**
 * Back-off before the next automatic (fallback) AP start after `fails` consecutive failed starts:
 * max(after_s, NET_AP_RETRY_MIN_S) doubled per further failure, capped at NET_AP_RETRY_MAX_S.
 * 0 when fails == 0.
 */
#define NET_AP_RETRY_MIN_S 30u
#define NET_AP_RETRY_MAX_S 600u
uint32_t net_ap_retry_delay_s(uint32_t after_s, uint8_t fails);

/**
 * True when the IPv4 subnet ip/mask overlaps ap_ip/ap_mask (either contains the other). Such an
 * Ethernet address must not be used (DESIGN.md §14: the Ethernet subnet never overlaps the
 * recovery-AP subnet). A zero ip never overlaps.
 */
bool net_subnet_overlaps(uint32_t ip, uint32_t mask, uint32_t ap_ip, uint32_t ap_mask);

#ifdef __cplusplus
}
#endif
