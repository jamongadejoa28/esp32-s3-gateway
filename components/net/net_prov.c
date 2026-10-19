/* Pure provisional-change state machine and recovery-AP policy (contract: net_prov.h). */
#include "net_prov.h"

#include <string.h>

#include "net/net.h"

void net_prov_init(net_prov_fsm_t *f) {
    memset(f, 0, sizeof(*f));
    f->state = NET_PROV_NONE;
}

bool net_prov_pending(const net_prov_fsm_t *f) {
    return f->state == NET_PROV_APPLY_PENDING || f->state == NET_PROV_AWAIT_CONFIRM;
}

esp_err_t net_prov_start(net_prov_fsm_t *f, uint64_t now_ms, uint32_t apply_in_s, uint32_t confirm_s) {
    if (net_prov_pending(f) || f->confirming) {
        return ESP_ERR_INVALID_STATE;
    }
    if (apply_in_s > NET_PROV_APPLY_MAX_S || confirm_s < NET_PROV_CONFIRM_MIN_S ||
        confirm_s > NET_PROV_CONFIRM_MAX_S) {
        return ESP_ERR_INVALID_ARG;
    }
    f->state = NET_PROV_APPLY_PENDING;
    f->deadline_ms = now_ms + (uint64_t)apply_in_s * 1000u;
    f->confirm_s = confirm_s;
    return ESP_OK;
}

net_prov_action_t net_prov_tick(net_prov_fsm_t *f, uint64_t now_ms) {
    if (f->confirming || now_ms < f->deadline_ms) {
        return NET_PROV_ACT_NONE;
    }
    if (f->state == NET_PROV_APPLY_PENDING) {
        f->state = NET_PROV_AWAIT_CONFIRM;
        f->deadline_ms = now_ms + (uint64_t)f->confirm_s * 1000u;
        return NET_PROV_ACT_APPLY_CAND;
    }
    if (f->state == NET_PROV_AWAIT_CONFIRM) {
        f->state = NET_PROV_REVERTED;
        f->deadline_ms = 0;
        return NET_PROV_ACT_APPLY_PREV;
    }
    return NET_PROV_ACT_NONE;
}

esp_err_t net_prov_confirm_begin(net_prov_fsm_t *f) {
    if (!net_prov_pending(f) || f->confirming) {
        return ESP_ERR_INVALID_STATE;
    }
    f->confirming = true;
    return ESP_OK;
}

net_prov_action_t net_prov_confirm_end(net_prov_fsm_t *f, bool committed) {
    if (!f->confirming) {
        return NET_PROV_ACT_NONE;
    }
    f->confirming = false;
    if (!committed) {
        return NET_PROV_ACT_NONE;
    }
    const bool applied = f->state == NET_PROV_AWAIT_CONFIRM;
    f->state = NET_PROV_CONFIRMED;
    f->deadline_ms = 0;
    return applied ? NET_PROV_ACT_NONE : NET_PROV_ACT_APPLY_CAND;
}

esp_err_t net_prov_revert(net_prov_fsm_t *f, net_prov_action_t *act) {
    if (!net_prov_pending(f) || f->confirming) {
        return ESP_ERR_INVALID_STATE;
    }
    *act = f->state == NET_PROV_AWAIT_CONFIRM ? NET_PROV_ACT_APPLY_PREV : NET_PROV_ACT_NONE;
    f->state = NET_PROV_REVERTED;
    f->deadline_ms = 0;
    return ESP_OK;
}

void net_prov_settle(net_prov_fsm_t *f) {
    if (f->state == NET_PROV_CONFIRMED || f->state == NET_PROV_REVERTED) {
        f->state = NET_PROV_NONE;
        f->deadline_ms = 0;
    }
}

static uint32_t ceil_s(uint64_t ms) {
    const uint64_t s = (ms + 999u) / 1000u;
    return s > UINT32_MAX ? UINT32_MAX : (uint32_t)s;
}

uint32_t net_prov_left_s(const net_prov_fsm_t *f, uint64_t now_ms) {
    if (!net_prov_pending(f) || now_ms >= f->deadline_ms) {
        return 0;
    }
    return ceil_s(f->deadline_ms - now_ms);
}

bool net_ap_should_fallback(bool fallback_en, bool ap_active, bool eth_has_ip, uint64_t no_ip_since_ms,
                            uint64_t now_ms, uint32_t after_s) {
    if (!fallback_en || ap_active || eth_has_ip || now_ms < no_ip_since_ms) {
        return false;
    }
    return now_ms - no_ip_since_ms >= (uint64_t)after_s * 1000u;
}

/* Idle shutdown applies at all (see net_ap_should_stop). */
static bool idle_applies(bool ap_active, uint8_t reason, uint8_t clients, bool eth_has_ip) {
    if (!ap_active || clients > 0) {
        return false;
    }
    return !(reason == NET_AP_REASON_NO_LINK && !eth_has_ip);
}

bool net_ap_should_stop(bool ap_active, uint8_t reason, uint8_t clients, bool eth_has_ip,
                        uint64_t idle_since_ms, uint64_t now_ms, uint32_t idle_min) {
    if (!idle_applies(ap_active, reason, clients, eth_has_ip) || now_ms < idle_since_ms) {
        return false;
    }
    return now_ms - idle_since_ms >= (uint64_t)idle_min * 60000u;
}

uint32_t net_ap_off_in_s(bool ap_active, uint8_t reason, uint8_t clients, bool eth_has_ip,
                         uint64_t idle_since_ms, uint64_t now_ms, uint32_t idle_min) {
    if (!idle_applies(ap_active, reason, clients, eth_has_ip)) {
        return 0;
    }
    const uint64_t end = idle_since_ms + (uint64_t)idle_min * 60000u;
    return now_ms >= end ? 0 : ceil_s(end - now_ms);
}

uint32_t net_ap_retry_delay_s(uint32_t after_s, uint8_t fails) {
    if (fails == 0) {
        return 0;
    }
    uint32_t d = after_s > NET_AP_RETRY_MIN_S ? after_s : NET_AP_RETRY_MIN_S;
    for (uint8_t i = 1; i < fails && d < NET_AP_RETRY_MAX_S; i++) {
        d *= 2u;
    }
    return d > NET_AP_RETRY_MAX_S ? NET_AP_RETRY_MAX_S : d;
}

bool net_subnet_overlaps(uint32_t ip, uint32_t mask, uint32_t ap_ip, uint32_t ap_mask) {
    if (ip == 0) {
        return false;
    }
    const uint32_t common = mask & ap_mask; /* the shorter prefix of the two (contiguous masks) */
    return (ip & common) == (ap_ip & common);
}
