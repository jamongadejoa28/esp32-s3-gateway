/* Supervisor policy (pure C): status LED selection and the health-reboot tracker.
 * Contract: sysmgr_pure.h; LED states: board/board.h. */
#include "board/board.h"
#include "sysmgr_pure.h"

uint8_t sys_led_select(const sys_led_inputs_t *in) {
    if (!in) {
        return BOARD_LED_FAULT;
    }
    if (in->reset_armed) {
        return BOARD_LED_RESET_ARMED;
    }
    if (in->ap_armed) {
        return BOARD_LED_AP_ARMED;
    }
    if (in->booting) {
        return BOARD_LED_BOOT;
    }
    if (in->ota) {
        return BOARD_LED_OTA;
    }
    if (in->fault) {
        return BOARD_LED_FAULT;
    }
    if (in->critical) {
        return BOARD_LED_CRITICAL;
    }
    if (in->alarms) {
        return BOARD_LED_ALARM;
    }
    if (in->comm_lost) {
        return BOARD_LED_COMM_LOST;
    }
    if (in->ap_active) {
        return BOARD_LED_AP;
    }
    if (!in->net_ok) {
        return BOARD_LED_NO_NET;
    }
    return BOARD_LED_OK;
}

bool sys_stale_update(sys_stale_track_t *t, uint32_t stale_mask, uint64_t up_ms) {
    if (!t) {
        return false;
    }
    const bool changed = stale_mask != t->mask;
    if (stale_mask && !t->stale) {
        t->stale = true;
        t->since_ms = up_ms;
    } else if (!stale_mask) {
        t->stale = false;
        t->since_ms = 0;
    }
    t->mask = stale_mask;
    return changed;
}

bool sys_health_reboot_due(const sys_stale_track_t *t, bool armed, uint64_t up_ms, uint64_t limit_ms,
                           uint32_t prior_reboots, uint32_t max_reboots) {
    if (!t || !armed || !t->stale || up_ms < t->since_ms || prior_reboots >= max_reboots) {
        return false;
    }
    return up_ms - t->since_ms >= limit_ms;
}
