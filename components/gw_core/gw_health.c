/* Heartbeat registry (contract: gw_core/gw_health.h). Device only (esp_timer). */
#include "gw_core/gw_health.h"

#include <stdatomic.h>

#include "esp_timer.h"

static _Atomic uint32_t s_last_ms[GW_HB_COUNT];
static _Atomic uint32_t s_seen;

static uint32_t now_ms32(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

void gw_hb_beat(gw_hb_t who) {
    if ((unsigned)who >= GW_HB_COUNT) {
        return;
    }
    atomic_store_explicit(&s_last_ms[who], now_ms32(), memory_order_relaxed);
    atomic_fetch_or_explicit(&s_seen, 1u << who, memory_order_release);
}

uint32_t gw_hb_stale_mask(uint32_t max_age_ms) {
    const uint32_t now = now_ms32();
    const uint32_t seen = atomic_load_explicit(&s_seen, memory_order_acquire);
    uint32_t stale = 0;
    for (unsigned i = 0; i < GW_HB_COUNT; i++) {
        if (!(seen & (1u << i)) ||
            now - atomic_load_explicit(&s_last_ms[i], memory_order_relaxed) > max_age_ms) {
            stale |= 1u << i;
        }
    }
    return stale;
}
