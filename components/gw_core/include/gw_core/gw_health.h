/*
 * gw_health.h - task heartbeat registry (lock-free; IDF-free header).
 *
 * Lives in gw_core so every producer can beat without a dependency on sysmgr (mex150, store and web
 * are below or beside sysmgr in the component graph; see docs/ARCHITECTURE.md §1). Producers:
 *   GW_HB_MEX      mex150 "mex_poll" task, every loop iteration (also while devices are offline)
 *   GW_HB_EVT      gw_core itself, from its internal GW_EVT_SYS_TICK handler (proves dispatching)
 *   GW_HB_PERSIST  store "persist" task, every loop iteration (<= 1 s)
 *   GW_HB_HTTPD    web: a 2 s esp_timer queues a no-op httpd_queue_work() item that beats
 *   GW_HB_SNMP     snmp_gw on_idle hook of the agent task (<= 100 ms cadence while it runs, also
 *                  with SNMP disabled in the configuration: the task keeps running)
 *   GW_HB_NET      net "net_mgr" task, every loop iteration (<= 1 s): provisional-network revert,
 *                  AP fallback and AP idle stop all run there
 * Consumer: the sysmgr supervisor (mark-valid after GW_HB_REQUIRED_MASK has been fresh, bounded
 * health reboot, health LED, EVT_HEALTH log; GW_HB_WATCHED_MASK only for LED + log) and
 * GET /system/info diag.hb_stale.
 *
 * Implementation (gw_core/gw_health.c, device): one atomic uint32 millisecond stamp per source
 * (esp_timer, wraps after 49 days; ages are computed with unsigned subtraction) plus an atomic
 * "seen" bitmask. All functions are lock-free and callable from any task and from esp_timer
 * callbacks (not from ISRs).
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Heartbeat sources (bit positions of the masks below). */
typedef enum {
    GW_HB_MEX = 0,
    GW_HB_EVT = 1,
    GW_HB_PERSIST = 2,
    GW_HB_HTTPD = 3,
    GW_HB_SNMP = 4,
    GW_HB_NET = 5,
    GW_HB_COUNT
} gw_hb_t;

/** Sources that must be fresh before the running image is marked valid (and whose staleness
 *  triggers the bounded health reboot). */
#define GW_HB_REQUIRED_MASK                                                                                  \
    ((1u << GW_HB_MEX) | (1u << GW_HB_EVT) | (1u << GW_HB_PERSIST) | (1u << GW_HB_HTTPD) | (1u << GW_HB_NET))

/** Optional sources: stale (once the subsystem started) -> FAULT LED + EVT_HEALTH, never a reboot.
 *  The supervisor ignores a source whose init failed (that is an init fault already). */
#define GW_HB_WATCHED_MASK (1u << GW_HB_SNMP)

#define GW_HB_MAX_AGE_MS 5000 /* a heartbeat older than this is stale */

/** Record a heartbeat of `who` now (monotonic clock). Out-of-range values are ignored. */
void gw_hb_beat(gw_hb_t who);

/**
 * Bitmask (bit = gw_hb_t) of sources whose last beat is older than max_age_ms or that never beat
 * since boot.
 */
uint32_t gw_hb_stale_mask(uint32_t max_age_ms);

#ifdef __cplusplus
}
#endif
