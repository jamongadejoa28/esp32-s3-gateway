/*
 * store_dev.h - store-internal helpers of the device build (FreeRTOS); not a public header.
 */
#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** From long-running persist work (directory wipes, big appends): feed the persist task's TWDT
 * subscription and beat GW_HB_PERSIST. No-op in any other task. */
void store_wdt_feed(void);

#ifdef __cplusplus
}
#endif
