/*
 * gw_time.h - clocks and calendar helpers.
 *
 * Two clocks:
 *   mono  - milliseconds since boot (esp_timer), never jumps; use for timeouts, ages, rates.
 *   wall  - UTC epoch milliseconds (gettimeofday). Only meaningful when gw_time_valid().
 * The RTC (PCF85063) stores UTC; local time is only applied for display/file names via TZ.
 *
 * Device-only functions are marked [device] and live in gw_core/gw_time.c (esp_timer,
 * settimeofday; not host-built). The calendar helpers are pure and live in gw_core/gw_time_civil.c,
 * which is listed in cmake/gw_host_sources.cmake (GW_HOST_SOURCES_GW_CORE) and host-tested.
 * No IDF types in this header.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Wall clock values before 2024-01-01T00:00:00Z are treated as "not set". */
#define GW_TIME_VALID_MIN_S 1704067200LL

/** [device] Milliseconds since boot. Any task/ISR. */
uint64_t gw_time_mono_ms(void);

/** [device] Wall time ms UTC, or 0 when !gw_time_valid(). Any task. */
int64_t gw_time_wall_ms(void);

/** [device] True once the wall clock has been set to a plausible value (>= GW_TIME_VALID_MIN_S). */
bool gw_time_valid(void);

/**
 * [device] Set the system wall clock (settimeofday) and post GW_EVT_TIME_SYNC{source, by}.
 * Does NOT write the RTC: sysmgr handles GW_EVT_TIME_SYNC with source != RTC by calling
 * board_rtc_set_utc(). Rejects values < GW_TIME_VALID_MIN_S (returns false). Any task.
 * `by` may be NULL ("" in the event).
 */
bool gw_time_set_wall_ms(int64_t wall_ms, uint8_t source /* gw_time_src_t */, const char *by);

/**
 * [device] Apply a POSIX TZ string (setenv("TZ") + tzset()). Returns false if tz is empty/too long.
 * Called by net only: in net_init() and in its CONFIG_CHANGED{TIME} handler (docs/ARCHITECTURE.md §7).
 */
bool gw_time_set_tz(const char *tz);

/* ---- Pure calendar helpers (UTC, proleptic Gregorian, valid 1970..2105) ---- */

typedef struct {
    uint16_t year; /* 1970.. */
    uint8_t mon;   /* 1..12 */
    uint8_t day;   /* 1..31 */
    uint8_t hour;  /* 0..23 */
    uint8_t min;   /* 0..59 */
    uint8_t sec;   /* 0..59 */
    uint8_t wday;  /* 0 = Sunday (output only) */
} gw_civil_t;

/** epoch seconds (>= 0) -> civil UTC. */
void gw_time_to_civil(int64_t epoch_s, gw_civil_t *out);

/** civil UTC -> epoch seconds; returns -1 if any field is out of range. wday is ignored. */
int64_t gw_time_from_civil(const gw_civil_t *c);

/** UTC date as decimal YYYYMMDD (history file names /data/hist/dN/YYYYMMDD.bin). */
uint32_t gw_time_yyyymmdd(int64_t epoch_s);

/**
 * SNMPv2-TC DateAndTime, 11-octet form with UTC direction '+' 0:0 (RFC 2579):
 * year(2,BE) month day hour min sec decisec '+' 0 0. Returns 11.
 */
size_t gw_time_snmp_date(int64_t wall_ms, uint8_t out[11]);

/** ISO 8601 UTC "YYYY-MM-DDTHH:MM:SS.mmmZ" (out >= 25 bytes). Returns length or 0 if cap too small. */
size_t gw_time_iso8601(int64_t wall_ms, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
