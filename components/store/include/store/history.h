/*
 * history.h - per-device trend history (DESIGN.md §8).
 *
 * Rings in PSRAM for every device index 0..GW_MAX_DEVICES-1, allocated once by history_init()
 * whether or not the device is configured (budgeted in ARCHITECTURE.md §6), so a device added later
 * through PUT /config/modbus records immediately:
 *   fast: 1 s  x 3600 (1 h)   hist_fast_t
 *   slow: 1 min x 2880 (48 h) hist_slow_t (min/avg/max per minute)
 * Ring position is time: history_sample() is called exactly once per second for every device index
 * (missing data recorded as HIST_F_GAP), so the k-th newest fast record is k seconds old and the
 * k-th newest slow record covers the k-th previous whole minute, on the monotonic clock, whether or
 * not the wall clock is valid.
 * Files: /data/hist/d<dev>/YYYYMMDD.bin (UTC date), header hist_file_hdr_t + hist_slow_t records,
 * appended in batches of HIST_FLUSH_BATCH via the persist task (and on reboot/OTA), retention
 * HIST_RETENTION_DAYS, last 24 h reloaded at boot. Files are only written while wall time is valid.
 *
 * Units: temp/hum/cur/st/sh are raw x10 (as the registers). HIST_GAP marks missing samples
 * (device offline, stale snapshot, or no data) and is rendered as JSON null.
 *
 * Threading: history_sample() is called ONLY from the gw_evt task (1 Hz GW_EVT_SYS_TICK).
 * Queries may be called from any other task (httpd, snmp); rings are protected by a mutex held
 * only while copying; file reads happen without the mutex.
 */
#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "mex150/service.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HIST_FAST_LEN 3600
#define HIST_SLOW_LEN 2880
#define HIST_FLUSH_BATCH 10 /* slow records per file append */
#define HIST_RETENTION_DAYS 30
#define HIST_RELOAD_HOURS 24
#define HIST_MAX_POINTS 1500 /* per channel per query */
#define HIST_GAP INT16_MIN
#define HIST_FILE_MAGIC 0x31485747u /* "GWH1" little-endian */

/* hist_fast_t.flags */
#define HIST_F_GAP 0x01     /* no valid sample this second (all values HIST_GAP) */
#define HIST_F_RUNNING 0x02 /* mex_running() */
#define HIST_F_ALARM 0x04   /* any active alarm on this device */

/** Channels of a query (order = REST "ch" keys temp, hum, cur, st, sh). */
typedef enum { HIST_CH_TEMP = 0, HIST_CH_HUM, HIST_CH_CUR, HIST_CH_ST, HIST_CH_SH, HIST_CH_COUNT } hist_ch_t;

/** 1-second sample (24 bytes). st/sh = setpoints 40012/40013. */
typedef struct {
    uint32_t ts_s; /* epoch s UTC; when wall time is invalid: uptime s with bit31 set */
    int16_t temp, hum, cur, st, sh;
    uint32_t coils;
    uint8_t flags;
} hist_fast_t;

/** Stage indexes for hist_slow_t.stage_on_s. */
typedef enum {
    HIST_STG_BLOWER = 0,
    HIST_STG_COOL,
    HIST_STG_HEAT,
    HIST_STG_HUM,
    HIST_STG_DEHUM,
    HIST_STG_COUNT
} hist_stage_t;

/** 1-minute aggregate (40 bytes, also the on-disk record; little-endian, packed by layout). */
typedef struct {
    uint32_t ts_s;            /* minute start, epoch s UTC */
    int16_t tmin, tavg, tmax; /* HIST_GAP if samples == 0 */
    int16_t hmin, havg, hmax;
    int16_t cmin, cavg, cmax;
    int16_t st, sh;                     /* last setpoints in the minute */
    uint8_t samples;                    /* valid 1 s samples, 0..60 */
    uint8_t flags;                      /* OR of hist_fast_t.flags over the minute */
    uint8_t stage_on_s[HIST_STG_COUNT]; /* seconds with >= 1 stage of that kind on (0..60) */
    uint8_t reserved;
    uint32_t alarm_mask; /* alarm coils 17..32 OR-ed over the minute (bits 0..15) */
} hist_slow_t;

static_assert(sizeof(hist_fast_t) == 24, "hist_fast_t layout");
static_assert(sizeof(hist_slow_t) == 40, "hist_slow_t layout");

/** Daily file header (16 bytes). */
typedef struct {
    uint32_t magic;    /* HIST_FILE_MAGIC */
    uint16_t version;  /* 1 */
    uint16_t rec_size; /* sizeof(hist_slow_t) */
    uint32_t day;      /* YYYYMMDD */
    uint8_t dev;
    uint8_t reserved[3];
} hist_file_hdr_t;

static_assert(sizeof(hist_file_hdr_t) == 16, "hist_file_hdr_t layout");

/* ---- Pure aggregation helpers (host-tested) ---- */

/** Minute accumulator. */
typedef struct {
    uint32_t minute_ts;
    int32_t sum[3];
    int16_t min[3], max[3];
    uint16_t n;
    int16_t st, sh;
    uint8_t flags;
    uint8_t stage_on[HIST_STG_COUNT];
    uint32_t alarm_mask;
} hist_acc_t;

void hist_acc_reset(hist_acc_t *a, uint32_t minute_ts);
/** Add one second; gap samples only contribute flags. stages from mex_derive_stages(). */
void hist_acc_add(hist_acc_t *a, const hist_fast_t *s);
/** Produce the minute record (avg rounded half away from zero). */
void hist_acc_finish(const hist_acc_t *a, hist_slow_t *out);

/** Fill a fast sample from a snapshot (s NULL / offline / stale -> gap). */
void hist_fast_from_snapshot(const mex_snapshot_t *s, bool fresh, bool any_alarm, uint32_t ts_s,
                             hist_fast_t *out);

/**
 * Effective resolution for a query: the smallest allowed step >= requested such that
 * span_s / step <= HIST_MAX_POINTS. Allowed steps: 1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200.
 * Steps < 60 are only possible for data within the fast ring (last hour).
 */
uint32_t hist_pick_res(uint32_t span_s, uint32_t requested_s);

/* ---- Device API ---- */

/** Allocate rings (PSRAM) for all GW_MAX_DEVICES indexes and reload the last 24 h. Before persist_start(). */
esp_err_t history_init(void);

/**
 * [gw_evt only] Take this second's sample of dev (snapshot fetched by the caller). Caller: the
 * alarm service's GW_EVT_SYS_TICK handler, once per tick for EVERY dev 0..GW_MAX_DEVICES-1
 * (s NULL / fresh=false for unconfigured or offline devices), with any_alarm = alarm_mask(dev) != 0
 * and ts_s = tick wall seconds, or uptime seconds | 0x80000000 when wall time is invalid.
 */
void history_sample(uint8_t dev, const mex_snapshot_t *s, bool fresh, bool any_alarm, uint32_t ts_s);

/**
 * Factory reset (sysmgr, when logs/history are not kept): clear the RAM rings, drop pending slow
 * records and ask the persist task to delete FS_DIR_HIST contents; later history_flush_request()
 * calls write nothing until reboot. Returns once the job is queued.
 */
esp_err_t history_factory_reset(void);

/** Request writing all pending slow records now (reboot/OTA). Non-blocking; use persist_flush(). */
void history_flush_request(void);

#define HIST_STAGE_GAP 0xFFFFu /* hist_series_t.stage[] value of a gap bucket (JSON null) */

/**
 * Columnar query result. Caller allocates the arrays (n_max entries each); min/max/stage may be NULL.
 * Output arrays hold raw x10 values or HIST_GAP.
 */
typedef struct {
    /* in */
    uint32_t n_max;              /* capacity of each array, <= HIST_MAX_POINTS */
    int16_t *avg[HIST_CH_COUNT]; /* required (fast data: the sample itself) */
    int16_t *min[HIST_CH_COUNT]; /* optional; only temp/hum/cur filled, st/sh entries ignored */
    int16_t *max[HIST_CH_COUNT];
    /* optional (REST ?stages=1): per bucket, seconds in which >= 1 stage of that kind was on
     * (fast data: from hist_fast_t.coils via mex_derive_stages; slow data: sum of
     * hist_slow_t.stage_on_s), 0..dt_s, HIST_STAGE_GAP for gap buckets */
    uint16_t *stage[HIST_STG_COUNT];
    /* out */
    int64_t t0_ms;      /* wall ms UTC of bucket 0's start; 0 when it is not known (wall time invalid) */
    uint64_t t0_age_ms; /* (now - bucket 0 start) on the monotonic clock; always valid */
    uint32_t dt_s;      /* effective resolution */
    uint32_t n;         /* points written */
} hist_series_t;

/**
 * Relative query: the last span_s seconds up to now (REST ?span=, WS hello backfill), at >= res_s
 * resolution (hist_pick_res). Anchored on the ring positions (monotonic clock), so it works whether
 * or not the wall clock is valid; t0_ms is set only when wall time is valid. span_s <= 30 days;
 * older than 48 h needs daily files and therefore valid wall time (else those buckets are gaps).
 * May read files: never call from gw_evt or persist.
 * Returns ESP_OK, ESP_ERR_INVALID_ARG (dev >= GW_MAX_DEVICES, span 0 or > 30 days, NULL arrays) or
 * ESP_ERR_INVALID_STATE (history not initialised, or called from gw_evt/persist).
 */
esp_err_t history_query_span(uint8_t dev, uint32_t span_s, uint32_t res_s, hist_series_t *io);

/**
 * Absolute query [from_ms, to_ms) (REST ?from=&to=) at >= res_s resolution. Buckets with no data ->
 * HIST_GAP. Sources: fast ring (dt < 60), slow ring (<= 48 h), daily files (older). Samples recorded
 * while wall time was invalid are not addressable by wall time and appear as gaps. May read files:
 * never call from gw_evt or persist. Returns ESP_OK, ESP_ERR_INVALID_ARG (bad range/dev, span > 30
 * days, from_ms more than HIST_RETENTION_DAYS before now), ESP_ERR_INVALID_STATE (wall time
 * currently invalid -> REST 400 bad_request; also: history not initialised or called from
 * gw_evt/persist).
 */
esp_err_t history_query(uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s, hist_series_t *io);

/** CSV export row callback: one call per bucket in time order (ts_ms 0 if unknown). false = stop. */
typedef bool (*hist_row_cb_t)(void *arg, int64_t ts_ms, const hist_slow_t *row);

/**
 * Iterate rows (minute aggregates, or 1 s samples mapped into hist_slow_t with min=avg=max when
 * res_s < 60) for CSV streaming without large buffers. Same task restrictions and errors as
 * history_query().
 */
esp_err_t history_foreach(uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s, hist_row_cb_t cb,
                          void *arg);

/** Relative variant of history_foreach() (same anchoring as history_query_span()). */
esp_err_t history_foreach_span(uint8_t dev, uint32_t span_s, uint32_t res_s, hist_row_cb_t cb, void *arg);

#ifdef __cplusplus
}
#endif
