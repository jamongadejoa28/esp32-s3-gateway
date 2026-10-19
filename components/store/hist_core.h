/*
 * hist_core.h - pure history engine behind store/history.h (store-internal, host-tested).
 *
 * One hist_dev_t per device index holds the fast/slow rings (caller memory, PSRAM on the device),
 * the minute accumulator and the records waiting for the daily-file writer. Ring positions are
 * time: every tick pushes exactly one fast sample and every 60th tick one slow record. Records are
 * addressed by ABSOLUTE indexes (fast_total / slow_total count everything ever pushed) so a query
 * can copy the rings in chunks, releasing the lock in between, without losing its anchor.
 *
 * Daily files (stdio, any base directory): <base>/d<dev>/YYYYMMDD.bin = hist_file_hdr_t + records.
 * Not thread-safe: the device wrapper (history.c) serialises with a mutex through hist_env_t.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_err.h"
#include "gw_core/gw_ring.h"
#include "store/history.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HIST_PEND_MAX 60   /* pending minute records per device (1 h of writer backlog) */
#define HIST_SPAN_MAX_S (30u * 86400u)
#define HIST_TS_UPTIME 0x80000000u /* ts_s flag: uptime seconds (wall time was invalid) */

typedef struct {
    gw_ring_t fast; /* hist_fast_t x HIST_FAST_LEN */
    gw_ring_t slow; /* hist_slow_t x HIST_SLOW_LEN */
    hist_acc_t acc;
    uint8_t acc_ticks;     /* ticks accumulated in the in-progress minute, 0..59 */
    uint64_t last_mono_ms; /* monotonic ms of the newest fast sample (0 = none yet) */
    uint64_t slot_base_ms; /* mono ms of the start of 1 s slot 0 (first sample - 500 ms) */
    uint64_t next_slot;    /* index of the next 1 s slot to fill, counted from slot_base_ms */
    uint32_t gap_filled;   /* missed ticks filled with gap samples (diagnostics) */
    uint32_t dup_dropped;  /* samples dropped because their slot was already filled */
    uint64_t fast_total;   /* fast samples pushed since init */
    uint64_t slow_total;   /* slow records pushed since init (incl. reloaded ones) */
    hist_slow_t pend[HIST_PEND_MAX];
    uint16_t n_pend;
    uint32_t pend_dropped; /* minutes lost because the writer fell behind */
    /* reload state */
    uint32_t reload_now_s;
    int32_t reload_next; /* next free slot (minutes before now - 1), -1 = done */
    bool reload_any;
} hist_dev_t;

/** True iff ts_s is a wall-clock timestamp (not uptime-flagged, >= GW_TIME_VALID_MIN_S). */
bool hist_ts_wall(uint32_t ts_s);

/** Bind rings to caller memory (HIST_FAST_LEN x 24 B, HIST_SLOW_LEN x 40 B) and clear. */
void hist_dev_init(hist_dev_t *d, void *fast_mem, void *slow_mem);
/** Forget all samples, the accumulator and pending records (rings keep their memory). */
void hist_dev_clear(hist_dev_t *d);

/**
 * Push this tick's sample. Every 60th pushed sample closes the minute into the slow ring; a closed
 * minute with samples > 0 and a wall timestamp is queued for the file writer. Returns true when
 * the pending queue reached a multiple of HIST_FLUSH_BATCH (caller marks the writer dirty).
 *
 * Ring position must stay time even when ticks are lost (gw_evt queue full, stalled handler) or
 * delivered in a burst. mono_ms places the sample in a 1 s slot (slot 0 is centred on the first
 * sample, so +-499 ms of handler jitter never changes the slot): skipped slots are filled with gap
 * samples first (oldest first, through the normal minute accumulator; beyond HIST_FAST_LEN + 59
 * missed slots the excess is pushed as whole gap minutes, at most HIST_SLOW_LEN), and a sample
 * whose slot is already filled (a burst of late ticks) is dropped. mono_ms = 0 disables placement
 * (one push per call).
 */
bool hist_dev_sample(hist_dev_t *d, const hist_fast_t *s, uint64_t mono_ms);

/** Pop up to cap pending records (oldest first). */
size_t hist_dev_take_pending(hist_dev_t *d, hist_slow_t *out, size_t cap);
/** Put records back at the FRONT of the pending queue after a failed write (drops what no longer fits). */
void hist_dev_unget_pending(hist_dev_t *d, const hist_slow_t *recs, size_t n);

/**
 * Boot reload: begin(now_s), add() every file record of the last HIST_RELOAD_HOURS in ascending
 * order, end(). The slow ring then holds one record per minute before now (gap records where no
 * data exists) so ring positions stay time; nothing is pushed when no record was added.
 */
void hist_dev_reload_begin(hist_dev_t *d, uint32_t now_s);
bool hist_dev_reload_add(void *dev /* hist_dev_t* */, const hist_slow_t *r);
void hist_dev_reload_end(hist_dev_t *d);

/** One fast sample as a one-second slow record (samples 0/1, min = avg = max). */
void hist_slow_from_fast(const hist_fast_t *f, hist_slow_t *out);

/** hist_pick_res() with a custom point limit. */
uint32_t hist_pick_res_limit(uint32_t span_s, uint32_t requested_s, uint32_t limit);

/* ---- 10-minute rollups of the daily files (query cache) ---- */

/*
 * Queries reaching back further than the slow ring (48 h) would otherwise decode every 1-minute
 * record of up to 30 daily files (~1.6 MB of flash) per request. The device keeps one hist_day_t
 * per (device, UTC day) in PSRAM instead, built once from the day's file and updated by the file
 * writer, and queries with dt a multiple of HIST_COARSE_S read those rollups (env.coarse) for
 * everything older than the rings. A rollup record covering [start, start + HIST_COARSE_S) is
 * spread over the buckets it overlaps in proportion to its minutes (avg weights, stage seconds and
 * sample counts; min/max apply to each overlapped bucket), so bucket edges in that part are exact
 * to 10 minutes rather than to the minute.
 */
#define HIST_COARSE_S 600u
#define HIST_COARSE_MIN (HIST_COARSE_S / 60u)
#define HIST_COARSE_PER_DAY (86400u / HIST_COARSE_S)

typedef struct {
    int32_t wsum[3];   /* sum of minute avg x samples (temp, hum, cur) */
    int16_t mn[3], mx[3];
    int16_t st, sh;    /* setpoints of the newest minute with samples */
    uint16_t samples;  /* valid 1 s samples, 0..600 */
    uint16_t stage[HIST_STG_COUNT];
    uint16_t alarm;    /* alarm coils 17..32 OR-ed */
    uint8_t flags;     /* OR of the minutes' flags */
    uint8_t minutes;   /* minute records added (0 = no record: the period is absent, not a gap) */
} hist_coarse_t;

typedef struct {
    uint32_t day; /* UTC epoch day (ts / 86400) */
    hist_coarse_t c[HIST_COARSE_PER_DAY];
} hist_day_t;

/** Clear d for UTC epoch day `day`. */
void hist_day_reset(hist_day_t *d, uint32_t day);
/** Add one minute record (ignored unless wall-stamped and inside d's day). */
void hist_day_add(hist_day_t *d, const hist_slow_t *r);
/** hist_rec_cb_t adaptor of hist_day_add (dev = hist_day_t*); always continues. */
bool hist_day_add_cb(void *day, const hist_slow_t *r);

/** Rollup callback: start = wall second of the period start; return false to stop. */
typedef bool (*hist_coarse_cb_t)(void *arg, uint32_t start, const hist_coarse_t *c);

/* ---- queries ---- */

typedef bool (*hist_rec_cb_t)(void *arg, const hist_slow_t *r);

/** Environment of a query: ring lock and daily-file iteration (either may be NULL). */
typedef struct {
    void (*lock)(void *arg);
    void (*unlock)(void *arg);
    void *lock_arg;
    /* call cb for every file record of dev with from_s <= ts_s < to_s in ascending order */
    void (*files)(void *arg, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_rec_cb_t cb, void *cb_arg);
    void *files_arg;
    /* optional: call cb for every rollup of dev with from_s <= start < to_s in ascending order
     * (from_s is a multiple of HIST_COARSE_S). Used instead of files for queries with dt a
     * multiple of HIST_COARSE_S. Periods without any record are skipped. */
    void (*coarse)(void *arg, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_coarse_cb_t cb, void *cb_arg);
    void *coarse_arg;
} hist_env_t;

/**
 * Relative query (history_query_span / history_foreach_span semantics). Exactly one of io / row_cb.
 * now_wall_ms = 0 when the wall clock is invalid.
 */
esp_err_t hist_core_span(hist_dev_t *d, uint8_t dev, uint32_t span_s, uint32_t res_s, uint64_t now_mono_ms,
                         int64_t now_wall_ms, const hist_env_t *env, hist_series_t *io, hist_row_cb_t row_cb,
                         void *row_arg);

/** Absolute query (history_query / history_foreach semantics). now_wall_ms must be valid (> 0). */
esp_err_t hist_core_range(hist_dev_t *d, uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s,
                          int64_t now_wall_ms, const hist_env_t *env, hist_series_t *io, hist_row_cb_t row_cb,
                          void *row_arg);

/* ---- daily files (stdio) ---- */

/** Append records (any days, ascending) to <base>/d<dev>/YYYYMMDD.bin; creates dirs/headers. */
esp_err_t hist_files_append(const char *base, uint8_t dev, const hist_slow_t *recs, size_t n);
/** Iterate file records with from_s <= ts < to_s ascending (hist_env_t.files signature, arg = base). */
void hist_files_iter(void *base, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_rec_cb_t cb, void *cb_arg);
/**
 * Delete daily files (and set-aside <day>.bad files) older than HIST_RETENTION_DAYS before now_s.
 * Returns the number deleted; *failed (may be NULL) = expired files that could not be deleted.
 */
int hist_files_retention(const char *base, uint8_t dev, uint32_t now_s, int *failed);

#ifdef __cplusplus
}
#endif
