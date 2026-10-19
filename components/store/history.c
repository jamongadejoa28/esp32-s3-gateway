/*
 * history.c - per-device trend history (device): PSRAM rings for every device index, the 1 Hz
 * sample entry point (gw_evt), the daily-file writer (persist), boot reload, the 10-minute rollup
 * cache of the daily files and the query API. Contract: store/history.h. Engine: history_core.c.
 *
 * Rollup cache (hist_core.h hist_day_t): one PSRAM slot per (device, UTC day) for the last
 * HIST_DAY_SLOTS days, ~6.4 KB each, built from the day's file the first time a query needs it
 * (or by the boot warm-up job in the persist task) and kept current by the file writer, which adds
 * every record it appends. Spans/ranges older than the slow ring therefore read PSRAM instead of
 * up to 30 daily files (~1.6 MB) on the httpd task. A build reads the file outside the lock and is
 * installed only if no append started or ended meanwhile (per-device generation counter, bumped at
 * both ends of an append; a build never starts while an append of that device is in progress).
 */
#include "store/history.h"

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "hist_core.h"
#include "store/fs.h"
#include "store/persist.h"
#include "store_dev.h"

static const char *TAG = "history";

static hist_dev_t *s_dev[GW_MAX_DEVICES];
static SemaphoreHandle_t s_mtx;
static bool s_ready;
static volatile bool s_frozen; /* set once by history_factory_reset(), read by every task */
static uint32_t s_retention_day; /* epoch day of the last retention pass */
static EXT_RAM_BSS_ATTR hist_slow_t s_wbuf[HIST_PEND_MAX]; /* persist writer scratch (persist task only) */

#define HIST_DAY_SLOTS 32 /* > HIST_RETENTION_DAYS + 1: index day % 32 never collides in range */
#define HIST_DAY_NONE UINT32_MAX
static_assert(HIST_DAY_SLOTS > HIST_RETENTION_DAYS + 1, "rollup slots must cover the retention");

typedef struct {
    uint32_t day; /* UTC epoch day held, HIST_DAY_NONE = slot unused */
    hist_day_t *p; /* NULL with day set: the day has no file (nothing to roll up yet) */
} day_slot_t;

static day_slot_t s_days[GW_MAX_DEVICES][HIST_DAY_SLOTS]; /* under s_mtx */
static uint32_t s_day_gen[GW_MAX_DEVICES];                /* under s_mtx: ++ before and after every append */
static bool s_day_busy[GW_MAX_DEVICES];                   /* under s_mtx: append of that device in progress */
static uint32_t s_warm_dev, s_warm_back;                   /* warm-up cursor (persist task only) */
static bool s_warm_queued;                                 /* gw_evt task only */
#define HIST_WARM_AFTER_MS 60000u                          /* let the boot settle first */

static void h_lock(void *arg) {
    (void)arg;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void h_unlock(void *arg) {
    (void)arg;
    xSemaphoreGive(s_mtx);
}

/* Daily-file reads for queries; none once a factory reset froze history (the wipe must be able to
 * unlink every file, and esp_littlefs refuses to unlink an open one). */
static void h_files(void *base, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_rec_cb_t cb, void *cb_arg) {
    if (s_frozen)
        return;
    hist_files_iter(base, dev, from_s, to_s, cb, cb_arg);
}

static void *psram_calloc(size_t n, size_t sz) {
    void *p = heap_caps_calloc(n, sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p)
        p = heap_caps_calloc(n, sz, MALLOC_CAP_8BIT); /* boards without PSRAM (never in production) */
    return p;
}

/* ---- rollup cache ---- */

static void days_clear_locked(void) {
    for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++) {
        for (unsigned i = 0; i < HIST_DAY_SLOTS; i++) {
            heap_caps_free(s_days[dev][i].p);
            s_days[dev][i].p = NULL;
            s_days[dev][i].day = HIST_DAY_NONE;
        }
        s_day_gen[dev]++;
    }
}

/* Make sure the rollup of (dev, day) is cached. Reads the day file outside the lock (any task but
 * gw_evt). Returns false when it could not be built (no memory, factory reset). */
static bool day_ensure(uint8_t dev, uint32_t day) {
    day_slot_t *slot = &s_days[dev][day % HIST_DAY_SLOTS];
    for (int attempt = 0; attempt < 5; attempt++) {
        h_lock(NULL);
        const bool have = slot->day == day;
        const bool busy = s_day_busy[dev];
        const uint32_t gen = s_day_gen[dev];
        h_unlock(NULL);
        if (have)
            return true;
        if (s_frozen)
            return false;
        if (busy) {
            vTaskDelay(pdMS_TO_TICKS(20)); /* the file is being appended to: read it afterwards */
            continue;
        }
        hist_day_t *nd = heap_caps_malloc(sizeof(*nd), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!nd) {
            ESP_LOGW(TAG, "d%u: no PSRAM for a rollup day", dev);
            return false;
        }
        hist_day_reset(nd, day);
        uint32_t n_rec = 0;
        hist_files_iter((void *)FS_DIR_HIST, dev, day * 86400u, day * 86400u + 86400u, hist_day_add_cb, nd);
        for (unsigned i = 0; i < HIST_COARSE_PER_DAY; i++)
            n_rec += nd->c[i].minutes;
        hist_day_t *old = NULL;
        bool installed = false;
        h_lock(NULL);
        if (!s_frozen && s_day_gen[dev] == gen) {
            old = slot->p;
            slot->p = n_rec ? nd : NULL;
            slot->day = day;
            installed = true;
        }
        h_unlock(NULL);
        heap_caps_free(old);
        if (!installed || !n_rec)
            heap_caps_free(nd);
        if (installed)
            return true;
        /* the writer appended while the file was read: read again */
    }
    return false;
}

/* hist_env_t.coarse: rollups of dev with from_s <= start < to_s, ascending, copied out in chunks. */
static void h_coarse(void *arg, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_coarse_cb_t cb, void *cb_arg) {
    (void)arg;
    if (s_frozen || dev >= GW_MAX_DEVICES || to_s <= from_s)
        return;
    for (uint32_t day = from_s / 86400u; (uint64_t)day * 86400u < to_s; day++) {
        if (!day_ensure(dev, day))
            continue; /* that day is missing from this answer (logged) */
        const uint32_t base = day * 86400u;
        uint32_t i = from_s > base ? (from_s - base + HIST_COARSE_S - 1) / HIST_COARSE_S : 0;
        while (i < HIST_COARSE_PER_DAY && base + i * HIST_COARSE_S < to_s) {
            enum { CH = 16 };
            hist_coarse_t buf[CH];
            uint32_t idx[CH];
            unsigned cnt = 0;
            bool gone = false;
            h_lock(NULL);
            const day_slot_t *slot = &s_days[dev][day % HIST_DAY_SLOTS];
            if (slot->day != day) {
                gone = true; /* evicted meanwhile (factory reset / write failure) */
            } else if (!slot->p) {
                i = HIST_COARSE_PER_DAY; /* no file for that day */
            } else {
                for (; cnt < CH && i < HIST_COARSE_PER_DAY && base + i * HIST_COARSE_S < to_s; i++) {
                    if (slot->p->c[i].minutes) {
                        buf[cnt] = slot->p->c[i];
                        idx[cnt++] = i;
                    }
                }
            }
            h_unlock(NULL);
            if (gone)
                break;
            for (unsigned k = 0; k < cnt; k++) {
                if (!cb(cb_arg, base + idx[k] * HIST_COARSE_S, &buf[k]))
                    return;
            }
        }
    }
}

/* Writer side (persist task), around every append: keep cached days current, or drop them when
 * the append failed part-way (what reached the file is then unknown). */
static void days_append_begin(uint8_t dev) {
    h_lock(NULL);
    s_day_busy[dev] = true;
    s_day_gen[dev]++;
    h_unlock(NULL);
}

static void days_note_append(uint8_t dev, const hist_slow_t *recs, size_t n, bool ok) {
    h_lock(NULL);
    s_day_busy[dev] = false;
    s_day_gen[dev]++;
    for (size_t i = 0; i < n; i++) {
        if (!hist_ts_wall(recs[i].ts_s))
            continue;
        const uint32_t day = recs[i].ts_s / 86400u;
        day_slot_t *slot = &s_days[dev][day % HIST_DAY_SLOTS];
        if (slot->day != day)
            continue;
        if (!ok) {
            heap_caps_free(slot->p);
            slot->p = NULL;
            slot->day = HIST_DAY_NONE;
            continue;
        }
        if (!slot->p) {
            /* the day had no file when cached: the append created it with these records */
            slot->p = heap_caps_malloc(sizeof(*slot->p), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!slot->p) {
                slot->day = HIST_DAY_NONE; /* rebuilt from the file by the next query */
                continue;
            }
            hist_day_reset(slot->p, day);
        }
        hist_day_add(slot->p, &recs[i]);
    }
    h_unlock(NULL);
}

/* Boot warm-up (persist job, one day per run, re-queued until done): build the rollups of the days
 * older than the boot reload so the first long query after a reboot does not read them either. */
static void history_warm_job(void *arg) {
    (void)arg;
    if (!s_ready || s_frozen || !gw_time_valid())
        return;
    const uint32_t today = (uint32_t)(gw_time_wall_ms() / 1000 / 86400);
    const uint32_t first_back = HIST_RELOAD_HOURS / 24u; /* newer days are in the slow ring */
    if (s_warm_back < first_back)
        s_warm_back = first_back;
    if (s_warm_back > HIST_RETENTION_DAYS) {
        s_warm_back = first_back;
        if (++s_warm_dev >= GW_MAX_DEVICES)
            return; /* done */
    }
    (void)day_ensure((uint8_t)s_warm_dev, today - s_warm_back);
    s_warm_back++;
    store_wdt_feed();
    (void)persist_submit(history_warm_job, NULL, 0); /* queue full: the rest is built on demand */
}

static const hist_env_t s_env = {
    .lock = h_lock,
    .unlock = h_unlock,
    .lock_arg = NULL,
    .files = h_files,
    .files_arg = (void *)FS_DIR_HIST,
    .coarse = h_coarse,
    .coarse_arg = NULL,
};

/* ---- persist writer ---- */

static void history_writer(void *arg) {
    (void)arg;
    if (!s_ready || s_frozen)
        return;
    for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++) {
        h_lock(NULL);
        size_t n = hist_dev_take_pending(s_dev[dev], s_wbuf, HIST_PEND_MAX);
        h_unlock(NULL);
        if (!n)
            continue;
        days_append_begin((uint8_t)dev);
        esp_err_t err = hist_files_append(FS_DIR_HIST, (uint8_t)dev, s_wbuf, n);
        days_note_append((uint8_t)dev, s_wbuf, n, err == ESP_OK);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "d%u: append of %u records failed: %s", dev, (unsigned)n, esp_err_to_name(err));
            h_lock(NULL);
            hist_dev_unget_pending(s_dev[dev], s_wbuf, n);
            h_unlock(NULL);
        }
        store_wdt_feed();
    }
    if (gw_time_valid()) {
        int64_t now_s = gw_time_wall_ms() / 1000;
        uint32_t day = (uint32_t)(now_s / 86400);
        if (day != s_retention_day) {
            int removed = 0, failed = 0;
            for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++) {
                int f = 0;
                removed += hist_files_retention(FS_DIR_HIST, (uint8_t)dev, (uint32_t)now_s, &f);
                failed += f;
            }
            /* A file open in a query cannot be unlinked (EBUSY): keep the day pending so the next
             * writer run (every HIST_FLUSH_BATCH minutes) tries again. */
            if (failed == 0)
                s_retention_day = day;
            if (removed || failed)
                ESP_LOGI(TAG, "retention: %d daily files deleted, %d to retry", removed, failed);
        }
    }
}

/* ---- init / sample ---- */

esp_err_t history_init(void) {
    if (s_ready)
        return ESP_OK;
    s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx)
        return ESP_ERR_NO_MEM;
    for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++)
        for (unsigned i = 0; i < HIST_DAY_SLOTS; i++)
            s_days[dev][i].day = HIST_DAY_NONE;
    for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++) {
        hist_dev_t *d = psram_calloc(1, sizeof(*d));
        void *fast = psram_calloc(HIST_FAST_LEN, sizeof(hist_fast_t));
        void *slow = psram_calloc(HIST_SLOW_LEN, sizeof(hist_slow_t));
        if (!d || !fast || !slow) {
            heap_caps_free(d);
            heap_caps_free(fast);
            heap_caps_free(slow);
            ESP_LOGE(TAG, "ring allocation failed for d%u", dev);
            return ESP_ERR_NO_MEM;
        }
        hist_dev_init(d, fast, slow);
        s_dev[dev] = d;
    }
    if (gw_time_valid()) {
        uint32_t now_s = (uint32_t)(gw_time_wall_ms() / 1000);
        uint32_t from = now_s - HIST_RELOAD_HOURS * 3600u;
        for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++) {
            hist_dev_t *d = s_dev[dev];
            hist_dev_reload_begin(d, now_s);
            hist_files_iter((void *)FS_DIR_HIST, (uint8_t)dev, from, now_s, hist_dev_reload_add, d);
            hist_dev_reload_end(d);
            if (gw_ring_count(&d->slow))
                ESP_LOGI(TAG, "d%u: reloaded the last %u h", dev, (unsigned)HIST_RELOAD_HOURS);
        }
    } else {
        ESP_LOGW(TAG, "wall time invalid: history not reloaded");
    }
    esp_err_t err = persist_register(PERSIST_HISTORY, history_writer, NULL);
    if (err != ESP_OK)
        return err;
    s_ready = true;
    return ESP_OK;
}

void history_sample(uint8_t dev, const mex_snapshot_t *s, bool fresh, bool any_alarm, uint32_t ts_s) {
    if (!s_ready || dev >= GW_MAX_DEVICES)
        return;
    hist_fast_t f;
    hist_fast_from_snapshot(s, fresh, any_alarm, ts_s, &f);
    uint64_t mono = gw_time_mono_ms();
    h_lock(NULL);
    bool flush = hist_dev_sample(s_dev[dev], &f, mono);
    h_unlock(NULL);
    if (flush)
        persist_mark_dirty(PERSIST_HISTORY);
    if (!s_warm_queued && !s_frozen && mono >= HIST_WARM_AFTER_MS && gw_time_valid() &&
        persist_submit(history_warm_job, NULL, 0) == ESP_OK)
        s_warm_queued = true; /* non-blocking; retried on the next tick while the queue is full */
}

void history_flush_request(void) {
    if (s_ready && !s_frozen)
        persist_mark_dirty(PERSIST_HISTORY);
}

static void history_wipe_job(void *arg) {
    (void)arg;
    if (fs_clear_dir(FS_DIR_HIST) != ESP_OK)
        ESP_LOGE(TAG, "history directory wipe incomplete");
}

esp_err_t history_factory_reset(void) {
    if (!s_ready)
        return ESP_ERR_INVALID_STATE;
    h_lock(NULL);
    s_frozen = true;
    for (unsigned dev = 0; dev < GW_MAX_DEVICES; dev++)
        hist_dev_clear(s_dev[dev]);
    days_clear_locked();
    h_unlock(NULL);
    ESP_LOGW(TAG, "factory reset: history dropped, file writes disabled until reboot");
    return persist_submit(history_wipe_job, NULL, 1000);
}

/* ---- queries ---- */

static esp_err_t query_guard(uint8_t dev) {
    if (dev >= GW_MAX_DEVICES)
        return ESP_ERR_INVALID_ARG;
    if (!s_ready)
        return ESP_ERR_INVALID_STATE;
    if (gw_events_in_loop_task() || persist_in_task()) {
        ESP_LOGE(TAG, "history queries are not allowed from gw_evt/persist");
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

static int64_t wall_now(void) {
    return gw_time_valid() ? gw_time_wall_ms() : 0;
}

esp_err_t history_query_span(uint8_t dev, uint32_t span_s, uint32_t res_s, hist_series_t *io) {
    esp_err_t err = query_guard(dev);
    if (err != ESP_OK)
        return err;
    if (!io)
        return ESP_ERR_INVALID_ARG;
    return hist_core_span(s_dev[dev], dev, span_s, res_s, gw_time_mono_ms(), wall_now(), &s_env, io, NULL, NULL);
}

esp_err_t history_query(uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s, hist_series_t *io) {
    esp_err_t err = query_guard(dev);
    if (err != ESP_OK)
        return err;
    if (!io)
        return ESP_ERR_INVALID_ARG;
    int64_t now = wall_now();
    if (now <= 0)
        return ESP_ERR_INVALID_STATE;
    return hist_core_range(s_dev[dev], dev, from_ms, to_ms, res_s, now, &s_env, io, NULL, NULL);
}

esp_err_t history_foreach(uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s, hist_row_cb_t cb,
                          void *arg) {
    esp_err_t err = query_guard(dev);
    if (err != ESP_OK)
        return err;
    if (!cb)
        return ESP_ERR_INVALID_ARG;
    int64_t now = wall_now();
    if (now <= 0)
        return ESP_ERR_INVALID_STATE;
    return hist_core_range(s_dev[dev], dev, from_ms, to_ms, res_s, now, &s_env, NULL, cb, arg);
}

esp_err_t history_foreach_span(uint8_t dev, uint32_t span_s, uint32_t res_s, hist_row_cb_t cb, void *arg) {
    esp_err_t err = query_guard(dev);
    if (err != ESP_OK)
        return err;
    if (!cb)
        return ESP_ERR_INVALID_ARG;
    return hist_core_span(s_dev[dev], dev, span_s, res_s, gw_time_mono_ms(), wall_now(), &s_env, NULL, cb, arg);
}
