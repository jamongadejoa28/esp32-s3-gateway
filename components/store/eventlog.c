/*
 * eventlog.c - event and audit logs (device): lock-free-ish RAM tails filled from any task,
 * flushed to the two-file rings by the persist task, merged queries and the gw_evt -> log glue.
 * Contract: store/eventlog.h. File format and queries: evlog_core.c. EVT_BOOT / EVT_HEALTH (sysmgr)
 * and EVT_NET_PROVISIONAL (net) are appended by their owners, not by the glue.
 *
 * evlog_append() holds a spinlock only for a 32-byte copy, so it is safe while the caller holds its
 * own module lock (ARCHITECTURE.md §5 rule 7). File access (persist writer, queries, factory reset)
 * is serialised by a separate mutex that no other lock is ever taken under.
 */
#include "store/eventlog.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "evlog_core.h"
#include "store/fs.h"
#include "store/persist.h"

static const char *TAG = "evlog";

#define EVLOG_WRITE_RETRIES 3

typedef struct {
    evlog_rec_t tail[EVLOG_RAM_TAIL]; /* ring: newest EVLOG_RAM_TAIL records */
    uint32_t head;                    /* next slot */
    uint32_t count;
    uint32_t next_seq;    /* seq of the next append */
    uint32_t flushed_seq; /* highest seq known to be on flash */
    uint32_t lost;        /* records overwritten in RAM before reaching flash */
    unsigned write_failures;
    evlog_files_t files;
} evlog_state_t;

static EXT_RAM_BSS_ATTR evlog_state_t s_log[EVLOG_COUNT]; /* PSRAM: task-only data */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED; /* tails, seqs, flags */
static SemaphoreHandle_t s_fmtx;                          /* files */
static bool s_ready;
static bool s_frozen;
static EXT_RAM_BSS_ATTR evlog_rec_t s_wbuf[EVLOG_RAM_TAIL]; /* persist writer scratch (persist task only) */

static const persist_item_t s_item[EVLOG_COUNT] = {PERSIST_EVENTS, PERSIST_AUDIT};
static _Atomic(evlog_hook_t) s_hook;

void evlog_set_hook(evlog_hook_t fn) {
    atomic_store(&s_hook, fn);
}

/* ---- append ---- */

uint32_t evlog_append(evlog_kind_t kind, const evlog_rec_t *r) {
    if ((unsigned)kind >= EVLOG_COUNT || !r)
        return 0;
    evlog_rec_t rec = *r;
    int64_t wall = gw_time_valid() ? gw_time_wall_ms() : 0;
    rec.ts = wall > 0 ? (uint32_t)(wall / 1000) : 0;
    evlog_state_t *l = &s_log[kind];
    uint32_t seq = 0;
    bool urgent = false;
    portENTER_CRITICAL(&s_mux);
    if (s_ready && !s_frozen) {
        seq = l->next_seq++;
        if (l->next_seq == 0)
            l->next_seq = 1; /* 2^32 records: never in practice; keep 0 reserved */
        rec.seq = seq;
        if (l->count == EVLOG_RAM_TAIL) {
            const evlog_rec_t *old = &l->tail[l->head];
            if (old->seq > l->flushed_seq)
                l->lost++;
        }
        l->tail[l->head] = rec;
        l->head = (l->head + 1) % EVLOG_RAM_TAIL;
        if (l->count < EVLOG_RAM_TAIL)
            l->count++;
        /* The log debounce (PERSIST_DEBOUNCE_LOG_MS) batches appends; a burst that fills half the
         * RAM tail is written at once so nothing is overwritten before it reached flash. */
        urgent = seq - l->flushed_seq >= EVLOG_RAM_TAIL / 2;
    }
    portEXIT_CRITICAL(&s_mux);
    if (seq) {
        if (urgent)
            persist_mark_urgent(s_item[kind]);
        else
            persist_mark_dirty(s_item[kind]);
        const evlog_hook_t hook = atomic_load(&s_hook);
        if (hook)
            hook(kind, &rec);
    }
    return seq;
}

static void fill_user(char dst[12], const char *user) {
    memset(dst, 0, 12);
    if (!user)
        return;
    for (size_t i = 0; i < 12 && user[i]; i++)
        dst[i] = user[i];
}

uint32_t evlog_event(evlog_type_t type, uint16_t dev, uint16_t code, uint8_t sev, int16_t value,
                     const char *user, uint32_t extra) {
    evlog_rec_t r = {.dev = dev, .code = code, .type = (uint8_t)type, .sev = sev, .value = value, .extra = extra};
    fill_user(r.user, user);
    return evlog_append(EVLOG_EVENTS, &r);
}

uint32_t evlog_audit(evlog_type_t type, uint16_t dev, uint16_t code, int16_t value, const char *user,
                     uint32_t extra) {
    evlog_rec_t r = {.dev = dev, .code = code, .type = (uint8_t)type, .sev = 0, .value = value, .extra = extra};
    fill_user(r.user, user);
    return evlog_append(EVLOG_AUDIT, &r);
}

uint32_t evlog_last_seq(evlog_kind_t kind) {
    if ((unsigned)kind >= EVLOG_COUNT)
        return 0;
    portENTER_CRITICAL(&s_mux);
    uint32_t s = s_log[kind].next_seq ? s_log[kind].next_seq - 1 : 0;
    portEXIT_CRITICAL(&s_mux);
    return s;
}

/* Copy the RAM tail in ascending seq order. Caller holds s_mux. */
static size_t tail_copy_locked(const evlog_state_t *l, evlog_rec_t *out, uint32_t min_seq_exclusive) {
    size_t n = 0;
    uint32_t start = (l->head + EVLOG_RAM_TAIL - l->count) % EVLOG_RAM_TAIL;
    for (uint32_t i = 0; i < l->count; i++) {
        const evlog_rec_t *r = &l->tail[(start + i) % EVLOG_RAM_TAIL];
        if (r->seq > min_seq_exclusive)
            out[n++] = *r;
    }
    return n;
}

/* ---- persist writers ---- */

static void evlog_writer(void *arg) {
    evlog_kind_t kind = (evlog_kind_t)(uintptr_t)arg;
    evlog_state_t *l = &s_log[kind];
    portENTER_CRITICAL(&s_mux);
    bool frozen = s_frozen;
    size_t n = frozen ? 0 : tail_copy_locked(l, s_wbuf, l->flushed_seq);
    uint32_t lost = l->lost;
    l->lost = 0;
    portEXIT_CRITICAL(&s_mux);
    if (lost)
        ESP_LOGW(TAG, "%s: %u records dropped before reaching flash", kind == EVLOG_EVENTS ? "events" : "audit",
                 (unsigned)lost);
    if (!n)
        return;
    xSemaphoreTake(s_fmtx, portMAX_DELAY);
    esp_err_t err = evlog_files_append(&l->files, s_wbuf, n);
    xSemaphoreGive(s_fmtx);
    if (err == ESP_OK) {
        portENTER_CRITICAL(&s_mux);
        if (s_wbuf[n - 1].seq > l->flushed_seq)
            l->flushed_seq = s_wbuf[n - 1].seq;
        portEXIT_CRITICAL(&s_mux);
        l->write_failures = 0;
        return;
    }
    ESP_LOGE(TAG, "append failed (%u records)", (unsigned)n);
    if (++l->write_failures < EVLOG_WRITE_RETRIES)
        persist_mark_dirty(s_item[kind]);
}

/* ---- queries ---- */

size_t evlog_query(evlog_kind_t kind, uint32_t before, size_t limit, const evlog_filter_t *f, evlog_rec_t *out,
                   uint32_t *next) {
    if (next)
        *next = 0;
    if ((unsigned)kind >= EVLOG_COUNT || !out || !s_ready)
        return 0;
    if (gw_events_in_loop_task() || persist_in_task()) {
        ESP_LOGE(TAG, "evlog_query from gw_evt/persist is not allowed");
        return 0;
    }
    evlog_rec_t *ram = malloc(sizeof(evlog_rec_t) * EVLOG_RAM_TAIL);
    if (!ram)
        return 0;
    evlog_state_t *l = &s_log[kind];
    xSemaphoreTake(s_fmtx, portMAX_DELAY);
    portENTER_CRITICAL(&s_mux);
    size_t n_ram = s_frozen ? 0 : tail_copy_locked(l, ram, 0);
    portEXIT_CRITICAL(&s_mux);
    size_t n = evlog_core_query(s_frozen ? NULL : &l->files, ram, n_ram, before, limit, f, out, next);
    xSemaphoreGive(s_fmtx);
    free(ram);
    return n;
}

/* ---- factory reset ---- */

static void evlog_wipe_job(void *arg) {
    (void)arg;
    xSemaphoreTake(s_fmtx, portMAX_DELAY);
    for (unsigned k = 0; k < EVLOG_COUNT; k++)
        (void)evlog_files_clear(&s_log[k].files);
    esp_err_t err = fs_clear_dir(FS_DIR_LOG);
    xSemaphoreGive(s_fmtx);
    if (err != ESP_OK)
        ESP_LOGE(TAG, "log directory wipe incomplete");
}

esp_err_t evlog_factory_reset(void) {
    portENTER_CRITICAL(&s_mux);
    s_frozen = true;
    for (unsigned k = 0; k < EVLOG_COUNT; k++) {
        s_log[k].count = 0;
        s_log[k].head = 0;
    }
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGW(TAG, "factory reset: logs dropped, appends disabled until reboot");
    return persist_submit(evlog_wipe_job, NULL, 1000);
}

/* ---- gw_evt glue ---- */

static bool s_comm_lost[GW_MAX_DEVICES];
static struct {
    bool known;
    bool up;
} s_net[2];

static void on_comm(const gw_evt_comm_t *c) {
    if (c->dev >= GW_MAX_DEVICES)
        return;
    if (!c->online) {
        evlog_event(EVT_COMM_LOST, c->dev, 0, 0, c->last_err, NULL, c->offline_count);
        s_comm_lost[c->dev] = true;
    } else if (s_comm_lost[c->dev]) {
        evlog_event(EVT_COMM_RESTORED, c->dev, 0, 0, 0, NULL, 0);
        s_comm_lost[c->dev] = false;
    }
}

static void on_net(const gw_evt_net_t *n) {
    if (n->netif > GW_NETIF_AP)
        return;
    if (n->netif == GW_NETIF_ETH) {
        bool up = n->link_up && n->has_ip;
        /* provisional-state changes are logged by net itself (EVT_NET_PROVISIONAL with the initiator) */
        if (!s_net[0].known || s_net[0].up != up)
            evlog_event(EVT_NET_LINK, EVLOG_DEV_NONE, GW_NETIF_ETH, 0, up ? 1 : 0, NULL, up ? n->ip : 0);
        s_net[0].up = up;
        s_net[0].known = true;
    } else {
        bool up = n->link_up;
        if ((!s_net[1].known && up) || (s_net[1].known && s_net[1].up != up))
            evlog_event(EVT_AP, EVLOG_DEV_NONE, 0, 0, up ? 1 : 0, NULL, up ? n->ip : 0);
        s_net[1].up = up;
        s_net[1].known = true;
    }
}

static void glue_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    if (!data)
        return;
    switch (id) {
    case GW_EVT_COMM:
        on_comm(data);
        break;
    case GW_EVT_WRITE_RESULT: {
        const gw_evt_write_t *w = data;
        evlog_audit(AUD_REG_WRITE, w->dev, w->addr, (int16_t)w->raw_req, w->by,
                    EVLOG_REG_WRITE_EXTRA(w->raw_before, w->state, w->reason));
        break;
    }
    case GW_EVT_CONFIG_CHANGED: {
        const gw_evt_config_t *c = data;
        evlog_audit(AUD_CONFIG_CHANGE, EVLOG_DEV_NONE, c->section, 0, c->by, c->rev);
        break;
    }
    case GW_EVT_NET_STATE:
        on_net(data);
        break;
    case GW_EVT_TIME_SYNC: {
        const gw_evt_time_t *t = data;
        evlog_event(EVT_TIME_SET, EVLOG_DEV_NONE, t->source, 0, 0, t->by, (uint32_t)(int32_t)(t->delta_ms / 1000));
        break;
    }
    case GW_EVT_OTA: {
        const gw_evt_ota_t *o = data;
        evlog_event(EVT_OTA, EVLOG_DEV_NONE, o->phase, 0, 0, o->by, (uint32_t)o->err);
        break;
    }
    case GW_EVT_REBOOT: {
        const gw_evt_reboot_t *r = data;
        evlog_event(EVT_REBOOT, EVLOG_DEV_NONE, r->reason, 0, 0, NULL, r->in_ms);
        break;
    }
    default:
        break;
    }
}

esp_err_t eventlog_init(void) {
    if (s_ready)
        return ESP_OK;
    s_fmtx = xSemaphoreCreateMutex();
    if (!s_fmtx)
        return ESP_ERR_NO_MEM;
    static const char *const names[EVLOG_COUNT] = {"events", "audit"};
    for (unsigned k = 0; k < EVLOG_COUNT; k++) {
        evlog_state_t *l = &s_log[k];
        esp_err_t err = evlog_files_open(&l->files, FS_DIR_LOG, names[k]);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "%s: open failed: %s", names[k], esp_err_to_name(err));
            return err;
        }
        l->flushed_seq = l->files.last_seq;
        l->next_seq = l->files.last_seq + 1;
        if (l->next_seq == 0)
            l->next_seq = 1;
        ESP_LOGI(TAG, "%s: %u + %u records, last seq %u", names[k], (unsigned)l->files.count[0],
                 (unsigned)l->files.count[1], (unsigned)l->files.last_seq);
        esp_err_t reg = persist_register(s_item[k], evlog_writer, (void *)(uintptr_t)k);
        if (reg != ESP_OK)
            return reg;
    }
    portENTER_CRITICAL(&s_mux);
    s_ready = true;
    portEXIT_CRITICAL(&s_mux);

    static const int32_t ids[] = {GW_EVT_COMM,      GW_EVT_WRITE_RESULT, GW_EVT_CONFIG_CHANGED, GW_EVT_NET_STATE,
                                  GW_EVT_TIME_SYNC, GW_EVT_OTA,          GW_EVT_REBOOT};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        esp_err_t err = gw_events_register(ids[i], glue_handler, NULL, NULL);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "event glue %d not registered: %s", (int)ids[i], esp_err_to_name(err));
            return err;
        }
    }
    /* EVT_BOOT is appended by the sysmgr supervisor, EVT_HEALTH too (DECISIONS.md F). */
    return ESP_OK;
}

typedef struct {
    evlog_delete_t filter;
    uint32_t deleted;
} delete_alarm_job_t;
static esp_err_t delete_alarm_work(void *arg) {
    delete_alarm_job_t *job = arg;
    evlog_state_t *l = &s_log[EVLOG_EVENTS];
    xSemaphoreTake(s_fmtx, portMAX_DELAY);
    esp_err_t err = evlog_files_delete_alarms(&l->files, &job->filter, &job->deleted);
    /* Even a partial filesystem failure must not resurrect removed records from the RAM tail. */
    if (err == ESP_OK) {
        portENTER_CRITICAL(&s_mux);
        uint32_t n = 0;
        const uint32_t first = (l->head + EVLOG_RAM_TAIL - l->count) % EVLOG_RAM_TAIL;
        for (uint32_t i = 0; i < l->count; i++) {
            evlog_rec_t r = l->tail[(first + i) % EVLOG_RAM_TAIL];
            if (evlog_delete_match(&job->filter, &r)) {
                if (r.seq > l->flushed_seq)
                    job->deleted++;
            } else
                l->tail[(first + n++) % EVLOG_RAM_TAIL] = r;
        }
        l->count = n;
        l->head = (first + n) % EVLOG_RAM_TAIL;
        portEXIT_CRITICAL(&s_mux);
    }
    xSemaphoreGive(s_fmtx);
    return err;
}
esp_err_t evlog_delete_alarms(const evlog_delete_t *filter, uint32_t *deleted) {
    if (!s_ready || s_frozen || !filter || !deleted || gw_events_in_loop_task() || persist_in_task())
        return ESP_ERR_INVALID_STATE;
    delete_alarm_job_t job = {.filter = *filter};
    job.filter.through_seq = evlog_last_seq(EVLOG_EVENTS);
    esp_err_t err = persist_run(delete_alarm_work, &job, sizeof(job), 12000);
    *deleted = job.deleted;
    return err;
}
