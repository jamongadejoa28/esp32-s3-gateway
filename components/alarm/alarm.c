/*
 * alarm.c - the alarm service (device): engine instance behind a mutex, gw_evt handlers for
 * SNAPSHOT / COMM / SYS_TICK / CONFIG_CHANGED, event-log + GW_EVT_ALARM emission, the 1 Hz rule
 * evaluation and history sampler, and the query/ack API. Contract: alarm/alarm.h ("Service").
 *
 * Lock order: the engine mutex is a leaf; while it is held only evlog_append() (spinlock) and
 * gw_events_post(..., 0) are called (ARCHITECTURE.md §5 rule 7). Snapshots are fetched and
 * history_sample() is called outside the mutex.
 */
#include <string.h>

#include "alarm/alarm.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "mex150/model.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/history.h"

static const char *TAG = "alarm";

static EXT_RAM_BSS_ATTR alm_engine_t s_eng; /* PSRAM: task-only data (ARCHITECTURE §6.1) */
static SemaphoreHandle_t s_mtx;
static bool s_ready;
static uint32_t s_post_drops;
/* gw_evt task only (handlers): MODBUS poll period and the last snapshot seq fed per device */
static uint32_t s_poll_ms = 1000;
static uint32_t s_fed_seq[GW_MAX_DEVICES];
static bool s_fed_valid[GW_MAX_DEVICES];

static void eng_lock(void) {
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void eng_unlock(void) {
    xSemaphoreGive(s_mtx);
}

static int64_t wall_now(void) {
    return gw_time_valid() ? gw_time_wall_ms() : 0;
}

/* Engine callback (engine mutex held): log first so the event carries the log seq, then post. */
static void on_transition(void *arg, const alm_transition_t *t) {
    (void)arg;
    uint8_t type = t->type == ALM_EV_RAISE ? EVT_ALARM_RAISE : t->type == ALM_EV_CLEAR ? EVT_ALARM_CLEAR
                                                                                      : EVT_ALARM_ACK;
    uint16_t code = alm_catalog[t->id].code;
    const char *user = t->type == ALM_EV_ACK ? t->user : NULL;
    uint32_t seq = evlog_event((evlog_type_t)type, t->dev, code, (uint8_t)t->sev, t->value, user, 0);
    gw_evt_alarm_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.dev = t->dev;
    ev.type = (uint8_t)t->type; /* alm_ev_type_t == gw_alarm_type_t */
    ev.sev = (uint8_t)t->sev;
    ev.code = code;
    ev.value = t->value;
    ev.seq = seq;
    ev.ts_ms = t->ts_ms;
    if (user)
        gw_strlcpy(ev.user, user, sizeof(ev.user));
    if (gw_events_post(GW_EVT_ALARM, &ev, sizeof(ev), 0) != ESP_OK)
        s_post_drops++;
    ESP_LOGI(TAG, "d%u %s %s (sev %u, value %d)", (unsigned)t->dev, alm_catalog[t->id].id,
             t->type == ALM_EV_RAISE ? "raised" : t->type == ALM_EV_CLEAR ? "cleared" : "acked", (unsigned)t->sev,
             (int)t->value);
}

/* Configured and enabled devices (cfg_modbus_t) -> engine enable flags. Engine mutex held. */
static void apply_modbus_locked(const cfg_modbus_t *m, int64_t wall) {
    s_poll_ms = m->port.poll_ms;
    for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++) {
        bool en = false;
        for (unsigned i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++)
            if (m->devices[i].id == dev)
                en = m->devices[i].enabled;
        alm_engine_set_enabled(&s_eng, dev, en, wall);
    }
}

static void on_snapshot(const gw_evt_snapshot_t *sn) {
    if (sn->dev >= GW_MAX_DEVICES)
        return;
    mex_snapshot_t snap;
    if (!mex_service_snapshot(sn->dev, &snap))
        return;
    /* Two queued SNAPSHOT events would both read the newest snapshot: feed each poll only once so
     * one poll never counts twice toward debounce_raise / debounce_clear. */
    if (s_fed_valid[sn->dev] && snap.seq == s_fed_seq[sn->dev])
        return;
    s_fed_seq[sn->dev] = snap.seq;
    s_fed_valid[sn->dev] = true;
    int64_t wall = wall_now();
    eng_lock();
    alm_engine_feed_snapshot(&s_eng, sn->dev, &snap, wall);
    eng_unlock();
}

static void on_comm(const gw_evt_comm_t *c) {
    if (c->dev >= GW_MAX_DEVICES)
        return;
    int64_t wall = c->ts_ms ? c->ts_ms : wall_now();
    eng_lock();
    alm_engine_feed_comm(&s_eng, c->dev, c->online, wall);
    eng_unlock();
}

static void on_tick(const gw_evt_tick_t *t) {
    int64_t wall = t->time_valid ? t->wall_ms : 0;
    uint32_t ts_s = t->time_valid ? (uint32_t)(t->wall_ms / 1000) : (t->uptime_s | 0x80000000u);
    for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++) {
        mex_snapshot_t snap;
        bool ok = mex_service_snapshot(dev, &snap);
        /* Judge freshness when the snapshot is read, not when the tick was posted: mex_poll may
         * publish in between (snap.mono_ms > t->mono_ms), which is the freshest data there is. */
        uint64_t now = gw_time_mono_ms();
        bool fresh = ok && alm_sample_fresh(&snap, now, s_poll_ms);
        eng_lock();
        alm_engine_tick_rules(&s_eng, dev, ok ? &snap : NULL, fresh, now, wall);
        uint32_t mask = alm_engine_mask(&s_eng, dev);
        eng_unlock();
        history_sample(dev, ok ? &snap : NULL, fresh, mask != 0, ts_s);
    }
}

static void on_config(const gw_evt_config_t *c) {
    int64_t wall = wall_now();
    if (c->section == CFG_SEC_ALARMS) {
        cfg_alarms_t a;
        if (cfg_get_section(CFG_SEC_ALARMS, &a, sizeof(a)) != ESP_OK)
            return;
        alm_params_t p;
        alm_params_from_config(&a, &p);
        eng_lock();
        alm_engine_set_params(&s_eng, &p, wall);
        eng_unlock();
    } else if (c->section == CFG_SEC_MODBUS) {
        cfg_modbus_t m;
        if (cfg_get_section(CFG_SEC_MODBUS, &m, sizeof(m)) != ESP_OK)
            return;
        eng_lock();
        apply_modbus_locked(&m, wall);
        eng_unlock();
    }
}

static void alarm_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    if (!data)
        return;
    switch (id) {
    case GW_EVT_SNAPSHOT:
        on_snapshot(data);
        break;
    case GW_EVT_COMM:
        on_comm(data);
        break;
    case GW_EVT_SYS_TICK:
        on_tick(data);
        break;
    case GW_EVT_CONFIG_CHANGED:
        on_config(data);
        break;
    default:
        break;
    }
}

esp_err_t alarm_init(void) {
    if (s_ready)
        return ESP_OK;
    s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx)
        return ESP_ERR_NO_MEM;
    cfg_alarms_t a;
    cfg_modbus_t m;
    esp_err_t err = cfg_get_section(CFG_SEC_ALARMS, &a, sizeof(a));
    if (err == ESP_OK)
        err = cfg_get_section(CFG_SEC_MODBUS, &m, sizeof(m));
    if (err != ESP_OK)
        return err;
    alm_params_t p;
    alm_params_from_config(&a, &p);
    eng_lock();
    alm_engine_init(&s_eng, &p, on_transition, NULL);
    apply_modbus_locked(&m, wall_now());
    eng_unlock();
    s_ready = true;
    static const int32_t ids[] = {GW_EVT_SNAPSHOT, GW_EVT_COMM, GW_EVT_SYS_TICK, GW_EVT_CONFIG_CHANGED};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        err = gw_events_register(ids[i], alarm_handler, NULL, NULL);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "handler %d not registered: %s", (int)ids[i], esp_err_to_name(err));
            return err;
        }
    }
    ESP_LOGI(TAG, "engine ready (%u catalog entries, %u rules)", (unsigned)ALM_COUNT, (unsigned)p.n_rules);
    return ESP_OK;
}

size_t alarm_get_active(alm_active_t *out, size_t cap) {
    if (!s_ready)
        return 0;
    eng_lock();
    size_t n = alm_engine_active(&s_eng, out, cap);
    eng_unlock();
    return n;
}

esp_err_t alarm_ack(uint8_t dev, alm_id_t id, const char *user) {
    if (!s_ready)
        return ESP_ERR_INVALID_STATE;
    if (dev >= GW_MAX_DEVICES || (unsigned)id >= ALM_COUNT)
        return ESP_ERR_NOT_FOUND;
    eng_lock();
    int rc = alm_engine_ack(&s_eng, dev, id, user, wall_now());
    eng_unlock();
    if (rc < 0)
        return ESP_ERR_NOT_FOUND;
    evlog_audit(AUD_ALARM_ACK, dev, alm_catalog[id].code, 0, user, 0);
    return ESP_OK;
}

size_t alarm_ack_all(const char *user) {
    if (!s_ready)
        return 0;
    eng_lock();
    size_t n = alm_engine_ack_all(&s_eng, user, wall_now());
    eng_unlock();
    evlog_audit(AUD_ALARM_ACK, EVLOG_DEV_NONE, 0, (int16_t)(n > INT16_MAX ? INT16_MAX : n), user, 0);
    return n;
}

uint32_t alarm_counts(uint16_t per_sev[4]) {
    if (per_sev)
        memset(per_sev, 0, 4 * sizeof(per_sev[0]));
    if (!s_ready)
        return 0;
    uint32_t total = 0;
    eng_lock();
    for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++) {
        for (unsigned id = 0; id < ALM_COUNT; id++) {
            if (!s_eng.slot[dev][id].active)
                continue;
            total++;
            uint8_t sev = s_eng.p.sev[id];
            if (per_sev && sev < 4)
                per_sev[sev]++;
        }
    }
    eng_unlock();
    return total;
}

uint32_t alarm_mask(uint8_t dev) {
    if (!s_ready || dev >= GW_MAX_DEVICES)
        return 0;
    eng_lock();
    uint32_t m = alm_engine_mask(&s_eng, dev);
    eng_unlock();
    return m;
}
