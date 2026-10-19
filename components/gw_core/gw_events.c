/*
 * gw_events.c - the "gw_evt" esp_event loop, its task and the 1 Hz GW_EVT_SYS_TICK timer.
 * Contract: gw_core/gw_events.h. Device only (FreeRTOS, esp_event, esp_timer).
 *
 * The loop is created WITH its esp_event-owned task (name/prio/core/stack from gw_events.h). That
 * matters: for a loop without a dedicated task, esp_event_post_to() first takes the loop's
 * recursive mutex with the caller's timeout, and esp_event_loop_run() holds that mutex while the
 * handlers run, so every timeout-0 post would fail while any handler is busy. With a dedicated
 * task posting is a plain xQueueSendToBack (ARCHITECTURE §5 rule 7). CONFIG_ESP_EVENT_LOOP_IN_EXT_RAM
 * is off, so esp_event uses xTaskCreatePinnedToCore and the stack is internal RAM. The task handle
 * (needed by gw_events_in_loop_task()) is looked up by name right after creation.
 */
#include "gw_core/gw_events.h"

#include <stdatomic.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_time.h"

static const char *TAG = "gw_evt";

ESP_EVENT_DEFINE_BASE(GW_EVENT);

#define GW_EVT_TICK_PERIOD_US 1000000ULL

static esp_event_loop_handle_t s_loop;
static TaskHandle_t volatile s_task; /* written once at init (or by the gw_evt task itself) */
static esp_timer_handle_t s_tick_timer;
static atomic_bool s_ready;
static atomic_uint_fast32_t s_dropped;
static atomic_uint_fast32_t s_uptime_s;
static portMUX_TYPE s_init_mux = portMUX_INITIALIZER_UNLOCKED;
static bool s_init_started;

/* Exact payload size per event id (gw_events.h payload table). */
static const uint8_t s_payload_size[GW_EVT_ID_COUNT] = {
    [GW_EVT_SNAPSHOT] = sizeof(gw_evt_snapshot_t),     [GW_EVT_COMM] = sizeof(gw_evt_comm_t),
    [GW_EVT_ALARM] = sizeof(gw_evt_alarm_t),           [GW_EVT_WRITE_RESULT] = sizeof(gw_evt_write_t),
    [GW_EVT_CONFIG_CHANGED] = sizeof(gw_evt_config_t), [GW_EVT_NET_STATE] = sizeof(gw_evt_net_t),
    [GW_EVT_TIME_SYNC] = sizeof(gw_evt_time_t),        [GW_EVT_OTA] = sizeof(gw_evt_ota_t),
    [GW_EVT_SESSION] = sizeof(gw_evt_session_t),       [GW_EVT_SYS_TICK] = sizeof(gw_evt_tick_t),
    [GW_EVT_REBOOT] = sizeof(gw_evt_reboot_t),
};

/* esp_timer task context: build and post the tick without blocking. */
static void tick_timer_cb(void *arg) {
    (void)arg;
    gw_evt_tick_t t = {0};
    t.uptime_s = (uint32_t)atomic_fetch_add(&s_uptime_s, 1) + 1u;
    t.mono_ms = gw_time_mono_ms();
    t.time_valid = gw_time_valid();
    t.wall_ms = t.time_valid ? gw_time_wall_ms() : 0;
    (void)gw_events_post(GW_EVT_SYS_TICK, &t, sizeof(t), 0);
}

/* First SYS_TICK handler: proves the loop dispatches (GW_HB_EVT). */
static void tick_beat_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    (void)data;
    if (s_task == NULL) /* defensive: xTaskGetHandle() failed at init */
        s_task = xTaskGetCurrentTaskHandle();
    gw_hb_beat(GW_HB_EVT);
}

esp_err_t gw_events_init(void) {
    portENTER_CRITICAL(&s_init_mux);
    bool already = s_init_started;
    s_init_started = true;
    portEXIT_CRITICAL(&s_init_mux);
    if (already)
        return atomic_load(&s_ready) ? ESP_OK : ESP_ERR_INVALID_STATE;

    esp_err_t err;
    esp_event_loop_args_t args = {
        .queue_size = GW_EVT_QUEUE_LEN,
        .task_name = GW_EVT_TASK_NAME,
        .task_priority = GW_EVT_TASK_PRIO,
        .task_stack_size = GW_EVT_TASK_STACK,
        .task_core_id = GW_EVT_TASK_CORE,
    };
    err = esp_event_loop_create(&args, &s_loop);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "loop create failed: %s", esp_err_to_name(err));
        goto fail;
    }
    /* esp_event keeps the task handle private; the name is unique in this firmware. */
    s_task = xTaskGetHandle(GW_EVT_TASK_NAME);
    if (s_task == NULL)
        ESP_LOGW(TAG, "task handle lookup failed; resolved on first tick");
    err = esp_event_handler_instance_register_with(s_loop, GW_EVENT, GW_EVT_SYS_TICK, tick_beat_handler, NULL,
                                                   NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tick handler register failed: %s", esp_err_to_name(err));
        goto fail_loop;
    }
    atomic_store(&s_ready, true);

    const esp_timer_create_args_t targs = {
        .callback = tick_timer_cb,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "gw_tick",
        .skip_unhandled_events = true,
    };
    err = esp_timer_create(&targs, &s_tick_timer);
    if (err == ESP_OK)
        err = esp_timer_start_periodic(s_tick_timer, GW_EVT_TICK_PERIOD_US);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tick timer failed: %s", esp_err_to_name(err));
        atomic_store(&s_ready, false);
        if (s_tick_timer) {
            esp_timer_delete(s_tick_timer);
            s_tick_timer = NULL;
        }
        goto fail_loop;
    }
    ESP_LOGI(TAG, "event loop running (prio %d, core %d, queue %d)", GW_EVT_TASK_PRIO, GW_EVT_TASK_CORE,
             GW_EVT_QUEUE_LEN);
    return ESP_OK;

fail_loop:
    esp_event_loop_delete(s_loop); /* also deletes the loop's task */
    s_loop = NULL;
    s_task = NULL;
fail:
    portENTER_CRITICAL(&s_init_mux);
    s_init_started = false;
    portEXIT_CRITICAL(&s_init_mux);
    return err;
}

esp_err_t gw_events_post(gw_event_id_t id, const void *data, size_t len, uint32_t timeout_ms) {
    if ((unsigned)id >= GW_EVT_ID_COUNT || len > GW_EVT_PAYLOAD_MAX || len != s_payload_size[id] ||
        (len && !data))
        return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&s_ready))
        return ESP_ERR_INVALID_STATE;
    if (timeout_ms && gw_events_in_loop_task()) {
        ESP_LOGW(TAG, "post(%d) with timeout from gw_evt: forced to 0", (int)id);
        timeout_ms = 0;
    }
    TickType_t ticks = timeout_ms ? pdMS_TO_TICKS(timeout_ms) : 0;
    if (timeout_ms && ticks == 0)
        ticks = 1;
    esp_err_t err = esp_event_post_to(s_loop, GW_EVENT, (int32_t)id, data, len, ticks);
    if (err == ESP_ERR_TIMEOUT) {
        uint32_t n = (uint32_t)atomic_fetch_add(&s_dropped, 1) + 1u;
        /* Rate-limit the log: first drop and every 64th. */
        if (n == 1 || (n & 63u) == 0)
            ESP_LOGW(TAG, "queue full: event %d dropped (%u total)", (int)id, (unsigned)n);
    }
    return err;
}

esp_err_t gw_events_register(int32_t id, esp_event_handler_t handler, void *arg,
                             esp_event_handler_instance_t *instance) {
    if (!handler || (id != ESP_EVENT_ANY_ID && (id < 0 || id >= GW_EVT_ID_COUNT)))
        return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&s_ready))
        return ESP_ERR_INVALID_STATE;
    return esp_event_handler_instance_register_with(s_loop, GW_EVENT, id, handler, arg, instance);
}

esp_err_t gw_events_unregister(int32_t id, esp_event_handler_instance_t instance) {
    if (!instance)
        return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&s_ready))
        return ESP_ERR_INVALID_STATE;
    if (gw_events_in_loop_task())
        return ESP_ERR_INVALID_STATE; /* documented: any task except gw_evt */
    return esp_event_handler_instance_unregister_with(s_loop, GW_EVENT, id, instance);
}

uint32_t gw_events_dropped(void) {
    return (uint32_t)atomic_load(&s_dropped);
}

bool gw_events_in_loop_task(void) {
    return s_task != NULL && xTaskGetCurrentTaskHandle() == s_task;
}
