/* Scheduled reboot (sysmgr.h sys_reboot): post GW_EVT_REBOOT (web closes WebSockets with bye
 * "reboot", history flushes), wait delay_ms, flush persist (3 s max), restart. A short-lived task
 * does the waiting because persist_flush() blocks and must not run in the esp_timer task. */
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_events.h"
#include "store/eventlog.h"
#include "store/history.h"
#include "store/persist.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"

static const char *TAG = "reboot";

#define REBOOT_TASK_STACK 3072
#define REBOOT_TASK_PRIO 4 /* above persist (3) is irrelevant: it only waits */
#define REBOOT_FLUSH_MS 3000
#define REBOOT_MAX_DELAY_MS 60000

static atomic_bool s_pending;
static uint32_t s_delay_ms;
static uint8_t s_reason;

bool sys_reboot_pending(void) {
    return atomic_load(&s_pending);
}

static void restart_now(void *arg) {
    (void)arg;
    esp_restart();
}

static void reboot_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(s_delay_ms));
    history_flush_request();
    esp_err_t err = persist_flush(REBOOT_FLUSH_MS);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "persist flush incomplete (%s); restarting anyway", esp_err_to_name(err));
    }
    ESP_LOGW(TAG, "restarting (reason %u)", s_reason);
    esp_restart();
}

esp_err_t sys_reboot(uint8_t reason, uint32_t delay_ms, const char *by) {
    if (atomic_exchange(&s_pending, true)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (delay_ms > REBOOT_MAX_DELAY_MS) {
        delay_ms = REBOOT_MAX_DELAY_MS;
    }
    s_delay_ms = delay_ms;
    s_reason = reason;

    const gw_evt_reboot_t ev = {.reason = reason, .in_ms = delay_ms};
    esp_err_t err = gw_events_post(GW_EVT_REBOOT, &ev, sizeof(ev), gw_events_in_loop_task() ? 0 : 50);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "REBOOT event not posted: %s", esp_err_to_name(err));
    }
    /* User-initiated reboots are audited here (callers do not audit them again). OTA/rollback/
     * factory reset have their own audit records; HEALTH is logged as EVT_HEALTH by the supervisor. */
    if (reason == GW_REBOOT_USER || reason == GW_REBOOT_CONSOLE || reason == GW_REBOOT_CONFIG_IMPORT) {
        evlog_audit(AUD_REBOOT, EVLOG_DEV_NONE, reason, 0, by, 0);
    }
    ESP_LOGW(TAG, "reboot scheduled in %u ms (reason %u, by %s)", (unsigned)delay_ms, reason, by ? by : "-");

    if (xTaskCreatePinnedToCore(reboot_task, "sys_reboot", REBOOT_TASK_STACK, NULL, REBOOT_TASK_PRIO, NULL,
                                tskNO_AFFINITY) == pdPASS) {
        return ESP_OK;
    }
    /* No memory for the task: restart from a timer without flushing (still better than no reboot). */
    ESP_LOGE(TAG, "reboot task not created; restarting without flush");
    static esp_timer_handle_t t;
    const esp_timer_create_args_t args = {.callback = restart_now, .name = "sys_restart"};
    if (!t && esp_timer_create(&args, &t) != ESP_OK) {
        esp_restart();
    }
    if (esp_timer_start_once(t, (uint64_t)(delay_ms ? delay_ms : 1) * 1000) != ESP_OK) {
        esp_restart();
    }
    return ESP_OK;
}
