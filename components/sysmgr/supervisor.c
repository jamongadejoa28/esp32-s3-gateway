/*
 * Supervisor task (sysmgr.h supervisor_start, init order step 14): health/mark-valid, status LED,
 * BOOT button gestures, RTC write after a time sync, syslog housekeeping. Subscribed to the task
 * watchdog. Inputs arrive through a queue (button events from the esp_timer task, TIME_SYNC from a
 * gw_evt handler) so neither producer ever blocks.
 */
#include <stdatomic.h>
#include <string.h>

#include "alarm/alarm.h"
#include "board/board.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_time.h"
#include "mex150/service.h"
#include "net/net.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"
#include "sysmgr_pure.h"

static const char *TAG = "supervisor";

#define SUP_QUEUE_LEN 16
#define SUP_BEEP_ARMED_MS 80
#define SUP_BEEP_RESET_MS 400

typedef enum { SUP_MSG_BUTTON = 0, SUP_MSG_TIME_SYNC = 1 } sup_msg_kind_t;

typedef struct {
    uint8_t kind;
    uint8_t btn_ev;
    uint8_t time_src;
    uint32_t held_ms;
} sup_msg_t;

/* Init faults that keep a PENDING_VERIFY image from being marked valid: everything except the
 * optional subsystems (SNMP, syslog) and Modbus (retried on CONFIG_CHANGED; a Modbus service that
 * never runs already leaves the required MEX heartbeat stale). */
#define SYS_INIT_FAULT_BLOCKS_VALID                                                                          \
    (SYS_INIT_FAULT_FS | SYS_INIT_FAULT_STORE | SYS_INIT_FAULT_NET | SYS_INIT_FAULT_WEB | SYS_INIT_FAULT_CORE)

static QueueHandle_t s_q;
static bool s_valid_block_logged;
static atomic_bool s_started;
static atomic_uint s_init_faults; /* SYS_INIT_FAULT_* (sysmgr.h), latched until reboot */

void sys_init_fault_set(uint32_t bits) {
    atomic_fetch_or(&s_init_faults, bits);
}

void sys_init_fault_clear(uint32_t bits) {
    atomic_fetch_and(&s_init_faults, ~bits);
}

uint32_t sys_init_faults(void) {
    return atomic_load(&s_init_faults);
}

/* supervisor task only */
static bool s_ap_armed, s_reset_armed;
static bool s_marked_valid, s_pending_verify, s_booting = true;
static sys_stale_track_t s_stale;
static uint64_t s_watch_since_ms; /* uptime when a watched heartbeat went stale, 0 = fresh */
static uint32_t s_watch_mask;     /* watched heartbeats shown as stale (LED, EVT_HEALTH) */

/* Consecutive health reboots without a healthy period in between. RTC no-init memory survives
 * esp_restart() (not power loss); the magic word detects garbage after power-on. Bounds a reboot
 * loop caused by a permanently failing component: after SYS_HEALTH_REBOOT_MAX the device stays up
 * with the FAULT LED (SNMP/web stay reachable) until it has been healthy once. */
#define SUP_HB_MAGIC 0x48425242u /* "HBRB" */
static RTC_NOINIT_ATTR uint32_t s_hb_reboot_magic;
static RTC_NOINIT_ATTR uint32_t s_hb_reboot_count;
static bool s_hb_limit_logged;

static uint32_t health_reboots(void) {
    if (s_hb_reboot_magic != SUP_HB_MAGIC) {
        s_hb_reboot_magic = SUP_HB_MAGIC;
        s_hb_reboot_count = 0;
    }
    return s_hb_reboot_count;
}
static cfg_modbus_t s_modbus;
static net_status_t s_net;
static mex_snapshot_t s_snap;

/* ---- producers (other tasks) ---- */

static void on_button(board_btn_event_t ev, uint32_t held_ms, void *arg) {
    (void)arg;
    const sup_msg_t m = {.kind = SUP_MSG_BUTTON, .btn_ev = (uint8_t)ev, .held_ms = held_ms};
    if (s_q && xQueueSend(s_q, &m, 0) != pdTRUE) {
        ESP_LOGW(TAG, "button event %d dropped", ev);
    }
}

static void on_time_sync(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_time_t *e = data;
    if (!e || e->source == GW_TIME_SRC_RTC) {
        return; /* the RTC itself was the source */
    }
    const sup_msg_t m = {.kind = SUP_MSG_TIME_SYNC, .time_src = e->source};
    if (s_q) {
        xQueueSend(s_q, &m, 0);
    }
}

/* ---- consumers (supervisor task) ---- */

static void handle_button(const sup_msg_t *m) {
    switch ((board_btn_event_t)m->btn_ev) {
    case BOARD_BTN_AP_ARMED:
        s_ap_armed = true;
        board_buzzer_beep(SUP_BEEP_ARMED_MS);
        break;
    case BOARD_BTN_AP_DISARMED:
        s_ap_armed = false;
        break;
    case BOARD_BTN_RESET_ARMED:
        s_reset_armed = true;
        board_buzzer_beep(SUP_BEEP_RESET_MS);
        ESP_LOGW(TAG, "BOOT held 10 s: factory reset on release (keep holding to %u s to cancel)",
                 BOARD_BTN_RESET_CANCEL_MS / 1000);
        break;
    case BOARD_BTN_RESET_DISARMED:
        s_reset_armed = false;
        ESP_LOGW(TAG, "factory reset cancelled (button held too long)");
        break;
    case BOARD_BTN_RELEASED_AP: {
        s_ap_armed = false;
        const esp_err_t err = net_ap_start(NET_AP_REASON_BUTTON);
        ESP_LOGI(TAG, "BOOT 3-8 s: recovery AP requested (%s)", esp_err_to_name(err));
        break;
    }
    case BOARD_BTN_RELEASED_RESET: {
        s_reset_armed = false;
        const esp_err_t err = sys_factory_reset(false, "@button");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "factory reset: %s", esp_err_to_name(err));
        }
        break;
    }
    case BOARD_BTN_RELEASED_SHORT:
    case BOARD_BTN_RELEASED_NONE:
        s_ap_armed = false;
        s_reset_armed = false;
        break;
    default:
        break;
    }
}

static void write_rtc(uint8_t src) {
    if (!board_rtc_present()) {
        return;
    }
    /* Use the clock now (not the event's stamp) so queueing delay does not skew the RTC. */
    const int64_t ms = gw_time_wall_ms();
    if (!ms) {
        return;
    }
    const esp_err_t err = board_rtc_set_utc(ms / 1000);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "RTC updated (source %u)", src);
    } else {
        ESP_LOGW(TAG, "RTC write failed: %s", esp_err_to_name(err));
    }
}

static bool any_enabled_device_offline(void) {
    if (cfg_get_section(CFG_SEC_MODBUS, &s_modbus, sizeof(s_modbus)) != ESP_OK) {
        return false;
    }
    const size_t n = s_modbus.n_devices > GW_MAX_DEVICES ? GW_MAX_DEVICES : s_modbus.n_devices;
    for (size_t i = 0; i < n; i++) {
        if (s_modbus.devices[i].enabled && mex_service_snapshot(s_modbus.devices[i].id, &s_snap) && !s_snap.online) {
            return true;
        }
    }
    return false;
}

/* Optional heartbeats (GW_HB_WATCHED_MASK): FAULT LED + EVT_HEALTH after SYS_WATCHED_STALE_MS, no
 * reboot. A source whose subsystem failed to start is skipped (its init fault shows already). */
#define SYS_WATCHED_STALE_MS 10000u

static void watched_step(uint64_t up_ms, uint32_t all_stale) {
    uint32_t watch = GW_HB_WATCHED_MASK;
    if (sys_init_faults() & SYS_INIT_FAULT_SNMP) {
        watch &= ~(1u << GW_HB_SNMP);
    }
    const uint32_t stale = all_stale & watch;
    if (!stale) {
        s_watch_since_ms = 0;
    } else if (!s_watch_since_ms) {
        s_watch_since_ms = up_ms ? up_ms : 1;
    }
    const uint32_t shown = (stale && up_ms - s_watch_since_ms >= SYS_WATCHED_STALE_MS) ? stale : 0;
    if (shown != s_watch_mask) {
        s_watch_mask = shown;
        if (shown) {
            ESP_LOGE(TAG, "optional service heartbeat stale: mask 0x%02x", (unsigned)shown);
        } else {
            ESP_LOGI(TAG, "optional service heartbeats fresh");
        }
        evlog_event(EVT_HEALTH, EVLOG_DEV_NONE, (uint16_t)(shown | (s_stale.stale ? s_stale.mask : 0)), 0, 0,
                    NULL, 0);
    }
}

static void health_step(uint64_t up_ms) {
    const uint32_t all_stale = gw_hb_stale_mask(GW_HB_MAX_AGE_MS);
    const uint32_t stale = all_stale & GW_HB_REQUIRED_MASK;
    if (!s_booting) {
        watched_step(up_ms, all_stale);
    }
    if (s_booting && (stale == 0 || up_ms >= SYS_BOOT_GRACE_MS)) {
        s_booting = false;
    }
    if (!s_booting && sys_stale_update(&s_stale, stale, up_ms)) {
        if (stale) {
            ESP_LOGW(TAG, "stale heartbeats: mask 0x%02x", (unsigned)stale);
        } else {
            ESP_LOGI(TAG, "all heartbeats fresh");
        }
        evlog_event(EVT_HEALTH, EVLOG_DEV_NONE, (uint16_t)stale, 0, 0, NULL, 0);
    }

    /* A PENDING_VERIFY image is committed only if init had no fault outside the optional
     * subsystems: e.g. auth_init failing keeps httpd (and its heartbeat) alive but nobody could log
     * in to call the rollback API. Such an image stays unconfirmed and the limit below reboots it
     * into the previous one. A valid image only needs fresh heartbeats (as before). */
    const uint32_t blocking = sys_init_faults() & SYS_INIT_FAULT_BLOCKS_VALID;
    if (s_pending_verify && !s_marked_valid && blocking && !s_valid_block_logged && up_ms >= SYS_VALID_AFTER_MS) {
        s_valid_block_logged = true;
        ESP_LOGE(TAG, "new image has init faults 0x%02x: not marking it valid", (unsigned)blocking);
    }
    if (!s_marked_valid && up_ms >= SYS_VALID_AFTER_MS && stale == 0 && (!s_pending_verify || blocking == 0)) {
        s_marked_valid = true;
        if (health_reboots()) {
            s_hb_reboot_count = 0; /* healthy period: re-arm the bounded health reboot */
        }
        if (s_pending_verify) {
            const esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "running image marked valid (rollback cancelled)");
                gw_evt_ota_t ev = {.phase = GW_OTA_VALIDATED};
                gw_strlcpy(ev.version, esp_app_get_description()->version, sizeof(ev.version));
                gw_events_post(GW_EVT_OTA, &ev, sizeof(ev), 50);
            } else {
                ESP_LOGE(TAG, "mark valid failed: %s", esp_err_to_name(err));
                s_marked_valid = false;
            }
        }
    }
    if (s_pending_verify && !s_marked_valid && up_ms >= SYS_PENDING_VERIFY_LIMIT_MS && !sys_reboot_pending()) {
        ESP_LOGE(TAG, "new image never became healthy (mask 0x%02x, init faults 0x%02x): rebooting into the "
                      "previous image",
                 (unsigned)stale, (unsigned)blocking);
        evlog_event(EVT_HEALTH, EVLOG_DEV_NONE, (uint16_t)stale, 0, 1, NULL, 0);
        sys_reboot(GW_REBOOT_HEALTH, 0, NULL);
    }
    /* Valid (non-PENDING_VERIFY) image: armed as soon as the boot grace is over, even if the image
     * never had a fully fresh sample in this boot (a required task that hangs early, or one that
     * never started). A PENDING_VERIFY image is governed by the limit above until marked valid. */
    const bool armed = !s_booting && (!s_pending_verify || s_marked_valid);
    if (sys_reboot_pending()) {
        return;
    }
    const uint32_t prior = health_reboots();
    if (sys_health_reboot_due(&s_stale, armed, up_ms, SYS_HEALTH_REBOOT_MS, prior, SYS_HEALTH_REBOOT_MAX)) {
        ESP_LOGE(TAG, "heartbeat mask 0x%02x stale for %u s: rebooting (%u/%u)", (unsigned)s_stale.mask,
                 SYS_HEALTH_REBOOT_MS / 1000, (unsigned)(prior + 1), (unsigned)SYS_HEALTH_REBOOT_MAX);
        evlog_event(EVT_HEALTH, EVLOG_DEV_NONE, (uint16_t)s_stale.mask, 0, 1, NULL, 0);
        s_hb_reboot_count = prior + 1;
        if (sys_reboot(GW_REBOOT_HEALTH, 0, NULL) != ESP_OK) {
            s_hb_reboot_count = prior;
        }
    } else if (armed && s_stale.stale && prior >= SYS_HEALTH_REBOOT_MAX && !s_hb_limit_logged &&
               up_ms - s_stale.since_ms >= SYS_HEALTH_REBOOT_MS) {
        s_hb_limit_logged = true;
        ESP_LOGE(TAG, "heartbeat mask 0x%02x stale, but %u health reboots in a row already: staying up",
                 (unsigned)s_stale.mask, (unsigned)prior);
    }
}

static void led_step(void) {
    sys_led_inputs_t in = {0};
    in.reset_armed = s_reset_armed || sys_factory_reset_pending();
    in.ap_armed = s_ap_armed;
    const bool init_fault = atomic_load(&s_init_faults) != 0;
    in.booting = s_booting && !init_fault; /* an init failure shows FAULT at once */
    in.ota = sys_ota_in_progress();
    in.fault = init_fault || (!s_booting && (s_stale.stale || s_watch_mask != 0));
    uint16_t per_sev[4] = {0};
    alarm_counts(per_sev);
    in.critical = per_sev[ALM_SEV_CRITICAL];
    in.alarms = (uint16_t)(per_sev[ALM_SEV_MAJOR] + per_sev[ALM_SEV_MINOR]);
    in.comm_lost = any_enabled_device_offline();
    net_get_status(&s_net);
    in.ap_active = s_net.ap_active;
    in.net_ok = s_net.eth_has_ip;
    board_led_set((board_led_t)sys_led_select(&in));
}

static void supervisor_task(void *arg) {
    (void)arg;
    const esp_err_t wdt = esp_task_wdt_add(NULL);
    if (wdt != ESP_OK) {
        ESP_LOGW(TAG, "task watchdog subscription failed: %s", esp_err_to_name(wdt));
    }
    uint64_t last_slow = 0;
    for (;;) {
        sup_msg_t m;
        while (xQueueReceive(s_q, &m, pdMS_TO_TICKS(SYS_SUPERVISOR_PERIOD_MS)) == pdTRUE) {
            if (m.kind == SUP_MSG_BUTTON) {
                handle_button(&m);
            } else if (m.kind == SUP_MSG_TIME_SYNC) {
                write_rtc(m.time_src);
            }
            if (wdt == ESP_OK) {
                esp_task_wdt_reset();
            }
            /* Keep the LED responsive to gestures even under a burst of messages. */
            if (uxQueueMessagesWaiting(s_q) == 0) {
                break;
            }
        }
        const uint64_t up = gw_time_mono_ms();
        if (up - last_slow >= 1000) {
            last_slow = up;
            health_step(up);
            syslog_service();
        }
        led_step();
        if (wdt == ESP_OK) {
            esp_task_wdt_reset();
        }
    }
}

esp_err_t supervisor_start(void) {
    if (atomic_exchange(&s_started, true)) {
        return ESP_ERR_INVALID_STATE;
    }
    s_q = xQueueCreate(SUP_QUEUE_LEN, sizeof(sup_msg_t));
    if (!s_q) {
        atomic_store(&s_started, false);
        return ESP_ERR_NO_MEM;
    }
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    s_pending_verify = run && esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY;

    /* Boot record (DECISIONS.md F: appended here, not by app_main). */
    evlog_event(EVT_BOOT, EVLOG_DEV_NONE, (uint16_t)esp_reset_reason(), 0, 0, NULL, sys_boot_count());
    if (s_pending_verify) {
        gw_evt_ota_t ev = {.phase = GW_OTA_PENDING};
        gw_strlcpy(ev.version, esp_app_get_description()->version, sizeof(ev.version));
        gw_events_post(GW_EVT_OTA, &ev, sizeof(ev), 50);
        ESP_LOGW(TAG, "image %s is PENDING_VERIFY: marked valid after %u s healthy", ev.version,
                 SYS_VALID_AFTER_MS / 1000);
    }

    esp_err_t err = gw_events_register(GW_EVT_TIME_SYNC, on_time_sync, NULL, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TIME_SYNC handler: %s (RTC will not follow NTP/browser time)", esp_err_to_name(err));
    }
    if (xTaskCreatePinnedToCore(supervisor_task, SYS_SUPERVISOR_TASK_NAME, SYS_SUPERVISOR_STACK, NULL,
                                SYS_SUPERVISOR_TASK_PRIO, NULL, SYS_SUPERVISOR_CORE) != pdPASS) {
        ESP_LOGE(TAG, "supervisor task not created");
        return ESP_ERR_NO_MEM;
    }
    board_button_set_cb(on_button, NULL);
    return ESP_OK;
}
