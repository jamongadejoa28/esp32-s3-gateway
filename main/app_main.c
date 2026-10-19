/*
 * MESTIO gateway entry point: init order and the glue no component owns (docs/ARCHITECTURE.md §3,
 * §8). Every subsystem registers its own gw_evt handlers; main only adds
 *   - the NVS boot counter (= SNMP engine boots, gw_defs.h GW_NVS_NS_BOOTS),
 *   - the alarm catalog hooks for store before config_load(),
 *   - CONFIG_CHANGED{MODBUS} -> mex_service_reconfigure() (or a retried mex_service_start()),
 *   - failure policy: only a missing event loop is fatal (restart). Everything else is logged,
 *     latched with sys_init_fault_set() (FAULT LED, GET /system/info diag.init_faults) and the
 *     gateway keeps running with whatever works. A failed LittleFS mount runs on RAM defaults.
 *     A subsystem that never beats its heartbeat is handled by the supervisor (health reboot,
 *     bounded, or OTA rollback for a PENDING_VERIFY image).
 * app_main returns when init is done (its task is deleted; every service runs in its own task).
 */
#include <inttypes.h>
#include <stdatomic.h>
#include <string.h>

#include "alarm/alarm.h"
#include "auth/auth.h"
#include "board/board.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_defs.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "mex150/service.h"
#include "net/net.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "snmp_gw/snmp_gw.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/fs.h"
#include "store/history.h"
#include "store/persist.h"
#include "store/secrets.h"
#include "sysmgr/sysmgr.h"
#include "web/web.h"

static const char *TAG = "gw_main";

#define FATAL_RESTART_DELAY_MS 10000
/* Boot watchdog: nothing else supervises steps 2-13 (app_main is not on the TWDT and the
 * supervisor starts last). A new OTA image that hangs there must still reboot, so the bootloader
 * rolls a PENDING_VERIFY image back. Generous: a first-boot LittleFS format only writes the
 * superblocks, PBKDF2 runs once (< 0.5 s), W5500 bring-up has its own timeouts. */
#define BOOT_WATCHDOG_US (120LL * 1000 * 1000)
#define BOOTS_MAX 0x7FFFFFFFu /* snmpEngineBoots range (RFC 3414) */

static atomic_bool s_mex_started;

/* ---------------------------------------------------------------- helpers */

static void log_version(void) {
    const esp_app_desc_t *desc = esp_app_get_description();
    ESP_LOGI(TAG, "%s %s (IDF %s, built %s %s)", desc->project_name, desc->version, desc->idf_ver, desc->date,
             desc->time);

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        /* The supervisor posts GW_EVT_OTA{PENDING} and marks the image valid once healthy. */
        ESP_LOGW(TAG, "running %s is PENDING_VERIFY (rollback armed)", running->label);
    }
}

/* Record a non-fatal init failure: log, latch for the supervisor/diagnostics, show FAULT now. */
static bool init_ok(esp_err_t err, const char *what, uint32_t fault_bit) {
    if (err == ESP_OK) {
        return true;
    }
    ESP_LOGE(TAG, "%s failed: %s", what, esp_err_to_name(err));
    sys_init_fault_set(fault_bit);
    board_led_set(BOARD_LED_FAULT);
    return false;
}

/* Only for failures nothing can run without (the event loop). A PENDING_VERIFY image rolls back. */
static void fatal_restart(const char *what, esp_err_t err) {
    ESP_LOGE(TAG, "FATAL: %s (%s); restarting in %u s", what, esp_err_to_name(err),
             FATAL_RESTART_DELAY_MS / 1000);
    board_led_set(BOARD_LED_FAULT);
    vTaskDelay(pdMS_TO_TICKS(FATAL_RESTART_DELAY_MS));
    esp_restart();
}

static esp_err_t nvs_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS: %s, erasing", esp_err_to_name(err));
        err = nvs_flash_erase();
        if (err == ESP_OK) {
            err = nvs_flash_init();
        }
    }
    return err;
}

/* Read GW_NVS_KEY_BOOTS from `ns` (0 if missing/unreadable). */
static uint32_t nvs_read_boots(const char *ns) {
    nvs_handle_t h;
    uint32_t v = 0;
    if (nvs_open(ns, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u32(h, GW_NVS_KEY_BOOTS, &v) != ESP_OK) {
            v = 0;
        }
        nvs_close(h);
    }
    return v;
}

/*
 * Increment the boot counter (SNMP snmpEngineBoots) before snmp_gw_start() reads it. It lives in the
 * factory namespace, which a factory reset keeps, so it never decreases for the same engine ID.
 * A counter left in the legacy namespace GW_NVS_NS by earlier firmware is merged (max) and removed
 * only after the new value is committed.
 */
static uint32_t boot_count_increment(void) {
    const uint32_t legacy = strcmp(GW_NVS_NS, GW_NVS_NS_BOOTS) != 0 ? nvs_read_boots(GW_NVS_NS) : 0;
    uint32_t boots = nvs_read_boots(GW_NVS_NS_BOOTS);
    if (legacy > boots) {
        boots = legacy;
    }
    boots = boots < BOOTS_MAX ? boots + 1 : BOOTS_MAX;

    nvs_handle_t h;
    esp_err_t err = nvs_open(GW_NVS_NS_BOOTS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_u32(h, GW_NVS_KEY_BOOTS, boots);
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "boot counter not stored: %s", esp_err_to_name(err));
        return boots;
    }
    if (legacy && nvs_open(GW_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        if (nvs_erase_key(h, GW_NVS_KEY_BOOTS) == ESP_OK) {
            nvs_commit(h);
        }
        nvs_close(h);
    }
    return boots;
}

/* ---------------------------------------------------------------- Modbus glue */

/* cfg_modbus_t is ~130 bytes; static: app_main uses it once before the CONFIG_CHANGED handler is
 * registered, afterwards only the gw_evt task does. */
static cfg_modbus_t s_mb;

static esp_err_t modbus_apply(void) {
    esp_err_t err = cfg_get_section(CFG_SEC_MODBUS, &s_mb, sizeof(s_mb));
    if (err != ESP_OK) {
        return err;
    }
    if (atomic_load(&s_mex_started)) {
        return mex_service_reconfigure(&s_mb.port, s_mb.devices, s_mb.n_devices);
    }
    err = mex_service_start(&s_mb.port, s_mb.devices, s_mb.n_devices);
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
        atomic_store(&s_mex_started, true);
        return ESP_OK;
    }
    return err;
}

/* gw_evt: CONFIG_CHANGED{MODBUS} (PUT /config/modbus, config import, factory reset). A service that
 * failed to start at boot gets another chance with the new configuration. */
static void on_config_changed(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_config_t *e = data;
    if (!e || e->section != CFG_SEC_MODBUS) {
        return;
    }
    const bool was_started = atomic_load(&s_mex_started);
    const esp_err_t err = modbus_apply();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Modbus %s (rev %" PRIu32 "): %s", was_started ? "reconfigure" : "start", e->rev,
                 esp_err_to_name(err));
    } else if (!was_started) {
        sys_init_fault_clear(SYS_INIT_FAULT_MODBUS);
        ESP_LOGI(TAG, "Modbus service started after configuration change");
    }
}

/* ---------------------------------------------------------------- boot watchdog */

static void boot_watchdog_expired(void *arg) {
    (void)arg;
    /* esp_timer task: init is stuck in app_main. A plain restart (no persist flush: the tasks
     * that would do it may be the ones that hang). */
    ESP_LOGE(TAG, "init did not finish within %d s: restarting", (int)(BOOT_WATCHDOG_US / 1000000));
    esp_restart();
}

static esp_timer_handle_t boot_watchdog_arm(void) {
    const esp_timer_create_args_t args = {
        .callback = boot_watchdog_expired, .name = "boot_wdt", .dispatch_method = ESP_TIMER_TASK};
    esp_timer_handle_t t = NULL;
    if (esp_timer_create(&args, &t) != ESP_OK || esp_timer_start_once(t, BOOT_WATCHDOG_US) != ESP_OK) {
        ESP_LOGW(TAG, "boot watchdog unavailable");
        if (t) {
            esp_timer_delete(t);
        }
        return NULL;
    }
    return t;
}

static void boot_watchdog_disarm(esp_timer_handle_t t) {
    if (t) {
        (void)esp_timer_stop(t);
        (void)esp_timer_delete(t);
    }
}

/* ---------------------------------------------------------------- app_main */

void app_main(void) {
    const uint64_t t0 = gw_time_mono_ms();
    esp_timer_handle_t boot_wdt = boot_watchdog_arm();

    /* 1. version, OTA state */
    log_version();

    /* 2. NVS + boot counter (before snmp_gw_start, which reads it as snmpEngineBoots) */
    const esp_err_t nvs_err = nvs_init();
    uint32_t boots = 0;
    if (nvs_err == ESP_OK) {
        boots = boot_count_increment();
        ESP_LOGI(TAG, "boot #%" PRIu32, boots);
    } else {
        /* secrets_load then uses a per-boot AP PSK; SNMP engine boots reads 1 */
        ESP_LOGE(TAG, "NVS unavailable: %s", esp_err_to_name(nvs_err));
    }

    /* 3. crypto backend (secrets_load hashes), board (RTC -> clock, LED boot, buzzer, button) */
    if (gw_crypto_init() != GW_CRYPTO_OK) {
        ESP_LOGE(TAG, "crypto backend init failed: logins and SNMPv3 will fail");
        sys_init_fault_set(SYS_INIT_FAULT_CORE);
    }
    if (board_init() != ESP_OK) {
        ESP_LOGW(TAG, "board init incomplete (see board logs)");
    }
    if (nvs_err != ESP_OK) {
        sys_init_fault_set(SYS_INIT_FAULT_STORE);
        board_led_set(BOARD_LED_FAULT);
    }

    /* 4. LittleFS. Failure: keep going on RAM defaults (stores read nothing, persist writes fail). */
    if (!init_ok(fs_mount(FS_BASE, FS_PARTITION_LABEL), "LittleFS mount", SYS_INIT_FAULT_FS)) {
        ESP_LOGE(TAG, "running on factory defaults in RAM: configuration and logs are NOT saved");
    }

    /* 5. configuration (catalog hooks first: sev_override keys), secrets (factory AP PSK in NVS) */
    cfg_set_alarm_catalog(&alm_cfg_catalog);
    init_ok(config_load(), "config_load", SYS_INIT_FAULT_STORE);
    init_ok(secrets_load(), "secrets_load", SYS_INIT_FAULT_STORE);

    /* 6. event loop + 1 Hz tick: nothing below works without it */
    const esp_err_t evt_err = gw_events_init();
    if (evt_err != ESP_OK) {
        fatal_restart("event loop", evt_err);
    }

    /* 7. logs, history rings (PSRAM), persist task (registered writers exist by now) */
    init_ok(eventlog_init(), "eventlog_init", SYS_INIT_FAULT_STORE);
    init_ok(history_init(), "history_init", SYS_INIT_FAULT_STORE);
    init_ok(persist_start(), "persist_start", SYS_INIT_FAULT_STORE);

    /* 8. alarm engine (+ history sampler, rule pass) */
    init_ok(alarm_init(), "alarm_init", SYS_INIT_FAULT_CORE);

    /* 9. Ethernet, recovery AP fallback, SNTP, allowlist (Ethernet failure is handled inside).
     * The TCP/IP core must exist even if net_init() fails: steps 11-13 open lwIP sockets. */
    const esp_err_t netif_err = esp_netif_init();
    if (netif_err != ESP_OK && netif_err != ESP_ERR_INVALID_STATE) {
        fatal_restart("TCP/IP stack", netif_err);
    }
    init_ok(net_init(), "net_init", SYS_INIT_FAULT_NET);

    /* 10. Modbus polling (UART1). Retried on the next CONFIG_CHANGED{MODBUS} if it fails. The
     * handler is registered afterwards (nothing can commit config before web/SNMP/console start),
     * so s_mb is only ever used by one task at a time. */
    init_ok(modbus_apply(), "Modbus service start", SYS_INIT_FAULT_MODBUS);
    init_ok(gw_events_register(GW_EVT_CONFIG_CHANGED, on_config_changed, NULL, NULL), "Modbus config handler",
            SYS_INIT_FAULT_CORE);

    /* 11. users/sessions, then the HTTP server (UI, REST, WS, HTTPD heartbeat). The server starts
     * even if auth failed so the status of the device stays visible. */
    init_ok(auth_init(), "auth_init", SYS_INIT_FAULT_WEB);
    init_ok(web_start(), "web_start", SYS_INIT_FAULT_WEB);

    /* 12-13. optional subsystems: SNMP agent, syslog, USB console */
    init_ok(snmp_gw_start(), "snmp_gw_start", SYS_INIT_FAULT_SNMP);
    init_ok(syslog_init(), "syslog_init", SYS_INIT_FAULT_SYSLOG);
    const esp_err_t con_err = console_start();
    if (con_err != ESP_OK) {
        ESP_LOGW(TAG, "console unavailable: %s", esp_err_to_name(con_err));
    }

    /* 14. supervisor: health/mark-valid, LED, button, EVT_BOOT + OTA{PENDING} */
    const esp_err_t sup_err = supervisor_start();
    if (sup_err != ESP_OK) {
        /* Without it the image is never marked valid (rollback on the next reboot) and the LED
         * stays as set here. */
        ESP_LOGE(TAG, "supervisor_start failed: %s", esp_err_to_name(sup_err));
        sys_init_fault_set(SYS_INIT_FAULT_CORE);
        board_led_set(BOARD_LED_FAULT);
    }

    boot_watchdog_disarm(boot_wdt); /* the supervisor watches from here on */

    const uint32_t faults = sys_init_faults();
    ESP_LOGI(TAG, "init done in %" PRIu32 " ms (boot #%" PRIu32 ", faults 0x%02" PRIx32
                  "); internal heap free %u B (min %u B), PSRAM free %u B",
             (uint32_t)(gw_time_mono_ms() - t0), boots, faults,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}
