/*
 * sysmgr.h - supervisor (health, LED, button, mark-valid), OTA writer, firmware info/rollback,
 * reboot scheduling, factory reset, syslog client, console, diagnostics, core dump summary.
 * IDF-free header. Unless noted, functions are thread-safe and callable from any task (not ISR).
 * sysmgr PRIV_REQUIRES board, net, store, alarm and mex150 (LED state: alarm_counts(),
 * mex_service_snapshot(); syslog: alm_find_code(); console "status"). It never depends on web:
 * web reacts to GW_EVT_REBOOT itself, and heartbeats live in gw_core/gw_health.h.
 */
#pragma once

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ======================= Supervisor ======================= */

#define SYS_SUPERVISOR_TASK_PRIO 2
#define SYS_VALID_AFTER_MS                                                                                   \
    60000 /* healthy this long after boot -> esp_ota_mark_app_valid_cancel_rollback() */

/**
 * Start the "supervisor" task (init order step 14): mark-valid once SYS_VALID_AFTER_MS have passed
 * and gw_hb_stale_mask(GW_HB_MAX_AGE_MS) & GW_HB_REQUIRED_MASK == 0 (gw_core/gw_health.h; posts
 * GW_EVT_OTA{VALIDATED} if the image was PENDING_VERIFY), LED state selection (alarm_counts(),
 * enabled devices offline via mex_service_snapshot()), button gestures (BOOT 3-8 s ->
 * net_ap_start(NET_AP_REASON_BUTTON); >= 10 s -> factory reset), TIME_SYNC -> RTC write. The AP
 * fallback timer (no link/IP after boot) belongs to net, not to the supervisor.
 */
esp_err_t supervisor_start(void);

/* Init failures app_main reports (bits, latched until reboot or cleared on recovery). Any bit selects the FAULT LED (also
 * during the boot grace) and is shown in GET /system/info diag.init_faults. The gateway keeps
 * running with whatever works (DECISIONS.md, Integrator). */
#define SYS_INIT_FAULT_FS 0x01u      /* LittleFS mount failed: RAM defaults, nothing is persisted */
#define SYS_INIT_FAULT_STORE 0x02u   /* config/secrets/eventlog/history/persist init failed */
#define SYS_INIT_FAULT_MODBUS 0x04u  /* mex_service_start failed (retried on CONFIG_CHANGED{MODBUS}) */
#define SYS_INIT_FAULT_NET 0x08u     /* net_init failed */
#define SYS_INIT_FAULT_WEB 0x10u     /* auth_init or web_start failed */
#define SYS_INIT_FAULT_SNMP 0x20u    /* snmp_gw_start failed (optional subsystem) */
#define SYS_INIT_FAULT_SYSLOG 0x40u  /* syslog_init failed (optional subsystem) */
#define SYS_INIT_FAULT_CORE 0x80u    /* alarm or another core service failed to start */

/** OR `bits` into the init-fault latch. Any task, also before supervisor_start(). */
void sys_init_fault_set(uint32_t bits);

/** Clear `bits` once the subsystem recovered (e.g. a retried Modbus start). Any task. */
void sys_init_fault_clear(uint32_t bits);

/** Current init-fault bits (0 = clean boot). */
uint32_t sys_init_faults(void);

/* ======================= Firmware ======================= */

#define SYS_OTA_REBOOT_DELAY_MS 2000

typedef struct sys_ota sys_ota_t; /* opaque upload session */

/**
 * Begin an upload into the next OTA slot. image_len = Content-Length; sha256 = expected digest
 * (X-Firmware-SHA256). Posts GW_EVT_OTA{BEGIN}.
 * @return ESP_OK, ESP_ERR_INVALID_STATE (another upload active, a reboot is scheduled, or the
 *         running image is still PENDING_VERIFY after an update, i.e. not yet marked valid by the
 *         supervisor -> 423, retry shortly), ESP_ERR_INVALID_SIZE
 *         (0 or larger than the partition -> 413), ESP_ERR_NOT_FOUND (no OTA partition).
 */
esp_err_t sys_ota_begin(size_t image_len, const uint8_t sha256[32], bool allow_downgrade, const char *by,
                        sys_ota_t **out);

/** Write the next chunk (hashing as it goes). On error the session is aborted and freed. */
esp_err_t sys_ota_write(sys_ota_t *ota, const void *data, size_t len);

/**
 * Finish: compare SHA-256 (ESP_ERR_INVALID_CRC -> 422 hash_mismatch), esp_ota_end(), check
 * esp_app_desc_t.project_name == GW_PROJECT_NAME and version >= running unless allow_downgrade
 * (ESP_ERR_INVALID_VERSION -> 422 image_invalid), set boot partition, post GW_EVT_OTA{DONE},
 * audit, schedule reboot in SYS_OTA_REBOOT_DELAY_MS. The session is freed in every case.
 * version_out receives the new image's version on success.
 * The checks prove integrity, not authenticity: images are not signed (accepted risk, see
 * DECISIONS.md FIXER and DESIGN.md §14); any admin session can install firmware.
 */
esp_err_t sys_ota_end(sys_ota_t *ota, char version_out[GW_VERSION_SZ]);

/** Abort and free (NULL ok). Posts GW_EVT_OTA{FAILED}. */
void sys_ota_abort(sys_ota_t *ota);

typedef struct {
    char running_slot[8]; /* "ota_0" | "ota_1" */
    char running_version[GW_VERSION_SZ];
    char running_state[16]; /* "valid" | "pending_verify" | "new" | "invalid" | "aborted" | "undefined" */
    char other_slot[8];
    char other_version[GW_VERSION_SZ]; /* "" if empty/unreadable */
    bool other_valid;                  /* bootable (rollback possible) */
} sys_fw_info_t;

esp_err_t sys_fw_info(sys_fw_info_t *out);

/** Boot the other valid slot after SYS_OTA_REBOOT_DELAY_MS. ESP_ERR_NOT_FOUND if none valid. */
esp_err_t sys_rollback(const char *by);

/* ======================= Reboot / factory reset ======================= */

/**
 * Schedule a reboot: post GW_EVT_REBOOT{reason, delay} (web's ws_hub handler sends bye "reboot" and
 * closes WS clients; history requests a flush), then after delay_ms run persist_flush(3000) and
 * esp_restart(). sysmgr does not call into web. reason = gw_reboot_reason_t.
 * A second call while one is scheduled returns ESP_ERR_INVALID_STATE.
 */
esp_err_t sys_reboot(uint8_t reason, uint32_t delay_ms, const char *by);

/**
 * Factory reset (web/button/console), using only store APIs: audit AUD_FACTORY_RESET, then
 * config_factory_reset(keep_network) and secrets_factory_reset() (RAM -> defaults, files rewritten
 * by persist, both stores frozen until reboot); unless keep_network also evlog_factory_reset() and
 * history_factory_reset(). Erase NVS namespace GW_NVS_NS ("gw"; GW_NVS_NS_FACTORY with the factory
 * AP PSK and the boot counter / SNMP engine boots is kept) and the stored core dump, then sys_reboot(GW_REBOOT_FACTORY_RESET, ...) which
 * flushes persist first. Asynchronous; returns ESP_OK once the reboot is scheduled (partial store
 * failures are logged only), ESP_ERR_INVALID_STATE when a reset/reboot is already pending.
 */
esp_err_t sys_factory_reset(bool keep_network, const char *by);

/* ======================= Syslog / console ======================= */

/** Start the UDP syslog client (RFC 5424) from the notify/security config; re-applies on change. */
esp_err_t syslog_init(void);

/** Queue a syslog message (severity 0..7). Dropped if disabled or above min_sev. Non-blocking. */
void sys_syslog(uint8_t severity, const char *msgid, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/** Start the USB-Serial-JTAG console: status, ip, net-reset, factory-reset --yes, reboot, log. */
esp_err_t console_start(void);

/* ======================= Diagnostics ======================= */

typedef struct {
    char fw[GW_VERSION_SZ]; /* app version */
    char build[24];         /* "YYYY-MM-DD HH:MM:SS" of the image */
    char idf[GW_VERSION_SZ];
    uint8_t mac[GW_MAC_LEN]; /* base MAC */
    uint32_t uptime_s;
    bool time_valid;
    uint32_t heap_int_free;
    uint32_t heap_int_min; /* heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) */
    uint32_t psram_free;
    char part_running[8];
    char part_state[16];  /* as sys_fw_info_t.running_state */
    uint8_t reset_reason; /* esp_reset_reason_t */
    uint32_t boot_count;  /* NVS GW_NVS_NS_BOOTS/GW_NVS_KEY_BOOTS (also SNMP engine boots) */
    uint32_t evt_dropped; /* gw_events_dropped() */
    uint32_t hb_stale;    /* gw_hb_stale_mask(GW_HB_MAX_AGE_MS) */
    uint32_t init_faults; /* sys_init_faults() (SYS_INIT_FAULT_* bits) */
} sys_info_t;

void sys_get_info(sys_info_t *out);

#define SYS_COREDUMP_BT_MAX 16

/**
 * Summary of the stored core dump (esp_core_dump_get_summary()). The web exposes ONLY this summary
 * (GET /system/coredump): the full ELF contains RAM (password hashes, keys, session tokens) and is
 * retrieved over USB with `idf.py coredump-info` instead.
 */
typedef struct {
    char task[16];                    /* task that crashed */
    uint32_t pc;                      /* exception PC */
    uint32_t cause;                   /* Xtensa EXCCAUSE */
    uint32_t vaddr;                   /* EXCVADDR */
    uint32_t bt[SYS_COREDUMP_BT_MAX]; /* backtrace PCs */
    uint8_t bt_depth;                 /* valid entries in bt */
    bool bt_corrupted;
    char app_sha256[17]; /* crashed image's ELF SHA-256 prefix (CONFIG_APP_RETRIEVE_LEN_ELF_SHA
                            hex chars, at most 16) */
} sys_coredump_summary_t;

/** Read the summary. ESP_ERR_NOT_FOUND if no (valid) core dump is stored. */
esp_err_t sys_coredump_summary(sys_coredump_summary_t *out);

#ifdef __cplusplus
}
#endif
