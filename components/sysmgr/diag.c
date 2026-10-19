/* Diagnostics (sysmgr.h sys_get_info, sys_coredump_summary) and the console task table. */
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "board/board.h"
#include "esp_app_desc.h"
#include "esp_core_dump.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_time.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"
#include "sysmgr_pure.h"

static const char *TAG = "diag";

#define DIAG_MAX_TASKS 40

static atomic_bool s_boots_read;
static atomic_uint s_boots;

uint32_t sys_boot_count(void) {
    if (!atomic_load(&s_boots_read)) {
        uint32_t v = 0;
        nvs_handle_t h;
        if (nvs_open(GW_NVS_NS_BOOTS, NVS_READONLY, &h) == ESP_OK) {
            if (nvs_get_u32(h, GW_NVS_KEY_BOOTS, &v) != ESP_OK) {
                v = 0;
            }
            nvs_close(h);
        }
        atomic_store(&s_boots, v);
        atomic_store(&s_boots_read, true);
    }
    return atomic_load(&s_boots);
}

static void running_state(char *out, size_t cap) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    const char *s = "undefined";
    if (run && esp_ota_get_state_partition(run, &st) == ESP_OK) {
        s = st == ESP_OTA_IMG_NEW              ? "new"
            : st == ESP_OTA_IMG_PENDING_VERIFY ? "pending_verify"
            : st == ESP_OTA_IMG_VALID          ? "valid"
            : st == ESP_OTA_IMG_INVALID        ? "invalid"
            : st == ESP_OTA_IMG_ABORTED        ? "aborted"
                                               : "undefined";
    }
    gw_strlcpy(out, s, cap);
}

void sys_get_info(sys_info_t *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    const esp_app_desc_t *d = esp_app_get_description();
    gw_strlcpy(out->fw, d->version, sizeof(out->fw));
    if (!sys_build_date_iso(d->date, d->time, out->build, sizeof(out->build))) {
        snprintf(out->build, sizeof(out->build), "%.11s %.8s", d->date, d->time);
    }
    gw_strlcpy(out->idf, d->idf_ver, sizeof(out->idf));
    board_base_mac(out->mac);
    out->uptime_s = (uint32_t)(gw_time_mono_ms() / 1000u);
    out->time_valid = gw_time_valid();
    out->heap_int_free = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    out->heap_int_min = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    out->psram_free = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    const esp_partition_t *run = esp_ota_get_running_partition();
    gw_strlcpy(out->part_running, run ? run->label : "", sizeof(out->part_running));
    running_state(out->part_state, sizeof(out->part_state));
    out->reset_reason = (uint8_t)esp_reset_reason();
    out->boot_count = sys_boot_count();
    out->evt_dropped = gw_events_dropped();
    out->hb_stale = gw_hb_stale_mask(GW_HB_MAX_AGE_MS);
    out->init_faults = sys_init_faults();
}

esp_err_t sys_coredump_summary(sys_coredump_summary_t *out) {
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    if (esp_core_dump_image_check() != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_core_dump_summary_t *sum = malloc(sizeof(*sum));
    if (!sum) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = esp_core_dump_get_summary(sum);
    if (err != ESP_OK) {
        free(sum);
        ESP_LOGW(TAG, "core dump summary: %s", esp_err_to_name(err));
        return ESP_ERR_NOT_FOUND;
    }
    memcpy(out->task, sum->exc_task, sizeof(out->task) - 1);
    out->task[sizeof(out->task) - 1] = '\0';
    out->pc = sum->exc_pc;
    out->cause = sum->ex_info.exc_cause;
    out->vaddr = sum->ex_info.exc_vaddr;
    const uint32_t depth = sum->exc_bt_info.depth < SYS_COREDUMP_BT_MAX ? sum->exc_bt_info.depth : SYS_COREDUMP_BT_MAX;
    memcpy(out->bt, sum->exc_bt_info.bt, depth * sizeof(out->bt[0]));
    out->bt_depth = (uint8_t)depth;
    out->bt_corrupted = sum->exc_bt_info.corrupted;
    size_t n = CONFIG_APP_RETRIEVE_LEN_ELF_SHA;
    if (n > sizeof(out->app_sha256) - 1) {
        n = sizeof(out->app_sha256) - 1;
    }
    if (n > sizeof(sum->app_elf_sha256)) {
        n = sizeof(sum->app_elf_sha256);
    }
    size_t i = 0;
    for (; i < n && sum->app_elf_sha256[i]; i++) {
        out->app_sha256[i] = (char)sum->app_elf_sha256[i];
    }
    out->app_sha256[i] = '\0';
    free(sum);
    return ESP_OK;
}

void sys_print_tasks(void) {
#if CONFIG_FREERTOS_USE_TRACE_FACILITY
    const UBaseType_t cap = DIAG_MAX_TASKS;
    TaskStatus_t *ts = malloc(cap * sizeof(*ts));
    if (!ts) {
        printf("tasks: out of memory\n");
        return;
    }
    const UBaseType_t n = uxTaskGetSystemState(ts, cap, NULL);
    printf("%-16s %4s %5s %s\n", "task", "prio", "core", "stack_free");
    for (UBaseType_t i = 0; i < n; i++) {
        const BaseType_t core = xTaskGetCoreID(ts[i].xHandle);
        printf("%-16s %4u %5d %" PRIu32 "\n", ts[i].pcTaskName, (unsigned)ts[i].uxCurrentPriority,
               core == tskNO_AFFINITY ? -1 : (int)core, (uint32_t)ts[i].usStackHighWaterMark);
    }
    if (n == 0) {
        printf("(more than %u tasks)\n", (unsigned)cap);
    }
    free(ts);
#else
    printf("tasks: CONFIG_FREERTOS_USE_TRACE_FACILITY disabled\n");
#endif
}
