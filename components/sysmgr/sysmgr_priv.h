/* sysmgr_priv.h - internal interfaces between the sysmgr device files. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define SYS_SUPERVISOR_TASK_NAME "supervisor"
#define SYS_SUPERVISOR_STACK 3584
#define SYS_SUPERVISOR_CORE 1
#define SYS_SUPERVISOR_PERIOD_MS 250

#define SYS_BOOT_GRACE_MS 30000          /* LED BOOT / no FAULT before all heartbeats were seen */
#define SYS_PENDING_VERIFY_LIMIT_MS 300000 /* unhealthy new image -> reboot -> bootloader rollback */
#define SYS_HEALTH_REBOOT_MS 120000      /* required heartbeat stale this long (valid image) -> reboot */
#define SYS_HEALTH_REBOOT_MAX 3          /* consecutive health reboots without a healthy period */

/* ota_writer.c: true while an upload session is open (LED OTA). */
bool sys_ota_in_progress(void);

/* reboot.c: true once a reboot or factory reset has been scheduled. */
bool sys_reboot_pending(void);

/* factory_reset.c: true once a factory reset has been executed (LED RESET_ARMED until reboot). */
bool sys_factory_reset_pending(void);

/* syslog.c: periodic work from the supervisor task (DNS (re)resolution, drop reports). */
void syslog_service(void);

/* diag.c: NVS boot counter (cached after the first read). */
uint32_t sys_boot_count(void);

/* diag.c: print a task/stack table to stdout (console "status"). */
void sys_print_tasks(void);
