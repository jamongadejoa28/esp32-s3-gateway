/*
 * fs.h - LittleFS mount and the file layout of the "data" partition.
 * Mounted once at boot (init step 4) with format_if_mount_failed = true. No image is flashed.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FS_BASE "/data"
#define FS_PARTITION_LABEL "data"
#define FS_DIR_CFG FS_BASE "/cfg"
#define FS_DIR_SEC FS_BASE "/sec"
#define FS_DIR_HIST FS_BASE "/hist" /* per device: FS_DIR_HIST "/d<dev>/YYYYMMDD.bin" */
#define FS_DIR_LOG FS_BASE "/log"
#define FS_PATH_CONFIG FS_DIR_CFG "/gateway.json"
#define FS_PATH_SECRETS FS_DIR_SEC "/secrets.json"
#define FS_CONFIG_MAX (16u * 1024u) /* largest accepted config file */
#define FS_SECRETS_MAX (8u * 1024u)

/** Mount `label` at `base` and create the directory layout. Formats on mount failure. */
esp_err_t fs_mount(const char *base, const char *label);

/** Unmount (factory reset / tests). */
esp_err_t fs_unmount(void);

/** Total/used bytes of the mounted partition. */
esp_err_t fs_info(size_t *total, size_t *used);

/**
 * Recursively delete the contents of `dir` (keeps the directory). Persist task only.
 * Used by evlog_factory_reset() (FS_DIR_LOG) and history_factory_reset() (FS_DIR_HIST). Config and
 * secrets are reset by rewriting them from RAM defaults (config_factory_reset/secrets_factory_reset),
 * never by deleting their directories (a later dirty mark would resurrect old RAM content).
 */
esp_err_t fs_clear_dir(const char *dir);

#ifdef __cplusplus
}
#endif
