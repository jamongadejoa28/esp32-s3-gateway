/*
 * fs.c - LittleFS mount of the "data" partition and its directory layout (device only).
 * Contract: store/fs.h.
 */
#include "store/fs.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_littlefs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gw_core/gw_defs.h"
#include "store/persist.h"
#include "store_dev.h"

static const char *TAG = "fs";

static char s_label[16];
static bool s_mounted;

static esp_err_t ensure_dir(const char *path) {
    if (mkdir(path, 0775) == 0 || errno == EEXIST)
        return ESP_OK;
    ESP_LOGE(TAG, "mkdir %s failed (errno %d)", path, errno);
    return ESP_FAIL;
}

esp_err_t fs_mount(const char *base, const char *label) {
    if (!base || !label || strlen(label) >= sizeof(s_label))
        return ESP_ERR_INVALID_ARG;
    if (s_mounted)
        return ESP_OK;
    esp_vfs_littlefs_conf_t conf = {
        .base_path = base,
        .partition_label = label,
        .format_if_mount_failed = true,
        .dont_mount = false,
    };
    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mount '%s' at %s failed: %s", label, base, esp_err_to_name(err));
        return err;
    }
    gw_strlcpy(s_label, label, sizeof(s_label));
    s_mounted = true;

    /* Layout (fs.h). Only the canonical base gets the canonical tree. */
    if (strcmp(base, FS_BASE) == 0) {
        static const char *const dirs[] = {FS_DIR_CFG, FS_DIR_SEC, FS_DIR_HIST, FS_DIR_LOG};
        for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
            err = ensure_dir(dirs[i]);
            if (err != ESP_OK)
                return err;
        }
        for (unsigned d = 0; d < GW_MAX_DEVICES; d++) {
            char p[32];
            snprintf(p, sizeof(p), FS_DIR_HIST "/d%u", d);
            err = ensure_dir(p);
            if (err != ESP_OK)
                return err;
        }
    }
    size_t total = 0, used = 0;
    if (esp_littlefs_info(s_label, &total, &used) == ESP_OK)
        ESP_LOGI(TAG, "mounted '%s' at %s: %u of %u KiB used", label, base, (unsigned)(used / 1024),
                 (unsigned)(total / 1024));
    return ESP_OK;
}

esp_err_t fs_unmount(void) {
    if (!s_mounted)
        return ESP_ERR_INVALID_STATE;
    esp_err_t err = esp_vfs_littlefs_unregister(s_label);
    if (err == ESP_OK)
        s_mounted = false;
    return err;
}

esp_err_t fs_info(size_t *total, size_t *used) {
    if (!s_mounted)
        return ESP_ERR_INVALID_STATE;
    size_t t = 0, u = 0;
    esp_err_t err = esp_littlefs_info(s_label, &t, &u);
    if (err != ESP_OK)
        return err;
    if (total)
        *total = t;
    if (used)
        *used = u;
    return ESP_OK;
}

#define FS_UNLINK_BUSY_TRIES 40 /* x 50 ms: a query/CSV export holding the file open gets 2 s */

/* esp_littlefs refuses to unlink a file with an open descriptor (EBUSY): retry for a while. */
static int unlink_retry(const char *path) {
    for (int i = 0;; i++) {
        if (unlink(path) == 0)
            return 0;
        if (errno != EBUSY || i + 1 >= FS_UNLINK_BUSY_TRIES)
            return -1;
        store_wdt_feed();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

/* Depth-limited recursive delete of dir's contents; path buffer reused across levels. */
static esp_err_t clear_dir_rec(char *path, size_t cap, int depth) {
    if (depth > 4)
        return ESP_FAIL;
    DIR *dp = opendir(path);
    if (!dp)
        return errno == ENOENT ? ESP_OK : ESP_FAIL;
    esp_err_t rc = ESP_OK;
    size_t base_len = strlen(path);
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        int n = snprintf(path + base_len, cap - base_len, "/%s", de->d_name);
        if (n <= 0 || (size_t)n >= cap - base_len) {
            rc = ESP_FAIL;
            path[base_len] = '\0';
            continue;
        }
        bool is_dir = de->d_type == DT_DIR;
        if (de->d_type == DT_UNKNOWN) {
            struct stat st;
            is_dir = stat(path, &st) == 0 && S_ISDIR(st.st_mode);
        }
        if (is_dir) {
            if (clear_dir_rec(path, cap, depth + 1) != ESP_OK || rmdir(path) != 0)
                rc = ESP_FAIL;
        } else if (unlink_retry(path) != 0) {
            ESP_LOGW(TAG, "unlink %s failed (errno %d)", path, errno);
            rc = ESP_FAIL;
        }
        path[base_len] = '\0';
        store_wdt_feed(); /* large trees: keep the persist task's TWDT fed */
    }
    closedir(dp);
    return rc;
}

esp_err_t fs_clear_dir(const char *dir) {
    if (!dir)
        return ESP_ERR_INVALID_ARG;
    char path[128];
    if (strlen(dir) >= sizeof(path))
        return ESP_ERR_INVALID_ARG;
    gw_strlcpy(path, dir, sizeof(path));
    esp_err_t rc = clear_dir_rec(path, sizeof(path), 0);
    if (rc != ESP_OK)
        ESP_LOGW(TAG, "clear %s incomplete", dir);
    return rc;
}
