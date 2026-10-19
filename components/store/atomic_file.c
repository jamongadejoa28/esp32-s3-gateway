/*
 * atomic_file.c - crash-safe small-file replace and fallback load (pure C: stdio + POSIX).
 * Contract: store/atomic_file.h. Host-tested on a temp directory; on the device the paths live on
 * the LittleFS VFS (rename replaces an existing destination atomically, fsync commits the file).
 */
#define _POSIX_C_SOURCE 200809L

#include "store/atomic_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gw_core/gw_crypto.h"
#include "store_priv.h"

static bool make_path(char out[ATOMIC_PATH_MAX], const char *path, const char *suffix) {
    int n = snprintf(out, ATOMIC_PATH_MAX, "%s%s", path, suffix);
    return n > 0 && n < ATOMIC_PATH_MAX;
}

static bool file_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

esp_err_t atomic_write(const char *path, const void *data, size_t len) {
    char tmp[ATOMIC_PATH_MAX], bak[ATOMIC_PATH_MAX];
    if (!path || (!data && len) || !make_path(tmp, path, ".tmp") || !make_path(bak, path, ".bak"))
        return ESP_ERR_INVALID_ARG;

    FILE *f = fopen(tmp, "wb");
    if (!f)
        return ESP_FAIL;
    bool ok = (len == 0 || fwrite(data, 1, len, f) == len);
    ok = ok && fflush(f) == 0;
    ok = ok && fsync(fileno(f)) == 0;
    if (fclose(f) != 0)
        ok = false;
    if (!ok) {
        remove(tmp);
        return ESP_FAIL;
    }
    /* X.tmp is complete. Keep the previous version as X.bak, then move the new one in place. A crash
     * between the two renames leaves X.tmp and X.bak, both complete (load order X, X.tmp, X.bak). */
    if (file_exists(path) && rename(path, bak) != 0)
        return ESP_FAIL;
    if (rename(tmp, path) != 0)
        return ESP_FAIL;
    return ESP_OK;
}

/* Read a whole file into a malloc'd NUL-terminated buffer. ESP_ERR_NOT_FOUND for unreadable or
 * oversized files (skip to the next candidate), ESP_ERR_NO_MEM on allocation failure. */
static esp_err_t read_all(const char *p, size_t max_len, char **out, size_t *len) {
    FILE *f = fopen(p, "rb");
    if (!f)
        return ESP_ERR_NOT_FOUND;
    esp_err_t rc = ESP_ERR_NOT_FOUND;
    char *buf = NULL;
    if (fseek(f, 0, SEEK_END) != 0)
        goto done;
    long sz = ftell(f);
    if (sz < 0 || (unsigned long)sz > max_len || fseek(f, 0, SEEK_SET) != 0)
        goto done;
    buf = malloc((size_t)sz + 1);
    if (!buf) {
        rc = ESP_ERR_NO_MEM;
        goto done;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        gw_secure_zero(buf, (size_t)sz + 1);
        free(buf);
        buf = NULL;
        goto done;
    }
    buf[sz] = '\0';
    *out = buf;
    *len = (size_t)sz;
    rc = ESP_OK;
done:
    fclose(f);
    return rc;
}

esp_err_t atomic_read(const char *path, size_t max_len, atomic_accept_fn accept, void *arg, char **out,
                      size_t *len, atomic_src_t *src) {
    if (src)
        *src = ATOMIC_SRC_NONE;
    if (!path || !out)
        return ESP_ERR_INVALID_ARG;
    *out = NULL;
    if (len)
        *len = 0;
    char cand[3][ATOMIC_PATH_MAX];
    static const atomic_src_t ids[3] = {ATOMIC_SRC_MAIN, ATOMIC_SRC_TMP, ATOMIC_SRC_BAK};
    if (!make_path(cand[0], path, "") || !make_path(cand[1], path, ".tmp") || !make_path(cand[2], path, ".bak"))
        return ESP_ERR_INVALID_ARG;
    for (int i = 0; i < 3; i++) {
        char *buf = NULL;
        size_t n = 0;
        esp_err_t rc = read_all(cand[i], max_len, &buf, &n);
        if (rc == ESP_ERR_NO_MEM)
            return rc;
        if (rc != ESP_OK)
            continue;
        if (!accept || accept(buf, n, arg)) {
            *out = buf;
            if (len)
                *len = n;
            if (src)
                *src = ids[i];
            return ESP_OK;
        }
        gw_secure_zero(buf, n); /* candidates may hold secrets */
        free(buf);
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t atomic_remove(const char *path) {
    char p[ATOMIC_PATH_MAX];
    static const char *const suffix[3] = {"", ".tmp", ".bak"};
    if (!path)
        return ESP_ERR_INVALID_ARG;
    esp_err_t rc = ESP_OK;
    for (int i = 0; i < 3; i++) {
        if (!make_path(p, path, suffix[i]))
            return ESP_ERR_INVALID_ARG;
        if (remove(p) != 0 && errno != ENOENT)
            rc = ESP_FAIL;
    }
    return rc;
}

esp_err_t atomic_drop_backups(const char *path) {
    char p[ATOMIC_PATH_MAX];
    static const char *const suffix[2] = {".bak", ".tmp"};
    if (!path)
        return ESP_ERR_INVALID_ARG;
    esp_err_t rc = ESP_OK;
    for (int i = 0; i < 2; i++) {
        if (!make_path(p, path, suffix[i]))
            return ESP_ERR_INVALID_ARG;
        if (remove(p) != 0 && errno != ENOENT)
            rc = ESP_FAIL;
    }
    return rc;
}
