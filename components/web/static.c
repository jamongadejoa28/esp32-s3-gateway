/* Static UI: gzip files streamed from the read-only LittleFS paired with the running app, strong ETags,
 * If-None-Match -> 304, immutable caching for content-hashed files and no-cache for "/" and the
 * favicon. Every response carries the security headers. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_app_desc.h"
#include "esp_littlefs.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "gw_core/gw_health.h"
#include "mex150/regmap.h"
#include "web/web_assets.h"
#include "web_priv.h"

static const char *TAG = "web_static";

#define CACHE_IMMUTABLE "public, max-age=31536000, immutable"
#define CACHE_REVALIDATE "no-cache"
#ifndef WEB_FS_BASE
#define WEB_FS_BASE "/web"
#endif
#define WEB_READ_CHUNK 1024

static bool s_mounted;

esp_err_t web_assets_mount(void) {
    if (s_mounted || !gw_web_assets_count)
        return ESP_OK;
    const esp_partition_t *run = esp_ota_get_running_partition();
    if (!run)
        return ESP_ERR_NOT_FOUND;
    const char *label = run->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0   ? "web_0"
                        : run->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1 ? "web_1"
                                                                          : NULL;
    if (!label)
        return ESP_ERR_NOT_FOUND;
    const esp_vfs_littlefs_conf_t conf = {
        .base_path = WEB_FS_BASE,
        .partition_label = label,
        .format_if_mount_failed = false,
        .read_only = true,
    };
    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK)
        return err;
    char identity[sizeof("GW_WEB_ID:") + 64];
    FILE *f = fopen(WEB_FS_BASE "/.asset-id", "rb");
    const size_t n = f ? fread(identity, 1, sizeof(identity), f) : 0;
    if (f)
        fclose(f);
    if (n != strlen(gw_web_assets_id) || memcmp(identity, gw_web_assets_id, n) != 0) {
        ESP_LOGE(TAG, "%s does not match this firmware; install the matching web image", label);
        esp_vfs_littlefs_unregister(label);
        return ESP_ERR_INVALID_CRC;
    }
    for (size_t i = 0; i < gw_web_assets_count; i++) {
        char filename[160];
        struct stat st;
        const web_asset_t *a = &gw_web_assets[i];
        const int used = snprintf(filename, sizeof(filename), WEB_FS_BASE "/%s", a->file);
        if (used < 0 || used >= (int)sizeof(filename) || stat(filename, &st) != 0 ||
            st.st_size != (off_t)a->len) {
            ESP_LOGE(TAG, "%s is missing or truncated in %s", a->file, label);
            esp_vfs_littlefs_unregister(label);
            return ESP_ERR_INVALID_CRC;
        }
    }
    s_mounted = true;
    ESP_LOGI(TAG, "serving %u gzip files from %s (read-only)", (unsigned)gw_web_assets_count, label);
    return ESP_OK;
}

const web_asset_t *web_asset_find(const char *path, size_t len) {
    if (!path || !len) {
        return NULL;
    }
    size_t lo = 0;
    size_t hi = gw_web_assets_count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const char *p = gw_web_assets[mid].path;
        if (!p) {
            return NULL; /* malformed table */
        }
        /* Compare path[0..len) with the NUL-terminated p in strcmp order. */
        int c = strncmp(path, p, len);
        if (c == 0 && p[len] != '\0') {
            c = -1; /* path is a proper prefix of p: sorts before it */
        }
        if (c == 0) {
            return &gw_web_assets[mid];
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return NULL;
}

esp_err_t web_static_serve(httpd_req_t *req, const char *path, size_t len) {
    web_rstate_t *rs = web_rs(req);
    const web_asset_t *a = web_asset_find(path, len);
    if (!a || !a->file) {
        if (rs) {
            rs->api = true; /* JSON error body, no-store */
        }
        return web_send_error_raw(req, 404, WEB_E_NOT_FOUND);
    }
    if (!s_mounted)
        return web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
    char filename[160];
    int used = snprintf(filename, sizeof(filename), WEB_FS_BASE "/%s", a->file);
    if (used < 0 || used >= (int)sizeof(filename))
        return web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
    FILE *f = fopen(filename, "rb");
    struct stat st;
    if (!f || fstat(fileno(f), &st) != 0 || st.st_size != (off_t)a->len) {
        if (f)
            fclose(f);
        return web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
    }
    if (rs) {
        rs->cache_set = true;
    }
    httpd_resp_set_hdr(req, "Cache-Control", a->immutable ? CACHE_IMMUTABLE : CACHE_REVALIDATE);
    if (a->etag && a->etag[0]) {
        httpd_resp_set_hdr(req, "ETag", a->etag);
        char inm[128];
        size_t n = httpd_req_get_hdr_value_len(req, "If-None-Match");
        if (n && n < sizeof(inm) &&
            httpd_req_get_hdr_value_str(req, "If-None-Match", inm, sizeof(inm)) == ESP_OK &&
            web_etag_match(inm, a->etag)) {
            httpd_resp_set_status(req, web_status_line(304));
            web_security_headers(req);
            fclose(f);
            return httpd_resp_send(req, NULL, 0);
        }
    }
    httpd_resp_set_status(req, web_status_line(200));
    httpd_resp_set_type(req, a->mime ? a->mime : "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Vary", "Accept-Encoding");
    web_security_headers(req);
    char buf[WEB_READ_CHUNK];
    size_t left = a->len;
    esp_err_t err = ESP_OK;
    while (left) {
        size_t want = left < sizeof(buf) ? left : sizeof(buf);
        size_t got = fread(buf, 1, want, f);
        if (got != want) {
            err = ESP_FAIL;
            break;
        }
        err = httpd_resp_send_chunk(req, buf, got);
        if (err != ESP_OK)
            break;
        left -= got;
        gw_hb_beat(GW_HB_HTTPD);
    }
    fclose(f);
    if (err == ESP_OK)
        err = httpd_resp_send_chunk(req, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "send %s failed: %s", a->path, esp_err_to_name(err));
    }
    return err;
}

const char *web_meta_etag(void) {
    static char etag[24];
    if (!etag[0]) {
        char sha[17] = {0};
        esp_app_get_elf_sha256(sha, sizeof(sha));
        snprintf(etag, sizeof(etag), "\"%.12s-%u\"", sha, (unsigned)MEX_REGMAP_VERSION);
    }
    return etag;
}
