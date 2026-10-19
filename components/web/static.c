/* Static UI (web/web_assets.h, DESIGN.md §11): gzip bodies from the app image, strong ETags,
 * If-None-Match -> 304, immutable caching for content-hashed files and no-cache for "/" and the
 * favicon. Every response carries the security headers. */
#include <stdio.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_log.h"
#include "mex150/regmap.h"
#include "web/web_assets.h"
#include "web_priv.h"

static const char *TAG = "web_static";

#define CACHE_IMMUTABLE "public, max-age=31536000, immutable"
#define CACHE_REVALIDATE "no-cache"

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
    if (!a || !a->gz) {
        if (rs) {
            rs->api = true; /* JSON error body, no-store */
        }
        return web_send_error_raw(req, 404, WEB_E_NOT_FOUND);
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
            return httpd_resp_send(req, NULL, 0);
        }
    }
    httpd_resp_set_status(req, web_status_line(200));
    httpd_resp_set_type(req, a->mime ? a->mime : "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Vary", "Accept-Encoding");
    web_security_headers(req);
    esp_err_t err = httpd_resp_send(req, (const char *)a->gz, (ssize_t)a->len);
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
