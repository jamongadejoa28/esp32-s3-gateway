/*
 * web_assets.h - metadata for gzip files in the running app's paired read-only LittleFS.
 *
 * tools/gen_web_assets.py emits this small table and stages gzip bodies separately in webfs/.
 * cmake/gw_web_assets.cmake creates web.bin and the firmware/web OTA package. No web body is
 * embedded in app rodata. Builds with GW_WEB_ASSETS=OFF use the empty fallback table.
 * static.c streams only listed files, preserving ETag/304 and immutable content-hash caching.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *path; /* URL path, unique, e.g. "/" or "/assets/app.3f9a1c0d.js" */
    const char *mime; /* Content-Type, e.g. "text/html; charset=utf-8", "image/svg+xml" */
    const char *etag; /* strong ETag including the quotes, e.g. "\"3f9a1c0d\"" (content hash) */
    const char *file; /* gzip file relative to the read-only LittleFS mount; never a request path */
    uint32_t len;     /* gzip file size */
    bool immutable;   /* true for content-hashed files; false for "/" and "/favicon.svg" */
} web_asset_t;

/** Generated table, sorted by path (strcmp order) so lookups may bisect. */
extern const web_asset_t gw_web_assets[];
/** Number of entries in gw_web_assets (0 for the fallback build). */
extern const size_t gw_web_assets_count;
/** SHA-256 identity of the metadata and gzip bodies; checked against LittleFS at mount. */
extern const char gw_web_assets_id[];

/**
 * Asset for the URL path path[0..len) (no query string), or NULL. Exact match only; "/index.html"
 * is not an alias of "/". Implemented by components/web/static.c (stream C).
 */
const web_asset_t *web_asset_find(const char *path, size_t len);

#ifdef __cplusplus
}
#endif
