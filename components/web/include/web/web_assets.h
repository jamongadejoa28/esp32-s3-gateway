/*
 * web_assets.h - the static UI embedded in the app image (pure C, host-safe).
 *
 * Producer (stream G): tools/gen_web_assets.py turns the output of tools/build_web.mjs (stream D)
 * into ${build}/web_assets.c defining exactly `gw_web_assets` and `gw_web_assets_count` below.
 * The CMake hook is cmake/gw_web_assets.cmake (owned by G), included from
 * components/web/CMakeLists.txt: when node and web/ sources are available it adds a custom command
 * (re-run on any change below web/) that builds, gzips and generates the table; otherwise (no node, or
 * GW_WEB_ASSETS=OFF) it compiles components/web/fallback/web_assets_fallback.c, an empty table, and
 * prints a CMake warning: the firmware then serves no UI (API and /ws still work).
 * Consumer (stream C): components/web/static.c implements web_asset_find() and serves the assets.
 *
 * Every entry is gzip-compressed (Content-Encoding: gzip). Paths are the URL paths: "/" is
 * index.html (Cache-Control: no-cache, ETag/If-None-Match -> 304), "/favicon.svg", and the
 * content-hashed bundle files "/assets/<name>.<hash>.<ext>" (immutable: Cache-Control: public,
 * max-age=31536000, immutable). Tables are const (flash rodata) and safe from any task.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *path;  /* URL path, unique, e.g. "/" or "/assets/app.3f9a1c0d.js" */
    const char *mime;  /* Content-Type, e.g. "text/html; charset=utf-8", "image/svg+xml" */
    const char *etag;  /* strong ETag including the quotes, e.g. "\"3f9a1c0d\"" (content hash) */
    const uint8_t *gz; /* gzip -9 body */
    uint32_t len;      /* bytes at gz */
    bool immutable;    /* true for content-hashed files; false for "/" and "/favicon.svg" */
} web_asset_t;

/** Generated table, sorted by path (strcmp order) so lookups may bisect. */
extern const web_asset_t gw_web_assets[];
/** Number of entries in gw_web_assets (0 for the fallback build). */
extern const size_t gw_web_assets_count;

/**
 * Asset for the URL path path[0..len) (no query string), or NULL. Exact match only; "/index.html"
 * is not an alias of "/". Implemented by components/web/static.c (stream C).
 */
const web_asset_t *web_asset_find(const char *path, size_t len);

#ifdef __cplusplus
}
#endif
