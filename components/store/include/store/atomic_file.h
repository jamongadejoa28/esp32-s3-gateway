/*
 * atomic_file.h - crash-safe small-file replace and fallback load (pure C: stdio + POSIX
 * fsync/rename; works on LittleFS VFS and on the host for tests).
 *
 * Write protocol (DESIGN.md §7): write X.tmp -> fflush + fsync -> rename X -> X.bak (if X exists)
 * -> rename X.tmp -> X. A crash at any point leaves at least one of X, X.tmp, X.bak complete.
 * Load order: X, X.tmp, X.bak; the first candidate whose content the caller's `accept` callback
 * approves wins. Writes must run in the persist task on the device.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ATOMIC_PATH_MAX 64 /* path incl. ".tmp"/".bak" suffix must fit */

typedef enum { ATOMIC_SRC_NONE = 0, ATOMIC_SRC_MAIN, ATOMIC_SRC_TMP, ATOMIC_SRC_BAK } atomic_src_t;

/**
 * Atomically replace `path` with data[0..len). Parent directory must exist.
 * @return ESP_OK, ESP_ERR_INVALID_ARG (path too long), ESP_FAIL (I/O error; X unchanged).
 */
esp_err_t atomic_write(const char *path, const void *data, size_t len);

/** Return true to accept a candidate's content (e.g. parses and validates). */
typedef bool (*atomic_accept_fn)(const char *data, size_t len, void *arg);

/**
 * Load the first acceptable candidate into a malloc'd, NUL-terminated buffer (*out; caller
 * free()s). Candidates larger than max_len are skipped. accept may be NULL (accept any readable).
 * *src (optional) tells which file was used.
 * @return ESP_OK, ESP_ERR_NOT_FOUND (no acceptable candidate), ESP_ERR_NO_MEM.
 */
esp_err_t atomic_read(const char *path, size_t max_len, atomic_accept_fn accept, void *arg, char **out,
                      size_t *len, atomic_src_t *src);

/** Remove X, X.tmp and X.bak (missing files are not an error). */
esp_err_t atomic_remove(const char *path);

#ifdef __cplusplus
}
#endif
