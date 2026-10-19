/*
 * evlog_core.h - pure two-file record ring behind store/eventlog.h (store-internal, host-tested).
 *
 * A log is two files <dir>/<name>.0 and <name>.1 of 32-byte records appended in seq order. The
 * file holding the highest seq is active; when it reaches EVLOG_RECS_PER_FILE the other file is
 * truncated and becomes active. Torn tails (size not a multiple of 32) are cut at open.
 * Not thread-safe: eventlog.c serialises file access with a mutex.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_err.h"
#include "store/eventlog.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EVLOG_PATH_SZ 128

typedef struct {
    char path[2][EVLOG_PATH_SZ];
    uint32_t count[2]; /* records in each file */
    uint8_t active;
    uint32_t last_seq; /* highest seq stored in the files (0 = none) */
} evlog_files_t;

/** Bind to <dir>/<name>.0|1, repair torn tails and recover active file / last seq. Missing files
 * are fine (empty log). ESP_ERR_INVALID_ARG if the paths do not fit. */
esp_err_t evlog_files_open(evlog_files_t *f, const char *dir, const char *name);

/** Append records (ascending seq), rotating as needed. ESP_FAIL on I/O error (counts resynced). */
esp_err_t evlog_files_append(evlog_files_t *f, const evlog_rec_t *recs, size_t n);

/** Delete both files and reset the counters (last_seq kept). */
esp_err_t evlog_files_clear(evlog_files_t *f);

/** True iff r matches filter f (NULL = any). */
bool evlog_filter_match(const evlog_filter_t *f, const evlog_rec_t *r);

/**
 * Newest-first query over the RAM tail (ram[0..n_ram), ASCENDING seq, contiguous newest records,
 * may include records not yet on flash) and the files (f may be NULL). Semantics of evlog_query().
 */
size_t evlog_core_query(const evlog_files_t *f, const evlog_rec_t *ram, size_t n_ram, uint32_t before,
                        size_t limit, const evlog_filter_t *flt, evlog_rec_t *out, uint32_t *next);

#ifdef __cplusplus
}
#endif
