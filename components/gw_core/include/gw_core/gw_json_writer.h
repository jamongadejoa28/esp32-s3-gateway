/*
 * gw_json_writer.h - allocation-light streaming JSON writer (pure C, host-safe).
 *
 * Three output modes:
 *   fixed   - caller buffer; overflow sets GW_JW_E_OVERFLOW (sticky) and drops further output.
 *   dynamic - malloc'd buffer grown by doubling up to max_cap (device: SPIRAM_USE_MALLOC places
 *             blocks > 4 KB in PSRAM). Result obtained with gw_jw_data()/gw_jw_detach().
 *   stream  - caller scratch buffer flushed through a sink callback whenever it fills and at
 *             gw_jw_finish(); used with httpd_resp_send_chunk() (web) and ws frame building.
 *
 * Grammar is enforced: values inside objects must be preceded by gw_jw_key(); commas are inserted
 * automatically; misuse sets GW_JW_E_STATE. Errors are sticky: after the first error every call
 * is a no-op and gw_jw_finish() returns that error.
 *
 * Strings: input must be UTF-8. '"', '\\' and U+0000..U+001F are escaped (\n, \r, \t, \b, \f or
 * \u00XX); '/' is not escaped except in the sequence "</" which is written as "<\/". Invalid UTF-8
 * bytes are replaced by U+FFFD so the output is always valid JSON.
 *
 * Numbers: integers are written exactly; gw_jw_fixed() writes scaled register values without
 * floating point (235, 10 -> 23.5). No floating-point API by design.
 *
 * Thread-safety: a writer instance belongs to one task.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GW_JW_MAX_DEPTH 16

#define GW_JW_OK 0
#define GW_JW_E_OVERFLOW (-1) /* fixed buffer full or dynamic max_cap reached */
#define GW_JW_E_NO_MEM (-2)
#define GW_JW_E_SINK (-3)  /* sink returned non-zero */
#define GW_JW_E_STATE (-4) /* grammar misuse (value without key, unbalanced close, depth) */

/** Sink for stream mode. Return 0 on success; any other value aborts the writer (GW_JW_E_SINK). */
typedef int (*gw_jw_sink_t)(void *arg, const char *data, size_t len);

/** Writer state. Treat all fields as private; stack-allocate and use the functions below. */
typedef struct gw_jw {
    char *buf;
    size_t len;     /* bytes currently in buf */
    size_t cap;     /* capacity of buf */
    size_t max_cap; /* dynamic mode growth limit */
    size_t total;   /* total bytes produced (stream mode: including flushed bytes) */
    gw_jw_sink_t sink;
    void *sink_arg;
    uint32_t comma;  /* bit d: a value was already written at depth d */
    uint32_t is_obj; /* bit d: container at depth d is an object */
    uint8_t depth;
    uint8_t mode; /* 0 fixed, 1 dynamic, 2 stream */
    bool after_key;
    int err;
} gw_jw_t;

/** Fixed mode. One byte of cap is reserved for the terminating NUL written by gw_jw_finish(). */
void gw_jw_init_fixed(gw_jw_t *w, char *buf, size_t cap);
/** Dynamic mode. initial >= 64 recommended. Returns GW_JW_OK or GW_JW_E_NO_MEM. */
int gw_jw_init_dynamic(gw_jw_t *w, size_t initial, size_t max_cap);
/** Stream mode. buf/cap is scratch space (>= 64 bytes); sink receives every full chunk. */
void gw_jw_init_stream(gw_jw_t *w, char *buf, size_t cap, gw_jw_sink_t sink, void *arg);

/**
 * Finish: verifies all containers are closed, NUL-terminates (fixed/dynamic) or flushes the
 * remaining bytes to the sink (stream; the sink is NOT called with len 0). Returns the sticky error.
 */
int gw_jw_finish(gw_jw_t *w);
/** Sticky error so far (GW_JW_OK if none). */
int gw_jw_error(const gw_jw_t *w);
/** Output buffer (fixed/dynamic; NUL-terminated after gw_jw_finish()). */
const char *gw_jw_data(const gw_jw_t *w);
/** Bytes produced in total (excluding the NUL). */
size_t gw_jw_length(const gw_jw_t *w);
/** Dynamic mode: transfer ownership of the buffer to the caller (free() it). Writer becomes empty. */
char *gw_jw_detach(gw_jw_t *w, size_t *len);
/** Dynamic mode: free the buffer. No-op for other modes. Safe to call twice. */
void gw_jw_free(gw_jw_t *w);

/* ---- Structure ---- */
void gw_jw_obj_open(gw_jw_t *w);
void gw_jw_obj_close(gw_jw_t *w);
void gw_jw_arr_open(gw_jw_t *w);
void gw_jw_arr_close(gw_jw_t *w);
/** Object member name; must be followed by exactly one value or container. */
void gw_jw_key(gw_jw_t *w, const char *key);

/* ---- Values ---- */
void gw_jw_str(gw_jw_t *w, const char *s); /* NULL writes null */
void gw_jw_strn(gw_jw_t *w, const char *s, size_t n);
void gw_jw_int(gw_jw_t *w, int64_t v);
void gw_jw_uint(gw_jw_t *w, uint64_t v);
void gw_jw_bool(gw_jw_t *w, bool v);
void gw_jw_null(gw_jw_t *w);
/**
 * Fixed-point: writes value/divisor with exactly log10(divisor) fraction digits.
 * divisor must be 1, 10, 100 or 1000 (else GW_JW_E_STATE). (235,10)->23.5 (-5,10)->-0.5 (7,1)->7
 */
void gw_jw_fixed(gw_jw_t *w, int64_t value, uint16_t divisor);
/** Insert pre-serialized JSON text verbatim as one value (caller guarantees validity). */
void gw_jw_raw(gw_jw_t *w, const char *json, size_t len);

/* ---- key + value shorthands ---- */
void gw_jw_kstr(gw_jw_t *w, const char *k, const char *s);
void gw_jw_kint(gw_jw_t *w, const char *k, int64_t v);
void gw_jw_kuint(gw_jw_t *w, const char *k, uint64_t v);
void gw_jw_kbool(gw_jw_t *w, const char *k, bool v);
void gw_jw_knull(gw_jw_t *w, const char *k);
void gw_jw_kfixed(gw_jw_t *w, const char *k, int64_t value, uint16_t divisor);
void gw_jw_kobj(gw_jw_t *w, const char *k); /* key + obj_open */
void gw_jw_karr(gw_jw_t *w, const char *k); /* key + arr_open */

#ifdef __cplusplus
}
#endif
