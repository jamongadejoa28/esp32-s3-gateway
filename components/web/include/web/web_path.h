/*
 * web_path.h - pure HTTP string helpers used by the router (host-tested; no IDF).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEB_MAX_PARAMS 3
#define WEB_PARAM_SZ 32

/** Path parameters captured by web_path_match(). Names point into the pattern string. */
typedef struct {
    uint8_t n;
    const char *name[WEB_MAX_PARAMS];
    uint8_t name_len[WEB_MAX_PARAMS];
    char value[WEB_MAX_PARAMS][WEB_PARAM_SZ];
} web_params_t;

/**
 * Match path[0..path_len) (no query string) against a pattern of '/'-separated segments.
 * Literal segments must match exactly (case-sensitive). "{name}" matches one non-empty segment of
 * [A-Za-z0-9._~-] shorter than WEB_PARAM_SZ (no percent-decoding: '%' never matches). No
 * wildcards; trailing slashes are significant. out may be NULL.
 */
bool web_path_match(const char *pattern, const char *path, size_t path_len, web_params_t *out);

/** Value of a captured parameter by name, or NULL. */
const char *web_params_get(const web_params_t *p, const char *name);

/**
 * Percent-decode in[0..len) ('+' -> space) into out (NUL-terminated). Returns the decoded length,
 * or -1 on malformed escapes, embedded NUL, or overflow.
 */
int web_url_decode(const char *in, size_t len, char *out, size_t cap);

/**
 * Find key in a raw query string ("a=1&b=x%20y"; no leading '?') and decode its value into out.
 * A key present without '=' yields "". Returns false if absent or undecodable.
 */
bool web_query_get(const char *query, const char *key, char *out, size_t cap);

/** Extract cookie `name` from a Cookie header value. Returns false if absent or too long. */
bool web_cookie_get(const char *cookie_header, const char *name, char *out, size_t cap);

/**
 * CSRF origin check: `origin` is an Origin header ("http://h[:p]") or a Referer URL. Returns true
 * iff its authority (host[:port], case-insensitive) equals the Host header value. "null" or an
 * unparsable value -> false.
 */
bool web_origin_matches_host(const char *origin, const char *host);

#ifdef __cplusplus
}
#endif
