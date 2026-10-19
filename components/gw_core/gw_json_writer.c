/*
 * gw_json_writer.c - streaming JSON writer (pure C, host-tested). Contract: gw_core/gw_json_writer.h.
 */
#include "gw_core/gw_json_writer.h"

#include <stdlib.h>
#include <string.h>

enum { JW_FIXED = 0, JW_DYNAMIC = 1, JW_STREAM = 2 };

static void jw_fail(gw_jw_t *w, int err) {
    if (w->err == GW_JW_OK)
        w->err = err;
}

/* Make room for n more bytes in dynamic mode (keeping one byte for the NUL). */
static bool jw_grow(gw_jw_t *w, size_t n) {
    size_t need = w->len + n + 1;
    if (need <= w->cap)
        return true;
    if (need > w->max_cap) {
        jw_fail(w, GW_JW_E_OVERFLOW);
        return false;
    }
    size_t ncap = w->cap ? w->cap : 64;
    while (ncap < need) {
        size_t next = ncap * 2;
        if (next < ncap || next > w->max_cap) {
            next = w->max_cap;
        }
        ncap = next;
    }
    char *nb = realloc(w->buf, ncap);
    if (!nb) {
        jw_fail(w, GW_JW_E_NO_MEM);
        return false;
    }
    w->buf = nb;
    w->cap = ncap;
    return true;
}

static void jw_flush(gw_jw_t *w) {
    if (w->len == 0 || w->err)
        return;
    if (w->sink(w->sink_arg, w->buf, w->len) != 0) {
        jw_fail(w, GW_JW_E_SINK);
        return;
    }
    w->len = 0;
}

static void jw_put(gw_jw_t *w, const char *s, size_t n) {
    if (w->err || n == 0)
        return;
    switch (w->mode) {
    case JW_FIXED:
        if (w->cap == 0 || w->len + n > w->cap - 1) {
            jw_fail(w, GW_JW_E_OVERFLOW);
            return;
        }
        memcpy(w->buf + w->len, s, n);
        w->len += n;
        break;
    case JW_DYNAMIC:
        if (!jw_grow(w, n))
            return;
        memcpy(w->buf + w->len, s, n);
        w->len += n;
        break;
    default: /* stream */
        while (n) {
            size_t room = w->cap - w->len;
            if (room == 0) {
                jw_flush(w);
                if (w->err)
                    return;
                room = w->cap;
            }
            size_t k = n < room ? n : room;
            memcpy(w->buf + w->len, s, k);
            w->len += k;
            s += k;
            n -= k;
        }
        break;
    }
}

static void jw_out(gw_jw_t *w, const char *s, size_t n) {
    if (w->err)
        return;
    jw_put(w, s, n);
    if (!w->err)
        w->total += n;
}

static void jw_c(gw_jw_t *w, char c) {
    jw_out(w, &c, 1);
}

static void jw_init_common(gw_jw_t *w) {
    w->len = 0;
    w->total = 0;
    w->comma = 0;
    w->is_obj = 0;
    w->depth = 0;
    w->after_key = false;
    w->err = GW_JW_OK;
    w->sink = NULL;
    w->sink_arg = NULL;
    w->max_cap = 0;
}

void gw_jw_init_fixed(gw_jw_t *w, char *buf, size_t cap) {
    jw_init_common(w);
    w->mode = JW_FIXED;
    w->buf = buf;
    w->cap = buf ? cap : 0;
    if (buf && cap)
        buf[0] = '\0';
}

int gw_jw_init_dynamic(gw_jw_t *w, size_t initial, size_t max_cap) {
    jw_init_common(w);
    w->mode = JW_DYNAMIC;
    if (initial < 16)
        initial = 16;
    if (max_cap < initial)
        max_cap = initial;
    w->max_cap = max_cap;
    w->buf = malloc(initial);
    w->cap = w->buf ? initial : 0;
    if (!w->buf) {
        w->err = GW_JW_E_NO_MEM;
        return GW_JW_E_NO_MEM;
    }
    w->buf[0] = '\0';
    return GW_JW_OK;
}

void gw_jw_init_stream(gw_jw_t *w, char *buf, size_t cap, gw_jw_sink_t sink, void *arg) {
    jw_init_common(w);
    w->mode = JW_STREAM;
    w->buf = buf;
    w->cap = cap;
    w->sink = sink;
    w->sink_arg = arg;
    if (!buf || cap == 0 || !sink)
        w->err = GW_JW_E_STATE;
}

int gw_jw_finish(gw_jw_t *w) {
    if (!w->err && (w->depth != 0 || w->after_key))
        jw_fail(w, GW_JW_E_STATE);
    if (w->mode == JW_STREAM) {
        if (!w->err)
            jw_flush(w);
    } else if (w->buf && w->cap) {
        size_t at = w->len < w->cap ? w->len : w->cap - 1;
        w->buf[at] = '\0';
    }
    return w->err;
}

int gw_jw_error(const gw_jw_t *w) {
    return w->err;
}

const char *gw_jw_data(const gw_jw_t *w) {
    return w->buf;
}

size_t gw_jw_length(const gw_jw_t *w) {
    return w->total;
}

char *gw_jw_detach(gw_jw_t *w, size_t *len) {
    if (w->mode != JW_DYNAMIC || !w->buf) {
        if (len)
            *len = 0;
        return NULL;
    }
    char *b = w->buf;
    size_t at = w->len < w->cap ? w->len : w->cap - 1;
    b[at] = '\0';
    if (len)
        *len = at;
    w->buf = NULL;
    w->cap = 0;
    w->len = 0;
    return b;
}

void gw_jw_free(gw_jw_t *w) {
    if (w->mode != JW_DYNAMIC)
        return;
    free(w->buf);
    w->buf = NULL;
    w->cap = 0;
    w->len = 0;
}

/* ---- grammar ---- */

static bool top_is_obj(const gw_jw_t *w) {
    return w->depth > 0 && ((w->is_obj >> w->depth) & 1u);
}

/* Emit whatever must precede a value (comma), after checking the grammar. */
static bool jw_value_prefix(gw_jw_t *w) {
    if (w->err)
        return false;
    if (w->depth == 0) {
        if (w->comma & 1u) { /* a second top-level value */
            jw_fail(w, GW_JW_E_STATE);
            return false;
        }
        return true;
    }
    if (top_is_obj(w)) {
        if (!w->after_key) {
            jw_fail(w, GW_JW_E_STATE);
            return false;
        }
        return true;
    }
    if ((w->comma >> w->depth) & 1u)
        jw_c(w, ',');
    return !w->err;
}

static void jw_value_done(gw_jw_t *w) {
    w->comma |= 1u << w->depth;
    w->after_key = false;
}

static void jw_open(gw_jw_t *w, bool obj) {
    if (!jw_value_prefix(w))
        return;
    if (w->depth >= GW_JW_MAX_DEPTH) {
        jw_fail(w, GW_JW_E_STATE);
        return;
    }
    jw_c(w, obj ? '{' : '[');
    if (w->err)
        return;
    jw_value_done(w); /* the container itself is the value at the outer depth */
    w->depth++;
    if (obj)
        w->is_obj |= 1u << w->depth;
    else
        w->is_obj &= ~(1u << w->depth);
    w->comma &= ~(1u << w->depth);
}

static void jw_close(gw_jw_t *w, bool obj) {
    if (w->err)
        return;
    if (w->depth == 0 || top_is_obj(w) != obj || w->after_key) {
        jw_fail(w, GW_JW_E_STATE);
        return;
    }
    jw_c(w, obj ? '}' : ']');
    w->comma &= ~(1u << w->depth);
    w->depth--;
}

void gw_jw_obj_open(gw_jw_t *w) {
    jw_open(w, true);
}
void gw_jw_obj_close(gw_jw_t *w) {
    jw_close(w, true);
}
void gw_jw_arr_open(gw_jw_t *w) {
    jw_open(w, false);
}
void gw_jw_arr_close(gw_jw_t *w) {
    jw_close(w, false);
}

/* ---- strings ---- */

/* Length of a valid UTF-8 sequence at s (n bytes available), or 0 if invalid. */
static size_t utf8_seq_len(const unsigned char *s, size_t n) {
    unsigned char c = s[0];
    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return (n >= 2 && (s[1] & 0xC0) == 0x80) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (n < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80)
            return 0;
        if (c == 0xE0 && s[1] < 0xA0)
            return 0; /* overlong */
        if (c == 0xED && s[1] >= 0xA0)
            return 0; /* UTF-16 surrogate */
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (n < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80)
            return 0;
        if (c == 0xF0 && s[1] < 0x90)
            return 0; /* overlong */
        if (c == 0xF4 && s[1] >= 0x90)
            return 0; /* > U+10FFFF */
        return 4;
    }
    return 0;
}

static void jw_escaped(gw_jw_t *w, const char *str, size_t n) {
    static const char hex[] = "0123456789abcdef";
    const unsigned char *s = (const unsigned char *)str;
    size_t run = 0; /* start of the pending verbatim run */
    jw_c(w, '"');
    size_t i = 0;
    while (i < n && !w->err) {
        unsigned char c = s[i];
        const char *esc = NULL;
        char ubuf[6];
        size_t esc_len = 0;
        if (c == '"') {
            esc = "\\\"";
            esc_len = 2;
        } else if (c == '\\') {
            esc = "\\\\";
            esc_len = 2;
        } else if (c < 0x20) {
            switch (c) {
            case '\n':
                esc = "\\n";
                break;
            case '\r':
                esc = "\\r";
                break;
            case '\t':
                esc = "\\t";
                break;
            case '\b':
                esc = "\\b";
                break;
            case '\f':
                esc = "\\f";
                break;
            default:
                ubuf[0] = '\\';
                ubuf[1] = 'u';
                ubuf[2] = '0';
                ubuf[3] = '0';
                ubuf[4] = hex[c >> 4];
                ubuf[5] = hex[c & 0xF];
                esc = ubuf;
                esc_len = 6;
                break;
            }
            if (esc_len == 0)
                esc_len = 2;
        } else if (c == '/' && i > 0 && s[i - 1] == '<') {
            esc = "\\/";
            esc_len = 2;
        } else if (c >= 0x80) {
            size_t l = utf8_seq_len(s + i, n - i);
            if (l == 0) {
                esc = "\xEF\xBF\xBD"; /* U+FFFD */
                esc_len = 3;
            } else {
                i += l;
                continue; /* valid multibyte: part of the verbatim run */
            }
        } else {
            i++;
            continue;
        }
        jw_out(w, (const char *)s + run, i - run);
        jw_out(w, esc, esc_len);
        i += 1;
        run = i;
    }
    if (run < n)
        jw_out(w, (const char *)s + run, n - run);
    jw_c(w, '"');
}

void gw_jw_key(gw_jw_t *w, const char *key) {
    if (w->err)
        return;
    if (!top_is_obj(w) || w->after_key || !key) {
        jw_fail(w, GW_JW_E_STATE);
        return;
    }
    if ((w->comma >> w->depth) & 1u)
        jw_c(w, ',');
    jw_escaped(w, key, strlen(key));
    jw_c(w, ':');
    if (!w->err)
        w->after_key = true;
}

void gw_jw_strn(gw_jw_t *w, const char *s, size_t n) {
    if (!jw_value_prefix(w))
        return;
    if (!s) {
        jw_out(w, "null", 4);
    } else {
        jw_escaped(w, s, n);
    }
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_str(gw_jw_t *w, const char *s) {
    gw_jw_strn(w, s, s ? strlen(s) : 0);
}

static void jw_digits(gw_jw_t *w, bool neg, uint64_t mag) {
    char tmp[24];
    size_t p = sizeof(tmp);
    do {
        tmp[--p] = (char)('0' + (mag % 10u));
        mag /= 10u;
    } while (mag);
    if (neg)
        tmp[--p] = '-';
    jw_out(w, tmp + p, sizeof(tmp) - p);
}

void gw_jw_int(gw_jw_t *w, int64_t v) {
    if (!jw_value_prefix(w))
        return;
    uint64_t mag = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    jw_digits(w, v < 0, mag);
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_uint(gw_jw_t *w, uint64_t v) {
    if (!jw_value_prefix(w))
        return;
    jw_digits(w, false, v);
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_bool(gw_jw_t *w, bool v) {
    if (!jw_value_prefix(w))
        return;
    if (v)
        jw_out(w, "true", 4);
    else
        jw_out(w, "false", 5);
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_null(gw_jw_t *w) {
    if (!jw_value_prefix(w))
        return;
    jw_out(w, "null", 4);
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_fixed(gw_jw_t *w, int64_t value, uint16_t divisor) {
    unsigned frac_digits;
    switch (divisor) {
    case 1:
        frac_digits = 0;
        break;
    case 10:
        frac_digits = 1;
        break;
    case 100:
        frac_digits = 2;
        break;
    case 1000:
        frac_digits = 3;
        break;
    default:
        jw_fail(w, GW_JW_E_STATE);
        return;
    }
    if (!jw_value_prefix(w))
        return;
    bool neg = value < 0;
    uint64_t mag = neg ? (uint64_t)0 - (uint64_t)value : (uint64_t)value;
    uint64_t ip = mag / divisor, fp = mag % divisor;
    jw_digits(w, neg, ip);
    if (frac_digits) {
        char tmp[4];
        tmp[0] = '.';
        for (unsigned i = frac_digits; i > 0; i--) {
            tmp[i] = (char)('0' + (fp % 10u));
            fp /= 10u;
        }
        jw_out(w, tmp, frac_digits + 1);
    }
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_raw(gw_jw_t *w, const char *json, size_t len) {
    if (!json || len == 0) {
        jw_fail(w, GW_JW_E_STATE);
        return;
    }
    if (!jw_value_prefix(w))
        return;
    jw_out(w, json, len);
    if (!w->err)
        jw_value_done(w);
}

void gw_jw_kstr(gw_jw_t *w, const char *k, const char *s) {
    gw_jw_key(w, k);
    gw_jw_str(w, s);
}
void gw_jw_kint(gw_jw_t *w, const char *k, int64_t v) {
    gw_jw_key(w, k);
    gw_jw_int(w, v);
}
void gw_jw_kuint(gw_jw_t *w, const char *k, uint64_t v) {
    gw_jw_key(w, k);
    gw_jw_uint(w, v);
}
void gw_jw_kbool(gw_jw_t *w, const char *k, bool v) {
    gw_jw_key(w, k);
    gw_jw_bool(w, v);
}
void gw_jw_knull(gw_jw_t *w, const char *k) {
    gw_jw_key(w, k);
    gw_jw_null(w);
}
void gw_jw_kfixed(gw_jw_t *w, const char *k, int64_t value, uint16_t divisor) {
    gw_jw_key(w, k);
    gw_jw_fixed(w, value, divisor);
}
void gw_jw_kobj(gw_jw_t *w, const char *k) {
    gw_jw_key(w, k);
    gw_jw_obj_open(w);
}
void gw_jw_karr(gw_jw_t *w, const char *k) {
    gw_jw_key(w, k);
    gw_jw_arr_open(w);
}
