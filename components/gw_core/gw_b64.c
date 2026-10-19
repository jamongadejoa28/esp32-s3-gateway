/* gw_b64.h implementation: base64 (RFC 4648 §4, padded), base64url (§5, unpadded) and hex.
 * Pure C, reentrant, no allocation; host-tested (tests/test_gw_b64.py). Decoders are strict:
 * no whitespace, canonical padding only, non-zero trailing bits rejected. */
#include "gw_core/gw_b64.h"

#include <stdbool.h>

static const char k_std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char k_url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Value of c in the alphabet of v, or -1. Branchy but table-free (inputs are short). */
static int b64_val(char c, gw_b64_variant_t v) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (v == GW_B64_STD) {
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
    } else {
        if (c == '-') {
            return 62;
        }
        if (c == '_') {
            return 63;
        }
    }
    return -1;
}

int gw_b64_encode(const void *in, size_t n, char *out, size_t cap, gw_b64_variant_t v) {
    if ((!in && n) || !out || (v != GW_B64_STD && v != GW_B64_URL)) {
        return -1;
    }
    const size_t need = (v == GW_B64_STD) ? GW_B64_STD_LEN(n) : GW_B64_URL_LEN(n);
    if (need >= cap || need > (size_t)INT32_MAX) {
        return -1;
    }
    const char *a = (v == GW_B64_STD) ? k_std : k_url;
    const uint8_t *p = in;
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t x = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) | p[i + 2];
        out[o++] = a[(x >> 18) & 63];
        out[o++] = a[(x >> 12) & 63];
        out[o++] = a[(x >> 6) & 63];
        out[o++] = a[x & 63];
    }
    const size_t rem = n - i;
    if (rem) {
        uint32_t x = (uint32_t)p[i] << 16;
        if (rem == 2) {
            x |= (uint32_t)p[i + 1] << 8;
        }
        out[o++] = a[(x >> 18) & 63];
        out[o++] = a[(x >> 12) & 63];
        if (rem == 2) {
            out[o++] = a[(x >> 6) & 63];
        }
        if (v == GW_B64_STD) {
            if (rem == 1) {
                out[o++] = '=';
            }
            out[o++] = '=';
        }
    }
    out[o] = '\0';
    return (int)o;
}

int gw_b64_decode(const char *in, size_t len, uint8_t *out, size_t cap, gw_b64_variant_t v) {
    if ((!in && len) || (!out && cap) || (v != GW_B64_STD && v != GW_B64_URL) || len > (size_t)INT32_MAX) {
        return -1;
    }
    size_t data_len = len;
    if (v == GW_B64_STD) {
        /* Padded form: total length multiple of 4, at most two trailing '='. */
        if (len % 4) {
            return -1;
        }
        if (len && in[len - 1] == '=') {
            data_len--;
            if (in[len - 2] == '=') {
                data_len--;
            }
        }
    } else if (len % 4 == 1) {
        return -1; /* a single trailing sextet cannot encode a byte */
    }
    const size_t full = data_len / 4;
    const size_t tail = data_len % 4; /* 0, 2 or 3 (1 rejected below) */
    if (tail == 1) {
        return -1;
    }
    const size_t out_len = full * 3 + (tail ? tail - 1 : 0);
    if (out_len > cap) {
        return -1;
    }
    size_t o = 0;
    size_t i = 0;
    for (size_t q = 0; q < full; q++, i += 4) {
        int a = b64_val(in[i], v), b = b64_val(in[i + 1], v), c = b64_val(in[i + 2], v),
            d = b64_val(in[i + 3], v);
        if ((a | b | c | d) < 0) {
            return -1;
        }
        uint32_t x = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[o++] = (uint8_t)(x >> 16);
        out[o++] = (uint8_t)(x >> 8);
        out[o++] = (uint8_t)x;
    }
    if (tail) {
        int a = b64_val(in[i], v), b = b64_val(in[i + 1], v);
        int c = (tail == 3) ? b64_val(in[i + 2], v) : 0;
        if ((a | b | c) < 0) {
            return -1;
        }
        uint32_t x = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
        /* Canonical encoding: bits below the last full byte must be zero. */
        if ((tail == 2 && (x & 0xFFFFu)) || (tail == 3 && (x & 0xFFu))) {
            return -1;
        }
        out[o++] = (uint8_t)(x >> 16);
        if (tail == 3) {
            out[o++] = (uint8_t)(x >> 8);
        }
    }
    /* Any '=' left inside the data part (STD) or anywhere (URL) was rejected by b64_val(). */
    return (int)o;
}

int gw_hex_encode(const void *in, size_t n, char *out, size_t cap) {
    static const char hex[] = "0123456789abcdef";
    if ((!in && n) || !out || n > ((size_t)INT32_MAX - 1) / 2 || cap < 2 * n + 1) {
        return -1;
    }
    const uint8_t *p = in;
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hex[p[i] >> 4];
        out[2 * i + 1] = hex[p[i] & 15];
    }
    out[2 * n] = '\0';
    return (int)(2 * n);
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int gw_hex_decode(const char *in, size_t len, uint8_t *out, size_t cap) {
    if ((!in && len) || (!out && cap) || (len & 1u) || len / 2 > cap || len > (size_t)INT32_MAX) {
        return -1;
    }
    for (size_t i = 0; i < len; i += 2) {
        int hi = hex_val(in[i]), lo = hex_val(in[i + 1]);
        if ((hi | lo) < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(len / 2);
}
