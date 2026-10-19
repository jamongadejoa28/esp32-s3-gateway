/*
 * gw_b64.h - binary-to-text codecs: base64 (RFC 4648 §4), base64url (§5, unpadded) and hex.
 * Pure C, reentrant, no allocation. Used for session tokens/CSRF (url), password records (std),
 * SNMP localized keys and SHA-256 headers (hex).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GW_B64_STD = 0, /* alphabet "+/" with '=' padding (encode pads; decode requires correct padding) */
    GW_B64_URL = 1, /* alphabet "-_" without padding (encode never pads; decode rejects '=') */
} gw_b64_variant_t;

/** Encoded length excluding NUL for n input bytes. */
#define GW_B64_STD_LEN(n) ((((n) + 2) / 3) * 4)
#define GW_B64_URL_LEN(n) ((((n) * 4) + 2) / 3)
/** Maximum decoded length for an encoded string of len chars. */
#define GW_B64_DEC_MAX(len) ((((len) + 3) / 4) * 3)

/**
 * Encode in[0..n) into out (NUL-terminated). cap includes the NUL.
 * Returns the encoded length (excluding NUL) or -1 if cap is too small / bad args.
 */
int gw_b64_encode(const void *in, size_t n, char *out, size_t cap, gw_b64_variant_t v);

/**
 * Decode exactly `len` chars of `in` (no whitespace accepted). Returns the number of bytes written
 * or -1 on an invalid character, bad padding, non-zero trailing bits, or out overflow.
 */
int gw_b64_decode(const char *in, size_t len, uint8_t *out, size_t cap, gw_b64_variant_t v);

/** Lowercase hex encode; cap includes NUL (>= 2n+1). Returns 2n or -1. */
int gw_hex_encode(const void *in, size_t n, char *out, size_t cap);

/** Hex decode (either case) of exactly len chars (even). Returns len/2 or -1. */
int gw_hex_decode(const char *in, size_t len, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
