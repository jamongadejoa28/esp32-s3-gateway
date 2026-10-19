/*
 * gw_crypto.h - crypto primitives used by auth, SNMPv3, OTA and identity derivation.
 *
 * Pure C API (no IDF types). Backend implementations:
 *   - device: gw_core/crypto_psa.c (PSA Crypto API of TF-PSA-Crypto/mbedTLS 4.x in IDF 6.1)
 *   - host tests: gw_core/crypto_openssl.c (OpenSSL 3 libcrypto; excluded from the IDF build)
 * Backend-independent parts (gw_hash_len, gw_ct_equal, gw_secure_zero) are in gw_crypto_util.c and
 * gw_snmp_key_localize() in gw_snmp_key.c; both are pure and built for device and host.
 * Backends must produce bit-identical results (RFC 4231/7914/3414/3826 vectors in tests).
 *
 * Thread-safety: every function is reentrant; streaming contexts are owned by one caller at a
 * time. gw_crypto_init() must have returned GW_CRYPTO_OK before any other call (device: calls
 * psa_crypto_init()). All functions are callable from any task, never from an ISR.
 * Return values: GW_CRYPTO_OK (0) or a negative GW_CRYPTO_E_* code.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GW_CRYPTO_OK 0
#define GW_CRYPTO_E_ARG (-1)         /* NULL pointer, bad length, unknown algorithm */
#define GW_CRYPTO_E_UNSUPPORTED (-2) /* algorithm not compiled into the backend */
#define GW_CRYPTO_E_FAIL (-3)        /* backend failure */
#define GW_CRYPTO_E_NO_MEM (-4)

#define GW_MD5_LEN 16
#define GW_SHA1_LEN 20
#define GW_SHA256_LEN 32
#define GW_HASH_MAX_LEN 32
#define GW_AES128_KEY_LEN 16
#define GW_AES_BLOCK_LEN 16

typedef enum { GW_HASH_MD5 = 0, GW_HASH_SHA1 = 1, GW_HASH_SHA256 = 2 } gw_hash_alg_t;

/** Digest length in bytes of `alg` (0 for an unknown value). */
size_t gw_hash_len(gw_hash_alg_t alg);

/** Initialise the backend. Idempotent; call once at boot before anything else in this header. */
int gw_crypto_init(void);

/* ---- One-shot ---- */

/** out[gw_hash_len(alg)] = HASH(data[0..len)). data may be NULL iff len == 0. */
int gw_hash(gw_hash_alg_t alg, const void *data, size_t len, uint8_t *out);

/** out[gw_hash_len(alg)] = HMAC-alg(key, data). key may be any length (hashed if > block size). */
int gw_hmac(gw_hash_alg_t alg, const uint8_t *key, size_t key_len, const void *data, size_t len,
            uint8_t *out);

/**
 * PBKDF2-HMAC-SHA256 (RFC 8018). iterations >= 1, out_len 1..64. Cost is linear in iterations
 * (device: ~10000 iterations must stay <= 400 ms, measured in Phase 0 spike C).
 */
int gw_pbkdf2_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint8_t *out, size_t out_len);

/**
 * AES-128 in CFB128 mode (full 128-bit feedback, as RFC 3826 SNMPv3 usmAesCfb128Protocol).
 * Any `len` (no padding). `in` and `out` may be the same buffer (the PSA implementation must stage
 * through a scratch buffer: the ESP AES driver rejects in-place partial-block CFB). key/iv: 16 bytes.
 */
int gw_aes128_cfb(bool encrypt, const uint8_t key[GW_AES128_KEY_LEN], const uint8_t iv[GW_AES_BLOCK_LEN],
                  const uint8_t *in, uint8_t *out, size_t len);

/** Fill buf with `len` bytes from the CSPRNG (device: hardware RNG via PSA). */
int gw_random(void *buf, size_t len);

/**
 * Constant-time comparison: returns true iff a[0..len) == b[0..len). Execution time depends only
 * on len. Use for every comparison of secrets (password hashes, CSRF tokens, session hashes, MACs).
 */
bool gw_ct_equal(const void *a, const void *b, size_t len);

/** Overwrite `len` bytes with zeros in a way the compiler cannot elide (secret hygiene). */
void gw_secure_zero(void *p, size_t len);

/**
 * SNMPv3 USM key from a passphrase (RFC 3414 A.2): Ku = HASH(first 1 MiB of pass repeated), then
 * localized key = HASH(Ku || engine_id || Ku). alg GW_HASH_MD5 or GW_HASH_SHA1 (out receives
 * gw_hash_len(alg) bytes: 16 / 20). pass_len >= 1; engine_len 1..32 (SNMP_V3_MAX_ENGINE_ID_LENGTH).
 * Cost: one hash over 1 MiB (~100-300 ms on device): never call from gw_evt or the agent task.
 * On error out is zeroed. Returns GW_CRYPTO_OK or GW_CRYPTO_E_*.
 */
int gw_snmp_key_localize(gw_hash_alg_t alg, const char *pass, size_t pass_len, const uint8_t *engine_id,
                         size_t engine_len, uint8_t *out);

/* ---- Streaming (SNMP over pbuf chains, OTA image hashing, password-to-key expansion) ---- */

/** Opaque streaming context. Allocated by *_begin(), released by *_finish() or *_abort(). */
typedef struct gw_hash_ctx gw_hash_ctx_t;

/** Begin a hash. Returns NULL on bad alg / out of memory. */
gw_hash_ctx_t *gw_hash_begin(gw_hash_alg_t alg);
/** Begin an HMAC with the given key. Returns NULL on bad alg / out of memory. */
gw_hash_ctx_t *gw_hmac_begin(gw_hash_alg_t alg, const uint8_t *key, size_t key_len);
/** Absorb data. On error the context stays valid and must still be finished or aborted. */
int gw_hash_update(gw_hash_ctx_t *ctx, const void *data, size_t len);
/** Write the digest/MAC (gw_hash_len(alg) bytes) to out and free ctx (also on error). */
int gw_hash_finish(gw_hash_ctx_t *ctx, uint8_t *out);
/** Free ctx without producing output. NULL is a no-op. */
void gw_hash_abort(gw_hash_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
