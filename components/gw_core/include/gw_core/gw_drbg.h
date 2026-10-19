/*
 * gw_drbg.h - HMAC_DRBG with HMAC-SHA-256 (NIST SP 800-90A Rev.1 §10.1.2), no prediction
 * resistance, built on gw_hmac_begin()/gw_hash_update()/gw_hash_finish() (gw_crypto.h).
 *
 * Why: on the ESP32-S3 the hardware RNG is only a TRUE RNG while an entropy source runs (RF, or
 * the SAR ADC between bootloader_random_enable/disable). An Ethernet-only gateway normally has
 * neither, so gw_random() (crypto_psa.c) draws from this DRBG, seeded once at boot with >= 384
 * bits read while the SAR ADC source is on, and mixes fresh hardware RNG output into every
 * request as additional input (true entropy whenever the recovery AP has the RF on).
 *
 * Pure C (host-tested against an independent Python implementation, tests/test_snmpv3_crypto.py).
 * Not thread-safe: the device wrapper serializes calls.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GW_DRBG_OUTLEN 32               /* SHA-256 */
#define GW_DRBG_SEED_MIN 32             /* entropy bytes accepted by instantiate/reseed */
#define GW_DRBG_MAX_REQUEST 65536u      /* SP 800-90A: max_number_of_bits_per_request = 2^19 */
#define GW_DRBG_RESEED_INTERVAL 100000u /* caller reseeds before this (SP 800-90A allows 2^48) */

typedef struct {
    uint8_t k[GW_DRBG_OUTLEN];
    uint8_t v[GW_DRBG_OUTLEN];
    uint32_t reseed_counter; /* 0 = not instantiated */
} gw_drbg_t;

/** Instantiate from entropy (>= GW_DRBG_SEED_MIN bytes, includes the nonce) and an optional
 *  personalization string. Returns GW_CRYPTO_OK or GW_CRYPTO_E_*. */
int gw_drbg_instantiate(gw_drbg_t *d, const uint8_t *entropy, size_t entropy_len, const uint8_t *pers,
                        size_t pers_len);
/** Reseed with entropy (>= GW_DRBG_SEED_MIN bytes) and optional additional input. */
int gw_drbg_reseed(gw_drbg_t *d, const uint8_t *entropy, size_t entropy_len, const uint8_t *add, size_t add_len);
/** Generate out_len (1..GW_DRBG_MAX_REQUEST) bytes with optional additional input.
 *  GW_CRYPTO_E_ARG if not instantiated or the reseed interval is exhausted (out is zeroed). */
int gw_drbg_generate(gw_drbg_t *d, uint8_t *out, size_t out_len, const uint8_t *add, size_t add_len);
/** True when the caller should reseed (counter beyond GW_DRBG_RESEED_INTERVAL). */
bool gw_drbg_needs_reseed(const gw_drbg_t *d);
/** Wipe the state (uninstantiate). */
void gw_drbg_wipe(gw_drbg_t *d);

#ifdef __cplusplus
}
#endif
