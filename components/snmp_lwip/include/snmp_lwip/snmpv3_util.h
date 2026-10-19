/*
 * snmpv3_util.h - pure SNMPv3 USM helpers shared by the device crypto backend (snmpv3_psa.c) and the
 * host tests (tests/snmp_host/snmpv3_host.c, OpenSSL backend), so the RFC 3826 IV/key derivation
 * that both use is one piece of code (pure C, no IDF/lwIP headers; static inline, no link
 * dependency).
 *
 * Also declares the on-target known-answer self-test of the lwIP crypto hooks
 * (snmpv3_auth/snmpv3_crypt/snmpv3_password_to_key_*), implemented in snmpv3_selftest.c
 * (device only; snmp_gw runs it at boot in debug builds, docs/HW_TEST.md).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SNMPV3_AES_KEY_LEN 16   /* usmAesCfb128Protocol: AES-128 */
#define SNMPV3_AES_IV_LEN 16    /* one AES block */
#define SNMPV3_PRIV_PARAM_LEN 8 /* msgPrivacyParameters (the "salt") */
#define SNMPV3_HMAC96_LEN 12    /* HMAC-MD5-96 / HMAC-SHA-96 transmitted digest length */

/**
 * RFC 3826 §3.1.2.1: IV = msgAuthoritativeEngineBoots (32-bit big-endian) ||
 * msgAuthoritativeEngineTime (32-bit big-endian) || msgPrivacyParameters (8 octets).
 */
static inline void snmpv3_aes_iv(uint32_t engine_boots, uint32_t engine_time,
                                 const uint8_t priv_param[SNMPV3_PRIV_PARAM_LEN], uint8_t iv[SNMPV3_AES_IV_LEN]) {
    iv[0] = (uint8_t)(engine_boots >> 24);
    iv[1] = (uint8_t)(engine_boots >> 16);
    iv[2] = (uint8_t)(engine_boots >> 8);
    iv[3] = (uint8_t)engine_boots;
    iv[4] = (uint8_t)(engine_time >> 24);
    iv[5] = (uint8_t)(engine_time >> 16);
    iv[6] = (uint8_t)(engine_time >> 8);
    iv[7] = (uint8_t)engine_time;
    memcpy(&iv[8], priv_param, SNMPV3_PRIV_PARAM_LEN);
}

/**
 * RFC 3826 §3.1.2.1: the AES-128 encryption key is the first 128 bits of the localized privacy key
 * (localized with the user's authentication hash, RFC 3414 A.2). Returns false when the localized
 * key is shorter than 16 octets (e.g. none).
 */
static inline bool snmpv3_aes_key(const uint8_t *localized, size_t localized_len, uint8_t key[SNMPV3_AES_KEY_LEN]) {
    if (localized == NULL || localized_len < SNMPV3_AES_KEY_LEN) {
        return false;
    }
    memcpy(key, localized, SNMPV3_AES_KEY_LEN);
    return true;
}

/**
 * [device] Known-answer self-test of the lwIP SNMPv3 crypto hooks on the real backend: HMAC-SHA-96
 * and HMAC-MD5-96 (snmpv3_auth) over a two-pbuf chain, AES-128-CFB (snmpv3_crypt, RFC 3826 IV)
 * encrypt + decrypt over a chain with a chunk crossing the pbuf boundary, DES rejected with ERR_ARG,
 * and snmpv3_password_to_key_{sha,md5} against RFC 3414 A.3 ("maplesyrup"). The vectors are
 * cross-checked on the host by tests/test_snmp_crypto_kat.py. Takes ~0.3-0.6 s (two 1 MiB
 * password expansions). Returns 0 when every check passed, else the number of failed checks
 * (each logged). Call from the SNMP agent task.
 */
int snmpv3_selftest(void);

#ifdef __cplusplus
}
#endif
