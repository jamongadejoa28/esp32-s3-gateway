/* gw_crypto.h device backend on the PSA Crypto API (TF-PSA-Crypto in mbedTLS 4.x, IDF 6.1).
 *
 * Must produce results bit-identical to the host backend crypto_openssl.c (same vectors in
 * tests/test_snmpv3_crypto.py; on-device check listed in docs/HW_TEST.md). gw_hash_len,
 * gw_ct_equal and gw_secure_zero live in gw_crypto_util.c and are NOT defined here.
 *
 *  - hashes:  psa_hash_* (ESP SHA engine with software fallback when the engine is busy)
 *  - HMAC:    RFC 2104 on top of psa_hash_* (any key length incl. 0, no key-store slots needed)
 *  - PBKDF2:  psa_key_derivation with PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)
 *  - AES-CFB: psa_cipher with PSA_ALG_CFB, staged through separate in/out chunk buffers (the ESP AES
 *             driver rejects in-place partial-block CFB updates)
 *  - random:  HMAC_DRBG-SHA256 (gw_drbg.c) seeded in gw_crypto_init() with 512 bits read from the
 *             hardware RNG while the SAR ADC entropy source is on (bootloader_random_enable), with
 *             fresh hardware RNG output mixed into every request. psa_generate_random() is NOT used:
 *             in IDF 6.1 it is esp_fill_random() without a DRBG (MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG),
 *             which is only pseudo-random while neither RF nor the SAR ADC source runs - the normal
 *             state of an Ethernet-only gateway (docs/en/api-reference/system/random.rst).
 * Everything is reentrant; contexts are heap-allocated (internal RAM, < 512 bytes). */
#include <stdlib.h>
#include <string.h>

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_drbg.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

static const char *TAG = "gw_crypto";

#define HMAC_BLOCK 64 /* MD5, SHA-1 and SHA-256 all use 64-byte blocks */
#define CFB_CHUNK 64  /* block multiple */

struct gw_hash_ctx {
    gw_hash_alg_t alg;
    bool hmac;
    psa_hash_operation_t op;
    uint8_t opad_key[HMAC_BLOCK]; /* K' ^ opad (HMAC only) */
};

static psa_algorithm_t psa_alg(gw_hash_alg_t alg) {
    switch (alg) {
    case GW_HASH_MD5:
        return PSA_ALG_MD5;
    case GW_HASH_SHA1:
        return PSA_ALG_SHA_1;
    case GW_HASH_SHA256:
        return PSA_ALG_SHA_256;
    default:
        return 0;
    }
}

static int map_status(psa_status_t st) {
    switch (st) {
    case PSA_SUCCESS:
        return GW_CRYPTO_OK;
    case PSA_ERROR_INVALID_ARGUMENT:
        return GW_CRYPTO_E_ARG;
    case PSA_ERROR_NOT_SUPPORTED:
        return GW_CRYPTO_E_UNSUPPORTED;
    case PSA_ERROR_INSUFFICIENT_MEMORY:
        return GW_CRYPTO_E_NO_MEM;
    default:
        return GW_CRYPTO_E_FAIL;
    }
}

/* ---------------------------------------------------------------- DRBG state (gw_random) */

#define DRBG_SEED_BYTES 64 /* 512 bits: entropy input + nonce */
#define DRBG_ADD_BYTES 16  /* fresh hardware RNG per request (true entropy whenever RF runs) */

static gw_drbg_t s_drbg;
static SemaphoreHandle_t s_drbg_mtx;
static StaticSemaphore_t s_drbg_mtx_buf;

/* Seed while the SAR ADC entropy source is on. Must run before Wi-Fi/RF and before any ADC use
 * (bootloader_random.h); app_main calls gw_crypto_init() at step 3, before net_init(). */
static int drbg_seed(void) {
    uint8_t seed[DRBG_SEED_BYTES];
    struct {
        uint8_t mac[6];
        int64_t t_us;
        char tag[12];
    } pers = {.tag = "mestio-gw"};
    (void)esp_read_mac(pers.mac, ESP_MAC_BASE);
    bootloader_random_enable();
    esp_fill_random(seed, sizeof(seed)); /* paced by the driver to the RNG's entropy rate */
    bootloader_random_disable();
    pers.t_us = esp_timer_get_time();
    int rc = gw_drbg_instantiate(&s_drbg, seed, sizeof(seed), (const uint8_t *)&pers, sizeof(pers));
    gw_secure_zero(seed, sizeof(seed));
    return rc;
}

int gw_crypto_init(void) {
    psa_status_t st = psa_crypto_init(); /* idempotent */
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)st);
        return GW_CRYPTO_E_FAIL;
    }
    if (!s_drbg_mtx) {
        s_drbg_mtx = xSemaphoreCreateMutexStatic(&s_drbg_mtx_buf);
        int rc = drbg_seed();
        if (rc != GW_CRYPTO_OK) {
            ESP_LOGE(TAG, "DRBG seeding failed: %d", rc);
            gw_drbg_wipe(&s_drbg);
            return rc;
        }
    }
    return GW_CRYPTO_OK;
}

/* ---------------------------------------------------------------- streaming hash / HMAC */

gw_hash_ctx_t *gw_hash_begin(gw_hash_alg_t alg) {
    psa_algorithm_t a = psa_alg(alg);
    if (!a) {
        return NULL;
    }
    gw_hash_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->alg = alg;
    c->op = psa_hash_operation_init();
    if (psa_hash_setup(&c->op, a) != PSA_SUCCESS) {
        psa_hash_abort(&c->op);
        free(c);
        return NULL;
    }
    return c;
}

gw_hash_ctx_t *gw_hmac_begin(gw_hash_alg_t alg, const uint8_t *key, size_t key_len) {
    psa_algorithm_t a = psa_alg(alg);
    if (!a || (!key && key_len)) {
        return NULL;
    }
    gw_hash_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->alg = alg;
    c->hmac = true;
    c->op = psa_hash_operation_init();

    /* K' = key (<= block) or HASH(key), zero-padded to the block size. */
    uint8_t k[HMAC_BLOCK] = {0};
    psa_status_t st = PSA_SUCCESS;
    if (key_len > HMAC_BLOCK) {
        size_t got = 0;
        st = psa_hash_compute(a, key, key_len, k, sizeof(k), &got);
    } else if (key_len) {
        memcpy(k, key, key_len);
    }
    uint8_t ipad[HMAC_BLOCK];
    for (size_t i = 0; i < HMAC_BLOCK; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        c->opad_key[i] = (uint8_t)(k[i] ^ 0x5cu);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_setup(&c->op, a);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&c->op, ipad, sizeof(ipad));
    }
    mbedtls_platform_zeroize(k, sizeof(k));
    mbedtls_platform_zeroize(ipad, sizeof(ipad));
    if (st != PSA_SUCCESS) {
        gw_hash_abort(c);
        return NULL;
    }
    return c;
}

int gw_hash_update(gw_hash_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || (!data && len)) {
        return GW_CRYPTO_E_ARG;
    }
    if (!len) {
        return GW_CRYPTO_OK;
    }
    return map_status(psa_hash_update(&ctx->op, data, len));
}

int gw_hash_finish(gw_hash_ctx_t *ctx, uint8_t *out) {
    if (!ctx) {
        return GW_CRYPTO_E_ARG;
    }
    int rc = GW_CRYPTO_E_ARG;
    if (out) {
        const size_t want = gw_hash_len(ctx->alg);
        uint8_t inner[GW_HASH_MAX_LEN];
        size_t got = 0;
        psa_status_t st = psa_hash_finish(&ctx->op, inner, sizeof(inner), &got);
        if (st == PSA_SUCCESS && got == want && ctx->hmac) {
            /* outer = HASH(K' ^ opad || inner) */
            ctx->op = psa_hash_operation_init();
            st = psa_hash_setup(&ctx->op, psa_alg(ctx->alg));
            if (st == PSA_SUCCESS) {
                st = psa_hash_update(&ctx->op, ctx->opad_key, sizeof(ctx->opad_key));
            }
            if (st == PSA_SUCCESS) {
                st = psa_hash_update(&ctx->op, inner, want);
            }
            if (st == PSA_SUCCESS) {
                st = psa_hash_finish(&ctx->op, inner, sizeof(inner), &got);
            }
        }
        if (st == PSA_SUCCESS && got == want) {
            memcpy(out, inner, want);
            rc = GW_CRYPTO_OK;
        } else {
            rc = st == PSA_SUCCESS ? GW_CRYPTO_E_FAIL : map_status(st);
        }
        mbedtls_platform_zeroize(inner, sizeof(inner));
    }
    gw_hash_abort(ctx);
    return rc;
}

void gw_hash_abort(gw_hash_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    psa_hash_abort(&ctx->op); /* safe on an inactive/finished operation */
    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    free(ctx);
}

/* ---------------------------------------------------------------- one-shot */

int gw_hash(gw_hash_alg_t alg, const void *data, size_t len, uint8_t *out) {
    if ((!data && len) || !out) {
        return GW_CRYPTO_E_ARG;
    }
    psa_algorithm_t a = psa_alg(alg);
    if (!a) {
        return GW_CRYPTO_E_ARG;
    }
    static const uint8_t empty[1];
    size_t got = 0;
    psa_status_t st = psa_hash_compute(a, len ? data : empty, len, out, gw_hash_len(alg), &got);
    if (st != PSA_SUCCESS) {
        return map_status(st);
    }
    return got == gw_hash_len(alg) ? GW_CRYPTO_OK : GW_CRYPTO_E_FAIL;
}

int gw_hmac(gw_hash_alg_t alg, const uint8_t *key, size_t key_len, const void *data, size_t len,
            uint8_t *out) {
    if ((!data && len) || !out || (!key && key_len)) {
        return GW_CRYPTO_E_ARG;
    }
    if (!psa_alg(alg)) {
        return GW_CRYPTO_E_ARG;
    }
    gw_hash_ctx_t *c = gw_hmac_begin(alg, key, key_len);
    if (!c) {
        return GW_CRYPTO_E_NO_MEM;
    }
    int rc = gw_hash_update(c, data, len);
    int frc = gw_hash_finish(c, out);
    return rc != GW_CRYPTO_OK ? rc : frc;
}

int gw_pbkdf2_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint8_t *out, size_t out_len) {
    if ((!pass && pass_len) || (!salt && salt_len) || !out || iterations < 1 || out_len < 1 || out_len > 64) {
        return GW_CRYPTO_E_ARG;
    }
    static const uint8_t empty[1];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iterations);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt_len ? salt : empty,
                                            salt_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pass_len ? pass : empty,
                                            pass_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&op, out, out_len);
    }
    psa_key_derivation_abort(&op);
    if (st != PSA_SUCCESS) {
        mbedtls_platform_zeroize(out, out_len);
        ESP_LOGE(TAG, "pbkdf2 failed: %d", (int)st);
        return map_status(st);
    }
    return GW_CRYPTO_OK;
}

int gw_aes128_cfb(bool encrypt, const uint8_t key[GW_AES128_KEY_LEN], const uint8_t iv[GW_AES_BLOCK_LEN],
                  const uint8_t *in, uint8_t *out, size_t len) {
    if (!key || !iv || ((!in || !out) && len)) {
        return GW_CRYPTO_E_ARG;
    }
    if (!len) {
        return GW_CRYPTO_OK;
    }
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&attr, PSA_ALG_CFB);
    psa_set_key_usage_flags(&attr, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_bits(&attr, GW_AES128_KEY_LEN * 8);
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st = psa_import_key(&attr, key, GW_AES128_KEY_LEN, &id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        return map_status(st);
    }

    psa_cipher_operation_t op = psa_cipher_operation_init();
    st = encrypt ? psa_cipher_encrypt_setup(&op, id, PSA_ALG_CFB)
                 : psa_cipher_decrypt_setup(&op, id, PSA_ALG_CFB);
    if (st == PSA_SUCCESS) {
        st = psa_cipher_set_iv(&op, iv, GW_AES_BLOCK_LEN);
    }
    uint8_t ib[CFB_CHUNK];
    uint8_t ob[CFB_CHUNK + GW_AES_BLOCK_LEN];
    size_t done = 0;
    size_t written = 0;
    while (st == PSA_SUCCESS && done < len) {
        size_t n = len - done < CFB_CHUNK ? len - done : CFB_CHUNK;
        size_t got = 0;
        memcpy(ib, in + done, n); /* in and out may alias: stage the input first */
        st = psa_cipher_update(&op, ib, n, ob, sizeof(ob), &got);
        if (st == PSA_SUCCESS) {
            if (written + got > len) {
                st = PSA_ERROR_CORRUPTION_DETECTED;
                break;
            }
            memcpy(out + written, ob, got);
            written += got;
            done += n;
        }
    }
    if (st == PSA_SUCCESS) {
        size_t got = 0;
        st = psa_cipher_finish(&op, ob, sizeof(ob), &got);
        if (st == PSA_SUCCESS) {
            if (written + got != len) {
                st = PSA_ERROR_CORRUPTION_DETECTED;
            } else {
                memcpy(out + written, ob, got);
            }
        }
    }
    psa_cipher_abort(&op);
    psa_destroy_key(id);
    mbedtls_platform_zeroize(ib, sizeof(ib));
    mbedtls_platform_zeroize(ob, sizeof(ob));
    if (st != PSA_SUCCESS) {
        mbedtls_platform_zeroize(out, len);
        return map_status(st);
    }
    return GW_CRYPTO_OK;
}

int gw_random(void *buf, size_t len) {
    if (!buf && len) {
        return GW_CRYPTO_E_ARG;
    }
    if (!len) {
        return GW_CRYPTO_OK;
    }
    if (!s_drbg_mtx) {
        return GW_CRYPTO_E_FAIL; /* gw_crypto_init() not run: never hand out unseeded bytes */
    }
    uint8_t add[DRBG_ADD_BYTES + sizeof(int64_t)];
    esp_fill_random(add, DRBG_ADD_BYTES);
    const int64_t t_us = esp_timer_get_time();
    memcpy(add + DRBG_ADD_BYTES, &t_us, sizeof(t_us));
    int rc = GW_CRYPTO_OK;
    xSemaphoreTake(s_drbg_mtx, portMAX_DELAY);
    if (gw_drbg_needs_reseed(&s_drbg) && s_drbg.reseed_counter) {
        uint8_t ent[GW_DRBG_SEED_MIN];
        esp_fill_random(ent, sizeof(ent));
        rc = gw_drbg_reseed(&s_drbg, ent, sizeof(ent), NULL, 0);
        gw_secure_zero(ent, sizeof(ent));
    }
    uint8_t *out = buf;
    while (rc == GW_CRYPTO_OK && len) {
        const size_t n = len > GW_DRBG_MAX_REQUEST ? GW_DRBG_MAX_REQUEST : len;
        rc = gw_drbg_generate(&s_drbg, out, n, add, sizeof(add));
        out += n;
        len -= n;
    }
    xSemaphoreGive(s_drbg_mtx);
    gw_secure_zero(add, sizeof(add));
    if (rc != GW_CRYPTO_OK) {
        gw_secure_zero(buf, (size_t)(out - (uint8_t *)buf) + len);
        return rc == GW_CRYPTO_E_ARG ? GW_CRYPTO_E_FAIL : rc;
    }
    return GW_CRYPTO_OK;
}
