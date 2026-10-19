/* SNMPv3 crypto backend for lwIP on PSA Crypto (TF-PSA-Crypto / mbedTLS 4.x).
 *
 * Replaces upstream snmpv3_mbedtls.c, whose cipher/md5/sha1 APIs are private in mbedTLS 4 and
 * whose DES support no longer exists. Implements the hooks declared in upstream snmpv3_priv.h
 * (snmpv3_auth, snmpv3_crypt) and lwip/apps/snmpv3.h (snmpv3_password_to_key_{md5,sha}).
 *
 * Supported: HMAC-MD5-96, HMAC-SHA-96 (RFC 3414), AES-128-CFB (RFC 3826). DES -> ERR_ARG.
 * All functions are reentrant (no static state); lwIP calls auth/crypt only from the SNMP
 * agent thread. Keys are imported as volatile PSA keys and destroyed before returning; plaintext
 * staging buffers are wiped with mbedtls_platform_zeroize(). Password-to-key delegates to gw_crypto
 * (snmp_lwip PRIV_REQUIRES gw_core; its public header stays gw_core-free). */
#include <stdbool.h>
#include <string.h>

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && LWIP_SNMP_V3 && LWIP_SNMP_V3_CRYPTO && !LWIP_SNMP_V3_MBEDTLS

#include "gw_core/gw_crypto.h"
#include "lwip/apps/snmpv3.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "snmp_lwip/snmpv3_util.h"
#include "snmp_pbuf_stream.h"
#include "snmpv3_priv.h"

#define CHUNK_LEN 64

/* Copies n bytes from the stream position into buf and advances the stream. */
static err_t stream_read(struct snmp_pbuf_stream *s, u8_t *buf, u16_t n) {
    if (s->length < n || pbuf_copy_partial(s->pbuf, buf, n, s->offset) != n) {
        return ERR_BUF;
    }
    s->offset += n;
    s->length -= n;
    return ERR_OK;
}

static psa_status_t import_key(psa_key_type_t type, psa_algorithm_t alg, psa_key_usage_t usage,
                               const u8_t *key, size_t key_len, mbedtls_svc_key_id_t *id) {
    psa_status_t st = psa_crypto_init(); /* idempotent; IDF also runs it at startup */
    if (st != PSA_SUCCESS) {
        return st;
    }
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_type(&attr, type);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, (size_t)key_len * 8);
    st = psa_import_key(&attr, key, key_len, id);
    psa_reset_key_attributes(&attr);
    return st;
}

err_t snmpv3_auth(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, snmpv3_auth_algo_t algo,
                  u8_t *hmac_out) {
    psa_algorithm_t hash;
    size_t key_len;
    if (algo == SNMP_V3_AUTH_ALGO_MD5) {
        hash = PSA_ALG_MD5;
        key_len = SNMP_V3_MD5_LEN;
    } else if (algo == SNMP_V3_AUTH_ALGO_SHA) {
        hash = PSA_ALG_SHA_1;
        key_len = SNMP_V3_SHA_LEN;
    } else {
        return ERR_ARG;
    }

    const psa_algorithm_t alg = PSA_ALG_HMAC(hash);
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    if (import_key(PSA_KEY_TYPE_HMAC, alg, PSA_KEY_USAGE_SIGN_MESSAGE, key, key_len, &id) != PSA_SUCCESS) {
        return ERR_ARG;
    }

    /* Work on a copy so the caller's stream position is unchanged (upstream semantics). */
    struct snmp_pbuf_stream rd;
    snmp_pbuf_stream_init(&rd, stream->pbuf, stream->offset, stream->length);

    err_t err = ERR_ARG;
    u8_t buf[CHUNK_LEN];
    size_t mac_len = 0;
    psa_mac_operation_t op = psa_mac_operation_init();
    if (psa_mac_sign_setup(&op, id, alg) != PSA_SUCCESS) {
        goto out;
    }
    for (u16_t done = 0; done < length;) {
        u16_t n = (u16_t)LWIP_MIN((u16_t)sizeof(buf), (u16_t)(length - done));
        if (stream_read(&rd, buf, n) != ERR_OK || psa_mac_update(&op, buf, n) != PSA_SUCCESS) {
            goto out;
        }
        done = (u16_t)(done + n);
    }
    /* lwIP's buffer holds the full digest (20 bytes); it transmits/compares the first 12. */
    if (psa_mac_sign_finish(&op, hmac_out, key_len, &mac_len) == PSA_SUCCESS && mac_len == key_len) {
        err = ERR_OK;
    }

out:
    psa_mac_abort(&op);
    psa_destroy_key(id);
    return err;
}

err_t snmpv3_crypt(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, const u8_t *priv_param,
                   const u32_t engine_boots, const u32_t engine_time, snmpv3_priv_algo_t algo,
                   snmpv3_priv_mode_t mode) {
    if (algo != SNMP_V3_PRIV_ALGO_AES) {
        return ERR_ARG; /* DES is not available in mbedTLS 4 / PSA */
    }

    /* RFC 3826 3.1.2.1 IV and AES key: shared, host-tested helpers (snmp_lwip/snmpv3_util.h). */
    u8_t iv[SNMPV3_AES_IV_LEN];
    u8_t aes_key[SNMPV3_AES_KEY_LEN];
    if (key == NULL || priv_param == NULL || !snmpv3_aes_key(key, SNMP_V3_SHA_LEN, aes_key)) {
        return ERR_ARG;
    }
    snmpv3_aes_iv(engine_boots, engine_time, priv_param, iv);

    const bool encrypt = (mode == SNMP_V3_PRIV_MODE_ENCRYPT);
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t ist = import_key(PSA_KEY_TYPE_AES, PSA_ALG_CFB,
                                  encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT, aes_key,
                                  SNMPV3_AES_KEY_LEN, &id);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    if (ist != PSA_SUCCESS) {
        return ERR_ARG;
    }

    struct snmp_pbuf_stream rd;
    struct snmp_pbuf_stream wr;
    snmp_pbuf_stream_init(&rd, stream->pbuf, stream->offset, stream->length);
    snmp_pbuf_stream_init(&wr, stream->pbuf, stream->offset, stream->length);

    err_t err = ERR_ARG;
    /* Separate in/out buffers: the ESP AES driver rejects in-place partial-block CFB updates.
     * CHUNK_LEN is a block multiple, so only the final chunk can be partial. */
    u8_t in[CHUNK_LEN];
    u8_t outb[CHUNK_LEN];
    size_t tail = 0;
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st = encrypt ? psa_cipher_encrypt_setup(&op, id, PSA_ALG_CFB)
                              : psa_cipher_decrypt_setup(&op, id, PSA_ALG_CFB);
    if (st != PSA_SUCCESS || psa_cipher_set_iv(&op, iv, sizeof(iv)) != PSA_SUCCESS) {
        goto out;
    }

    for (u16_t done = 0; done < length;) {
        u16_t n = (u16_t)LWIP_MIN((u16_t)sizeof(in), (u16_t)(length - done));
        size_t out_len = 0;
        if (stream_read(&rd, in, n) != ERR_OK ||
            psa_cipher_update(&op, in, n, outb, sizeof(outb), &out_len) != PSA_SUCCESS || out_len != n ||
            snmp_pbuf_stream_writebuf(&wr, outb, n) != ERR_OK) {
            goto out;
        }
        done = (u16_t)(done + n);
    }
    if (psa_cipher_finish(&op, outb, sizeof(outb), &tail) == PSA_SUCCESS && tail == 0) {
        err = ERR_OK;
    }

out:
    psa_cipher_abort(&op);
    psa_destroy_key(id);
    mbedtls_platform_zeroize(in, sizeof(in)); /* not elidable, unlike memset before return */
    mbedtls_platform_zeroize(outb, sizeof(outb));
    return err;
}

/* RFC 3414 A.2 password-to-key + localization. Delegates to the single, host-tested implementation
 * gw_snmp_key_localize() (gw_core/gw_snmp_key.c, RFC 3414 A.3 vectors in tests/), so there is one
 * copy of the algorithm. On failure (including an empty password) the key is zeroed. */
void snmpv3_password_to_key_md5(const u8_t *password, size_t passwordlen, const u8_t *engineID,
                                u8_t engineLength, u8_t *key) {
    (void)gw_snmp_key_localize(GW_HASH_MD5, (const char *)password, passwordlen, engineID, engineLength, key);
}

void snmpv3_password_to_key_sha(const u8_t *password, size_t passwordlen, const u8_t *engineID,
                                u8_t engineLength, u8_t *key) {
    (void)gw_snmp_key_localize(GW_HASH_SHA1, (const char *)password, passwordlen, engineID, engineLength,
                               key);
}

#endif /* LWIP_SNMP && LWIP_SNMP_V3 && LWIP_SNMP_V3_CRYPTO && !LWIP_SNMP_V3_MBEDTLS */
