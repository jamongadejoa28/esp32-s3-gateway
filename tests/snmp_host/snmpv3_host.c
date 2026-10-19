/* Host twin of components/snmp_lwip/snmpv3_psa.c for the lwIP SNMP test harness: the same lwIP hooks
 * (snmpv3_auth / snmpv3_crypt / snmpv3_password_to_key_*) on the OpenSSL gw_crypto backend, with the
 * IV and AES key taken from the shared helpers in snmp_lwip/snmpv3_util.h exactly like the device
 * backend. Semantics mirrored: caller's stream untouched by auth, in-place crypt, DES -> ERR_ARG,
 * every error -> ERR_ARG, secrets wiped. */
#include <stdlib.h>
#include <string.h>

#include "gw_core/gw_crypto.h"
#include "lwip/apps/snmpv3.h"
#include "lwip/pbuf.h"
#include "snmp_lwip/snmpv3_util.h"
#include "snmp_pbuf_stream.h"
#include "snmpv3_priv.h"

#define CHUNK_LEN 64

err_t snmpv3_auth(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, snmpv3_auth_algo_t algo,
                  u8_t *hmac_out) {
    gw_hash_alg_t alg;
    size_t key_len;
    if (algo == SNMP_V3_AUTH_ALGO_MD5) {
        alg = GW_HASH_MD5;
        key_len = SNMP_V3_MD5_LEN;
    } else if (algo == SNMP_V3_AUTH_ALGO_SHA) {
        alg = GW_HASH_SHA1;
        key_len = SNMP_V3_SHA_LEN;
    } else {
        return ERR_ARG;
    }
    gw_hash_ctx_t *ctx = gw_hmac_begin(alg, key, key_len);
    if (ctx == NULL) {
        return ERR_ARG;
    }
    u8_t buf[CHUNK_LEN];
    u16_t off = stream->offset;
    for (u16_t done = 0; done < length;) {
        u16_t n = (u16_t)((length - done) < CHUNK_LEN ? (length - done) : CHUNK_LEN);
        if (stream->length < (u16_t)(done + n) || pbuf_copy_partial(stream->pbuf, buf, n, (u16_t)(off + done)) != n ||
            gw_hash_update(ctx, buf, n) != GW_CRYPTO_OK) {
            gw_hash_abort(ctx);
            return ERR_ARG;
        }
        done = (u16_t)(done + n);
    }
    return gw_hash_finish(ctx, hmac_out) == GW_CRYPTO_OK ? ERR_OK : ERR_ARG;
}

err_t snmpv3_crypt(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, const u8_t *priv_param,
                   const u32_t engine_boots, const u32_t engine_time, snmpv3_priv_algo_t algo,
                   snmpv3_priv_mode_t mode) {
    if (algo != SNMP_V3_PRIV_ALGO_AES || key == NULL || priv_param == NULL) {
        return ERR_ARG;
    }
    u8_t iv[SNMPV3_AES_IV_LEN];
    u8_t aes_key[SNMPV3_AES_KEY_LEN];
    if (!snmpv3_aes_key(key, SNMP_V3_SHA_LEN, aes_key)) {
        return ERR_ARG;
    }
    snmpv3_aes_iv(engine_boots, engine_time, priv_param, iv);
    u8_t *in = malloc(length ? length : 1);
    u8_t *out = malloc(length ? length : 1);
    err_t err = ERR_ARG;
    struct snmp_pbuf_stream wr;
    if (in != NULL && out != NULL && stream->length >= length &&
        pbuf_copy_partial(stream->pbuf, in, length, stream->offset) == length &&
        gw_aes128_cfb(mode == SNMP_V3_PRIV_MODE_ENCRYPT, aes_key, iv, in, out, length) == GW_CRYPTO_OK &&
        snmp_pbuf_stream_init(&wr, stream->pbuf, stream->offset, stream->length) == ERR_OK &&
        snmp_pbuf_stream_writebuf(&wr, out, length) == ERR_OK) {
        err = ERR_OK;
    }
    if (in != NULL) {
        gw_secure_zero(in, length);
    }
    if (out != NULL) {
        gw_secure_zero(out, length);
    }
    free(in);
    free(out);
    gw_secure_zero(aes_key, sizeof(aes_key));
    return err;
}

void snmpv3_password_to_key_md5(const u8_t *password, size_t passwordlen, const u8_t *engineID, u8_t engineLength,
                                u8_t *key) {
    (void)gw_snmp_key_localize(GW_HASH_MD5, (const char *)password, passwordlen, engineID, engineLength, key);
}

void snmpv3_password_to_key_sha(const u8_t *password, size_t passwordlen, const u8_t *engineID, u8_t engineLength,
                                u8_t *key) {
    (void)gw_snmp_key_localize(GW_HASH_SHA1, (const char *)password, passwordlen, engineID, engineLength, key);
}
