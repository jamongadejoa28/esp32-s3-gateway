/* gw_crypto.h backend on OpenSSL 3 libcrypto. HOST TESTS ONLY: excluded from the IDF build
 * (gw_core/CMakeLists.txt EXCLUDE_SRCS) and listed in GW_HOST_ONLY_SOURCES; link with -lcrypto.
 * The device backend (crypto_psa.c) must produce identical results for every function. */
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "gw_core/gw_crypto.h"

struct gw_hash_ctx {
    gw_hash_alg_t alg;
    EVP_MD_CTX *md;   /* plain hash */
    EVP_MAC_CTX *mac; /* HMAC */
};

static const char *md_name(gw_hash_alg_t alg) {
    switch (alg) {
    case GW_HASH_MD5:
        return "MD5";
    case GW_HASH_SHA1:
        return "SHA1";
    case GW_HASH_SHA256:
        return "SHA256";
    default:
        return NULL;
    }
}

int gw_crypto_init(void) {
    return GW_CRYPTO_OK;
}

gw_hash_ctx_t *gw_hash_begin(gw_hash_alg_t alg) {
    const char *name = md_name(alg);
    if (!name) {
        return NULL;
    }
    gw_hash_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->alg = alg;
    c->md = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    int ok = c->md && md && EVP_DigestInit_ex(c->md, md, NULL) == 1;
    EVP_MD_free(md);
    if (!ok) {
        gw_hash_abort(c);
        return NULL;
    }
    return c;
}

gw_hash_ctx_t *gw_hmac_begin(gw_hash_alg_t alg, const uint8_t *key, size_t key_len) {
    const char *name = md_name(alg);
    if (!name || (!key && key_len)) {
        return NULL;
    }
    gw_hash_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->alg = alg;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    c->mac = mac ? EVP_MAC_CTX_new(mac) : NULL;
    EVP_MAC_free(mac);
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)name, 0),
                           OSSL_PARAM_construct_end()};
    static const uint8_t empty_key[1];
    if (!c->mac || EVP_MAC_init(c->mac, key_len ? key : empty_key, key_len, params) != 1) {
        gw_hash_abort(c);
        return NULL;
    }
    return c;
}

int gw_hash_update(gw_hash_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || (!data && len)) {
        return GW_CRYPTO_E_ARG;
    }
    if (len == 0) {
        return GW_CRYPTO_OK;
    }
    int ok = ctx->mac ? EVP_MAC_update(ctx->mac, data, len) : EVP_DigestUpdate(ctx->md, data, len);
    return ok == 1 ? GW_CRYPTO_OK : GW_CRYPTO_E_FAIL;
}

int gw_hash_finish(gw_hash_ctx_t *ctx, uint8_t *out) {
    if (!ctx) {
        return GW_CRYPTO_E_ARG;
    }
    int rc = GW_CRYPTO_E_ARG;
    if (out) {
        size_t want = gw_hash_len(ctx->alg);
        uint8_t buf[EVP_MAX_MD_SIZE];
        int ok;
        size_t got = 0;
        if (ctx->mac) {
            ok = EVP_MAC_final(ctx->mac, buf, &got, sizeof(buf));
        } else {
            unsigned int n = 0;
            ok = EVP_DigestFinal_ex(ctx->md, buf, &n);
            got = n;
        }
        if (ok == 1 && got == want) {
            memcpy(out, buf, want);
            rc = GW_CRYPTO_OK;
        } else {
            rc = GW_CRYPTO_E_FAIL;
        }
        gw_secure_zero(buf, sizeof(buf));
    }
    gw_hash_abort(ctx);
    return rc;
}

void gw_hash_abort(gw_hash_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    EVP_MD_CTX_free(ctx->md);
    EVP_MAC_CTX_free(ctx->mac);
    free(ctx);
}

int gw_hash(gw_hash_alg_t alg, const void *data, size_t len, uint8_t *out) {
    if ((!data && len) || !out) {
        return GW_CRYPTO_E_ARG;
    }
    gw_hash_ctx_t *c = gw_hash_begin(alg);
    if (!c) {
        return md_name(alg) ? GW_CRYPTO_E_NO_MEM : GW_CRYPTO_E_ARG;
    }
    int rc = gw_hash_update(c, data, len);
    int frc = gw_hash_finish(c, out);
    return rc != GW_CRYPTO_OK ? rc : frc;
}

int gw_hmac(gw_hash_alg_t alg, const uint8_t *key, size_t key_len, const void *data, size_t len,
            uint8_t *out) {
    if ((!data && len) || !out || (!key && key_len)) {
        return GW_CRYPTO_E_ARG;
    }
    gw_hash_ctx_t *c = gw_hmac_begin(alg, key, key_len);
    if (!c) {
        return md_name(alg) ? GW_CRYPTO_E_NO_MEM : GW_CRYPTO_E_ARG;
    }
    int rc = gw_hash_update(c, data, len);
    int frc = gw_hash_finish(c, out);
    return rc != GW_CRYPTO_OK ? rc : frc;
}

int gw_pbkdf2_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint8_t *out, size_t out_len) {
    if ((!pass && pass_len) || (!salt && salt_len) || !out || iterations < 1 || out_len < 1 || out_len > 64 ||
        pass_len > INT32_MAX || salt_len > INT32_MAX || iterations > INT32_MAX) {
        return GW_CRYPTO_E_ARG;
    }
    static const uint8_t empty[1];
    int ok =
        PKCS5_PBKDF2_HMAC((const char *)(pass_len ? pass : empty), (int)pass_len, salt_len ? salt : empty,
                          (int)salt_len, (int)iterations, EVP_sha256(), (int)out_len, out);
    return ok == 1 ? GW_CRYPTO_OK : GW_CRYPTO_E_FAIL;
}

int gw_aes128_cfb(bool encrypt, const uint8_t key[GW_AES128_KEY_LEN], const uint8_t iv[GW_AES_BLOCK_LEN],
                  const uint8_t *in, uint8_t *out, size_t len) {
    if (!key || !iv || ((!in || !out) && len) || len > INT32_MAX) {
        return GW_CRYPTO_E_ARG;
    }
    if (len == 0) {
        return GW_CRYPTO_OK;
    }
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) {
        return GW_CRYPTO_E_NO_MEM;
    }
    int n = 0;
    int ok = EVP_CipherInit_ex(c, EVP_aes_128_cfb128(), NULL, key, iv, encrypt ? 1 : 0) == 1 &&
             EVP_CipherUpdate(c, out, &n, in, (int)len) == 1 && (size_t)n == len;
    EVP_CIPHER_CTX_free(c);
    return ok ? GW_CRYPTO_OK : GW_CRYPTO_E_FAIL;
}

int gw_random(void *buf, size_t len) {
    if (!buf && len) {
        return GW_CRYPTO_E_ARG;
    }
    if (len > INT32_MAX) {
        return GW_CRYPTO_E_ARG;
    }
    return (len == 0 || RAND_bytes(buf, (int)len) == 1) ? GW_CRYPTO_OK : GW_CRYPTO_E_FAIL;
}
