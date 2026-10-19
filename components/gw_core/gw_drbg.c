/* HMAC_DRBG (SHA-256), NIST SP 800-90A Rev.1 §10.1.2. Contract: gw_core/gw_drbg.h. Pure C. */
#include "gw_core/gw_drbg.h"

#include <string.h>

#include "gw_core/gw_crypto.h"

/* out = HMAC(key, a || b || c || d); any part may be NULL/0. */
static int hmac4(const uint8_t key[GW_DRBG_OUTLEN], const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                 const uint8_t *c, size_t cl, const uint8_t *e, size_t el, uint8_t out[GW_DRBG_OUTLEN]) {
    gw_hash_ctx_t *h = gw_hmac_begin(GW_HASH_SHA256, key, GW_DRBG_OUTLEN);
    if (!h) {
        return GW_CRYPTO_E_NO_MEM;
    }
    int rc = GW_CRYPTO_OK;
    if (al && rc == GW_CRYPTO_OK) {
        rc = gw_hash_update(h, a, al);
    }
    if (bl && rc == GW_CRYPTO_OK) {
        rc = gw_hash_update(h, b, bl);
    }
    if (cl && rc == GW_CRYPTO_OK) {
        rc = gw_hash_update(h, c, cl);
    }
    if (el && rc == GW_CRYPTO_OK) {
        rc = gw_hash_update(h, e, el);
    }
    if (rc != GW_CRYPTO_OK) {
        gw_hash_abort(h);
        return rc;
    }
    return gw_hash_finish(h, out);
}

/* HMAC_DRBG_Update(provided_data = p1 || p2). */
static int update(gw_drbg_t *d, const uint8_t *p1, size_t l1, const uint8_t *p2, size_t l2) {
    static const uint8_t zero = 0x00, one = 0x01;
    uint8_t k[GW_DRBG_OUTLEN];
    int rc = hmac4(d->k, d->v, GW_DRBG_OUTLEN, &zero, 1, p1, l1, p2, l2, k);
    if (rc == GW_CRYPTO_OK) {
        memcpy(d->k, k, sizeof(k));
        rc = hmac4(d->k, d->v, GW_DRBG_OUTLEN, NULL, 0, NULL, 0, NULL, 0, d->v);
    }
    if (rc == GW_CRYPTO_OK && (l1 + l2) > 0) {
        rc = hmac4(d->k, d->v, GW_DRBG_OUTLEN, &one, 1, p1, l1, p2, l2, k);
        if (rc == GW_CRYPTO_OK) {
            memcpy(d->k, k, sizeof(k));
            rc = hmac4(d->k, d->v, GW_DRBG_OUTLEN, NULL, 0, NULL, 0, NULL, 0, d->v);
        }
    }
    gw_secure_zero(k, sizeof(k));
    if (rc != GW_CRYPTO_OK) {
        gw_drbg_wipe(d); /* never continue from a half-updated state */
    }
    return rc;
}

int gw_drbg_instantiate(gw_drbg_t *d, const uint8_t *entropy, size_t entropy_len, const uint8_t *pers,
                        size_t pers_len) {
    if (!d || !entropy || entropy_len < GW_DRBG_SEED_MIN || (pers_len && !pers)) {
        return GW_CRYPTO_E_ARG;
    }
    memset(d->k, 0x00, sizeof(d->k));
    memset(d->v, 0x01, sizeof(d->v));
    int rc = update(d, entropy, entropy_len, pers, pers_len);
    if (rc == GW_CRYPTO_OK) {
        d->reseed_counter = 1;
    }
    return rc;
}

int gw_drbg_reseed(gw_drbg_t *d, const uint8_t *entropy, size_t entropy_len, const uint8_t *add, size_t add_len) {
    if (!d || !d->reseed_counter || !entropy || entropy_len < GW_DRBG_SEED_MIN || (add_len && !add)) {
        return GW_CRYPTO_E_ARG;
    }
    int rc = update(d, entropy, entropy_len, add, add_len);
    if (rc == GW_CRYPTO_OK) {
        d->reseed_counter = 1;
    }
    return rc;
}

int gw_drbg_generate(gw_drbg_t *d, uint8_t *out, size_t out_len, const uint8_t *add, size_t add_len) {
    if (!out || !out_len || out_len > GW_DRBG_MAX_REQUEST) {
        return GW_CRYPTO_E_ARG;
    }
    if (!d || !d->reseed_counter || d->reseed_counter > GW_DRBG_RESEED_INTERVAL || (add_len && !add)) {
        gw_secure_zero(out, out_len);
        return GW_CRYPTO_E_ARG;
    }
    int rc = GW_CRYPTO_OK;
    if (add_len) {
        rc = update(d, add, add_len, NULL, 0);
    }
    size_t done = 0;
    while (rc == GW_CRYPTO_OK && done < out_len) {
        rc = hmac4(d->k, d->v, GW_DRBG_OUTLEN, NULL, 0, NULL, 0, NULL, 0, d->v);
        if (rc == GW_CRYPTO_OK) {
            size_t n = out_len - done < GW_DRBG_OUTLEN ? out_len - done : GW_DRBG_OUTLEN;
            memcpy(out + done, d->v, n);
            done += n;
        }
    }
    if (rc == GW_CRYPTO_OK) {
        rc = update(d, add, add_len, NULL, 0);
    }
    if (rc != GW_CRYPTO_OK) {
        gw_secure_zero(out, out_len);
        return rc;
    }
    d->reseed_counter++;
    return GW_CRYPTO_OK;
}

bool gw_drbg_needs_reseed(const gw_drbg_t *d) {
    return !d || d->reseed_counter == 0 || d->reseed_counter >= GW_DRBG_RESEED_INTERVAL;
}

void gw_drbg_wipe(gw_drbg_t *d) {
    if (d) {
        gw_secure_zero(d, sizeof(*d));
    }
}
