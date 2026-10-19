/* SNMPv3 USM password-to-key and key localization (RFC 3414 A.2) on the gw_crypto streaming API. */
#include <string.h>

#include "gw_core/gw_crypto.h"

#define EXPANSION_LEN 1048576u /* RFC 3414 A.2: hash the first 1 MiB of the repeated password */
#define CHUNK_LEN 64u
#define ENGINE_ID_MAX 32u

static int hash_ku(gw_hash_alg_t alg, const char *pass, size_t pass_len, uint8_t *ku) {
    gw_hash_ctx_t *ctx = gw_hash_begin(alg);
    if (!ctx) {
        return GW_CRYPTO_E_NO_MEM;
    }
    uint8_t chunk[CHUNK_LEN];
    size_t idx = 0;
    int rc = GW_CRYPTO_OK;
    for (uint32_t done = 0; done < EXPANSION_LEN && rc == GW_CRYPTO_OK; done += CHUNK_LEN) {
        for (size_t i = 0; i < CHUNK_LEN; i++) {
            chunk[i] = (uint8_t)pass[idx];
            idx = (idx + 1 == pass_len) ? 0 : idx + 1;
        }
        rc = gw_hash_update(ctx, chunk, CHUNK_LEN);
    }
    gw_secure_zero(chunk, sizeof(chunk));
    int frc = gw_hash_finish(ctx, ku);
    return rc != GW_CRYPTO_OK ? rc : frc;
}

int gw_snmp_key_localize(gw_hash_alg_t alg, const char *pass, size_t pass_len, const uint8_t *engine_id,
                         size_t engine_len, uint8_t *out) {
    if (alg != GW_HASH_MD5 && alg != GW_HASH_SHA1) {
        return GW_CRYPTO_E_ARG;
    }
    size_t hlen = gw_hash_len(alg);
    if (!out) {
        return GW_CRYPTO_E_ARG;
    }
    memset(out, 0, hlen);
    if (!pass || pass_len == 0 || !engine_id || engine_len == 0 || engine_len > ENGINE_ID_MAX) {
        return GW_CRYPTO_E_ARG;
    }

    uint8_t ku[GW_HASH_MAX_LEN];
    int rc = hash_ku(alg, pass, pass_len, ku);
    if (rc == GW_CRYPTO_OK) {
        gw_hash_ctx_t *ctx = gw_hash_begin(alg);
        if (!ctx) {
            rc = GW_CRYPTO_E_NO_MEM;
        } else {
            rc = gw_hash_update(ctx, ku, hlen);
            if (rc == GW_CRYPTO_OK) {
                rc = gw_hash_update(ctx, engine_id, engine_len);
            }
            if (rc == GW_CRYPTO_OK) {
                rc = gw_hash_update(ctx, ku, hlen);
            }
            int frc = gw_hash_finish(ctx, out);
            if (rc == GW_CRYPTO_OK) {
                rc = frc;
            }
        }
    }
    gw_secure_zero(ku, sizeof(ku));
    if (rc != GW_CRYPTO_OK) {
        memset(out, 0, hlen);
    }
    return rc;
}
