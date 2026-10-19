/* Backend-independent helpers of gw_crypto.h (pure C; device and host). */
#include <stdint.h>

#include "gw_core/gw_crypto.h"

size_t gw_hash_len(gw_hash_alg_t alg) {
    switch (alg) {
    case GW_HASH_MD5:
        return GW_MD5_LEN;
    case GW_HASH_SHA1:
        return GW_SHA1_LEN;
    case GW_HASH_SHA256:
        return GW_SHA256_LEN;
    default:
        return 0;
    }
}

bool gw_ct_equal(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = a;
    const volatile uint8_t *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return diff == 0;
}

void gw_secure_zero(void *p, size_t len) {
    volatile uint8_t *v = p;
    while (len--) {
        *v++ = 0;
    }
}
