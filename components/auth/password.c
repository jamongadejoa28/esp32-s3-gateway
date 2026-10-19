/* Password records "pbkdf2-sha256$<iter>$<salt b64 std>$<dk b64 std>" (auth.h, DESIGN.md §6).
 * Pure C on gw_crypto.h (device: PSA, host: OpenSSL); host-tested with RFC 7914 vectors. */
#include <stdio.h>
#include <string.h>

#include "auth/auth.h"
#include "auth_priv.h"
#include "gw_core/gw_b64.h"
#include "gw_core/gw_crypto.h"

#define SALT_B64_LEN GW_B64_STD_LEN(AUTH_SALT_LEN) /* 24 */
#define DK_B64_LEN GW_B64_STD_LEN(AUTH_DK_LEN)     /* 44 */

int auth_pw_hash_salt(const char *password, uint32_t iterations, const uint8_t salt[AUTH_SALT_LEN], char *out,
                      size_t cap) {
    if (!password || !salt || !out || iterations < AUTH_PBKDF2_ITER_MIN ||
        iterations > AUTH_PBKDF2_ITER_MAX) {
        return -1;
    }
    uint8_t dk[AUTH_DK_LEN];
    char salt_b64[SALT_B64_LEN + 1];
    char dk_b64[DK_B64_LEN + 1];
    int rc = -1;
    if (gw_pbkdf2_sha256((const uint8_t *)password, strlen(password), salt, AUTH_SALT_LEN, iterations, dk,
                         sizeof(dk)) == GW_CRYPTO_OK &&
        gw_b64_encode(salt, AUTH_SALT_LEN, salt_b64, sizeof(salt_b64), GW_B64_STD) == SALT_B64_LEN &&
        gw_b64_encode(dk, sizeof(dk), dk_b64, sizeof(dk_b64), GW_B64_STD) == DK_B64_LEN) {
        int n = snprintf(out, cap, AUTH_PW_PREFIX "%u$%s$%s", (unsigned)iterations, salt_b64, dk_b64);
        rc = (n > 0 && (size_t)n < cap) ? 0 : -1;
    }
    gw_secure_zero(dk, sizeof(dk));
    gw_secure_zero(dk_b64, sizeof(dk_b64));
    if (rc && cap) {
        out[0] = '\0';
    }
    return rc;
}

int auth_pw_hash(const char *password, uint32_t iterations, char *out, size_t cap) {
    uint8_t salt[AUTH_SALT_LEN];
    if (gw_random(salt, sizeof(salt)) != GW_CRYPTO_OK) {
        if (out && cap) {
            out[0] = '\0';
        }
        return -1;
    }
    return auth_pw_hash_salt(password, iterations, salt, out, cap);
}

/* Parse decimal digits [s, end) without leading zeros into *out (<= AUTH_PBKDF2_ITER_MAX). */
static bool parse_iter(const char *s, const char *end, uint32_t *out) {
    size_t n = (size_t)(end - s);
    if (n == 0 || n > 7 || (s[0] == '0')) {
        return false;
    }
    uint32_t v = 0;
    for (const char *p = s; p < end; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        v = v * 10u + (uint32_t)(*p - '0');
    }
    if (v < AUTH_PBKDF2_ITER_MIN || v > AUTH_PBKDF2_ITER_MAX) {
        return false;
    }
    *out = v;
    return true;
}

bool auth_pw_parse(const char *record, uint32_t *iterations, uint8_t salt[AUTH_SALT_LEN],
                   uint8_t dk[AUTH_DK_LEN]) {
    if (!record) {
        return false;
    }
    const size_t plen = sizeof(AUTH_PW_PREFIX) - 1;
    if (strncmp(record, AUTH_PW_PREFIX, plen) != 0) {
        return false;
    }
    const char *it = record + plen;
    const char *d1 = strchr(it, '$');
    if (!d1) {
        return false;
    }
    const char *s = d1 + 1;
    const char *d2 = strchr(s, '$');
    if (!d2) {
        return false;
    }
    const char *k = d2 + 1;
    uint32_t iter = 0;
    uint8_t sbuf[AUTH_SALT_LEN];
    uint8_t kbuf[AUTH_DK_LEN];
    bool ok = parse_iter(it, d1, &iter) && (size_t)(d2 - s) == SALT_B64_LEN && strlen(k) == DK_B64_LEN &&
              gw_b64_decode(s, SALT_B64_LEN, sbuf, sizeof(sbuf), GW_B64_STD) == AUTH_SALT_LEN &&
              gw_b64_decode(k, DK_B64_LEN, kbuf, sizeof(kbuf), GW_B64_STD) == AUTH_DK_LEN;
    if (ok) {
        if (iterations) {
            *iterations = iter;
        }
        if (salt) {
            memcpy(salt, sbuf, sizeof(sbuf));
        }
        if (dk) {
            memcpy(dk, kbuf, sizeof(kbuf));
        }
    }
    gw_secure_zero(kbuf, sizeof(kbuf));
    return ok;
}

uint32_t auth_pw_record_iterations(const char *record) {
    uint32_t iter = 0;
    return auth_pw_parse(record, &iter, NULL, NULL) ? iter : 0;
}

void auth_pw_dummy_verify(const char *password, uint32_t iterations) {
    static const uint8_t dummy_salt[AUTH_SALT_LEN] = {0x6d, 0x65, 0x73, 0x74, 0x69, 0x6f, 0x2d, 0x64,
                                                      0x75, 0x6d, 0x6d, 0x79, 0x2d, 0x73, 0x61, 0x6c};
    uint8_t dk[AUTH_DK_LEN];
    const char *p = password ? password : "";
    if (iterations < AUTH_PBKDF2_ITER_MIN || iterations > AUTH_PBKDF2_ITER_MAX) {
        iterations = AUTH_PBKDF2_ITER_DEFAULT;
    }
    (void)gw_pbkdf2_sha256((const uint8_t *)p, strlen(p), dummy_salt, sizeof(dummy_salt), iterations, dk,
                           sizeof(dk));
    gw_secure_zero(dk, sizeof(dk));
}

bool auth_pw_verify(const char *password, const char *record) {
    uint32_t iter = 0;
    uint8_t salt[AUTH_SALT_LEN];
    uint8_t want[AUTH_DK_LEN];
    uint8_t got[AUTH_DK_LEN];
    if (!password || !auth_pw_parse(record, &iter, salt, want)) {
        auth_pw_dummy_verify(password, AUTH_PBKDF2_ITER_DEFAULT);
        return false;
    }
    bool ok = gw_pbkdf2_sha256((const uint8_t *)password, strlen(password), salt, sizeof(salt), iter, got,
                               sizeof(got)) == GW_CRYPTO_OK &&
              gw_ct_equal(got, want, sizeof(got));
    gw_secure_zero(got, sizeof(got));
    gw_secure_zero(want, sizeof(want));
    return ok;
}
