/* Password policy, user-name rule and status mapping (auth.h; DESIGN.md §5, API.md §4.1). Pure C. */
#include <string.h>

#include "auth/auth.h"
#include "gw_core/gw_defs.h"

/* Decode one UTF-8 sequence at s (n bytes left). Returns its length (1..4) and the code point, or
 * 0 for an invalid/overlong/surrogate/out-of-range sequence. */
static size_t utf8_next(const unsigned char *s, size_t n, uint32_t *cp) {
    unsigned char c = s[0];
    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    size_t len;
    uint32_t v;
    uint32_t min;
    if ((c & 0xE0) == 0xC0) {
        len = 2;
        v = c & 0x1Fu;
        min = 0x80;
    } else if ((c & 0xF0) == 0xE0) {
        len = 3;
        v = c & 0x0Fu;
        min = 0x800;
    } else if ((c & 0xF8) == 0xF0) {
        len = 4;
        v = c & 0x07u;
        min = 0x10000;
    } else {
        return 0;
    }
    if (len > n) {
        return 0;
    }
    for (size_t i = 1; i < len; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            return 0;
        }
        v = (v << 6) | (s[i] & 0x3Fu);
    }
    if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) {
        return 0;
    }
    *cp = v;
    return len;
}

static bool ascii_ieq(const char *a, const char *b) {
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') {
            x = (char)(x - 'A' + 'a');
        }
        if (y >= 'A' && y <= 'Z') {
            y = (char)(y - 'A' + 'a');
        }
        if (x != y) {
            return false;
        }
        if (!x) {
            return true;
        }
    }
}

uint32_t auth_policy_check(const char *user, const char *password) {
    if (!password) {
        return AUTH_PW_TOO_SHORT;
    }
    uint32_t bad = 0;
    const size_t bytes = strlen(password);
    const unsigned char *p = (const unsigned char *)password;
    size_t cps = 0;
    bool lower = false, upper = false, digit = false, other = false;
    for (size_t i = 0; i < bytes;) {
        uint32_t cp = 0;
        size_t l = utf8_next(p + i, bytes - i, &cp);
        if (!l) {
            bad |= AUTH_PW_INVALID_CHARS;
            i++;
            cps++;
            continue;
        }
        i += l;
        cps++;
        if (cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F)) {
            bad |= AUTH_PW_INVALID_CHARS;
        } else if (cp >= 'a' && cp <= 'z') {
            lower = true;
        } else if (cp >= 'A' && cp <= 'Z') {
            upper = true;
        } else if (cp >= '0' && cp <= '9') {
            digit = true;
        } else {
            other = true;
        }
    }
    if (cps < GW_PASSWORD_MIN) {
        bad |= AUTH_PW_TOO_SHORT;
    }
    if (bytes > GW_PASSWORD_MAX) {
        bad |= AUTH_PW_TOO_LONG;
    }
    if ((int)lower + (int)upper + (int)digit + (int)other < 3) {
        bad |= AUTH_PW_CLASSES;
    }
    if (user && user[0] && ascii_ieq(user, password)) {
        bad |= AUTH_PW_EQUALS_USER;
    }
    if (strcmp(password, AUTH_FACTORY_PASSWORD) == 0) {
        bad |= AUTH_PW_FACTORY_DEFAULT;
    }
    return bad;
}

const char *auth_policy_rule_name(uint32_t bit) {
    switch (bit) {
    case AUTH_PW_TOO_SHORT:
        return "min_length";
    case AUTH_PW_TOO_LONG:
        return "max_length";
    case AUTH_PW_CLASSES:
        return "classes";
    case AUTH_PW_EQUALS_USER:
        return "not_username";
    case AUTH_PW_FACTORY_DEFAULT:
        return "not_default";
    case AUTH_PW_REUSED:
        return "not_previous";
    case AUTH_PW_INVALID_CHARS:
        return "charset";
    default:
        return NULL;
    }
}

bool auth_name_valid(const char *name) {
    if (!name || !(name[0] >= 'a' && name[0] <= 'z')) {
        return false;
    }
    size_t n = 1;
    for (const char *p = name + 1; *p; p++, n++) {
        char c = *p;
        if (n >= GW_USER_NAME_MAX) {
            return false;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
            return false;
        }
    }
    return true;
}

int auth_http_status(auth_status_t st) {
    switch (st) {
    case AUTH_OK:
        return 200;
    case AUTH_E_BAD_CREDENTIALS:
    case AUTH_E_NO_SESSION:
        return 401;
    case AUTH_E_LOCKED:
        return 429;
    case AUTH_E_NOT_FOUND:
        return 404;
    case AUTH_E_EXISTS:
    case AUTH_E_LIMIT:
    case AUTH_E_LAST_ADMIN:
    case AUTH_E_SELF:
        return 409;
    case AUTH_E_POLICY:
    case AUTH_E_BAD_NAME:
    case AUTH_E_BAD_ROLE:
    case AUTH_E_WRONG_PASSWORD:
        return 422;
    case AUTH_E_STORE:
    default:
        return 503;
    }
}

const char *auth_status_code(auth_status_t st) {
    switch (st) {
    case AUTH_OK:
        return "ok";
    case AUTH_E_BAD_CREDENTIALS:
        return "bad_credentials";
    case AUTH_E_LOCKED:
        return "rate_limited";
    case AUTH_E_NO_SESSION:
        return "unauthorized";
    case AUTH_E_POLICY:
        return "policy";
    case AUTH_E_EXISTS:
        return "exists";
    case AUTH_E_NOT_FOUND:
        return "not_found";
    case AUTH_E_LIMIT:
        return "limit";
    case AUTH_E_LAST_ADMIN:
        return "last_admin";
    case AUTH_E_BAD_NAME:
    case AUTH_E_BAD_ROLE:
        return "validation";
    case AUTH_E_SELF:
        return "self";
    case AUTH_E_WRONG_PASSWORD:
        return "wrong_password";
    case AUTH_E_STORE:
    default:
        return "unavailable";
    }
}
