/* Firmware version comparison and OTA image acceptance (pure C). Contract: sysmgr_pure.h. */
#include <string.h>

#include "sysmgr_pure.h"

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool is_ident_char(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
}

/* Numeric part without leading zeros; advances *p. */
static bool parse_num(const char **p, uint32_t *out) {
    const char *s = *p;
    if (!is_digit(*s)) {
        return false;
    }
    if (s[0] == '0' && is_digit(s[1])) {
        return false;
    }
    uint64_t v = 0;
    while (is_digit(*s)) {
        v = v * 10 + (uint64_t)(*s - '0');
        if (v > UINT32_MAX) {
            return false;
        }
        s++;
    }
    *out = (uint32_t)v;
    *p = s;
    return true;
}

/* Dot-separated identifiers up to '+' or end. */
static bool valid_idents(const char *s, size_t n) {
    if (n == 0) {
        return false;
    }
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            const size_t len = i - start;
            if (len == 0) {
                return false;
            }
            bool numeric = true;
            for (size_t k = start; k < i; k++) {
                if (!is_ident_char(s[k])) {
                    return false;
                }
                numeric = numeric && is_digit(s[k]);
            }
            if (numeric && len > 1 && s[start] == '0') {
                return false;
            }
            start = i + 1;
        }
    }
    return true;
}

bool sys_ver_parse(const char *s, sys_ver_t *out) {
    if (!s || !out) {
        return false;
    }
    sys_ver_t v;
    memset(&v, 0, sizeof(v));
    if (*s == 'v' || *s == 'V') {
        s++;
    }
    if (!parse_num(&s, &v.major) || *s++ != '.' || !parse_num(&s, &v.minor) || *s++ != '.' ||
        !parse_num(&s, &v.patch)) {
        return false;
    }
    if (*s == '-') {
        s++;
        const char *end = strchr(s, '+');
        const size_t n = end ? (size_t)(end - s) : strlen(s);
        if (!valid_idents(s, n) || n >= SYS_VER_PRE_SZ) {
            return false;
        }
        memcpy(v.pre, s, n);
        v.pre[n] = '\0';
        s += n;
    }
    if (*s == '+') {
        s++;
        if (!valid_idents(s, strlen(s))) {
            return false;
        }
        s += strlen(s);
    }
    if (*s) {
        return false;
    }
    *out = v;
    return true;
}

/* Compare one prerelease identifier pair (SemVer 2.0.0 §11.4). */
static int cmp_ident(const char *a, size_t al, const char *b, size_t bl) {
    bool an = true, bn = true;
    for (size_t i = 0; i < al; i++) {
        an = an && is_digit(a[i]);
    }
    for (size_t i = 0; i < bl; i++) {
        bn = bn && is_digit(b[i]);
    }
    if (an && bn) {
        if (al != bl) {
            return al < bl ? -1 : 1; /* no leading zeros: longer is larger */
        }
        const int c = memcmp(a, b, al);
        return c < 0 ? -1 : c > 0;
    }
    if (an != bn) {
        return an ? -1 : 1; /* numeric identifiers rank lower */
    }
    const size_t n = al < bl ? al : bl;
    const int c = memcmp(a, b, n);
    if (c) {
        return c < 0 ? -1 : 1;
    }
    return al == bl ? 0 : (al < bl ? -1 : 1);
}

int sys_ver_cmp(const sys_ver_t *a, const sys_ver_t *b) {
    if (a->major != b->major) {
        return a->major < b->major ? -1 : 1;
    }
    if (a->minor != b->minor) {
        return a->minor < b->minor ? -1 : 1;
    }
    if (a->patch != b->patch) {
        return a->patch < b->patch ? -1 : 1;
    }
    const bool ap = a->pre[0] != '\0', bp = b->pre[0] != '\0';
    if (!ap || !bp) {
        return ap == bp ? 0 : (ap ? -1 : 1);
    }
    const char *x = a->pre, *y = b->pre;
    for (;;) {
        const size_t xl = strcspn(x, "."), yl = strcspn(y, ".");
        const int c = cmp_ident(x, xl, y, yl);
        if (c) {
            return c;
        }
        const bool xe = x[xl] == '\0', ye = y[yl] == '\0';
        if (xe || ye) {
            return xe == ye ? 0 : (xe ? -1 : 1); /* fewer identifiers rank lower */
        }
        x += xl + 1;
        y += yl + 1;
    }
}

esp_err_t sys_ota_check_image(const char *project_name, const char *new_version, const char *expect_project,
                              const char *running_version, bool allow_downgrade) {
    if (!project_name || !expect_project || strcmp(project_name, expect_project) != 0) {
        return ESP_ERR_INVALID_VERSION;
    }
    sys_ver_t nv, rv;
    if (!sys_ver_parse(new_version, &nv)) {
        return ESP_ERR_INVALID_VERSION;
    }
    if (allow_downgrade || !sys_ver_parse(running_version, &rv)) {
        return ESP_OK;
    }
    return sys_ver_cmp(&nv, &rv) >= 0 ? ESP_OK : ESP_ERR_INVALID_VERSION;
}

bool sys_build_date_iso(const char *date, const char *time, char *out, size_t cap) {
    static const char MONTHS[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    if (!out || cap < 20) {
        return false;
    }
    out[0] = '\0';
    if (!date || !time || strlen(date) != 11 || strlen(time) != 8) {
        return false;
    }
    int mon = 0;
    for (int i = 0; i < 12; i++) {
        if (!memcmp(date, MONTHS + 3 * i, 3)) {
            mon = i + 1;
        }
    }
    /* __DATE__ pads single-digit days with a space: "Oct  9 2026". */
    const char d0 = date[4] == ' ' ? '0' : date[4];
    if (!mon || date[3] != ' ' || date[6] != ' ' || !is_digit(d0) || !is_digit(date[5]) || !is_digit(date[7]) ||
        !is_digit(date[8]) || !is_digit(date[9]) || !is_digit(date[10])) {
        return false;
    }
    if (!is_digit(time[0]) || !is_digit(time[1]) || time[2] != ':' || !is_digit(time[3]) || !is_digit(time[4]) ||
        time[5] != ':' || !is_digit(time[6]) || !is_digit(time[7])) {
        return false;
    }
    memcpy(out, date + 7, 4);
    out[4] = '-';
    out[5] = (char)('0' + mon / 10);
    out[6] = (char)('0' + mon % 10);
    out[7] = '-';
    out[8] = d0;
    out[9] = date[5];
    out[10] = ' ';
    memcpy(out + 11, time, 8);
    out[19] = '\0';
    return true;
}
