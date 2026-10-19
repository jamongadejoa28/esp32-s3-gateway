/* web_path.h implementation: route pattern matching, URL decoding, query/cookie lookup and the
 * Origin/Referer authority check. Pure C (no IDF), host-tested in tests/test_web_core.py. */
#include "web/web_path.h"

#include <string.h>

static bool param_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '_' || c == '~' || c == '-';
}

bool web_path_match(const char *pattern, const char *path, size_t path_len, web_params_t *out) {
    if (!pattern || !path) {
        return false;
    }
    web_params_t tmp;
    web_params_t *p = out ? out : &tmp;
    memset(p, 0, sizeof(*p));
    const char *pp = pattern;
    const char *pe = pattern + strlen(pattern);
    const char *up = path;
    const char *ue = path + path_len;
    if (pp == pe || up == ue || *pp != '/' || *up != '/') {
        return false;
    }
    while (pp < pe && up < ue) {
        if (*pp != '/' || *up != '/') {
            return false;
        }
        pp++;
        up++;
        const char *ps = pp;
        while (pp < pe && *pp != '/') {
            pp++;
        }
        const char *us = up;
        while (up < ue && *up != '/') {
            up++;
        }
        const size_t pl = (size_t)(pp - ps);
        const size_t ul = (size_t)(up - us);
        if (pl >= 2 && ps[0] == '{' && ps[pl - 1] == '}') {
            if (ul == 0 || ul >= WEB_PARAM_SZ || p->n >= WEB_MAX_PARAMS || pl - 2 > UINT8_MAX) {
                return false;
            }
            for (size_t i = 0; i < ul; i++) {
                if (!param_char(us[i])) {
                    return false;
                }
            }
            p->name[p->n] = ps + 1;
            p->name_len[p->n] = (uint8_t)(pl - 2);
            memcpy(p->value[p->n], us, ul);
            p->value[p->n][ul] = '\0';
            p->n++;
        } else if (pl != ul || memcmp(ps, us, pl) != 0) {
            return false;
        }
    }
    return pp == pe && up == ue;
}

const char *web_params_get(const web_params_t *p, const char *name) {
    if (!p || !name) {
        return NULL;
    }
    const size_t nl = strlen(name);
    for (size_t i = 0; i < p->n && i < WEB_MAX_PARAMS; i++) {
        if (p->name[i] && p->name_len[i] == nl && memcmp(p->name[i], name, nl) == 0) {
            return p->value[i];
        }
    }
    return NULL;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int web_url_decode(const char *in, size_t len, char *out, size_t cap) {
    if ((!in && len) || !out || cap == 0) {
        return -1;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= len) {
                return -1;
            }
            int hi = hexval(in[i + 1]);
            int lo = hexval(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            c = (char)((hi << 4) | lo);
            i += 2;
        } else if (c == '+') {
            c = ' ';
        }
        if (c == '\0' || o + 1 >= cap) {
            return -1;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return (int)o;
}

bool web_query_get(const char *query, const char *key, char *out, size_t cap) {
    if (!query || !key || !out || !cap) {
        return false;
    }
    const size_t kl = strlen(key);
    const char *p = query;
    while (*p) {
        const char *amp = strchr(p, '&');
        const char *end = amp ? amp : p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        const char *kend = eq ? eq : end;
        char kbuf[32];
        int kn =
            (kend - p) < (long)sizeof(kbuf) ? web_url_decode(p, (size_t)(kend - p), kbuf, sizeof(kbuf)) : -1;
        if (kn >= 0 && (size_t)kn == kl && memcmp(kbuf, key, kl) == 0) {
            if (!eq) {
                out[0] = '\0';
                return true;
            }
            return web_url_decode(eq + 1, (size_t)(end - eq - 1), out, cap) >= 0;
        }
        if (!amp) {
            break;
        }
        p = amp + 1;
    }
    return false;
}

bool web_cookie_get(const char *cookie_header, const char *name, char *out, size_t cap) {
    if (!cookie_header || !name || !out || !cap) {
        return false;
    }
    const size_t nl = strlen(name);
    const char *p = cookie_header;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ';') {
            p++;
        }
        const char *end = strchr(p, ';');
        if (!end) {
            end = p + strlen(p);
        }
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (eq) {
            const char *ke = eq;
            while (ke > p && (ke[-1] == ' ' || ke[-1] == '\t')) {
                ke--;
            }
            if ((size_t)(ke - p) == nl && memcmp(p, name, nl) == 0) {
                const char *v = eq + 1;
                const char *ve = end;
                while (v < ve && (*v == ' ' || *v == '\t')) {
                    v++;
                }
                while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) {
                    ve--;
                }
                if (ve - v >= 2 && *v == '"' && ve[-1] == '"') {
                    v++;
                    ve--;
                }
                const size_t vl = (size_t)(ve - v);
                if (vl + 1 > cap) {
                    return false;
                }
                memcpy(out, v, vl);
                out[vl] = '\0';
                return true;
            }
        }
        p = end;
    }
    return false;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

bool web_origin_matches_host(const char *origin, const char *host) {
    if (!origin || !host || !host[0]) {
        return false;
    }
    const char *p = origin;
    static const char *const schemes[] = {"http://", "https://"};
    size_t skip = 0;
    for (size_t i = 0; i < 2 && !skip; i++) {
        size_t n = strlen(schemes[i]);
        size_t j = 0;
        while (j < n && p[j] && lower(p[j]) == schemes[i][j]) {
            j++;
        }
        if (j == n) {
            skip = n;
        }
    }
    if (!skip) {
        return false; /* includes "null" */
    }
    p += skip;
    const char *e = p;
    while (*e && *e != '/' && *e != '?' && *e != '#') {
        if (*e == '@' || *e == ' ' || *e == '\\') {
            return false;
        }
        e++;
    }
    const size_t al = (size_t)(e - p);
    if (al == 0 || al != strlen(host)) {
        return false;
    }
    for (size_t i = 0; i < al; i++) {
        if (lower(p[i]) != lower(host[i])) {
            return false;
        }
    }
    return true;
}
