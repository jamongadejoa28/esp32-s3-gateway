/*
 * config_json.c - JSON mapping of gw_config_t (pure C, host-tested). Contract: store/config_json.h.
 *
 * Parsing uses cJSON; output uses the streaming gw_json_writer. One parser per section serves both
 * shapes: the file/export shape (lenient: unknown members ignored, secrets never present) and the
 * REST shape (strict: unknown members -> "unknown_field", write-only secrets moved into a
 * cfg_secret_input_t and wiped from the cJSON tree).
 */
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_ip4.h"
#include "mex150/regmap.h"
#include "store/config_json.h"
#include "store_priv.h"

#define JSON_MAX_DEPTH 16 /* config documents nest at most 5 levels; bounds cJSON recursion */
#define PATH_SZ 64

typedef struct {
    cfg_verr_t *err;
    bool strict;             /* REST: unknown members rejected */
    bool file;               /* file/export shape */
    cfg_secret_input_t *sec; /* REST secrets sink (NULL: secret members are unknown) */
} jctx_t;

/* ------------------------------------------------------------------ error/path helpers */

__attribute__((format(printf, 3, 4))) static bool jerr(jctx_t *c, const char *code, const char *fmt, ...) {
    if (c->err) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(c->err->field, sizeof(c->err->field), fmt, ap);
        va_end(ap);
        gw_strlcpy(c->err->code, code, sizeof(c->err->code));
    }
    return false;
}

/* "<base>.<key>"; silently truncated to the error field size (paths are diagnostics). */
static const char *jp(char out[PATH_SZ], const char *base, const char *key) {
    int n = snprintf(out, PATH_SZ, "%s.%s", base, key);
    if (n < 0)
        out[0] = '\0';
    return out;
}

static bool in_list(const char *name, const char *const *list) {
    for (; *list; list++)
        if (!strcmp(name, *list))
            return true;
    return false;
}

/* Strict mode: every member of obj must be in `allowed` (or `extra` when non-NULL). */
static bool j_members(jctx_t *c, const cJSON *obj, const char *const *allowed, const char *const *extra,
                      const char *path) {
    if (!c->strict)
        return true;
    const cJSON *it;
    cJSON_ArrayForEach(it, obj) {
        if (!it->string || (!in_list(it->string, allowed) && !(extra && in_list(it->string, extra))))
            return jerr(c, "unknown_field", "%s%s%s", path, path[0] ? "." : "", it->string ? it->string : "");
    }
    return true;
}

/* Is s[i..] (just after a backslash inside a string) the escape "u0000"? */
static bool is_nul_escape(const char *s, size_t len, size_t i) {
    return s[i] == 'u' && i + 4 < len && s[i + 1] == '0' && s[i + 2] == '0' && s[i + 3] == '0' && s[i + 4] == '0';
}

/*
 * Bounded nesting pre-scan (outside strings) so a hostile body cannot drive cJSON's recursion deep.
 * Also reports a \u0000 escape inside a string (*nul_esc): cJSON decodes it into an embedded NUL
 * that every strlen() would silently truncate at. When patch is true such escapes are rewritten to
 * \u0001 in place, so the value reaches the field validators as a control character (422 format).
 */
static bool json_scan(char *patch_buf, const char *s, size_t len, int max_depth, bool *nul_esc) {
    int depth = 0;
    bool in_str = false, esc = false;
    for (size_t i = 0; i < len; i++) {
        char ch = s[i];
        if (in_str) {
            if (esc) {
                esc = false;
                if (is_nul_escape(s, len, i)) {
                    if (nul_esc)
                        *nul_esc = true;
                    if (patch_buf)
                        patch_buf[i + 4] = '1';
                }
            } else if (ch == '\\') {
                esc = true;
            } else if (ch == '"') {
                in_str = false;
            }
            continue;
        }
        if (ch == '"')
            in_str = true;
        else if (ch == '{' || ch == '[') {
            if (++depth > max_depth)
                return false;
        } else if (ch == '}' || ch == ']')
            depth--;
    }
    return true;
}

static cJSON *parse_doc(const char *json, size_t len) {
    bool nul_esc = false;
    if (!json || len == 0 || !json_scan(NULL, json, len, JSON_MAX_DEPTH, &nul_esc))
        return NULL;
    if (!nul_esc)
        return cJSON_ParseWithLength(json, len);
    char *copy = malloc(len);
    if (!copy)
        return NULL;
    memcpy(copy, json, len);
    (void)json_scan(copy, json, len, JSON_MAX_DEPTH, NULL);
    cJSON *root = cJSON_ParseWithLength(copy, len);
    gw_secure_zero(copy, len); /* bodies may carry write-only secrets */
    free(copy);
    return root;
}

void store_json_wipe(cJSON *node) {
    for (; node; node = node->next) {
        if (cJSON_IsString(node) && node->valuestring)
            gw_secure_zero(node->valuestring, strlen(node->valuestring));
        if (node->child)
            store_json_wipe(node->child);
    }
}

/* Every parsed tree may hold write-only secrets on any path (also unknown members, type errors and
 * members after the first error): wipe all string values before freeing. */
static void delete_wiped(cJSON *root) {
    if (!root)
        return;
    store_json_wipe(root);
    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ typed getters
 * Each takes the member item (NULL = absent: nothing changes, success). */

static bool j_bool(jctx_t *c, const cJSON *it, bool *out, const char *path) {
    if (!it)
        return true;
    if (!cJSON_IsBool(it))
        return jerr(c, "type", "%s", path);
    *out = cJSON_IsTrue(it);
    return true;
}

static bool j_num(jctx_t *c, const cJSON *it, double *out, const char *path) {
    if (!cJSON_IsNumber(it))
        return jerr(c, "type", "%s", path);
    double d = it->valuedouble;
    if (!isfinite(d))
        return jerr(c, "type", "%s", path);
    *out = d;
    return true;
}

static bool j_i64(jctx_t *c, const cJSON *it, int64_t lo, int64_t hi, int64_t *out, const char *path) {
    double d;
    if (!j_num(c, it, &d, path))
        return false;
    if (d < -9.0e15 || d > 9.0e15 || floor(d) != d)
        return jerr(c, d == floor(d) ? "range" : "type", "%s", path);
    int64_t v = (int64_t)d;
    if (v < lo || v > hi)
        return jerr(c, "range", "%s", path);
    *out = v;
    return true;
}

#define J_UINT(c, it, hi, dst, path)                                                                         \
    do {                                                                                                     \
        if (it) {                                                                                            \
            int64_t v_;                                                                                      \
            if (!j_i64((c), (it), 0, (hi), &v_, (path)))                                                     \
                return false;                                                                                \
            (dst) = v_;                                                                                      \
        }                                                                                                    \
    } while (0)

static bool j_strtype(jctx_t *c, const cJSON *it, const char *path) {
    if (!cJSON_IsString(it) || !it->valuestring)
        return jerr(c, "type", "%s", path);
    return true;
}

/* UTF-8 text without control characters, at most max_bytes (and < cap). */
static bool j_text(jctx_t *c, const cJSON *it, char *dst, size_t cap, size_t max_bytes, const char *path) {
    if (!it)
        return true;
    if (!j_strtype(c, it, path))
        return false;
    size_t n = strlen(it->valuestring);
    if (n > max_bytes || n >= cap)
        return jerr(c, "length", "%s", path);
    if (!store_text_ok(it->valuestring, n + 1, max_bytes))
        return jerr(c, "format", "%s", path);
    store_strset(dst, cap, it->valuestring);
    return true;
}

/* Printable ASCII in [lo, hi], min..max chars (secrets, communities). */
static bool j_ascii(jctx_t *c, const cJSON *it, char *dst, size_t cap, size_t min_len, size_t max_len, char lo,
                    char hi, const char *path) {
    if (!j_strtype(c, it, path))
        return false;
    size_t n = strlen(it->valuestring);
    if (n < min_len || n > max_len || n >= cap)
        return jerr(c, "length", "%s", path);
    if (!store_ascii_ok(it->valuestring, n + 1, min_len, max_len, lo, hi))
        return jerr(c, "format", "%s", path);
    store_strset(dst, cap, it->valuestring);
    return true;
}

/* SNMPv3 passphrase: GW_SNMP_PASS_MIN..GW_SNMP_PASS_MAX bytes (as the web layer and the key
 * localization count them) of UTF-8 text without control characters (the schema has no pattern). */
static bool j_pass(jctx_t *c, const cJSON *it, char *dst, size_t cap, const char *path) {
    if (!j_strtype(c, it, path))
        return false;
    size_t n = strlen(it->valuestring);
    if (n < GW_SNMP_PASS_MIN || n > GW_SNMP_PASS_MAX || n >= cap)
        return jerr(c, "length", "%s", path);
    if (!store_text_ok(it->valuestring, n + 1, GW_SNMP_PASS_MAX))
        return jerr(c, "format", "%s", path);
    store_strset(dst, cap, it->valuestring);
    return true;
}

/* Wipe a secret string inside the cJSON tree once it has been consumed. */
static void j_wipe(const cJSON *it) {
    if (it && cJSON_IsString(it) && it->valuestring)
        gw_secure_zero(it->valuestring, strlen(it->valuestring));
}

static bool j_ip(jctx_t *c, const cJSON *it, bool optional, uint32_t *out, const char *path) {
    if (!it)
        return true;
    if (!j_strtype(c, it, path))
        return false;
    if (optional && it->valuestring[0] == '\0') {
        *out = 0;
        return true;
    }
    uint32_t ip;
    if (!gw_ip4_parse(it->valuestring, &ip))
        return jerr(c, "format", "%s", path);
    *out = ip;
    return true;
}

static bool j_obj(jctx_t *c, const cJSON *it, const char *path) {
    if (!cJSON_IsObject(it))
        return jerr(c, "type", "%s", path);
    return true;
}

static bool j_arr(jctx_t *c, const cJSON *it, int max_items, const char *path) {
    if (!cJSON_IsArray(it))
        return jerr(c, "type", "%s", path);
    if (cJSON_GetArraySize(it) > max_items)
        return jerr(c, "too_many", "%s", path);
    return true;
}

#define MEMBER(obj, name) cJSON_GetObjectItemCaseSensitive((obj), (name))

/* ------------------------------------------------------------------ section parsers */

static bool p_general(jctx_t *c, const cJSON *o, cfg_general_t *g) {
    static const char *const allowed[] = {"site", "location", "contact", "lang", NULL};
    char p[PATH_SZ];
    if (!j_obj(c, o, "general") || !j_members(c, o, allowed, NULL, "general"))
        return false;
    if (!j_text(c, MEMBER(o, "site"), g->site, sizeof(g->site), GW_TEXT_MAX, jp(p, "general", "site")) ||
        !j_text(c, MEMBER(o, "location"), g->location, sizeof(g->location), GW_TEXT_MAX,
                jp(p, "general", "location")) ||
        !j_text(c, MEMBER(o, "contact"), g->contact, sizeof(g->contact), GW_TEXT_MAX, jp(p, "general", "contact")))
        return false;
    const cJSON *l = MEMBER(o, "lang");
    if (l) {
        if (!j_strtype(c, l, "general.lang"))
            return false;
        if (strcmp(l->valuestring, "ko") != 0 && strcmp(l->valuestring, "en") != 0)
            return jerr(c, "range", "general.lang");
        store_strset(g->lang, sizeof(g->lang), l->valuestring);
    }
    return true;
}

static bool p_network(jctx_t *c, const cJSON *o, cfg_network_t *n) {
    static const char *const allowed[] = {"eth", "hostname", "ap", NULL};
    static const char *const eth_allowed[] = {"mode", "ip", "mask", "gw", "dns1", "dns2", NULL};
    static const char *const ap_allowed[] = {"fallback", "ssid", "channel", "idle_min", "fallback_after_s", NULL};
    static const char *const ap_secret[] = {"psk", NULL};
    if (!j_obj(c, o, "network") || !j_members(c, o, allowed, NULL, "network"))
        return false;
    const cJSON *e = MEMBER(o, "eth");
    if (e) {
        if (!j_obj(c, e, "network.eth") || !j_members(c, e, eth_allowed, NULL, "network.eth"))
            return false;
        const cJSON *m = MEMBER(e, "mode");
        if (m) {
            if (!j_strtype(c, m, "network.eth.mode"))
                return false;
            if (!strcmp(m->valuestring, "static"))
                n->eth.mode = CFG_ETH_STATIC;
            else if (!strcmp(m->valuestring, "dhcp"))
                n->eth.mode = CFG_ETH_DHCP;
            else
                return jerr(c, "range", "network.eth.mode");
        }
        if (!j_ip(c, MEMBER(e, "ip"), false, &n->eth.ip, "network.eth.ip") ||
            !j_ip(c, MEMBER(e, "mask"), false, &n->eth.mask, "network.eth.mask") ||
            !j_ip(c, MEMBER(e, "gw"), true, &n->eth.gw, "network.eth.gw") ||
            !j_ip(c, MEMBER(e, "dns1"), true, &n->eth.dns1, "network.eth.dns1") ||
            !j_ip(c, MEMBER(e, "dns2"), true, &n->eth.dns2, "network.eth.dns2"))
            return false;
    }
    const cJSON *h = MEMBER(o, "hostname");
    if (h && !j_ascii(c, h, n->hostname, sizeof(n->hostname), 1, GW_HOSTNAME_MAX, 0x21, 0x7E, "network.hostname"))
        return false;
    const cJSON *ap = MEMBER(o, "ap");
    if (ap) {
        if (!j_obj(c, ap, "network.ap") || !j_members(c, ap, ap_allowed, c->sec ? ap_secret : NULL, "network.ap"))
            return false;
        if (!j_bool(c, MEMBER(ap, "fallback"), &n->ap.fallback, "network.ap.fallback"))
            return false;
        const cJSON *ssid = MEMBER(ap, "ssid");
        if (ssid) {
            if (!j_text(c, ssid, n->ap.ssid, sizeof(n->ap.ssid), GW_SSID_MAX, "network.ap.ssid"))
                return false;
            if (n->ap.ssid[0] == '\0')
                return jerr(c, "length", "network.ap.ssid");
        }
        J_UINT(c, MEMBER(ap, "channel"), 255, n->ap.channel, "network.ap.channel");
        J_UINT(c, MEMBER(ap, "idle_min"), 65535, n->ap.idle_min, "network.ap.idle_min");
        J_UINT(c, MEMBER(ap, "fallback_after_s"), 65535, n->ap.fallback_after_s, "network.ap.fallback_after_s");
        const cJSON *psk = MEMBER(ap, "psk");
        if (psk && c->sec) {
            bool ok = j_ascii(c, psk, c->sec->ap_psk, sizeof(c->sec->ap_psk), GW_PSK_MIN, GW_PSK_MAX, 0x20, 0x7E,
                              "network.ap.psk");
            j_wipe(psk);
            if (!ok)
                return false;
            c->sec->has_ap_psk = true;
        }
    }
    return true;
}

static const mex_dev_cfg_t *find_dev(const cfg_modbus_t *m, uint8_t id) {
    if (!m)
        return NULL;
    for (unsigned i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++)
        if (m->devices[i].id == id)
            return &m->devices[i];
    return NULL;
}

static bool p_modbus(jctx_t *c, const cJSON *o, cfg_modbus_t *m, const cfg_modbus_t *cur) {
    static const char *const allowed[] = {"devices", "port",   "poll_ms",       "timeout_ms",
                                          "retries", "gap_ms", "offline_after", NULL};
    static const char *const dev_allowed[] = {"id", "name", "slave", "enabled", "template_id", "display_mask", NULL};
    static const char *const port_allowed[] = {"baud", "parity", "stop", NULL};
    char p[PATH_SZ];
    if (!j_obj(c, o, "modbus") || !j_members(c, o, allowed, NULL, "modbus"))
        return false;
    const cJSON *devs = MEMBER(o, "devices");
    if (devs) {
        if (!j_arr(c, devs, GW_MAX_DEVICES, "modbus.devices"))
            return false;
        mex_dev_cfg_t out[GW_MAX_DEVICES];
        memset(out, 0, sizeof(out));
        unsigned n = 0;
        const cJSON *d;
        cJSON_ArrayForEach(d, devs) {
            char base[PATH_SZ];
            snprintf(base, sizeof(base), "modbus.devices[%u]", n);
            if (!j_obj(c, d, base) || !j_members(c, d, dev_allowed, NULL, base))
                return false;
            const cJSON *idj = MEMBER(d, "id");
            if (!idj)
                return jerr(c, "required", "%s", jp(p, base, "id"));
            int64_t id;
            if (!j_i64(c, idj, 0, GW_MAX_DEVICES - 1, &id, jp(p, base, "id")))
                return false;
            const mex_dev_cfg_t *prev = find_dev(cur, (uint8_t)id);
            mex_dev_cfg_t *dv = &out[n];
            if (prev) {
                *dv = *prev;
            } else {
                dv->id = (uint8_t)id;
                dv->slave = (uint8_t)(id + 1);
                dv->enabled = true;
                dv->display_mask = GW_CHANNEL_DISPLAY_DEFAULT;
                store_strset(dv->name, sizeof(dv->name), "");
            }
            if (!dv->template_id[0])
                store_strset(dv->template_id, sizeof(dv->template_id), GW_DEFAULT_TEMPLATE_ID);
            if (!j_text(c, MEMBER(d, "template_id"), dv->template_id, sizeof(dv->template_id),
                        GW_TEMPLATE_ID_SZ - 1, jp(p, base, "template_id")))
                return false;
            if (!gw_device_template_find(dv->template_id))
                return jerr(c, "range", "%s", jp(p, base, "template_id"));
            if (!j_text(c, MEMBER(d, "name"), dv->name, sizeof(dv->name), GW_DEV_NAME_SZ - 1, jp(p, base, "name")))
                return false;
            J_UINT(c, MEMBER(d, "display_mask"), UINT32_MAX, dv->display_mask, jp(p, base, "display_mask"));
            J_UINT(c, MEMBER(d, "slave"), 255, dv->slave, jp(p, base, "slave"));
            if (!j_bool(c, MEMBER(d, "enabled"), &dv->enabled, jp(p, base, "enabled")))
                return false;
            n++;
        }
        memcpy(m->devices, out, sizeof(out));
        m->n_devices = (uint8_t)n;
    }
    const cJSON *port = MEMBER(o, "port");
    if (port) {
        if (!j_obj(c, port, "modbus.port") || !j_members(c, port, port_allowed, NULL, "modbus.port"))
            return false;
        J_UINT(c, MEMBER(port, "baud"), 4000000, m->port.baud, "modbus.port.baud");
        const cJSON *par = MEMBER(port, "parity");
        if (par) {
            if (!j_strtype(c, par, "modbus.port.parity"))
                return false;
            const char *v = par->valuestring;
            if (strlen(v) != 1 || !strchr("NEO", v[0]))
                return jerr(c, "range", "modbus.port.parity");
            m->port.parity = v[0];
        }
        J_UINT(c, MEMBER(port, "stop"), 255, m->port.stop, "modbus.port.stop");
    }
    J_UINT(c, MEMBER(o, "poll_ms"), 65535, m->port.poll_ms, "modbus.poll_ms");
    J_UINT(c, MEMBER(o, "timeout_ms"), 65535, m->port.timeout_ms, "modbus.timeout_ms");
    J_UINT(c, MEMBER(o, "retries"), 255, m->port.retries, "modbus.retries");
    J_UINT(c, MEMBER(o, "gap_ms"), 65535, m->port.gap_ms, "modbus.gap_ms");
    J_UINT(c, MEMBER(o, "offline_after"), 255, m->port.offline_after, "modbus.offline_after");
    return true;
}

/* "temp" | "hum" | "cur" | "reg:<4xxxx>" -> register address (0 if malformed). */
static uint16_t rule_src_addr(const char *s) {
    if (!strcmp(s, "temp"))
        return 40036;
    if (!strcmp(s, "hum"))
        return 40037;
    if (!strcmp(s, "cur"))
        return 40011;
    if (strncmp(s, "reg:", 4) != 0)
        return 0;
    s += 4;
    unsigned v = 0;
    for (int i = 0; i < 5; i++) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        v = v * 10u + (unsigned)(s[i] - '0');
    }
    if (s[5] != '\0' || v < 40000 || v > 49999)
        return 0;
    return (uint16_t)v;
}

static bool p_rule(jctx_t *c, const cJSON *o, cfg_rule_t *r, unsigned idx) {
    static const char *const allowed[] = {"id", "name", "enabled", "dev",     "src",
                                          "op", "thr",  "hyst",    "delay_s", "sev", NULL};
    char base[PATH_SZ], p[PATH_SZ];
    snprintf(base, sizeof(base), "alarms.rules[%u]", idx);
    if (!j_obj(c, o, base) || !j_members(c, o, allowed, NULL, base))
        return false;
    memset(r, 0, sizeof(*r));
    r->enabled = true;
    r->sev = 2;
    r->op = CFG_OP_GT;
    static const char *const required[] = {"id", "src", "op", "thr", NULL};
    for (const char *const *k = required; *k; k++)
        if (!MEMBER(o, *k))
            return jerr(c, "required", "%s", jp(p, base, *k));
    J_UINT(c, MEMBER(o, "id"), 255, r->id, jp(p, base, "id"));
    if (!j_text(c, MEMBER(o, "name"), r->name, sizeof(r->name), GW_RULE_NAME_SZ - 1, jp(p, base, "name")) ||
        !j_bool(c, MEMBER(o, "enabled"), &r->enabled, jp(p, base, "enabled")))
        return false;
    J_UINT(c, MEMBER(o, "dev"), 255, r->dev, jp(p, base, "dev"));
    const cJSON *src = MEMBER(o, "src");
    if (!j_strtype(c, src, jp(p, base, "src")))
        return false;
    r->addr = rule_src_addr(src->valuestring);
    if (!r->addr)
        return jerr(c, "format", "%s", jp(p, base, "src"));
    const mex_reg_t *reg = mex_reg_find(r->addr);
    if (!reg)
        return jerr(c, "unknown_register", "%s", jp(p, base, "src"));
    const cJSON *op = MEMBER(o, "op");
    if (!j_strtype(c, op, jp(p, base, "op")))
        return false;
    if (!strcmp(op->valuestring, ">"))
        r->op = CFG_OP_GT;
    else if (!strcmp(op->valuestring, "<"))
        r->op = CFG_OP_LT;
    else
        return jerr(c, "range", "%s", jp(p, base, "op"));
    double d;
    int32_t raw;
    if (!j_num(c, MEMBER(o, "thr"), &d, jp(p, base, "thr")))
        return false;
    if (!mex_reg_from_value(reg, d, &raw))
        return jerr(c, "range", "%s", jp(p, base, "thr"));
    r->thr = raw;
    const cJSON *hy = MEMBER(o, "hyst");
    if (hy) {
        if (!j_num(c, hy, &d, jp(p, base, "hyst")))
            return false;
        if (d < 0 || !mex_reg_from_value(reg, d, &raw))
            return jerr(c, "range", "%s", jp(p, base, "hyst"));
        r->hyst = raw;
    }
    J_UINT(c, MEMBER(o, "delay_s"), 65535, r->delay_s, jp(p, base, "delay_s"));
    J_UINT(c, MEMBER(o, "sev"), 255, r->sev, jp(p, base, "sev"));
    return true;
}

static bool p_rules(jctx_t *c, const cJSON *arr, cfg_alarms_t *a) {
    if (!j_arr(c, arr, GW_MAX_RULES, "alarms.rules"))
        return false;
    cfg_rule_t rules[GW_MAX_RULES];
    unsigned n = 0;
    const cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        if (!p_rule(c, it, &rules[n], n))
            return false;
        n++;
    }
    memset(a->rules, 0, sizeof(a->rules));
    memcpy(a->rules, rules, n * sizeof(rules[0]));
    a->n_rules = (uint8_t)n;
    return true;
}

static bool p_alarms(jctx_t *c, const cJSON *o, cfg_alarms_t *a) {
    static const char *const allowed[] = {"debounce_raise", "debounce_clear", "sev_override", NULL};
    static const char *const file_extra[] = {"rules", NULL};
    if (!j_obj(c, o, "alarms") || !j_members(c, o, allowed, c->file ? file_extra : NULL, "alarms"))
        return false;
    J_UINT(c, MEMBER(o, "debounce_raise"), 255, a->debounce_raise, "alarms.debounce_raise");
    J_UINT(c, MEMBER(o, "debounce_clear"), 255, a->debounce_clear, "alarms.debounce_clear");
    const cJSON *ov = MEMBER(o, "sev_override");
    if (ov) {
        if (!j_obj(c, ov, "alarms.sev_override"))
            return false;
        const cfg_alarm_catalog_t *cat = cfg_alarm_catalog();
        cfg_sev_override_t tmp[GW_MAX_SEV_OVERRIDES];
        memset(tmp, 0, sizeof(tmp)); /* padding too: sections are compared byte-wise on commit */
        unsigned n = 0;
        const cJSON *it;
        cJSON_ArrayForEach(it, ov) {
            char p[PATH_SZ];
            snprintf(p, sizeof(p), "alarms.sev_override.%s", it->string ? it->string : "");
            uint16_t code = 0;
            if (!it->string || !cat || !cat->code_from_id || !cat->code_from_id(it->string, &code)) {
                if (c->file)
                    continue; /* stale id in a stored/imported file: dropped, not fatal */
                return jerr(c, "unknown_field", "%s", p);
            }
            int64_t sev;
            if (!j_i64(c, it, 0, 3, &sev, p))
                return false;
            bool dup = false;
            for (unsigned k = 0; k < n; k++) {
                if (tmp[k].code == code) {
                    tmp[k].sev = (uint8_t)sev;
                    dup = true;
                }
            }
            if (dup)
                continue;
            if (n >= GW_MAX_SEV_OVERRIDES)
                return jerr(c, "too_many", "alarms.sev_override");
            tmp[n].code = code;
            tmp[n].sev = (uint8_t)sev;
            n++;
        }
        memset(a->sev_override, 0, sizeof(a->sev_override));
        memcpy(a->sev_override, tmp, n * sizeof(tmp[0]));
        a->n_sev_override = (uint8_t)n;
    }
    if (c->file) {
        const cJSON *rules = MEMBER(o, "rules");
        if (rules && !p_rules(c, rules, a))
            return false;
    }
    return true;
}

static const cfg_trap_t *find_trap(const cfg_snmp_t *s, const char *host, uint16_t port) {
    if (!s)
        return NULL;
    for (unsigned i = 0; i < s->n_traps && i < GW_MAX_TRAP_TARGETS; i++)
        if (s->traps[i].port == port && !strncmp(s->traps[i].host, host, GW_HOST_SZ))
            return &s->traps[i];
    return NULL;
}

static bool p_snmp(jctx_t *c, const cJSON *o, cfg_snmp_t *s, const cfg_snmp_t *cur) {
    static const char *const allowed[] = {"enabled", "v1", "v2c", "auth_traps", "v3", "traps", "sys", NULL};
    static const char *const secret[] = {"ro", "rw", NULL};
    static const char *const v3_allowed[] = {"enabled", "users", NULL};
    static const char *const user_allowed[] = {"name", "access", "enabled", NULL};
    static const char *const user_secret[] = {"auth_pass", "priv_pass", NULL};
    static const char *const trap_allowed[] = {"host", "port", "version", "inform", "enabled", NULL};
    static const char *const trap_secret[] = {"community", NULL};
    static const char *const sys_allowed[] = {"name", "contact", "location", NULL};
    char p[PATH_SZ];
    if (!j_obj(c, o, "snmp") || !j_members(c, o, allowed, c->sec ? secret : NULL, "snmp"))
        return false;
    if (!j_bool(c, MEMBER(o, "enabled"), &s->enabled, "snmp.enabled") ||
        !j_bool(c, MEMBER(o, "v1"), &s->v1, "snmp.v1") || !j_bool(c, MEMBER(o, "v2c"), &s->v2c, "snmp.v2c") ||
        !j_bool(c, MEMBER(o, "auth_traps"), &s->auth_traps, "snmp.auth_traps"))
        return false;
    if (c->sec) {
        const cJSON *ro = MEMBER(o, "ro"), *rw = MEMBER(o, "rw");
        if (ro) {
            bool ok = j_ascii(c, ro, c->sec->snmp_ro, sizeof(c->sec->snmp_ro), 0, GW_COMMUNITY_MAX, 0x21, 0x7E,
                              "snmp.ro");
            j_wipe(ro);
            if (!ok)
                return false;
            c->sec->has_snmp_ro = true;
        }
        if (rw) {
            bool ok = j_ascii(c, rw, c->sec->snmp_rw, sizeof(c->sec->snmp_rw), 0, GW_COMMUNITY_MAX, 0x21, 0x7E,
                              "snmp.rw");
            j_wipe(rw);
            if (!ok)
                return false;
            c->sec->has_snmp_rw = true;
        }
    }
    const cJSON *v3 = MEMBER(o, "v3");
    if (v3) {
        if (!j_obj(c, v3, "snmp.v3") || !j_members(c, v3, v3_allowed, NULL, "snmp.v3") ||
            !j_bool(c, MEMBER(v3, "enabled"), &s->v3, "snmp.v3.enabled"))
            return false;
        const cJSON *users = MEMBER(v3, "users");
        if (users) {
            if (!j_arr(c, users, GW_MAX_SNMP_V3_USERS, "snmp.v3.users"))
                return false;
            unsigned i = 0;
            const cJSON *u;
            cJSON_ArrayForEach(u, users) {
                char base[PATH_SZ];
                snprintf(base, sizeof(base), "snmp.v3.users[%u]", i);
                if (!j_obj(c, u, base) || !j_members(c, u, user_allowed, c->sec ? user_secret : NULL, base))
                    return false;
                cfg_snmp_v3user_t *dst = &s->users[i];
                const cJSON *nm = MEMBER(u, "name");
                if (nm && !j_ascii(c, nm, dst->name, sizeof(dst->name), 1, GW_SNMP_USER_MAX, 0x21, 0x7E,
                                   jp(p, base, "name")))
                    return false;
                const cJSON *ac = MEMBER(u, "access");
                if (ac) {
                    if (!j_strtype(c, ac, jp(p, base, "access")))
                        return false;
                    if (!strcmp(ac->valuestring, "ro"))
                        dst->access = CFG_SNMP_RO;
                    else if (!strcmp(ac->valuestring, "rw"))
                        dst->access = CFG_SNMP_RW;
                    else
                        return jerr(c, "range", "%s", jp(p, base, "access"));
                }
                if (!j_bool(c, MEMBER(u, "enabled"), &dst->enabled, jp(p, base, "enabled")))
                    return false;
                if (c->sec) {
                    const cJSON *ap = MEMBER(u, "auth_pass"), *pp = MEMBER(u, "priv_pass");
                    if (ap) {
                        bool ok = j_pass(c, ap, c->sec->v3[i].auth_pass, sizeof(c->sec->v3[i].auth_pass),
                                         jp(p, base, "auth_pass"));
                        j_wipe(ap);
                        if (!ok)
                            return false;
                        c->sec->v3[i].has_auth = true;
                    }
                    if (pp) {
                        bool ok = j_pass(c, pp, c->sec->v3[i].priv_pass, sizeof(c->sec->v3[i].priv_pass),
                                         jp(p, base, "priv_pass"));
                        j_wipe(pp);
                        if (!ok)
                            return false;
                        c->sec->v3[i].has_priv = true;
                    }
                }
                i++;
            }
        }
    }
    const cJSON *traps = MEMBER(o, "traps");
    if (traps) {
        if (!j_arr(c, traps, GW_MAX_TRAP_TARGETS, "snmp.traps"))
            return false;
        cfg_trap_t out[GW_MAX_TRAP_TARGETS];
        memset(out, 0, sizeof(out));
        unsigned n = 0;
        const cJSON *t;
        cJSON_ArrayForEach(t, traps) {
            char base[PATH_SZ];
            snprintf(base, sizeof(base), "snmp.traps[%u]", n);
            if (!j_obj(c, t, base) || !j_members(c, t, trap_allowed, c->sec ? trap_secret : NULL, base))
                return false;
            const cJSON *hj = MEMBER(t, "host");
            if (!hj)
                return jerr(c, "required", "%s", jp(p, base, "host"));
            char host[GW_HOST_SZ];
            if (!j_ascii(c, hj, host, sizeof(host), 1, GW_HOST_MAX, 0x21, 0x7E, jp(p, base, "host")))
                return false;
            uint16_t port = 162;
            J_UINT(c, MEMBER(t, "port"), 65535, port, jp(p, base, "port"));
            cfg_trap_t *dst = &out[n];
            const cfg_trap_t *prev = find_trap(cur, host, port);
            if (prev) {
                *dst = *prev;
            } else {
                dst->enabled = true;
                dst->version = CFG_SNMP_V2C;
                dst->inform = false;
            }
            store_strset(dst->host, sizeof(dst->host), host);
            dst->port = port;
            const cJSON *ver = MEMBER(t, "version");
            if (ver) {
                if (!j_strtype(c, ver, jp(p, base, "version")))
                    return false;
                if (!strcmp(ver->valuestring, "v1"))
                    dst->version = CFG_SNMP_V1;
                else if (!strcmp(ver->valuestring, "v2c"))
                    dst->version = CFG_SNMP_V2C;
                else
                    return jerr(c, "range", "%s", jp(p, base, "version"));
            }
            if (!j_bool(c, MEMBER(t, "inform"), &dst->inform, jp(p, base, "inform")) ||
                !j_bool(c, MEMBER(t, "enabled"), &dst->enabled, jp(p, base, "enabled")))
                return false;
            const cJSON *cm = c->sec ? MEMBER(t, "community") : NULL;
            if (cm) {
                bool ok = j_ascii(c, cm, c->sec->trap[n].community, sizeof(c->sec->trap[n].community), 1,
                                  GW_COMMUNITY_MAX, 0x21, 0x7E, jp(p, base, "community"));
                j_wipe(cm);
                if (!ok)
                    return false;
                c->sec->trap[n].has = true;
            }
            n++;
        }
        memcpy(s->traps, out, sizeof(out));
        s->n_traps = (uint8_t)n;
        if (c->sec) {
            c->sec->has_traps = true;
            cfg_trap_remap(cur, s, c->sec->trap_from);
        }
    }
    const cJSON *sys = MEMBER(o, "sys");
    if (sys) {
        if (!j_obj(c, sys, "snmp.sys") || !j_members(c, sys, sys_allowed, NULL, "snmp.sys"))
            return false;
        if (!j_text(c, MEMBER(sys, "name"), s->sys_name, sizeof(s->sys_name), GW_TEXT_MAX, "snmp.sys.name") ||
            !j_text(c, MEMBER(sys, "contact"), s->sys_contact, sizeof(s->sys_contact), GW_TEXT_MAX,
                    "snmp.sys.contact") ||
            !j_text(c, MEMBER(sys, "location"), s->sys_location, sizeof(s->sys_location), GW_TEXT_MAX,
                    "snmp.sys.location"))
            return false;
    }
    return true;
}

static bool p_time(jctx_t *c, const cJSON *o, cfg_time_t *t) {
    static const char *const allowed[] = {"ntp", "tz", NULL};
    static const char *const ntp_allowed[] = {"enabled", "servers", "interval_min", NULL};
    if (!j_obj(c, o, "time") || !j_members(c, o, allowed, NULL, "time"))
        return false;
    const cJSON *ntp = MEMBER(o, "ntp");
    if (ntp) {
        if (!j_obj(c, ntp, "time.ntp") || !j_members(c, ntp, ntp_allowed, NULL, "time.ntp") ||
            !j_bool(c, MEMBER(ntp, "enabled"), &t->ntp_enabled, "time.ntp.enabled"))
            return false;
        const cJSON *sv = MEMBER(ntp, "servers");
        if (sv) {
            if (!j_arr(c, sv, GW_MAX_NTP_SERVERS, "time.ntp.servers"))
                return false;
            char tmp[GW_MAX_NTP_SERVERS][GW_HOST_SZ];
            memset(tmp, 0, sizeof(tmp));
            unsigned i = 0;
            const cJSON *it;
            cJSON_ArrayForEach(it, sv) {
                char p[PATH_SZ];
                snprintf(p, sizeof(p), "time.ntp.servers[%u]", i);
                if (!j_ascii(c, it, tmp[i], sizeof(tmp[i]), 1, GW_HOST_MAX, 0x21, 0x7E, p))
                    return false;
                i++;
            }
            memcpy(t->servers, tmp, sizeof(tmp));
        }
        J_UINT(c, MEMBER(ntp, "interval_min"), 65535, t->interval_min, "time.ntp.interval_min");
    }
    const cJSON *tz = MEMBER(o, "tz");
    if (tz && !j_ascii(c, tz, t->tz, sizeof(t->tz), 1, GW_TZ_SZ - 1, 0x21, 0x7E, "time.tz"))
        return false;
    return true;
}

static bool p_security(jctx_t *c, const cJSON *o, cfg_security_t *s) {
    static const char *const allowed[] = {"idle_min", "lockout", "ip_allow", "services", NULL};
    static const char *const lock_allowed[] = {"max_fail", "lock_min", NULL};
    static const char *const svc_allowed[] = {"snmp", "syslog", NULL};
    if (!j_obj(c, o, "security") || !j_members(c, o, allowed, NULL, "security"))
        return false;
    J_UINT(c, MEMBER(o, "idle_min"), 65535, s->idle_min, "security.idle_min");
    const cJSON *lk = MEMBER(o, "lockout");
    if (lk) {
        if (!j_obj(c, lk, "security.lockout") || !j_members(c, lk, lock_allowed, NULL, "security.lockout"))
            return false;
        J_UINT(c, MEMBER(lk, "max_fail"), 255, s->max_fail, "security.lockout.max_fail");
        J_UINT(c, MEMBER(lk, "lock_min"), 255, s->lock_min, "security.lockout.lock_min");
    }
    const cJSON *al = MEMBER(o, "ip_allow");
    if (al) {
        if (!j_arr(c, al, GW_MAX_IP_ALLOW, "security.ip_allow"))
            return false;
        cfg_cidr_t tmp[GW_MAX_IP_ALLOW];
        memset(tmp, 0, sizeof(tmp));
        unsigned n = 0;
        const cJSON *it;
        cJSON_ArrayForEach(it, al) {
            char p[PATH_SZ];
            snprintf(p, sizeof(p), "security.ip_allow[%u]", n);
            if (!j_strtype(c, it, p))
                return false;
            if (!gw_cidr_parse(it->valuestring, &tmp[n].net, &tmp[n].mask))
                return jerr(c, "format", "%s", p);
            n++;
        }
        memcpy(s->ip_allow, tmp, sizeof(tmp));
        s->n_ip_allow = (uint8_t)n;
    }
    const cJSON *sv = MEMBER(o, "services");
    if (sv) {
        if (!j_obj(c, sv, "security.services") || !j_members(c, sv, svc_allowed, NULL, "security.services") ||
            !j_bool(c, MEMBER(sv, "snmp"), &s->svc_snmp, "security.services.snmp") ||
            !j_bool(c, MEMBER(sv, "syslog"), &s->svc_syslog, "security.services.syslog"))
            return false;
    }
    return true;
}

static bool p_notify(jctx_t *c, const cJSON *o, cfg_notify_t *n) {
    static const char *const allowed[] = {"syslog", NULL};
    static const char *const sl_allowed[] = {"enabled", "host", "port", "facility", "min_sev", NULL};
    if (!j_obj(c, o, "notify") || !j_members(c, o, allowed, NULL, "notify"))
        return false;
    const cJSON *sl = MEMBER(o, "syslog");
    if (sl) {
        if (!j_obj(c, sl, "notify.syslog") || !j_members(c, sl, sl_allowed, NULL, "notify.syslog") ||
            !j_bool(c, MEMBER(sl, "enabled"), &n->syslog_enabled, "notify.syslog.enabled"))
            return false;
        const cJSON *h = MEMBER(sl, "host");
        if (h && !j_ascii(c, h, n->host, sizeof(n->host), 0, GW_HOST_MAX, 0x21, 0x7E, "notify.syslog.host"))
            return false;
        J_UINT(c, MEMBER(sl, "port"), 65535, n->port, "notify.syslog.port");
        J_UINT(c, MEMBER(sl, "facility"), 255, n->facility, "notify.syslog.facility");
        J_UINT(c, MEMBER(sl, "min_sev"), 255, n->min_sev, "notify.syslog.min_sev");
    }
    return true;
}

/* Parse section s from obj into sec (already holding the base values). cur: for merge lookups. */
static bool p_section(jctx_t *c, cfg_section_t s, const cJSON *obj, void *sec, const gw_config_t *cur) {
    switch (s) {
    case CFG_SEC_GENERAL:
        return p_general(c, obj, sec);
    case CFG_SEC_NETWORK:
        return p_network(c, obj, sec);
    case CFG_SEC_MODBUS:
        return p_modbus(c, obj, sec, cur ? &cur->modbus : NULL);
    case CFG_SEC_ALARMS:
        return p_alarms(c, obj, sec);
    case CFG_SEC_SNMP:
        return p_snmp(c, obj, sec, cur ? &cur->snmp : NULL);
    case CFG_SEC_TIME:
        return p_time(c, obj, sec);
    case CFG_SEC_SECURITY:
        return p_security(c, obj, sec);
    case CFG_SEC_NOTIFY:
        return p_notify(c, obj, sec);
    default:
        return jerr(c, "unknown_field", "%s", "");
    }
}

/* ------------------------------------------------------------------ migration */

/* Single-step migrators: s_migrate[v] upgrades a document from schema v to v + 1 in place.
 * Schema 1 is the first version, so the chain is currently empty. */
typedef int (*cfg_migrator_t)(cJSON *root, cfg_verr_t *err);
static const cfg_migrator_t s_migrate[CFG_SCHEMA_VERSION + 1] = {NULL};

int cfg_migrate(struct cJSON *root, int from, cfg_verr_t *err) {
    if (err) {
        err->field[0] = '\0';
        err->code[0] = '\0';
    }
    if (!cJSON_IsObject(root))
        return CFG_JSON_E_PARSE;
    if (from > CFG_SCHEMA_VERSION) {
        if (err) {
            gw_strlcpy(err->field, "schema", sizeof(err->field));
            gw_strlcpy(err->code, "unsupported_schema", sizeof(err->code));
        }
        return CFG_JSON_E_SCHEMA;
    }
    if (from < 1) {
        if (err) {
            gw_strlcpy(err->field, "schema", sizeof(err->field));
            gw_strlcpy(err->code, "range", sizeof(err->code));
        }
        return CFG_JSON_E_INVALID;
    }
    for (int v = from; v < CFG_SCHEMA_VERSION; v++) {
        if (!s_migrate[v]) {
            if (err) {
                gw_strlcpy(err->field, "schema", sizeof(err->field));
                gw_strlcpy(err->code, "unsupported_schema", sizeof(err->code));
            }
            return CFG_JSON_E_SCHEMA;
        }
        int rc = s_migrate[v](root, err);
        if (rc != CFG_JSON_OK)
            return rc;
    }
    cJSON *sch = cJSON_GetObjectItemCaseSensitive(root, "schema");
    if (sch && cJSON_IsNumber(sch))
        cJSON_SetNumberValue(sch, CFG_SCHEMA_VERSION);
    return CFG_JSON_OK;
}

/* ------------------------------------------------------------------ whole document */

int cfg_from_json_ex(const char *json, size_t len, const uint8_t mac[GW_MAC_LEN], gw_config_t *out,
                     cfg_verr_t *err, int *schema_from) {
    if (schema_from)
        *schema_from = 0;
    if (err) {
        err->field[0] = '\0';
        err->code[0] = '\0';
    }
    if (!out)
        return CFG_JSON_E_PARSE;
    cfg_defaults(out, mac);
    cJSON *root = parse_doc(json, len);
    if (!root || !cJSON_IsObject(root)) {
        delete_wiped(root);
        return CFG_JSON_E_PARSE;
    }
    jctx_t c = {.err = err, .strict = false, .file = true, .sec = NULL};
    int rc = CFG_JSON_OK;
    int from = 1;
    const cJSON *sch = MEMBER(root, "schema");
    if (sch) {
        int64_t v;
        if (!j_i64(&c, sch, 0, INT32_MAX, &v, "schema")) {
            rc = CFG_JSON_E_INVALID;
            goto out;
        }
        from = (int)v;
    }
    if (schema_from)
        *schema_from = from;
    rc = cfg_migrate(root, from, err);
    if (rc != CFG_JSON_OK)
        goto out;
    const cJSON *rev = MEMBER(root, "rev");
    if (rev) {
        int64_t v;
        if (!j_i64(&c, rev, 0, UINT32_MAX, &v, "rev")) {
            rc = CFG_JSON_E_INVALID;
            goto out;
        }
        out->rev = (uint32_t)v;
    }
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++) {
        const cJSON *so = MEMBER(root, cfg_section_name((cfg_section_t)s));
        if (!so)
            continue;
        /* Merge base for keyed arrays (devices by id, traps by host:port) = the defaults in `out`
         * (the section parsers finish all lookups before they overwrite the array). */
        if (!p_section(&c, (cfg_section_t)s, so, cfg_section_ptr(out, (cfg_section_t)s), out)) {
            rc = CFG_JSON_E_INVALID;
            goto out;
        }
    }
    out->schema = CFG_SCHEMA_VERSION;
    if (!cfg_validate(out, err))
        rc = CFG_JSON_E_INVALID;
out:
    delete_wiped(root);
    return rc;
}

int cfg_from_json(const char *json, size_t len, const uint8_t mac[GW_MAC_LEN], gw_config_t *out,
                  cfg_verr_t *err) {
    return cfg_from_json_ex(json, len, mac, out, err, NULL);
}

int cfg_section_from_json(cfg_section_t s, const char *json, size_t len, const gw_config_t *cur, void *out_sec,
                          cfg_secret_input_t *secrets, cfg_verr_t *err) {
    if (err) {
        err->field[0] = '\0';
        err->code[0] = '\0';
    }
    if (secrets) {
        memset(secrets, 0, sizeof(*secrets));
        for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
            secrets->trap_from[i] = -1;
    }
    size_t sz = cfg_section_size(s);
    if (!cur || !out_sec || sz == 0)
        return CFG_JSON_E_INVALID;
    cJSON *root = parse_doc(json, len);
    if (!root || !cJSON_IsObject(root)) {
        delete_wiped(root);
        return CFG_JSON_E_PARSE;
    }
    memcpy(out_sec, cfg_section_cptr(cur, s), sz);
    bool takes_secrets = (s == CFG_SEC_NETWORK || s == CFG_SEC_SNMP);
    jctx_t c = {.err = err, .strict = true, .file = false, .sec = takes_secrets ? secrets : NULL};
    bool ok = p_section(&c, s, root, out_sec, cur);
    delete_wiped(root);
    if (!ok) {
        if (secrets)
            gw_secure_zero(secrets, sizeof(*secrets));
        return CFG_JSON_E_INVALID;
    }
    return CFG_JSON_OK;
}

int cfg_rules_from_json(const char *json, size_t len, cfg_alarms_t *inout, cfg_verr_t *err) {
    if (err) {
        err->field[0] = '\0';
        err->code[0] = '\0';
    }
    if (!inout)
        return CFG_JSON_E_INVALID;
    cJSON *root = parse_doc(json, len);
    if (!root || !cJSON_IsArray(root)) {
        delete_wiped(root);
        return CFG_JSON_E_PARSE;
    }
    jctx_t c = {.err = err, .strict = true, .file = false, .sec = NULL};
    bool ok = p_rules(&c, root, inout);
    delete_wiped(root);
    return ok ? CFG_JSON_OK : CFG_JSON_E_INVALID;
}

/* ------------------------------------------------------------------ writers */

static void w_ip(gw_jw_t *w, const char *k, uint32_t ip, bool optional) {
    if (optional && ip == 0) {
        gw_jw_kstr(w, k, "");
        return;
    }
    char b[GW_IP4_STR_SZ];
    gw_ip4_format(ip, b);
    gw_jw_kstr(w, k, b);
}

static void w_general(gw_jw_t *w, const cfg_general_t *g) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "site", g->site);
    gw_jw_kstr(w, "location", g->location);
    gw_jw_kstr(w, "contact", g->contact);
    gw_jw_kstr(w, "lang", g->lang);
    gw_jw_obj_close(w);
}

/* rest: REST GET shape (psk_set when flags, provisional when prov_json != NULL). */
static void w_network(gw_jw_t *w, const cfg_network_t *n, bool rest, const cfg_secret_flags_t *flags,
                      const char *prov_json) {
    gw_jw_obj_open(w);
    gw_jw_kobj(w, "eth");
    gw_jw_kstr(w, "mode", n->eth.mode == CFG_ETH_DHCP ? "dhcp" : "static");
    w_ip(w, "ip", n->eth.ip, false);
    w_ip(w, "mask", n->eth.mask, false);
    w_ip(w, "gw", n->eth.gw, true);
    w_ip(w, "dns1", n->eth.dns1, true);
    w_ip(w, "dns2", n->eth.dns2, true);
    gw_jw_obj_close(w);
    gw_jw_kstr(w, "hostname", n->hostname);
    gw_jw_kobj(w, "ap");
    gw_jw_kbool(w, "fallback", n->ap.fallback);
    gw_jw_kstr(w, "ssid", n->ap.ssid);
    if (rest && flags)
        gw_jw_kbool(w, "psk_set", flags->ap_psk_set);
    gw_jw_kuint(w, "channel", n->ap.channel);
    gw_jw_kuint(w, "idle_min", n->ap.idle_min);
    gw_jw_kuint(w, "fallback_after_s", n->ap.fallback_after_s);
    gw_jw_obj_close(w);
    if (rest) {
        gw_jw_key(w, "provisional");
        if (prov_json && prov_json[0])
            gw_jw_raw(w, prov_json, strlen(prov_json));
        else
            gw_jw_null(w);
    }
    gw_jw_obj_close(w);
}

static void w_modbus(gw_jw_t *w, const cfg_modbus_t *m) {
    gw_jw_obj_open(w);
    gw_jw_karr(w, "devices");
    for (unsigned i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++) {
        const mex_dev_cfg_t *d = &m->devices[i];
        gw_jw_obj_open(w);
        gw_jw_kuint(w, "id", d->id);
        gw_jw_kstr(w, "name", d->name);
        gw_jw_kstr(w, "template_id", d->template_id[0] ? d->template_id : GW_DEFAULT_TEMPLATE_ID);
        gw_jw_kuint(w, "display_mask", d->display_mask);
        gw_jw_kuint(w, "slave", d->slave);
        gw_jw_kbool(w, "enabled", d->enabled);
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_kobj(w, "port");
    gw_jw_kuint(w, "baud", m->port.baud);
    char par[2] = {m->port.parity, '\0'};
    gw_jw_kstr(w, "parity", par);
    gw_jw_kuint(w, "stop", m->port.stop);
    gw_jw_obj_close(w);
    gw_jw_kuint(w, "poll_ms", m->port.poll_ms);
    gw_jw_kuint(w, "timeout_ms", m->port.timeout_ms);
    gw_jw_kuint(w, "retries", m->port.retries);
    gw_jw_kuint(w, "gap_ms", m->port.gap_ms);
    gw_jw_kuint(w, "offline_after", m->port.offline_after);
    gw_jw_obj_close(w);
}

static void w_rule(gw_jw_t *w, const cfg_rule_t *r) {
    uint16_t scale = cfg_rule_scale(r->addr);
    gw_jw_obj_open(w);
    gw_jw_kuint(w, "id", r->id);
    gw_jw_kstr(w, "name", r->name);
    gw_jw_kbool(w, "enabled", r->enabled);
    gw_jw_kuint(w, "dev", r->dev);
    char src[12];
    if (r->addr == 40036)
        gw_strlcpy(src, "temp", sizeof(src));
    else if (r->addr == 40037)
        gw_strlcpy(src, "hum", sizeof(src));
    else if (r->addr == 40011)
        gw_strlcpy(src, "cur", sizeof(src));
    else
        snprintf(src, sizeof(src), "reg:%u", (unsigned)r->addr);
    gw_jw_kstr(w, "src", src);
    gw_jw_kstr(w, "op", r->op == CFG_OP_LT ? "<" : ">");
    gw_jw_kfixed(w, "thr", r->thr, scale);
    gw_jw_kfixed(w, "hyst", r->hyst, scale);
    gw_jw_kuint(w, "delay_s", r->delay_s);
    gw_jw_kuint(w, "sev", r->sev);
    gw_jw_obj_close(w);
}

static void w_rules_arr(gw_jw_t *w, const cfg_alarms_t *a) {
    gw_jw_arr_open(w);
    for (unsigned i = 0; i < a->n_rules && i < GW_MAX_RULES; i++)
        w_rule(w, &a->rules[i]);
    gw_jw_arr_close(w);
}

static void w_alarms(gw_jw_t *w, const cfg_alarms_t *a, bool with_rules) {
    gw_jw_obj_open(w);
    gw_jw_kuint(w, "debounce_raise", a->debounce_raise);
    gw_jw_kuint(w, "debounce_clear", a->debounce_clear);
    gw_jw_kobj(w, "sev_override");
    const cfg_alarm_catalog_t *cat = cfg_alarm_catalog();
    for (unsigned i = 0; i < a->n_sev_override && i < GW_MAX_SEV_OVERRIDES; i++) {
        const char *id = (cat && cat->id_from_code) ? cat->id_from_code(a->sev_override[i].code) : NULL;
        if (id)
            gw_jw_kuint(w, id, a->sev_override[i].sev);
    }
    gw_jw_obj_close(w);
    if (with_rules) {
        gw_jw_key(w, "rules");
        w_rules_arr(w, a);
    }
    gw_jw_obj_close(w);
}

static void w_snmp(gw_jw_t *w, const cfg_snmp_t *s, bool rest, const cfg_secret_flags_t *flags) {
    gw_jw_obj_open(w);
    gw_jw_kbool(w, "enabled", s->enabled);
    gw_jw_kbool(w, "v1", s->v1);
    gw_jw_kbool(w, "v2c", s->v2c);
    if (rest && flags) {
        gw_jw_kbool(w, "ro_set", flags->snmp_ro_set);
        gw_jw_kbool(w, "rw_set", flags->snmp_rw_set);
    }
    gw_jw_kbool(w, "auth_traps", s->auth_traps);
    gw_jw_kobj(w, "v3");
    gw_jw_kbool(w, "enabled", s->v3);
    gw_jw_karr(w, "users");
    for (unsigned i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        const cfg_snmp_v3user_t *u = &s->users[i];
        gw_jw_obj_open(w);
        gw_jw_kstr(w, "name", u->name);
        gw_jw_kstr(w, "access", u->access == CFG_SNMP_RW ? "rw" : "ro");
        gw_jw_kbool(w, "enabled", u->enabled);
        if (rest) {
            gw_jw_kstr(w, "auth", "sha");
            gw_jw_kstr(w, "priv", "aes");
            if (flags)
                gw_jw_kbool(w, "keys_set", flags->v3_keys_set[i]);
        }
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_obj_close(w);
    gw_jw_karr(w, "traps");
    for (unsigned i = 0; i < s->n_traps && i < GW_MAX_TRAP_TARGETS; i++) {
        const cfg_trap_t *t = &s->traps[i];
        gw_jw_obj_open(w);
        gw_jw_kstr(w, "host", t->host);
        gw_jw_kuint(w, "port", t->port);
        gw_jw_kstr(w, "version", t->version == CFG_SNMP_V1 ? "v1" : "v2c");
        gw_jw_kbool(w, "inform", t->inform);
        if (rest && flags)
            gw_jw_kbool(w, "community_set", flags->trap_comm_set[i]);
        gw_jw_kbool(w, "enabled", t->enabled);
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_kobj(w, "sys");
    gw_jw_kstr(w, "name", s->sys_name);
    gw_jw_kstr(w, "contact", s->sys_contact);
    gw_jw_kstr(w, "location", s->sys_location);
    gw_jw_obj_close(w);
    gw_jw_obj_close(w);
}

static void w_time(gw_jw_t *w, const cfg_time_t *t) {
    gw_jw_obj_open(w);
    gw_jw_kobj(w, "ntp");
    gw_jw_kbool(w, "enabled", t->ntp_enabled);
    gw_jw_karr(w, "servers");
    for (unsigned i = 0; i < GW_MAX_NTP_SERVERS; i++)
        if (t->servers[i][0])
            gw_jw_str(w, t->servers[i]);
    gw_jw_arr_close(w);
    gw_jw_kuint(w, "interval_min", t->interval_min);
    gw_jw_obj_close(w);
    gw_jw_kstr(w, "tz", t->tz);
    gw_jw_obj_close(w);
}

static void w_security(gw_jw_t *w, const cfg_security_t *s) {
    gw_jw_obj_open(w);
    gw_jw_kuint(w, "idle_min", s->idle_min);
    gw_jw_kobj(w, "lockout");
    gw_jw_kuint(w, "max_fail", s->max_fail);
    gw_jw_kuint(w, "lock_min", s->lock_min);
    gw_jw_obj_close(w);
    gw_jw_karr(w, "ip_allow");
    for (unsigned i = 0; i < s->n_ip_allow && i < GW_MAX_IP_ALLOW; i++) {
        char b[GW_CIDR_STR_SZ];
        gw_cidr_format(s->ip_allow[i].net, s->ip_allow[i].mask, b);
        gw_jw_str(w, b);
    }
    gw_jw_arr_close(w);
    gw_jw_kobj(w, "services");
    gw_jw_kbool(w, "snmp", s->svc_snmp);
    gw_jw_kbool(w, "syslog", s->svc_syslog);
    gw_jw_obj_close(w);
    gw_jw_obj_close(w);
}

static void w_notify(gw_jw_t *w, const cfg_notify_t *n) {
    gw_jw_obj_open(w);
    gw_jw_kobj(w, "syslog");
    gw_jw_kbool(w, "enabled", n->syslog_enabled);
    gw_jw_kstr(w, "host", n->host);
    gw_jw_kuint(w, "port", n->port);
    gw_jw_kuint(w, "facility", n->facility);
    gw_jw_kuint(w, "min_sev", n->min_sev);
    gw_jw_obj_close(w);
    gw_jw_obj_close(w);
}

static void w_section(gw_jw_t *w, cfg_section_t s, const gw_config_t *c, bool rest, const cfg_secret_flags_t *flags,
                      const char *prov_json) {
    switch (s) {
    case CFG_SEC_GENERAL:
        w_general(w, &c->general);
        break;
    case CFG_SEC_NETWORK:
        w_network(w, &c->network, rest, flags, prov_json);
        break;
    case CFG_SEC_MODBUS:
        w_modbus(w, &c->modbus);
        break;
    case CFG_SEC_ALARMS:
        w_alarms(w, &c->alarms, !rest);
        break;
    case CFG_SEC_SNMP:
        w_snmp(w, &c->snmp, rest, flags);
        break;
    case CFG_SEC_TIME:
        w_time(w, &c->time);
        break;
    case CFG_SEC_SECURITY:
        w_security(w, &c->security);
        break;
    case CFG_SEC_NOTIFY:
        w_notify(w, &c->notify);
        break;
    default:
        break;
    }
}

int cfg_to_json(const gw_config_t *c, const char *fw, gw_jw_t *w) {
    if (!c || !w)
        return CFG_JSON_E_WRITE;
    gw_jw_obj_open(w);
    gw_jw_kuint(w, "schema", CFG_SCHEMA_VERSION);
    gw_jw_kuint(w, "rev", c->rev);
    if (fw)
        gw_jw_kstr(w, "fw", fw);
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++) {
        gw_jw_key(w, cfg_section_name((cfg_section_t)s));
        w_section(w, (cfg_section_t)s, c, false, NULL, NULL);
    }
    gw_jw_obj_close(w);
    return gw_jw_error(w) == GW_JW_OK ? CFG_JSON_OK : CFG_JSON_E_WRITE;
}

int cfg_section_to_json(cfg_section_t s, const gw_config_t *c, const cfg_secret_flags_t *flags, gw_jw_t *w) {
    if (!c || !w || cfg_section_size(s) == 0)
        return CFG_JSON_E_WRITE;
    w_section(w, s, c, true, flags, NULL);
    return gw_jw_error(w) == GW_JW_OK ? CFG_JSON_OK : CFG_JSON_E_WRITE;
}

int cfg_network_to_json(const gw_config_t *c, const cfg_secret_flags_t *flags, const char *provisional_json,
                        gw_jw_t *w) {
    if (!c || !w)
        return CFG_JSON_E_WRITE;
    w_network(w, &c->network, true, flags, provisional_json);
    return gw_jw_error(w) == GW_JW_OK ? CFG_JSON_OK : CFG_JSON_E_WRITE;
}

int cfg_rules_to_json(const cfg_alarms_t *a, gw_jw_t *w) {
    if (!a || !w)
        return CFG_JSON_E_WRITE;
    w_rules_arr(w, a);
    return gw_jw_error(w) == GW_JW_OK ? CFG_JSON_OK : CFG_JSON_E_WRITE;
}
