/*
 * secrets.c - pure part of the secrets model: defaults, validation, JSON file mapping, read-back
 * flags and the trap-community remap (host-tested). The RAM store is secrets_store.c.
 *
 * File: {"schema":1,"users":[{"name","role","hash","must_change","changed"}],
 *        "snmp":{"ro","rw","v3":[{"slot","auth_key","priv_key"}],"trap_comm":[...]},"ap_psk"}
 * v3 entries are written only for slots with keys; "slot" is the fixed cfg_snmp_t.users index
 * (a "name" member, as sketched in DESIGN.md §7, is accepted and ignored: localized keys depend on
 * the engine ID and passphrase, not on the user name).
 */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "gw_core/gw_crypto.h"
#include "store/config_json.h"
#include "store/secrets.h"
#include "store_priv.h"

/* ------------------------------------------------------------------ pure helpers */

static bool user_name_ok(const char *s, size_t cap) {
    size_t n = 0;
    while (n < cap && s[n])
        n++;
    if (n == 0 || n >= cap || n > GW_USER_NAME_MAX)
        return false;
    if (s[0] < 'a' || s[0] > 'z')
        return false;
    for (size_t i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
            return false;
    }
    return true;
}

void sec_defaults(gw_secrets_t *s, const char *factory_ap_psk) {
    memset(s, 0, sizeof(*s));
    s->schema = SEC_SCHEMA_VERSION;
    s->n_users = 0;
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        store_strset(s->trap_comm[i], sizeof(s->trap_comm[i]), SEC_DEFAULT_TRAP);
    store_strset(s->ap_psk, sizeof(s->ap_psk), factory_ap_psk ? factory_ap_psk : "");
}

bool sec_validate(const gw_secrets_t *s) {
    if (!s || s->schema != SEC_SCHEMA_VERSION || s->n_users > GW_MAX_USERS)
        return false;
    bool admin = false;
    for (unsigned i = 0; i < s->n_users; i++) {
        const sec_user_t *u = &s->users[i];
        if (!user_name_ok(u->name, sizeof(u->name)))
            return false;
        if (u->role < GW_ROLE_VIEWER || u->role > GW_ROLE_ADMIN)
            return false;
        if (!store_ascii_ok(u->hash, sizeof(u->hash), 1, SEC_HASH_SZ - 1, 0x21, 0x7E))
            return false;
        if (u->changed_ms < 0)
            return false;
        for (unsigned j = 0; j < i; j++)
            if (!strcmp(s->users[j].name, u->name))
                return false;
        if (u->role == GW_ROLE_ADMIN)
            admin = true;
    }
    if (s->n_users > 0 && !admin)
        return false;
    if (!store_ascii_ok(s->snmp_ro, sizeof(s->snmp_ro), 0, GW_COMMUNITY_MAX, 0x21, 0x7E) ||
        !store_ascii_ok(s->snmp_rw, sizeof(s->snmp_rw), 0, GW_COMMUNITY_MAX, 0x21, 0x7E))
        return false;
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        if (!store_ascii_ok(s->trap_comm[i], sizeof(s->trap_comm[i]), 1, GW_COMMUNITY_MAX, 0x21, 0x7E))
            return false;
    if (!store_ascii_ok(s->ap_psk, sizeof(s->ap_psk), GW_PSK_MIN, GW_PSK_MAX, 0x20, 0x7E))
        return false;
    return true;
}

void sec_flags(const gw_secrets_t *s, cfg_secret_flags_t *out) {
    memset(out, 0, sizeof(*out));
    out->ap_psk_set = s->ap_psk[0] != '\0';
    out->snmp_ro_set = s->snmp_ro[0] != '\0';
    out->snmp_rw_set = s->snmp_rw[0] != '\0';
    for (unsigned i = 0; i < GW_MAX_SNMP_V3_USERS; i++)
        out->v3_keys_set[i] = s->v3[i].set;
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        out->trap_comm_set[i] = strncmp(s->trap_comm[i], SEC_DEFAULT_TRAP, GW_COMMUNITY_SZ) != 0;
}

int sec_find_user(const gw_secrets_t *s, const char *name) {
    if (!s || !name)
        return -1;
    for (unsigned i = 0; i < s->n_users && i < GW_MAX_USERS; i++)
        if (!strncmp(s->users[i].name, name, GW_USER_NAME_SZ))
            return (int)i;
    return -1;
}

void sec_trap_remap(gw_secrets_t *s, const cfg_secret_input_t *in, uint8_t n_traps) {
    if (!s || !in || !in->has_traps)
        return;
    char next[GW_MAX_TRAP_TARGETS][GW_COMMUNITY_SZ];
    memset(next, 0, sizeof(next));
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++) {
        const char *src = SEC_DEFAULT_TRAP;
        if (i < n_traps) {
            if (in->trap[i].has)
                src = in->trap[i].community;
            else if (in->trap_from[i] >= 0 && in->trap_from[i] < GW_MAX_TRAP_TARGETS)
                src = s->trap_comm[in->trap_from[i]];
        }
        store_strset(next[i], sizeof(next[i]), src);
    }
    memcpy(s->trap_comm, next, sizeof(next));
    gw_secure_zero(next, sizeof(next));
}

/* ------------------------------------------------------------------ hex */

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 0xF];
    }
    out[2 * n] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static bool hex_decode(const char *s, uint8_t *out, size_t n) {
    if (!s || strlen(s) != 2 * n)
        return false;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* ------------------------------------------------------------------ JSON */

static bool str_into(const cJSON *it, char *dst, size_t cap) {
    if (!cJSON_IsString(it) || !it->valuestring || strlen(it->valuestring) >= cap)
        return false;
    store_strset(dst, cap, it->valuestring);
    return true;
}

static int sec_parse(const cJSON *root, gw_secrets_t *out) {
    const cJSON *sch = cJSON_GetObjectItemCaseSensitive(root, "schema");
    if (sch) {
        if (!cJSON_IsNumber(sch) || sch->valuedouble != floor(sch->valuedouble) || sch->valuedouble < 1)
            return CFG_JSON_E_INVALID;
        if (sch->valuedouble > SEC_SCHEMA_VERSION)
            return CFG_JSON_E_SCHEMA;
    }
    const cJSON *users = cJSON_GetObjectItemCaseSensitive(root, "users");
    if (users) {
        if (!cJSON_IsArray(users) || cJSON_GetArraySize(users) > GW_MAX_USERS)
            return CFG_JSON_E_INVALID;
        unsigned n = 0;
        const cJSON *u;
        cJSON_ArrayForEach(u, users) {
            sec_user_t *d = &out->users[n];
            memset(d, 0, sizeof(*d));
            gw_role_t role;
            const cJSON *rj = cJSON_GetObjectItemCaseSensitive(u, "role");
            if (!cJSON_IsObject(u) || !str_into(cJSON_GetObjectItemCaseSensitive(u, "name"), d->name, sizeof(d->name)) ||
                !str_into(cJSON_GetObjectItemCaseSensitive(u, "hash"), d->hash, sizeof(d->hash)) ||
                !cJSON_IsString(rj) || !gw_role_from_name(rj->valuestring, &role))
                return CFG_JSON_E_INVALID;
            d->role = (uint8_t)role;
            const cJSON *mc = cJSON_GetObjectItemCaseSensitive(u, "must_change");
            if (mc) {
                if (!cJSON_IsBool(mc))
                    return CFG_JSON_E_INVALID;
                d->must_change = cJSON_IsTrue(mc);
            }
            const cJSON *ch = cJSON_GetObjectItemCaseSensitive(u, "changed");
            if (ch && !cJSON_IsNull(ch)) {
                if (!cJSON_IsNumber(ch) || ch->valuedouble < 0 || ch->valuedouble > 9.0e15 ||
                    ch->valuedouble != floor(ch->valuedouble))
                    return CFG_JSON_E_INVALID;
                d->changed_ms = (int64_t)ch->valuedouble;
            }
            n++;
        }
        out->n_users = (uint8_t)n;
    }
    const cJSON *snmp = cJSON_GetObjectItemCaseSensitive(root, "snmp");
    if (snmp) {
        if (!cJSON_IsObject(snmp))
            return CFG_JSON_E_INVALID;
        const cJSON *ro = cJSON_GetObjectItemCaseSensitive(snmp, "ro");
        const cJSON *rw = cJSON_GetObjectItemCaseSensitive(snmp, "rw");
        if ((ro && !str_into(ro, out->snmp_ro, sizeof(out->snmp_ro))) ||
            (rw && !str_into(rw, out->snmp_rw, sizeof(out->snmp_rw))))
            return CFG_JSON_E_INVALID;
        const cJSON *v3 = cJSON_GetObjectItemCaseSensitive(snmp, "v3");
        if (v3) {
            if (!cJSON_IsArray(v3) || cJSON_GetArraySize(v3) > GW_MAX_SNMP_V3_USERS)
                return CFG_JSON_E_INVALID;
            unsigned pos = 0;
            const cJSON *k;
            cJSON_ArrayForEach(k, v3) {
                const cJSON *sl = cJSON_GetObjectItemCaseSensitive(k, "slot");
                unsigned slot = pos;
                if (sl) {
                    if (!cJSON_IsNumber(sl) || sl->valuedouble < 0 || sl->valuedouble >= GW_MAX_SNMP_V3_USERS ||
                        sl->valuedouble != floor(sl->valuedouble))
                        return CFG_JSON_E_INVALID;
                    slot = (unsigned)sl->valuedouble;
                }
                sec_v3_keys_t *dk = &out->v3[slot];
                const cJSON *ak = cJSON_GetObjectItemCaseSensitive(k, "auth_key");
                const cJSON *pk = cJSON_GetObjectItemCaseSensitive(k, "priv_key");
                if (!cJSON_IsObject(k) || !cJSON_IsString(ak) || !cJSON_IsString(pk) ||
                    !hex_decode(ak->valuestring, dk->auth_key, SEC_V3_KEY_LEN) ||
                    !hex_decode(pk->valuestring, dk->priv_key, SEC_V3_KEY_LEN))
                    return CFG_JSON_E_INVALID;
                dk->set = true;
                pos++;
            }
        }
        const cJSON *tc = cJSON_GetObjectItemCaseSensitive(snmp, "trap_comm");
        if (tc) {
            if (!cJSON_IsArray(tc) || cJSON_GetArraySize(tc) > GW_MAX_TRAP_TARGETS)
                return CFG_JSON_E_INVALID;
            unsigned i = 0;
            const cJSON *t;
            cJSON_ArrayForEach(t, tc) {
                if (!str_into(t, out->trap_comm[i], sizeof(out->trap_comm[i])))
                    return CFG_JSON_E_INVALID;
                i++;
            }
        }
    }
    const cJSON *psk = cJSON_GetObjectItemCaseSensitive(root, "ap_psk");
    if (psk && !str_into(psk, out->ap_psk, sizeof(out->ap_psk)))
        return CFG_JSON_E_INVALID;
    return CFG_JSON_OK;
}

int sec_from_json(const char *json, size_t len, const char *factory_ap_psk, gw_secrets_t *out) {
    if (!out)
        return CFG_JSON_E_PARSE;
    sec_defaults(out, factory_ap_psk);
    if (!json || len == 0)
        return CFG_JSON_E_PARSE;
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root || !cJSON_IsObject(root)) {
        if (root) {
            store_json_wipe(root);
            cJSON_Delete(root);
        }
        return CFG_JSON_E_PARSE;
    }
    int rc = sec_parse(root, out);
    store_json_wipe(root);
    cJSON_Delete(root);
    if (rc == CFG_JSON_OK && !sec_validate(out))
        rc = CFG_JSON_E_INVALID;
    if (rc != CFG_JSON_OK) {
        gw_secure_zero(out, sizeof(*out));
        sec_defaults(out, factory_ap_psk);
    }
    return rc;
}

int sec_to_json(const gw_secrets_t *s, gw_jw_t *w) {
    if (!s || !w)
        return CFG_JSON_E_WRITE;
    char hex[2 * SEC_V3_KEY_LEN + 1];
    gw_jw_obj_open(w);
    gw_jw_kuint(w, "schema", SEC_SCHEMA_VERSION);
    gw_jw_karr(w, "users");
    for (unsigned i = 0; i < s->n_users && i < GW_MAX_USERS; i++) {
        const sec_user_t *u = &s->users[i];
        gw_jw_obj_open(w);
        gw_jw_kstr(w, "name", u->name);
        gw_jw_kstr(w, "role", gw_role_name((gw_role_t)u->role));
        gw_jw_kstr(w, "hash", u->hash);
        gw_jw_kbool(w, "must_change", u->must_change);
        if (u->changed_ms > 0)
            gw_jw_kint(w, "changed", u->changed_ms);
        else
            gw_jw_knull(w, "changed");
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_kobj(w, "snmp");
    gw_jw_kstr(w, "ro", s->snmp_ro);
    gw_jw_kstr(w, "rw", s->snmp_rw);
    gw_jw_karr(w, "v3");
    for (unsigned i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        if (!s->v3[i].set)
            continue;
        gw_jw_obj_open(w);
        gw_jw_kuint(w, "slot", i);
        hex_encode(s->v3[i].auth_key, SEC_V3_KEY_LEN, hex);
        gw_jw_kstr(w, "auth_key", hex);
        hex_encode(s->v3[i].priv_key, SEC_V3_KEY_LEN, hex);
        gw_jw_kstr(w, "priv_key", hex);
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_karr(w, "trap_comm");
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        gw_jw_str(w, s->trap_comm[i]);
    gw_jw_arr_close(w);
    gw_jw_obj_close(w);
    gw_jw_kstr(w, "ap_psk", s->ap_psk);
    gw_jw_obj_close(w);
    gw_secure_zero(hex, sizeof(hex));
    return gw_jw_error(w) == GW_JW_OK ? CFG_JSON_OK : CFG_JSON_E_WRITE;
}
