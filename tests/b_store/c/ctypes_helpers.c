/*
 * ctypes_helpers.c - flat C entry points for stream B's Python tests (JSON in, JSON out), so the
 * Python side can fuzz/round-trip without mirroring C struct layouts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alarm/alarm.h"
#include "gw_core/gw_json_writer.h"
#include "store/config.h"
#include "store/config_json.h"
#include "store/secrets.h"

static const uint8_t k_mac[GW_MAC_LEN] = {0x24, 0x6F, 0x28, 0x12, 0x34, 0x56};

static void put_err(char *errbuf, const cfg_verr_t *e) {
    if (errbuf)
        snprintf(errbuf, 80, "%s|%s", e->field, e->code);
}

void t_install_catalog(int on) {
    cfg_set_alarm_catalog(on ? &alm_cfg_catalog : NULL);
}

size_t t_sizeof_config(void) {
    return sizeof(gw_config_t);
}

/* Parse a file/export document; on success write cfg_to_json() into out. Returns the parse rc, or
 * CFG_JSON_E_WRITE (-4) when the output does not fit. */
int t_cfg_roundtrip(const char *json, size_t len, char *out, size_t cap, char *errbuf) {
    gw_config_t *c = malloc(sizeof(*c));
    cfg_verr_t e = {{0}, {0}};
    int rc = cfg_from_json(json, len, k_mac, c, &e);
    put_err(errbuf, &e);
    if (rc == CFG_JSON_OK) {
        gw_jw_t w;
        gw_jw_init_fixed(&w, out, cap);
        rc = cfg_to_json(c, NULL, &w);
        if (gw_jw_finish(&w) != GW_JW_OK)
            rc = CFG_JSON_E_WRITE;
    }
    free(c);
    return rc;
}

int t_cfg_defaults_json(const char *fw, char *out, size_t cap) {
    gw_config_t *c = malloc(sizeof(*c));
    cfg_defaults(c, k_mac);
    gw_jw_t w;
    gw_jw_init_fixed(&w, out, cap);
    int rc = cfg_to_json(c, fw, &w);
    if (gw_jw_finish(&w) != GW_JW_OK)
        rc = CFG_JSON_E_WRITE;
    free(c);
    return rc;
}

static void flags_from_mask(cfg_secret_flags_t *f, unsigned mask) {
    memset(f, 0, sizeof(*f));
    f->ap_psk_set = mask & 1u;
    f->snmp_ro_set = mask & 2u;
    f->snmp_rw_set = mask & 4u;
    f->v3_keys_set[0] = mask & 8u;
    f->v3_keys_set[1] = mask & 16u;
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        f->trap_comm_set[i] = mask & (32u << i);
}

/* REST GET of section s from a base document (NULL/"" = defaults). flags_mask: see above; -1 = NULL. */
int t_section_get(int s, const char *base, size_t base_len, int flags_mask, char *out, size_t cap) {
    gw_config_t *c = malloc(sizeof(*c));
    int rc = CFG_JSON_OK;
    if (base && base_len)
        rc = cfg_from_json(base, base_len, k_mac, c, NULL);
    else
        cfg_defaults(c, k_mac);
    if (rc == CFG_JSON_OK) {
        cfg_secret_flags_t f;
        flags_from_mask(&f, flags_mask < 0 ? 0 : (unsigned)flags_mask);
        gw_jw_t w;
        gw_jw_init_fixed(&w, out, cap);
        rc = cfg_section_to_json((cfg_section_t)s, c, flags_mask < 0 ? NULL : &f, &w);
        if (gw_jw_finish(&w) != GW_JW_OK)
            rc = CFG_JSON_E_WRITE;
    }
    free(c);
    return rc;
}

/* Summary of the extracted secrets as JSON (test only: secrets in clear). */
static void secrets_json(const cfg_secret_input_t *s, gw_jw_t *w) {
    gw_jw_obj_open(w);
    if (s->has_ap_psk)
        gw_jw_kstr(w, "ap_psk", s->ap_psk);
    if (s->has_snmp_ro)
        gw_jw_kstr(w, "ro", s->snmp_ro);
    if (s->has_snmp_rw)
        gw_jw_kstr(w, "rw", s->snmp_rw);
    gw_jw_karr(w, "v3");
    for (unsigned i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        gw_jw_obj_open(w);
        if (s->v3[i].has_auth)
            gw_jw_kstr(w, "auth", s->v3[i].auth_pass);
        if (s->v3[i].has_priv)
            gw_jw_kstr(w, "priv", s->v3[i].priv_pass);
        gw_jw_obj_close(w);
    }
    gw_jw_arr_close(w);
    gw_jw_karr(w, "trap");
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++) {
        if (s->trap[i].has)
            gw_jw_str(w, s->trap[i].community);
        else
            gw_jw_null(w);
    }
    gw_jw_arr_close(w);
    gw_jw_kbool(w, "has_traps", s->has_traps);
    gw_jw_karr(w, "trap_from");
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        gw_jw_int(w, s->trap_from[i]);
    gw_jw_arr_close(w);
    gw_jw_obj_close(w);
}

/*
 * REST PUT of section s onto a base document, then cfg_validate_with(). Output (on rc 0):
 * {"section":<GET body, every *_set flag true>,"secrets":{...},"valid":bool}. errbuf gets "field|code" of the
 * parse error or the validation error.
 */
int t_section_put(int s, const char *base, size_t base_len, const char *body, size_t body_len, char *out,
                  size_t cap, char *errbuf) {
    gw_config_t *c = malloc(sizeof(*c));
    gw_config_t *n = malloc(sizeof(*n));
    cfg_secret_input_t *sec = malloc(sizeof(*sec));
    int rc = CFG_JSON_OK;
    if (base && base_len)
        rc = cfg_from_json(base, base_len, k_mac, c, NULL);
    else
        cfg_defaults(c, k_mac);
    if (rc != CFG_JSON_OK)
        goto done;
    *n = *c;
    cfg_verr_t e = {{0}, {0}};
    rc = cfg_section_from_json((cfg_section_t)s, body, body_len, c, cfg_section_ptr(n, (cfg_section_t)s), sec, &e);
    put_err(errbuf, &e);
    if (rc != CFG_JSON_OK)
        goto done;
    bool valid = cfg_validate_with(c, (cfg_section_t)s, cfg_section_cptr(n, (cfg_section_t)s), &e);
    if (!valid)
        put_err(errbuf, &e);
    gw_jw_t w;
    gw_jw_init_fixed(&w, out, cap);
    gw_jw_obj_open(&w);
    cfg_secret_flags_t f;
    flags_from_mask(&f, 0x1FFu);
    gw_jw_key(&w, "section");
    cfg_section_to_json((cfg_section_t)s, n, &f, &w);
    gw_jw_key(&w, "secrets");
    secrets_json(sec, &w);
    gw_jw_kbool(&w, "valid", valid);
    gw_jw_obj_close(&w);
    if (gw_jw_finish(&w) != GW_JW_OK)
        rc = CFG_JSON_E_WRITE;
done:
    free(c);
    free(n);
    free(sec);
    return rc;
}

/* PUT /config/rules onto defaults; out = GET body of the resulting rules; errbuf on failure. */
int t_rules_put(const char *body, size_t len, char *out, size_t cap, char *errbuf) {
    gw_config_t *c = malloc(sizeof(*c));
    cfg_defaults(c, k_mac);
    cfg_alarms_t a = c->alarms;
    cfg_verr_t e = {{0}, {0}};
    int rc = cfg_rules_from_json(body, len, &a, &e);
    if (rc == CFG_JSON_OK && !cfg_validate_with(c, CFG_SEC_ALARMS, &a, &e))
        rc = CFG_JSON_E_INVALID;
    put_err(errbuf, &e);
    if (rc == CFG_JSON_OK) {
        gw_jw_t w;
        gw_jw_init_fixed(&w, out, cap);
        cfg_rules_to_json(&a, &w);
        if (gw_jw_finish(&w) != GW_JW_OK)
            rc = CFG_JSON_E_WRITE;
    }
    free(c);
    return rc;
}

/* Network GET with an explicit provisional value. */
int t_network_get(const char *prov, char *out, size_t cap) {
    gw_config_t *c = malloc(sizeof(*c));
    cfg_defaults(c, k_mac);
    cfg_secret_flags_t f;
    flags_from_mask(&f, 1);
    gw_jw_t w;
    gw_jw_init_fixed(&w, out, cap);
    int rc = cfg_network_to_json(c, &f, prov, &w);
    if (gw_jw_finish(&w) != GW_JW_OK)
        rc = CFG_JSON_E_WRITE;
    free(c);
    return rc;
}

/* ["<s>"] through the writer (fixed mode). Returns the writer error. */
int t_jw_string(const char *s, size_t n, char *out, size_t cap) {
    gw_jw_t w;
    gw_jw_init_fixed(&w, out, cap);
    gw_jw_arr_open(&w);
    gw_jw_strn(&w, s, n);
    gw_jw_arr_close(&w);
    return gw_jw_finish(&w);
}

/* Secrets file round trip: parse (factory psk) and serialize again. */
int t_sec_roundtrip(const char *json, size_t len, const char *psk, char *out, size_t cap) {
    gw_secrets_t *s = malloc(sizeof(*s));
    int rc = sec_from_json(json, len, psk, s);
    if (rc == CFG_JSON_OK) {
        gw_jw_t w;
        gw_jw_init_fixed(&w, out, cap);
        rc = sec_to_json(s, &w);
        if (gw_jw_finish(&w) != GW_JW_OK)
            rc = CFG_JSON_E_WRITE;
    }
    free(s);
    return rc;
}
