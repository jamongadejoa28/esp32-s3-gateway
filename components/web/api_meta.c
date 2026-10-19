/* GET /meta/registers and /meta/alarms (docs/API.md §4.2): the register map and alarm catalog as
 * the single source for the UI. Both carry a strong ETag with Cache-Control no-cache and answer
 * If-None-Match with 304: /meta/registers = build id + map version, /meta/alarms = build id + a hash
 * of the effective severities (sev_override is configuration, not build-time). */
#include <stdio.h>
#include <stdlib.h>

#include "esp_app_desc.h"

#include "alarm/alarm.h"
#include "mex150/regmap.h"
#include "store/config.h"
#include "web_priv.h"

static void scaled(gw_jw_t *w, const char *key, int32_t raw, uint16_t scale) {
    gw_jw_kfixed(w, key, raw, scale ? scale : 1);
}

esp_err_t h_meta_registers(web_ctx_t *c) {
    const char *etag = web_meta_etag();
    web_set_header(c, "ETag", etag);
    web_set_header(c, "Cache-Control", "no-cache");
    char inm[96];
    if (web_header(c, "If-None-Match", inm, sizeof(inm)) && web_etag_match(inm, etag)) {
        return web_send_status(c, 304);
    }
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        return ESP_OK;
    }
    gw_jw_obj_open(&w);
    gw_jw_kuint(&w, "version", MEX_REGMAP_VERSION);
    gw_jw_karr(&w, "groups");
    for (int g = 0; g < MEX_GRP_COUNT; g++) {
        gw_jw_str(&w, mex_group_name((mex_group_t)g));
    }
    gw_jw_arr_close(&w);

    gw_jw_karr(&w, "regs");
    for (size_t i = 0; i < MEX_REG_COUNT; i++) {
        const mex_reg_t *r = &mex_regs[i];
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "key", r->key);
        gw_jw_kuint(&w, "addr", r->addr);
        gw_jw_kuint(&w, "scale", r->scale);
        gw_jw_kbool(&w, "signed", r->is_signed);
        gw_jw_kstr(&w, "access", r->writable ? "rw" : "ro");
        scaled(&w, "min", r->min, r->scale);
        scaled(&w, "max", r->max, r->scale);
        if (r->disabled == MEX_DIS_NONE) {
            gw_jw_knull(&w, "disabled");
        } else {
            scaled(&w, "disabled", r->disabled, r->scale);
        }
        gw_jw_kbool(&w, "stopped_only", (r->flags & MEX_F_STOPPED) != 0);
        gw_jw_kbool(&w, "snmp_rw", (r->flags & MEX_F_SNMP_RW) != 0);
        gw_jw_kbool(&w, "runbit", (r->flags & MEX_F_RUNBIT) != 0);
        gw_jw_kbool(&w, "bits", (r->flags & MEX_F_BITS) != 0);
        gw_jw_kstr(&w, "group", mex_group_name(r->group));
        gw_jw_kstr(&w, "unit", r->unit ? r->unit : "");
        gw_jw_kstr(&w, "ko", r->ko ? r->ko : "");
        gw_jw_kstr(&w, "en", r->en ? r->en : "");
        bool any_enum = false;
        for (size_t e = 0; e < MEX_ENUM_COUNT; e++) {
            if (mex_enums[e].reg != (mex_reg_id_t)i) {
                continue;
            }
            if (!any_enum) {
                gw_jw_karr(&w, "enum");
                any_enum = true;
            }
            gw_jw_obj_open(&w);
            gw_jw_kint(&w, "value", mex_enums[e].value);
            gw_jw_kstr(&w, "ko", mex_enums[e].ko ? mex_enums[e].ko : "");
            gw_jw_kstr(&w, "en", mex_enums[e].en ? mex_enums[e].en : "");
            gw_jw_obj_close(&w);
        }
        if (any_enum) {
            gw_jw_arr_close(&w);
        }
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);

    gw_jw_karr(&w, "bits");
    for (size_t i = 0; i < MEX_BIT_COUNT; i++) {
        const mex_bit_t *b = &mex_bits[i];
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "key", b->key);
        gw_jw_kuint(&w, "addr", b->addr);
        gw_jw_kuint(&w, "lsb", b->lsb);
        gw_jw_kuint(&w, "width", b->width);
        gw_jw_kstr(&w, "unit", b->unit ? b->unit : "");
        gw_jw_kstr(&w, "ko", b->ko ? b->ko : "");
        gw_jw_kstr(&w, "en", b->en ? b->en : "");
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);

    gw_jw_karr(&w, "coils");
    for (size_t i = 0; i < MEX_COIL_COUNT; i++) {
        const mex_coil_t *k = &mex_coils[i];
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "key", k->key);
        gw_jw_kuint(&w, "n", k->n);
        gw_jw_kstr(&w, "group", mex_group_name(k->group));
        gw_jw_kstr(&w, "ko", k->ko ? k->ko : "");
        gw_jw_kstr(&w, "en", k->en ? k->en : "");
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    gw_jw_obj_close(&w);
    return web_stream_end(c, &w);
}

esp_err_t h_meta_alarms(web_ctx_t *c) {
    cfg_alarms_t *cfg = malloc(sizeof(*cfg));
    alm_params_t *p = malloc(sizeof(*p));
    if (!cfg || !p || cfg_get_section(CFG_SEC_ALARMS, cfg, sizeof(*cfg)) != ESP_OK) {
        free(cfg);
        free(p);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    alm_params_from_config(cfg, p);
    free(cfg);
    /* Effective severities (catalog default unless overridden) also key the ETag: a
     * /config/alarms sev_override change must invalidate the cached catalog. */
    uint8_t sev[ALM_COUNT];
    for (size_t i = 0; i < ALM_COUNT; i++) {
        sev[i] = p->sev[i] <= ALM_SEV_CRITICAL ? p->sev[i] : alm_catalog[i].sev;
    }
    char build[17] = {0};
    esp_app_get_elf_sha256(build, sizeof(build));
    char etag[WEB_META_ALARMS_ETAG_SZ];
    web_meta_alarms_etag(etag, build, sev, ALM_COUNT);
    web_set_header(c, "ETag", etag);
    web_set_header(c, "Cache-Control", "no-cache");
    char inm[96];
    if (web_header(c, "If-None-Match", inm, sizeof(inm)) && web_etag_match(inm, etag)) {
        free(p);
        return web_send_status(c, 304);
    }
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        free(p);
        return ESP_OK;
    }
    char src[24];
    gw_jw_arr_open(&w);
    for (size_t i = 0; i < ALM_COUNT; i++) {
        const alm_desc_t *a = &alm_catalog[i];
        switch (a->src) {
        case ALM_SRC_COIL:
            snprintf(src, sizeof(src), "coil:%u", (unsigned)a->addr);
            break;
        case ALM_SRC_BIT:
            snprintf(src, sizeof(src), "bit:%u.%u", (unsigned)a->addr, (unsigned)a->bit);
            break;
        case ALM_SRC_COMM:
            snprintf(src, sizeof(src), "comm");
            break;
        default:
            snprintf(src, sizeof(src), "rule:%u", (unsigned)a->addr);
            break;
        }
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "id", a->id);
        gw_jw_kuint(&w, "code", a->code);
        gw_jw_kuint(&w, "sev", sev[i]);
        gw_jw_kstr(&w, "ko", a->ko ? a->ko : "");
        gw_jw_kstr(&w, "en", a->en ? a->en : "");
        gw_jw_kstr(&w, "source", src);
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    free(p);
    return web_stream_end(c, &w);
}
