/* JSON body builders shared by REST handlers (web_core.h). Pure C on gw_json_writer. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "auth/auth.h"
#include "web_core.h"

void web_json_error_open(gw_jw_t *w, const char *code, const char *message, const char *field) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "error", code ? code : "internal");
    if (message) {
        gw_jw_kstr(w, "message", message);
    }
    if (field) {
        gw_jw_kstr(w, "field", field);
    }
}

void web_json_error(gw_jw_t *w, const char *code, const char *message, const char *field) {
    web_json_error_open(w, code, message, field);
    gw_jw_obj_close(w);
}

void web_json_write_range_rejected(gw_jw_t *w, uint16_t addr) {
    web_json_error_open(w, "rejected", NULL, NULL);
    gw_jw_kstr(w, "state", "rejected");
    gw_jw_kuint(w, "cmd", 0);
    gw_jw_kuint(w, "addr", addr);
    gw_jw_kstr(w, "reason", "range");
    gw_jw_obj_close(w);
}

void web_meta_alarms_etag(char out[WEB_META_ALARMS_ETAG_SZ], const char *build, const uint8_t *sev, size_t n) {
    uint32_t h = 2166136261u; /* FNV-1a 32 */
    for (size_t i = 0; sev && i < n; i++) {
        h ^= sev[i];
        h *= 16777619u;
    }
    snprintf(out, WEB_META_ALARMS_ETAG_SZ, "\"%.12s-a%08" PRIx32 "\"", build ? build : "", h);
}

void web_json_hist_value(gw_jw_t *w, int16_t v) {
    if (v == HIST_GAP) {
        gw_jw_null(w);
    } else {
        gw_jw_int(w, v);
    }
}

void web_json_epoch_ms(gw_jw_t *w, int64_t ms) {
    if (ms > 0) {
        gw_jw_int(w, ms);
    } else {
        gw_jw_null(w);
    }
}

static void series(gw_jw_t *w, const char *key, const int16_t *v, uint32_t n) {
    gw_jw_karr(w, key);
    for (uint32_t i = 0; v && i < n; i++) {
        web_json_hist_value(w, v[i]);
    }
    gw_jw_arr_close(w);
}

void web_json_history(gw_jw_t *w, const hist_series_t *s, bool minmax, bool stages) {
    static const char *const ch_names[HIST_CH_COUNT] = {"temp", "hum", "cur", "st", "sh"};
    static const char *const stg_names[HIST_STG_COUNT] = {"blower", "cool", "heat", "hum", "dehum"};
    const uint32_t n = s->n <= s->n_max ? s->n : s->n_max;
    gw_jw_obj_open(w);
    gw_jw_key(w, "t0");
    web_json_epoch_ms(w, s->t0_ms);
    gw_jw_kuint(w, "t0_age_ms", s->t0_age_ms);
    gw_jw_kuint(w, "dt", s->dt_s);
    gw_jw_kuint(w, "n", n);
    gw_jw_kobj(w, "ch");
    for (int c = 0; c < HIST_CH_COUNT; c++) {
        series(w, ch_names[c], s->avg[c], n);
    }
    gw_jw_obj_close(w);
    if (minmax) {
        gw_jw_kobj(w, "min");
        for (int c = 0; c <= HIST_CH_CUR; c++) {
            series(w, ch_names[c], s->min[c], s->min[c] ? n : 0);
        }
        gw_jw_obj_close(w);
        gw_jw_kobj(w, "max");
        for (int c = 0; c <= HIST_CH_CUR; c++) {
            series(w, ch_names[c], s->max[c], s->max[c] ? n : 0);
        }
        gw_jw_obj_close(w);
    }
    if (stages) {
        gw_jw_kobj(w, "stages");
        for (int k = 0; k < HIST_STG_COUNT; k++) {
            gw_jw_karr(w, stg_names[k]);
            for (uint32_t i = 0; s->stage[k] && i < n; i++) {
                if (s->stage[k][i] == HIST_STAGE_GAP) {
                    gw_jw_null(w);
                } else {
                    gw_jw_uint(w, s->stage[k][i]);
                }
            }
            gw_jw_arr_close(w);
        }
        gw_jw_obj_close(w);
    }
    gw_jw_obj_close(w);
}

const char *web_wstate_name(int state) {
    switch (state) {
    case 0:
        return "pending";
    case 1:
        return "applied";
    case 2:
        return "rejected";
    case 3:
        return "uncertain";
    default:
        return "rejected";
    }
}

void web_json_policy_rules(gw_jw_t *w, uint32_t bits) {
    gw_jw_arr_open(w);
    for (uint32_t b = 1; b && b <= AUTH_PW_INVALID_CHARS; b <<= 1) {
        const char *name = (bits & b) ? auth_policy_rule_name(b) : NULL;
        if (name) {
            gw_jw_str(w, name);
        }
    }
    gw_jw_arr_close(w);
}
