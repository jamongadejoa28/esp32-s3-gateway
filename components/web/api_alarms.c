/* /alarms/active, /alarms/ack, /alarms/history(.csv) (docs/API.md §4.7). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alarm/alarm.h"
#include "store/eventlog.h"
#include "web_priv.h"

#define ACTIVE_MAX (GW_MAX_DEVICES * ALM_COUNT)
#define HISTORY_LIMIT_DEFAULT 50
#define CSV_MAX_ROWS 8192

static const char *alarm_id(uint16_t code) {
    const alm_desc_t *d = alm_find_code(code);
    return d ? d->id : "unknown";
}

static const char *ev_type_name(uint8_t type) {
    switch (type) {
    case EVT_ALARM_RAISE:
        return "raise";
    case EVT_ALARM_CLEAR:
        return "clear";
    default:
        return "ack";
    }
}

/* NUL-terminated copy of the 12-byte record user field ("" if empty). */
static void rec_user(const evlog_rec_t *r, char out[13]) {
    memcpy(out, r->user, sizeof(r->user));
    out[12] = '\0';
}

/* ---------------------------------------------------------------- active */

esp_err_t h_alarms_active(web_ctx_t *c) {
    alm_active_t *a = malloc(sizeof(*a) * ACTIVE_MAX);
    if (!a) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    size_t total = alarm_get_active(a, ACTIVE_MAX);
    size_t n = total < ACTIVE_MAX ? total : ACTIVE_MAX;
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        free(a);
        return ESP_OK;
    }
    char key[ALM_KEY_SZ];
    gw_jw_arr_open(&w);
    for (size_t i = 0; i < n; i++) {
        const alm_active_t *x = &a[i];
        if ((size_t)x->id >= ALM_COUNT) {
            continue;
        }
        const alm_desc_t *d = &alm_catalog[x->id];
        alm_key_format(x->dev, x->id, key);
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "key", key);
        gw_jw_kuint(&w, "dev", x->dev);
        gw_jw_kstr(&w, "id", d->id);
        gw_jw_kuint(&w, "code", d->code);
        gw_jw_kuint(&w, "sev", x->sev);
        gw_jw_key(&w, "since");
        web_json_epoch_ms(&w, x->since_ms);
        gw_jw_kbool(&w, "acked", x->acked);
        if (x->acked && x->ack_by[0]) {
            gw_jw_kstr(&w, "ack_by", x->ack_by);
        } else {
            gw_jw_knull(&w, "ack_by");
        }
        gw_jw_key(&w, "ack_ts");
        web_json_epoch_ms(&w, x->acked ? x->ack_ms : 0);
        gw_jw_kint(&w, "value", x->value);
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    free(a);
    return web_stream_end(c, &w);
}

/* ---------------------------------------------------------------- ack */

esp_err_t h_alarms_ack(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"keys", "all", NULL};
    esp_err_t ret = ESP_OK;
    if (!web_json_only(c, root, allowed, NULL)) {
        cJSON_Delete(root);
        return ESP_OK;
    }
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(root, "keys");
    const cJSON *all = cJSON_GetObjectItemCaseSensitive(root, "all");
    if ((keys && all) || (!keys && !all)) {
        ret = web_send_validation(c, keys ? "all" : "keys", keys ? "unknown_field" : "required",
                                  "exactly one of keys or all");
    } else if (all) {
        if (!cJSON_IsTrue(all)) {
            ret = web_send_validation(c, "all", "type", "must be true");
        } else {
            (void)alarm_ack_all(web_user(c));
            ret = web_send_status(c, 204);
        }
    } else if (!cJSON_IsArray(keys) || cJSON_GetArraySize(keys) > ACTIVE_MAX) {
        ret = web_send_validation(c, "keys", cJSON_IsArray(keys) ? "too_many" : "type", NULL);
    } else {
        /* Validate every key first so a malformed one acks nothing. */
        int i = 0;
        const cJSON *k;
        bool ok = true;
        cJSON_ArrayForEach(k, keys) {
            uint8_t dev;
            alm_id_t id;
            if (!cJSON_IsString(k) || !alm_key_parse(k->valuestring, &dev, &id)) {
                char field[24];
                snprintf(field, sizeof(field), "keys[%d]", i);
                ret = web_send_validation(c, field, "format", "malformed alarm key");
                ok = false;
                break;
            }
            i++;
        }
        if (ok) {
            cJSON_ArrayForEach(k, keys) {
                uint8_t dev;
                alm_id_t id;
                if (alm_key_parse(k->valuestring, &dev, &id)) {
                    (void)alarm_ack(dev, id, web_user(c)); /* not active -> ignored (idempotent) */
                }
            }
            ret = web_send_status(c, 204);
        }
    }
    cJSON_Delete(root);
    return ret;
}

/* ---------------------------------------------------------------- history */

typedef struct {
    uint32_t before;
    size_t limit;
    evlog_filter_t f;
} alarm_q_t;

static bool parse_alarm_query(web_ctx_t *c, alarm_q_t *q, bool csv) {
    int64_t before = 0, limit = HISTORY_LIMIT_DEFAULT, dev = -1, sev = -1;
    web_q_t qb = web_query_i64(c, "before", &before);
    web_q_t ql = csv ? WEB_Q_ABSENT : web_query_i64(c, "limit", &limit);
    web_q_t qd = web_query_i64(c, "dev", &dev);
    web_q_t qs = web_query_i64(c, "sev", &sev);
    bool ok = qb != WEB_Q_INVALID && ql != WEB_Q_INVALID && qd != WEB_Q_INVALID && qs != WEB_Q_INVALID &&
              before >= 0 && before <= UINT32_MAX && limit >= 1 && limit <= EVLOG_QUERY_MAX &&
              (qd == WEB_Q_ABSENT || (dev >= 0 && dev < GW_MAX_DEVICES)) &&
              (qs == WEB_Q_ABSENT || (sev >= 0 && sev <= ALM_SEV_CRITICAL));
    if (!ok) {
        web_send_error(c, 400, WEB_E_BAD_REQUEST, "before>=0, limit 1..200, dev 0..3, sev 0..3", NULL);
        return false;
    }
    q->before = (uint32_t)before;
    q->limit = (size_t)limit;
    q->f.dev = (int16_t)(qd == WEB_Q_OK ? dev : -1);
    q->f.min_sev = (int8_t)(qs == WEB_Q_OK ? sev : -1);
    q->f.type_min = EVT_ALARM_RAISE;
    q->f.type_max = EVT_ALARM_ACK;
    return true;
}

esp_err_t h_alarms_history(web_ctx_t *c) {
    alarm_q_t q;
    if (!parse_alarm_query(c, &q, false)) {
        return ESP_OK;
    }
    evlog_rec_t *recs = malloc(sizeof(*recs) * EVLOG_QUERY_MAX);
    if (!recs) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    uint32_t next = 0;
    size_t n = evlog_query(EVLOG_EVENTS, q.before, q.limit, &q.f, recs, &next);
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        free(recs);
        return ESP_OK;
    }
    char user[13];
    gw_jw_obj_open(&w);
    gw_jw_karr(&w, "items");
    for (size_t i = 0; i < n; i++) {
        const evlog_rec_t *r = &recs[i];
        rec_user(r, user);
        gw_jw_obj_open(&w);
        gw_jw_kuint(&w, "seq", r->seq);
        gw_jw_key(&w, "ts");
        web_json_epoch_ms(&w, (int64_t)r->ts * 1000);
        gw_jw_kuint(&w, "dev", r->dev == EVLOG_DEV_NONE ? 0u : r->dev);
        gw_jw_kstr(&w, "id", alarm_id(r->code));
        gw_jw_kuint(&w, "code", r->code);
        gw_jw_kstr(&w, "type", ev_type_name(r->type));
        gw_jw_kuint(&w, "sev", r->sev);
        gw_jw_kint(&w, "value", r->value);
        if (user[0]) {
            gw_jw_kstr(&w, "user", user);
        } else {
            gw_jw_knull(&w, "user");
        }
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    if (next) {
        gw_jw_kuint(&w, "next", next);
    } else {
        gw_jw_knull(&w, "next");
    }
    gw_jw_obj_close(&w);
    free(recs);
    return web_stream_end(c, &w);
}

esp_err_t h_alarms_history_csv(web_ctx_t *c) {
    alarm_q_t q;
    if (!parse_alarm_query(c, &q, true)) {
        return ESP_OK;
    }
    evlog_rec_t *recs = malloc(sizeof(*recs) * EVLOG_QUERY_MAX);
    if (!recs) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    if (web_stream_begin(c, 200, "text/csv; charset=utf-8", "mestio-alarms.csv", NULL) != ESP_OK) {
        free(recs);
        return ESP_OK;
    }
    char line[WEB_CSV_ROW_MAX];
    char user[13];
    int n = web_csv_alarm_header(line, sizeof(line));
    esp_err_t err = web_stream_write(c, WEB_CSV_BOM, 3);
    if (err == ESP_OK && n > 0) {
        err = web_stream_write(c, line, (size_t)n);
    }
    uint32_t before = q.before;
    size_t rows = 0;
    while (err == ESP_OK && rows < CSV_MAX_ROWS) {
        uint32_t next = 0;
        size_t want = CSV_MAX_ROWS - rows < EVLOG_QUERY_MAX ? CSV_MAX_ROWS - rows : EVLOG_QUERY_MAX;
        size_t got = evlog_query(EVLOG_EVENTS, before, want, &q.f, recs, &next);
        for (size_t i = 0; i < got && err == ESP_OK; i++) {
            const evlog_rec_t *r = &recs[i];
            rec_user(r, user);
            n = web_csv_alarm_row(line, sizeof(line), r->seq, (int64_t)r->ts * 1000,
                                  r->dev == EVLOG_DEV_NONE ? 0u : r->dev, alarm_id(r->code), r->code,
                                  ev_type_name(r->type), r->sev, r->value, user);
            err = n > 0 ? web_stream_write(c, line, (size_t)n) : ESP_FAIL;
        }
        rows += got;
        if (!next || !got) {
            break;
        }
        before = next;
    }
    free(recs);
    if (err != ESP_OK) {
        return ESP_FAIL; /* truncate the started stream */
    }
    return web_stream_end(c, NULL);
}
