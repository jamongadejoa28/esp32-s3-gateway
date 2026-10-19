/* Devices, live data, register writes, commands, history (JSON + CSV), statistics
 * (docs/API.md §4.4-§4.6). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "gw_core/gw_time.h"
#include "alarm/alarm.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mex150/regmap.h"
#include "mex150/service.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/history.h"
#include "web_priv.h"

static const char *TAG = "api_dev";

#define WRITE_WAIT_MS 1500
#define HIST_SPAN_MAX_S (30u * 86400u)

/* ---------------------------------------------------------------- helpers */

/* Register belongs to the slow poll group (reported only once slow_valid). */
static bool is_slow_reg(uint16_t addr) {
    for (size_t i = 0; i < MEX_SLOW_BLOCKS; i++) {
        const mex_block_t *b = &mex_slow_blocks[i];
        unsigned first = MEX_ADDR_BASE + 1u + b->start;
        if (addr >= first && addr < first + b->count) {
            return true;
        }
    }
    return false;
}

static void live_regs(gw_jw_t *w, const mex_snapshot_t *s) {
    char k[8];
    gw_jw_kobj(w, "regs");
    if (s->seq) {
        for (size_t i = 0; i < MEX_REG_COUNT; i++) {
            const mex_reg_t *r = &mex_regs[i];
            if (!s->slow_valid && is_slow_reg(r->addr)) {
                continue;
            }
            snprintf(k, sizeof(k), "%u", (unsigned)r->addr);
            gw_jw_kint(w, k, mex_snap_raw(s, r->addr));
        }
    }
    gw_jw_obj_close(w);
}

static void derived(gw_jw_t *w, const mex_snapshot_t *s) {
    gw_jw_key(w, "derived");
    if (!s->seq) {
        gw_jw_null(w);
        return;
    }
    mex_stages_t st;
    mex_derive_stages(s, &st);
    const uint8_t mode = mex_mode_mask(s);
    gw_jw_obj_open(w);
    gw_jw_kfixed(w, "temp", mex_snap_raw(s, 40036), 10);
    gw_jw_kfixed(w, "hum", mex_snap_raw(s, 40037), 10);
    gw_jw_kfixed(w, "current", mex_snap_raw(s, 40011), 10);
    gw_jw_kbool(w, "running", mex_running(s));
    gw_jw_kobj(w, "stages");
    gw_jw_kuint(w, "cool", st.cool);
    gw_jw_kuint(w, "heat", st.heat);
    gw_jw_kuint(w, "hum", st.hum);
    gw_jw_kuint(w, "dehum", st.dehum);
    gw_jw_obj_close(w);
    gw_jw_karr(w, "mode");
    static const char *const modes[4] = {"cool", "heat", "hum", "dehum"};
    for (int i = 0; i < 4; i++) {
        if (mode & (1u << i)) {
            gw_jw_str(w, modes[i]);
        }
    }
    gw_jw_arr_close(w);
    gw_jw_kuint(w, "delay_s", mex_delay_s(s));
    gw_jw_obj_close(w);
}

/* ---------------------------------------------------------------- GET /devices, live */

esp_err_t h_devices(web_ctx_t *c) {
    cfg_modbus_t *m = malloc(sizeof(*m));
    if (!m || cfg_get_section(CFG_SEC_MODBUS, m, sizeof(*m)) != ESP_OK) {
        free(m);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    char buf[768];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_arr_open(&w);
    for (size_t i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++) {
        const mex_dev_cfg_t *d = &m->devices[i];
        mex_snapshot_t s;
        if (!mex_service_snapshot(d->id, &s)) {
            memset(&s, 0, sizeof(s));
        }
        gw_jw_obj_open(&w);
        gw_jw_kuint(&w, "id", d->id);
        gw_jw_kstr(&w, "name", d->name);
        gw_jw_kuint(&w, "slave", d->slave);
        gw_jw_kbool(&w, "enabled", d->enabled);
        gw_jw_kbool(&w, "online", d->enabled && s.online);
        gw_jw_key(&w, "last_ms");
        web_json_epoch_ms(&w, s.wall_ms);
        gw_jw_kuint(&w, "seq", s.seq);
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    free(m);
    return web_send_jw(c, 200, &w);
}

esp_err_t h_device_live(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    mex_snapshot_t s;
    if (!mex_service_snapshot(dev, &s)) {
        memset(&s, 0, sizeof(s));
    }
    gw_jw_t w;
    if (web_jw_dynamic(&w, 4096) != GW_JW_OK) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    gw_jw_obj_open(&w);
    gw_jw_kuint(&w, "seq", s.seq);
    gw_jw_key(&w, "ts");
    web_json_epoch_ms(&w, s.wall_ms);
    gw_jw_kbool(&w, "online", s.online);
    /* Same window as writes at enqueue and the 1 Hz rule pass (service.h MEX_FRESH_MS note). */
    cfg_modbus_t mb;
    const uint32_t poll_ms = cfg_get_section(CFG_SEC_MODBUS, &mb, sizeof(mb)) == ESP_OK ? mb.port.poll_ms : 0;
    gw_jw_kbool(&w, "fresh", alm_sample_fresh(&s, gw_time_mono_ms(), poll_ms));
    gw_jw_kbool(&w, "slow_valid", s.slow_valid);
    live_regs(&w, &s);
    gw_jw_kuint(&w, "coils", s.coils);
    derived(&w, &s);
    gw_jw_obj_close(&w);
    return web_send_jw_free(c, 200, &w);
}

/* ---------------------------------------------------------------- writes */

typedef struct {
    const mex_wresult_t *r;
    const char *reason;
} rej_arg_t;

static void rejected_extra(gw_jw_t *w, void *arg) {
    const rej_arg_t *a = arg;
    gw_jw_kstr(w, "state", "rejected");
    gw_jw_kuint(w, "cmd", a->r->cmd);
    gw_jw_kuint(w, "addr", a->r->addr);
    gw_jw_kstr(w, "reason", a->reason);
}

static esp_err_t send_write_result(web_ctx_t *c, esp_err_t err, uint16_t addr, mex_wresult_t *r) {
    if (err == ESP_ERR_INVALID_ARG) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown device", NULL);
    }
    if (err == ESP_ERR_NO_MEM) {
        return web_send_error(c, 503, WEB_E_BUSY, "write queue full", NULL);
    }
    if (err != ESP_OK) {
        return web_send_esp_err(c, err);
    }
    if (!r->addr) {
        r->addr = addr;
    }
    char rbuf[MEX_REASON_NAME_SZ];
    const char *reason = mex_reason_name(r->reason, rbuf, sizeof(rbuf)); /* use the return value */
    char buf[160];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    switch (r->state) {
    case MEX_W_APPLIED:
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "state", "applied");
        gw_jw_kuint(&w, "cmd", r->cmd);
        gw_jw_kuint(&w, "addr", r->addr);
        gw_jw_kint(&w, "raw", r->raw_after);
        gw_jw_obj_close(&w);
        return web_send_jw(c, 200, &w);
    case MEX_W_PENDING:
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "state", "pending");
        gw_jw_kuint(&w, "cmd", r->cmd);
        gw_jw_kuint(&w, "addr", r->addr);
        gw_jw_obj_close(&w);
        return web_send_jw(c, 202, &w);
    case MEX_W_UNCERTAIN:
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "state", "uncertain");
        gw_jw_kuint(&w, "cmd", r->cmd);
        gw_jw_kuint(&w, "addr", r->addr);
        if (r->reason == MEX_R_VERIFY) {
            gw_jw_kint(&w, "raw", r->raw_after);
        }
        gw_jw_kstr(&w, "reason", reason);
        gw_jw_obj_close(&w);
        return web_send_jw(c, 202, &w);
    case MEX_W_REJECTED:
    default:
        if (r->reason == MEX_R_UNKNOWN) {
            return web_send_unknown_register(c);
        }
        if (r->reason == MEX_R_BUSY) {
            return web_send_error(c, 503, WEB_E_BUSY, "write queue full", NULL);
        }
        rej_arg_t a = {.r = r, .reason = reason};
        return web_send_error_ex(c, 409, WEB_E_REJECTED, NULL, NULL, rejected_extra, &a);
    }
}

static esp_err_t do_write(web_ctx_t *c, uint8_t dev, uint16_t addr, int32_t raw) {
    mex_wresult_t r;
    memset(&r, 0, sizeof(r));
    esp_err_t err = mex_service_write(dev, addr, raw, web_user(c), WRITE_WAIT_MS, &r);
    if (err == ESP_OK || err == ESP_ERR_NO_MEM) {
        ESP_LOGI(TAG, "write d%u %u=%" PRId32 " by %s -> state %d reason %d cmd %" PRIu32, dev, addr, raw,
                 web_user(c), (int)r.state, r.reason, r.cmd);
    }
    return send_write_result(c, err, addr, &r);
}

esp_err_t h_register_write(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    uint32_t a32 = 0;
    const mex_reg_t *reg =
        (web_param_u32(c, "addr", &a32) && a32 <= UINT16_MAX) ? mex_reg_find((uint16_t)a32) : NULL;
    if (!reg) {
        return web_send_unknown_register(c);
    }
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"value", "raw", NULL};
    if (!web_json_only(c, root, allowed, NULL)) {
        cJSON_Delete(root);
        return ESP_OK;
    }
    const cJSON *jv = cJSON_GetObjectItemCaseSensitive(root, "value");
    const cJSON *jr = cJSON_GetObjectItemCaseSensitive(root, "raw");
    int32_t raw = 0;
    esp_err_t ret = ESP_OK;
    if ((jv && jr) || (!jv && !jr)) {
        ret = web_send_validation(c, jv ? "raw" : "value", jv ? "unknown_field" : "required",
                                  "exactly one of value or raw");
    } else if (jv) {
        if (!cJSON_IsNumber(jv)) {
            ret = web_send_validation(c, "value", "type", "must be a number");
        } else if (!mex_reg_from_value(reg, jv->valuedouble, &raw)) {
            /* write-result schema: no "message" member (additionalProperties false). */
            char body[112];
            gw_jw_t w;
            gw_jw_init_fixed(&w, body, sizeof(body));
            web_json_write_range_rejected(&w, reg->addr);
            ret = web_send_jw(c, 409, &w);
        } else {
            cJSON_Delete(root);
            return do_write(c, dev, reg->addr, raw);
        }
    } else {
        int64_t v = 0;
        if (web_json_int(c, root, "raw", INT32_MIN, INT32_MAX, &v, NULL)) {
            cJSON_Delete(root);
            return do_write(c, dev, reg->addr, (int32_t)v);
        }
    }
    cJSON_Delete(root);
    return ret;
}

esp_err_t h_device_run(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"run", NULL};
    bool run = false;
    if (!web_json_only(c, root, allowed, NULL) || !web_json_bool(c, root, "run", &run, NULL)) {
        cJSON_Delete(root);
        return ESP_OK;
    }
    cJSON_Delete(root);
    return do_write(c, dev, 40005, run ? 1 : 0);
}

esp_err_t h_device_command(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    uint32_t id = 0;
    mex_wresult_t r;
    if (!web_param_u32(c, "id", &id) || !id || !mex_service_command(dev, id, &r)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "unknown command", NULL);
    }
    char reason[MEX_REASON_NAME_SZ];
    char buf[256];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kuint(&w, "cmd", r.cmd);
    gw_jw_kuint(&w, "dev", r.dev);
    gw_jw_kuint(&w, "addr", r.addr);
    gw_jw_kstr(&w, "state", web_wstate_name(r.state));
    gw_jw_kint(&w, "raw", r.raw_after);
    gw_jw_kint(&w, "requested", r.raw_req);
    if (r.state == MEX_W_APPLIED || r.state == MEX_W_PENDING) {
        gw_jw_knull(&w, "reason");
    } else {
        gw_jw_kstr(&w, "reason", mex_reason_name(r.reason, reason, sizeof(reason)));
    }
    gw_jw_key(&w, "ts");
    web_json_epoch_ms(&w, r.ts_ms);
    gw_jw_obj_close(&w);
    return web_send_jw(c, 200, &w);
}

/* ---------------------------------------------------------------- history */

typedef struct {
    bool span_mode;
    uint32_t span_s;
    int64_t from_ms, to_ms;
    uint32_t res_s;
    bool stages;
} hist_q_t;

/* Parse ?span= | ?from=&to=, ?res=, ?stages=. Sends 400 and returns false on error. */
static bool parse_hist_query(web_ctx_t *c, hist_q_t *q) {
    memset(q, 0, sizeof(*q));
    int64_t span = 0, from = 0, to = 0, res = 1;
    bool stages = false;
    web_q_t qs = web_query_i64(c, "span", &span);
    web_q_t qf = web_query_i64(c, "from", &from);
    web_q_t qt = web_query_i64(c, "to", &to);
    web_q_t qr = web_query_i64(c, "res", &res);
    web_q_t qg = web_query_bool(c, "stages", &stages);
    bool ok = qs != WEB_Q_INVALID && qf != WEB_Q_INVALID && qt != WEB_Q_INVALID && qr != WEB_Q_INVALID &&
              qg != WEB_Q_INVALID;
    if (ok && qs == WEB_Q_OK) {
        ok = qf == WEB_Q_ABSENT && qt == WEB_Q_ABSENT && span >= 1 && span <= HIST_SPAN_MAX_S;
        q->span_mode = true;
        q->span_s = (uint32_t)span;
    } else if (ok) {
        ok = qf == WEB_Q_OK && qt == WEB_Q_OK && from >= 0 && to > from &&
             to - from <= (int64_t)HIST_SPAN_MAX_S * 1000;
        q->from_ms = from;
        q->to_ms = to;
    }
    ok = ok && res >= 1 && res <= 86400;
    if (!ok) {
        web_send_error(c, 400, WEB_E_BAD_REQUEST, "span (1..2592000) or from<to within 30 days; res >= 1",
                       NULL);
        return false;
    }
    q->res_s = (uint32_t)res;
    q->stages = stages;
    return true;
}

static uint32_t q_span_s(const hist_q_t *q) {
    return q->span_mode ? q->span_s : (uint32_t)((q->to_ms - q->from_ms + 999) / 1000);
}

/* One allocation for every query array (PSRAM via malloc for > 4 KB). */
typedef struct {
    hist_series_t s;
    int16_t *block;
} hist_buf_t;

static bool hist_alloc(hist_buf_t *b) {
    const size_t n = HIST_MAX_POINTS;
    const size_t arrays = HIST_CH_COUNT + 3 + 3 + HIST_STG_COUNT;
    memset(b, 0, sizeof(*b));
    b->block = malloc(arrays * n * sizeof(int16_t));
    if (!b->block) {
        return false;
    }
    int16_t *p = b->block;
    b->s.n_max = (uint32_t)n;
    for (int i = 0; i < HIST_CH_COUNT; i++, p += n) {
        b->s.avg[i] = p;
    }
    for (int i = 0; i <= HIST_CH_CUR; i++, p += n) {
        b->s.min[i] = p;
    }
    for (int i = 0; i <= HIST_CH_CUR; i++, p += n) {
        b->s.max[i] = p;
    }
    for (int i = 0; i < HIST_STG_COUNT; i++, p += n) {
        b->s.stage[i] = (uint16_t *)p;
    }
    return true;
}

static esp_err_t hist_err(web_ctx_t *c, esp_err_t err) {
    if (err == ESP_ERR_INVALID_STATE) {
        return web_send_error(c, 400, WEB_E_BAD_REQUEST, "wall clock not valid: use span", NULL);
    }
    if (err == ESP_ERR_INVALID_ARG) {
        return web_send_error(c, 400, WEB_E_BAD_REQUEST, NULL, NULL);
    }
    return web_send_esp_err(c, err);
}

esp_err_t h_device_history(web_ctx_t *c) {
    uint8_t dev;
    hist_q_t q;
    if (!web_dev_param(c, &dev) || !parse_hist_query(c, &q)) {
        return ESP_OK;
    }
    hist_buf_t b;
    if (!hist_alloc(&b)) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    if (!q.stages) {
        for (int i = 0; i < HIST_STG_COUNT; i++) {
            b.s.stage[i] = NULL;
        }
    }
    esp_err_t err = q.span_mode ? history_query_span(dev, q.span_s, q.res_s, &b.s)
                                : history_query(dev, q.from_ms, q.to_ms, q.res_s, &b.s);
    if (err != ESP_OK) {
        free(b.block);
        return hist_err(c, err);
    }
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        free(b.block);
        return ESP_OK;
    }
    web_json_history(&w, &b.s, b.s.dt_s >= 60, q.stages);
    free(b.block);
    return web_stream_end(c, &w);
}

typedef struct {
    web_ctx_t *c;
    bool agg;
    bool failed;
    uint32_t rows;
} csv_arg_t;

static bool csv_row(void *arg, int64_t ts_ms, const hist_slow_t *row) {
    csv_arg_t *a = arg;
    char line[WEB_CSV_ROW_MAX];
    int n = web_csv_hist_row(line, sizeof(line), ts_ms, row, a->agg);
    if (n < 0 || web_stream_write(a->c, line, (size_t)n) != ESP_OK) {
        a->failed = true;
        return false;
    }
    a->rows++;
    return true;
}

esp_err_t h_device_history_csv(web_ctx_t *c) {
    uint8_t dev;
    hist_q_t q;
    if (!web_dev_param(c, &dev) || !parse_hist_query(c, &q)) {
        return ESP_OK;
    }
    const uint32_t dt = hist_pick_res(q_span_s(&q), q.res_s);
    /* CSV rows need ISO 8601 UTC times (API.md §4.6): without a valid wall clock the export is
     * refused in both modes (the JSON span query still works). */
    if (!gw_time_valid()) {
        return web_send_error(c, 400, WEB_E_BAD_REQUEST, "wall clock not valid: set the time to export CSV",
                              NULL);
    }
    int64_t from_s, to_s;
    if (q.span_mode) {
        to_s = gw_time_wall_ms() / 1000;
        from_s = to_s - q.span_s;
    } else {
        from_s = q.from_ms / 1000;
        to_s = q.to_ms / 1000;
    }
    char fname[64];
    snprintf(fname, sizeof(fname), "mestio-d%u-%" PRId64 "-%" PRId64 ".csv", (unsigned)dev, from_s, to_s);
    if (web_stream_begin(c, 200, "text/csv; charset=utf-8", fname, NULL) != ESP_OK) {
        return ESP_OK;
    }
    char head[128];
    csv_arg_t a = {.c = c, .agg = dt >= 60};
    int n = web_csv_hist_header(head, sizeof(head), a.agg);
    esp_err_t err = web_stream_write(c, WEB_CSV_BOM, 3);
    if (err == ESP_OK && n > 0) {
        err = web_stream_write(c, head, (size_t)n);
    }
    if (err == ESP_OK) {
        err = q.span_mode ? history_foreach_span(dev, q.span_s, dt, csv_row, &a)
                          : history_foreach(dev, q.from_ms, q.to_ms, dt, csv_row, &a);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "history csv: %s", esp_err_to_name(err));
        }
    }
    if (err != ESP_OK || a.failed) {
        return ESP_FAIL; /* status already sent: truncate the stream */
    }
    return web_stream_end(c, NULL);
}

/* ---------------------------------------------------------------- statistics */

esp_err_t h_device_stats(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    mex_stats_t s;
    mex_service_stats(dev, &s, false);
    char buf[320];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kuint(&w, "tx", s.tx);
    gw_jw_kuint(&w, "rx_ok", s.rx_ok);
    gw_jw_kuint(&w, "crc", s.crc);
    gw_jw_kuint(&w, "timeout", s.timeout);
    gw_jw_kuint(&w, "exception", s.exception);
    gw_jw_kuint(&w, "malformed", s.malformed);
    gw_jw_kobj(&w, "rtt_ms");
    gw_jw_kuint(&w, "last", s.rtt_last);
    gw_jw_kuint(&w, "avg", s.rtt_avg);
    gw_jw_kuint(&w, "max", s.rtt_max);
    gw_jw_obj_close(&w);
    gw_jw_key(&w, "online_since");
    web_json_epoch_ms(&w, s.online_since_ms);
    gw_jw_kuint(&w, "offline_count", s.offline_count);
    gw_jw_kuint(&w, "cycles", s.cycles);
    gw_jw_obj_close(&w);
    return web_send_jw(c, 200, &w);
}

esp_err_t h_device_stats_reset(web_ctx_t *c) {
    uint8_t dev;
    if (!web_dev_param(c, &dev)) {
        return ESP_OK;
    }
    mex_stats_t s;
    mex_service_stats(dev, &s, true);
    evlog_audit(AUD_STATS_RESET, dev, 0, 0, web_user(c), 0);
    return web_send_status(c, 204);
}
