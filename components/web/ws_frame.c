/* WebSocket frame builders and client-message parser (web_core.h, API.md §5). Pure C on
 * gw_json_writer + cJSON; host-tested. Frames are built once per event by the gw_evt handlers in
 * ws_hub.c into pool buffers. */
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "web_core.h"

static void reg_key(char out[8], uint16_t addr) {
    snprintf(out, 8, "%u", (unsigned)addr);
}

static void opt_ms(gw_jw_t *w, const char *key, int64_t ms) {
    gw_jw_key(w, key);
    web_json_epoch_ms(w, ms);
}

/* Previous raw of addr in the state, or false if it was not reported. */
static bool prev_raw(const ws_snap_state_t *st, uint16_t addr, int32_t *raw) {
    for (size_t i = 0; i < st->n; i++) {
        if (st->addr[i] == addr) {
            *raw = st->raw[i];
            return true;
        }
    }
    return false;
}

int ws_frame_snap(ws_snap_state_t *st, gw_jw_t *w, uint8_t dev, uint32_t seq, int64_t ts_ms, bool online,
                  const uint16_t *addr, const int32_t *raw, size_t n, uint32_t coils, bool force_full,
                  uint64_t now_mono_ms, uint32_t full_period_s) {
    if (!st || !w || (n && (!addr || !raw))) {
        return GW_JW_E_STATE;
    }
    if (n > WS_SNAP_MAX_REGS) {
        n = WS_SNAP_MAX_REGS;
    }
    const bool full = !st->valid || force_full || now_mono_ms < st->last_full_mono_ms ||
                      now_mono_ms - st->last_full_mono_ms >= (uint64_t)full_period_s * 1000u;
    char k[8];
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "snap");
    gw_jw_kuint(w, "dev", dev);
    gw_jw_kuint(w, "seq", seq);
    opt_ms(w, "ts", ts_ms);
    gw_jw_kbool(w, "on", online);
    gw_jw_kbool(w, "full", full);
    gw_jw_kobj(w, "r");
    for (size_t i = 0; i < n; i++) {
        int32_t p = 0;
        if (full || !prev_raw(st, addr[i], &p) || p != raw[i]) {
            reg_key(k, addr[i]);
            gw_jw_kint(w, k, raw[i]);
        }
    }
    gw_jw_obj_close(w);
    if (full || coils != st->coils) {
        gw_jw_kuint(w, "c", coils);
    }
    gw_jw_obj_close(w);
    int err = gw_jw_error(w);
    if (err == GW_JW_OK) {
        st->valid = true;
        st->coils = coils;
        st->n = (uint8_t)n;
        if (n) {
            memcpy(st->addr, addr, n * sizeof(addr[0]));
            memcpy(st->raw, raw, n * sizeof(raw[0]));
        }
        if (full) {
            st->last_full_mono_ms = now_mono_ms;
        }
    }
    return err;
}

static const char *alarm_type_name(unsigned type) {
    switch (type) {
    case 1:
        return "raise";
    case 2:
        return "clear";
    default:
        return "ack";
    }
}

void ws_frame_alarm(gw_jw_t *w, uint8_t dev, const char *id, unsigned code, unsigned type, unsigned sev,
                    int64_t ts_ms, uint32_t seq, int value, const char *user) {
    char key[40];
    snprintf(key, sizeof(key), "%u:%s", (unsigned)dev, id ? id : "");
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "alarm");
    gw_jw_kuint(w, "dev", dev);
    gw_jw_kstr(w, "key", key);
    gw_jw_kstr(w, "id", id ? id : "");
    gw_jw_kuint(w, "code", code);
    gw_jw_kstr(w, "type", alarm_type_name(type));
    gw_jw_kuint(w, "sev", sev);
    opt_ms(w, "ts", ts_ms);
    gw_jw_kuint(w, "seq", seq);
    gw_jw_kint(w, "value", value);
    if (type == 3 && user && user[0]) {
        gw_jw_kstr(w, "user", user);
    }
    gw_jw_obj_close(w);
}

void ws_frame_write(gw_jw_t *w, uint8_t dev, uint32_t cmd, unsigned addr, int state, bool include_raw,
                    int32_t raw, const char *reason, const char *by) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "write");
    gw_jw_kuint(w, "dev", dev);
    gw_jw_kuint(w, "cmd", cmd);
    gw_jw_kuint(w, "addr", addr);
    gw_jw_kstr(w, "state", web_wstate_name(state));
    if (include_raw) {
        gw_jw_kint(w, "raw", raw);
    }
    if (reason) {
        gw_jw_kstr(w, "reason", reason);
    }
    gw_jw_kstr(w, "by", by ? by : "");
    gw_jw_obj_close(w);
}

void ws_frame_comm(gw_jw_t *w, uint8_t dev, bool online, unsigned rtt, uint32_t crc, uint32_t timeout,
                   uint32_t exception, uint32_t malformed) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "comm");
    gw_jw_kuint(w, "dev", dev);
    gw_jw_kbool(w, "online", online);
    gw_jw_kuint(w, "rtt", rtt > 65535u ? 65535u : rtt);
    gw_jw_kobj(w, "err");
    gw_jw_kuint(w, "crc", crc);
    gw_jw_kuint(w, "timeout", timeout);
    gw_jw_kuint(w, "exception", exception);
    gw_jw_kuint(w, "malformed", malformed);
    gw_jw_obj_close(w);
    gw_jw_obj_close(w);
}

void ws_frame_sys(gw_jw_t *w, uint32_t heap, uint32_t heap_min, uint32_t psram, uint32_t up_s,
                  int64_t time_ms, uint32_t alarms) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "sys");
    gw_jw_kuint(w, "heap", heap);
    gw_jw_kuint(w, "heap_min", heap_min);
    gw_jw_kuint(w, "psram", psram);
    gw_jw_kuint(w, "up", up_s);
    opt_ms(w, "time", time_ms);
    gw_jw_kuint(w, "alarms", alarms > 200u ? 200u : alarms);
    gw_jw_obj_close(w);
}

void ws_frame_hello(gw_jw_t *w, int64_t srv_ms, const uint8_t *devs, const uint32_t *seqs, size_t n,
                    const char *meta_etag) {
    char k[4];
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "hello");
    gw_jw_kuint(w, "v", 1);
    opt_ms(w, "srv", srv_ms);
    gw_jw_karr(w, "devs");
    for (size_t i = 0; i < n; i++) {
        gw_jw_uint(w, devs[i]);
    }
    gw_jw_arr_close(w);
    gw_jw_kobj(w, "seq");
    for (size_t i = 0; i < n; i++) {
        snprintf(k, sizeof(k), "%u", (unsigned)(devs[i] % 10u));
        gw_jw_kuint(w, k, seqs ? seqs[i] : 0u);
    }
    gw_jw_obj_close(w);
    gw_jw_kstr(w, "meta", meta_etag ? meta_etag : "");
    gw_jw_obj_close(w);
}

void ws_frame_bye(gw_jw_t *w, const char *reason) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "bye");
    gw_jw_kstr(w, "reason", reason ? reason : "session_expired");
    gw_jw_obj_close(w);
}

void ws_frame_pong(gw_jw_t *w, int64_t srv_ms) {
    gw_jw_obj_open(w);
    gw_jw_kstr(w, "t", "pong");
    opt_ms(w, "srv", srv_ms);
    gw_jw_obj_close(w);
}

ws_msg_t ws_parse_client(const char *data, size_t len, uint32_t *topics) {
    static const struct {
        const char *name;
        uint32_t bit;
    } names[] = {{"snap", WS_TOPIC_SNAP_BIT},
                 {"alarm", WS_TOPIC_ALARM_BIT},
                 {"comm", WS_TOPIC_COMM_BIT},
                 {"write", WS_TOPIC_WRITE_BIT},
                 {"sys", WS_TOPIC_SYS_BIT}};
    if (!data || !len) {
        return WS_MSG_INVALID;
    }
    cJSON *root = cJSON_ParseWithLength(data, len);
    if (!root) {
        return WS_MSG_INVALID;
    }
    ws_msg_t r = WS_MSG_UNKNOWN;
    const cJSON *t = cJSON_IsObject(root) ? cJSON_GetObjectItemCaseSensitive(root, "t") : NULL;
    if (!cJSON_IsObject(root)) {
        r = WS_MSG_INVALID;
    } else if (cJSON_IsString(t) && strcmp(t->valuestring, "ping") == 0) {
        r = WS_MSG_PING;
    } else if (cJSON_IsString(t) && strcmp(t->valuestring, "sub") == 0) {
        const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "topics");
        if (!cJSON_IsArray(arr)) {
            r = WS_MSG_INVALID;
        } else {
            uint32_t mask = 0;
            const cJSON *it;
            cJSON_ArrayForEach(it, arr) {
                if (!cJSON_IsString(it)) {
                    continue;
                }
                for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                    if (strcmp(it->valuestring, names[i].name) == 0) {
                        mask |= names[i].bit;
                    }
                }
            }
            if (topics) {
                *topics = mask;
            }
            r = WS_MSG_SUB;
        }
    }
    cJSON_Delete(root);
    return r;
}
