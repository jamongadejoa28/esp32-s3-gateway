/* CSV rows for GET /devices/{d}/history.csv and /alarms/history.csv (API.md §4.6/§4.7).
 * Pure C; CRLF line ends; the BOM is sent once by the handler (WEB_CSV_BOM). */
#include <stdio.h>
#include <string.h>

#include "gw_core/gw_time.h"
#include "web_core.h"

static bool put(char *out, size_t cap, size_t *len, const char *s, size_t n) {
    if (*len + n + 1 > cap) {
        return false;
    }
    memcpy(out + *len, s, n);
    *len += n;
    out[*len] = '\0';
    return true;
}

static bool puts_(char *out, size_t cap, size_t *len, const char *s) {
    return put(out, cap, len, s, strlen(s));
}

/* raw x10 -> "23.5" / "-0.5"; HIST_GAP -> "" */
static bool put_x10(char *out, size_t cap, size_t *len, int16_t v) {
    if (v == HIST_GAP) {
        return true;
    }
    int32_t x = v;
    unsigned a = (unsigned)(x < 0 ? -x : x);
    char b[16];
    int n = snprintf(b, sizeof(b), "%s%u.%u", x < 0 ? "-" : "", a / 10u, a % 10u);
    return n > 0 && put(out, cap, len, b, (size_t)n);
}

static bool put_time(char *out, size_t cap, size_t *len, int64_t ts_ms) {
    if (ts_ms <= 0) {
        return true;
    }
    char t[32];
    size_t n = gw_time_iso8601(ts_ms, t, sizeof(t));
    return n > 0 && put(out, cap, len, t, n);
}

bool web_csv_field(char *out, size_t cap, size_t *len, const char *s) {
    if (!s) {
        return true;
    }
    bool quote = strpbrk(s, ",\"\r\n") != NULL;
    bool formula = s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@';
    if (!quote && !formula) {
        return puts_(out, cap, len, s);
    }
    if (quote && !put(out, cap, len, "\"", 1)) {
        return false;
    }
    if (formula && !put(out, cap, len, "'", 1)) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        if (*p == '"' && !put(out, cap, len, "\"", 1)) {
            return false;
        }
        if (!put(out, cap, len, p, 1)) {
            return false;
        }
    }
    return !quote || put(out, cap, len, "\"", 1);
}

int web_csv_hist_header(char *out, size_t cap, bool agg) {
    static const char base[] = "time,temp,hum,current,set_temp,set_hum";
    static const char ext[] = ",temp_min,temp_max,hum_min,hum_max,current_min,current_max";
    size_t len = 0;
    if (!out || !cap) {
        return -1;
    }
    out[0] = '\0';
    if (!puts_(out, cap, &len, base) || (agg && !puts_(out, cap, &len, ext)) ||
        !puts_(out, cap, &len, "\r\n")) {
        return -1;
    }
    return (int)len;
}

int web_csv_hist_row(char *out, size_t cap, int64_t ts_ms, const hist_slow_t *r, bool agg) {
    size_t len = 0;
    if (!out || !cap || !r) {
        return -1;
    }
    out[0] = '\0';
    const bool gap = r->samples == 0;
    const int16_t g = HIST_GAP;
    bool ok = put_time(out, cap, &len, ts_ms) && puts_(out, cap, &len, ",") &&
              put_x10(out, cap, &len, gap ? g : r->tavg) && puts_(out, cap, &len, ",") &&
              put_x10(out, cap, &len, gap ? g : r->havg) && puts_(out, cap, &len, ",") &&
              put_x10(out, cap, &len, gap ? g : r->cavg) && puts_(out, cap, &len, ",") &&
              put_x10(out, cap, &len, gap ? g : r->st) && puts_(out, cap, &len, ",") &&
              put_x10(out, cap, &len, gap ? g : r->sh);
    if (ok && agg) {
        const int16_t v[6] = {r->tmin, r->tmax, r->hmin, r->hmax, r->cmin, r->cmax};
        for (int i = 0; ok && i < 6; i++) {
            ok = puts_(out, cap, &len, ",") && put_x10(out, cap, &len, gap ? g : v[i]);
        }
    }
    ok = ok && puts_(out, cap, &len, "\r\n");
    return ok ? (int)len : -1;
}

int web_csv_alarm_header(char *out, size_t cap) {
    size_t len = 0;
    if (!out || !cap) {
        return -1;
    }
    out[0] = '\0';
    return puts_(out, cap, &len, "seq,time,dev,id,code,type,sev,value,user\r\n") ? (int)len : -1;
}

int web_csv_alarm_row(char *out, size_t cap, uint32_t seq, int64_t ts_ms, unsigned dev, const char *id,
                      unsigned code, const char *type, unsigned sev, int value, const char *user) {
    size_t len = 0;
    if (!out || !cap) {
        return -1;
    }
    out[0] = '\0';
    char num[16];
    bool ok = snprintf(num, sizeof(num), "%u,", (unsigned)seq) > 0 && puts_(out, cap, &len, num) &&
              put_time(out, cap, &len, ts_ms) && snprintf(num, sizeof(num), ",%u,", dev) > 0 &&
              puts_(out, cap, &len, num) && web_csv_field(out, cap, &len, id) &&
              snprintf(num, sizeof(num), ",%u,", code) > 0 && puts_(out, cap, &len, num) &&
              web_csv_field(out, cap, &len, type) && snprintf(num, sizeof(num), ",%u,%d,", sev, value) > 0 &&
              puts_(out, cap, &len, num) && web_csv_field(out, cap, &len, user) &&
              puts_(out, cap, &len, "\r\n");
    return ok ? (int)len : -1;
}
