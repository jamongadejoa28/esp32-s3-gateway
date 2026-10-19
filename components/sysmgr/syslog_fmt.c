/* RFC 5424 syslog formatting, rate limiting and severity mapping (pure C). Contract: sysmgr_pure.h. */
#include <stdio.h>
#include <string.h>

#include "gw_core/gw_time.h"
#include "sysmgr_pure.h"

#define SL_HOSTNAME_MAX 255
#define SL_APPNAME_MAX 48
#define SL_MSGID_MAX 32

typedef struct {
    char *buf;
    size_t cap; /* usable bytes (excluding NUL) */
    size_t len;
} sbuf_t;

static void put(sbuf_t *b, char c) {
    if (b->len < b->cap) {
        b->buf[b->len++] = c;
    }
}

/* PRINTUSASCII field (33..126), max chars, "-" when empty. */
static void put_field(sbuf_t *b, const char *s, size_t max) {
    size_t n = 0;
    for (; s && s[n] && n < max; n++) {
        const unsigned char c = (unsigned char)s[n];
        put(b, (c >= 33 && c <= 126) ? (char)c : '_');
    }
    if (n == 0) {
        put(b, '-');
    }
}

static bool has_non_ascii(const char *s) {
    for (; s && *s; s++) {
        if ((unsigned char)*s >= 0x80) {
            return true;
        }
    }
    return false;
}

size_t syslog_format(char *out, size_t cap, uint8_t facility, uint8_t severity, int64_t wall_ms,
                     const char *hostname, const char *app, const char *msgid, const char *msg) {
    if (!out || cap < 2) {
        return 0;
    }
    if (facility > 23) {
        facility = 23;
    }
    if (severity > 7) {
        severity = 7;
    }
    size_t limit = cap - 1;
    if (limit > SYSLOG_MAX_LINE) {
        limit = SYSLOG_MAX_LINE;
    }
    sbuf_t b = {.buf = out, .cap = limit, .len = 0};

    char head[16];
    const int hn = snprintf(head, sizeof(head), "<%u>1 ", (unsigned)facility * 8u + severity);
    for (int i = 0; i < hn; i++) {
        put(&b, head[i]);
    }
    char ts[32];
    if (wall_ms > 0 && gw_time_iso8601(wall_ms, ts, sizeof(ts)) > 0) {
        for (const char *p = ts; *p; p++) {
            put(&b, *p);
        }
    } else {
        put(&b, '-');
    }
    put(&b, ' ');
    put_field(&b, hostname, SL_HOSTNAME_MAX);
    put(&b, ' ');
    put_field(&b, app, SL_APPNAME_MAX);
    put(&b, ' ');
    put(&b, '-'); /* PROCID */
    put(&b, ' ');
    put_field(&b, msgid, SL_MSGID_MAX);
    put(&b, ' ');
    put(&b, '-'); /* STRUCTURED-DATA */
    if (msg && *msg) {
        put(&b, ' ');
        if (has_non_ascii(msg)) {
            put(&b, (char)0xEF);
            put(&b, (char)0xBB);
            put(&b, (char)0xBF);
        }
        for (const char *p = msg; *p; p++) {
            const unsigned char c = (unsigned char)*p;
            put(&b, (c < 0x20 || c == 0x7F) ? ' ' : (char)c);
        }
    }
    /* Never end inside a UTF-8 sequence: drop a trailing incomplete sequence. */
    size_t len = b.len;
    if (len > 0 && ((unsigned char)out[len - 1] & 0x80)) {
        size_t i = len;
        size_t cont = 0;
        while (i > 0 && ((unsigned char)out[i - 1] & 0xC0) == 0x80 && cont < 3) {
            i--;
            cont++;
        }
        if (i > 0) {
            const unsigned char lead = (unsigned char)out[i - 1];
            size_t need = (lead & 0xE0) == 0xC0 ? 1 : (lead & 0xF0) == 0xE0 ? 2 : (lead & 0xF8) == 0xF0 ? 3 : 0;
            if ((lead & 0xC0) == 0xC0 && cont < need) {
                len = i - 1; /* incomplete: cut before the lead byte */
            }
        }
    }
    out[len] = '\0';
    return len;
}

bool syslog_rl_take(syslog_rl_t *rl, uint32_t now_ms, uint32_t rate, uint32_t burst) {
    const uint32_t cap = burst * 1000u;
    if (!rl->primed) {
        rl->primed = true;
        rl->milli_tokens = cap;
        rl->last_ms = now_ms;
    } else {
        const uint32_t dt = now_ms - rl->last_ms; /* wraps safely */
        rl->last_ms = now_ms;
        const uint64_t add = (uint64_t)dt * rate;
        const uint64_t t = rl->milli_tokens + add;
        rl->milli_tokens = t > cap ? cap : (uint32_t)t;
    }
    if (rl->milli_tokens >= 1000u) {
        rl->milli_tokens -= 1000u;
        return true;
    }
    rl->dropped++;
    return false;
}

uint32_t syslog_rl_take_dropped(syslog_rl_t *rl) {
    const uint32_t n = rl->dropped;
    rl->dropped = 0;
    return n;
}

uint8_t syslog_alarm_severity(uint8_t type, uint8_t sev) {
    if (type != 1 /* GW_ALARM_RAISE */) {
        return 5;
    }
    switch (sev) {
    case 3: /* ALM_SEV_CRITICAL */
        return 2;
    case 2: /* ALM_SEV_MAJOR */
        return 3;
    case 1: /* ALM_SEV_MINOR */
        return 4;
    default:
        return 5;
    }
}
