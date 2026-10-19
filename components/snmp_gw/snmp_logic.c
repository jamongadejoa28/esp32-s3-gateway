/* Pure building blocks of the gateway SNMP agent (contract: snmp_logic.h, registry.h OID helpers).
 * Host-built (cmake/gw_host_sources.cmake) and tested by tests/test_snmp_logic.py. */
#include "snmp_logic.h"

#include <string.h>

#include "gw_core/gw_crypto.h"
#include "mex150/regmap.h"
#include "mex150/service.h"
#include "snmp_gw/registry.h"

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif
#ifndef CONFIG_GW_SNMP_ENTERPRISE_PEN
#define CONFIG_GW_SNMP_ENTERPRISE_PEN 32473 /* host builds: the Kconfig default (RFC 5612 documentation PEN) */
#endif

_Static_assert(SNMP_GW_OID_MAX >= 8 + 5, "gateway OIDs (mestioGwMIB = 8 arcs) need room for a table cell");

/* strnlen() is POSIX, not C11. */
static size_t bounded_len(const char *s, size_t max) {
    size_t n = 0;
    while (n < max && s[n] != '\0') {
        n++;
    }
    return n;
}

/* ---------------------------------------------------------------- OIDs (registry.h) */

static const uint32_t ENTERPRISES[] = {1, 3, 6, 1, 4, 1};

size_t snmp_oid_build(uint32_t pen, const uint32_t *suffix, size_t n, uint32_t *out, size_t cap) {
    const size_t prefix = sizeof(ENTERPRISES) / sizeof(ENTERPRISES[0]);
    if (out == NULL || pen == 0 || (suffix == NULL && n > 0) || prefix + 2 + n > cap) {
        return 0;
    }
    memcpy(out, ENTERPRISES, sizeof(ENTERPRISES));
    out[prefix] = pen;
    out[prefix + 1] = 1;
    for (size_t i = 0; i < n; i++) {
        out[prefix + 2 + i] = suffix[i];
    }
    return prefix + 2 + n;
}

uint32_t snmp_gw_pen(void) {
    return (uint32_t)CONFIG_GW_SNMP_ENTERPRISE_PEN;
}

size_t snmp_gw_oid(const uint32_t *suffix, size_t n, uint32_t *out, size_t cap) {
    return snmp_oid_build(snmp_gw_pen(), suffix, n, out, cap);
}

/* ---------------------------------------------------------------- token bucket */

void snmp_tb_init(snmp_tbucket_t *tb, uint32_t rate, uint32_t burst) {
    tb->rate = rate ? rate : 1;
    tb->burst = burst ? burst : 1;
    tb->milli = (uint64_t)tb->burst * 1000u;
    tb->last_ms = 0;
    tb->started = false;
}

bool snmp_tb_take(snmp_tbucket_t *tb, uint64_t now_ms) {
    if (!tb->started) {
        tb->started = true;
        tb->last_ms = now_ms;
    } else if (now_ms > tb->last_ms) {
        uint64_t add = (now_ms - tb->last_ms) * tb->rate; /* milli-tokens: rate/s * ms */
        uint64_t cap = (uint64_t)tb->burst * 1000u;
        tb->milli = (add >= cap || tb->milli + add >= cap) ? cap : tb->milli + add;
        tb->last_ms = now_ms;
    }
    if (tb->milli < 1000u) {
        return false;
    }
    tb->milli -= 1000u;
    return true;
}

/* ---------------------------------------------------------------- comm-loss coalescing */

void snmp_cc_init(snmp_comm_coalesce_t *cc) {
    memset(cc, 0, sizeof(*cc));
    for (size_t i = 0; i < GW_MAX_DEVICES; i++) {
        cc->dev[i].reported_online = true;
        cc->dev[i].latest_online = true;
    }
}

void snmp_cc_event(snmp_comm_coalesce_t *cc, uint8_t dev, bool online, uint64_t now_ms) {
    if (dev >= GW_MAX_DEVICES) {
        return;
    }
    snmp_comm_dev_t *d = &cc->dev[dev];
    d->latest_online = online;
    if (d->pending) {
        return; /* already scheduled: the due report carries the latest state */
    }
    if (online == d->reported_online) {
        return; /* nothing to report (e.g. first "online" after boot) */
    }
    uint64_t due = now_ms + SNMP_COMM_HOLD_MS;
    if (d->ever_reported && d->last_report_ms + SNMP_COMM_MIN_INTERVAL_MS > due) {
        due = d->last_report_ms + SNMP_COMM_MIN_INTERVAL_MS;
    }
    d->pending = true;
    d->due_ms = due;
}

size_t snmp_cc_poll(snmp_comm_coalesce_t *cc, uint64_t now_ms, snmp_comm_report_t *out, size_t cap) {
    size_t n = 0;
    for (uint8_t i = 0; i < GW_MAX_DEVICES && n < cap; i++) {
        snmp_comm_dev_t *d = &cc->dev[i];
        if (!d->pending || now_ms < d->due_ms) {
            continue;
        }
        d->pending = false;
        if (d->latest_online == d->reported_online) {
            continue; /* flapped back within the window: nothing to report */
        }
        d->reported_online = d->latest_online;
        d->ever_reported = true;
        d->last_report_ms = now_ms;
        out[n].dev = i;
        out[n].online = d->latest_online;
        n++;
    }
    return n;
}

/* ---------------------------------------------------------------- USM user table */

void snmp_usm_clear(snmp_usm_table_t *t) {
    gw_secure_zero(t, sizeof(*t));
}

void snmp_usm_build(snmp_usm_table_t *t, const cfg_snmp_t *cfg, const sec_v3_keys_t *keys) {
    snmp_usm_clear(t);
    if (cfg == NULL || !cfg->v3 || keys == NULL) {
        return;
    }
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        const cfg_snmp_v3user_t *u = &cfg->users[i];
        size_t len = bounded_len(u->name, sizeof(u->name));
        if (!u->enabled || !keys[i].set || len == 0 || len > GW_SNMP_USER_MAX) {
            continue;
        }
        if (u->access != CFG_SNMP_RO && u->access != CFG_SNMP_RW) {
            continue;
        }
        bool dup = false;
        for (size_t j = 0; j < i; j++) {
            if (t->user[j].valid && strcmp(t->user[j].name, u->name) == 0) {
                dup = true;
            }
        }
        if (dup) {
            continue;
        }
        snmp_usm_user_t *d = &t->user[i];
        memcpy(d->name, u->name, len);
        d->name[len] = '\0';
        d->access = u->access;
        memcpy(d->auth_key, keys[i].auth_key, SEC_V3_KEY_LEN);
        memcpy(d->priv_key, keys[i].priv_key, SEC_V3_KEY_LEN);
        d->valid = true;
    }
}

const snmp_usm_user_t *snmp_usm_find(const snmp_usm_table_t *t, const char *name) {
    if (t == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        if (t->user[i].valid && strcmp(t->user[i].name, name) == 0) {
            return &t->user[i];
        }
    }
    return NULL;
}

uint8_t snmp_usm_count(const snmp_usm_table_t *t) {
    uint8_t n = 0;
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        n = (uint8_t)(n + (t->user[i].valid ? 1 : 0));
    }
    return n;
}

const snmp_usm_user_t *snmp_usm_at(const snmp_usm_table_t *t, uint8_t idx) {
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        if (t->user[i].valid) {
            if (idx == 0) {
                return &t->user[i];
            }
            idx--;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- inform tracking */

void snmp_inf_init(snmp_inform_table_t *t) {
    memset(t, 0, sizeof(*t));
}

int snmp_inf_add(snmp_inform_table_t *t, uint8_t target, uint32_t ip, int32_t req_id, uint64_t now_ms,
                 uint32_t test_gen, const void *msg, size_t msg_len, bool *evicted, snmp_inform_t *evicted_out) {
    int idx = -1;
    *evicted = false;
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        if (!t->slot[i].used) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        idx = 0;
        for (int i = 1; i < SNMP_INFORM_SLOTS; i++) {
            if (t->slot[i].order < t->slot[idx].order) {
                idx = i;
            }
        }
        *evicted = true;
        if (evicted_out != NULL) {
            *evicted_out = t->slot[idx];
        }
    }
    snmp_inform_t *s = &t->slot[idx];
    memset(s, 0, sizeof(*s));
    s->used = true;
    s->target = target;
    s->ip = ip;
    s->sends = 1;
    s->req_id[0] = req_id;
    s->due_ms = now_ms + SNMP_GW_INFORM_TIMEOUT_MS;
    s->test_gen = test_gen;
    s->order = t->next_order++;
    if (msg != NULL) {
        s->msg_len = (uint16_t)(msg_len > sizeof(s->msg) ? sizeof(s->msg) : msg_len);
        memcpy(s->msg, msg, s->msg_len);
    }
    return idx;
}

void snmp_inf_resent(snmp_inform_table_t *t, int i, int32_t req_id, uint64_t now_ms) {
    if (i < 0 || i >= SNMP_INFORM_SLOTS || !t->slot[i].used) {
        return;
    }
    snmp_inform_t *s = &t->slot[i];
    if (s->sends < SNMP_INFORM_IDS) {
        s->req_id[s->sends] = req_id;
    }
    s->sends++;
    s->due_ms = now_ms + SNMP_GW_INFORM_TIMEOUT_MS;
}

int snmp_inf_match(const snmp_inform_table_t *t, int32_t req_id, uint32_t peer_ip) {
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        const snmp_inform_t *s = &t->slot[i];
        if (!s->used || s->ip != peer_ip) {
            continue;
        }
        size_t n = s->sends < SNMP_INFORM_IDS ? s->sends : SNMP_INFORM_IDS;
        for (size_t k = 0; k < n; k++) {
            if (s->req_id[k] == req_id) {
                return i;
            }
        }
    }
    return -1;
}

int snmp_inf_peer(const snmp_inform_table_t *t, uint32_t peer_ip) {
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        if (t->slot[i].used && t->slot[i].ip == peer_ip) {
            return i;
        }
    }
    return -1;
}

int snmp_inf_due(const snmp_inform_table_t *t, uint64_t now_ms) {
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        if (t->slot[i].used && now_ms >= t->slot[i].due_ms) {
            return i;
        }
    }
    return -1;
}

bool snmp_inf_can_retry(const snmp_inform_table_t *t, int i) {
    return i >= 0 && i < SNMP_INFORM_SLOTS && t->slot[i].used && t->slot[i].sends < SNMP_INFORM_IDS;
}

void snmp_inf_free(snmp_inform_table_t *t, int i) {
    if (i >= 0 && i < SNMP_INFORM_SLOTS) {
        memset(&t->slot[i], 0, sizeof(t->slot[i]));
    }
}

size_t snmp_inf_drop_target(snmp_inform_table_t *t, uint8_t target) {
    size_t n = 0;
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        if (t->slot[i].used && t->slot[i].target == target) {
            snmp_inf_free(t, i);
            n++;
        }
    }
    return n;
}

size_t snmp_inf_free_slots(const snmp_inform_table_t *t) {
    size_t n = 0;
    for (int i = 0; i < SNMP_INFORM_SLOTS; i++) {
        n += t->slot[i].used ? 0u : 1u;
    }
    return n;
}

/* ---------------------------------------------------------------- alarm event ring */

void snmp_evring_init(snmp_evring_t *r) {
    memset(r, 0, sizeof(*r));
}

bool snmp_evring_insert(snmp_evring_t *r, const snmp_alarm_ev_t *ev) {
    if (ev == NULL || ev->seq == 0) {
        return false;
    }
    size_t pos = r->n; /* insertion point: first element with seq > ev->seq */
    while (pos > 0 && r->ev[pos - 1].seq > ev->seq) {
        pos--;
    }
    if (pos > 0 && r->ev[pos - 1].seq == ev->seq) {
        return false; /* duplicate */
    }
    if (r->n == SNMP_GW_EVENTS_KEPT) {
        if (pos == 0) {
            return false; /* older than everything kept */
        }
        /* drop the oldest, shift [1, pos) one down, insert at pos - 1 */
        memmove(&r->ev[0], &r->ev[1], (pos - 1) * sizeof(r->ev[0]));
        r->ev[pos - 1] = *ev;
        return true;
    }
    memmove(&r->ev[pos + 1], &r->ev[pos], (r->n - pos) * sizeof(r->ev[0]));
    r->ev[pos] = *ev;
    r->n++;
    return true;
}

const snmp_alarm_ev_t *snmp_evring_find(const snmp_evring_t *r, uint32_t seq) {
    for (size_t i = 0; i < r->n; i++) {
        if (r->ev[i].seq == seq) {
            return &r->ev[i];
        }
    }
    return NULL;
}

const snmp_alarm_ev_t *snmp_evring_next(const snmp_evring_t *r, uint32_t after) {
    for (size_t i = 0; i < r->n; i++) {
        if (r->ev[i].seq > after) {
            return &r->ev[i];
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- misc */

bool snmp_text_ok(const uint8_t *s, size_t len, size_t max) {
    if (len > max || (s == NULL && len > 0)) {
        return false;
    }
    size_t i = 0;
    while (i < len) {
        uint8_t c = s[i];
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7F) {
                return false;
            }
            i++;
            continue;
        }
        size_t need;
        uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF) {
            need = 1;
            cp = c & 0x1Fu;
        } else if (c >= 0xE0 && c <= 0xEF) {
            need = 2;
            cp = c & 0x0Fu;
        } else if (c >= 0xF0 && c <= 0xF4) {
            need = 3;
            cp = c & 0x07u;
        } else {
            return false;
        }
        if (need >= len - i) { /* the last continuation byte s[i + need] must exist */
            return false;
        }
        for (size_t k = 1; k <= need; k++) {
            uint8_t cc = s[i + k];
            if ((cc & 0xC0u) != 0x80u) {
                return false;
            }
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += need + 1;
    }
    return true;
}

int snmp_localize_key_for(const char *pass, const uint8_t *engine_id, size_t engine_len,
                          uint8_t out[SEC_V3_KEY_LEN]) {
    if (out == NULL) {
        return GW_CRYPTO_E_ARG;
    }
    size_t len = pass ? bounded_len(pass, GW_SNMP_PASS_MAX + 1) : 0;
    if (len < GW_SNMP_PASS_MIN || len > GW_SNMP_PASS_MAX) {
        memset(out, 0, SEC_V3_KEY_LEN);
        return GW_CRYPTO_E_ARG;
    }
    return gw_snmp_key_localize(GW_HASH_SHA1, pass, len, engine_id, engine_len, out);
}

int snmp_err_for_reason(int reason) {
    switch (reason) {
    case MEX_R_OK:
        return SNMP_PROTO_NOERROR;
    case MEX_R_RANGE:
        return SNMP_PROTO_WRONGVALUE;
    case MEX_R_READONLY:
    case MEX_R_UNKNOWN:
        return SNMP_PROTO_NOTWRITABLE;
    case MEX_R_INTERLOCK:
        return SNMP_PROTO_INCONSISTENTVALUE;
    case MEX_R_OFFLINE:
    case MEX_R_BUSY:
        return SNMP_PROTO_RESOURCEUNAVAILABLE;
    default:
        return SNMP_PROTO_GENERR;
    }
}

int32_t snmp_write_result_code(int state) {
    switch (state) {
    case MEX_W_PENDING:
        return 2;
    case MEX_W_APPLIED:
        return 3;
    case MEX_W_REJECTED:
        return 4;
    case MEX_W_UNCERTAIN:
        return 5;
    default:
        return 1;
    }
}

const char *snmp_principal_view(const char *by, bool authenticated) {
    if (by == NULL || by[0] == '\0') {
        return "";
    }
    if (by[0] == '@' || authenticated) {
        return by; /* non-web origin ("@snmp", "@console"), or an SNMPv3 (authenticated, encrypted) reader */
    }
    return SNMP_PRINCIPAL_WEB;
}

bool snmp_last_write_supersedes(bool have, uint32_t stored_cmd, uint32_t pending_cmd) {
    /* Command ids are global, > 0 and increasing since boot (mex150 service.h); compare in serial
     * arithmetic so a wrap after 2^32 writes cannot freeze the record. */
    return have && stored_cmd != 0 && pending_cmd != 0 && (int32_t)(stored_cmd - pending_cmd) >= 0;
}
