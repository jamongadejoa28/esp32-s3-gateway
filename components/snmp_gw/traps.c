/* Notifications: v1/v2c traps and v2c informs to <= GW_MAX_TRAP_TARGETS targets (contract: snmp_gw.h).
 *
 * lwIP sends to its trap destination slot 0 only (SNMP_TRAP_DESTINATIONS=1), so every target is
 * addressed in turn: slot 0 <- target IP, transport trap port <- target port, trap community <-
 * the target's secret community, default trap version <- target version. Enterprise notifications
 * use eoid = mestioGwMIB (…PEN.1): v1 enterprise …PEN.1 + specific-trap N, v2c snmpTrapOID
 * …PEN.1.0.N (RFC 3584 §3.2 mapping, done by lwIP). Generic notifications (coldStart,
 * authenticationFailure) use eoid = snmp (1.3.6.1.2.1.11) and specific-trap = generic-trap: lwIP
 * builds the v2c snmpTrapOID as snmpTraps.(specific + 1) (snmp_prepare_trap_oid), and forces the v1
 * specific-trap to 0 for generic traps. The v2c sysUpTime.0 / snmpTrapOID.0 instance arcs come from
 * snmp_lwip's build-time fix of upstream snmp_traps.c (components/snmp_lwip/snmp_traps_fix.cmake).
 *
 * Rate limits: alarm/config/firmware notifications take one token per notification (fan-out to all
 * targets included), SNMP_GW_TRAP_RATE/s with a burst of SNMP_GW_TRAP_RATE. authenticationFailure has
 * its own small bucket (SGW_AUTH_TRAP_*), so a flood of bad requests cannot starve alarm traps, and it
 * is always sent as a plain trap (never tracked as an inform). COMM reports are already limited per
 * device by the pure coalescer (snmp_logic.h) and bypass the bucket, so the latest comm state is
 * always reported. Inform retransmissions, coldStart and test notifications are not limited.
 * Informs are tracked only while the inform table has a free slot; otherwise the notification is
 * sent as a plain trap instead of evicting an inform in flight. An inform whose first send fails
 * (no route yet, no memory) is still tracked and retransmitted on the normal schedule.
 *
 * Everything here runs in the agent task except the counters, the test-trap rendezvous
 * (sgw_traps_test, httpd worker) and sgw_traps_count_drop. */
#include <stdatomic.h>
#include <string.h>

#include "alarm/alarm.h"
#if __has_include("esp_attr.h")
#include "esp_attr.h"
#endif
#ifndef EXT_RAM_BSS_ATTR
#define EXT_RAM_BSS_ATTR /* host build */
#endif
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_ip4.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static const char *TAG = "snmp_trap";

/* Internal notification kinds kept in inform slots besides the queued message types. */
#define SGW_MSG_COLDSTART 100
#define SGW_MSG_AUTHFAIL 101
#define SGW_MSG_COMM_REPORT 102

#define MAX_VB 7

typedef struct {
    bool enabled;
    bool inform;
    uint8_t version; /* cfg_snmp_version_t */
    uint16_t port;
    uint32_t ip; /* host order */
    char host[GW_HOST_SZ];
    char community[GW_COMMUNITY_SZ];
} target_t;

typedef struct {
    bool generic;
    s32_t trap; /* generic-trap or specific-trap number */
    struct snmp_varbind *vbs;
} notif_t;

/* Agent task only. */
static target_t s_t[GW_MAX_TRAP_TARGETS];
static uint8_t s_nt;
static bool s_enabled;
static bool s_auth_traps;
static snmp_tbucket_t s_tb;      /* alarm / config / firmware notifications */
static snmp_tbucket_t s_tb_auth; /* authenticationFailure */
static snmp_comm_coalesce_t s_cc;
static EXT_RAM_BSS_ATTR snmp_inform_table_t s_inf; /* PSRAM: snmp_agent task only */
static struct snmp_obj_id s_eoid;
static EXT_RAM_BSS_ATTR struct snmp_varbind s_vb[MAX_VB];
static s32_t s_vb_int[MAX_VB];
static u8_t s_vb_date[11]; /* DateAndTime, gw_time_snmp_date() */
static char s_vb_text[2][GW_TEXT_SZ];
static cfg_alarms_t s_alarms_scratch;

/* coldStart delivery state (agent). */
_Static_assert(GW_MAX_TRAP_TARGETS <= 8, "coldStart target mask is 8 bits");
static struct {
    bool active;
    uint8_t done; /* bit per target index: delivered */
    uint64_t next_ms;
    uint64_t end_ms;
} s_cold;

/* Rate-limited warnings (agent). */
typedef struct {
    bool logged;
    uint64_t last_ms;
    uint32_t suppressed;
} log_limit_t;
static log_limit_t s_log_rate;
static log_limit_t s_log_auth;
static log_limit_t s_log_full;

/* SNMP group (1.3.6.1.2.1.11): enterprise of generic traps (RFC 1215, as lwIP's *_generic use). */
static const struct snmp_obj_id s_snmp_grp = {7, {1, 3, 6, 1, 2, 1, 11}};

/* Any task. */
static atomic_uint s_sent;
static atomic_uint s_dropped;
static atomic_uint s_inform_failed;

/* Test-trap rendezvous (snmp_gw_test_trap in the httpd worker <-> agent). */
static SemaphoreHandle_t s_test_mutex;
static StaticSemaphore_t s_test_mutex_buf;
static SemaphoreHandle_t s_test_done;
static StaticSemaphore_t s_test_done_buf;
static portMUX_TYPE s_test_mux = portMUX_INITIALIZER_UNLOCKED;
static struct {
    uint32_t gen; /* current test generation; 0 = none */
    bool open;    /* caller still waiting */
    uint8_t n;
    uint8_t pending; /* informs not yet acknowledged / given up */
    uint8_t target[GW_MAX_TRAP_TARGETS];
    snmp_gw_test_result_t res[GW_MAX_TRAP_TARGETS];
} s_test;
static uint32_t s_test_counter;

uint32_t sgw_traps_sent(void) {
    return atomic_load(&s_sent);
}

uint32_t sgw_traps_dropped(void) {
    return atomic_load(&s_dropped);
}

uint32_t sgw_informs_failed(void) {
    return atomic_load(&s_inform_failed);
}

void sgw_traps_count_drop(void) {
    atomic_fetch_add(&s_dropped, 1);
}

esp_err_t sgw_traps_sync_init(void) {
    s_test_mutex = xSemaphoreCreateMutexStatic(&s_test_mutex_buf);
    s_test_done = xSemaphoreCreateBinaryStatic(&s_test_done_buf);
    return (s_test_mutex != NULL && s_test_done != NULL) ? ESP_OK : ESP_ERR_NO_MEM;
}

/* True when a warning may be logged now; *suppressed receives the number held back since the last one. */
static bool log_allowed(log_limit_t *l, uint64_t now, uint32_t *suppressed) {
    if (l->logged && now - l->last_ms < SGW_LOG_INTERVAL_MS) {
        l->suppressed++;
        return false;
    }
    *suppressed = l->suppressed;
    l->logged = true;
    l->last_ms = now;
    l->suppressed = 0;
    return true;
}

void sgw_traps_init(void) {
    snmp_tb_init(&s_tb, SNMP_GW_TRAP_RATE, SNMP_GW_TRAP_RATE);
    snmp_tb_init(&s_tb_auth, SGW_AUTH_TRAP_RATE, SGW_AUTH_TRAP_BURST);
    memset(&s_cold, 0, sizeof(s_cold));
    snmp_cc_init(&s_cc);
    snmp_inf_init(&s_inf);
    size_t len = snmp_gw_oid(NULL, 0, s_eoid.id, SNMP_MAX_OBJ_ID_LEN); /* mestioGwMIB */
    s_eoid.len = (u8_t)len;
}

/* ---------------------------------------------------------------- test rendezvous helpers */

/* Result of the test inform/trap towards target ti (agent). */
static void test_result(uint32_t gen, uint8_t ti, bool ok, bool resolves_pending) {
    bool done = false;
    taskENTER_CRITICAL(&s_test_mux);
    if (s_test.open && gen != 0 && s_test.gen == gen) {
        for (uint8_t i = 0; i < s_test.n; i++) {
            if (s_test.target[i] == ti) {
                s_test.res[i].ok = ok;
            }
        }
        if (resolves_pending && s_test.pending > 0) {
            s_test.pending--;
            done = (s_test.pending == 0);
        }
    }
    taskEXIT_CRITICAL(&s_test_mux);
    if (done) {
        xSemaphoreGive(s_test_done);
    }
}

/* ---------------------------------------------------------------- varbinds */

static bool vb_oid(struct snmp_varbind *vb, const uint32_t *suffix, size_t n) {
    size_t len = snmp_gw_oid(suffix, n, vb->oid.id, SNMP_MAX_OBJ_ID_LEN);
    vb->oid.len = (u8_t)len;
    return len != 0;
}

static void vb_link(uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        s_vb[i].next = (i + 1 < count) ? &s_vb[i + 1] : NULL;
    }
}

static void vb_int(uint8_t i, u8_t type, s32_t v) {
    s_vb_int[i] = v;
    s_vb[i].type = type;
    s_vb[i].value = &s_vb_int[i];
    s_vb[i].value_len = sizeof(s32_t);
}

static void vb_text(uint8_t i, uint8_t slot, const char *text) {
    gw_strlcpy(s_vb_text[slot], text ? text : "", sizeof(s_vb_text[slot]));
    s_vb[i].type = SNMP_ASN1_TYPE_OCTET_STRING;
    s_vb[i].value = s_vb_text[slot];
    s_vb[i].value_len = (u16_t)strlen(s_vb_text[slot]);
}

static void vb_date(uint8_t i, int64_t wall_ms) {
    s_vb[i].type = SNMP_ASN1_TYPE_OCTET_STRING;
    s_vb[i].value = s_vb_date;
    s_vb[i].value_len = (u16_t)gw_time_snmp_date(wall_ms > 0 ? wall_ms : 0, s_vb_date);
}

static const char *alarm_name(uint16_t code) {
    const alm_desc_t *d = alm_find_code(code);
    if (d == NULL) {
        return "";
    }
    if (d->src == ALM_SRC_RULE && cfg_get_section(CFG_SEC_ALARMS, &s_alarms_scratch, sizeof(s_alarms_scratch)) == ESP_OK) {
        for (uint8_t i = 0; i < s_alarms_scratch.n_rules && i < GW_MAX_RULES; i++) {
            if (s_alarms_scratch.rules[i].id == d->addr && s_alarms_scratch.rules[i].name[0] != '\0') {
                return s_alarms_scratch.rules[i].name;
            }
        }
    }
    return d->en;
}

/* Build the notification for message m into the static varbind storage. */
static bool build(const sgw_msg_t *m, notif_t *n) {
    memset(n, 0, sizeof(*n));
    switch (m->type) {
    case SGW_MSG_COLDSTART:
        n->generic = true;
        n->trap = SNMP_GENTRAP_COLDSTART;
        return true;
    case SGW_MSG_AUTHFAIL:
        n->generic = true;
        n->trap = SNMP_GENTRAP_AUTH_FAILURE;
        return true;
    case SGW_MSG_ALARM: {
        const uint32_t base[] = {GWMIB_gwAlarms, GWMIB_gwAlarmNotifObjects};
        static const uint32_t leaf[MAX_VB] = {GWMIB_gwAlarmDevIndex, GWMIB_gwAlarmCode, GWMIB_gwAlarmName,
                                              GWMIB_gwAlarmSeverity, GWMIB_gwAlarmTime,  GWMIB_gwAlarmValue,
                                              GWMIB_gwAlarmSeq};
        for (uint8_t i = 0; i < MAX_VB; i++) {
            const uint32_t sfx[] = {base[0], base[1], leaf[i], 0};
            if (!vb_oid(&s_vb[i], sfx, 4)) {
                return false;
            }
        }
        vb_int(0, SNMP_ASN1_TYPE_INTEGER, (s32_t)GWMIB_DEV_INDEX(m->u.alarm.dev));
        vb_int(1, SNMP_ASN1_TYPE_INTEGER, m->u.alarm.code);
        vb_text(2, 0, alarm_name(m->u.alarm.code));
        vb_int(3, SNMP_ASN1_TYPE_INTEGER, GWMIB_SEVERITY(m->u.alarm.sev));
        vb_date(4, m->u.alarm.ts_ms);
        vb_int(5, SNMP_ASN1_TYPE_INTEGER, m->u.alarm.value);
        vb_int(6, SNMP_ASN1_TYPE_UNSIGNED32, (s32_t)m->u.alarm.seq);
        vb_link(7);
        n->trap = m->u.alarm.raised ? SNMP_GW_TRAP_ALARM_RAISED : SNMP_GW_TRAP_ALARM_CLEARED;
        n->vbs = s_vb;
        return true;
    }
    case SGW_MSG_COMM_REPORT: {
        const uint32_t idx = GWMIB_DEV_INDEX(m->u.comm.dev);
        const uint32_t name[] = {GWMIB_gwDevices, GWMIB_gwDevTable, GWMIB_gwDevEntry, GWMIB_gwDevName, idx};
        const uint32_t online[] = {GWMIB_gwDevices, GWMIB_gwDevTable, GWMIB_gwDevEntry, GWMIB_gwDevOnline, idx};
        const uint32_t ts[] = {GWMIB_gwAlarms, GWMIB_gwAlarmNotifObjects, GWMIB_gwAlarmTime, 0};
        if (!vb_oid(&s_vb[0], name, 5) || !vb_oid(&s_vb[1], online, 5) || !vb_oid(&s_vb[2], ts, 4)) {
            return false;
        }
        const sgw_dev_t *d = sgw_dev_by_index(idx);
        vb_text(0, 0, d ? d->name : "");
        vb_int(1, SNMP_ASN1_TYPE_INTEGER, GWMIB_TRUTH(m->u.comm.online));
        vb_date(2, gw_time_wall_ms());
        vb_link(3);
        n->trap = m->u.comm.online ? SNMP_GW_TRAP_COMM_RESTORED : SNMP_GW_TRAP_COMM_LOST;
        n->vbs = s_vb;
        return true;
    }
    case SGW_MSG_CONFIG: {
        const uint32_t sec[] = {GWMIB_gwInfo, GWMIB_gwLastConfigSection, 0};
        const uint32_t rev[] = {GWMIB_gwInfo, GWMIB_gwConfigRev, 0};
        if (!vb_oid(&s_vb[0], sec, 3) || !vb_oid(&s_vb[1], rev, 3)) {
            return false;
        }
        const char *name = cfg_section_name((cfg_section_t)m->u.config.section);
        vb_text(0, 0, name ? name : "");
        vb_int(1, SNMP_ASN1_TYPE_UNSIGNED32, (s32_t)m->u.config.rev);
        vb_link(2);
        n->trap = SNMP_GW_TRAP_CONFIG_CHANGED;
        n->vbs = s_vb;
        return true;
    }
    case SGW_MSG_FIRMWARE:
    case SGW_MSG_TEST: {
        const uint32_t fw[] = {GWMIB_gwInfo, GWMIB_gwFwVersion, 0};
        if (!vb_oid(&s_vb[0], fw, 3)) {
            return false;
        }
        vb_text(0, 1, m->type == SGW_MSG_FIRMWARE ? m->u.fw.version : sgw_fw_version());
        vb_link(1);
        n->trap = m->type == SGW_MSG_FIRMWARE ? SNMP_GW_TRAP_FIRMWARE_UPDATED : SNMP_GW_TRAP_TEST;
        n->vbs = s_vb;
        return true;
    }
    default:
        return false;
    }
}

/* ---------------------------------------------------------------- sending */

static bool can_inform(const target_t *t) {
    return t->inform && t->version == CFG_SNMP_V2C;
}

/* One datagram to target ti. ERR_OK if lwIP handed it to the transport; failures are logged unless
 * quiet. For an inform, *req_id is set even when sending fails (lwIP assigns it first). */
static err_t send_one(uint8_t ti, const notif_t *n, bool inform, s32_t *req_id, bool quiet) {
    const target_t *t = &s_t[ti];
    ip_addr_t dst;
    ip_addr_set_ip4_u32_val(dst, lwip_htonl(t->ip));
    snmp_trap_dst_ip_set(0, &dst);
    snmp_trap_dst_enable(0, 1);
    snmp_transport_set_trap_port(t->port);
    snmp_set_community_trap(t->community);
    snmp_set_default_trap_version(t->version == CFG_SNMP_V1 ? SGW_SNMP_V1 : SGW_SNMP_V2C);

    /* Not lwIP's snmp_send_*_generic(): they pass specific-trap 0, which lwIP maps to the v2c
     * snmpTrapOID coldStart for every generic trap (see file comment). */
    const struct snmp_obj_id *eoid = n->generic ? &s_snmp_grp : &s_eoid;
    const s32_t gen = n->generic ? n->trap : SNMP_GENTRAP_ENTERPRISE_SPECIFIC;
    err_t e = inform ? snmp_send_inform(eoid, gen, n->trap, n->vbs, req_id) : snmp_send_trap(eoid, gen, n->trap, n->vbs);
    snmp_trap_dst_enable(0, 0);
    snmp_transport_set_trap_port(0);
    if (e != ERR_OK) {
        if (!quiet) {
            ESP_LOGW(TAG, "%s %s%ld to %s:%u failed: %d", inform ? "inform" : "trap", n->generic ? "generic " : "",
                     (long)n->trap, t->host, (unsigned)t->port, e);
        }
        return e;
    }
    atomic_fetch_add(&s_sent, 1);
    return ERR_OK;
}

/* An inform slot ends without acknowledgement (given up or evicted). */
static void inform_failed(const snmp_inform_t *s) {
    atomic_fetch_add(&s_inform_failed, 1);
    ESP_LOGW(TAG, "inform to %s not acknowledged", s->target < GW_MAX_TRAP_TARGETS ? s_t[s->target].host : "?");
    if (s->test_gen != 0) {
        test_result(s->test_gen, s->target, false, true);
    }
}

static void track_inform(uint8_t ti, s32_t req_id, uint32_t test_gen, const sgw_msg_t *m) {
    bool evicted = false;
    snmp_inform_t old;
    (void)snmp_inf_add(&s_inf, ti, s_t[ti].ip, req_id, gw_time_mono_ms(), test_gen, m, sizeof(*m), &evicted, &old);
    if (evicted) {
        inform_failed(&old);
    }
}

/* Send m to target ti as an inform if the target wants informs and a slot is free (else as a trap).
 * The inform is tracked after a successful send, and after a failed one too when track_failed (it is
 * then retransmitted on the inform schedule; coldStart has its own retry loop instead). */
static err_t send_tracked(uint8_t ti, const notif_t *n, const sgw_msg_t *m, bool allow_inform, bool track_failed,
                          bool quiet) {
    bool inform = allow_inform && can_inform(&s_t[ti]);
    if (inform && snmp_inf_free_slots(&s_inf) == 0) {
        uint32_t held;
        if (log_allowed(&s_log_full, gw_time_mono_ms(), &held)) {
            ESP_LOGW(TAG, "inform table full (%d in flight): sending as trap (%lu more)", SNMP_INFORM_SLOTS,
                     (unsigned long)held);
        }
        inform = false;
    }
    s32_t rid = 0;
    err_t e = send_one(ti, n, inform, &rid, quiet);
    if (inform && (e == ERR_OK || track_failed)) {
        track_inform(ti, rid, 0, m);
    }
    return e;
}

/* Fan a notification out to every enabled target. tb: rate-limit bucket (NULL = not limited). */
static void notify(const sgw_msg_t *m, snmp_tbucket_t *tb, bool allow_inform) {
    if (!s_enabled || s_nt == 0) {
        return;
    }
    if (tb != NULL && !snmp_tb_take(tb, gw_time_mono_ms())) {
        uint32_t held;
        atomic_fetch_add(&s_dropped, 1);
        if (log_allowed(&s_log_rate, gw_time_mono_ms(), &held)) { /* do not flood the log during a storm */
            ESP_LOGW(TAG, "rate limit: notification type %u dropped (%lu dropped so far)", (unsigned)m->type,
                     (unsigned long)atomic_load(&s_dropped));
        }
        return;
    }
    notif_t n;
    if (!build(m, &n)) {
        ESP_LOGE(TAG, "cannot build notification type %u", (unsigned)m->type);
        return;
    }
    for (uint8_t ti = 0; ti < s_nt; ti++) {
        if (s_t[ti].enabled) {
            (void)send_tracked(ti, &n, m, allow_inform, true, false);
        }
    }
}

/* ---------------------------------------------------------------- configuration */

void sgw_traps_configure(const sgw_trap_cfg_t *cfg) {
    target_t nt[GW_MAX_TRAP_TARGETS];
    memset(nt, 0, sizeof(nt));
    uint8_t n = cfg->n <= GW_MAX_TRAP_TARGETS ? cfg->n : GW_MAX_TRAP_TARGETS;
    for (uint8_t i = 0; i < n; i++) {
        const cfg_trap_t *c = &cfg->traps[i];
        target_t *t = &nt[i];
        gw_strlcpy(t->host, c->host, sizeof(t->host));
        gw_strlcpy(t->community, cfg->community[i], sizeof(t->community));
        t->port = c->port ? c->port : 162;
        t->version = c->version;
        t->inform = c->inform;
        t->enabled = c->enabled && gw_ip4_parse(c->host, &t->ip) && t->ip != 0 && t->community[0] != '\0';
        if (c->enabled && !t->enabled) {
            ESP_LOGW(TAG, "trap target %u (%s) ignored: invalid address or empty community", (unsigned)i, c->host);
        }
    }
    /* Pending informs of a target whose identity or community changed are abandoned, and all of them
     * when SNMP is disabled (no datagram may leave a disabled agent). */
    for (uint8_t i = 0; i < GW_MAX_TRAP_TARGETS; i++) {
        const target_t *o = &s_t[i];
        const target_t *w = &nt[i];
        bool same = cfg->enabled && i < n && i < s_nt && o->enabled && w->enabled && o->ip == w->ip &&
                    o->port == w->port && o->version == w->version && can_inform(w) &&
                    strcmp(o->community, w->community) == 0;
        if (same) {
            continue;
        }
        for (int k = 0; k < SNMP_INFORM_SLOTS; k++) {
            if (s_inf.slot[k].used && s_inf.slot[k].target == i) {
                if (s_inf.slot[k].test_gen != 0) {
                    test_result(s_inf.slot[k].test_gen, i, false, true);
                }
                snmp_inf_free(&s_inf, k);
            }
        }
    }
    gw_secure_zero(s_t, sizeof(s_t));
    memcpy(s_t, nt, sizeof(nt));
    gw_secure_zero(nt, sizeof(nt));
    s_nt = n;
    s_enabled = cfg->enabled;
    s_auth_traps = cfg->auth_traps;
}

/* ---------------------------------------------------------------- agent entry points */

/* One coldStart round: every enabled target not yet reached. Called at start and from on_idle. At
 * agent start the link / DHCP is usually not up yet (lwIP answers ERR_RTE), so targets are retried
 * every SGW_COLD_RETRY_MS until each was reached or SGW_COLD_WINDOW_MS passed. */
static void cold_try(uint64_t now) {
    if (!s_cold.active || now < s_cold.next_ms) {
        return;
    }
    if (!s_enabled) {
        s_cold.active = false; /* a disabled agent never announces itself */
        return;
    }
    const sgw_msg_t m = {.type = SGW_MSG_COLDSTART};
    notif_t n;
    (void)build(&m, &n);
    uint8_t missing = 0;
    for (uint8_t ti = 0; ti < s_nt; ti++) {
        const uint8_t bit = (uint8_t)(1u << ti);
        if (!s_t[ti].enabled || (s_cold.done & bit) != 0) {
            continue;
        }
        if (send_tracked(ti, &n, &m, true, false, true) == ERR_OK) {
            s_cold.done |= bit;
        } else {
            missing++;
        }
    }
    if (missing == 0) {
        s_cold.active = false;
    } else if (now >= s_cold.end_ms) {
        s_cold.active = false;
        ESP_LOGW(TAG, "coldStart not delivered to %u target(s): no route within %u s", (unsigned)missing,
                 (unsigned)(SGW_COLD_WINDOW_MS / 1000u));
    } else {
        s_cold.next_ms = now + SGW_COLD_RETRY_MS;
    }
}

void sgw_traps_cold_start(void) {
    const uint64_t now = gw_time_mono_ms();
    s_cold.active = true;
    s_cold.done = 0;
    s_cold.next_ms = now;
    s_cold.end_ms = now + SGW_COLD_WINDOW_MS;
    cold_try(now);
}

void sgw_traps_auth_fail(uint32_t peer_ip) {
    uint32_t held;
    if (log_allowed(&s_log_auth, gw_time_mono_ms(), &held)) {
        char ip[GW_IP4_STR_SZ];
        gw_ip4_format(peer_ip, ip);
        ESP_LOGW(TAG, "SNMP authentication failure from %s (%lu more not logged)", ip, (unsigned long)held);
    }
    if (!s_auth_traps) {
        return;
    }
    const sgw_msg_t m = {.type = SGW_MSG_AUTHFAIL};
    notify(&m, &s_tb_auth, false); /* own bucket; plain trap: no inform slots, no retransmissions */
}

static void run_test(uint32_t gen) {
    taskENTER_CRITICAL(&s_test_mux);
    bool live = s_test.open && s_test.gen == gen;
    taskEXIT_CRITICAL(&s_test_mux);
    if (!live) {
        return; /* the caller gave up before the agent got to it */
    }
    sgw_msg_t m = {.type = SGW_MSG_TEST};
    notif_t n;
    uint8_t pending = 0;
    if (s_enabled && build(&m, &n)) {
        for (uint8_t ti = 0; ti < s_nt; ti++) {
            if (!s_t[ti].enabled) {
                continue;
            }
            const bool inform = can_inform(&s_t[ti]);
            s32_t rid = 0;
            bool sent = send_one(ti, &n, inform, &rid, false) == ERR_OK;
            taskENTER_CRITICAL(&s_test_mux);
            uint8_t k = s_test.n;
            if (k < GW_MAX_TRAP_TARGETS) {
                s_test.target[k] = ti;
                memcpy(s_test.res[k].host, s_t[ti].host, sizeof(s_test.res[k].host));
                s_test.res[k].ok = sent && !inform; /* an inform is ok once acknowledged */
                s_test.n = (uint8_t)(k + 1);
                if (sent && inform) {
                    s_test.pending++;
                }
            }
            taskEXIT_CRITICAL(&s_test_mux);
            if (sent && inform) {
                track_inform(ti, rid, gen, &m);
                pending++;
            }
        }
    }
    if (pending == 0) {
        xSemaphoreGive(s_test_done);
    }
}

void sgw_traps_on_msg(const sgw_msg_t *m) {
    switch (m->type) {
    case SGW_MSG_ALARM:
    case SGW_MSG_CONFIG:
    case SGW_MSG_FIRMWARE:
        notify(m, &s_tb, true);
        break;
    case SGW_MSG_COMM:
        snmp_cc_event(&s_cc, m->u.comm.dev, m->u.comm.online, gw_time_mono_ms());
        break;
    case SGW_MSG_TEST:
        run_test(m->u.test.gen);
        break;
    default:
        ESP_LOGW(TAG, "unknown agent message %u", (unsigned)m->type);
        break;
    }
}

void sgw_traps_on_idle(uint64_t now_ms) {
    cold_try(now_ms);

    snmp_comm_report_t rep[GW_MAX_DEVICES];
    size_t n = snmp_cc_poll(&s_cc, now_ms, rep, GW_MAX_DEVICES);
    for (size_t i = 0; i < n; i++) {
        sgw_msg_t m = {.type = SGW_MSG_COMM_REPORT};
        m.u.comm.dev = rep[i].dev;
        m.u.comm.online = rep[i].online;
        /* Not rate limited: the coalescer already committed this state as reported (<= 1 per device
         * per SNMP_COMM_MIN_INTERVAL_MS); dropping it here would lose the final state for good. */
        notify(&m, NULL, true);
    }

    for (int guard = 0; guard < SNMP_INFORM_SLOTS; guard++) {
        int k = snmp_inf_due(&s_inf, now_ms);
        if (k < 0) {
            break;
        }
        snmp_inform_t *s = &s_inf.slot[k];
        sgw_msg_t m;
        notif_t nf;
        memcpy(&m, s->msg, sizeof(m));
        if (s_enabled && snmp_inf_can_retry(&s_inf, k) && s->target < s_nt && s_t[s->target].enabled &&
            build(&m, &nf)) {
            s32_t rid = 0;
            if (send_one(s->target, &nf, true, &rid, false) == ERR_OK) {
                snmp_inf_resent(&s_inf, k, rid, now_ms);
                continue;
            }
            /* send failed (no route, no memory): count as a try and wait for the next timeout */
            snmp_inf_resent(&s_inf, k, s->req_id[0], now_ms);
            continue;
        }
        snmp_inform_t copy = *s;
        snmp_inf_free(&s_inf, k);
        inform_failed(&copy);
    }
}

bool sgw_traps_inform_peer(uint32_t peer_ip, char community[SNMP_COMMUNITY_SZ]) {
    int k = snmp_inf_peer(&s_inf, peer_ip);
    if (k < 0 || s_inf.slot[k].target >= s_nt) {
        return false;
    }
    gw_strlcpy(community, s_t[s_inf.slot[k].target].community, SNMP_COMMUNITY_SZ);
    return true;
}

void sgw_traps_inform_ack(int32_t request_id, uint32_t peer_ip) {
    int k = snmp_inf_match(&s_inf, request_id, peer_ip);
    if (k < 0) {
        return; /* late or unknown acknowledgement */
    }
    uint32_t gen = s_inf.slot[k].test_gen;
    uint8_t ti = s_inf.slot[k].target;
    snmp_inf_free(&s_inf, k);
    if (gen != 0) {
        test_result(gen, ti, true, true);
    }
}

/* ---------------------------------------------------------------- snmp_gw_test_trap [httpd worker] */

/* Milliseconds left until deadline (0 when passed). */
static uint32_t remaining_ms(uint64_t deadline) {
    const uint64_t now = gw_time_mono_ms();
    return now >= deadline ? 0u : (uint32_t)(deadline - now);
}

size_t sgw_traps_test(snmp_gw_test_result_t *out, size_t cap, uint32_t timeout_ms) {
    /* One deadline for all waits: the whole call blocks at most timeout_ms (snmp_gw.h). */
    const uint64_t deadline = gw_time_mono_ms() + timeout_ms;
    if (xSemaphoreTake(s_test_mutex, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return 0; /* another test is running */
    }
    (void)xSemaphoreTake(s_test_done, 0); /* drop a stale completion of an abandoned test */
    taskENTER_CRITICAL(&s_test_mux);
    uint32_t gen = ++s_test_counter;
    if (gen == 0) {
        gen = ++s_test_counter;
    }
    memset(&s_test, 0, sizeof(s_test));
    s_test.gen = gen;
    s_test.open = true;
    taskEXIT_CRITICAL(&s_test_mux);

    sgw_msg_t m = {.type = SGW_MSG_TEST};
    m.u.test.gen = gen;
    uint32_t left = remaining_ms(deadline);
    if (sgw_post(&m, left < SGW_TEST_POST_MS ? left : SGW_TEST_POST_MS) == ESP_OK) {
        (void)xSemaphoreTake(s_test_done, pdMS_TO_TICKS(remaining_ms(deadline)));
    } else {
        ESP_LOGW(TAG, "test notification: agent queue full");
    }

    size_t n = 0;
    taskENTER_CRITICAL(&s_test_mux);
    s_test.open = false;
    for (uint8_t i = 0; i < s_test.n && n < cap; i++) {
        out[n++] = s_test.res[i];
    }
    taskEXIT_CRITICAL(&s_test_mux);
    xSemaphoreGive(s_test_mutex);
    return n;
}
