/*
 * Syslog client: RFC 5424 over UDP (sysmgr.h; /config/notify, services.syslog master switch).
 *
 * No task of its own (ARCHITECTURE.md §2): messages are formatted in the caller (mostly the gw_evt
 * handlers below) and sent with a non-blocking sendto (dropped on EAGAIN). A token bucket
 * (SYSLOG_RATE/s, burst SYSLOG_BURST) protects the network; drops are reported once a minute.
 * A host name target is resolved without blocking: lwIP dns_gethostbyname() runs in the TCP/IP
 * thread (esp_netif_tcpip_exec) and answers through a callback; the supervisor calls
 * syslog_service() every second to (re)start resolution (after config changes, every 10 min).
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "alarm/alarm.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "lwip/dns.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mex150/service.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"
#include "sysmgr_pure.h"

static const char *TAG = "syslog";

#define SYSLOG_RATE 10  /* messages per second */
#define SYSLOG_BURST 30 /* bucket size */
#define SYSLOG_RESOLVE_EVERY_MS (10u * 60u * 1000u)
#define SYSLOG_RETRY_MS 30000u
#define SYSLOG_DROP_REPORT_MS 60000u
#define SYSLOG_MSG_SZ 224
#define SYSLOG_AUDIT_Q 8 /* AUDIT records from the evlog hook, drained by syslog_service() */

typedef struct {
    bool enabled;
    uint8_t facility, min_sev;
    uint16_t port;
    bool host_is_ip;
    char host[GW_HOST_SZ];
    char hostname[GW_HOSTNAME_SZ];
} sl_cfg_t;

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static sl_cfg_t s_cfg;        /* under s_mux */
static syslog_rl_t s_rl;      /* under s_mux */
static _Atomic uint32_t s_ip; /* resolved destination (host order), 0 = none */
static atomic_int s_sock = -1;
static atomic_bool s_inited;
static atomic_bool s_need_resolve;
static atomic_uint s_gen; /* config generation: stale DNS answers are ignored */
static uint64_t s_resolve_ms, s_drop_report_ms; /* supervisor task only */
static char s_resolve_host[GW_HOST_SZ];         /* handed to the TCP/IP thread */
static evlog_rec_t s_audit_q[SYSLOG_AUDIT_Q];   /* under s_mux */
static uint8_t s_audit_head, s_audit_n;         /* under s_mux */

static void audit_drain(void);

static uint32_t parse_ip(const char *s, bool *ok) {
    struct in_addr a;
    *ok = s[0] && inet_aton(s, &a) != 0;
    return *ok ? ntohl(a.s_addr) : 0;
}

static void reload_config(void) {
    static cfg_notify_t n;
    static cfg_security_t sec;
    static cfg_network_t net;
    sl_cfg_t c;
    memset(&c, 0, sizeof(c));
    if (cfg_get_section(CFG_SEC_NOTIFY, &n, sizeof(n)) != ESP_OK ||
        cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec)) != ESP_OK ||
        cfg_get_section(CFG_SEC_NETWORK, &net, sizeof(net)) != ESP_OK) {
        return;
    }
    c.enabled = n.syslog_enabled && sec.svc_syslog && n.host[0];
    c.facility = n.facility > 23 ? 16 : n.facility;
    c.min_sev = n.min_sev > 7 ? 7 : n.min_sev;
    c.port = n.port ? n.port : 514;
    gw_strlcpy(c.host, n.host, sizeof(c.host));
    gw_strlcpy(c.hostname, net.hostname, sizeof(c.hostname));
    bool is_ip = false;
    const uint32_t ip = parse_ip(c.host, &is_ip);
    c.host_is_ip = is_ip;

    taskENTER_CRITICAL(&s_mux);
    const bool host_changed = strcmp(c.host, s_cfg.host) != 0;
    s_cfg = c;
    taskEXIT_CRITICAL(&s_mux);
    atomic_fetch_add(&s_gen, 1);
    if (is_ip) {
        atomic_store(&s_ip, ip);
    } else if (host_changed) {
        atomic_store(&s_ip, 0);
    }
    atomic_store(&s_need_resolve, c.enabled && !is_ip);
    if (c.enabled) {
        ESP_LOGI(TAG, "syslog to %s:%u (facility %u, min severity %u)", c.host, c.port, c.facility, c.min_sev);
    } else {
        ESP_LOGI(TAG, "syslog off");
    }
}

/* ---- DNS (TCP/IP thread) ---- */

static void dns_found(const char *name, const ip_addr_t *addr, void *arg) {
    (void)name;
    if ((unsigned)(uintptr_t)arg != atomic_load(&s_gen)) {
        return; /* config changed meanwhile */
    }
    if (addr && IP_IS_V4(addr)) {
        atomic_store(&s_ip, lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(addr))));
    } else {
        ESP_LOGW(TAG, "cannot resolve syslog host");
    }
}

static esp_err_t resolve_in_tcpip(void *ctx) {
    ip_addr_t addr;
    const err_t e = dns_gethostbyname(s_resolve_host, &addr, dns_found, ctx);
    if (e == ERR_OK) {
        dns_found(s_resolve_host, &addr, ctx);
    } else if (e != ERR_INPROGRESS) {
        dns_found(s_resolve_host, NULL, ctx);
    }
    return ESP_OK;
}

void syslog_service(void) {
    if (!atomic_load(&s_inited)) {
        return;
    }
    const uint64_t now = gw_time_mono_ms();
    sl_cfg_t c;
    taskENTER_CRITICAL(&s_mux);
    c = s_cfg;
    taskEXIT_CRITICAL(&s_mux);
    if (c.enabled && !c.host_is_ip) {
        const bool due = atomic_load(&s_need_resolve) ||
                         now - s_resolve_ms >= (atomic_load(&s_ip) ? SYSLOG_RESOLVE_EVERY_MS : SYSLOG_RETRY_MS);
        if (due) {
            s_resolve_ms = now;
            atomic_store(&s_need_resolve, false);
            gw_strlcpy(s_resolve_host, c.host, sizeof(s_resolve_host));
            esp_netif_tcpip_exec(resolve_in_tcpip, (void *)(uintptr_t)atomic_load(&s_gen));
        }
    }
    audit_drain();
    if (now - s_drop_report_ms >= SYSLOG_DROP_REPORT_MS) {
        s_drop_report_ms = now;
        taskENTER_CRITICAL(&s_mux);
        const uint32_t dropped = syslog_rl_take_dropped(&s_rl);
        taskEXIT_CRITICAL(&s_mux);
        if (dropped) {
            sys_syslog(4, "SYSLOG", "%u messages dropped by the rate limit", (unsigned)dropped);
        }
    }
}

/* ---- sending ---- */

static void send_line(uint8_t severity, const char *msgid, const char *msg) {
    const int sock = atomic_load(&s_sock);
    const uint32_t ip = atomic_load(&s_ip);
    sl_cfg_t c;
    taskENTER_CRITICAL(&s_mux);
    c = s_cfg;
    const bool ok = c.enabled && severity <= c.min_sev && sock >= 0 && ip != 0 &&
                    syslog_rl_take(&s_rl, (uint32_t)gw_time_mono_ms(), SYSLOG_RATE, SYSLOG_BURST);
    taskEXIT_CRITICAL(&s_mux);
    if (!ok) {
        return;
    }
    char line[SYSLOG_MAX_LINE + 1];
    const size_t len = syslog_format(line, sizeof(line), c.facility, severity, gw_time_wall_ms(), c.hostname,
                                     SYSLOG_APP_NAME, msgid, msg);
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET;
    to.sin_port = htons(c.port);
    to.sin_addr.s_addr = htonl(ip);
    /* Non-blocking: a full send buffer drops the message (never stalls gw_evt). */
    (void)sendto(sock, line, len, MSG_DONTWAIT, (const struct sockaddr *)&to, sizeof(to));
}

void sys_syslog(uint8_t severity, const char *msgid, const char *fmt, ...) {
    if (!atomic_load(&s_inited) || !fmt) {
        return;
    }
    taskENTER_CRITICAL(&s_mux);
    const bool wanted = s_cfg.enabled && severity <= s_cfg.min_sev;
    taskEXIT_CRITICAL(&s_mux);
    if (!wanted) {
        return;
    }
    char msg[SYSLOG_MSG_SZ];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    send_line(severity, msgid, msg);
}

/* ---- AUDIT records without a gw_evt event (evlog hook -> queue -> supervisor) ---- */

/* Audit types forwarded from the event log. The others are covered by gw_evt handlers below
 * (config_change, reg_write, session login/logout, OTA, reboot, time) or are UI-only. */
static uint8_t audit_severity(uint8_t type) {
    switch (type) {
    case AUD_LOCKOUT:
    case AUD_FACTORY_RESET:
        return 4;
    case AUD_LOGIN_FAIL:
    case AUD_PASSWORD:
    case AUD_USER_ADD:
    case AUD_USER_MOD:
    case AUD_USER_DEL:
    case AUD_USER_TARGET:
    case AUD_CONFIG_IMPORT:
        return 5;
    default:
        return 0xFF; /* not forwarded */
    }
}

/* evlog hook: any task, possibly under the caller's module lock -> copy only (sysmgr never logs
 * from here; the send happens in syslog_service()). */
static void on_evlog_append(evlog_kind_t kind, const evlog_rec_t *r) {
    if (kind != EVLOG_AUDIT || !r) {
        return;
    }
    const uint8_t sev = audit_severity(r->type);
    taskENTER_CRITICAL(&s_mux);
    if (sev <= 7 && s_cfg.enabled && sev <= s_cfg.min_sev) {
        if (s_audit_n < SYSLOG_AUDIT_Q) {
            s_audit_q[(s_audit_head + s_audit_n) % SYSLOG_AUDIT_Q] = *r;
            s_audit_n++;
        } else {
            s_rl.dropped++; /* reported with the rate-limit drops */
        }
    }
    taskEXIT_CRITICAL(&s_mux);
}

static void ip_str(uint32_t ip, char out[GW_IP4_STR_SZ]);

/* Account changes arrive as a pair: the action record (user=actor) and the AUD_USER_TARGET record
 * (user=target, extra=action seq) appended right after it. The action is held here (supervisor
 * task only) until its target arrives so syslog gets one line "user_del target=bob by=admin"; if
 * the target record does not follow (queue overflow), the action is sent alone with target=? on
 * the next drain. */
static evlog_rec_t s_acct_pending;
static bool s_acct_have;
static bool s_acct_aged;

static bool is_account_action(const evlog_rec_t *r) {
    return r->type == AUD_USER_ADD || r->type == AUD_USER_MOD || r->type == AUD_USER_DEL ||
           (r->type == AUD_PASSWORD && r->extra != 0);
}

static void rec_user(const evlog_rec_t *r, char out[sizeof(r->user) + 1]) {
    memcpy(out, r->user, sizeof(r->user));
    out[sizeof(r->user)] = '\0';
    if (!out[0]) {
        out[0] = '-';
        out[1] = '\0';
    }
}

/* One line for an account action; target may be NULL (unknown). */
static void account_send(const evlog_rec_t *act, const char *target) {
    char by[sizeof(act->user) + 1];
    rec_user(act, by);
    const char *t = target ? target : "?";
    const uint8_t sev = audit_severity(act->type);
    switch (act->type) {
    case AUD_PASSWORD:
        sys_syslog(sev, "AUDIT", "password target=%s by=%s (admin reset)", t, by);
        break;
    case AUD_USER_ADD:
    case AUD_USER_MOD:
        sys_syslog(sev, "AUDIT", "%s target=%s by=%s role=%d", act->type == AUD_USER_ADD ? "user_add" : "user_mod",
                   t, by, act->value);
        break;
    default:
        sys_syslog(sev, "AUDIT", "user_del target=%s by=%s", t, by);
        break;
    }
}

static void acct_flush(void) {
    if (s_acct_have) {
        s_acct_have = false;
        account_send(&s_acct_pending, NULL);
    }
}

static void audit_send(const evlog_rec_t *r) {
    if (is_account_action(r)) {
        acct_flush();
        s_acct_pending = *r;
        s_acct_have = true;
        s_acct_aged = false;
        return;
    }
    if (r->type == AUD_USER_TARGET) {
        char target[sizeof(r->user) + 1];
        rec_user(r, target);
        if (s_acct_have && s_acct_pending.seq == r->extra) {
            s_acct_have = false;
            account_send(&s_acct_pending, target);
        } else {
            sys_syslog(audit_severity(r->type), "AUDIT", "user_target target=%s ref=%u", target,
                       (unsigned)r->extra);
        }
        return;
    }
    char user[sizeof(r->user) + 1];
    memcpy(user, r->user, sizeof(r->user));
    user[sizeof(r->user)] = '\0';
    const char *u = user[0] ? user : "-";
    char ip[GW_IP4_STR_SZ];
    ip_str(r->extra, ip);
    const uint8_t sev = audit_severity(r->type);
    switch (r->type) {
    case AUD_LOGIN_FAIL:
        sys_syslog(sev, "AUDIT", "login_fail user=%s ip=%s", u, ip);
        break;
    case AUD_LOCKOUT:
        sys_syslog(sev, "AUDIT", "lockout ip=%s minutes=%d", ip, r->value);
        break;
    case AUD_PASSWORD: /* own change (admin resets are account actions above) */
        sys_syslog(sev, "AUDIT", "password target=%s by=%s", u, u);
        break;
    case AUD_CONFIG_IMPORT:
        sys_syslog(sev, "AUDIT", "config_import by=%s rev=%u", u, (unsigned)r->extra);
        break;
    case AUD_FACTORY_RESET:
        sys_syslog(sev, "AUDIT", "factory_reset by=%s keep_network=%d", u, r->value);
        break;
    default:
        break;
    }
}

/* supervisor task (syslog_service) */
static void audit_drain(void) {
    for (;;) {
        evlog_rec_t r = {0};
        taskENTER_CRITICAL(&s_mux);
        const bool have = s_audit_n > 0;
        if (have) {
            r = s_audit_q[s_audit_head];
            s_audit_head = (uint8_t)((s_audit_head + 1) % SYSLOG_AUDIT_Q);
            s_audit_n--;
        }
        taskEXIT_CRITICAL(&s_mux);
        if (!have) {
            /* An action still waiting since the previous drain lost its target record. */
            if (s_acct_have && s_acct_aged) {
                acct_flush();
            }
            s_acct_aged = s_acct_have;
            return;
        }
        audit_send(&r);
    }
}

/* ---- gw_evt handlers ---- */

static const char *alarm_type_name(uint8_t t) {
    return t == GW_ALARM_RAISE ? "raise" : t == GW_ALARM_CLEAR ? "clear" : t == GW_ALARM_ACK ? "ack" : "?";
}

static const char *ota_phase_name(uint8_t p) {
    static const char *const N[] = {"begin", "done", "failed", "rollback", "pending_verify", "validated"};
    return p < sizeof(N) / sizeof(N[0]) ? N[p] : "?";
}

static const char *reboot_reason_name(uint8_t r) {
    static const char *const N[] = {"user", "ota", "rollback", "factory_reset", "config_import", "console", "health"};
    return r < sizeof(N) / sizeof(N[0]) ? N[r] : "?";
}

static const char *time_src_name(uint8_t s) {
    static const char *const N[] = {"rtc", "ntp", "browser", "console"};
    return s < sizeof(N) / sizeof(N[0]) ? N[s] : "?";
}

static const char *wstate_name(uint8_t s) {
    return s == MEX_W_APPLIED ? "applied" : s == MEX_W_REJECTED ? "rejected" : s == MEX_W_UNCERTAIN ? "uncertain" : "?";
}

static void ip_str(uint32_t ip, char out[GW_IP4_STR_SZ]) {
    snprintf(out, GW_IP4_STR_SZ, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 0xFF),
             (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    if (!data) {
        return;
    }
    switch (id) {
    case GW_EVT_ALARM: {
        const gw_evt_alarm_t *e = data;
        const alm_desc_t *d = alm_find_code(e->code);
        sys_syslog(syslog_alarm_severity(e->type, e->sev), "ALARM", "dev=%u alarm=%s (%s) %s sev=%s value=%d seq=%u%s%s",
                   e->dev, d ? d->id : "?", d ? d->en : "?", alarm_type_name(e->type),
                   alm_sev_name((alm_sev_t)e->sev), e->value, (unsigned)e->seq, e->user[0] ? " by=" : "", e->user);
        break;
    }
    case GW_EVT_CONFIG_CHANGED: {
        const gw_evt_config_t *e = data;
        if (e->section == CFG_SEC_NOTIFY || e->section == CFG_SEC_SECURITY || e->section == CFG_SEC_NETWORK) {
            reload_config();
        }
        const char *name = cfg_section_name((cfg_section_t)e->section);
        sys_syslog(5, "AUDIT", "config_change section=%s rev=%u by=%s", name ? name : "?", (unsigned)e->rev,
                   e->by[0] ? e->by : "-");
        break;
    }
    case GW_EVT_WRITE_RESULT: {
        const gw_evt_write_t *e = data;
        sys_syslog(5, "AUDIT", "reg_write dev=%u addr=%u raw=%ld before=%ld after=%ld state=%s reason=%d cmd=%u by=%s",
                   e->dev, e->addr, (long)e->raw_req, (long)e->raw_before, (long)e->raw_after, wstate_name(e->state),
                   e->reason, (unsigned)e->cmd, e->by[0] ? e->by : "-");
        break;
    }
    case GW_EVT_SESSION: {
        const gw_evt_session_t *e = data;
        static const char *const K[] = {"login", "logout", "expired", "revoked"};
        sys_syslog(5, "AUDIT", "session %s user=%s", e->kind < 4 ? K[e->kind] : "?", e->user[0] ? e->user : "-");
        break;
    }
    case GW_EVT_OTA: {
        const gw_evt_ota_t *e = data;
        sys_syslog(e->phase == GW_OTA_FAILED ? 4 : 5, "FIRMWARE", "ota %s version=%s err=%ld by=%s",
                   ota_phase_name(e->phase), e->version[0] ? e->version : "-", (long)e->err, e->by[0] ? e->by : "-");
        break;
    }
    case GW_EVT_REBOOT: {
        const gw_evt_reboot_t *e = data;
        sys_syslog(4, "SYSTEM", "reboot reason=%s in_ms=%u", reboot_reason_name(e->reason), (unsigned)e->in_ms);
        break;
    }
    case GW_EVT_NET_STATE: {
        const gw_evt_net_t *e = data;
        char ip[GW_IP4_STR_SZ];
        ip_str(e->ip, ip);
        if (e->netif == GW_NETIF_ETH) {
            sys_syslog(e->link_up && e->has_ip ? 5 : 4, "NET", "eth link=%s ip=%s provisional=%u",
                       e->link_up ? "up" : "down", e->has_ip ? ip : "-", e->prov);
        } else {
            sys_syslog(5, "NET", "recovery_ap %s clients=%u", e->link_up ? "on" : "off", e->ap_clients);
        }
        break;
    }
    case GW_EVT_TIME_SYNC: {
        const gw_evt_time_t *e = data;
        sys_syslog(5, "TIME", "time set source=%s delta_ms=%lld%s%s", time_src_name(e->source), (long long)e->delta_ms,
                   e->by[0] ? " by=" : "", e->by);
        break;
    }
    default:
        break;
    }
}

esp_err_t syslog_init(void) {
    if (atomic_load(&s_inited)) {
        return ESP_ERR_INVALID_STATE;
    }
    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket: errno %d", errno);
        return ESP_FAIL;
    }
    const int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        ESP_LOGW(TAG, "O_NONBLOCK not set (errno %d); MSG_DONTWAIT still applies", errno);
    }
    atomic_store(&s_sock, sock);
    reload_config();
    atomic_store(&s_inited, true);
    evlog_set_hook(on_evlog_append);
    static const gw_event_id_t IDS[] = {GW_EVT_ALARM, GW_EVT_CONFIG_CHANGED, GW_EVT_WRITE_RESULT, GW_EVT_SESSION,
                                        GW_EVT_OTA,   GW_EVT_REBOOT,         GW_EVT_NET_STATE,    GW_EVT_TIME_SYNC};
    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) {
        const esp_err_t err = gw_events_register(IDS[i], on_event, NULL, NULL);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "event %d handler: %s", IDS[i], esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}
