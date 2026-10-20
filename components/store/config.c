/*
 * config.c - pure part of the configuration model: defaults, validation, section metadata,
 * trap-community remap and the SNMP secrets check (host-tested; no IDF headers).
 * The RAM store (mutex, load, commit, persist) is config_store.c.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "gw_core/gw_ident.h"
#include "gw_core/gw_ip4.h"
#include "mex150/regmap.h"
#include "store/config.h"
#include "store_priv.h"

/* ------------------------------------------------------------------ helpers */

static const cfg_alarm_catalog_t *s_catalog;

void cfg_set_alarm_catalog(const cfg_alarm_catalog_t *cat) {
    s_catalog = cat;
}

const cfg_alarm_catalog_t *cfg_alarm_catalog(void) {
    return s_catalog;
}

void store_strset(char *dst, size_t cap, const char *src) {
    if (!cap)
        return;
    memset(dst, 0, cap);
    gw_strlcpy(dst, src ? src : "", cap);
}

static size_t bounded_len(const char *s, size_t cap, bool *terminated) {
    size_t n = 0;
    while (n < cap && s[n])
        n++;
    *terminated = n < cap;
    return n;
}

bool store_text_ok(const char *s, size_t cap, size_t max_bytes) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n > max_bytes)
        return false;
    const unsigned char *p = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c < 0x20 || c == 0x7F)
            return false;
        if (c < 0x80) {
            i++;
            continue;
        }
        size_t l;
        if (c >= 0xC2 && c <= 0xDF)
            l = 2;
        else if (c >= 0xE0 && c <= 0xEF)
            l = 3;
        else if (c >= 0xF0 && c <= 0xF4)
            l = 4;
        else
            return false;
        if (i + l > n)
            return false;
        for (size_t k = 1; k < l; k++)
            if ((p[i + k] & 0xC0) != 0x80)
                return false;
        if (c == 0xE0 && p[i + 1] < 0xA0)
            return false;
        if (c == 0xED && p[i + 1] >= 0xA0)
            return false;
        if (c == 0xF0 && p[i + 1] < 0x90)
            return false;
        if (c == 0xF4 && p[i + 1] >= 0x90)
            return false;
        /* C1 control characters U+0080..U+009F are encoded C2 80..C2 9F */
        if (c == 0xC2 && p[i + 1] < 0xA0)
            return false;
        i += l;
    }
    return true;
}

bool store_ascii_ok(const char *s, size_t cap, size_t min_len, size_t max_len, char lo, char hi) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n < min_len || n > max_len)
        return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < lo || s[i] > hi)
            return false;
    return true;
}

static bool is_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

/* DNS name or IPv4 literal: ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$, 1..GW_HOST_MAX. */
static bool host_ok(const char *s, size_t cap) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n == 0 || n > GW_HOST_MAX)
        return false;
    if (!is_alnum(s[0]) || !is_alnum(s[n - 1]))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!is_alnum(s[i]) && s[i] != '.' && s[i] != '-')
            return false;
    return true;
}

/* RFC 1123 label: ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$, 1..GW_HOSTNAME_MAX. */
static bool label_ok(const char *s, size_t cap) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n == 0 || n > GW_HOSTNAME_MAX)
        return false;
    if (!is_alnum(s[0]) || !is_alnum(s[n - 1]))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!is_alnum(s[i]) && s[i] != '-')
            return false;
    return true;
}

/* POSIX TZ: ^[A-Za-z<>+\-0-9,.:/]+$, 1..GW_TZ_SZ-1. */
static bool tz_ok(const char *s, size_t cap) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n == 0 || n > GW_TZ_SZ - 1)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!is_alnum(c) && !strchr("<>+-,.:/", c))
            return false;
    }
    return true;
}

/* SNMPv3 user name: ^[A-Za-z0-9_.-]+$, 1..GW_SNMP_USER_MAX. */
static bool snmp_user_ok(const char *s, size_t cap) {
    bool term;
    size_t n = bounded_len(s, cap, &term);
    if (!term || n == 0 || n > GW_SNMP_USER_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!is_alnum(s[i]) && !strchr("_.-", s[i]))
            return false;
    return true;
}

/* ------------------------------------------------------------------ section metadata */

static const char *const s_section_names[CFG_SEC_COUNT] = {
    [CFG_SEC_GENERAL] = "general", [CFG_SEC_NETWORK] = "network",   [CFG_SEC_MODBUS] = "modbus",
    [CFG_SEC_ALARMS] = "alarms",   [CFG_SEC_SNMP] = "snmp",         [CFG_SEC_TIME] = "time",
    [CFG_SEC_SECURITY] = "security", [CFG_SEC_NOTIFY] = "notify",
};

const char *cfg_section_name(cfg_section_t s) {
    if (s == CFG_SEC_SECRETS)
        return "secrets";
    if ((unsigned)s >= CFG_SEC_COUNT)
        return NULL;
    return s_section_names[s];
}

bool cfg_section_from_name(const char *name, cfg_section_t *out) {
    if (!name)
        return false;
    for (unsigned i = 0; i < CFG_SEC_COUNT; i++) {
        if (!strcmp(name, s_section_names[i])) {
            if (out)
                *out = (cfg_section_t)i;
            return true;
        }
    }
    if (!strcmp(name, "secrets")) {
        if (out)
            *out = CFG_SEC_SECRETS;
        return true;
    }
    return false;
}

size_t cfg_section_size(cfg_section_t s) {
    switch (s) {
    case CFG_SEC_GENERAL:
        return sizeof(cfg_general_t);
    case CFG_SEC_NETWORK:
        return sizeof(cfg_network_t);
    case CFG_SEC_MODBUS:
        return sizeof(cfg_modbus_t);
    case CFG_SEC_ALARMS:
        return sizeof(cfg_alarms_t);
    case CFG_SEC_SNMP:
        return sizeof(cfg_snmp_t);
    case CFG_SEC_TIME:
        return sizeof(cfg_time_t);
    case CFG_SEC_SECURITY:
        return sizeof(cfg_security_t);
    case CFG_SEC_NOTIFY:
        return sizeof(cfg_notify_t);
    default:
        return 0;
    }
}

const void *cfg_section_cptr(const gw_config_t *c, cfg_section_t s) {
    if (!c)
        return NULL;
    switch (s) {
    case CFG_SEC_GENERAL:
        return &c->general;
    case CFG_SEC_NETWORK:
        return &c->network;
    case CFG_SEC_MODBUS:
        return &c->modbus;
    case CFG_SEC_ALARMS:
        return &c->alarms;
    case CFG_SEC_SNMP:
        return &c->snmp;
    case CFG_SEC_TIME:
        return &c->time;
    case CFG_SEC_SECURITY:
        return &c->security;
    case CFG_SEC_NOTIFY:
        return &c->notify;
    default:
        return NULL;
    }
}

void *cfg_section_ptr(gw_config_t *c, cfg_section_t s) {
    return (void *)cfg_section_cptr(c, s);
}

/* ------------------------------------------------------------------ defaults */

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static void def_general(cfg_general_t *g) {
    memset(g, 0, sizeof(*g));
    store_strset(g->lang, sizeof(g->lang), "ko");
}

static void def_network(cfg_network_t *n, const uint8_t mac[GW_MAC_LEN]) {
    static const uint8_t zero_mac[GW_MAC_LEN] = {0};
    if (!mac)
        mac = zero_mac;
    memset(n, 0, sizeof(*n));
    n->eth.mode = CFG_ETH_STATIC;
    n->eth.ip = IP4(192, 168, 10, 150);
    n->eth.mask = IP4(255, 255, 255, 0);
    n->eth.gw = IP4(192, 168, 10, 1);
    n->eth.dns1 = IP4(192, 168, 10, 1);
    n->eth.dns2 = 0;
    char tmp[GW_SSID_SZ > GW_HOSTNAME_SZ ? GW_SSID_SZ : GW_HOSTNAME_SZ];
    gw_ident_hostname(mac, tmp);
    store_strset(n->hostname, sizeof(n->hostname), tmp);
    n->ap.fallback = true;
    gw_ident_ssid(mac, tmp);
    store_strset(n->ap.ssid, sizeof(n->ap.ssid), tmp);
    n->ap.channel = 6;
    n->ap.idle_min = 15;
    n->ap.fallback_after_s = 120;
}

static void def_modbus(cfg_modbus_t *m) {
    memset(m, 0, sizeof(*m));
    m->port.baud = 9600;
    m->port.parity = 'N';
    m->port.stop = 1;
    m->port.poll_ms = 1000;
    m->port.timeout_ms = 300;
    m->port.gap_ms = 5;
    m->port.retries = 1;
    m->port.offline_after = 3;
    m->devices[0].id = 0;
    m->devices[0].slave = 1;
    m->devices[0].enabled = true;
    store_strset(m->devices[0].name, sizeof(m->devices[0].name), "MEX150");
    store_strset(m->devices[0].template_id, sizeof(m->devices[0].template_id), GW_DEFAULT_TEMPLATE_ID);
    m->devices[0].display_mask = GW_CHANNEL_DISPLAY_DEFAULT;
    m->n_devices = 1;
}

static void def_alarms(cfg_alarms_t *a) {
    memset(a, 0, sizeof(*a));
    a->debounce_raise = 2;
    a->debounce_clear = 3;
}

static void def_snmp(cfg_snmp_t *s) {
    memset(s, 0, sizeof(*s));
    s->enabled = false;
    s->v1 = false;
    s->v2c = false;
    s->v3 = true;
    store_strset(s->users[0].name, sizeof(s->users[0].name), "gwmonitor");
    s->users[0].access = CFG_SNMP_RO;
    s->users[0].enabled = true;
    store_strset(s->users[1].name, sizeof(s->users[1].name), "gwadmin");
    s->users[1].access = CFG_SNMP_RW;
    s->users[1].enabled = true;
    s->n_traps = 0;
    s->auth_traps = false;
}

static void def_time(cfg_time_t *t) {
    memset(t, 0, sizeof(*t));
    t->ntp_enabled = false;
    store_strset(t->servers[0], sizeof(t->servers[0]), "pool.ntp.org");
    store_strset(t->servers[1], sizeof(t->servers[1]), "time.google.com");
    t->interval_min = 60;
    store_strset(t->tz, sizeof(t->tz), "KST-9");
}

static void def_security(cfg_security_t *s) {
    memset(s, 0, sizeof(*s));
    s->idle_min = 15;
    s->max_fail = 5;
    s->lock_min = 5;
    s->n_ip_allow = 0;
    s->svc_snmp = true;
    s->svc_syslog = true;
}

static void def_notify(cfg_notify_t *n) {
    memset(n, 0, sizeof(*n));
    n->syslog_enabled = false;
    n->port = 514;
    n->facility = 16;
    n->min_sev = 5;
}

void cfg_section_defaults(cfg_section_t s, void *sec, const uint8_t mac[GW_MAC_LEN]) {
    if (!sec)
        return;
    switch (s) {
    case CFG_SEC_GENERAL:
        def_general(sec);
        break;
    case CFG_SEC_NETWORK:
        def_network(sec, mac);
        break;
    case CFG_SEC_MODBUS:
        def_modbus(sec);
        break;
    case CFG_SEC_ALARMS:
        def_alarms(sec);
        break;
    case CFG_SEC_SNMP:
        def_snmp(sec);
        break;
    case CFG_SEC_TIME:
        def_time(sec);
        break;
    case CFG_SEC_SECURITY:
        def_security(sec);
        break;
    case CFG_SEC_NOTIFY:
        def_notify(sec);
        break;
    default:
        break;
    }
}

void cfg_defaults(gw_config_t *c, const uint8_t mac[GW_MAC_LEN]) {
    memset(c, 0, sizeof(*c));
    c->schema = CFG_SCHEMA_VERSION;
    c->rev = 0;
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++)
        cfg_section_defaults((cfg_section_t)s, cfg_section_ptr(c, (cfg_section_t)s), mac);
}

/* ------------------------------------------------------------------ validation */

typedef struct {
    const cfg_general_t *general;
    const cfg_network_t *network;
    const cfg_modbus_t *modbus;
    const cfg_alarms_t *alarms;
    const cfg_snmp_t *snmp;
    const cfg_time_t *time;
    const cfg_security_t *security;
    const cfg_notify_t *notify;
} cfg_view_t;

__attribute__((format(printf, 3, 4))) static bool fail(cfg_verr_t *err, const char *code, const char *fmt, ...) {
    if (err) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->field, sizeof(err->field), fmt, ap);
        va_end(ap);
        gw_strlcpy(err->code, code, sizeof(err->code));
    }
    return false;
}

static bool v_general(const cfg_general_t *g, cfg_verr_t *err) {
    if (!store_text_ok(g->site, sizeof(g->site), GW_TEXT_MAX))
        return fail(err, "format", "general.site");
    if (!store_text_ok(g->location, sizeof(g->location), GW_TEXT_MAX))
        return fail(err, "format", "general.location");
    if (!store_text_ok(g->contact, sizeof(g->contact), GW_TEXT_MAX))
        return fail(err, "format", "general.contact");
    if (strcmp(g->lang, "ko") != 0 && strcmp(g->lang, "en") != 0)
        return fail(err, "range", "general.lang");
    return true;
}

/* Optional unicast address (DNS server / gateway): 0 = none. */
static bool unicast_ok(uint32_t ip) {
    return gw_ip4_host_valid(ip, 0xFFFFFFFFu);
}

static bool v_network(const cfg_network_t *n, cfg_verr_t *err) {
    const cfg_eth_t *e = &n->eth;
    if (e->mode != CFG_ETH_STATIC && e->mode != CFG_ETH_DHCP)
        return fail(err, "range", "network.eth.mode");
    if (e->mode == CFG_ETH_STATIC) {
        int prefix = gw_ip4_prefix_len(e->mask);
        if (prefix < 8 || prefix > 30)
            return fail(err, "range", "network.eth.mask");
        if (!gw_ip4_host_valid(e->ip, e->mask))
            return fail(err, "range", "network.eth.ip");
        if (gw_ip4_nets_overlap(e->ip & e->mask, e->mask, CFG_AP_IP & CFG_AP_MASK, CFG_AP_MASK))
            return fail(err, "overlap", "network.eth.ip");
        if (e->gw != 0) {
            if (!gw_ip4_host_valid(e->gw, e->mask) || !gw_ip4_in_net(e->gw, e->ip, e->mask) || e->gw == e->ip)
                return fail(err, "range", "network.eth.gw");
        }
    }
    if (e->dns1 != 0 && !unicast_ok(e->dns1))
        return fail(err, "range", "network.eth.dns1");
    if (e->dns2 != 0 && !unicast_ok(e->dns2))
        return fail(err, "range", "network.eth.dns2");
    if (!label_ok(n->hostname, sizeof(n->hostname)))
        return fail(err, "format", "network.hostname");
    const cfg_ap_t *ap = &n->ap;
    if (!store_text_ok(ap->ssid, sizeof(ap->ssid), GW_SSID_MAX) || ap->ssid[0] == '\0')
        return fail(err, "format", "network.ap.ssid");
    if (ap->channel < 1 || ap->channel > 13)
        return fail(err, "range", "network.ap.channel");
    if (ap->idle_min < 1 || ap->idle_min > 120)
        return fail(err, "range", "network.ap.idle_min");
    if (ap->fallback_after_s < 30 || ap->fallback_after_s > 3600)
        return fail(err, "range", "network.ap.fallback_after_s");
    return true;
}

static bool baud_ok(uint32_t b) {
    static const uint32_t ok[] = {1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200};
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (ok[i] == b)
            return true;
    return false;
}

static bool v_modbus(const cfg_modbus_t *m, cfg_verr_t *err) {
    const mex_port_cfg_t *p = &m->port;
    if (!baud_ok(p->baud))
        return fail(err, "range", "modbus.port.baud");
    if (p->parity != 'N' && p->parity != 'E' && p->parity != 'O')
        return fail(err, "range", "modbus.port.parity");
    if (p->stop != 1 && p->stop != 2)
        return fail(err, "range", "modbus.port.stop");
    if (p->poll_ms < 200 || p->poll_ms > 60000)
        return fail(err, "range", "modbus.poll_ms");
    if (p->timeout_ms < 50 || p->timeout_ms > 2000)
        return fail(err, "range", "modbus.timeout_ms");
    if (p->retries > 3)
        return fail(err, "range", "modbus.retries");
    if (p->gap_ms > 100)
        return fail(err, "range", "modbus.gap_ms");
    if (p->offline_after < 1 || p->offline_after > 10)
        return fail(err, "range", "modbus.offline_after");
    if (m->n_devices < 1)
        return fail(err, "required", "modbus.devices");
    if (m->n_devices > GW_MAX_DEVICES)
        return fail(err, "too_many", "modbus.devices");
    for (unsigned i = 0; i < m->n_devices; i++) {
        const mex_dev_cfg_t *d = &m->devices[i];
        if (d->id >= GW_MAX_DEVICES)
            return fail(err, "range", "modbus.devices[%u].id", i);
        if (d->slave < 1 || d->slave > 247)
            return fail(err, "range", "modbus.devices[%u].slave", i);
        if (!memchr(d->template_id, 0, sizeof(d->template_id)) ||
            (d->template_id[0] && !gw_device_template_find(d->template_id)))
            return fail(err, "range", "modbus.devices[%u].template_id", i);
        if (!store_text_ok(d->name, sizeof(d->name), GW_DEV_NAME_SZ - 1))
            return fail(err, "format", "modbus.devices[%u].name", i);
        for (unsigned j = 0; j < i; j++) {
            if (m->devices[j].id == d->id)
                return fail(err, "duplicate", "modbus.devices[%u].id", i);
            if (d->enabled && m->devices[j].enabled && m->devices[j].slave == d->slave)
                return fail(err, "duplicate", "modbus.devices[%u].slave", i);
        }
    }
    return true;
}

static bool dev_configured(const cfg_modbus_t *m, uint8_t dev) {
    for (unsigned i = 0; i < m->n_devices && i < GW_MAX_DEVICES; i++)
        if (m->devices[i].id == dev)
            return true;
    return false;
}

uint16_t cfg_rule_scale(uint16_t addr) {
    const mex_reg_t *r = mex_reg_find(addr);
    return (r && r->scale) ? r->scale : 1;
}

static bool v_rule(const cfg_rule_t *r, unsigned i, const cfg_modbus_t *m, cfg_verr_t *err) {
    if (r->id < 1 || r->id > GW_MAX_RULES)
        return fail(err, "range", "alarms.rules[%u].id", i);
    if (!store_text_ok(r->name, sizeof(r->name), GW_RULE_NAME_SZ - 1))
        return fail(err, "format", "alarms.rules[%u].name", i);
    if (r->dev >= GW_MAX_DEVICES || !dev_configured(m, r->dev))
        return fail(err, "range", "alarms.rules[%u].dev", i);
    const mex_reg_t *reg = mex_reg_find(r->addr);
    if (!reg)
        return fail(err, "unknown_register", "alarms.rules[%u].src", i);
    if (r->op != CFG_OP_GT && r->op != CFG_OP_LT)
        return fail(err, "range", "alarms.rules[%u].op", i);
    if (r->thr < reg->min || r->thr > reg->max)
        return fail(err, "range", "alarms.rules[%u].thr", i);
    if (r->hyst < 0 || r->hyst > reg->max - reg->min)
        return fail(err, "range", "alarms.rules[%u].hyst", i);
    if (r->delay_s > 3600)
        return fail(err, "range", "alarms.rules[%u].delay_s", i);
    if (r->sev < 1 || r->sev > 3)
        return fail(err, "range", "alarms.rules[%u].sev", i);
    return true;
}

static bool v_alarms(const cfg_alarms_t *a, const cfg_modbus_t *m, cfg_verr_t *err) {
    if (a->debounce_raise < 1 || a->debounce_raise > 10)
        return fail(err, "range", "alarms.debounce_raise");
    if (a->debounce_clear < 1 || a->debounce_clear > 10)
        return fail(err, "range", "alarms.debounce_clear");
    if (a->n_sev_override > GW_MAX_SEV_OVERRIDES)
        return fail(err, "too_many", "alarms.sev_override");
    const cfg_alarm_catalog_t *cat = cfg_alarm_catalog();
    for (unsigned i = 0; i < a->n_sev_override; i++) {
        const cfg_sev_override_t *o = &a->sev_override[i];
        const char *id = (cat && cat->id_from_code) ? cat->id_from_code(o->code) : NULL;
        if (!id)
            return fail(err, "unknown_field", "alarms.sev_override.%u", (unsigned)o->code);
        if (o->sev > 3)
            return fail(err, "range", "alarms.sev_override.%s", id);
        for (unsigned j = 0; j < i; j++)
            if (a->sev_override[j].code == o->code)
                return fail(err, "duplicate", "alarms.sev_override.%s", id);
    }
    if (a->n_rules > GW_MAX_RULES)
        return fail(err, "too_many", "alarms.rules");
    for (unsigned i = 0; i < a->n_rules; i++) {
        if (!v_rule(&a->rules[i], i, m, err))
            return false;
        for (unsigned j = 0; j < i; j++)
            if (a->rules[j].id == a->rules[i].id)
                return fail(err, "duplicate", "alarms.rules[%u].id", i);
    }
    return true;
}

static bool v_snmp(const cfg_snmp_t *s, cfg_verr_t *err) {
    for (unsigned i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        const cfg_snmp_v3user_t *u = &s->users[i];
        if (!snmp_user_ok(u->name, sizeof(u->name)))
            return fail(err, "format", "snmp.v3.users[%u].name", i);
        if (u->access != CFG_SNMP_RO && u->access != CFG_SNMP_RW)
            return fail(err, "range", "snmp.v3.users[%u].access", i);
        for (unsigned j = 0; j < i; j++)
            if (!strcmp(s->users[j].name, u->name))
                return fail(err, "duplicate", "snmp.v3.users[%u].name", i);
    }
    if (s->n_traps > GW_MAX_TRAP_TARGETS)
        return fail(err, "too_many", "snmp.traps");
    for (unsigned i = 0; i < s->n_traps; i++) {
        const cfg_trap_t *t = &s->traps[i];
        uint32_t ip;
        bool term;
        (void)bounded_len(t->host, sizeof(t->host), &term);
        if (!term || !gw_ip4_parse(t->host, &ip) || !unicast_ok(ip))
            return fail(err, "format", "snmp.traps[%u].host", i);
        if (t->port == 0)
            return fail(err, "range", "snmp.traps[%u].port", i);
        if (t->version != CFG_SNMP_V1 && t->version != CFG_SNMP_V2C)
            return fail(err, "range", "snmp.traps[%u].version", i);
        if (t->inform && t->version != CFG_SNMP_V2C)
            return fail(err, "range", "snmp.traps[%u].inform", i);
        for (unsigned j = 0; j < i; j++)
            if (!strcmp(s->traps[j].host, t->host) && s->traps[j].port == t->port)
                return fail(err, "duplicate", "snmp.traps[%u].host", i);
    }
    if (!store_text_ok(s->sys_name, sizeof(s->sys_name), GW_TEXT_MAX))
        return fail(err, "format", "snmp.sys.name");
    if (!store_text_ok(s->sys_contact, sizeof(s->sys_contact), GW_TEXT_MAX))
        return fail(err, "format", "snmp.sys.contact");
    if (!store_text_ok(s->sys_location, sizeof(s->sys_location), GW_TEXT_MAX))
        return fail(err, "format", "snmp.sys.location");
    return true;
}

static bool v_time(const cfg_time_t *t, cfg_verr_t *err) {
    for (unsigned i = 0; i < GW_MAX_NTP_SERVERS; i++) {
        if (t->servers[i][0] == '\0')
            continue;
        if (!host_ok(t->servers[i], sizeof(t->servers[i])))
            return fail(err, "format", "time.ntp.servers[%u]", i);
    }
    if (t->ntp_enabled && t->servers[0][0] == '\0' && t->servers[1][0] == '\0')
        return fail(err, "required", "time.ntp.servers");
    if (t->interval_min < 15 || t->interval_min > 1440)
        return fail(err, "range", "time.ntp.interval_min");
    if (!tz_ok(t->tz, sizeof(t->tz)))
        return fail(err, "format", "time.tz");
    return true;
}

static bool v_security(const cfg_security_t *s, cfg_verr_t *err) {
    if (s->idle_min < 5 || s->idle_min > 120)
        return fail(err, "range", "security.idle_min");
    if (s->max_fail < 3 || s->max_fail > 10)
        return fail(err, "range", "security.lockout.max_fail");
    if (s->lock_min < 1 || s->lock_min > 30)
        return fail(err, "range", "security.lockout.lock_min");
    if (s->n_ip_allow > GW_MAX_IP_ALLOW)
        return fail(err, "too_many", "security.ip_allow");
    for (unsigned i = 0; i < s->n_ip_allow; i++) {
        const cfg_cidr_t *c = &s->ip_allow[i];
        if (!gw_ip4_mask_valid(c->mask) || (c->net & ~c->mask) != 0)
            return fail(err, "format", "security.ip_allow[%u]", i);
        for (unsigned j = 0; j < i; j++)
            if (s->ip_allow[j].net == c->net && s->ip_allow[j].mask == c->mask)
                return fail(err, "duplicate", "security.ip_allow[%u]", i);
    }
    return true;
}

static bool v_notify(const cfg_notify_t *n, cfg_verr_t *err) {
    if (n->host[0] != '\0' && !host_ok(n->host, sizeof(n->host)))
        return fail(err, "format", "notify.syslog.host");
    if (n->syslog_enabled && n->host[0] == '\0')
        return fail(err, "required", "notify.syslog.host");
    if (n->port == 0)
        return fail(err, "range", "notify.syslog.port");
    if (n->facility > 23)
        return fail(err, "range", "notify.syslog.facility");
    if (n->min_sev > 7)
        return fail(err, "range", "notify.syslog.min_sev");
    return true;
}

static bool validate_view(const cfg_view_t *v, cfg_verr_t *err) {
    if (err) {
        err->field[0] = '\0';
        err->code[0] = '\0';
    }
    return v_general(v->general, err) && v_network(v->network, err) && v_modbus(v->modbus, err) &&
           v_alarms(v->alarms, v->modbus, err) && v_snmp(v->snmp, err) && v_time(v->time, err) &&
           v_security(v->security, err) && v_notify(v->notify, err);
}

static void view_of(const gw_config_t *c, cfg_view_t *v) {
    v->general = &c->general;
    v->network = &c->network;
    v->modbus = &c->modbus;
    v->alarms = &c->alarms;
    v->snmp = &c->snmp;
    v->time = &c->time;
    v->security = &c->security;
    v->notify = &c->notify;
}

bool cfg_validate(const gw_config_t *c, cfg_verr_t *err) {
    if (!c)
        return fail(err, "required", "%s", "");
    cfg_view_t v;
    view_of(c, &v);
    return validate_view(&v, err);
}

bool cfg_validate_with(const gw_config_t *base, cfg_section_t s, const void *sec, cfg_verr_t *err) {
    if (!base || !sec || cfg_section_size(s) == 0)
        return fail(err, "required", "%s", cfg_section_name(s) ? cfg_section_name(s) : "");
    cfg_view_t v;
    view_of(base, &v);
    switch (s) {
    case CFG_SEC_GENERAL:
        v.general = sec;
        break;
    case CFG_SEC_NETWORK:
        v.network = sec;
        break;
    case CFG_SEC_MODBUS:
        v.modbus = sec;
        break;
    case CFG_SEC_ALARMS:
        v.alarms = sec;
        break;
    case CFG_SEC_SNMP:
        v.snmp = sec;
        break;
    case CFG_SEC_TIME:
        v.time = sec;
        break;
    case CFG_SEC_SECURITY:
        v.security = sec;
        break;
    case CFG_SEC_NOTIFY:
        v.notify = sec;
        break;
    default:
        return fail(err, "required", "%s", "");
    }
    return validate_view(&v, err);
}

/* ------------------------------------------------------------------ SNMP helpers */

void cfg_trap_remap(const cfg_snmp_t *old, const cfg_snmp_t *nw, int8_t from[GW_MAX_TRAP_TARGETS]) {
    bool used[GW_MAX_TRAP_TARGETS] = {false};
    unsigned n_old = old ? old->n_traps : 0;
    if (n_old > GW_MAX_TRAP_TARGETS)
        n_old = GW_MAX_TRAP_TARGETS;
    unsigned n_new = nw ? nw->n_traps : 0;
    if (n_new > GW_MAX_TRAP_TARGETS)
        n_new = GW_MAX_TRAP_TARGETS;
    for (unsigned i = 0; i < GW_MAX_TRAP_TARGETS; i++) {
        from[i] = -1;
        if (i >= n_new)
            continue;
        for (unsigned j = 0; j < n_old; j++) {
            if (!used[j] && old->traps[j].port == nw->traps[i].port &&
                strncmp(old->traps[j].host, nw->traps[i].host, GW_HOST_SZ) == 0) {
                used[j] = true;
                from[i] = (int8_t)j;
                break;
            }
        }
    }
}

bool cfg_snmp_check_secrets(const cfg_snmp_t *s, const cfg_secret_flags_t *after, cfg_verr_t *err) {
    if (!s || !after)
        return fail(err, "required", "snmp");
    if ((s->v1 || s->v2c) && !after->snmp_ro_set)
        return fail(err, "required", "snmp.ro");
    return true;
}
