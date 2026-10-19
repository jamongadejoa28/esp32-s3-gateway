/* t_config.c - store/config.c + config_json.c: defaults, validation, metadata, trap remap, JSON
 * parse/merge/secrets/migration (file and REST shapes). */
#include <malloc.h>
#include <stdlib.h>

#include "alarm/alarm.h"
#include "bt.h"
#include "cJSON.h"
#include "gw_core/gw_ip4.h"
#include "store/config.h"
#include "store/config_json.h"

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static const uint8_t MAC[GW_MAC_LEN] = {0x24, 0x6F, 0x28, 0x12, 0xAB, 0xCD};
static gw_config_t g_def, g_c, g_n;

static void test_defaults(void) {
    cfg_defaults(&g_def, MAC);
    cfg_verr_t e;
    CHECK(cfg_validate(&g_def, &e));
    CHECK_EQ(g_def.schema, CFG_SCHEMA_VERSION);
    CHECK_EQ(g_def.rev, 0);
    CHECK_STR(g_def.general.lang, "ko");
    CHECK_STR(g_def.general.site, "");
    CHECK_EQ(g_def.network.eth.mode, CFG_ETH_STATIC);
    CHECK_EQ(g_def.network.eth.ip, IP(192, 168, 10, 150));
    CHECK_EQ(g_def.network.eth.mask, IP(255, 255, 255, 0));
    CHECK_EQ(g_def.network.eth.gw, IP(192, 168, 10, 1));
    CHECK_EQ(g_def.network.eth.dns1, IP(192, 168, 10, 1));
    CHECK_EQ(g_def.network.eth.dns2, 0);
    CHECK_STR(g_def.network.hostname, "mestio-gw-abcd");
    CHECK_STR(g_def.network.ap.ssid, "MESTIO-GW-ABCD");
    CHECK(g_def.network.ap.fallback);
    CHECK_EQ(g_def.network.ap.channel, 6);
    CHECK_EQ(g_def.network.ap.idle_min, 15);
    CHECK_EQ(g_def.network.ap.fallback_after_s, 120);
    CHECK_EQ(g_def.modbus.n_devices, 1);
    CHECK_EQ(g_def.modbus.devices[0].id, 0);
    CHECK_EQ(g_def.modbus.devices[0].slave, 1);
    CHECK(g_def.modbus.devices[0].enabled);
    CHECK_STR(g_def.modbus.devices[0].name, "MEX150");
    CHECK_EQ(g_def.modbus.port.baud, 9600);
    CHECK_EQ(g_def.modbus.port.parity, 'N');
    CHECK_EQ(g_def.modbus.port.stop, 1);
    CHECK_EQ(g_def.modbus.port.poll_ms, 1000);
    CHECK_EQ(g_def.modbus.port.timeout_ms, 300);
    CHECK_EQ(g_def.modbus.port.retries, 1);
    CHECK_EQ(g_def.modbus.port.gap_ms, 5);
    CHECK_EQ(g_def.modbus.port.offline_after, 3);
    CHECK_EQ(g_def.alarms.debounce_raise, 2);
    CHECK_EQ(g_def.alarms.debounce_clear, 3);
    CHECK_EQ(g_def.alarms.n_rules, 0);
    CHECK_EQ(g_def.alarms.n_sev_override, 0);
    CHECK(!g_def.snmp.enabled);
    CHECK(!g_def.snmp.v1);
    CHECK(!g_def.snmp.v2c);
    CHECK(g_def.snmp.v3);
    CHECK_STR(g_def.snmp.users[0].name, "gwmonitor");
    CHECK_EQ(g_def.snmp.users[0].access, CFG_SNMP_RO);
    CHECK_STR(g_def.snmp.users[1].name, "gwadmin");
    CHECK_EQ(g_def.snmp.users[1].access, CFG_SNMP_RW);
    CHECK_EQ(g_def.snmp.n_traps, 0);
    CHECK(!g_def.snmp.auth_traps);
    CHECK(!g_def.time.ntp_enabled);
    CHECK_STR(g_def.time.servers[0], "pool.ntp.org");
    CHECK_STR(g_def.time.servers[1], "time.google.com");
    CHECK_EQ(g_def.time.interval_min, 60);
    CHECK_STR(g_def.time.tz, "KST-9");
    CHECK_EQ(g_def.security.idle_min, 15);
    CHECK_EQ(g_def.security.max_fail, 5);
    CHECK_EQ(g_def.security.lock_min, 5);
    CHECK_EQ(g_def.security.n_ip_allow, 0);
    CHECK(g_def.security.svc_snmp);
    CHECK(g_def.security.svc_syslog);
    CHECK(!g_def.notify.syslog_enabled);
    CHECK_EQ(g_def.notify.port, 514);
    CHECK_EQ(g_def.notify.facility, 16);
    CHECK_EQ(g_def.notify.min_sev, 5);
    /* section defaults agree with the whole-config defaults */
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++) {
        size_t sz = cfg_section_size((cfg_section_t)s);
        void *buf = malloc(sz);
        memset(buf, 0xA5, sz);
        cfg_section_defaults((cfg_section_t)s, buf, MAC);
        CHECK(memcmp(buf, cfg_section_cptr(&g_def, (cfg_section_t)s), sz) == 0);
        free(buf);
    }
    /* NULL mac */
    cfg_defaults(&g_c, NULL);
    CHECK_STR(g_c.network.hostname, "mestio-gw-0000");
}

static void test_metadata(void) {
    static const char *names[] = {"general", "network", "modbus", "alarms", "snmp", "time", "security", "notify"};
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++) {
        CHECK_STR(cfg_section_name((cfg_section_t)s), names[s]);
        cfg_section_t back = CFG_SEC_COUNT;
        CHECK(cfg_section_from_name(names[s], &back));
        CHECK_EQ(back, s);
        CHECK(cfg_section_size((cfg_section_t)s) > 0);
        CHECK(cfg_section_ptr(&g_c, (cfg_section_t)s) != NULL);
    }
    CHECK_STR(cfg_section_name(CFG_SEC_SECRETS), "secrets");
    cfg_section_t s;
    CHECK(cfg_section_from_name("secrets", &s));
    CHECK_EQ(s, CFG_SEC_SECRETS);
    CHECK(!cfg_section_from_name("bogus", &s));
    CHECK(!cfg_section_from_name(NULL, &s));
    CHECK(cfg_section_name(CFG_SEC_COUNT) == NULL);
    CHECK_EQ(cfg_section_size(CFG_SEC_SECRETS), 0);
    CHECK(cfg_section_ptr(&g_c, CFG_SEC_SECRETS) == NULL);
    CHECK(cfg_section_cptr(&g_c, CFG_SEC_GENERAL) == &g_c.general);
    CHECK(cfg_section_cptr(&g_c, CFG_SEC_NOTIFY) == &g_c.notify);
}

/* ---- validation table ---- */

typedef void (*mut_fn)(gw_config_t *c);
#define MUT(name, body)                                                                                      \
    static void name(gw_config_t *c) {                                                                       \
        body;                                                                                                \
    }

MUT(m_lang, strcpy(c->general.lang, "de"))
MUT(m_site_ctrl, strcpy(c->general.site, "a\tb"))
MUT(m_site_utf8, strcpy(c->general.site, "a\xff"))
MUT(m_site_unterminated, memset(c->general.site, 'x', sizeof(c->general.site)))
MUT(m_mode, c->network.eth.mode = 7)
MUT(m_mask, c->network.eth.mask = IP(255, 0, 255, 0))
MUT(m_mask31, c->network.eth.mask = IP(255, 255, 255, 254))
MUT(m_ip_net, c->network.eth.ip = IP(192, 168, 10, 0))
MUT(m_ip_bcast, c->network.eth.ip = IP(192, 168, 10, 255))
MUT(m_ip_loop, c->network.eth.ip = IP(127, 0, 0, 1))
MUT(m_overlap, { c->network.eth.ip = IP(192, 168, 150, 10); c->network.eth.gw = IP(192, 168, 150, 1); })
MUT(m_overlap16, { c->network.eth.ip = IP(192, 168, 1, 10); c->network.eth.mask = IP(255, 255, 0, 0); c->network.eth.gw = 0; })
MUT(m_gw_out, c->network.eth.gw = IP(10, 0, 0, 1))
MUT(m_gw_same, c->network.eth.gw = c->network.eth.ip)
MUT(m_dns, c->network.eth.dns1 = IP(224, 0, 0, 1))
MUT(m_dns2, c->network.eth.dns2 = IP(0, 0, 0, 5))
MUT(m_host, strcpy(c->network.hostname, "-bad"))
MUT(m_host2, strcpy(c->network.hostname, "a.b"))
MUT(m_host_empty, c->network.hostname[0] = 0)
MUT(m_ssid, c->network.ap.ssid[0] = 0)
MUT(m_chan, c->network.ap.channel = 14)
MUT(m_idle, c->network.ap.idle_min = 0)
MUT(m_fallback, c->network.ap.fallback_after_s = 29)
MUT(m_baud, c->modbus.port.baud = 9601)
MUT(m_parity, c->modbus.port.parity = 'X')
MUT(m_stop, c->modbus.port.stop = 3)
MUT(m_poll, c->modbus.port.poll_ms = 199)
MUT(m_tmo, c->modbus.port.timeout_ms = 2001)
MUT(m_retries, c->modbus.port.retries = 4)
MUT(m_gap, c->modbus.port.gap_ms = 101)
MUT(m_offline, c->modbus.port.offline_after = 0)
MUT(m_ndev0, c->modbus.n_devices = 0)
MUT(m_ndev5, c->modbus.n_devices = 5)
MUT(m_devid, c->modbus.devices[0].id = 4)
MUT(m_slave0, c->modbus.devices[0].slave = 0)
MUT(m_slave248, c->modbus.devices[0].slave = 248)
MUT(m_dupid, { c->modbus.n_devices = 2; c->modbus.devices[1] = c->modbus.devices[0]; c->modbus.devices[1].slave = 2; })
MUT(m_dupslave, { c->modbus.n_devices = 2; c->modbus.devices[1] = c->modbus.devices[0]; c->modbus.devices[1].id = 1; })
MUT(m_devname, strcpy(c->modbus.devices[0].name, "\x01"))
MUT(m_deb_r, c->alarms.debounce_raise = 0)
MUT(m_deb_c, c->alarms.debounce_clear = 11)
MUT(m_ovr_code, { c->alarms.n_sev_override = 1; c->alarms.sev_override[0].code = 999; c->alarms.sev_override[0].sev = 1; })
MUT(m_ovr_rule, { c->alarms.n_sev_override = 1; c->alarms.sev_override[0].code = 401; c->alarms.sev_override[0].sev = 1; })
MUT(m_ovr_sev, { c->alarms.n_sev_override = 1; c->alarms.sev_override[0].code = 127; c->alarms.sev_override[0].sev = 4; })
MUT(m_ovr_dup, { c->alarms.n_sev_override = 2; c->alarms.sev_override[0].code = 127; c->alarms.sev_override[1].code = 127; })
MUT(m_ovr_many, c->alarms.n_sev_override = GW_MAX_SEV_OVERRIDES + 1)
MUT(m_users_name, strcpy(c->snmp.users[0].name, "bad name"))
MUT(m_users_dup, strcpy(c->snmp.users[1].name, "gwmonitor"))
MUT(m_users_acc, c->snmp.users[1].access = 2)
MUT(m_trap_host, { c->snmp.n_traps = 1; strcpy(c->snmp.traps[0].host, "nms.local"); c->snmp.traps[0].port = 162; })
MUT(m_trap_port, { c->snmp.n_traps = 1; strcpy(c->snmp.traps[0].host, "10.0.0.5"); c->snmp.traps[0].port = 0; })
MUT(m_trap_inform, { c->snmp.n_traps = 1; strcpy(c->snmp.traps[0].host, "10.0.0.5"); c->snmp.traps[0].port = 162; c->snmp.traps[0].version = CFG_SNMP_V1; c->snmp.traps[0].inform = true; })
MUT(m_trap_dup, { c->snmp.n_traps = 2; strcpy(c->snmp.traps[0].host, "10.0.0.5"); c->snmp.traps[0].port = 162; c->snmp.traps[1] = c->snmp.traps[0]; })
MUT(m_trap_many, c->snmp.n_traps = 5)
MUT(m_sysname, strcpy(c->snmp.sys_name, "\x7f"))
MUT(m_ntp_srv, strcpy(c->time.servers[0], "bad host"))
MUT(m_ntp_none, { c->time.ntp_enabled = true; c->time.servers[0][0] = 0; c->time.servers[1][0] = 0; })
MUT(m_ntp_int, c->time.interval_min = 14)
MUT(m_tz, strcpy(c->time.tz, "KST 9"))
MUT(m_tz_empty, c->time.tz[0] = 0)
MUT(m_idle_min, c->security.idle_min = 4)
MUT(m_maxfail, c->security.max_fail = 11)
MUT(m_lockmin, c->security.lock_min = 0)
MUT(m_allow_host_bits, { c->security.n_ip_allow = 1; c->security.ip_allow[0].net = IP(10, 0, 0, 1); c->security.ip_allow[0].mask = IP(255, 0, 0, 0); })
MUT(m_allow_mask, { c->security.n_ip_allow = 1; c->security.ip_allow[0].net = 0; c->security.ip_allow[0].mask = IP(0, 255, 0, 0); })
MUT(m_allow_dup, { c->security.n_ip_allow = 2; c->security.ip_allow[0].net = IP(10, 0, 0, 0); c->security.ip_allow[0].mask = IP(255, 0, 0, 0); c->security.ip_allow[1] = c->security.ip_allow[0]; })
MUT(m_allow_many, c->security.n_ip_allow = 9)
MUT(m_syslog_host, { c->notify.syslog_enabled = true; c->notify.host[0] = 0; })
MUT(m_syslog_badhost, strcpy(c->notify.host, "a_b"))
MUT(m_syslog_port, c->notify.port = 0)
MUT(m_syslog_fac, c->notify.facility = 24)
MUT(m_syslog_sev, c->notify.min_sev = 8)

static void rule0(gw_config_t *c) {
    c->alarms.n_rules = 1;
    cfg_rule_t *r = &c->alarms.rules[0];
    memset(r, 0, sizeof(*r));
    r->id = 1;
    strcpy(r->name, "warm");
    r->enabled = true;
    r->dev = 0;
    r->addr = 40036;
    r->op = CFG_OP_GT;
    r->thr = 280;
    r->hyst = 10;
    r->delay_s = 60;
    r->sev = 2;
}
MUT(m_rule_id, { rule0(c); c->alarms.rules[0].id = 9; })
MUT(m_rule_dev, { rule0(c); c->alarms.rules[0].dev = 1; })
MUT(m_rule_reg, { rule0(c); c->alarms.rules[0].addr = 40001; })
MUT(m_rule_op, { rule0(c); c->alarms.rules[0].op = 2; })
MUT(m_rule_thr, { rule0(c); c->alarms.rules[0].thr = 851; })
MUT(m_rule_thr_lo, { rule0(c); c->alarms.rules[0].thr = -251; })
MUT(m_rule_hyst, { rule0(c); c->alarms.rules[0].hyst = -1; })
MUT(m_rule_delay, { rule0(c); c->alarms.rules[0].delay_s = 3601; })
MUT(m_rule_sev, { rule0(c); c->alarms.rules[0].sev = 0; })
MUT(m_rule_dup, { rule0(c); c->alarms.n_rules = 2; c->alarms.rules[1] = c->alarms.rules[0]; })
MUT(m_rule_name, { rule0(c); strcpy(c->alarms.rules[0].name, "\x02"); })
MUT(m_rule_many, { rule0(c); c->alarms.n_rules = 9; })

static const struct {
    mut_fn fn;
    const char *field, *code;
} k_bad[] = {
    {m_lang, "general.lang", "range"},
    {m_site_ctrl, "general.site", "format"},
    {m_site_utf8, "general.site", "format"},
    {m_site_unterminated, "general.site", "format"},
    {m_mode, "network.eth.mode", "range"},
    {m_mask, "network.eth.mask", "range"},
    {m_mask31, "network.eth.mask", "range"},
    {m_ip_net, "network.eth.ip", "range"},
    {m_ip_bcast, "network.eth.ip", "range"},
    {m_ip_loop, "network.eth.ip", "range"},
    {m_overlap, "network.eth.ip", "overlap"},
    {m_overlap16, "network.eth.ip", "overlap"},
    {m_gw_out, "network.eth.gw", "range"},
    {m_gw_same, "network.eth.gw", "range"},
    {m_dns, "network.eth.dns1", "range"},
    {m_dns2, "network.eth.dns2", "range"},
    {m_host, "network.hostname", "format"},
    {m_host2, "network.hostname", "format"},
    {m_host_empty, "network.hostname", "format"},
    {m_ssid, "network.ap.ssid", "format"},
    {m_chan, "network.ap.channel", "range"},
    {m_idle, "network.ap.idle_min", "range"},
    {m_fallback, "network.ap.fallback_after_s", "range"},
    {m_baud, "modbus.port.baud", "range"},
    {m_parity, "modbus.port.parity", "range"},
    {m_stop, "modbus.port.stop", "range"},
    {m_poll, "modbus.poll_ms", "range"},
    {m_tmo, "modbus.timeout_ms", "range"},
    {m_retries, "modbus.retries", "range"},
    {m_gap, "modbus.gap_ms", "range"},
    {m_offline, "modbus.offline_after", "range"},
    {m_ndev0, "modbus.devices", "required"},
    {m_ndev5, "modbus.devices", "too_many"},
    {m_devid, "modbus.devices[0].id", "range"},
    {m_slave0, "modbus.devices[0].slave", "range"},
    {m_slave248, "modbus.devices[0].slave", "range"},
    {m_dupid, "modbus.devices[1].id", "duplicate"},
    {m_dupslave, "modbus.devices[1].slave", "duplicate"},
    {m_devname, "modbus.devices[0].name", "format"},
    {m_deb_r, "alarms.debounce_raise", "range"},
    {m_deb_c, "alarms.debounce_clear", "range"},
    {m_ovr_code, "alarms.sev_override.999", "unknown_field"},
    {m_ovr_rule, "alarms.sev_override.401", "unknown_field"},
    {m_ovr_sev, "alarms.sev_override.high_temp", "range"},
    {m_ovr_dup, "alarms.sev_override.high_temp", "duplicate"},
    {m_ovr_many, "alarms.sev_override", "too_many"},
    {m_rule_id, "alarms.rules[0].id", "range"},
    {m_rule_dev, "alarms.rules[0].dev", "range"},
    {m_rule_reg, "alarms.rules[0].src", "unknown_register"},
    {m_rule_op, "alarms.rules[0].op", "range"},
    {m_rule_thr, "alarms.rules[0].thr", "range"},
    {m_rule_thr_lo, "alarms.rules[0].thr", "range"},
    {m_rule_hyst, "alarms.rules[0].hyst", "range"},
    {m_rule_delay, "alarms.rules[0].delay_s", "range"},
    {m_rule_sev, "alarms.rules[0].sev", "range"},
    {m_rule_dup, "alarms.rules[1].id", "duplicate"},
    {m_rule_name, "alarms.rules[0].name", "format"},
    {m_rule_many, "alarms.rules", "too_many"},
    {m_users_name, "snmp.v3.users[0].name", "format"},
    {m_users_dup, "snmp.v3.users[1].name", "duplicate"},
    {m_users_acc, "snmp.v3.users[1].access", "range"},
    {m_trap_host, "snmp.traps[0].host", "format"},
    {m_trap_port, "snmp.traps[0].port", "range"},
    {m_trap_inform, "snmp.traps[0].inform", "range"},
    {m_trap_dup, "snmp.traps[1].host", "duplicate"},
    {m_trap_many, "snmp.traps", "too_many"},
    {m_sysname, "snmp.sys.name", "format"},
    {m_ntp_srv, "time.ntp.servers[0]", "format"},
    {m_ntp_none, "time.ntp.servers", "required"},
    {m_ntp_int, "time.ntp.interval_min", "range"},
    {m_tz, "time.tz", "format"},
    {m_tz_empty, "time.tz", "format"},
    {m_idle_min, "security.idle_min", "range"},
    {m_maxfail, "security.lockout.max_fail", "range"},
    {m_lockmin, "security.lockout.lock_min", "range"},
    {m_allow_host_bits, "security.ip_allow[0]", "format"},
    {m_allow_mask, "security.ip_allow[0]", "format"},
    {m_allow_dup, "security.ip_allow[1]", "duplicate"},
    {m_allow_many, "security.ip_allow", "too_many"},
    {m_syslog_host, "notify.syslog.host", "required"},
    {m_syslog_badhost, "notify.syslog.host", "format"},
    {m_syslog_port, "notify.syslog.port", "range"},
    {m_syslog_fac, "notify.syslog.facility", "range"},
    {m_syslog_sev, "notify.syslog.min_sev", "range"},
};

static void test_validation(void) {
    cfg_set_alarm_catalog(&alm_cfg_catalog);
    for (size_t i = 0; i < sizeof(k_bad) / sizeof(k_bad[0]); i++) {
        g_c = g_def;
        k_bad[i].fn(&g_c);
        cfg_verr_t e;
        memset(&e, 0, sizeof(e));
        bool ok = cfg_validate(&g_c, &e);
        if (ok || strcmp(e.field, k_bad[i].field) != 0 || strcmp(e.code, k_bad[i].code) != 0)
            fprintf(stderr, "case %zu: ok=%d field='%s' code='%s' (want %s/%s)\n", i, ok, e.field, e.code,
                    k_bad[i].field, k_bad[i].code);
        CHECK(!ok);
        CHECK_STR(e.field, k_bad[i].field);
        CHECK_STR(e.code, k_bad[i].code);
        CHECK(!cfg_validate(&g_c, NULL)); /* err optional */
    }
    /* valid variants */
    g_c = g_def;
    rule0(&g_c);
    CHECK(cfg_validate(&g_c, NULL));
    g_c.alarms.rules[0].addr = 40059; /* any REG row, slow group */
    g_c.alarms.rules[0].thr = 5000;
    g_c.alarms.rules[0].op = CFG_OP_LT;
    CHECK(cfg_validate(&g_c, NULL));
    g_c = g_def;
    g_c.network.eth.mode = CFG_ETH_DHCP; /* static fields not checked in DHCP mode */
    g_c.network.eth.ip = 0;
    g_c.network.eth.mask = 0;
    CHECK(cfg_validate(&g_c, NULL));
    g_c = g_def;
    g_c.network.eth.gw = 0; /* no gateway */
    g_c.network.eth.dns1 = 0;
    CHECK(cfg_validate(&g_c, NULL));
    g_c = g_def;
    g_c.network.eth.ip = IP(192, 168, 151, 10); /* adjacent to the AP /24 */
    g_c.network.eth.gw = IP(192, 168, 151, 1);
    CHECK(cfg_validate(&g_c, NULL));
    g_c = g_def;
    g_c.modbus.n_devices = 2;
    g_c.modbus.devices[1] = g_c.modbus.devices[0];
    g_c.modbus.devices[1].id = 3;
    g_c.modbus.devices[1].enabled = false; /* same slave allowed when disabled */
    CHECK(cfg_validate(&g_c, NULL));
    g_c.alarms.n_sev_override = 2;
    g_c.alarms.sev_override[0].code = 127;
    g_c.alarms.sev_override[0].sev = 3;
    g_c.alarms.sev_override[1].code = 301;
    g_c.alarms.sev_override[1].sev = 0;
    CHECK(cfg_validate(&g_c, NULL));
    strcpy(g_c.general.site, "B동 전산실");
    strcpy(g_c.snmp.sys_location, "서울");
    CHECK(cfg_validate(&g_c, NULL));
    /* without a catalog every override is rejected */
    cfg_set_alarm_catalog(NULL);
    cfg_verr_t e;
    CHECK(!cfg_validate(&g_c, &e));
    CHECK_STR(e.code, "unknown_field");
    cfg_set_alarm_catalog(&alm_cfg_catalog);
}

static void test_validate_with(void) {
    g_c = g_def;
    cfg_modbus_t m = g_def.modbus;
    m.port.poll_ms = 50;
    cfg_verr_t e;
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_MODBUS, &m, &e));
    CHECK_STR(e.field, "modbus.poll_ms");
    CHECK(memcmp(&g_c, &g_def, sizeof(g_c)) == 0); /* base untouched */
    /* cross-section: a rule references device 1; removing it via MODBUS is rejected */
    g_c = g_def;
    g_c.modbus.n_devices = 2;
    g_c.modbus.devices[1] = g_c.modbus.devices[0];
    g_c.modbus.devices[1].id = 1;
    g_c.modbus.devices[1].slave = 2;
    rule0(&g_c);
    g_c.alarms.rules[0].dev = 1;
    CHECK(cfg_validate(&g_c, NULL));
    m = g_c.modbus;
    m.n_devices = 1;
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_MODBUS, &m, &e));
    CHECK_STR(e.field, "alarms.rules[0].dev");
    /* and adding a rule for an existing device via ALARMS works */
    cfg_alarms_t a = g_c.alarms;
    a.rules[0].dev = 0;
    CHECK(cfg_validate_with(&g_c, CFG_SEC_ALARMS, &a, &e));
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_SECRETS, &a, &e));
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_ALARMS, NULL, &e));
}

static void test_trap_remap_and_secrets_check(void) {
    cfg_snmp_t o = g_def.snmp, n = g_def.snmp;
    o.n_traps = 3;
    strcpy(o.traps[0].host, "10.0.0.1");
    o.traps[0].port = 162;
    strcpy(o.traps[1].host, "10.0.0.2");
    o.traps[1].port = 162;
    strcpy(o.traps[2].host, "10.0.0.1");
    o.traps[2].port = 1162;
    n.n_traps = 4;
    strcpy(n.traps[0].host, "10.0.0.2"); /* moved from slot 1 */
    n.traps[0].port = 162;
    strcpy(n.traps[1].host, "10.0.0.1"); /* same host, other port -> slot 2 */
    n.traps[1].port = 1162;
    strcpy(n.traps[2].host, "10.0.0.9"); /* new */
    n.traps[2].port = 162;
    strcpy(n.traps[3].host, "10.0.0.2"); /* duplicate of an already used old slot -> new */
    n.traps[3].port = 162;
    int8_t from[GW_MAX_TRAP_TARGETS];
    cfg_trap_remap(&o, &n, from);
    CHECK_EQ(from[0], 1);
    CHECK_EQ(from[1], 2);
    CHECK_EQ(from[2], -1);
    CHECK_EQ(from[3], -1);
    n.n_traps = 1;
    cfg_trap_remap(&o, &n, from);
    CHECK_EQ(from[0], 1);
    CHECK_EQ(from[1], -1);
    CHECK_EQ(from[3], -1);
    cfg_trap_remap(NULL, &n, from);
    CHECK_EQ(from[0], -1);

    cfg_secret_flags_t f;
    memset(&f, 0, sizeof(f));
    cfg_snmp_t s = g_def.snmp;
    cfg_verr_t e;
    CHECK(cfg_snmp_check_secrets(&s, &f, &e));
    s.v2c = true;
    CHECK(!cfg_snmp_check_secrets(&s, &f, &e));
    CHECK_STR(e.field, "snmp.ro");
    CHECK_STR(e.code, "required");
    f.snmp_ro_set = true;
    CHECK(cfg_snmp_check_secrets(&s, &f, &e));
    s.v2c = false;
    s.v1 = true;
    f.snmp_ro_set = false;
    CHECK(!cfg_snmp_check_secrets(&s, &f, NULL));
}

/* ---- JSON ---- */

static char *to_json(const gw_config_t *c, const char *fw) {
    gw_jw_t w;
    CHECK_EQ(gw_jw_init_dynamic(&w, 256, 1 << 16), GW_JW_OK);
    CHECK_EQ(cfg_to_json(c, fw, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    return gw_jw_detach(&w, NULL);
}

static int from_json(const char *s, gw_config_t *out, cfg_verr_t *e) {
    return cfg_from_json(s, strlen(s), MAC, out, e);
}

static void test_json_roundtrip(void) {
    /* rich configuration -> JSON -> parse -> byte-identical struct */
    g_c = g_def;
    g_c.rev = 4242;
    strcpy(g_c.general.site, "B동 \"전산실\"\\");
    strcpy(g_c.general.lang, "en");
    g_c.network.eth.mode = CFG_ETH_DHCP;
    g_c.network.eth.dns2 = IP(8, 8, 8, 8);
    g_c.modbus.n_devices = 3;
    for (int i = 1; i < 3; i++) {
        g_c.modbus.devices[i] = g_c.modbus.devices[0];
        g_c.modbus.devices[i].id = (uint8_t)(i + 1);
        g_c.modbus.devices[i].slave = (uint8_t)(10 + i);
        g_c.modbus.devices[i].enabled = i == 1;
        snprintf(g_c.modbus.devices[i].name, sizeof(g_c.modbus.devices[i].name), "공조기 %d", i);
    }
    g_c.modbus.port.parity = 'E';
    g_c.modbus.port.stop = 2;
    g_c.modbus.port.baud = 19200;
    rule0(&g_c);
    g_c.alarms.n_rules = 3;
    g_c.alarms.rules[1] = g_c.alarms.rules[0];
    g_c.alarms.rules[1].id = 5;
    g_c.alarms.rules[1].addr = 40021; /* signed, scale 10 */
    g_c.alarms.rules[1].thr = -15;
    g_c.alarms.rules[1].hyst = 5;
    g_c.alarms.rules[1].op = CFG_OP_LT;
    g_c.alarms.rules[1].dev = 2;
    g_c.alarms.rules[1].enabled = false;
    g_c.alarms.rules[2] = g_c.alarms.rules[0];
    g_c.alarms.rules[2].id = 8;
    g_c.alarms.rules[2].addr = 40059; /* scale 1 */
    g_c.alarms.rules[2].thr = 12000;
    g_c.alarms.rules[2].hyst = 0;
    g_c.alarms.rules[2].sev = 3;
    g_c.alarms.n_sev_override = 2;
    g_c.alarms.sev_override[0].code = 129;
    g_c.alarms.sev_override[0].sev = 2;
    g_c.alarms.sev_override[1].code = 201;
    g_c.alarms.sev_override[1].sev = 0;
    g_c.snmp.enabled = true;
    g_c.snmp.v2c = true;
    g_c.snmp.auth_traps = true;
    g_c.snmp.users[1].enabled = false;
    g_c.snmp.n_traps = 2;
    strcpy(g_c.snmp.traps[0].host, "192.168.10.20");
    g_c.snmp.traps[0].port = 162;
    g_c.snmp.traps[0].version = CFG_SNMP_V2C;
    g_c.snmp.traps[0].inform = true;
    g_c.snmp.traps[0].enabled = true;
    strcpy(g_c.snmp.traps[1].host, "10.1.2.3");
    g_c.snmp.traps[1].port = 10162;
    g_c.snmp.traps[1].version = CFG_SNMP_V1;
    strcpy(g_c.snmp.sys_name, "gw-1");
    g_c.time.ntp_enabled = true;
    memset(g_c.time.servers[1], 0, sizeof(g_c.time.servers[1]));
    strcpy(g_c.time.tz, "<+0330>-3:30");
    g_c.security.n_ip_allow = 2;
    gw_cidr_parse("10.0.0.0/8", &g_c.security.ip_allow[0].net, &g_c.security.ip_allow[0].mask);
    gw_cidr_parse("192.168.10.7", &g_c.security.ip_allow[1].net, &g_c.security.ip_allow[1].mask);
    g_c.security.svc_syslog = false;
    g_c.notify.syslog_enabled = true;
    strcpy(g_c.notify.host, "syslog.example");
    g_c.notify.min_sev = 3;
    cfg_verr_t e;
    CHECK(cfg_validate(&g_c, &e));
    char *js = to_json(&g_c, "1.2.3");
    CHECK(js && strstr(js, "\"fw\":\"1.2.3\"") != NULL);
    CHECK(js && strstr(js, "\"thr\":-1.5") != NULL);
    CHECK(js && strstr(js, "\"src\":\"reg:40059\"") != NULL);
    CHECK(js && strstr(js, "\"sev_override\":{\"high_hum\":2,\"contamination\":0}") != NULL);
    CHECK(js && strstr(js, "\"ip_allow\":[\"10.0.0.0/8\",\"192.168.10.7/32\"]") != NULL);
    CHECK(js && strstr(js, "\"servers\":[\"pool.ntp.org\"]") != NULL);
    CHECK(js && strstr(js, "\"psk") == NULL && strstr(js, "_set") == NULL && strstr(js, "provisional") == NULL);
    CHECK_EQ(from_json(js, &g_n, &e), CFG_JSON_OK);
    CHECK(memcmp(&g_c, &g_n, sizeof(g_c)) == 0);
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++)
        if (memcmp(cfg_section_cptr(&g_c, (cfg_section_t)s), cfg_section_cptr(&g_n, (cfg_section_t)s),
                   cfg_section_size((cfg_section_t)s)) != 0) {
            const uint8_t *a = cfg_section_cptr(&g_c, (cfg_section_t)s), *b = cfg_section_cptr(&g_n, (cfg_section_t)s);
            for (size_t k = 0; k < cfg_section_size((cfg_section_t)s); k++)
                if (a[k] != b[k]) {
                    fprintf(stderr, "section %s differs at +%zu: %02x vs %02x\n", cfg_section_name((cfg_section_t)s), k,
                            a[k], b[k]);
                    break;
                }
        }
    char *js2 = to_json(&g_n, "1.2.3");
    CHECK_STR(js2, js);
    free(js);
    free(js2);
    /* defaults round trip */
    js = to_json(&g_def, NULL);
    CHECK(js && strncmp(js, "{\"schema\":1,\"rev\":0,\"general\":", 30) == 0);
    CHECK_EQ(from_json(js, &g_n, &e), CFG_JSON_OK);
    CHECK(memcmp(&g_def, &g_n, sizeof(g_c)) == 0);
    free(js);
}

static void test_json_file_parse(void) {
    cfg_verr_t e;
    /* missing everything -> defaults (schema 1 assumed) */
    CHECK_EQ(from_json("{}", &g_n, &e), CFG_JSON_OK);
    CHECK(memcmp(&g_def, &g_n, sizeof(g_n)) == 0);
    /* partial sections + unknown members ignored */
    CHECK_EQ(from_json("{\"schema\":1,\"rev\":7,\"future\":{\"x\":1},\"general\":{\"site\":\"S\",\"zzz\":1},"
                       "\"network\":{\"ap\":{\"channel\":11,\"psk_set\":true}},\"modbus\":{\"poll_ms\":2000}}",
                       &g_n, &e),
             CFG_JSON_OK);
    CHECK_EQ(g_n.rev, 7);
    CHECK_STR(g_n.general.site, "S");
    CHECK_STR(g_n.general.lang, "ko");
    CHECK_EQ(g_n.network.ap.channel, 11);
    CHECK_STR(g_n.network.ap.ssid, "MESTIO-GW-ABCD");
    CHECK_EQ(g_n.modbus.port.poll_ms, 2000);
    CHECK_EQ(g_n.modbus.n_devices, 1);
    /* schema handling */
    CHECK_EQ(from_json("{\"schema\":2}", &g_n, &e), CFG_JSON_E_SCHEMA);
    CHECK_STR(e.code, "unsupported_schema");
    CHECK_EQ(from_json("{\"schema\":0}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(from_json("{\"schema\":\"1\"}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "schema");
    CHECK_EQ(from_json("{\"schema\":1.5}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(from_json("{\"rev\":-1}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(from_json("{\"rev\":4294967296}", &g_n, &e), CFG_JSON_E_INVALID);
    /* not JSON / wrong top-level type / too deep */
    CHECK_EQ(from_json("", &g_n, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(from_json("[]", &g_n, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(from_json("{\"general\":", &g_n, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(from_json("null", &g_n, &e), CFG_JSON_E_PARSE);
    char deep[200];
    memset(deep, 0, sizeof(deep));
    for (int i = 0; i < 40; i++)
        strcat(deep, "[");
    CHECK_EQ(from_json(deep, &g_n, &e), CFG_JSON_E_PARSE);
    /* brackets inside strings do not count toward the depth */
    char str_deep[160] = "{\"general\":{\"site\":\"";
    for (int i = 0; i < 40; i++)
        strcat(str_deep, "[");
    strcat(str_deep, "\"}}");
    CHECK_EQ(from_json(str_deep, &g_n, &e), CFG_JSON_OK);
    /* type errors name the field */
    CHECK_EQ(from_json("{\"general\":[]}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "general");
    CHECK_STR(e.code, "type");
    CHECK_EQ(from_json("{\"modbus\":{\"poll_ms\":\"1000\"}}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "modbus.poll_ms");
    CHECK_STR(e.code, "type");
    CHECK_EQ(from_json("{\"modbus\":{\"poll_ms\":100.5}}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "type");
    CHECK_EQ(from_json("{\"modbus\":{\"poll_ms\":70000}}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "range");
    CHECK_EQ(from_json("{\"modbus\":{\"poll_ms\":100}}", &g_n, &e), CFG_JSON_E_INVALID); /* semantic */
    CHECK_STR(e.field, "modbus.poll_ms");
    CHECK_STR(e.code, "range");
    CHECK_EQ(from_json("{\"network\":{\"eth\":{\"ip\":\"192.168.1.300\"}}}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "network.eth.ip");
    CHECK_STR(e.code, "format");
    CHECK_EQ(from_json("{\"general\":{\"site\":\"0123456789012345678901234567890123456789012345678901234567890123\"}}",
                       &g_n, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "length");
    CHECK_EQ(from_json("{\"time\":{\"ntp\":{\"servers\":[\"a\",\"b\",\"c\"]}}}", &g_n, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "too_many");
    /* file mode: stale sev_override ids are dropped, known ones kept */
    CHECK_EQ(from_json("{\"alarms\":{\"sev_override\":{\"gone_alarm\":1,\"high_temp\":3}}}", &g_n, &e), CFG_JSON_OK);
    CHECK_EQ(g_n.alarms.n_sev_override, 1);
    CHECK_EQ(g_n.alarms.sev_override[0].code, 127);
    CHECK_EQ(g_n.alarms.sev_override[0].sev, 3);
    /* file rules: required members */
    CHECK_EQ(from_json("{\"alarms\":{\"rules\":[{\"id\":1,\"src\":\"temp\",\"op\":\">\"}]}}", &g_n, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules[0].thr");
    CHECK_STR(e.code, "required");
    CHECK_EQ(from_json("{\"alarms\":{\"rules\":[{\"id\":1,\"src\":\"reg:40001\",\"op\":\">\",\"thr\":1}]}}", &g_n, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "unknown_register");
    CHECK_EQ(from_json("{\"alarms\":{\"rules\":[{\"id\":1,\"src\":\"reg:4003\",\"op\":\">\",\"thr\":1}]}}", &g_n, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "format");
    CHECK_EQ(from_json("{\"alarms\":{\"rules\":[{\"id\":1,\"src\":\"temp\",\"op\":\">\",\"thr\":23.45}]}}", &g_n, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules[0].thr");
    CHECK_EQ(from_json("{\"alarms\":{\"rules\":[{\"id\":2,\"src\":\"hum\",\"op\":\"<\",\"thr\":30,\"hyst\":2.5}]}}",
                       &g_n, &e),
             CFG_JSON_OK);
    CHECK_EQ(g_n.alarms.rules[0].addr, 40037);
    CHECK_EQ(g_n.alarms.rules[0].thr, 300);
    CHECK_EQ(g_n.alarms.rules[0].hyst, 25);
    CHECK_EQ(g_n.alarms.rules[0].op, CFG_OP_LT);
    CHECK(g_n.alarms.rules[0].enabled);
    CHECK_EQ(g_n.alarms.rules[0].sev, 2);
    /* modbus device merge in file mode: missing fields from per-id defaults */
    CHECK_EQ(from_json("{\"modbus\":{\"devices\":[{\"id\":0},{\"id\":2,\"name\":\"B\"}]}}", &g_n, &e), CFG_JSON_OK);
    CHECK_EQ(g_n.modbus.n_devices, 2);
    CHECK_STR(g_n.modbus.devices[0].name, "MEX150");
    CHECK_EQ(g_n.modbus.devices[1].slave, 3);
    CHECK(g_n.modbus.devices[1].enabled);
    /* null pointers */
    CHECK_EQ(cfg_from_json(NULL, 0, MAC, &g_n, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(cfg_from_json("{}", 2, MAC, NULL, &e), CFG_JSON_E_PARSE);
}

static void test_migrate(void) {
    cfg_verr_t e;
    cJSON *root = cJSON_Parse("{\"schema\":1}");
    CHECK_EQ(cfg_migrate(root, 1, &e), CFG_JSON_OK);
    CHECK_EQ(cfg_migrate(root, 2, &e), CFG_JSON_E_SCHEMA);
    CHECK_STR(e.code, "unsupported_schema");
    CHECK_EQ(cfg_migrate(root, 0, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(cfg_migrate(NULL, 1, &e), CFG_JSON_E_PARSE);
    cJSON_Delete(root);
}

static char g_out[8192];

static int put(cfg_section_t s, const char *body, void *out, cfg_secret_input_t *sec, cfg_verr_t *e) {
    return cfg_section_from_json(s, body, strlen(body), &g_c, out, sec, e);
}

static void test_rest_put(void) {
    cfg_verr_t e;
    cfg_secret_input_t sec;
    g_c = g_def;
    /* merge: absent members keep their value */
    cfg_general_t gen;
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"Server room B\"}", &gen, NULL, &e), CFG_JSON_OK);
    CHECK_STR(gen.site, "Server room B");
    CHECK_STR(gen.lang, "ko");
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"x\",\"bogus\":1}", &gen, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "general.bogus");
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(put(CFG_SEC_GENERAL, "[1]", &gen, NULL, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(put(CFG_SEC_GENERAL, "{", &gen, NULL, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"lang\":\"jp\"}", &gen, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "range");

    /* network: psk is a secret (needs a sink), psk_set / provisional are not accepted */
    cfg_network_t net;
    CHECK_EQ(put(CFG_SEC_NETWORK,
                 "{\"eth\":{\"mode\":\"static\",\"ip\":\"10.20.30.40\",\"mask\":\"255.255.255.0\",\"gw\":\"10.20.30.1\"},"
                 "\"ap\":{\"psk\":\"new-ap-secret-42\"}}",
                 &net, &sec, &e),
             CFG_JSON_OK);
    CHECK(sec.has_ap_psk);
    CHECK_STR(sec.ap_psk, "new-ap-secret-42");
    CHECK_EQ(net.eth.ip, IP(10, 20, 30, 40));
    CHECK_EQ(net.eth.dns1, IP(192, 168, 10, 1)); /* kept */
    CHECK(cfg_validate_with(&g_c, CFG_SEC_NETWORK, &net, &e));
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"ap\":{\"psk\":\"short\"}}", &net, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "network.ap.psk");
    CHECK_STR(e.code, "length");
    CHECK(!sec.has_ap_psk && sec.ap_psk[0] == 0); /* wiped on error */
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"ap\":{\"psk\":\"new-ap-secret-42\"}}", &net, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"ap\":{\"psk_set\":true}}", &net, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"provisional\":null}", &net, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"eth\":{\"gw\":\"\",\"dns2\":\"\"}}", &net, &sec, &e), CFG_JSON_OK);
    CHECK_EQ(net.eth.gw, 0);
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"eth\":{\"ip\":\"\"}}", &net, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "network.eth.ip");
    CHECK_EQ(put(CFG_SEC_NETWORK, "{\"eth\":{\"ip\":\"192.168.150.20\"}}", &net, &sec, &e), CFG_JSON_OK);
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_NETWORK, &net, &e));
    CHECK_STR(e.code, "overlap");

    /* modbus: devices matched by id; array replaces */
    cfg_modbus_t mb;
    CHECK_EQ(put(CFG_SEC_MODBUS,
                 "{\"poll_ms\":2000,\"devices\":[{\"id\":0,\"name\":\"MEX150 #1\"},{\"id\":1,\"slave\":2}]}", &mb, NULL,
                 &e),
             CFG_JSON_OK);
    CHECK_EQ(mb.port.poll_ms, 2000);
    CHECK_EQ(mb.n_devices, 2);
    CHECK_STR(mb.devices[0].name, "MEX150 #1");
    CHECK_EQ(mb.devices[0].slave, 1);
    CHECK(mb.devices[1].enabled);
    CHECK_EQ(mb.devices[1].slave, 2);
    CHECK(cfg_validate_with(&g_c, CFG_SEC_MODBUS, &mb, &e));
    CHECK_EQ(put(CFG_SEC_MODBUS, "{\"devices\":[{\"slave\":2}]}", &mb, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "modbus.devices[0].id");
    CHECK_STR(e.code, "required");
    CHECK_EQ(put(CFG_SEC_MODBUS, "{\"devices\":[{\"id\":4}]}", &mb, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "range");
    CHECK_EQ(put(CFG_SEC_MODBUS, "{\"devices\":[{\"id\":0},{\"id\":1},{\"id\":2},{\"id\":3},{\"id\":0}]}", &mb, NULL, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "too_many");
    CHECK_EQ(put(CFG_SEC_MODBUS, "{\"port\":{\"parity\":\"EE\"}}", &mb, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(put(CFG_SEC_MODBUS, "{\"port\":{\"parity\":\"O\",\"baud\":115200}}", &mb, NULL, &e), CFG_JSON_OK);
    CHECK_EQ(mb.port.parity, 'O');

    /* alarms (REST shape excludes rules) */
    cfg_alarms_t al;
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{\"high_hum\":2}}", &al, NULL, &e), CFG_JSON_OK);
    CHECK_EQ(al.n_sev_override, 1);
    CHECK_EQ(al.sev_override[0].code, 129);
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{\"rule_1\":2}}", &al, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.sev_override.rule_1");
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{\"nope\":2}}", &al, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{\"high_hum\":4}}", &al, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "range");
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"rules\":[]}", &al, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules");
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{}}", &al, NULL, &e), CFG_JSON_OK);
    CHECK_EQ(al.n_sev_override, 0);
    cfg_set_alarm_catalog(NULL);
    CHECK_EQ(put(CFG_SEC_ALARMS, "{\"sev_override\":{\"high_hum\":2}}", &al, NULL, &e), CFG_JSON_E_INVALID);
    cfg_set_alarm_catalog(&alm_cfg_catalog);

    /* snmp: secrets moved out, trap communities remapped by host:port */
    g_c.snmp.n_traps = 2;
    strcpy(g_c.snmp.traps[0].host, "192.168.10.20");
    g_c.snmp.traps[0].port = 162;
    g_c.snmp.traps[0].enabled = true;
    g_c.snmp.traps[0].inform = true;
    g_c.snmp.traps[0].version = CFG_SNMP_V2C;
    strcpy(g_c.snmp.traps[1].host, "192.168.10.21");
    g_c.snmp.traps[1].port = 162;
    cfg_snmp_t sn;
    CHECK_EQ(put(CFG_SEC_SNMP,
                 "{\"enabled\":true,\"rw\":\"\",\"ro\":\"public-x\","
                 "\"v3\":{\"users\":[{\"name\":\"gwmonitor\",\"access\":\"ro\",\"enabled\":true,"
                 "\"auth_pass\":\"monitor-pass-1\",\"priv_pass\":\"monitor-priv-1\"},"
                 "{\"name\":\"gwadmin\",\"access\":\"rw\",\"enabled\":false}]},"
                 "\"traps\":[{\"host\":\"192.168.10.21\"},{\"host\":\"192.168.10.30\",\"version\":\"v1\",\"community\":\"nms-trap\"}]}",
                 &sn, &sec, &e),
             CFG_JSON_OK);
    CHECK(sn.enabled);
    CHECK(sec.has_snmp_rw && sec.snmp_rw[0] == 0);
    CHECK(sec.has_snmp_ro);
    CHECK_STR(sec.snmp_ro, "public-x");
    CHECK(sec.v3[0].has_auth && sec.v3[0].has_priv);
    CHECK_STR(sec.v3[0].auth_pass, "monitor-pass-1");
    CHECK(!sec.v3[1].has_auth);
    CHECK(!sn.users[1].enabled);
    CHECK_EQ(sn.n_traps, 2);
    CHECK(sec.has_traps);
    CHECK_EQ(sec.trap_from[0], 1);
    CHECK_EQ(sec.trap_from[1], -1);
    CHECK(!sec.trap[0].has);
    CHECK(sec.trap[1].has);
    CHECK_STR(sec.trap[1].community, "nms-trap");
    CHECK_EQ(sn.traps[1].version, CFG_SNMP_V1);
    CHECK_EQ(sn.traps[1].port, 162);
    CHECK(sn.traps[1].enabled);
    CHECK(cfg_validate_with(&g_c, CFG_SEC_SNMP, &sn, &e));
    /* no traps member -> no remap */
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"v2c\":true}", &sn, &sec, &e), CFG_JSON_OK);
    CHECK(!sec.has_traps);
    CHECK_EQ(sn.n_traps, 2);
    /* errors */
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"ro\":\"has space\"}", &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "snmp.ro");
    CHECK_STR(e.code, "format");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"v3\":{\"users\":[{\"auth_pass\":\"short\"}]}}", &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "snmp.v3.users[0].auth_pass");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"v3\":{\"users\":[{},{},{}]}}", &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "too_many");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"traps\":[{\"port\":162}]}", &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "snmp.traps[0].host");
    CHECK_STR(e.code, "required");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"traps\":[{\"host\":\"10.0.0.1\",\"version\":\"v3\"}]}", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"ro\":\"x\"}", &sn, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"ro_set\":true}", &sn, &sec, &e), CFG_JSON_E_INVALID);

    /* time / security / notify */
    cfg_time_t tm;
    CHECK_EQ(put(CFG_SEC_TIME, "{\"ntp\":{\"enabled\":true}}", &tm, NULL, &e), CFG_JSON_OK);
    CHECK(tm.ntp_enabled);
    CHECK_STR(tm.servers[0], "pool.ntp.org");
    CHECK_EQ(put(CFG_SEC_TIME, "{\"ntp\":{\"servers\":[\"ntp.local\"]},\"tz\":\"UTC0\"}", &tm, NULL, &e), CFG_JSON_OK);
    CHECK_STR(tm.servers[0], "ntp.local");
    CHECK_STR(tm.servers[1], "");
    CHECK_STR(tm.tz, "UTC0");
    cfg_security_t sc;
    CHECK_EQ(put(CFG_SEC_SECURITY, "{\"idle_min\":30,\"ip_allow\":[\"192.168.10.0/24\",\"10.1.1.1\"]}", &sc, NULL, &e),
             CFG_JSON_OK);
    CHECK_EQ(sc.idle_min, 30);
    CHECK_EQ(sc.n_ip_allow, 2);
    CHECK_EQ(sc.ip_allow[1].mask, 0xFFFFFFFFu);
    CHECK_EQ(put(CFG_SEC_SECURITY, "{\"ip_allow\":[\"10.0.0.1/8\"]}", &sc, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "security.ip_allow[0]");
    CHECK_STR(e.code, "format");
    CHECK_EQ(put(CFG_SEC_SECURITY, "{\"ip_allow\":[]}", &sc, NULL, &e), CFG_JSON_OK);
    CHECK_EQ(sc.n_ip_allow, 0);
    cfg_notify_t nt;
    CHECK_EQ(put(CFG_SEC_NOTIFY, "{\"syslog\":{\"enabled\":true,\"host\":\"192.168.10.20\"}}", &nt, NULL, &e),
             CFG_JSON_OK);
    CHECK(nt.syslog_enabled);
    CHECK_EQ(nt.port, 514);
    CHECK(cfg_validate_with(&g_c, CFG_SEC_NOTIFY, &nt, &e));
    CHECK_EQ(put(CFG_SEC_NOTIFY, "{\"syslog\":{\"host\":\"\",\"enabled\":true}}", &nt, NULL, &e), CFG_JSON_OK);
    CHECK(!cfg_validate_with(&g_c, CFG_SEC_NOTIFY, &nt, &e));
    /* bad section / args */
    CHECK_EQ(cfg_section_from_json(CFG_SEC_SECRETS, "{}", 2, &g_c, &nt, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_EQ(cfg_section_from_json(CFG_SEC_NOTIFY, "{}", 2, NULL, &nt, NULL, &e), CFG_JSON_E_INVALID);
}

static void test_rules_json(void) {
    cfg_verr_t e;
    cfg_alarms_t a = g_def.alarms;
    const char *body =
        "[{\"id\":1,\"name\":\"Room too warm\",\"enabled\":true,\"dev\":0,\"src\":\"temp\",\"op\":\">\",\"thr\":28.0,"
        "\"hyst\":1.0,\"delay_s\":60,\"sev\":2},"
        "{\"id\":2,\"name\":\"Overcurrent\",\"enabled\":false,\"dev\":0,\"src\":\"reg:40011\",\"op\":\">\",\"thr\":15.0,"
        "\"hyst\":0.5,\"delay_s\":5,\"sev\":3}]";
    CHECK_EQ(cfg_rules_from_json(body, strlen(body), &a, &e), CFG_JSON_OK);
    CHECK_EQ(a.n_rules, 2);
    CHECK_EQ(a.rules[0].thr, 280);
    CHECK_EQ(a.rules[1].addr, 40011);
    CHECK_EQ(a.rules[1].hyst, 5);
    CHECK(cfg_validate_with(&g_def, CFG_SEC_ALARMS, &a, &e));
    gw_jw_t w;
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_rules_to_json(&a, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_out,
              "[{\"id\":1,\"name\":\"Room too warm\",\"enabled\":true,\"dev\":0,\"src\":\"temp\",\"op\":\">\",\"thr\":28.0,"
              "\"hyst\":1.0,\"delay_s\":60,\"sev\":2},"
              "{\"id\":2,\"name\":\"Overcurrent\",\"enabled\":false,\"dev\":0,\"src\":\"cur\",\"op\":\">\",\"thr\":15.0,"
              "\"hyst\":0.5,\"delay_s\":5,\"sev\":3}]");
    CHECK_EQ(cfg_rules_from_json("[]", 2, &a, &e), CFG_JSON_OK);
    CHECK_EQ(a.n_rules, 0);
    CHECK_EQ(cfg_rules_from_json("{}", 2, &a, &e), CFG_JSON_E_PARSE);
    const char *bad = "[{\"id\":1,\"src\":\"temp\",\"op\":\">\",\"thr\":1,\"x\":1}]";
    CHECK_EQ(cfg_rules_from_json(bad, strlen(bad), &a, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules[0].x");
    const char *nine = "[{},{},{},{},{},{},{},{},{}]";
    CHECK_EQ(cfg_rules_from_json(nine, strlen(nine), &a, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "too_many");
    const char *opbad = "[{\"id\":1,\"src\":\"temp\",\"op\":\">=\",\"thr\":1}]";
    CHECK_EQ(cfg_rules_from_json(opbad, strlen(opbad), &a, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules[0].op");
    const char *neg = "[{\"id\":1,\"src\":\"temp\",\"op\":\">\",\"thr\":1,\"hyst\":-1}]";
    CHECK_EQ(cfg_rules_from_json(neg, strlen(neg), &a, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "alarms.rules[0].hyst");
}

static void test_rest_get(void) {
    cfg_secret_flags_t f;
    memset(&f, 0, sizeof(f));
    f.ap_psk_set = true;
    f.v3_keys_set[0] = true;
    gw_jw_t w;
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_NETWORK, &g_def, &f, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_out, "{\"eth\":{\"mode\":\"static\",\"ip\":\"192.168.10.150\",\"mask\":\"255.255.255.0\","
                     "\"gw\":\"192.168.10.1\",\"dns1\":\"192.168.10.1\",\"dns2\":\"\"},\"hostname\":\"mestio-gw-abcd\","
                     "\"ap\":{\"fallback\":true,\"ssid\":\"MESTIO-GW-ABCD\",\"psk_set\":true,\"channel\":6,"
                     "\"idle_min\":15,\"fallback_after_s\":120},\"provisional\":null}");
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_network_to_json(&g_def, NULL, "{\"state\":\"await_confirm\",\"left_s\":97}", &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK(strstr(g_out, "\"provisional\":{\"state\":\"await_confirm\",\"left_s\":97}}") != NULL);
    CHECK(strstr(g_out, "psk_set") == NULL);
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_SNMP, &g_def, &f, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_out, "{\"enabled\":false,\"v1\":false,\"v2c\":false,\"ro_set\":false,\"rw_set\":false,"
                     "\"auth_traps\":false,\"v3\":{\"enabled\":true,\"users\":["
                     "{\"name\":\"gwmonitor\",\"access\":\"ro\",\"enabled\":true,\"auth\":\"sha\",\"priv\":\"aes\","
                     "\"keys_set\":true},"
                     "{\"name\":\"gwadmin\",\"access\":\"rw\",\"enabled\":true,\"auth\":\"sha\",\"priv\":\"aes\","
                     "\"keys_set\":false}]},\"traps\":[],\"sys\":{\"name\":\"\",\"contact\":\"\",\"location\":\"\"}}");
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_ALARMS, &g_def, NULL, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_out, "{\"debounce_raise\":2,\"debounce_clear\":3,\"sev_override\":{}}");
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_TIME, &g_def, NULL, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_out, "{\"ntp\":{\"enabled\":false,\"servers\":[\"pool.ntp.org\",\"time.google.com\"],"
                     "\"interval_min\":60},\"tz\":\"KST-9\"}");
    gw_jw_init_fixed(&w, g_out, sizeof(g_out));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_SECRETS, &g_def, NULL, &w), CFG_JSON_E_WRITE);
    /* writer overflow is reported */
    char small[16];
    gw_jw_init_fixed(&w, small, sizeof(small));
    CHECK_EQ(cfg_section_to_json(CFG_SEC_MODBUS, &g_def, NULL, &w), CFG_JSON_E_WRITE);
}

/* ---- secret hygiene / string edge cases of REST bodies ---- */

static const char *g_marker;
static int g_marker_leaks;

/* cJSON free hook: count freed blocks that still contain the marker secret */
static void scan_free(void *p) {
    if (p && g_marker) {
        size_t n = malloc_usable_size(p), m = strlen(g_marker);
        const char *b = p;
        for (size_t i = 0; i + m <= n; i++)
            if (memcmp(b + i, g_marker, m) == 0) {
                g_marker_leaks++;
                break;
            }
    }
    free(p);
}

static int put_scan(cfg_section_t s, const char *body, const char *marker, void *out, cfg_secret_input_t *sec,
                    cfg_verr_t *e) {
    cJSON_Hooks h = {.malloc_fn = malloc, .free_fn = scan_free};
    cJSON_InitHooks(&h);
    g_marker = marker;
    g_marker_leaks = 0;
    int rc = cfg_section_from_json(s, body, strlen(body), &g_c, out, sec, e);
    g_marker = NULL;
    cJSON_InitHooks(NULL);
    return rc;
}

static void test_rest_strings_and_wipe(void) {
    cfg_verr_t e;
    cfg_secret_input_t sec;
    cfg_snmp_t sn;
    cfg_network_t net;
    cfg_general_t gen;
    g_c = g_def;
    /* write-only secrets are wiped from the parse tree on every error path */
    CHECK_EQ(put_scan(CFG_SEC_SNMP, "{\"ro\":\"SuperSecretComm\",\"bogus\":1}", "SuperSecretComm", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(g_marker_leaks, 0);
    CHECK_EQ(put_scan(CFG_SEC_SNMP, "{\"enabled\":\"x\",\"v3\":{\"users\":[{\"auth_pass\":\"MyV3Passphrase\"}]}}",
                      "MyV3Passphrase", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "type");
    CHECK_EQ(g_marker_leaks, 0);
    CHECK_EQ(put_scan(CFG_SEC_SNMP,
                      "{\"v3\":{\"users\":[{\"name\":\"bad name\"},{\"name\":\"u2\",\"auth_pass\":\"SecondUserPass\"}]}}",
                      "SecondUserPass", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_EQ(g_marker_leaks, 0);
    CHECK_EQ(put_scan(CFG_SEC_NETWORK, "{\"ap\":{\"psk\":\"ApSecret-123456\"},\"eth\":{\"ip\":\"x\"}}", "ApSecret-123456",
                      &net, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_EQ(g_marker_leaks, 0);
    CHECK_EQ(put_scan(CFG_SEC_SNMP, "\"NotAnObjectSecret\"", "NotAnObjectSecret", &sn, &sec, &e), CFG_JSON_E_PARSE);
    CHECK_EQ(g_marker_leaks, 0);
    /* success path too (the parsers wipe what they consume; the rest is wiped before the free) */
    CHECK_EQ(put_scan(CFG_SEC_SNMP, "{\"ro\":\"GoodSecretComm\"}", "GoodSecretComm", &sn, &sec, &e), CFG_JSON_OK);
    CHECK_EQ(g_marker_leaks, 0);
    CHECK_STR(sec.snmp_ro, "GoodSecretComm");

    /* an escaped NUL never truncates a value silently: it is a control character -> 422 format */
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"abc\\u0000\\u0007def\"}", &gen, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.field, "general.site");
    CHECK_STR(e.code, "format");
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"abc\\u0000\"}", &gen, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "format");
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"si\\u0000te\":\"x\"}", &gen, NULL, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "unknown_field");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"ro\":\"pub\\u0000lic\"}", &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "format");
    /* an escaped backslash followed by "u0000" is plain text */
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"a\\\\u0000b\"}", &gen, NULL, &e), CFG_JSON_OK);
    CHECK_STR(gen.site, "a\\u0000b");
    CHECK_EQ(put(CFG_SEC_GENERAL, "{\"site\":\"\\u00e9t\\u00e9\"}", &gen, NULL, &e), CFG_JSON_OK);
    CHECK_STR(gen.site, "\xc3\xa9t\xc3\xa9");

    /* SNMPv3 passphrases: UTF-8 text, 8..64 bytes (schema has no ASCII pattern) */
    CHECK_EQ(put(CFG_SEC_SNMP,
                 "{\"v3\":{\"users\":[{\"name\":\"gwmonitor\",\"access\":\"ro\",\"enabled\":true,"
                 "\"auth_pass\":\"p\xc3\xa4ssw\xc3\xb6rd-1\",\"priv_pass\":\"\xed\x8c\xa8\xec\x8a\xa4\xec\x9b\x8c\xeb\x93\x9c\xeb\x8b\xa4\"}]}}",
                 &sn, &sec, &e),
             CFG_JSON_OK);
    CHECK(sec.v3[0].has_auth && sec.v3[0].has_priv);
    CHECK_STR(sec.v3[0].auth_pass, "p\xc3\xa4ssw\xc3\xb6rd-1");
    CHECK_EQ(strlen(sec.v3[0].priv_pass), 15);
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"v3\":{\"users\":[{\"name\":\"u\",\"auth_pass\":\"bell\\u0007bell\"}]}}", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "format");
    CHECK_EQ(put(CFG_SEC_SNMP, "{\"v3\":{\"users\":[{\"name\":\"u\",\"auth_pass\":\"\xff\xfe-not-utf8\"}]}}", &sn, &sec, &e),
             CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "format");
    char body[256];
    char longp[66];
    memset(longp, 'a', 65);
    longp[65] = 0;
    snprintf(body, sizeof(body), "{\"v3\":{\"users\":[{\"name\":\"u\",\"auth_pass\":\"%s\"}]}}", longp);
    CHECK_EQ(put(CFG_SEC_SNMP, body, &sn, &sec, &e), CFG_JSON_E_INVALID);
    CHECK_STR(e.code, "length");
    longp[64] = 0;
    snprintf(body, sizeof(body), "{\"v3\":{\"users\":[{\"name\":\"u\",\"auth_pass\":\"%s\"}]}}", longp);
    CHECK_EQ(put(CFG_SEC_SNMP, body, &sn, &sec, &e), CFG_JSON_OK);
    g_c = g_def;
}

int main(void) {
    cfg_set_alarm_catalog(&alm_cfg_catalog);
    test_defaults();
    test_metadata();
    test_validation();
    test_validate_with();
    test_trap_remap_and_secrets_check();
    test_json_roundtrip();
    test_json_file_parse();
    test_migrate();
    test_rest_put();
    test_rest_strings_and_wipe();
    test_rules_json();
    test_rest_get();
    return BT_DONE();
}
