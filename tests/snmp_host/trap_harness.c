/* Host harness for components/snmp_gw/traps.c (tests/test_snmp_traps_host.py): the real traps.c +
 * snmp_logic.c on top of the real lwIP SNMP trap encoder (upstream snmp_traps.c after
 * components/snmp_lwip/snmp_traps_fix.cmake, force-included snmp_lwip_port.h like the firmware), with
 * every outgoing datagram captured instead of sent. Single-threaded: sgw_post() runs the agent's
 * message handler synchronously, the FreeRTOS shims never block.
 *
 * Reads one command per line from stdin; prints zero or more result lines, then "OK".
 *   init                                      sgw_traps_sync_init + sgw_traps_init
 *   clock MS | route 0|1 | queue 0|1           monotonic time, routability (ERR_RTE), agent queue accepts
 *   target HOST PORT VER INFORM EN COMMUNITY   append a target (VER: 0 v1, 1 v2c)
 *   apply EN AUTH                              sgw_traps_configure with the targets appended so far
 *   cold | authfail IP | idle
 *   alarm DEV CODE SEV RAISED VALUE SEQ | comm DEV ONLINE | config SEC REV | fw VERSION
 *   ack REQ IP                                 sgw_traps_inform_ack
 *   peer IP                                    -> "PEER 1 community" or "PEER 0"
 *   test TIMEOUT                               -> "TEST n host:ok ..."
 *   stats                                      -> "STATS sent dropped inform_failed"
 * Captured datagrams print as "PKT a.b.c.d PORT HEX". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alarm/alarm.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_ip4.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp.h"
#include "lwip/pbuf.h"
#include "snmp_gw_priv.h"
#include "snmp_msg.h"

static uint64_t s_now = 1000;
static bool s_route = true;
static bool s_queue_ok = true;
static uint16_t s_trap_port;
static sgw_trap_cfg_t s_cfg;

/* ---------------------------------------------------------------- lwIP port hooks */

u32_t sys_now(void) {
    return (u32_t)s_now;
}

uint32_t snmp_lwip_sysuptime_cs(void) {
    return (uint32_t)(s_now / 10u);
}

err_t snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port) {
    (void)handle;
    static unsigned char buf[2048];
    const u16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    char ip[GW_IP4_STR_SZ];
    gw_ip4_format(lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(dst))), ip);
    /* same substitution as snmp_transport.c (traps are always sent outside snmp_receive) */
    printf("PKT %s %u ", ip, (unsigned)((port == 162 && s_trap_port != 0) ? s_trap_port : port));
    for (u16_t i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
    putchar('\n');
    return ERR_OK;
}

u8_t snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result) {
    (void)handle;
    (void)dst;
    if (!s_route) {
        return 0; /* lwIP then answers ERR_RTE, like the device before link/DHCP */
    }
    ip_addr_set_ip4_u32_val(*result, lwip_htonl(0xC0A80102)); /* 192.168.1.2 */
    return 1;
}

const char *esp_err_to_name(int code) {
    static char b[16];
    snprintf(b, sizeof(b), "0x%x", code);
    return b;
}

/* lwIP USM hooks referenced by snmp_msg.c / snmpv3.c (no v3 requests reach this harness). */
err_t snmpv3_get_user(const char *username, snmpv3_auth_algo_t *auth_algo, u8_t *auth_key,
                      snmpv3_priv_algo_t *priv_algo, u8_t *priv_key) {
    (void)username;
    (void)auth_algo;
    (void)auth_key;
    (void)priv_algo;
    (void)priv_key;
    return ERR_VAL;
}
u8_t snmpv3_get_amount_of_users(void) {
    return 0;
}
err_t snmpv3_get_user_storagetype(const char *username, snmpv3_user_storagetype_t *type) {
    (void)username;
    (void)type;
    return ERR_VAL;
}
err_t snmpv3_get_username(char *username, u8_t index) {
    (void)username;
    (void)index;
    return ERR_VAL;
}
void snmpv3_get_engine_id(const char **id, u8_t *len) {
    static const char eid[] = {(char)0x80, 0x00, 0x7E, (char)0xD9, 0x04, 't', 'e', 's', 't'};
    *id = eid;
    *len = sizeof(eid);
}
err_t snmpv3_set_engine_id(const char *id, u8_t len) {
    (void)id;
    (void)len;
    return ERR_OK;
}
u32_t snmpv3_get_engine_boots(void) {
    return 1;
}
void snmpv3_set_engine_boots(u32_t boots) {
    (void)boots;
}
u32_t snmpv3_get_engine_time(void) {
    return 0;
}
void snmpv3_reset_engine_time(void) {
}
err_t snmpv3_auth(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, snmpv3_auth_algo_t algo,
                  u8_t *hmac_out) {
    (void)stream;
    (void)length;
    (void)key;
    (void)algo;
    (void)hmac_out;
    return ERR_ARG;
}
err_t snmpv3_crypt(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key, const u8_t *priv_param,
                   const u32_t engine_boots, const u32_t engine_time, snmpv3_priv_algo_t algo,
                   snmpv3_priv_mode_t mode) {
    (void)stream;
    (void)length;
    (void)key;
    (void)priv_param;
    (void)engine_boots;
    (void)engine_time;
    (void)algo;
    (void)mode;
    return ERR_ARG;
}
void snmpv3_password_to_key_sha(const u8_t *password, size_t passwordlen, const u8_t *engineID, u8_t engineLength,
                                u8_t *key) {
    (void)password;
    (void)passwordlen;
    (void)engineID;
    (void)engineLength;
    (void)key;
}
void snmpv3_password_to_key_md5(const u8_t *password, size_t passwordlen, const u8_t *engineID, u8_t engineLength,
                                u8_t *key) {
    (void)password;
    (void)passwordlen;
    (void)engineID;
    (void)engineLength;
    (void)key;
}

/* ---------------------------------------------------------------- fakes of other snmp_gw / components */

void snmp_transport_set_trap_port(uint16_t port) {
    s_trap_port = (port == 162) ? 0 : port;
}

uint64_t gw_time_mono_ms(void) {
    return s_now;
}
int64_t gw_time_wall_ms(void) {
    return 1760000000000LL; /* 2025-10-09T08:53:20Z */
}

const char *sgw_fw_version(void) {
    return "1.2.3-test";
}

static const sgw_dev_t s_dev = {.id = 0, .slave = 1, .enabled = true, .name = "MEX150 #1"};
const sgw_dev_t *sgw_dev_by_index(uint32_t idx) {
    return idx == 1 ? &s_dev : NULL;
}

esp_err_t cfg_get_section(cfg_section_t s, void *out, size_t size) {
    if (s != CFG_SEC_ALARMS || size != sizeof(cfg_alarms_t)) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, size);
    return ESP_OK;
}

const char *cfg_section_name(cfg_section_t s) {
    return s == CFG_SEC_SNMP ? "snmp" : "other";
}

esp_err_t sgw_post(const sgw_msg_t *m, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!s_queue_ok) {
        return ESP_ERR_TIMEOUT;
    }
    sgw_traps_on_msg(m); /* the agent task, run synchronously */
    return ESP_OK;
}

/* ---------------------------------------------------------------- driver */

static uint32_t ip_arg(const char *s) {
    uint32_t ip = 0;
    return gw_ip4_parse(s, &ip) ? ip : 0;
}

int main(void) {
    char line[512];
    char cmd[32];
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (fgets(line, sizeof(line), stdin) != NULL) {
        if (sscanf(line, "%31s", cmd) != 1) {
            continue;
        }
        const char *a = line + strlen(cmd) + (line[strlen(cmd)] == ' ' ? 1 : 0);
        if (!strcmp(cmd, "init")) {
            if (sgw_traps_sync_init() != ESP_OK) {
                puts("ERR");
            }
            sgw_traps_init();
            memset(&s_cfg, 0, sizeof(s_cfg));
        } else if (!strcmp(cmd, "clock")) {
            unsigned long long t;
            sscanf(a, "%llu", &t);
            s_now = t;
        } else if (!strcmp(cmd, "route")) {
            s_route = atoi(a) != 0;
        } else if (!strcmp(cmd, "queue")) {
            s_queue_ok = atoi(a) != 0;
        } else if (!strcmp(cmd, "target")) {
            char host[64], comm[64];
            unsigned port, ver, inform, en;
            if (sscanf(a, "%63s %u %u %u %u %63s", host, &port, &ver, &inform, &en, comm) == 6 &&
                s_cfg.n < GW_MAX_TRAP_TARGETS) {
                cfg_trap_t *t = &s_cfg.traps[s_cfg.n];
                gw_strlcpy(t->host, host, sizeof(t->host));
                t->port = (uint16_t)port;
                t->version = (uint8_t)ver;
                t->inform = inform != 0;
                t->enabled = en != 0;
                gw_strlcpy(s_cfg.community[s_cfg.n], comm, sizeof(s_cfg.community[0]));
                s_cfg.n++;
            }
        } else if (!strcmp(cmd, "apply")) {
            unsigned en, auth;
            sscanf(a, "%u %u", &en, &auth);
            s_cfg.enabled = en != 0;
            s_cfg.auth_traps = auth != 0;
            sgw_traps_configure(&s_cfg);
            memset(&s_cfg, 0, sizeof(s_cfg));
        } else if (!strcmp(cmd, "cold")) {
            sgw_traps_cold_start();
        } else if (!strcmp(cmd, "authfail")) {
            char ip[32];
            sscanf(a, "%31s", ip);
            sgw_traps_auth_fail(ip_arg(ip));
        } else if (!strcmp(cmd, "idle")) {
            sgw_traps_on_idle(s_now);
        } else if (!strcmp(cmd, "alarm")) {
            unsigned dev, code, sev, raised, seq;
            int value;
            sscanf(a, "%u %u %u %u %d %u", &dev, &code, &sev, &raised, &value, &seq);
            sgw_msg_t m = {.type = SGW_MSG_ALARM};
            m.u.alarm.dev = (uint8_t)dev;
            m.u.alarm.code = (uint16_t)code;
            m.u.alarm.sev = (uint8_t)sev;
            m.u.alarm.raised = raised != 0;
            m.u.alarm.value = (int16_t)value;
            m.u.alarm.seq = seq;
            m.u.alarm.ts_ms = gw_time_wall_ms();
            sgw_traps_on_msg(&m);
        } else if (!strcmp(cmd, "comm")) {
            unsigned dev, online;
            sscanf(a, "%u %u", &dev, &online);
            sgw_msg_t m = {.type = SGW_MSG_COMM};
            m.u.comm.dev = (uint8_t)dev;
            m.u.comm.online = online != 0;
            sgw_traps_on_msg(&m);
        } else if (!strcmp(cmd, "config")) {
            unsigned sec, rev;
            sscanf(a, "%u %u", &sec, &rev);
            sgw_msg_t m = {.type = SGW_MSG_CONFIG};
            m.u.config.section = (uint8_t)sec;
            m.u.config.rev = rev;
            sgw_traps_on_msg(&m);
        } else if (!strcmp(cmd, "fw")) {
            sgw_msg_t m = {.type = SGW_MSG_FIRMWARE};
            sscanf(a, "%31s", m.u.fw.version);
            sgw_traps_on_msg(&m);
        } else if (!strcmp(cmd, "ack")) {
            long req;
            char ip[32];
            sscanf(a, "%ld %31s", &req, ip);
            sgw_traps_inform_ack((int32_t)req, ip_arg(ip));
        } else if (!strcmp(cmd, "peer")) {
            char ip[32];
            char comm[SNMP_COMMUNITY_SZ];
            sscanf(a, "%31s", ip);
            if (sgw_traps_inform_peer(ip_arg(ip), comm)) {
                printf("PEER 1 %s\n", comm);
            } else {
                puts("PEER 0");
            }
        } else if (!strcmp(cmd, "test")) {
            unsigned timeout;
            sscanf(a, "%u", &timeout);
            snmp_gw_test_result_t res[GW_MAX_TRAP_TARGETS];
            size_t n = sgw_traps_test(res, GW_MAX_TRAP_TARGETS, timeout);
            printf("TEST %u", (unsigned)n);
            for (size_t i = 0; i < n; i++) {
                printf(" %s:%d", res[i].host, res[i].ok ? 1 : 0);
            }
            putchar('\n');
        } else if (!strcmp(cmd, "stats")) {
            printf("STATS %lu %lu %lu\n", (unsigned long)sgw_traps_sent(), (unsigned long)sgw_traps_dropped(),
                   (unsigned long)sgw_informs_failed());
        } else {
            printf("ERR unknown command %s\n", cmd);
        }
        puts("OK");
    }
    return 0;
}
