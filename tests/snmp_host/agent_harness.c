/* Host harness: the real lwIP SNMP agent core + the gateway's usm.c, registry.c, mib_system.c,
 * mib_mex_setpoint.c, mib_util.c and snmp_logic.c, on a UDP socket at 127.0.0.1, so pysnmp can act
 * as the manager (tests/test_snmp_agent_host.py). Everything the device takes from other components
 * or FreeRTOS is faked below; the per-datagram header peek and community mapping are the transport's
 * own (snmp_lwip/snmp_transport_util.h), the context handling mirrors snmp_transport.c.
 *
 * Fixed set-up: engine ID 80 00 7E D9 03 24 6F 28 A0 B1 C2 (PEN 32473, format 3, MAC), boots 5,
 * users gwmonitor (RO, slot 0) and gwadmin (RW, slot 1) with keys localized from the passphrases in
 * argv, v1/v2c communities "pub-ro-123" / "priv-rw-456", one device (id 0) with a fake snapshot.
 * Prints "PORT <n>" on stdout, then one line per notable event (COMMIT ..., WRITE ..., LASTWRITE ...).
 * Exits after 30 s without a datagram (the test kills it earlier). */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "gw_core/gw_crypto.h"
#include "gw_core/gw_ident.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/pbuf.h"
#include "mex150/model.h"
#include "snmp_gw_priv.h"
#include "snmp_msg.h"
#include "snmp_transport_util.h"

static int s_sock = -1;
static uint64_t s_t0_ms;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void event(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

/* ---------------------------------------------------------------- lwIP port hooks */

u32_t sys_now(void) {
    return (u32_t)(now_ms() - s_t0_ms);
}

err_t snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port) {
    (void)handle;
    unsigned char buf[2048];
    u16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    to.sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(dst));
    return sendto(s_sock, buf, n, 0, (struct sockaddr *)&to, sizeof(to)) == (ssize_t)n ? ERR_OK : ERR_IF;
}

u8_t snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result) {
    (void)handle;
    (void)dst;
    ip_addr_set_ip4_u32_val(*result, htonl(0x7F000001));
    return 1;
}

const char *esp_err_to_name(int code) {
    static char b[16];
    snprintf(b, sizeof(b), "0x%x", code);
    return b;
}

/* ---------------------------------------------------------------- transport context (mirror) */

static struct {
    char user[SNMP_COMMUNITY_SZ];
    snmp_user_access_t access;
    bool user_set;
    uint8_t version;
    uint32_t peer;
} s_ctx;

void snmp_ctx_set_user(const char *user, snmp_user_access_t access) {
    if (s_ctx.user_set) {
        return;
    }
    s_ctx.user_set = true;
    gw_strlcpy(s_ctx.user, user ? user : "", sizeof(s_ctx.user));
    s_ctx.access = access;
}
bool snmp_ctx_can_write(void) {
    return s_ctx.version != SGW_SNMP_V3 || s_ctx.access == SNMP_ACCESS_RW;
}
const char *snmp_ctx_user(void) {
    return s_ctx.user;
}
uint8_t snmp_ctx_version(void) {
    return s_ctx.version;
}
uint32_t snmp_ctx_peer_ip(void) {
    return s_ctx.peer;
}
bool snmp_transport_in_agent_thread(void) {
    return true;
}
uint32_t snmp_transport_dropped(void) {
    return 0;
}

/* ---------------------------------------------------------------- agent.c accessors (fakes) */

static uint8_t s_eid[GW_ENGINE_ID_LEN] = {0x80, 0x00, 0x7E, 0xD9, 0x03, 0x24, 0x6F, 0x28, 0xA0, 0xB1, 0xC2};
static uint32_t s_boots = 5;
static uint64_t s_time_base;
static char s_sys[3][GW_TEXT_SZ] = {"ops@example.com", "mestio-gw-b1c2", "Lab"};
static const sgw_dev_t s_dev = {.id = 0, .slave = 1, .enabled = true, .name = "MEX150"};

const uint8_t *sgw_engine_id(uint8_t *len) {
    *len = sizeof(s_eid);
    return s_eid;
}
uint32_t sgw_engine_boots(void) {
    return s_boots;
}
void sgw_engine_boots_set(uint32_t b) {
    s_boots = b;
}
uint32_t sgw_engine_time(void) {
    return (uint32_t)((now_ms() - s_time_base) / 1000u);
}
void sgw_engine_time_reset(void) {
    s_time_base = now_ms();
}
const char *sgw_sys_string(sgw_sys_t w) {
    return (unsigned)w < 3 ? s_sys[w] : "";
}
void sgw_sys_string_set(sgw_sys_t w, const char *v) {
    gw_strlcpy(s_sys[w], v, sizeof(s_sys[w]));
}
const char *sgw_fw_version(void) {
    return "1.2.3-test";
}
uint32_t sgw_uptime_cs(void) {
    return sys_now() / 10u;
}
uint8_t sgw_dev_count(void) {
    return 1;
}
const sgw_dev_t *sgw_dev_at(uint8_t i) {
    return i == 0 ? &s_dev : NULL;
}
const sgw_dev_t *sgw_dev_by_index(uint32_t idx) {
    return idx == 1 ? &s_dev : NULL;
}
void sgw_last_write_put(const sgw_last_write_t *w) {
    event("LASTWRITE state=%u addr=%u raw=%ld by=%s", (unsigned)w->state, (unsigned)w->addr, (long)w->raw_req,
          w->by);
}
void sgw_last_write_put_pending(const sgw_last_write_t *w) {
    sgw_last_write_put(w);
}

/* ---------------------------------------------------------------- store fakes */

static cfg_snmp_t s_cfg;

esp_err_t cfg_get_section(cfg_section_t s, void *out, size_t size) {
    if (s != CFG_SEC_SNMP || size != sizeof(s_cfg)) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(out, &s_cfg, sizeof(s_cfg));
    return ESP_OK;
}

esp_err_t cfg_commit(cfg_section_t s, const void *sec, size_t size, const char *by, cfg_verr_t *err) {
    (void)err;
    if (s != CFG_SEC_SNMP || size != sizeof(s_cfg)) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(&s_cfg, sec, sizeof(s_cfg));
    event("COMMIT snmp by=%s name=%s contact=%s location=%s", by, s_cfg.sys_name, s_cfg.sys_contact,
          s_cfg.sys_location);
    return ESP_OK;
}

/* ---------------------------------------------------------------- mex150 fakes */

/* Register table from regmap.def (data only; the same X-macro expansion as regmap.c). */
const mex_reg_t mex_regs[MEX_REG_COUNT] = {
#define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en)                  \
    {#key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en},
#include "mex150/regmap_x.h"
};

static uint16_t s_regs[MEX_REGS_LEN];
static bool s_running;
static int s_write_mode; /* argv: 0 applied, 1 rejected (exception 2), 2 uncertain, 3 pending */

const mex_reg_t *mex_reg_find(uint16_t addr) {
    for (size_t i = 0; i < MEX_REG_COUNT; i++) {
        if (mex_regs[i].addr == addr) {
            return &mex_regs[i];
        }
    }
    return NULL;
}

bool mex_service_snapshot(uint8_t dev, mex_snapshot_t *out) {
    memset(out, 0, sizeof(*out));
    if (dev != 0) {
        return false;
    }
    memcpy(out->regs, s_regs, sizeof(s_regs));
    out->online = true;
    out->seq = 7;
    out->mono_ms = gw_time_mono_ms();
    out->slow_valid = true;
    out->measurement_valid = true;
    return true;
}

/* Simplified stand-in for model.c's checks (enough to drive the SNMP error mapping). */
mex_reason_t mex_check_write_snap(uint16_t addr, int32_t raw, const mex_snapshot_t *s, uint64_t now) {
    (void)s;
    (void)now;
    const mex_reg_t *r = mex_reg_find(addr);
    if (r == NULL) {
        return MEX_R_UNKNOWN;
    }
    if (!r->writable) {
        return MEX_R_READONLY;
    }
    if ((r->flags & MEX_F_STOPPED) && s_running) {
        return MEX_R_INTERLOCK;
    }
    if ((raw < r->min || raw > r->max) && raw != r->disabled) {
        return MEX_R_RANGE;
    }
    return MEX_R_OK;
}

int32_t mex_snap_raw(const mex_snapshot_t *s, uint16_t addr) {
    return (int16_t)s->regs[mex_reg_index(addr)];
}

const char *mex_reason_name(int reason, char *buf, size_t cap) {
    snprintf(buf, cap, "reason%d", reason);
    return buf;
}

esp_err_t mex_service_write(uint8_t dev, uint16_t addr, int32_t raw, const char *who, uint32_t wait_ms,
                            mex_wresult_t *out) {
    event("WRITE dev=%u addr=%u raw=%ld who=%s wait=%lu", (unsigned)dev, (unsigned)addr, (long)raw, who,
          (unsigned long)wait_ms);
    memset(out, 0, sizeof(*out));
    out->cmd = 42;
    out->dev = dev;
    out->addr = addr;
    out->raw_req = raw;
    switch (s_write_mode) {
    case 1:
        out->state = MEX_W_REJECTED;
        out->reason = MEX_R_EXCEPTION(2);
        break;
    case 2:
        out->state = MEX_W_UNCERTAIN;
        out->reason = MEX_R_VERIFY;
        break;
    case 3:
        out->state = MEX_W_PENDING;
        break;
    default:
        out->state = MEX_W_APPLIED;
        s_regs[mex_reg_index(addr)] = (uint16_t)raw;
        break;
    }
    return ESP_OK;
}

uint64_t gw_time_mono_ms(void) {
    return now_ms();
}
int64_t gw_time_wall_ms(void) {
    return 1760000000000LL;
}

/* ---------------------------------------------------------------- receive loop (mirrors snmp_transport.c) */

static const char RO[] = "pub-ro-123";
static const char RW[] = "priv-rw-456";
static const char V3_COMMUNITY[] = "\x01usm";

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s monitor_auth monitor_priv admin_auth admin_priv write_mode\n", argv[0]);
        return 2;
    }
    s_t0_ms = now_ms();
    s_time_base = s_t0_ms;
    s_write_mode = atoi(argv[5]);
    s_regs[mex_reg_index(40012)] = 230;
    if (gw_crypto_init() != 0) {
        return 1;
    }

    /* configuration: v3 users with localized keys (what snmp_gw_localize_key stores in secrets) */
    memset(&s_cfg, 0, sizeof(s_cfg));
    s_cfg.enabled = s_cfg.v2c = s_cfg.v3 = true;
    gw_strlcpy(s_cfg.users[0].name, "gwmonitor", sizeof(s_cfg.users[0].name));
    s_cfg.users[0].access = CFG_SNMP_RO;
    s_cfg.users[0].enabled = true;
    gw_strlcpy(s_cfg.users[1].name, "gwadmin", sizeof(s_cfg.users[1].name));
    s_cfg.users[1].access = CFG_SNMP_RW;
    s_cfg.users[1].enabled = true;
    sec_v3_keys_t keys[GW_MAX_SNMP_V3_USERS];
    memset(keys, 0, sizeof(keys));
    for (int u = 0; u < 2; u++) {
        if (snmp_localize_key_for(argv[1 + 2 * u], s_eid, sizeof(s_eid), keys[u].auth_key) != 0 ||
            snmp_localize_key_for(argv[2 + 2 * u], s_eid, sizeof(s_eid), keys[u].priv_key) != 0) {
            fprintf(stderr, "bad passphrase\n");
            return 2;
        }
        keys[u].set = true;
    }
    sgw_usm_configure(&s_cfg, keys);
    gw_secure_zero(keys, sizeof(keys));

    if (snmp_registry_add(&sgw_mod_system) || snmp_registry_add(&sgw_mod_framework) ||
        snmp_registry_add(&sgw_mod_usm) || snmp_registry_add(&sgw_mod_mex_setpoint) ||
        snmp_registry_start()) {
        fprintf(stderr, "registry failed\n");
        return 1;
    }
    snmp_set_auth_traps_enabled(0);
    snmp_v1_enable(1);
    snmp_v2c_enable(1);
    snmp_v3_enable(1);

    s_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = 0};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (s_sock < 0 || bind(s_sock, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(s_sock, (struct sockaddr *)&a, &al) != 0) {
        perror("socket");
        return 1;
    }
    event("PORT %u", (unsigned)ntohs(a.sin_port));

    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s_sock, &fds);
        struct timeval tv = {.tv_sec = 30};
        int r = select(s_sock + 1, &fds, NULL, NULL, &tv);
        if (r <= 0) {
            return r == 0 ? 0 : 1;
        }
        unsigned char buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) {
            continue;
        }
        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)n, PBUF_RAM);
        if (p == NULL) {
            continue;
        }
        pbuf_take(p, buf, (u16_t)n);
        /* the transport's own per-datagram decisions (snmp_lwip/snmp_transport_util.h) */
        int pdu_tag;
        char community[SNMP_COMMUNITY_SZ];
        int version = snmp_tr_peek(buf, (size_t)n, &pdu_tag, community);
        memset(&s_ctx, 0, sizeof(s_ctx));
        s_ctx.version = (uint8_t)(version < 0 ? 0 : version);
        s_ctx.peer = ntohl(from.sin_addr.s_addr);
        switch (snmp_tr_pick_communities(version, community, RW)) {
        case SNMP_TR_COMM_V3:
            snmp_set_community(V3_COMMUNITY);
            snmp_set_community_write(V3_COMMUNITY);
            break;
        case SNMP_TR_COMM_RW:
            snmp_set_community(RW);
            snmp_set_community_write(RW);
            break;
        default:
            snmp_set_community(RO);
            snmp_set_community_write(RW);
            break;
        }
        ip_addr_t src;
        ip_addr_set_ip4_u32_val(src, from.sin_addr.s_addr);
        const u32_t before =
            snmp_stats.unknownusernames + snmp_stats.unsupportedseclevels + snmp_stats.wrongdigests;
        snmp_receive(&s_sock, p, &src, ntohs(from.sin_port));
        pbuf_free(p);
        if (snmp_stats.unknownusernames + snmp_stats.unsupportedseclevels + snmp_stats.wrongdigests !=
            before) {
            event("USMSTATS unknown=%lu seclevel=%lu digest=%lu ctxuser=%s",
                  (unsigned long)snmp_stats.unknownusernames, (unsigned long)snmp_stats.unsupportedseclevels,
                  (unsigned long)snmp_stats.wrongdigests, s_ctx.user);
        }
    }
}
