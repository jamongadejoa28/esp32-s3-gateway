/* Host driver for components/snmp_gw/snmp_logic.c (tests/test_snmp_logic.py).
 *
 * Reads one command per line from stdin and prints one result line per command, so the Python
 * tests can run long randomized sequences against reference models. Commands:
 *   tb_init RATE BURST | tb_take NOW                         -> 1/0
 *   cc_init | cc_event DEV ONLINE NOW | cc_poll NOW          -> "dev:online ..." (or "-")
 *   ev_init | ev_ins SEQ | ev_dump | ev_find SEQ | ev_next AFTER
 *   inf_init | inf_add TARGET IP REQ NOW GEN | inf_resent SLOT REQ NOW | inf_match REQ IP | inf_peer IP
 *   inf_due NOW | inf_retry SLOT | inf_free SLOT | inf_drop TARGET | inf_free_slots
 *   usm V3 EN0 NAME0 ACC0 KEYS0 EN1 NAME1 ACC1 KEYS1          (NAME "-" = empty) -> count
 *   usm_find NAME                                             -> "slot access auth0 priv0" or NONE
 *   usm_at IDX                                                -> name or NONE
 *   text HEX MAX                                              -> 1/0 (snmp_text_ok)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmp_logic.h"

static snmp_tbucket_t tb;
static snmp_comm_coalesce_t cc;
static snmp_evring_t ev;
static snmp_inform_table_t inf;
static snmp_usm_table_t usm;
static cfg_snmp_t ucfg;
static sec_v3_keys_t ukeys[GW_MAX_SNMP_V3_USERS];

static int hexval(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

int main(void) {
    char line[512];
    char cmd[32];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        if (sscanf(line, "%31s", cmd) != 1) {
            continue;
        }
        const char *a = line + strlen(cmd);
        if (!strcmp(cmd, "tb_init")) {
            unsigned r, b;
            sscanf(a, "%u %u", &r, &b);
            snmp_tb_init(&tb, r, b);
            puts("ok");
        } else if (!strcmp(cmd, "tb_take")) {
            unsigned long long now;
            sscanf(a, "%llu", &now);
            printf("%d\n", snmp_tb_take(&tb, now) ? 1 : 0);
        } else if (!strcmp(cmd, "cc_init")) {
            snmp_cc_init(&cc);
            puts("ok");
        } else if (!strcmp(cmd, "cc_event")) {
            unsigned dev, online;
            unsigned long long now;
            sscanf(a, "%u %u %llu", &dev, &online, &now);
            snmp_cc_event(&cc, (uint8_t)dev, online != 0, now);
            puts("ok");
        } else if (!strcmp(cmd, "cc_poll")) {
            unsigned long long now;
            sscanf(a, "%llu", &now);
            snmp_comm_report_t rep[GW_MAX_DEVICES];
            size_t n = snmp_cc_poll(&cc, now, rep, GW_MAX_DEVICES);
            if (n == 0) {
                puts("-");
            } else {
                for (size_t i = 0; i < n; i++) {
                    printf("%s%u:%u", i ? " " : "", rep[i].dev, rep[i].online ? 1u : 0u);
                }
                putchar('\n');
            }
        } else if (!strcmp(cmd, "ev_init")) {
            snmp_evring_init(&ev);
            puts("ok");
        } else if (!strcmp(cmd, "ev_ins")) {
            unsigned long seq;
            sscanf(a, "%lu", &seq);
            snmp_alarm_ev_t e = {.seq = (uint32_t)seq, .ts_ms = (int64_t)seq * 1000, .type = 1, .code = 117};
            printf("%d\n", snmp_evring_insert(&ev, &e) ? 1 : 0);
        } else if (!strcmp(cmd, "ev_dump")) {
            if (ev.n == 0) {
                puts("-");
            } else {
                for (size_t i = 0; i < ev.n; i++) {
                    printf("%s%lu", i ? " " : "", (unsigned long)ev.ev[i].seq);
                }
                putchar('\n');
            }
        } else if (!strcmp(cmd, "ev_find") || !strcmp(cmd, "ev_next")) {
            unsigned long seq;
            sscanf(a, "%lu", &seq);
            const snmp_alarm_ev_t *e =
                !strcmp(cmd, "ev_find") ? snmp_evring_find(&ev, (uint32_t)seq) : snmp_evring_next(&ev, (uint32_t)seq);
            printf("%lu\n", e ? (unsigned long)e->seq : 0ul);
        } else if (!strcmp(cmd, "inf_init")) {
            snmp_inf_init(&inf);
            puts("ok");
        } else if (!strcmp(cmd, "inf_add")) {
            unsigned t, gen;
            unsigned long ip;
            long req;
            unsigned long long now;
            sscanf(a, "%u %lu %ld %llu %u", &t, &ip, &req, &now, &gen);
            bool evicted = false;
            snmp_inform_t old;
            uint8_t msg[3] = {(uint8_t)t, 0xAB, 0xCD};
            int k = snmp_inf_add(&inf, (uint8_t)t, (uint32_t)ip, (int32_t)req, now, gen, msg, sizeof(msg), &evicted, &old);
            printf("%d %d %ld\n", k, evicted ? 1 : 0, evicted ? (long)old.req_id[0] : -1L);
        } else if (!strcmp(cmd, "inf_resent")) {
            int k;
            long req;
            unsigned long long now;
            sscanf(a, "%d %ld %llu", &k, &req, &now);
            snmp_inf_resent(&inf, k, (int32_t)req, now);
            printf("%u\n", (unsigned)inf.slot[k].sends);
        } else if (!strcmp(cmd, "inf_match")) {
            long req;
            unsigned long ip;
            sscanf(a, "%ld %lu", &req, &ip);
            printf("%d\n", snmp_inf_match(&inf, (int32_t)req, (uint32_t)ip));
        } else if (!strcmp(cmd, "inf_peer")) {
            unsigned long ip;
            sscanf(a, "%lu", &ip);
            printf("%d\n", snmp_inf_peer(&inf, (uint32_t)ip));
        } else if (!strcmp(cmd, "inf_due")) {
            unsigned long long now;
            sscanf(a, "%llu", &now);
            printf("%d\n", snmp_inf_due(&inf, now));
        } else if (!strcmp(cmd, "inf_retry")) {
            int k;
            sscanf(a, "%d", &k);
            printf("%d\n", snmp_inf_can_retry(&inf, k) ? 1 : 0);
        } else if (!strcmp(cmd, "inf_free")) {
            int k;
            sscanf(a, "%d", &k);
            snmp_inf_free(&inf, k);
            puts("ok");
        } else if (!strcmp(cmd, "inf_drop")) {
            unsigned t;
            sscanf(a, "%u", &t);
            printf("%u\n", (unsigned)snmp_inf_drop_target(&inf, (uint8_t)t));
        } else if (!strcmp(cmd, "inf_free_slots")) {
            printf("%u\n", (unsigned)snmp_inf_free_slots(&inf));
        } else if (!strcmp(cmd, "usm")) {
            unsigned v3, en[2], acc[2], keys[2];
            char name[2][64];
            sscanf(a, "%u %u %63s %u %u %u %63s %u %u", &v3, &en[0], name[0], &acc[0], &keys[0], &en[1], name[1],
                   &acc[1], &keys[1]);
            memset(&ucfg, 0, sizeof(ucfg));
            memset(ukeys, 0, sizeof(ukeys));
            ucfg.v3 = v3 != 0;
            for (int i = 0; i < 2; i++) {
                ucfg.users[i].enabled = en[i] != 0;
                ucfg.users[i].access = (uint8_t)acc[i];
                if (strcmp(name[i], "-") != 0) {
                    /* deliberately not gw_strlcpy: an over-long name must reach the table unterminated-safe */
                    strncpy(ucfg.users[i].name, name[i], sizeof(ucfg.users[i].name));
                }
                ukeys[i].set = keys[i] != 0;
                memset(ukeys[i].auth_key, 0x10 + i, SEC_V3_KEY_LEN);
                memset(ukeys[i].priv_key, 0x20 + i, SEC_V3_KEY_LEN);
            }
            snmp_usm_build(&usm, &ucfg, ukeys);
            printf("%u\n", (unsigned)snmp_usm_count(&usm));
        } else if (!strcmp(cmd, "usm_find")) {
            char name[64] = "";
            sscanf(a, "%63s", name);
            const snmp_usm_user_t *u = snmp_usm_find(&usm, strcmp(name, "-") ? name : "");
            if (u == NULL) {
                puts("NONE");
            } else {
                printf("%d %u %02x %02x\n", (int)(u - usm.user), (unsigned)u->access, u->auth_key[0], u->priv_key[0]);
            }
        } else if (!strcmp(cmd, "usm_at")) {
            unsigned idx;
            sscanf(a, "%u", &idx);
            const snmp_usm_user_t *u = snmp_usm_at(&usm, (uint8_t)idx);
            puts(u ? u->name : "NONE");
        } else if (!strcmp(cmd, "text")) {
            char hex[400] = "";
            unsigned max;
            sscanf(a, "%399s %u", hex, &max);
            uint8_t buf[200];
            size_t n = 0;
            if (strcmp(hex, "-") != 0) {
                for (size_t i = 0; hex[i] && hex[i + 1] && n < sizeof(buf); i += 2) {
                    buf[n++] = (uint8_t)(hexval(hex[i]) * 16 + hexval(hex[i + 1]));
                }
            }
            printf("%d\n", snmp_text_ok(buf, n, max) ? 1 : 0);
        } else {
            printf("ERR %s\n", cmd);
        }
        fflush(stdout);
    }
    return 0;
}
