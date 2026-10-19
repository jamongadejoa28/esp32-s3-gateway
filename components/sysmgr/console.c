/*
 * USB-Serial-JTAG console (sysmgr.h console_start): esp_console REPL task "console" (prio 1).
 * Commands: status, ip, net-reset, factory-reset --yes [--keep-network], reboot, log, ap, time.
 * Physical access is the authentication; destructive commands still need an explicit flag where
 * DESIGN.md asks for one. Output goes to stdout (the same USB-Serial-JTAG console as ESP_LOG).
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alarm/alarm.h"
#include "esp_app_desc.h"
#include "esp_console.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "mex150/service.h"
#include "net/net.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"

static const char *TAG = "console";

#define CONSOLE_USER "@console"
#define CONSOLE_LOG_MAX 50

static void print_ip(const char *label, uint32_t ip) {
    printf("%s%u.%u.%u.%u\n", label, (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 8) & 0xFF),
           (unsigned)(ip & 0xFF));
}

static void print_time(void) {
    const int64_t ms = gw_time_wall_ms();
    char iso[32];
    if (ms && gw_time_iso8601(ms, iso, sizeof(iso))) {
        printf("time:      %s (UTC)\n", iso);
    } else {
        printf("time:      not set\n");
    }
}

static int cmd_status(int argc, char **argv) {
    (void)argc;
    (void)argv;
    static sys_info_t info;
    static cfg_modbus_t mb;
    static mex_snapshot_t snap;
    sys_get_info(&info);
    printf("firmware:  %s (built %s, IDF %s)\n", info.fw, info.build, info.idf);
    printf("partition: %s (%s), boots %" PRIu32 ", reset reason %u\n", info.part_running, info.part_state,
           info.boot_count, info.reset_reason);
    printf("uptime:    %" PRIu32 " s\n", info.uptime_s);
    print_time();
    printf("heap:      internal %" PRIu32 " free (min %" PRIu32 "), PSRAM %" PRIu32 " free\n", info.heap_int_free,
           info.heap_int_min, info.psram_free);
    printf("health:    stale heartbeats 0x%02" PRIx32 ", dropped events %" PRIu32 "\n", info.hb_stale, info.evt_dropped);
    uint16_t sev[4] = {0};
    const uint32_t total = alarm_counts(sev);
    printf("alarms:    %" PRIu32 " active (critical %u, major %u, minor %u, info %u)\n", total, sev[ALM_SEV_CRITICAL],
           sev[ALM_SEV_MAJOR], sev[ALM_SEV_MINOR], sev[ALM_SEV_INFO]);
    if (cfg_get_section(CFG_SEC_MODBUS, &mb, sizeof(mb)) == ESP_OK) {
        for (size_t i = 0; i < mb.n_devices && i < GW_MAX_DEVICES; i++) {
            const mex_dev_cfg_t *d = &mb.devices[i];
            const bool ok = mex_service_snapshot(d->id, &snap);
            printf("device %u:  \"%s\" slave %u %s%s, seq %" PRIu32 "\n", d->id, d->name, d->slave,
                   d->enabled ? "" : "disabled ", ok && snap.online ? "online" : "offline", ok ? snap.seq : 0);
        }
    }
    sys_print_tasks();
    return 0;
}

static int cmd_ip(int argc, char **argv) {
    (void)argc;
    (void)argv;
    static net_status_t st;
    net_get_status(&st);
    printf("hostname:  %s\n", st.hostname);
    printf("ethernet:  link %s, %s, mode %s, MAC %02x:%02x:%02x:%02x:%02x:%02x, link changes %" PRIu32 "\n",
           st.eth_link ? "up" : "down", st.eth_has_ip ? "addressed" : "no address",
           st.eth_mode == CFG_ETH_DHCP ? "dhcp" : "static", st.eth_mac[0], st.eth_mac[1], st.eth_mac[2], st.eth_mac[3],
           st.eth_mac[4], st.eth_mac[5], st.link_changes);
    if (st.eth_has_ip) {
        print_ip("  ip       ", st.ip);
        print_ip("  mask     ", st.mask);
        print_ip("  gateway  ", st.gw);
        print_ip("  dns1     ", st.dns1);
        print_ip("  dns2     ", st.dns2);
    }
    printf("recovery AP: %s, SSID \"%s\", clients %u", st.ap_active ? "on" : "off", st.ap_ssid, st.ap_clients);
    if (st.ap_active && st.ap_off_in_s) {
        printf(", off in %" PRIu32 " s", st.ap_off_in_s);
    }
    printf("\n");
    if (st.prov != NET_PROV_NONE) {
        printf("provisional change: state %u, %" PRIu32 " s left\n", st.prov, st.prov_left_s);
    }
    printf("sntp:      %s\n", st.sntp_synced ? "synchronized" : "not synchronized");
    return 0;
}

static int cmd_net_reset(int argc, char **argv) {
    (void)argc;
    (void)argv;
    const esp_err_t err = net_reset_defaults(CONSOLE_USER);
    printf("net-reset: %s\n", err == ESP_OK ? "factory network settings applied" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static int cmd_factory_reset(int argc, char **argv) {
    bool yes = false, keep = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--yes")) {
            yes = true;
        } else if (!strcmp(argv[i], "--keep-network")) {
            keep = true;
        } else {
            printf("unknown option %s\n", argv[i]);
            return 1;
        }
    }
    if (!yes) {
        printf("This erases configuration, users and secrets%s and reboots.\n"
               "Run: factory-reset --yes [--keep-network]\n",
               keep ? "" : ", logs and history");
        return 1;
    }
    const esp_err_t err = sys_factory_reset(keep, CONSOLE_USER);
    printf("factory-reset: %s\n", err == ESP_OK ? "done, rebooting" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static int cmd_reboot(int argc, char **argv) {
    (void)argc;
    (void)argv;
    const esp_err_t err = sys_reboot(GW_REBOOT_CONSOLE, 500, CONSOLE_USER);
    printf("reboot: %s\n", err == ESP_OK ? "scheduled" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static bool parse_level(const char *s, esp_log_level_t *out) {
    static const char *const N[] = {"none", "error", "warn", "info", "debug", "verbose"};
    for (int i = 0; i < 6; i++) {
        if (!strcmp(s, N[i])) {
            *out = (esp_log_level_t)i;
            return true;
        }
    }
    return false;
}

static int cmd_log(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "level")) {
        esp_log_level_t lvl;
        if (argc != 4 || !parse_level(argv[3], &lvl)) {
            printf("usage: log level <tag|*> <none|error|warn|info|debug|verbose>\n");
            return 1;
        }
        esp_log_level_set(argv[2], lvl);
        printf("log level of %s set to %s\n", argv[2], argv[3]);
        return 0;
    }
    evlog_kind_t kind = EVLOG_EVENTS;
    int argi = 1;
    if (argc > argi && (!strcmp(argv[argi], "audit") || !strcmp(argv[argi], "events"))) {
        kind = !strcmp(argv[argi], "audit") ? EVLOG_AUDIT : EVLOG_EVENTS;
        argi++;
    }
    long n = 20;
    if (argc > argi) {
        char *end;
        n = strtol(argv[argi], &end, 10);
        if (*end || n < 1 || n > CONSOLE_LOG_MAX) {
            printf("usage: log [events|audit] [1..%d] | log level <tag> <level>\n", CONSOLE_LOG_MAX);
            return 1;
        }
    }
    static EXT_RAM_BSS_ATTR evlog_rec_t recs[CONSOLE_LOG_MAX];
    const evlog_filter_t any = EVLOG_FILTER_ANY;
    const size_t got = evlog_query(kind, 0, (size_t)n, &any, recs, NULL);
    for (size_t i = 0; i < got; i++) {
        const evlog_rec_t *r = &recs[i];
        char ts[32] = "-";
        if (r->ts) {
            gw_time_iso8601((int64_t)r->ts * 1000, ts, sizeof(ts));
        }
        char user[sizeof(r->user) + 1];
        memcpy(user, r->user, sizeof(r->user));
        user[sizeof(r->user)] = '\0';
        printf("%6" PRIu32 " %s %-14s dev=%d code=%u sev=%u value=%d user=%s extra=%" PRIu32 "\n", r->seq, ts,
               evlog_type_name(r->type), r->dev == EVLOG_DEV_NONE ? -1 : (int)r->dev, r->code, r->sev, r->value,
               user[0] ? user : "-", r->extra);
    }
    if (!got) {
        printf("(no records)\n");
    }
    return 0;
}

static int cmd_ap(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "start") && strcmp(argv[1], "stop"))) {
        printf("usage: ap start|stop\n");
        return 1;
    }
    const esp_err_t err = !strcmp(argv[1], "start") ? net_ap_start(NET_AP_REASON_CONSOLE) : net_ap_stop();
    printf("ap %s: %s\n", argv[1], esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static int cmd_time(int argc, char **argv) {
    if (argc == 1) {
        print_time();
        return 0;
    }
    char *end;
    const long long s = strtoll(argv[1], &end, 10);
    if (argc != 2 || *end || s < GW_TIME_VALID_MIN_S) {
        printf("usage: time [<UTC epoch seconds>=%lld]\n", (long long)GW_TIME_VALID_MIN_S);
        return 1;
    }
    if (!gw_time_set_wall_ms((int64_t)s * 1000, GW_TIME_SRC_CONSOLE, CONSOLE_USER)) {
        printf("time: rejected\n");
        return 1;
    }
    print_time();
    return 0;
}

esp_err_t console_start(void) {
    static esp_console_repl_t *repl;
    if (repl) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_console_repl_config_t rc = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    rc.prompt = "mestio> ";
    rc.task_stack_size = 4096;
    rc.task_priority = 1;
    rc.max_cmdline_length = 128;
    rc.max_history_len = 16;
    const esp_console_dev_usb_serial_jtag_config_t hw = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    esp_err_t err = esp_console_new_repl_usb_serial_jtag(&hw, &rc, &repl);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "REPL: %s", esp_err_to_name(err));
        repl = NULL;
        return err;
    }
    static const esp_console_cmd_t CMDS[] = {
        {.command = "status", .help = "Firmware, health, alarms, devices and tasks", .func = cmd_status},
        {.command = "ip", .help = "Ethernet, recovery AP and SNTP state", .func = cmd_ip},
        {.command = "net-reset", .help = "Apply factory network settings and AP PSK now", .func = cmd_net_reset},
        {.command = "factory-reset",
         .help = "Erase configuration/users/secrets (and logs) and reboot",
         .hint = "--yes [--keep-network]",
         .func = cmd_factory_reset},
        {.command = "reboot", .help = "Restart the gateway", .func = cmd_reboot},
        {.command = "log",
         .help = "Show recent event/audit records, or set a log level",
         .hint = "[events|audit] [n] | level <tag> <level>",
         .func = cmd_log},
        {.command = "ap", .help = "Start or stop the recovery AP", .hint = "start|stop", .func = cmd_ap},
        {.command = "time", .help = "Show the clock, or set it (UTC epoch seconds)", .hint = "[epoch_s]", .func = cmd_time},
    };
    for (size_t i = 0; i < sizeof(CMDS) / sizeof(CMDS[0]) && err == ESP_OK; i++) {
        err = esp_console_cmd_register(&CMDS[i]);
    }
    if (err == ESP_OK) {
        err = esp_console_register_help_command();
    }
    if (err == ESP_OK) {
        err = esp_console_start_repl(repl);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "console: %s", esp_err_to_name(err));
    }
    return err;
}
