/*
 * net_mgr - network state machine (contract: net/net.h).
 *
 * Threading
 *   - s_lock (leaf mutex) protects `s` (configs in effect, provisional FSM, interface state). No
 *     other module's API is called while it is held, except gw_events_post(..., 0) is NOT done
 *     under it either (events are built under the lock and posted after unlocking).
 *   - s_fast (allowlist, addresses, hostname) is copied in/out under a spinlock critical section so
 *     the per-request checks (net_ip_allowed/net_host_allowed) never block on a mutex.
 *   - The "net_mgr" task owns every esp_netif/esp_wifi/SNTP reconfiguration; the public API and the
 *     IDF/gw_evt event handlers only update state and queue commands (non-blocking).
 * Pure decision logic (provisional FSM, AP fallback/idle policy) is in net_prov.c (host-tested).
 */
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "board/board.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "lwip/dns.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "lwip_hooks/net_lwip_hooks.h"
#include "gw_core/gw_health.h"
#include "net/ip_filter.h"
#include "net/net.h"
#include "net_priv.h"
#include "net_prov.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/secrets.h"

static const char *TAG = "net";

_Static_assert(NET_HOOK_AP_IP_HOST == CFG_AP_IP, "lwIP strong-host hook must use the AP address");

/* ------------------------------------------------------------------------------------------------ */

typedef struct {
    ip_filter_t filter;
    uint32_t eth_ip, eth_mask; /* 0 when Ethernet has no address */
    bool ap_active;
    char hostname[GW_HOSTNAME_SZ];
} net_fast_t;

typedef enum {
    CMD_WAKE = 0, /* run the tick now (provisional start) */
    CMD_APPLY,    /* re-apply the config in effect to the interfaces */
    CMD_AP_START, /* arg = net_ap_reason_t */
    CMD_AP_STOP,
    CMD_AP_CLIENTS, /* station joined/left */
    CMD_SNTP,       /* time section changed */
    CMD_PSK,        /* secrets changed: re-read the stored AP PSK */
} net_cmd_id_t;

typedef struct {
    uint8_t id;
    uint8_t arg;
} net_cmd_t;

typedef struct {
    /* configuration */
    cfg_network_t active; /* in effect on the interfaces */
    cfg_network_t prev;   /* committed config to restore on revert */
    cfg_network_t cand;   /* provisional candidate */
    char psk_active[GW_PSK_SZ], psk_prev[GW_PSK_SZ], psk_cand[GW_PSK_SZ];
    bool cand_has_psk;
    char prov_by[GW_USER_NAME_SZ];
    net_prov_fsm_t prov;
    ip_filter_t filter;
    /* Ethernet */
    bool eth_present, eth_link, eth_has_ip;
    uint32_t ip, mask, gw, dns1, dns2;
    uint8_t eth_mac[GW_MAC_LEN];
    uint32_t link_changes;
    uint64_t no_ip_since_ms;
    /* AP */
    bool ap_active;
    uint8_t ap_reason, ap_clients;
    uint64_t ap_idle_since_ms;
    uint8_t ap_fails;         /* consecutive failed AP starts */
    uint64_t ap_retry_at_ms;  /* no automatic (fallback) start before this */
} net_state_t;

static net_state_t s;
static SemaphoreHandle_t s_lock;
static QueueHandle_t s_q;
/* Set once net_init() has fully succeeded (net_mgr task running). The mutating API refuses to
 * queue work or start a provisional change before that: nothing would ever process it. */
static atomic_bool s_running;
static bool s_idf_handlers, s_cfg_handler; /* registered by an earlier (failed) net_init() attempt */

static inline bool running(void) {
    return atomic_load_explicit(&s_running, memory_order_acquire);
}
static esp_netif_t *s_eth_netif;
static portMUX_TYPE s_fast_mux = portMUX_INITIALIZER_UNLOCKED;
static net_fast_t s_fast;

/* net_mgr task only: what is currently applied, to skip needless interface restarts. */
static cfg_eth_t s_eth_applied;
static char s_eth_applied_host[GW_HOSTNAME_SZ];
static bool s_eth_applied_valid;
static char s_ap_run_ssid[GW_SSID_SZ], s_ap_run_psk[GW_PSK_SZ];
static uint8_t s_ap_run_ch;
static gw_secrets_t s_sec_scratch; /* secrets_get() buffer (net_mgr task / net_init only), wiped */

static inline void lock(void) {
    xSemaphoreTake(s_lock, portMAX_DELAY);
}
static inline void unlock(void) {
    xSemaphoreGive(s_lock);
}

static uint64_t now_ms(void) {
    return gw_time_mono_ms();
}

static void fast_read(net_fast_t *out) {
    taskENTER_CRITICAL(&s_fast_mux);
    *out = s_fast;
    taskEXIT_CRITICAL(&s_fast_mux);
}

/* Caller holds s_lock (single writer at a time). */
static void fast_publish_locked(void) {
    net_fast_t f;
    f.filter = s.filter;
    f.eth_ip = s.eth_has_ip ? s.ip : 0;
    f.eth_mask = s.eth_has_ip ? s.mask : 0;
    f.ap_active = s.ap_active;
    memcpy(f.hostname, s.active.hostname, sizeof(f.hostname));
    taskENTER_CRITICAL(&s_fast_mux);
    s_fast = f;
    taskEXIT_CRITICAL(&s_fast_mux);
}

static bool send_cmd(net_cmd_id_t id, uint8_t arg) {
    if (!s_q) {
        return false;
    }
    const net_cmd_t c = {.id = (uint8_t)id, .arg = arg};
    if (xQueueSend(s_q, &c, 0) != pdTRUE) {
        ESP_LOGW(TAG, "command %d dropped (queue full)", id);
        return false;
    }
    return true;
}

/* Build under the lock, post after unlocking (never post while holding s_lock). */
static void build_evt_locked(gw_netif_t nif, gw_evt_net_t *e) {
    memset(e, 0, sizeof(*e));
    e->netif = (uint8_t)nif;
    e->prov = s.prov.state;
    if (nif == GW_NETIF_ETH) {
        e->link_up = s.eth_link;
        e->has_ip = s.eth_has_ip;
        if (s.eth_has_ip) {
            e->ip = s.ip;
            e->mask = s.mask;
            e->gw = s.gw;
        }
    } else {
        e->link_up = s.ap_active;
        e->has_ip = s.ap_active;
        e->ap_clients = s.ap_clients;
        if (s.ap_active) {
            e->ip = CFG_AP_IP;
            e->mask = CFG_AP_MASK;
        }
    }
}

static void post_evt(const gw_evt_net_t *e) {
    esp_err_t err = gw_events_post(GW_EVT_NET_STATE, e, sizeof(*e), 0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "NET_STATE dropped: %s", esp_err_to_name(err));
    }
}

static void post_state(gw_netif_t nif) {
    gw_evt_net_t e;
    lock();
    build_evt_locked(nif, &e);
    unlock();
    post_evt(&e);
}

static bool psk_valid(const char *p) {
    size_t n = 0;
    for (; p[n]; n++) {
        if (p[n] < 0x20 || p[n] > 0x7E || n >= GW_PSK_MAX) {
            return false;
        }
    }
    return n >= GW_PSK_MIN;
}

static void wipe(void *p, size_t n) {
    gw_secure_zero(p, n);
}

/* ------------------------------------------------------------------------------------------------ */
/* Interface application (net_mgr task, or net_init before the task exists)                         */

static esp_err_t clear_dns_slot(void *ctx) {
    dns_setserver((u8_t)(uintptr_t)ctx, NULL);
    return ESP_OK;
}

static void set_dns(esp_netif_dns_type_t type, uint32_t addr) {
    if (addr) {
        esp_netif_dns_info_t d = {0};
        d.ip.type = ESP_IPADDR_TYPE_V4;
        d.ip.u_addr.ip4.addr = htonl(addr);
        esp_err_t err = esp_netif_set_dns_info(s_eth_netif, type, &d);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "DNS %d: %s", (int)type, esp_err_to_name(err));
        }
    } else {
        esp_netif_tcpip_exec(clear_dns_slot, (void *)(uintptr_t)type);
    }
}

static void apply_eth(const cfg_network_t *cfg) {
    if (!s_eth_netif) {
        return;
    }
    if (s_eth_applied_valid && !memcmp(&s_eth_applied, &cfg->eth, sizeof(cfg->eth)) &&
        !strcmp(s_eth_applied_host, cfg->hostname)) {
        return; /* unchanged: keep the lease / connections */
    }
    esp_err_t err = esp_netif_dhcpc_stop(s_eth_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGW(TAG, "dhcpc stop: %s", esp_err_to_name(err));
    }
    err = esp_netif_set_hostname(s_eth_netif, cfg->hostname);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "hostname: %s", esp_err_to_name(err));
    }
    const uint64_t now = now_ms();
    if (cfg->eth.mode == CFG_ETH_DHCP) {
        lock();
        if (s.eth_has_ip) {
            s.no_ip_since_ms = now;
        }
        s.eth_has_ip = false;
        s.ip = s.mask = s.gw = s.dns1 = s.dns2 = 0;
        fast_publish_locked();
        unlock();
        err = esp_netif_dhcpc_start(s_eth_netif);
        if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
            ESP_LOGE(TAG, "dhcpc start: %s", esp_err_to_name(err));
        }
        ESP_LOGI(TAG, "Ethernet: DHCP, hostname %s", cfg->hostname);
    } else {
        esp_netif_ip_info_t ip = {0};
        ip.ip.addr = htonl(cfg->eth.ip);
        ip.netmask.addr = htonl(cfg->eth.mask);
        ip.gw.addr = htonl(cfg->eth.gw);
        err = esp_netif_set_ip_info(s_eth_netif, &ip);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "static IP: %s", esp_err_to_name(err));
        }
        set_dns(ESP_NETIF_DNS_MAIN, cfg->eth.dns1);
        set_dns(ESP_NETIF_DNS_BACKUP, cfg->eth.dns2);
        char a[GW_IP4_STR_SZ];
        const uint32_t v = cfg->eth.ip;
        snprintf(a, sizeof(a), "%u.%u.%u.%u", (unsigned)(v >> 24), (unsigned)(v >> 16 & 0xFF),
                 (unsigned)(v >> 8 & 0xFF), (unsigned)(v & 0xFF));
        ESP_LOGI(TAG, "Ethernet: static %s/%d, hostname %s", a, __builtin_popcount(cfg->eth.mask), cfg->hostname);
        lock();
        const bool had = s.eth_has_ip;
        s.ip = cfg->eth.ip;
        s.mask = cfg->eth.mask;
        s.gw = cfg->eth.gw;
        s.dns1 = cfg->eth.dns1;
        s.dns2 = cfg->eth.dns2;
        s.eth_has_ip = s.eth_link && cfg->eth.ip != 0 && err == ESP_OK;
        if (had && !s.eth_has_ip) {
            s.no_ip_since_ms = now;
        }
        fast_publish_locked();
        unlock();
    }
    s_eth_applied = cfg->eth;
    gw_strlcpy(s_eth_applied_host, cfg->hostname, sizeof(s_eth_applied_host));
    s_eth_applied_valid = true;
    post_state(GW_NETIF_ETH);
}

static void apply_ap_if_running(const cfg_network_t *cfg, const char *psk) {
    lock();
    const bool active = s.ap_active;
    unlock();
    if (!active) {
        return;
    }
    if (!strcmp(s_ap_run_ssid, cfg->ap.ssid) && !strcmp(s_ap_run_psk, psk) && s_ap_run_ch == cfg->ap.channel) {
        return;
    }
    esp_err_t err = net_wifi_ap_start(cfg->ap.ssid, psk, cfg->ap.channel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "AP reconfigure failed: %s", esp_err_to_name(err));
        return;
    }
    gw_strlcpy(s_ap_run_ssid, cfg->ap.ssid, sizeof(s_ap_run_ssid));
    gw_strlcpy(s_ap_run_psk, psk, sizeof(s_ap_run_psk));
    s_ap_run_ch = cfg->ap.channel;
    lock();
    s.ap_clients = 0;
    s.ap_idle_since_ms = now_ms();
    unlock();
    post_state(GW_NETIF_AP);
}

static void apply_all(void) {
    static cfg_network_t cfg; /* net_mgr task only */
    static char psk[GW_PSK_SZ];
    lock();
    cfg = s.active;
    memcpy(psk, s.psk_active, sizeof(psk));
    fast_publish_locked(); /* hostname */
    unlock();
    apply_eth(&cfg);
    apply_ap_if_running(&cfg, psk);
    wipe(psk, sizeof(psk));
}

static void ap_start(net_ap_reason_t reason) {
    char ssid[GW_SSID_SZ], psk[GW_PSK_SZ];
    uint8_t ch;
    lock();
    if (s.ap_active) {
        s.ap_reason = (uint8_t)reason;
        s.ap_idle_since_ms = now_ms(); /* a new request restarts the idle countdown */
        unlock();
        post_state(GW_NETIF_AP);
        return;
    }
    gw_strlcpy(ssid, s.active.ap.ssid, sizeof(ssid));
    memcpy(psk, s.psk_active, sizeof(psk));
    ch = s.active.ap.channel;
    unlock();

    esp_err_t err = net_wifi_ap_start(ssid, psk, ch);
    if (err == ESP_OK) {
        gw_strlcpy(s_ap_run_ssid, ssid, sizeof(s_ap_run_ssid));
        gw_strlcpy(s_ap_run_psk, psk, sizeof(s_ap_run_psk));
        s_ap_run_ch = ch;
    }
    wipe(psk, sizeof(psk));
    if (err != ESP_OK) {
        lock();
        if (s.ap_fails < UINT8_MAX) {
            s.ap_fails++;
        }
        const uint32_t retry_s = net_ap_retry_delay_s(s.active.ap.fallback_after_s, s.ap_fails);
        s.ap_retry_at_ms = now_ms() + (uint64_t)retry_s * 1000u;
        unlock();
        ESP_LOGE(TAG, "recovery AP start failed: %s (automatic retry in %u s)", esp_err_to_name(err),
                 (unsigned)retry_s);
        return;
    }
    lock();
    s.ap_fails = 0;
    s.ap_retry_at_ms = 0;
    s.ap_active = true;
    s.ap_reason = (uint8_t)reason;
    s.ap_clients = 0;
    s.ap_idle_since_ms = now_ms();
    fast_publish_locked();
    unlock();
    ESP_LOGI(TAG, "recovery AP up (reason %d): SSID \"%s\", http://192.168.150.1/", reason, ssid);
    post_state(GW_NETIF_AP);
}

static void ap_stop(bool manual) {
    lock();
    const bool active = s.ap_active;
    unlock();
    if (!active) {
        return;
    }
    esp_err_t err = net_wifi_ap_stop();
    if (err != ESP_OK) {
        return;
    }
    wipe(s_ap_run_psk, sizeof(s_ap_run_psk));
    s_ap_run_ssid[0] = '\0';
    lock();
    s.ap_active = false;
    s.ap_reason = NET_AP_REASON_NONE;
    s.ap_clients = 0;
    if (manual && !s.eth_has_ip) {
        s.no_ip_since_ms = now_ms(); /* restart the fallback countdown after a manual stop */
    }
    fast_publish_locked();
    unlock();
    ESP_LOGI(TAG, "recovery AP down (%s)", manual ? "requested" : "idle");
    post_state(GW_NETIF_AP);
}

static void refresh_ap_clients(void) {
    const uint8_t n = net_wifi_ap_clients();
    lock();
    const bool changed = n != s.ap_clients;
    if (changed && n == 0) {
        s.ap_idle_since_ms = now_ms();
    }
    s.ap_clients = n;
    unlock();
    if (changed) {
        post_state(GW_NETIF_AP);
    }
}

/* Secrets changed: adopt the stored AP PSK, except while a provisional PSK is on the air (it is
 * stored by net_confirm() or dropped by the revert, which then restores this stored value). */
static void reload_psk(void) {
    secrets_get(&s_sec_scratch);
    lock();
    const bool pending = net_prov_pending(&s.prov);
    const bool on_air = pending && s.cand_has_psk && s.prov.state == NET_PROV_AWAIT_CONFIRM;
    if (pending) {
        gw_strlcpy(s.psk_prev, s_sec_scratch.ap_psk, sizeof(s.psk_prev));
    }
    if (!on_air) {
        gw_strlcpy(s.psk_active, s_sec_scratch.ap_psk, sizeof(s.psk_active));
    }
    unlock();
    wipe(&s_sec_scratch, sizeof(s_sec_scratch));
    if (!on_air) {
        apply_all();
    }
}

static void apply_sntp(void) {
    static cfg_time_t t; /* net_mgr task only */
    if (cfg_get_section(CFG_SEC_TIME, &t, sizeof(t)) == ESP_OK) {
        net_sntp_apply(&t);
    }
}

/* EVENTS log record of a provisional transition (the eventlog glue only maps NET_STATE to
 * net_link/ap; DECISIONS.md F). `by` is copied under the lock by the caller. */
static void log_prov(uint8_t state, const char *by) {
    evlog_event(EVT_NET_PROVISIONAL, EVLOG_DEV_NONE, state, 0, 0, by, 0);
}

/* One second of timers: provisional apply/revert, AP fallback, AP idle stop. */
static void tick(void) {
    const uint64_t now = now_ms();
    gw_evt_net_t e;
    lock();
    const net_prov_action_t act = net_prov_tick(&s.prov, now);
    const uint8_t pstate = s.prov.state;
    const uint32_t confirm_s = s.prov.confirm_s;
    char by[GW_USER_NAME_SZ];
    memcpy(by, s.prov_by, sizeof(by));
    if (act == NET_PROV_ACT_APPLY_CAND) {
        s.active = s.cand;
        if (s.cand_has_psk) {
            memcpy(s.psk_active, s.psk_cand, sizeof(s.psk_active));
        }
    } else if (act == NET_PROV_ACT_APPLY_PREV) {
        s.active = s.prev;
        memcpy(s.psk_active, s.psk_prev, sizeof(s.psk_active));
        wipe(s.psk_cand, sizeof(s.psk_cand));
        wipe(s.psk_prev, sizeof(s.psk_prev));
        s.cand_has_psk = false;
    }
    build_evt_locked(GW_NETIF_ETH, &e);
    unlock();

    if (act != NET_PROV_ACT_NONE) {
        if (act == NET_PROV_ACT_APPLY_CAND) {
            ESP_LOGW(TAG, "provisional network config applied; confirm within %u s", (unsigned)confirm_s);
        } else {
            ESP_LOGW(TAG, "provisional network config not confirmed: reverted");
        }
        apply_all();
        post_evt(&e);
        log_prov(pstate, by);
        if (pstate == NET_PROV_REVERTED) {
            lock();
            net_prov_settle(&s.prov);
            unlock();
            post_state(GW_NETIF_ETH);
        }
    }

    lock();
    const bool fallback = now >= s.ap_retry_at_ms &&
                          net_ap_should_fallback(s.active.ap.fallback, s.ap_active, s.eth_has_ip, s.no_ip_since_ms,
                                                 now, s.active.ap.fallback_after_s);
    const bool stop = net_ap_should_stop(s.ap_active, s.ap_reason, s.ap_clients, s.eth_has_ip,
                                         s.ap_idle_since_ms, now, s.active.ap.idle_min);
    unlock();
    if (fallback) {
        ESP_LOGW(TAG, "no Ethernet IP: starting the recovery AP");
        ap_start(NET_AP_REASON_NO_LINK);
    } else if (stop) {
        ap_stop(false);
    }
}

static void net_task(void *arg) {
    (void)arg;
    TickType_t last = xTaskGetTickCount();
    for (;;) {
        const TickType_t period = pdMS_TO_TICKS(NET_TICK_MS);
        const TickType_t elapsed = xTaskGetTickCount() - last;
        net_cmd_t c;
        if (xQueueReceive(s_q, &c, elapsed >= period ? 0 : period - elapsed) == pdTRUE) {
            switch ((net_cmd_id_t)c.id) {
            case CMD_WAKE:
                tick();
                break;
            case CMD_APPLY:
                apply_all();
                break;
            case CMD_AP_START:
                ap_start((net_ap_reason_t)c.arg);
                break;
            case CMD_AP_STOP:
                ap_stop(true);
                break;
            case CMD_AP_CLIENTS:
                refresh_ap_clients();
                break;
            case CMD_SNTP:
                apply_sntp();
                break;
            case CMD_PSK:
                reload_psk();
                break;
            default:
                break;
            }
        }
        if (xTaskGetTickCount() - last >= period) {
            last = xTaskGetTickCount();
            tick();
        }
        gw_hb_beat(GW_HB_NET); /* supervisor: required heartbeat (provisional revert, AP fallback) */
    }
}

/* ------------------------------------------------------------------------------------------------ */
/* IDF event handlers (default event loop task)                                                     */

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)data;
    const uint64_t now = now_ms();
    lock();
    switch (id) {
    case ETHERNET_EVENT_CONNECTED:
        s.eth_link = true;
        s.link_changes++;
        if (s.active.eth.mode == CFG_ETH_STATIC && s.active.eth.ip) {
            s.eth_has_ip = true;
            s.ip = s.active.eth.ip;
            s.mask = s.active.eth.mask;
            s.gw = s.active.eth.gw;
        }
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        s.eth_link = false;
        s.link_changes++;
        if (s.eth_has_ip) {
            s.no_ip_since_ms = now;
        }
        s.eth_has_ip = false;
        break;
    default:
        unlock();
        return;
    }
    fast_publish_locked();
    unlock();
    ESP_LOGI(TAG, "Ethernet link %s", id == ETHERNET_EVENT_CONNECTED ? "up" : "down");
    post_state(GW_NETIF_ETH);
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    if (id == IP_EVENT_ETH_GOT_IP) {
        const ip_event_got_ip_t *ev = data;
        if (!ev || ev->esp_netif != s_eth_netif) {
            return;
        }
        uint32_t d1 = 0, d2 = 0;
        esp_netif_dns_info_t dns;
        if (esp_netif_get_dns_info(s_eth_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
            d1 = ntohl(dns.ip.u_addr.ip4.addr);
        }
        if (esp_netif_get_dns_info(s_eth_netif, ESP_NETIF_DNS_BACKUP, &dns) == ESP_OK) {
            d2 = ntohl(dns.ip.u_addr.ip4.addr);
        }
        const uint32_t lip = ntohl(ev->ip_info.ip.addr), lmask = ntohl(ev->ip_info.netmask.addr);
        if (net_subnet_overlaps(lip, lmask, CFG_AP_IP, CFG_AP_MASK)) {
            /* DESIGN.md §14: the Ethernet subnet never overlaps the recovery-AP subnet. cfg_validate
             * enforces it for static addresses only; a (rogue) DHCP lease is not used: it is not
             * published as eth_ip (so the AP exemption/Host rules never see it), the AP fallback
             * still runs, and the strong-host hook only accepts 192.168.150.1 on the AP netif. */
            lock();
            const bool was = s.eth_has_ip;
            if (was) {
                s.no_ip_since_ms = now_ms();
            }
            s.eth_has_ip = false;
            fast_publish_locked();
            unlock();
            ESP_LOGE(TAG, "DHCP lease " IPSTR "/" IPSTR " overlaps the recovery-AP subnet: ignored",
                     IP2STR(&ev->ip_info.ip), IP2STR(&ev->ip_info.netmask));
            post_state(GW_NETIF_ETH);
            return;
        }
        lock();
        s.eth_has_ip = true;
        s.ip = lip;
        s.mask = lmask;
        s.gw = ntohl(ev->ip_info.gw.addr);
        s.dns1 = d1;
        s.dns2 = d2;
        fast_publish_locked();
        unlock();
        ESP_LOGI(TAG, "Ethernet IP " IPSTR, IP2STR(&ev->ip_info.ip));
        post_state(GW_NETIF_ETH);
    } else if (id == IP_EVENT_ETH_LOST_IP) {
        lock();
        if (s.eth_has_ip) {
            s.no_ip_since_ms = now_ms();
        }
        s.eth_has_ip = false;
        fast_publish_locked();
        unlock();
        ESP_LOGW(TAG, "Ethernet IP lost");
        post_state(GW_NETIF_ETH);
    }
}

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)data;
    if (id == WIFI_EVENT_AP_STACONNECTED || id == WIFI_EVENT_AP_STADISCONNECTED) {
        send_cmd(CMD_AP_CLIENTS, 0);
    }
}

/* ------------------------------------------------------------------------------------------------ */
/* gw_evt handlers                                                                                  */

static void load_filter(void) {
    static cfg_security_t sec; /* gw_evt task / net_init only */
    if (cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec)) != ESP_OK) {
        return;
    }
    uint32_t nets[GW_MAX_IP_ALLOW], masks[GW_MAX_IP_ALLOW];
    const size_t n = sec.n_ip_allow > GW_MAX_IP_ALLOW ? GW_MAX_IP_ALLOW : sec.n_ip_allow;
    for (size_t i = 0; i < n; i++) {
        nets[i] = sec.ip_allow[i].net;
        masks[i] = sec.ip_allow[i].mask;
    }
    lock();
    ip_filter_set(&s.filter, nets, masks, n);
    fast_publish_locked();
    unlock();
}

static void on_config_changed(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_config_t *e = data;
    if (!e) {
        return;
    }
    switch (e->section) {
    case CFG_SEC_TIME: {
        static cfg_time_t t; /* gw_evt task only */
        if (cfg_get_section(CFG_SEC_TIME, &t, sizeof(t)) == ESP_OK && !gw_time_set_tz(t.tz)) {
            ESP_LOGW(TAG, "invalid TZ \"%s\"", t.tz);
        }
        send_cmd(CMD_SNTP, 0);
        break;
    }
    case CFG_SEC_SECURITY:
        load_filter();
        break;
    case CFG_SEC_SECRETS:
        send_cmd(CMD_PSK, 0);
        break;
    default:
        break; /* NETWORK changes only go through net_apply_provisional()/net_confirm() */
    }
}

/* ------------------------------------------------------------------------------------------------ */
/* Public API                                                                                       */

/* Retryable: every step that must not run twice (handler registration, Ethernet driver creation)
 * is recorded, so a net_init() that failed part-way can be called again. */
esp_err_t net_init(void) {
    if (running()) {
        return ESP_ERR_INVALID_STATE;
    }
    /* lwIP/TCP-IP task and the default loop first, before any return that can fail: web, SNMP and
     * syslog open lwIP sockets after net_init() even when it failed, and lwIP asserts if its
     * TCP/IP core was never started. Both calls are idempotent (ESP_ERR_INVALID_STATE). */
    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_netif_init: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "default event loop: %s", esp_err_to_name(err));
        return err;
    }
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    if (!s_q) {
        s_q = xQueueCreate(NET_QUEUE_LEN, sizeof(net_cmd_t));
    }
    if (!s_lock || !s_q) {
        return ESP_ERR_NO_MEM;
    }
    net_prov_init(&s.prov);

    err = cfg_get_section(CFG_SEC_NETWORK, &s.active, sizeof(s.active));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "network config unavailable: %s", esp_err_to_name(err));
        return err;
    }
    s.prev = s.active;
    {
        static cfg_time_t t;
        if (cfg_get_section(CFG_SEC_TIME, &t, sizeof(t)) == ESP_OK && !gw_time_set_tz(t.tz)) {
            ESP_LOGW(TAG, "invalid TZ \"%s\"", t.tz);
        }
    }
    load_filter();
    secrets_get(&s_sec_scratch);
    gw_strlcpy(s.psk_active, s_sec_scratch.ap_psk, sizeof(s.psk_active));
    wipe(&s_sec_scratch, sizeof(s_sec_scratch));
    s.no_ip_since_ms = now_ms();
    lock();
    fast_publish_locked();
    unlock();

    if (!s_idf_handlers) {
        static const struct {
            esp_event_base_t const *base;
            int32_t id;
            esp_event_handler_t fn;
        } regs[] = {
            {&ETH_EVENT, ESP_EVENT_ANY_ID, on_eth_event},
            {&IP_EVENT, IP_EVENT_ETH_GOT_IP, on_ip_event},
            {&IP_EVENT, IP_EVENT_ETH_LOST_IP, on_ip_event},
            {&WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event},
        };
        esp_event_handler_instance_t inst[sizeof(regs) / sizeof(regs[0])] = {0};
        size_t n = 0;
        for (; n < sizeof(regs) / sizeof(regs[0]); n++) {
            err = esp_event_handler_instance_register(*regs[n].base, regs[n].id, regs[n].fn, NULL, &inst[n]);
            if (err != ESP_OK) {
                break;
            }
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "event handlers: %s", esp_err_to_name(err));
            while (n-- > 0) { /* roll back so a retry does not register twice */
                esp_event_handler_instance_unregister(*regs[n].base, regs[n].id, inst[n]);
            }
            return err;
        }
        s_idf_handlers = true;
    }

    /* Ethernet is not fatal: the recovery AP (fallback timer, BOOT button) still works. */
    uint8_t mac[GW_MAC_LEN] = {0};
    lock();
    const bool eth_done = s.eth_present;
    unlock();
    if (eth_done) {
        /* created by an earlier attempt */
    } else if (net_eth_create(&s_eth_netif, mac) == ESP_OK) {
        lock();
        s.eth_present = true;
        memcpy(s.eth_mac, mac, sizeof(mac));
        unlock();
        static cfg_network_t cfg0;
        cfg0 = s.active;
        apply_eth(&cfg0);
        err = net_eth_start();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Ethernet start: %s", esp_err_to_name(err));
        }
    } else {
        s_eth_netif = NULL;
        if (esp_read_mac(mac, ESP_MAC_ETH) == ESP_OK) {
            memcpy(s.eth_mac, mac, sizeof(mac));
        }
    }

    if (!s_cfg_handler) {
        err = gw_events_register(GW_EVT_CONFIG_CHANGED, on_config_changed, NULL, NULL);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "CONFIG_CHANGED handler: %s (TZ/SNTP/allowlist/PSK changes need a reboot)",
                     esp_err_to_name(err));
        } else {
            s_cfg_handler = true;
        }
    }
    if (xTaskCreatePinnedToCore(net_task, NET_TASK_NAME, NET_TASK_STACK, NULL, NET_TASK_PRIO, NULL,
                                NET_TASK_CORE) != pdPASS) {
        ESP_LOGE(TAG, "net_mgr task not created");
        return ESP_ERR_NO_MEM;
    }
    atomic_store_explicit(&s_running, true, memory_order_release);
    send_cmd(CMD_SNTP, 0);

    /* Serial console only (never syslog): how to reach the device without Ethernet. */
    char fact[GW_PSK_SZ];
    secrets_factory_ap_psk(fact);
    lock();
    const bool is_factory = fact[0] && !strcmp(fact, s.psk_active);
    unlock();
    if (is_factory) {
        ESP_LOGI(TAG, "recovery AP SSID \"%s\", factory PSK \"%s\"", s.active.ap.ssid, fact);
    } else {
        ESP_LOGI(TAG, "recovery AP SSID \"%s\" (PSK changed by an administrator)", s.active.ap.ssid);
    }
    wipe(fact, sizeof(fact));
    return ESP_OK;
}

void net_get_status(net_status_t *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (!s_lock) {
        return;
    }
    const uint64_t now = now_ms();
    lock();
    out->eth_link = s.eth_link;
    out->eth_has_ip = s.eth_has_ip;
    out->eth_mode = s.active.eth.mode;
    if (s.eth_has_ip) {
        out->ip = s.ip;
        out->mask = s.mask;
        out->gw = s.gw;
        out->dns1 = s.dns1;
        out->dns2 = s.dns2;
    }
    memcpy(out->eth_mac, s.eth_mac, sizeof(out->eth_mac));
    gw_strlcpy(out->hostname, s.active.hostname, sizeof(out->hostname));
    out->link_changes = s.link_changes;
    out->ap_active = s.ap_active;
    out->ap_reason = s.ap_reason;
    out->ap_clients = s.ap_clients;
    out->ap_ip = s.ap_active ? CFG_AP_IP : 0;
    gw_strlcpy(out->ap_ssid, s.active.ap.ssid, sizeof(out->ap_ssid));
    out->ap_off_in_s = net_ap_off_in_s(s.ap_active, s.ap_reason, s.ap_clients, s.eth_has_ip, s.ap_idle_since_ms,
                                       now, s.active.ap.idle_min);
    out->prov = s.prov.state;
    out->prov_left_s = net_prov_left_s(&s.prov, now);
    unlock();
    out->sntp_synced = net_sntp_status(&out->sntp_last_ms);
}

esp_err_t net_apply_provisional(const cfg_network_t *candidate, const char *ap_psk, uint32_t apply_in_s,
                                uint32_t confirm_s, const char *by) {
    if (!candidate || (ap_psk && !psk_valid(ap_psk))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    gw_evt_net_t e;
    lock();
    esp_err_t err = net_prov_start(&s.prov, now_ms(), apply_in_s, confirm_s);
    if (err == ESP_OK) {
        s.prev = s.active;
        s.cand = *candidate;
        memcpy(s.psk_prev, s.psk_active, sizeof(s.psk_prev));
        s.cand_has_psk = ap_psk != NULL;
        if (ap_psk) {
            gw_strlcpy(s.psk_cand, ap_psk, sizeof(s.psk_cand));
        }
        gw_strlcpy(s.prov_by, by ? by : "", sizeof(s.prov_by));
        build_evt_locked(GW_NETIF_ETH, &e);
    }
    unlock();
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGW(TAG, "provisional network change by %s: apply in %u s, confirm within %u s", by ? by : "?",
             (unsigned)apply_in_s, (unsigned)confirm_s);
    post_evt(&e);
    log_prov(NET_PROV_APPLY_PENDING, by);
    if (apply_in_s == 0) {
        send_cmd(CMD_WAKE, 0);
    }
    return ESP_OK;
}

static esp_err_t set_psk_fn(gw_secrets_t *sec, void *arg) {
    gw_strlcpy(sec->ap_psk, (const char *)arg, sizeof(sec->ap_psk));
    return ESP_OK;
}

esp_err_t net_confirm(const char *by) {
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    static cfg_network_t cand; /* serialized by the `confirming` flag */
    char psk[GW_PSK_SZ];
    bool has_psk;
    lock();
    esp_err_t err = net_prov_confirm_begin(&s.prov);
    if (err == ESP_OK) {
        cand = s.cand;
        has_psk = s.cand_has_psk;
        memcpy(psk, s.psk_cand, sizeof(psk));
    }
    unlock();
    if (err != ESP_OK) {
        return err;
    }

    cfg_verr_t verr = {0};
    err = cfg_commit(CFG_SEC_NETWORK, &cand, sizeof(cand), by, &verr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "confirm: commit failed (%s, %s %s)", esp_err_to_name(err), verr.field, verr.code);
    }
    esp_err_t psk_err = ESP_OK;
    if (err == ESP_OK && has_psk) {
        psk_err = secrets_modify(set_psk_fn, psk, by);
        if (psk_err != ESP_OK) {
            ESP_LOGE(TAG, "confirm: AP PSK not stored (%s); keeping the stored PSK", esp_err_to_name(psk_err));
        }
    }
    wipe(psk, sizeof(psk));

    gw_evt_net_t e;
    lock();
    const net_prov_action_t act = net_prov_confirm_end(&s.prov, err == ESP_OK);
    const uint8_t pstate = s.prov.state;
    if (err == ESP_OK) {
        s.active = cand;
        if (has_psk && psk_err == ESP_OK) {
            memcpy(s.psk_active, s.psk_cand, sizeof(s.psk_active));
        }
        wipe(s.psk_cand, sizeof(s.psk_cand));
        wipe(s.psk_prev, sizeof(s.psk_prev));
        s.cand_has_psk = false;
        s.prev = s.active;
    }
    build_evt_locked(GW_NETIF_ETH, &e);
    unlock();
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGI(TAG, "provisional network config confirmed by %s", by ? by : "?");
    if (act == NET_PROV_ACT_APPLY_CAND) {
        send_cmd(CMD_APPLY, 0);
    }
    if (psk_err != ESP_OK) {
        send_cmd(CMD_PSK, 0); /* re-apply the stored PSK so RAM and flash agree */
    }
    post_evt(&e);
    log_prov(pstate, by);
    lock();
    net_prov_settle(&s.prov);
    unlock();
    post_state(GW_NETIF_ETH);
    return psk_err == ESP_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t net_revert(void) {
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    net_prov_action_t act = NET_PROV_ACT_NONE;
    gw_evt_net_t e;
    lock();
    esp_err_t err = net_prov_revert(&s.prov, &act);
    if (err == ESP_OK) {
        if (act == NET_PROV_ACT_APPLY_PREV) {
            s.active = s.prev;
            memcpy(s.psk_active, s.psk_prev, sizeof(s.psk_active));
        }
        wipe(s.psk_cand, sizeof(s.psk_cand));
        wipe(s.psk_prev, sizeof(s.psk_prev));
        s.cand_has_psk = false;
        build_evt_locked(GW_NETIF_ETH, &e);
    }
    unlock();
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGW(TAG, "provisional network change reverted");
    if (act == NET_PROV_ACT_APPLY_PREV) {
        send_cmd(CMD_APPLY, 0);
    }
    post_evt(&e);
    log_prov(NET_PROV_REVERTED, NULL);
    lock();
    net_prov_settle(&s.prov);
    unlock();
    post_state(GW_NETIF_ETH);
    return ESP_OK;
}

esp_err_t net_reset_defaults(const char *by) {
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    static cfg_network_t def; /* console task; serialized by the config store */
    uint8_t mac[GW_MAC_LEN];
    board_base_mac(mac);
    cfg_section_defaults(CFG_SEC_NETWORK, &def, mac);
    cfg_verr_t verr = {0};
    esp_err_t err = cfg_commit(CFG_SEC_NETWORK, &def, sizeof(def), by, &verr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "net-reset: commit failed (%s, %s %s)", esp_err_to_name(err), verr.field, verr.code);
        return err;
    }
    char fact[GW_PSK_SZ];
    secrets_factory_ap_psk(fact);
    esp_err_t psk_err = fact[0] ? secrets_modify(set_psk_fn, fact, by) : ESP_ERR_INVALID_STATE;
    if (psk_err != ESP_OK) {
        ESP_LOGW(TAG, "net-reset: factory AP PSK not restored (%s)", esp_err_to_name(psk_err));
    }
    lock();
    if (net_prov_pending(&s.prov) && !s.prov.confirming) {
        net_prov_action_t act;
        net_prov_revert(&s.prov, &act); /* superseded: the defaults are applied below */
        net_prov_settle(&s.prov);
    }
    s.active = def;
    s.prev = def;
    if (psk_err == ESP_OK) {
        gw_strlcpy(s.psk_active, fact, sizeof(s.psk_active));
    }
    wipe(s.psk_cand, sizeof(s.psk_cand));
    wipe(s.psk_prev, sizeof(s.psk_prev));
    s.cand_has_psk = false;
    unlock();
    wipe(fact, sizeof(fact));
    ESP_LOGW(TAG, "network reset to factory defaults by %s", by ? by : "?");
    send_cmd(CMD_APPLY, 0);
    return ESP_OK;
}

esp_err_t net_ap_start(net_ap_reason_t reason) {
    if (reason == NET_AP_REASON_NONE || reason > NET_AP_REASON_CONSOLE) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    return send_cmd(CMD_AP_START, (uint8_t)reason) ? ESP_OK : ESP_ERR_TIMEOUT;
}

esp_err_t net_ap_stop(void) {
    if (!running()) {
        return ESP_ERR_INVALID_STATE;
    }
    return send_cmd(CMD_AP_STOP, 0) ? ESP_OK : ESP_ERR_TIMEOUT;
}

bool net_ap_active(void) {
    net_fast_t f;
    fast_read(&f);
    return f.ap_active;
}

bool net_ip_allowed(uint32_t peer_ip, uint32_t local_ip) {
    net_fast_t f;
    fast_read(&f);
    return ip_filter_allows(&f.filter, peer_ip, local_ip, CFG_AP_IP, CFG_AP_MASK);
}

bool net_host_allowed(const char *host_hdr) {
    net_fast_t f;
    fast_read(&f);
    const uint32_t ips[2] = {f.eth_ip, CFG_AP_IP};
    return ip_filter_host_ok(host_hdr, ips, 2, f.hostname);
}

bool net_sock_info(int sockfd, uint32_t *peer_ip, uint32_t *local_ip, bool *via_ap) {
    struct sockaddr_storage peer, local;
    socklen_t plen = sizeof(peer), llen = sizeof(local);
    if (sockfd < 0 || getpeername(sockfd, (struct sockaddr *)&peer, &plen) != 0 ||
        getsockname(sockfd, (struct sockaddr *)&local, &llen) != 0 || peer.ss_family != AF_INET ||
        local.ss_family != AF_INET) {
        return false;
    }
    const uint32_t p = ntohl(((const struct sockaddr_in *)&peer)->sin_addr.s_addr);
    const uint32_t l = ntohl(((const struct sockaddr_in *)&local)->sin_addr.s_addr);
    if (peer_ip) {
        *peer_ip = p;
    }
    if (local_ip) {
        *local_ip = l;
    }
    if (via_ap) {
        *via_ap = l == CFG_AP_IP && (p & CFG_AP_MASK) == (CFG_AP_IP & CFG_AP_MASK);
    }
    return true;
}

bool net_ip_allowed_fd(int sockfd) {
    uint32_t peer, local;
    if (!net_sock_info(sockfd, &peer, &local, NULL)) {
        return false;
    }
    return net_ip_allowed(peer, local);
}

uint32_t net_local_ip_for(uint32_t dst_ip) {
    net_fast_t f;
    fast_read(&f);
    if (f.ap_active && (dst_ip & CFG_AP_MASK) == (CFG_AP_IP & CFG_AP_MASK)) {
        return CFG_AP_IP;
    }
    return f.eth_ip; /* on-link or via the Ethernet default gateway; 0 when no address */
}
