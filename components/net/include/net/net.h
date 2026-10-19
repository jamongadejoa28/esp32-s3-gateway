/*
 * net.h - networking: W5500 Ethernet (primary), recovery SoftAP, provisional apply/confirm/revert,
 * SNTP, IP allowlist (DESIGN.md §0, §5, §6). IDF-free header.
 *
 * net_init() reads the network/time/security config and AP PSK (secrets) itself, then:
 * gw_time_set_tz(time.tz), esp_netif_init + default event loop, gpio_install_isr_service(0), SPI2
 * @ BOARD_ETH_SPI_MHZ, W5500 (pins from board_pins.h: net PRIV_REQUIRES board; MAC from
 * esp_read_mac(ESP_MAC_ETH)), static IP or DHCP, hostname, SNTP per config, and the AP fallback
 * timer (net owns it: no Ethernet link/IP for ap.fallback_after_s after boot -> AP). It logs the AP
 * SSID on the serial console and, while ap_psk is still the factory PSK, the PSK too (serial only,
 * never syslog). It registers gw_evt handlers for CONFIG_CHANGED{TIME, SECURITY, SECRETS} (TZ +
 * SNTP / allowlist / AP PSK re-apply). It does NOT react to CONFIG_CHANGED{NETWORK}: network
 * changes only go through net_apply_provisional()/net_confirm().
 *
 * Provisional flow (PUT /config/network):
 *   validated candidate -> net_apply_provisional(cand, 3, 120) -> after apply_in_s the interface
 *   is reconfigured (state AWAIT_CONFIRM) -> POST /config/network/confirm -> net_confirm() commits
 *   the candidate with cfg_commit(NETWORK) -> CONFIRMED. Without confirmation within confirm_s the
 *   previous (committed) config is re-applied -> REVERTED. Each transition posts GW_EVT_NET_STATE.
 *
 * All functions are thread-safe, non-blocking, callable from any task except ISRs.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "store/config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NET_APPLY_DELAY_S 3
#define NET_CONFIRM_S 120
#define NET_AP_MAX_CLIENTS 2

typedef enum {
    NET_PROV_NONE = 0,          /* no provisional change */
    NET_PROV_APPLY_PENDING = 1, /* accepted, applying in <= apply_in_s */
    NET_PROV_AWAIT_CONFIRM = 2, /* applied, waiting for net_confirm() */
    NET_PROV_CONFIRMED = 3,     /* committed (transient, then NONE) */
    NET_PROV_REVERTED = 4,      /* timed out, previous config restored (transient, then NONE) */
} net_prov_state_t;

typedef enum {
    NET_AP_REASON_NONE = 0,
    NET_AP_REASON_BUTTON = 1,  /* BOOT held 3-8 s */
    NET_AP_REASON_NO_LINK = 2, /* no Ethernet link/IP for fallback_after_s */
    NET_AP_REASON_CONSOLE = 3,
} net_ap_reason_t;

typedef struct {
    /* Ethernet */
    bool eth_link;
    bool eth_has_ip;
    uint8_t eth_mode;                  /* cfg_eth_mode_t in effect */
    uint32_t ip, mask, gw, dns1, dns2; /* in effect (DHCP lease or static) */
    uint8_t eth_mac[GW_MAC_LEN];
    char hostname[GW_HOSTNAME_SZ];
    uint32_t link_changes;
    /* AP */
    bool ap_active;
    uint8_t ap_reason; /* net_ap_reason_t */
    uint8_t ap_clients;
    uint32_t ap_ip;
    char ap_ssid[GW_SSID_SZ];
    uint32_t ap_off_in_s; /* idle shutdown countdown, 0 if stations connected / n.a. */
    /* Provisional */
    uint8_t prov;         /* net_prov_state_t */
    uint32_t prov_left_s; /* seconds until apply (APPLY_PENDING) or revert (AWAIT_CONFIRM) */
    /* SNTP */
    bool sntp_synced;
    int64_t sntp_last_ms;
} net_status_t;

/** Bring up networking (init order step 9). Ethernet failure is not fatal (AP fallback still works). */
esp_err_t net_init(void);

/** Snapshot of the current state. */
void net_get_status(net_status_t *out);

/**
 * Start a provisional change (candidate already validated with cfg_validate_with()). ap_psk (8..63
 * printable ASCII, copied; NULL = unchanged) is part of the same provisional change: the AP runs
 * with it after apply_in_s, net_confirm() stores it with secrets_modify(), and a revert restores
 * the previous PSK. The PSK copy is wiped when the change ends.
 * @return ESP_OK, ESP_ERR_INVALID_STATE if a provisional change is already pending (REST 423),
 *         ESP_ERR_INVALID_ARG.
 */
esp_err_t net_apply_provisional(const cfg_network_t *candidate, const char *ap_psk, uint32_t apply_in_s,
                                uint32_t confirm_s, const char *by);

/** Keep the provisional config (cfg_commit(NETWORK) + secrets_modify for a provisional PSK).
 * ESP_ERR_INVALID_STATE unless AWAIT_CONFIRM/APPLY_PENDING. */
esp_err_t net_confirm(const char *by);

/** Revert a pending provisional change now. ESP_ERR_INVALID_STATE if none. */
esp_err_t net_revert(void);

/** Console "net-reset": commit factory network defaults and apply immediately (no confirm). */
esp_err_t net_reset_defaults(const char *by);

/** Start/stop the recovery AP. Start is idempotent (reason updated). */
esp_err_t net_ap_start(net_ap_reason_t reason);
esp_err_t net_ap_stop(void);
bool net_ap_active(void);

/** Allowlist decision for a peer seen on local address local_ip (ip_filter_allows(): AP exemption only
 * for local == AP address AND peer inside the AP subnet). Lock-free read. */
bool net_ip_allowed(uint32_t peer_ip, uint32_t local_ip);

/**
 * DNS-rebinding defence for HTTP (router step 0, WS handshake): true iff the Host header value
 * names this device: the current Ethernet IPv4, the AP address CFG_AP_IP, the configured hostname
 * or "<hostname>.local" (case-insensitive), each with an optional ":<port>". NULL/empty -> false.
 * See ip_filter_host_ok(). Lock-free read of the current addresses.
 */
bool net_host_allowed(const char *host_hdr);

/** Same for an accepted TCP socket (getpeername/getsockname); httpd open_fn. */
bool net_ip_allowed_fd(int sockfd);

/** Peer/local IPv4 of a socket and whether it comes from the recovery AP (ip_filter.h AP rule:
 * local == AP address and peer in the AP subnet). False on error. */
bool net_sock_info(int sockfd, uint32_t *peer_ip, uint32_t *local_ip, bool *via_ap);

/** Local IPv4 to use as trap source towards dst (snmp_get_local_ip_for_dst). 0 if no route. */
uint32_t net_local_ip_for(uint32_t dst_ip);

#ifdef __cplusplus
}
#endif
