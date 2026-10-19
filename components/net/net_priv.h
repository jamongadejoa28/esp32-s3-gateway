/* net_priv.h - internal interfaces between net_mgr.c and the interface drivers of the net component.
 * Every function here is called from the "net_mgr" task only (except where noted). */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"
#include "gw_core/gw_defs.h"
#include "store/config.h"

/* net_mgr task (DECISIONS.md F: owns every esp_netif/esp_wifi/SNTP reconfiguration so the public
 * API stays non-blocking and callable from gw_evt/httpd). */
#define NET_TASK_NAME "net_mgr"
#define NET_TASK_PRIO 3
#define NET_TASK_STACK 4096
#define NET_TASK_CORE 0
#define NET_QUEUE_LEN 16
#define NET_TICK_MS 1000

/* eth_w5500.c ---------------------------------------------------------------------------------- */

/**
 * SPI2 bus + W5500 MAC/PHY (INT GPIO12, RST GPIO39 with a retry without hardware reset when the
 * driver install fails), MAC from esp_read_mac(ESP_MAC_ETH), esp_netif (route priority above the
 * AP) attached through the esp_eth glue. Does not start the driver. mac_out receives the MAC.
 */
esp_err_t net_eth_create(esp_netif_t **netif_out, uint8_t mac_out[GW_MAC_LEN]);

/** esp_eth_start() after the IP configuration has been applied. */
esp_err_t net_eth_start(void);

/* wifi_ap.c ------------------------------------------------------------------------------------ */

/** Start the SoftAP, or reconfigure it when already running (stations are disconnected).
 * Wi-Fi is initialised on first use (RAM storage, NVS disabled); the AP netif is fixed at
 * CFG_AP_IP/CFG_AP_MASK with a DHCP server that offers neither router nor DNS. */
esp_err_t net_wifi_ap_start(const char *ssid, const char *psk, uint8_t channel);

/** Stop the SoftAP (Wi-Fi stays initialised for the next start). */
esp_err_t net_wifi_ap_stop(void);

/** Number of associated stations (0 when stopped / on error). */
uint8_t net_wifi_ap_clients(void);

/* sntp_time.c ---------------------------------------------------------------------------------- */

/** (Re)configure SNTP from the time section: stop when disabled, else restart with the servers and
 * interval. Server name strings are kept in static storage (lwIP keeps the pointers). */
esp_err_t net_sntp_apply(const cfg_time_t *t);

/** Last successful sync (any task). */
bool net_sntp_status(int64_t *last_ms);
