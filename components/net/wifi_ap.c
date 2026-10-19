/* On-demand recovery SoftAP (DESIGN.md §5): WPA2/WPA3-PSK mixed, PMF capable, 192.168.150.1/24 with
 * a DHCP server (no router/DNS offered, so client OSes keep their own default route), max
 * NET_AP_MAX_CLIENTS stations, channel from config. Wi-Fi runs from RAM only (no NVS). Called from
 * the net_mgr task only.
 *
 * Internal RAM: esp_wifi_init() allocates the `wifi` task stack, the static RX/management buffers
 * and the driver context (~25-35 KB of internal RAM) and only esp_wifi_deinit() frees them. Stopping
 * the AP therefore tears everything down (driver, AP netif, DHCP server) so an Ethernet-only gateway
 * gets that RAM back after a cable/DHCP outage started the fallback AP (ARCHITECTURE.md §6.1). */
#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/inet.h"
#include "net/net.h"
#include "net_priv.h"

static const char *TAG = "wifi_ap";

static esp_netif_t *s_ap_netif; /* created on AP start, destroyed on AP stop */
static bool s_dhcps_ready;        /* static address + DHCP server configured on s_ap_netif */
static bool s_drv_inited;         /* esp_wifi_init() succeeded */
static bool s_wifi_inited;        /* everything above + RAM storage + AP mode */
static bool s_started;

static void teardown(void);

/* Non-asserting equivalent of esp_netif_create_default_wifi_ap() (which asserts/aborts on any
 * failure, and on a duplicate "WIFI_AP_DEF" key). Runs at most once successfully; a failed attempt
 * releases what it created so the next attempt starts clean. */
static esp_err_t create_netif(void) {
    if (s_ap_netif) {
        return ESP_OK;
    }
    esp_netif_t *n = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (n) { /* created elsewhere: reuse rather than duplicating the key */
        s_ap_netif = n;
        return ESP_OK;
    }
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_WIFI_AP();
    n = esp_netif_new(&cfg);
    if (!n) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = esp_netif_attach_wifi_ap(n);
    if (err == ESP_OK) {
        err = esp_wifi_set_default_wifi_ap_handlers();
    }
    if (err != ESP_OK) {
        esp_netif_destroy_default_wifi(n); /* clears the driver glue + handlers, destroys n */
        return err;
    }
    s_ap_netif = n;
    return ESP_OK;
}

static esp_err_t setup_netif(void) {
    esp_err_t err = create_netif();
    if (err != ESP_OK || s_dhcps_ready) {
        return err;
    }
    err = esp_netif_dhcps_stop(s_ap_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        return err;
    }
    esp_netif_ip_info_t ip = {0};
    ip.ip.addr = htonl(CFG_AP_IP);
    ip.netmask.addr = htonl(CFG_AP_MASK);
    ip.gw.addr = 0; /* no gateway behind the AP */
    err = esp_netif_set_ip_info(s_ap_netif, &ip);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t offer = 0; /* dhcps_offer_t: neither OFFER_ROUTER nor OFFER_DNS */
    err = esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_ROUTER_SOLICITATION_ADDRESS, &offer,
                                 sizeof(offer));
    if (err == ESP_OK) {
        err = esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer,
                                     sizeof(offer));
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DHCP server options: %s", esp_err_to_name(err));
    }
    err = esp_netif_dhcps_start(s_ap_netif);
    if (err == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        err = ESP_OK;
    }
    s_dhcps_ready = (err == ESP_OK);
    return err;
}

/* Idempotent and retryable: each stage is recorded, so a failure part-way (e.g. ESP_ERR_NO_MEM from
 * esp_wifi_init under internal-heap pressure) leaves a state the next call can resume from. */
static esp_err_t init_wifi(void) {
    esp_err_t err = setup_netif();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "AP netif: %s", esp_err_to_name(err));
        return err;
    }
    if (!s_drv_inited) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        cfg.nvs_enable = 0;
        err = esp_wifi_init(&cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Wi-Fi init: %s", esp_err_to_name(err));
            return err;
        }
        s_drv_inited = true;
    }
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err == ESP_OK) {
        err = esp_wifi_set_mode(WIFI_MODE_AP);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi mode: %s", esp_err_to_name(err));
        return err;
    }
    s_wifi_inited = true;
    return ESP_OK;
}

esp_err_t net_wifi_ap_start(const char *ssid, const char *psk, uint8_t channel) {
    if (!ssid || !psk) {
        return ESP_ERR_INVALID_ARG;
    }
    const size_t ssid_len = strlen(ssid), psk_len = strlen(psk);
    if (ssid_len == 0 || ssid_len > GW_SSID_MAX || psk_len < GW_PSK_MIN || psk_len > GW_PSK_MAX || channel < 1 ||
        channel > 13) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_wifi_inited) {
        esp_err_t err = init_wifi();
        if (err != ESP_OK) {
            teardown(); /* do not keep a half-initialised driver's RAM until the retry */
            return err;
        }
    }
    wifi_config_t wc;
    memset(&wc, 0, sizeof(wc));
    memcpy(wc.ap.ssid, ssid, ssid_len);
    wc.ap.ssid_len = (uint8_t)ssid_len;
    memcpy(wc.ap.password, psk, psk_len);
    wc.ap.channel = channel;
    wc.ap.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    wc.ap.pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
    wc.ap.max_connection = NET_AP_MAX_CLIENTS;
    wc.ap.beacon_interval = 100;
    wc.ap.dtim_period = 1;
    wc.ap.pmf_cfg.capable = true;
    wc.ap.pmf_cfg.required = false; /* WPA2 clients without PMF must still connect */
    wc.ap.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &wc);
    memset(&wc, 0, sizeof(wc)); /* the PSK copy */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "AP config: %s", esp_err_to_name(err));
        if (!s_started) {
            teardown();
        }
        return err;
    }
    if (!s_started) {
        err = esp_wifi_start();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Wi-Fi start: %s", esp_err_to_name(err));
            teardown();
            return err;
        }
        s_started = true;
    }
    ESP_LOGI(TAG, "recovery AP \"%s\" on channel %u", ssid, channel);
    return ESP_OK;
}

/* Release everything init_wifi()/create_netif() acquired, in reverse order. Every stage is
 * optional, so this also cleans up after a start that failed part-way. */
static void teardown(void) {
    if (s_drv_inited) {
        esp_err_t err = esp_wifi_deinit(); /* frees the wifi task, static RX/mgmt buffers, driver */
        if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_INIT) {
            ESP_LOGW(TAG, "Wi-Fi deinit: %s", esp_err_to_name(err));
        }
        s_drv_inited = false;
    }
    s_wifi_inited = false;
    if (s_ap_netif) {
        if (s_dhcps_ready) {
            (void)esp_netif_dhcps_stop(s_ap_netif);
        }
        esp_netif_destroy_default_wifi(s_ap_netif); /* driver glue + default handlers + netif/dhcps */
        s_ap_netif = NULL;
    }
    s_dhcps_ready = false;
}

esp_err_t net_wifi_ap_stop(void) {
    if (!s_started) {
        teardown(); /* nothing on the air; make sure no driver RAM is left behind */
        return ESP_OK;
    }
    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi stop: %s", esp_err_to_name(err));
        return err;
    }
    s_started = false;
    teardown();
    ESP_LOGI(TAG, "recovery AP stopped (Wi-Fi driver released)");
    return ESP_OK;
}

uint8_t net_wifi_ap_clients(void) {
    if (!s_started) {
        return 0;
    }
    wifi_sta_list_t list;
    if (esp_wifi_ap_get_sta_list(&list) != ESP_OK || list.num < 0) {
        return 0;
    }
    return list.num > 255 ? 255 : (uint8_t)list.num;
}
