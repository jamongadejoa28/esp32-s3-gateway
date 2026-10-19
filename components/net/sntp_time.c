/* SNTP client (esp_netif_sntp) driven by the time config section. A successful sync sets the wall
 * clock through gw_time_set_wall_ms(source NTP), which posts GW_EVT_TIME_SYNC; the sysmgr
 * supervisor then writes the RTC (ARCHITECTURE.md §4.5).
 *
 * lwIP's sntp_sync_time() is a weak symbol in IDF 6.1 (components/lwip/apps/sntp/sntp.c) whose
 * default implementation calls settimeofday() itself. It is overridden here so the clock is set
 * exactly once, by gw_time (correct first_valid/delta in the event). Smooth sync is not used. */
#include <stdatomic.h>
#include <string.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "net_priv.h"

static const char *TAG = "sntp";

static char s_servers[GW_MAX_NTP_SERVERS][GW_HOST_SZ]; /* lwIP keeps these pointers */
static bool s_running;                                 /* net_mgr task only */
static atomic_bool s_synced;
static _Atomic int64_t s_last_ms;

void sntp_sync_time(struct timeval *tv) {
    /* Runs in the TCP/IP thread when a server answered. */
    const int64_t ms = (int64_t)tv->tv_sec * 1000 + tv->tv_usec / 1000;
    if (gw_time_set_wall_ms(ms, GW_TIME_SRC_NTP, NULL)) {
        atomic_store(&s_last_ms, ms);
        atomic_store(&s_synced, true);
    }
    sntp_set_sync_status(SNTP_SYNC_STATUS_COMPLETED);
}

bool net_sntp_status(int64_t *last_ms) {
    if (last_ms) {
        *last_ms = atomic_load(&s_last_ms);
    }
    return atomic_load(&s_synced);
}

esp_err_t net_sntp_apply(const cfg_time_t *t) {
    if (s_running) {
        esp_netif_sntp_deinit();
        s_running = false;
    }
    if (!t || !t->ntp_enabled) {
        ESP_LOGI(TAG, "SNTP off");
        return ESP_OK;
    }
    size_t n = 0;
    memset(s_servers, 0, sizeof(s_servers));
    for (size_t i = 0; i < GW_MAX_NTP_SERVERS; i++) {
        if (t->servers[i][0]) {
            gw_strlcpy(s_servers[n++], t->servers[i], GW_HOST_SZ);
        }
    }
    if (n == 0) {
        ESP_LOGW(TAG, "SNTP enabled without servers");
        return ESP_ERR_INVALID_ARG;
    }
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(n, ESP_SNTP_SERVER_LIST(s_servers[0], s_servers[1]));
    cfg.start = true;
    cfg.smooth_sync = false;
    cfg.server_from_dhcp = false;
    cfg.wait_for_sync = false;
    cfg.sync_cb = NULL;
    const uint32_t interval_min = t->interval_min ? t->interval_min : 60;
    esp_sntp_set_sync_interval(interval_min * 60u * 1000u);
    esp_err_t err = esp_netif_sntp_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SNTP init: %s", esp_err_to_name(err));
        return err;
    }
    s_running = true;
    ESP_LOGI(TAG, "SNTP on: %s%s%s, every %u min", s_servers[0], n > 1 ? ", " : "", n > 1 ? s_servers[1] : "",
             (unsigned)interval_min);
    return ESP_OK;
}
