/* Board bring-up (board.h, init order step 3). Every sub-step is non-fatal: a missing RTC or LED
 * must never stop the gateway from booting, so board_init() logs failures and returns ESP_OK unless
 * it is called twice. */
#include <stdatomic.h>
#include <string.h>

#include "board/board.h"
#include "board_priv.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"

static const char *TAG = "board";

static atomic_bool s_inited;

static void load_rtc_time(void) {
    if (board_rtc_init() != ESP_OK) {
        return;
    }
    int64_t epoch_s = 0;
    esp_err_t err = board_rtc_get_utc(&epoch_s);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "RTC time not usable (%s): wall clock stays invalid until NTP/browser sync",
                 esp_err_to_name(err));
        return;
    }
    /* The gw_evt loop does not exist yet, so the TIME_SYNC event is skipped (gw_time.h). */
    if (gw_time_set_wall_ms(epoch_s * 1000, GW_TIME_SRC_RTC, NULL)) {
        ESP_LOGI(TAG, "system time restored from RTC (UTC %lld)", (long long)epoch_s);
    }
}

esp_err_t board_init(void) {
    if (atomic_exchange(&s_inited, true)) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = board_i2c_init();
    if (err == ESP_OK) {
        load_rtc_time();
    }
    err = board_led_init();
    if (err == ESP_OK) {
        board_led_set(BOARD_LED_BOOT);
    }
    board_buzzer_init(); /* logs its own failure; the pin is LOW either way */
    err = board_button_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "BOOT button unavailable: AP/factory-reset gestures disabled");
    }
    return ESP_OK;
}

void board_base_mac(uint8_t mac[GW_MAC_LEN]) {
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        /* Cannot happen on a programmed module; keep the identity deterministic anyway. */
        ESP_LOGE(TAG, "eFuse base MAC unreadable");
        memset(mac, 0, GW_MAC_LEN);
    }
}
