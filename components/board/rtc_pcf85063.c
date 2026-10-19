/* PCF85063 RTC @0x51 holding UTC (board.h). Register codec: pcf85063_codec.c (host-tested). */
#include <stdatomic.h>

#include "board/board.h"
#include "board_pins.h"
#include "board_priv.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_time.h"
#include "pcf85063_codec.h"

static const char *TAG = "rtc";

static i2c_master_dev_handle_t s_dev;
static SemaphoreHandle_t s_lock; /* serializes read-modify-write sequences */
static atomic_bool s_present;

static esp_err_t rd(uint8_t reg, uint8_t *buf, size_t len) {
    return i2c_master_transmit_receive(s_dev, &reg, 1, buf, len, BOARD_I2C_TIMEOUT_MS);
}

esp_err_t board_rtc_init(void) {
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) {
            return ESP_ERR_NO_MEM;
        }
    }
    esp_err_t err = board_i2c_probe(BOARD_RTC_I2C_ADDR);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "PCF85063 not found at 0x%02x: %s", BOARD_RTC_I2C_ADDR, esp_err_to_name(err));
        return ESP_ERR_NOT_FOUND;
    }
    err = board_i2c_add(BOARD_RTC_I2C_ADDR, &s_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "add device failed: %s", esp_err_to_name(err));
        return err;
    }
    atomic_store(&s_present, true);
    return ESP_OK;
}

bool board_rtc_present(void) {
    return atomic_load(&s_present);
}

esp_err_t board_rtc_get_utc(int64_t *epoch_s) {
    if (!epoch_s) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!board_rtc_present()) {
        return ESP_ERR_NOT_FOUND;
    }
    uint8_t ctrl1 = 0, r[PCF85063_TIME_LEN];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = rd(PCF85063_REG_CTRL1, &ctrl1, 1);
    if (err == ESP_OK) {
        err = rd(PCF85063_REG_SECONDS, r, sizeof(r));
    }
    xSemaphoreGive(s_lock);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "read failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }
    if (ctrl1 & (PCF85063_CTRL1_STOP | PCF85063_CTRL1_12_24)) {
        /* Stopped or in 12 h mode: never written by this firmware, not trustworthy. */
        return ESP_ERR_INVALID_STATE;
    }
    const int rc = pcf85063_decode(r, epoch_s);
    if (rc != PCF_OK) {
        ESP_LOGW(TAG, "RTC time not valid (%s)",
                 rc == PCF_E_OSF ? "oscillator stopped" : rc == PCF_E_BCD ? "bad BCD" : "out of range");
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

esp_err_t board_rtc_set_utc(int64_t epoch_s) {
    if (epoch_s < GW_TIME_VALID_MIN_S) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!board_rtc_present()) {
        return ESP_ERR_NOT_FOUND;
    }
    uint8_t buf[1 + PCF85063_TIME_LEN];
    buf[0] = PCF85063_REG_SECONDS;
    if (!pcf85063_encode(epoch_s, &buf[1])) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint8_t ctrl1 = 0;
    esp_err_t err = rd(PCF85063_REG_CTRL1, &ctrl1, 1);
    if (err == ESP_OK && (ctrl1 & (PCF85063_CTRL1_STOP | PCF85063_CTRL1_12_24))) {
        /* Run in 24-hour mode; keep the other bits (capacitor selection, interrupts). */
        const uint8_t w[2] = {PCF85063_REG_CTRL1, (uint8_t)(ctrl1 & ~(PCF85063_CTRL1_STOP | PCF85063_CTRL1_12_24))};
        err = i2c_master_transmit(s_dev, w, sizeof(w), BOARD_I2C_TIMEOUT_MS);
    }
    if (err == ESP_OK) {
        /* Writing the seconds register also clears the OS flag (bit 7 = 0). */
        err = i2c_master_transmit(s_dev, buf, sizeof(buf), BOARD_I2C_TIMEOUT_MS);
    }
    xSemaphoreGive(s_lock);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "write failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }
    return ESP_OK;
}
