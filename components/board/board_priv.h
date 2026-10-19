/* board_priv.h - internal interfaces between the board component's device files. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

#define BOARD_I2C_TIMEOUT_MS 50
#define BOARD_BTN_POLL_MS 20 /* button sampling period (esp_timer) */

/* i2c_bus.c */
esp_err_t board_i2c_init(void);
/** Add a 7-bit device on the board bus. ESP_ERR_INVALID_STATE before board_i2c_init(). */
esp_err_t board_i2c_add(uint16_t addr, i2c_master_dev_handle_t *out);
/** Probe a 7-bit address (ESP_OK = ACK). */
esp_err_t board_i2c_probe(uint16_t addr);

/* rtc_pcf85063.c */
esp_err_t board_rtc_init(void);

/* status_led.c */
esp_err_t board_led_init(void);

/* buzzer.c */
esp_err_t board_buzzer_init(void);

/* button.c */
esp_err_t board_button_init(void);
