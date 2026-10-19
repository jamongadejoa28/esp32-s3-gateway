/* Board I2C bus (new i2c_master driver). The driver serializes transactions with its own bus lock,
 * so devices may be used from several tasks. Only the RTC (0x51) is attached; the TCA9554 relay
 * expander (0x20) is never touched (board_io.h). */
#include "board_pins.h"
#include "board_priv.h"
#include "esp_log.h"

static const char *TAG = "board_i2c";

static i2c_master_bus_handle_t s_bus;

esp_err_t board_i2c_init(void) {
    if (s_bus) {
        return ESP_OK;
    }
    const i2c_master_bus_config_t cfg = {
        .i2c_port = BOARD_I2C_PORT,
        .sda_io_num = BOARD_I2C_SDA_GPIO,
        .scl_io_num = BOARD_I2C_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true, /* the board has external pull-ups; harmless */
    };
    esp_err_t err = i2c_new_master_bus(&cfg, &s_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bus init failed: %s", esp_err_to_name(err));
        s_bus = NULL;
    }
    return err;
}

esp_err_t board_i2c_add(uint16_t addr, i2c_master_dev_handle_t *out) {
    if (!s_bus) {
        return ESP_ERR_INVALID_STATE;
    }
    const i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = addr,
        .scl_speed_hz = BOARD_I2C_HZ,
    };
    return i2c_master_bus_add_device(s_bus, &dev, out);
}

esp_err_t board_i2c_probe(uint16_t addr) {
    if (!s_bus) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2c_master_probe(s_bus, addr, BOARD_I2C_TIMEOUT_MS);
}
