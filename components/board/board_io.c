/* Board digital inputs / relays hook (board_io.h): intentionally not implemented in this product.
 * Every function touches no hardware (GPIO4..11 and the TCA9554 stay unconfigured). */
#include "board/board_io.h"

esp_err_t board_io_init(void) {
    return ESP_ERR_NOT_SUPPORTED;
}

bool board_io_available(void) {
    return false;
}

esp_err_t board_io_read_inputs(uint8_t *mask) {
    if (mask) {
        *mask = 0;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t board_io_set_relay(uint8_t idx, bool on) {
    (void)idx;
    (void)on;
    return ESP_ERR_NOT_SUPPORTED;
}
