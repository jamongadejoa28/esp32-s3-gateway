/*
 * board_io.h - hook for the board's 8 digital inputs (GPIO4..11) and 8 relays (TCA9554 @0x20).
 * NOT implemented in this product (user decision): every function is a stub that touches no
 * hardware. The API exists so a future build can add board I/O without changing callers.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOARD_IO_DI_COUNT 8
#define BOARD_IO_RELAY_COUNT 8

/** Stub: returns ESP_ERR_NOT_SUPPORTED, configures nothing. */
esp_err_t board_io_init(void);

/** False in this product. */
bool board_io_available(void);

/** Stub: *mask = 0, returns ESP_ERR_NOT_SUPPORTED. Bit i = DI(i+1). */
esp_err_t board_io_read_inputs(uint8_t *mask);

/** Stub: returns ESP_ERR_NOT_SUPPORTED. idx 0..7. */
esp_err_t board_io_set_relay(uint8_t idx, bool on);

#ifdef __cplusplus
}
#endif
