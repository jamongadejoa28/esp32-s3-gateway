/*
 * mex_uart.h - PRIVATE to components/mex150 (device only). RS485 on UART1 (board_pins.h), automatic
 * direction control by the transceiver (no DE pin). Only the "mex_poll" task calls the I/O functions;
 * open/close happen in mex_service_start() before the task exists or after a failed start.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mex150/service.h"

/** Install the UART driver on BOARD_RS485_UART, route TX/RX pins and apply the line settings. */
esp_err_t mex_uart_open(const mex_port_cfg_t *port);

/** Change baud/parity/stop bits of the open port. */
esp_err_t mex_uart_apply(const mex_port_cfg_t *port);

/** Uninstall the driver (no-op if not installed). */
void mex_uart_close(void);

/** Idle gap before a request (RS485 turnaround), then drop stale received bytes. */
void mex_uart_gap(uint16_t gap_ms);

/** Send n bytes and wait until the last stop bit left. 0 or MEX_TXN_E_UART. */
int mex_uart_write(const uint8_t *buf, size_t n);

/** Read up to want bytes, returning when all arrived or after timeout_ms. Count or MEX_TXN_E_UART. */
int mex_uart_read(uint8_t *buf, size_t want, uint32_t timeout_ms);
