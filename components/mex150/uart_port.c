/*
 * uart_port.c - RS485 UART1 access for the MEX150 service (device only; see mex_uart.h).
 *
 * The board's transceiver switches direction automatically (no DE/RTS line), so the UART runs in
 * plain UART mode. The RX ring buffer holds several maximum-size RTU frames; TX is unbuffered
 * (requests are 8 bytes and fit the hardware FIFO).
 */
#include "mex_uart.h"

#include <limits.h>

#include "board_pins.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mex150/frame.h"
#include "mex_core.h"

static const char *TAG = "mex_uart";

#define MEX_UART_PORT ((uart_port_t)BOARD_RS485_UART)
#define MEX_UART_RX_BUF 1024 /* > SOC_UART_FIFO_LEN, 4 x MEX_FRAME_MAX */
#define MEX_UART_RX_TOUT_SYMBOLS 3 /* RX FIFO -> ring buffer after 3 idle symbols (< 3.5 char RTU gap) */

static uint32_t s_baud = 9600;

static uart_parity_t parity_of(char p) {
    return p == 'E' ? UART_PARITY_EVEN : p == 'O' ? UART_PARITY_ODD : UART_PARITY_DISABLE;
}

static uart_stop_bits_t stop_of(uint8_t s) {
    return s == 2 ? UART_STOP_BITS_2 : UART_STOP_BITS_1;
}

static TickType_t ms_to_ticks_ceil(uint32_t ms) {
    const TickType_t t = (TickType_t)((ms + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS);
    return (ms && !t) ? 1 : t;
}

esp_err_t mex_uart_open(const mex_port_cfg_t *port) {
    if (!port)
        return ESP_ERR_INVALID_ARG;
    if (uart_is_driver_installed(MEX_UART_PORT))
        return ESP_ERR_INVALID_STATE;
    const uart_config_t cfg = {
        .baud_rate = (int)port->baud,
        .data_bits = UART_DATA_8_BITS,
        .parity = parity_of(port->parity),
        .stop_bits = stop_of(port->stop),
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t err = uart_driver_install(MEX_UART_PORT, MEX_UART_RX_BUF, 0, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "driver install failed: %s", esp_err_to_name(err));
        return err;
    }
    err = uart_param_config(MEX_UART_PORT, &cfg);
    if (err == ESP_OK)
        err = uart_set_pin(MEX_UART_PORT, BOARD_RS485_TX_GPIO, BOARD_RS485_RX_GPIO, UART_PIN_NO_CHANGE,
                           UART_PIN_NO_CHANGE);
    if (err == ESP_OK)
        err = uart_set_mode(MEX_UART_PORT, UART_MODE_UART);
    if (err == ESP_OK)
        err = uart_set_rx_timeout(MEX_UART_PORT, MEX_UART_RX_TOUT_SYMBOLS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART%d setup failed: %s", (int)MEX_UART_PORT, esp_err_to_name(err));
        uart_driver_delete(MEX_UART_PORT);
        return err;
    }
    s_baud = port->baud;
    ESP_LOGI(TAG, "UART%d TX=%d RX=%d %lu %c%u", (int)MEX_UART_PORT, BOARD_RS485_TX_GPIO, BOARD_RS485_RX_GPIO,
             (unsigned long)port->baud, port->parity, (unsigned)port->stop);
    return ESP_OK;
}

esp_err_t mex_uart_apply(const mex_port_cfg_t *port) {
    if (!port)
        return ESP_ERR_INVALID_ARG;
    if (!uart_is_driver_installed(MEX_UART_PORT))
        return ESP_ERR_INVALID_STATE;
    esp_err_t err = uart_set_baudrate(MEX_UART_PORT, port->baud);
    if (err == ESP_OK)
        err = uart_set_parity(MEX_UART_PORT, parity_of(port->parity));
    if (err == ESP_OK)
        err = uart_set_stop_bits(MEX_UART_PORT, stop_of(port->stop));
    if (err == ESP_OK)
        err = uart_set_rx_timeout(MEX_UART_PORT, MEX_UART_RX_TOUT_SYMBOLS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "line settings failed: %s", esp_err_to_name(err));
        return err;
    }
    s_baud = port->baud;
    uart_flush_input(MEX_UART_PORT);
    ESP_LOGI(TAG, "line settings %lu %c%u", (unsigned long)port->baud, port->parity, (unsigned)port->stop);
    return ESP_OK;
}

void mex_uart_close(void) {
    if (uart_is_driver_installed(MEX_UART_PORT))
        uart_driver_delete(MEX_UART_PORT);
}

void mex_uart_gap(uint16_t gap_ms) {
    if (gap_ms)
        vTaskDelay(ms_to_ticks_ceil(gap_ms));
    uart_flush_input(MEX_UART_PORT); /* late bytes of a previous (timed-out) answer */
}

int mex_uart_write(const uint8_t *buf, size_t n) {
    if (!buf || !n)
        return MEX_TXN_E_UART;
    const int w = uart_write_bytes(MEX_UART_PORT, buf, n);
    if (w < 0 || (size_t)w != n)
        return MEX_TXN_E_UART;
    /* 11 bit times per byte worst case (8 data + parity + 2 stop) + scheduling margin. */
    const uint32_t ms = (uint32_t)((n * 11u * 1000u + s_baud - 1u) / (s_baud ? s_baud : 9600u)) + 20u;
    return uart_wait_tx_done(MEX_UART_PORT, ms_to_ticks_ceil(ms)) == ESP_OK ? 0 : MEX_TXN_E_UART;
}

/* uart_read_bytes() applies ticks_to_wait to every ring-buffer chunk, so a call for many bytes on a
 * line that trickles (noise, a babbling node, a second master) could block for want x timeout and trip
 * the TWDT. mex_rx_bounded() turns these primitives into a read with a total deadline. */
_Static_assert(sizeof(TickType_t) == sizeof(uint32_t), "mex_rx_bounded wrap arithmetic needs 32-bit ticks");

static uint32_t rx_now(void *ctx) {
    (void)ctx;
    return (uint32_t)xTaskGetTickCount();
}

static int rx_avail(void *ctx) {
    (void)ctx;
    size_t n = 0;
    if (uart_get_buffered_data_len(MEX_UART_PORT, &n) != ESP_OK)
        return -1;
    return n > (size_t)INT_MAX ? INT_MAX : (int)n;
}

static int rx_recv(void *ctx, uint8_t *buf, size_t n, uint32_t wait) {
    (void)ctx;
    return uart_read_bytes(MEX_UART_PORT, buf, (uint32_t)n, (TickType_t)wait);
}

static const mex_rx_ops_t s_rx_ops = {.ctx = NULL, .now = rx_now, .avail = rx_avail, .recv = rx_recv};

int mex_uart_read(uint8_t *buf, size_t want, uint32_t timeout_ms) {
    if (!buf)
        return MEX_TXN_E_UART;
    if (!want)
        return 0;
    const int got = mex_rx_bounded(&s_rx_ops, buf, want, (uint32_t)ms_to_ticks_ceil(timeout_ms));
    if (got < 0)
        ESP_LOGW(TAG, "UART read failed");
    return got;
}
