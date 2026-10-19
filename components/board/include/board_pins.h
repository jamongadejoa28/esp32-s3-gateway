/*
 * board_pins.h - Waveshare ESP32-S3-ETH-8DI-8RO pin map (DESIGN.md §1). Pure C (plain ints).
 * GPIO33..37 are used by the octal PSRAM; never touch them.
 */
#pragma once

/* W5500 Ethernet (SPI2) */
#define BOARD_ETH_SPI_HOST 1 /* SPI2_HOST */
#define BOARD_ETH_MOSI_GPIO 13
#define BOARD_ETH_MISO_GPIO 14
#define BOARD_ETH_SCLK_GPIO 15
#define BOARD_ETH_CS_GPIO 16
#define BOARD_ETH_INT_GPIO 12 /* NOT the component default 4 (= DI1 on this board) */
#define BOARD_ETH_RST_GPIO 39 /* from the pin matrix; unverified on hardware -> may become -1 */
#define BOARD_ETH_SPI_MHZ 20

/* RS485 (UART1, automatic direction control, no DE pin) */
#define BOARD_RS485_UART 1
#define BOARD_RS485_TX_GPIO 17
#define BOARD_RS485_RX_GPIO 18

/* I2C bus: TCA9554 @0x20 (relays - never accessed), PCF85063 RTC @0x51 */
#define BOARD_I2C_PORT 0
#define BOARD_I2C_SDA_GPIO 42
#define BOARD_I2C_SCL_GPIO 41
#define BOARD_I2C_HZ 100000
#define BOARD_RTC_I2C_ADDR 0x51
#define BOARD_RTC_INT_GPIO 40
#define BOARD_TCA9554_I2C_ADDR 0x20 /* reserved for board_io; untouched */

/* Status LED (single WS2812 via RMT) */
#define BOARD_LED_GPIO 38

/* Buzzer: strapping pin, driven LOW at boot and kept LOW */
#define BOARD_BUZZER_GPIO 46

/* BOOT button (active low, strapping pin) */
#define BOARD_BUTTON_GPIO 0

/* Digital inputs DI1..DI8 = GPIO4..11: NOT used; reserved for board_io. Never configure them. */
#define BOARD_DI_FIRST_GPIO 4
#define BOARD_DI_COUNT 8

/* TF card (NOT used; GPIO45 is a strapping pin) */
#define BOARD_TF_D0_GPIO 45
#define BOARD_TF_CMD_GPIO 47
#define BOARD_TF_CLK_GPIO 48
