/*
 * pcf85063_codec.h - PCF85063 time register codec (pure C, host-tested in tests/test_board_pure.py).
 * Private to the board component. The RTC keeps UTC (DESIGN.md §5) in 24-hour mode.
 *
 * Register block read/written starting at PCF85063_REG_SECONDS (7 bytes):
 *   [0] seconds (bit 7 = OS oscillator-stop flag)  [1] minutes  [2] hours (24 h)  [3] days
 *   [4] weekdays (0 = Sunday)  [5] months  [6] years (00..99 = 2000..2099)
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCF85063_REG_CTRL1 0x00
#define PCF85063_REG_CTRL2 0x01
#define PCF85063_REG_SECONDS 0x04
#define PCF85063_TIME_LEN 7

#define PCF85063_CTRL1_STOP 0x20  /* clock stopped */
#define PCF85063_CTRL1_12_24 0x02 /* 1 = 12-hour mode */
#define PCF85063_OS_FLAG 0x80

/* Decode results. */
#define PCF_OK 0
#define PCF_E_OSF 1   /* oscillator stopped since the last write: time not trustworthy */
#define PCF_E_BCD 2   /* malformed BCD digit */
#define PCF_E_RANGE 3 /* field out of range or before GW_TIME_VALID_MIN_S */

/** BCD byte -> 0..99, or -1 if a nibble is > 9. */
int pcf_bcd_decode(uint8_t b);

/** 0..99 -> BCD byte (values > 99 are reduced modulo 100). */
uint8_t pcf_bcd_encode(uint8_t v);

/** Decode the 7 time registers to UTC epoch seconds. Returns PCF_OK or PCF_E_*. */
int pcf85063_decode(const uint8_t r[PCF85063_TIME_LEN], int64_t *epoch_s);

/**
 * Encode UTC epoch seconds (2000-01-01 .. 2099-12-31) into the 7 time registers with the OS flag
 * cleared. Returns false when epoch_s is outside that range.
 */
bool pcf85063_encode(int64_t epoch_s, uint8_t r[PCF85063_TIME_LEN]);

#ifdef __cplusplus
}
#endif
