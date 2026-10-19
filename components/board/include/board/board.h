/*
 * board.h - board services: I2C bus, PCF85063 RTC (UTC), WS2812 status LED, buzzer (held LOW),
 * BOOT button gestures. IDF-free header. Never touches GPIO4..11 or the TCA9554 (see board_io.h).
 *
 * board_init() (init order step 3): I2C bus -> RTC read -> if the RTC holds a valid time, sets the
 * system clock via gw_time_set_wall_ms(source RTC) (the TIME_SYNC event is skipped because the
 * event loop does not exist yet) -> LED "boot" -> buzzer GPIO46 LOW -> button ISR + debounce timer.
 * RTC failure is not fatal (board_rtc_present() == false).
 *
 * Threading: all functions are thread-safe (the I2C bus has an internal mutex) and callable from
 * any task, not from ISRs. RTC calls block for an I2C transaction (< 5 ms).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Button gesture thresholds (DESIGN.md §5) */
#define BOARD_BTN_DEBOUNCE_MS 30
#define BOARD_BTN_AP_MIN_MS 3000
#define BOARD_BTN_AP_MAX_MS 8000
#define BOARD_BTN_RESET_MS 10000
/* Stuck-button guard (stream F addition, DECISIONS.md F): a reset armed at 10 s is disarmed again
 * if the button is still held at 30 s; the release then does nothing. */
#define BOARD_BTN_RESET_CANCEL_MS 30000

/**
 * LED states (rendered by board; chosen by the sysmgr supervisor, sys_led_select(), highest
 * priority first):
 *   RESET_ARMED  solid red         - BOOT held >= 10 s, factory reset on release
 *   AP_ARMED     solid blue        - BOOT held 3..8 s, AP on release
 *   BOOT         white solid       - boot grace: until every required heartbeat is fresh or 30 s
 *                                    passed (so a link still coming up does not read as NO_NET);
 *                                    skipped when app_main latched an init fault
 *   OTA          blue fast blink   - firmware upload in progress
 *   FAULT        red fast blink    - init failure (sys_init_fault_set) / stale heartbeat
 *   CRITICAL     red slow blink    - critical alarm active
 *   ALARM        amber slow blink  - major/minor alarm active
 *   COMM_LOST    amber solid       - an enabled device is offline
 *   AP           blue slow blink   - recovery AP active
 *   NO_NET       white slow blink  - no Ethernet link/IP
 *   OK           green dim solid   - all good
 *   OFF
 * Before supervisor_start() board_init() shows BOOT and app_main may set FAULT directly.
 */
typedef enum {
    BOARD_LED_OFF = 0,
    BOARD_LED_BOOT,
    BOARD_LED_OK,
    BOARD_LED_NO_NET,
    BOARD_LED_AP,
    BOARD_LED_COMM_LOST,
    BOARD_LED_ALARM,
    BOARD_LED_CRITICAL,
    BOARD_LED_FAULT,
    BOARD_LED_OTA,
    BOARD_LED_AP_ARMED,
    BOARD_LED_RESET_ARMED,
    BOARD_LED_COUNT
} board_led_t;

/** Button events. *_ARMED fire while still held; RELEASED_* fire once on release. */
typedef enum {
    BOARD_BTN_PRESSED = 0,
    BOARD_BTN_AP_ARMED,       /* held >= BOARD_BTN_AP_MIN_MS */
    BOARD_BTN_AP_DISARMED,    /* held > BOARD_BTN_AP_MAX_MS (no action on release unless reset) */
    BOARD_BTN_RESET_ARMED,    /* held >= BOARD_BTN_RESET_MS */
    BOARD_BTN_RELEASED_SHORT, /* < BOARD_BTN_AP_MIN_MS: no action */
    BOARD_BTN_RELEASED_AP,    /* released within 3..8 s: start recovery AP */
    BOARD_BTN_RELEASED_NONE,  /* released within 8..10 s: no action */
    BOARD_BTN_RELEASED_RESET, /* released after >= 10 s: factory reset */
    BOARD_BTN_RESET_DISARMED, /* held >= BOARD_BTN_RESET_CANCEL_MS: reset cancelled (stream F addition) */
} board_btn_event_t;

/** Button callback: runs in the esp_timer task; must not block (forward to the supervisor queue). */
typedef void (*board_btn_cb_t)(board_btn_event_t ev, uint32_t held_ms, void *arg);

/** Initialise board peripherals (see file comment). */
esp_err_t board_init(void);

/** Set the status LED state (non-blocking; rendering happens in the LED driver). */
void board_led_set(board_led_t state);

/** Register the single button callback (supervisor). NULL disables. */
void board_button_set_cb(board_btn_cb_t cb, void *arg);

/** Current debounced button level (true = pressed). */
bool board_button_pressed(void);

/** RTC detected on the I2C bus at init. */
bool board_rtc_present(void);

/**
 * Read the RTC as UTC epoch seconds.
 * @return ESP_OK, ESP_ERR_NOT_FOUND (no RTC), ESP_ERR_INVALID_STATE (oscillator-stop flag set or
 *         implausible value: time not trustworthy), ESP_FAIL (I2C error).
 */
esp_err_t board_rtc_get_utc(int64_t *epoch_s);

/** Write UTC epoch seconds (>= GW_TIME_VALID_MIN_S) and clear the oscillator-stop flag. */
esp_err_t board_rtc_set_utc(int64_t epoch_s);

/** eFuse base MAC (identity source for gw_ident_*). */
void board_base_mac(uint8_t mac[GW_MAC_LEN]);

/**
 * Sound the buzzer (GPIO46) for ms milliseconds (clamped to 1..1000), then drive it LOW again.
 * Non-blocking (esp_timer); a beep in progress is extended. No-op before board_init().
 * Stream F addition (DECISIONS.md F): used for button gesture feedback.
 */
void board_buzzer_beep(uint32_t ms);

#ifdef __cplusplus
}
#endif
