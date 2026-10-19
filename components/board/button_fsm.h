/*
 * button_fsm.h - BOOT button debounce + gesture state machine (pure C, host-tested in
 * tests/test_board_pure.py). Private to the board component; button.c feeds it the raw GPIO level
 * every BOARD_BTN_POLL_MS from an esp_timer callback.
 *
 * Time is an injected monotonic millisecond counter (wraps are handled with unsigned arithmetic).
 * Gestures (board.h):
 *   press (debounced)                           -> BOARD_BTN_PRESSED
 *   held >= BOARD_BTN_AP_MIN_MS                 -> BOARD_BTN_AP_ARMED
 *   held >  BOARD_BTN_AP_MAX_MS                 -> BOARD_BTN_AP_DISARMED
 *   held >= BOARD_BTN_RESET_MS                  -> BOARD_BTN_RESET_ARMED
 *   held >= BOARD_BTN_RESET_CANCEL_MS           -> BOARD_BTN_RESET_DISARMED (stuck-button guard)
 *   release: < AP_MIN short, AP_MIN..AP_MAX ap, AP_MAX..RESET none (cancel window), >= RESET reset
 *            (none again once the reset was disarmed).
 * Hold durations are measured from the first raw edge of the press to the first raw edge of the
 * release (debounce does not shorten them). Thresholds crossed between two samples are emitted, in
 * order, before the release event, so a RELEASED_RESET is always preceded by RESET_ARMED.
 * A button already pressed at init is ignored until it has been released once.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BTN_FSM_MAX_EVENTS 6 /* PRESSED/armed thresholds/release emitted by one step at most */

typedef struct {
    uint8_t ev;       /* board_btn_event_t */
    uint32_t held_ms; /* hold time at the event (0 for PRESSED) */
} btn_fsm_event_t;

typedef struct {
    bool level;         /* debounced level (true = pressed) */
    bool ignore;        /* pressed at init: wait for a release first */
    bool cand_active;   /* raw level differs from `level` since cand_ms */
    uint32_t cand_ms;   /* first sample time of the pending raw change */
    uint32_t press_ms;  /* raw edge time of the current press */
    uint8_t flags;      /* BTN_F_* thresholds already emitted for the current press */
    uint32_t debounce_ms;
} btn_fsm_t;

/** Reset the machine. `pressed_now` = raw level at init (a held button is ignored until released). */
void btn_fsm_init(btn_fsm_t *f, bool pressed_now, uint32_t now_ms, uint32_t debounce_ms);

/**
 * Feed one raw sample. Writes up to BTN_FSM_MAX_EVENTS events to out (cap >= BTN_FSM_MAX_EVENTS)
 * and returns their number.
 */
size_t btn_fsm_step(btn_fsm_t *f, bool raw_pressed, uint32_t now_ms, btn_fsm_event_t *out, size_t cap);

/** Debounced level. */
bool btn_fsm_pressed(const btn_fsm_t *f);

/** Release classification for a hold of held_ms (pure helper, exported for tests). */
uint8_t btn_fsm_classify(uint32_t held_ms, bool reset_disarmed);

#ifdef __cplusplus
}
#endif
