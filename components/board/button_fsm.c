/* BOOT button gesture state machine (pure C). Contract: button_fsm.h. */
#include "button_fsm.h"

#include <string.h>

#include "board/board.h"

enum {
    BTN_F_AP_ARMED = 1u << 0,
    BTN_F_AP_DISARMED = 1u << 1,
    BTN_F_RESET_ARMED = 1u << 2,
    BTN_F_RESET_DISARMED = 1u << 3,
};

void btn_fsm_init(btn_fsm_t *f, bool pressed_now, uint32_t now_ms, uint32_t debounce_ms) {
    memset(f, 0, sizeof(*f));
    f->level = pressed_now;
    f->ignore = pressed_now;
    f->cand_ms = now_ms;
    f->debounce_ms = debounce_ms;
}

bool btn_fsm_pressed(const btn_fsm_t *f) {
    return f->level && !f->ignore;
}

uint8_t btn_fsm_classify(uint32_t held_ms, bool reset_disarmed) {
    if (held_ms < BOARD_BTN_AP_MIN_MS) {
        return BOARD_BTN_RELEASED_SHORT;
    }
    if (held_ms <= BOARD_BTN_AP_MAX_MS) {
        return BOARD_BTN_RELEASED_AP;
    }
    if (held_ms < BOARD_BTN_RESET_MS || reset_disarmed) {
        return BOARD_BTN_RELEASED_NONE;
    }
    return BOARD_BTN_RELEASED_RESET;
}

static size_t emit(btn_fsm_event_t *out, size_t n, size_t cap, uint8_t ev, uint32_t held) {
    if (n < cap) {
        out[n].ev = ev;
        out[n].held_ms = held;
        return n + 1;
    }
    return n;
}

/* Emit every hold threshold reached at `held` that was not emitted yet for this press. */
static size_t emit_thresholds(btn_fsm_t *f, uint32_t held, btn_fsm_event_t *out, size_t n, size_t cap) {
    if (held >= BOARD_BTN_AP_MIN_MS && !(f->flags & BTN_F_AP_ARMED)) {
        f->flags |= BTN_F_AP_ARMED;
        n = emit(out, n, cap, BOARD_BTN_AP_ARMED, held);
    }
    if (held > BOARD_BTN_AP_MAX_MS && !(f->flags & BTN_F_AP_DISARMED)) {
        f->flags |= BTN_F_AP_DISARMED;
        n = emit(out, n, cap, BOARD_BTN_AP_DISARMED, held);
    }
    if (held >= BOARD_BTN_RESET_MS && !(f->flags & BTN_F_RESET_ARMED)) {
        f->flags |= BTN_F_RESET_ARMED;
        n = emit(out, n, cap, BOARD_BTN_RESET_ARMED, held);
    }
    if (held >= BOARD_BTN_RESET_CANCEL_MS && !(f->flags & BTN_F_RESET_DISARMED)) {
        f->flags |= BTN_F_RESET_DISARMED;
        n = emit(out, n, cap, BOARD_BTN_RESET_DISARMED, held);
    }
    return n;
}

size_t btn_fsm_step(btn_fsm_t *f, bool raw_pressed, uint32_t now_ms, btn_fsm_event_t *out, size_t cap) {
    size_t n = 0;

    if (raw_pressed == f->level) {
        f->cand_active = false;
    } else {
        if (!f->cand_active) {
            f->cand_active = true;
            f->cand_ms = now_ms;
        }
        if ((uint32_t)(now_ms - f->cand_ms) >= f->debounce_ms) {
            /* Debounced transition; its physical edge happened at cand_ms. */
            const uint32_t edge = f->cand_ms;
            f->level = raw_pressed;
            f->cand_active = false;
            if (f->ignore) {
                if (!raw_pressed) {
                    f->ignore = false; /* the pre-init press is over */
                }
                return 0;
            }
            if (raw_pressed) {
                f->press_ms = edge;
                f->flags = 0;
                n = emit(out, n, cap, BOARD_BTN_PRESSED, 0);
                /* A very long debounce could already pass a threshold. */
                return emit_thresholds(f, (uint32_t)(now_ms - f->press_ms), out, n, cap);
            }
            const uint32_t held = (uint32_t)(edge - f->press_ms);
            n = emit_thresholds(f, held, out, n, cap);
            n = emit(out, n, cap, btn_fsm_classify(held, (f->flags & BTN_F_RESET_DISARMED) != 0), held);
            f->flags = 0;
            return n;
        }
    }

    if (f->level && !f->ignore) {
        /* While a release is being debounced the hold ended at its raw edge, not now. */
        const uint32_t until = f->cand_active ? f->cand_ms : now_ms;
        n = emit_thresholds(f, (uint32_t)(until - f->press_ms), out, n, cap);
    }
    return n;
}
