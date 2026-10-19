/* BOOT button (GPIO0, active low). Sampled every BOARD_BTN_POLL_MS by an esp_timer; debounce and
 * gestures are the pure button_fsm.c. Polling instead of a GPIO ISR because esp_timer start/stop
 * are not ISR-safe in IDF 6.1 (DECISIONS.md F); the cost is one short callback per 20 ms. */
#include <stdatomic.h>

#include "board/board.h"
#include "board_pins.h"
#include "board_priv.h"
#include "button_fsm.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

static const char *TAG = "button";

static esp_timer_handle_t s_timer;
static btn_fsm_t s_fsm; /* esp_timer task only (after init) */
static atomic_bool s_pressed;
static portMUX_TYPE s_cb_mux = portMUX_INITIALIZER_UNLOCKED;
static board_btn_cb_t s_cb;
static void *s_cb_arg;

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static bool raw_pressed(void) {
    return gpio_get_level(BOARD_BUTTON_GPIO) == 0;
}

static void poll(void *arg) {
    (void)arg;
    btn_fsm_event_t ev[BTN_FSM_MAX_EVENTS];
    const size_t n = btn_fsm_step(&s_fsm, raw_pressed(), now_ms(), ev, BTN_FSM_MAX_EVENTS);
    atomic_store(&s_pressed, btn_fsm_pressed(&s_fsm));
    if (!n) {
        return;
    }
    portENTER_CRITICAL(&s_cb_mux);
    board_btn_cb_t cb = s_cb;
    void *cb_arg = s_cb_arg;
    portEXIT_CRITICAL(&s_cb_mux);
    for (size_t i = 0; i < n; i++) {
        ESP_LOGD(TAG, "event %u held %u ms", ev[i].ev, (unsigned)ev[i].held_ms);
        if (cb) {
            cb((board_btn_event_t)ev[i].ev, ev[i].held_ms, cb_arg);
        }
    }
}

esp_err_t board_button_init(void) {
    if (s_timer) {
        return ESP_OK;
    }
    const gpio_config_t io = {
        .pin_bit_mask = 1ULL << BOARD_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&io);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO%d config failed: %s", BOARD_BUTTON_GPIO, esp_err_to_name(err));
        return err;
    }
    btn_fsm_init(&s_fsm, raw_pressed(), now_ms(), BOARD_BTN_DEBOUNCE_MS);
    if (btn_fsm_pressed(&s_fsm) == false && raw_pressed()) {
        ESP_LOGW(TAG, "BOOT held at init: ignored until released");
    }
    const esp_timer_create_args_t targs = {
        .callback = poll,
        .name = "button",
        .dispatch_method = ESP_TIMER_TASK,
        .skip_unhandled_events = true,
    };
    err = esp_timer_create(&targs, &s_timer);
    if (err == ESP_OK) {
        err = esp_timer_start_periodic(s_timer, BOARD_BTN_POLL_MS * 1000);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "poll timer failed: %s", esp_err_to_name(err));
        if (s_timer) {
            esp_timer_delete(s_timer);
            s_timer = NULL;
        }
    }
    return err;
}

void board_button_set_cb(board_btn_cb_t cb, void *arg) {
    portENTER_CRITICAL(&s_cb_mux);
    s_cb = cb;
    s_cb_arg = arg;
    portEXIT_CRITICAL(&s_cb_mux);
}

bool board_button_pressed(void) {
    return atomic_load(&s_pressed);
}
