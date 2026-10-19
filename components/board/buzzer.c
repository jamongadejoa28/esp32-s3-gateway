/* Buzzer on GPIO46 (strapping pin): driven LOW from board_init() on and kept LOW except during a
 * board_buzzer_beep() (non-blocking, esp_timer turns it off). */
#include <stdatomic.h>

#include "board/board.h"
#include "board_pins.h"
#include "board_priv.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "buzzer";

#define BUZZER_MAX_MS 1000

static esp_timer_handle_t s_off_timer;
static atomic_bool s_ready;

static void buzzer_off(void *arg) {
    (void)arg;
    gpio_set_level(BOARD_BUZZER_GPIO, 0);
}

esp_err_t board_buzzer_init(void) {
    const gpio_config_t io = {
        .pin_bit_mask = 1ULL << BOARD_BUZZER_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    /* Level first so the pin never glitches HIGH when it becomes an output. */
    gpio_set_level(BOARD_BUZZER_GPIO, 0);
    esp_err_t err = gpio_config(&io);
    if (err == ESP_OK) {
        err = gpio_set_level(BOARD_BUZZER_GPIO, 0);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO%d config failed: %s", BOARD_BUZZER_GPIO, esp_err_to_name(err));
        return err;
    }
    if (!s_off_timer) {
        const esp_timer_create_args_t targs = {.callback = buzzer_off, .name = "buzzer"};
        err = esp_timer_create(&targs, &s_off_timer);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "beep timer unavailable: %s", esp_err_to_name(err));
            return ESP_OK; /* the pin is safely LOW; only beeps are unavailable */
        }
    }
    atomic_store(&s_ready, true);
    return ESP_OK;
}

void board_buzzer_beep(uint32_t ms) {
    if (!atomic_load(&s_ready)) {
        return;
    }
    if (ms == 0) {
        ms = 1;
    } else if (ms > BUZZER_MAX_MS) {
        ms = BUZZER_MAX_MS;
    }
    esp_timer_stop(s_off_timer); /* ESP_ERR_INVALID_STATE when idle: fine */
    /* Pin HIGH before the off-timer is armed: if this task is preempted in between, the beep only
     * gets longer. The reverse order could let the timer fire first and leave the buzzer on. */
    gpio_set_level(BOARD_BUZZER_GPIO, 1);
    if (esp_timer_start_once(s_off_timer, (uint64_t)ms * 1000) != ESP_OK) {
        gpio_set_level(BOARD_BUZZER_GPIO, 0);
    }
}
