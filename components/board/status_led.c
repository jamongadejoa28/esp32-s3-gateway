/* WS2812 status LED on GPIO38 (espressif/led_strip, RMT backend). board_led_set() only stores the
 * requested state (atomic); a 50 ms esp_timer renders solid/blink patterns and refreshes the strip
 * only when the output colour changes. */
#include <stdatomic.h>

#include "board/board.h"
#include "board_pins.h"
#include "board_priv.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "led_strip.h"

static const char *TAG = "led";

#define LED_TICK_MS 50

typedef enum { PAT_SOLID = 0, PAT_SLOW = 1, PAT_FAST = 2 } led_pat_t;

typedef struct {
    uint8_t r, g, b;
    uint8_t pat;
} led_style_t;

/* Dim levels: the LED sits behind a light pipe on a DIN-rail device. */
static const led_style_t STYLE[BOARD_LED_COUNT] = {
    [BOARD_LED_OFF] = {0, 0, 0, PAT_SOLID},
    [BOARD_LED_BOOT] = {24, 24, 24, PAT_SOLID},
    [BOARD_LED_OK] = {0, 12, 0, PAT_SOLID},
    [BOARD_LED_NO_NET] = {24, 24, 24, PAT_SLOW},
    [BOARD_LED_AP] = {0, 0, 48, PAT_SLOW},
    [BOARD_LED_COMM_LOST] = {48, 18, 0, PAT_SOLID},
    [BOARD_LED_ALARM] = {48, 18, 0, PAT_SLOW},
    [BOARD_LED_CRITICAL] = {64, 0, 0, PAT_SLOW},
    [BOARD_LED_FAULT] = {64, 0, 0, PAT_FAST},
    [BOARD_LED_OTA] = {0, 0, 48, PAT_FAST},
    [BOARD_LED_AP_ARMED] = {0, 0, 64, PAT_SOLID},
    [BOARD_LED_RESET_ARMED] = {64, 0, 0, PAT_SOLID},
};

static led_strip_handle_t s_strip;
static esp_timer_handle_t s_timer;
static atomic_uint s_state = BOARD_LED_BOOT;
static uint32_t s_last_rgb = 0xFFFFFFFFu; /* esp_timer task only */
static uint32_t s_ticks;                  /* esp_timer task only */

static void render(void *arg) {
    (void)arg;
    s_ticks++;
    unsigned st = atomic_load(&s_state);
    if (st >= BOARD_LED_COUNT) {
        st = BOARD_LED_OFF;
    }
    const led_style_t *s = &STYLE[st];
    bool on = true;
    if (s->pat == PAT_SLOW) {
        on = (s_ticks / (500 / LED_TICK_MS)) % 2 == 0; /* 1 Hz */
    } else if (s->pat == PAT_FAST) {
        on = (s_ticks / (100 / LED_TICK_MS)) % 2 == 0; /* 5 Hz */
    }
    const uint32_t rgb = on ? ((uint32_t)s->r << 16 | (uint32_t)s->g << 8 | s->b) : 0;
    if (rgb == s_last_rgb) {
        return;
    }
    esp_err_t err = led_strip_set_pixel(s_strip, 0, rgb >> 16, (rgb >> 8) & 0xFF, rgb & 0xFF);
    if (err == ESP_OK) {
        err = led_strip_refresh(s_strip);
    }
    if (err == ESP_OK) {
        s_last_rgb = rgb;
    }
}

esp_err_t board_led_init(void) {
    if (s_strip) {
        return ESP_OK;
    }
    const led_strip_config_t cfg = {
        .strip_gpio_num = BOARD_LED_GPIO,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };
    const led_strip_rmt_config_t rmt = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
    };
    esp_err_t err = led_strip_new_rmt_device(&cfg, &rmt, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_strip init failed: %s", esp_err_to_name(err));
        s_strip = NULL;
        return err;
    }
    const esp_timer_create_args_t targs = {
        .callback = render,
        .name = "status_led",
        .dispatch_method = ESP_TIMER_TASK,
        .skip_unhandled_events = true,
    };
    err = esp_timer_create(&targs, &s_timer);
    if (err == ESP_OK) {
        err = esp_timer_start_periodic(s_timer, LED_TICK_MS * 1000);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led timer failed: %s", esp_err_to_name(err));
        if (s_timer) {
            esp_timer_delete(s_timer);
            s_timer = NULL;
        }
        led_strip_del(s_strip);
        s_strip = NULL;
        return err;
    }
    return ESP_OK;
}

void board_led_set(board_led_t state) {
    if ((unsigned)state >= BOARD_LED_COUNT) {
        return;
    }
    atomic_store(&s_state, (unsigned)state);
}
