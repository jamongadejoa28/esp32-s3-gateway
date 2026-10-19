/* Device clocks of gw_core/gw_time.h ([device] functions). The pure calendar helpers live in
 * gw_time_civil.c (host-tested). */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"

static const char *TAG = "gw_time";

/* Upper bound of the calendar helpers (2105-12-31T23:59:59Z, gw_time_civil.c). */
#define GW_TIME_VALID_MAX_S 4291747199LL
#define TIME_EVT_POST_MS 10

static atomic_bool s_was_valid; /* wall time was valid at least once since boot */

uint64_t gw_time_mono_ms(void) {
    return (uint64_t)esp_timer_get_time() / 1000u;
}

static int64_t raw_wall_ms(void) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int64_t gw_time_wall_ms(void) {
    const int64_t ms = raw_wall_ms();
    return ms >= GW_TIME_VALID_MIN_S * 1000 ? ms : 0;
}

bool gw_time_valid(void) {
    return gw_time_wall_ms() != 0;
}

bool gw_time_set_wall_ms(int64_t wall_ms, uint8_t source, const char *by) {
    if (wall_ms < GW_TIME_VALID_MIN_S * 1000 || wall_ms > GW_TIME_VALID_MAX_S * 1000 + 999) {
        ESP_LOGW(TAG, "rejected implausible time %lld ms (source %u)", (long long)wall_ms, source);
        return false;
    }
    const int64_t old = gw_time_wall_ms();
    struct timeval tv = {.tv_sec = (time_t)(wall_ms / 1000), .tv_usec = (suseconds_t)((wall_ms % 1000) * 1000)};
    if (settimeofday(&tv, NULL) != 0) {
        ESP_LOGE(TAG, "settimeofday failed");
        return false;
    }
    const bool first = !atomic_exchange(&s_was_valid, true);

    gw_evt_time_t ev = {
        .source = source,
        .first_valid = first,
        .wall_ms = wall_ms,
        .delta_ms = old ? wall_ms - old : 0,
    };
    gw_strlcpy(ev.by, by ? by : "", sizeof(ev.by));
    /* Before gw_events_init() (RTC load in board_init) this returns ESP_ERR_INVALID_STATE: the
     * event is intentionally skipped (gw_time.h). */
    esp_err_t err = gw_events_post(GW_EVT_TIME_SYNC, &ev, sizeof(ev),
                                   gw_events_in_loop_task() ? 0 : TIME_EVT_POST_MS);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "TIME_SYNC event dropped: %s", esp_err_to_name(err));
    }
    ESP_LOGI(TAG, "wall clock set (source %u, delta %lld ms%s)", source, (long long)ev.delta_ms,
             first ? ", first valid" : "");
    return true;
}

bool gw_time_set_tz(const char *tz) {
    if (!tz || !tz[0] || strlen(tz) >= GW_TZ_SZ) {
        return false;
    }
    if (setenv("TZ", tz, 1) != 0) {
        return false;
    }
    tzset();
    return true;
}
