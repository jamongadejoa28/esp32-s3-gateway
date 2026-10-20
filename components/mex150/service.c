/*
 * service.c - MEX150 polling/write service (contract: mex150/service.h; DESIGN.md §9).
 *
 * Thin FreeRTOS binding of the pure engine in mex_core.c: one mutex protects the shared core state,
 * the "mex_poll" task drives mex_core_run_once() and owns UART1 (uart_port.c), and the core's
 * callbacks become gw_evt events (SNAPSHOT, COMM, WRITE_RESULT), TWDT feeds and GW_HB_MEX beats.
 * mex_service_write() waits for its command on a per-caller binary semaphore that the WRITE_RESULT
 * callback gives.
 */
#include "mex150/service.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_time.h"
#include "mex_core.h"
#include "mex_uart.h"

static const char *TAG = "mex150";

#define MEX_TASK_NAME "mex_poll"
#define MEX_TASK_PRIO 10
#define MEX_TASK_STACK 4096
#define MEX_TASK_CORE 1
#define MEX_WAITERS                                                                                          \
    (MEX_WRITE_QUEUE_LEN + 4)   /* > queue: callers whose command was rejected still hold one briefly */
#define MEX_EVT_POST_WAIT_MS 20 /* from API callers (httpd/snmp); the poll task posts with 0 */

static_assert(MEX_R_EXCEPTION(255) <= INT16_MAX, "every reason fits gw_evt_write_t.reason");
static_assert(MEX_TXN_E_UART >= INT16_MIN, "transaction errors fit gw_evt_comm_t.last_err");

typedef struct {
    bool used;
    uint8_t dev;
    uint32_t cmd; /* 0 until the command id is known */
    SemaphoreHandle_t sem;
    StaticSemaphore_t sem_buf;
} waiter_t;

static mex_core_t s_core;
static SemaphoreHandle_t s_lock;
static StaticSemaphore_t s_lock_buf;
static SemaphoreHandle_t s_wlock;
static StaticSemaphore_t s_wlock_buf;
static waiter_t s_waiters[MEX_WAITERS];
static TaskHandle_t s_task;
static atomic_bool s_started;
static bool s_wdt;

/* ---- core I/O bindings ---- */

static void io_lock(void *ctx) {
    (void)ctx;
    xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void io_unlock(void *ctx) {
    (void)ctx;
    xSemaphoreGive(s_lock);
}

static uint64_t io_mono(void *ctx) {
    (void)ctx;
    return gw_time_mono_ms();
}

static int64_t io_wall(void *ctx) {
    (void)ctx;
    return gw_time_wall_ms();
}

static void io_gap(void *ctx, uint16_t gap_ms) {
    (void)ctx;
    mex_uart_gap(gap_ms);
}

static int io_write(void *ctx, const uint8_t *buf, size_t n) {
    (void)ctx;
    return mex_uart_write(buf, n);
}

static int io_read(void *ctx, uint8_t *buf, size_t want, uint32_t timeout_ms) {
    (void)ctx;
    return mex_uart_read(buf, want, timeout_ms);
}

static int io_port_apply(void *ctx, const mex_port_cfg_t *port) {
    (void)ctx;
    return mex_uart_apply(port) == ESP_OK ? 0 : -1;
}

static void io_feed(void *ctx) {
    (void)ctx;
    if (s_wdt)
        esp_task_wdt_reset();
    gw_hb_beat(GW_HB_MEX);
}

static bool in_poll_task(void) {
    return s_task && xTaskGetCurrentTaskHandle() == s_task;
}

static void post(gw_event_id_t id, const void *data, size_t len) {
    const esp_err_t err = gw_events_post(id, data, len, in_poll_task() ? 0 : MEX_EVT_POST_WAIT_MS);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) /* INVALID_STATE: bus not started (early boot) */
        ESP_LOGW(TAG, "event %d dropped: %s", (int)id, esp_err_to_name(err));
}

static void io_on_snapshot(void *ctx, uint8_t dev, uint32_t seq, uint64_t mono_ms, bool slow_fresh) {
    (void)ctx;
    static bool ready[GW_MAX_DEVICES]; /* last published readiness; poll task only */
    mex_snapshot_t snap;
    if (mex_core_snapshot(&s_core, dev, &snap) && (seq == 1 || ready[dev] != snap.measurement_valid)) {
        ready[dev] = snap.measurement_valid;
        ESP_LOGI(TAG, "dev%u measurements %s: temp_raw=%u hum_raw=%u", (unsigned)dev,
                 snap.measurement_valid ? "ready" : "pending", (unsigned)snap.regs[36],
                 (unsigned)snap.regs[37]);
    }
    const gw_evt_snapshot_t ev = {.dev = dev, .slow_fresh = slow_fresh, .seq = seq, .mono_ms = mono_ms};
    post(GW_EVT_SNAPSHOT, &ev, sizeof ev);
}

static void io_on_comm(void *ctx, uint8_t dev, bool online, int last_err, uint32_t offline_count,
                       int64_t ts_ms) {
    (void)ctx;
    if (online)
        ESP_LOGI(TAG, "dev%u online", (unsigned)dev);
    else
        ESP_LOGW(TAG, "dev%u offline (last error %d, offline count %lu)", (unsigned)dev, last_err,
                 (unsigned long)offline_count);
    const gw_evt_comm_t ev = {
        .dev = dev,
        .online = online,
        .last_err = (int16_t)last_err,
        .offline_count = offline_count,
        .ts_ms = ts_ms,
    };
    post(GW_EVT_COMM, &ev, sizeof ev);
}

static void io_on_write(void *ctx, const mex_wresult_t *res, int32_t raw_before, const char *who) {
    (void)ctx;
    static const char *const state_names[] = {"pending", "applied", "rejected", "uncertain"};
    char rbuf[MEX_REASON_NAME_SZ];
    ESP_LOGI(TAG, "dev%u write %u=%ld cmd %lu by '%s': %s (%s) %ld -> %ld", (unsigned)res->dev,
             (unsigned)res->addr, (long)res->raw_req, (unsigned long)res->cmd, who,
             state_names[(unsigned)res->state & 3u], mex_reason_name(res->reason, rbuf, sizeof rbuf),
             (long)raw_before, (long)res->raw_after);
    gw_evt_write_t ev = {
        .dev = res->dev,
        .state = (uint8_t)res->state,
        .addr = res->addr,
        .reason = (int16_t)res->reason,
        .cmd = res->cmd,
        .raw_req = res->raw_req,
        .raw_before = raw_before,
        .raw_after = res->raw_after,
    };
    gw_strlcpy(ev.by, who, sizeof ev.by);
    post(GW_EVT_WRITE_RESULT, &ev, sizeof ev);

    if (!res->cmd)
        return; /* rejected before queueing: the submitter already has the result */
    xSemaphoreTake(s_wlock, portMAX_DELAY);
    for (size_t i = 0; i < MEX_WAITERS; i++) {
        waiter_t *w = &s_waiters[i];
        if (w->used && w->cmd == res->cmd && w->dev == res->dev)
            xSemaphoreGive(w->sem);
    }
    xSemaphoreGive(s_wlock);
}

/* ---- waiters ---- */

static waiter_t *waiter_claim(uint8_t dev) {
    waiter_t *found = NULL;
    xSemaphoreTake(s_wlock, portMAX_DELAY);
    for (size_t i = 0; i < MEX_WAITERS && !found; i++) {
        if (!s_waiters[i].used) {
            found = &s_waiters[i];
            found->used = true;
            found->dev = dev;
            found->cmd = 0;
            xSemaphoreTake(found->sem, 0); /* drop a give that raced with the previous owner's release */
        }
    }
    xSemaphoreGive(s_wlock);
    return found;
}

static void waiter_set_cmd(waiter_t *w, uint32_t cmd) {
    xSemaphoreTake(s_wlock, portMAX_DELAY);
    w->cmd = cmd;
    xSemaphoreGive(s_wlock);
}

static void waiter_release(waiter_t *w) {
    if (!w)
        return;
    xSemaphoreTake(s_wlock, portMAX_DELAY);
    w->used = false;
    w->cmd = 0;
    xSemaphoreGive(s_wlock);
}

/* ---- task ---- */

static void poll_task(void *arg) {
    (void)arg;
    const esp_err_t err = esp_task_wdt_add(NULL);
    s_wdt = err == ESP_OK;
    if (!s_wdt)
        ESP_LOGW(TAG, "TWDT subscription failed: %s", esp_err_to_name(err));
    for (;;) {
        const uint32_t wait_ms = mex_core_run_once(&s_core);
        if (wait_ms) /* woken early by a queued write or a reconfiguration */
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait_ms) ? pdMS_TO_TICKS(wait_ms) : 1);
    }
}

/* ---- API ---- */

static bool init_sync_objects(void) {
    if (!s_lock)
        s_lock = xSemaphoreCreateMutexStatic(&s_lock_buf);
    if (!s_wlock)
        s_wlock = xSemaphoreCreateMutexStatic(&s_wlock_buf);
    for (size_t i = 0; i < MEX_WAITERS; i++) {
        if (!s_waiters[i].sem)
            s_waiters[i].sem = xSemaphoreCreateBinaryStatic(&s_waiters[i].sem_buf);
        if (!s_waiters[i].sem)
            return false;
    }
    return s_lock && s_wlock;
}

esp_err_t mex_service_start(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n) {
    if (!mex_core_cfg_valid(port, devs, n))
        return ESP_ERR_INVALID_ARG;
    if (atomic_load(&s_started) || s_task)
        return ESP_ERR_INVALID_STATE;
    if (!init_sync_objects())
        return ESP_ERR_NO_MEM;

    const mex_core_io_t io = {
        .ctx = NULL,
        .lock = io_lock,
        .unlock = io_unlock,
        .mono_ms = io_mono,
        .wall_ms = io_wall,
        .gap = io_gap,
        .write = io_write,
        .read = io_read,
        .port_apply = io_port_apply,
        .feed = io_feed,
        .on_snapshot = io_on_snapshot,
        .on_comm = io_on_comm,
        .on_write = io_on_write,
    };
    mex_core_init(&s_core, &io);

    esp_err_t err = mex_uart_open(port);
    if (err != ESP_OK)
        return err == ESP_ERR_NO_MEM ? ESP_ERR_NO_MEM : err;
    err = mex_core_configure(&s_core, port, devs, n);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "configure failed: %s", esp_err_to_name(err));
        mex_uart_close();
        return err;
    }
    if (xTaskCreatePinnedToCore(poll_task, MEX_TASK_NAME, MEX_TASK_STACK, NULL, MEX_TASK_PRIO, &s_task,
                                MEX_TASK_CORE) != pdPASS) {
        s_task = NULL;
        mex_uart_close();
        ESP_LOGE(TAG, "task creation failed");
        return ESP_ERR_NO_MEM;
    }
    atomic_store(&s_started, true);
    size_t enabled = 0;
    for (size_t i = 0; i < n; i++)
        enabled += devs[i].enabled;
    ESP_LOGI(TAG, "started: %u device(s), %u enabled, poll %u ms, timeout %u ms, retries %u", (unsigned)n,
             (unsigned)enabled, (unsigned)port->poll_ms, (unsigned)port->timeout_ms, (unsigned)port->retries);
    return ESP_OK;
}

esp_err_t mex_service_reconfigure(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n) {
    if (!mex_core_cfg_valid(port, devs, n))
        return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&s_started))
        return ESP_ERR_INVALID_STATE;
    const esp_err_t err = mex_core_reconfigure(&s_core, port, devs, n);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "reconfiguration queued (%u device(s))", (unsigned)n);
        xTaskNotifyGive(s_task);
    }
    return err;
}

bool mex_service_snapshot(uint8_t dev, mex_snapshot_t *out) {
    if (!out)
        return false;
    if (!atomic_load(&s_started)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    return mex_core_snapshot(&s_core, dev, out);
}

esp_err_t mex_service_write(uint8_t dev, uint16_t addr, int32_t raw, const char *who, uint32_t wait_ms,
                            mex_wresult_t *out) {
    if (!out)
        return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&s_started) || in_poll_task()) { /* the poll task executes the queue: never wait on it */
        memset(out, 0, sizeof *out);
        out->state = MEX_W_REJECTED;
        out->dev = dev;
        out->addr = addr;
        out->raw_req = raw;
        return ESP_ERR_INVALID_STATE;
    }
    waiter_t *w = wait_ms ? waiter_claim(dev) : NULL;
    const esp_err_t err = mex_core_write_submit(&s_core, dev, addr, raw, who, out);
    if (err != ESP_OK || out->state != MEX_W_PENDING) {
        waiter_release(w);
        return err;
    }
    xTaskNotifyGive(s_task);
    if (!w) {
        if (wait_ms)
            ESP_LOGW(TAG, "no waiter slot: cmd %lu returns pending", (unsigned long)out->cmd);
        return ESP_OK;
    }
    const uint32_t cmd = out->cmd;
    waiter_set_cmd(w, cmd);
    const TickType_t t0 = xTaskGetTickCount();
    const TickType_t total = pdMS_TO_TICKS(wait_ms) ? pdMS_TO_TICKS(wait_ms) : 1;
    for (;;) {
        mex_wresult_t r;
        if (mex_core_command(&s_core, dev, cmd, &r) && r.state != MEX_W_PENDING) {
            *out = r;
            break;
        }
        const TickType_t elapsed = xTaskGetTickCount() - t0;
        if (elapsed >= total)
            break; /* still PENDING: caller polls mex_service_command() */
        xSemaphoreTake(w->sem, total - elapsed);
    }
    waiter_release(w);
    return ESP_OK;
}

bool mex_service_command(uint8_t dev, uint32_t cmd, mex_wresult_t *out) {
    if (!out)
        return false;
    if (!atomic_load(&s_started)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    return mex_core_command(&s_core, dev, cmd, out);
}

void mex_service_stats(uint8_t dev, mex_stats_t *out, bool reset) {
    if (!out)
        return;
    if (!atomic_load(&s_started)) {
        memset(out, 0, sizeof *out);
        return;
    }
    mex_core_stats(&s_core, dev, out, reset);
}
