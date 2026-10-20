/*
 * persist.c - the single LittleFS writer task "persist" (prio 3, core 1, stack 4096, TWDT).
 * Contract: store/persist.h.
 *
 * Coalescing items are a lock-free dirty bitmask plus the time of the first mark; the task writes
 * an item PERSIST_DEBOUNCE_MS (event/audit logs: PERSIST_DEBOUNCE_LOG_MS) after its first mark (bit cleared before the writer runs, so a mark
 * during the write schedules another write). One-shot jobs and flush markers share one FIFO queue,
 * so a flush marker is processed after every job queued before it.
 */
#include "store/persist.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gw_core/gw_health.h"
#include "store_dev.h"

static const char *TAG = "persist";

#define PERSIST_TASK_NAME "persist"
#define PERSIST_TASK_PRIO 3
#define PERSIST_TASK_CORE 1
#define PERSIST_TASK_STACK 4096
#define PERSIST_IDLE_WAIT_MS 1000 /* loop period without work (heartbeat <= 1 s) */

typedef struct {
    persist_fn_t fn; /* NULL: control message (arg = flush generation, 0 = wake-up) */
    void *arg;
} persist_job_t;

static struct {
    persist_fn_t fn;
    void *arg;
} s_writers[PERSIST_ITEM_COUNT];

static atomic_uint s_dirty;                              /* bit = persist_item_t */
static atomic_uint s_first_mark_ms[PERSIST_ITEM_COUNT]; /* esp_timer ms (wraps) of the first mark */
static QueueHandle_t s_queue;
static TaskHandle_t s_task;
static SemaphoreHandle_t s_flush_mutex;
static SemaphoreHandle_t s_flush_sem;
static atomic_uint s_flush_req;
static atomic_uint s_flush_done;
static bool s_wdt;

static uint32_t debounce_ms(unsigned item) {
    return (item == PERSIST_EVENTS || item == PERSIST_AUDIT) ? PERSIST_DEBOUNCE_LOG_MS : PERSIST_DEBOUNCE_MS;
}

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

void store_wdt_feed(void) {
    if (!persist_in_task())
        return;
    if (s_wdt)
        esp_task_wdt_reset();
    gw_hb_beat(GW_HB_PERSIST);
}

bool persist_in_task(void) {
    return s_task != NULL && xTaskGetCurrentTaskHandle() == s_task;
}

esp_err_t persist_register(persist_item_t item, persist_fn_t fn, void *arg) {
    if ((unsigned)item >= PERSIST_ITEM_COUNT || !fn)
        return ESP_ERR_INVALID_ARG;
    if (s_writers[item].fn && s_writers[item].fn != fn)
        return ESP_ERR_INVALID_STATE;
    s_writers[item].arg = arg;
    s_writers[item].fn = fn; /* single-word store; read by the persist task */
    return ESP_OK;
}

void persist_mark_dirty(persist_item_t item) {
    if ((unsigned)item >= PERSIST_ITEM_COUNT)
        return;
    unsigned bit = 1u << item;
    unsigned prev = atomic_fetch_or(&s_dirty, bit);
    if (prev & bit)
        return; /* already pending: the first mark's deadline stands (no postponement) */
    atomic_store(&s_first_mark_ms[item], now_ms());
    /* 0 -> 1 transition: wake the task so the debounce timer starts now (best effort). */
    if (s_queue && !persist_in_task()) {
        persist_job_t wake = {.fn = NULL, .arg = (void *)(uintptr_t)0};
        (void)xQueueSendToBack(s_queue, &wake, 0);
    }
}

void persist_mark_urgent(persist_item_t item) {
    if ((unsigned)item >= PERSIST_ITEM_COUNT)
        return;
    /* A stamp one debounce in the past makes the item due at the next pass (a writer running right
     * now clears the bit first, so this mark always schedules one more write). */
    atomic_store(&s_first_mark_ms[item], now_ms() - debounce_ms(item));
    atomic_fetch_or(&s_dirty, 1u << item);
    if (s_queue && !persist_in_task()) {
        persist_job_t wake = {.fn = NULL, .arg = (void *)(uintptr_t)0};
        (void)xQueueSendToBack(s_queue, &wake, 0);
    }
}

static void write_item(unsigned i) {
    unsigned bit = 1u << i;
    atomic_fetch_and(&s_dirty, ~bit);
    if (s_writers[i].fn)
        s_writers[i].fn(s_writers[i].arg);
    else
        ESP_LOGW(TAG, "item %u dirty but no writer registered", i);
    store_wdt_feed();
}

/* Write items whose debounce expired (or all when force). Returns ms until the next one is due. */
static uint32_t service_dirty(bool force) {
    uint32_t wait = PERSIST_IDLE_WAIT_MS;
    unsigned dirty = atomic_load(&s_dirty);
    for (unsigned i = 0; i < PERSIST_ITEM_COUNT; i++) {
        if (!(dirty & (1u << i)))
            continue;
        /* Stamp of the 0 -> 1 transition (a stale stamp only makes the write earlier). */
        uint32_t age = now_ms() - atomic_load(&s_first_mark_ms[i]);
        const uint32_t deb = debounce_ms(i);
        if (force || age >= deb) {
            write_item(i);
        } else {
            uint32_t left = deb - age;
            if (left < wait)
                wait = left;
        }
    }
    return wait;
}

static void persist_task(void *arg) {
    (void)arg;
    s_wdt = esp_task_wdt_add(NULL) == ESP_OK;
    if (!s_wdt)
        ESP_LOGW(TAG, "task watchdog not available");
    for (;;) {
        if (s_wdt)
            esp_task_wdt_reset();
        gw_hb_beat(GW_HB_PERSIST);
        uint32_t wait = service_dirty(false);
        persist_job_t job;
        if (xQueueReceive(s_queue, &job, pdMS_TO_TICKS(wait ? wait : 1)) != pdTRUE)
            continue;
        if (job.fn) {
            job.fn(job.arg);
            store_wdt_feed();
            continue;
        }
        unsigned gen = (unsigned)(uintptr_t)job.arg;
        if (gen == 0)
            continue; /* wake-up: re-evaluate the debounce timers */
        service_dirty(true);
        atomic_store(&s_flush_done, gen);
        xSemaphoreGive(s_flush_sem);
    }
}

esp_err_t persist_start(void) {
    if (s_task)
        return ESP_OK;
    s_queue = xQueueCreate(PERSIST_QUEUE_LEN, sizeof(persist_job_t));
    s_flush_mutex = xSemaphoreCreateMutex();
    s_flush_sem = xSemaphoreCreateBinary();
    if (!s_queue || !s_flush_mutex || !s_flush_sem)
        goto nomem;
    /* Stamp the marks made before the task existed (boot-time defaults etc.). */
    for (unsigned i = 0; i < PERSIST_ITEM_COUNT; i++)
        if (atomic_load(&s_dirty) & (1u << i))
            atomic_store(&s_first_mark_ms[i], now_ms());
    if (xTaskCreatePinnedToCore(persist_task, PERSIST_TASK_NAME, PERSIST_TASK_STACK, NULL, PERSIST_TASK_PRIO,
                                &s_task, PERSIST_TASK_CORE) != pdPASS) {
        s_task = NULL;
        goto nomem;
    }
    ESP_LOGI(TAG, "started");
    return ESP_OK;
nomem:
    if (s_queue)
        vQueueDelete(s_queue);
    if (s_flush_mutex)
        vSemaphoreDelete(s_flush_mutex);
    if (s_flush_sem)
        vSemaphoreDelete(s_flush_sem);
    s_queue = NULL;
    s_flush_mutex = s_flush_sem = NULL;
    ESP_LOGE(TAG, "start failed: no memory");
    return ESP_ERR_NO_MEM;
}

esp_err_t persist_submit(persist_fn_t fn, void *arg, uint32_t timeout_ms) {
    if (!fn)
        return ESP_ERR_INVALID_ARG;
    if (!s_queue)
        return ESP_ERR_INVALID_STATE;
    if (persist_in_task())
        timeout_ms = 0; /* the task cannot wait for itself */
    persist_job_t job = {.fn = fn, .arg = arg};
    return xQueueSendToBack(s_queue, &job, pdMS_TO_TICKS(timeout_ms)) == pdTRUE ? ESP_OK : ESP_ERR_TIMEOUT;
}

esp_err_t persist_flush(uint32_t timeout_ms) {
    if (!s_queue || persist_in_task())
        return ESP_ERR_INVALID_STATE;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    if (xSemaphoreTake(s_flush_mutex, pdMS_TO_TICKS(timeout_ms)) != pdTRUE)
        return ESP_ERR_TIMEOUT;
    unsigned gen = atomic_fetch_add(&s_flush_req, 1) + 1;
    if (gen == 0) /* 0 is the wake-up marker */
        gen = atomic_fetch_add(&s_flush_req, 1) + 1;
    esp_err_t rc = ESP_ERR_TIMEOUT;
    persist_job_t marker = {.fn = NULL, .arg = (void *)(uintptr_t)gen};
    int64_t left_us = deadline - esp_timer_get_time();
    if (left_us > 0 && xQueueSendToBack(s_queue, &marker, pdMS_TO_TICKS(left_us / 1000)) == pdTRUE) {
        for (;;) {
            if ((int)(atomic_load(&s_flush_done) - gen) >= 0) {
                rc = ESP_OK;
                break;
            }
            left_us = deadline - esp_timer_get_time();
            if (left_us <= 0)
                break;
            TickType_t t = pdMS_TO_TICKS(left_us / 1000);
            (void)xSemaphoreTake(s_flush_sem, t ? t : 1);
        }
    }
    xSemaphoreGive(s_flush_mutex);
    if (rc != ESP_OK)
        ESP_LOGW(TAG, "flush timed out after %u ms", (unsigned)timeout_ms);
    return rc;
}

typedef struct {
    atomic_uint refs;
    SemaphoreHandle_t done;
    persist_result_fn_t fn;
    esp_err_t result;
    unsigned char data[];
} result_job_t;
static void result_release(result_job_t *job) {
    if (atomic_fetch_sub(&job->refs, 1) == 1) {
        vSemaphoreDelete(job->done);
        free(job);
    }
}
static void result_work(void *arg) {
    result_job_t *job = arg;
    job->result = job->fn(job->data);
    xSemaphoreGive(job->done);
    result_release(job);
}
esp_err_t persist_run(persist_result_fn_t fn, void *data, size_t size, uint32_t timeout_ms) {
    if (!fn || !data || !size || size > 4096)
        return ESP_ERR_INVALID_ARG;
    if (persist_in_task())
        return fn(data);
    result_job_t *job = calloc(1, sizeof(*job) + size);
    if (!job)
        return ESP_ERR_NO_MEM;
    job->done = xSemaphoreCreateBinary();
    if (!job->done) {
        free(job);
        return ESP_ERR_NO_MEM;
    }
    atomic_init(&job->refs, 2);
    job->fn = fn;
    memcpy(job->data, data, size);
    esp_err_t err = persist_submit(result_work, job, 0);
    if (err != ESP_OK) {
        result_release(job);
        result_release(job);
        return err;
    }
    if (xSemaphoreTake(job->done, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        err = job->result;
        memcpy(data, job->data, size);
    } else
        err = ESP_ERR_TIMEOUT;
    result_release(job);
    return err;
}
