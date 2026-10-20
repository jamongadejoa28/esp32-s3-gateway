/*
 * persist.h - the single task that writes LittleFS ("persist", prio 3, core 1, stack 4096, TWDT).
 *
 * Rule: no other task writes flash (reads are fine anywhere except gw_evt). Producers either mark a
 * coalescing item dirty (the registered writer runs once for any number of marks) or submit a
 * one-shot job. The task also beats GW_HB_PERSIST (gw_core/gw_health.h) every loop (<= 1 s).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PERSIST_QUEUE_LEN 16
#define PERSIST_DEBOUNCE_MS 500 /* CONFIG/SECRETS/HISTORY are written at most this long after the first mark */
/* EVENTS/AUDIT: every log append reopens the file and LittleFS then copies the partial last block
 * into a freshly erased one (~4 KB programmed + 1 erase per append, whatever the record count).
 * Batching sustained producers (SNMP SETs, alarm chatter, login floods) over 10 s cuts that wear
 * ~20x; a crash loses at most the last 10 s of records (planned reboots call persist_flush()). */
#define PERSIST_DEBOUNCE_LOG_MS 10000

typedef enum {
    PERSIST_CONFIG = 0, /* /data/cfg/gateway.json  (writer registered by config.c) */
    PERSIST_SECRETS,    /* /data/sec/secrets.json  (secrets.c) */
    PERSIST_EVENTS,     /* event log tail          (eventlog.c) */
    PERSIST_AUDIT,      /* audit log tail          (eventlog.c) */
    PERSIST_HISTORY,    /* pending slow records    (history.c) */
    PERSIST_ITEM_COUNT
} persist_item_t;

/** Runs in the persist task. May block on flash. Must not call persist_flush(). */
typedef void (*persist_fn_t)(void *arg);

/** Register the writer of a coalescing item (once, at init, before or after persist_start()). */
esp_err_t persist_register(persist_item_t item, persist_fn_t fn, void *arg);

/** Start the task. Call after fs_mount() and the *_init()s that register writers. */
esp_err_t persist_start(void);

/** Mark an item dirty. Lock-free, non-blocking, any task (not ISR). */
void persist_mark_dirty(persist_item_t item);

/** Mark an item dirty and due now (skips the debounce), e.g. a log tail that is filling up.
 *  Lock-free, non-blocking, any task (not ISR). */
void persist_mark_urgent(persist_item_t item);

/**
 * Queue a one-shot job (e.g. delete old history files, factory-reset file wipe).
 * Returns ESP_ERR_TIMEOUT if the queue stayed full for timeout_ms.
 */
esp_err_t persist_submit(persist_fn_t fn, void *arg, uint32_t timeout_ms);

/**
 * Block until every item dirty at call time is written and all queued jobs have run
 * (reboot/OTA/factory reset). Not from the persist or gw_evt task. ESP_ERR_TIMEOUT on timeout.
 */
esp_err_t persist_flush(uint32_t timeout_ms);

/** Run a one-shot writer with a private copy of data, copying results back only on completion.
 * Timed-out callers never leave a stack pointer with the worker. Not from gw_evt. */
typedef esp_err_t (*persist_result_fn_t)(void *data);
esp_err_t persist_run(persist_result_fn_t fn, void *data, size_t size, uint32_t timeout_ms);

/** True while called from the persist task. */
bool persist_in_task(void);

#ifdef __cplusplus
}
#endif
