/*
 * mex_core.h - PRIVATE to components/mex150. Pure-C engine behind service.c (host-testable).
 *
 * The core implements everything of mex150/service.h that does not need FreeRTOS or the UART driver:
 * the Modbus transaction (monitor exchange(): gap, request, early-stopping receive, retries, per-error
 * counters, RTT), the per-device poll cycle (poll_plan.h), COMM state machine, the write queue with
 * validation at enqueue and before send, write -> read-back -> APPLIED/REJECTED/UNCERTAIN, command
 * history, multi-device round-robin and reconfiguration at cycle boundaries.
 *
 * All I/O, time, locking and event delivery are injected through mex_core_io_t, so tests drive it
 * with a simulated MEX150 (tests/test_mex_core.py) and service.c binds it to UART1/FreeRTOS/gw_evt.
 *
 * Threading contract
 *   - mex_core_run_once() is called by exactly one thread (the poll task); it is the only caller of
 *     the bus callbacks (gap/write/read/port_apply/feed).
 *   - Every other mex_core_* function may be called from any thread concurrently with it.
 *   - Shared state is only touched between io.lock() and io.unlock(); the lock is never held across
 *     bus I/O or any io.on_* callback (a callback may therefore call mex_core_command() etc.).
 *   - on_write is called from the poll task for queued commands and from the submitting thread for
 *     rejections at enqueue (cmd 0, incl. MEX_R_BUSY).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "mex150/frame.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mex150/regmap.h"
#include "mex150/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Injected environment. Every callback is mandatory unless marked optional. */
typedef struct {
    void *ctx;
    void (*lock)(void *ctx);
    void (*unlock)(void *ctx);
    uint64_t (*mono_ms)(void *ctx); /* monotonic ms (never 0 after boot) */
    int64_t (*wall_ms)(void *ctx);  /* wall ms UTC, 0 when invalid */
    /** Idle gap before a request (RS485 turnaround), then discard any stale received bytes. */
    void (*gap)(void *ctx, uint16_t gap_ms);
    /** Send n bytes and wait until they left the wire. 0 or MEX_TXN_E_UART. */
    int (*write)(void *ctx, const uint8_t *buf, size_t n);
    /** Receive up to `want` bytes, returning as soon as `want` arrived or after timeout_ms.
     * Returns the byte count (0 on timeout) or MEX_TXN_E_UART. */
    int (*read)(void *ctx, uint8_t *buf, size_t want, uint32_t timeout_ms);
    /** Apply baud/parity/stop. 0 on success. Optional (NULL = nothing to do). */
    int (*port_apply)(void *ctx, const mex_port_cfg_t *port);
    /** Called before every transaction attempt and at the start of each run_once (TWDT/heartbeat).
     * Optional. */
    void (*feed)(void *ctx);
    /** A new snapshot of dev was published (post GW_EVT_SNAPSHOT). Optional. */
    void (*on_snapshot)(void *ctx, uint8_t dev, uint32_t seq, uint64_t mono_ms, bool slow_fresh);
    /** COMM decided/changed for an enabled dev (post GW_EVT_COMM). Optional. */
    void (*on_comm)(void *ctx, uint8_t dev, bool online, int last_err, uint32_t offline_count, int64_t ts_ms);
    /** Final write outcome (APPLIED/REJECTED/UNCERTAIN; post GW_EVT_WRITE_RESULT, wake waiters).
     * `who` is the principal given to mex_core_write_submit() ("" if none). Optional. */
    void (*on_write)(void *ctx, const mex_wresult_t *res, int32_t raw_before, const char *who);
} mex_core_io_t;

typedef enum { MEX_COMM_UNKNOWN = 0, MEX_COMM_ONLINE = 1, MEX_COMM_OFFLINE = 2 } mex_comm_t;

/** Per-device state (index = device id). Shared fields are protected by io.lock. */
typedef struct {
    mex_dev_cfg_t cfg;
    bool configured;
    uint8_t comm;        /* mex_comm_t */
    uint8_t fail_cycles; /* consecutive failed cycles (saturating) */
    int16_t last_err;    /* last transaction result (0, >0 exception, <0 MEX_RESP_E_* / MEX_TXN_E_*) */
    mex_snapshot_t snap; /* published snapshot */
    mex_stats_t stats;
    uint32_t rtt_avg_x8;   /* EWMA(1/8) of RTT, fixed point x8 */
    uint64_t next_due_ms;  /* poll-task only */
    uint64_t last_slow_ms; /* poll-task only: mono of the last successful slow-group read (0 = never) */
    bool write_since_slow; /* poll-task only */
} mex_core_dev_t;

typedef enum { MEX_WQ_FREE = 0, MEX_WQ_QUEUED = 1, MEX_WQ_SENT = 2 } mex_wq_phase_t;

/** Write-queue entry: from enqueue until its final state is published (QUEUED -> SENT -> FREE). */
typedef struct {
    uint32_t cmd;
    uint8_t phase; /* mex_wq_phase_t */
    uint8_t dev;
    uint16_t addr;
    int32_t raw_req;
    /* outcome, valid in MEX_WQ_SENT */
    uint8_t state; /* mex_wstate_t */
    bool have_read;
    int reason;
    int32_t raw_before, raw_after;
    char who[GW_USER_NAME_SZ];
} mex_core_wq_t;

/** Finalised write waiting for its on_write callback (poll-task scratch). */
typedef struct {
    mex_wresult_t res;
    int32_t raw_before;
    char who[GW_USER_NAME_SZ];
} mex_core_fin_t;

/** Why a device cycle was scheduled (fairness bookkeeping of mex_core_run_once()). */
typedef enum { MEX_PICK_DUE = 0, MEX_PICK_WRITE = 1, MEX_PICK_PROBE = 2 } mex_core_pick_t;

#define MEX_CORE_PLAN_CAP (MEX_PLAN_MAX + 2 * MEX_SLOW_BLOCKS)
#define MEX_CORE_IDLE_MAX_MS 500 /* longest wait run_once asks for (heartbeat/TWDT cadence) */

typedef struct {
    mex_core_io_t io;
    bool configured;
    mex_port_cfg_t port; /* poll-task owned after mex_core_configure() */
    mex_core_dev_t dev[GW_MAX_DEVICES];
    mex_core_wq_t wq[MEX_WRITE_QUEUE_LEN];
    mex_wresult_t hist[MEX_CMD_HISTORY]; /* cmd 0 = empty slot */
    uint32_t next_cmd;
    uint8_t rr_last;
    uint8_t last_pick; /* poll-task only: why the last cycle ran (mex_core_pick_t) */
    /* pending reconfiguration (written by any thread under lock, applied by the poll task) */
    bool pend;
    mex_port_cfg_t pend_port;
    mex_dev_cfg_t pend_devs[GW_MAX_DEVICES];
    size_t pend_n;
    /* poll-task scratch */
    mex_core_fin_t fin[MEX_WRITE_QUEUE_LEN];
    size_t fin_n;
    uint8_t rx[MEX_FRAME_MAX];
} mex_core_t;

/** Range checks of mex_port_cfg_t (service.h comments). */
bool mex_core_port_valid(const mex_port_cfg_t *port);

/** Full configuration check: port valid, n <= GW_MAX_DEVICES, ids < GW_MAX_DEVICES and unique,
 * slave 1..247 and unique among enabled devices, name NUL-terminated within GW_DEV_NAME_SZ. */
bool mex_core_cfg_valid(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n);

/** Zero the core and bind the I/O. */
void mex_core_init(mex_core_t *c, const mex_core_io_t *io);

/** Initial configuration (before the poll thread runs). Calls io.port_apply. ESP_ERR_INVALID_ARG if
 * invalid, ESP_ERR_INVALID_STATE if already configured. */
esp_err_t mex_core_configure(mex_core_t *c, const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n);

/** Store a new configuration; applied by the next mex_core_run_once() (cycle boundary). Any thread. */
esp_err_t mex_core_reconfigure(mex_core_t *c, const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n);

/**
 * Poll-thread step: apply a pending reconfiguration, then run at most one device cycle. Order:
 *   1. the device of the oldest queued write - unless the previous cycle was also write-triggered and
 *      another enabled device is due (so continuous write traffic cannot starve the other devices);
 *   2. the most overdue enabled device (round-robin on ties) - except that after an OFFLINE probe a due
 *      ONLINE/UNKNOWN device goes first (dead devices cannot starve live ones).
 * Returns 0 if a cycle ran (call again), else how many ms to idle (<= MEX_CORE_IDLE_MAX_MS).
 */
uint32_t mex_core_run_once(mex_core_t *c);

/**
 * Validate and enqueue a write (service.h mex_service_write() semantics without the waiting).
 * *out: PENDING with cmd > 0, or the immediate REJECTED result (cmd 0; on_write already called).
 * Returns ESP_OK, ESP_ERR_NO_MEM (queue full, REJECTED/MEX_R_BUSY) or ESP_ERR_INVALID_ARG (dev not
 * configured / out NULL; nothing reported).
 */
esp_err_t mex_core_write_submit(mex_core_t *c, uint8_t dev, uint16_t addr, int32_t raw, const char *who,
                                mex_wresult_t *out);

/** Copy a recent command (pending or final). False if unknown/evicted. */
bool mex_core_command(mex_core_t *c, uint8_t dev, uint32_t cmd, mex_wresult_t *out);

/** Copy the published snapshot. False (out zeroed) if dev is not configured. */
bool mex_core_snapshot(mex_core_t *c, uint8_t dev, mex_snapshot_t *out);

/** Copy (then optionally reset) the counters of dev; unknown dev -> zeroed. */
void mex_core_stats(mex_core_t *c, uint8_t dev, mex_stats_t *out, bool reset);

/** COMM state of dev (mex_comm_t), MEX_COMM_UNKNOWN if not configured. Any thread. */
uint8_t mex_core_comm(mex_core_t *c, uint8_t dev);

/** sizeof(mex_core_t), for host tests that allocate the core from Python. */
size_t mex_core_sizeof(void);

/**
 * Receive primitives of a driver whose blocking read restarts its wait for every chunk that arrives
 * (ESP-IDF uart_read_bytes(): ticks_to_wait applies to each ring-buffer receive, not to the call).
 * Time is in driver units (FreeRTOS ticks on the target), `now` may wrap.
 */
typedef struct {
    void *ctx;
    uint32_t (*now)(void *ctx);
    /** Bytes that can be read without waiting; < 0 on driver error. */
    int (*avail)(void *ctx);
    /** Read up to n bytes waiting at most `wait` per chunk; byte count or < 0 on driver error. */
    int (*recv)(void *ctx, uint8_t *buf, size_t n, uint32_t wait);
} mex_rx_ops_t;

/**
 * mex_core_io_t.read() semantics on top of such a driver: returns once `want` bytes arrived or `timeout`
 * elapsed IN TOTAL (a byte trickling in just before each chunk wait expires cannot extend it). A blocking
 * receive only ever asks for one byte, so each driver call waits at most the remaining time; buffered
 * bytes are taken without waiting. Returns the byte count (0 on timeout) or MEX_TXN_E_UART.
 */
int mex_rx_bounded(const mex_rx_ops_t *ops, uint8_t *buf, size_t want, uint32_t timeout);

#ifdef __cplusplus
}
#endif
