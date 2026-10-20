/*
 * service.h - MEX150 polling/write service (frozen interface, DESIGN.md §9).
 *
 * The service owns UART1 and one task "mex_poll" (prio 10, core 1, stack 4096, TWDT-subscribed).
 * It polls every enabled device round-robin with the poll plan (poll_plan.h), keeps one
 * snapshot per device, executes queued writes between blocks, beats GW_HB_MEX
 * (gw_core/gw_health.h) every loop iteration, and posts:
 *   GW_EVT_SNAPSHOT     after every successful full cycle of a device
 *   GW_EVT_COMM         when an enabled device's state is first decided after boot/reconfigure and
 *                       on every later online <-> offline transition (exact rules: gw_events.h)
 *   GW_EVT_WRITE_RESULT for every write attempt's final state, including rejections at enqueue
 * Every function below is thread-safe and callable from any task except "mex_poll" itself
 * (and not from ISRs). Functions never block on the bus except mex_service_write() (bounded by
 * wait_ms). Header is IDF-free (esp_err_t via gw_err.h) so store/config.h can embed the types.
 *
 * Fields added beyond DESIGN.md §9 (documented in DECISIONS.md): mex_snapshot_t.slow_valid,
 * mex_wresult_t.{dev,addr,raw_req,ts_ms}, mex_stats_t.{online_since_ms,cycles}, and
 * mex_service_command().
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/device_templates.h"
#include "gw_core/gw_err.h"
#include "mex150/regmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Freshness (DECISIONS.md "Contract issues — resolution"): a write is sent only with data younger
 * than MEX_FRESH_MS (the published snapshot or this cycle's fast-group re-read). At enqueue the
 * window is MEX_FRESH_MS, or poll_ms + MEX_FRESH_MS for an ONLINE device whose last cycle succeeded
 * when poll_ms > MEX_FRESH_MS (else every write would be "offline" at long poll periods). The alarm
 * service's 1 Hz pass uses the same window (alm_sample_fresh). */
#define MEX_FRESH_MS 3000     /* writes require a snapshot younger than this (monitor rule) */
#define MEX_WRITE_QUEUE_LEN 8 /* pending writes across all devices */
#define MEX_CMD_HISTORY 16    /* recent results kept for mex_service_command() */
#define MEX_SLOW_PERIOD_MS 10000
#define MEX_OFFLINE_POLL_MS 2000

/** RS485 port and timing. Validated by cfg_validate() (store/config.h). */
typedef struct {
    uint32_t baud;         /* 1200..115200; default 9600 */
    char parity;           /* 'N', 'E' or 'O'; default 'N' */
    uint8_t stop;          /* 1 or 2; default 1 */
    uint16_t poll_ms;      /* full-cycle period per device, 200..60000; default 1000 */
    uint16_t timeout_ms;   /* response timeout per transaction, 50..2000; default 300 */
    uint16_t gap_ms;       /* idle gap before each request (RS485 turnaround), 0..100; default 5 */
    uint8_t retries;       /* extra attempts per transaction, 0..3; default 1 */
    uint8_t offline_after; /* consecutive failed cycles before offline, 1..10; default 3 */
} mex_port_cfg_t;

/** One MEX150 on the bus. id is the stable device index used everywhere (dev). */
typedef struct {
    uint8_t id;    /* 0..GW_MAX_DEVICES-1, unique */
    uint8_t slave; /* Modbus unit 1..247, unique among enabled devices */
    bool enabled;
    char name[GW_DEV_NAME_SZ];           /* UTF-8 display name */
    char template_id[GW_TEMPLATE_ID_SZ]; /* empty legacy value means mex150 */
    uint32_t display_mask; /* channel n displayed when bit n is set; collection/control unchanged */
} mex_dev_cfg_t;

/** Latest known device state. Copied out whole; never partially updated. */
typedef struct {
    uint16_t regs[MEX_REGS_LEN]; /* wire values, index = addr - 40000 (regs[36] = 40036) */
    uint32_t coils;              /* bit n-1 = coil n (1..32) */
    int64_t wall_ms;             /* wall time of the last successful cycle (0 if time invalid) */
    uint64_t mono_ms;            /* gw_time_mono_ms() of the last successful cycle (0 = never) */
    uint32_t seq;                /* +1 per successful cycle, starts at 1; 0 = never polled */
    bool online;
    bool slow_valid; /* slow group (40027-30, 40053-54, 40059) read at least once since online */
    /* Startup/reconnect 0/0 is ambiguous: wait for either measurement to leave zero once per
     * connection. Thereafter zero (including 0/0) is valid. This is a gateway startup policy,
     * not a measurement-ready bit supplied by the controller. */
    bool measurement_valid;
} mex_snapshot_t;

typedef enum { MEX_W_PENDING = 0, MEX_W_APPLIED = 1, MEX_W_REJECTED = 2, MEX_W_UNCERTAIN = 3 } mex_wstate_t;

/** Write outcome (monitor semantics: exception -> REJECTED; read-back equal -> APPLIED; else UNCERTAIN). */
typedef struct {
    uint32_t cmd; /* command id (> 0), unique since boot; 0 if rejected before queueing */
    mex_wstate_t state;
    int reason;        /* mex_reason_t or MEX_R_EXCEPTION(n); MEX_R_OK when applied/pending */
    int32_t raw_after; /* register raw read back (APPLIED/UNCERTAIN-with-read); == raw_before (the raw
                          of the snapshot that validated the write) when nothing was read back, as in
                          gw_evt_write_t (regmap.h terminology; 40005 = full word) */
    uint8_t dev;
    uint16_t addr;
    int32_t raw_req; /* write request raw (0/1 for 40005) */
    int64_t ts_ms;   /* wall ms when the state was last updated (0 if time invalid) */
} mex_wresult_t;

/** Per-device counters (reset by mex_service_stats(..., true)). */
typedef struct {
    uint32_t tx, rx_ok, crc, timeout, exception, malformed, offline_count;
    uint16_t rtt_last, rtt_avg, rtt_max; /* ms, request start -> last byte; avg = EWMA 1/8 */
    int64_t online_since_ms;             /* wall ms of the last offline->online transition, 0 = n/a */
    uint32_t cycles;                     /* successful full cycles */
} mex_stats_t;

/**
 * Install UART1 (pins from board_pins.h: mex150 PRIV_REQUIRES board), copy the configuration and
 * start "mex_poll". devs[0..n) with n <= GW_MAX_DEVICES; disabled devices are kept but never polled
 * and never produce GW_EVT_COMM.
 * @return ESP_OK, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_STATE (already started), ESP_ERR_NO_MEM.
 */
esp_err_t mex_service_start(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n);

/**
 * Apply a new configuration at the next cycle boundary (UART reconfigured if needed). Devices whose
 * slave/enabled changed get snapshot.online=false (seq kept), return to the "unknown" COMM state
 * WITHOUT posting GW_EVT_COMM (gw_events.h), and their queued writes complete as
 * REJECTED/MEX_R_CANCELLED. Called by the CONFIG_CHANGED{MODBUS} handler that app_main registers.
 * Non-blocking.
 */
esp_err_t mex_service_reconfigure(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n);

/** Copy the latest snapshot of dev. Returns false if dev is unknown (out zeroed). */
bool mex_service_snapshot(uint8_t dev, mex_snapshot_t *out);

/**
 * Validate and queue a single-register write (FC06), then wait up to wait_ms for the outcome.
 *   raw  - write request raw (regmap.h): integer at register scale (e.g. -15 = -1.5 for 40021);
 *          0/1 for 40005.
 *   who  - principal for audit/events, copied (<= GW_USER_NAME_MAX chars): a web user name, or
 *          "@snmp" / "@console" for non-web origins (web names cannot start with '@').
 * Validation (mex_check_write(), model.h) happens at enqueue AND again right before sending.
 * Results in *out:
 *   REJECTED + reason immediately (cmd = 0) when validation fails at enqueue,
 *   PENDING (cmd > 0) when wait_ms elapsed first (poll later with mex_service_command()),
 *   else the final state.
 * Every final state is posted as GW_EVT_WRITE_RESULT (audit + WS "write"), including the immediate
 * rejections (cmd = 0, incl. MEX_R_UNKNOWN and MEX_R_BUSY); nothing is posted for ESP_ERR_INVALID_ARG
 * or ESP_ERR_INVALID_STATE.
 * After a write the slow group is re-read in the same cycle; PENDING persists until the
 * post-write snapshot has been published (monitor rule).
 * @return ESP_OK (inspect *out), ESP_ERR_INVALID_ARG (unknown dev / NULL out),
 *         ESP_ERR_NO_MEM (queue full: out->state REJECTED, reason MEX_R_BUSY),
 *         ESP_ERR_INVALID_STATE (service not started).
 */
esp_err_t mex_service_write(uint8_t dev, uint16_t addr, int32_t raw, const char *who, uint32_t wait_ms,
                            mex_wresult_t *out);

/** Look up a recent command (last MEX_CMD_HISTORY). Returns false if unknown/evicted. */
bool mex_service_command(uint8_t dev, uint32_t cmd, mex_wresult_t *out);

/** Copy (and optionally reset after copying) the counters of dev. Unknown dev -> zeroed out. */
void mex_service_stats(uint8_t dev, mex_stats_t *out, bool reset);

#ifdef __cplusplus
}
#endif
