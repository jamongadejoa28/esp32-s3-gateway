/*
 * model.h - MEX150 domain rules on snapshots (pure C, host-safe).
 *
 * mex_validate() is the legacy monitor predicate kept for equivalence tests; production code
 * (service, REST, SNMP set_test) uses mex_check_write(), which is regmap-driven and returns the
 * reason. Invariant (tested exhaustively for addr 40000..40060, raw -400..20100 and all
 * online/running combinations):
 *     mex_check_write(a, v, on, run) == MEX_R_OK  <=>  mex_validate(&{6, a, v, false, 0}, on, run)
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mex150/frame.h"
#include "mex150/regmap.h"
#include "mex150/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Monitor-compatible command (layout identical to esp32-s3-monitor include/domain/model.h). */
typedef struct {
    uint8_t fc;       /* 6 = write single register; 5 (coil write) is always rejected here */
    uint16_t address; /* 4xxxx for FC06 */
    int32_t value;    /* raw */
    bool stopped_only;
    uint32_t id;
} mex_command_t;

/**
 * Legacy predicate, identical to the monitor for FC06 (ranges incl. sentinels, 40021/40022/>=40027
 * interlock, `online` must already include freshness). Deviation: FC05 returns false because all
 * coils are read-only in this product (DESIGN.md §9).
 */
bool mex_validate(const mex_command_t *cmd, bool online, bool running);

/** Unit running: (regs[5] & 0xFF) != 0 (bits 15..8 are the delay countdown, not "running"). */
bool mex_running(const mex_snapshot_t *s);

/** Remaining run/stop delay in seconds: regs[5] >> 8. */
uint8_t mex_delay_s(const mex_snapshot_t *s);

/** s->online && s->mono_ms != 0 && now_mono_ms - s->mono_ms < MEX_FRESH_MS. */
bool mex_fresh(const mex_snapshot_t *s, uint64_t now_mono_ms);

/**
 * Full check of a write request raw (regmap.h terminology) in priority order: UNKNOWN (no REG row)
 * > READONLY > OFFLINE (!online_fresh) > INTERLOCK (MEX_F_STOPPED and running) > RANGE (RUNBIT rows
 * accept only 0/1).
 */
mex_reason_t mex_check_write(uint16_t addr, int32_t raw, bool online_fresh, bool running);

/** Convenience: mex_check_write() using the snapshot (freshness against now_mono_ms). */
mex_reason_t mex_check_write_snap(uint16_t addr, int32_t raw, const mex_snapshot_t *s, uint64_t now_mono_ms);

/** Register raw (mex_reg_decode: full word for 40005/bitfields) of a REG row from a snapshot
 * (0 if addr is not a REG row). */
int32_t mex_snap_raw(const mex_snapshot_t *s, uint16_t addr);

/** Coil n (1..32) state. */
static inline bool mex_coil(const mex_snapshot_t *s, unsigned n) {
    return n >= 1 && n <= 32 && ((s->coils >> (n - 1)) & 1u);
}

/**
 * Active stage counts derived from the run-status coils (unambiguous in the map):
 *   cool  = coils 2, 3, 16 (cool1..3)      heat = coils 4..7 (heat1..4)
 *   hum   = coils 8, 9 (hum1..2)           dehum = coil 15 (dehumidifying, 0/1)
 *   blower = coil 1
 * The proportional bitfields 40006..40008 are exposed raw (BIT rows) and not used here.
 */
typedef struct {
    uint8_t cool, heat, hum, dehum;
    bool blower;
} mex_stages_t;

void mex_derive_stages(const mex_snapshot_t *s, mex_stages_t *out);

/** Mode bitmask from coils 12..15: bit0 cooling, bit1 heating, bit2 humidifying, bit3 dehumidifying. */
uint8_t mex_mode_mask(const mex_snapshot_t *s);

/** Alarm coils 17..32 as a 16-bit mask: bit (n-17) = coil n. Bit 15 (coil 32) is the combined flag. */
static inline uint16_t mex_alarm_coils(const mex_snapshot_t *s) {
    return (uint16_t)(s->coils >> 16);
}

#ifdef __cplusplus
}
#endif
