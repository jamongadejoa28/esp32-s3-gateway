/*
 * poll_plan.h - which Modbus blocks are read in a cycle (pure C, host-safe). DESIGN.md §9.
 *
 * Fast group (every cycle):  coils {1,0,8}{1,8,8}{1,16,8}{1,24,8}
 *                            holding {3,1,3}{3,4,4}{3,10,12}{3,35,2}
 * Slow group (every MEX_SLOW_PERIOD_MS, right after any write, and on the first cycle after
 * coming online): holding {3,26,4}{3,52,2}{3,58,1}
 * Offline device: only the first fast block, every MEX_OFFLINE_POLL_MS.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mex150/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One read request. start is the PDU address (coil n -> n-1, register 4xxxx -> 4xxxx-40001). */
typedef struct {
    uint8_t fc; /* MEX_FC_READ_COILS or MEX_FC_READ_HOLDING */
    uint16_t start;
    uint16_t count;
} mex_block_t;

#define MEX_FAST_BLOCKS 8
#define MEX_SLOW_BLOCKS 3
#define MEX_PLAN_MAX (MEX_FAST_BLOCKS + MEX_SLOW_BLOCKS)

extern const mex_block_t mex_fast_blocks[MEX_FAST_BLOCKS];
extern const mex_block_t mex_slow_blocks[MEX_SLOW_BLOCKS];

/** Slow group due: never read, write since last slow read, or now - last >= MEX_SLOW_PERIOD_MS. */
bool mex_plan_slow_due(uint64_t now_mono_ms, uint64_t last_slow_mono_ms, bool write_since_slow);

/**
 * Blocks for this cycle into out[cap] (cap >= MEX_PLAN_MAX): offline -> {fast[0]} only; online ->
 * fast blocks, then slow blocks if slow_due. Returns the count.
 */
size_t mex_plan_cycle(bool online, bool slow_due, mex_block_t *out, size_t cap);

/**
 * Store decoded block values into a snapshot being assembled: FC01 values[j] -> coils bit
 * (start + j); FC03 values[j] -> regs[start + j + 1]. Out-of-range indexes are ignored.
 */
void mex_block_store(const mex_block_t *b, const uint16_t *values, mex_snapshot_t *s);

#ifdef __cplusplus
}
#endif
