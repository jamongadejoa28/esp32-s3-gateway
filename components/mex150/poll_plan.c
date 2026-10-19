/*
 * poll_plan.c - Modbus blocks per poll cycle (pure C, host-safe; contract: mex150/poll_plan.h, DESIGN.md §9).
 */
#include "mex150/poll_plan.h"

#include "mex150/frame.h"

/* Coils 1..32 in blocks of 8 (PDU 0, 8, 16, 24); holding 40002-04, 40005-08, 40011-22, 40036-37. */
const mex_block_t mex_fast_blocks[MEX_FAST_BLOCKS] = {
    {MEX_FC_READ_COILS, 0, 8},   {MEX_FC_READ_COILS, 8, 8},   {MEX_FC_READ_COILS, 16, 8},
    {MEX_FC_READ_COILS, 24, 8},  {MEX_FC_READ_HOLDING, 1, 3}, {MEX_FC_READ_HOLDING, 4, 4},
    {MEX_FC_READ_HOLDING, 10, 12}, {MEX_FC_READ_HOLDING, 35, 2},
};

/* 40027-30 (limits), 40053-54 (options), 40059 (cylinder hours). */
const mex_block_t mex_slow_blocks[MEX_SLOW_BLOCKS] = {
    {MEX_FC_READ_HOLDING, 26, 4},
    {MEX_FC_READ_HOLDING, 52, 2},
    {MEX_FC_READ_HOLDING, 58, 1},
};

_Static_assert(MEX_MAX_READ >= 12, "largest block must fit the value buffer");

bool mex_plan_slow_due(uint64_t now_mono_ms, uint64_t last_slow_mono_ms, bool write_since_slow) {
    if (last_slow_mono_ms == 0 || write_since_slow)
        return true;
    if (now_mono_ms < last_slow_mono_ms) /* clock anomaly: re-read rather than wait forever */
        return true;
    return now_mono_ms - last_slow_mono_ms >= MEX_SLOW_PERIOD_MS;
}

size_t mex_plan_cycle(bool online, bool slow_due, mex_block_t *out, size_t cap) {
    if (!out || cap == 0)
        return 0;
    size_t n = 0;
    if (!online) {
        out[n++] = mex_fast_blocks[0];
        return n;
    }
    for (size_t i = 0; i < MEX_FAST_BLOCKS && n < cap; i++)
        out[n++] = mex_fast_blocks[i];
    if (slow_due) {
        for (size_t i = 0; i < MEX_SLOW_BLOCKS && n < cap; i++)
            out[n++] = mex_slow_blocks[i];
    }
    return n;
}

void mex_block_store(const mex_block_t *b, const uint16_t *values, mex_snapshot_t *s) {
    if (!b || !values || !s)
        return;
    for (unsigned j = 0; j < b->count; j++) {
        if (b->fc == MEX_FC_READ_COILS) {
            const unsigned bit = (unsigned)b->start + j;
            if (bit >= MEX_COILS_LEN)
                continue;
            if (values[j])
                s->coils |= 1u << bit;
            else
                s->coils &= ~(1u << bit);
        } else if (b->fc == MEX_FC_READ_HOLDING) {
            const unsigned idx = (unsigned)b->start + j + 1u;
            if (idx >= MEX_REGS_LEN)
                continue;
            s->regs[idx] = values[j];
        }
    }
}
