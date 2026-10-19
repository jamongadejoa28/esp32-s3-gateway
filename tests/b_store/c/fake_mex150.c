/*
 * fake_mex150.c - host-test stand-in for the stream-A mex150 functions that store/alarm call
 * (regmap lookups, snapshot decoding, stage derivation, slow poll blocks). Built from the same
 * regmap.def through regmap_x.h, with the semantics documented in mex150/regmap.h, model.h and
 * poll_plan.h, so store/alarm tests do not depend on another stream's in-progress sources.
 */
#include <math.h>
#include <string.h>

#include "mex150/frame.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mex150/regmap.h"

static const mex_reg_t fake_regs[] = {
#define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en)                   \
    {#key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en},
#include "mex150/regmap_x.h"
};

const mex_block_t mex_slow_blocks[MEX_SLOW_BLOCKS] = {
    {MEX_FC_READ_HOLDING, 26, 4},
    {MEX_FC_READ_HOLDING, 52, 2},
    {MEX_FC_READ_HOLDING, 58, 1},
};

const mex_reg_t *mex_reg_find(uint16_t addr) {
    for (size_t i = 0; i < sizeof(fake_regs) / sizeof(fake_regs[0]); i++)
        if (fake_regs[i].addr == addr)
            return &fake_regs[i];
    return NULL;
}

bool mex_reg_from_value(const mex_reg_t *r, double value, int32_t *raw) {
    if (!r || !isfinite(value))
        return false;
    double x = value * r->scale;
    double rounded = round(x);
    if (fabs(x - rounded) > 1e-6 || rounded < (double)INT32_MIN || rounded > (double)INT32_MAX)
        return false;
    *raw = (int32_t)rounded;
    return true;
}

int32_t mex_snap_raw(const mex_snapshot_t *s, uint16_t addr) {
    const mex_reg_t *r = mex_reg_find(addr);
    if (!r || addr < MEX_ADDR_BASE || addr - MEX_ADDR_BASE >= MEX_REGS_LEN)
        return 0;
    uint16_t wire = s->regs[addr - MEX_ADDR_BASE];
    return r->is_signed ? (int32_t)(int16_t)wire : (int32_t)wire;
}

bool mex_running(const mex_snapshot_t *s) {
    return (s->regs[5] & 0xFFu) != 0;
}

bool mex_fresh(const mex_snapshot_t *s, uint64_t now_mono_ms) {
    /* same semantics as mex150/model.c */
    return s && s->online && s->mono_ms != 0 && now_mono_ms >= s->mono_ms && now_mono_ms - s->mono_ms < MEX_FRESH_MS;
}

void mex_derive_stages(const mex_snapshot_t *s, mex_stages_t *out) {
    memset(out, 0, sizeof(*out));
    out->blower = mex_coil(s, 1);
    out->cool = (uint8_t)(mex_coil(s, 2) + mex_coil(s, 3) + mex_coil(s, 16));
    out->heat = (uint8_t)(mex_coil(s, 4) + mex_coil(s, 5) + mex_coil(s, 6) + mex_coil(s, 7));
    out->hum = (uint8_t)(mex_coil(s, 8) + mex_coil(s, 9));
    out->dehum = (uint8_t)mex_coil(s, 15);
}
