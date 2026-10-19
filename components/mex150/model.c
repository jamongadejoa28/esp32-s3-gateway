/*
 * model.c - MEX150 domain rules on snapshots (pure C, host-safe; contract: mex150/model.h).
 */
#include "mex150/model.h"

bool mex_validate(const mex_command_t *c, bool online, bool running) {
    /* Verbatim port of esp32-s3-monitor mex_validate() for FC06 (ranges include the disabled sentinels
     * as the lower bound, interlock on 40021/40022/>=40027). FC05: coils are read-only here. */
    if (!c || !online || (c->stopped_only && running))
        return false;
    if (c->fc != MEX_FC_WRITE_SINGLE)
        return false;
    int lo = 0, hi = -1;
    switch (c->address) {
    case 40005:
        lo = 0;
        hi = 1;
        break;
    case 40012:
        lo = 50;
        hi = 500;
        break;
    case 40013:
        lo = 200;
        hi = 800;
        break;
    case 40014:
    case 40015:
        lo = 1;
        hi = 100;
        break;
    case 40016:
    case 40017:
        lo = 10;
        hi = 100;
        break;
    case 40018:
    case 40019:
        lo = 1;
        hi = 180;
        break;
    case 40021:
        lo = -100;
        hi = 100;
        break;
    case 40022:
        lo = -300;
        hi = 300;
        break;
    case 40027:
        lo = 249;
        hi = 500;
        break;
    case 40028:
        lo = 49;
        hi = 200;
        break;
    case 40029:
        lo = 599;
        hi = 900;
        break;
    case 40030:
        lo = 99;
        hi = 400;
        break;
    case 40053:
    case 40054:
        lo = 0;
        hi = 1;
        break;
    case 40059:
        lo = 1000;
        hi = 20000;
        break;
    default:
        return false;
    }
    if (running && (c->address == 40021 || c->address == 40022 || c->address >= 40027))
        return false;
    return c->value >= lo && c->value <= hi;
}

bool mex_running(const mex_snapshot_t *s) {
    return s && (s->regs[5] & 0xFFu) != 0;
}

uint8_t mex_delay_s(const mex_snapshot_t *s) {
    return s ? (uint8_t)(s->regs[5] >> 8) : 0;
}

bool mex_fresh(const mex_snapshot_t *s, uint64_t now_mono_ms) {
    return s && s->online && s->mono_ms != 0 && now_mono_ms >= s->mono_ms &&
           now_mono_ms - s->mono_ms < MEX_FRESH_MS;
}

mex_reason_t mex_check_write(uint16_t addr, int32_t raw, bool online_fresh, bool running) {
    const mex_reg_t *r = mex_reg_find(addr);
    if (!r)
        return MEX_R_UNKNOWN;
    if (!r->writable)
        return MEX_R_READONLY;
    if (!online_fresh)
        return MEX_R_OFFLINE;
    if ((r->flags & MEX_F_STOPPED) && running)
        return MEX_R_INTERLOCK;
    return mex_reg_check_value(r, raw);
}

mex_reason_t mex_check_write_snap(uint16_t addr, int32_t raw, const mex_snapshot_t *s, uint64_t now_mono_ms) {
    return mex_check_write(addr, raw, mex_fresh(s, now_mono_ms), mex_running(s));
}

int32_t mex_snap_raw(const mex_snapshot_t *s, uint16_t addr) {
    const mex_reg_t *r = mex_reg_find(addr);
    if (!s || !r)
        return 0;
    return mex_reg_decode(r, s->regs[mex_reg_index(addr)]);
}

void mex_derive_stages(const mex_snapshot_t *s, mex_stages_t *out) {
    if (!out)
        return;
    *out = (mex_stages_t){0};
    if (!s)
        return;
    out->blower = mex_coil(s, 1);
    out->cool = (uint8_t)(mex_coil(s, 2) + mex_coil(s, 3) + mex_coil(s, 16));
    out->heat = (uint8_t)(mex_coil(s, 4) + mex_coil(s, 5) + mex_coil(s, 6) + mex_coil(s, 7));
    out->hum = (uint8_t)(mex_coil(s, 8) + mex_coil(s, 9));
    out->dehum = (uint8_t)mex_coil(s, 15);
}

uint8_t mex_mode_mask(const mex_snapshot_t *s) {
    if (!s)
        return 0;
    return (uint8_t)((s->coils >> 11) & 0x0Fu); /* coils 12..15 -> bits 0..3 */
}
