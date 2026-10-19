/*
 * engine.c - the pure alarm engine (host-tested). Contract: alarm/alarm.h "Engine semantics".
 *
 * State lives in a caller-owned alm_engine_t (static in the service). Every transition is emitted
 * exactly once through the emit callback, synchronously, after the slot has been updated.
 */
#include <string.h>

#include "alarm/alarm.h"
#include "mex150/frame.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"

/* ------------------------------------------------------------------ helpers */

static int16_t clamp16(int32_t v) {
    if (v < INT16_MIN)
        return INT16_MIN;
    if (v > INT16_MAX)
        return INT16_MAX;
    return (int16_t)v;
}

/* Registers of the slow poll group are 0 until the first slow read (mex_snapshot_t.slow_valid). */
static bool is_slow_reg(uint16_t addr) {
    for (unsigned i = 0; i < MEX_SLOW_BLOCKS; i++) {
        const mex_block_t *b = &mex_slow_blocks[i];
        if (b->fc != MEX_FC_READ_HOLDING)
            continue;
        uint32_t first = 40001u + b->start;
        if (addr >= first && addr < first + b->count)
            return true;
    }
    return false;
}

/* Catalog index of the alarm of rule `rule_id` (code 400 + id), or -1. */
static int rule_alarm(uint8_t rule_id) {
    const alm_desc_t *d = alm_find_code((uint16_t)(400u + rule_id));
    if (!d || d->src != ALM_SRC_RULE)
        return -1;
    return (int)(d - alm_catalog);
}

static void emit(alm_engine_t *e, uint8_t dev, alm_id_t id, alm_ev_type_t type, int16_t value, int64_t ts,
                 const char *user) {
    if (!e->emit)
        return;
    alm_transition_t t;
    memset(&t, 0, sizeof(t));
    t.dev = dev;
    t.id = id;
    t.type = type;
    t.sev = (alm_sev_t)e->p.sev[id];
    t.value = value;
    t.ts_ms = ts;
    if (user)
        gw_strlcpy(t.user, user, sizeof(t.user));
    e->emit(e->emit_arg, &t);
}

static void slot_reset_counters(alm_slot_t *s) {
    s->up = 0;
    s->down = 0;
    s->pend_mono_ms = 0;
}

static void do_raise(alm_engine_t *e, uint8_t dev, alm_id_t id, int16_t value, int64_t wall_ms) {
    alm_slot_t *s = &e->slot[dev][id];
    s->active = true;
    s->acked = false;
    s->value = value;
    s->since_ms = wall_ms;
    s->ack_ms = 0;
    s->ack_by[0] = '\0';
    slot_reset_counters(s);
    emit(e, dev, id, ALM_EV_RAISE, value, wall_ms, NULL);
}

static void do_clear(alm_engine_t *e, uint8_t dev, alm_id_t id, int16_t value, int64_t wall_ms) {
    alm_slot_t *s = &e->slot[dev][id];
    s->active = false;
    s->acked = false;
    s->ack_ms = 0;
    s->ack_by[0] = '\0';
    slot_reset_counters(s);
    emit(e, dev, id, ALM_EV_CLEAR, value, wall_ms, NULL);
}

static void reset_device_counters(alm_engine_t *e, uint8_t dev) {
    for (unsigned i = 0; i < ALM_COUNT; i++)
        slot_reset_counters(&e->slot[dev][i]);
}

/* ------------------------------------------------------------------ parameters */

void alm_params_from_config(const cfg_alarms_t *c, alm_params_t *out) {
    memset(out, 0, sizeof(*out));
    out->debounce_raise = 2;
    out->debounce_clear = 3;
    for (unsigned i = 0; i < ALM_COUNT; i++)
        out->sev[i] = (uint8_t)alm_catalog[i].sev;
    if (!c)
        return;
    if (c->debounce_raise >= 1 && c->debounce_raise <= 10)
        out->debounce_raise = c->debounce_raise;
    if (c->debounce_clear >= 1 && c->debounce_clear <= 10)
        out->debounce_clear = c->debounce_clear;
    for (unsigned i = 0; i < c->n_sev_override && i < GW_MAX_SEV_OVERRIDES; i++) {
        const alm_desc_t *d = alm_find_code(c->sev_override[i].code);
        if (d && d->src != ALM_SRC_RULE && c->sev_override[i].sev <= ALM_SEV_CRITICAL)
            out->sev[d - alm_catalog] = c->sev_override[i].sev;
    }
    unsigned n = c->n_rules < GW_MAX_RULES ? c->n_rules : GW_MAX_RULES;
    memcpy(out->rules, c->rules, n * sizeof(c->rules[0]));
    out->n_rules = (uint8_t)n;
    for (unsigned i = 0; i < n; i++) {
        int a = rule_alarm(c->rules[i].id);
        if (a < 0)
            continue;
        uint8_t sev = c->rules[i].sev;
        out->sev[a] = sev < ALM_SEV_MINOR ? ALM_SEV_MINOR : (sev > ALM_SEV_CRITICAL ? ALM_SEV_CRITICAL : sev);
    }
}

static const cfg_rule_t *find_rule(const alm_params_t *p, uint8_t rule_id) {
    for (unsigned i = 0; i < p->n_rules && i < GW_MAX_RULES; i++)
        if (p->rules[i].id == rule_id)
            return &p->rules[i];
    return NULL;
}

/* ------------------------------------------------------------------ engine */

void alm_engine_init(alm_engine_t *e, const alm_params_t *p, alm_emit_fn emit_fn, void *arg) {
    memset(e, 0, sizeof(*e));
    if (p)
        e->p = *p;
    else
        alm_params_from_config(NULL, &e->p);
    for (unsigned d = 0; d < GW_MAX_DEVICES; d++) {
        e->online[d] = true; /* unknown: not frozen until a COMM says offline */
        e->enabled[d] = false;
    }
    e->emit = emit_fn;
    e->emit_arg = arg;
}

void alm_engine_set_params(alm_engine_t *e, const alm_params_t *p, int64_t wall_ms) {
    /* Clear rule alarms whose rule disappeared, was disabled or moved to another device — emitted
     * with the severity they were raised with (old parameters still installed). */
    for (unsigned id = 0; id < ALM_COUNT; id++) {
        const alm_desc_t *d = &alm_catalog[id];
        if (d->src != ALM_SRC_RULE)
            continue;
        const cfg_rule_t *nr = find_rule(p, (uint8_t)d->addr);
        const cfg_rule_t *orule = find_rule(&e->p, (uint8_t)d->addr);
        bool changed = !nr || !orule || memcmp(nr, orule, sizeof(*nr)) != 0;
        for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++) {
            alm_slot_t *s = &e->slot[dev][id];
            if (s->active && (!nr || !nr->enabled || nr->dev != dev))
                do_clear(e, dev, (alm_id_t)id, s->value, wall_ms);
            if (changed)
                s->pend_mono_ms = 0;
        }
    }
    e->p = *p;
}

void alm_engine_feed_snapshot(alm_engine_t *e, uint8_t dev, const mex_snapshot_t *s, int64_t wall_ms) {
    if (dev >= GW_MAX_DEVICES || !s || !s->online || !e->enabled[dev] || !e->online[dev])
        return;
    for (unsigned id = 0; id < ALM_COUNT; id++) {
        const alm_desc_t *d = &alm_catalog[id];
        bool on;
        if (d->src == ALM_SRC_COIL) {
            on = mex_coil(s, d->addr);
        } else if (d->src == ALM_SRC_BIT) {
            unsigned idx = (unsigned)d->addr - MEX_ADDR_BASE;
            if (d->addr < MEX_ADDR_BASE || idx >= MEX_REGS_LEN || d->bit > 15)
                continue;
            if (is_slow_reg(d->addr) && !s->slow_valid)
                continue;
            on = (s->regs[idx] >> d->bit) & 1u;
        } else {
            continue;
        }
        alm_slot_t *sl = &e->slot[dev][id];
        if (on) {
            sl->down = 0;
            if (!sl->active) {
                if (sl->up < 255)
                    sl->up++;
                if (sl->up >= e->p.debounce_raise) {
                    int16_t v = d->vreg ? clamp16(mex_snap_raw(s, d->vreg)) : 1;
                    do_raise(e, dev, (alm_id_t)id, v, wall_ms);
                }
            }
        } else {
            sl->up = 0;
            if (sl->active) {
                if (sl->down < 255)
                    sl->down++;
                if (sl->down >= e->p.debounce_clear) {
                    int16_t v = d->vreg ? clamp16(mex_snap_raw(s, d->vreg)) : 1;
                    do_clear(e, dev, (alm_id_t)id, v, wall_ms);
                }
            }
        }
    }
}

void alm_engine_feed_comm(alm_engine_t *e, uint8_t dev, bool online, int64_t wall_ms) {
    if (dev >= GW_MAX_DEVICES || !e->enabled[dev])
        return;
    reset_device_counters(e, dev); /* frozen while offline; start fresh when back */
    e->online[dev] = online;
    for (unsigned id = 0; id < ALM_COUNT; id++) {
        if (alm_catalog[id].src != ALM_SRC_COMM)
            continue;
        alm_slot_t *s = &e->slot[dev][id];
        if (!online && !s->active)
            do_raise(e, dev, (alm_id_t)id, 1, wall_ms);
        else if (online && s->active)
            do_clear(e, dev, (alm_id_t)id, 1, wall_ms);
    }
}

void alm_engine_set_enabled(alm_engine_t *e, uint8_t dev, bool enabled, int64_t wall_ms) {
    if (dev >= GW_MAX_DEVICES)
        return;
    if (!enabled) {
        for (unsigned id = 0; id < ALM_COUNT; id++) {
            alm_slot_t *s = &e->slot[dev][id];
            if (s->active)
                do_clear(e, dev, (alm_id_t)id, s->value, wall_ms);
        }
        memset(e->slot[dev], 0, sizeof(e->slot[dev]));
        e->enabled[dev] = false;
        e->online[dev] = true;
        return;
    }
    if (!e->enabled[dev]) {
        memset(e->slot[dev], 0, sizeof(e->slot[dev]));
        e->enabled[dev] = true;
        e->online[dev] = true;
    }
}

bool alm_sample_fresh(const mex_snapshot_t *s, uint64_t now_mono_ms, uint32_t poll_ms) {
    if (!s || !s->online || s->mono_ms == 0)
        return false;
    uint64_t window = poll_ms > MEX_FRESH_MS ? (uint64_t)poll_ms + MEX_FRESH_MS : MEX_FRESH_MS;
    uint64_t age = now_mono_ms > s->mono_ms ? now_mono_ms - s->mono_ms : 0;
    return age < window;
}

void alm_engine_tick_rules(alm_engine_t *e, uint8_t dev, const mex_snapshot_t *s, bool fresh, uint64_t mono_ms,
                           int64_t wall_ms) {
    if (dev >= GW_MAX_DEVICES || !e->enabled[dev])
        return;
    bool evaluable = e->online[dev] && s && fresh && s->online;
    uint64_t now = mono_ms ? mono_ms : 1;
    for (unsigned i = 0; i < e->p.n_rules && i < GW_MAX_RULES; i++) {
        const cfg_rule_t *r = &e->p.rules[i];
        if (r->dev != dev || !r->enabled)
            continue;
        int a = rule_alarm(r->id);
        if (a < 0)
            continue;
        alm_slot_t *sl = &e->slot[dev][a];
        if (!evaluable || !mex_reg_find(r->addr) || (is_slow_reg(r->addr) && !s->slow_valid)) {
            sl->pend_mono_ms = 0; /* frozen: an on-delay never spans unobserved time */
            continue;
        }
        int32_t v = mex_snap_raw(s, r->addr);
        bool raise_c, clear_c;
        if (r->op == CFG_OP_LT) {
            raise_c = v < r->thr;
            clear_c = v >= r->thr + r->hyst;
        } else {
            raise_c = v > r->thr;
            clear_c = v <= r->thr - r->hyst;
        }
        if (!sl->active) {
            if (!raise_c) {
                sl->pend_mono_ms = 0;
                continue;
            }
            if (sl->pend_mono_ms == 0)
                sl->pend_mono_ms = now;
            uint64_t held = now >= sl->pend_mono_ms ? now - sl->pend_mono_ms : 0;
            if (held >= (uint64_t)r->delay_s * 1000u)
                do_raise(e, dev, (alm_id_t)a, clamp16(v), wall_ms);
        } else if (clear_c) {
            do_clear(e, dev, (alm_id_t)a, clamp16(v), wall_ms);
        }
    }
}

int alm_engine_ack(alm_engine_t *e, uint8_t dev, alm_id_t id, const char *user, int64_t wall_ms) {
    if (dev >= GW_MAX_DEVICES || (unsigned)id >= ALM_COUNT)
        return -1;
    alm_slot_t *s = &e->slot[dev][id];
    if (!s->active)
        return -1;
    if (s->acked)
        return 1;
    s->acked = true;
    s->ack_ms = wall_ms;
    gw_strlcpy(s->ack_by, user ? user : "", sizeof(s->ack_by));
    emit(e, dev, id, ALM_EV_ACK, s->value, wall_ms, s->ack_by);
    return 0;
}

size_t alm_engine_ack_all(alm_engine_t *e, const char *user, int64_t wall_ms) {
    size_t n = 0;
    for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++)
        for (unsigned id = 0; id < ALM_COUNT; id++)
            if (e->slot[dev][id].active && !e->slot[dev][id].acked &&
                alm_engine_ack(e, dev, (alm_id_t)id, user, wall_ms) == 0)
                n++;
    return n;
}

/* Sort order: severity desc, since asc, dev asc, id asc. */
static bool before(const alm_engine_t *e, uint8_t da, uint8_t ia, uint8_t db, uint8_t ib) {
    uint8_t sa = e->p.sev[ia], sb = e->p.sev[ib];
    if (sa != sb)
        return sa > sb;
    int64_t ta = e->slot[da][ia].since_ms, tb = e->slot[db][ib].since_ms;
    if (ta != tb)
        return ta < tb;
    if (da != db)
        return da < db;
    return ia < ib;
}

size_t alm_engine_active(const alm_engine_t *e, alm_active_t *out, size_t cap) {
    uint8_t ld[GW_MAX_DEVICES * ALM_COUNT], li[GW_MAX_DEVICES * ALM_COUNT];
    size_t n = 0;
    for (uint8_t dev = 0; dev < GW_MAX_DEVICES; dev++) {
        for (uint8_t id = 0; id < ALM_COUNT; id++) {
            if (!e->slot[dev][id].active)
                continue;
            /* insertion sort: n <= 4 x ALM_COUNT */
            size_t k = n++;
            while (k > 0 && before(e, dev, id, ld[k - 1], li[k - 1])) {
                ld[k] = ld[k - 1];
                li[k] = li[k - 1];
                k--;
            }
            ld[k] = dev;
            li[k] = id;
        }
    }
    for (size_t i = 0; out && i < n && i < cap; i++) {
        const alm_slot_t *s = &e->slot[ld[i]][li[i]];
        alm_active_t *o = &out[i];
        memset(o, 0, sizeof(*o));
        o->dev = ld[i];
        o->id = (alm_id_t)li[i];
        o->sev = (alm_sev_t)e->p.sev[li[i]];
        o->value = s->value;
        o->since_ms = s->since_ms;
        o->acked = s->acked;
        o->ack_ms = s->ack_ms;
        gw_strlcpy(o->ack_by, s->ack_by, sizeof(o->ack_by));
    }
    return n;
}

uint32_t alm_engine_mask(const alm_engine_t *e, uint8_t dev) {
    if (dev >= GW_MAX_DEVICES)
        return 0;
    uint32_t m = 0;
    for (unsigned id = 0; id < ALM_COUNT; id++)
        if (e->slot[dev][id].active)
            m |= 1u << id;
    return m;
}
