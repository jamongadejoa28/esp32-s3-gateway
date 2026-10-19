/*
 * history_core.c - pure history engine: minute aggregation, PSRAM-ring bookkeeping, relative and
 * absolute bucket queries with decimation and gaps, and the daily files (stdio). Host-tested.
 * Contracts: store/history.h (public helpers) and hist_core.h (store-internal engine).
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gw_core/gw_time.h"
#include "hist_core.h"
#include "mex150/model.h"

#define CHUNK 16 /* records copied per lock hold during queries (bounded stack frames) */

/* ------------------------------------------------------------------ public pure helpers */

bool hist_ts_wall(uint32_t ts_s) {
    return !(ts_s & HIST_TS_UPTIME) && (int64_t)ts_s >= GW_TIME_VALID_MIN_S;
}

static void stages_of(uint32_t coils, mex_stages_t *st) {
    mex_snapshot_t s;
    memset(&s, 0, sizeof(s));
    s.coils = coils;
    mex_derive_stages(&s, st);
}

void hist_acc_reset(hist_acc_t *a, uint32_t minute_ts) {
    memset(a, 0, sizeof(*a));
    a->minute_ts = minute_ts;
    a->st = HIST_GAP;
    a->sh = HIST_GAP;
}

void hist_acc_add(hist_acc_t *a, const hist_fast_t *s) {
    a->flags |= s->flags;
    if (s->flags & HIST_F_GAP)
        return;
    const int16_t v[3] = {s->temp, s->hum, s->cur};
    for (int i = 0; i < 3; i++) {
        if (a->n == 0 || v[i] < a->min[i])
            a->min[i] = v[i];
        if (a->n == 0 || v[i] > a->max[i])
            a->max[i] = v[i];
        a->sum[i] += v[i];
    }
    a->n++;
    a->st = s->st;
    a->sh = s->sh;
    mex_stages_t st;
    stages_of(s->coils, &st);
    if (st.blower && a->stage_on[HIST_STG_BLOWER] < 255)
        a->stage_on[HIST_STG_BLOWER]++;
    if (st.cool && a->stage_on[HIST_STG_COOL] < 255)
        a->stage_on[HIST_STG_COOL]++;
    if (st.heat && a->stage_on[HIST_STG_HEAT] < 255)
        a->stage_on[HIST_STG_HEAT]++;
    if (st.hum && a->stage_on[HIST_STG_HUM] < 255)
        a->stage_on[HIST_STG_HUM]++;
    if (st.dehum && a->stage_on[HIST_STG_DEHUM] < 255)
        a->stage_on[HIST_STG_DEHUM]++;
    a->alarm_mask |= (s->coils >> 16) & 0xFFFFu;
}

/* Integer division rounded half away from zero. */
static int64_t div_round(int64_t num, int64_t den) {
    if (den <= 0)
        return 0;
    return num >= 0 ? (num + den / 2) / den : -((-num + den / 2) / den);
}

void hist_acc_finish(const hist_acc_t *a, hist_slow_t *out) {
    memset(out, 0, sizeof(*out));
    out->ts_s = a->minute_ts;
    out->flags = a->flags;
    memcpy(out->stage_on_s, a->stage_on, sizeof(out->stage_on_s));
    out->alarm_mask = a->alarm_mask;
    out->samples = (uint8_t)(a->n > 255 ? 255 : a->n);
    int16_t *mn[3] = {&out->tmin, &out->hmin, &out->cmin};
    int16_t *av[3] = {&out->tavg, &out->havg, &out->cavg};
    int16_t *mx[3] = {&out->tmax, &out->hmax, &out->cmax};
    for (int i = 0; i < 3; i++) {
        if (a->n == 0) {
            *mn[i] = *av[i] = *mx[i] = HIST_GAP;
        } else {
            *mn[i] = a->min[i];
            *mx[i] = a->max[i];
            *av[i] = (int16_t)div_round(a->sum[i], a->n);
        }
    }
    out->st = a->n ? a->st : HIST_GAP;
    out->sh = a->n ? a->sh : HIST_GAP;
}

static int16_t clamp16(int32_t v) {
    if (v <= INT16_MIN)
        return INT16_MIN + 1; /* INT16_MIN is the gap marker */
    if (v > INT16_MAX)
        return INT16_MAX;
    return (int16_t)v;
}

void hist_fast_from_snapshot(const mex_snapshot_t *s, bool fresh, bool any_alarm, uint32_t ts_s,
                             hist_fast_t *out) {
    memset(out, 0, sizeof(*out));
    out->ts_s = ts_s;
    if (any_alarm)
        out->flags |= HIST_F_ALARM;
    if (!s || !fresh || !s->online) {
        out->temp = out->hum = out->cur = out->st = out->sh = HIST_GAP;
        out->coils = 0;
        out->flags |= HIST_F_GAP;
        return;
    }
    out->temp = clamp16(mex_snap_raw(s, 40036));
    out->hum = clamp16(mex_snap_raw(s, 40037));
    out->cur = clamp16(mex_snap_raw(s, 40011));
    out->st = clamp16(mex_snap_raw(s, 40012));
    out->sh = clamp16(mex_snap_raw(s, 40013));
    out->coils = s->coils;
    if (mex_running(s))
        out->flags |= HIST_F_RUNNING;
}

static const uint32_t s_steps[] = {1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200};
#define N_STEPS (sizeof(s_steps) / sizeof(s_steps[0]))

uint32_t hist_pick_res_limit(uint32_t span_s, uint32_t requested_s, uint32_t limit) {
    if (span_s == 0)
        span_s = 1;
    if (limit == 0)
        limit = 1;
    for (size_t i = 0; i < N_STEPS; i++) {
        uint32_t st = s_steps[i];
        if (st < requested_s)
            continue;
        if (st < 60 && span_s > HIST_FAST_LEN)
            continue;
        if ((span_s + st - 1) / st <= limit)
            return st;
    }
    return s_steps[N_STEPS - 1];
}

uint32_t hist_pick_res(uint32_t span_s, uint32_t requested_s) {
    return hist_pick_res_limit(span_s, requested_s, HIST_MAX_POINTS);
}

void hist_slow_from_fast(const hist_fast_t *f, hist_slow_t *out) {
    hist_acc_t a;
    hist_acc_reset(&a, f->ts_s);
    hist_acc_add(&a, f);
    hist_acc_finish(&a, out);
}

/* ------------------------------------------------------------------ device rings */

void hist_dev_init(hist_dev_t *d, void *fast_mem, void *slow_mem) {
    memset(d, 0, sizeof(*d));
    gw_ring_init(&d->fast, fast_mem, sizeof(hist_fast_t), HIST_FAST_LEN);
    gw_ring_init(&d->slow, slow_mem, sizeof(hist_slow_t), HIST_SLOW_LEN);
    d->reload_next = -1;
}

void hist_dev_clear(hist_dev_t *d) {
    gw_ring_clear(&d->fast);
    gw_ring_clear(&d->slow);
    memset(&d->acc, 0, sizeof(d->acc));
    d->acc_ticks = 0;
    d->last_mono_ms = 0;
    d->slot_base_ms = 0;
    d->next_slot = 0;
    d->n_pend = 0;
    d->reload_next = -1;
    /* fast_total / slow_total keep counting: absolute indexes stay unique */
}

static void push_slow(hist_dev_t *d, const hist_slow_t *r) {
    gw_ring_push(&d->slow, r);
    d->slow_total++;
}

/* Push one fast sample through the minute accumulator (one 1 s slot). */
static bool push_fast(hist_dev_t *d, const hist_fast_t *s) {
    gw_ring_push(&d->fast, s);
    d->fast_total++;
    if (d->acc_ticks == 0)
        hist_acc_reset(&d->acc, s->ts_s);
    hist_acc_add(&d->acc, s);
    if (++d->acc_ticks < 60)
        return false;
    hist_slow_t rec;
    hist_acc_finish(&d->acc, &rec);
    d->acc_ticks = 0;
    push_slow(d, &rec);
    if (rec.samples == 0 || !hist_ts_wall(rec.ts_s))
        return false;
    if (d->n_pend >= HIST_PEND_MAX) {
        memmove(&d->pend[0], &d->pend[1], (HIST_PEND_MAX - 1) * sizeof(d->pend[0]));
        d->n_pend--;
        d->pend_dropped++;
    }
    d->pend[d->n_pend++] = rec;
    return (d->n_pend % HIST_FLUSH_BATCH) == 0;
}

static void gap_fast(const hist_fast_t *like, uint32_t ts_s, hist_fast_t *out) {
    memset(out, 0, sizeof(*out));
    out->ts_s = ts_s;
    out->temp = out->hum = out->cur = out->st = out->sh = HIST_GAP;
    out->flags = HIST_F_GAP | (like->flags & HIST_F_ALARM);
}

/* Fill `missed` skipped slots (the oldest first) that precede a sample stamped ts_s. */
static bool fill_missed(hist_dev_t *d, const hist_fast_t *s, uint64_t missed) {
    bool flush = false;
    hist_fast_t g;
    uint64_t rem = missed;
    if (rem > (uint64_t)HIST_FAST_LEN + 59u) {
        /* finish the minute in progress, then whole gap minutes straight into the slow ring */
        while (d->acc_ticks != 0 && rem > 0) {
            gap_fast(s, s->ts_s - (uint32_t)rem, &g);
            flush |= push_fast(d, &g);
            rem--;
        }
        uint64_t minutes = (rem - HIST_FAST_LEN) / 60u;
        uint64_t push = minutes < HIST_SLOW_LEN ? minutes : HIST_SLOW_LEN;
        for (uint64_t i = 0; i < push; i++) {
            hist_slow_t r;
            memset(&r, 0, sizeof(r));
            r.ts_s = s->ts_s - (uint32_t)(rem - (minutes - push + i) * 60u);
            r.tmin = r.tavg = r.tmax = r.hmin = r.havg = r.hmax = r.cmin = r.cavg = r.cmax = HIST_GAP;
            r.st = r.sh = HIST_GAP;
            r.flags = HIST_F_GAP;
            push_slow(d, &r);
        }
        rem -= minutes * 60u;
    }
    for (; rem > 0; rem--) {
        gap_fast(s, s->ts_s - (uint32_t)rem, &g);
        flush |= push_fast(d, &g);
    }
    d->gap_filled += (uint32_t)(missed > UINT32_MAX ? UINT32_MAX : missed);
    return flush;
}

bool hist_dev_sample(hist_dev_t *d, const hist_fast_t *s, uint64_t mono_ms) {
    bool flush = false;
    if (mono_ms != 0) {
        if (d->last_mono_ms == 0 || mono_ms < d->slot_base_ms) {
            d->slot_base_ms = mono_ms > 500u ? mono_ms - 500u : 0;
            d->next_slot = 0;
        }
        uint64_t slot = (mono_ms - d->slot_base_ms) / 1000u;
        if (slot < d->next_slot) {
            d->dup_dropped++;
            return false;
        }
        if (slot > d->next_slot)
            flush |= fill_missed(d, s, slot - d->next_slot);
        d->next_slot = slot + 1;
    }
    d->last_mono_ms = mono_ms ? mono_ms : 1;
    flush |= push_fast(d, s);
    return flush;
}

size_t hist_dev_take_pending(hist_dev_t *d, hist_slow_t *out, size_t cap) {
    size_t n = d->n_pend < cap ? d->n_pend : cap;
    if (!n)
        return 0;
    memcpy(out, d->pend, n * sizeof(*out));
    memmove(&d->pend[0], &d->pend[n], (d->n_pend - n) * sizeof(d->pend[0]));
    d->n_pend = (uint16_t)(d->n_pend - n);
    return n;
}

void hist_dev_unget_pending(hist_dev_t *d, const hist_slow_t *recs, size_t n) {
    size_t room = HIST_PEND_MAX - d->n_pend;
    if (n > room) {
        d->pend_dropped += (uint32_t)(n - room);
        recs += n - room; /* drop the oldest of the returned records */
        n = room;
    }
    if (!n)
        return;
    memmove(&d->pend[n], &d->pend[0], d->n_pend * sizeof(d->pend[0]));
    memcpy(&d->pend[0], recs, n * sizeof(*recs));
    d->n_pend = (uint16_t)(d->n_pend + n);
}

static void push_gap_slot(hist_dev_t *d, int32_t slot) {
    hist_slow_t g;
    memset(&g, 0, sizeof(g));
    g.ts_s = d->reload_now_s - (uint32_t)(slot + 1) * 60u;
    g.tmin = g.tavg = g.tmax = g.hmin = g.havg = g.hmax = g.cmin = g.cavg = g.cmax = HIST_GAP;
    g.st = g.sh = HIST_GAP;
    g.flags = HIST_F_GAP;
    push_slow(d, &g);
}

void hist_dev_reload_begin(hist_dev_t *d, uint32_t now_s) {
    uint32_t slots = HIST_RELOAD_HOURS * 60u;
    if (slots > HIST_SLOW_LEN)
        slots = HIST_SLOW_LEN;
    d->reload_now_s = now_s;
    d->reload_next = (int32_t)slots - 1;
    d->reload_any = false;
}

bool hist_dev_reload_add(void *dev, const hist_slow_t *r) {
    hist_dev_t *d = dev;
    if (d->reload_next < 0)
        return false;
    if (!hist_ts_wall(r->ts_s) || r->ts_s >= d->reload_now_s || r->samples == 0)
        return true;
    int64_t slot = (int64_t)((d->reload_now_s - r->ts_s + 30u) / 60u) - 1;
    if (slot < 0 || slot > d->reload_next)
        return true; /* too recent, or a later record for an already filled minute */
    for (int32_t s = d->reload_next; s > slot; s--)
        push_gap_slot(d, s);
    push_slow(d, r);
    d->reload_next = (int32_t)slot - 1;
    d->reload_any = true;
    return d->reload_next >= 0;
}

void hist_dev_reload_end(hist_dev_t *d) {
    if (d->reload_any) {
        for (int32_t s = d->reload_next; s >= 0; s--)
            push_gap_slot(d, s);
    }
    d->reload_next = -1;
}

/* ------------------------------------------------------------------ 10-minute rollups */

void hist_day_reset(hist_day_t *d, uint32_t day) {
    memset(d, 0, sizeof(*d));
    d->day = day;
}

void hist_day_add(hist_day_t *d, const hist_slow_t *r) {
    if (!hist_ts_wall(r->ts_s) || r->ts_s / 86400u != d->day)
        return;
    hist_coarse_t *c = &d->c[(r->ts_s % 86400u) / HIST_COARSE_S];
    if (c->minutes < UINT8_MAX)
        c->minutes++;
    c->flags |= r->flags;
    c->alarm |= (uint16_t)(r->alarm_mask & 0xFFFFu);
    if (r->samples == 0)
        return;
    const int16_t mn[3] = {r->tmin, r->hmin, r->cmin};
    const int16_t av[3] = {r->tavg, r->havg, r->cavg};
    const int16_t mx[3] = {r->tmax, r->hmax, r->cmax};
    for (int i = 0; i < 3; i++) {
        if (c->samples == 0 || mn[i] < c->mn[i])
            c->mn[i] = mn[i];
        if (c->samples == 0 || mx[i] > c->mx[i])
            c->mx[i] = mx[i];
        c->wsum[i] += (int32_t)av[i] * r->samples;
    }
    c->samples = (uint16_t)(c->samples + r->samples > UINT16_MAX ? UINT16_MAX : c->samples + r->samples);
    c->st = r->st;
    c->sh = r->sh;
    for (int k = 0; k < HIST_STG_COUNT; k++) {
        uint32_t v = (uint32_t)c->stage[k] + r->stage_on_s[k];
        c->stage[k] = (uint16_t)(v > UINT16_MAX ? UINT16_MAX : v);
    }
}

bool hist_day_add_cb(void *day, const hist_slow_t *r) {
    hist_day_add(day, r);
    return true;
}

/* ------------------------------------------------------------------ bucket emitter */

/* Weights are kept in tenths of a sample so a rollup (10 minutes) can be split over the buckets it
 * overlaps by its minutes (k/10). Minute and second records contribute x10: exact as before. */
#define W_SCALE 10u
static_assert(HIST_COARSE_MIN == W_SCALE, "rollup split unit");

typedef struct {
    int64_t wsum[3];   /* x W_SCALE */
    uint32_t samples;  /* x W_SCALE */
    int16_t mn[3], mx[3];
    int16_t st, sh;
    uint32_t stage[HIST_STG_COUNT]; /* x W_SCALE */
    uint8_t flags;
    uint32_t alarm;
} bucket_t;

/* One record's share of a bucket (all weighted fields already scaled). */
typedef struct {
    uint8_t flags;
    uint32_t alarm;
    uint32_t samples;
    int64_t wsum[3];
    int16_t mn[3], mx[3];
    int16_t st, sh;
    uint32_t stage[HIST_STG_COUNT];
} contrib_t;

static uint32_t unscale(uint32_t v) {
    return (v + W_SCALE / 2) / W_SCALE;
}

typedef struct {
    hist_series_t *io;
    hist_row_cb_t cb;
    void *cb_arg;
    bool stop;
    bool t0_known;
    int64_t t0_ms;
    uint32_t dt, n, next;
    int64_t cur;
    bucket_t b;
} emit_t;

static void emit_init(emit_t *e, hist_series_t *io, hist_row_cb_t cb, void *arg, uint32_t dt, uint32_t n) {
    memset(e, 0, sizeof(*e));
    e->io = io;
    e->cb = cb;
    e->cb_arg = arg;
    e->dt = dt;
    e->n = n;
    e->cur = -1;
}

static void emit_out(emit_t *e, uint32_t idx, const bucket_t *b) {
    if (e->stop)
        return;
    bool gap = !b || b->samples == 0;
    int16_t avg[3], st = HIST_GAP, sh = HIST_GAP;
    uint32_t samples = 0;
    if (!gap) {
        samples = unscale(b->samples);
        if (samples == 0)
            samples = 1; /* a sliver of a rollup still carries data */
    }
    for (int i = 0; i < 3; i++)
        avg[i] = gap ? HIST_GAP : clamp16((int32_t)div_round(b->wsum[i], b->samples));
    if (!gap) {
        st = b->st;
        sh = b->sh;
    }
    if (e->io) {
        hist_series_t *io = e->io;
        io->avg[HIST_CH_TEMP][idx] = avg[0];
        io->avg[HIST_CH_HUM][idx] = avg[1];
        io->avg[HIST_CH_CUR][idx] = avg[2];
        io->avg[HIST_CH_ST][idx] = st;
        io->avg[HIST_CH_SH][idx] = sh;
        for (int i = 0; i < 3; i++) {
            if (io->min[i])
                io->min[i][idx] = gap ? HIST_GAP : b->mn[i];
            if (io->max[i])
                io->max[i][idx] = gap ? HIST_GAP : b->mx[i];
        }
        for (int k = 0; k < HIST_STG_COUNT; k++) {
            if (!io->stage[k])
                continue;
            uint32_t v = gap ? HIST_STAGE_GAP : unscale(b->stage[k]);
            if (!gap && v > 0xFFFEu)
                v = 0xFFFEu;
            io->stage[k][idx] = (uint16_t)v;
        }
        return;
    }
    hist_slow_t r;
    memset(&r, 0, sizeof(r));
    int64_t ts_ms = e->t0_known ? e->t0_ms + (int64_t)idx * e->dt * 1000 : 0;
    r.ts_s = e->t0_known ? (uint32_t)(ts_ms / 1000) : 0;
    r.tavg = avg[0];
    r.havg = avg[1];
    r.cavg = avg[2];
    r.tmin = gap ? HIST_GAP : b->mn[0];
    r.tmax = gap ? HIST_GAP : b->mx[0];
    r.hmin = gap ? HIST_GAP : b->mn[1];
    r.hmax = gap ? HIST_GAP : b->mx[1];
    r.cmin = gap ? HIST_GAP : b->mn[2];
    r.cmax = gap ? HIST_GAP : b->mx[2];
    r.st = st;
    r.sh = sh;
    if (b) {
        r.samples = (uint8_t)(samples > 255 ? 255 : samples);
        r.flags = b->flags;
        for (int k = 0; k < HIST_STG_COUNT; k++) {
            uint32_t v = gap ? 0 : unscale(b->stage[k]);
            r.stage_on_s[k] = (uint8_t)(v > 255 ? 255 : v);
        }
        r.alarm_mask = b->alarm;
    } else {
        r.flags = HIST_F_GAP;
    }
    if (!e->cb(e->cb_arg, ts_ms, &r))
        e->stop = true;
}

static void emit_flush(emit_t *e) {
    if (e->cur < 0)
        return;
    while (e->next < (uint32_t)e->cur)
        emit_out(e, e->next++, NULL);
    emit_out(e, (uint32_t)e->cur, &e->b);
    e->next = (uint32_t)e->cur + 1;
    e->cur = -1;
}

static void emit_contrib(emit_t *e, int64_t bidx, const contrib_t *c) {
    if (e->stop || bidx < 0 || bidx >= (int64_t)e->n)
        return;
    if (bidx < e->cur || (e->cur < 0 && bidx < (int64_t)e->next))
        return; /* out of order (wall clock stepped back): dropped */
    if (bidx != e->cur) {
        emit_flush(e);
        e->cur = bidx;
        memset(&e->b, 0, sizeof(e->b));
    }
    bucket_t *b = &e->b;
    b->flags |= c->flags;
    b->alarm |= c->alarm;
    if (c->samples == 0)
        return;
    for (int i = 0; i < 3; i++) {
        if (b->samples == 0 || c->mn[i] < b->mn[i])
            b->mn[i] = c->mn[i];
        if (b->samples == 0 || c->mx[i] > b->mx[i])
            b->mx[i] = c->mx[i];
        b->wsum[i] += c->wsum[i];
    }
    b->samples += c->samples;
    b->st = c->st;
    b->sh = c->sh;
    for (int k = 0; k < HIST_STG_COUNT; k++)
        b->stage[k] += c->stage[k];
}

static void emit_add(emit_t *e, int64_t bidx, const hist_slow_t *r) {
    contrib_t c;
    c.flags = r->flags;
    c.alarm = r->alarm_mask;
    c.samples = (uint32_t)r->samples * W_SCALE;
    const int16_t mn[3] = {r->tmin, r->hmin, r->cmin};
    const int16_t av[3] = {r->tavg, r->havg, r->cavg};
    const int16_t mx[3] = {r->tmax, r->hmax, r->cmax};
    for (int i = 0; i < 3; i++) {
        c.mn[i] = mn[i];
        c.mx[i] = mx[i];
        c.wsum[i] = (int64_t)av[i] * r->samples * W_SCALE;
    }
    c.st = r->st;
    c.sh = r->sh;
    for (int k = 0; k < HIST_STG_COUNT; k++)
        c.stage[k] = (uint32_t)r->stage_on_s[k] * W_SCALE;
    emit_contrib(e, bidx, &c);
}

/* `minutes` (1..HIST_COARSE_MIN) of rollup r fall into bucket bidx. */
static void emit_coarse(emit_t *e, int64_t bidx, const hist_coarse_t *r, uint32_t minutes) {
    contrib_t c;
    c.flags = r->flags;
    c.alarm = r->alarm;
    c.samples = (uint32_t)r->samples * minutes;
    for (int i = 0; i < 3; i++) {
        c.mn[i] = r->mn[i];
        c.mx[i] = r->mx[i];
        c.wsum[i] = (int64_t)r->wsum[i] * minutes;
    }
    c.st = r->st;
    c.sh = r->sh;
    for (int k = 0; k < HIST_STG_COUNT; k++)
        c.stage[k] = (uint32_t)r->stage[k] * minutes;
    emit_contrib(e, bidx, &c);
}

/* Spread rollup r over buckets: bucket_of() maps the minute starting at wall second mts to a
 * bucket index (< 0 = not served from the rollups). Buckets come out non-decreasing. */
typedef int64_t (*minute_bucket_fn)(const void *ctx, int64_t mts);

static void emit_coarse_split(emit_t *e, uint32_t start, const hist_coarse_t *r, minute_bucket_fn bucket_of,
                              const void *ctx) {
    int64_t prev = -1;
    uint32_t cnt = 0;
    for (uint32_t k = 0; k < HIST_COARSE_MIN; k++) {
        int64_t b = bucket_of(ctx, (int64_t)start + 60 * (int64_t)k);
        if (b < 0)
            continue;
        if (cnt && b != prev) {
            emit_coarse(e, prev, r, cnt);
            cnt = 0;
        }
        prev = b;
        cnt++;
    }
    if (cnt)
        emit_coarse(e, prev, r, cnt);
}

static void emit_finish(emit_t *e) {
    emit_flush(e);
    while (!e->stop && e->next < e->n)
        emit_out(e, e->next++, NULL);
}

/* ------------------------------------------------------------------ query helpers */

static void env_lock(const hist_env_t *env) {
    if (env && env->lock)
        env->lock(env->lock_arg);
}

static void env_unlock(const hist_env_t *env) {
    if (env && env->unlock)
        env->unlock(env->lock_arg);
}

static bool series_ok(const hist_series_t *io) {
    if (io->n_max == 0)
        return false;
    for (int ch = 0; ch < HIST_CH_COUNT; ch++)
        if (!io->avg[ch])
            return false;
    return true;
}

typedef struct {
    uint64_t fast_total, slow_total;
    uint32_t fast_count, slow_count;
    uint8_t acc_ticks;
    uint64_t last_mono;
    uint32_t ring_first_wall; /* first wall-stamped slow record (0 = none) */
} snap_meta_t;

static void take_meta(hist_dev_t *d, const hist_env_t *env, snap_meta_t *m, bool want_first_wall) {
    env_lock(env);
    m->fast_total = d->fast_total;
    m->slow_total = d->slow_total;
    m->fast_count = gw_ring_count(&d->fast);
    m->slow_count = gw_ring_count(&d->slow);
    m->acc_ticks = d->acc_ticks;
    m->last_mono = d->last_mono_ms;
    m->ring_first_wall = 0;
    if (want_first_wall) {
        for (uint32_t i = 0; i < m->slow_count; i++) {
            const hist_slow_t *r = gw_ring_at(&d->slow, i);
            if (r && hist_ts_wall(r->ts_s)) {
                m->ring_first_wall = r->ts_s;
                break;
            }
        }
    }
    env_unlock(env);
}

/* Copy the slow record with absolute minute index a (in-progress minute -> finished copy of acc).
 * Caller holds the lock. */
static bool slow_at_abs(hist_dev_t *d, int64_t a, hist_slow_t *out) {
    if (a < 0)
        return false;
    if ((uint64_t)a == d->slow_total) {
        if (d->acc_ticks == 0)
            return false;
        hist_acc_finish(&d->acc, out);
        return true;
    }
    if ((uint64_t)a > d->slow_total)
        return false;
    uint64_t back = d->slow_total - 1 - (uint64_t)a;
    if (back >= gw_ring_count(&d->slow))
        return false;
    *out = *(const hist_slow_t *)gw_ring_newest(&d->slow, (uint32_t)back);
    return true;
}

static bool fast_at_abs(hist_dev_t *d, int64_t a, hist_fast_t *out) {
    if (a < 0 || (uint64_t)a >= d->fast_total)
        return false;
    uint64_t back = d->fast_total - 1 - (uint64_t)a;
    if (back >= gw_ring_count(&d->fast))
        return false;
    *out = *(const hist_fast_t *)gw_ring_newest(&d->fast, (uint32_t)back);
    return true;
}

static void finish_series(hist_series_t *io, const emit_t *e, uint64_t t0_age) {
    if (!io)
        return;
    io->t0_ms = e->t0_known ? e->t0_ms : 0;
    io->t0_age_ms = t0_age;
    io->dt_s = e->dt;
    io->n = e->n;
}

/* ---- relative (span) ---- */

typedef struct {
    emit_t *e;
    int64_t slot0_wall_s;
    int64_t j_lo, j_hi;
    uint32_t m;
} span_file_ctx_t;

static int64_t span_bucket(const void *ctx, int64_t mts) {
    const span_file_ctx_t *c = ctx;
    int64_t diff = c->slot0_wall_s - mts;
    int64_t j = (diff >= 0 ? diff + 30 : diff - 30) / 60;
    if (j < c->j_lo || j > c->j_hi)
        return -1;
    return (int64_t)c->e->n - 1 - j / c->m;
}

static bool span_file_cb(void *arg, const hist_slow_t *r) {
    span_file_ctx_t *c = arg;
    int64_t b = span_bucket(c, (int64_t)r->ts_s);
    if (b >= 0)
        emit_add(c->e, b, r);
    return !c->e->stop;
}

static bool span_coarse_cb(void *arg, uint32_t start, const hist_coarse_t *r) {
    span_file_ctx_t *c = arg;
    emit_coarse_split(c->e, start, r, span_bucket, c);
    return !c->e->stop;
}

/* Rollups replace the minute files when the bucket width is a whole number of rollup periods. */
static bool use_coarse(const hist_env_t *env, uint32_t dt) {
    return env && env->coarse && dt >= HIST_COARSE_S && dt % HIST_COARSE_S == 0;
}

static int64_t floor_coarse(int64_t s) {
    return s - ((s % HIST_COARSE_S) + HIST_COARSE_S) % HIST_COARSE_S;
}

esp_err_t hist_core_span(hist_dev_t *d, uint8_t dev, uint32_t span_s, uint32_t res_s, uint64_t now_mono_ms,
                         int64_t now_wall_ms, const hist_env_t *env, hist_series_t *io, hist_row_cb_t row_cb,
                         void *row_arg) {
    if (!d || span_s == 0 || span_s > HIST_SPAN_MAX_S || (!io) == (!row_cb))
        return ESP_ERR_INVALID_ARG;
    if (io && !series_ok(io))
        return ESP_ERR_INVALID_ARG;
    uint32_t limit = io ? (io->n_max < HIST_MAX_POINTS ? io->n_max : HIST_MAX_POINTS) : HIST_MAX_POINTS;
    uint32_t dt = hist_pick_res_limit(span_s, res_s, limit);
    uint32_t n = (span_s + dt - 1) / dt;
    if (n > limit)
        n = limit;
    snap_meta_t m;
    take_meta(d, env, &m, false);
    emit_t e;
    emit_init(&e, io, row_cb, row_arg, dt, n);
    uint64_t t0_age;

    if (dt < 60) {
        uint64_t anchor = m.last_mono ? m.last_mono : now_mono_ms;
        uint64_t age0 = now_mono_ms > anchor ? now_mono_ms - anchor : 0;
        uint64_t total = (uint64_t)n * dt; /* sample ages 0..total-1 */
        t0_age = age0 + (total - 1) * 1000u;
        if (now_wall_ms > 0) {
            e.t0_known = true;
            e.t0_ms = now_wall_ms - (int64_t)t0_age;
        }
        int64_t k = (int64_t)total - 1;
        while (k >= 0 && !e.stop) {
            hist_fast_t buf[CHUNK];
            bool ok[CHUNK];
            int64_t ks[CHUNK];
            int cnt = 0;
            env_lock(env);
            for (; k >= 0 && cnt < CHUNK; k--, cnt++) {
                ks[cnt] = k;
                ok[cnt] = fast_at_abs(d, (int64_t)m.fast_total - 1 - k, &buf[cnt]);
            }
            env_unlock(env);
            for (int i = 0; i < cnt; i++) {
                if (!ok[i])
                    continue;
                hist_slow_t r;
                hist_slow_from_fast(&buf[i], &r);
                emit_add(&e, (int64_t)n - 1 - ks[i] / dt, &r);
            }
        }
    } else {
        uint32_t mm = dt / 60;
        int64_t S = (int64_t)n * mm;
        bool have_acc = m.acc_ticks > 0;
        int64_t a0 = have_acc ? (int64_t)m.slow_total : (int64_t)m.slow_total - 1;
        uint32_t ticks0 = have_acc ? m.acc_ticks : 60;
        uint64_t slot0_mono;
        if (m.last_mono == 0)
            slot0_mono = now_mono_ms;
        else
            slot0_mono = m.last_mono > (uint64_t)(ticks0 - 1) * 1000u ? m.last_mono - (uint64_t)(ticks0 - 1) * 1000u : 0;
        uint64_t age0 = now_mono_ms > slot0_mono ? now_mono_ms - slot0_mono : 0;
        t0_age = age0 + (uint64_t)(S - 1) * 60000u;
        if (now_wall_ms > 0) {
            e.t0_known = true;
            e.t0_ms = now_wall_ms - (int64_t)t0_age;
        }
        int64_t ring_lo = (int64_t)m.slow_total - (int64_t)m.slow_count; /* oldest abs minute held */
        int64_t j_ring_end = a0 - ring_lo;                                  /* last slot served by RAM */
        if (j_ring_end > S - 1)
            j_ring_end = S - 1;
        /* Older slots: 10-minute rollups or daily files (wall time needed to address them). */
        const bool coarse = use_coarse(env, dt);
        if (j_ring_end < S - 1 && now_wall_ms > 0 && env && (coarse || env->files)) {
            span_file_ctx_t fc = {.e = &e, .m = mm};
            fc.slot0_wall_s = (now_wall_ms - (int64_t)age0) / 1000;
            fc.j_lo = j_ring_end + 1;
            fc.j_hi = S - 1;
            int64_t from_s = fc.slot0_wall_s - fc.j_hi * 60 - 30;
            int64_t to_s = fc.slot0_wall_s - fc.j_lo * 60 + 30;
            if (from_s < 0)
                from_s = 0;
            if (coarse) {
                from_s = floor_coarse(from_s);
                if (to_s > from_s)
                    env->coarse(env->coarse_arg, dev, (uint32_t)from_s, (uint32_t)to_s, span_coarse_cb, &fc);
            } else if (to_s > from_s) {
                env->files(env->files_arg, dev, (uint32_t)from_s, (uint32_t)to_s, span_file_cb, &fc);
            }
        }
        int64_t j = j_ring_end;
        while (j >= 0 && !e.stop) {
            hist_slow_t buf[CHUNK];
            bool ok[CHUNK];
            int64_t js[CHUNK];
            int cnt = 0;
            env_lock(env);
            for (; j >= 0 && cnt < CHUNK; j--, cnt++) {
                js[cnt] = j;
                ok[cnt] = slow_at_abs(d, a0 - j, &buf[cnt]);
            }
            env_unlock(env);
            for (int i = 0; i < cnt; i++)
                if (ok[i])
                    emit_add(&e, (int64_t)n - 1 - js[i] / mm, &buf[i]);
        }
    }
    emit_finish(&e);
    finish_series(io, &e, t0_age);
    return ESP_OK;
}

/* ---- absolute (range) ---- */

typedef struct {
    emit_t *e;
    int64_t from_s, end_s;
    uint32_t dt;
    int64_t coarse_to; /* rollup minutes must start before this (the RAM ring serves the rest) */
} range_ctx_t;

static void range_add(range_ctx_t *c, const hist_slow_t *r) {
    if (!hist_ts_wall(r->ts_s))
        return;
    int64_t ts = r->ts_s;
    if (ts < c->from_s || ts >= c->end_s)
        return;
    emit_add(c->e, (ts - c->from_s) / c->dt, r);
}

static bool range_file_cb(void *arg, const hist_slow_t *r) {
    range_ctx_t *c = arg;
    range_add(c, r);
    return !c->e->stop;
}

static int64_t range_bucket(const void *ctx, int64_t mts) {
    const range_ctx_t *c = ctx;
    if (mts < c->from_s || mts >= c->end_s || mts >= c->coarse_to)
        return -1;
    return (mts - c->from_s) / c->dt;
}

static bool range_coarse_cb(void *arg, uint32_t start, const hist_coarse_t *r) {
    range_ctx_t *c = arg;
    emit_coarse_split(c->e, start, r, range_bucket, c);
    return !c->e->stop;
}

esp_err_t hist_core_range(hist_dev_t *d, uint8_t dev, int64_t from_ms, int64_t to_ms, uint32_t res_s,
                          int64_t now_wall_ms, const hist_env_t *env, hist_series_t *io, hist_row_cb_t row_cb,
                          void *row_arg) {
    if (!d || (!io) == (!row_cb))
        return ESP_ERR_INVALID_ARG;
    if (now_wall_ms <= 0)
        return ESP_ERR_INVALID_STATE;
    if (from_ms < 0 || to_ms <= from_ms)
        return ESP_ERR_INVALID_ARG;
    /* Nothing older than the retention exists, and t0_age_ms must stay within the REST schema
     * (31 days): a start more than HIST_RETENTION_DAYS back is a bad request (as the mock). */
    if (now_wall_ms - from_ms > (int64_t)HIST_RETENTION_DAYS * 86400 * 1000)
        return ESP_ERR_INVALID_ARG;
    if (io && !series_ok(io))
        return ESP_ERR_INVALID_ARG;
    int64_t span_ms = to_ms - from_ms;
    if (span_ms > (int64_t)HIST_SPAN_MAX_S * 1000)
        return ESP_ERR_INVALID_ARG;
    uint32_t span_s = (uint32_t)((span_ms + 999) / 1000);
    int64_t from_s = from_ms / 1000;
    int64_t now_s = now_wall_ms / 1000;
    uint32_t limit = io ? (io->n_max < HIST_MAX_POINTS ? io->n_max : HIST_MAX_POINTS) : HIST_MAX_POINTS;
    uint32_t dt = hist_pick_res_limit(span_s, res_s, limit);
    if (dt < 60 && now_s - from_s > HIST_FAST_LEN)
        dt = hist_pick_res_limit(span_s, res_s > 60 ? res_s : 60, limit); /* only minutes reach back */
    uint32_t n = (span_s + dt - 1) / dt;
    if (n > limit)
        n = limit;
    emit_t e;
    emit_init(&e, io, row_cb, row_arg, dt, n);
    e.t0_known = true;
    e.t0_ms = from_s * 1000;
    uint64_t t0_age = now_wall_ms > e.t0_ms ? (uint64_t)(now_wall_ms - e.t0_ms) : 0;
    range_ctx_t rc = {.e = &e, .from_s = from_s, .end_s = from_s + (int64_t)n * dt, .dt = dt};
    snap_meta_t m;
    take_meta(d, env, &m, dt >= 60);

    if (dt < 60) {
        int64_t a = (int64_t)m.fast_total - (int64_t)m.fast_count;
        for (;;) {
            hist_fast_t buf[CHUNK];
            int cnt = 0;
            env_lock(env);
            for (; cnt < CHUNK && a < (int64_t)d->fast_total; a++)
                if (fast_at_abs(d, a, &buf[cnt]))
                    cnt++;
            bool more = a < (int64_t)d->fast_total;
            env_unlock(env);
            for (int i = 0; i < cnt; i++) {
                hist_slow_t r;
                hist_slow_from_fast(&buf[i], &r);
                range_add(&rc, &r);
            }
            if (!more || e.stop)
                break;
        }
    } else {
        int64_t file_to = rc.end_s;
        if (m.ring_first_wall && (int64_t)m.ring_first_wall < file_to)
            file_to = m.ring_first_wall;
        if (use_coarse(env, dt)) {
            rc.coarse_to = file_to;
            const int64_t c_from = floor_coarse(from_s);
            if (file_to > c_from)
                env->coarse(env->coarse_arg, dev, (uint32_t)c_from, (uint32_t)file_to, range_coarse_cb, &rc);
        } else if (env && env->files && file_to > from_s) {
            env->files(env->files_arg, dev, (uint32_t)from_s, (uint32_t)file_to, range_file_cb, &rc);
        }
        int64_t a = (int64_t)m.slow_total - (int64_t)m.slow_count;
        while (!e.stop) {
            hist_slow_t buf[CHUNK];
            int cnt = 0;
            env_lock(env);
            /* finished minutes up to the CURRENT total, then the in-progress one */
            for (; cnt < CHUNK && a <= (int64_t)d->slow_total; a++)
                if (slow_at_abs(d, a, &buf[cnt]))
                    cnt++;
            bool more = a <= (int64_t)d->slow_total;
            env_unlock(env);
            for (int i = 0; i < cnt; i++)
                range_add(&rc, &buf[i]);
            if (!more)
                break;
        }
    }
    emit_finish(&e);
    finish_series(io, &e, t0_age);
    return ESP_OK;
}

/* ------------------------------------------------------------------ daily files */

static int day_path(char *out, size_t cap, const char *base, uint8_t dev, uint32_t day) {
    return snprintf(out, cap, "%s/d%u/%08u.bin", base, (unsigned)dev, (unsigned)day);
}

static bool hdr_ok(const hist_file_hdr_t *h, uint32_t day, uint8_t dev) {
    return h->magic == HIST_FILE_MAGIC && h->version == 1 && h->rec_size == sizeof(hist_slow_t) && h->day == day &&
           h->dev == dev;
}

static esp_err_t append_day(const char *base, uint8_t dev, uint32_t day, const hist_slow_t *recs, size_t n) {
    char path[96];
    if (day_path(path, sizeof(path), base, dev, day) >= (int)sizeof(path))
        return ESP_ERR_INVALID_ARG;
    struct stat st;
    bool fresh;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT)
            return ESP_FAIL; /* transient: the caller keeps the records and retries */
        fresh = true;
    } else {
        /* a file shorter than its header was torn while being created: nothing to lose */
        fresh = st.st_size < (off_t)sizeof(hist_file_hdr_t);
    }
    if (!fresh) {
        hist_file_hdr_t h;
        FILE *f = fopen(path, "rb");
        if (!f)
            return ESP_FAIL; /* e.g. ENOMEM in the FS layer: never truncate the day on that */
        bool got = fread(&h, sizeof(h), 1, f) == 1;
        fclose(f);
        if (!got)
            return ESP_FAIL;
        if (!hdr_ok(&h, day, dev)) {
            /* foreign/corrupt header: keep the old file aside (<day>.bad, removed by retention) */
            char bad[96];
            if (snprintf(bad, sizeof(bad), "%.*s.bad", (int)(strlen(path) - 4), path) >= (int)sizeof(bad))
                return ESP_FAIL;
            (void)remove(bad);
            if (rename(path, bad) != 0)
                return ESP_FAIL;
            fresh = true;
        } else {
            long body = (long)st.st_size - (long)sizeof(h);
            long torn = body % (long)sizeof(hist_slow_t);
            if (torn && truncate(path, (off_t)(st.st_size - torn)) != 0)
                return ESP_FAIL;
        }
    }
    FILE *f = fopen(path, fresh ? "wb" : "ab");
    if (!f)
        return ESP_FAIL;
    bool ok = true;
    if (fresh) {
        hist_file_hdr_t h = {.magic = HIST_FILE_MAGIC, .version = 1, .rec_size = sizeof(hist_slow_t), .day = day,
                             .dev = dev};
        ok = fwrite(&h, sizeof(h), 1, f) == 1;
    }
    ok = ok && fwrite(recs, sizeof(*recs), n, f) == n;
    ok = ok && fflush(f) == 0;
    ok = ok && fsync(fileno(f)) == 0;
    if (fclose(f) != 0)
        ok = false;
    return ok ? ESP_OK : ESP_FAIL;
}

esp_err_t hist_files_append(const char *base, uint8_t dev, const hist_slow_t *recs, size_t n) {
    if (!base || (!recs && n))
        return ESP_ERR_INVALID_ARG;
    char dir[80];
    if (snprintf(dir, sizeof(dir), "%s/d%u", base, (unsigned)dev) >= (int)sizeof(dir))
        return ESP_ERR_INVALID_ARG;
    if (mkdir(dir, 0775) != 0 && errno != EEXIST)
        return ESP_FAIL;
    size_t i = 0;
    esp_err_t rc = ESP_OK;
    while (i < n) {
        uint32_t day = gw_time_yyyymmdd(recs[i].ts_s);
        size_t j = i + 1;
        while (j < n && gw_time_yyyymmdd(recs[j].ts_s) == day)
            j++;
        esp_err_t r = append_day(base, dev, day, &recs[i], j - i);
        if (r != ESP_OK)
            rc = r;
        i = j;
    }
    return rc;
}

void hist_files_iter(void *base_arg, uint8_t dev, uint32_t from_s, uint32_t to_s, hist_rec_cb_t cb, void *cb_arg) {
    const char *base = base_arg;
    if (!base || !cb || to_s <= from_s)
        return;
    for (int64_t dayn = from_s / 86400; dayn * 86400 < (int64_t)to_s; dayn++) {
        uint32_t day = gw_time_yyyymmdd(dayn * 86400);
        char path[96];
        if (day_path(path, sizeof(path), base, dev, day) >= (int)sizeof(path))
            return;
        FILE *f = fopen(path, "rb");
        if (!f)
            continue;
        hist_file_hdr_t h;
        if (fread(&h, sizeof(h), 1, f) != 1 || !hdr_ok(&h, day, dev)) {
            fclose(f);
            continue;
        }
        hist_slow_t buf[CHUNK];
        size_t got;
        bool go = true;
        while (go && (got = fread(buf, sizeof(buf[0]), CHUNK, f)) > 0) {
            for (size_t i = 0; i < got; i++) {
                if (buf[i].ts_s < from_s || buf[i].ts_s >= to_s)
                    continue;
                if (!cb(cb_arg, &buf[i])) {
                    go = false;
                    break;
                }
            }
        }
        fclose(f);
        if (!go)
            return;
    }
}

int hist_files_retention(const char *base, uint8_t dev, uint32_t now_s, int *failed) {
    if (failed)
        *failed = 0;
    if (!base || now_s < HIST_RETENTION_DAYS * 86400u)
        return 0;
    uint32_t cutoff = gw_time_yyyymmdd((int64_t)now_s - (int64_t)HIST_RETENTION_DAYS * 86400);
    char dir[80];
    if (snprintf(dir, sizeof(dir), "%s/d%u", base, (unsigned)dev) >= (int)sizeof(dir))
        return 0;
    DIR *dp = opendir(dir);
    if (!dp)
        return 0;
    int removed = 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        const char *nm = de->d_name;
        if (strlen(nm) != 12 || (strcmp(nm + 8, ".bin") != 0 && strcmp(nm + 8, ".bad") != 0))
            continue;
        uint32_t day = 0;
        bool digits = true;
        for (int i = 0; i < 8; i++) {
            if (nm[i] < '0' || nm[i] > '9') {
                digits = false;
                break;
            }
            day = day * 10u + (uint32_t)(nm[i] - '0');
        }
        if (!digits || day >= cutoff)
            continue;
        char path[96];
        if (snprintf(path, sizeof(path), "%s/%s", dir, nm) >= (int)sizeof(path))
            continue;
        if (remove(path) == 0)
            removed++;
        else if (failed)
            (*failed)++; /* e.g. EBUSY: the file is open in a query; the caller retries later */
    }
    closedir(dp);
    return removed;
}
