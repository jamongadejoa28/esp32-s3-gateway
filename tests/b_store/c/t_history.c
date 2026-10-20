/* t_history.c - store/history_core.c: aggregation, ring wrap, span/range queries with decimation and
 * gaps, stage seconds, row iteration, daily files (append/iter/torn tail/retention), boot reload. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bt.h"
#include "gw_core/gw_time.h"
#include "hist_core.h"

#define W0 1792371600u /* a valid wall second (2026-10-18T01:00:00Z) */
static char g_base[512];
static int g_locks, g_unlocks, g_file_calls;

static void lk(void *a) {
    (void)a;
    CHECK_EQ(g_locks, g_unlocks); /* never nested */
    g_locks++;
}
static void ulk(void *a) {
    (void)a;
    g_unlocks++;
}
static void files_counting(void *arg, uint8_t dev, uint32_t from, uint32_t to, hist_rec_cb_t cb,
                           void *cb_arg) {
    g_file_calls++;
    hist_files_iter(arg, dev, from, to, cb, cb_arg);
}

static hist_env_t g_env = {lk, ulk, NULL, files_counting, g_base, NULL, NULL};

/* ---- deterministic signal ---- */
static int16_t temp_of(uint64_t k) {
    return (int16_t)(200 + (int)(k % 10) - (int)(k % 4));
}
static int16_t hum_of(uint64_t k) {
    return (int16_t)(400 + (int)(k % 7));
}
static uint32_t coils_of(uint64_t k) {
    uint32_t c = 0;
    if (k % 2 == 0)
        c |= 1u << 0; /* blower */
    if (k % 3 == 0)
        c |= 1u << 1; /* cool1 */
    if (k % 5 == 0)
        c |= 1u << 14; /* dehumidifying */
    if (k % 11 == 0)
        c |= 1u << 22; /* coil 23 leak alarm */
    return c;
}
static bool gap_of(uint64_t k, int gap_mod) {
    return gap_mod && (k % (uint64_t)gap_mod) == (uint64_t)gap_mod - 1;
}

static void make_sample(uint64_t k, uint32_t ts, int gap_mod, hist_fast_t *f) {
    mex_snapshot_t s;
    memset(&s, 0, sizeof(s));
    s.online = true;
    s.measurement_valid = true;
    s.mono_ms = 1;
    s.regs[36] = (uint16_t)temp_of(k);
    s.regs[37] = (uint16_t)hum_of(k);
    s.regs[11] = 42;
    s.regs[12] = 230;
    s.regs[13] = 500;
    s.regs[5] = 1;
    s.coils = coils_of(k);
    hist_fast_from_snapshot(&s, !gap_of(k, gap_mod), false, ts, f);
}

static hist_fast_t *g_fast;
static hist_slow_t *g_slow;
static hist_dev_t g_dev;

/* feed n ticks starting at sample index k0; ts = wall (W0 + k) or uptime-flagged; mono = 1000*(k+1) */
static void feed(hist_dev_t *d, uint64_t k0, uint64_t n, bool wall, int gap_mod) {
    for (uint64_t k = k0; k < k0 + n; k++) {
        hist_fast_t f;
        uint32_t ts = wall ? (uint32_t)(W0 + k) : (uint32_t)(k | HIST_TS_UPTIME);
        make_sample(k, ts, gap_mod, &f);
        hist_dev_sample(d, &f, 1000u * (k + 1));
    }
}

static void fresh_dev(void) {
    hist_dev_init(&g_dev, g_fast, g_slow);
}

/* ---- series buffers ---- */
static int16_t A[HIST_CH_COUNT][HIST_MAX_POINTS], MN[3][HIST_MAX_POINTS], MX[3][HIST_MAX_POINTS];
static uint16_t ST[HIST_STG_COUNT][HIST_MAX_POINTS];

static void series(hist_series_t *io, uint32_t n_max, bool minmax, bool stages) {
    memset(io, 0, sizeof(*io));
    io->n_max = n_max;
    for (int c = 0; c < HIST_CH_COUNT; c++)
        io->avg[c] = A[c];
    for (int c = 0; c < 3 && minmax; c++) {
        io->min[c] = MN[c];
        io->max[c] = MX[c];
    }
    for (int s = 0; s < HIST_STG_COUNT && stages; s++)
        io->stage[s] = ST[s];
}

static int64_t avg_round(int64_t sum, int64_t n) {
    return sum >= 0 ? (sum + n / 2) / n : -((-sum + n / 2) / n);
}

/* ------------------------------------------------------------------ pure helpers */

static void test_acc_and_snapshot(void) {
    hist_acc_t a;
    hist_acc_reset(&a, 123);
    hist_slow_t r;
    hist_acc_finish(&a, &r);
    CHECK_EQ(r.ts_s, 123);
    CHECK_EQ(r.samples, 0);
    CHECK_EQ(r.tavg, HIST_GAP);
    CHECK_EQ(r.tmin, HIST_GAP);
    CHECK_EQ(r.st, HIST_GAP);
    /* rounding half away from zero, negative temperatures */
    const int16_t temps[] = {-3, -2}; /* avg -2.5 -> -3 */
    for (int i = 0; i < 2; i++) {
        hist_fast_t f;
        memset(&f, 0, sizeof(f));
        f.temp = temps[i];
        f.hum = (int16_t)(500 + i); /* 500.5 -> 501 */
        f.cur = 10;
        f.st = (int16_t)(100 + i);
        f.sh = 5;
        f.coils =
            (i ? (1u << 0) | (1u << 3) | (1u << 7) : (1u << 14)) | (1u << 29); /* bit 14 = coil 15 dehum */
        f.flags = i ? HIST_F_RUNNING : HIST_F_ALARM;
        hist_acc_add(&a, &f);
    }
    hist_fast_t g;
    memset(&g, 0, sizeof(g));
    g.flags = HIST_F_GAP;
    g.temp = 999; /* ignored */
    hist_acc_add(&a, &g);
    hist_acc_finish(&a, &r);
    CHECK_EQ(r.samples, 2);
    CHECK_EQ(r.tavg, -3);
    CHECK_EQ(r.tmin, -3);
    CHECK_EQ(r.tmax, -2);
    CHECK_EQ(r.havg, 501);
    CHECK_EQ(r.st, 101); /* last valid */
    CHECK_EQ(r.flags, HIST_F_RUNNING | HIST_F_ALARM | HIST_F_GAP);
    CHECK_EQ(r.stage_on_s[HIST_STG_BLOWER], 1);
    CHECK_EQ(r.stage_on_s[HIST_STG_HEAT], 1);
    CHECK_EQ(r.stage_on_s[HIST_STG_HUM], 1);
    CHECK_EQ(r.stage_on_s[HIST_STG_DEHUM], 1);
    CHECK_EQ(r.stage_on_s[HIST_STG_COOL], 0);
    CHECK_EQ(r.alarm_mask, 1u << 13); /* coil 30 -> bit 13 */

    /* snapshot -> fast sample */
    mex_snapshot_t s;
    memset(&s, 0, sizeof(s));
    s.online = true;
    s.regs[36] = 0xFFF6; /* -1.0 C, signed */
    s.measurement_valid = true;
    s.regs[37] = 480;
    s.regs[11] = 42;
    s.regs[12] = 230;
    s.regs[13] = 500;
    s.regs[5] = 0x0A00; /* delay running but unit stopped */
    s.coils = 0x00410001;
    hist_fast_t f;
    hist_fast_from_snapshot(&s, true, true, 77, &f);
    CHECK_EQ(f.ts_s, 77);
    CHECK_EQ(f.temp, -10);
    CHECK_EQ(f.hum, 480);
    CHECK_EQ(f.cur, 42);
    CHECK_EQ(f.st, 230);
    CHECK_EQ(f.sh, 500);
    CHECK_EQ(f.coils, 0x00410001u);
    CHECK_EQ(f.flags, HIST_F_ALARM);
    s.regs[5] = 0x0001;
    hist_fast_from_snapshot(&s, true, false, 77, &f);
    CHECK_EQ(f.flags, HIST_F_RUNNING);
    hist_fast_from_snapshot(&s, false, true, 78, &f);
    CHECK_EQ(f.flags, HIST_F_GAP | HIST_F_ALARM);
    CHECK_EQ(f.temp, HIST_GAP);
    CHECK_EQ(f.coils, 0);
    s.online = false;
    hist_fast_from_snapshot(&s, true, false, 79, &f);
    CHECK_EQ(f.flags, HIST_F_GAP);
    s.online = true;
    s.measurement_valid = false;
    s.regs[36] = s.regs[37] = 0;
    hist_fast_from_snapshot(&s, true, false, 79, &f);
    CHECK_EQ(f.temp, HIST_GAP); /* a complete poll with startup 0/0 must not pollute history */
    CHECK_EQ(f.hum, HIST_GAP);
    CHECK_EQ(f.flags, HIST_F_GAP);
    s.measurement_valid = true;
    hist_fast_from_snapshot(&s, true, false, 79, &f);
    CHECK_EQ(f.temp, 0); /* once confirmed, a real zero pair is retained */
    CHECK_EQ(f.hum, 0);
    hist_fast_from_snapshot(NULL, true, false, 80, &f);
    CHECK_EQ(f.flags, HIST_F_GAP);
    CHECK_EQ(f.ts_s, 80);

    CHECK(hist_ts_wall(W0));
    CHECK(!hist_ts_wall(5 | HIST_TS_UPTIME));
    CHECK(!hist_ts_wall(1000)); /* before 2024 */
}

static void test_pick_res(void) {
    static const struct {
        uint32_t span, req, want;
    } c[] = {
        {900, 1, 1},      {1500, 1, 1},        {1501, 1, 5},          {3600, 1, 5},     {3600, 0, 5},
        {3600, 7, 10},    {3600, 30, 30},      {3601, 1, 60},         {86400, 1, 60},   {86400, 60, 60},
        {172800, 1, 300}, {7 * 86400, 1, 600}, {30 * 86400, 1, 1800}, {60, 7200, 7200}, {60, 9000, 7200},
        {0, 1, 1},        {3600, 61, 300},
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        uint32_t got = hist_pick_res(c[i].span, c[i].req);
        if (got != c[i].want)
            fprintf(stderr, "pick_res(%u,%u)=%u want %u\n", c[i].span, c[i].req, got, c[i].want);
        CHECK_EQ(got, c[i].want);
    }
    CHECK_EQ(hist_pick_res_limit(3600, 1, 100), 60);
    CHECK_EQ(hist_pick_res_limit(600, 1, 100), 10);
    for (uint32_t span = 1; span <= 30u * 86400u; span = span * 3 + 7) {
        uint32_t dt = hist_pick_res(span, 1);
        CHECK((span + dt - 1) / dt <= HIST_MAX_POINTS);
        CHECK(dt >= 60 || span <= HIST_FAST_LEN);
    }
}

/* ------------------------------------------------------------------ rings */

static void test_ring_and_pending(void) {
    fresh_dev();
    feed(&g_dev, 0, 3600 + 125, true, 0);
    CHECK_EQ(gw_ring_count(&g_dev.fast), HIST_FAST_LEN);
    CHECK_EQ(g_dev.fast_total, 3725);
    CHECK_EQ(g_dev.slow_total, 62);
    CHECK_EQ(g_dev.acc_ticks, 5);
    const hist_fast_t *newest = gw_ring_newest(&g_dev.fast, 0);
    CHECK_EQ(newest->ts_s, W0 + 3724);
    CHECK_EQ(newest->temp, temp_of(3724));
    const hist_fast_t *oldest = gw_ring_at(&g_dev.fast, 0);
    CHECK_EQ(oldest->ts_s, W0 + 125);
    /* minute 61: samples 3660..3719 */
    const hist_slow_t *m = gw_ring_newest(&g_dev.slow, 0);
    CHECK_EQ(m->ts_s, W0 + 3660);
    CHECK_EQ(m->samples, 60);
    int64_t sum = 0;
    int16_t mn = INT16_MAX, mx = INT16_MIN;
    for (uint64_t k = 3660; k < 3720; k++) {
        sum += temp_of(k);
        if (temp_of(k) < mn)
            mn = temp_of(k);
        if (temp_of(k) > mx)
            mx = temp_of(k);
    }
    CHECK_EQ(m->tavg, avg_round(sum, 60));
    CHECK_EQ(m->tmin, mn);
    CHECK_EQ(m->tmax, mx);
    CHECK_EQ(m->stage_on_s[HIST_STG_BLOWER], 30);
    CHECK_EQ(m->stage_on_s[HIST_STG_COOL], 20);
    CHECK_EQ(m->stage_on_s[HIST_STG_DEHUM], 12);
    CHECK(m->alarm_mask & (1u << 6));
    /* every finished wall minute is pending (60 max: 62 minutes -> 2 dropped) */
    CHECK_EQ(g_dev.n_pend, HIST_PEND_MAX);
    CHECK_EQ(g_dev.pend_dropped, 2);
    hist_slow_t buf[HIST_PEND_MAX];
    size_t n = hist_dev_take_pending(&g_dev, buf, 10);
    CHECK_EQ(n, 10);
    CHECK_EQ(buf[0].ts_s, W0 + 2 * 60);
    CHECK_EQ(g_dev.n_pend, 50);
    hist_dev_unget_pending(&g_dev, buf, 10);
    CHECK_EQ(g_dev.n_pend, 60);
    CHECK_EQ(g_dev.pend[0].ts_s, W0 + 120);
    hist_dev_unget_pending(&g_dev, buf, 3); /* no room: dropped */
    CHECK_EQ(g_dev.n_pend, 60);
    CHECK_EQ(g_dev.pend_dropped, 5);
    CHECK_EQ(hist_dev_take_pending(&g_dev, buf, HIST_PEND_MAX), 60);
    CHECK_EQ(hist_dev_take_pending(&g_dev, buf, HIST_PEND_MAX), 0);

    /* uptime-stamped minutes and empty minutes are not queued for files */
    fresh_dev();
    feed(&g_dev, 0, 120, false, 0);
    CHECK_EQ(g_dev.n_pend, 0);
    CHECK_EQ(g_dev.slow_total, 2);
    fresh_dev();
    feed(&g_dev, 0, 60, true, 1); /* every sample a gap */
    CHECK_EQ(g_dev.slow_total, 1);
    CHECK_EQ(g_dev.n_pend, 0);
    const hist_slow_t *gm = gw_ring_newest(&g_dev.slow, 0);
    CHECK_EQ(gm->samples, 0);
    CHECK_EQ(gm->tavg, HIST_GAP);
    CHECK(gm->flags & HIST_F_GAP);
    /* flush signal every HIST_FLUSH_BATCH queued minutes */
    fresh_dev();
    int signals = 0;
    for (uint64_t k = 0; k < 60u * 25u; k++) {
        hist_fast_t f;
        make_sample(k, (uint32_t)(W0 + k), 0, &f);
        signals += hist_dev_sample(&g_dev, &f, 1000u * (k + 1));
    }
    CHECK_EQ(signals, 2);
    hist_dev_clear(&g_dev);
    CHECK_EQ(gw_ring_count(&g_dev.fast), 0);
    CHECK_EQ(g_dev.n_pend, 0);
    CHECK_EQ(g_dev.fast_total, 1500); /* absolute counters keep running */
}

/* ------------------------------------------------------------------ span queries */

static void test_span_fast(void) {
    fresh_dev();
    feed(&g_dev, 0, 500, false, 13); /* wall invalid; every 13th sample a gap */
    hist_series_t io;
    series(&io, HIST_MAX_POINTS, true, true);
    uint64_t now = 1000u * 500 + 250; /* 250 ms after the newest sample */
    g_locks = g_unlocks = 0;
    CHECK_EQ(hist_core_span(&g_dev, 0, 20, 1, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(g_locks, g_unlocks);
    CHECK(g_locks >= 2);
    CHECK_EQ(io.dt_s, 1);
    CHECK_EQ(io.n, 20);
    CHECK_EQ(io.t0_ms, 0); /* wall invalid */
    CHECK_EQ(io.t0_age_ms, 250 + 19 * 1000);
    for (uint32_t b = 0; b < 20; b++) {
        uint64_t k = 480 + b;
        if (gap_of(k, 13)) {
            CHECK_EQ(A[HIST_CH_TEMP][b], HIST_GAP);
            CHECK_EQ(A[HIST_CH_ST][b], HIST_GAP);
            CHECK_EQ(ST[HIST_STG_BLOWER][b], HIST_STAGE_GAP);
        } else {
            CHECK_EQ(A[HIST_CH_TEMP][b], temp_of(k));
            CHECK_EQ(MN[0][b], temp_of(k));
            CHECK_EQ(MX[0][b], temp_of(k));
            CHECK_EQ(A[HIST_CH_HUM][b], hum_of(k));
            CHECK_EQ(A[HIST_CH_CUR][b], 42);
            CHECK_EQ(A[HIST_CH_ST][b], 230);
            CHECK_EQ(A[HIST_CH_SH][b], 500);
            CHECK_EQ(ST[HIST_STG_BLOWER][b], k % 2 == 0);
            CHECK_EQ(ST[HIST_STG_COOL][b], k % 3 == 0);
        }
    }
    /* wall valid now: t0 = now_wall - t0_age */
    CHECK_EQ(hist_core_span(&g_dev, 0, 20, 1, now, 2000000000000LL, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.t0_ms, 2000000000000LL - (int64_t)io.t0_age_ms);

    /* 5 s buckets: avg/min/max over valid samples, stage seconds summed */
    series(&io, HIST_MAX_POINTS, true, true);
    CHECK_EQ(hist_core_span(&g_dev, 0, 100, 5, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 5);
    CHECK_EQ(io.n, 20);
    CHECK_EQ(io.t0_age_ms, 250 + 99 * 1000);
    for (uint32_t b = 0; b < 20; b++) {
        int64_t sum = 0, n = 0, blower = 0;
        int16_t mn = INT16_MAX, mx = INT16_MIN;
        for (uint64_t k = 400 + 5 * b; k < 405 + 5 * b; k++) {
            if (gap_of(k, 13))
                continue;
            sum += temp_of(k);
            n++;
            blower += k % 2 == 0;
            mn = temp_of(k) < mn ? temp_of(k) : mn;
            mx = temp_of(k) > mx ? temp_of(k) : mx;
        }
        CHECK_EQ(A[HIST_CH_TEMP][b], avg_round(sum, n));
        CHECK_EQ(MN[0][b], mn);
        CHECK_EQ(MX[0][b], mx);
        CHECK_EQ(ST[HIST_STG_BLOWER][b], blower);
    }
    /* span longer than the data: leading gaps */
    series(&io, HIST_MAX_POINTS, false, false);
    CHECK_EQ(hist_core_span(&g_dev, 0, 600, 1, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 1);
    CHECK_EQ(io.n, 600);
    for (uint32_t b = 0; b < 100; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], HIST_GAP);
    CHECK_EQ(A[HIST_CH_TEMP][599], temp_of(499));
    /* capacity limit: n_max 50 forces coarser buckets */
    series(&io, 50, false, false);
    CHECK_EQ(hist_core_span(&g_dev, 0, 300, 1, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 10);
    CHECK_EQ(io.n, 30);
    /* argument errors */
    CHECK_EQ(hist_core_span(&g_dev, 0, 0, 1, now, 0, &g_env, &io, NULL, NULL), ESP_ERR_INVALID_ARG);
    CHECK_EQ(hist_core_span(&g_dev, 0, HIST_SPAN_MAX_S + 1, 1, now, 0, &g_env, &io, NULL, NULL),
             ESP_ERR_INVALID_ARG);
    io.avg[HIST_CH_SH] = NULL;
    CHECK_EQ(hist_core_span(&g_dev, 0, 10, 1, now, 0, &g_env, &io, NULL, NULL), ESP_ERR_INVALID_ARG);
    CHECK_EQ(hist_core_span(&g_dev, 0, 10, 1, now, 0, &g_env, NULL, NULL, NULL), ESP_ERR_INVALID_ARG);
    /* empty device: all gaps, anchored on now */
    fresh_dev();
    series(&io, HIST_MAX_POINTS, false, false);
    CHECK_EQ(hist_core_span(&g_dev, 0, 10, 1, 5000, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.t0_age_ms, 9000);
    for (int b = 0; b < 10; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], HIST_GAP);
}

static void test_span_minutes(void) {
    fresh_dev();
    feed(&g_dev, 0, 60 * 10 + 17, false, 0); /* 10 whole minutes + 17 ticks */
    hist_series_t io;
    series(&io, HIST_MAX_POINTS, true, true);
    uint64_t now = 1000u * (617) + 400;
    CHECK_EQ(hist_core_span(&g_dev, 0, 300, 60, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 60);
    CHECK_EQ(io.n, 5);
    /* newest bucket = in-progress minute (17 samples, started at tick 600) */
    CHECK_EQ(io.t0_age_ms, (now - 601000u) + 4u * 60000u);
    for (uint32_t b = 0; b < 5; b++) {
        uint64_t first = 600 - 60u * (4 - b), last = b == 4 ? 617 : first + 60;
        int64_t sum = 0, n = 0, cool = 0;
        for (uint64_t k = first; k < last; k++) {
            sum += hum_of(k);
            n++;
            cool += k % 3 == 0;
        }
        CHECK_EQ(A[HIST_CH_HUM][b], avg_round(sum, n));
        CHECK_EQ(ST[HIST_STG_COOL][b], cool);
    }
    /* 300 s buckets: 5 slots each; data only for the newest 11 slots */
    series(&io, HIST_MAX_POINTS, false, true);
    CHECK_EQ(hist_core_span(&g_dev, 0, 3600 * 2, 300, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 300);
    CHECK_EQ(io.n, 24);
    for (uint32_t b = 0; b < 21; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], HIST_GAP);
    /* bucket avg = sample-weighted mean of the per-minute (rounded) averages */
    int64_t wsum = 0, sum = 0;
    for (uint64_t m0 = 360; m0 < 617; m0 += 60) {
        uint64_t m1 = m0 + 60 < 617 ? m0 + 60 : 617;
        int64_t ms = 0;
        for (uint64_t k = m0; k < m1; k++)
            ms += temp_of(k);
        wsum += avg_round(ms, (int64_t)(m1 - m0)) * (int64_t)(m1 - m0);
    }
    CHECK_EQ(A[HIST_CH_TEMP][23], avg_round(wsum, 617 - 360));
    CHECK_EQ(ST[HIST_STG_BLOWER][23], (617 - 360 + 1) / 2);
    /* exactly at a minute boundary: no in-progress slot */
    fresh_dev();
    feed(&g_dev, 0, 120, false, 0);
    series(&io, HIST_MAX_POINTS, false, false);
    CHECK_EQ(hist_core_span(&g_dev, 0, 120, 60, 120000, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.n, 2);
    CHECK_EQ(io.t0_age_ms, (120000u - 61000u) + 60000u);
    sum = 0;
    for (uint64_t k = 0; k < 60; k++)
        sum += temp_of(k);
    CHECK_EQ(A[HIST_CH_TEMP][0], avg_round(sum, 60));
}

/* ------------------------------------------------------------------ files */

static void make_minute(uint32_t ts, int16_t t, hist_slow_t *r) {
    memset(r, 0, sizeof(*r));
    r->ts_s = ts;
    r->tmin = (int16_t)(t - 1);
    r->tavg = t;
    r->tmax = (int16_t)(t + 1);
    r->hmin = r->havg = r->hmax = 500;
    r->cmin = r->cavg = r->cmax = 10;
    r->st = 230;
    r->sh = 500;
    r->samples = 60;
    r->stage_on_s[HIST_STG_BLOWER] = 60;
}

static char g_path[700];
static const char *day_file(uint8_t dev, uint32_t ts) {
    snprintf(g_path, sizeof(g_path), "%s/d%u/%08u.bin", g_base, (unsigned)dev,
             (unsigned)gw_time_yyyymmdd(ts));
    return g_path;
}

static long fsize(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

typedef struct {
    uint32_t n;
    uint32_t last_ts;
    bool ordered;
    uint32_t stop_after;
} iter_ctx_t;

static bool iter_cb(void *a, const hist_slow_t *r) {
    iter_ctx_t *c = a;
    if (c->n && r->ts_s < c->last_ts)
        c->ordered = false;
    c->last_ts = r->ts_s;
    c->n++;
    return !(c->stop_after && c->n >= c->stop_after);
}

static void test_files(void) {
    /* 2 days of minutes around a midnight, appended in batches */
    uint32_t day0 = (W0 / 86400u) * 86400u; /* 2026-10-18 00:00:00Z */
    uint32_t start = day0 + 86400u - 30u * 60u;
    static hist_slow_t recs[120];
    for (int i = 0; i < 120; i++)
        make_minute(start + 60u * (uint32_t)i, (int16_t)(200 + i), &recs[i]);
    CHECK_EQ(hist_files_append(g_base, 2, recs, 50), ESP_OK);
    CHECK_EQ(hist_files_append(g_base, 2, recs + 50, 70), ESP_OK);
    CHECK_EQ(fsize(day_file(2, start)), 16 + 30 * 40);
    CHECK_EQ(fsize(day_file(2, start + 3600)), 16 + 90 * 40);
    iter_ctx_t c = {0, 0, true, 0};
    hist_files_iter(g_base, 2, start, start + 120 * 60, iter_cb, &c);
    CHECK_EQ(c.n, 120);
    CHECK(c.ordered);
    c = (iter_ctx_t){0, 0, true, 0};
    hist_files_iter(g_base, 2, start + 600, start + 1200, iter_cb, &c); /* [10, 20) minutes */
    CHECK_EQ(c.n, 10);
    c = (iter_ctx_t){0, 0, true, 7};
    hist_files_iter(g_base, 2, start, start + 120 * 60, iter_cb, &c); /* early stop */
    CHECK_EQ(c.n, 7);
    c = (iter_ctx_t){0, 0, true, 0};
    hist_files_iter(g_base, 3, start, start + 120 * 60, iter_cb, &c); /* other device: nothing */
    CHECK_EQ(c.n, 0);
    /* torn tail is cut on the next append */
    const char *p = day_file(2, start + 3600);
    FILE *f = fopen(p, "ab");
    fwrite("garbage", 1, 7, f);
    fclose(f);
    hist_slow_t extra;
    make_minute(start + 120 * 60, 999, &extra);
    CHECK_EQ(hist_files_append(g_base, 2, &extra, 1), ESP_OK);
    CHECK_EQ(fsize(p), 16 + 91 * 40);
    /* foreign header: the day starts over */
    f = fopen(day_file(2, start), "r+b");
    fwrite("XXXX", 1, 4, f);
    fclose(f);
    c = (iter_ctx_t){0, 0, true, 0};
    hist_files_iter(g_base, 2, start, start + 1800, iter_cb, &c);
    CHECK_EQ(c.n, 0); /* unreadable header -> skipped */
    long foreign_size = fsize(day_file(2, start));
    CHECK_EQ(hist_files_append(g_base, 2, recs, 1), ESP_OK);
    CHECK_EQ(fsize(day_file(2, start)), 16 + 40);
    {
        /* the foreign file was kept aside, not truncated */
        char bad[sizeof(g_path)];
        snprintf(bad, sizeof(bad), "%s", day_file(2, start));
        memcpy(bad + strlen(bad) - 4, ".bad", 4);
        CHECK_EQ(fsize(bad), foreign_size);
    }
    /* a transient read failure must not restart the day: unreadable (directory) path -> ESP_FAIL */
    {
        uint32_t tday = day0 + 5u * 86400u;
        const char *tp = day_file(2, tday);
        CHECK_EQ(mkdir(tp, 0755), 0);
        char inner[sizeof(g_path) + 8];
        snprintf(inner, sizeof(inner), "%s/x", tp);
        FILE *fx = fopen(inner, "wb");
        CHECK(fx != NULL);
        if (fx) {
            fwrite("0123456789abcdefghij", 1, 20, fx);
            fclose(fx);
        }
        hist_slow_t r1;
        make_minute(tday + 60u, 1, &r1);
        CHECK_EQ(hist_files_append(g_base, 2, &r1, 1), ESP_FAIL);
        CHECK(fsize(inner) == 20);
        remove(inner);
        rmdir(tp);
    }
    /* retention: keep 30 days */
    for (int d = 0; d < 35; d++) {
        hist_slow_t r;
        make_minute(day0 - (uint32_t)d * 86400u + 3600u, 1, &r);
        CHECK_EQ(hist_files_append(g_base, 1, &r, 1), ESP_OK);
    }
    /* an undeletable expired file (here: a non-empty directory; on the device EBUSY) is reported */
    char stuck[sizeof(g_path)], stuck_in[sizeof(g_path) + 8];
    snprintf(stuck, sizeof(stuck), "%s", day_file(1, day0 - 40u * 86400u));
    CHECK_EQ(mkdir(stuck, 0755), 0);
    snprintf(stuck_in, sizeof(stuck_in), "%s/x", stuck);
    FILE *fs = fopen(stuck_in, "wb");
    if (fs)
        fclose(fs);
    /* an old set-aside .bad file expires like the day it belonged to */
    char oldbad[sizeof(g_path)];
    snprintf(oldbad, sizeof(oldbad), "%s", day_file(1, day0 - 33u * 86400u));
    memcpy(oldbad + strlen(oldbad) - 4, ".bad", 4);
    FILE *fb = fopen(oldbad, "wb");
    if (fb)
        fclose(fb);
    int failed = -1;
    int removed = hist_files_retention(g_base, 1, day0 + 3600, &failed);
    CHECK_EQ(removed, 5); /* days -31..-34 and the .bad of day -33 */
    CHECK_EQ(failed, 1);
    CHECK(fsize(oldbad) < 0);
    CHECK(fsize(day_file(1, day0 - 30u * 86400u)) > 0);
    CHECK(fsize(day_file(1, day0 - 31u * 86400u)) < 0);
    remove(stuck_in);
    CHECK_EQ(hist_files_retention(g_base, 1, day0 + 3600, &failed), 1); /* retried: now gone */
    CHECK_EQ(failed, 0);
    CHECK_EQ(hist_files_retention(g_base, 1, day0 + 3600, NULL), 0);
    CHECK_EQ(hist_files_retention(g_base, 7, day0, &failed), 0); /* missing dir */
    CHECK_EQ(failed, 0);
}

/* ------------------------------------------------------------------ range queries + reload */

typedef struct {
    uint32_t n, gaps;
    int64_t first_ts, last_ts;
    uint32_t max_samples;
    uint32_t stop_at;
} rows_t;

static bool row_cb(void *a, int64_t ts_ms, const hist_slow_t *r) {
    rows_t *c = a;
    if (c->n == 0)
        c->first_ts = ts_ms;
    c->last_ts = ts_ms;
    c->n++;
    if (r->samples == 0)
        c->gaps++;
    if (r->samples > c->max_samples)
        c->max_samples = r->samples;
    if (r->samples) {
        CHECK(r->tmin <= r->tavg && r->tavg <= r->tmax);
    }
    return !(c->stop_at && c->n >= c->stop_at);
}

static void test_range_and_reload(void) {
    /* RAM: 2 h of wall-stamped samples starting at W0 (k = 0..7199); files: the same minutes
     * (as the writer would have produced them) plus 3 days of older minutes. */
    fresh_dev();
    feed(&g_dev, 0, 7200, true, 0);
    static hist_slow_t pend[HIST_PEND_MAX];
    size_t n = hist_dev_take_pending(&g_dev, pend, HIST_PEND_MAX);
    CHECK_EQ(n, 60); /* the newest hour */
    CHECK_EQ(hist_files_append(g_base, 0, pend, n), ESP_OK);
    static hist_slow_t old[3 * 1440];
    for (uint32_t i = 0; i < 3 * 1440; i++)
        make_minute(W0 - 3u * 86400u + 60u * i, (int16_t)(100 + (int)(i % 50)), &old[i]);
    CHECK_EQ(hist_files_append(g_base, 0, old, 3 * 1440), ESP_OK);

    int64_t now_wall = (int64_t)(W0 + 7200) * 1000 + 300;
    hist_series_t io;
    /* fast absolute query inside the last hour */
    series(&io, HIST_MAX_POINTS, true, false);
    int64_t from = (int64_t)(W0 + 7000) * 1000;
    CHECK_EQ(hist_core_range(&g_dev, 0, from, from + 100000, 1, now_wall, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 1);
    CHECK_EQ(io.n, 100);
    CHECK_EQ(io.t0_ms, from);
    CHECK_EQ(io.t0_age_ms, now_wall - from);
    for (uint32_t b = 0; b < 100; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], temp_of(7000 + b));
    /* future part of a range is gaps */
    CHECK_EQ(hist_core_range(&g_dev, 0, from + 190000, from + 210000, 1, now_wall, &g_env, &io, NULL, NULL),
             ESP_OK);
    CHECK_EQ(A[HIST_CH_TEMP][0], temp_of(7190));
    CHECK_EQ(A[HIST_CH_TEMP][15], HIST_GAP);
    /* an old range cannot use 1 s data: minimum 60 s */
    from = (int64_t)(W0 - 86400) * 1000;
    series(&io, HIST_MAX_POINTS, true, true);
    g_file_calls = 0;
    CHECK_EQ(hist_core_range(&g_dev, 0, from, from + 600000, 1, now_wall, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 60);
    CHECK_EQ(io.n, 10);
    CHECK(g_file_calls == 1);
    for (uint32_t b = 0; b < 10; b++) {
        uint32_t i = 2 * 1440 + b; /* index into old[] */
        CHECK_EQ(A[HIST_CH_TEMP][b], old[i].tavg);
        CHECK_EQ(MN[0][b], old[i].tmin);
        CHECK_EQ(ST[HIST_STG_BLOWER][b], 60);
    }
    /* range across files and RAM without double counting (30 min buckets) */
    from = (int64_t)(W0 - 3600) * 1000;
    int64_t to = (int64_t)(W0 + 7200) * 1000;
    rows_t rc = {0};
    CHECK_EQ(hist_core_range(&g_dev, 0, from, to, 1800, now_wall, &g_env, NULL, row_cb, &rc), ESP_OK);
    CHECK_EQ(rc.n, 6);
    CHECK_EQ(rc.first_ts, from);
    CHECK_EQ(rc.max_samples, 255); /* 1800 samples clamp in the row type */
    series(&io, HIST_MAX_POINTS, false, true);
    CHECK_EQ(hist_core_range(&g_dev, 0, from, to, 1800, now_wall, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 1800);
    CHECK_EQ(ST[HIST_STG_BLOWER][0], 1800); /* file minutes: 30 x 60 s */
    CHECK_EQ(ST[HIST_STG_BLOWER][2], 900);  /* RAM: every 2nd second */
    CHECK_EQ(ST[HIST_STG_BLOWER][5], 900);  /* overlap file+RAM counted once */
    /* row iteration stops on request */
    rc = (rows_t){0};
    rc.stop_at = 2;
    CHECK_EQ(hist_core_range(&g_dev, 0, from, to, 60, now_wall, &g_env, NULL, row_cb, &rc), ESP_OK);
    CHECK_EQ(rc.n, 2);
    /* 1 s rows (CSV of the last minutes) */
    rc = (rows_t){0};
    from = (int64_t)(W0 + 7100) * 1000;
    CHECK_EQ(hist_core_range(&g_dev, 0, from, from + 60000, 1, now_wall, &g_env, NULL, row_cb, &rc), ESP_OK);
    CHECK_EQ(rc.n, 60);
    CHECK_EQ(rc.gaps, 0);
    CHECK_EQ(rc.last_ts, from + 59000);
    /* relative query older than the rings reads the files (needs wall time) */
    series(&io, HIST_MAX_POINTS, false, false);
    g_file_calls = 0;
    CHECK_EQ(hist_core_span(&g_dev, 0, 3 * 86400, 1, 7200000 + 300, now_wall, &g_env, &io, NULL, NULL),
             ESP_OK);
    CHECK_EQ(io.dt_s, 300);
    CHECK_EQ(g_file_calls, 1);
    uint32_t gaps = 0;
    for (uint32_t b = 0; b < io.n; b++)
        gaps += A[HIST_CH_TEMP][b] == HIST_GAP;
    CHECK(gaps <= 2); /* files cover everything older than the RAM */
    /* ...and without wall time those slots are gaps */
    g_file_calls = 0;
    CHECK_EQ(hist_core_span(&g_dev, 0, 3 * 86400, 1, 7200000 + 300, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(g_file_calls, 0);
    CHECK_EQ(A[HIST_CH_TEMP][0], HIST_GAP);
    /* errors */
    CHECK_EQ(hist_core_range(&g_dev, 0, from, from, 1, now_wall, &g_env, &io, NULL, NULL),
             ESP_ERR_INVALID_ARG);
    CHECK_EQ(hist_core_range(&g_dev, 0, from, from + 1000, 1, 0, &g_env, &io, NULL, NULL),
             ESP_ERR_INVALID_STATE);
    CHECK_EQ(hist_core_range(&g_dev, 0, -5, 1000, 1, now_wall, &g_env, &io, NULL, NULL), ESP_ERR_INVALID_ARG);
    CHECK_EQ(hist_core_range(&g_dev, 0, 0, (int64_t)(HIST_SPAN_MAX_S + 1) * 1000, 60, now_wall, &g_env, &io,
                             NULL, NULL),
             ESP_ERR_INVALID_ARG);
    /* a start older than the retention (?from=1&to=2) is refused; exactly the retention is fine */
    CHECK_EQ(hist_core_range(&g_dev, 0, 1000, 2000, 1, now_wall, &g_env, &io, NULL, NULL),
             ESP_ERR_INVALID_ARG);
    {
        const int64_t oldest = now_wall - (int64_t)HIST_RETENTION_DAYS * 86400 * 1000;
        CHECK_EQ(hist_core_range(&g_dev, 0, oldest - 1000, oldest + 3600000, 60, now_wall, &g_env, &io, NULL,
                                 NULL),
                 ESP_ERR_INVALID_ARG);
        CHECK_EQ(hist_core_range(&g_dev, 0, oldest, oldest + 3600000, 60, now_wall, &g_env, &io, NULL, NULL),
                 ESP_OK);
        CHECK(io.t0_age_ms < (uint64_t)HIST_RETENTION_DAYS * 86400 * 1000 + 1000); /* from floored to 1 s */
    }

    /* boot reload: the last 24 h from files, positions = minutes before now */
    hist_dev_t d2;
    static hist_fast_t f2[HIST_FAST_LEN];
    static hist_slow_t s2[HIST_SLOW_LEN];
    hist_dev_init(&d2, f2, s2);
    uint32_t now_s = W0 + 7200 + 600; /* rebooted 10 minutes after the last file record */
    hist_dev_reload_begin(&d2, now_s);
    hist_files_iter(g_base, 0, now_s - 86400u, now_s, hist_dev_reload_add, &d2);
    hist_dev_reload_end(&d2);
    CHECK_EQ(gw_ring_count(&d2.slow), 1440);
    CHECK_EQ(d2.slow_total, 1440);
    const hist_slow_t *r0 = gw_ring_newest(&d2.slow, 0);
    CHECK_EQ(r0->samples, 0); /* the 10 minutes while off are gaps */
    CHECK_EQ(r0->ts_s, now_s - 60);
    int found = -1;
    for (uint32_t i = 0; i < 20; i++) {
        const hist_slow_t *r = gw_ring_newest(&d2.slow, i);
        if (r->samples) {
            found = (int)i;
            break;
        }
    }
    CHECK_EQ(found, 10);
    CHECK_EQ(((const hist_slow_t *)gw_ring_newest(&d2.slow, 10))->ts_s, W0 + 7140);
    CHECK_EQ(d2.n_pend, 0);
    /* a span query right after boot shows the reloaded data */
    series(&io, HIST_MAX_POINTS, false, false);
    CHECK_EQ(hist_core_span(&d2, 0, 1800, 60, 1000, (int64_t)now_s * 1000, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.n, 30);
    CHECK_EQ(A[HIST_CH_TEMP][29], HIST_GAP);
    CHECK(A[HIST_CH_TEMP][19] != HIST_GAP);
    /* no files at all: nothing pushed */
    hist_dev_init(&d2, f2, s2);
    hist_dev_reload_begin(&d2, now_s);
    hist_files_iter(g_base, 3, now_s - 86400u, now_s, hist_dev_reload_add, &d2);
    hist_dev_reload_end(&d2);
    CHECK_EQ(gw_ring_count(&d2.slow), 0);
}

/* ------------------------------------------------------------------ missed / bunched ticks */

static void const_sample(uint32_t ts, int16_t temp, hist_fast_t *f) {
    memset(f, 0, sizeof(*f));
    f->ts_s = ts;
    f->temp = temp;
    f->hum = 400;
    f->cur = 10;
    f->st = 230;
    f->sh = 500;
}

static void feed_const(uint64_t k0, uint64_t n, int16_t temp) {
    for (uint64_t k = k0; k < k0 + n; k++) {
        hist_fast_t f;
        const_sample((uint32_t)(W0 + k), temp, &f);
        hist_dev_sample(&g_dev, &f, 1000u * (k + 1));
    }
}

static void test_missed_ticks(void) {
    /* 300 s of 10.0, 600 s without any tick, 300 s of 20.0 */
    fresh_dev();
    feed_const(0, 300, 100);
    feed_const(900, 300, 200);
    CHECK_EQ(g_dev.gap_filled, 600);
    CHECK_EQ(g_dev.fast_total, 1200);
    CHECK_EQ(g_dev.slow_total, 20);
    hist_series_t io;
    series(&io, HIST_MAX_POINTS, false, false);
    uint64_t now = 1200u * 1000u + 250u;
    CHECK_EQ(hist_core_span(&g_dev, 5, 1200, 60, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.n, 20);
    for (uint32_t b = 0; b < 20 && io.n == 20; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], b < 5 ? 100 : b < 15 ? HIST_GAP : 200);
    /* the absolute query over the same window agrees */
    series(&io, HIST_MAX_POINTS, false, false);
    int64_t wall_now = (int64_t)(W0 + 1200u) * 1000 + 250;
    CHECK_EQ(hist_core_range(&g_dev, 5, (int64_t)W0 * 1000, (int64_t)(W0 + 1200u) * 1000, 60, wall_now,
                             &g_env, &io, NULL, NULL),
             ESP_OK);
    CHECK_EQ(io.n, 20);
    for (uint32_t b = 0; b < 20 && io.n == 20; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], b < 5 ? 100 : b < 15 ? HIST_GAP : 200);
    /* last 1 s samples: the 600 missed seconds are gaps */
    series(&io, HIST_MAX_POINTS, false, false);
    CHECK_EQ(hist_core_span(&g_dev, 5, 1200, 1, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.n, 1200);
    CHECK_EQ(A[HIST_CH_TEMP][299], 100);
    CHECK_EQ(A[HIST_CH_TEMP][300], HIST_GAP);
    CHECK_EQ(A[HIST_CH_TEMP][899], HIST_GAP);
    CHECK_EQ(A[HIST_CH_TEMP][900], 200);

    /* handler jitter (+-400 ms) neither adds gaps nor drops samples */
    fresh_dev();
    for (uint64_t k = 0; k < 600; k++) {
        hist_fast_t f;
        const_sample((uint32_t)(W0 + k), 150, &f);
        uint64_t jitter = k == 0 ? 400u : (k * 7919u) % 800u; /* -400..+399 ms around the first */
        hist_dev_sample(&g_dev, &f, 1000u * (k + 1) + jitter);
    }
    CHECK_EQ(g_dev.fast_total, 600);
    CHECK_EQ(g_dev.gap_filled, 0);
    CHECK_EQ(g_dev.dup_dropped, 0);

    /* a burst: ticks 600..602 queued and delivered together 2.9 s late -> 2 gaps + 1 sample, the
     * other two dropped; the following on-time tick lands in the next free slot */
    fresh_dev();
    feed_const(0, 600, 100);
    for (int i = 0; i < 3; i++) {
        hist_fast_t f;
        const_sample((uint32_t)(W0 + 600 + i), 300, &f);
        hist_dev_sample(&g_dev, &f, 603000u + 400u);
    }
    CHECK_EQ(g_dev.fast_total, 603);
    CHECK_EQ(g_dev.gap_filled, 2);
    CHECK_EQ(g_dev.dup_dropped, 2);
    hist_fast_t f;
    const_sample((uint32_t)(W0 + 603), 300, &f);
    hist_dev_sample(&g_dev, &f, 604000u);
    CHECK_EQ(g_dev.fast_total, 604);

    /* a very long stall (2 h): whole gap minutes go straight to the slow ring, ages stay right */
    fresh_dev();
    feed_const(0, 600, 100);
    feed_const(7800, 600, 200);
    CHECK_EQ(g_dev.gap_filled, 7200);
    CHECK_EQ(g_dev.slow_total, 140);
    CHECK(g_dev.fast_total < 600 + 600 + HIST_FAST_LEN + 60);
    series(&io, HIST_MAX_POINTS, false, false);
    now = 8400u * 1000u + 250u;
    CHECK_EQ(hist_core_span(&g_dev, 5, 8400, 600, now, 0, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.n, 14);
    for (uint32_t b = 0; b < 14 && io.n == 14; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], b == 0 ? 100 : b == 13 ? 200 : HIST_GAP);
    series(&io, HIST_MAX_POINTS, false, false);
    wall_now = (int64_t)(W0 + 8400u) * 1000 + 250;
    CHECK_EQ(hist_core_range(&g_dev, 5, (int64_t)W0 * 1000, (int64_t)(W0 + 8400u) * 1000, 600, wall_now,
                             &g_env, &io, NULL, NULL),
             ESP_OK);
    CHECK_EQ(io.n, 14);
    for (uint32_t b = 0; b < 14 && io.n == 14; b++)
        CHECK_EQ(A[HIST_CH_TEMP][b], b == 0 ? 100 : b == 13 ? 200 : HIST_GAP);
}

/* ------------------------------------------------------------------ 10-minute rollups */

static int g_coarse_calls;

/* Reference rollup provider: what the device cache serves, rebuilt from the files on every call. */
static void coarse_from_files(void *arg, uint8_t dev, uint32_t from, uint32_t to, hist_coarse_cb_t cb,
                              void *cb_arg) {
    g_coarse_calls++;
    CHECK_EQ(from % HIST_COARSE_S, 0);
    static hist_day_t d;
    for (uint32_t day = from / 86400u; (uint64_t)day * 86400u < to; day++) {
        hist_day_reset(&d, day);
        hist_files_iter(arg, dev, day * 86400u, day * 86400u + 86400u, hist_day_add_cb, &d);
        for (uint32_t i = 0; i < HIST_COARSE_PER_DAY; i++) {
            uint32_t st = day * 86400u + i * HIST_COARSE_S;
            if (st < from || st >= to || !d.c[i].minutes)
                continue;
            if (!cb(cb_arg, st, &d.c[i]))
                return;
        }
    }
}

static hist_env_t g_env_c = {lk, ulk, NULL, files_counting, g_base, coarse_from_files, g_base};

static int16_t RA[HIST_CH_COUNT][HIST_MAX_POINTS], RMN[3][HIST_MAX_POINTS], RMX[3][HIST_MAX_POINTS];
static uint16_t RST[HIST_STG_COUNT][HIST_MAX_POINTS];

static void keep_reference(uint32_t n) {
    for (uint32_t b = 0; b < n; b++) {
        for (int c = 0; c < HIST_CH_COUNT; c++)
            RA[c][b] = A[c][b];
        for (int c = 0; c < 3; c++) {
            RMN[c][b] = MN[c][b];
            RMX[c][b] = MX[c][b];
        }
        for (int k = 0; k < HIST_STG_COUNT; k++)
            RST[k][b] = ST[k][b];
    }
}

static void test_coarse(void) {
    /* rollup accumulation */
    static hist_day_t d;
    const uint32_t day0 = (W0 / 86400u) * 86400u;
    hist_day_reset(&d, day0 / 86400u);
    hist_slow_t r;
    make_minute(day0 + 600, 100, &r);
    hist_day_add(&d, &r);
    make_minute(day0 + 660, 110, &r);
    r.stage_on_s[HIST_STG_COOL] = 30;
    r.alarm_mask = 0x10004u;
    hist_day_add(&d, &r);
    make_minute(day0 + 720, 0, &r);
    r.samples = 0;
    r.flags = HIST_F_GAP;
    hist_day_add(&d, &r); /* gap minute: counted, flags only */
    make_minute(day0 - 60, 999, &r);
    hist_day_add(&d, &r); /* previous day: ignored */
    make_minute(600 | HIST_TS_UPTIME, 999, &r);
    hist_day_add(&d, &r); /* uptime-stamped: ignored */
    const hist_coarse_t *c = &d.c[1];
    CHECK_EQ(d.c[0].minutes, 0);
    CHECK_EQ(c->minutes, 3);
    CHECK_EQ(c->samples, 120);
    CHECK_EQ(c->wsum[0], 100 * 60 + 110 * 60);
    CHECK_EQ(c->mn[0], 99);
    CHECK_EQ(c->mx[0], 111);
    CHECK_EQ(c->stage[HIST_STG_BLOWER], 120);
    CHECK_EQ(c->stage[HIST_STG_COOL], 30);
    CHECK_EQ(c->alarm, 0x0004u);
    CHECK(c->flags & HIST_F_GAP);

    /* 8 days of minutes before W0 for device 3 (slowly rising: +1 per hour), 2 minutes in RAM */
    const uint32_t n_old = 8u * 1440u;
    static hist_slow_t old[8 * 1440];
    for (uint32_t i = 0; i < n_old; i++) {
        make_minute(W0 - 8u * 86400u + 60u * i, (int16_t)(100 + (int)(i / 60u)), &old[i]);
        old[i].stage_on_s[HIST_STG_HEAT] = (uint8_t)(i % 61u);
    }
    CHECK_EQ(hist_files_append(g_base, 3, old, n_old), ESP_OK);
    fresh_dev();
    feed(&g_dev, 0, 120, true, 0);
    const int64_t now_wall = (int64_t)(W0 + 120) * 1000 + 300;
    const uint64_t now_mono = 120000u + 300u;
    hist_series_t io;

    /* aligned absolute range, 30 min buckets: every rollup lies inside one bucket -> identical */
    const int64_t from = (int64_t)(((W0 - 5u * 86400u) / 600u) * 600u) * 1000;
    const int64_t to = from + 2 * 86400 * 1000;
    series(&io, HIST_MAX_POINTS, true, true);
    CHECK_EQ(hist_core_range(&g_dev, 3, from, to, 1800, now_wall, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 1800);
    const uint32_t nr = io.n;
    CHECK_EQ(nr, 96);
    keep_reference(nr);
    g_file_calls = g_coarse_calls = 0;
    series(&io, HIST_MAX_POINTS, true, true);
    CHECK_EQ(hist_core_range(&g_dev, 3, from, to, 1800, now_wall, &g_env_c, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(g_file_calls, 0);
    CHECK_EQ(g_coarse_calls, 1);
    CHECK_EQ(io.n, nr);
    for (uint32_t b = 0; b < nr; b++) {
        for (int ch = 0; ch < HIST_CH_COUNT; ch++)
            CHECK_EQ(A[ch][b], RA[ch][b]);
        for (int ch = 0; ch < 3; ch++) {
            CHECK_EQ(MN[ch][b], RMN[ch][b]);
            CHECK_EQ(MX[ch][b], RMX[ch][b]);
        }
        for (int k = 0; k < HIST_STG_COUNT; k++)
            CHECK_EQ(ST[k][b], RST[k][b]);
    }
    /* CSV rows: same buckets, same clamped counts */
    rows_t ra = {0}, rb = {0};
    CHECK_EQ(hist_core_range(&g_dev, 3, from, to, 1800, now_wall, &g_env, NULL, row_cb, &ra), ESP_OK);
    CHECK_EQ(hist_core_range(&g_dev, 3, from, to, 1800, now_wall, &g_env_c, NULL, row_cb, &rb), ESP_OK);
    CHECK_EQ(ra.n, rb.n);
    CHECK_EQ(ra.gaps, rb.gaps);
    CHECK_EQ(ra.max_samples, rb.max_samples);

    /* 7 day span (10 min buckets, not aligned to the rollups): rollups are split by minutes */
    series(&io, HIST_MAX_POINTS, true, true);
    CHECK_EQ(hist_core_span(&g_dev, 3, 7 * 86400, 1, now_mono, now_wall, &g_env, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 600);
    const uint32_t ns = io.n;
    const int64_t t0 = io.t0_ms;
    keep_reference(ns);
    g_file_calls = g_coarse_calls = 0;
    series(&io, HIST_MAX_POINTS, true, true);
    CHECK_EQ(hist_core_span(&g_dev, 3, 7 * 86400, 1, now_mono, now_wall, &g_env_c, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(g_file_calls, 0);
    CHECK_EQ(g_coarse_calls, 1);
    CHECK_EQ(io.n, ns);
    CHECK_EQ(io.t0_ms, t0);
    uint32_t gaps_ref = 0, gaps = 0;
    for (uint32_t b = 0; b < ns; b++) {
        gaps_ref += RA[HIST_CH_TEMP][b] == HIST_GAP;
        gaps += A[HIST_CH_TEMP][b] == HIST_GAP;
        if (RA[HIST_CH_TEMP][b] == HIST_GAP || A[HIST_CH_TEMP][b] == HIST_GAP)
            continue;
        int dv = A[HIST_CH_TEMP][b] - RA[HIST_CH_TEMP][b];
        CHECK(dv >= -1 && dv <= 1); /* +1 per hour: a 10 min shift moves the average by < 1 */
        CHECK(MN[0][b] <= RMN[0][b] && MX[0][b] >= RMX[0][b]);
        int ds = (int)ST[HIST_STG_BLOWER][b] - (int)RST[HIST_STG_BLOWER][b];
        CHECK(ds >= -60 && ds <= 60);
    }
    CHECK(gaps <= gaps_ref); /* never more gaps than the exact answer */
    CHECK(gaps_ref - gaps <= 1);
    /* the rollups do not reach into the RAM ring: no double counting at the boundary */
    CHECK_EQ(A[HIST_CH_TEMP][ns - 1], RA[HIST_CH_TEMP][ns - 1]);
    /* without wall time nothing older than the ring is addressed */
    g_coarse_calls = 0;
    CHECK_EQ(hist_core_span(&g_dev, 3, 7 * 86400, 1, now_mono, 0, &g_env_c, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(g_coarse_calls, 0);
    /* dt not a multiple of 10 min (3 days -> 5 min buckets) keeps reading the minute files */
    g_file_calls = g_coarse_calls = 0;
    CHECK_EQ(hist_core_span(&g_dev, 3, 3 * 86400, 1, now_mono, now_wall, &g_env_c, &io, NULL, NULL), ESP_OK);
    CHECK_EQ(io.dt_s, 300);
    CHECK_EQ(g_coarse_calls, 0);
    CHECK_EQ(g_file_calls, 1);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    snprintf(g_base, sizeof(g_base), "%s", argv[1]);
    g_fast = calloc(HIST_FAST_LEN, sizeof(hist_fast_t));
    g_slow = calloc(HIST_SLOW_LEN, sizeof(hist_slow_t));
    test_acc_and_snapshot();
    test_pick_res();
    test_ring_and_pending();
    test_span_fast();
    test_span_minutes();
    test_missed_ticks();
    test_files();
    test_range_and_reload();
    test_coarse();
    free(g_fast);
    free(g_slow);
    return BT_DONE();
}
