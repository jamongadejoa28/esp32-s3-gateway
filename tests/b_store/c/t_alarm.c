/* t_alarm.c - alarm/catalog.c + engine.c: catalog/keys, params, debounce, BIT alarms, comm-loss
 * freeze, enable/disable, rules (delay, hysteresis, LT/GT, freeze, slow group), ack, sorting, mask. */
#include "alarm/alarm.h"
#include "bt.h"

#define MAXT 256
static alm_transition_t g_tr[MAXT];
static int g_ntr;

static void on_emit(void *arg, const alm_transition_t *t) {
    CHECK(arg == (void *)0x1234);
    if (g_ntr < MAXT)
        g_tr[g_ntr++] = *t;
}

static int count_type(alm_ev_type_t type, alm_id_t id) {
    int n = 0;
    for (int i = 0; i < g_ntr; i++)
        if (g_tr[i].type == type && g_tr[i].id == id)
            n++;
    return n;
}

static alm_engine_t g_e;

static void snap_init(mex_snapshot_t *s) {
    memset(s, 0, sizeof(*s));
    s->online = true;
    s->slow_valid = true;
    s->mono_ms = 1;
    s->seq = 1;
    s->regs[36] = 250;
    s->regs[37] = 500;
    s->regs[11] = 30;
    s->regs[27] = 300; /* 40027 hi_temp limit */
}

static void set_coil(mex_snapshot_t *s, unsigned n, bool on) {
    if (on)
        s->coils |= 1u << (n - 1);
    else
        s->coils &= ~(1u << (n - 1));
}

static void test_catalog(void) {
    CHECK_EQ(ALM_COUNT, 25);
    CHECK_STR(alm_catalog[ALM_high_temp].id, "high_temp");
    CHECK_EQ(alm_catalog[ALM_high_temp].code, 127);
    CHECK_EQ(alm_catalog[ALM_high_temp].src, ALM_SRC_COIL);
    CHECK_EQ(alm_catalog[ALM_high_temp].addr, 27);
    CHECK_EQ(alm_catalog[ALM_high_temp].vreg, 40036);
    CHECK_EQ(alm_catalog[ALM_leak].sev, ALM_SEV_CRITICAL);
    CHECK_EQ(alm_catalog[ALM_contamination].src, ALM_SRC_BIT);
    CHECK_EQ(alm_catalog[ALM_contamination].bit, 7);
    CHECK_EQ(alm_catalog[ALM_comm_lost].src, ALM_SRC_COMM);
    CHECK_EQ(alm_catalog[ALM_rule_8].code, 408);
    CHECK_EQ(alm_catalog[ALM_rule_8].addr, 8);
    CHECK_STR(alm_catalog[ALM_fire].ko, "화재경보");
    CHECK(alm_find_code(301) == &alm_catalog[ALM_comm_lost]);
    CHECK(alm_find_code(132) == NULL);
    CHECK(alm_find_id("leak") == &alm_catalog[ALM_leak]);
    CHECK(alm_find_id("LEAK") == NULL);
    CHECK(alm_find_id(NULL) == NULL);
    CHECK(alarm_code_valid(401));
    CHECK(!alarm_code_valid(0));
    uint16_t code = 0;
    CHECK(alm_cfg_catalog.code_from_id("high_hum", &code));
    CHECK_EQ(code, 129);
    CHECK(!alm_cfg_catalog.code_from_id("rule_1", &code));
    CHECK(!alm_cfg_catalog.code_from_id("nope", &code));
    CHECK_STR(alm_cfg_catalog.id_from_code(201), "contamination");
    CHECK(alm_cfg_catalog.id_from_code(405) == NULL);
    CHECK(alm_cfg_catalog.id_from_code(999) == NULL);
    CHECK_STR(alm_sev_name(ALM_SEV_CRITICAL), "critical");
    CHECK_STR(alm_sev_name(ALM_SEV_INFO), "info");
    CHECK_STR(alm_sev_name((alm_sev_t)9), "info");
    /* unique ids and codes */
    for (int i = 0; i < ALM_COUNT; i++)
        for (int j = 0; j < i; j++) {
            CHECK(alm_catalog[i].code != alm_catalog[j].code);
            CHECK(strcmp(alm_catalog[i].id, alm_catalog[j].id) != 0);
        }
    char key[ALM_KEY_SZ];
    alm_key_format(2, ALM_high_temp, key);
    CHECK_STR(key, "2:high_temp");
    uint8_t dev = 9;
    alm_id_t id = ALM_COUNT;
    CHECK(alm_key_parse("2:high_temp", &dev, &id));
    CHECK_EQ(dev, 2);
    CHECK_EQ(id, ALM_high_temp);
    CHECK(alm_key_parse("0:rule_3", &dev, &id));
    CHECK_EQ(id, ALM_rule_3);
    static const char *const bad[] = {"4:leak", "x:leak", "0leak", "0:", "0:nope", "", "10:leak", ":leak", "0:leak "};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(!alm_key_parse(bad[i], &dev, &id));
    CHECK(!alm_key_parse(NULL, &dev, &id));
    alm_key_format(0, ALM_COUNT, key);
    CHECK_STR(key, "");
}

static void rule(cfg_alarms_t *a, uint8_t id, uint8_t dev, uint16_t addr, uint8_t op, int32_t thr, int32_t hyst,
                 uint16_t delay, uint8_t sev) {
    cfg_rule_t *r = &a->rules[a->n_rules++];
    memset(r, 0, sizeof(*r));
    r->id = id;
    r->enabled = true;
    r->dev = dev;
    r->addr = addr;
    r->op = op;
    r->thr = thr;
    r->hyst = hyst;
    r->delay_s = delay;
    r->sev = sev;
}

static void test_params(void) {
    alm_params_t p;
    alm_params_from_config(NULL, &p);
    CHECK_EQ(p.debounce_raise, 2);
    CHECK_EQ(p.debounce_clear, 3);
    CHECK_EQ(p.sev[ALM_leak], ALM_SEV_CRITICAL);
    CHECK_EQ(p.n_rules, 0);
    cfg_alarms_t a;
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 0; /* invalid -> default */
    a.debounce_clear = 5;
    a.n_sev_override = 3;
    a.sev_override[0] = (cfg_sev_override_t){127, ALM_SEV_CRITICAL};
    a.sev_override[1] = (cfg_sev_override_t){401, ALM_SEV_INFO}; /* rule: ignored */
    a.sev_override[2] = (cfg_sev_override_t){123, 9};             /* invalid sev: ignored */
    rule(&a, 3, 0, 40036, CFG_OP_GT, 280, 10, 0, ALM_SEV_MINOR);
    rule(&a, 9, 0, 40036, CFG_OP_GT, 280, 10, 0, ALM_SEV_MINOR); /* no catalog entry: no severity */
    alm_params_from_config(&a, &p);
    CHECK_EQ(p.debounce_raise, 2);
    CHECK_EQ(p.debounce_clear, 5);
    CHECK_EQ(p.sev[ALM_high_temp], ALM_SEV_CRITICAL);
    CHECK_EQ(p.sev[ALM_rule_1], ALM_SEV_MAJOR);
    CHECK_EQ(p.sev[ALM_leak], ALM_SEV_CRITICAL);
    CHECK_EQ(p.sev[ALM_rule_3], ALM_SEV_MINOR);
    CHECK_EQ(p.n_rules, 2);
}

static void test_debounce_and_bits(void) {
    alm_params_t p;
    alm_params_from_config(NULL, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    mex_snapshot_t s;
    snap_init(&s);
    set_coil(&s, 27, true);
    s.regs[36] = (uint16_t)-35; /* signed -3.5 */
    /* disabled device: ignored */
    alm_engine_feed_snapshot(&g_e, 0, &s, 1000);
    alm_engine_feed_snapshot(&g_e, 0, &s, 1000);
    CHECK_EQ(g_ntr, 0);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    alm_engine_feed_snapshot(&g_e, 0, &s, 1000);
    CHECK_EQ(g_ntr, 0);
    alm_engine_feed_snapshot(&g_e, 0, &s, 2000);
    CHECK_EQ(g_ntr, 1);
    CHECK_EQ(g_tr[0].type, ALM_EV_RAISE);
    CHECK_EQ(g_tr[0].id, ALM_high_temp);
    CHECK_EQ(g_tr[0].dev, 0);
    CHECK_EQ(g_tr[0].value, -35);
    CHECK_EQ(g_tr[0].ts_ms, 2000);
    CHECK_EQ(g_tr[0].sev, ALM_SEV_MAJOR);
    CHECK_EQ(alm_engine_mask(&g_e, 0), 1u << ALM_high_temp);
    /* still set: no repeat */
    alm_engine_feed_snapshot(&g_e, 0, &s, 3000);
    CHECK_EQ(g_ntr, 1);
    /* clear needs 3 consecutive polls; an intermediate set resets the count */
    set_coil(&s, 27, false);
    alm_engine_feed_snapshot(&g_e, 0, &s, 4000);
    alm_engine_feed_snapshot(&g_e, 0, &s, 5000);
    set_coil(&s, 27, true);
    alm_engine_feed_snapshot(&g_e, 0, &s, 6000);
    set_coil(&s, 27, false);
    alm_engine_feed_snapshot(&g_e, 0, &s, 7000);
    alm_engine_feed_snapshot(&g_e, 0, &s, 8000);
    CHECK_EQ(g_ntr, 1);
    s.regs[36] = 241;
    alm_engine_feed_snapshot(&g_e, 0, &s, 9000);
    CHECK_EQ(g_ntr, 2);
    CHECK_EQ(g_tr[1].type, ALM_EV_CLEAR);
    CHECK_EQ(g_tr[1].value, 241);
    CHECK_EQ(alm_engine_mask(&g_e, 0), 0);
    /* a single-poll glitch never raises */
    set_coil(&s, 23, true);
    alm_engine_feed_snapshot(&g_e, 0, &s, 10000);
    set_coil(&s, 23, false);
    alm_engine_feed_snapshot(&g_e, 0, &s, 11000);
    set_coil(&s, 23, true);
    alm_engine_feed_snapshot(&g_e, 0, &s, 12000);
    CHECK_EQ(g_ntr, 2);
    alm_engine_feed_snapshot(&g_e, 0, &s, 13000);
    CHECK_EQ(g_ntr, 3);
    CHECK_EQ(g_tr[2].id, ALM_leak);
    CHECK_EQ(g_tr[2].value, 1);
    CHECK_EQ(g_tr[2].sev, ALM_SEV_CRITICAL);
    /* register-bit alarm: 40003 bit 7 */
    s.regs[3] = 1u << 7;
    alm_engine_feed_snapshot(&g_e, 0, &s, 14000);
    alm_engine_feed_snapshot(&g_e, 0, &s, 15000);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_contamination), 1);
    /* coil 32 (combined) is status only */
    set_coil(&s, 32, true);
    for (int i = 0; i < 5; i++)
        alm_engine_feed_snapshot(&g_e, 0, &s, 16000);
    CHECK_EQ(g_ntr, 4);
    /* an offline snapshot is ignored */
    s.online = false;
    set_coil(&s, 23, false);
    for (int i = 0; i < 5; i++)
        alm_engine_feed_snapshot(&g_e, 0, &s, 17000);
    CHECK_EQ(g_ntr, 4);
    /* other devices are independent */
    CHECK_EQ(alm_engine_mask(&g_e, 1), 0);
    alm_engine_feed_snapshot(&g_e, 7, &s, 0); /* out of range: ignored */
}

static void test_comm_freeze_and_disable(void) {
    alm_params_t p;
    alm_params_from_config(NULL, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 1, true, 0);
    alm_engine_feed_comm(&g_e, 0, false, 5); /* dev 0 disabled: ignored */
    CHECK_EQ(g_ntr, 0);
    mex_snapshot_t s;
    snap_init(&s);
    set_coil(&s, 30, true); /* fire */
    alm_engine_feed_snapshot(&g_e, 1, &s, 100);
    alm_engine_feed_snapshot(&g_e, 1, &s, 200);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_fire), 1);
    set_coil(&s, 21, true); /* pending raise of humidifier_fault: 1 of 2 */
    alm_engine_feed_snapshot(&g_e, 1, &s, 300);
    /* comm lost: raised at once, device alarms frozen (not cleared) */
    alm_engine_feed_comm(&g_e, 1, false, 400);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_comm_lost), 1);
    CHECK_EQ(g_tr[g_ntr - 1].ts_ms, 400);
    CHECK_EQ(g_tr[g_ntr - 1].value, 1);
    alm_engine_feed_comm(&g_e, 1, false, 450); /* repeated: nothing */
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_comm_lost), 1);
    set_coil(&s, 30, false);
    for (int i = 0; i < 5; i++)
        alm_engine_feed_snapshot(&g_e, 1, &s, 500);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_fire), 0);
    CHECK(alm_engine_mask(&g_e, 1) & (1u << ALM_fire));
    /* rules are frozen too */
    cfg_alarms_t a;
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 2;
    a.debounce_clear = 3;
    rule(&a, 1, 1, 40036, CFG_OP_GT, 100, 0, 0, 3);
    alm_params_from_config(&a, &p);
    alm_engine_set_params(&g_e, &p, 0);
    alm_engine_tick_rules(&g_e, 1, &s, true, 1000, 600);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 0);
    /* back online: comm_lost cleared, counters restart (humidifier needs 2 fresh polls) */
    alm_engine_feed_comm(&g_e, 1, true, 700);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_comm_lost), 1);
    alm_engine_feed_snapshot(&g_e, 1, &s, 800);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_humidifier_fault), 0);
    alm_engine_feed_snapshot(&g_e, 1, &s, 900);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_humidifier_fault), 1);
    alm_engine_feed_snapshot(&g_e, 1, &s, 1000);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_fire), 1); /* 3 polls clear after return */
    alm_engine_tick_rules(&g_e, 1, &s, true, 2000, 1100);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 1);
    CHECK_EQ(g_tr[g_ntr - 1].sev, ALM_SEV_CRITICAL);
    /* disabling clears everything of the device and ignores later feeds */
    int before = g_ntr;
    alm_engine_set_enabled(&g_e, 1, false, 1200);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_humidifier_fault), 1);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_1), 1);
    CHECK_EQ(g_ntr, before + 2);
    CHECK_EQ(alm_engine_mask(&g_e, 1), 0);
    alm_engine_feed_comm(&g_e, 1, false, 1300);
    alm_engine_feed_snapshot(&g_e, 1, &s, 1300);
    alm_engine_feed_snapshot(&g_e, 1, &s, 1400);
    alm_engine_tick_rules(&g_e, 1, &s, true, 3000, 1400);
    CHECK_EQ(g_ntr, before + 2);
    /* re-enable: starts clean */
    alm_engine_set_enabled(&g_e, 1, true, 1500);
    alm_engine_set_enabled(&g_e, 1, true, 1500); /* idempotent */
    alm_engine_feed_snapshot(&g_e, 1, &s, 1600);
    CHECK_EQ(g_ntr, before + 2);
    /* a device that never answered: comm_lost on the first decision */
    alm_engine_set_enabled(&g_e, 3, true, 0);
    alm_engine_feed_comm(&g_e, 3, false, 1700);
    CHECK(alm_engine_mask(&g_e, 3) == (1u << ALM_comm_lost));
    alm_engine_feed_comm(&g_e, 3, true, 1800);
    CHECK_EQ(alm_engine_mask(&g_e, 3), 0);
    alm_engine_set_enabled(&g_e, 9, true, 0); /* out of range */
}

/* advance the monotonic/wall clock by 1 s and evaluate the rules of dev */
static void tickr(uint8_t dev, const mex_snapshot_t *s, bool fresh, uint64_t *t) {
    *t += 1000;
    alm_engine_tick_rules(&g_e, dev, s, fresh, *t, (int64_t)*t);
}

static void test_rules(void) {
    cfg_alarms_t a;
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 2;
    a.debounce_clear = 3;
    rule(&a, 1, 0, 40036, CFG_OP_GT, 280, 10, 5, 2);  /* temp > 28.0 for 5 s, clear <= 27.0 */
    rule(&a, 2, 0, 40037, CFG_OP_LT, 300, 20, 0, 1);  /* hum < 30.0 immediately, clear >= 32.0 */
    rule(&a, 3, 0, 40027, CFG_OP_GT, 290, 0, 0, 3);   /* slow-group register */
    rule(&a, 4, 1, 40036, CFG_OP_GT, 0, 0, 0, 2);     /* device 1 */
    alm_params_t p;
    alm_params_from_config(&a, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    mex_snapshot_t s;
    snap_init(&s);
    s.regs[36] = 281;
    s.regs[37] = 400;
    s.slow_valid = false; /* 40027 = 300 but not read yet */
    uint64_t t = 10000;
    for (int i = 0; i < 5; i++, t += 1000)
        alm_engine_tick_rules(&g_e, 0, &s, true, t, (int64_t)t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 0); /* held 4 s */
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_3), 0); /* slow register unknown: frozen */
    alm_engine_tick_rules(&g_e, 0, &s, true, t, (int64_t)t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 1); /* held 5 s */
    CHECK_EQ(g_tr[g_ntr - 1].value, 281);
    CHECK_EQ(g_tr[g_ntr - 1].sev, 2);
    s.slow_valid = true;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_3), 1);
    /* hysteresis: 27.1 keeps it, 27.0 clears */
    s.regs[36] = 271;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_1), 0);
    s.regs[36] = 270;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_1), 1);
    CHECK_EQ(g_tr[g_ntr - 1].value, 270);
    /* on-delay restarts when the condition drops out, and a stale/offline tick resets it */
    s.regs[36] = 300;
    for (int i = 0; i < 4; i++)
        tickr(0, &s, true, &t);
    tickr(0, &s, false, &t); /* stale */
    for (int i = 0; i < 5; i++)
        tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 1);
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 2);
    tickr(0, NULL, true, &t); /* no snapshot: frozen */
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_1), 1);
    /* LT rule with immediate raise and hysteresis */
    s.regs[37] = 299;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_2), 1);
    s.regs[37] = 319;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_2), 0);
    s.regs[37] = 320;
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_2), 1);
    /* rule for a disabled device never fires */
    tickr(1, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_4), 0);
    /* rule changes: disabled rule 1 clears; removed rule 3 clears; changed rule keeps state */
    int n0 = g_ntr;
    cfg_alarms_t b = a;
    b.rules[0].enabled = false;
    b.n_rules = 2; /* drops rules 3 and 4 */
    alm_params_from_config(&b, &p);
    alm_engine_set_params(&g_e, &p, 99);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_1), 2);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_3), 1);
    CHECK_EQ(g_ntr, n0 + 2);
    CHECK_EQ(g_tr[g_ntr - 1].ts_ms, 99);
    /* disabled rule is not evaluated */
    for (int i = 0; i < 10; i++)
        tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 2);
    /* moving a rule to another device clears it on the old one */
    b.rules[1].thr = 900; /* hum < 90.0: raise on dev 0 */
    alm_params_from_config(&b, &p);
    alm_engine_set_params(&g_e, &p, 0);
    tickr(0, &s, true, &t);
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_2), 2);
    b.rules[1].dev = 1;
    alm_params_from_config(&b, &p);
    alm_engine_set_params(&g_e, &p, 0);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_rule_2), 2);
}

static void test_ack_and_listing(void) {
    alm_params_t p;
    cfg_alarms_t a;
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 1;
    a.debounce_clear = 1;
    a.n_sev_override = 1;
    a.sev_override[0] = (cfg_sev_override_t){125, ALM_SEV_CRITICAL}; /* drain_fault upgraded */
    alm_params_from_config(&a, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    alm_engine_set_enabled(&g_e, 2, true, 0);
    mex_snapshot_t s;
    snap_init(&s);
    set_coil(&s, 24, true); /* supply: minor */
    alm_engine_feed_snapshot(&g_e, 0, &s, 100);
    set_coil(&s, 17, true); /* blower: major */
    alm_engine_feed_snapshot(&g_e, 0, &s, 200);
    set_coil(&s, 25, true); /* drain: critical by override */
    alm_engine_feed_snapshot(&g_e, 2, &s, 300); /* dev 2 raises supply, blower, drain at 300 */
    alm_engine_feed_comm(&g_e, 0, false, 50); /* comm_lost major, oldest */
    alm_active_t act[16];
    size_t n = alm_engine_active(&g_e, act, 16);
    CHECK_EQ(n, 6);
    CHECK_EQ(act[0].id, ALM_drain_fault);
    CHECK_EQ(act[0].sev, ALM_SEV_CRITICAL);
    CHECK_EQ(act[1].id, ALM_comm_lost); /* major, since 50 */
    CHECK_EQ(act[2].id, ALM_blower_fault);
    CHECK_EQ(act[2].dev, 0);
    CHECK_EQ(act[3].id, ALM_blower_fault);
    CHECK_EQ(act[3].dev, 2);
    CHECK_EQ(act[4].id, ALM_supply_fault);
    CHECK_EQ(act[4].dev, 0);
    CHECK_EQ(act[4].since_ms, 100);
    CHECK_EQ(act[5].sev, ALM_SEV_MINOR);
    CHECK_EQ(alm_engine_active(&g_e, act, 2), 6); /* total even when capped */
    CHECK_EQ(alm_engine_active(&g_e, NULL, 0), 6);
    /* ack */
    int nt = g_ntr;
    CHECK_EQ(alm_engine_ack(&g_e, 0, ALM_supply_fault, "operator1", 400), 0);
    CHECK_EQ(g_ntr, nt + 1);
    CHECK_EQ(g_tr[nt].type, ALM_EV_ACK);
    CHECK_STR(g_tr[nt].user, "operator1");
    CHECK_EQ(g_tr[nt].ts_ms, 400);
    CHECK_EQ(alm_engine_ack(&g_e, 0, ALM_supply_fault, "other", 500), 1);
    CHECK_EQ(g_ntr, nt + 1);
    CHECK_EQ(alm_engine_ack(&g_e, 0, ALM_leak, "x", 500), -1);
    CHECK_EQ(alm_engine_ack(&g_e, 5, ALM_leak, "x", 500), -1);
    CHECK_EQ(alm_engine_ack(&g_e, 0, ALM_COUNT, "x", 500), -1);
    n = alm_engine_active(&g_e, act, 16);
    CHECK(act[4].acked);
    CHECK_STR(act[4].ack_by, "operator1");
    CHECK_EQ(act[4].ack_ms, 400);
    CHECK_EQ(alm_engine_ack_all(&g_e, "admin", 600), 5);
    CHECK_EQ(alm_engine_ack_all(&g_e, "admin", 700), 0);
    /* ack does not clear; clear removes the acked alarm */
    set_coil(&s, 24, false);
    set_coil(&s, 25, false); /* drain was only meant for dev 2 */
    alm_engine_feed_comm(&g_e, 0, true, 750);
    alm_engine_feed_snapshot(&g_e, 0, &s, 800);
    CHECK_EQ(count_type(ALM_EV_CLEAR, ALM_supply_fault), 1);
    CHECK_EQ(alm_engine_active(&g_e, act, 16), 4);
    /* raising again starts unacknowledged */
    set_coil(&s, 24, true);
    alm_engine_feed_snapshot(&g_e, 0, &s, 900);
    n = alm_engine_active(&g_e, act, 16);
    for (size_t i = 0; i < n; i++)
        if (act[i].id == ALM_supply_fault && act[i].dev == 0) {
            CHECK(!act[i].acked);
            CHECK_STR(act[i].ack_by, "");
        }
    CHECK_EQ(alm_engine_mask(&g_e, 2), (1u << ALM_supply_fault) | (1u << ALM_blower_fault) | (1u << ALM_drain_fault));
    CHECK_EQ(alm_engine_mask(&g_e, 4), 0);
    /* every transition carried the effective severity */
    for (int i = 0; i < g_ntr; i++)
        CHECK_EQ(g_tr[i].sev, p.sev[g_tr[i].id]);
}

/* Freshness of the 1 Hz pass: judged at evaluation time; a long poll period is not staleness. */
static void test_sample_fresh(void) {
    mex_snapshot_t s;
    snap_init(&s);
    s.mono_ms = 5000;
    CHECK(alm_sample_fresh(&s, 4995, 1000)); /* published after the tick was posted: age 0 */
    CHECK(alm_sample_fresh(&s, 5000, 1000));
    CHECK(alm_sample_fresh(&s, 7999, 1000));
    CHECK(!alm_sample_fresh(&s, 8000, 1000));
    CHECK(!alm_sample_fresh(&s, 8000, 3000)); /* poll <= 3 s: plain MEX_FRESH_MS */
    CHECK(alm_sample_fresh(&s, 12999, 5000)); /* poll 5 s: 5 s + 3 s */
    CHECK(!alm_sample_fresh(&s, 13000, 5000));
    CHECK(alm_sample_fresh(&s, 5000 + 62999, 60000));
    CHECK(!alm_sample_fresh(NULL, 5000, 1000));
    s.online = false;
    CHECK(!alm_sample_fresh(&s, 5000, 1000));
    s.online = true;
    s.mono_ms = 0;
    CHECK(!alm_sample_fresh(&s, 5000, 1000));

    /* rule with a 3 s on-delay; every snapshot is published 5 ms after its tick was posted */
    cfg_alarms_t a;
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 2;
    a.debounce_clear = 3;
    rule(&a, 1, 0, 40036, CFG_OP_GT, 280, 10, 3, 2);
    alm_params_t p;
    alm_params_from_config(&a, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    snap_init(&s);
    s.regs[36] = 300;
    uint64_t tick = 100000;
    int raised_at = -1;
    for (int i = 0; i < 10 && raised_at < 0; i++, tick += 1000) {
        s.mono_ms = tick + 5;
        uint64_t now = tick + 5; /* handler reads the clock after fetching the snapshot */
        alm_engine_tick_rules(&g_e, 0, &s, alm_sample_fresh(&s, now, 1000), now, (int64_t)now);
        if (count_type(ALM_EV_RAISE, ALM_rule_1))
            raised_at = i;
    }
    CHECK_EQ(raised_at, 3);

    /* poll_ms 5000, delay 10 s: snapshot refreshed every 5 s, 1 Hz ticks in between */
    memset(&a, 0, sizeof(a));
    a.debounce_raise = 2;
    a.debounce_clear = 3;
    rule(&a, 1, 0, 40036, CFG_OP_GT, 280, 10, 10, 2);
    alm_params_from_config(&a, &p);
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    snap_init(&s);
    s.regs[36] = 300;
    raised_at = -1;
    uint64_t now = 200000;
    for (int i = 0; i < 30 && raised_at < 0; i++, now += 1000) {
        if (i % 5 == 0)
            s.mono_ms = now - 200; /* poll cycle finished 200 ms before this tick */
        alm_engine_tick_rules(&g_e, 0, &s, alm_sample_fresh(&s, now, 5000), now, (int64_t)now);
        if (count_type(ALM_EV_RAISE, ALM_rule_1))
            raised_at = i;
    }
    CHECK_EQ(raised_at, 10);
    /* the fixed 3 s window would have reset the on-delay every poll period: never raised */
    g_ntr = 0;
    alm_engine_init(&g_e, &p, on_emit, (void *)0x1234);
    alm_engine_set_enabled(&g_e, 0, true, 0);
    now = 300000;
    for (int i = 0; i < 30; i++, now += 1000) {
        if (i % 5 == 0)
            s.mono_ms = now - 200;
        alm_engine_tick_rules(&g_e, 0, &s, alm_sample_fresh(&s, now, 1000), now, (int64_t)now);
    }
    CHECK_EQ(count_type(ALM_EV_RAISE, ALM_rule_1), 0);
}

int main(void) {
    test_catalog();
    test_params();
    test_debounce_and_bits();
    test_comm_freeze_and_disable();
    test_rules();
    test_sample_fresh();
    test_ack_and_listing();
    return BT_DONE();
}
