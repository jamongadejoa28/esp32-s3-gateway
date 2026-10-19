/* Gateway SNMP agent facade (contract: snmp_gw/snmp_gw.h; DESIGN.md §10, ARCHITECTURE.md §2-§5).
 *
 * snmp_gw_start() (app_main, init step 12) registers the MIB modules and the gw_evt handlers and
 * starts the transport task. Everything that touches lwIP runs in the agent task through the
 * transport hooks: on_start (MIBs, configuration, coldStart, debug self-test), on_msg (queued work
 * from other tasks), on_idle (heartbeat, pending configuration apply, trap timers). gw_evt handlers
 * only copy event data into small locked records, set flags and post messages with timeout 0.
 *
 * Configuration changes are signalled with the atomic s_apply_pending flag, not a queued message: a
 * message can be lost when the shared queue is full (alarm/comm bursts), and a lost apply would keep
 * revoked communities or v3 keys working. on_idle runs at least every SNMP_RECV_TIMEOUT_MS. */
#include <stdatomic.h>
#include <string.h>

#include "alarm/alarm.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_ident.h"
#include "gw_core/gw_time.h"
#include "mib_oids.h"
#include "net/net.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "snmp_gw_priv.h"
#include "snmp_lwip/snmpv3_util.h"
#include "store/eventlog.h"

static const char *TAG = "snmp_gw";

/* ---------------------------------------------------------------- state */

/* Set once in snmp_gw_start() before the agent task exists; read-only afterwards. */
static uint8_t s_mac[GW_MAC_LEN];
static uint8_t s_engine_id[GW_ENGINE_ID_LEN];
static uint8_t s_engine_id_len;
static char s_fw_version[GW_VERSION_SZ];
static bool s_started;

/* Agent task only. */
static uint32_t s_boots;
static int64_t s_time_base_us;
static sgw_dev_t s_devs[GW_MAX_DEVICES];
static uint8_t s_n_devs;
static char s_sys[3][GW_TEXT_SZ];
static cfg_snmp_t s_cfg_snmp;      /* apply scratch (large; not on the agent stack) */
static gw_secrets_t s_sec_scratch; /* apply scratch, wiped after use */
static sgw_trap_cfg_t s_trap_cfg;  /* apply scratch, wiped after use */
static evlog_rec_t s_seed[SGW_EVENT_SEED_BATCH];

/* Any task -> agent: re-read configuration + secrets at the next on_idle. */
static atomic_bool s_apply_pending;

/* Shared with gw_evt / httpd (s_lock). */
static SemaphoreHandle_t s_lock;
static StaticSemaphore_t s_lock_buf;
static sgw_last_write_t s_last_write;
static char s_last_config[16];
static snmp_evring_t s_events;

/* ---------------------------------------------------------------- small accessors */

uint32_t sgw_uptime_cs(void) {
    return (uint32_t)(esp_timer_get_time() / 10000); /* == snmp_lwip_sysuptime_cs() */
}

const uint8_t *sgw_mac(void) {
    return s_mac;
}

const char *sgw_fw_version(void) {
    return s_fw_version;
}

const uint8_t *sgw_engine_id(uint8_t *len) {
    *len = s_engine_id_len;
    return s_engine_id;
}

uint32_t sgw_engine_boots(void) {
    return s_boots;
}

void sgw_engine_boots_set(uint32_t boots) {
    /* lwIP increments boots when engine time wraps (RFC 3414 2.2.2). Kept in RAM only: flash writes
     * belong to the persist task / app_main, and the next boot increments the NVS counter anyway. */
    s_boots = boots;
}

uint32_t sgw_engine_time(void) {
    return (uint32_t)((esp_timer_get_time() - s_time_base_us) / 1000000);
}

void sgw_engine_time_reset(void) {
    s_time_base_us = esp_timer_get_time();
}

uint8_t sgw_dev_count(void) {
    return s_n_devs;
}

const sgw_dev_t *sgw_dev_at(uint8_t i) {
    return i < s_n_devs ? &s_devs[i] : NULL;
}

const sgw_dev_t *sgw_dev_by_index(uint32_t dev_index) {
    for (uint8_t i = 0; i < s_n_devs; i++) {
        if (GWMIB_DEV_INDEX(s_devs[i].id) == dev_index) {
            return &s_devs[i];
        }
    }
    return NULL;
}

bool sgw_snap_fresh(const mex_snapshot_t *s) {
    cfg_modbus_t mb;
    const uint32_t poll_ms = cfg_get_section(CFG_SEC_MODBUS, &mb, sizeof(mb)) == ESP_OK ? mb.port.poll_ms : 0;
    return alm_sample_fresh(s, gw_time_mono_ms(), poll_ms);
}

const char *sgw_sys_string(sgw_sys_t which) {
    return (unsigned)which < 3 ? s_sys[which] : "";
}

void sgw_sys_string_set(sgw_sys_t which, const char *value) {
    if ((unsigned)which < 3 && value != NULL) {
        gw_strlcpy(s_sys[which], value, sizeof(s_sys[which]));
    }
}

static void lock(void) {
    xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void unlock(void) {
    xSemaphoreGive(s_lock);
}

void sgw_last_write_get(sgw_last_write_t *out) {
    lock();
    *out = s_last_write;
    unlock();
}

void sgw_last_write_put(const sgw_last_write_t *in) {
    lock();
    s_last_write = *in;
    s_last_write.valid = true;
    unlock();
}

void sgw_last_write_put_pending(const sgw_last_write_t *in) {
    lock();
    /* The final GW_EVT_WRITE_RESULT (gw_evt, other core) may already be stored: never replace it. */
    if (!snmp_last_write_supersedes(s_last_write.valid, s_last_write.cmd, in->cmd)) {
        s_last_write = *in;
        s_last_write.valid = true;
    }
    unlock();
}

void sgw_last_config_get(char out[16]) {
    lock();
    memcpy(out, s_last_config, sizeof(s_last_config));
    unlock();
}

bool sgw_event_get(uint32_t seq, snmp_alarm_ev_t *out) {
    lock();
    const snmp_alarm_ev_t *e = snmp_evring_find(&s_events, seq);
    if (e != NULL) {
        *out = *e;
    }
    unlock();
    return e != NULL;
}

void sgw_events_copy(snmp_evring_t *out) {
    lock();
    *out = s_events;
    unlock();
}

static void event_insert(const snmp_alarm_ev_t *ev) {
    lock();
    (void)snmp_evring_insert(&s_events, ev);
    unlock();
}

esp_err_t sgw_post(const sgw_msg_t *m, uint32_t timeout_ms) {
    return snmp_transport_post(m, sizeof(*m), timeout_ms);
}

/* ---------------------------------------------------------------- configuration apply [agent] */

static void refresh_devices(void) {
    cfg_modbus_t mb;
    s_n_devs = 0;
    if (cfg_get_section(CFG_SEC_MODBUS, &mb, sizeof(mb)) != ESP_OK) {
        ESP_LOGW(TAG, "modbus config unavailable; device tables empty");
        return;
    }
    for (uint8_t i = 0; i < mb.n_devices && i < GW_MAX_DEVICES; i++) {
        const mex_dev_cfg_t *d = &mb.devices[i];
        if (d->id >= GW_MAX_DEVICES) {
            continue;
        }
        sgw_dev_t e = {.id = d->id, .slave = d->slave, .enabled = d->enabled};
        gw_strlcpy(e.name, d->name, sizeof(e.name));
        /* insertion sort by id (<= 4 entries), duplicates ignored */
        uint8_t pos = s_n_devs;
        bool dup = false;
        for (uint8_t k = 0; k < s_n_devs; k++) {
            if (s_devs[k].id == e.id) {
                dup = true;
            }
        }
        if (dup) {
            continue;
        }
        while (pos > 0 && s_devs[pos - 1].id > e.id) {
            s_devs[pos] = s_devs[pos - 1];
            pos--;
        }
        s_devs[pos] = e;
        s_n_devs++;
    }
}

static void refresh_sys_strings(const cfg_snmp_t *snmp) {
    cfg_general_t gen;
    cfg_network_t net;
    bool have_gen = cfg_get_section(CFG_SEC_GENERAL, &gen, sizeof(gen)) == ESP_OK;
    bool have_net = cfg_get_section(CFG_SEC_NETWORK, &net, sizeof(net)) == ESP_OK;
    /* Configured SNMP value, else the matching general/network setting (DESIGN.md §5: "" -> hostname). */
    gw_strlcpy(s_sys[SGW_SYS_CONTACT],
               snmp->sys_contact[0] ? snmp->sys_contact : (have_gen ? gen.contact : ""), GW_TEXT_SZ);
    gw_strlcpy(s_sys[SGW_SYS_NAME], snmp->sys_name[0] ? snmp->sys_name : (have_net ? net.hostname : ""),
               GW_TEXT_SZ);
    gw_strlcpy(s_sys[SGW_SYS_LOCATION],
               snmp->sys_location[0] ? snmp->sys_location : (have_gen ? gen.location : ""), GW_TEXT_SZ);
}

static void apply_config(void) {
    cfg_security_t sec;
    if (cfg_get_section(CFG_SEC_SNMP, &s_cfg_snmp, sizeof(s_cfg_snmp)) != ESP_OK ||
        cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec)) != ESP_OK) {
        ESP_LOGE(TAG, "configuration unavailable; SNMP stays disabled");
        snmp_transport_set_enabled(false);
        return;
    }
    secrets_get(&s_sec_scratch);

    const bool enabled = s_cfg_snmp.enabled && sec.svc_snmp;
    snmp_access_cfg_t acc = {.v1 = s_cfg_snmp.v1, .v2c = s_cfg_snmp.v2c, .v3 = s_cfg_snmp.v3};
    gw_strlcpy(acc.ro, s_sec_scratch.snmp_ro, sizeof(acc.ro));
    gw_strlcpy(acc.rw, s_sec_scratch.snmp_rw, sizeof(acc.rw));
    if (acc.ro[0] == '\0') {
        acc.v1 = acc.v2c = false; /* defence in depth: cfg_snmp_check_secrets forbids this state */
    }
    snmp_transport_set_access(&acc);
    sgw_usm_configure(&s_cfg_snmp, s_sec_scratch.v3);

    memset(&s_trap_cfg, 0, sizeof(s_trap_cfg));
    s_trap_cfg.enabled = enabled;
    s_trap_cfg.auth_traps = s_cfg_snmp.auth_traps;
    s_trap_cfg.n = s_cfg_snmp.n_traps <= GW_MAX_TRAP_TARGETS ? s_cfg_snmp.n_traps : GW_MAX_TRAP_TARGETS;
    memcpy(s_trap_cfg.traps, s_cfg_snmp.traps, sizeof(s_trap_cfg.traps));
    memcpy(s_trap_cfg.community, s_sec_scratch.trap_comm, sizeof(s_trap_cfg.community));
    sgw_traps_configure(&s_trap_cfg);

    gw_secure_zero(&acc, sizeof(acc));
    gw_secure_zero(&s_sec_scratch, sizeof(s_sec_scratch));
    gw_secure_zero(&s_trap_cfg, sizeof(s_trap_cfg));

    refresh_devices();
    refresh_sys_strings(&s_cfg_snmp);
    snmp_transport_set_enabled(enabled);
    snmp_registry_notify_config();
    ESP_LOGI(TAG, "SNMP %s (v1 %d, v2c %d, v3 %d, %u trap target(s))", enabled ? "enabled" : "disabled",
             s_cfg_snmp.v1, s_cfg_snmp.v2c, s_cfg_snmp.v3, (unsigned)s_cfg_snmp.n_traps);
}

/* Seed the alarm event table with the last SNMP_GW_EVENTS_KEPT alarm transitions of the event log
 * (events received since start are already there; the ring merges by seq). */
static void seed_events(void) {
    evlog_filter_t f = {.dev = -1, .min_sev = -1, .type_min = EVT_ALARM_RAISE, .type_max = EVT_ALARM_ACK};
    uint32_t before = 0;
    size_t total = 0;
    while (total < SNMP_GW_EVENTS_KEPT) {
        uint32_t next = 0;
        size_t n = evlog_query(EVLOG_EVENTS, before, SGW_EVENT_SEED_BATCH, &f, s_seed, &next);
        for (size_t i = 0; i < n; i++) {
            const evlog_rec_t *r = &s_seed[i];
            snmp_alarm_ev_t ev = {.seq = r->seq,
                                  .ts_ms = (int64_t)r->ts * 1000,
                                  .type = r->type,
                                  .dev = (uint8_t)r->dev,
                                  .sev = r->sev,
                                  .code = r->code,
                                  .value = r->value};
            size_t ul = 0;
            while (ul < sizeof(r->user) && ul < GW_USER_NAME_MAX && r->user[ul] != '\0') {
                ul++;
            }
            memcpy(ev.user, r->user, ul);
            ev.user[ul] = '\0';
            if (r->dev < GW_MAX_DEVICES) {
                event_insert(&ev);
            }
        }
        total += n;
        if (n == 0 || next == 0) {
            break;
        }
        before = next;
    }
}

/* ---------------------------------------------------------------- transport hooks [agent] */

static void on_start(void *arg) {
    (void)arg;
    s_time_base_us = esp_timer_get_time();
    sgw_traps_init();
    esp_err_t err = snmp_registry_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "MIB registry start failed: %s", esp_err_to_name(err));
    }
    apply_config();
#if defined(CONFIG_LOG_DEFAULT_LEVEL_DEBUG) || defined(CONFIG_LOG_DEFAULT_LEVEL_VERBOSE)
    /* Debug builds (sdkconfig.defaults.debug): on-target SNMPv3 crypto known-answer test. */
    if (snmpv3_selftest() != 0) {
        ESP_LOGE(TAG, "SNMPv3 crypto self-test FAILED: v3 authentication/privacy is unreliable");
    }
#endif
    seed_events();
    sgw_traps_cold_start();
}

static void on_idle(void *arg) {
    (void)arg;
    gw_hb_beat(GW_HB_SNMP);
    if (atomic_exchange(&s_apply_pending, false)) {
        apply_config();
    }
    sgw_traps_on_idle(gw_time_mono_ms());
}

static void on_msg(const void *msg, size_t len, void *arg) {
    (void)arg;
    sgw_msg_t m;
    if (len != sizeof(m)) {
        ESP_LOGW(TAG, "dropping malformed agent message (%u bytes)", (unsigned)len);
        return;
    }
    memcpy(&m, msg, sizeof(m));
    sgw_traps_on_msg(&m);
}

static bool accept_peer(uint32_t peer_ip, uint32_t local_ip, void *arg) {
    (void)arg;
    return net_ip_allowed(peer_ip, local_ip);
}

static bool inform_peer(uint32_t peer_ip, char community[SNMP_COMMUNITY_SZ], void *arg) {
    (void)arg;
    return sgw_traps_inform_peer(peer_ip, community);
}

static void on_inform_ack(int32_t request_id, uint32_t peer_ip, void *arg) {
    (void)arg;
    sgw_traps_inform_ack(request_id, peer_ip);
}

static void on_auth_fail(uint32_t peer_ip, void *arg) {
    (void)arg;
    sgw_traps_auth_fail(peer_ip);
}

/* ---------------------------------------------------------------- gw_evt handlers [gw_evt] */

static void request_apply(void) {
    atomic_store(&s_apply_pending, true); /* cannot be lost; picked up by on_idle */
}

static void on_alarm(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_alarm_t *a = data;
    snmp_alarm_ev_t ev = {.seq = a->seq,
                          .ts_ms = a->ts_ms,
                          .type = a->type,
                          .dev = a->dev,
                          .sev = a->sev,
                          .code = a->code,
                          .value = a->value};
    gw_strlcpy(ev.user, a->user, sizeof(ev.user));
    event_insert(&ev);
    if (a->type == GW_ALARM_RAISE || a->type == GW_ALARM_CLEAR) {
        (void)snmp_gw_trap_alarm(a->dev, a->code, a->sev, a->type == GW_ALARM_RAISE, a->value, a->seq, a->ts_ms);
    }
}

static void on_comm(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_comm_t *c = data;
    (void)snmp_gw_trap_comm(c->dev, c->online);
}

static void on_config(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_config_t *c = data;
    const char *name = cfg_section_name((cfg_section_t)c->section);
    lock();
    gw_strlcpy(s_last_config, name ? name : "", sizeof(s_last_config));
    unlock();
    request_apply(); /* any section may feed the agent (snmp, security, secrets, modbus, names) */
    (void)snmp_gw_trap_config(c->section, c->rev);
}

static void on_ota(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_ota_t *o = data;
    if (o->phase == GW_OTA_VALIDATED) {
        (void)snmp_gw_trap_firmware(o->version);
    }
}

static void on_write(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    (void)id;
    const gw_evt_write_t *w = data;
    sgw_last_write_t lw = {.dev = w->dev,
                           .state = w->state,
                           .addr = w->addr,
                           .raw_req = w->raw_req,
                           .reason = w->reason,
                           .cmd = w->cmd,
                           .ts_ms = gw_time_wall_ms()};
    gw_strlcpy(lw.by, w->by, sizeof(lw.by));
    sgw_last_write_put(&lw);
}

/* ---------------------------------------------------------------- start */

static uint32_t read_boots(void) {
    nvs_handle_t h;
    uint32_t boots = 0;
    esp_err_t err = nvs_open(GW_NVS_NS_BOOTS, NVS_READONLY, &h);
    if (err == ESP_OK) {
        err = nvs_get_u32(h, GW_NVS_KEY_BOOTS, &boots);
        nvs_close(h);
    }
    if (err != ESP_OK || boots == 0) {
        ESP_LOGW(TAG, "engine boots unavailable in NVS (%s); using 1", esp_err_to_name(err));
        boots = 1;
    }
    return boots;
}

static esp_err_t register_handlers(void) {
    static const struct {
        int32_t id;
        esp_event_handler_t fn;
    } h[] = {
        {GW_EVT_ALARM, on_alarm},   {GW_EVT_COMM, on_comm},          {GW_EVT_CONFIG_CHANGED, on_config},
        {GW_EVT_OTA, on_ota},       {GW_EVT_WRITE_RESULT, on_write},
    };
    for (size_t i = 0; i < sizeof(h) / sizeof(h[0]); i++) {
        esp_err_t err = gw_events_register(h[i].id, h[i].fn, NULL, NULL);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t snmp_gw_start(void) {
    if (s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    s_lock = xSemaphoreCreateMutexStatic(&s_lock_buf);
    esp_err_t err = sgw_traps_sync_init();
    if (s_lock == NULL || err != ESP_OK) {
        return ESP_ERR_NO_MEM;
    }
    snmp_evring_init(&s_events);

    err = esp_efuse_mac_get_default(s_mac);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "base MAC unavailable: %s", esp_err_to_name(err));
        return err;
    }
    s_engine_id_len = (uint8_t)gw_ident_engine_id(snmp_gw_pen(), s_mac, s_engine_id);
    s_boots = read_boots();
    gw_strlcpy(s_fw_version, esp_app_get_description()->version, sizeof(s_fw_version));

    static const snmp_module_t *const mods[] = {
        &sgw_mod_system, &sgw_mod_framework, &sgw_mod_usm,     &sgw_mod_gw,        &sgw_mod_dev,
        &sgw_mod_mex_status, &sgw_mod_mex_setpoint, &sgw_mod_mex_regs, &sgw_mod_alarm, &sgw_mod_comm,
    };
    for (size_t i = 0; i < sizeof(mods) / sizeof(mods[0]); i++) {
        err = snmp_registry_add(mods[i]);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "register module %s: %s", mods[i]->name, esp_err_to_name(err));
            return err;
        }
    }
    static const snmp_transport_hooks_t hooks = {
        .on_start = on_start,
        .on_idle = on_idle,
        .on_msg = on_msg,
        .accept = accept_peer,
        .inform_peer = inform_peer,
        .on_inform_ack = on_inform_ack,
        .on_auth_fail = on_auth_fail,
        .arg = NULL,
    };
    err = snmp_transport_start(&hooks);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "transport start: %s", esp_err_to_name(err));
        return err;
    }
    s_started = true; /* the queue exists: handlers may post from now on */
    err = register_handlers();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "gw_evt handlers: %s (no traps or config updates)", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "agent started (engine boots %lu)", (unsigned long)s_boots);
    return ESP_OK;
}

esp_err_t snmp_gw_apply_config(void) {
    if (!s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    request_apply();
    return ESP_OK;
}

/* ---------------------------------------------------------------- trap requests [any] */

static esp_err_t post_or_count(const sgw_msg_t *m) {
    if (!s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = sgw_post(m, 0);
    if (err != ESP_OK) {
        sgw_traps_count_drop();
    }
    return err;
}

esp_err_t snmp_gw_trap_alarm(uint8_t dev, uint16_t code, uint8_t sev, bool raised, int16_t value, uint32_t seq,
                             int64_t ts_ms) {
    if (dev >= GW_MAX_DEVICES) {
        return ESP_ERR_INVALID_ARG;
    }
    sgw_msg_t m = {.type = SGW_MSG_ALARM};
    m.u.alarm.dev = dev;
    m.u.alarm.code = code;
    m.u.alarm.sev = sev;
    m.u.alarm.raised = raised;
    m.u.alarm.value = value;
    m.u.alarm.seq = seq;
    m.u.alarm.ts_ms = ts_ms;
    return post_or_count(&m);
}

esp_err_t snmp_gw_trap_comm(uint8_t dev, bool online) {
    if (dev >= GW_MAX_DEVICES) {
        return ESP_ERR_INVALID_ARG;
    }
    sgw_msg_t m = {.type = SGW_MSG_COMM};
    m.u.comm.dev = dev;
    m.u.comm.online = online;
    return post_or_count(&m);
}

esp_err_t snmp_gw_trap_config(uint8_t section, uint32_t rev) {
    sgw_msg_t m = {.type = SGW_MSG_CONFIG};
    m.u.config.section = section;
    m.u.config.rev = rev;
    return post_or_count(&m);
}

esp_err_t snmp_gw_trap_firmware(const char *version) {
    sgw_msg_t m = {.type = SGW_MSG_FIRMWARE};
    gw_strlcpy(m.u.fw.version, version ? version : "", sizeof(m.u.fw.version));
    return post_or_count(&m);
}

size_t snmp_gw_test_trap(snmp_gw_test_result_t *out, size_t cap, uint32_t timeout_ms) {
    if (!s_started || out == NULL || cap == 0) {
        return 0;
    }
    return sgw_traps_test(out, cap, timeout_ms);
}

/* ---------------------------------------------------------------- keys, identity, MIB text */

esp_err_t snmp_gw_localize_key(const char *pass, uint8_t out[20]) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t eid[GW_ENGINE_ID_LEN];
    size_t elen = snmp_gw_engine_id(eid, sizeof(eid));
    if (elen == 0) {
        memset(out, 0, SEC_V3_KEY_LEN);
        return ESP_ERR_INVALID_STATE;
    }
    return snmp_localize_key_for(pass, eid, elen, out) == GW_CRYPTO_OK ? ESP_OK : ESP_ERR_INVALID_ARG;
}

size_t snmp_gw_engine_id(uint8_t *out, size_t cap) {
    uint8_t mac[GW_MAC_LEN];
    uint8_t eid[GW_ENGINE_ID_LEN];
    if (out == NULL || cap < GW_ENGINE_ID_LEN) {
        return 0;
    }
    if (s_engine_id_len != 0) {
        memcpy(out, s_engine_id, s_engine_id_len);
        return s_engine_id_len;
    }
    /* Before snmp_gw_start() (e.g. early config handling): derive it the same way. */
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        return 0;
    }
    size_t n = gw_ident_engine_id(snmp_gw_pen(), mac, eid);
    memcpy(out, eid, n);
    return n;
}

extern const uint8_t _binary_MESTIO_GW_MIB_txt_gz_start[] asm("_binary_MESTIO_GW_MIB_txt_gz_start");
extern const uint8_t _binary_MESTIO_GW_MIB_txt_gz_end[] asm("_binary_MESTIO_GW_MIB_txt_gz_end");

const uint8_t *snmp_gw_mib_gz(size_t *len) {
    if (len != NULL) {
        *len = (size_t)(_binary_MESTIO_GW_MIB_txt_gz_end - _binary_MESTIO_GW_MIB_txt_gz_start);
    }
    return _binary_MESTIO_GW_MIB_txt_gz_start;
}
