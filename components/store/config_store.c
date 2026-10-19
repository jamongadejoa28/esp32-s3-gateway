/*
 * config_store.c - the in-RAM configuration store (device): load with fallback, copies under a
 * mutex, validated commits (CONFIG_CHANGED + persist), snapshot JSON for the persist writer and
 * config export, factory reset. Contract: store/config.h ("Device store").
 */
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_events.h"
#include "store/atomic_file.h"
#include "store/config.h"
#include "store/config_json.h"
#include "store/fs.h"
#include "store/persist.h"
#include "store_priv.h"

static const char *TAG = "config";

#define CFG_EVT_POST_MS 200     /* commit callers are httpd/snmp/console tasks, never gw_evt */
#define CFG_WRITE_RETRIES 3     /* consecutive failed file writes before waiting for the next change */
#define CFG_JSON_INITIAL (4096) /* serialized config is ~3 KB */

#define CFG_REV_ADOPT_MAX 0x7FFFFFFFu /* highest imported rev cfg_commit_all() adopts */

static gw_config_t s_cfg;
static StaticSemaphore_t s_mtx_buf;
static SemaphoreHandle_t s_mtx;
static portMUX_TYPE s_once = portMUX_INITIALIZER_UNLOCKED;
static bool s_loaded;
static bool s_frozen;
static uint8_t s_mac[GW_MAC_LEN];
static unsigned s_write_failures;

static void cfg_lock(void) {
    if (!s_mtx) {
        portENTER_CRITICAL(&s_once);
        if (!s_mtx)
            s_mtx = xSemaphoreCreateMutexStatic(&s_mtx_buf);
        portEXIT_CRITICAL(&s_once);
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void cfg_unlock(void) {
    xSemaphoreGive(s_mtx);
}

/* cJSON trees of large bodies (config import, PUT bodies) prefer PSRAM (ARCHITECTURE.md §6). */
static void *cjson_malloc(size_t sz) {
    return heap_caps_malloc_prefer(sz, 2, MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
}

static void post_changed(cfg_section_t s, uint32_t rev, const char *by) {
    gw_evt_config_t ev = {.section = (uint8_t)s, .rev = rev};
    gw_strlcpy(ev.by, by ? by : "", sizeof(ev.by));
    esp_err_t err = gw_events_post(GW_EVT_CONFIG_CHANGED, &ev, sizeof(ev), CFG_EVT_POST_MS);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
        ESP_LOGW(TAG, "CONFIG_CHANGED(%s) not posted: %s", cfg_section_name(s), esp_err_to_name(err));
}

/* Next revision; saturates instead of wrapping to 0 (consumers rely on it never going back). */
static uint32_t rev_next(uint32_t rev) {
    return rev < UINT32_MAX ? rev + 1 : UINT32_MAX;
}

/* ---- persist writer ---- */

static void config_writer(void *arg) {
    (void)arg;
    char *json = NULL;
    size_t len = 0;
    esp_err_t err = cfg_snapshot_json(&json, &len);
    if (err == ESP_OK)
        err = atomic_write(FS_PATH_CONFIG, json, len);
    free(json);
    if (err == ESP_OK) {
        cfg_lock();
        bool frozen = s_frozen;
        cfg_unlock();
        /* factory reset: the pre-reset configuration must not survive as gateway.json.bak */
        if (frozen && atomic_drop_backups(FS_PATH_CONFIG) != ESP_OK) {
            ESP_LOGE(TAG, "factory reset: removing the old configuration backup failed");
            err = ESP_FAIL; /* retried below */
        }
    }
    if (err == ESP_OK) {
        s_write_failures = 0;
        ESP_LOGD(TAG, "saved (%u bytes)", (unsigned)len);
        return;
    }
    ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    if (++s_write_failures < CFG_WRITE_RETRIES)
        persist_mark_dirty(PERSIST_CONFIG);
}

/* ---- load ---- */

typedef struct {
    gw_config_t *cand;
    int schema_from;
} load_ctx_t;

static bool load_accept(const char *data, size_t len, void *arg) {
    load_ctx_t *c = arg;
    cfg_verr_t err;
    int rc = cfg_from_json_ex(data, len, s_mac, c->cand, &err, &c->schema_from);
    if (rc != CFG_JSON_OK)
        ESP_LOGW(TAG, "candidate rejected (rc %d, field '%s', %s)", rc, err.field, err.code);
    return rc == CFG_JSON_OK;
}

esp_err_t config_load(void) {
    static const char *const src_name[] = {"none", "main", "tmp", "bak"};
    cJSON_Hooks hooks = {.malloc_fn = cjson_malloc, .free_fn = free};
    cJSON_InitHooks(&hooks);
    if (esp_efuse_mac_get_default(s_mac) != ESP_OK)
        ESP_LOGW(TAG, "base MAC unavailable; identity defaults use 00:00:00:00:00:00");
    esp_err_t reg = persist_register(PERSIST_CONFIG, config_writer, NULL);
    if (reg != ESP_OK)
        ESP_LOGE(TAG, "persist_register: %s", esp_err_to_name(reg));

    gw_config_t *cand = malloc(sizeof(*cand));
    if (!cand) {
        cfg_lock();
        cfg_defaults(&s_cfg, s_mac);
        s_loaded = true;
        cfg_unlock();
        return ESP_ERR_NO_MEM;
    }
    load_ctx_t ctx = {.cand = cand, .schema_from = 0};
    char *buf = NULL;
    size_t len = 0;
    atomic_src_t src = ATOMIC_SRC_NONE;
    esp_err_t err = atomic_read(FS_PATH_CONFIG, FS_CONFIG_MAX, load_accept, &ctx, &buf, &len, &src);
    free(buf);
    bool rewrite = false;
    cfg_lock();
    if (err == ESP_OK) {
        s_cfg = *cand;
        rewrite = src != ATOMIC_SRC_MAIN || ctx.schema_from < CFG_SCHEMA_VERSION;
        ESP_LOGI(TAG, "loaded from %s (schema %d, rev %u)", src_name[src], ctx.schema_from, (unsigned)s_cfg.rev);
    } else {
        cfg_defaults(&s_cfg, s_mac);
        rewrite = true;
        ESP_LOGW(TAG, "no valid configuration file (%s): factory defaults", esp_err_to_name(err));
    }
    s_loaded = true;
    cfg_unlock();
    free(cand);
    if (rewrite)
        persist_mark_dirty(PERSIST_CONFIG);
    return err == ESP_ERR_NO_MEM ? ESP_ERR_NO_MEM : ESP_OK;
}

/* ---- readers ---- */

/* Before config_load() (programming error) callers still get a valid configuration. */
static void ensure_loaded_locked(void) {
    if (!s_loaded) {
        cfg_defaults(&s_cfg, s_mac);
        s_loaded = true;
    }
}

void cfg_get(gw_config_t *out) {
    if (!out)
        return;
    cfg_lock();
    ensure_loaded_locked();
    *out = s_cfg;
    cfg_unlock();
}

esp_err_t cfg_get_section(cfg_section_t s, void *out, size_t out_size) {
    size_t sz = cfg_section_size(s);
    if (!out || sz == 0)
        return ESP_ERR_INVALID_ARG;
    if (out_size != sz)
        return ESP_ERR_INVALID_SIZE;
    cfg_lock();
    ensure_loaded_locked();
    memcpy(out, cfg_section_cptr(&s_cfg, s), sz);
    cfg_unlock();
    return ESP_OK;
}

uint32_t cfg_rev(void) {
    cfg_lock();
    uint32_t r = s_cfg.rev;
    cfg_unlock();
    return r;
}

/* ---- commits ---- */

esp_err_t cfg_commit(cfg_section_t s, const void *sec, size_t size, const char *by, cfg_verr_t *err) {
    size_t sz = cfg_section_size(s);
    if (!sec || sz == 0)
        return ESP_ERR_INVALID_ARG;
    if (size != sz)
        return ESP_ERR_INVALID_SIZE;
    cfg_lock();
    ensure_loaded_locked();
    if (s_frozen) {
        cfg_unlock();
        return ESP_ERR_INVALID_STATE;
    }
    if (memcmp(cfg_section_cptr(&s_cfg, s), sec, sz) == 0) {
        cfg_unlock();
        return ESP_OK;
    }
    if (!cfg_validate_with(&s_cfg, s, sec, err)) {
        cfg_unlock();
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(cfg_section_ptr(&s_cfg, s), sec, sz);
    uint32_t rev = s_cfg.rev = rev_next(s_cfg.rev);
    cfg_unlock();
    ESP_LOGI(TAG, "%s committed by %s (rev %u)", cfg_section_name(s), by ? by : "-", (unsigned)rev);
    persist_mark_dirty(PERSIST_CONFIG);
    post_changed(s, rev, by);
    return ESP_OK;
}

esp_err_t cfg_commit_all(const gw_config_t *c, const char *by, cfg_verr_t *err) {
    if (!c)
        return ESP_ERR_INVALID_ARG;
    if (!cfg_validate(c, err))
        return ESP_ERR_INVALID_ARG;
    uint32_t changed = 0;
    cfg_lock();
    ensure_loaded_locked();
    if (s_frozen) {
        cfg_unlock();
        return ESP_ERR_INVALID_STATE;
    }
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++)
        if (memcmp(cfg_section_cptr(&s_cfg, (cfg_section_t)s), cfg_section_cptr(c, (cfg_section_t)s),
                   cfg_section_size((cfg_section_t)s)) != 0)
            changed |= 1u << s;
    /* rev = max(current, imported) + 1, but the revision must stay monotonic: an imported rev above
     * CFG_REV_ADOPT_MAX is not adopted (it would leave no room before wrapping). */
    uint32_t base = s_cfg.rev;
    if (c->rev > base && c->rev <= CFG_REV_ADOPT_MAX)
        base = c->rev;
    uint32_t rev = rev_next(base);
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++)
        memcpy(cfg_section_ptr(&s_cfg, (cfg_section_t)s), cfg_section_cptr(c, (cfg_section_t)s),
               cfg_section_size((cfg_section_t)s));
    s_cfg.schema = CFG_SCHEMA_VERSION;
    s_cfg.rev = rev;
    cfg_unlock();
    ESP_LOGI(TAG, "configuration replaced by %s (rev %u, changed 0x%02x)", by ? by : "-", (unsigned)rev,
             (unsigned)changed);
    persist_mark_dirty(PERSIST_CONFIG);
    for (unsigned s = 0; s < CFG_SEC_COUNT; s++)
        if (changed & (1u << s))
            post_changed((cfg_section_t)s, rev, by);
    return ESP_OK;
}

esp_err_t cfg_snapshot_json(char **out, size_t *len) {
    if (!out)
        return ESP_ERR_INVALID_ARG;
    *out = NULL;
    if (len)
        *len = 0;
    gw_config_t *copy = malloc(sizeof(*copy));
    if (!copy)
        return ESP_ERR_NO_MEM;
    cfg_get(copy);
    gw_jw_t w;
    if (gw_jw_init_dynamic(&w, CFG_JSON_INITIAL, FS_CONFIG_MAX) != GW_JW_OK) {
        free(copy);
        return ESP_ERR_NO_MEM;
    }
    int rc = cfg_to_json(copy, NULL, &w);
    int jrc = gw_jw_finish(&w);
    free(copy);
    if (rc != CFG_JSON_OK || jrc != GW_JW_OK) {
        gw_jw_free(&w);
        return jrc == GW_JW_E_NO_MEM ? ESP_ERR_NO_MEM : ESP_ERR_INVALID_SIZE;
    }
    size_t n = 0;
    *out = gw_jw_detach(&w, &n);
    if (len)
        *len = n;
    return *out ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t config_factory_reset(bool keep_network) {
    cfg_network_t net;
    cfg_lock();
    ensure_loaded_locked();
    net = s_cfg.network;
    uint32_t rev = s_cfg.rev;
    cfg_defaults(&s_cfg, s_mac);
    if (keep_network)
        s_cfg.network = net;
    s_cfg.rev = rev_next(rev);
    s_frozen = true;
    cfg_unlock();
    ESP_LOGW(TAG, "factory reset (keep_network=%d): store frozen until reboot", (int)keep_network);
    persist_mark_dirty(PERSIST_CONFIG);
    return ESP_OK;
}
