/*
 * secrets_store.c - the in-RAM secrets store (device): factory AP PSK in NVS, load with fallback,
 * atomic modifications under a mutex, persist writer with wiped buffers, factory reset.
 * Contract: store/secrets.h ("Device store").
 */
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_ident.h"
#include "nvs.h"
#include "store/atomic_file.h"
#include "store/config_json.h"
#include "store/fs.h"
#include "store/persist.h"
#include "store/secrets.h"
#include "store_priv.h"

static const char *TAG = "secrets";

#define SEC_EVT_POST_MS 200
#define SEC_WRITE_RETRIES 3

static gw_secrets_t s_sec;
static gw_secrets_t s_scratch; /* secrets_modify() working copy; wiped after every use */
static char s_factory_psk[GW_PSK_SZ];
static StaticSemaphore_t s_mtx_buf;
static SemaphoreHandle_t s_mtx;
static portMUX_TYPE s_once = portMUX_INITIALIZER_UNLOCKED;
static bool s_loaded;
static bool s_frozen;
static unsigned s_write_failures;

static void sec_lock(void) {
    if (!s_mtx) {
        portENTER_CRITICAL(&s_once);
        if (!s_mtx)
            s_mtx = xSemaphoreCreateMutexStatic(&s_mtx_buf);
        portEXIT_CRITICAL(&s_once);
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void sec_unlock(void) {
    xSemaphoreGive(s_mtx);
}

static bool psk_ok(const char *p) {
    return store_ascii_ok(p, GW_PSK_SZ, GW_PSK_MIN, GW_PSK_MAX, 0x20, 0x7E);
}

/* Random PSK. false when gw_random() failed: out then holds a boot-only PSK from the hardware RNG
 * (esp_fill_random) that must never be stored as the permanent factory credential. */
static bool random_psk(char out[GW_PSK_SZ]) {
    uint8_t rnd[GW_AP_PSK_RAND_LEN];
    bool ok = gw_random(rnd, sizeof(rnd)) == GW_CRYPTO_OK;
    if (!ok) {
        ESP_LOGE(TAG, "gw_random failed: hardware RNG used, AP PSK not stored");
        esp_fill_random(rnd, sizeof(rnd));
    }
    gw_ident_ap_psk_format(rnd, out);
    gw_secure_zero(rnd, sizeof(rnd));
    return ok;
}

/* Factory PSK: NVS gw_fact/ap_psk, generated once per device lifetime. */
static void load_factory_psk(void) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(GW_NVS_NS_FACTORY, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        (void)random_psk(s_factory_psk);
        ESP_LOGE(TAG, "NVS %s unavailable (%s): AP PSK for this boot only", GW_NVS_NS_FACTORY,
                 esp_err_to_name(err));
        return;
    }
    size_t sz = sizeof(s_factory_psk);
    err = nvs_get_str(h, GW_NVS_KEY_AP_PSK, s_factory_psk, &sz);
    if (err != ESP_OK || !psk_ok(s_factory_psk)) {
        if (err == ESP_OK)
            ESP_LOGE(TAG, "stored factory AP PSK invalid: regenerating");
        if (!random_psk(s_factory_psk)) {
            /* stays boot-only: the next boot generates (and stores) a proper one */
            nvs_close(h);
            return;
        }
        err = nvs_set_str(h, GW_NVS_KEY_AP_PSK, s_factory_psk);
        if (err == ESP_OK)
            err = nvs_commit(h);
        if (err != ESP_OK)
            ESP_LOGE(TAG, "storing factory AP PSK failed: %s", esp_err_to_name(err));
        else
            ESP_LOGI(TAG, "factory AP PSK generated");
    }
    nvs_close(h);
}

static void secrets_writer(void *arg) {
    (void)arg;
    gw_secrets_t *copy = malloc(sizeof(*copy));
    char *buf = malloc(FS_SECRETS_MAX);
    esp_err_t err = ESP_ERR_NO_MEM;
    if (copy && buf) {
        secrets_get(copy);
        gw_jw_t w;
        gw_jw_init_fixed(&w, buf, FS_SECRETS_MAX);
        int rc = sec_to_json(copy, &w);
        int jrc = gw_jw_finish(&w);
        if (rc == CFG_JSON_OK && jrc == GW_JW_OK)
            err = atomic_write(FS_PATH_SECRETS, buf, gw_jw_length(&w));
        else
            err = ESP_ERR_INVALID_SIZE;
    }
    if (err == ESP_OK) {
        sec_lock();
        bool frozen = s_frozen;
        sec_unlock();
        /* factory reset: old users, hashes, communities and keys must not survive in secrets.json.bak */
        if (frozen && atomic_drop_backups(FS_PATH_SECRETS) != ESP_OK) {
            ESP_LOGE(TAG, "factory reset: removing the old secrets backup failed");
            err = ESP_FAIL;
        }
    }
    if (copy) {
        gw_secure_zero(copy, sizeof(*copy));
        free(copy);
    }
    if (buf) {
        gw_secure_zero(buf, FS_SECRETS_MAX);
        free(buf);
    }
    if (err == ESP_OK) {
        s_write_failures = 0;
        return;
    }
    ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    if (++s_write_failures < SEC_WRITE_RETRIES)
        persist_mark_dirty(PERSIST_SECRETS);
}

static bool load_accept(const char *data, size_t len, void *arg) {
    int rc = sec_from_json(data, len, s_factory_psk, (gw_secrets_t *)arg);
    if (rc != CFG_JSON_OK)
        ESP_LOGW(TAG, "candidate rejected (rc %d)", rc);
    return rc == CFG_JSON_OK;
}

esp_err_t secrets_load(void) {
    static const char *const src_name[] = {"none", "main", "tmp", "bak"};
    load_factory_psk();
    esp_err_t reg = persist_register(PERSIST_SECRETS, secrets_writer, NULL);
    if (reg != ESP_OK)
        ESP_LOGE(TAG, "persist_register: %s", esp_err_to_name(reg));
    char *buf = NULL;
    size_t len = 0;
    atomic_src_t src = ATOMIC_SRC_NONE;
    sec_lock();
    esp_err_t err = atomic_read(FS_PATH_SECRETS, FS_SECRETS_MAX, load_accept, &s_scratch, &buf, &len, &src);
    if (buf) {
        gw_secure_zero(buf, len);
        free(buf);
    }
    bool rewrite;
    if (err == ESP_OK) {
        s_sec = s_scratch;
        rewrite = src != ATOMIC_SRC_MAIN;
        ESP_LOGI(TAG, "loaded from %s (%u users)", src_name[src], (unsigned)s_sec.n_users);
    } else {
        sec_defaults(&s_sec, s_factory_psk);
        rewrite = true;
        ESP_LOGW(TAG, "no valid secrets file (%s): defaults", esp_err_to_name(err));
    }
    gw_secure_zero(&s_scratch, sizeof(s_scratch));
    s_loaded = true;
    sec_unlock();
    if (rewrite)
        persist_mark_dirty(PERSIST_SECRETS);
    return err == ESP_ERR_NO_MEM ? ESP_ERR_NO_MEM : ESP_OK;
}

void secrets_factory_ap_psk(char out[GW_PSK_SZ]) {
    sec_lock();
    gw_strlcpy(out, s_factory_psk, GW_PSK_SZ);
    sec_unlock();
}

static void ensure_loaded_locked(void) {
    if (!s_loaded) {
        sec_defaults(&s_sec, s_factory_psk);
        s_loaded = true;
    }
}

void secrets_get(gw_secrets_t *out) {
    if (!out)
        return;
    sec_lock();
    ensure_loaded_locked();
    *out = s_sec;
    sec_unlock();
}

void secrets_flags(cfg_secret_flags_t *out) {
    if (!out)
        return;
    sec_lock();
    ensure_loaded_locked();
    sec_flags(&s_sec, out);
    sec_unlock();
}

esp_err_t secrets_modify(esp_err_t (*fn)(gw_secrets_t *s, void *arg), void *arg, const char *by) {
    if (!fn)
        return ESP_ERR_INVALID_ARG;
    sec_lock();
    ensure_loaded_locked();
    if (s_frozen) {
        sec_unlock();
        return ESP_ERR_INVALID_STATE;
    }
    s_scratch = s_sec;
    esp_err_t rc = fn(&s_scratch, arg);
    if (rc == ESP_OK && !sec_validate(&s_scratch))
        rc = ESP_ERR_INVALID_ARG;
    if (rc == ESP_OK)
        s_sec = s_scratch;
    gw_secure_zero(&s_scratch, sizeof(s_scratch));
    sec_unlock();
    if (rc != ESP_OK)
        return rc;
    persist_mark_dirty(PERSIST_SECRETS);
    gw_evt_config_t ev = {.section = CFG_SEC_SECRETS, .rev = cfg_rev()};
    gw_strlcpy(ev.by, by ? by : "", sizeof(ev.by));
    esp_err_t perr = gw_events_post(GW_EVT_CONFIG_CHANGED, &ev, sizeof(ev), SEC_EVT_POST_MS);
    if (perr != ESP_OK && perr != ESP_ERR_INVALID_STATE)
        ESP_LOGW(TAG, "CONFIG_CHANGED(secrets) not posted: %s", esp_err_to_name(perr));
    return ESP_OK;
}

esp_err_t secrets_factory_reset(void) {
    sec_lock();
    gw_secure_zero(&s_sec, sizeof(s_sec));
    sec_defaults(&s_sec, s_factory_psk);
    s_loaded = true;
    s_frozen = true;
    sec_unlock();
    ESP_LOGW(TAG, "factory reset: store frozen until reboot");
    persist_mark_dirty(PERSIST_SECRETS);
    return ESP_OK;
}
