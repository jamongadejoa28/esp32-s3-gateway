/*
 * Firmware upload, firmware info and rollback (sysmgr.h).
 *
 * Upload: sys_ota_begin -> sys_ota_write* (SHA-256 while writing; the app descriptor in the first
 * 288 bytes is checked as soon as it has arrived so a wrong image fails fast) -> sys_ota_end (hash
 * compare, esp_ota_end image validation, descriptor re-check from flash, set boot partition, audit,
 * reboot in SYS_OTA_REBOOT_DELAY_MS). esp_ota_begin(OTA_WITH_SEQUENTIAL_WRITES) erases sector by
 * sector while writing instead of blocking the caller for a whole-partition erase.
 * Images are not signed (accepted risk, DESIGN.md §14): integrity, project and version only.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "store/eventlog.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"
#include "sysmgr_pure.h"

static const char *TAG = "ota";

#define OTA_DESC_OFFSET (sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t))
#define OTA_HEAD_LEN (OTA_DESC_OFFSET + sizeof(esp_app_desc_t))

struct sys_ota {
    esp_ota_handle_t handle;
    const esp_partition_t *part;
    gw_hash_ctx_t *hash;
    uint8_t expect[GW_SHA256_LEN];
    size_t expected_len, written;
    bool allow_downgrade;
    bool head_checked;
    bool touched; /* esp_ota_write() was called: the slot's first sector no longer holds the old image */
    uint8_t head[OTA_HEAD_LEN]; /* first bytes of the image (app descriptor) */
    char by[GW_USER_NAME_SZ];
};

static atomic_bool s_active;

/* Cached "other slot is bootable" verdict (a full image verify reads the whole slot). The
 * generation is bumped whenever an upload may have changed the slot. */
static atomic_uint s_slot_gen = 1;
static portMUX_TYPE s_cache_mux = portMUX_INITIALIZER_UNLOCKED;
static struct {
    unsigned gen; /* 0: empty */
    const esp_partition_t *part;
    bool bootable;
    esp_app_desc_t desc;
} s_cache;

bool sys_ota_in_progress(void) {
    return atomic_load(&s_active);
}

static void post_ota(gw_ota_phase_t phase, esp_err_t err, const char *version, const char *by) {
    gw_evt_ota_t ev = {.phase = (uint8_t)phase, .err = err};
    gw_strlcpy(ev.version, version ? version : "", sizeof(ev.version));
    gw_strlcpy(ev.by, by ? by : "", sizeof(ev.by));
    esp_err_t e = gw_events_post(GW_EVT_OTA, &ev, sizeof(ev), gw_events_in_loop_task() ? 0 : 50);
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "OTA event dropped: %s", esp_err_to_name(e));
    }
}

/* Abort the session after a failure: discard the partial image, audit, notify, free. */
static void fail(sys_ota_t *ota, esp_err_t err) {
    if (ota->handle) {
        esp_ota_abort(ota->handle);
    }
    if (ota->touched && ota->part) {
        /* esp_ota_abort() leaves the partial image (header + app descriptor of the rejected upload)
         * and the slot's old otadata state in place, so it would still look like a rollback target.
         * Erase the first sector: no image magic -> never offered or booted. */
        const uint32_t sec = ota->part->erase_size ? ota->part->erase_size : 4096u;
        const esp_err_t e = esp_partition_erase_range(ota->part, 0, sec);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "erasing the rejected image header in %s: %s", ota->part->label, esp_err_to_name(e));
        }
    }
    atomic_fetch_add(&s_slot_gen, 1u);
    gw_hash_abort(ota->hash);
    evlog_audit(AUD_OTA_UPLOAD, EVLOG_DEV_NONE, 1, 0, ota->by, (uint32_t)err);
    post_ota(GW_OTA_FAILED, err, NULL, ota->by);
    ESP_LOGW(TAG, "upload by %s failed after %u bytes: %s", ota->by, (unsigned)ota->written, esp_err_to_name(err));
    gw_secure_zero(ota, sizeof(*ota));
    free(ota);
    atomic_store(&s_active, false);
}

static esp_err_t check_desc(const esp_app_desc_t *d, bool allow_downgrade) {
    if (d->magic_word != ESP_APP_DESC_MAGIC_WORD) {
        return ESP_ERR_INVALID_VERSION;
    }
    char project[sizeof(d->project_name) + 1], version[sizeof(d->version) + 1];
    memcpy(project, d->project_name, sizeof(d->project_name));
    project[sizeof(d->project_name)] = '\0';
    memcpy(version, d->version, sizeof(d->version));
    version[sizeof(d->version)] = '\0';
    const esp_err_t err = sys_ota_check_image(project, version, GW_PROJECT_NAME, esp_app_get_description()->version,
                                              allow_downgrade);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "image rejected: project \"%s\" version \"%s\" (running %s, downgrade %s)", project, version,
                 esp_app_get_description()->version, allow_downgrade ? "allowed" : "refused");
    }
    return err;
}

esp_err_t sys_ota_begin(size_t image_len, const uint8_t sha256[32], bool allow_downgrade, const char *by,
                        sys_ota_t **out) {
    if (!sha256 || !out) {
        return ESP_ERR_INVALID_ARG;
    }
    *out = NULL;
    if (sys_reboot_pending() || atomic_exchange(&s_active, true)) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        atomic_store(&s_active, false);
        return ESP_ERR_NOT_FOUND;
    }
    if (image_len < OTA_HEAD_LEN || image_len > part->size) {
        atomic_store(&s_active, false);
        return ESP_ERR_INVALID_SIZE;
    }
    sys_ota_t *ota = calloc(1, sizeof(*ota));
    if (!ota) {
        atomic_store(&s_active, false);
        return ESP_ERR_NO_MEM;
    }
    ota->part = part;
    ota->expected_len = image_len;
    ota->allow_downgrade = allow_downgrade;
    memcpy(ota->expect, sha256, sizeof(ota->expect));
    gw_strlcpy(ota->by, by ? by : "", sizeof(ota->by));
    ota->hash = gw_hash_begin(GW_HASH_SHA256);
    if (!ota->hash) {
        free(ota);
        atomic_store(&s_active, false);
        return ESP_ERR_NO_MEM;
    }
    /* esp_ota_begin() refuses while the running image is still PENDING_VERIFY (not yet marked valid
     * by the supervisor, up to SYS_VALID_AFTER_MS after an update). That is a "retry shortly", not an
     * internal error: answer it before opening a session (no failed-upload audit/event). */
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t run_st;
    if (run && esp_ota_get_state_partition(run, &run_st) == ESP_OK && run_st == ESP_OTA_IMG_PENDING_VERIFY) {
        gw_hash_abort(ota->hash);
        free(ota);
        atomic_store(&s_active, false);
        ESP_LOGW(TAG, "upload refused: running image not yet validated");
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &ota->handle);
    if (err == ESP_ERR_OTA_ROLLBACK_INVALID_STATE) {
        ota->handle = 0;
        gw_hash_abort(ota->hash);
        free(ota);
        atomic_store(&s_active, false);
        ESP_LOGW(TAG, "upload refused: running image not yet validated");
        return ESP_ERR_INVALID_STATE;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin(%s): %s", part->label, esp_err_to_name(err));
        ota->handle = 0;
        fail(ota, err);
        return err == ESP_ERR_NO_MEM ? err : ESP_FAIL;
    }
    ESP_LOGI(TAG, "upload of %u bytes into %s by %s", (unsigned)image_len, part->label, ota->by);
    post_ota(GW_OTA_BEGIN, ESP_OK, NULL, ota->by);
    *out = ota;
    return ESP_OK;
}

esp_err_t sys_ota_write(sys_ota_t *ota, const void *data, size_t len) {
    if (!ota || (!data && len)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return ESP_OK;
    }
    if (len > ota->expected_len - ota->written) {
        fail(ota, ESP_ERR_INVALID_SIZE);
        return ESP_ERR_INVALID_SIZE;
    }
    if (!ota->head_checked) {
        const size_t take = ota->written < OTA_HEAD_LEN ? OTA_HEAD_LEN - ota->written : 0;
        const size_t n = take < len ? take : len;
        memcpy(ota->head + ota->written, data, n);
        if (ota->written + n >= OTA_HEAD_LEN) {
            ota->head_checked = true;
            const esp_image_header_t *ih = (const esp_image_header_t *)ota->head;
            esp_app_desc_t desc;
            memcpy(&desc, ota->head + OTA_DESC_OFFSET, sizeof(desc));
            esp_err_t err = ih->magic != ESP_IMAGE_HEADER_MAGIC ? ESP_ERR_INVALID_VERSION
                                                                 : check_desc(&desc, ota->allow_downgrade);
            if (err != ESP_OK) {
                fail(ota, err);
                return err;
            }
        }
    }
    if (gw_hash_update(ota->hash, data, len) != GW_CRYPTO_OK) {
        fail(ota, ESP_FAIL);
        return ESP_FAIL;
    }
    ota->touched = true;
    atomic_fetch_add(&s_slot_gen, 1u);
    esp_err_t err = esp_ota_write(ota->handle, data, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(err));
        err = err == ESP_ERR_OTA_VALIDATE_FAILED ? ESP_ERR_INVALID_VERSION : ESP_FAIL;
        fail(ota, err);
        return err;
    }
    ota->written += len;
    return ESP_OK;
}

esp_err_t sys_ota_end(sys_ota_t *ota, char version_out[GW_VERSION_SZ]) {
    if (!ota) {
        return ESP_ERR_INVALID_ARG;
    }
    if (ota->written != ota->expected_len) {
        fail(ota, ESP_ERR_INVALID_SIZE);
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t digest[GW_SHA256_LEN];
    const int hrc = gw_hash_finish(ota->hash, digest);
    ota->hash = NULL;
    if (hrc != GW_CRYPTO_OK) {
        fail(ota, ESP_FAIL);
        return ESP_FAIL;
    }
    if (!gw_ct_equal(digest, ota->expect, sizeof(digest))) {
        fail(ota, ESP_ERR_INVALID_CRC);
        return ESP_ERR_INVALID_CRC;
    }
    esp_err_t err = esp_ota_end(ota->handle);
    ota->handle = 0; /* esp_ota_end frees the handle in every case */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(err));
        err = err == ESP_ERR_OTA_VALIDATE_FAILED ? ESP_ERR_INVALID_VERSION : ESP_FAIL;
        fail(ota, err);
        return err;
    }
    esp_app_desc_t desc;
    err = esp_ota_get_partition_description(ota->part, &desc);
    if (err == ESP_OK) {
        err = check_desc(&desc, ota->allow_downgrade);
    } else {
        err = ESP_ERR_INVALID_VERSION;
    }
    if (err != ESP_OK) {
        fail(ota, err);
        return err;
    }
    err = esp_ota_set_boot_partition(ota->part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set boot partition: %s", esp_err_to_name(err));
        fail(ota, ESP_FAIL);
        return ESP_FAIL;
    }
    char version[GW_VERSION_SZ];
    memcpy(version, desc.version, sizeof(version) - 1);
    version[sizeof(version) - 1] = '\0';
    char by[GW_USER_NAME_SZ];
    gw_strlcpy(by, ota->by, sizeof(by));
    ESP_LOGW(TAG, "firmware %s written to %s by %s; rebooting", version, ota->part->label, by);
    gw_secure_zero(ota, sizeof(*ota));
    free(ota);
    atomic_fetch_add(&s_slot_gen, 1u);

    evlog_audit(AUD_OTA_UPLOAD, EVLOG_DEV_NONE, 0, 0, by, 0);
    post_ota(GW_OTA_DONE, ESP_OK, version, by);
    if (version_out) {
        gw_strlcpy(version_out, version, GW_VERSION_SZ);
    }
    atomic_store(&s_active, false);
    err = sys_reboot(GW_REBOOT_OTA, SYS_OTA_REBOOT_DELAY_MS, by);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "reboot already scheduled (%s): the new image boots with it", esp_err_to_name(err));
    }
    return ESP_OK;
}

void sys_ota_abort(sys_ota_t *ota) {
    if (ota) {
        fail(ota, ESP_ERR_INVALID_STATE);
    }
}

static const char *state_name(const esp_partition_t *p) {
    esp_ota_img_states_t st;
    if (!p || esp_ota_get_state_partition(p, &st) != ESP_OK) {
        return "undefined";
    }
    switch (st) {
    case ESP_OTA_IMG_NEW:
        return "new";
    case ESP_OTA_IMG_PENDING_VERIFY:
        return "pending_verify";
    case ESP_OTA_IMG_VALID:
        return "valid";
    case ESP_OTA_IMG_INVALID:
        return "invalid";
    case ESP_OTA_IMG_ABORTED:
        return "aborted";
    default:
        return "undefined";
    }
}

/* Full check, uncached: descriptor readable and of this project, otadata state not
 * INVALID/ABORTED, and the whole image verifies (segments + checksum + appended SHA-256, the same
 * check esp_ota_set_boot_partition() makes), so a slot left half-written (power loss during an
 * upload) or holding a foreign image is never offered as a rollback target. */
static bool other_bootable_uncached(const esp_partition_t *other, esp_app_desc_t *desc) {
    if (!other || esp_ota_get_partition_description(other, desc) != ESP_OK) {
        return false;
    }
    if (strncmp(desc->project_name, GW_PROJECT_NAME, sizeof(desc->project_name)) != 0) {
        return false;
    }
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(other, &st) == ESP_OK &&
        (st == ESP_OTA_IMG_INVALID || st == ESP_OTA_IMG_ABORTED)) {
        return false;
    }
    esp_image_metadata_t *md = malloc(sizeof(*md)); /* ~0.3 KiB: keep it off the httpd stack */
    if (!md) {
        return false;
    }
    const esp_partition_pos_t pos = {.offset = other->address, .size = other->size};
    const esp_err_t err = esp_image_verify(ESP_IMAGE_VERIFY_SILENT, &pos, md);
    free(md);
    return err == ESP_OK;
}

/* Cached by slot generation; *desc is filled whenever the descriptor was readable. */
static bool other_bootable(const esp_partition_t *other, esp_app_desc_t *desc) {
    if (!other) {
        return false;
    }
    const unsigned gen = atomic_load(&s_slot_gen);
    taskENTER_CRITICAL(&s_cache_mux);
    const bool hit = s_cache.gen == gen && s_cache.part == other;
    bool ok = s_cache.bootable;
    if (hit) {
        *desc = s_cache.desc;
    }
    taskEXIT_CRITICAL(&s_cache_mux);
    if (hit) {
        return ok;
    }
    memset(desc, 0, sizeof(*desc));
    ok = other_bootable_uncached(other, desc);
    if (atomic_load(&s_slot_gen) == gen) { /* no upload touched the slot meanwhile */
        taskENTER_CRITICAL(&s_cache_mux);
        s_cache.gen = gen;
        s_cache.part = other;
        s_cache.bootable = ok;
        s_cache.desc = *desc;
        taskEXIT_CRITICAL(&s_cache_mux);
    }
    return ok;
}

esp_err_t sys_fw_info(sys_fw_info_t *out) {
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    const esp_partition_t *run = esp_ota_get_running_partition();
    if (!run) {
        return ESP_ERR_NOT_FOUND;
    }
    gw_strlcpy(out->running_slot, run->label, sizeof(out->running_slot));
    gw_strlcpy(out->running_version, esp_app_get_description()->version, sizeof(out->running_version));
    gw_strlcpy(out->running_state, state_name(run), sizeof(out->running_state));
    const esp_partition_t *other = esp_ota_get_next_update_partition(NULL);
    if (other) {
        gw_strlcpy(out->other_slot, other->label, sizeof(out->other_slot));
        esp_app_desc_t desc;
        memset(&desc, 0, sizeof(desc));
        out->other_valid = other_bootable(other, &desc);
        if (desc.magic_word == ESP_APP_DESC_MAGIC_WORD) {
            memcpy(out->other_version, desc.version, sizeof(out->other_version) - 1);
            out->other_version[sizeof(out->other_version) - 1] = '\0';
        }
    }
    return ESP_OK;
}

esp_err_t sys_rollback(const char *by) {
    if (sys_reboot_pending() || sys_ota_in_progress()) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_partition_t *other = esp_ota_get_next_update_partition(NULL);
    esp_app_desc_t desc;
    if (!other_bootable(other, &desc)) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t err = esp_ota_set_boot_partition(other);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rollback to %s: %s", other->label, esp_err_to_name(err));
        return err == ESP_ERR_OTA_VALIDATE_FAILED ? ESP_ERR_NOT_FOUND : ESP_FAIL;
    }
    char version[GW_VERSION_SZ];
    memcpy(version, desc.version, sizeof(version) - 1);
    version[sizeof(version) - 1] = '\0';
    ESP_LOGW(TAG, "rollback to %s (%s) by %s", other->label, version, by ? by : "-");
    evlog_audit(AUD_ROLLBACK, EVLOG_DEV_NONE, 0, 0, by, 0);
    post_ota(GW_OTA_ROLLBACK, ESP_OK, version, by);
    return sys_reboot(GW_REBOOT_ROLLBACK, SYS_OTA_REBOOT_DELAY_MS, by);
}
