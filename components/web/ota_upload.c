/* POST /system/firmware: stream GWOTA1 to the inactive app/LittleFS pair. App validation stays in
 * sysmgr; web readback, filesystem mount and pair identity are verified before committing boot.
 * One 4 KiB internal buffer is reused for reception and readback. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_heap_caps.h"
#include "esp_littlefs.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "gw_core/gw_b64.h"
#include "gw_core/gw_health.h"
#include "gw_core/gw_crypto.h"
#include "sysmgr/sysmgr.h"
#include "web/ota_package.h"
#include "web_priv.h"

static const char *TAG = "ota_upload";

#define OTA_CHUNK 4096
#ifndef WEB_CHECK_BASE
#define WEB_CHECK_BASE "/webcheck"
#endif

static bool read_exact(web_ctx_t *c, void *data, size_t len) {
    size_t done = 0;
    while (done < len) {
        int n = web_body_read(c, (char *)data + done, len - done);
        if (n <= 0)
            return false;
        done += (size_t)n;
        gw_hb_beat(GW_HB_HTTPD);
    }
    return true;
}

/* Verify bytes read back from flash, then check the filesystem identity is present in the new
 * application's rodata. A mismatched pair never becomes bootable, even if individually valid. */
static esp_err_t verify_web(const esp_partition_t *web, const esp_partition_t *app, size_t app_len,
                            const uint8_t expected[32], char *buf) {
    gw_hash_ctx_t *hash = gw_hash_begin(GW_HASH_SHA256);
    if (!hash)
        return ESP_ERR_NO_MEM;
    for (size_t pos = 0; pos < web->size; pos += OTA_CHUNK) {
        if (esp_partition_read(web, pos, buf, OTA_CHUNK) != ESP_OK ||
            gw_hash_update(hash, buf, OTA_CHUNK) != GW_CRYPTO_OK) {
            gw_hash_abort(hash);
            return ESP_FAIL;
        }
        gw_hb_beat(GW_HB_HTTPD);
    }
    uint8_t digest[32];
    if (gw_hash_finish(hash, digest) != GW_CRYPTO_OK || !gw_ct_equal(digest, expected, 32))
        return ESP_ERR_INVALID_CRC;
    const esp_vfs_littlefs_conf_t conf = {
        .base_path = WEB_CHECK_BASE,
        .partition_label = web->label,
        .format_if_mount_failed = false,
        .read_only = true,
    };
    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK)
        return ESP_ERR_OTA_VALIDATE_FAILED;
    char id[75];
    FILE *f = fopen(WEB_CHECK_BASE "/.asset-id", "rb");
    const size_t n = f ? fread(id, 1, sizeof(id), f) : 0;
    if (f)
        fclose(f);
    esp_vfs_littlefs_unregister(web->label);
    if (n != 74 || memcmp(id, "GW_WEB_ID:", 10) != 0)
        return ESP_ERR_OTA_VALIDATE_FAILED;
    id[74] = '\0';
    size_t carry = 0;
    for (size_t pos = 0; pos < app_len;) {
        size_t take = app_len - pos < OTA_CHUNK - carry ? app_len - pos : OTA_CHUNK - carry;
        if (esp_partition_read(app, pos, buf + carry, take) != ESP_OK)
            return ESP_FAIL;
        size_t have = carry + take;
        for (size_t i = 0; i + sizeof(id) <= have; i++)
            if (memcmp(buf + i, id, sizeof(id)) == 0)
                return ESP_OK;
        carry = have < sizeof(id) - 1 ? have : sizeof(id) - 1;
        memmove(buf, buf + have - carry, carry);
        pos += take;
        gw_hb_beat(GW_HB_HTTPD);
    }
    return ESP_ERR_OTA_VALIDATE_FAILED;
}

/* Refusals before the body is consumed: answer, then fail so the router closes the connection
 * instead of letting httpd drain up to 3 MB on the httpd task. */
static esp_err_t refuse(esp_err_t sent) {
    (void)sent;
    return ESP_FAIL;
}

/* sys_ota_begin() ESP_ERR_INVALID_STATE also covers "running image not yet marked valid". */
static bool running_pending_verify(void) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    return run && esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY;
}

esp_err_t h_firmware_upload(web_ctx_t *c) {
    char ct[64];
    if (!web_header(c, "Content-Type", ct, sizeof(ct)) || !web_ct_is_octet(ct)) {
        return refuse(
            web_send_error(c, 400, WEB_E_BAD_REQUEST, "Content-Type must be application/octet-stream", NULL));
    }
    const size_t len = c->req->content_len;
    if (!len) {
        return refuse(web_send_error(c, 400, WEB_E_BAD_REQUEST, "Content-Length required", NULL));
    }
    char hex[72];
    uint8_t sha[32];
    if (!web_header(c, "X-Firmware-SHA256", hex, sizeof(hex)) || strlen(hex) != 64 ||
        gw_hex_decode(hex, 64, sha, sizeof(sha)) != 32) {
        return refuse(
            web_send_error(c, 400, WEB_E_BAD_REQUEST, "X-Firmware-SHA256 must be 64 hex digits", NULL));
    }
    bool allow_downgrade = false;
    if (web_query_bool(c, "allow_downgrade", &allow_downgrade) == WEB_Q_INVALID) {
        return refuse(web_send_error(c, 400, WEB_E_BAD_REQUEST, "allow_downgrade must be 0/1", NULL));
    }

    uint8_t header[WEB_OTA_HEADER_SIZE];
    if (len < sizeof(header))
        return refuse(
            web_send_error(c, 422, WEB_E_IMAGE_INVALID, "upload the .gwota firmware and web package", NULL));
    if (!read_exact(c, header, sizeof(header)))
        return ESP_FAIL;
    if (!web_ota_header_valid(header, len))
        return refuse(web_send_error(c, 422, WEB_E_IMAGE_INVALID,
                                     "invalid .gwota package; a standalone .bin is not supported", NULL));
    const size_t app_len = web_ota_u32(header + 8);
    const esp_partition_t *app = esp_ota_get_next_update_partition(NULL);
    const char *label = app && app->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0   ? "web_0"
                        : app && app->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1 ? "web_1"
                                                                                 : NULL;
    const esp_partition_t *web =
        label ? esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_LITTLEFS, label)
              : NULL;
    if (!web || web->size != WEB_OTA_FS_SIZE || app_len > app->size)
        return refuse(web_send_error(c, 422, WEB_E_IMAGE_INVALID,
                                     "partition layout does not support this package", NULL));
    char *buf = heap_caps_malloc(OTA_CHUNK, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf) {
        return refuse(web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL));
    }
    sys_ota_t *ota = NULL;
    esp_err_t e = sys_ota_begin(app_len, header + 16, allow_downgrade, web_user(c), &ota);
    if (e != ESP_OK) {
        free(buf);
        switch (e) {
        case ESP_ERR_INVALID_STATE:
            return refuse(web_send_error(
                c, 423, WEB_E_LOCKED,
                running_pending_verify() ? "firmware still being validated, retry shortly"
                                         : "an upload is in progress or a reboot is pending, retry shortly",
                NULL));
        case ESP_ERR_INVALID_SIZE:
            return refuse(
                len < 1024 ? web_send_error(c, 422, WEB_E_IMAGE_INVALID, "image too small", NULL)
                           : web_send_error(c, 413, WEB_E_TOO_LARGE, "image larger than the OTA slot", NULL));
        default:
            return refuse(web_send_esp_err(c, e));
        }
    }
    gw_hash_ctx_t *hash = gw_hash_begin(GW_HASH_SHA256);
    if (!hash || gw_hash_update(hash, header, sizeof(header)) != GW_CRYPTO_OK) {
        gw_hash_abort(hash);
        sys_ota_abort(ota);
        free(buf);
        return refuse(web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL));
    }
    ESP_LOGI(TAG, "package of %u bytes into %s/%s by %s", (unsigned)len, app->label, label, web_user(c));
    size_t done = sizeof(header), app_done = 0, web_done = 0, erased = 0;
    while (done < len) {
        size_t remaining = app_done < app_len ? app_len - app_done : WEB_OTA_FS_SIZE - web_done;
        size_t want = remaining < OTA_CHUNK ? remaining : OTA_CHUNK;
        int r = web_body_read(c, buf, want);
        if (r <= 0) {
            ESP_LOGW(TAG, "upload aborted after %u bytes (receive error)", (unsigned)done);
            sys_ota_abort(ota);
            gw_hash_abort(hash);
            free(buf);
            return ESP_FAIL; /* connection is broken: nothing can be sent */
        }
        if (gw_hash_update(hash, buf, (size_t)r) != GW_CRYPTO_OK) {
            sys_ota_abort(ota);
            ota = NULL;
            e = ESP_FAIL;
        } else if (app_done < app_len) {
            e = sys_ota_write(ota, buf, (size_t)r);
            app_done += (size_t)r;
            if (e != ESP_OK)
                ota = NULL; /* writer freed the failed session */
        } else {
            e = ESP_OK;
            while (erased < web_done + (size_t)r && e == ESP_OK) {
                e = esp_partition_erase_range(web, erased, OTA_CHUNK);
                erased += OTA_CHUNK;
            }
            if (e == ESP_OK)
                e = esp_partition_write(web, web_done, buf, (size_t)r);
            web_done += (size_t)r;
        }
        if (e != ESP_OK) {
            if (ota)
                sys_ota_abort(ota);
            gw_hash_abort(hash);
            /* sys_ota_write aborted and freed the session */
            ESP_LOGE(TAG, "write failed at %u: %s", (unsigned)done, esp_err_to_name(e));
            free(buf);
            if (e == ESP_ERR_OTA_VALIDATE_FAILED || e == ESP_ERR_INVALID_VERSION) {
                (void)web_send_error(c, 422, WEB_E_IMAGE_INVALID, "not a valid firmware image", NULL);
            } else {
                (void)web_send_error(c, 500, WEB_E_INTERNAL, "flash write failed", NULL);
            }
            /* The rest of the body (up to 3 MB) must not be drained on the httpd task: an error after
             * the reply makes the router return ESP_FAIL, so httpd deletes the session at once. */
            return ESP_FAIL;
        }
        done += (size_t)r;
        gw_hb_beat(GW_HB_HTTPD); /* the httpd task is busy here, but alive */
    }
    uint8_t digest[32];
    e = gw_hash_finish(hash, digest) == GW_CRYPTO_OK && gw_ct_equal(digest, sha, 32) ? ESP_OK
                                                                                     : ESP_ERR_INVALID_CRC;
    if (e == ESP_OK)
        e = verify_web(web, app, app_len, header + 48, buf);
    free(buf);
    if (e != ESP_OK) {
        sys_ota_abort(ota);
        return e == ESP_ERR_INVALID_CRC
                   ? web_send_error(c, 422, WEB_E_HASH_MISMATCH, "package or web image SHA-256 mismatch",
                                    NULL)
                   : web_send_error(c, 422, WEB_E_IMAGE_INVALID,
                                    "invalid LittleFS image or mismatched firmware/web pair", NULL);
    }
    char version[GW_VERSION_SZ] = {0};
    e = sys_ota_end(ota, version);
    switch (e) {
    case ESP_OK: {
        char body[96];
        gw_jw_t w;
        gw_jw_init_fixed(&w, body, sizeof(body));
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "version", version);
        gw_jw_kuint(&w, "reboot_in_s", (SYS_OTA_REBOOT_DELAY_MS + 999u) / 1000u);
        gw_jw_obj_close(&w);
        ESP_LOGW(TAG, "firmware %s accepted, rebooting", version);
        return web_send_jw(c, 200, &w);
    }
    case ESP_ERR_INVALID_CRC:
        return web_send_error(c, 422, WEB_E_HASH_MISMATCH,
                              "application SHA-256 does not match package header", NULL);
    case ESP_ERR_INVALID_VERSION:
        return web_send_error(c, 422, WEB_E_IMAGE_INVALID, "wrong project, chip or a downgrade", NULL);
    case ESP_ERR_OTA_VALIDATE_FAILED:
        return web_send_error(c, 422, WEB_E_IMAGE_INVALID, "corrupt image", NULL);
    default:
        return web_send_esp_err(c, e);
    }
}
