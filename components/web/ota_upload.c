/* POST /system/firmware (docs/API.md §4.10, DESIGN.md §6): streamed upload into the next OTA slot
 * through the sysmgr OTA writer, which hashes while writing and checks SHA-256, project name, chip
 * and version in sys_ota_end(). Runs on the httpd task (RAW_BODY route): the body is never buffered;
 * a 4 KB internal-RAM chunk feeds esp_ota_write. */
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "gw_core/gw_b64.h"
#include "gw_core/gw_health.h"
#include "sysmgr/sysmgr.h"
#include "web_priv.h"

static const char *TAG = "ota_upload";

#define OTA_CHUNK 4096

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

    char *buf = heap_caps_malloc(OTA_CHUNK, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf) {
        return refuse(web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL));
    }
    sys_ota_t *ota = NULL;
    esp_err_t e = sys_ota_begin(len, sha, allow_downgrade, web_user(c), &ota);
    if (e != ESP_OK) {
        free(buf);
        switch (e) {
        case ESP_ERR_INVALID_STATE:
            return refuse(web_send_error(c, 423, WEB_E_LOCKED,
                                         running_pending_verify()
                                             ? "firmware still being validated, retry shortly"
                                             : "an upload is in progress or a reboot is pending, retry shortly",
                                         NULL));
        case ESP_ERR_INVALID_SIZE:
            return refuse(len < 1024 ? web_send_error(c, 422, WEB_E_IMAGE_INVALID, "image too small", NULL)
                                     : web_send_error(c, 413, WEB_E_TOO_LARGE, "image larger than the OTA slot",
                                                      NULL));
        default:
            return refuse(web_send_esp_err(c, e));
        }
    }
    ESP_LOGI(TAG, "upload of %u bytes by %s", (unsigned)len, web_user(c));
    size_t done = 0;
    while (done < len) {
        size_t want = len - done < OTA_CHUNK ? len - done : OTA_CHUNK;
        int r = web_body_read(c, buf, want);
        if (r <= 0) {
            ESP_LOGW(TAG, "upload aborted after %u bytes (receive error)", (unsigned)done);
            sys_ota_abort(ota);
            free(buf);
            return ESP_FAIL; /* connection is broken: nothing can be sent */
        }
        e = sys_ota_write(ota, buf, (size_t)r);
        if (e != ESP_OK) {
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
    free(buf);
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
        return web_send_error(c, 422, WEB_E_HASH_MISMATCH, "SHA-256 does not match X-Firmware-SHA256", NULL);
    case ESP_ERR_INVALID_VERSION:
        return web_send_error(c, 422, WEB_E_IMAGE_INVALID, "wrong project, chip or a downgrade", NULL);
    case ESP_ERR_OTA_VALIDATE_FAILED:
        return web_send_error(c, 422, WEB_E_IMAGE_INVALID, "corrupt image", NULL);
    default:
        return web_send_esp_err(c, e);
    }
}
