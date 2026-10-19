/* Factory reset (sysmgr.h sys_factory_reset) using only the store factory-reset APIs, then erase NVS
 * namespace GW_NVS_NS (GW_NVS_NS_FACTORY with the factory AP PSK and the boot counter survives) and
 * reboot (persist is flushed first by sys_reboot). Callable from httpd (web), the supervisor (BOOT >= 10 s) and the
 * console. */
#include <stdatomic.h>

#include "esp_core_dump.h"
#include "esp_log.h"
#include "gw_core/gw_defs.h"
#include "gw_core/gw_events.h"
#include "nvs.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/history.h"
#include "store/secrets.h"
#include "sysmgr/sysmgr.h"
#include "sysmgr_priv.h"

static const char *TAG = "factory_reset";

static atomic_bool s_done;

bool sys_factory_reset_pending(void) {
    return atomic_load(&s_done);
}

static esp_err_t erase_nvs_ns(void) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(GW_NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK; /* nothing stored yet */
    }
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_erase_all(h);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t sys_factory_reset(bool keep_network, const char *by) {
    if (sys_reboot_pending() || atomic_exchange(&s_done, true)) {
        return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGW(TAG, "factory reset by %s (keep network: %s)", by ? by : "-", keep_network ? "yes" : "no");
    /* Audit first: the logs are wiped below unless the network (and logs) are kept. */
    evlog_audit(AUD_FACTORY_RESET, EVLOG_DEV_NONE, 0, keep_network ? 1 : 0, by, 0);

    esp_err_t err = config_factory_reset(keep_network);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "config reset: %s", esp_err_to_name(err));
    }
    esp_err_t e2 = secrets_factory_reset();
    if (e2 != ESP_OK) {
        ESP_LOGE(TAG, "secrets reset: %s", esp_err_to_name(e2));
        err = err == ESP_OK ? e2 : err;
    }
    if (!keep_network) {
        e2 = evlog_factory_reset();
        if (e2 != ESP_OK) {
            ESP_LOGE(TAG, "event log reset: %s", esp_err_to_name(e2));
        }
        e2 = history_factory_reset();
        if (e2 != ESP_OK) {
            ESP_LOGE(TAG, "history reset: %s", esp_err_to_name(e2));
        }
    }
    e2 = erase_nvs_ns();
    if (e2 != ESP_OK) {
        ESP_LOGE(TAG, "NVS namespace \"%s\" erase: %s", GW_NVS_NS, esp_err_to_name(e2));
        err = err == ESP_OK ? e2 : err;
    }
    /* A stored core dump is a RAM image (password hashes, SNMP keys, session tokens, AP PSK): it
     * must not survive a reset meant to wipe secrets. Erases the whole coredump partition;
     * ESP_ERR_NOT_FOUND/INVALID_SIZE: no usable coredump partition, so nothing to wipe. */
    e2 = esp_core_dump_image_erase();
    if (e2 != ESP_OK && e2 != ESP_ERR_NOT_FOUND && e2 != ESP_ERR_INVALID_SIZE) {
        ESP_LOGE(TAG, "core dump erase: %s", esp_err_to_name(e2));
        err = err == ESP_OK ? e2 : err;
    }
    /* The stores are frozen now; reboot even after a partial failure so the device never keeps
     * running half-reset. The persist flush in sys_reboot writes the default files. */
    e2 = sys_reboot(GW_REBOOT_FACTORY_RESET, SYS_OTA_REBOOT_DELAY_MS, by);
    if (e2 != ESP_OK) {
        ESP_LOGE(TAG, "reboot not scheduled: %s", esp_err_to_name(e2));
        return e2;
    }
    /* sysmgr.h: "returns once scheduled". The reset is running and the device reboots; a partial
     * store failure is in the log above, not a reason to tell the operator it failed. */
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "factory reset completed with errors (%s); rebooting", esp_err_to_name(err));
    }
    return ESP_OK;
}
