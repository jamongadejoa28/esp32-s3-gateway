/* SNMP MIB module registry (contract: snmp_gw/registry.h). snmp_gw_pen()/snmp_gw_oid() are pure and
 * live in snmp_logic.c (host-tested). */
#include "snmp_gw/registry.h"

#include <string.h>

#include "esp_log.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_snmpv2_framework.h"
#include "lwip/apps/snmp_snmpv2_usm.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static const char *TAG = "snmp_reg";

static const snmp_module_t *s_mods[SNMP_GW_MAX_MODULES];
static uint8_t s_n_mods;
static bool s_started;
static const struct snmp_mib *s_mibs[SNMP_GW_MAX_MODULES];
static struct snmp_obj_id s_device_oid; /* sysObjectID: …PEN.1.1 (gwInfo) */

esp_err_t snmp_registry_add(const snmp_module_t *m) {
    if (m == NULL || m->mib == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    for (uint8_t i = 0; i < s_n_mods; i++) {
        if (s_mods[i] == m) {
            return ESP_OK; /* idempotent */
        }
    }
    if (s_n_mods >= SNMP_GW_MAX_MODULES) {
        return ESP_ERR_NO_MEM;
    }
    s_mods[s_n_mods++] = m;
    return ESP_OK;
}

esp_err_t snmp_registry_start(void) {
    if (!snmp_transport_in_agent_thread()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t n = 0;
    for (uint8_t i = 0; i < s_n_mods; i++) {
        const snmp_module_t *m = s_mods[i];
        esp_err_t err = m->init ? m->init() : ESP_OK;
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "module %s: init failed (%s); not served", m->name ? m->name : "?", esp_err_to_name(err));
            continue;
        }
        if (m->mib->base_oid == NULL || m->mib->base_oid_len == 0 || m->mib->root_node == NULL) {
            ESP_LOGE(TAG, "module %s: no base OID after init; not served", m->name ? m->name : "?");
            continue;
        }
        s_mibs[n++] = m->mib;
    }

    const uint32_t gw_info[] = {GWMIB_gwInfo};
    size_t len = snmp_gw_oid(gw_info, 1, s_device_oid.id, SNMP_MAX_OBJ_ID_LEN);
    if (len == 0) {
        return ESP_ERR_INVALID_SIZE;
    }
    s_device_oid.len = (u8_t)len;
    snmp_set_device_enterprise_oid(&s_device_oid);
    snmp_set_mibs(s_mibs, n);
    s_started = true;
    ESP_LOGI(TAG, "%u MIB modules registered (enterprise %lu)", (unsigned)n, (unsigned long)snmp_gw_pen());
    return ESP_OK;
}

void snmp_registry_notify_config(void) {
    if (!s_started) {
        return;
    }
    for (uint8_t i = 0; i < s_n_mods; i++) {
        if (s_mods[i]->on_config != NULL) {
            s_mods[i]->on_config();
        }
    }
}

/* lwIP's SNMP-FRAMEWORK-MIB (snmpEngine group) and SNMP-USER-BASED-SM-MIB (usmStats, usmUserTable
 * read-only), served as registry modules so they share the module order and diagnostics. */
const snmp_module_t sgw_mod_framework = {.name = "snmpFramework", .mib = &snmpframeworkmib};
const snmp_module_t sgw_mod_usm = {.name = "snmpUsm", .mib = &snmpusmmib};
