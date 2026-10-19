/* Shared helpers of the MIB modules (contract: snmp_gw_priv.h "MIB helpers"). Agent task only. */
#include <string.h>

#include "esp_log.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_core.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static const char *TAG = "snmp_mib";

uint8_t sgw_oid(uint32_t *out, size_t cap, const uint32_t *suffix, size_t n) {
    size_t len = snmp_gw_oid(suffix, n, out, cap);
    if (len == 0 || len > UINT8_MAX) {
        ESP_LOGE(TAG, "OID does not fit (%u arcs)", (unsigned)(n + GWMIB_ROOT_LEN));
        return 0;
    }
    return (uint8_t)len;
}

s16_t sgw_value_str(void *value, const char *s, size_t max) {
    size_t n = 0;
    if (s != NULL) {
        while (n < max && n < SNMP_MAX_OCTET_STRING_LEN && s[n] != '\0') {
            n++;
        }
        memcpy(value, s, n);
    }
    return (s16_t)n;
}

const char *sgw_principal(const char *by) {
    return snmp_principal_view(by, snmp_ctx_version() == SGW_SNMP_V3);
}

s16_t sgw_value_date(void *value, int64_t wall_ms) {
    return (s16_t)gw_time_snmp_date(wall_ms > 0 ? wall_ms : 0, (uint8_t *)value);
}

snmp_err_t sgw_dev_row_get(const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell) {
    if (row_oid_len != 1) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    const sgw_dev_t *d = sgw_dev_by_index(row_oid[0]);
    if (d == NULL) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    cell->reference.u32 = d->id;
    return SNMP_ERR_NOERROR;
}

snmp_err_t sgw_dev_row_next(struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    struct snmp_next_oid_state state;
    u32_t result[1];
    snmp_next_oid_init(&state, row_oid->id, row_oid->len, result, 1);
    for (uint8_t i = 0; i < sgw_dev_count(); i++) {
        const sgw_dev_t *d = sgw_dev_at(i);
        u32_t test[1] = {GWMIB_DEV_INDEX(d->id)};
        snmp_next_oid_check(&state, test, 1, (void *)(uintptr_t)d->id);
    }
    if (state.status != SNMP_NEXT_OID_STATUS_SUCCESS) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    cell->reference.u32 = (u32_t)(uintptr_t)state.reference;
    return SNMP_ERR_NOERROR;
}
