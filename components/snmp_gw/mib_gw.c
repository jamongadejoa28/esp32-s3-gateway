/* gwInfo (…PEN.1.1, MESTIO-GW-MIB): firmware, MAC, uptime, wall clock, alarm count, configuration
 * revision, last write result, notification counters. Read-only scalars. Agent task only. */
#include <string.h>

#include "alarm/alarm.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_scalar.h"
#include "mex150/regmap.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static s16_t gw_get(struct snmp_node_instance *instance, void *value) {
    const u32_t arc = instance->node->oid;
    switch (arc) {
    case GWMIB_gwFwVersion:
        return sgw_value_str(value, sgw_fw_version(), GW_VERSION_SZ - 1);
    case GWMIB_gwMacAddress:
        memcpy(value, sgw_mac(), GW_MAC_LEN);
        return GW_MAC_LEN;
    case GWMIB_gwUptime:
        return sgw_value_u32(value, sgw_uptime_cs());
    case GWMIB_gwTimeValid:
        return sgw_value_s32(value, GWMIB_TRUTH(gw_time_valid()));
    case GWMIB_gwWallTime:
        return sgw_value_date(value, gw_time_wall_ms());
    case GWMIB_gwActiveAlarms: {
        uint16_t per_sev[4];
        return sgw_value_u32(value, alarm_counts(per_sev));
    }
    case GWMIB_gwConfigRev:
        return sgw_value_u32(value, cfg_rev());
    case GWMIB_gwLastConfigSection: {
        char sec[16];
        sgw_last_config_get(sec);
        return sgw_value_str(value, sec, sizeof(sec) - 1);
    }
    case GWMIB_gwTrapsSent:
        return sgw_value_u32(value, sgw_traps_sent());
    case GWMIB_gwTrapsDropped:
        return sgw_value_u32(value, sgw_traps_dropped()); /* rate limit + queue full (counted once) */
    case GWMIB_gwInformsFailed:
        return sgw_value_u32(value, sgw_informs_failed());
    default:
        break;
    }

    sgw_last_write_t w;
    sgw_last_write_get(&w);
    switch (arc) {
    case GWMIB_gwLastWriteResult:
        return sgw_value_s32(value, w.valid ? snmp_write_result_code(w.state) : 1);
    case GWMIB_gwLastWriteDevIndex:
        return sgw_value_s32(value, w.valid ? (s32_t)GWMIB_DEV_INDEX(w.dev) : 0);
    case GWMIB_gwLastWriteRegAddr:
        return sgw_value_s32(value, w.valid ? w.addr : 0);
    case GWMIB_gwLastWriteValue:
        return sgw_value_s32(value, w.valid ? w.raw_req : 0);
    case GWMIB_gwLastWriteReason: {
        char buf[MEX_REASON_NAME_SZ];
        const char *r = (w.valid && w.reason != MEX_R_OK) ? mex_reason_name(w.reason, buf, sizeof(buf)) : "";
        return sgw_value_str(value, r, 32);
    }
    case GWMIB_gwLastWriteTime:
        return sgw_value_date(value, w.valid ? w.ts_ms : 0);
    case GWMIB_gwLastWriteCommand:
        return sgw_value_u32(value, w.valid ? w.cmd : 0);
    case GWMIB_gwLastWritePrincipal:
        return sgw_value_str(value, w.valid ? sgw_principal(w.by) : "", GW_USER_NAME_MAX);
    default:
        return -1;
    }
}

#define S(name, type) static const struct snmp_scalar_node s_##name = SNMP_SCALAR_CREATE_NODE_READONLY(GWMIB_##name, type, gw_get)
S(gwFwVersion, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwMacAddress, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwUptime, SNMP_ASN1_TYPE_TIMETICKS);
S(gwTimeValid, SNMP_ASN1_TYPE_INTEGER);
S(gwWallTime, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwActiveAlarms, SNMP_ASN1_TYPE_GAUGE);
S(gwConfigRev, SNMP_ASN1_TYPE_UNSIGNED32);
S(gwLastConfigSection, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwLastWriteResult, SNMP_ASN1_TYPE_INTEGER);
S(gwLastWriteDevIndex, SNMP_ASN1_TYPE_INTEGER);
S(gwLastWriteRegAddr, SNMP_ASN1_TYPE_INTEGER);
S(gwLastWriteValue, SNMP_ASN1_TYPE_INTEGER);
S(gwLastWriteReason, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwLastWriteTime, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwLastWriteCommand, SNMP_ASN1_TYPE_UNSIGNED32);
S(gwLastWritePrincipal, SNMP_ASN1_TYPE_OCTET_STRING);
S(gwTrapsSent, SNMP_ASN1_TYPE_COUNTER);
S(gwTrapsDropped, SNMP_ASN1_TYPE_COUNTER);
S(gwInformsFailed, SNMP_ASN1_TYPE_COUNTER);
#undef S

static const struct snmp_node *const s_nodes[] = {
    &s_gwFwVersion.node.node,        &s_gwMacAddress.node.node,        &s_gwUptime.node.node,
    &s_gwTimeValid.node.node,        &s_gwWallTime.node.node,          &s_gwActiveAlarms.node.node,
    &s_gwConfigRev.node.node,        &s_gwLastConfigSection.node.node, &s_gwLastWriteResult.node.node,
    &s_gwLastWriteDevIndex.node.node, &s_gwLastWriteRegAddr.node.node, &s_gwLastWriteValue.node.node,
    &s_gwLastWriteReason.node.node,  &s_gwLastWriteTime.node.node,     &s_gwLastWriteCommand.node.node,
    &s_gwLastWritePrincipal.node.node, &s_gwTrapsSent.node.node,       &s_gwTrapsDropped.node.node,
    &s_gwInformsFailed.node.node,
};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_gwInfo, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t gw_init(void) {
    const uint32_t sfx[] = {GWMIB_gwInfo};
    return sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) == GWMIB_BRANCH_LEN ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

const snmp_module_t sgw_mod_gw = {.name = "gwInfo", .mib = &s_mib, .init = gw_init, .on_config = NULL};
