/* MIB-II system group 1.3.6.1.2.1.1 (RFC 3418): sysDescr, sysObjectID, sysUpTime, sysContact,
 * sysName, sysLocation, sysServices. sysContact/sysName/sysLocation are writable (RW community or a
 * read-write v3 user) and persisted through cfg_commit(CFG_SEC_SNMP) (DESIGN.md §10). An empty
 * configured value reads as its fallback (general.contact, network.hostname, general.location);
 * writing "" restores that fallback. */
#include <string.h>

#include "esp_log.h"
#include "lwip/apps/snmp_scalar.h"
#include "snmp_gw_priv.h"

static const char *TAG = "mib_system";

#define SYS_DESCR_MAX 255
#define SYS_SERVICES 72 /* application (layer 7: 64) + end-to-end (layer 4: 8), RFC 3418 */

enum { SYS_DESCR = 1, SYS_OBJECT_ID = 2, SYS_UPTIME = 3, SYS_CONTACT = 4, SYS_NAME = 5, SYS_LOCATION = 6, SYS_SERVICES_ARC = 7 };

static cfg_snmp_t s_scratch; /* SET scratch (agent task only) */

static sgw_sys_t sys_of(u32_t arc) {
    return arc == SYS_CONTACT ? SGW_SYS_CONTACT : (arc == SYS_NAME ? SGW_SYS_NAME : SGW_SYS_LOCATION);
}

static s16_t sys_get(struct snmp_node_instance *instance, void *value) {
    const u32_t arc = instance->node->oid;
    switch (arc) {
    case SYS_DESCR: {
        char descr[GW_VERSION_SZ + sizeof(GW_PRODUCT_NAME) + 2];
        size_t n = strlen(GW_PRODUCT_NAME);
        memcpy(descr, GW_PRODUCT_NAME, n);
        descr[n++] = ' ';
        gw_strlcpy(&descr[n], sgw_fw_version(), sizeof(descr) - n);
        return sgw_value_str(value, descr, SYS_DESCR_MAX);
    }
    case SYS_OBJECT_ID: {
        const struct snmp_obj_id *oid = snmp_get_device_enterprise_oid();
        memcpy(value, oid->id, oid->len * sizeof(u32_t));
        return (s16_t)(oid->len * sizeof(u32_t));
    }
    case SYS_UPTIME:
        return sgw_value_u32(value, sgw_uptime_cs());
    case SYS_CONTACT:
    case SYS_NAME:
    case SYS_LOCATION:
        return sgw_value_str(value, sgw_sys_string(sys_of(arc)), GW_TEXT_MAX);
    case SYS_SERVICES_ARC:
        return sgw_value_s32(value, SYS_SERVICES);
    default:
        return -1;
    }
}

static snmp_err_t sys_set_test(struct snmp_node_instance *instance, u16_t len, void *value) {
    (void)instance;
    if (!snmp_ctx_can_write()) {
        return SNMP_ERR_NOTWRITABLE;
    }
    if (len > GW_TEXT_MAX) {
        return SNMP_ERR_WRONGLENGTH;
    }
    return snmp_text_ok((const uint8_t *)value, len, GW_TEXT_MAX) ? SNMP_ERR_NOERROR : SNMP_ERR_WRONGVALUE;
}

static snmp_err_t sys_set_value(struct snmp_node_instance *instance, u16_t len, void *value) {
    const u32_t arc = instance->node->oid;
    char text[GW_TEXT_SZ];
    if (len > GW_TEXT_MAX) {
        return SNMP_ERR_WRONGLENGTH;
    }
    memcpy(text, value, len);
    text[len] = '\0';
    if (cfg_get_section(CFG_SEC_SNMP, &s_scratch, sizeof(s_scratch)) != ESP_OK) {
        return SNMP_ERR_GENERROR;
    }
    char *field = arc == SYS_CONTACT ? s_scratch.sys_contact
                                     : (arc == SYS_NAME ? s_scratch.sys_name : s_scratch.sys_location);
    gw_strlcpy(field, text, GW_TEXT_SZ);
    cfg_verr_t verr = {{0}, {0}};
    esp_err_t err = cfg_commit(CFG_SEC_SNMP, &s_scratch, sizeof(s_scratch), SGW_WHO, &verr);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SET %u rejected by the configuration store: %s (%s %s)", (unsigned)arc, esp_err_to_name(err),
                 verr.field, verr.code);
        return SNMP_ERR_COMMITFAILED;
    }
    if (text[0] != '\0') {
        sgw_sys_string_set(sys_of(arc), text); /* visible at once; CONFIG_CHANGED re-applies fallbacks */
    }
    ESP_LOGI(TAG, "sys%s changed by SNMP", arc == SYS_CONTACT ? "Contact" : (arc == SYS_NAME ? "Name" : "Location"));
    return SNMP_ERR_NOERROR;
}

#define RO_SCALAR(arc, type) SNMP_SCALAR_CREATE_NODE_READONLY(arc, type, sys_get)
#define RW_SCALAR(arc)                                                                                       \
    SNMP_SCALAR_CREATE_NODE(arc, SNMP_NODE_INSTANCE_READ_WRITE, SNMP_ASN1_TYPE_OCTET_STRING, sys_get,         \
                            sys_set_test, sys_set_value)

static const struct snmp_scalar_node s_descr = RO_SCALAR(SYS_DESCR, SNMP_ASN1_TYPE_OCTET_STRING);
static const struct snmp_scalar_node s_objid = RO_SCALAR(SYS_OBJECT_ID, SNMP_ASN1_TYPE_OBJECT_ID);
static const struct snmp_scalar_node s_uptime = RO_SCALAR(SYS_UPTIME, SNMP_ASN1_TYPE_TIMETICKS);
static const struct snmp_scalar_node s_contact = RW_SCALAR(SYS_CONTACT);
static const struct snmp_scalar_node s_name = RW_SCALAR(SYS_NAME);
static const struct snmp_scalar_node s_location = RW_SCALAR(SYS_LOCATION);
static const struct snmp_scalar_node s_services = RO_SCALAR(SYS_SERVICES_ARC, SNMP_ASN1_TYPE_INTEGER);

static const struct snmp_node *const s_nodes[] = {
    &s_descr.node.node, &s_objid.node.node,    &s_uptime.node.node,   &s_contact.node.node,
    &s_name.node.node,  &s_location.node.node, &s_services.node.node,
};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(1, s_nodes);
static const u32_t s_base[] = {1, 3, 6, 1, 2, 1, 1};
static const struct snmp_mib s_mib = SNMP_MIB_CREATE(s_base, &s_root.node);

const snmp_module_t sgw_mod_system = {.name = "system", .mib = &s_mib, .init = NULL, .on_config = NULL};
