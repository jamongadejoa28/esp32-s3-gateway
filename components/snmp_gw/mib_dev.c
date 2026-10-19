/* gwDevices (…PEN.1.2): gwDevTable (configured Modbus devices, INDEX gwDevIndex = id + 1) and
 * gwDevCount. Device names/slaves come from the agent's configuration cache; online/age/seq from the
 * latest snapshot (mex_service_snapshot copies). Agent task only. */
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_table.h"
#include "mex150/service.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

#define AGE_NEVER 0xFFFFFFFFu

static s16_t dev_get(struct snmp_node_instance *cell, void *value) {
    const uint8_t dev = sgw_cell_dev(cell);
    const sgw_dev_t *d = sgw_dev_by_index(GWMIB_DEV_INDEX(dev));
    if (d == NULL) {
        return -1; /* removed by a configuration change during this request */
    }
    switch (sgw_cell_column(cell)) {
    case GWMIB_gwDevName:
        return sgw_value_str(value, d->name, GW_DEV_NAME_SZ - 1);
    case GWMIB_gwDevSlave:
        return sgw_value_s32(value, d->slave);
    case GWMIB_gwDevEnabled:
        return sgw_value_s32(value, GWMIB_TRUTH(d->enabled));
    default:
        break;
    }
    mex_snapshot_t s;
    if (!mex_service_snapshot(dev, &s)) {
        s.online = false;
        s.mono_ms = 0;
        s.seq = 0;
    }
    switch (sgw_cell_column(cell)) {
    case GWMIB_gwDevOnline:
        return sgw_value_s32(value, GWMIB_TRUTH(s.online));
    case GWMIB_gwDevDataAge: {
        uint64_t now = gw_time_mono_ms();
        uint64_t age = (s.mono_ms == 0 || now < s.mono_ms) ? AGE_NEVER : now - s.mono_ms;
        return sgw_value_u32(value, age >= AGE_NEVER ? AGE_NEVER : (uint32_t)age);
    }
    case GWMIB_gwDevSeq:
        return sgw_value_u32(value, s.seq);
    default:
        return -1;
    }
}

static snmp_err_t dev_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_get(row_oid, row_oid_len, cell);
}

static snmp_err_t dev_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_next(row_oid, cell);
}

static const struct snmp_table_col_def s_cols[] = {
    {GWMIB_gwDevName, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY},
    {GWMIB_gwDevSlave, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY},
    {GWMIB_gwDevEnabled, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY},
    {GWMIB_gwDevOnline, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY},
    {GWMIB_gwDevDataAge, SNMP_ASN1_TYPE_UNSIGNED32, SNMP_NODE_INSTANCE_READ_ONLY},
    {GWMIB_gwDevSeq, SNMP_ASN1_TYPE_COUNTER, SNMP_NODE_INSTANCE_READ_ONLY},
};
static const struct snmp_table_node s_table =
    SNMP_TABLE_CREATE(GWMIB_gwDevTable, s_cols, dev_cell, dev_next_cell, dev_get, NULL, NULL);

static s16_t count_get(struct snmp_node_instance *instance, void *value) {
    (void)instance;
    return sgw_value_s32(value, sgw_dev_count());
}
static const struct snmp_scalar_node s_count =
    SNMP_SCALAR_CREATE_NODE_READONLY(GWMIB_gwDevCount, SNMP_ASN1_TYPE_INTEGER, count_get);

static const struct snmp_node *const s_nodes[] = {&s_table.node.node, &s_count.node.node};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_gwDevices, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t dev_init(void) {
    const uint32_t sfx[] = {GWMIB_gwDevices};
    return sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) == GWMIB_BRANCH_LEN ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

const snmp_module_t sgw_mod_dev = {.name = "gwDevices", .mib = &s_mib, .init = dev_init, .on_config = NULL};
