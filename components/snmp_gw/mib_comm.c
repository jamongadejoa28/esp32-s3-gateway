/* gwComm (…PEN.1.7): gwCommTable, Modbus counters / RTT per configured device (INDEX gwDevIndex),
 * from mex_service_stats() copies (never reset from SNMP). Agent task only. */
#include "lwip/apps/snmp_table.h"
#include "mex150/service.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static s16_t comm_get(struct snmp_node_instance *cell, void *value) {
    mex_stats_t st;
    mex_service_stats(sgw_cell_dev(cell), &st, false);
    switch (sgw_cell_column(cell)) {
    case GWMIB_gwCommTx:
        return sgw_value_u32(value, st.tx);
    case GWMIB_gwCommRxOk:
        return sgw_value_u32(value, st.rx_ok);
    case GWMIB_gwCommCrcErrors:
        return sgw_value_u32(value, st.crc);
    case GWMIB_gwCommTimeouts:
        return sgw_value_u32(value, st.timeout);
    case GWMIB_gwCommExceptions:
        return sgw_value_u32(value, st.exception);
    case GWMIB_gwCommMalformed:
        return sgw_value_u32(value, st.malformed);
    case GWMIB_gwCommOfflineCount:
        return sgw_value_u32(value, st.offline_count);
    case GWMIB_gwCommRttLast:
        return sgw_value_u32(value, st.rtt_last);
    case GWMIB_gwCommRttAvg:
        return sgw_value_u32(value, st.rtt_avg);
    case GWMIB_gwCommRttMax:
        return sgw_value_u32(value, st.rtt_max);
    case GWMIB_gwCommCycles:
        return sgw_value_u32(value, st.cycles);
    case GWMIB_gwCommOnlineSince:
        return sgw_value_date(value, st.online_since_ms);
    default:
        return -1;
    }
}

static snmp_err_t comm_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_get(row_oid, row_oid_len, cell);
}

static snmp_err_t comm_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_next(row_oid, cell);
}

#define COL(name, type) {GWMIB_##name, type, SNMP_NODE_INSTANCE_READ_ONLY}
static const struct snmp_table_col_def s_cols[] = {
    COL(gwCommTx, SNMP_ASN1_TYPE_COUNTER),          COL(gwCommRxOk, SNMP_ASN1_TYPE_COUNTER),
    COL(gwCommCrcErrors, SNMP_ASN1_TYPE_COUNTER),   COL(gwCommTimeouts, SNMP_ASN1_TYPE_COUNTER),
    COL(gwCommExceptions, SNMP_ASN1_TYPE_COUNTER),  COL(gwCommMalformed, SNMP_ASN1_TYPE_COUNTER),
    COL(gwCommOfflineCount, SNMP_ASN1_TYPE_COUNTER), COL(gwCommRttLast, SNMP_ASN1_TYPE_GAUGE),
    COL(gwCommRttAvg, SNMP_ASN1_TYPE_GAUGE),        COL(gwCommRttMax, SNMP_ASN1_TYPE_GAUGE),
    COL(gwCommCycles, SNMP_ASN1_TYPE_COUNTER),      COL(gwCommOnlineSince, SNMP_ASN1_TYPE_OCTET_STRING),
};
#undef COL
static const struct snmp_table_node s_table =
    SNMP_TABLE_CREATE(GWMIB_gwCommTable, s_cols, comm_cell, comm_next_cell, comm_get, NULL, NULL);

static const struct snmp_node *const s_nodes[] = {&s_table.node.node};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_gwComm, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t comm_init(void) {
    const uint32_t sfx[] = {GWMIB_gwComm};
    return sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) == GWMIB_BRANCH_LEN ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

const snmp_module_t sgw_mod_comm = {.name = "gwComm", .mib = &s_mib, .init = comm_init, .on_config = NULL};
