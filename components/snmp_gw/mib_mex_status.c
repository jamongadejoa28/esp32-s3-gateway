/* mexStatus (…PEN.1.3): mexStatusTable, one row per configured device (INDEX gwDevIndex). Values come
 * from the latest snapshot copy (mex_service_snapshot); register words use the project-wide "raw"
 * convention (regmap.h): temperature/humidity/current in tenths (GwTenths), bit-field words as
 * unsigned. mexStatusValid tells whether the device is online with fresh data. Agent task only. */
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_table.h"
#include "mex150/model.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static s16_t status_get(struct snmp_node_instance *cell, void *value) {
    mex_snapshot_t s;
    if (!mex_service_snapshot(sgw_cell_dev(cell), &s)) {
        return -1;
    }
    mex_stages_t st;
    switch (sgw_cell_column(cell)) {
    case GWMIB_mexStatusValid:
        return sgw_value_s32(value, GWMIB_TRUTH(sgw_snap_fresh(&s)));
    case GWMIB_mexTemperature:
        return sgw_value_s32(value, mex_snap_raw(&s, 40036));
    case GWMIB_mexHumidity:
        return sgw_value_s32(value, mex_snap_raw(&s, 40037));
    case GWMIB_mexCurrent:
        return sgw_value_s32(value, mex_snap_raw(&s, 40011));
    case GWMIB_mexRunState:
        return sgw_value_s32(value, mex_running(&s) ? GWMIB_RUNSTATE_RUNNING : GWMIB_RUNSTATE_STOPPED);
    case GWMIB_mexDelayRemaining:
        return sgw_value_s32(value, mex_delay_s(&s));
    case GWMIB_mexModeFlags:
        return (s16_t)snmp_encode_bits((u8_t *)value, SNMP_MAX_VALUE_SIZE, mex_mode_mask(&s), 4);
    case GWMIB_mexStagesCool:
        mex_derive_stages(&s, &st);
        return sgw_value_u32(value, st.cool);
    case GWMIB_mexStagesHeat:
        mex_derive_stages(&s, &st);
        return sgw_value_u32(value, st.heat);
    case GWMIB_mexStagesHum:
        mex_derive_stages(&s, &st);
        return sgw_value_u32(value, st.hum);
    case GWMIB_mexStagesDehum:
        mex_derive_stages(&s, &st);
        return sgw_value_u32(value, st.dehum);
    case GWMIB_mexBlower:
        mex_derive_stages(&s, &st);
        return sgw_value_s32(value, GWMIB_TRUTH(st.blower));
    case GWMIB_mexCoils:
        return sgw_value_u32(value, s.coils);
    case GWMIB_mexInputPort:
        return sgw_value_u32(value, s.regs[mex_reg_index(40002)]);
    case GWMIB_mexAlarmDetail1:
        return sgw_value_u32(value, s.regs[mex_reg_index(40003)]);
    case GWMIB_mexAlarmDetail2:
        return sgw_value_u32(value, s.regs[mex_reg_index(40004)]);
    case GWMIB_mexCoolProp:
        return sgw_value_u32(value, s.regs[mex_reg_index(40006)]);
    case GWMIB_mexHeatProp:
        return sgw_value_u32(value, s.regs[mex_reg_index(40007)]);
    case GWMIB_mexHumProp:
        return sgw_value_u32(value, s.regs[mex_reg_index(40008)]);
    default:
        return -1;
    }
}

static snmp_err_t status_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len,
                              struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_get(row_oid, row_oid_len, cell);
}

static snmp_err_t status_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_next(row_oid, cell);
}

#define COL(name, type) {GWMIB_##name, type, SNMP_NODE_INSTANCE_READ_ONLY}
static const struct snmp_table_col_def s_cols[] = {
    COL(mexStatusValid, SNMP_ASN1_TYPE_INTEGER),     COL(mexTemperature, SNMP_ASN1_TYPE_INTEGER),
    COL(mexHumidity, SNMP_ASN1_TYPE_INTEGER),        COL(mexCurrent, SNMP_ASN1_TYPE_INTEGER),
    COL(mexRunState, SNMP_ASN1_TYPE_INTEGER),        COL(mexDelayRemaining, SNMP_ASN1_TYPE_INTEGER),
    COL(mexModeFlags, SNMP_ASN1_TYPE_OCTET_STRING),  COL(mexStagesCool, SNMP_ASN1_TYPE_UNSIGNED32),
    COL(mexStagesHeat, SNMP_ASN1_TYPE_UNSIGNED32),   COL(mexStagesHum, SNMP_ASN1_TYPE_UNSIGNED32),
    COL(mexStagesDehum, SNMP_ASN1_TYPE_UNSIGNED32),  COL(mexBlower, SNMP_ASN1_TYPE_INTEGER),
    COL(mexCoils, SNMP_ASN1_TYPE_UNSIGNED32),        COL(mexInputPort, SNMP_ASN1_TYPE_UNSIGNED32),
    COL(mexAlarmDetail1, SNMP_ASN1_TYPE_UNSIGNED32), COL(mexAlarmDetail2, SNMP_ASN1_TYPE_UNSIGNED32),
    COL(mexCoolProp, SNMP_ASN1_TYPE_UNSIGNED32),     COL(mexHeatProp, SNMP_ASN1_TYPE_UNSIGNED32),
    COL(mexHumProp, SNMP_ASN1_TYPE_UNSIGNED32),
};
#undef COL
static const struct snmp_table_node s_table =
    SNMP_TABLE_CREATE(GWMIB_mexStatusTable, s_cols, status_cell, status_next_cell, status_get, NULL, NULL);

static const struct snmp_node *const s_nodes[] = {&s_table.node.node};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_mexStatus, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t status_init(void) {
    const uint32_t sfx[] = {GWMIB_mexStatus};
    return sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) == GWMIB_BRANCH_LEN ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

const snmp_module_t sgw_mod_mex_status = {.name = "mexStatus", .mib = &s_mib, .init = status_init, .on_config = NULL};
