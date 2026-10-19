/* mexRegisters (…PEN.1.5): mexRegTable, every REG row of regmap.def for every configured device,
 * INDEX { gwDevIndex, mexRegAddr }. Read-only generic view (the extension point for other controller
 * types): key, English name, raw (regmap.h convention), decimal value text, scale, unit, writable,
 * validity (online + fresh, and for slow-group registers read since online). Agent task only. */
#include <string.h>

#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_table.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

#define REF(dev, addr) (((u32_t)(dev) << 16) | (u32_t)(addr))
#define REF_DEV(ref) ((uint8_t)((ref) >> 16))
#define REF_ADDR(ref) ((uint16_t)((ref) & 0xFFFFu))

static bool in_slow_group(uint16_t addr) {
    for (size_t i = 0; i < MEX_SLOW_BLOCKS; i++) {
        const mex_block_t *b = &mex_slow_blocks[i];
        unsigned pdu = (unsigned)addr - 40001u;
        if (b->fc == MEX_FC_READ_HOLDING && pdu >= b->start && pdu < (unsigned)b->start + b->count) {
            return true;
        }
    }
    return false;
}

static s16_t reg_get(struct snmp_node_instance *cell, void *value) {
    const u32_t ref = cell->reference.u32;
    const mex_reg_t *r = mex_reg_find(REF_ADDR(ref));
    if (r == NULL) {
        return -1;
    }
    switch (sgw_cell_column(cell)) {
    case GWMIB_mexRegKey:
        return sgw_value_str(value, r->key, 32);
    case GWMIB_mexRegName:
        return sgw_value_str(value, r->en, GW_TEXT_MAX);
    case GWMIB_mexRegScale:
        return sgw_value_s32(value, r->scale);
    case GWMIB_mexRegUnit:
        return sgw_value_str(value, r->unit, 8);
    case GWMIB_mexRegWritable:
        return sgw_value_s32(value, GWMIB_TRUTH(r->writable));
    default:
        break;
    }
    mex_snapshot_t s;
    if (!mex_service_snapshot(REF_DEV(ref), &s)) {
        return -1;
    }
    const int32_t raw = mex_snap_raw(&s, r->addr);
    switch (sgw_cell_column(cell)) {
    case GWMIB_mexRegRaw:
        return sgw_value_s32(value, raw);
    case GWMIB_mexRegValue: {
        char buf[17];
        int n = mex_reg_format(r, raw, buf, sizeof(buf));
        return sgw_value_str(value, n < 0 ? "" : buf, 16);
    }
    case GWMIB_mexRegValid: {
        bool valid = sgw_snap_fresh(&s) && (!in_slow_group(r->addr) || s.slow_valid);
        return sgw_value_s32(value, GWMIB_TRUTH(valid));
    }
    default:
        return -1;
    }
}

static snmp_err_t reg_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell) {
    (void)column;
    if (row_oid_len != 2 || row_oid[1] > UINT16_MAX) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    const sgw_dev_t *d = sgw_dev_by_index(row_oid[0]);
    const mex_reg_t *r = mex_reg_find((uint16_t)row_oid[1]);
    if (d == NULL || r == NULL) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    cell->reference.u32 = REF(d->id, r->addr);
    return SNMP_ERR_NOERROR;
}

static snmp_err_t reg_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    struct snmp_next_oid_state state;
    u32_t result[2];
    snmp_next_oid_init(&state, row_oid->id, row_oid->len, result, 2);
    for (uint8_t i = 0; i < sgw_dev_count(); i++) {
        const sgw_dev_t *d = sgw_dev_at(i);
        for (size_t k = 0; k < MEX_REG_COUNT; k++) {
            u32_t test[2] = {GWMIB_DEV_INDEX(d->id), mex_regs[k].addr};
            snmp_next_oid_check(&state, test, 2, (void *)(uintptr_t)REF(d->id, mex_regs[k].addr));
        }
    }
    if (state.status != SNMP_NEXT_OID_STATUS_SUCCESS) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    cell->reference.u32 = (u32_t)(uintptr_t)state.reference;
    return SNMP_ERR_NOERROR;
}

#define COL(name, type) {GWMIB_##name, type, SNMP_NODE_INSTANCE_READ_ONLY}
static const struct snmp_table_col_def s_cols[] = {
    COL(mexRegKey, SNMP_ASN1_TYPE_OCTET_STRING),  COL(mexRegName, SNMP_ASN1_TYPE_OCTET_STRING),
    COL(mexRegRaw, SNMP_ASN1_TYPE_INTEGER),       COL(mexRegValue, SNMP_ASN1_TYPE_OCTET_STRING),
    COL(mexRegScale, SNMP_ASN1_TYPE_INTEGER),     COL(mexRegUnit, SNMP_ASN1_TYPE_OCTET_STRING),
    COL(mexRegWritable, SNMP_ASN1_TYPE_INTEGER),  COL(mexRegValid, SNMP_ASN1_TYPE_INTEGER),
};
#undef COL
static const struct snmp_table_node s_table =
    SNMP_TABLE_CREATE(GWMIB_mexRegTable, s_cols, reg_cell, reg_next_cell, reg_get, NULL, NULL);

static const struct snmp_node *const s_nodes[] = {&s_table.node.node};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_mexRegisters, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t regs_init(void) {
    const uint32_t sfx[] = {GWMIB_mexRegisters};
    return sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) == GWMIB_BRANCH_LEN ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

const snmp_module_t sgw_mod_mex_regs = {.name = "mexRegisters", .mib = &s_mib, .init = regs_init, .on_config = NULL};
