/* mexSetpoints (…PEN.1.4): mexSetpointTable, one row per configured device (INDEX gwDevIndex); one
 * read-write Integer32 column per regmap.def REG row flagged SNMP_RW, column = address - 40000
 * (GWMIB_SP_COLUMN, generated identically by tools/gen_mib.py). Values are write-request raws at
 * register scale (e.g. 235 = 23.5 °C).
 *
 * SET (ARCHITECTURE.md §4.2): set_test requires write access (v1/v2c RW community or a v3 RW user,
 * snmp_ctx_can_write) and runs the same mex_check_write() validation as the web API against the
 * current snapshot; set_value queues the write with mex_service_write(..., "@snmp", 1000 ms):
 * REJECTED (device exception, interlock re-check, cancelled) or a full queue -> error (lwIP answers
 * commitFailed for a single varbind); APPLIED -> noError; UNCERTAIN or still PENDING after 1 s ->
 * noError, the outcome is visible in gwLastWriteResult (and the audit log / WS "write"). Agent task. */
#include <string.h>

#include "esp_log.h"
#include "gw_core/gw_time.h"
#include "lwip/apps/snmp_table.h"
#include "mex150/model.h"
#include "mex150/service.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

static const char *TAG = "mib_setpoint";

static struct snmp_table_col_def s_cols[MEX_REG_COUNT];

static uint16_t col_addr(const struct snmp_node_instance *cell) {
    return (uint16_t)(MEX_ADDR_BASE + sgw_cell_column(cell));
}

static s16_t sp_get(struct snmp_node_instance *cell, void *value) {
    mex_snapshot_t s;
    if (!mex_service_snapshot(sgw_cell_dev(cell), &s)) {
        return -1;
    }
    return sgw_value_s32(value, mex_snap_raw(&s, col_addr(cell)));
}

static snmp_err_t sp_set_test(struct snmp_node_instance *cell, u16_t len, void *value) {
    if (!snmp_ctx_can_write()) {
        return SNMP_ERR_NOTWRITABLE;
    }
    if (len != sizeof(s32_t)) {
        return SNMP_ERR_WRONGLENGTH;
    }
    const uint8_t dev = sgw_cell_dev(cell);
    const uint16_t addr = col_addr(cell);
    const int32_t raw = *(const s32_t *)value;
    mex_snapshot_t s;
    if (!mex_service_snapshot(dev, &s)) {
        return SNMP_ERR_RESOURCEUNAVAILABLE;
    }
    const mex_reason_t r = mex_check_write_snap(addr, raw, &s, gw_time_mono_ms());
    if (r != MEX_R_OK) {
        char buf[MEX_REASON_NAME_SZ];
        ESP_LOGI(TAG, "SET dev %u reg %u = %ld refused: %s", (unsigned)dev, (unsigned)addr, (long)raw,
                 mex_reason_name(r, buf, sizeof(buf)));
    }
    return (snmp_err_t)snmp_err_for_reason(r);
}

static snmp_err_t sp_set_value(struct snmp_node_instance *cell, u16_t len, void *value) {
    if (len != sizeof(s32_t)) {
        return SNMP_ERR_WRONGLENGTH;
    }
    const uint8_t dev = sgw_cell_dev(cell);
    const uint16_t addr = col_addr(cell);
    const int32_t raw = *(const s32_t *)value;
    mex_wresult_t res;
    memset(&res, 0, sizeof(res));
    esp_err_t err = mex_service_write(dev, addr, raw, SGW_WHO, SGW_SET_WAIT_MS, &res);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SET dev %u reg %u = %ld: %s", (unsigned)dev, (unsigned)addr, (long)raw, esp_err_to_name(err));
        return SNMP_ERR_COMMITFAILED;
    }
    switch (res.state) {
    case MEX_W_APPLIED:
        return SNMP_ERR_NOERROR;
    case MEX_W_PENDING: {
        /* The final state arrives later as GW_EVT_WRITE_RESULT; show "pending" meanwhile, unless
         * that result already arrived (gw_evt runs on the other core): put_pending never replaces it. */
        sgw_last_write_t lw = {.dev = dev,
                               .state = MEX_W_PENDING,
                               .addr = addr,
                               .raw_req = raw,
                               .reason = MEX_R_OK,
                               .cmd = res.cmd,
                               .ts_ms = gw_time_wall_ms()};
        gw_strlcpy(lw.by, SGW_WHO, sizeof(lw.by));
        sgw_last_write_put_pending(&lw);
        return SNMP_ERR_NOERROR;
    }
    case MEX_W_UNCERTAIN:
        return SNMP_ERR_NOERROR; /* reported in gwLastWriteResult via GW_EVT_WRITE_RESULT */
    case MEX_W_REJECTED:
    default: {
        char buf[MEX_REASON_NAME_SZ];
        ESP_LOGW(TAG, "SET dev %u reg %u = %ld rejected: %s", (unsigned)dev, (unsigned)addr, (long)raw,
                 mex_reason_name(res.reason, buf, sizeof(buf)));
        return SNMP_ERR_COMMITFAILED;
    }
    }
}

static snmp_err_t sp_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_get(row_oid, row_oid_len, cell);
}

static snmp_err_t sp_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    return sgw_dev_row_next(row_oid, cell);
}

/* Columns are filled at init (column_count set there). */
static struct snmp_table_node s_table = {{{SNMP_NODE_TABLE, GWMIB_mexSetpointTable},
                                          snmp_table_get_instance,
                                          snmp_table_get_next_instance},
                                         0,
                                         s_cols,
                                         sp_cell,
                                         sp_next_cell,
                                         sp_get,
                                         sp_set_test,
                                         sp_set_value};

static const struct snmp_node *const s_nodes[] = {&s_table.node.node};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_mexSetpoints, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t sp_init(void) {
    const uint32_t sfx[] = {GWMIB_mexSetpoints};
    if (sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) != GWMIB_BRANCH_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    u16_t n = 0;
    for (size_t i = 0; i < MEX_REG_COUNT; i++) {
        const mex_reg_t *r = &mex_regs[i];
        if ((r->flags & MEX_F_SNMP_RW) == 0) {
            continue;
        }
        if (!r->writable || (r->flags & MEX_F_RUNBIT) != 0) {
            ESP_LOGE(TAG, "regmap row %s: SNMP_RW on a non-writable/RUNBIT register ignored", r->key);
            continue;
        }
        s_cols[n].index = GWMIB_SP_COLUMN(r->addr);
        s_cols[n].asn1_type = SNMP_ASN1_TYPE_INTEGER;
        s_cols[n].access = SNMP_NODE_INSTANCE_READ_WRITE;
        n++;
    }
    s_table.column_count = n;
    return n > 0 ? ESP_OK : ESP_ERR_NOT_FOUND;
}

const snmp_module_t sgw_mod_mex_setpoint = {.name = "mexSetpoints", .mib = &s_mib, .init = sp_init, .on_config = NULL};
