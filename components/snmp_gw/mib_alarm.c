/* gwAlarms (…PEN.1.6): gwAlarmActiveTable (INDEX gwDevIndex, gwAlarmActiveCode) from
 * alarm_get_active(), severity counters from alarm_counts(), and gwAlarmEventTable (INDEX
 * gwAlarmEventSeq): the SNMP_GW_EVENTS_KEPT newest alarm transitions (seeded from the event log at
 * start, then fed by GW_EVT_ALARM). gwAlarmNotifObjects (.8) are accessible-for-notify only.
 *
 * Each varbind is resolved by get_instance/get_next_instance -> get_value -> release before the next
 * one (snmp_msg.c), so the row found by the instance functions is kept in a static "current row"
 * buffer for get_value. Agent task only. */
#include <string.h>

#include "alarm/alarm.h"
#include "esp_heap_caps.h"
#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_table.h"
#include "mib_oids.h"
#include "snmp_gw_priv.h"

#define ACTIVE_MAX (GW_MAX_DEVICES * ALM_COUNT)

/* Work buffers (~6 KB), PSRAM-preferring heap at init (agent task only, never touched from an ISR or
 * with the cache disabled), so they do not count against the internal-RAM gate (ARCHITECTURE.md §6). */
typedef struct {
    alm_active_t active[ACTIVE_MAX]; /* alarm_get_active() copy */
    snmp_evring_t ring;              /* event ring copy */
} alarm_work_t;

static alarm_work_t *s_w;
static alm_active_t s_active_cur; /* row of the varbind being processed */
static snmp_alarm_ev_t s_ev_cur;

/* ---------------------------------------------------------------- active alarms */

static size_t load_active(void) {
    size_t n = alarm_get_active(s_w->active, ACTIVE_MAX);
    return n > ACTIVE_MAX ? ACTIVE_MAX : n;
}

static uint16_t active_code(const alm_active_t *a) {
    return (unsigned)a->id < ALM_COUNT ? alm_catalog[a->id].code : 0;
}

static s16_t active_get(struct snmp_node_instance *cell, void *value) {
    const alm_active_t *a = &s_active_cur;
    switch (sgw_cell_column(cell)) {
    case GWMIB_gwAlarmActiveName:
        return sgw_value_str(value, (unsigned)a->id < ALM_COUNT ? alm_catalog[a->id].en : "", GW_TEXT_MAX);
    case GWMIB_gwAlarmActiveSeverity:
        return sgw_value_s32(value, GWMIB_SEVERITY(a->sev));
    case GWMIB_gwAlarmActiveSince:
        return sgw_value_date(value, a->since_ms);
    case GWMIB_gwAlarmActiveAcked:
        return sgw_value_s32(value, GWMIB_TRUTH(a->acked));
    case GWMIB_gwAlarmActiveAckedBy:
        return sgw_value_str(value, a->acked ? sgw_principal(a->ack_by) : "", GW_USER_NAME_MAX);
    case GWMIB_gwAlarmActiveValue:
        return sgw_value_s32(value, a->value);
    default:
        return -1;
    }
}

static snmp_err_t active_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len,
                              struct snmp_node_instance *cell) {
    (void)column;
    if (row_oid_len != 2) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    size_t n = load_active();
    for (size_t i = 0; i < n; i++) {
        if (GWMIB_DEV_INDEX(s_w->active[i].dev) == row_oid[0] && active_code(&s_w->active[i]) == row_oid[1]) {
            s_active_cur = s_w->active[i];
            cell->reference.u32 = (u32_t)i;
            return SNMP_ERR_NOERROR;
        }
    }
    return SNMP_ERR_NOSUCHINSTANCE;
}

static snmp_err_t active_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    struct snmp_next_oid_state state;
    u32_t result[2];
    snmp_next_oid_init(&state, row_oid->id, row_oid->len, result, 2);
    size_t n = load_active();
    for (size_t i = 0; i < n; i++) {
        u32_t test[2] = {GWMIB_DEV_INDEX(s_w->active[i].dev), active_code(&s_w->active[i])};
        snmp_next_oid_check(&state, test, 2, (void *)(uintptr_t)i);
    }
    if (state.status != SNMP_NEXT_OID_STATUS_SUCCESS) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    size_t i = (size_t)(uintptr_t)state.reference;
    s_active_cur = s_w->active[i];
    cell->reference.u32 = (u32_t)i;
    return SNMP_ERR_NOERROR;
}

#define COL(name, type) {GWMIB_##name, type, SNMP_NODE_INSTANCE_READ_ONLY}
static const struct snmp_table_col_def s_active_cols[] = {
    COL(gwAlarmActiveName, SNMP_ASN1_TYPE_OCTET_STRING),  COL(gwAlarmActiveSeverity, SNMP_ASN1_TYPE_INTEGER),
    COL(gwAlarmActiveSince, SNMP_ASN1_TYPE_OCTET_STRING), COL(gwAlarmActiveAcked, SNMP_ASN1_TYPE_INTEGER),
    COL(gwAlarmActiveAckedBy, SNMP_ASN1_TYPE_OCTET_STRING), COL(gwAlarmActiveValue, SNMP_ASN1_TYPE_INTEGER),
};
static const struct snmp_table_node s_active_table = SNMP_TABLE_CREATE(
    GWMIB_gwAlarmActiveTable, s_active_cols, active_cell, active_next_cell, active_get, NULL, NULL);

/* ---------------------------------------------------------------- counters */

static s16_t count_get(struct snmp_node_instance *instance, void *value) {
    uint16_t per_sev[4] = {0, 0, 0, 0};
    uint32_t total = alarm_counts(per_sev);
    switch (instance->node->oid) {
    case GWMIB_gwAlarmActiveCount:
        return sgw_value_u32(value, total);
    case GWMIB_gwAlarmCriticalCount:
        return sgw_value_u32(value, per_sev[ALM_SEV_CRITICAL]);
    case GWMIB_gwAlarmMajorCount:
        return sgw_value_u32(value, per_sev[ALM_SEV_MAJOR]);
    case GWMIB_gwAlarmMinorCount:
        return sgw_value_u32(value, per_sev[ALM_SEV_MINOR]);
    case GWMIB_gwAlarmInfoCount:
        return sgw_value_u32(value, per_sev[ALM_SEV_INFO]);
    default:
        return -1;
    }
}

#define CNT(name)                                                                                            \
    static const struct snmp_scalar_node s_##name =                                                          \
        SNMP_SCALAR_CREATE_NODE_READONLY(GWMIB_##name, SNMP_ASN1_TYPE_GAUGE, count_get)
CNT(gwAlarmActiveCount);
CNT(gwAlarmCriticalCount);
CNT(gwAlarmMajorCount);
CNT(gwAlarmMinorCount);
CNT(gwAlarmInfoCount);
#undef CNT

/* ---------------------------------------------------------------- event table */

static s16_t event_get(struct snmp_node_instance *cell, void *value) {
    const snmp_alarm_ev_t *e = &s_ev_cur;
    switch (sgw_cell_column(cell)) {
    case GWMIB_gwAlarmEventTime:
        return sgw_value_date(value, e->ts_ms);
    case GWMIB_gwAlarmEventType:
        return sgw_value_s32(value, GWMIB_EVENT_TYPE(e->type));
    case GWMIB_gwAlarmEventDevIndex:
        return sgw_value_s32(value, (s32_t)GWMIB_DEV_INDEX(e->dev));
    case GWMIB_gwAlarmEventCode:
        return sgw_value_s32(value, e->code);
    case GWMIB_gwAlarmEventSeverity:
        return sgw_value_s32(value, GWMIB_SEVERITY(e->sev));
    case GWMIB_gwAlarmEventValue:
        return sgw_value_s32(value, e->value);
    case GWMIB_gwAlarmEventUser:
        return sgw_value_str(value, sgw_principal(e->user), GW_USER_NAME_MAX);
    default:
        return -1;
    }
}

static snmp_err_t event_cell(const u32_t *column, const u32_t *row_oid, u8_t row_oid_len,
                             struct snmp_node_instance *cell) {
    (void)column;
    if (row_oid_len != 1 || row_oid[0] == 0 || !sgw_event_get(row_oid[0], &s_ev_cur)) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    cell->reference.u32 = row_oid[0];
    return SNMP_ERR_NOERROR;
}

static snmp_err_t event_next_cell(const u32_t *column, struct snmp_obj_id *row_oid, struct snmp_node_instance *cell) {
    (void)column;
    struct snmp_next_oid_state state;
    u32_t result[1];
    sgw_events_copy(&s_w->ring);
    snmp_next_oid_init(&state, row_oid->id, row_oid->len, result, 1);
    for (uint8_t i = 0; i < s_w->ring.n; i++) {
        u32_t test[1] = {s_w->ring.ev[i].seq};
        snmp_next_oid_check(&state, test, 1, (void *)(uintptr_t)i);
    }
    if (state.status != SNMP_NEXT_OID_STATUS_SUCCESS) {
        return SNMP_ERR_NOSUCHINSTANCE;
    }
    snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
    s_ev_cur = s_w->ring.ev[(uintptr_t)state.reference];
    cell->reference.u32 = s_ev_cur.seq;
    return SNMP_ERR_NOERROR;
}

static const struct snmp_table_col_def s_event_cols[] = {
    COL(gwAlarmEventTime, SNMP_ASN1_TYPE_OCTET_STRING), COL(gwAlarmEventType, SNMP_ASN1_TYPE_INTEGER),
    COL(gwAlarmEventDevIndex, SNMP_ASN1_TYPE_INTEGER),  COL(gwAlarmEventCode, SNMP_ASN1_TYPE_INTEGER),
    COL(gwAlarmEventSeverity, SNMP_ASN1_TYPE_INTEGER),  COL(gwAlarmEventValue, SNMP_ASN1_TYPE_INTEGER),
    COL(gwAlarmEventUser, SNMP_ASN1_TYPE_OCTET_STRING),
};
#undef COL
static const struct snmp_table_node s_event_table =
    SNMP_TABLE_CREATE(GWMIB_gwAlarmEventTable, s_event_cols, event_cell, event_next_cell, event_get, NULL, NULL);

/* ---------------------------------------------------------------- module */

static const struct snmp_node *const s_nodes[] = {
    &s_active_table.node.node,       &s_gwAlarmActiveCount.node.node, &s_gwAlarmCriticalCount.node.node,
    &s_gwAlarmMajorCount.node.node,  &s_gwAlarmMinorCount.node.node,  &s_gwAlarmInfoCount.node.node,
    &s_event_table.node.node,
};
static const struct snmp_tree_node s_root = SNMP_CREATE_TREE_NODE(GWMIB_gwAlarms, s_nodes);
static u32_t s_base[GWMIB_BRANCH_LEN];
static const struct snmp_mib s_mib = {s_base, GWMIB_BRANCH_LEN, &s_root.node};

static esp_err_t alarm_mib_init(void) {
    const uint32_t sfx[] = {GWMIB_gwAlarms};
    if (sgw_oid(s_base, GWMIB_BRANCH_LEN, sfx, 1) != GWMIB_BRANCH_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    s_w = heap_caps_calloc_prefer(1, sizeof(*s_w), 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                  MALLOC_CAP_DEFAULT);
    return s_w != NULL ? ESP_OK : ESP_ERR_NO_MEM;
}

const snmp_module_t sgw_mod_alarm = {.name = "gwAlarms", .mib = &s_mib, .init = alarm_mib_init, .on_config = NULL};
