/* lwIP SNMPv3 USM/engine callbacks (lwip/apps/snmpv3.h) for the gateway (contract: snmp_gw.h).
 *
 * Users come from the pure table in snmp_logic.c (fixed slots of cfg_snmp_t + localized keys from
 * secrets): unknown, disabled or keyless users (and any user while v3 is disabled) are unknown to
 * lwIP (ERR_VAL -> usmStatsUnknownUserNames). A valid user ALWAYS reports HMAC-SHA-96 + AES-128,
 * never *_ALGO_INVAL, so lwIP rejects noAuthNoPriv and authNoPriv for it (snmp_msg.c step 5:
 * unsupportedSecLevel). RO/RW: the requesting principal is recorded in the transport's request
 * context (first lookup of a v3 datagram); writable nodes check snmp_ctx_can_write().
 * All callbacks run in the snmp_agent task only (lwIP calls them from snmp_receive). */
#include <string.h>

#include "lwip/apps/snmpv3.h"
#include "snmp_gw_priv.h"

static snmp_usm_table_t s_usm;

void sgw_usm_configure(const cfg_snmp_t *cfg, const sec_v3_keys_t *keys) {
    snmp_usm_build(&s_usm, cfg, keys);
}

err_t snmpv3_get_user(const char *username, snmpv3_auth_algo_t *auth_algo, u8_t *auth_key,
                      snmpv3_priv_algo_t *priv_algo, u8_t *priv_key) {
    const snmp_usm_user_t *u = snmp_usm_find(&s_usm, username);
    if (u == NULL) {
        return ERR_VAL;
    }
    if (auth_algo != NULL) {
        *auth_algo = SNMP_V3_AUTH_ALGO_SHA;
    }
    if (auth_key != NULL) {
        memcpy(auth_key, u->auth_key, SGW_V3_KEY_BUF);
    }
    if (priv_algo != NULL) {
        *priv_algo = SNMP_V3_PRIV_ALGO_AES;
    }
    if (priv_key != NULL) {
        memcpy(priv_key, u->priv_key, SGW_V3_KEY_BUF);
    }
    if (snmp_ctx_version() == SGW_SNMP_V3) {
        /* Latched by the transport: only the first lookup of the datagram (msgUserName) counts. */
        snmp_ctx_set_user(u->name, u->access == CFG_SNMP_RW ? SNMP_ACCESS_RW : SNMP_ACCESS_RO);
    }
    return ERR_OK;
}

u8_t snmpv3_get_amount_of_users(void) {
    return snmp_usm_count(&s_usm);
}

err_t snmpv3_get_username(char *username, u8_t index) {
    const snmp_usm_user_t *u = snmp_usm_at(&s_usm, index);
    if (u == NULL || username == NULL) {
        return ERR_VAL;
    }
    /* lwIP's buffer is SGW_V3_USER_BUF bytes; names are <= GW_SNMP_USER_MAX. */
    size_t n = strlen(u->name);
    memcpy(username, u->name, n + 1);
    return ERR_OK;
}

err_t snmpv3_get_user_storagetype(const char *username, snmpv3_user_storagetype_t *storagetype) {
    if (snmp_usm_find(&s_usm, username) == NULL) {
        return ERR_VAL;
    }
    if (storagetype != NULL) {
        *storagetype = SNMP_V3_USER_STORAGETYPE_NONVOLATILE; /* configured, persisted in /data */
    }
    return ERR_OK;
}

void snmpv3_get_engine_id(const char **id, u8_t *len) {
    *id = (const char *)sgw_engine_id(len);
}

err_t snmpv3_set_engine_id(const char *id, u8_t len) {
    /* The engine ID is derived from PEN + MAC (DESIGN.md §5) and the stored localized keys depend on
     * it, so it is not settable; accept only a no-op write of the current value. */
    u8_t cur_len = 0;
    const uint8_t *cur = sgw_engine_id(&cur_len);
    return (id != NULL && len == cur_len && memcmp(id, cur, len) == 0) ? ERR_OK : ERR_VAL;
}

u32_t snmpv3_get_engine_boots(void) {
    return sgw_engine_boots();
}

void snmpv3_set_engine_boots(u32_t boots) {
    sgw_engine_boots_set(boots);
}

u32_t snmpv3_get_engine_time(void) {
    return sgw_engine_time();
}

void snmpv3_reset_engine_time(void) {
    sgw_engine_time_reset();
}
