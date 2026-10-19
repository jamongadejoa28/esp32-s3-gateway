/*
 * secrets.h - write-only secrets: web users (password records), SNMP communities, SNMPv3
 * localized keys, AP PSK. File /data/sec/secrets.json (DESIGN.md §7):
 *   {"schema":1,"users":[{"name","role","hash","must_change","changed"}],
 *    "snmp":{"ro","rw","v3":[{"name","auth_key","priv_key"}],"trap_comm":[...]},"ap_psk"}
 * v3 keys are stored localized (hex), never passphrases. Never exported, never returned by any API
 * (no exceptions: GET /system/coredump returns a summary only, docs/API.md §4.12).
 *
 * Pure part: types, defaults, validation, JSON (cJSON/gw_json_writer), flags.
 * Device part (secrets.c): one gw_secrets_t behind a mutex; changes go through secrets_modify()
 * which persists via the persist task and posts GW_EVT_CONFIG_CHANGED{CFG_SEC_SECRETS}.
 * Copies of secrets must be wiped with gw_secure_zero() after use.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "gw_core/gw_json_writer.h"
#include "store/config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEC_SCHEMA_VERSION 1
#define SEC_HASH_SZ 100   /* "pbkdf2-sha256$<iter>$<salt_b64>$<dk_b64>" + NUL */
#define SEC_V3_KEY_LEN 20 /* localized HMAC-SHA key; AES-128 uses the first 16 bytes of priv */
/* No default v1/v2c RO community: "" rejects every community request until an admin sets one
 * (and v1/v2c can only be enabled once it is set, cfg_snmp_check_secrets). */
#define SEC_DEFAULT_TRAP "mestio-trap" /* sent only to configured trap targets */

typedef struct {
    char name[GW_USER_NAME_SZ];
    uint8_t role; /* gw_role_t (VIEWER..ADMIN) */
    bool must_change;
    char hash[SEC_HASH_SZ]; /* auth password record (auth.h) */
    int64_t changed_ms;     /* wall ms of last password change (0 = unknown) */
} sec_user_t;

typedef struct {
    bool set; /* both keys present */
    uint8_t auth_key[SEC_V3_KEY_LEN];
    uint8_t priv_key[SEC_V3_KEY_LEN];
} sec_v3_keys_t;

typedef struct {
    uint16_t schema;
    sec_user_t users[GW_MAX_USERS];
    uint8_t n_users;
    char snmp_ro[GW_COMMUNITY_SZ];          /* default "" = v1/v2c requests rejected */
    char snmp_rw[GW_COMMUNITY_SZ];          /* default "" = SNMP SET via community disabled */
    sec_v3_keys_t v3[GW_MAX_SNMP_V3_USERS]; /* slot-aligned with the fixed cfg_snmp_t.users slots */
    /* Index-aligned with cfg_snmp_t.traps at all times; whenever the trap list is replaced the
     * communities are remapped by target identity (sec_trap_remap). Default SEC_DEFAULT_TRAP. */
    char trap_comm[GW_MAX_TRAP_TARGETS][GW_COMMUNITY_SZ];
    char ap_psk[GW_PSK_SZ]; /* default: the factory PSK (below) */
} gw_secrets_t;

/* ---- Pure ---- */

/**
 * Defaults: no users (auth_init() creates the factory admin), empty RO/RW communities, trap
 * communities SEC_DEFAULT_TRAP, ap_psk = factory_ap_psk (8..63 chars; the device passes the
 * factory PSK from NVS, see secrets_load()).
 */
void sec_defaults(gw_secrets_t *s, const char *factory_ap_psk);

/** Structural validation (lengths, roles, unique names, >= 1 admin when users exist). */
bool sec_validate(const gw_secrets_t *s);

/** Parse the secrets file (unknown fields ignored, missing from sec_defaults(factory_ap_psk)).
 * 0 or CFG_JSON_E_*. */
int sec_from_json(const char *json, size_t len, const char *factory_ap_psk, gw_secrets_t *out);

/** Serialize the secrets file (persist only). */
int sec_to_json(const gw_secrets_t *s, gw_jw_t *w);

/** Read-back flags for REST GET bodies. */
void sec_flags(const gw_secrets_t *s, cfg_secret_flags_t *out);

/** Index of user `name` or -1. */
int sec_find_user(const gw_secrets_t *s, const char *name);

/**
 * Apply a trap-list replacement to the communities (cfg_secret_input_t semantics): new slot i <
 * n_traps gets in->trap[i].community if in->trap[i].has, else old slot in->trap_from[i] (>= 0), else
 * SEC_DEFAULT_TRAP; slots >= n_traps are reset to SEC_DEFAULT_TRAP. No-op unless in->has_traps.
 * Use inside secrets_modify(); the caller then commits the matching cfg_snmp_t.
 */
void sec_trap_remap(gw_secrets_t *s, const cfg_secret_input_t *in, uint8_t n_traps);

/* ---- Device store ---- */

/**
 * Load /data/sec/secrets.json (X, X.tmp, X.bak, defaults). After fs_mount() and nvs_flash_init().
 * Factory AP PSK: read from NVS GW_NVS_NS_FACTORY/GW_NVS_KEY_AP_PSK (gw_defs.h); on the very first
 * boot it is generated (gw_random() -> gw_ident_ap_psk_format()) and stored there. That namespace
 * survives factory reset, so the PSK printed on a production label / the serial log stays valid
 * for the device's lifetime unless an admin changes ap_psk.
 */
esp_err_t secrets_load(void);

/** The factory AP PSK (valid after secrets_load()); for net's boot log line only. */
void secrets_factory_ap_psk(char out[GW_PSK_SZ]);

/** Copy everything (caller wipes the copy). */
void secrets_get(gw_secrets_t *out);

/** Copy the read-back flags. */
void secrets_flags(cfg_secret_flags_t *out);

/**
 * Atomically modify secrets: fn runs under the secrets mutex on a scratch copy; if it returns
 * ESP_OK and sec_validate() passes, the copy is swapped in, persisted (dirty flag) and
 * GW_EVT_CONFIG_CHANGED{CFG_SEC_SECRETS, by} is posted. fn must not block or call other store
 * APIs. Returns fn's error, ESP_ERR_INVALID_ARG on validation failure, ESP_ERR_INVALID_STATE after
 * secrets_factory_reset(), or ESP_OK.
 */
esp_err_t secrets_modify(esp_err_t (*fn)(gw_secrets_t *s, void *arg), void *arg, const char *by);

/**
 * Factory reset of the secrets (sysmgr sys_factory_reset): replace RAM by sec_defaults(factory PSK)
 * (no users: auth_init() recreates admin at the next boot), mark the file dirty so the persist task
 * rewrites it atomically, and freeze: later secrets_modify() calls return ESP_ERR_INVALID_STATE
 * until reboot. Posts no event. Returns once the write is queued.
 */
esp_err_t secrets_factory_reset(void);

#ifdef __cplusplus
}
#endif
