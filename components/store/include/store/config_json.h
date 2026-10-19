/*
 * config_json.h - JSON mapping of gw_config_t (pure C: cJSON for parsing, gw_json_writer for output).
 *
 * Two shapes exist (docs/API.md §Config):
 *   file/export shape - cfg_to_json()/cfg_from_json(): whole document with "schema" and "rev";
 *                       "alarms" includes "rules". Never contains secrets.
 *   REST shape        - cfg_section_to_json()/cfg_section_from_json(): one section as served by
 *                       GET/PUT /api/v1/config/<section>; write-only secrets appear as "<x>_set"
 *                       booleans on GET and as plain fields on PUT. "alarms" excludes "rules"
 *                       (served by /config/rules via cfg_rules_*()).
 * Value formats: IPv4 as dotted quad strings ("" or absent = 0 for optional gw/dns), CIDR strings,
 * rule "src" as "temp"|"hum"|"cur"|"reg:<addr>", "op" as ">"|"<", rule thr/hyst as decimal numbers
 * at the source register scale (30.5), severities as integers 0..3, parity as "N"|"E"|"O",
 * sev_override as an object {"<alarm id>": sev} (ids <-> codes through cfg_set_alarm_catalog();
 * unknown or rule_* ids -> CFG_JSON_E_INVALID, field "alarms.sev_override.<id>", code
 * "unknown_field").
 * Return codes: CFG_JSON_OK or a negative CFG_JSON_E_*; *err (optional) names the field.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_json_writer.h"
#include "store/config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cJSON; /* espressif/cjson; forward-declared to keep this header include-light */

#define CFG_JSON_OK 0
#define CFG_JSON_E_PARSE (-1)   /* not JSON / wrong top-level type -> REST 400 invalid_json */
#define CFG_JSON_E_SCHEMA (-2)  /* schema newer than CFG_SCHEMA_VERSION -> 422 unsupported_schema */
#define CFG_JSON_E_INVALID (-3) /* type/range/validation error -> REST 422 validation */
#define CFG_JSON_E_WRITE (-4)   /* writer error */

/**
 * Parse a file/export document: out = cfg_defaults(mac); overlay present fields (unknown fields
 * ignored); migrate from its "schema" (missing = 1) to CFG_SCHEMA_VERSION; cfg_validate().
 */
int cfg_from_json(const char *json, size_t len, const uint8_t mac[GW_MAC_LEN], gw_config_t *out,
                  cfg_verr_t *err);

/**
 * Write the file/export document (all sections, "schema", "rev") as one complete JSON object.
 * fw != NULL adds a top-level "fw" member (config export bundle, docs/API.md §4.11); the persisted
 * file passes NULL. cfg_from_json() ignores "fw".
 */
int cfg_to_json(const gw_config_t *c, const char *fw, gw_jw_t *w);

/**
 * In-place migration of a parsed document from schema `from` to CFG_SCHEMA_VERSION (chain of
 * single-step migrators). from > CFG_SCHEMA_VERSION -> CFG_JSON_E_SCHEMA.
 */
int cfg_migrate(struct cJSON *root, int from, cfg_verr_t *err);

/** REST GET body of section s. flags may be NULL (then "<x>_set" fields are omitted).
 * CFG_SEC_NETWORK writes "provisional": null; use cfg_network_to_json() to report a pending change. */
int cfg_section_to_json(cfg_section_t s, const gw_config_t *c, const cfg_secret_flags_t *flags, gw_jw_t *w);

/**
 * REST GET body of the network section with the live provisional state (added by stream B, see
 * DECISIONS.md): provisional_json is a complete JSON value inserted verbatim as "provisional"
 * (e.g. {"state":"await_confirm","left_s":97}); NULL or "" writes null.
 */
int cfg_network_to_json(const gw_config_t *c, const cfg_secret_flags_t *flags, const char *provisional_json,
                        gw_jw_t *w);

/**
 * REST PUT body of section s, merged onto cur's section: absent fields keep their current value,
 * arrays present in the body replace the whole array, unknown fields -> CFG_JSON_E_INVALID
 * ("unknown_field"). Write-only secret fields are moved into *secrets (may be NULL for sections
 * without secrets; then such fields are rejected). For CFG_SEC_SNMP with "traps" present it sets
 * secrets->has_traps and fills secrets->trap_from with cfg_trap_remap(cur, result) so stored trap
 * communities follow their (host, port), never the array position. Does NOT run
 * cfg_validate_with(); the caller passes the result to cfg_commit() (SNMP: after
 * cfg_snmp_check_secrets()).
 */
int cfg_section_from_json(cfg_section_t s, const char *json, size_t len, const gw_config_t *cur,
                          void *out_sec, cfg_secret_input_t *secrets, cfg_verr_t *err);

/** GET /config/rules body: JSON array of rules. */
int cfg_rules_to_json(const cfg_alarms_t *a, gw_jw_t *w);

/** PUT /config/rules body (array, max GW_MAX_RULES) replacing inout->rules / n_rules. */
int cfg_rules_from_json(const char *json, size_t len, cfg_alarms_t *inout, cfg_verr_t *err);

#ifdef __cplusplus
}
#endif
