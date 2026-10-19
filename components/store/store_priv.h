/*
 * store_priv.h - store-internal helpers shared by the pure and device sources (not a public header).
 * Pure: no IDF headers.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "store/config.h"
#include "store/config_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Catalog hooks installed with cfg_set_alarm_catalog() (NULL when none). */
const cfg_alarm_catalog_t *cfg_alarm_catalog(void);

/** Copy src into dst[cap] and zero the rest of dst (canonical buffers compare byte-identical). */
void store_strset(char *dst, size_t cap, const char *src);

/** True iff s is NUL-terminated within cap, at most max_bytes long and valid UTF-8 without control
 * characters (U+0000..U+001F, U+007F). */
bool store_text_ok(const char *s, size_t cap, size_t max_bytes);

/** True iff s (NUL-terminated within cap) has 0 < len <= max chars, all in [lo, hi] (ASCII). */
bool store_ascii_ok(const char *s, size_t cap, size_t min_len, size_t max_len, char lo, char hi);

/**
 * cfg_from_json() that also reports the document's schema version before migration
 * (*schema_from, 0 when the document was rejected before reading it). Used by config_load() to
 * rewrite a migrated file.
 */
int cfg_from_json_ex(const char *json, size_t len, const uint8_t mac[GW_MAC_LEN], gw_config_t *out,
                     cfg_verr_t *err, int *schema_from);

struct cJSON;
/** Zero every string value of a cJSON tree (node, its siblings and children) before cJSON_Delete. */
void store_json_wipe(struct cJSON *node);

/**
 * After a successful atomic_write(path) in the factory-reset (frozen) state: remove path.bak and
 * path.tmp so no pre-reset copy survives (DESIGN §5: factory reset deletes the cfg and sec dirs).
 * ESP_OK when both are gone (missing counts as gone).
 */
esp_err_t atomic_drop_backups(const char *path);

/** Rule source register scale (1 or 10) of a REG row address; 1 for unknown addresses. */
uint16_t cfg_rule_scale(uint16_t addr);

#ifdef __cplusplus
}
#endif
