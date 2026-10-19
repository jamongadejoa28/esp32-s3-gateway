/*
 * registry.h - SNMP MIB module registry (frozen, DESIGN.md §10).
 *
 * Modules register before the agent starts; snmp_registry_start() runs in the agent task
 * (snmp_transport on_start hook): it calls each module's init(), builds the array of
 * `const struct snmp_mib *` and hands it to lwIP snmp_set_mibs(). on_config() is invoked in the
 * agent task after configuration changes that may affect a module (sysName, devices, ...).
 *
 * OIDs: enterprise subtree is 1.3.6.1.4.1.<PEN>.1 with PEN = CONFIG_GW_SNMP_ENTERPRISE_PEN.
 * Modules build their base OID arrays at init() with snmp_gw_oid(); lwIP's device enterprise OID
 * (snmp_set_device_enterprise_oid) is ...PEN.1.1.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snmp_mib; /* lwip/apps/snmp_core.h */

#define SNMP_GW_MAX_MODULES 12
#define SNMP_GW_OID_MAX 32 /* <= SNMP_MAX_OBJ_ID_LEN (50) */

typedef struct {
    const char *name;           /* diagnostics only */
    const struct snmp_mib *mib; /* its base_oid array must be filled by init() before use */
    esp_err_t (*init)(void);    /* agent task, once, from snmp_registry_start(); may be NULL */
    void (*on_config)(void);    /* agent task, after relevant config changes; may be NULL */
} snmp_module_t;

/** Register a module (static storage). Max SNMP_GW_MAX_MODULES, only before snmp_registry_start(). */
esp_err_t snmp_registry_add(const snmp_module_t *m);

/** [agent task] init() every module, then snmp_set_mibs() in registration order. */
esp_err_t snmp_registry_start(void);

/** [agent task] Call every module's on_config(). */
void snmp_registry_notify_config(void);

/** Enterprise number in use (Kconfig CONFIG_GW_SNMP_ENTERPRISE_PEN, default 32473). */
uint32_t snmp_gw_pen(void);

/**
 * Write 1.3.6.1.4.1.<PEN>.1 followed by suffix[0..n) into out[cap]. Returns the total length, or 0
 * if it does not fit. Example: suffix {1} -> gw (…PEN.1.1); {3} -> mexStatusTable branch.
 */
size_t snmp_gw_oid(const uint32_t *suffix, size_t n, uint32_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
