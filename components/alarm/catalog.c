/*
 * catalog.c - alarm catalog expanded from alarm_catalog.def, lookups, keys and the store hooks
 * (pure C, host-tested). Contract: alarm/alarm.h.
 */
#include <stdio.h>
#include <string.h>

#include "alarm/alarm.h"

const alm_desc_t alm_catalog[ALM_COUNT] = {
#define ALM(id_, code_, kind_, addr_, bit_, sev_, vreg_, ko_, en_)                                            \
    [ALM_##id_] = {#id_, (code_), (kind_), (addr_), (bit_), (sev_), (vreg_), (ko_), (en_)},
#include "alarm/alarm_x.h"
};

const alm_desc_t *alm_find_code(uint16_t code) {
    for (unsigned i = 0; i < ALM_COUNT; i++)
        if (alm_catalog[i].code == code)
            return &alm_catalog[i];
    return NULL;
}

const alm_desc_t *alm_find_id(const char *id) {
    if (!id)
        return NULL;
    for (unsigned i = 0; i < ALM_COUNT; i++)
        if (!strcmp(alm_catalog[i].id, id))
            return &alm_catalog[i];
    return NULL;
}

bool alarm_code_valid(uint16_t code) {
    return alm_find_code(code) != NULL;
}

static bool cat_code_from_id(const char *id, uint16_t *code) {
    const alm_desc_t *d = alm_find_id(id);
    if (!d || d->src == ALM_SRC_RULE)
        return false;
    if (code)
        *code = d->code;
    return true;
}

static const char *cat_id_from_code(uint16_t code) {
    const alm_desc_t *d = alm_find_code(code);
    return (d && d->src != ALM_SRC_RULE) ? d->id : NULL;
}

const cfg_alarm_catalog_t alm_cfg_catalog = {
    .code_from_id = cat_code_from_id,
    .id_from_code = cat_id_from_code,
};

const char *alm_sev_name(alm_sev_t s) {
    switch (s) {
    case ALM_SEV_INFO:
        return "info";
    case ALM_SEV_MINOR:
        return "minor";
    case ALM_SEV_MAJOR:
        return "major";
    case ALM_SEV_CRITICAL:
        return "critical";
    default:
        return "info";
    }
}

void alm_key_format(uint8_t dev, alm_id_t id, char out[ALM_KEY_SZ]) {
    if ((unsigned)id >= ALM_COUNT) {
        out[0] = '\0';
        return;
    }
    snprintf(out, ALM_KEY_SZ, "%u:%s", (unsigned)dev, alm_catalog[id].id);
}

bool alm_key_parse(const char *key, uint8_t *dev, alm_id_t *id) {
    if (!key || key[0] < '0' || key[0] > '9' || key[1] != ':')
        return false;
    unsigned d = (unsigned)(key[0] - '0');
    if (d >= GW_MAX_DEVICES)
        return false;
    const alm_desc_t *desc = alm_find_id(key + 2);
    if (!desc)
        return false;
    if (dev)
        *dev = (uint8_t)d;
    if (id)
        *id = (alm_id_t)(desc - alm_catalog);
    return true;
}
