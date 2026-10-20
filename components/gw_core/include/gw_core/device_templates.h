/* Protocol-independent template catalog; never reads a device or executes a control command. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GW_TEMPLATE_ID_SZ 16
#define GW_DEFAULT_TEMPLATE_ID "mex150"
#define GW_CHANNEL_DISPLAY_DEFAULT 0x003FFFFFu

typedef struct {
    uint8_t id;
    const char *key, *ko, *en, *access, *source;
    uint16_t addr;
    uint8_t scale;
    const char *unit;
} gw_template_channel_t;

typedef struct {
    const char *id, *name, *vendor, *category, *description;
    uint32_t baud;
    uint8_t data_bits;
    const char *parity;
    uint8_t stop_bits;
    const gw_template_channel_t *channels;
    size_t channel_count;
} gw_device_template_t;

extern const gw_device_template_t gw_device_templates[];
extern const size_t gw_device_template_count;

/** Exact match; NULL/empty/unknown IDs are rejected. */
const gw_device_template_t *gw_device_template_find(const char *id);

#ifdef __cplusplus
}
#endif
